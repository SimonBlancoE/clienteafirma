//! Firmador XMLDSig (`AOXMLDSigSigner`): firmas XML sin propiedades XAdES en
//! las variantes Enveloping, Enveloped, Detached (internamente separada) y
//! Externally Detached, en modo implícito o explícito, con cofirma y
//! contrafirma (firmas hermanas con referencia `CountersignedSignature`).

use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::{CounterSignTarget, SignInfo, Signer, SignersTree};

use crate::c14n::{C14N_10, C14n};
use crate::dom::{Document, NodeId};
use crate::dsig::{self, DSIG_NS, DsNames, Placeholders, ReferenceSpec, TransformSpec};
use crate::mime;
use crate::splice;
use crate::util::{self, esc_attr, uuid_v4};
use crate::xades::{self, info::Arena, multi::copy_transforms, sign::custom_transforms};

pub const FORMAT_XMLDSIG: &str = "XMLDSig";
pub const FORMAT_DETACHED: &str = "XMLDSig Detached";
pub const FORMAT_EXTERNALLY_DETACHED: &str = "XMLDSig Externally Detached";
pub const FORMAT_ENVELOPED: &str = "XMLDSig Enveloped";
pub const FORMAT_ENVELOPING: &str = "XMLDSig Enveloping";
const CSURI: &str = "http://uri.etsi.org/01903#CountersignedSignature";
const DEFAULT_DIGEST: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

fn canonical_format(f: &str) -> Option<&'static str> {
    [
        FORMAT_ENVELOPING,
        FORMAT_ENVELOPED,
        FORMAT_DETACHED,
        FORMAT_EXTERNALLY_DETACHED,
    ]
    .into_iter()
    .find(|c| c.eq_ignore_ascii_case(f.trim()))
}

/// Los datos se tratan como XML si se analizan con el analizador de
/// `Utils.getNewDocumentBuilder` (se admite un DTD interno pero no uno
/// externo, cuyo acceso está prohibido).
fn load_xml_dsig(data: &[u8]) -> Option<Document> {
    let (doc, _) = Document::parse_bytes(data).ok()?;
    if let Some(dt) = &doc.doctype {
        let text = &doc.source()[dt.clone()];
        let head = text.split('[').next().unwrap_or("");
        if head.contains("SYSTEM") || head.contains("PUBLIC") {
            return None;
        }
    }
    Some(doc)
}

fn key_info(ds: &DsNames, id: &str, key: &dyn SigningKey, only_cert: bool) -> String {
    let mut s = format!("<{} Id=\"{}\">", ds.q("KeyInfo"), esc_attr(id));
    if let Some(kv) = dsig::render_key_value(ds, key.certificate()) {
        s.push_str(&kv);
    }
    s.push_str(&dsig::render_x509_data(
        ds,
        &xades::sign::key_info_certs(key, only_cert),
    ));
    s.push_str(&format!("</{}>", ds.q("KeyInfo")));
    s
}

/// `XmlDSigUtil.cleanReferencesList`: quita la transformada Base64 de las
/// referencias sin `Id`.
fn clean_references(refs: &mut [ReferenceSpec]) {
    for r in refs.iter_mut() {
        if r.id.is_none() {
            r.transforms
                .retain(|t| !matches!(t, TransformSpec::Plain(a) if a == dsig::BASE64));
        }
    }
}

struct SigParts {
    ds: DsNames,
    id: String,
    c14n: String,
    sig_uri: String,
    refs: Vec<ReferenceSpec>,
    key_info: String,
    objects: Vec<String>,
}

impl SigParts {
    fn signature_id(&self) -> String {
        format!("Signature-{}", self.id)
    }

    fn render(&self, ph: &mut Placeholders, ds_in_scope: bool) -> String {
        let ds = &self.ds;
        let id_attr = format!("Id=\"Signature-{}\"", self.id);
        let mut s = if ds_in_scope {
            format!("<{} {id_attr}{}>", ds.q("Signature"), ds.xmlns())
        } else {
            format!("<{}{} {id_attr}>", ds.q("Signature"), ds.xmlns())
        };
        s.push_str(&dsig::render_signed_info(
            ds,
            &self.c14n,
            &self.sig_uri,
            &self.refs,
            ph,
        ));
        s.push_str(&format!(
            "<{sv} Id=\"SignatureValue-{}\">{}</{sv}>",
            self.id,
            ph.signature_value(),
            sv = ds.q("SignatureValue")
        ));
        s.push_str(&self.key_info);
        for o in &self.objects {
            s.push_str(o);
        }
        s.push_str(&format!("</{}>", ds.q("Signature")));
        s
    }
}

fn complete(
    text: String,
    ph: &Placeholders,
    parts: &SigParts,
    key: &dyn SigningKey,
    alg: afirma_core::SignatureAlgorithm,
) -> afirma_core::Result<String> {
    dsig::complete(
        text,
        ph,
        &dsig::Completion {
            key,
            algorithm: alg,
            signature_id: &parts.signature_id(),
            resolver: &dsig::NoResolver,
            verify: false,
            error_code: codes::INTERNAL_XML_SIGNING_ERROR,
        },
    )
}

fn resolve_alg(
    algorithm: &str,
    key: &dyn SigningKey,
) -> afirma_core::Result<(String, afirma_core::SignatureAlgorithm)> {
    xades::resolve_algorithm(algorithm, key.key_algorithm())
}

/// Lee un fichero `file:` (AOUtil.loadFile).
fn load_file_uri(uri: &str) -> afirma_core::Result<Vec<u8>> {
    let u = afirma_core::aoutil::create_uri(uri).map_err(|e| {
        AfirmaError::new(
            codes::DERREFERENCING_DATA_ERROR,
            format!("No se han podido obtener los datos de la URI externa: {e}"),
        )
    })?;
    match u.file_path() {
        Some(p) => std::fs::read(&p).map_err(|e| {
            AfirmaError::new(
                codes::DERREFERENCING_DATA_ERROR,
                format!("No se han podido obtener los datos de la URI externa: {e}"),
            )
        }),
        None => Err(AfirmaError::new(
            codes::DERREFERENCING_DATA_ERROR,
            format!("No se pueden descargar datos remotos: {uri}"),
        )),
    }
}

fn uri_scheme(uri: &str) -> Option<String> {
    afirma_core::aoutil::create_uri(uri)
        .ok()
        .map(|u| u.scheme().to_string())
}

/// Firmador XMLDSig.
#[derive(Default)]
pub struct XmldsigSigner;

impl XmldsigSigner {
    pub fn new() -> Self {
        XmldsigSigner
    }
}

fn sign_impl(
    data: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    p: &ExtraParams,
) -> afirma_core::Result<Vec<u8>> {
    let (sig_uri, sig_alg) = resolve_alg(algorithm, key).map_err(|_| {
        AfirmaError::new(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            format!("Los formatos de firma XML no soportan el algoritmo de firma {algorithm}"),
        )
    })?;
    let format_raw = p.get_or("format", FORMAT_ENVELOPING).to_string();
    let mode_raw = p.get_or("mode", "implicit").to_string();
    let digest_uri = p
        .get_or("referencesDigestMethod", DEFAULT_DIGEST)
        .to_string();
    let c14n_param = p.get_or("canonicalizationAlgorithm", C14N_10).to_string();
    let avoid_b64 = p.get_bool("avoidBase64Transforms", false);
    let avoid_xpath = p.get_bool("avoidXpathExtraTransformsOnEnveloped", false);
    let prefix = p.get_or("xmlSignaturePrefix", "ds").to_string();
    let mut mime_type = p.get("mimeType").map(str::to_string);
    let mut encoding = p.get("encoding").map(str::to_string);
    if encoding
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case("base64"))
    {
        encoding = Some(dsig::BASE64.to_string());
    }
    let mut uri = p
        .get("uri")
        .filter(|u| afirma_core::aoutil::create_uri(u).is_ok())
        .map(str::to_string);
    let precalc = p.get("precalculatedHashAlgorithm").map(str::to_string);
    let only_cert = p.get_bool("includeOnlySignningCertificate", false);

    // Utils.checkIllegalParams (validación sin distinguir mayúsculas).
    let implicit = if mode_raw.eq_ignore_ascii_case("implicit") {
        true
    } else if mode_raw.eq_ignore_ascii_case("explicit") {
        false
    } else {
        return Err(AfirmaError::unsupported(format!(
            "El modo de firma '{mode_raw}' no esta soportado"
        )));
    };
    let format = canonical_format(&format_raw);
    if format == Some(FORMAT_ENVELOPED) && !implicit {
        return Err(AfirmaError::unsupported(
            "No se puede realizar una firma enveloped sobre un contenido explicito",
        ));
    }
    if format == Some(FORMAT_EXTERNALLY_DETACHED) && implicit {
        return Err(AfirmaError::unsupported(
            "No se puede realizar una firma XML Externally Detached con contenido Implicito",
        ));
    }
    if format == Some(FORMAT_EXTERNALLY_DETACHED) && uri.is_none() && precalc.is_none() {
        return Err(AfirmaError::unsupported(
            "La firma XML Externally Detached necesita un Message Digest precalculado o una URI accesible",
        ));
    }
    let Some(format) = format else {
        return Err(AfirmaError::unsupported(format!(
            "El formato de firma '{format_raw}' no esta soportado"
        )));
    };
    if data.is_empty() && !(format == FORMAT_EXTERNALLY_DETACHED && uri.is_some()) {
        return Err(AfirmaError::invalid_argument(
            "No se han indicado los datos a firmar",
        ));
    }
    let ds = DsNames::new(&prefix);
    let content_id = format!("CONTENT-{}-CONTENT", uuid_v4());
    let mut is_base64 = false;
    let mut was_encoded = false;
    let mut output_encoding: Option<String> = None;
    let mut xml_doc: Option<Document> = None;
    let mut data_text: String;
    if implicit {
        match load_xml_dsig(data) {
            Some(doc) => {
                if mime_type.is_none() || mime_type.as_deref() == Some(mime::DEFAULT_MIMETYPE) {
                    mime_type = Some("text/xml".into());
                }
                if encoding.is_none() {
                    encoding = doc.xml_decl.as_ref().and_then(|d| d.encoding.clone());
                }
                if let Some(e) = &encoding {
                    if e != dsig::BASE64 {
                        output_encoding = Some(e.clone());
                    }
                }
                let root = doc.document_element().expect("raíz");
                if format == FORMAT_DETACHED {
                    data_text = format!(
                        "<CONTENT Encoding=\"{}\" Id=\"{content_id}\" MimeType=\"{}\">{}</CONTENT>",
                        esc_attr(encoding.as_deref().unwrap_or("")),
                        esc_attr(mime_type.as_deref().unwrap_or("")),
                        doc.node_source(root)
                    );
                } else {
                    data_text = doc.node_source(root).to_string();
                }
                xml_doc = Some(doc);
            }
            None => {
                if format == FORMAT_ENVELOPED {
                    return Err(AfirmaError::new(
                        codes::XML_DOCUMENT_NEEDED,
                        "La firma requiere que los datos sean un documento XML",
                    ));
                }
                uri = None;
                encoding = Some(dsig::BASE64.to_string());
                let mut mt = mime_type
                    .clone()
                    .unwrap_or_else(|| mime::DEFAULT_MIMETYPE.to_string());
                let text;
                if util::is_base64(data) {
                    let decoded =
                        util::b64_decode(&String::from_utf8_lossy(data)).unwrap_or_default();
                    mt = mime::detect(&decoded);
                    text = String::from_utf8_lossy(data).into_owned();
                } else {
                    if mt == mime::DEFAULT_MIMETYPE {
                        mt = mime::detect(data);
                    }
                    text = util::b64(data);
                    was_encoded = true;
                }
                mime_type = Some(mt);
                is_base64 = true;
                data_text = util::esc_text(&text);
            }
        }
    } else {
        let digest = if let Some(u) = &uri {
            let bytes = load_file_uri(u)?;
            afirma_core::DigestAlgorithm::Sha1.digest(&bytes)
        } else if precalc.is_some() {
            data.to_vec()
        } else {
            afirma_core::DigestAlgorithm::Sha1.digest(data)
        };
        encoding = Some(dsig::BASE64.to_string());
        mime_type = Some(match &precalc {
            Some(a) => format!("hash/{}", a.to_lowercase()),
            None => "hash/sha1".into(),
        });
        data_text = util::b64(&digest);
        is_base64 = true;
    }
    if dsig::digest_from_uri(&digest_uri).is_none() {
        return Err(AfirmaError::new(
            codes::INVALID_REFERENCES_HASH_ALGORITHM_URI,
            format!(
                "No se ha podido obtener un generador de huellas digitales para el algoritmo {digest_uri}"
            ),
        ));
    }
    let c14n: Option<String> = if c14n_param.eq_ignore_ascii_case("none") {
        None
    } else {
        if C14n::from_uri(&c14n_param).is_none() {
            return Err(AfirmaError::new(
                codes::INVALID_CANONICALIZATION_URI,
                format!(
                    "No se ha podido crear la transformacion de canonicalizacion para el algoritmo {c14n_param}"
                ),
            ));
        }
        Some(c14n_param.clone())
    };
    let reference_id = format!("Reference-{}", uuid_v4());
    let mut t = custom_transforms(p)?;
    if !is_base64 {
        if let Some(c) = &c14n {
            t.push(TransformSpec::Plain(c.clone()));
        }
    } else if was_encoded && !avoid_b64 {
        t.push(TransformSpec::Plain(dsig::BASE64.into()));
    }
    let mut refs = Vec::new();
    let mut objects = Vec::new();
    // Contenido del contenedor antes de la firma.
    let mut before_sig = String::new();
    match format {
        FORMAT_ENVELOPING => {
            let object_id = format!("Object-{}", uuid_v4());
            let mut o = format!("<{}", ds.q("Object"));
            if let Some(e) = &encoding {
                o.push_str(&format!(" Encoding=\"{}\"", esc_attr(e)));
            }
            o.push_str(&format!(" Id=\"{object_id}\""));
            if let Some(m) = &mime_type {
                o.push_str(&format!(" MimeType=\"{}\"", esc_attr(m)));
            }
            o.push('>');
            o.push_str(&data_text);
            o.push_str(&format!("</{}>", ds.q("Object")));
            objects.push(o);
            let mut r = ReferenceSpec::new(format!("#{object_id}"), &digest_uri);
            r.id = Some(reference_id.clone());
            r.ty = Some(dsig::OBJECT_TYPE.into());
            r.transforms = t.clone();
            refs.push(r);
        }
        FORMAT_DETACHED => {
            if is_base64 {
                data_text = format!(
                    "<CONTENT Encoding=\"{}\" Id=\"{content_id}\" MimeType=\"{}\">{data_text}</CONTENT>",
                    esc_attr(encoding.as_deref().unwrap_or("")),
                    esc_attr(mime_type.as_deref().unwrap_or(""))
                );
            }
            before_sig = data_text.clone();
            let mut r = ReferenceSpec::new(format!("#{content_id}"), &digest_uri);
            r.id = Some(reference_id.clone());
            r.ty = Some(dsig::OBJECT_TYPE.into());
            r.transforms = t.clone();
            refs.push(r);
        }
        FORMAT_EXTERNALLY_DETACHED => {
            let scheme = uri.as_deref().and_then(uri_scheme);
            if precalc.is_some()
                && (uri.is_none()
                    || scheme.as_deref() == Some("")
                    || scheme.as_deref() == Some("file"))
            {
                let name = afirma_core::algorithms::java_digest_algorithm_name(
                    precalc.as_deref().unwrap_or(""),
                );
                let dm = match name.to_uppercase().as_str() {
                    "SHA1" => "http://www.w3.org/2000/09/xmldsig#sha1",
                    "SHA-256" => "http://www.w3.org/2001/04/xmlenc#sha256",
                    "SHA-512" => "http://www.w3.org/2001/04/xmlenc#sha512",
                    "RIPEMD160" => "http://www.w3.org/2001/04/xmlenc#ripemd160",
                    _ => {
                        return Err(AfirmaError::new(
                            codes::INVALID_PRECALCULATED_DATA_HASH_ALGORITHM,
                            format!(
                                "Metodo de Message Digest para la referencia Externally Detached no soportado: {}",
                                precalc.as_deref().unwrap_or("")
                            ),
                        ));
                    }
                };
                let mut r = ReferenceSpec::new("", dm);
                r.id = Some(reference_id.clone());
                r.ty = Some(dsig::OBJECT_TYPE.into());
                r.digest = Some(data.to_vec());
                refs.push(r);
            } else if scheme.as_deref() == Some("file") {
                let bytes = load_file_uri(uri.as_deref().unwrap_or(""))?;
                let alg = dsig::digest_from_uri(&digest_uri).expect("comprobado");
                let mut r = ReferenceSpec::new("", &digest_uri);
                r.id = Some(reference_id.clone());
                r.ty = Some(dsig::OBJECT_TYPE.into());
                r.digest = Some(alg.digest(&bytes));
                refs.push(r);
            } else if let Some(u) = &uri {
                // http/https/urn: Santuario descargaría el recurso al firmar.
                refs.push(ReferenceSpec::new(u.clone(), &digest_uri));
            } else {
                return Err(AfirmaError::new(
                    codes::INTERNAL_XML_SIGNING_ERROR,
                    "Error al generar la firma Externally Detached, no se ha podido crear la referencia externa",
                ));
            }
        }
        _ => {
            // Enveloped
            t.push(TransformSpec::Plain(dsig::ENVELOPED.into()));
            if !avoid_xpath {
                t.push(TransformSpec::XPath(format!(
                    "not(ancestor-or-self::{prefix}:Signature)"
                )));
            }
            let mut r = ReferenceSpec::new("", &digest_uri);
            r.id = Some(reference_id.clone());
            r.ty = Some(dsig::OBJECT_TYPE.into());
            r.transforms = t.clone();
            refs.push(r);
        }
    }
    let id = uuid_v4();
    let mut ki_ref = ReferenceSpec::new(format!("#KeyInfo-{id}"), &digest_uri);
    ki_ref.transforms = t.clone();
    refs.push(ki_ref);
    clean_references(&mut refs);
    let parts = SigParts {
        ds: ds.clone(),
        id: id.clone(),
        c14n: c14n.clone().unwrap_or_else(|| C14N_10.to_string()),
        sig_uri,
        refs,
        key_info: key_info(&ds, &format!("KeyInfo-{id}"), key, only_cert),
        objects,
    };
    let mut ph = Placeholders::new();
    let enc = output_encoding.unwrap_or_else(|| "UTF-8".into());
    let out = if format == FORMAT_ENVELOPED {
        let doc = xml_doc.expect("XML");
        let root = doc.document_element().expect("raíz");
        let in_scope = doc.lookup_namespace(root, Some(&prefix)).as_deref() == Some(DSIG_NS)
            && !prefix.is_empty();
        let text = splice::insert_last_child(&doc, root, &parts.render(&mut ph, in_scope));
        let signed = complete(text, &ph, &parts, key, sig_alg)?;
        splice::finish_preserving(&doc, &signed, &enc)
    } else {
        let sig_text = parts.render(&mut ph, false);
        // Envoltorio AFIRMA salvo firma Enveloping con una única firma.
        let qname = ds.q("Signature");
        let existing = xml_doc.as_ref().map(|d| {
            d.descendants(d.root())
                .into_iter()
                .filter(|&n| d.element(n).is_some_and(|e| e.qname() == qname))
                .count()
        });
        let unwrap = format == FORMAT_ENVELOPING && existing.unwrap_or(0) == 0;
        let text = if unwrap {
            sig_text
        } else {
            format!("<AFIRMA>{before_sig}{sig_text}</AFIRMA>")
        };
        let signed = complete(text, &ph, &parts, key, sig_alg)?;
        splice::finish(&signed, &enc)
    };
    out.map_err(|m| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, m))
}

fn local(doc: &Document, n: NodeId) -> &str {
    doc.element(n).map(|e| e.local.as_str()).unwrap_or("")
}

fn parse_sign(sign: &[u8]) -> afirma_core::Result<Document> {
    Document::parse_bytes(sign).map(|(d, _)| d).map_err(|e| {
        AfirmaError::invalid_signature_format(format!(
            "No se ha podido leer el documento de firmas: {e}"
        ))
    })
}

/// Raíz con envoltorio `<AFIRMA>` si la raíz es una firma.
fn wrap_if_signature(doc: &Document) -> (String, bool) {
    let root = doc.document_element().expect("raíz");
    if doc
        .element(root)
        .is_some_and(|e| e.is(DSIG_NS, "Signature"))
    {
        (format!("<AFIRMA>{}</AFIRMA>", doc.node_source(root)), true)
    } else {
        (doc.source().to_string(), false)
    }
}

fn search_data_element(doc: &Document, uri: &str) -> Option<NodeId> {
    let id = uri.strip_prefix('#').unwrap_or(uri);
    let root = doc.document_element()?;
    if doc.element(root).and_then(|e| e.attr("Id")) == Some(id) {
        return Some(root);
    }
    for &c in doc.children(root).iter().rev() {
        if doc.element(c).and_then(|e| e.attr("Id")) == Some(id) {
            return Some(c);
        }
        if local(doc, c) == "Signature" {
            for &sc in doc.children(c).iter().rev() {
                if doc.element(sc).and_then(|e| e.attr("Id")) == Some(id) {
                    return Some(sc);
                }
            }
        }
    }
    None
}

fn is_enveloping_root(doc: &Document) -> bool {
    let Some(root) = doc.document_element() else {
        return false;
    };
    let e = doc.element(root).expect("raíz");
    e.local == "Signature"
        || (e.qname() == "AFIRMA"
            && doc
                .children(root)
                .first()
                .is_some_and(|&c| local(doc, c) == "Signature"))
}

fn cosign_impl(
    sign: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    p: &ExtraParams,
) -> afirma_core::Result<Vec<u8>> {
    let (sig_uri, sig_alg) = resolve_alg(algorithm, key).map_err(|_| {
        AfirmaError::new(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            format!("Los formatos de firma XML no soportan el algoritmo de firma {algorithm}"),
        )
    })?;
    let digest_uri = p
        .get_or("referencesDigestMethod", DEFAULT_DIGEST)
        .to_string();
    let c14n = p.get_or("canonicalizationAlgorithm", C14N_10).to_string();
    let prefix = p.get_or("xmlSignaturePrefix", "ds").to_string();
    let only_cert = p.get_bool("includeOnlySignningCertificate", false);
    if dsig::digest_from_uri(&digest_uri).is_none() || C14n::from_uri(&c14n).is_none() {
        return Err(AfirmaError::unsupported(
            "Hay al menos un algoritmo no soportado",
        ));
    }
    let doc0 = parse_sign(sign)?;
    let (text, _) = wrap_if_signature(&doc0);
    let doc = Document::parse(&text)
        .map_err(|e| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, e.to_string()))?;
    let root = doc.document_element().expect("raíz");
    let first = doc
        .find_descendants(doc.root(), DSIG_NS, "Signature")
        .into_iter()
        .next()
        .ok_or_else(|| {
            AfirmaError::invalid_signature_format("No se ha encontrado ninguna firma")
        })?;
    let ds = DsNames::new(&prefix);
    let enveloping = is_enveloping_root(&doc);
    let mut refs = Vec::new();
    let mut object: Option<String> = None;
    for (i, r) in doc
        .find_descendants(first, DSIG_NS, "Reference")
        .into_iter()
        .enumerate()
    {
        let re = doc.element(r).expect("elemento");
        let style = re
            .attr("Id")
            .is_some_and(|x| x.starts_with("StyleReference-"));
        if i != 0 && !style {
            continue;
        }
        let transforms = copy_transforms(&doc, r, &prefix)?;
        let rid = if style {
            format!("StyleReference-{}", uuid_v4())
        } else {
            format!("Reference-{}", uuid_v4())
        };
        let uri = re.attr("URI").unwrap_or("").to_string();
        let mut spec = if enveloping {
            let found = search_data_element(&doc, &uri).ok_or_else(|| {
                AfirmaError::new(
                    codes::INTERNAL_XML_SIGNING_ERROR,
                    "No se ha encontrado el nodo de datos de la firma",
                )
            })?;
            let fe = doc.element(found).expect("elemento");
            let object_id = format!("Object-{}", uuid_v4());
            let content = doc
                .children(found)
                .first()
                .map(|&c| doc.node_source(c).to_string())
                .unwrap_or_default();
            object = Some(format!(
                "<{o} Encoding=\"{}\" Id=\"{object_id}\" MimeType=\"{}\">{content}</{o}>",
                esc_attr(fe.attr("Encoding").unwrap_or("")),
                esc_attr(fe.attr("MimeType").unwrap_or("")),
                o = ds.q("Object")
            ));
            ReferenceSpec::new(format!("#{object_id}"), &digest_uri)
        } else {
            ReferenceSpec::new(uri, &digest_uri)
        };
        spec.id = Some(rid);
        spec.ty = Some(dsig::OBJECT_TYPE.into());
        spec.transforms = transforms;
        refs.push(spec);
    }
    let id = uuid_v4();
    let mut ki = ReferenceSpec::new(format!("#KeyInfo-{id}"), &digest_uri);
    ki.transforms = vec![TransformSpec::Plain(c14n.clone())];
    refs.push(ki);
    let parts = SigParts {
        ds: ds.clone(),
        id: id.clone(),
        c14n,
        sig_uri,
        refs,
        key_info: key_info(&ds, &format!("KeyInfo-{id}"), key, only_cert),
        objects: object.into_iter().collect(),
    };
    let mut ph = Placeholders::new();
    let in_scope =
        !prefix.is_empty() && doc.lookup_namespace(root, Some(&prefix)).as_deref() == Some(DSIG_NS);
    let full = splice::insert_last_child(&doc, root, &parts.render(&mut ph, in_scope));
    let signed = complete(full, &ph, &parts, key, sig_alg)?;
    splice::finish(&strip_decl(&signed), "UTF-8")
        .map_err(|m| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, m))
}

/// Quita la declaración XML del texto (se reescribe al serializar).
fn strip_decl(text: &str) -> String {
    match Document::parse(text) {
        Ok(d) => {
            // Se conserva el prólogo salvo la declaración.
            let decl_end = d.xml_decl.as_ref().map(|x| x.range.end).unwrap_or(0);
            text[decl_end..].trim_start_matches('\n').to_string()
        }
        Err(_) => text.to_string(),
    }
}

fn signature_value_id(doc: &Document, sig: NodeId) -> Option<String> {
    doc.find_descendants(sig, DSIG_NS, "SignatureValue")
        .into_iter()
        .next()
        .and_then(|v| {
            doc.element(v)
                .and_then(|e| e.attr("Id"))
                .map(str::to_string)
        })
}

fn first_cert_cn(doc: &Document, sig: NodeId) -> Option<String> {
    let c = doc
        .find_descendants(sig, DSIG_NS, "X509Certificate")
        .into_iter()
        .next()?;
    let der = util::b64_decode(&doc.text_content(c))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(afirma_core::aoutil::get_cn(&crate::dn::java_name(
        cert.subject(),
    )))
}

fn countersign_impl(
    sign: &[u8],
    algorithm: &str,
    target: &CounterSignTarget,
    key: &dyn SigningKey,
    p: &ExtraParams,
) -> afirma_core::Result<Vec<u8>> {
    let (sig_uri, sig_alg) = resolve_alg(algorithm, key).map_err(|_| {
        AfirmaError::new(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            format!("Los formatos de firma XML no soportan el algoritmo de firma {algorithm}"),
        )
    })?;
    let digest_uri = p
        .get_or("referencesDigestMethod", DEFAULT_DIGEST)
        .to_string();
    let c14n = p.get_or("canonicalizationAlgorithm", C14N_10).to_string();
    let prefix = p.get_or("xmlSignaturePrefix", "ds").to_string();
    let only_cert = p.get_bool("includeOnlySignningCertificate", false);
    if dsig::digest_from_uri(&digest_uri).is_none() || C14n::from_uri(&c14n).is_none() {
        return Err(AfirmaError::unsupported(
            "Hay al menos un algoritmo no soportado",
        ));
    }
    let doc0 = parse_sign(sign)?;
    let declared = doc0.xml_decl.as_ref().and_then(|d| d.encoding.clone());
    let enc = match p.get("encoding") {
        Some(e) if e.eq_ignore_ascii_case("base64") || e == dsig::BASE64 => "UTF-8".to_string(),
        Some(e) => e.to_string(),
        None => declared.unwrap_or_else(|| "UTF-8".into()),
    };
    let (mut text, _) = wrap_if_signature(&doc0);
    let doc = Document::parse(&text)
        .map_err(|e| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, e.to_string()))?;
    let root = doc.document_element().expect("raíz");
    let sigs = doc.find_descendants(root, DSIG_NS, "Signature");
    let all_uris: Vec<String> = doc
        .find_descendants(doc.root(), DSIG_NS, "Reference")
        .into_iter()
        .filter_map(|r| {
            doc.element(r)
                .and_then(|e| e.attr("URI"))
                .map(str::to_string)
        })
        .collect();
    let targets: Vec<NodeId> = match target {
        CounterSignTarget::Tree => sigs.clone(),
        CounterSignTarget::Leafs => {
            let mut out = Vec::new();
            for &s in &sigs {
                let id = signature_value_id(&doc, s).ok_or_else(|| {
                    AfirmaError::new(
                        codes::INTERNAL_XML_SIGNING_ERROR,
                        "Firma sin identificador de SignatureValue",
                    )
                })?;
                if !all_uris.iter().any(|u| *u == format!("#{id}")) {
                    out.push(s);
                }
            }
            out
        }
        CounterSignTarget::Nodes(idx) => {
            // Preorden: firmas principales y, recursivamente, sus contrafirmas.
            let is_cs = |s: NodeId| {
                doc.find_descendants(s, DSIG_NS, "Reference")
                    .into_iter()
                    .any(|r| doc.element(r).and_then(|e| e.attr("Type")) == Some(CSURI))
            };
            fn add_sub(doc: &Document, sigs: &[NodeId], sv_id: &str, out: &mut Vec<NodeId>) {
                for &s in sigs {
                    let refs_it = doc.find_descendants(s, DSIG_NS, "Reference");
                    if refs_it.iter().any(|&r| {
                        doc.element(r).and_then(|e| e.attr("URI")) == Some(&format!("#{sv_id}"))
                    }) {
                        if out.contains(&s) {
                            continue;
                        }
                        out.push(s);
                        if let Some(id) = signature_value_id(doc, s) {
                            if id != sv_id {
                                add_sub(doc, sigs, &id, out);
                            }
                        }
                    }
                }
            }
            let mut order = Vec::new();
            for &s in &sigs {
                if !is_cs(s) {
                    order.push(s);
                    if let Some(id) = signature_value_id(&doc, s) {
                        add_sub(&doc, &sigs, &id, &mut order);
                    }
                }
            }
            order
                .iter()
                .enumerate()
                .filter(|(i, _)| idx.contains(i))
                .map(|(_, &s)| s)
                .collect()
        }
        CounterSignTarget::Signers(names) => sigs
            .iter()
            .copied()
            .filter(|&s| first_cert_cn(&doc, s).is_some_and(|cn| names.contains(&cn)))
            .collect(),
    };
    let ds = DsNames::new(&prefix);
    let target_svs: Vec<String> = targets
        .iter()
        .map(|&s| signature_value_id(&doc, s).unwrap_or_default())
        .collect();
    for sv in target_svs {
        let d = Document::parse(&text)
            .map_err(|e| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, e.to_string()))?;
        let root = d.document_element().expect("raíz");
        let mut r = ReferenceSpec::new(format!("#{sv}"), &digest_uri);
        r.id = Some(format!("Reference-{}", uuid_v4()));
        r.ty = Some(CSURI.into());
        r.transforms = vec![TransformSpec::Plain(c14n.clone())];
        let id = uuid_v4();
        let ki = ReferenceSpec::new(format!("#KeyInfo-{id}"), &digest_uri);
        let parts = SigParts {
            ds: ds.clone(),
            id: id.clone(),
            c14n: c14n.clone(),
            sig_uri: sig_uri.clone(),
            refs: vec![r, ki],
            key_info: key_info(&ds, &format!("KeyInfo-{id}"), key, only_cert),
            objects: vec![],
        };
        let mut ph = Placeholders::new();
        let in_scope = !prefix.is_empty()
            && d.lookup_namespace(root, Some(&prefix)).as_deref() == Some(DSIG_NS);
        let full = splice::insert_last_child(&d, root, &parts.render(&mut ph, in_scope));
        text = complete(full, &ph, &parts, key, sig_alg)?;
    }
    let d = Document::parse(&text)
        .map_err(|e| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, e.to_string()))?;
    splice::finish_preserving(&d, &text, &enc)
        .map_err(|m| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, m))
}

/// `XmlDSigUtil.guessXmlDSigNamespacePrefix`.
fn guess_prefix(text: &str) -> &'static str {
    let count = |p: &str| text.matches(p).count();
    let (e, ds, dsig, d11) = (
        count("<Signature"),
        count("<ds:Signature"),
        count("<dsig:Signature"),
        count("<dsig11:Signature"),
    );
    if ds >= e && ds >= dsig && ds >= d11 {
        "ds"
    } else if e >= ds && e >= dsig && e >= d11 {
        ""
    } else if dsig >= e && dsig >= ds && dsig >= d11 {
        "dsig"
    } else {
        "dsig11"
    }
}

fn signers_structure_impl(sign: &[u8]) -> afirma_core::Result<SignersTree> {
    let doc0 = parse_sign(sign)?;
    let root0 = doc0.document_element().expect("raíz");
    let prefix = guess_prefix(doc0.node_source(root0));
    let complete_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}:")
    };
    let sig_qname = format!("{complete_prefix}Signature");
    let text = if doc0.element(root0).is_some_and(|e| e.qname() == sig_qname) {
        format!("<AFIRMA>{}</AFIRMA>", doc0.node_source(root0))
    } else {
        doc0.source().to_string()
    };
    let doc =
        Document::parse(&text).map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
    let root = doc.document_element().expect("raíz");
    let sigs: Vec<NodeId> = doc
        .descendants(root)
        .into_iter()
        .skip(1)
        .filter(|&n| doc.element(n).is_some_and(|e| e.qname() == sig_qname))
        .collect();
    let mut ids = Vec::new();
    let mut refs = Vec::new();
    let mut infos = Vec::new();
    for &s in &sigs {
        ids.push(
            doc.element(s)
                .and_then(|e| e.attr("Id"))
                .unwrap_or("")
                .to_string(),
        );
        infos.push(xades::info::simple_sign_info(
            &doc,
            s,
            Some("http://uri.etsi.org/01903#"),
        ));
        let first_ref = doc
            .find_descendants(s, DSIG_NS, "Reference")
            .into_iter()
            .next();
        let is_cs =
            first_ref.and_then(|r| doc.element(r).and_then(|e| e.attr("Type"))) == Some(CSURI);
        if is_cs {
            let uri = first_ref
                .and_then(|r| doc.element(r).and_then(|e| e.attr("URI")))
                .unwrap_or("");
            let target: String = uri.chars().skip(1).collect();
            let parent_id = doc
                .descendants(root)
                .into_iter()
                .filter(|&n| {
                    doc.element(n)
                        .is_some_and(|e| e.qname() == format!("{complete_prefix}SignatureValue"))
                })
                .find(|&v| doc.element(v).and_then(|e| e.attr("Id")) == Some(target.as_str()))
                .and_then(|v| doc.parent(v))
                .and_then(|p| {
                    doc.element(p)
                        .and_then(|e| e.attr("Id"))
                        .map(str::to_string)
                })
                .unwrap_or_default();
            refs.push(parent_id);
        } else {
            refs.push(String::new());
        }
    }
    let mut arena = Arena::new(infos);
    let mut tops = Vec::new();
    for i in 0..refs.len() {
        if refs[i].is_empty() {
            xades::info::generate_signs_tree(i, ids.len() as isize - 1, &mut arena, &ids, &refs);
            tops.push(i);
        }
    }
    Ok(SignersTree {
        signers: tops.into_iter().map(|t| arena.build(t)).collect(),
    })
}

fn is_sign_impl(data: &[u8]) -> bool {
    match Document::parse_bytes(data) {
        Ok((d, _)) => !d
            .find_descendants(d.root(), DSIG_NS, "Signature")
            .is_empty(),
        Err(_) => false,
    }
}

fn is_detached_root(doc: &Document) -> bool {
    doc.document_element()
        .and_then(|r| doc.children(r).first().copied())
        .is_some_and(|c| local(doc, c) == "CONTENT")
}

fn is_enveloped_root(doc: &Document) -> bool {
    doc.find_descendants(doc.root(), DSIG_NS, "Transform")
        .into_iter()
        .any(|t| doc.element(t).and_then(|e| e.attr("Algorithm")) == Some(dsig::ENVELOPED))
}

fn get_data_impl(sign: &[u8]) -> afirma_core::Result<Option<Vec<u8>>> {
    let bad = || AfirmaError::invalid_signature_format("Error al leer el fichero de firmas");
    if !is_sign_impl(sign) {
        return Err(AfirmaError::invalid_signature_format(
            "El documento no es un documento de firmas valido.",
        ));
    }
    let doc = parse_sign(sign)?;
    let root = doc.document_element().expect("raíz");
    let xml = |n: NodeId, remove: &[NodeId]| -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}",
            xades::info::standalone_element(&doc, n, remove)
        )
        .into_bytes()
    };
    if is_detached_root(&doc) {
        let first = *doc.children(root).first().ok_or_else(bad)?;
        let fe = doc.element(first).ok_or_else(bad)?;
        if fe.attr("MimeType") == Some("text/xml") {
            let inner = *doc.children(first).first().ok_or_else(bad)?;
            doc.element(inner).ok_or_else(bad)?;
            return Ok(Some(xml(inner, &[])));
        }
        return util::b64_decode(&doc.text_content(first))
            .map(Some)
            .ok_or_else(bad);
    }
    if is_enveloped_root(&doc) {
        // Java recorre una lista "viva": solo elimina las firmas 0, 2, 4...
        let sigs = doc.find_descendants(root, DSIG_NS, "Signature");
        let mut remove = Vec::new();
        for (i, &s) in sigs.iter().enumerate() {
            if i % 2 == 0 {
                if doc.parent(s) != Some(root) {
                    return Err(bad());
                }
                remove.push(s);
            }
        }
        return Ok(Some(xml(root, &remove)));
    }
    if is_enveloping_root(&doc) {
        let object = doc
            .find_descendants(doc.root(), DSIG_NS, "Object")
            .into_iter()
            .next()
            .ok_or_else(bad)?;
        if doc.element(object).and_then(|e| e.attr("MimeType")) == Some("text/xml") {
            let first = *doc.children(object).first().ok_or_else(bad)?;
            doc.element(first).ok_or_else(bad)?;
            return Ok(Some(xml(first, &[])));
        }
        return util::b64_decode(&doc.text_content(object))
            .map(Some)
            .ok_or_else(bad);
    }
    Ok(None)
}

impl Signer for XmldsigSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_XMLDSIG
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        sign_impl(data, algorithm, key, extra)
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        cosign_impl(sign, algorithm, key, extra)
    }

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        countersign_impl(sign, algorithm, target, key, extra)
    }

    fn signers_structure(
        &self,
        sign: &[u8],
        _params: &ExtraParams,
    ) -> afirma_core::Result<SignersTree> {
        signers_structure_impl(sign)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        is_sign_impl(data)
    }

    fn is_valid_data_file(&self, _data: &[u8]) -> bool {
        true
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        format!(
            "{}{}.xsig",
            original.unwrap_or("null"),
            in_text.unwrap_or("")
        )
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        get_data_impl(sign)
    }

    fn sign_info(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        if !is_sign_impl(sign) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma",
            ));
        }
        let doc = parse_sign(sign)?;
        let variant = if is_detached_root(&doc) {
            Some(FORMAT_DETACHED)
        } else if is_enveloped_root(&doc) {
            Some(FORMAT_ENVELOPED)
        } else if is_enveloping_root(&doc) {
            Some(FORMAT_ENVELOPING)
        } else {
            None
        };
        Ok(SignInfo {
            format: FORMAT_XMLDSIG.into(),
            variant: variant.map(str::to_string),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_guess() {
        assert_eq!(guess_prefix("<ds:Signature><ds:SignatureValue/>"), "ds");
        assert_eq!(guess_prefix("<Signature><SignatureValue/>"), "");
        assert_eq!(guess_prefix("<dsig:Signature>"), "dsig");
    }

    #[test]
    fn doc_with_text_kind() {
        use crate::dom::NodeKind;
        let d = Document::parse("<a>t</a>").unwrap();
        let r = d.document_element().unwrap();
        assert!(matches!(d.kind(d.children(r)[0]), NodeKind::Text { .. }));
    }
}
