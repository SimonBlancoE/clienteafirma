//! Firma XAdES simple (`XAdESSigner.sign`).

use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;

use super::props::{self, DataObjectFormat, KeyInfoOptions, PolicySpec, SignedProps};
use super::*;
use crate::c14n::{C14N_10, C14n};
use crate::dom::{Document, NodeId};
use crate::dsig::{self, DSIG_NS, External, Placeholders, ReferenceSpec, TransformSpec};
use crate::mime;
use crate::splice;
use crate::util::{self, esc_attr, uuid_v4};
use crate::xpath::{XNode, XPath};

/// Datos XML de entrada.
pub(crate) struct XmlInput {
    pub doc: Document,
    /// Codificación declarada en el documento.
    pub declared_encoding: Option<String>,
}

/// Analiza los datos como XML según el criterio de AutoFirma (sin DOCTYPE).
pub(crate) fn load_xml(data: &[u8]) -> Option<XmlInput> {
    let (doc, _) = Document::parse_bytes(data).ok()?;
    if doc.doctype.is_some() {
        return None;
    }
    let declared_encoding = doc.xml_decl.as_ref().and_then(|d| d.encoding.clone());
    Some(XmlInput { doc, declared_encoding })
}

/// `AOUtil.createURI`: comprueba si la URI es utilizable.
pub(crate) fn create_uri_ok(s: &str) -> bool {
    if s.trim().is_empty() {
        return false;
    }
    let mut t = s.replace('\\', "/");
    for (c, r) in [
        (' ', "%20"),
        ('<', "%3C"),
        ('>', "%3E"),
        ('"', "%22"),
        ('{', "%7B"),
        ('}', "%7D"),
        ('|', "%7C"),
        ('^', "%5E"),
        ('[', "%5B"),
        (']', "%5D"),
        ('`', "%60"),
    ] {
        t = t.replace(c, r);
    }
    let scheme = t.split_once(':').map(|(sch, _)| sch).filter(|sch| {
        !sch.is_empty()
            && sch.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && sch
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    match scheme {
        None => util::is_valid_uri(&format!("file://{}", t.replace('#', "%23"))),
        Some(sch) if sch.len() == 1 => true,
        Some("http") | Some("https") | Some("file") | Some("urn") => util::is_valid_uri(&t),
        Some(_) => false,
    }
}

/// Elemento raíz contenedor (`XAdESUtil.getRootElement`): etiquetas de
/// apertura y cierre.
pub(crate) fn root_element(p: &ExtraParams) -> (String, String) {
    let name = p.get("RootXmlNodeName").unwrap_or("AFIRMA").to_string();
    let id = format!("{name}-Root-{}", uuid_v4());
    let mut open = format!("<{name}");
    if let Some(ns) = p.get("RootXmlNodeNamespace") {
        match p.get("RootXmlNodeNamespacePrefix") {
            Some(prefix) => {
                let attr = if prefix.starts_with("xmlns:") {
                    prefix.to_string()
                } else {
                    format!("xmlns:{prefix}")
                };
                open.push_str(&format!(" {attr}=\"{}\"", esc_attr(ns)));
            }
            None => {
                // Java no declara el espacio de nombres (salida no válida si el
                // nombre lleva prefijo); aquí se declara (desviación documentada).
                match name.split_once(':') {
                    Some((pfx, _)) => open.push_str(&format!(" xmlns:{pfx}=\"{}\"", esc_attr(ns))),
                    None => open.push_str(&format!(" xmlns=\"{}\"", esc_attr(ns))),
                }
            }
        }
    }
    open.push_str(&format!(" Id=\"{}\">", esc_attr(&id)));
    (open, format!("</{name}>"))
}

/// Transformadas personalizadas `xmlTransforms` (`Utils.addCustomTransforms`).
pub(crate) fn custom_transforms(p: &ExtraParams) -> afirma_core::Result<Vec<TransformSpec>> {
    let n: usize = p
        .get("xmlTransforms")
        .unwrap_or("0")
        .trim()
        .parse()
        .map_err(|_| AfirmaError::invalid_argument("El parametro 'xmlTransforms' debe ser un numero entero"))?;
    let mut out = Vec::new();
    for i in 0..n {
        let ty = p.get(&format!("xmlTransform{i}Type"));
        let body = p.get(&format!("xmlTransform{i}Body"));
        match (ty, body) {
            (Some(dsig::XPATH), Some(b)) => out.push(TransformSpec::XPath(b.to_string())),
            (Some(dsig::XPATH2), Some(b)) => match p.get(&format!("xmlTransform{i}Subtype")) {
                Some(f @ ("subtract" | "intersect" | "union")) => out.push(TransformSpec::XPath2 {
                    filter: f.to_string(),
                    expr: b.to_string(),
                }),
                other => tracing::warn!("Transformacion XPATH2 de un tipo no soportado: {other:?}"),
            },
            (Some(t @ (dsig::BASE64 | dsig::ENVELOPED)), _) => out.push(TransformSpec::Plain(t.to_string())),
            (Some(t), _) => tracing::warn!("Transformacion no soportada, se omite: {t}"),
            _ => {}
        }
    }
    Ok(out)
}

/// `createDataObjectFormat`.
pub(crate) fn data_object_format(
    reference_id: &str,
    mime_type: Option<&str>,
    oid: Option<&str>,
    encoding: Option<&str>,
) -> DataObjectFormat {
    let mut data_oid = oid.map(str::to_string);
    if data_oid.is_none()
        && let Some(m) = mime_type
    {
        let o = mime::mime_to_oid(m);
        if !(m != mime::DEFAULT_MIMETYPE && o == mime::DEFAULT_OID) {
            data_oid = Some(o);
        }
    }
    DataObjectFormat {
        object_reference: format!("#{reference_id}"),
        description: None,
        object_identifier: data_oid.map(|o| props::ObjectIdentifier::oid_as_urn(&o)),
        mime_type: Some(mime_type.unwrap_or(mime::DEFAULT_MIMETYPE).to_string()),
        encoding: encoding.map(str::to_string),
    }
}

/// Primer elemento resultado de `insertEnvelopedSignatureOnNodeByXPath`.
fn xpath_insertion_node(doc: &Document, expr: &str) -> afirma_core::Result<NodeId> {
    let bad = |m: String| AfirmaError::new(codes::INVALID_NODE_SELECTOR_XPATH, m);
    let xp = XPath::compile(expr, &Default::default()).map_err(|e| {
        bad(format!(
            "No se ha podido evaluar la expresion indicada para la insercion de la firma Enveloped ('{expr}'): {e}"
        ))
    })?;
    let root = doc.document_element().ok_or_else(|| bad("documento sin raíz".into()))?;
    let nodes = xp.select(doc, XNode::Node(root), None).map_err(|e| {
        bad(format!(
            "No se ha podido evaluar la expresion indicada para la insercion de la firma Enveloped ('{expr}'): {e}"
        ))
    })?;
    if nodes.len() > 1 {
        tracing::warn!("La expresion '{expr}' ha devuelto varios nodos, se usara el primero");
    }
    match nodes.first() {
        Some(XNode::Node(n)) if doc.element(*n).is_some() => Ok(*n),
        Some(_) => Err(bad(format!(
            "La expresion indicada para la insercion de la firma Enveloped ('{expr}') no ha devuelto un elemento"
        ))),
        None => Err(bad(format!(
            "La expresion indicada para la insercion de la firma Enveloped ('{expr}') no ha devuelto ningun nodo"
        ))),
    }
}

/// Lee un fichero `file://` para una referencia Externally Detached sin datos.
fn read_file_uri(uri: &str) -> afirma_core::Result<Vec<u8>> {
    let path = &uri[7..];
    let decoded = percent_decode(path);
    std::fs::read(&decoded).map_err(|e| {
        AfirmaError::new(
            codes::LOADING_LOCAL_FILE_ERROR,
            format!("Error al leer el documento local al que referencia la firma: {uri}: {e}"),
        )
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Comprueba la URI de algoritmo de huella de las referencias.
pub(crate) fn check_digest_uri(uri: &str) -> afirma_core::Result<()> {
    if dsig::digest_from_uri(uri).is_none() {
        return Err(AfirmaError::new(
            codes::INVALID_REFERENCES_HASH_ALGORITHM_URI,
            format!("No se ha podido obtener un generador de huellas digitales para el algoritmo {uri}"),
        ));
    }
    Ok(())
}

/// Comprueba la URI de canonicalización.
pub(crate) fn check_c14n_uri(uri: &str) -> afirma_core::Result<()> {
    if C14n::from_uri(uri).is_none() {
        return Err(AfirmaError::new(
            codes::INVALID_CANONICALIZATION_URI,
            format!("No se ha podido crear el canonizador para el algoritmo indicado {uri}"),
        ));
    }
    Ok(())
}

/// Lee y valida el parámetro `encoding`.
pub(crate) fn encoding_param(p: &ExtraParams) -> afirma_core::Result<Option<String>> {
    let mut encoding = p.get("encoding").map(str::to_string);
    if encoding.as_deref().is_some_and(|e| e.eq_ignore_ascii_case("base64")) {
        encoding = Some(dsig::BASE64.to_string());
    }
    if let Some(e) = &encoding
        && !e.is_empty()
        && !util::is_valid_uri(e)
    {
        return Err(AfirmaError::new(
            codes::INVALID_ENCODING_URI,
            format!("La codificacion indicada en 'encoding' debe ser una URI: {e}"),
        ));
    }
    Ok(encoding)
}

/// Lista de certificados a incluir en `KeyInfo`.
pub(crate) fn key_info_certs(key: &dyn SigningKey, only_signing: bool) -> Vec<Vec<u8>> {
    let chain = key.certificate_chain();
    let chain = if chain.is_empty() {
        vec![key.certificate().to_vec()]
    } else {
        chain
    };
    if only_signing { vec![chain[0].clone()] } else { chain }
}

enum Layout {
    /// Documento nuevo: `before` + firma + `after`.
    New { before: String, after: String },
    /// Documento original con la firma como último hijo de `parent`.
    Splice { parent: NodeId },
}

/// Firma XAdES.
pub fn sign(
    data: Option<&[u8]>,
    algorithm: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    resolver: &dyn dsig::Resolver,
) -> afirma_core::Result<Vec<u8>> {
    let algorithm = if algorithm.trim().is_empty() {
        DEFAULT_SIGN_ALGO
    } else {
        algorithm
    };
    if algorithm.to_uppercase().starts_with("MD") {
        return Err(AfirmaError::invalid_argument(
            "XAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)",
        ));
    }
    let mut p = extra.clone();
    p.remove("validatePkcs1");
    let baseline = p.get("profile").is_some_and(|v| v.eq_ignore_ascii_case("baseline"));
    if baseline && p.get("xadesNamespace").is_some_and(|ns| !is_baseline_compatible(ns)) {
        tracing::warn!("El espacio de nombres indicado no es compatible con el perfil baseline, se ignorara");
        p.remove("xadesNamespace");
        p.remove("signedPropertiesTypeUrl");
    }
    let (sig_uri, sig_alg) = resolve_algorithm(algorithm, key.key_algorithm())?;

    let avoid_xpath = p.get_bool("avoidXpathExtraTransformsOnEnveloped", false);
    let only_cert = p.get_bool("includeOnlySignningCertificate", false);
    let use_manifest = p.get_bool("useManifest", false);
    let enveloped_xpath = p.get("insertEnvelopedSignatureOnNodeByXPath").map(str::to_string);
    let mut node_to_sign = p.get("nodeToSign").map(str::to_string);
    let avoid_enveloped = node_to_sign.is_some() && p.get_bool("avoidEnvelopedTransformWhenSigningNode", false);
    let format_raw = p.get_or("format", FORMAT_ENVELOPING).to_string();
    let digest_uri = p.get_or("referencesDigestMethod", DEFAULT_DIGEST_METHOD).to_string();
    let ext_hash_alg = p.get("precalculatedHashAlgorithm").unwrap_or(&digest_uri).to_string();
    let c14n_param = p.get_or("canonicalizationAlgorithm", C14N_10).to_string();
    let c14n: Option<String> = if c14n_param.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(c14n_param)
    };
    let xades_ns = p.get_or("xadesNamespace", NS_XADES_132).to_string();
    let sp_type = p.get_or("signedPropertiesTypeUrl", SIGNED_PROPERTIES_TYPE).to_string();
    let avoid_b64 = p.get_bool("avoidBase64Transforms", false);
    let add_key_value = p.get_bool("addKeyInfoKeyValue", true);
    let add_key_name = p.get_bool("addKeyInfoKeyName", false);
    let add_issuer_serial = p.get_bool("addKeyInfoX509IssuerSerial", false);
    let facturae = p.get_bool("facturaeSign", false);
    let output_enc = p.get("outputXmlEncoding").map(str::to_string);
    let mut mime_type = p.get("mimeType").map(str::to_string);
    let oid = p.get("contentTypeOid").map(str::to_string);
    let mut encoding = encoding_param(&p)?;
    let keep_ki_unsigned = baseline || p.get_bool("keepKeyInfoUnsigned", false);
    if p.contains("mode") {
        tracing::warn!("El parametro 'mode' esta obsoleto en XAdES y se ignora");
    }

    let mut format = canonical_format(&format_raw);
    if use_manifest {
        format = Some(FORMAT_EXTERNALLY_DETACHED);
    }
    let uri_param = p.get("uri").filter(|u| create_uri_ok(u)).map(str::to_string);
    let format = match format {
        Some(f) => f,
        None => {
            return Err(AfirmaError::unsupported(format!(
                "El formato de firma '{format_raw}' no esta soportado"
            )));
        }
    };
    if format == FORMAT_EXTERNALLY_DETACHED && uri_param.is_none() && !use_manifest {
        return Err(AfirmaError::unsupported(
            "Las firmas XML Externally Detached necesitan la URI para referenciar a los datos firmados",
        ));
    }
    if data.is_none_or(<[u8]>::is_empty) && format != FORMAT_EXTERNALLY_DETACHED {
        return Err(AfirmaError::new(
            codes::DATA_NOT_FOUND,
            "No se han proporcionado los datos a firmar",
        ));
    }
    check_digest_uri(&digest_uri)?;
    if let Some(c) = &c14n {
        check_c14n_uri(c)?;
    }

    let content_id = format!("CONTENT-{}", uuid_v4());
    let reference_id = format!("Reference-{}", uuid_v4());
    let sig_prefix = format!("Signature-{}", uuid_v4());
    let ds = DsNames::new(DS_PREFIX);

    let xml = data.and_then(load_xml);
    let mut output_encoding = "UTF-8".to_string();
    let mut is_base64 = false;
    let mut was_encoded = false;
    // Elemento de datos como texto (CONTENT u Object), si procede.
    let mut data_text: Option<String> = None;
    let mut layout: Option<Layout> = None;

    if let Some(x) = &xml {
        let doc = &x.doc;
        let root = doc.document_element().expect("raíz");
        if mime_type.is_none() || mime_type.as_deref() == Some(mime::DEFAULT_MIMETYPE) {
            mime_type = Some("text/xml".into());
        }
        output_encoding = output_enc
            .clone()
            .or_else(|| x.declared_encoding.clone())
            .unwrap_or_else(|| "UTF-8".into());
        if format == FORMAT_DETACHED {
            match &node_to_sign {
                Some(n) => {
                    let el = dsig::find_by_id_ci(doc, n).ok_or_else(|| {
                        AfirmaError::new(
                            codes::UNKWNON_XML_SIGNING_ERROR,
                            format!("No se ha encontrado el nodo a firmar: {n}"),
                        )
                    })?;
                    if el != root {
                        let parent = doc.parent(el).filter(|&pp| doc.element(pp).is_some()).unwrap_or(root);
                        layout = Some(Layout::Splice { parent });
                    } else {
                        data_text = Some(doc.node_source(root).to_string());
                    }
                }
                None => {
                    let mut t = String::from("<CONTENT");
                    if let Some(e) = encoding.as_deref().filter(|e| !e.is_empty()) {
                        t.push_str(&format!(" Encoding=\"{}\"", esc_attr(e)));
                    }
                    t.push_str(&format!(
                        " Id=\"{content_id}\" MimeType=\"{}\">",
                        esc_attr(mime_type.as_deref().unwrap_or(""))
                    ));
                    t.push_str(doc.node_source(root));
                    t.push_str("</CONTENT>");
                    data_text = Some(t);
                }
            }
        } else {
            data_text = Some(doc.node_source(root).to_string());
        }
    } else {
        if format == FORMAT_ENVELOPED || node_to_sign.is_some() {
            return Err(AfirmaError::new(
                codes::XML_DOCUMENT_NEEDED,
                "Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML",
            ));
        }
        if format == FORMAT_DETACHED || format == FORMAT_ENVELOPING {
            let d = data.unwrap_or_default();
            let text;
            if util::is_base64(d) && encoding.as_deref() == Some(dsig::BASE64) {
                let decoded = util::b64_decode(&String::from_utf8_lossy(d)).unwrap_or_default();
                if mime_type.is_none() {
                    mime_type = Some(mime::detect(&decoded));
                }
                text = util::b64(&decoded);
            } else {
                if mime_type.is_none() {
                    mime_type = Some(mime::detect(d));
                }
                text = util::b64(d);
                was_encoded = true;
            }
            is_base64 = true;
            encoding = Some(dsig::BASE64.to_string());
            data_text = Some(text);
        }
    }

    // Transformadas y referencia de datos.
    let mut transforms = custom_transforms(&p)?;
    if is_base64 && was_encoded && !avoid_b64 {
        transforms.push(TransformSpec::Plain(dsig::BASE64.into()));
    }
    let mut data_refs: Vec<ReferenceSpec> = Vec::new();
    let mut objects_before: Vec<String> = Vec::new();
    let mut manifest_dofs: Option<Vec<DataObjectFormat>> = None;
    let mime_or_default = mime_type.clone().unwrap_or_else(|| mime::DEFAULT_MIMETYPE.to_string());

    if format == FORMAT_ENVELOPING {
        if !is_base64 && let Some(c) = &c14n {
            transforms.push(TransformSpec::Plain(c.clone()));
        }
        let object_id = format!("Object-{}", uuid_v4());
        let mut obj = format!("<{}", ds.q("Object"));
        if let Some(e) = &encoding {
            obj.push_str(&format!(" Encoding=\"{}\"", esc_attr(e)));
        }
        obj.push_str(&format!(
            " Id=\"{object_id}\" MimeType=\"{}\">",
            esc_attr(&mime_or_default)
        ));
        obj.push_str(data_text.as_deref().unwrap_or(""));
        obj.push_str(&format!("</{}>", ds.q("Object")));
        objects_before.push(obj);
        let mut r = ReferenceSpec::new(format!("#{}", node_to_sign.clone().unwrap_or(object_id)), &digest_uri);
        r.id = Some(reference_id.clone());
        r.ty = if node_to_sign.is_some() {
            None
        } else {
            Some(dsig::OBJECT_TYPE.into())
        };
        r.transforms = transforms.clone();
        data_refs.push(r);
    } else if format == FORMAT_DETACHED {
        if !is_base64 && let Some(c) = &c14n {
            transforms.push(TransformSpec::Plain(c.clone()));
        }
        let mut r = ReferenceSpec::new(
            format!("#{}", node_to_sign.clone().unwrap_or(content_id.clone())),
            &digest_uri,
        );
        r.id = Some(reference_id.clone());
        r.transforms = transforms.clone();
        data_refs.push(r);
        if is_base64 {
            // CONTENT para datos binarios.
            let mut t = String::from("<CONTENT");
            t.push_str(&format!(" Encoding=\"{}\"", esc_attr(dsig::BASE64)));
            t.push_str(&format!(
                " Id=\"{content_id}\" MimeType=\"{}\">",
                esc_attr(&mime_or_default)
            ));
            t.push_str(data_text.as_deref().unwrap_or(""));
            t.push_str("</CONTENT>");
            data_text = Some(t);
        }
    } else if format == FORMAT_EXTERNALLY_DETACHED {
        let dm = props::digest_method_by_common_name(&ext_hash_alg).ok_or_else(|| {
            AfirmaError::new(
                codes::INVALID_PRECALCULATED_DATA_HASH_ALGORITHM,
                format!("No se ha podido crear el metodo de huella digital para la referencia a datos externos: {ext_hash_alg}"),
            )
        })?;
        if use_manifest {
            let refs = manifest_references(data, &reference_id, &p)?;
            let manifest_id = format!("Manifest-{}", uuid_v4());
            let mut ph_dummy = Placeholders::new();
            let mut m = format!(
                "<{} Id=\"ManifestObject-{}\">",
                ds.q("Object"),
                util::uuid_v3_from_bytes(reference_id.as_bytes())
            );
            m.push_str(&format!("<{} Id=\"{manifest_id}\">", ds.q("Manifest")));
            let mut dofs = Vec::new();
            for r in &refs {
                let mut spec = ReferenceSpec::new(r.uri.clone(), dm);
                spec.id = Some(r.id.clone());
                spec.digest = Some(r.digest.clone());
                m.push_str(&dsig::render_reference(&ds, &spec, &mut ph_dummy));
                dofs.push(data_object_format(
                    &r.id,
                    r.mime.as_deref(),
                    r.oid.as_deref(),
                    r.encoding.as_deref(),
                ));
            }
            m.push_str(&format!("</{}></{}>", ds.q("Manifest"), ds.q("Object")));
            objects_before.push(m);
            let mut r = ReferenceSpec::new(format!("#{manifest_id}"), &digest_uri);
            r.id = Some(format!("Manifest{reference_id}"));
            r.ty = Some(dsig::MANIFEST_TYPE.into());
            r.transforms = c14n.iter().map(|c| TransformSpec::Plain(c.clone())).collect();
            data_refs.push(r);
            manifest_dofs = Some(dofs);
        } else {
            let uri = p.get("uri").unwrap_or_default().to_string();
            let mut r = ReferenceSpec::new(uri.clone(), dm);
            r.id = Some(reference_id.clone());
            match data {
                Some(d) => r.digest = Some(d.to_vec()),
                None => {
                    let alg = dsig::digest_from_uri(&digest_uri).expect("comprobado");
                    r.digest_method = digest_uri.clone();
                    if uri.len() >= 7 && uri[..7].eq_ignore_ascii_case("file://") {
                        r.digest = Some(alg.digest(&read_file_uri(&uri)?));
                    } else if uri.to_ascii_lowercase().starts_with("http://")
                        || uri.to_ascii_lowercase().starts_with("https://")
                    {
                        match resolver.resolve(&uri) {
                            Some(External::Octets(b)) | Some(External::Xml(b)) => r.digest = Some(alg.digest(&b)),
                            None => {
                                return Err(AfirmaError::new(
                                    codes::DERREFERENCING_DATA_ERROR,
                                    format!("Error en la recuperacion de un recurso externo: {uri}"),
                                ));
                            }
                        }
                    }
                }
            }
            data_refs.push(r);
        }
    } else {
        // Enveloped
        let x = xml.as_ref().expect("los datos son XML");
        let doc = &x.doc;
        let root = doc.document_element().expect("raíz");
        if !avoid_enveloped {
            transforms.push(TransformSpec::Plain(dsig::ENVELOPED.into()));
        }
        if !facturae && let Some(c) = &c14n {
            transforms.push(TransformSpec::Plain(c.clone()));
        }
        if node_to_sign.is_none()
            && let Some(id) = doc.element(root).and_then(|e| e.attr("Id")).filter(|s| !s.is_empty())
        {
            node_to_sign = Some(id.to_string());
        }
        if !facturae && !avoid_xpath {
            transforms.push(TransformSpec::XPath(format!(
                "not(ancestor-or-self::{DS_PREFIX}:Signature)"
            )));
        }
        let mut r = ReferenceSpec::new(
            node_to_sign.as_ref().map(|n| format!("#{n}")).unwrap_or_default(),
            &digest_uri,
        );
        r.id = Some(reference_id.clone());
        r.transforms = transforms.clone();
        data_refs.push(r);
        let parent = match &enveloped_xpath {
            Some(xp) => xpath_insertion_node(doc, xp)?,
            None => match &node_to_sign {
                Some(n) => dsig::find_by_id_ci(doc, n).unwrap_or(root),
                None => root,
            },
        };
        layout = Some(Layout::Splice { parent });
    }

    // Contenedor por defecto.
    let layout = match layout {
        Some(l) => l,
        None => {
            let (open, close) = root_element(&p);
            match format {
                f if f == FORMAT_DETACHED => Layout::New {
                    before: format!("{open}{}", data_text.clone().unwrap_or_default()),
                    after: close,
                },
                f if f == FORMAT_ENVELOPING => {
                    // Se desenvuelve si solo hay una firma (la nueva).
                    let existing = xml
                        .as_ref()
                        .map(|x| x.doc.find_descendants(x.doc.root(), DSIG_NS, "Signature").len())
                        .unwrap_or(0);
                    if existing == 0 {
                        Layout::New {
                            before: String::new(),
                            after: String::new(),
                        }
                    } else {
                        Layout::New {
                            before: open,
                            after: close,
                        }
                    }
                }
                _ => Layout::New {
                    before: open,
                    after: close,
                },
            }
        }
    };

    // Propiedades firmadas.
    let cert = key.certificate().to_vec();
    let dofs = match manifest_dofs {
        Some(d) => d,
        None => vec![data_object_format(
            &reference_id,
            mime_type.as_deref(),
            oid.as_deref(),
            encoding.as_deref(),
        )],
    };
    let policy = props::policy_from_params(&p)?;
    let signed_props = SignedProps {
        baseline,
        signing_time: util::xades_time(&util::now()),
        cert_der: cert.clone(),
        cert_digest_uri: digest_uri.clone(),
        policy: policy.map(PolicySpec::Explicit).unwrap_or(PolicySpec::None),
        place: props::place_from_params(&p),
        roles: props::roles_from_params(&p),
        data_object_formats: dofs,
        commitments: props::commitments_from_params(&p, Some(&reference_id)),
    };
    let key_info = props::render_key_info(
        &ds,
        &format!("{sig_prefix}-KeyInfo"),
        &KeyInfoOptions {
            certs: key_info_certs(key, only_cert),
            key_value: add_key_value,
            key_name: add_key_name,
            issuer_serial: add_issuer_serial,
        },
    );

    let ds_in_scope = match &layout {
        Layout::Splice { parent } => xml
            .as_ref()
            .is_some_and(|x| x.doc.lookup_namespace(*parent, Some(DS_PREFIX)).as_deref() == Some(DSIG_NS)),
        Layout::New { .. } => false,
    };
    let assembly = Assembly {
        ds: ds.clone(),
        xades_prefix: XADES_PREFIX.into(),
        xades_ns,
        sig_prefix: sig_prefix.clone(),
        c14n_uri: c14n.clone().unwrap_or_else(|| C14N_10.to_string()),
        sig_method_uri: sig_uri,
        digest_uri: digest_uri.clone(),
        signed_props_type: sp_type,
        data_refs,
        objects_before,
        props: signed_props,
        key_info,
        keyinfo_reference: !keep_ki_unsigned,
        ds_in_scope,
        xades_in_scope: false,
    };
    let mut ph = Placeholders::new();
    let sig_text = assembly.render(&mut ph);
    let full = match &layout {
        Layout::New { before, after } => format!("{before}{sig_text}{after}"),
        Layout::Splice { parent } => splice::insert_last_child(&xml.as_ref().expect("XML").doc, *parent, &sig_text),
    };
    let completion = dsig::Completion {
        key,
        algorithm: sig_alg,
        signature_id: &assembly.signature_id(),
        resolver,
        verify: true,
        error_code: codes::UNKWNON_XML_SIGNING_ERROR,
    };
    let signed = dsig::complete(full, &ph, &completion)?;
    let bytes = match &layout {
        Layout::Splice { .. } => splice::finish_preserving(&xml.as_ref().expect("XML").doc, &signed, &output_encoding),
        Layout::New { .. } => splice::finish(&signed, &output_encoding),
    };
    bytes.map_err(|m| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, m))
}

/// Referencia de un Manifest.
struct ManifestRef {
    uri: String,
    digest: Vec<u8>,
    id: String,
    mime: Option<String>,
    oid: Option<String>,
    encoding: Option<String>,
}

/// `XAdESSigner.loadManifestReferencesData`.
fn manifest_references(
    data: Option<&[u8]>,
    reference_id: &str,
    p: &ExtraParams,
) -> afirma_core::Result<Vec<ManifestRef>> {
    if let Some(uri) = p.get("uri") {
        let Some(d) = data else {
            return Err(AfirmaError::new(
                codes::REFERENCE_HASH_NOT_FOUND,
                "No se ha proporcionado en el parametro de datos la huella correspondiente a los datos referenciados por la URI",
            ));
        };
        return Ok(vec![ManifestRef {
            uri: uri.to_string(),
            digest: d.to_vec(),
            id: reference_id.to_string(),
            mime: p.get("mimeType").map(str::to_string),
            oid: p.get("contentTypeOid").map(str::to_string),
            encoding: p.get("encoding").map(str::to_string),
        }]);
    }
    let mut out = Vec::new();
    let mut i = 1;
    while let Some(uri) = p.get(&format!("uri{i}")) {
        let md = p.get(&format!("md{i}")).ok_or_else(|| {
            AfirmaError::new(
                codes::REFERENCE_HASH_NOT_FOUND,
                format!("No se ha indicado la huella de la referencia {i} del manifest"),
            )
        })?;
        let digest = util::b64_decode(md).ok_or_else(|| {
            AfirmaError::new(
                codes::INVALID_REFERENCE_HASH,
                format!("Se ha indicado un base 64 no valido como huella de la referencia {i} del manifest"),
            )
        })?;
        out.push(ManifestRef {
            uri: uri.to_string(),
            digest,
            id: format!("Reference-{}", uuid_v4()),
            mime: p.get(&format!("mimeType{i}")).map(str::to_string),
            oid: p.get(&format!("contentTypeOid{i}")).map(str::to_string),
            encoding: p.get(&format!("encoding{i}")).map(str::to_string),
        });
        i += 1;
    }
    if out.is_empty() {
        return Err(AfirmaError::new(
            codes::MANIFEST_REFERENCES_NOT_FOUND,
            "No se han proporcionado las referencias y huellas de los datos a firmar",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris() {
        assert!(create_uri_ok("dataobject.txt"));
        assert!(create_uri_ok("https://example.org/doc.bin"));
        assert!(create_uri_ok("urn:id:1"));
        assert!(!create_uri_ok("ftp://x/y"));
        assert!(create_uri_ok("C:\\datos\\a.pdf"));
    }

    #[test]
    fn dof_oid_rules() {
        let oid = |d: &DataObjectFormat| d.object_identifier.as_ref().map(|o| o.identifier.clone());
        let d = data_object_format("R", Some("text/plain"), None, None);
        assert!(oid(&d).is_none());
        let d = data_object_format("R", Some("application/octet-stream"), None, None);
        assert_eq!(oid(&d).as_deref(), Some("urn:oid:1.2.840.113549.1.7.1"));
        let d = data_object_format("R", Some("text/xml"), None, None);
        assert_eq!(oid(&d).as_deref(), Some("urn:oid:1.2.840.10003.5.109.10"));
        let d = data_object_format("R", None, None, None);
        assert!(oid(&d).is_none());
        assert_eq!(d.mime_type.as_deref(), Some("application/octet-stream"));
    }
}
