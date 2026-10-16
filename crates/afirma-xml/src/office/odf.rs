//! Firmador ODF (`AOODFSigner`): firma XMLDSig de documentos OpenDocument
//! (ODF 1.2) en `META-INF/documentsignatures.xml`.

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::{CounterSignTarget, SignInfo, Signer, SignerNode, SignersTree};

use super::{ZipBuilder, check_size, read_zip};
use crate::c14n::{C14N_10, C14n, Kind};
use crate::dn::CertNames;
use crate::dom::Document;
use crate::dsig::{self, DSIG_NS, DsNames, Placeholders, ReferenceSpec, TransformSpec};
use crate::splice;
use crate::util::{b64, esc_attr, esc_text, uuid_v4};

pub const FORMAT_ODF: &str = "ODF (Open Document Format)";
pub const SIGNATURES_PATH: &str = "META-INF/documentsignatures.xml";
pub const MANIFEST_PATH: &str = "META-INF/manifest.xml";
pub const OPENOFFICE_NS: &str = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
pub const DEFAULT_DIGEST_METHOD: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

const SUPPORTED_MIMETYPES: &[&str] = &[
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
];

/// Política de algoritmo de firma del firmador ODF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OdfAlgorithmPolicy {
    /// Como Java: siempre `rsa-sha1`, se ignora el algoritmo pedido.
    JavaParity,
    /// Se usa el algoritmo pedido (validado con LibreOffice).
    #[default]
    Requested,
}

/// Firmador ODF.
#[derive(Default)]
pub struct OdfSigner {
    pub algorithm_policy: OdfAlgorithmPolicy,
}

impl OdfSigner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Firmador con el comportamiento exacto de Java (`rsa-sha1` siempre).
    pub fn java_parity() -> Self {
        OdfSigner {
            algorithm_policy: OdfAlgorithmPolicy::JavaParity,
        }
    }
}

/// `isValidDataFile`: ZIP con `mimetype` de texto, hoja de cálculo o presentación.
pub fn is_odf(data: &[u8]) -> bool {
    if !crate::mime::is_zip(data) {
        return false;
    }
    match crate::mime::zip_entry(data, "mimetype") {
        Some(m) => SUPPORTED_MIMETYPES.contains(&String::from_utf8_lossy(&m).as_ref()),
        None => false,
    }
}

/// `isSign`: documento ODF con `META-INF/documentsignatures.xml`.
pub fn is_signed_odf(data: &[u8]) -> bool {
    is_odf(data)
        && crate::mime::zip_names(data).is_some_and(|n| n.iter().any(|x| x == SIGNATURES_PATH))
}

/// C14N inclusiva del elemento raíz de un XML (`OdfXmlUtil.canonicalizeXml`).
fn canonical_root(xml: &[u8]) -> afirma_core::Result<Vec<u8>> {
    let (doc, _) = Document::parse_bytes(xml).map_err(|e| {
        AfirmaError::new(
            codes::INTERNAL_ODF_SIGNING_ERROR,
            format!("No ha sido posible generar la firma ODF: {e}"),
        )
    })?;
    let root = doc.document_element().expect("raíz");
    Ok(C14n::new(Kind::Inclusive10, false).canonicalize(&doc, root, &[]))
}

/// `SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss,SS")` (milisegundos con al menos dos cifras).
fn odf_date() -> String {
    let now = chrono::Local::now();
    format!(
        "{},{:02}",
        now.format("%Y-%m-%dT%H:%M:%S"),
        now.timestamp_subsec_millis()
    )
}

fn sign_odf(
    data: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    p: &ExtraParams,
    policy: OdfAlgorithmPolicy,
) -> afirma_core::Result<Vec<u8>> {
    check_size(data)?;
    let digest_uri = p
        .get_or("referencesDigestMethod", DEFAULT_DIGEST_METHOD)
        .to_string();
    let oo31 = p.get_bool("useOpenOffice31Mode", false);
    if !is_odf(data) {
        return Err(AfirmaError::new(
            codes::ODF_DOCUMENT_NEEDED,
            "Los datos introducidos no se corresponden con un documento ODF",
        ));
    }
    // El nombre Java del algoritmo debe corresponder a SHA1, SHA-256 o SHA-512.
    let digest = match afirma_core::algorithms::java_digest_algorithm_name(&digest_uri).as_str() {
        "SHA1" => DigestAlgorithm::Sha1,
        "SHA-256" => DigestAlgorithm::Sha256,
        "SHA-512" => DigestAlgorithm::Sha512,
        other => {
            return Err(AfirmaError::new(
                codes::INVALID_REFERENCES_HASH_ALGORITHM_URI,
                format!(
                    "No se ha podido obtener un generador de huellas digitales con el algoritmo {other}"
                ),
            ));
        }
    };
    if dsig::digest_from_uri(&digest_uri).is_none() {
        return Err(AfirmaError::new(
            codes::INVALID_REFERENCES_HASH_ALGORITHM_URI,
            format!(
                "La URI indicada no se asocia a un algoritmo de huella soportado : {digest_uri}"
            ),
        ));
    }
    let entries = read_zip(data, codes::ODF_DOCUMENT_NEEDED)?;
    let get = |name: &str| {
        entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| e.data.clone())
    };
    let unknown = |m: String| {
        AfirmaError::new(
            codes::UNKWNON_ODF_SIGNING_ERROR,
            format!("No ha sido posible generar la firma ODF: {m}"),
        )
    };
    let manifest_data = get(MANIFEST_PATH).ok_or_else(|| unknown("no hay manifest".into()))?;
    let (manifest_doc, _) = Document::parse_bytes(&manifest_data).map_err(|e| {
        AfirmaError::new(
            codes::INTERNAL_ODF_SIGNING_ERROR,
            format!("No ha sido posible generar la firma ODF: {e}"),
        )
    })?;
    let mroot = manifest_doc.document_element().expect("raíz");
    let file_entries: Vec<_> = manifest_doc
        .descendants(mroot)
        .into_iter()
        .filter(|&n| {
            manifest_doc
                .element(n)
                .is_some_and(|e| e.qname() == "manifest:file-entry")
        })
        .collect();

    let c14n_t = vec![TransformSpec::Plain(C14N_10.into())];
    let mut refs: Vec<ReferenceSpec> = Vec::new();
    let mk = |uri: &str, transforms: Vec<TransformSpec>, value: Vec<u8>| ReferenceSpec {
        id: None,
        ty: None,
        uri: Some(uri.to_string()),
        transforms,
        digest_method: digest_uri.clone(),
        digest: Some(value),
    };
    if !oo31 {
        let mt = get("mimetype").ok_or_else(|| unknown("no hay mimetype".into()))?;
        refs.push(mk("mimetype", vec![], digest.digest(&mt)));
        refs.push(mk(
            MANIFEST_PATH,
            c14n_t.clone(),
            digest.digest(&canonical_root(&manifest_data)?),
        ));
    }
    let mut cofirm = false;
    for fe in file_entries {
        let full_path = manifest_doc
            .element(fe)
            .and_then(|e| {
                e.attrs
                    .iter()
                    .find(|a| a.qname() == "manifest:full-path")
                    .map(|a| a.value.clone())
            })
            .unwrap_or_default();
        if full_path.ends_with('/') {
            continue;
        }
        let content = get(&full_path)
            .ok_or_else(|| unknown(format!("no se encuentra la entrada {full_path}")))?;
        let uri = full_path.replace(' ', "%20");
        let r = if matches!(
            full_path.as_str(),
            "content.xml" | "meta.xml" | "styles.xml" | "settings.xml"
        ) {
            mk(
                &uri,
                c14n_t.clone(),
                digest.digest(&canonical_root(&content)?),
            )
        } else {
            mk(&uri, vec![], digest.digest(&content))
        };
        if full_path == SIGNATURES_PATH {
            cofirm = true;
        } else {
            refs.push(r);
        }
    }
    let existing = get(SIGNATURES_PATH);
    if existing.is_some() {
        cofirm = true;
    }
    let mut manifest_out = manifest_data.clone();
    let sig_container: Document = if cofirm {
        let bytes =
            existing.ok_or_else(|| unknown("no se encuentra el fichero de firmas".into()))?;
        Document::parse_bytes(&bytes).map(|(d, _)| d).map_err(|e| {
            AfirmaError::new(
                codes::INTERNAL_ODF_SIGNING_ERROR,
                format!("No ha sido posible generar la firma ODF: {e}"),
            )
        })?
    } else {
        if oo31 {
            let extra = "<manifest:file-entry manifest:full-path=\"META-INF/documentsignatures.xml\" manifest:media-type=\"\"/><manifest:file-entry manifest:full-path=\"META-INF/\" manifest:media-type=\"\"/>";
            let text = splice::insert_last_child(&manifest_doc, mroot, extra);
            let d = Document::parse(&text).map_err(|e| unknown(e.to_string()))?;
            let root = d.document_element().expect("raíz");
            manifest_out = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}",
                d.node_source(root)
            )
            .into_bytes();
        }
        Document::parse(&format!(
            "<document-signatures xmlns=\"{OPENOFFICE_NS}\"></document-signatures>"
        ))
        .expect("XML fijo")
    };
    let signature_id = uuid_v4();
    let property_id = uuid_v4();
    refs.push(ReferenceSpec::new(format!("#{property_id}"), &digest_uri));

    // Algoritmo de firma.
    let (sig_uri, sig_alg) = match policy {
        OdfAlgorithmPolicy::JavaParity => (
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_string(),
            SignatureAlgorithm::new(DigestAlgorithm::Sha1, KeyAlgorithm::Rsa),
        ),
        OdfAlgorithmPolicy::Requested => crate::xades::resolve_algorithm(
            if algorithm.trim().is_empty() {
                crate::xades::DEFAULT_SIGN_ALGO
            } else {
                algorithm
            },
            key.key_algorithm(),
        )?,
    };
    let ds = DsNames::new("");
    let cert = key.certificate();
    let subject = CertNames::from_der(cert)
        .map(|n| n.subject_rfc2253)
        .unwrap_or_default();
    let mut ph = Placeholders::new();
    let mut sig = format!(
        "<Signature xmlns=\"{DSIG_NS}\" Id=\"{}\">",
        esc_attr(&signature_id)
    );
    sig.push_str(&dsig::render_signed_info(
        &ds, C14N_10, &sig_uri, &refs, &mut ph,
    ));
    sig.push_str(&format!(
        "<SignatureValue>{}</SignatureValue>",
        ph.signature_value()
    ));
    sig.push_str(&format!(
        "<KeyInfo><X509Data><X509SubjectName>{}</X509SubjectName><X509Certificate>{}</X509Certificate></X509Data></KeyInfo>",
        esc_text(&subject),
        b64(cert)
    ));
    sig.push_str(&format!(
        "<Object><SignatureProperties><SignatureProperty Id=\"{property_id}\" Target=\"#{signature_id}\"><dc:date xmlns:dc=\"http://purl.org/dc/elements/1.1/\">{}</dc:date></SignatureProperty></SignatureProperties></Object>",
        odf_date()
    ));
    sig.push_str("</Signature>");
    let root = sig_container.document_element().expect("raíz");
    let text = splice::insert_last_child(&sig_container, root, &sig);
    let signed = dsig::complete(
        text,
        &ph,
        &dsig::Completion {
            key,
            algorithm: sig_alg,
            signature_id: &signature_id,
            resolver: &dsig::NoResolver,
            verify: false,
            error_code: codes::UNKWNON_ODF_SIGNING_ERROR,
        },
    )?;
    let final_doc = Document::parse(&signed).map_err(|e| unknown(e.to_string()))?;
    let froot = final_doc.document_element().expect("raíz");
    let signatures_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>{}",
        final_doc.node_source(froot)
    )
    .into_bytes();

    let mut zb = ZipBuilder::new(codes::UNKWNON_ODF_SIGNING_ERROR);
    for e in &entries {
        if e.name == SIGNATURES_PATH || e.name == MANIFEST_PATH {
            continue;
        }
        // Desviación: `mimetype` sin comprimir (lo exige ODF; Java lo comprime).
        zb.add(&e.name, &e.data, e.name == "mimetype", e.is_dir)?;
    }
    zb.add(SIGNATURES_PATH, &signatures_xml, false, false)?;
    zb.add(MANIFEST_PATH, &manifest_out, false, false)?;
    zb.finish()
}

fn signers_odf(sign: &[u8]) -> afirma_core::Result<SignersTree> {
    check_size(sign)?;
    if !is_signed_odf(sign) {
        return Err(AfirmaError::invalid_signature_format(
            "Los datos indicados no son una firma ODF",
        ));
    }
    let Some(xml) = crate::mime::zip_entry(sign, SIGNATURES_PATH) else {
        return Ok(SignersTree::default());
    };
    let Ok((doc, _)) = Document::parse_bytes(&xml) else {
        return Ok(SignersTree::default());
    };
    let sigs = doc.find_descendants(doc.root(), DSIG_NS, "Signature");
    let mut nodes: Vec<(String, String, SignerNode)> = Vec::new(); // (id, parent id, nodo)
    for s in sigs {
        let id = doc
            .element(s)
            .and_then(|e| e.attr("Id"))
            .unwrap_or("")
            .to_string();
        let first_ref = doc
            .find_descendants(s, DSIG_NS, "Reference")
            .into_iter()
            .next();
        let parent = match first_ref.and_then(|r| doc.element(r)) {
            Some(r)
                if r.attr("Type") == Some("http://uri.etsi.org/01903#CountersignedSignature") =>
            {
                let uri = r.attr("URI").unwrap_or("");
                uri.get(1..uri.len().saturating_sub(5))
                    .unwrap_or("")
                    .to_string()
            }
            _ => String::new(),
        };
        nodes.push((
            id,
            parent,
            SignerNode {
                info: crate::xades::info::simple_sign_info(&doc, s, None),
                countersigners: vec![],
            },
        ));
    }
    // Anidamiento de contrafirmas heredadas (en la práctica no se producen).
    fn attach(nodes: &[(String, String, SignerNode)]) -> Vec<SignerNode> {
        let mut roots = Vec::new();
        let ids: Vec<String> = nodes.iter().map(|n| n.0.clone()).collect();
        let mut children: Vec<Vec<usize>> = vec![vec![]; nodes.len()];
        let mut is_root = vec![true; nodes.len()];
        for (i, n) in nodes.iter().enumerate() {
            if !n.1.is_empty() {
                if let Some(pi) = ids.iter().position(|x| *x == n.1) {
                    children[pi].push(i);
                    is_root[i] = false;
                }
            }
        }
        fn build(
            i: usize,
            nodes: &[(String, String, SignerNode)],
            children: &[Vec<usize>],
        ) -> SignerNode {
            let mut n = nodes[i].2.clone();
            n.countersigners = children[i]
                .iter()
                .map(|&c| build(c, nodes, children))
                .collect();
            n
        }
        for (i, root) in is_root.iter().enumerate() {
            if *root {
                roots.push(build(i, nodes, &children));
            }
        }
        roots
    }
    Ok(SignersTree {
        signers: attach(&nodes),
    })
}

impl Signer for OdfSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_ODF
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        sign_odf(data, algorithm, key, extra, self.algorithm_policy)
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        sign_odf(sign, algorithm, key, extra, self.algorithm_policy)
    }

    fn countersign(
        &self,
        _sign: &[u8],
        _algorithm: &str,
        _target: &CounterSignTarget,
        _key: &dyn SigningKey,
        _extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        Err(AfirmaError::unsupported(
            "No es posible realizar contrafirmas de ficheros ODF",
        ))
    }

    fn signers_structure(
        &self,
        sign: &[u8],
        _params: &ExtraParams,
    ) -> afirma_core::Result<SignersTree> {
        signers_odf(sign)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        is_signed_odf(data)
    }

    fn is_valid_data_file(&self, data: &[u8]) -> bool {
        is_odf(data)
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        let in_text = in_text.unwrap_or("");
        let Some(name) = original else {
            return format!("{in_text}.odf");
        };
        if name.chars().count() <= 4 {
            return format!("{name}{in_text}.odf");
        }
        let lower = name.to_lowercase();
        for ext in [".odt", ".odp", ".ods"] {
            if lower.ends_with(ext) {
                return format!("{}{in_text}{ext}", &name[..name.len() - 4]);
            }
        }
        format!("{name}{in_text}.odf")
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        if !is_signed_odf(sign) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un documento ODF firmado",
            ));
        }
        Ok(Some(sign.to_vec()))
    }

    fn sign_info(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        if !is_signed_odf(sign) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un objeto de firma",
            ));
        }
        Ok(SignInfo {
            format: FORMAT_ODF.into(),
            ..Default::default()
        })
    }
}

/// Resolutor de las URI relativas de un paquete ODF (para validar).
pub fn package_resolver(package: &[u8]) -> impl Fn(&str) -> Option<dsig::External> + '_ {
    move |uri: &str| {
        let name = uri.replace("%20", " ");
        crate::mime::zip_entry(package, &name).map(dsig::External::Octets)
    }
}

/// Valida criptográficamente las firmas de un documento ODF (sin
/// equivalente en Java, que no valida ODF): devuelve, por cada
/// `ds:Signature` de `META-INF/documentsignatures.xml`, si el valor de firma
/// y todas sus referencias son correctos.
pub fn verify_package(package: &[u8]) -> afirma_core::Result<Vec<bool>> {
    let bad =
        |e: String| AfirmaError::invalid_signature_format(format!("Firma ODF no valida: {e}"));
    let xml = crate::mime::zip_entry(package, SIGNATURES_PATH).ok_or_else(|| {
        AfirmaError::invalid_signature_format("El documento ODF no contiene firmas")
    })?;
    let (doc, _) = Document::parse_bytes(&xml).map_err(|e| bad(e.to_string()))?;
    let resolver = package_resolver(package);
    let mut out = Vec::new();
    for sig in doc.find_descendants(doc.root(), DSIG_NS, "Signature") {
        let ok = dsig::validate_core(&doc, sig, &resolver, None).is_ok_and(|c| c.is_valid());
        out.push(ok);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_names() {
        let s = OdfSigner::new();
        assert_eq!(s.signed_name(Some("a.ODT"), Some("_f")), "a_f.odt");
        assert_eq!(s.signed_name(Some("abc"), None), "abc.odf");
        assert_eq!(s.signed_name(None, Some("x")), "x.odf");
        assert_eq!(s.signed_name(Some("doc.txt"), None), "doc.txt.odf");
    }
}
