//! CMS/CAdES mínimo necesario para PAdES: atributos firmados, `SignedData`
//! desacoplado, sello de tiempo de firma y lectura/verificación de las
//! firmas existentes.
//!
//! Se usa la capa ASN.1 de `afirma-cms` (`asn1::{der, Tlv}`). Las funciones
//! de alto nivel de CAdES de `afirma-cms` no exponían aún una API para PAdES
//! (atributos sin `signingTime` y huella del rango de bytes) cuando se
//! escribió este módulo, por lo que se implementan aquí con el mismo
//! resultado que `CAdESTriPhaseSigner` de AutoFirma.

use afirma_cms::asn1::{Oid, Tag, Tlv, der, tags};
use afirma_core::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};

pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
pub const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
pub const OID_SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";
pub const OID_SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
pub const OID_OTHER_SIG_CERT: &str = "1.2.840.113549.1.9.16.2.19";
pub const OID_SIG_POLICY_ID: &str = "1.2.840.113549.1.9.16.2.15";
pub const OID_COMMITMENT_TYPE: &str = "1.2.840.113549.1.9.16.2.16";
pub const OID_SIGNER_ATTR: &str = "1.2.840.113549.1.9.16.2.18";
pub const OID_SIGNER_ATTR_V2: &str = "0.4.0.19122.1.1";
pub const OID_MIME_TYPE: &str = "0.4.0.1733.2.1";
pub const OID_SIGNATURE_TIMESTAMP: &str = "1.2.840.113549.1.9.16.2.14";
pub const OID_SPQ_URI: &str = "1.2.840.113549.1.9.16.5.1";
pub const OID_ROLE: &str = "2.5.4.72";
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Error de CMS.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CmsError {
    #[error("estructura CMS no válida: {0}")]
    Invalid(String),
    #[error("certificado no válido: {0}")]
    Certificate(String),
    #[error("algoritmo no soportado: {0}")]
    Algorithm(String),
}

impl From<afirma_cms::asn1::Asn1Error> for CmsError {
    fn from(e: afirma_cms::asn1::Asn1Error) -> Self {
        CmsError::Invalid(e.to_string())
    }
}

/// Política de firma (`AdESPolicy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigPolicy {
    /// OID de la política (sin el prefijo `urn:oid:`).
    pub identifier: String,
    /// Huella de la política (vacía → se codifica `0x00`).
    pub hash: Vec<u8>,
    /// OID del algoritmo de huella.
    pub hash_algorithm_oid: String,
    pub qualifier: Option<String>,
}

/// Indicación de compromiso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentType {
    pub oid: String,
    pub qualifiers: Option<Vec<String>>,
}

/// Configuración de los atributos firmados de PAdES.
#[derive(Debug, Clone)]
pub struct SignedAttrsConfig {
    /// Algoritmo de huella de la firma.
    pub digest: DigestAlgorithm,
    /// Usar `signingCertificateV2` (si no, `signingCertificate`).
    pub signing_certificate_v2: bool,
    /// Copiar las políticas del certificado en el atributo de certificado.
    pub include_cert_policies: bool,
    pub policy: Option<SigPolicy>,
    pub commitment_types: Vec<CommitmentType>,
    pub claimed_roles: Vec<String>,
    /// Perfil `baseline` (roles en `signer-attributes-v2`).
    pub baseline: bool,
    pub mime_type: Option<String>,
}

fn attribute(oid: &str, values: &[Vec<u8>]) -> Vec<u8> {
    der::sequence([der::oid_str(oid), der::set_of(values)])
}

fn alg_id_null(oid: &str) -> Vec<u8> {
    der::sequence([der::oid_str(oid), der::null()])
}

/// Campos de un certificado necesarios para CMS.
pub struct CertParts {
    /// Número de serie (complemento a dos).
    pub serial: Vec<u8>,
    /// Emisor y titular (`Name` DER).
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    /// `SubjectPublicKeyInfo` DER.
    pub spki: Vec<u8>,
    /// Valor de la extensión de políticas (SEQUENCE OF PolicyInformation).
    pub policies: Option<Vec<u8>>,
    pub ski: Option<Vec<u8>>,
}

/// Lee los campos de un certificado necesarios para CMS.
pub fn cert_parts(raw: &[u8]) -> Result<CertParts, CmsError> {
    use x509_parser::prelude::*;
    let (_, cert) =
        X509Certificate::from_der(raw).map_err(|e| CmsError::Certificate(e.to_string()))?;
    let policies = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "2.5.29.32")
        .map(|e| e.value.to_vec());
    let ski = cert
        .extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
            _ => None,
        });
    Ok(CertParts {
        serial: cert.tbs_certificate.raw_serial().to_vec(),
        issuer: cert.issuer().as_raw().to_vec(),
        subject: cert.subject().as_raw().to_vec(),
        spki: cert.public_key().raw.to_vec(),
        policies,
        ski,
    })
}

fn issuer_serial_ess(c: &CertParts) -> Vec<u8> {
    let general_name = der::explicit(4, &c.issuer);
    der::sequence([der::sequence([general_name]), der::integer_raw(&c.serial)])
}

/// Atributos firmados (`SET OF Attribute` en DER, con la etiqueta `0x31`):
/// lo que se firma con la clave.
pub fn signed_attributes(
    message_digest: &[u8],
    cert: &[u8],
    cfg: &SignedAttrsConfig,
) -> Result<Vec<u8>, CmsError> {
    let c = cert_parts(cert)?;
    let mut attrs = vec![
        attribute(OID_CONTENT_TYPE, &[der::oid_str(OID_DATA)]),
        attribute(OID_MESSAGE_DIGEST, &[der::octet_string(message_digest)]),
    ];
    let cert_hash = cfg.digest.digest(cert);
    let policies = if cfg.include_cert_policies {
        c.policies.clone()
    } else {
        None
    };
    if cfg.signing_certificate_v2 {
        let mut ess = Vec::new();
        if cfg.digest != DigestAlgorithm::Sha256 {
            ess.push(alg_id_null(cfg.digest.oid()));
        }
        ess.push(der::octet_string(&cert_hash));
        ess.push(issuer_serial_ess(&c));
        let mut sc = vec![der::sequence([der::sequence(ess)])];
        if let Some(p) = &policies {
            sc.push(p.clone());
        }
        attrs.push(attribute(OID_SIGNING_CERTIFICATE_V2, &[der::sequence(sc)]));
    } else {
        let ess = der::sequence([der::octet_string(&cert_hash), issuer_serial_ess(&c)]);
        let mut sc = vec![der::sequence([ess])];
        if let Some(p) = &policies {
            sc.push(p.clone());
        }
        attrs.push(attribute(OID_SIGNING_CERTIFICATE, &[der::sequence(sc)]));
    }
    if let Some(p) = &cfg.policy {
        let hash = if p.hash.is_empty() {
            vec![0u8]
        } else {
            p.hash.clone()
        };
        let mut v = vec![
            der::oid_str(&p.identifier),
            der::sequence([alg_id_null(&p.hash_algorithm_oid), der::octet_string(&hash)]),
        ];
        if let Some(q) = &p.qualifier {
            v.push(der::sequence([der::sequence([
                der::oid_str(OID_SPQ_URI),
                der::ia5_string(q),
            ])]));
        }
        attrs.push(attribute(OID_SIG_POLICY_ID, &[der::sequence(v)]));
    }
    for ct in &cfg.commitment_types {
        let mut v = vec![der::oid_str(&ct.oid)];
        if let Some(q) = ct.qualifiers.as_ref().filter(|q| !q.is_empty()) {
            v.push(der::sequence(q.iter().map(|o| der::oid_str(o))));
        }
        attrs.push(attribute(OID_COMMITMENT_TYPE, &[der::sequence(v)]));
    }
    let roles: Vec<Vec<u8>> = cfg
        .claimed_roles
        .iter()
        .filter(|r| !r.is_empty())
        .map(|r| attribute(OID_ROLE, &[der::utf8_string(r)]))
        .collect();
    if !roles.is_empty() {
        let oid = if cfg.baseline {
            OID_SIGNER_ATTR_V2
        } else {
            OID_SIGNER_ATTR
        };
        let v = der::sequence([der::explicit(0, &der::sequence(roles))]);
        attrs.push(attribute(oid, &[v]));
    }
    if let Some(m) = &cfg.mime_type {
        attrs.push(attribute(OID_MIME_TYPE, &[der::utf8_string(m)]));
    }
    Ok(der::set_of(attrs))
}

/// OID del `signatureAlgorithm` del `SignerInfo` (RSA → `rsaEncryption`).
fn signature_alg_oid(alg: SignatureAlgorithm) -> &'static str {
    match alg.key {
        KeyAlgorithm::Rsa => OID_RSA_ENCRYPTION,
        _ => alg.oid(),
    }
}

/// Construye el `ContentInfo` con el `SignedData` desacoplado.
pub fn signed_data(
    signed_attrs: &[u8],
    signature: &[u8],
    chain: &[Vec<u8>],
    alg: SignatureAlgorithm,
    unsigned_attrs: Option<&[u8]>,
) -> Result<Vec<u8>, CmsError> {
    let signer = chain
        .first()
        .ok_or_else(|| CmsError::Certificate("cadena vacía".into()))?;
    let c = cert_parts(signer)?;
    let sid = der::sequence([c.issuer.clone(), der::integer_raw(&c.serial)]);
    let attrs_tlv = Tlv::parse_single(signed_attrs)?;
    let mut si = vec![
        der::integer_i64(1),
        sid,
        alg_id_null(alg.digest.oid()),
        attrs_tlv.retagged_raw(Tag::context(0, true)),
        alg_id_null(signature_alg_oid(alg)),
        der::octet_string(signature),
    ];
    if let Some(u) = unsigned_attrs {
        let t = Tlv::parse_single(u)?;
        si.push(t.retagged_raw(Tag::context(1, true)));
    }
    let signer_info = der::sequence(si);
    let sd = der::sequence([
        der::integer_i64(1),
        der::set_of([alg_id_null(alg.digest.oid())]),
        der::sequence([der::oid_str(OID_DATA)]),
        der::implicit_content(0, true, &der::sorted_concat(chain.iter())),
        der::set_of([signer_info]),
    ]);
    Ok(der::sequence([
        der::oid_str(OID_SIGNED_DATA),
        der::explicit(0, &sd),
    ]))
}

// ---------------------------------------------------------------------------
// Lectura
// ---------------------------------------------------------------------------

/// Atributo leído (OID y valores codificados).
#[derive(Debug, Clone)]
pub struct ParsedAttr {
    pub oid: String,
    pub values: Vec<Vec<u8>>,
}

/// `SignerInfo` leído.
#[derive(Debug, Clone)]
pub struct ParsedSignerInfo {
    /// `IssuerAndSerialNumber` (emisor DER, serie) o `SubjectKeyIdentifier`.
    pub issuer: Option<Vec<u8>>,
    pub serial: Option<Vec<u8>>,
    pub ski: Option<Vec<u8>>,
    pub digest_oid: String,
    /// Atributos firmados re-etiquetados como `SET` (lo que se firmó).
    pub signed_attrs_der: Option<Vec<u8>>,
    pub signed_attrs: Vec<ParsedAttr>,
    pub signature_alg_oid: String,
    pub signature: Vec<u8>,
    pub unsigned_attrs: Vec<ParsedAttr>,
    /// Codificación original del `SignerInfo`.
    pub raw: Vec<u8>,
}

impl ParsedSignerInfo {
    pub fn signed_attr(&self, oid: &str) -> Option<&ParsedAttr> {
        self.signed_attrs.iter().find(|a| a.oid == oid)
    }
    pub fn unsigned_attr(&self, oid: &str) -> Option<&ParsedAttr> {
        self.unsigned_attrs.iter().find(|a| a.oid == oid)
    }
    /// Valor del atributo `messageDigest`.
    pub fn message_digest(&self) -> Option<Vec<u8>> {
        let v = self.signed_attr(OID_MESSAGE_DIGEST)?.values.first()?;
        Tlv::parse_single(v).ok()?.octet_string_content().ok()
    }
    /// Algoritmo de huella reconocido.
    pub fn digest_algorithm(&self) -> Option<DigestAlgorithm> {
        DigestAlgorithm::from_oid(&self.digest_oid)
    }
    /// Nombre del algoritmo de firma como `PdfPKCS7.getDigestAlgorithm()`
    /// (`SHA256withRSA`).
    pub fn algorithm_name(&self) -> String {
        let d = self
            .digest_algorithm()
            .map(|d| d.java_prefix().to_string())
            .unwrap_or_else(|| self.digest_oid.clone());
        let enc = match self.signature_alg_oid.as_str() {
            OID_RSA_ENCRYPTION => "RSA".to_string(),
            o => match SignatureAlgorithm::from_oid(o) {
                Some(a) => a.key.java_suffix().to_string(),
                None if o.starts_with("1.2.840.10045") => "ECDSA".into(),
                None => o.to_string(),
            },
        };
        format!("{d}with{enc}")
    }
}

/// `SignedData` leído.
#[derive(Debug, Clone)]
pub struct ParsedSignedData {
    pub certificates: Vec<Vec<u8>>,
    pub crls: usize,
    pub signer_infos: Vec<ParsedSignerInfo>,
    /// Contenido encapsulado (sellos de tiempo: `TSTInfo`).
    pub econtent_type: String,
    pub econtent: Option<Vec<u8>>,
}

fn parse_attrs(t: &Tlv<'_>) -> Result<Vec<ParsedAttr>, CmsError> {
    let mut out = Vec::new();
    for a in t.children()? {
        let parts = a.children()?;
        let oid = parts
            .first()
            .ok_or_else(|| CmsError::Invalid("atributo vacío".into()))?
            .as_oid()?
            .to_dotted();
        let values = match parts.get(1) {
            Some(set) => set.children()?.iter().map(Tlv::to_definite).collect(),
            None => Vec::new(),
        };
        out.push(ParsedAttr { oid, values });
    }
    Ok(out)
}

/// Lee un `ContentInfo` con `SignedData` (admite datos de relleno al final).
pub fn parse_signed_data(data: &[u8]) -> Result<ParsedSignedData, CmsError> {
    let (ci, _) = Tlv::parse(data)?;
    let parts = ci.children()?;
    let ct = parts
        .first()
        .ok_or_else(|| CmsError::Invalid("ContentInfo vacío".into()))?
        .as_oid()?;
    if ct.to_dotted() != OID_SIGNED_DATA {
        return Err(CmsError::Invalid("no es SignedData".into()));
    }
    let content = parts
        .get(1)
        .ok_or_else(|| CmsError::Invalid("sin contenido".into()))?
        .children()?;
    let sd = content
        .first()
        .ok_or_else(|| CmsError::Invalid("sin SignedData".into()))?
        .children()?;
    let mut idx = 1; // versión
    idx += 1; // digestAlgorithms
    let encap = sd
        .get(idx)
        .ok_or_else(|| CmsError::Invalid("sin encapContentInfo".into()))?
        .children()?;
    idx += 1;
    let econtent_type = encap
        .first()
        .map(|t| t.as_oid().map(|o| o.to_dotted()))
        .transpose()?
        .unwrap_or_default();
    let econtent = match encap.get(1) {
        Some(t) => {
            let inner = t.children()?;
            match inner.first() {
                Some(os) => Some(os.octet_string_content()?),
                None => None,
            }
        }
        None => None,
    };
    let mut certificates = Vec::new();
    let mut crls = 0;
    while let Some(t) = sd.get(idx) {
        if t.tag == Tag::context(0, true) {
            for c in t.children()? {
                if c.tag == tags::SEQUENCE {
                    certificates.push(c.to_definite());
                }
            }
            idx += 1;
        } else if t.tag == Tag::context(1, true) {
            crls = t.children()?.len();
            idx += 1;
        } else {
            break;
        }
    }
    let mut signer_infos = Vec::new();
    if let Some(sis) = sd.get(idx) {
        for si in sis.children()? {
            let f = si.children()?;
            let mut i = 1;
            let sid = f
                .get(i)
                .ok_or_else(|| CmsError::Invalid("sin sid".into()))?;
            i += 1;
            let (issuer, serial, ski) = if sid.tag == tags::SEQUENCE {
                let p = sid.children()?;
                (
                    p.first().map(|t| t.to_definite()),
                    p.get(1)
                        .map(|t| t.as_integer_bytes().map(<[u8]>::to_vec))
                        .transpose()?,
                    None,
                )
            } else {
                (None, None, Some(sid.value.to_vec()))
            };
            let digest_oid = f
                .get(i)
                .ok_or_else(|| CmsError::Invalid("sin digestAlgorithm".into()))?
                .children()?[0]
                .as_oid()?
                .to_dotted();
            i += 1;
            let mut signed_attrs_der = None;
            let mut signed_attrs = Vec::new();
            if let Some(t) = f.get(i).filter(|t| t.tag == Tag::context(0, true)) {
                signed_attrs_der = Some(der::tlv(tags::SET, t.value));
                signed_attrs = parse_attrs(t)?;
                i += 1;
            }
            let signature_alg_oid = f
                .get(i)
                .ok_or_else(|| CmsError::Invalid("sin signatureAlgorithm".into()))?
                .children()?[0]
                .as_oid()?
                .to_dotted();
            i += 1;
            let signature = f
                .get(i)
                .ok_or_else(|| CmsError::Invalid("sin firma".into()))?
                .octet_string_content()?;
            i += 1;
            let unsigned_attrs = match f.get(i).filter(|t| t.tag == Tag::context(1, true)) {
                Some(t) => parse_attrs(t)?,
                None => Vec::new(),
            };
            signer_infos.push(ParsedSignerInfo {
                issuer,
                serial,
                ski,
                digest_oid,
                signed_attrs_der,
                signed_attrs,
                signature_alg_oid,
                signature,
                unsigned_attrs,
                raw: si.to_definite(),
            });
        }
    }
    Ok(ParsedSignedData {
        certificates,
        crls,
        signer_infos,
        econtent_type,
        econtent,
    })
}

impl ParsedSignedData {
    /// Certificado del firmante de un `SignerInfo`.
    pub fn signer_cert(&self, si: &ParsedSignerInfo) -> Option<&Vec<u8>> {
        self.certificates.iter().find(|c| {
            let Ok(p) = cert_parts(c) else { return false };
            match (&si.issuer, &si.serial, &si.ski) {
                (Some(i), Some(s), _) => {
                    strip_int(&p.serial) == strip_int(s) && names_equal(&p.issuer, i)
                }
                (_, _, Some(k)) => p.ski.as_ref() == Some(k),
                _ => false,
            }
        })
    }

    /// Cadena de certificados ordenada a partir del firmante.
    pub fn chain_for(&self, si: &ParsedSignerInfo) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some(first) = self.signer_cert(si) else {
            return out;
        };
        out.push(first.clone());
        for _ in 0..10 {
            let Some(last) = out.last() else { break };
            let Ok(lp) = cert_parts(last) else { break };
            if lp.issuer == lp.subject {
                break;
            }
            let issuer = lp.issuer.clone();
            match self
                .certificates
                .iter()
                .find(|c| cert_parts(c).is_ok_and(|p| p.subject == issuer) && !out.contains(c))
            {
                Some(c) => out.push(c.clone()),
                None => break,
            }
        }
        out
    }
}

fn strip_int(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[first..]
}

fn names_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
        || match (
            x509_parser::x509::X509Name::from_der(a),
            x509_parser::x509::X509Name::from_der(b),
        ) {
            (Ok((_, x)), Ok((_, y))) => x.to_string() == y.to_string(),
            _ => false,
        }
}

use x509_parser::prelude::FromDer;

// ---------------------------------------------------------------------------
// Verificación criptográfica
// ---------------------------------------------------------------------------

/// Verifica una firma (PKCS#1 v1.5 o ECDSA DER) sobre `data` con la clave
/// pública del certificado.
pub fn verify_signature(
    cert: &[u8],
    digest: DigestAlgorithm,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CmsError> {
    verify_prehashed(cert, digest, &digest.digest(data), signature)
}

/// Verifica una firma sobre una huella ya calculada (con la verificación
/// RSA/ECDSA de `afirma-cms`).
pub fn verify_prehashed(
    cert: &[u8],
    digest: DigestAlgorithm,
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, CmsError> {
    let view = afirma_cms::cert::CertView::parse(cert)
        .map_err(|e| CmsError::Certificate(e.to_string()))?;
    let key = view
        .key_algorithm()
        .ok_or_else(|| CmsError::Algorithm("tipo de clave pública no soportado".into()))?;
    afirma_cms::verify::verify_prehashed_with_certificate(
        cert,
        SignatureAlgorithm::new(digest, key),
        hash,
        signature,
    )
    .map_err(|e| CmsError::Algorithm(e.0))
}

/// Resultado de verificar un `SignerInfo` (como `PdfPKCS7.verify()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerCheck {
    /// La huella de los datos coincide con `messageDigest`.
    pub digest_ok: bool,
    /// La firma es correcta.
    pub signature_ok: bool,
}

/// Verifica un `SignerInfo` contra la huella de los datos firmados.
pub fn verify_signer(
    sd: &ParsedSignedData,
    si: &ParsedSignerInfo,
    data_digest: &[u8],
) -> Result<SignerCheck, CmsError> {
    let digest = si
        .digest_algorithm()
        .ok_or_else(|| CmsError::Algorithm(si.digest_oid.clone()))?;
    let cert = sd.signer_cert(si).ok_or_else(|| {
        CmsError::Certificate("no se encuentra el certificado del firmante".into())
    })?;
    match &si.signed_attrs_der {
        Some(attrs) => {
            let md = si.message_digest().unwrap_or_default();
            let digest_ok = md == data_digest;
            let mut signature_ok = verify_signature(cert, digest, attrs, &si.signature)?;
            if !signature_ok {
                // Como Bouncy Castle: se prueba también con los atributos en
                // orden DER (firmas de terceros con el SET sin ordenar).
                if let Ok(t) = Tlv::parse_single(attrs) {
                    if let Ok(children) = t.children() {
                        let sorted = der::set_of(children.iter().map(|c| c.raw.to_vec()));
                        if sorted != *attrs {
                            signature_ok = verify_signature(cert, digest, &sorted, &si.signature)?;
                        }
                    }
                }
            }
            Ok(SignerCheck {
                digest_ok,
                signature_ok,
            })
        }
        None => {
            // Sin atributos firmados la firma es directamente sobre la huella
            // de los datos.
            let signature_ok = verify_prehashed(cert, digest, data_digest, &si.signature)?;
            Ok(SignerCheck {
                digest_ok: true,
                signature_ok,
            })
        }
    }
}

/// Añade (sustituyendo los existentes) el atributo no firmado
/// `signatureTimeStampToken` al primer `SignerInfo` de un `SignedData`.
pub fn add_signature_timestamp(cms: &[u8], token: &[u8]) -> Result<Vec<u8>, CmsError> {
    let (ci, _) = Tlv::parse(cms)?;
    let parts = ci.children()?;
    let content = parts
        .get(1)
        .ok_or_else(|| CmsError::Invalid("sin contenido".into()))?
        .children()?;
    let sd_tlv = content
        .first()
        .ok_or_else(|| CmsError::Invalid("sin SignedData".into()))?;
    let fields = sd_tlv.children()?;
    let mut new_fields: Vec<Vec<u8>> = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        if i == fields.len() - 1 {
            // signerInfos
            let mut sis = Vec::new();
            for (k, si) in f.children()?.iter().enumerate() {
                let sif = si.children()?;
                let mut out: Vec<Vec<u8>> = sif
                    .iter()
                    .filter(|t| t.tag != Tag::context(1, true))
                    .map(|t| t.to_definite())
                    .collect();
                if k == 0 {
                    let attr = attribute(OID_SIGNATURE_TIMESTAMP, &[token.to_vec()]);
                    out.push(der::implicit_content(1, true, &attr));
                }
                sis.push(der::sequence(out));
            }
            new_fields.push(der::set_of(sis));
        } else {
            new_fields.push(f.to_definite());
        }
    }
    let sd = der::sequence(new_fields);
    Ok(der::sequence([
        der::oid_str(OID_SIGNED_DATA),
        der::explicit(0, &sd),
    ]))
}

/// Fecha (`genTime`) de un sello de tiempo (`TimeStampToken`).
pub fn timestamp_gen_time(token: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let sd = parse_signed_data(token).ok()?;
    if sd.econtent_type != OID_TST_INFO {
        return None;
    }
    let tst = Tlv::parse_single(sd.econtent.as_deref()?).ok()?;
    let f = tst.children().ok()?;
    // version, policy, messageImprint, serialNumber, genTime
    f.get(4)?.as_time().ok()
}

/// `messageImprint` de un sello de tiempo: (OID del algoritmo, huella).
pub fn timestamp_imprint(token: &[u8]) -> Option<(String, Vec<u8>)> {
    let sd = parse_signed_data(token).ok()?;
    let tst = Tlv::parse_single(sd.econtent.as_deref()?).ok()?;
    let f = tst.children().ok()?;
    let mi = f.get(2)?.children().ok()?;
    let alg = mi
        .first()?
        .children()
        .ok()?
        .first()?
        .as_oid()
        .ok()?
        .to_dotted();
    let h = mi.get(1)?.octet_string_content().ok()?;
    Some((alg, h))
}

/// Oid de texto a `Oid`.
pub fn oid(s: &str) -> Oid {
    Oid::new(s)
}
