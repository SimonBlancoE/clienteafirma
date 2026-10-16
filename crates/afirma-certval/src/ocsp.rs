//! OCSP (RFC 6960): petición sin firmar y sin nonce con un único `CertID`
//! SHA-1 (la misma que genera BouncyCastle en `OcspHelper.createOcspRequest`)
//! y análisis y verificación de la respuesta.

use afirma_cms::asn1::{Tag, Tlv, der, tags};
use afirma_cms::cert::minimal_twos_complement;
use afirma_core::algorithms::DigestAlgorithm;
use chrono::{DateTime, Duration, Utc};

use crate::result::{RevocationInfo, RevocationReason, ValidationResult};
use crate::x509::{Cert, names_match};

/// `id-pkix-ocsp-basic`.
const OID_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

/// Identificador del certificado consultado (`CertID`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertId {
    pub hash: DigestAlgorithm,
    pub name_hash: Vec<u8>,
    pub key_hash: Vec<u8>,
    /// Número de serie (complemento a dos mínimo).
    pub serial: Vec<u8>,
}

impl CertId {
    /// `CertID` de un certificado con el nombre (DER) y la clave pública
    /// (contenido del BIT STRING) de su emisor.
    pub fn new(hash: DigestAlgorithm, serial: &[u8], issuer_name: &[u8], issuer_key: &[u8]) -> Self {
        CertId {
            hash,
            name_hash: hash.digest(issuer_name),
            key_hash: hash.digest(issuer_key),
            serial: minimal_twos_complement(serial).to_vec(),
        }
    }

    /// Codificación DER (`AlgorithmIdentifier` con parámetros NULL, como
    /// BouncyCastle y OpenSSL).
    pub fn to_der(&self) -> Vec<u8> {
        der::sequence([
            der::sequence([der::oid_str(self.hash.oid()), der::null()]),
            der::octet_string(&self.name_hash),
            der::octet_string(&self.key_hash),
            der::integer_raw(&self.serial),
        ])
    }

    fn parse(t: &Tlv<'_>) -> Result<CertId, String> {
        let f = t.children().map_err(|e| e.to_string())?;
        if f.len() != 4 {
            return Err("CertID mal formado".into());
        }
        let alg = f[0].children().map_err(|e| e.to_string())?;
        let oid = alg
            .first()
            .ok_or("CertID sin algoritmo")?
            .as_oid()
            .map_err(|e| e.to_string())?;
        let hash = DigestAlgorithm::from_oid(&oid.to_dotted())
            .ok_or_else(|| format!("Huella de CertID no soportada: {}", oid.to_dotted()))?;
        Ok(CertId {
            hash,
            name_hash: f[1].octet_string_content().map_err(|e| e.to_string())?,
            key_hash: f[2].octet_string_content().map_err(|e| e.to_string())?,
            serial: minimal_twos_complement(f[3].as_integer_bytes().map_err(|e| e.to_string())?).to_vec(),
        })
    }
}

/// `OCSPRequest` sin firma, sin `requestorName` y sin extensiones (sin
/// nonce), con una única petición.
pub(crate) fn build_request(cert_id: &CertId) -> Vec<u8> {
    der::sequence([der::sequence([der::sequence([der::sequence([cert_id.to_der()])])])])
}

/// Identificador del firmante de la respuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResponderId {
    ByName(Vec<u8>),
    /// SHA-1 de la clave pública (contenido del BIT STRING).
    ByKey(Vec<u8>),
}

/// Estado de un certificado en una respuesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CertStatus {
    Good,
    Revoked(RevocationInfo),
    Unknown,
}

/// `SingleResponse`.
#[derive(Debug, Clone)]
pub(crate) struct SingleResponse {
    pub cert_id: CertId,
    pub status: CertStatus,
    pub this_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
}

/// `BasicOCSPResponse`.
#[derive(Debug, Clone)]
pub(crate) struct BasicResponse {
    pub tbs: Vec<u8>,
    pub sig_alg: Vec<u8>,
    pub signature: Vec<u8>,
    pub certs: Vec<Vec<u8>>,
    pub responder: ResponderId,
    pub responses: Vec<SingleResponse>,
}

/// `OCSPResponse`.
#[derive(Debug, Clone)]
pub(crate) struct OcspResponse {
    pub status: i64,
    pub basic: Option<BasicResponse>,
}

fn e<E: std::fmt::Display>(err: E) -> String {
    format!("Respuesta OCSP mal formada: {err}")
}

fn parse_single(t: &Tlv<'_>) -> Result<SingleResponse, String> {
    let f = t.children().map_err(e)?;
    let cert_id = CertId::parse(f.first().ok_or("SingleResponse vacia")?)?;
    let st = f.get(1).ok_or("SingleResponse sin estado")?;
    let status = match (st.tag.class, st.tag.number) {
        (afirma_cms::asn1::Class::Context, 0) => CertStatus::Good,
        (afirma_cms::asn1::Class::Context, 1) => {
            let info = st.children().map_err(e)?;
            let time = info.first().and_then(|t| t.as_time().ok());
            let reason = info
                .iter()
                .find(|x| x.tag == Tag::context(0, true))
                .and_then(|x| x.children().ok()?.first()?.as_i64().ok())
                .and_then(|r| u8::try_from(r).ok())
                .map(RevocationReason);
            CertStatus::Revoked(RevocationInfo { time, reason })
        }
        (afirma_cms::asn1::Class::Context, 2) => CertStatus::Unknown,
        _ => return Err(format!("Estado de certificado OCSP desconocido: {}", st.tag)),
    };
    let this_update = f.get(2).ok_or("SingleResponse sin thisUpdate")?.as_time().map_err(e)?;
    let next_update = f
        .iter()
        .skip(3)
        .find(|x| x.tag == Tag::context(0, true))
        .map(|x| {
            x.children()
                .map_err(e)?
                .first()
                .ok_or_else(|| e("nextUpdate vacio"))?
                .as_time()
                .map_err(e)
        })
        .transpose()?;
    Ok(SingleResponse {
        cert_id,
        status,
        this_update,
        next_update,
    })
}

fn parse_basic(der_bytes: &[u8]) -> Result<BasicResponse, String> {
    let basic = Tlv::parse_single(der_bytes).and_then(|t| t.children()).map_err(e)?;
    let [tbs, sig_alg, sig, rest @ ..] = basic.as_slice() else {
        return Err(e("BasicOCSPResponse incompleta"));
    };
    let mut certs = Vec::new();
    if let Some(c) = rest.iter().find(|t| t.tag == Tag::context(0, true)) {
        for seq in c.children().map_err(e)? {
            for cert in seq.children().map_err(e)? {
                certs.push(cert.raw.to_vec());
            }
        }
    }
    let mut fields = tbs.children().map_err(e)?.into_iter().peekable();
    if fields.peek().is_some_and(|t| t.tag == Tag::context(0, true)) {
        fields.next();
    }
    let rid = fields.next().ok_or_else(|| e("sin responderID"))?;
    let inner = *rid
        .children()
        .map_err(e)?
        .first()
        .ok_or_else(|| e("responderID vacio"))?;
    let responder = match rid.tag {
        t if t == Tag::context(1, true) => ResponderId::ByName(inner.raw.to_vec()),
        t if t == Tag::context(2, true) => ResponderId::ByKey(inner.octet_string_content().map_err(e)?),
        t => return Err(format!("responderID desconocido: {t}")),
    };
    let _produced_at = fields.next().ok_or_else(|| e("sin producedAt"))?;
    let list = fields
        .next()
        .ok_or_else(|| e("sin respuestas"))?
        .expect(tags::SEQUENCE)
        .map_err(e)?;
    let responses = list
        .children()
        .map_err(e)?
        .iter()
        .map(parse_single)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BasicResponse {
        tbs: tbs.raw.to_vec(),
        sig_alg: sig_alg.raw.to_vec(),
        signature: sig.bit_string_content().map_err(e)?.to_vec(),
        certs,
        responder,
        responses,
    })
}

/// Analiza un `OCSPResponse` DER.
pub(crate) fn parse_response(data: &[u8]) -> Result<OcspResponse, String> {
    let top = Tlv::parse_single(data).and_then(|t| t.children()).map_err(e)?;
    let st = top.first().ok_or_else(|| e("vacia"))?;
    if st.tag != tags::ENUMERATED {
        return Err(e(format!("estado con etiqueta {}", st.tag)));
    }
    let status = st.as_i64().map_err(e)?;
    let mut basic = None;
    if let Some(rb) = top.get(1).filter(|t| t.tag == Tag::context(0, true)) {
        let rb = rb.children().map_err(e)?;
        let parts = rb
            .first()
            .ok_or_else(|| e("responseBytes vacio"))?
            .children()
            .map_err(e)?;
        let kind = parts
            .first()
            .ok_or_else(|| e("sin responseType"))?
            .as_oid()
            .map_err(e)?;
        if !kind.is(OID_OCSP_BASIC) {
            return Err(format!("Tipo de respuesta OCSP no soportado: {}", kind.to_dotted()));
        }
        let octets = parts
            .get(1)
            .ok_or_else(|| e("sin response"))?
            .octet_string_content()
            .map_err(e)?;
        basic = Some(parse_basic(&octets)?);
    }
    Ok(OcspResponse { status, basic })
}

/// Resultado para un `responseStatus` distinto de `successful`
/// (`OcspHelper.analyzeOcspResponse`).
pub(crate) fn status_result(status: i64) -> ValidationResult {
    match status {
        0 => ValidationResult::Valid,
        1 => ValidationResult::MalformedRequest,
        2 | 3 => ValidationResult::ServerError,
        5 => ValidationResult::SigRequired,
        6 => ValidationResult::Unauthorized,
        // Java lanza una excepción, que acaba en SERVER_ERROR.
        _ => ValidationResult::ServerError,
    }
}

/// Nombre del `responseStatus`.
pub(crate) fn status_name(status: i64) -> &'static str {
    match status {
        0 => "successful",
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "desconocido",
    }
}

/// Análisis de Java, sin ninguna comprobación de seguridad: estado de la
/// respuesta y, si es `successful`, estado de la **primera** respuesta
/// individual (sin verificar firma, `CertID` ni fechas).
pub(crate) fn java_analyze(data: &[u8]) -> Result<ValidationResult, String> {
    let resp = parse_response(data)?;
    if resp.status != 0 {
        return Ok(status_result(resp.status));
    }
    let basic = resp.basic.ok_or_else(|| e("sin responseBytes"))?;
    let first = basic
        .responses
        .first()
        .ok_or_else(|| e("sin respuestas individuales"))?;
    Ok(single_result(&first.status).0)
}

fn single_result(status: &CertStatus) -> (ValidationResult, Option<RevocationInfo>) {
    match status {
        CertStatus::Good => (ValidationResult::Valid, None),
        CertStatus::Revoked(info) => (ValidationResult::Revoked, Some(info.clone())),
        CertStatus::Unknown => (ValidationResult::Unknown, None),
    }
}

/// Parámetros de la verificación de una respuesta.
pub(crate) struct Check<'a> {
    /// Identificador pedido.
    pub cert_id: &'a CertId,
    /// Emisor del certificado (`None`: modo sin verificación, como Java).
    pub issuer: Option<&'a Cert>,
    /// Certificados adicionales en los que buscar un respondedor delegado
    /// que la respuesta no incluya.
    pub extra_certs: &'a [Cert],
    pub now: DateTime<Utc>,
    pub skew: Duration,
    /// Antigüedad máxima de una respuesta sin `nextUpdate`.
    pub max_age_without_next_update: Duration,
}

/// Resultado de evaluar una respuesta.
#[derive(Debug, Clone)]
pub(crate) struct Outcome {
    pub result: ValidationResult,
    pub revocation: Option<RevocationInfo>,
    pub detail: Option<String>,
}

impl Outcome {
    fn error(result: ValidationResult, detail: impl Into<String>) -> Self {
        Outcome {
            result,
            revocation: None,
            detail: Some(detail.into()),
        }
    }
}

fn sha1(data: &[u8]) -> Vec<u8> {
    DigestAlgorithm::Sha1.digest(data)
}

fn responder_matches(rid: &ResponderId, cert: &Cert) -> bool {
    match rid {
        ResponderId::ByName(n) => names_match(n, &cert.subject),
        ResponderId::ByKey(h) => cert.public_key_bits().is_some_and(|k| sha1(&k) == *h),
    }
}

/// Comprueba que la respuesta está firmada por el emisor del certificado o
/// por un respondedor delegado (emitido por ese emisor, con
/// `id-kp-OCSPSigning` y en vigor), RFC 6960 §4.2.2.2.
fn verify_signer(basic: &BasicResponse, check: &Check<'_>, issuer: &Cert) -> Result<(), String> {
    if responder_matches(&basic.responder, issuer) {
        return crate::sig::verify(&basic.sig_alg, &issuer.spki, &basic.tbs, &basic.signature)
            .map_err(|err| format!("La firma de la respuesta OCSP no es valida: {err}"));
    }
    let included: Vec<Cert> = basic.certs.iter().filter_map(|d| Cert::parse(d).ok()).collect();
    let mut last = None;
    for c in included.iter().chain(check.extra_certs.iter()) {
        if !responder_matches(&basic.responder, c) {
            continue;
        }
        if !c.is_issued_by(issuer) {
            last = Some("El certificado del respondedor OCSP no lo ha emitido la CA del certificado".to_string());
            continue;
        }
        if !c.ocsp_signing {
            last =
                Some("El certificado del respondedor OCSP no esta autorizado (sin uso id-kp-OCSPSigning)".to_string());
            continue;
        }
        if !c.is_valid_at(check.now, check.skew) {
            last = Some("El certificado del respondedor OCSP no esta en su periodo de validez".to_string());
            continue;
        }
        match crate::sig::verify(&basic.sig_alg, &c.spki, &basic.tbs, &basic.signature) {
            Ok(()) => return Ok(()),
            Err(err) => last = Some(format!("La firma de la respuesta OCSP no es valida: {err}")),
        }
    }
    Err(last.unwrap_or_else(|| {
        "La respuesta OCSP no esta firmada por el emisor del certificado ni por un respondedor autorizado".to_string()
    }))
}

/// `CertID` equivalentes (recalculando con la huella de la respuesta si el
/// respondedor no usó SHA-1).
fn same_cert(resp: &CertId, check: &Check<'_>, issuer: &Cert) -> bool {
    if resp.hash == check.cert_id.hash {
        return resp == check.cert_id;
    }
    let Some(key) = issuer.public_key_bits() else {
        return false;
    };
    *resp == CertId::new(resp.hash, &check.cert_id.serial, &issuer.subject, &key)
}

/// Evalúa una respuesta OCSP.
pub(crate) fn evaluate(data: &[u8], check: &Check<'_>) -> Outcome {
    let resp = match parse_response(data) {
        Ok(r) => r,
        Err(err) => return Outcome::error(ValidationResult::ServerError, err),
    };
    if resp.status != 0 {
        return Outcome::error(
            status_result(resp.status),
            format!(
                "El servicio OCSP respondio con el estado {} ({})",
                resp.status,
                status_name(resp.status)
            ),
        );
    }
    let Some(basic) = resp.basic else {
        return Outcome::error(ValidationResult::ServerError, "Respuesta OCSP sin contenido");
    };
    let Some(issuer) = check.issuer else {
        // Comportamiento de Java: primera respuesta, sin comprobaciones.
        return match basic.responses.first() {
            Some(s) => {
                let (result, revocation) = single_result(&s.status);
                Outcome {
                    result,
                    revocation,
                    detail: Some("Respuesta OCSP aceptada sin verificar: no se conoce el emisor".into()),
                }
            }
            None => Outcome::error(
                ValidationResult::ServerError,
                "Respuesta OCSP sin respuestas individuales",
            ),
        };
    };
    if let Err(detail) = verify_signer(&basic, check, issuer) {
        return Outcome::error(ValidationResult::ServerError, detail);
    }
    let Some(single) = basic.responses.iter().find(|s| same_cert(&s.cert_id, check, issuer)) else {
        return Outcome::error(
            ValidationResult::ServerError,
            "La respuesta OCSP no corresponde al certificado consultado",
        );
    };
    if single.this_update > check.now + check.skew {
        return Outcome::error(
            ValidationResult::ServerError,
            format!(
                "La respuesta OCSP tiene fecha futura (thisUpdate {})",
                single.this_update
            ),
        );
    }
    let expires = single
        .next_update
        .unwrap_or(single.this_update + check.max_age_without_next_update);
    if expires + check.skew < check.now {
        return Outcome::error(
            ValidationResult::ServerError,
            format!("La respuesta OCSP esta caducada (valida hasta {expires})"),
        );
    }
    let (result, revocation) = single_result(&single.status);
    Outcome {
        result,
        revocation,
        detail: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(status_result(1), ValidationResult::MalformedRequest);
        assert_eq!(status_result(2), ValidationResult::ServerError);
        assert_eq!(status_result(3), ValidationResult::ServerError);
        assert_eq!(status_result(4), ValidationResult::ServerError);
        assert_eq!(status_result(5), ValidationResult::SigRequired);
        assert_eq!(status_result(6), ValidationResult::Unauthorized);
        // OCSPResponse { responseStatus = unauthorized }.
        assert_eq!(
            java_analyze(&[0x30, 0x03, 0x0a, 0x01, 0x06]).unwrap(),
            ValidationResult::Unauthorized
        );
        assert!(java_analyze(&[0x30, 0x03, 0x0a, 0x01, 0x00]).is_err());
        assert!(java_analyze(b"basura").is_err());
    }

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/certval")
            .join(name);
        let data = std::fs::read(p).unwrap();
        crate::certs::parse_certificates(&data)
            .into_iter()
            .next()
            .unwrap_or(data)
    }

    #[test]
    fn dates() {
        let good = Cert::parse(&fixture("good.crt")).unwrap();
        let ca = Cert::parse(&fixture("ca.crt")).unwrap();
        let id = CertId::new(
            DigestAlgorithm::Sha1,
            &good.serial,
            &ca.subject,
            &ca.public_key_bits().unwrap(),
        );
        // Firmada por la propia CA (sin certificado de respondedor que caduque).
        let resp = fixture("resp_good_by_ca.der");
        let this_update = parse_response(&resp).unwrap().basic.unwrap().responses[0].this_update;
        let check = |now: DateTime<Utc>| {
            evaluate(
                &resp,
                &Check {
                    cert_id: &id,
                    issuer: Some(&ca),
                    extra_certs: &[],
                    now,
                    skew: Duration::minutes(5),
                    max_age_without_next_update: Duration::days(1),
                },
            )
        };
        assert_eq!(check(this_update).result, ValidationResult::Valid);
        assert_eq!(
            check(this_update - Duration::minutes(4)).result,
            ValidationResult::Valid
        );
        let r = check(this_update - Duration::minutes(6));
        assert_eq!(r.result, ValidationResult::ServerError);
        assert!(r.detail.unwrap().contains("futura"));
        assert_eq!(
            check(this_update + Duration::days(3649)).result,
            ValidationResult::Valid
        );
        assert_eq!(
            check(this_update + Duration::days(3651)).result,
            ValidationResult::ServerError
        );
    }
}
