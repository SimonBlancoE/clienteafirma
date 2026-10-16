//! Sellos de tiempo RFC 3161 (`CMSTimestamper`, `TsaParams`) y CAdES-T.
//!
//! * [`TsaParams`]: parámetros `tsa*` de los `extraParams`.
//! * [`build_request`]/[`TimeStampRequest`]: petición `TimeStampReq`.
//! * [`parse_response`]/[`validate_response`]: lectura y validación de la
//!   respuesta (estado, nonce, huella, política, atributo de certificado y
//!   firma de la TSA cuando es verificable).
//! * [`Timestamper`]: cliente completo con transporte intercambiable
//!   ([`TsaTransport`]); [`Timestamper::add_timestamp`] añade el atributo
//!   `signatureTimeStampToken` a los firmantes de un `SignedData` (CAdES-T).

/// TSA de pruebas en proceso (para las pruebas de este y otros crates).
pub mod mock;
pub mod transport;

use afirma_core::ExtraParams;
use afirma_core::algorithms::{DigestAlgorithm, SignatureAlgorithm};
use afirma_core::error::{AfirmaError, codes};
use chrono::{DateTime, Utc};

use crate::alg;
use crate::asn1::{Oid, Tlv, der, tags};
use crate::cms::{self, SignedData, SignedDataParts, SignerInfo, to_der_preserving};
use crate::oids;
use crate::verify;

pub use transport::{DefaultTransport, TsaTransport};

/// Extensión opcional de la petición (`tsaExtensionOid`...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsaRequestExtension {
    pub oid: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

/// Parámetros de conexión con la TSA (`TsaParams`).
#[derive(Clone, PartialEq, Eq)]
pub struct TsaParams {
    /// `tsaURL` (`http`, `https` o `socket`).
    pub url: String,
    /// `tsaPolicy` (por defecto `0.4.0.2023.1.1`).
    pub policy: String,
    /// `tsaHashAlgorithm` (por defecto SHA-512).
    pub hash_algorithm: DigestAlgorithm,
    /// `tsaRequireCert` (por defecto `true`).
    pub require_cert: bool,
    pub user: Option<String>,
    pub password: Option<String>,
    pub extension: Option<TsaRequestExtension>,
    /// Almacén de certificado cliente para HTTPS (`tsaSslKeyStore`, Base64).
    pub ssl_keystore: Option<Vec<u8>>,
    pub ssl_keystore_password: String,
    pub ssl_keystore_type: String,
    /// Almacén de confianza para HTTPS (`tsaSslTrustStore`, Base64).
    pub ssl_truststore: Option<Vec<u8>>,
    pub ssl_truststore_password: String,
    pub ssl_truststore_type: String,
    /// `verifyHostname` (por defecto `true`).
    pub verify_hostname: bool,
}

impl std::fmt::Debug for TsaParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsaParams")
            .field("url", &self.url)
            .field("policy", &self.policy)
            .field("hash_algorithm", &self.hash_algorithm)
            .field("require_cert", &self.require_cert)
            .field("user", &self.user)
            .field("ssl_keystore", &self.ssl_keystore.is_some())
            .field("ssl_truststore", &self.ssl_truststore.is_some())
            .field("verify_hostname", &self.verify_hostname)
            .finish_non_exhaustive()
    }
}

impl TsaParams {
    /// Parámetros por defecto para una URL.
    pub fn new(url: impl Into<String>) -> Self {
        TsaParams {
            url: url.into(),
            policy: oids::DEFAULT_TSA_POLICY.to_string(),
            hash_algorithm: DigestAlgorithm::Sha512,
            require_cert: true,
            user: None,
            password: None,
            extension: None,
            ssl_keystore: None,
            ssl_keystore_password: String::new(),
            ssl_keystore_type: "PKCS12".into(),
            ssl_truststore: None,
            ssl_truststore_password: String::new(),
            ssl_truststore_type: "PKCS12".into(),
            verify_hostname: true,
        }
    }

    /// Lee los parámetros de los `extraParams`. Devuelve `None` si no hay
    /// `tsaURL` (no se ha pedido sello).
    pub fn from_extra_params(p: &ExtraParams) -> afirma_core::Result<Option<Self>> {
        let Some(url) = p.get("tsaURL") else { return Ok(None) };
        let scheme_ok = url
            .split_once(':')
            .is_some_and(|(s, _)| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)));
        if !scheme_ok {
            return Err(AfirmaError::invalid_argument(format!("Se ha indicado una URL de TSA invalida ({url})")));
        }
        let mut t = TsaParams::new(url);
        if let Some(pol) = p.get("tsaPolicy") {
            t.policy = pol.to_string();
        }
        if let Some(h) = p.get("tsaHashAlgorithm") {
            t.hash_algorithm = alg::digest_from_java_name(h).ok_or_else(|| {
                AfirmaError::new(
                    codes::INVALID_TIMESTAMP_HASH_ALGORITHM,
                    format!("Algoritmo de huella para el sello no soportado: {h}"),
                )
            })?;
        }
        t.require_cert = !p.get("tsaRequireCert").is_some_and(|v| v.eq_ignore_ascii_case("false"));
        t.user = p.get("tsaUsr").map(str::to_string);
        t.password = p.get("tsaPwd").map(str::to_string);
        let b64 = |key: &str| -> afirma_core::Result<Option<Vec<u8>>> {
            match p.get(key) {
                Some(v) => afirma_core::base64_decode_lenient(v).map(Some).map_err(|e| {
                    AfirmaError::invalid_argument(format!(
                        "No se ha proporcionado en el parametro '{key}' un almacen en base 64: {e}"
                    ))
                }),
                None => Ok(None),
            }
        };
        t.ssl_keystore = b64("tsaSslKeyStore")?;
        t.ssl_keystore_password = p.get_or("tsaSslKeyStorePassword", "").to_string();
        t.ssl_keystore_type = p.get_or("tsaSslKeyStoreType", "PKCS12").to_string();
        t.ssl_truststore = b64("tsaSslTrustStore")?;
        t.ssl_truststore_password = p.get_or("tsaSslTrustStorePassword", "").to_string();
        t.ssl_truststore_type = p.get_or("tsaSslTrustStoreType", "PKCS12").to_string();
        if let (Some(oid), Some(value)) = (p.get("tsaExtensionOid"), p.get("tsaExtensionValueBase64")) {
            let value = afirma_core::base64_decode_lenient(value).map_err(|e| {
                AfirmaError::invalid_argument(format!(
                    "Las extensiones del sello de tiempo no estan adecuadamente codificadas: {e}"
                ))
            })?;
            t.extension = Some(TsaRequestExtension {
                oid: oid.to_string(),
                critical: p.get_bool("tsaExtensionCritical", false),
                value,
            });
        } else if p.contains("tsaExtensionOid") || p.contains("tsaExtensionValueBase64") {
            tracing::warn!("Se ha indicado solo una parte de la extension de la peticion de sello, se ignorara");
        }
        t.verify_hostname = p.get_bool("verifyHostname", true);
        Ok(Some(t))
    }
}

/// Petición de sello (`TimeStampReq`) ya codificada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampRequest {
    pub der: Vec<u8>,
    pub digest: DigestAlgorithm,
    pub imprint: Vec<u8>,
    pub policy: Option<Oid>,
    /// Nonce (INTEGER en complemento a dos).
    pub nonce: Vec<u8>,
    pub cert_req: bool,
}

/// Construye un `TimeStampReq` (RFC 3161 §2.4.1) como
/// `TimeStampRequestGenerator` de Bouncy Castle.
pub fn build_request(
    imprint: &[u8],
    digest: DigestAlgorithm,
    policy: Option<&str>,
    cert_req: bool,
    extension: Option<&TsaRequestExtension>,
    nonce: u64,
) -> afirma_core::Result<TimeStampRequest> {
    let policy = match policy {
        Some(p) => Some(
            p.parse::<Oid>()
                .map_err(|_| AfirmaError::invalid_argument(format!("Politica de sello de tiempo no valida: {p}")))?,
        ),
        None => None,
    };
    let nonce_der = der::integer_unsigned(&nonce.to_be_bytes());
    let mut parts = vec![der::integer_i64(1), der::sequence([alg::digest_alg_id(digest), der::octet_string(imprint)])];
    if let Some(p) = &policy {
        parts.push(der::oid(p));
    }
    parts.push(nonce_der.clone());
    if cert_req {
        parts.push(der::boolean(true));
    }
    if let Some(ext) = extension {
        let oid = ext
            .oid
            .parse::<Oid>()
            .map_err(|_| AfirmaError::invalid_argument(format!("OID de extension no valido: {}", ext.oid)))?;
        let mut e = vec![der::oid(&oid)];
        if ext.critical {
            e.push(der::boolean(true));
        }
        e.push(der::octet_string(&ext.value));
        parts.push(der::implicit_content(0, true, &der::sequence([der::sequence(e)])));
    }
    let nonce_bytes = Tlv::parse_single(&nonce_der).map(|t| t.value.to_vec()).unwrap_or_default();
    Ok(TimeStampRequest {
        der: der::sequence(parts),
        digest,
        imprint: imprint.to_vec(),
        policy,
        nonce: nonce_bytes,
        cert_req,
    })
}

/// Información de un sello de tiempo (`TSTInfo` y certificado de la TSA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampTokenInfo {
    /// Token completo (`ContentInfo` con el `SignedData` de la TSA), en DER.
    pub token: Vec<u8>,
    pub policy: String,
    pub imprint_algorithm: String,
    pub imprint: Vec<u8>,
    pub serial_number: Vec<u8>,
    pub gen_time: DateTime<Utc>,
    pub nonce: Option<Vec<u8>>,
    /// Certificado del firmante del sello, si viene incluido.
    pub tsa_certificate: Option<Vec<u8>>,
}

fn tsp_error(msg: impl Into<String>) -> AfirmaError {
    AfirmaError::new(codes::GENERATING_TIMESTAMP_ERROR, msg)
}

/// Lee un `TimeStampToken` (con las comprobaciones de `TimeStampToken` de
/// Bouncy Castle: tipo `id-ct-TSTInfo`, un único firmante con atributo de
/// certificado de firma).
pub fn parse_timestamp_token(token: &[u8]) -> afirma_core::Result<TimeStampTokenInfo> {
    let sd = SignedData::parse(token).map_err(|e| tsp_error(format!("El sello de tiempo no es un SignedData: {e}")))?;
    if !sd.econtent_type.is(oids::TST_INFO) {
        return Err(tsp_error("ContentInfo object not for a time stamp."));
    }
    if sd.signer_infos.len() != 1 {
        return Err(tsp_error(format!(
            "Time-stamp token signed by {} signers, but it must contain just the TSA signature.",
            sd.signer_infos.len()
        )));
    }
    let si = &sd.signer_infos[0];
    if !si.has_signed_attr(oids::SIGNING_CERTIFICATE) && !si.has_signed_attr(oids::SIGNING_CERTIFICATE_V2) {
        return Err(tsp_error("no signing certificate attribute found, time stamp invalid."));
    }
    let content = sd.content().ok_or_else(|| tsp_error("El sello de tiempo no contiene el TSTInfo"))?;
    let tst = Tlv::parse_single(&content).map_err(|e| tsp_error(format!("TSTInfo no valido: {e}")))?;
    let f = tst.children().map_err(|e| tsp_error(format!("TSTInfo no valido: {e}")))?;
    let get = |i: usize| f.get(i).copied().ok_or_else(|| tsp_error("TSTInfo incompleto"));
    let policy = get(1)?.as_oid().map_err(|e| tsp_error(e.to_string()))?.to_dotted();
    let mi = get(2)?.children().map_err(|e| tsp_error(e.to_string()))?;
    let imprint_algorithm = mi
        .first()
        .and_then(|a| a.children().ok())
        .and_then(|c| c.first().and_then(|o| o.as_oid().ok()))
        .map(|o| o.to_dotted())
        .ok_or_else(|| tsp_error("MessageImprint no valido"))?;
    let imprint =
        mi.get(1).and_then(|o| o.octet_string_content().ok()).ok_or_else(|| tsp_error("MessageImprint no valido"))?;
    let serial_number = get(3)?.as_integer_bytes().map_err(|e| tsp_error(e.to_string()))?.to_vec();
    let gen_time = get(4)?.as_time().map_err(|e| tsp_error(e.to_string()))?;
    let nonce = f.iter().skip(5).find(|t| t.tag == tags::INTEGER).map(|t| t.value.to_vec());
    let tsa_certificate = sd.signer_certificate(si).map(<[u8]>::to_vec);
    Ok(TimeStampTokenInfo {
        token: to_der_preserving(&sd.content_info),
        policy,
        imprint_algorithm,
        imprint,
        serial_number,
        gen_time,
        nonce,
        tsa_certificate,
    })
}

/// Respuesta de la TSA (`TimeStampResp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampResponse {
    pub status: i64,
    pub status_strings: Vec<String>,
    /// Valor de `PKIFailureInfo` (0 si no hay).
    pub fail_info: u32,
    /// Token (DER) si lo hay.
    pub token: Option<Vec<u8>>,
}

/// Lee un `TimeStampResp`.
pub fn parse_response(resp: &[u8]) -> afirma_core::Result<TimeStampResponse> {
    let bad = |e: String| tsp_error(format!("La respuesta de la TSA no tiene un formato valido: {e}"));
    let top = Tlv::parse_single(resp)
        .map_err(|e| bad(e.to_string()))?
        .expect(tags::SEQUENCE)
        .map_err(|e| bad(e.to_string()))?;
    let parts = top.children().map_err(|e| bad(e.to_string()))?;
    let status_info =
        parts.first().ok_or_else(|| bad("sin PKIStatusInfo".into()))?.children().map_err(|e| bad(e.to_string()))?;
    let status =
        status_info.first().ok_or_else(|| bad("sin estado".into()))?.as_i64().map_err(|e| bad(e.to_string()))?;
    let mut status_strings = Vec::new();
    let mut fail_info = 0u32;
    for t in status_info.iter().skip(1) {
        if t.tag == tags::SEQUENCE {
            for s in t.children().unwrap_or_default() {
                if let Ok(s) = s.as_string() {
                    status_strings.push(s);
                }
            }
        } else if t.tag == tags::BIT_STRING {
            // PKIFailureInfo como entero (`DERBitString.intValue()` de Bouncy Castle).
            if let Some((_, rest)) = t.value.split_first() {
                let mut v = 0u32;
                for (i, b) in rest.iter().take(4).enumerate() {
                    v |= u32::from(*b) << (8 * i);
                }
                fail_info = v;
            }
        }
    }
    let token = parts.get(1).map(|t| t.to_definite());
    Ok(TimeStampResponse { status, status_strings, fail_info, token })
}

/// Valida la respuesta frente a la petición (`TimeStampResponse.validate`)
/// y devuelve el token.
pub fn validate_response(resp: &TimeStampResponse, req: &TimeStampRequest) -> afirma_core::Result<TimeStampTokenInfo> {
    let invalid = |m: &str| tsp_error(format!("La respuesta de la TSA no es valida: {m}"));
    let Some(token) = &resp.token else {
        if resp.status == 0 || resp.status == 1 {
            return Err(invalid("no time stamp token found and one expected."));
        }
        return Err(tsp_error(format!(
            "Respuesta invalida de la TSA con el estado {} ({}) y el codigo {}",
            resp.status,
            resp.status_strings.join("; "),
            resp.fail_info
        )));
    };
    let info = parse_timestamp_token(token)?;
    if let Some(n) = &info.nonce {
        if crate::cert::minimal_twos_complement(n) != crate::cert::minimal_twos_complement(&req.nonce) {
            return Err(invalid("response contains wrong nonce value."));
        }
    } else {
        return Err(invalid("response contains wrong nonce value."));
    }
    if resp.status != 0 && resp.status != 1 {
        return Err(invalid("time stamp token found in failed request."));
    }
    if info.imprint != req.imprint {
        return Err(invalid("response for different message imprint digest."));
    }
    if info.imprint_algorithm != req.digest.oid() {
        return Err(invalid("response for different message imprint algorithm."));
    }
    if let Some(p) = &req.policy {
        if info.policy != p.to_dotted() {
            return Err(invalid("TSA responded with wrong policy."));
        }
    }
    if resp.fail_info != 0 {
        return Err(tsp_error(format!("Respuesta invalida de la TSA con el codigo {}", resp.fail_info)));
    }
    verify_token_signature(&info)?;
    Ok(info)
}

/// Verifica criptográficamente la firma del sello si incluye el certificado
/// de la TSA y el algoritmo es soportado (Java no lo hace; una firma
/// incorrecta se rechaza, un algoritmo no soportado solo se avisa).
pub fn verify_token_signature(info: &TimeStampTokenInfo) -> afirma_core::Result<()> {
    let Some(cert) = &info.tsa_certificate else { return Ok(()) };
    let sd = SignedData::parse(&info.token).map_err(|e| tsp_error(e.to_string()))?;
    let si = &sd.signer_infos[0];
    let content = sd.content().unwrap_or_default();
    match verify_signer_info(si, cert, Some(&content)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(tsp_error("La firma del sello de tiempo no es valida")),
        Err(e) => {
            tracing::warn!("No se ha podido verificar la firma del sello de tiempo: {e}");
            Ok(())
        }
    }
}

/// Verifica un SignerInfo con atributos firmados: huella del contenido
/// (si se da) y firma de los atributos.
pub fn verify_signer_info(
    si: &SignerInfo<'_>,
    cert: &[u8],
    content: Option<&[u8]>,
) -> Result<bool, verify::VerifyError> {
    let alg: SignatureAlgorithm =
        alg::signer_signature_algorithm(&si.digest_oid.to_dotted(), &si.signature_oid.to_dotted())
            .ok_or_else(|| verify::VerifyError(format!("algoritmo no soportado: {}", si.signature_oid)))?;
    let digest = DigestAlgorithm::from_oid(&si.digest_oid.to_dotted())
        .ok_or_else(|| verify::VerifyError(format!("huella no soportada: {}", si.digest_oid)))?;
    if let Some(c) = content {
        if si.message_digest().as_deref() != Some(digest.digest(c).as_slice()) {
            return Ok(false);
        }
    }
    let tbs = si.signed_attrs_to_be_signed().ok_or_else(|| verify::VerifyError("sin atributos firmados".into()))?;
    verify::verify_with_certificate(cert, alg, &tbs, &si.signature_value())
}

/// Cliente de sellado de tiempo (`CMSTimestamper`).
pub struct Timestamper {
    pub params: TsaParams,
    transport: Box<dyn TsaTransport>,
}

impl Timestamper {
    /// Cliente con el transporte por defecto (HTTP/HTTPS/socket).
    pub fn new(params: TsaParams) -> Self {
        Timestamper { params, transport: Box::new(DefaultTransport) }
    }

    pub fn with_transport(params: TsaParams, transport: Box<dyn TsaTransport>) -> Self {
        Timestamper { params, transport }
    }

    /// Obtiene un sello para una huella ya calculada (`getTimeStampToken`).
    /// Devuelve el token en DER.
    pub fn get_timestamp_token(&self, imprint: &[u8], digest: DigestAlgorithm) -> afirma_core::Result<Vec<u8>> {
        Ok(self.request_token(imprint, digest)?.token)
    }

    /// Como [`Self::get_timestamp_token`] pero con la información del sello.
    pub fn request_token(&self, imprint: &[u8], digest: DigestAlgorithm) -> afirma_core::Result<TimeStampTokenInfo> {
        // Nonce aleatorio de 63 bits (Java usa la hora en milisegundos).
        let nonce = rand::random::<u64>() >> 1;
        let req = build_request(
            imprint,
            digest,
            Some(&self.params.policy),
            self.params.require_cert,
            self.params.extension.as_ref(),
            nonce,
        )?;
        let raw = self.transport.send(&self.params, &req.der).map_err(|e| {
            AfirmaError::new(
                codes::TSA_CONNECTION_ERROR,
                format!("No se ha podido conectar con el servicio de sellado de tiempo: {e}"),
            )
        })?;
        let resp = parse_response(&raw)?;
        validate_response(&resp, &req)
    }

    /// Añade un `signatureTimeStampToken` a cada firmante de primer nivel
    /// (CAdES-T). Se conservan los demás atributos no firmados y el resultado
    /// se codifica en DER.
    pub fn add_timestamp(&self, cms: &[u8]) -> afirma_core::Result<Vec<u8>> {
        let digest = self.params.hash_algorithm;
        let sd = SignedData::parse(cms).map_err(|e| {
            AfirmaError::invalid_argument(format!("Los datos de entrada no son un SignedData de CMS: {e}"))
        })?;
        let mut signer_infos = Vec::new();
        for si in &sd.signer_infos {
            let token = self.get_timestamp_token(&digest.digest(&si.signature_value()), digest)?;
            signer_infos
                .push(add_unsigned_attribute(si, &cms::encode_attribute(oids::SIGNATURE_TIMESTAMP_TOKEN, &[token])));
        }
        Ok(SignedDataParts {
            digest_algorithms: cms::set_elements_der(&sd.digest_algorithms),
            encap_content_info: to_der_preserving(&sd.encap_content_info),
            certificates: sd.certificates.as_ref().map(cms::set_elements_der),
            crls: sd.crls.as_ref().map(cms::set_elements_der),
            signer_infos,
        }
        .encode())
    }
}

/// Reconstruye un SignerInfo añadiendo un atributo no firmado.
pub fn add_unsigned_attribute(si: &SignerInfo<'_>, attribute: &[u8]) -> Vec<u8> {
    let mut unsigned: Vec<Vec<u8>> = si.unsigned_attrs.as_ref().map(cms::set_elements_der).unwrap_or_default();
    unsigned.push(attribute.to_vec());
    cms::rebuild_signer_info(si, Some(&unsigned))
}
