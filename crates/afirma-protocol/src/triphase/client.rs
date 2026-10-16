//! Cliente de firma trifásica simple contra `SignatureService`
//! (`AOCAdESTriPhaseSigner`, `AOXAdESTriPhaseSigner`, `AOPDFTriPhaseSigner`,
//! `AOPkcs1TriPhaseSigner` y sus variantes ASiC-S/FacturaE).

use std::time::Duration;

use afirma_core::error::{ConfirmEffect, ErrorCode, codes};
use afirma_core::{AfirmaError, CounterSignTarget, ExtraParams, SigningKey};

use crate::http::{HttpClient, HttpError};
use crate::jbase64;
use crate::properties;
use crate::triphase::data::TriphaseData;

/// Operación criptográfica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoOperation {
    Sign,
    CoSign,
    CounterSign,
}

impl CryptoOperation {
    /// Nombre del protocolo (`sign`, `cosign`, `countersign`).
    pub fn name(self) -> &'static str {
        match self {
            CryptoOperation::Sign => "sign",
            CryptoOperation::CoSign => "cosign",
            CryptoOperation::CounterSign => "countersign",
        }
    }

    /// Interpreta el nombre sin distinguir mayúsculas.
    pub fn parse(name: &str) -> Option<CryptoOperation> {
        match name.to_ascii_lowercase().as_str() {
            "sign" => Some(CryptoOperation::Sign),
            "cosign" => Some(CryptoOperation::CoSign),
            "countersign" => Some(CryptoOperation::CounterSign),
            _ => None,
        }
    }
}

/// Formatos trifásicos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriphaseFormat {
    Cades,
    CadesAsics,
    Xades,
    XadesAsics,
    FacturaE,
    Pades,
    None,
}

impl TriphaseFormat {
    /// Formato trifásico a partir del nombre de formato del protocolo
    /// (`CAdEStri`, `XAdES-ASiC-S-tri`, `Adobe PDF TriPhase`...; sin
    /// distinguir mayúsculas).
    pub fn from_format_name(name: &str) -> Option<TriphaseFormat> {
        let n = name.to_ascii_lowercase();
        Some(match n.as_str() {
            "cadestri" => TriphaseFormat::Cades,
            "cades-asic-s-tri" => TriphaseFormat::CadesAsics,
            "xadestri" => TriphaseFormat::Xades,
            "xades-asic-s-tri" => TriphaseFormat::XadesAsics,
            "facturaetri" => TriphaseFormat::FacturaE,
            "padestri" | "adobe pdf triphase" => TriphaseFormat::Pades,
            "nonetri" => TriphaseFormat::None,
            _ => return None,
        })
    }

    /// Formato enviado al servidor.
    pub fn server_format(self) -> &'static str {
        match self {
            TriphaseFormat::Cades => "CAdES",
            TriphaseFormat::CadesAsics => "CAdES-ASiC-S",
            TriphaseFormat::Xades => "XAdES",
            TriphaseFormat::XadesAsics => "XAdES-ASiC-S",
            TriphaseFormat::FacturaE => "FacturaE",
            TriphaseFormat::Pades => "pades",
            TriphaseFormat::None => "NONE",
        }
    }

    fn is_xades_family(self) -> bool {
        matches!(self, TriphaseFormat::Xades | TriphaseFormat::XadesAsics | TriphaseFormat::FacturaE)
    }

    /// Indica si el formato admite la operación.
    pub fn supports(self, op: CryptoOperation) -> bool {
        match self {
            TriphaseFormat::Cades | TriphaseFormat::Xades => true,
            TriphaseFormat::XadesAsics => op != CryptoOperation::CounterSign,
            // La cofirma PAdES es una firma.
            TriphaseFormat::Pades => op != CryptoOperation::CounterSign,
            TriphaseFormat::CadesAsics | TriphaseFormat::FacturaE | TriphaseFormat::None => op == CryptoOperation::Sign,
        }
    }

    /// Nombre propuesto para el fichero firmado (`getSignedName`).
    pub fn signed_name(self, original: &str) -> String {
        match self {
            TriphaseFormat::Cades | TriphaseFormat::CadesAsics => format!("{original}.csig"),
            TriphaseFormat::None => format!("{original}.p1"),
            TriphaseFormat::Pades => {
                let lower = original.to_ascii_lowercase();
                if lower.ends_with(".pdf") {
                    format!("{}_signed.pdf", &original[..original.len() - 4])
                } else {
                    format!("{original}_signed.pdf")
                }
            }
            _ => format!("{original}.xsig"),
        }
    }
}

const PARAM_SERVER_URL: &str = "serverUrl";

/// Cliente trifásico.
#[derive(Debug, Clone)]
pub struct TriphaseClient {
    pub http: HttpClient,
}

impl TriphaseClient {
    pub fn new(http: HttpClient) -> Self {
        TriphaseClient { http }
    }

    /// Ejecuta la operación trifásica completa y devuelve la firma
    /// (`OK NEWID=` decodificado).
    ///
    /// `algorithm` es el nombre recibido (`SHA256withRSA`, `SHA256`...); se
    /// compone con el tipo de la clave antes de enviarlo. Los errores
    /// `ERR-21` del servidor se devuelven como errores de intervención del
    /// usuario ([`afirma_core::ErrorKind::NeedsIntervention`]).
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        format: TriphaseFormat,
        op: CryptoOperation,
        data: Option<&[u8]>,
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
        target: Option<&CounterSignTarget>,
    ) -> Result<Vec<u8>, AfirmaError> {
        if !format.supports(op) {
            return Err(AfirmaError::unsupported(format!(
                "No se soporta la operacion {} en el formato trifasico {}",
                op.name(),
                format.server_format()
            )));
        }
        let chain = key.certificate_chain();
        if chain.is_empty() {
            return Err(AfirmaError::invalid_argument("Es necesario proporcionar el certificado de firma"));
        }
        let data_mandatory = !(format.is_xades_family()
            && op == CryptoOperation::Sign
            && (extra.get("format") == Some("XAdES Externally Detached")
                || extra.get("useManifest").is_some_and(|v| v.eq_ignore_ascii_case("true"))));
        if data.is_none() && data_mandatory {
            return Err(AfirmaError::invalid_argument("No se ha proporcionado el identificador de documento a firmar"));
        }
        let server_url = extra.get(PARAM_SERVER_URL).unwrap_or("");
        if !is_valid_java_url(server_url) {
            return Err(AfirmaError::invalid_argument(format!(
                "No se ha proporcionado una URL valida para el servidor de firma: {}",
                extra.get(PARAM_SERVER_URL).unwrap_or("null")
            )));
        }
        let algo = afirma_core::algorithms::compose_signature_algorithm(algorithm, key.key_algorithm())
            .map_err(|_| AfirmaError::invalid_argument(format!("Algoritmo no soportado: {algorithm}")))?
            .java_name();

        // Parámetros enviados al servidor (copia: nunca se modifican los del llamante).
        let mut params = extra.clone();
        if op == CryptoOperation::CounterSign {
            let t = match target {
                Some(CounterSignTarget::Tree) => "tree",
                Some(CounterSignTarget::Leafs) | None => "leafs",
                Some(other) => {
                    return Err(AfirmaError::invalid_argument(format!(
                        "El objetivo indicado para la contrafirma no esta soportado: {}",
                        other.name()
                    )));
                }
            };
            params.set("target", t);
        }
        let cert_param = if format == TriphaseFormat::None {
            jbase64::encode_url_safe(&chain[0])
        } else {
            cert_chain_param(&chain, &params)
        };
        match format {
            TriphaseFormat::Cades | TriphaseFormat::CadesAsics => {
                params.remove(PARAM_SERVER_URL);
                params.remove("documentId");
            }
            TriphaseFormat::Xades | TriphaseFormat::XadesAsics | TriphaseFormat::FacturaE => {
                params.remove("validatePkcs1");
                params.remove(PARAM_SERVER_URL);
            }
            TriphaseFormat::Pades | TriphaseFormat::None => {}
        }
        let doc = data.map(jbase64::encode_url_safe);
        let props = if params.is_empty() || format == TriphaseFormat::None { None } else { Some(properties::store_base64_url(&params)) };
        let fmt = format.server_format();
        let cop = op.name();

        // ---- Prefirma ----
        let mut pre = format!("op=pre&cop={cop}&format={fmt}&algo={algo}&cert={cert_param}");
        match format {
            TriphaseFormat::Cades | TriphaseFormat::CadesAsics | TriphaseFormat::Pades => {
                pre.push_str(&format!("&doc={}", doc.as_deref().unwrap_or("")));
                if let Some(p) = &props {
                    pre.push_str(&format!("&params={p}"));
                }
            }
            TriphaseFormat::Xades | TriphaseFormat::XadesAsics | TriphaseFormat::FacturaE => {
                if let Some(d) = &doc {
                    pre.push_str(&format!("&doc={d}"));
                }
                if let Some(p) = &props {
                    pre.push_str(&format!("&params={p}"));
                }
            }
            TriphaseFormat::None => pre.push_str(&format!("&doc={}", doc.as_deref().unwrap_or(""))),
        }
        let pre_result = self.http.post(server_url, &pre).map_err(|e| presign_http_error(e, format == TriphaseFormat::None))?;
        if format != TriphaseFormat::None {
            if pre_result.len() <= 8 {
                return Err(AfirmaError::new(codes::MALFORMED_PRESIGN_RESPONSE, "No se han obtenido datos de la prefirma"));
            }
            if String::from_utf8_lossy(&pre_result[..8]).starts_with("ERR-") {
                return Err(server_error(&String::from_utf8_lossy(&pre_result), true, format, extra));
            }
        }
        let mut td = jbase64::decode_bytes(&pre_result, true)
            .map_err(|e| e.to_string())
            .and_then(|xml| TriphaseData::parse_xml(&xml).map_err(|e| e.to_string()))
            .map_err(|e| AfirmaError::new(codes::MALFORMED_PRESIGN_RESPONSE, "Error al analizar la prefirma enviada por el servidor").with_cause(e))?;

        // ---- Firma ----
        if format == TriphaseFormat::None {
            td.sign_first(key, &algo)?;
        } else {
            td.sign_all(key, &algo)?;
        }
        let session = jbase64::encode_url_safe(td.to_xml().as_bytes());

        // ---- Postfirma ----
        let mut post = format!("op=post&cop={cop}&format={fmt}&algo={algo}&cert={cert_param}");
        let mut http = self.http.clone();
        match format {
            TriphaseFormat::Cades | TriphaseFormat::CadesAsics => {
                if let Some(p) = &props {
                    post.push_str(&format!("&params={p}"));
                }
                post.push_str(&format!("&session={session}&doc={}", doc.as_deref().unwrap_or("")));
            }
            TriphaseFormat::Xades | TriphaseFormat::XadesAsics | TriphaseFormat::FacturaE => {
                post.push_str(&format!("&session={session}"));
                if let Some(d) = &doc {
                    post.push_str(&format!("&doc={d}"));
                }
                if let Some(p) = &props {
                    post.push_str(&format!("&params={p}"));
                }
                // El parámetro adicional `servicetimeout` es el tiempo de
                // espera de conexión de la postfirma XAdES.
                if let Some(t) = extra.get("servicetimeout") {
                    let ms = crate::version::java_parse_int(t)
                        .ok_or_else(|| AfirmaError::invalid_argument(format!("For input string: \"{t}\"")))?;
                    if ms >= 0 {
                        http = http.with_connect_timeout(if ms == 0 { None } else { Some(Duration::from_millis(ms as u64)) });
                    }
                }
            }
            TriphaseFormat::Pades => {
                post.push_str(&format!("&doc={}&session={session}", doc.as_deref().unwrap_or("")));
                if let Some(p) = &props {
                    post.push_str(&format!("&params={p}"));
                }
            }
            TriphaseFormat::None => post.push_str(&format!("&doc={}&session={session}", doc.as_deref().unwrap_or(""))),
        }
        let post_result = http.post(server_url, &post).map_err(|e| postsign_http_error(e, format == TriphaseFormat::None))?;
        if format != TriphaseFormat::None {
            if post_result.len() <= 8 {
                return Err(AfirmaError::new(codes::MALFORMED_POSTSIGN_RESPONSE, "No se han obtenido datos de la postfirma"));
            }
            if String::from_utf8_lossy(&post_result[..8]).starts_with("ERR-") {
                return Err(server_error(&String::from_utf8_lossy(&post_result), false, format, extra));
            }
        }
        parse_postsign_ok(&post_result)
    }
}

/// Interpreta `OK NEWID=<Base64 URL-safe>`.
pub fn parse_postsign_ok(body: &[u8]) -> Result<Vec<u8>, AfirmaError> {
    let text = String::from_utf8_lossy(body);
    let trimmed = crate::triphase::data::java_trim(&text);
    if !trimmed.starts_with("OK") {
        return Err(AfirmaError::new(codes::POSTSIGN_ERROR, format!("La firma trifasica no ha finalizado correctamente: {trimmed}")));
    }
    let malformed = || AfirmaError::new(codes::MALFORMED_POSTSIGN_RESPONSE, "El resultado devuelto por el servidor no es correcto");
    let encoded = trimmed.get("OK NEWID=".len()..).ok_or_else(malformed)?;
    jbase64::decode_url_safe(encoded).map_err(|e| malformed().with_cause(e))
}

/// `TriphaseUtil.prepareCertChainParam`: cadena completa en Base64 URL-safe
/// separada por comas, o solo el certificado de firma si
/// `includeOnlySignningCertificate=true`.
pub fn cert_chain_param(chain: &[Vec<u8>], extra: &ExtraParams) -> String {
    if extra.get("includeOnlySignningCertificate").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return jbase64::encode_url_safe(&chain[0]);
    }
    chain.iter().map(|c| jbase64::encode_url_safe(c)).collect::<Vec<_>>().join(",")
}

/// Validación de `new URL(text)` de Java: un esquema conocido seguido de `:`.
pub fn is_valid_java_url(text: &str) -> bool {
    let Some(colon) = text.find(':') else { return false };
    let scheme = text[..colon].to_ascii_lowercase();
    matches!(scheme.as_str(), "http" | "https" | "ftp" | "file" | "jar")
        && text[colon + 1..].len() > if scheme.starts_with("http") { 2 } else { 0 }
}

fn presign_http_error(e: HttpError, none_format: bool) -> AfirmaError {
    map_phase_http_error(e, none_format, true)
}

fn postsign_http_error(e: HttpError, none_format: bool) -> AfirmaError {
    map_phase_http_error(e, none_format, false)
}

fn map_phase_http_error(e: HttpError, none_format: bool, pre: bool) -> AfirmaError {
    let (bad_params, comm, http, timeout, conn) = if pre {
        (
            codes::INVALID_PARAMS_TO_PRESIGN,
            codes::PRESIGN_SERVICE_COMMUNICATION_ERROR,
            codes::PRESIGN_HTTP_ERROR,
            codes::PRESIGN_SERVICE_TIMEOUT,
            codes::PRESIGN_SERVICE_CONNECTION_ERROR,
        )
    } else {
        (
            codes::INVALID_PARAMS_TO_POSTSIGN,
            codes::POSTSIGN_SERVICE_COMMUNICATION_ERROR,
            codes::POSTSIGN_HTTP_ERROR,
            codes::POSTSIGN_SERVICE_TIMEOUT,
            codes::POSTSIGN_SERVICE_CONNECTION_ERROR,
        )
    };
    let phase = if pre { "prefirma" } else { "postfirma" };
    let code = match &e {
        HttpError::Status { code: 400, .. } if !none_format => bad_params,
        HttpError::Status { code, .. } if *code / 100 == 4 && !none_format => comm,
        HttpError::Status { .. } => http,
        HttpError::Timeout(_) => timeout,
        _ => conn,
    };
    AfirmaError::new(code, format!("Error en la llamada al servicio de {phase}")).with_cause(e)
}

/// Código de error de `AOTriphaseException` para `ERR-n`.
pub fn triphase_error_code(server_code: &str, presign: bool) -> ErrorCode {
    let n = server_code.strip_prefix("ERR-").and_then(|n| n.parse::<u32>().ok()).filter(|n| (1..=20).contains(n));
    let code = match (n, presign) {
        (Some(n), true) => 300408 + n,
        (Some(n), false) => 300429 + n,
        (None, true) => 300451,
        (None, false) => 300452,
    };
    codes::by_code(code).unwrap_or(if presign { codes::TRI_SERVER_UNKNOWN_PRESIGN_ERROR } else { codes::TRI_SERVER_UNKNOWN_POSTSIGN_ERROR })
}

/// Intervención solicitada por un `ERR-21:<código>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedIntervention {
    pub requestor: &'static str,
    pub code: ErrorCode,
    pub param: &'static str,
    pub password: bool,
    pub effect: ConfirmEffect,
}

/// Tabla de `ERR-21` por formato (`buildInternalException`).
pub fn err21_intervention(format: TriphaseFormat, code: &str, extra: &ExtraParams) -> Option<RequestedIntervention> {
    let confirm = |requestor, code, param| RequestedIntervention { requestor, code, param, password: false, effect: ConfirmEffect::SetParamTrue };
    match format {
        TriphaseFormat::Cades | TriphaseFormat::CadesAsics => match code {
            "signingLts" => Some(confirm("signingLts", codes::SIGNING_LTS, "allowSignLTSignature")),
            _ => None,
        },
        TriphaseFormat::Xades | TriphaseFormat::XadesAsics | TriphaseFormat::FacturaE => match code {
            "xPathNotFound" => Some(confirm("xPathNotFound", codes::XPATH_NOT_FOUND, "allowXadesEnvelopedWithoutXPath")),
            "signingLts" => Some(confirm("signingLts", codes::SIGNING_LTS, "allowSignLTSignature")),
            "signingLtsPossible" => Some(confirm("signingLtsPossible", codes::SIGNING_LTS, "allowSignLTSignature")),
            "agePolicyIncompatibilitySign" | "agePolicyIncompatibilityCosign" | "agePolicyIncompatibilityCounterSign" => {
                let requestor = match code {
                    "agePolicyIncompatibilitySign" => "agePolicyIncompatibilitySign",
                    "agePolicyIncompatibilityCosign" => "agePolicyIncompatibilityCosign",
                    _ => "agePolicyIncompatibilityCounterSign",
                };
                Some(RequestedIntervention {
                    requestor,
                    code: codes::SIGNING_WITH_POLICY_INCOMPATIBILITY,
                    param: "avoidAGEPolicyIncompatibilities",
                    password: false,
                    effect: ConfirmEffect::RemovePolicyParams,
                })
            }
            _ => None,
        },
        TriphaseFormat::Pades => match code {
            "signingCertifiedPdf" => Some(confirm("signingCertifiedPdf", codes::SIGNING_PDF_WITH_CERTIFIED_SIGN, "allowSigningCertifiedPdfs")),
            "signingPdfWithUnregisteredSigns" => Some(confirm(
                "signingPdfWithUnregisteredSigns",
                codes::SIGNING_PDF_WITH_UNREGISTER_SIGNATURES,
                "allowCosigningUnregisteredSignatures",
            )),
            "signingModifiedPdfForm" => Some(confirm("signingModifiedPdfForm", codes::SIGNING_PDF_WITH_MODIFIED_FORM, "allowModifiedForm")),
            "pdfShadowAttackSuspect" => Some(confirm("pdfShadowAttackSuspect", codes::SIGNING_PDF_WITH_SUSPICION_OF_PSA, "allowShadowAttack")),
            "pdfpasswordprotected" | "pdfbadpassword" => {
                let bad = extra.contains("ownerPassword") || extra.contains("userPassword");
                Some(if bad {
                    RequestedIntervention {
                        requestor: "pdfbadpassword",
                        code: codes::SIGNING_PDF_WITH_BAD_PASSWORD,
                        param: "userPassword",
                        password: true,
                        effect: ConfirmEffect::SetParamTrue,
                    }
                } else {
                    RequestedIntervention {
                        requestor: "pdfpasswordprotected",
                        code: codes::SIGNING_PDF_WITHOUT_PASSWORD,
                        param: "ownerPassword",
                        password: true,
                        effect: ConfirmEffect::SetParamTrue,
                    }
                })
            }
            _ => None,
        },
        TriphaseFormat::None => None,
    }
}

/// Convierte una respuesta `ERR-...` del servidor en el error de la
/// operación (`buildInternalException` + `getInternalException`).
pub fn server_error(msg: &str, presign: bool, format: TriphaseFormat, extra: &ExtraParams) -> AfirmaError {
    let sep = msg.find(':').unwrap_or(msg.len());
    if msg.starts_with("ERR-21:") {
        if let Some(sep2) = msg[sep + 1..].find(':').map(|p| p + sep + 1) {
            let code = &msg[sep + 1..sep2];
            let text = &msg[sep2 + 1..];
            if let Some(i) = err21_intervention(format, code, extra) {
                return if i.password {
                    AfirmaError::needs_password(i.code, text.trim(), i.requestor, i.param)
                } else {
                    AfirmaError::needs_confirmation(i.code, text.trim(), i.requestor, i.param, i.effect)
                };
            }
        }
    }
    let tri_code = &msg[..sep];
    let rest = msg.get(sep + 1..).unwrap_or("");
    let (class_name, int_message) = match rest.find(':') {
        Some(p2) => {
            let after = &rest[p2 + 1..];
            match after.find(':') {
                Some(p3) => (Some(after[..p3].trim().to_string()), after[p3 + 1..].trim().to_string()),
                None => (Some(after.trim().to_string()), rest[..p2].trim().to_string()),
            }
        }
        None => (None, rest.trim().to_string()),
    };
    // getInternalException: solo una clase `java.lang.Exception` acaba
    // instanciándose (comprobación invertida de Java) y produce un error
    // genérico sin código.
    if class_name.as_deref() == Some("java.lang.Exception") {
        return AfirmaError::msg(int_message);
    }
    let code = triphase_error_code(tri_code, presign);
    let mut err = AfirmaError::new(code, int_message);
    if let Some(c) = class_name {
        err = err.with_cause(c);
    }
    err
}

#[cfg(test)]
mod tests {
    use super::*;
    use afirma_core::ErrorKind;

    #[test]
    fn formats() {
        assert_eq!(TriphaseFormat::from_format_name("ADOBE PDF TRIPHASE"), Some(TriphaseFormat::Pades));
        assert_eq!(TriphaseFormat::from_format_name("cades-asic-s-tri").unwrap().server_format(), "CAdES-ASiC-S");
        assert_eq!(TriphaseFormat::from_format_name("CAdES"), None);
        assert!(!TriphaseFormat::CadesAsics.supports(CryptoOperation::CoSign));
        assert!(TriphaseFormat::XadesAsics.supports(CryptoOperation::CoSign));
        assert!(!TriphaseFormat::Pades.supports(CryptoOperation::CounterSign));
        assert_eq!(TriphaseFormat::Pades.signed_name("a.PDF"), "a_signed.pdf");
    }

    #[test]
    fn error_codes() {
        for n in 1..=20u32 {
            assert_eq!(triphase_error_code(&format!("ERR-{n}"), true).code, 300408 + n);
            assert_eq!(triphase_error_code(&format!("ERR-{n}"), false).code, 300429 + n);
        }
        assert_eq!(triphase_error_code("ERR-21", true).code, 300451);
        assert_eq!(triphase_error_code("ERR-99", false).code, 300452);
        let e = server_error("ERR-9: Error realizando la prefirma: java.lang.IllegalArgumentException: Datos nulos", true, TriphaseFormat::Cades, &ExtraParams::new());
        assert_eq!(e.code.unwrap().code, 300417);
        assert_eq!(e.message, "Datos nulos");
        let e = server_error("ERR-6: Formato erroneo", false, TriphaseFormat::Xades, &ExtraParams::new());
        assert_eq!(e.code.unwrap().code, 300435);
        assert_eq!(e.message, "Formato erroneo");
        let e = server_error("ERR-12: Error: java.lang.Exception", false, TriphaseFormat::Xades, &ExtraParams::new());
        assert_eq!(e.code, None);
    }

    #[test]
    fn err21_mapping() {
        let e = server_error(
            "ERR-21:signingLts: Se requiere intervencion del usuario: es.gob.afirma.core.SigningLTSException: LTS",
            true,
            TriphaseFormat::Cades,
            &ExtraParams::new(),
        );
        assert_eq!(e.code.unwrap().code, 501007);
        match e.kind {
            ErrorKind::NeedsIntervention { intervention: afirma_core::error::UserIntervention::Confirm { param, requestor_text, .. }, denied } => {
                assert_eq!(param, "allowSignLTSignature");
                assert_eq!(requestor_text, "signingLts");
                assert!(!denied);
            }
            other => panic!("{other:?}"),
        }
        // Código no reconocido por el formato → 300451.
        let e = server_error("ERR-21:xPathNotFound: x", true, TriphaseFormat::Cades, &ExtraParams::new());
        assert_eq!(e.code.unwrap().code, 300451);
        let e = server_error("ERR-21:pdfpasswordprotected: x", true, TriphaseFormat::Pades, &ExtraParams::new());
        assert!(matches!(e.kind, ErrorKind::NeedsIntervention { intervention: afirma_core::error::UserIntervention::Password { .. }, .. }));
        assert_eq!(e.code.unwrap().code, 212005);
        let mut ep = ExtraParams::new();
        ep.set("ownerPassword", "x");
        let e = server_error("ERR-21:pdfpasswordprotected: x", true, TriphaseFormat::Pades, &ep);
        assert_eq!(e.code.unwrap().code, 212004);
    }

    #[test]
    fn postsign_ok_parsing() {
        assert_eq!(parse_postsign_ok(b"OK NEWID=SG9sYQ==\r\n").unwrap(), b"Hola");
        assert_eq!(parse_postsign_ok(b"KO NEWID=SG9sYQ==").unwrap_err().code.unwrap().code, 300405);
        assert_eq!(parse_postsign_ok(b"OK NEWID=SG9s+Q==").unwrap_err().code.unwrap().code, 300407);
        assert_eq!(parse_postsign_ok(b"OK").unwrap_err().code.unwrap().code, 300407);
        assert!(is_valid_java_url("https://x/SignatureService"));
        assert!(!is_valid_java_url("x"));
        assert!(!is_valid_java_url(""));
    }
}
