//! Errores de AutoFirma-rs y códigos de error de AutoFirma (`ErrorCode`).
//!
//! Los códigos son números de 6 dígitos cuyo primer dígito indica la categoría
//! (1 hardware, 2 interno, 3 terceros, 4 comunicación, 5 funcional, 6 petición;
//! 62 = petición del navegador). Se muestran al usuario y se devuelven a la web
//! (`AF<código> - <descripción>`), así que deben coincidir con los de Java. La
//! tabla completa está en [`codes`].

use std::fmt;

pub mod codes;
pub mod messages;
pub mod protocol;

/// Código de error de AutoFirma.
#[derive(Debug, Clone, Copy, Eq)]
pub struct ErrorCode {
    pub code: u32,
    pub description: &'static str,
}

impl ErrorCode {
    pub const fn new(code: u32, description: &'static str) -> Self {
        ErrorCode { code, description }
    }

    /// Código como texto de 6 dígitos.
    pub fn code_str(&self) -> String {
        format!("{:06}", self.code)
    }

    /// Comprueba la categoría por prefijo (`"5"`, `"62"`...).
    pub fn check_type(&self, prefix: &str) -> bool {
        self.code_str().starts_with(prefix)
    }
}

/// Igual que en Java, dos códigos son iguales si lo es su número.
impl PartialEq for ErrorCode {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl std::hash::Hash for ErrorCode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}: {}", self.code, self.description)
    }
}

/// Efecto de que el usuario acepte una confirmación solicitada por un firmador
/// (`RuntimeConfigNeededException`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmEffect {
    /// Establecer `extraParams[param] = "true"` y reintentar.
    SetParamTrue,
    /// Eliminar los parámetros de política de firma y reintentar
    /// (`SignaturePolicyIncompatibilityException`).
    RemovePolicyParams,
}

/// Intervención del usuario necesaria para continuar una operación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIntervention {
    /// Confirmación sí/no. `requestor_text` es la clave del mensaje a mostrar
    /// (p. ej. `signingLts`, `agePolicyIncompatibilitySign`).
    Confirm {
        requestor_text: String,
        param: String,
        effect: ConfirmEffect,
    },
    /// Contraseña (p. ej. de un PDF protegido); se guarda en `extraParams[param]`.
    Password { requestor_text: String, param: String },
}

/// Tipo de error, para que los llamantes reaccionen sin mirar el código.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    General,
    /// Operación cancelada por el usuario (500001).
    Cancelled,
    /// Hace falta la intervención del usuario. `denied` indica que ya fue
    /// denegada (p. ej. por el servidor trifásico) y no debe preguntarse.
    NeedsIntervention {
        intervention: UserIntervention,
        denied: bool,
    },
    /// Los datos no son una firma del formato (`AOInvalidSignatureFormatException`).
    InvalidSignatureFormat,
    /// Operación no soportada por el formato (`UnsupportedOperationException`).
    Unsupported,
    /// Parámetro no válido (`IllegalArgumentException`).
    InvalidArgument,
}

/// Error de una operación de AutoFirma-rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfirmaError {
    pub code: Option<ErrorCode>,
    pub message: String,
    pub kind: ErrorKind,
    /// Descripción de la causa original, si la hay.
    pub cause: Option<String>,
}

impl AfirmaError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        AfirmaError {
            code: Some(code),
            message: message.into(),
            kind: ErrorKind::General,
            cause: None,
        }
    }

    /// Error con el mensaje igual a la descripción del código.
    pub fn from_code(code: ErrorCode) -> Self {
        Self::new(code, code.description)
    }

    /// Error sin código (se trata como desconocido).
    pub fn msg(message: impl Into<String>) -> Self {
        AfirmaError {
            code: None,
            message: message.into(),
            kind: ErrorKind::General,
            cause: None,
        }
    }

    pub fn cancelled() -> Self {
        AfirmaError {
            code: Some(codes::CANCELLED_OPERATION),
            message: codes::CANCELLED_OPERATION.description.to_string(),
            kind: ErrorKind::Cancelled,
            cause: None,
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        AfirmaError {
            code: None,
            message: message.into(),
            kind: ErrorKind::InvalidArgument,
            cause: None,
        }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        AfirmaError {
            code: None,
            message: message.into(),
            kind: ErrorKind::Unsupported,
            cause: None,
        }
    }

    /// Los datos no son una firma compatible (501006 por defecto).
    pub fn invalid_signature_format(message: impl Into<String>) -> Self {
        AfirmaError {
            code: Some(codes::COMPATIBLE_SIGNATURE_NOT_FOUND),
            message: message.into(),
            kind: ErrorKind::InvalidSignatureFormat,
            cause: None,
        }
    }

    pub fn needs_confirmation(
        code: ErrorCode,
        message: impl Into<String>,
        requestor_text: impl Into<String>,
        param: impl Into<String>,
        effect: ConfirmEffect,
    ) -> Self {
        AfirmaError {
            code: Some(code),
            message: message.into(),
            kind: ErrorKind::NeedsIntervention {
                intervention: UserIntervention::Confirm {
                    requestor_text: requestor_text.into(),
                    param: param.into(),
                    effect,
                },
                denied: false,
            },
            cause: None,
        }
    }

    pub fn needs_password(
        code: ErrorCode,
        message: impl Into<String>,
        requestor_text: impl Into<String>,
        param: impl Into<String>,
    ) -> Self {
        AfirmaError {
            code: Some(code),
            message: message.into(),
            kind: ErrorKind::NeedsIntervention {
                intervention: UserIntervention::Password {
                    requestor_text: requestor_text.into(),
                    param: param.into(),
                },
                denied: false,
            },
            cause: None,
        }
    }

    pub fn with_code(mut self, code: ErrorCode) -> Self {
        self.code = Some(code);
        self
    }

    pub fn with_cause(mut self, cause: impl fmt::Display) -> Self {
        self.cause = Some(cause.to_string());
        self
    }

    pub fn is_cancelled(&self) -> bool {
        self.kind == ErrorKind::Cancelled || self.code == Some(codes::CANCELLED_OPERATION)
    }

    /// Código efectivo (desconocido si no tiene).
    pub fn effective_code(&self) -> ErrorCode {
        self.code.unwrap_or(codes::UNKNOWN_SIGNING_ERROR)
    }
}

impl fmt::Display for AfirmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(c) = &self.cause {
            write!(f, ": {c}")?;
        }
        if let Some(code) = &self.code {
            write!(f, " ({code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for AfirmaError {}

impl From<crate::key::KeyError> for AfirmaError {
    fn from(e: crate::key::KeyError) -> Self {
        use crate::key::KeyError;
        match e {
            KeyError::Cancelled => AfirmaError::cancelled(),
            KeyError::WrongPin => AfirmaError::new(codes::INVALID_SMARTCARD_PIN, e.to_string()),
            KeyError::PinLocked => AfirmaError::new(codes::SMARTCARD_LOCKED, e.to_string()),
            KeyError::Unsupported(_) => AfirmaError::new(codes::INVALID_SIGNING_KEY, e.to_string()),
            KeyError::DeviceUnavailable | KeyError::Other(_) => {
                AfirmaError::new(codes::SIGNING_PKCS1_ERROR, e.to_string())
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, AfirmaError>;

/// Parámetros que elimina la confirmación de una incompatibilidad con la
/// política de firma (`SignaturePolicyIncompatibilityException.prepareOperationWithConfirmation`).
pub const POLICY_PARAMS: [&str; 5] = [
    "policyIdentifier",
    "policyIdentifierHash",
    "policyIdentifierHashAlgorithm",
    "policyDescription",
    "policyQualifier",
];

/// Constructores de las excepciones de AutoFirma con sus códigos por defecto
/// (§10.2 y §10.4).
impl AfirmaError {
    /// `AOUnsupportedSignAlgorithmException` (600107).
    pub fn unsupported_sign_algorithm(message: impl Into<String>) -> Self {
        Self::new(codes::UNSUPPORTED_SIGNATURE_ALGORITHM, message)
    }

    /// `AOUnsupportedSignFormatException` (600105).
    pub fn unsupported_sign_format(message: impl Into<String>) -> Self {
        Self::new(codes::UNSUPPORTED_SIGNATURE_FORMAT, message)
    }

    /// `AOFormatFileException`: los datos no son válidos para el formato
    /// (código elegido por quien lo lanza, p. ej. 501002 o 510002).
    pub fn format_file(message: impl Into<String>, code: ErrorCode) -> Self {
        Self::new(code, message)
    }

    /// `signvalidation.InvalidSignatureException` (500002).
    pub fn invalid_signature(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_SIGNATURE, message)
    }

    /// `InvalidLibraryException` (200002 por defecto).
    pub fn invalid_library(message: impl Into<String>) -> Self {
        Self::new(codes::LIBRARY_NOT_FOUND, message)
    }

    /// `InvalidOSException` (500003): `Se esperaba el sistema operativo: <os>`.
    pub fn invalid_os(expected_os: &str) -> Self {
        Self::new(
            codes::INCOMPATIBLE_OPERATING_SYSTEM,
            format!("Se esperaba el sistema operativo: {expected_os}"),
        )
    }

    /// `keystores.AuthenticationException` (200108 por defecto).
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::new(codes::SIGNING_KEY_AUTHENTICATION_ERROR, message)
    }

    /// `AOCancelledSMOperationException` (500001): cancelación en el diálogo
    /// de una tarjeta inteligente.
    pub fn cancelled_sm(message: impl Into<String>) -> Self {
        AfirmaError {
            message: message.into(),
            ..Self::cancelled()
        }
    }

    /// `SignaturePolicyIncompatibilityException` (501008): confirmación con
    /// el texto `agePolicyIncompatibilitySign/Cosign/CounterSign` según la
    /// operación (`OP_SIGN` = 1, `OP_COSIGN` = 2, `OP_COUNTERSIGN` = 3; otro
    /// valor = firma) y parámetro `avoidAGEPolicyIncompatibilities`. Al
    /// confirmarse se eliminan los parámetros de política.
    pub fn signature_policy_incompatibility(message: impl Into<String>, operation: i32) -> Self {
        let requestor = match operation {
            crate::constants::OP_COSIGN => crate::constants::REQUESTOR_AGE_POLICY_INCOMPATIBILITY_COSIGN,
            crate::constants::OP_COUNTERSIGN => crate::constants::REQUESTOR_AGE_POLICY_INCOMPATIBILITY_COUNTERSIGN,
            _ => crate::constants::REQUESTOR_AGE_POLICY_INCOMPATIBILITY_SIGN,
        };
        Self::needs_confirmation(
            codes::SIGNING_WITH_POLICY_INCOMPATIBILITY,
            message,
            requestor,
            crate::constants::EXTRA_PARAM_AVOID_AGE_POLICY_INCOMPATIBILITIES,
            ConfirmEffect::RemovePolicyParams,
        )
    }

    /// `SigningLTSException` (501007): confirmación con el texto `signingLts`
    /// (o `signingLtsPossible` si solo es posible que la firma sea longeva) y
    /// parámetro `allowSignLTSignature`.
    pub fn signing_lts(message: impl Into<String>, possible: bool) -> Self {
        Self::needs_confirmation(
            codes::SIGNING_LTS,
            message,
            if possible {
                crate::constants::REQUESTOR_SIGNING_LTS_POSSIBLE
            } else {
                crate::constants::REQUESTOR_SIGNING_LTS
            },
            crate::constants::EXTRA_PARAM_ALLOW_SIGN_LT_SIGNATURE,
            ConfirmEffect::SetParamTrue,
        )
    }

    /// Marca la intervención como ya denegada (`setDenied(true)`, p. ej. al
    /// recibirla del servidor trifásico).
    pub fn denied(mut self) -> Self {
        if let ErrorKind::NeedsIntervention { denied, .. } = &mut self.kind {
            *denied = true;
        }
        self
    }

    /// Aplica la confirmación del usuario a los parámetros para reintentar la
    /// operación (§3.5.4): `extraParams[param] = "true"` o eliminación de los
    /// parámetros de política. Devuelve `false` si el error no es una
    /// confirmación o ya estaba denegada.
    pub fn apply_confirmation(&self, extra_params: &mut crate::ExtraParams) -> bool {
        match &self.kind {
            ErrorKind::NeedsIntervention {
                intervention: UserIntervention::Confirm { param, effect, .. },
                denied: false,
            } => {
                match effect {
                    ConfirmEffect::SetParamTrue => {
                        extra_params.set(param.clone(), "true");
                    }
                    ConfirmEffect::RemovePolicyParams => {
                        for p in POLICY_PARAMS {
                            extra_params.remove(p);
                        }
                    }
                }
                true
            }
            _ => false,
        }
    }

    /// Aplica la contraseña introducida por el usuario
    /// (`extraParams[param] = contraseña`). Devuelve `false` si el error no
    /// pide contraseña o ya estaba denegado.
    pub fn apply_password(&self, extra_params: &mut crate::ExtraParams, password: &str) -> bool {
        match &self.kind {
            ErrorKind::NeedsIntervention {
                intervention: UserIntervention::Password { param, .. },
                denied: false,
            } => {
                extra_params.set(param.clone(), password);
                true
            }
            _ => false,
        }
    }

    /// `AOTriphaseException.parsePresignException`: `ERR-1`..`ERR-20` →
    /// 300409..300428; otro valor → 300451. La clase de la excepción del
    /// servidor se guarda como causa.
    pub fn triphase_presign(server_code: &str, message: impl Into<String>, exception_classname: Option<&str>) -> Self {
        let mut e = Self::new(triphase_error_code(server_code, true), message);
        e.cause = exception_classname.map(str::to_string);
        e
    }

    /// `AOTriphaseException.parsePostsignException`: `ERR-1`..`ERR-20` →
    /// 300430..300449; otro valor → 300452.
    pub fn triphase_postsign(server_code: &str, message: impl Into<String>, exception_classname: Option<&str>) -> Self {
        let mut e = Self::new(triphase_error_code(server_code, false), message);
        e.cause = exception_classname.map(str::to_string);
        e
    }

    /// Error de la prefirma trifásica según el fallo de la conexión:
    /// `HttpError` → 300400, tiempo agotado → 401302, otro → 401300.
    pub fn triphase_presign_connection(error: &crate::http::HttpClientError) -> Self {
        let code = match error {
            crate::http::HttpClientError::Http(_) => codes::PRESIGN_HTTP_ERROR,
            crate::http::HttpClientError::Timeout { .. } => codes::PRESIGN_SERVICE_TIMEOUT,
            _ => codes::PRESIGN_SERVICE_CONNECTION_ERROR,
        };
        Self::new(code, code.description).with_cause(error)
    }

    /// Error de la postfirma trifásica según el fallo de la conexión:
    /// `HttpError` → 300404, tiempo agotado → 401402, otro → 401400.
    pub fn triphase_postsign_connection(error: &crate::http::HttpClientError) -> Self {
        let code = match error {
            crate::http::HttpClientError::Http(_) => codes::POSTSIGN_HTTP_ERROR,
            crate::http::HttpClientError::Timeout { .. } => codes::POSTSIGN_SERVICE_TIMEOUT,
            _ => codes::POSTSIGN_SERVICE_CONNECTION_ERROR,
        };
        Self::new(code, code.description).with_cause(error)
    }

    /// Respuesta de error para la web según la versión del protocolo (§10.5).
    pub fn protocol_message(&self, supports_error_codes: bool) -> String {
        protocol::protocol_error_message(&self.effective_code(), supports_error_codes)
    }

    /// Texto para el usuario (§10.7).
    pub fn user_message(&self, params: &[&str]) -> String {
        messages::user_message(&self.effective_code(), params)
    }
}

/// Código de error de una respuesta `ERR-n` del servidor trifásico (§10.2).
pub fn triphase_error_code(server_code: &str, presign: bool) -> ErrorCode {
    let n = server_code
        .strip_prefix("ERR-")
        .and_then(|n| n.parse::<u32>().ok())
        .filter(|n| (1..=20).contains(n));
    let code = match (n, presign) {
        (Some(n), true) => 300408 + n,
        (Some(n), false) => 300429 + n,
        (None, true) => codes::TRI_SERVER_UNKNOWN_PRESIGN_ERROR.code,
        (None, false) => codes::TRI_SERVER_UNKNOWN_POSTSIGN_ERROR.code,
    };
    codes::by_code(code).unwrap_or(if presign {
        codes::TRI_SERVER_UNKNOWN_PRESIGN_ERROR
    } else {
        codes::TRI_SERVER_UNKNOWN_POSTSIGN_ERROR
    })
}

/// Valida un código de error de texto (exactamente 6 dígitos ASCII), como el
/// constructor de `ErrorCode`.
pub fn parse_error_code(code: &str) -> std::result::Result<u32, AfirmaError> {
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        code.parse()
            .map_err(|_| AfirmaError::invalid_argument("Los codigos de error deben ser un numero de 6 digitos"))
    } else {
        Err(AfirmaError::invalid_argument(
            "Los codigos de error deben ser un numero de 6 digitos",
        ))
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn triphase_codes() {
        assert_eq!(triphase_error_code("ERR-1", true), codes::TRI_SERVER_PRESIGN_ERROR_1);
        assert_eq!(triphase_error_code("ERR-20", true), codes::TRI_SERVER_PRESIGN_ERROR_20);
        assert_eq!(
            triphase_error_code("ERR-21", true),
            codes::TRI_SERVER_UNKNOWN_PRESIGN_ERROR
        );
        assert_eq!(triphase_error_code("ERR-7", false), codes::TRI_SERVER_POSTSIGN_ERROR_7);
        assert_eq!(
            triphase_error_code("X", false),
            codes::TRI_SERVER_UNKNOWN_POSTSIGN_ERROR
        );
        let e = AfirmaError::triphase_presign("ERR-9", "fallo", Some("java.lang.Exception"));
        assert_eq!(e.code, Some(codes::TRI_SERVER_PRESIGN_ERROR_9));
        assert_eq!(e.cause.as_deref(), Some("java.lang.Exception"));
        assert_eq!(
            AfirmaError::triphase_postsign("ERR-12", "x", None).code.unwrap().code,
            300441
        );
        let http = crate::http::HttpClientError::Http(crate::http::HttpError {
            status: 500,
            reason: None,
            body: vec![],
            url: "u".into(),
        });
        assert_eq!(
            AfirmaError::triphase_presign_connection(&http).code,
            Some(codes::PRESIGN_HTTP_ERROR)
        );
        let t = crate::http::HttpClientError::Timeout {
            url: "u".into(),
            message: "m".into(),
        };
        assert_eq!(
            AfirmaError::triphase_postsign_connection(&t).code,
            Some(codes::POSTSIGN_SERVICE_TIMEOUT)
        );
        let io = crate::http::HttpClientError::Io {
            url: "u".into(),
            message: "m".into(),
        };
        assert_eq!(AfirmaError::triphase_presign_connection(&io).code.unwrap().code, 401300);
    }

    #[test]
    fn confirmations() {
        let mut p = crate::ExtraParams::new();
        for k in POLICY_PARAMS {
            p.set(k, "x");
        }
        p.set("format", "XAdES");
        let e = AfirmaError::signature_policy_incompatibility("incompatible", crate::constants::OP_COSIGN);
        let ErrorKind::NeedsIntervention {
            intervention: UserIntervention::Confirm {
                requestor_text, param, ..
            },
            ..
        } = &e.kind
        else {
            panic!()
        };
        assert_eq!(requestor_text, "agePolicyIncompatibilityCosign");
        assert_eq!(param, "avoidAGEPolicyIncompatibilities");
        assert!(e.apply_confirmation(&mut p));
        assert_eq!(p.len(), 1);
        let lts = AfirmaError::signing_lts("lts", true);
        assert_eq!(lts.code, Some(codes::SIGNING_LTS));
        assert!(lts.apply_confirmation(&mut p));
        assert_eq!(p.get("allowSignLTSignature"), Some("true"));
        assert!(!lts.clone().denied().apply_confirmation(&mut p));
        let pw = AfirmaError::needs_password(
            codes::SIGNING_PDF_WITHOUT_PASSWORD,
            "pw",
            "pdfPasswordProtected",
            "ownerPassword",
        );
        assert!(pw.apply_password(&mut p, "1234"));
        assert_eq!(p.get("ownerPassword"), Some("1234"));
        assert_eq!(
            AfirmaError::invalid_os("WINDOWS").message,
            "Se esperaba el sistema operativo: WINDOWS"
        );
        assert!(AfirmaError::cancelled_sm("Cancelacion del dialogo de JMulticard").is_cancelled());
        assert_eq!(
            AfirmaError::unsupported_sign_format("x").protocol_message(false),
            "SAF_06: Formato de firma no soportado"
        );
        assert_eq!(
            AfirmaError::msg("sin codigo").user_message(&[]),
            messages::ERROR_GENERIC_TEXT
        );
        assert_eq!(parse_error_code("500001").unwrap(), 500001);
        assert!(parse_error_code("50001").is_err());
        assert!(parse_error_code("5000a1").is_err());
    }
}
