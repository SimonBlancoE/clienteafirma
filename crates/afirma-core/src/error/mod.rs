//! Errores de AutoFirma-rs y códigos de error de AutoFirma (`ErrorCode`).
//!
//! Los códigos son números de 6 dígitos cuyo primer dígito indica la categoría
//! (1 hardware, 2 interno, 3 terceros, 4 comunicación, 5 funcional, 6 petición;
//! 62 = petición del navegador). Se muestran al usuario y se devuelven a la web
//! (`AF<código> - <descripción>`), así que deben coincidir con los de Java. La
//! tabla completa está en [`codes`].

use std::fmt;

pub mod codes;

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
    Confirm { requestor_text: String, param: String, effect: ConfirmEffect },
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
    NeedsIntervention { intervention: UserIntervention, denied: bool },
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
        AfirmaError { code: Some(code), message: message.into(), kind: ErrorKind::General, cause: None }
    }

    /// Error con el mensaje igual a la descripción del código.
    pub fn from_code(code: ErrorCode) -> Self {
        Self::new(code, code.description)
    }

    /// Error sin código (se trata como desconocido).
    pub fn msg(message: impl Into<String>) -> Self {
        AfirmaError { code: None, message: message.into(), kind: ErrorKind::General, cause: None }
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
        AfirmaError { code: None, message: message.into(), kind: ErrorKind::InvalidArgument, cause: None }
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        AfirmaError { code: None, message: message.into(), kind: ErrorKind::Unsupported, cause: None }
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

    pub fn needs_password(code: ErrorCode, message: impl Into<String>, requestor_text: impl Into<String>, param: impl Into<String>) -> Self {
        AfirmaError {
            code: Some(code),
            message: message.into(),
            kind: ErrorKind::NeedsIntervention {
                intervention: UserIntervention::Password { requestor_text: requestor_text.into(), param: param.into() },
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
            KeyError::DeviceUnavailable | KeyError::Other(_) => AfirmaError::new(codes::SIGNING_PKCS1_ERROR, e.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, AfirmaError>;
