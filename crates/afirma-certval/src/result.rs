//! Resultado de la validación (`ValidationResult`) y datos del informe.

use std::fmt;

use chrono::{DateTime, Utc};

/// Resultado de la validación de un certificado X.509
/// (`es.gob.afirma.plugin.certvalidation.validation.ValidationResult`).
///
/// Los códigos numéricos (0..=11) y los nombres son los de Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ValidationResult {
    /// Válido.
    Valid = 0,
    /// No compatible X.509 o corrupto.
    Corrupt = 1,
    /// No se soporta la CA de expedición.
    CaNotSupported = 2,
    /// Aún no válido.
    NotYetValid = 3,
    /// Caducado.
    Expired = 4,
    /// Revocado.
    Revoked = 5,
    /// Desconocido.
    Unknown = 6,
    /// Error interno, de red o del servidor OCSP.
    ServerError = 7,
    /// No autorizado.
    Unauthorized = 8,
    /// Petición OCSP mal formada.
    MalformedRequest = 9,
    /// La petición OCSP no está firmada.
    SigRequired = 10,
    /// No se ha podido descargar la lista de certificados revocados.
    CannotDownloadCrl = 11,
}

impl ValidationResult {
    /// Todos los resultados, en orden de código.
    pub const ALL: [ValidationResult; 12] = [
        Self::Valid,
        Self::Corrupt,
        Self::CaNotSupported,
        Self::NotYetValid,
        Self::Expired,
        Self::Revoked,
        Self::Unknown,
        Self::ServerError,
        Self::Unauthorized,
        Self::MalformedRequest,
        Self::SigRequired,
        Self::CannotDownloadCrl,
    ];

    /// Código numérico de Java (`resultCode`).
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Resultado correspondiente a un código de Java.
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    /// Nombre de la constante Java (`VALID`, `CA_NOT_SUPPORTED`...).
    pub fn name(self) -> &'static str {
        match self {
            Self::Valid => "VALID",
            Self::Corrupt => "CORRUPT",
            Self::CaNotSupported => "CA_NOT_SUPPORTED",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::Unknown => "UNKNOWN",
            Self::ServerError => "SERVER_ERROR",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::MalformedRequest => "MALFORMED_REQUEST",
            Self::SigRequired => "SIG_REQUIRED",
            Self::CannotDownloadCrl => "CANNOT_DOWNLOAD_CRL",
        }
    }

    /// `isValid()`: el certificado es válido, está en su periodo de validez y
    /// no está revocado.
    pub fn is_ok(self) -> bool {
        self == Self::Valid
    }

    /// Descripción del resultado (`ValidationResult.N` de
    /// `certvalidationmessages.properties`) con las entidades HTML ya
    /// decodificadas ("Válido.", "Aún no válido."...).
    pub fn description(self) -> &'static str {
        match self {
            Self::Valid => "Válido.",
            Self::Corrupt => "Corrupto o no compatible con la norma X.509.",
            Self::CaNotSupported => "No es de una Autoridad de Certificación (CA) soportada.",
            Self::NotYetValid => "Aún no válido.",
            Self::Expired => "Caducado.",
            Self::Revoked => "Revocado.",
            Self::Unknown => "Desconocido.",
            Self::ServerError => "Error interno, de red o del servidor OCSP.",
            Self::Unauthorized => "No autorizado.",
            Self::MalformedRequest => "Peticion OCSP mal formada.",
            Self::SigRequired => "La petición OCSP no está firmada.",
            Self::CannotDownloadCrl => "No se ha podido descargar la lista de certificados revocados.",
        }
    }

    /// `toString()` de Java: el texto de `certvalidationmessages.properties`
    /// tal cual, con las entidades HTML sin decodificar (`V&aacute;lido.`).
    pub fn java_description(self) -> &'static str {
        match self {
            Self::Valid => "V&aacute;lido.",
            Self::CaNotSupported => "No es de una Autoridad de Certificaci&oacute;n (CA) soportada.",
            Self::NotYetValid => "A&uacute;n no v&aacute;lido.",
            Self::SigRequired => "La petici&oacute;n OCSP no est&aacute; firmada.",
            other => other.description(),
        }
    }

    /// Texto del diálogo "Estado de su certificado" del botón "Validar
    /// certificado de firma" (`ValidateCertAction`). `UNAUTHORIZED`,
    /// `MALFORMED_REQUEST`, `SIG_REQUIRED` y `CANNOT_DOWNLOAD_CRL` comparten
    /// "No se ha podido comprobar la validez del certificado".
    pub fn dialog_message(self) -> &'static str {
        match self {
            Self::Valid => "El certificado es válido",
            Self::Expired => "El certificado está caducado",
            Self::Revoked => "El certificado está revocado",
            Self::NotYetValid => "El certificado aun no es válido",
            Self::CaNotSupported => "Autoridad de certificación no soportada",
            Self::Corrupt => "El certificado está corrupto",
            Self::ServerError => "El servicio de validación devolvió un error",
            Self::Unknown => "Se desconoce el estado del certificado.",
            Self::Unauthorized | Self::MalformedRequest | Self::SigRequired | Self::CannotDownloadCrl => {
                "No se ha podido comprobar la validez del certificado"
            }
        }
    }

    /// `toJsonString()` de Java (sin uso en la interfaz), byte a byte:
    /// `{\n  "result": "OK"|"KO",\n  "reason": "<toString()>"\n}`.
    pub fn to_json_string(self) -> String {
        format!(
            "{{\n  \"result\": \"{}\",\n  \"reason\": \"{}\"\n}}",
            if self.is_ok() { "OK" } else { "KO" },
            self.java_description()
        )
    }
}

impl fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// Mecanismo con el que se comprobó la revocación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationMethod {
    /// No se llegó a consultar ningún servicio (certificado corrupto,
    /// caducado, CA no soportada, sin mecanismos declarados...).
    None,
    /// Consulta OCSP al servicio indicado (el último consultado).
    Ocsp { url: String },
    /// Listas de revocación consultadas (en el orden en que se intentaron).
    Crl { urls: Vec<String> },
}

/// Motivo de revocación (`CRLReason`, RFC 5280 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RevocationReason(pub u8);

impl RevocationReason {
    /// Descripción en español del motivo.
    pub fn description(self) -> &'static str {
        match self.0 {
            0 => "Sin especificar",
            1 => "Compromiso de la clave",
            2 => "Compromiso de la autoridad de certificación",
            3 => "Cambio de afiliación",
            4 => "Sustituido",
            5 => "Cese de actividad",
            6 => "Suspendido",
            8 => "Retirado de la lista de revocación",
            9 => "Privilegios retirados",
            10 => "Compromiso de la autoridad de atributos",
            _ => "Motivo desconocido",
        }
    }
}

/// Datos de la revocación de un certificado revocado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationInfo {
    /// Fecha de revocación.
    pub time: Option<DateTime<Utc>>,
    /// Motivo, si el servicio lo indica.
    pub reason: Option<RevocationReason>,
}

/// Origen del certificado del emisor usado en la validación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerSource {
    /// Indicado por quien llama ([`crate::ValidationOptions::issuer`]).
    Provided,
    /// Encontrado en la cadena indicada ([`crate::ValidationOptions::chain`]).
    Chain,
    /// Certificado de CA incluido en AutoFirma (tabla de
    /// `CertificateVerifierFactory`).
    Bundled,
    /// Descargado de la extensión AIA `caIssuers` del certificado.
    Downloaded { url: String },
    /// El certificado está autofirmado.
    SelfSigned,
}

/// Informe completo de una validación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// Resultado (el mismo que devuelve [`crate::validate_certificate`]).
    pub result: ValidationResult,
    /// Mecanismo de comprobación de la revocación usado.
    pub method: ValidationMethod,
    /// Detalle técnico en español (motivo del error, servicio consultado...).
    pub detail: Option<String>,
    /// Instante de referencia de la validación.
    pub checked_at: DateTime<Utc>,
    /// Fecha y motivo de la revocación si `result` es `REVOKED` y se conocen.
    pub revocation: Option<RevocationInfo>,
    /// De dónde se obtuvo el certificado del emisor (si se obtuvo).
    pub issuer_source: Option<IssuerSource>,
    /// No hay ningún mecanismo de validación para el certificado: Java no
    /// llega a validar y muestra el error
    /// [`crate::messages::NO_MECHANISM`] en lugar del diálogo de resultado.
    /// Solo ocurre en [`crate::SelectionMode::JavaFactory`] cuando la tabla
    /// de Java indica OCSP y el certificado no tiene extensión AIA.
    pub no_mechanism: bool,
}

impl ValidationReport {
    /// Indica si el certificado es válido.
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Texto que muestra AutoFirma al usuario: el del diálogo "Estado de su
    /// certificado" o, si no hay mecanismo de validación, el del error
    /// [`crate::messages::NO_MECHANISM`].
    pub fn dialog_message(&self) -> &'static str {
        if self.no_mechanism {
            crate::messages::NO_MECHANISM
        } else {
            self.result.dialog_message()
        }
    }

    /// Título del diálogo correspondiente a [`Self::dialog_message`]
    /// ("Estado de su certificado" o "Error").
    pub fn dialog_title(&self) -> &'static str {
        if self.no_mechanism {
            crate::messages::ERROR_TITLE
        } else {
            crate::messages::RESULT_DIALOG_TITLE
        }
    }

    /// Indica si el diálogo es de error (icono de error) o informativo
    /// (solo cuando el certificado es válido).
    pub fn dialog_is_error(&self) -> bool {
        self.no_mechanism || !self.result.is_ok()
    }
}
