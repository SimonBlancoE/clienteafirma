//! Errores del protocolo y su formato en la respuesta a la web
//! (`ProtocolInvocationLauncherErrorManager`).
//!
//! - Protocolo ≥ 4.1: `err-00:=AF<código> - <descripción Java>`
//!   (`err-11:=` para la cancelación).
//! - Protocolo < 4.1 (o desconocido): `SAF_NN: <mensaje localizado>` o
//!   `CANCEL`.

use std::fmt;

use afirma_core::error::{ErrorCode, codes};
use afirma_core::{AfirmaError, ErrorKind};

use crate::messages::{self, Locale};
use crate::version::ProtocolVersion;

/// Respuesta de cancelación en el formato antiguo.
pub const CANCEL_RESPONSE: &str = "CANCEL";

/// Origen de un error, que determina si se muestra un diálogo y si se sube
/// al servidor intermedio (en Java: `ParameterException`,
/// `SocketOperationException` y el resto de excepciones).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorOrigin {
    /// Error de los parámetros de la petición: diálogo y respuesta; Java no
    /// lo sube al servidor intermedio.
    Parameter,
    /// Error producido durante la operación (incluida la cancelación): se
    /// devuelve/sube sin diálogo.
    Operation,
    /// Error inesperado: diálogo y respuesta con el código genérico de la
    /// operación; Java no lo sube.
    Unexpected,
}

/// Error de una operación del protocolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: ErrorCode,
    /// Mensaje interno (para el registro; no viaja a la web).
    pub message: String,
    pub origin: ErrorOrigin,
    /// Parámetros `%0`, `%1`... del texto del diálogo (p. ej. el host en 400004).
    pub dialog_params: Vec<String>,
}

impl ProtocolError {
    pub fn new(code: ErrorCode, message: impl Into<String>, origin: ErrorOrigin) -> Self {
        ProtocolError { code, message: message.into(), origin, dialog_params: Vec::new() }
    }

    /// Error de parámetros (`ParameterException`).
    pub fn parameter(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message, ErrorOrigin::Parameter)
    }

    /// Error de la operación (`SocketOperationException`).
    pub fn operation(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message, ErrorOrigin::Operation)
    }

    /// Error de operación con el mensaje igual a la descripción del código.
    pub fn op_code(code: ErrorCode) -> Self {
        Self::operation(code, code.description)
    }

    /// Error inesperado (excepción no controlada).
    pub fn unexpected(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message, ErrorOrigin::Unexpected)
    }

    pub fn cancelled() -> Self {
        Self::operation(codes::CANCELLED_OPERATION, codes::CANCELLED_OPERATION.description)
    }

    pub fn with_dialog_params(mut self, params: Vec<String>) -> Self {
        self.dialog_params = params;
        self
    }

    pub fn is_cancelled(&self) -> bool {
        self.code == codes::CANCELLED_OPERATION
    }

    /// Indica si Java mostraría un diálogo de error.
    pub fn shows_dialog(&self) -> bool {
        !self.is_cancelled() && self.origin != ErrorOrigin::Operation
    }

    /// Convierte un error de un firmador/almacén en error de operación. Si no
    /// tiene código se usa `default_code`.
    pub fn from_afirma(err: &AfirmaError, default_code: ErrorCode) -> Self {
        if err.is_cancelled() || err.kind == ErrorKind::Cancelled {
            return Self::cancelled();
        }
        Self::operation(err.code.unwrap_or(default_code), err.to_string())
    }

    /// Texto de respuesta para la web según la versión de protocolo.
    pub fn response(&self, version: Option<ProtocolVersion>, locale: Locale) -> String {
        format_error(version, self.code, locale)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AF{:06}: {}", self.code.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

/// Descripción Java exacta de un código tal y como viaja en la respuesta.
/// Dos descripciones de Java empiezan por un espacio (200102 y 300202), lo
/// que produce un doble espacio tras ` - `.
pub fn wire_description(code: ErrorCode) -> String {
    match code.code {
        200102 | 300202 => format!(" {}", code.description.trim_start()),
        _ => code.description.to_string(),
    }
}

/// Texto de error para la web (`getErrorMessage`). `version == None`
/// equivale al `null` de Java (formato antiguo).
pub fn format_error(version: Option<ProtocolVersion>, code: ErrorCode, locale: Locale) -> String {
    match version {
        Some(v) if v.uses_error_codes() => {
            let prefix = if code == codes::CANCELLED_OPERATION { "err-11:=" } else { "err-00:=" };
            format!("{prefix}AF{:06} - {}", code.code, wire_description(code))
        }
        _ => {
            let saf = saf_code(code);
            if saf == CANCEL_RESPONSE {
                CANCEL_RESPONSE.to_string()
            } else {
                format!("{saf}: {}", messages::get(locale, saf_message_key(saf)))
            }
        }
    }
}

/// Código antiguo (`SAF_NN` o `CANCEL`) asociado a un código de error
/// (`OLD_ERRORS_ASSOCIATION`; los no asociados → `SAF_53`).
pub fn saf_code(code: ErrorCode) -> &'static str {
    match code.code {
        500001 => "CANCEL",
        200003 => "SAF_00",
        620012 => "SAF_01",
        620009 => "SAF_02",
        200115 | 200201 | 200305 | 200413 | 200600 | 420502 | 600009 | 600100 | 600101 | 600102 | 600104 | 600106 | 600107
        | 600110 | 600111 | 600112 | 600113 | 600116 | 600117 | 600118 | 600120 | 600121 | 600200 | 600201 | 600202 | 600300
        | 600301 | 600302 | 600303 | 600304 | 600306 | 600307 | 600402 | 600403 | 600405 | 600406 | 600410 | 600411 | 600413
        | 600415 | 600417 | 600420 | 600501 | 600701 | 600702 | 620013 | 620016 => "SAF_03",
        600002 => "SAF_04",
        200301 => "SAF_05",
        600105 => "SAF_06",
        201101 => "SAF_08",
        200111 | 200118 => "SAF_09",
        401200 | 420501 => "SAF_11",
        200100 | 200101 | 200116 | 200200 | 200400 | 200401 | 220004 => "SAF_12",
        600010 | 600119 | 600203 | 600305 | 600412 | 600414 | 600416 => "SAF_13",
        200701 => "SAF_14",
        220002 => "SAF_15",
        220003 | 401100 | 401101 | 401102 | 401103 | 401104 | 401105 => "SAF_16",
        501009 => "SAF_17",
        200114 => "SAF_18",
        501001 | 502001 | 504001 => "SAF_19",
        200412 => "SAF_20",
        620011 => "SAF_21",
        501008 => "SAF_23",
        200601 => "SAF_25",
        401501 | 401701 => "SAF_26",
        200410 | 200411 | 300701 | 300702 => "SAF_27",
        510005 => "SAF_28",
        510002 => "SAF_29",
        501002 => "SAF_30",
        501006 => "SAF_31",
        510008 => "SAF_32",
        212004 | 212005 => "SAF_33",
        212003 => "SAF_34",
        212007 => "SAF_35",
        510009 => "SAF_38",
        500002 => "SAF_39",
        500005 => "SAF_41",
        501010 => "SAF_43",
        510001 => "SAF_44",
        220001 => "SAF_45",
        620010 => "SAF_46",
        200110 => "SAF_51",
        511003 | 511004 => "SAF_52",
        _ => "SAF_53",
    }
}

/// Clave del texto (`ProtocolLauncher.N`) de cada código antiguo.
fn saf_message_key(saf: &str) -> &'static str {
    match saf {
        "SAF_00" => "ProtocolLauncher.0",
        "SAF_01" => "ProtocolLauncher.1",
        "SAF_02" => "ProtocolLauncher.2",
        "SAF_03" => "ProtocolLauncher.3",
        "SAF_04" => "ProtocolLauncher.4",
        "SAF_05" => "ProtocolLauncher.5",
        "SAF_06" => "ProtocolLauncher.6",
        "SAF_08" => "ProtocolLauncher.8",
        "SAF_09" => "ProtocolLauncher.9",
        "SAF_11" => "ProtocolLauncher.11",
        "SAF_12" => "ProtocolLauncher.12",
        "SAF_13" => "ProtocolLauncher.13",
        "SAF_14" => "ProtocolLauncher.14",
        "SAF_15" => "ProtocolLauncher.15",
        "SAF_16" => "ProtocolLauncher.16",
        "SAF_17" => "ProtocolLauncher.17",
        "SAF_18" => "ProtocolLauncher.18",
        "SAF_19" => "ProtocolLauncher.19",
        "SAF_20" => "ProtocolLauncher.20",
        "SAF_21" => "ProtocolLauncher.21",
        "SAF_23" => "ProtocolLauncher.33",
        "SAF_25" => "ProtocolLauncher.35",
        "SAF_26" => "ProtocolLauncher.36",
        "SAF_27" => "ProtocolLauncher.37",
        "SAF_28" => "ProtocolLauncher.38",
        "SAF_29" => "ProtocolLauncher.39",
        "SAF_30" => "ProtocolLauncher.40",
        "SAF_31" => "ProtocolLauncher.41",
        "SAF_32" => "ProtocolLauncher.42",
        "SAF_33" => "ProtocolLauncher.43",
        "SAF_34" => "ProtocolLauncher.44",
        "SAF_35" => "ProtocolLauncher.45",
        "SAF_38" => "ProtocolLauncher.48",
        "SAF_39" => "ProtocolLauncher.49",
        "SAF_41" => "ProtocolLauncher.53",
        "SAF_43" => "ProtocolLauncher.55",
        "SAF_44" => "ProtocolLauncher.56",
        "SAF_45" => "ProtocolLauncher.57",
        "SAF_46" => "ProtocolLauncher.58",
        "SAF_48" => "ProtocolLauncher.63",
        "SAF_49" => "ProtocolLauncher.64",
        "SAF_51" => "ProtocolLauncher.66",
        "SAF_52" => "ProtocolLauncher.68",
        _ => "ProtocolLauncher.69",
    }
}

/// Título del diálogo de error: `Error` (≥ 4.1) o `Error AF<código>`.
pub fn dialog_title(version: Option<ProtocolVersion>, code: ErrorCode, locale: Locale) -> String {
    match version {
        Some(v) if v.uses_error_codes() => messages::get(locale, "ProtocolLauncher.67"),
        _ => messages::get_with(locale, "ProtocolLauncher.29", &[&format!("AF{:06}", code.code)]),
    }
}

/// Texto del diálogo de error (`getText`): `Error.<código>` con la clave de
/// su categoría como alternativa. Se reproduce el fallo de Java por el que
/// los códigos 1xxxxx y 2xxxxx usan la alternativa genérica `Error`.
pub fn dialog_text(code: ErrorCode, locale: Locale, params: &[String]) -> String {
    let key = format!("Error.{:06}", code.code);
    let first = code.code / 100_000;
    let fallback = match first {
        3 => "Error.3XXXXX",
        4 => "Error.4XXXXX",
        5 => "Error.5XXXXX",
        6 if code.code / 10_000 == 62 => "Error.62XXXX",
        6 => "Error.6XXXXX",
        _ => "Error",
    };
    let mut text = messages::lookup(locale, &key)
        .or_else(|| messages::lookup(locale, fallback))
        .map(str::to_string)
        .unwrap_or_else(|| code.description.to_string());
    for (i, p) in params.iter().enumerate() {
        text = text.replace(&format!("%{i}"), p);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_format() {
        let v = Some(ProtocolVersion::V4_1);
        assert_eq!(
            format_error(v, codes::UNSUPPORTED_SIGNATURE_FORMAT, Locale::Es),
            "err-00:=AF600105 - El formato de firma indicado en la operacion de firma no esta soportado"
        );
        assert_eq!(format_error(v, codes::CANCELLED_OPERATION, Locale::Es), "err-11:=AF500001 - Operacion cancelada por el usuario");
        // Doble espacio por la descripción Java con espacio inicial.
        assert_eq!(
            format_error(v, codes::LOADING_LOCAL_FILE_ERROR, Locale::Es),
            "err-00:=AF200102 -  Error al cargar el fichero local para realizar la firma"
        );
        assert_eq!(
            format_error(Some(ProtocolVersion::new(5, 0)), codes::INVALID_SESSION_ID, Locale::Es),
            "err-00:=AF620010 - El identificador de sesion del websocket es incorrecto"
        );
    }

    #[test]
    fn legacy_format() {
        let v = Some(ProtocolVersion::V4);
        assert_eq!(format_error(v, codes::CANCELLED_OPERATION, Locale::Es), "CANCEL");
        assert_eq!(format_error(None, codes::CANCELLED_OPERATION, Locale::En), "CANCEL");
        assert_eq!(format_error(v, codes::SIGNATURE_FORMAT_NOT_FOUND, Locale::Es), "SAF_03: Error en los parámetros de entrada");
        assert_eq!(format_error(v, codes::SIGNATURE_FORMAT_NOT_FOUND, Locale::En), "SAF_03: Error in input parameters");
        assert_eq!(
            format_error(Some(ProtocolVersion::V3), codes::UNSUPPORTED_PROTOCOL_VERSION, Locale::Es),
            "SAF_21: La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible."
        );
        // Código no asociado → SAF_53.
        assert_eq!(format_error(v, codes::TSA_CONNECTION_ERROR, Locale::Es), "SAF_53: Error desconocido");
        assert_eq!(saf_code(codes::UNKNOWN_SIGNING_ERROR), "SAF_03");
        assert_eq!(saf_code(codes::UNSUPPORTED_HASH_ALGORITHM), "SAF_09");
        assert_eq!(format_error(v, codes::INVALID_SESSION_ID, Locale::Es), "SAF_46: Id de sesión inválido");
    }

    #[test]
    fn dialogs() {
        assert_eq!(dialog_title(Some(ProtocolVersion::V4_1), codes::INVALID_SESSION_ID, Locale::Es), "Error");
        assert_eq!(dialog_title(None, codes::INVALID_SESSION_ID, Locale::Es), "Error AF620010");
        assert_eq!(dialog_text(codes::INVALID_SESSION_ID, Locale::Es, &[]), "La petición no es válida.");
        assert!(dialog_text(codes::INVALID_DOMAIN_SSL_CERTIFICATE_ERROR, Locale::Es, &["h.example".into()]).ends_with("h.example"));
        // 2xxxxx sin texto propio → "Error" genérico (fallo reproducido de Java).
        assert_eq!(dialog_text(codes::UNKNOWN_SIGNING_ERROR, Locale::Es, &[]), "Se ha encontrado un error durante la operaci&oacute;n.");
        assert!(dialog_text(codes::SOCKET_INITIALIZING_ERROR, Locale::Es, &[]).starts_with("Autofirma no ha podido"));
    }
}
