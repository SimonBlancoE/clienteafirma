//! Textos de error que se muestran al usuario (`protocolmessages_es_ES`
//! de afirma-simple, §10.5 y §10.7) y título de los diálogos de error.
//!
//! Los textos son los exactos del fichero de mensajes en español (con las
//! entidades HTML y los espacios finales del original).

use super::ErrorCode;

/// Texto genérico (`Error`).
pub const ERROR_GENERIC_TEXT: &str = "Se ha encontrado un error durante la operaci&oacute;n.";

/// Textos por clave (`Error.<código>` y categorías `Error.NXXXXX`).
pub const ERROR_TEXTS: &[(&str, &str)] = &[
    ("Error", ERROR_GENERIC_TEXT),
    ("Error.1XXXXX", "Se ha producido un error con el dispositivo externo. No se puede completar la operación. "),
    ("Error.2XXXXX", "Ocurrió un error interno durante la operación "),
    (
        "Error.220001",
        "Autofirma no ha podido comunicarse con el navegador web. Reintente la operación o restaure\nla instalación de Autofirma si el problema persiste.",
    ),
    (
        "Error.220008",
        "No se han encontrado las claves para la conexión segura con el navegador.\nEjecute la función de restauración de la instalación desde el menú de herramientas de Autofirma para poder firmar.",
    ),
    ("Error.3XXXXX", "Un servicio o biblioteca externo devolvió un error durante el proceso. Se aborta la operación."),
    ("Error.4XXXXX", "Ocurrió un error al conectarse con un servicio o aplicativo externo. Se aborta la operación."),
    ("Error.400004", "Se ha interrumpido la operación al detectar una conexión con un entorno no seguro: %0"),
    ("Error.5XXXXX", "No se ha podido completar la operación."),
    (
        "Error.500006",
        "La firma requiere información que Autofirma no ha podido identificar. Compruebe si existe una versión más reciente de Autofirma.",
    ),
    (
        "Error.500007",
        "La validación de la firma requiere información que Autofirma no ha podido identificar. Compruebe si existe una versión más reciente de Autofirma.",
    ),
    ("Error.500002", "La firma que se trata de procesar es inválida."),
    ("Error.500003", "Su sistema operativo no es compatible con la operación solicitada."),
    (
        "Error.500004",
        "Su JRE no es compatible con la operación solicitada. Actualícela a la última versión compatiple.",
    ),
    (
        "Error.500005",
        "La aplicación web requiere una versión posterior de Autofirma. Actualicese a la última versión disponible.",
    ),
    ("Error.500008", "La operación de carga de fichero no está disponible en este sistema."),
    ("Error.500009", "La operación de carga de múltiples ficheros no está disponible en este sistema."),
    ("Error.501001", "No se han encontrado certificados para realizar la firma."),
    ("Error.501002", "El formato de fichero no es válido para la operación que se intenta realizar."),
    ("Error.501003", "El PIN del la tarjeta inteligente es incorrecto."),
    ("Error.501005", "El documento supera el tamaño máximo permitido."),
    ("Error.501006", "La firma no es compatible con el formato de firma utilizado."),
    ("Error.501007", "No se agregará la nueva firma porque la firma longeva original quedaría invalidada."),
    (
        "Error.501008",
        "No se firmará el documento porque la firma resultante sería incompatible con la política de firma.",
    ),
    ("Error.501009", "No se ha podido identificar un formato de firma para los datos."),
    ("Error.501010", "Sólo se permite la firma visible del documento PDF."),
    ("Error.502001", "No se han encontrado certificados para realizar la selección."),
    ("Error.504001", "No se han encontrado certificados para realizar la firma del lote."),
    ("Error.506001", "El directorio de entrada no existe."),
    ("Error.506002", "No se tiene acceso al directorio indicado."),
    ("Error.510001", "La firma no contiene los datos firmados necesarios para completar la operación."),
    ("Error.510002", "Para poder realizar esta operación es necesario seleccionar un fichero XML."),
    ("Error.510003", "Para poder realizar esta operación es necesario seleccionar un fichero ODF."),
    ("Error.510004", "Para poder realizar esta operación es necesario seleccionar un fichero OOXML."),
    ("Error.510005", "Para poder realizar esta operación es necesario seleccionar un fichero PDF."),
    ("Error.510006", "La firma no es compatible o está mal formada."),
    (
        "Error.510007",
        "El documento es una firma XML y no se puede volver a firmar. Pruebe a cofirmarla o contrafirmarla.",
    ),
    ("Error.510008", "La factura ya tiene una firma electrónica y no admite firmas adicionales."),
    ("Error.510009", "Para poder realizar esta operación es necesario seleccionar un fichero FacturaE."),
    ("Error.511003", "El almacén de claves esta bloqueado."),
    ("Error.511004", "La tarjeta inteligente esta bloqueada."),
    ("Error.6XXXXX", "Los parámetros recibidos no son corretos."),
    ("Error.62XXXX", "La petición no es válida."),
    (
        "Error.620011",
        "La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible.",
    ),
];

/// Título de los diálogos de error con protocolo ≥ 4.1 (`ProtocolLauncher.67`).
pub const ERROR_DIALOG_TITLE: &str = "Error";
/// Título de los diálogos de error con protocolo < 4.1 (`ProtocolLauncher.29`).
pub const ERROR_DIALOG_TITLE_WITH_CODE: &str = "Error %0";

fn lookup(key: &str) -> Option<&'static str> {
    ERROR_TEXTS.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// Clave de categoría (`Error.1XXXXX`...`Error.62XXXX`) de un código.
pub fn category_key(code: &ErrorCode) -> &'static str {
    let s = code.code_str();
    if s.starts_with("62") {
        "Error.62XXXX"
    } else {
        match s.as_bytes().first() {
            Some(b'1') => "Error.1XXXXX",
            Some(b'2') => "Error.2XXXXX",
            Some(b'3') => "Error.3XXXXX",
            Some(b'4') => "Error.4XXXXX",
            Some(b'5') => "Error.5XXXXX",
            Some(b'6') => "Error.6XXXXX",
            _ => "Error",
        }
    }
}

/// Texto que se muestra al usuario para un código
/// (`ProtocolInvocationLauncherErrorManager.getText`): `Error.<código>`; si
/// no existe, la clave de la categoría (salvo para los códigos 1xxxxx y
/// 2xxxxx, que por un `else` que falta en Java caen en la clave genérica
/// `Error`); y como último recurso la descripción del código. Los `%0..%n`
/// se sustituyen por los parámetros.
pub fn user_message(code: &ErrorCode, params: &[&str]) -> String {
    let key = format!("Error.{}", code.code_str());
    let s = code.code_str();
    let fallback = if s.starts_with('1') || s.starts_with('2') { "Error" } else { category_key(code) };
    let mut text = lookup(&key).or_else(|| lookup(fallback)).unwrap_or(code.description).to_string();
    for (i, p) in params.iter().enumerate() {
        text = text.replace(&format!("%{i}"), p);
    }
    text
}

/// Código con prefijo (`AF<código>`).
pub fn error_code_with_prefix(code: &ErrorCode) -> String {
    format!("AF{}", code.code_str())
}

/// Título del diálogo de error: `Error` con protocolo ≥ 4.1 y `Error AF<código>`
/// con versiones anteriores.
pub fn dialog_title(code: &ErrorCode, supports_error_codes: bool) -> String {
    if supports_error_codes {
        ERROR_DIALOG_TITLE.to_string()
    } else {
        ERROR_DIALOG_TITLE_WITH_CODE.replace("%0", &error_code_with_prefix(code))
    }
}

/// Mensaje que se registra cuando no hay interfaz gráfica:
/// `AF<código>: <mensaje>`.
pub fn headless_log_message(code: &ErrorCode, params: &[&str]) -> String {
    format!("{}: {}", error_code_with_prefix(code), user_message(code, params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;

    #[test]
    fn texts_and_fallbacks() {
        assert_eq!(user_message(&codes::INVALID_SIGNATURE, &[]), "La firma que se trata de procesar es inválida.");
        assert_eq!(
            user_message(&codes::INVALID_DOMAIN_SSL_CERTIFICATE_ERROR, &["ejemplo.es"]),
            "Se ha interrumpido la operación al detectar una conexión con un entorno no seguro: ejemplo.es"
        );
        // Categoría 3 sin texto propio.
        assert_eq!(
            user_message(&codes::PRESIGN_HTTP_ERROR, &[]),
            "Un servicio o biblioteca externo devolvió un error durante el proceso. Se aborta la operación."
        );
        // 2xxxxx sin texto propio → genérico (GOTCHA del else que falta).
        assert_eq!(user_message(&codes::SIGNING_PKCS1_ERROR, &[]), ERROR_GENERIC_TEXT);
        assert_eq!(user_message(&codes::SOCKET_INITIALIZING_ERROR, &[]).lines().count(), 2);
        assert_eq!(user_message(&codes::KEYSTORE_SMARTCARD_LOCKED, &[]), ERROR_GENERIC_TEXT);
        assert_eq!(user_message(&codes::UNSUPPORTED_PROTOCOL_VERSION, &[]).lines().count(), 2);
        assert_eq!(user_message(&codes::INVALID_SESSION_ID, &[]), "La petición no es válida.");
        assert_eq!(user_message(&codes::DATA_NOT_FOUND, &[]), "Los parámetros recibidos no son corretos.");
        assert_eq!(
            user_message(&codes::TSA_CONNECTION_ERROR, &[]),
            "Ocurrió un error al conectarse con un servicio o aplicativo externo. Se aborta la operación."
        );
        assert_eq!(user_message(&codes::CANCELLED_OPERATION, &[]), "No se ha podido completar la operación.");
        assert_eq!(dialog_title(&codes::CANCELLED_OPERATION, true), "Error");
        assert_eq!(dialog_title(&codes::CANCELLED_OPERATION, false), "Error AF500001");
        assert_eq!(
            headless_log_message(&codes::INVALID_SIGNATURE, &[]),
            "AF500002: La firma que se trata de procesar es inválida."
        );
    }
}
