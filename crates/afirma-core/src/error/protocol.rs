//! Cómo se comunican los errores a la web por el protocolo `afirma://`
//! (`ProtocolInvocationLauncherErrorManager.getErrorMessage`, §10.5).
//!
//! * Protocolo ≥ 4.1: `err-00:=AF<código> - <descripción>` (o `err-11:=`
//!   para la cancelación, 500001).
//! * Protocolo < 4.1: texto antiguo `SAF_xx: <mensaje>` según la tabla de
//!   asociación de Java (si el código no está asociado, `SAF_53: Error
//!   desconocido`); la cancelación devuelve literalmente `CANCEL`.

use super::ErrorCode;

/// Prefijo de los errores (protocolo ≥ 4.1).
pub const DEFAULT_ERROR_PREFIX: &str = "err-00:=";
/// Prefijo de la cancelación (protocolo ≥ 4.1).
pub const CANCELLATION_ERROR_PREFIX: &str = "err-11:=";
/// Respuesta de cancelación del protocolo antiguo.
pub const CANCEL_RESPONSE: &str = "CANCEL";
/// Código antiguo para errores no asociados.
pub const ERROR_UNKNOWN: &str = "SAF_53";

/// Mensajes de los códigos antiguos (`ProtocolLauncher.N` en español).
pub const SAF_MESSAGES: &[(&str, &str)] = &[
    (CANCEL_RESPONSE, CANCEL_RESPONSE),
    ("SAF_00", "No se han podido leer los datos a firmar"),
    ("SAF_01", "La URL recibida es nula"),
    ("SAF_02", "Protocolo no soportado"),
    ("SAF_03", "Error en los parámetros de entrada"),
    (
        "SAF_04",
        "Operación no soportada. Compruebe que dispone de la última versión de Autofirma.",
    ),
    ("SAF_05", "No se ha podido guardar los datos"),
    ("SAF_06", "Formato de firma no soportado"),
    ("SAF_08", "Error accediendo al almacén de claves y certificados"),
    ("SAF_09", "Error realizando la firma electrónica"),
    ("SAF_11", "Error en el envio del resultado de la operación."),
    ("SAF_12", "Error en el cifrado de los datos a enviar"),
    (
        "SAF_13",
        "Se ha pedido acceso a una dirección local, pero por seguridad se ha bloqueado el acceso",
    ),
    (
        "SAF_14",
        "<html>La aplicaci&oacute;n est&aacute; obsoleta y no puede procesarse la petici&oacute;n.<br>Por favor, instale una versi&oacute;n actualizada y reintente el proceso de nuevo.</html>",
    ),
    ("SAF_15", "Error en el descifrado de los datos"),
    ("SAF_16", "Error al recuperar los datos del servidor intermedio"),
    (
        "SAF_17",
        "Los datos proporcionados no son una firma electrónica reconocida",
    ),
    ("SAF_18", "Error al descodificar el certificado de firma"),
    (
        "SAF_19",
        "No hay ningun certificado válido en su almacén. Compruebe las fechas de caducidad e instale un certificado válido.",
    ),
    ("SAF_20", "Error en el procesado del lote de firma."),
    (
        "SAF_21",
        "La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible.",
    ),
    (
        "SAF_23",
        "Se ha establecido una política de firma no válida o parámetros no compatibles con ella.",
    ),
    ("SAF_25", "Error en la lectura de los datos a cargar."),
    ("SAF_26", "Error en la comunicación con el servicio de firma de lotes."),
    ("SAF_27", "El servicio informó de un error durante la firma del lote."),
    ("SAF_28", "El fichero no es un PDF o es un PDF no soportado."),
    (
        "SAF_29",
        "Las firmas XAdES Enveloped solo pueden realizarse sobre datos XML.",
    ),
    (
        "SAF_30",
        "El formato de los datos a firmar no es adecuado para el tipo de firma seleccionado.",
    ),
    (
        "SAF_31",
        "Los datos introducidos no se corresponden con un objeto de firma.",
    ),
    (
        "SAF_32",
        "La factura ya tiene una firma electrónica y no admite firmas adicionales.",
    ),
    (
        "SAF_33",
        "La contraseña proporcionada no es válida para el PDF actual o no se proporcionó ninguna contraseña.",
    ),
    ("SAF_34", "El PDF contiene firmas no registradas."),
    ("SAF_35", "El PDF está certificado."),
    (
        "SAF_38",
        "El archivo que intenta firmar no es una factura electrónica reconocida.",
    ),
    ("SAF_39", "La firma de entrada no es válida."),
    (
        "SAF_41",
        "El uso de este trámite web requiere una versión más reciente de Autofirma.\nActualice a la última versión disponible.",
    ),
    ("SAF_43", "Error durante la firma visible del PDF."),
    (
        "SAF_44",
        "La firma no contiene los datos y no se compatible con la configuración seleccionada",
    ),
    (
        "SAF_45",
        "No se pudo abrir un socket para la comunicación con la aplicación",
    ),
    ("SAF_46", "Id de sesión inválido"),
    // Claves ausentes de todos los ficheros de mensajes (`'!' + clave + '!'`).
    ("SAF_48", "!ProtocolLauncher.63!"),
    ("SAF_49", "!ProtocolLauncher.64!"),
    ("SAF_51", "El tipo de clave del certificado no está soportado."),
    ("SAF_52", "El almacen de claves esta bloqueado"),
    ("SAF_53", "Error desconocido"),
];

/// Asociación código → código antiguo, en el orden de inserción de Java
/// (`OLD_ERRORS_ASSOCIATION`; la última inserción gana, p. ej. 200115 acaba
/// en `SAF_03`).
const OLD_ERRORS_ASSOCIATION: &[(u32, &str)] = &[
    (500001, CANCEL_RESPONSE),
    (200003, "SAF_00"),
    (620012, "SAF_01"),
    (620009, "SAF_02"),
    (620013, "SAF_03"),
    (600420, "SAF_03"),
    (600121, "SAF_03"),
    (600100, "SAF_03"),
    (600300, "SAF_03"),
    (600307, "SAF_03"),
    (600306, "SAF_03"),
    (600403, "SAF_03"),
    (600112, "SAF_03"),
    (600701, "SAF_03"),
    (600702, "SAF_03"),
    (600413, "SAF_03"),
    (600415, "SAF_03"),
    (600116, "SAF_03"),
    (600303, "SAF_03"),
    (600201, "SAF_03"),
    (600120, "SAF_03"),
    (600410, "SAF_03"),
    (600304, "SAF_03"),
    (600202, "SAF_03"),
    (600118, "SAF_03"),
    (600411, "SAF_03"),
    (600113, "SAF_03"),
    (600405, "SAF_03"),
    (600406, "SAF_03"),
    (600301, "SAF_03"),
    (600117, "SAF_03"),
    (600101, "SAF_03"),
    (600106, "SAF_03"),
    (600104, "SAF_03"),
    (600302, "SAF_03"),
    (600200, "SAF_03"),
    (600402, "SAF_03"),
    (600102, "SAF_03"),
    (600009, "SAF_03"),
    (600110, "SAF_03"),
    (600111, "SAF_03"),
    (600107, "SAF_03"),
    (620016, "SAF_03"),
    (600417, "SAF_03"),
    (600501, "SAF_03"),
    (600002, "SAF_04"),
    (200301, "SAF_05"),
    (600105, "SAF_06"),
    (201101, "SAF_08"),
    (200115, "SAF_09"),
    (200111, "SAF_09"),
    (200118, "SAF_09"),
    (401200, "SAF_11"),
    (420501, "SAF_11"),
    (200100, "SAF_12"),
    (200101, "SAF_12"),
    (200116, "SAF_12"),
    (200200, "SAF_12"),
    (200400, "SAF_12"),
    (200401, "SAF_12"),
    (220004, "SAF_12"),
    (600010, "SAF_13"),
    (600414, "SAF_13"),
    (600416, "SAF_13"),
    (600305, "SAF_13"),
    (600203, "SAF_13"),
    (600119, "SAF_13"),
    (600412, "SAF_13"),
    (200701, "SAF_14"),
    (220002, "SAF_15"),
    (220003, "SAF_16"),
    (401100, "SAF_16"),
    (401101, "SAF_16"),
    (401102, "SAF_16"),
    (401104, "SAF_16"),
    (401103, "SAF_16"),
    (401105, "SAF_16"),
    (501009, "SAF_17"),
    (200114, "SAF_18"),
    (501001, "SAF_19"),
    (502001, "SAF_19"),
    (504001, "SAF_19"),
    (200412, "SAF_20"),
    (620011, "SAF_21"),
    (501008, "SAF_23"),
    (200601, "SAF_25"),
    (401501, "SAF_26"),
    (401701, "SAF_26"),
    (200410, "SAF_27"),
    (200411, "SAF_27"),
    (300701, "SAF_27"),
    (300702, "SAF_27"),
    (510005, "SAF_28"),
    (510002, "SAF_29"),
    (501002, "SAF_30"),
    (501006, "SAF_31"),
    (510008, "SAF_32"),
    (212004, "SAF_33"),
    (212005, "SAF_33"),
    (212003, "SAF_34"),
    (212007, "SAF_35"),
    (510009, "SAF_38"),
    (500002, "SAF_39"),
    (500005, "SAF_41"),
    (501010, "SAF_43"),
    (510001, "SAF_44"),
    (220001, "SAF_45"),
    (620010, "SAF_46"),
    (200110, "SAF_51"),
    (511003, "SAF_52"),
    (511004, "SAF_52"),
    (200115, "SAF_03"),
    (200201, "SAF_03"),
    (200413, "SAF_03"),
    (200600, "SAF_03"),
    (200305, "SAF_03"),
    (420502, "SAF_03"),
];

/// Código antiguo (`SAF_xx` o `CANCEL`) asociado a un código de error.
pub fn legacy_error_code(code: &ErrorCode) -> &'static str {
    OLD_ERRORS_ASSOCIATION
        .iter()
        .rev()
        .find(|(c, _)| *c == code.code)
        .map(|(_, s)| *s)
        .unwrap_or(ERROR_UNKNOWN)
}

/// Mensaje de un código antiguo.
pub fn legacy_message(saf: &str) -> Option<&'static str> {
    SAF_MESSAGES.iter().find(|(k, _)| *k == saf).map(|(_, v)| *v)
}

/// Respuesta de error para la web (`getErrorMessage`). `supports_error_codes`
/// indica si la versión del protocolo es ≥ 4.1
/// ([`crate::protocol_version::ProtocolVersion::supports_error_codes`]).
pub fn protocol_error_message(code: &ErrorCode, supports_error_codes: bool) -> String {
    if supports_error_codes {
        let prefix = if code.code == super::codes::CANCELLED_OPERATION.code {
            CANCELLATION_ERROR_PREFIX
        } else {
            DEFAULT_ERROR_PREFIX
        };
        format!("{prefix}AF{} - {}", code.code_str(), code.description)
    } else {
        let saf = legacy_error_code(code);
        if saf == CANCEL_RESPONSE {
            saf.to_string()
        } else {
            format!("{saf}: {}", legacy_message(saf).unwrap_or(""))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::codes;

    #[test]
    fn new_protocol() {
        assert_eq!(
            protocol_error_message(&codes::UNSUPPORTED_SIGNATURE_FORMAT, true),
            "err-00:=AF600105 - El formato de firma indicado en la operacion de firma no esta soportado"
        );
        assert_eq!(
            protocol_error_message(&codes::CANCELLED_OPERATION, true),
            format!("err-11:=AF500001 - {}", codes::CANCELLED_OPERATION.description)
        );
    }

    #[test]
    fn legacy_protocol() {
        assert_eq!(protocol_error_message(&codes::CANCELLED_OPERATION, false), "CANCEL");
        assert_eq!(
            protocol_error_message(&codes::LOADING_DATA_ERROR, false),
            "SAF_00: No se han podido leer los datos a firmar"
        );
        assert_eq!(
            protocol_error_message(&codes::UNSUPPORTED_SIGNATURE_FORMAT, false),
            "SAF_06: Formato de firma no soportado"
        );
        // La última inserción gana: 200115 → SAF_03.
        assert_eq!(
            protocol_error_message(&codes::UNKNOWN_SIGNING_ERROR, false),
            "SAF_03: Error en los parámetros de entrada"
        );
        // 200118 está en SAF_09 por ser el mismo número que UNKNOWN_SIGNING_BY_SOCKETS_ERROR.
        assert_eq!(legacy_error_code(&codes::UNSUPPORTED_HASH_ALGORITHM), "SAF_09");
        // 501001 (CERTIFICATE_NEEDED) comparte número con NO_CERTS_FOUND_SIGNING.
        assert_eq!(legacy_error_code(&codes::CERTIFICATE_NEEDED), "SAF_19");
        assert_eq!(
            protocol_error_message(&codes::SMARTCARD_LOCKED, false),
            "SAF_52: El almacen de claves esta bloqueado"
        );
        assert_eq!(
            protocol_error_message(&codes::PRESIGN_HTTP_ERROR, false),
            "SAF_53: Error desconocido"
        );
        assert_eq!(legacy_message("SAF_48"), Some("!ProtocolLauncher.63!"));
        // Todos los códigos asociados existen en la tabla general.
        for (c, saf) in OLD_ERRORS_ASSOCIATION {
            assert!(codes::by_code(*c).is_some(), "{c}");
            assert!(legacy_message(saf).is_some(), "{saf}");
        }
    }
}
