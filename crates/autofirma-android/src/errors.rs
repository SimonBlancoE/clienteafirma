//! Catálogo de errores de la aplicación (`docs/spec/09-android.md` §8.1): código `AA` de seis
//! cifras, texto para el usuario (en el idioma de la interfaz) y texto de administración (fijo,
//! en español, para el registro). Al usuario se muestra «AA<código> - <texto>»; al registro,
//! «AA<código> - <texto de administración>».
//!
//! Las categorías que intervienen en la firma y en las operaciones web son las de
//! `afirma_protocol::android::errors` (las mismas que se devuelven a la web); aquí se añaden
//! las que solo muestra la interfaz (dominios de confianza, importación de certificados y
//! DNIe) y el texto para el usuario sale de los catálogos de la aplicación por la clave de
//! `strings.xml`, en el idioma activo. El original regeneraba los textos al aplicar el idioma
//! y, en un proceso que no pasaba por una actividad con idioma, los tenía vacíos (§10 n.º 2).

pub use afirma_protocol::android::errors as web;

use crate::i18n::tr;

/// Texto «genérico» de la mayoría de los errores (`not_completed_request`).
const GENERIC: &str = k!("not_completed_request");

/// Un error del catálogo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCategory {
    /// Código de seis cifras (sin el prefijo `AA`).
    pub code: u32,
    /// Clave del texto para el usuario.
    pub user_key: &'static str,
    /// Texto de administración (registro).
    pub admin: &'static str,
}

impl From<web::ErrorCategory> for ErrorCategory {
    fn from(c: web::ErrorCategory) -> ErrorCategory {
        ErrorCategory {
            code: c.code,
            user_key: c.user_text.map_or(GENERIC, |t| t.key()),
            admin: c.admin_text,
        }
    }
}

impl ErrorCategory {
    const fn new(code: u32, user_key: &'static str, admin: &'static str) -> ErrorCategory {
        ErrorCategory { code, user_key, admin }
    }

    /// `AA200002`.
    pub fn code_str(&self) -> String {
        format!("AA{:06}", self.code)
    }

    /// Texto para el usuario: «AA<código> - <texto>».
    pub fn user_message(&self) -> String {
        format!("{} - {}", self.code_str(), tr(self.user_key))
    }

    /// Texto para el registro: «AA<código> - <texto de administración>».
    pub fn admin_message(&self) -> String {
        format!("{} - {}", self.code_str(), self.admin)
    }
}

/// Error del catálogo compartido con la firma web.
pub fn shared(c: web::ErrorCategory) -> ErrorCategory {
    c.into()
}

// Categorías que solo muestra la interfaz (afirma-protocol las deja a la aplicación).
pub const DOMAIN_FORMAT_INCORRECT: ErrorCategory = ErrorCategory::new(
    200700,
    k!("error_format_trusted_domains"),
    "Se han encontrado entradas no validas en el listado de dominios",
);
pub const LOAD_CERT_TO_IMPORT: ErrorCategory = ErrorCategory::new(
    201100,
    k!("cant_add_cert_message"),
    "Error en la carga de certificado para importar",
);

/// Categorías propias de la interfaz: las de arriba y las del DNIe (fase del DNIe por NFC).
pub const UI_ONLY: &[ErrorCategory] = &[
    DOMAIN_FORMAT_INCORRECT,
    LOAD_CERT_TO_IMPORT,
    ErrorCategory::new(
        300100,
        k!("unsupported_card"),
        "La tarjeta identificada en el lector es desconocida o no esta soportada",
    ),
    ErrorCategory::new(
        300102,
        k!("unsupported_card"),
        "No se ha podido conectar con la tarjeta",
    ),
    ErrorCategory::new(
        300103,
        k!("error_reading_dnie_try_again"),
        "La conexion con la tarjeta no esta inicializada",
    ),
    ErrorCategory::new(
        300104,
        k!("error_reading_dnie_try_again"),
        "Ocurrio un error inesperado durante la operacion",
    ),
    ErrorCategory::new(300105, k!("error_msc_pin"), "PIN incorrecto"),
    ErrorCategory::new(300106, k!("error_dni_blocked_dlg"), "Tarjeta bloqueada"),
    ErrorCategory::new(
        300108,
        k!("nfc_card_initializing_error"),
        "Error durante la validacion del CAN",
    ),
    ErrorCategory::new(
        300110,
        k!("error_reading_dnie_no_cert"),
        "No se dispone de certificado de firma digital",
    ),
];

/// Todas las categorías: las compartidas y las de la interfaz.
pub fn all() -> impl Iterator<Item = ErrorCategory> {
    web::CATEGORIES
        .iter()
        .copied()
        .map(shared)
        .chain(UI_ONLY.iter().copied())
}

/// Error del catálogo por su código.
pub fn by_code(code: u32) -> Option<ErrorCategory> {
    all().find(|c| c.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Language, set_language, test_lock};

    #[test]
    fn mensajes_con_codigo_y_texto_localizado() {
        let _lock = test_lock();
        set_language(Language::Es);
        let signing = shared(web::AA_ERROR_SIGNING);
        assert_eq!(
            signing.user_message(),
            "AA200002 - Hemos intentado procesar tu solicitud, pero no ha podido ser completada con éxito. Por favor revisa la documentación."
        );
        assert_eq!(signing.admin_message(), "AA200002 - Error durante la firma");
        assert!(
            shared(web::AA_OUT_OF_MEMORY)
                .user_message()
                .starts_with("AA200105 - El fichero seleccionado es demasiado grande")
        );
        set_language(Language::En);
        let english = LOAD_CERT_TO_IMPORT.user_message();
        assert!(english.starts_with("AA201100 - "));
        set_language(Language::Es);
        assert_ne!(LOAD_CERT_TO_IMPORT.user_message(), english);
    }

    #[test]
    fn catalogo_completo_sin_codigos_repetidos() {
        let mut codes: Vec<u32> = all().map(|c| c.code).collect();
        let len = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), len, "códigos repetidos");
        for code in [200000, 200002, 200102, 200105, 200301, 200700, 201100, 300106, 500001] {
            assert!(by_code(code).is_some(), "falta AA{code}");
        }
        assert_eq!(by_code(1), None);
        // Cada texto de usuario existe en los catálogos de la aplicación.
        for c in all() {
            assert_ne!(tr(c.user_key), c.user_key, "sin texto: {}", c.user_key);
        }
    }
}
