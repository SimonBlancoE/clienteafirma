//! Textos localizados del protocolo (`protocolmessages_*.properties` de
//! afirma-simple, copiados sin cambios en `resources/protocolmessages`).
//!
//! Se usan para los errores en formato antiguo (`SAF_NN: <texto>`, protocolo
//! anterior a 4.1) y para los textos de los diálogos de error.

use std::collections::HashMap;
use std::sync::OnceLock;

use afirma_core::ExtraParams;

/// Idioma de los mensajes de la aplicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Locale {
    /// `es_ES` (por defecto).
    #[default]
    Es,
    /// `en_US`.
    En,
    /// `ca_ES`.
    Ca,
    /// `gl_ES`.
    Gl,
    /// `eu_ES`.
    Eu,
    /// `va_ES`.
    Va,
}

impl Locale {
    /// Interpreta un identificador de idioma (`es_ES`, `en`, `ca-ES`...).
    /// Los idiomas no soportados devuelven `None`.
    pub fn parse(tag: &str) -> Option<Locale> {
        let lang = tag.split(['_', '-', '.']).next().unwrap_or("").to_ascii_lowercase();
        match lang.as_str() {
            "es" => Some(Locale::Es),
            "en" => Some(Locale::En),
            "ca" => Some(Locale::Ca),
            "gl" => Some(Locale::Gl),
            "eu" => Some(Locale::Eu),
            "va" => Some(Locale::Va),
            _ => None,
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Locale::Es => "es_ES",
            Locale::En => "en_US",
            Locale::Ca => "ca_ES",
            Locale::Gl => "gl_ES",
            Locale::Eu => "eu_ES",
            Locale::Va => "va_ES",
        }
    }

    fn source(self) -> &'static [u8] {
        match self {
            Locale::Es => include_bytes!("../resources/protocolmessages/protocolmessages_es_ES.properties"),
            Locale::En => include_bytes!("../resources/protocolmessages/protocolmessages_en_US.properties"),
            Locale::Ca => include_bytes!("../resources/protocolmessages/protocolmessages_ca_ES.properties"),
            Locale::Gl => include_bytes!("../resources/protocolmessages/protocolmessages_gl_ES.properties"),
            Locale::Eu => include_bytes!("../resources/protocolmessages/protocolmessages_eu_ES.properties"),
            Locale::Va => include_bytes!("../resources/protocolmessages/protocolmessages_va_ES.properties"),
        }
    }
}

fn bundles() -> &'static HashMap<Locale, ExtraParams> {
    static BUNDLES: OnceLock<HashMap<Locale, ExtraParams>> = OnceLock::new();
    BUNDLES.get_or_init(|| {
        [Locale::Es, Locale::En, Locale::Ca, Locale::Gl, Locale::Eu, Locale::Va]
            .into_iter()
            .map(|l| (l, ExtraParams::parse_bytes(l.source())))
            .collect()
    })
}

/// Texto de la clave o `None` si no existe en el idioma.
pub fn lookup(locale: Locale, key: &str) -> Option<&'static str> {
    bundles().get(&locale).and_then(|b| b.get(key))
}

/// `ProtocolMessages.getString(key)`: el texto o `!key!` si falta.
pub fn get(locale: Locale, key: &str) -> String {
    lookup(locale, key).map(str::to_string).unwrap_or_else(|| format!("!{key}!"))
}

/// `ProtocolMessages.getString(key, params...)`: sustituye `%0`, `%1`...
pub fn get_with(locale: Locale, key: &str, params: &[&str]) -> String {
    let mut text = get(locale, key);
    for (i, p) in params.iter().enumerate() {
        text = text.replace(&format!("%{i}"), p);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_load() {
        assert_eq!(get(Locale::Es, "ProtocolLauncher.69"), "Error desconocido");
        assert_eq!(get(Locale::En, "ProtocolLauncher.69"), "Unknown error");
        assert_eq!(
            get(Locale::Es, "ProtocolLauncher.21"),
            "La versión de Autofirma instalada no es compatible con este trámite.\nActualice a la última versión disponible."
        );
        assert_eq!(get(Locale::Es, "ProtocolLauncher.63"), "!ProtocolLauncher.63!");
        assert_eq!(get_with(Locale::Es, "ProtocolLauncher.29", &["AF600105"]), "Error AF600105");
        // Todos los idiomas cargan la clave genérica.
        for l in [Locale::Ca, Locale::Gl, Locale::Eu, Locale::Va] {
            assert!(lookup(l, "ProtocolLauncher.3").is_some(), "{l:?}");
        }
        assert_eq!(Locale::parse("en_US"), Some(Locale::En));
        assert_eq!(Locale::parse("fr"), None);
    }
}
