//! Mensajes de la línea de comandos (`CommandLineMessages`) y textos de
//! validación (`ValidationMessages`) en los seis idiomas de AutoFirma.
//!
//! Los ficheros `.properties` de Java se incluyen tal cual (`i18n/`) y se
//! decodifican como lo hace `PropertyResourceBundle` (UTF-8 y, si no es
//! válido, ISO-8859-1, que es el caso del gallego).
//!
//! Diferencias con Java (ver `docs/deviations/afirma-cli.md`):
//! - una clave que falta en el idioma activo se toma del español en lugar de
//!   imprimir `!clave!` (los catálogos que no son el español carecen de
//!   `CommandLineLauncher.146`–`149`);
//! - un idioma no soportado (p. ej. `fr_FR` o `en_GB`) se asimila al de su
//!   lengua (`en_GB` → `en_US`) o, si no hay ninguno, al español, en lugar de
//!   imprimir `!clave!` en todos los mensajes;
//! - las entidades HTML de los textos de validación (`&oacute;`) se
//!   convierten en caracteres.

use std::sync::OnceLock;

use afirma_core::ExtraParams;
use afirma_core::validity::{SignValidity, Validity, ValidityError};

/// Idiomas con catálogo propio (`LanguageManager.AFIRMA_DEFAULT_LOCALES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// Español (`es_ES`), idioma por defecto.
    EsEs,
    /// Inglés (`en_US`).
    EnUs,
    /// Catalán (`ca_ES`).
    CaEs,
    /// Gallego (`gl_ES`).
    GlEs,
    /// Euskera (`eu_ES`).
    EuEs,
    /// Valenciano (`va_ES`).
    VaEs,
}

impl Language {
    /// Todos los idiomas.
    pub const ALL: [Language; 6] = [
        Self::EsEs,
        Self::EnUs,
        Self::CaEs,
        Self::GlEs,
        Self::EuEs,
        Self::VaEs,
    ];

    /// Código Java del idioma (`es_ES`...).
    pub fn code(self) -> &'static str {
        match self {
            Self::EsEs => "es_ES",
            Self::EnUs => "en_US",
            Self::CaEs => "ca_ES",
            Self::GlEs => "gl_ES",
            Self::EuEs => "eu_ES",
            Self::VaEs => "va_ES",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::EsEs => 0,
            Self::EnUs => 1,
            Self::CaEs => 2,
            Self::GlEs => 3,
            Self::EuEs => 4,
            Self::VaEs => 5,
        }
    }

    /// Idioma de un identificador de configuración regional (`es_ES`,
    /// `en-GB`, `ca_ES.UTF-8`, `ca_ES@valencia`, `gl`...). Devuelve `None` si
    /// la lengua no tiene catálogo (o el texto es `C`/`POSIX`/vacío).
    pub fn from_locale(locale: &str) -> Option<Language> {
        let raw = locale.trim();
        let (base, modifier) = match raw.split_once('@') {
            Some((b, m)) => (b, Some(m)),
            None => (raw, None),
        };
        let base = base.split('.').next().unwrap_or("").replace('-', "_");
        let mut parts = base.split('_');
        let lang = parts.next().unwrap_or("").to_ascii_lowercase();
        let rest: Vec<String> = parts.map(|p| p.to_ascii_lowercase()).collect();
        let valencia = modifier.is_some_and(|m| m.eq_ignore_ascii_case("valencia"))
            || rest.iter().any(|p| p == "valencia");
        match lang.as_str() {
            "es" => Some(Self::EsEs),
            "en" => Some(Self::EnUs),
            "ca" if valencia => Some(Self::VaEs),
            "ca" => Some(Self::CaEs),
            "gl" => Some(Self::GlEs),
            "eu" => Some(Self::EuEs),
            "va" => Some(Self::VaEs),
            _ => None,
        }
    }

    /// Idioma de la línea de comandos (`processCommandLine`): la preferencia
    /// `default.locale` si está definida y, si no, la del sistema. Si
    /// ninguna tiene catálogo, español.
    pub fn resolve(preference: Option<&str>, os_locale: Option<&str>) -> Language {
        let pref = preference.map(str::trim).filter(|p| !p.is_empty());
        match pref {
            Some(p) => Self::from_locale(p).unwrap_or(Self::EsEs),
            None => os_locale.and_then(Self::from_locale).unwrap_or(Self::EsEs),
        }
    }
}

/// Configuración regional del sistema según las variables de entorno POSIX
/// (`LC_ALL`, `LC_MESSAGES`, `LANG`), como hace la JVM en Unix. En Windows y
/// macOS la aplicación puede indicar la suya en [`crate::CliEnv::os_locale`].
pub fn os_locale_from_env() -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|v| v.trim().to_string())
        .find(|v| !v.is_empty() && v != "C" && v != "POSIX" && !v.starts_with("C."))
}

const CLI_BUNDLES: [&[u8]; 6] = [
    include_bytes!("../i18n/commandlinemessages_es_ES.properties"),
    include_bytes!("../i18n/commandlinemessages_en_US.properties"),
    include_bytes!("../i18n/commandlinemessages_ca_ES.properties"),
    include_bytes!("../i18n/commandlinemessages_gl_ES.properties"),
    include_bytes!("../i18n/commandlinemessages_eu_ES.properties"),
    include_bytes!("../i18n/commandlinemessages_va_ES.properties"),
];

const VALIDATION_BUNDLES: [&[u8]; 6] = [
    include_bytes!("../i18n/validationmessages_es_ES.properties"),
    include_bytes!("../i18n/validationmessages_en_US.properties"),
    include_bytes!("../i18n/validationmessages_ca_ES.properties"),
    include_bytes!("../i18n/validationmessages_gl_ES.properties"),
    include_bytes!("../i18n/validationmessages_eu_ES.properties"),
    include_bytes!("../i18n/validationmessages_va_ES.properties"),
];

fn bundle(
    cache: &'static [OnceLock<ExtraParams>; 6],
    sources: &[&[u8]; 6],
    lang: Language,
) -> &'static ExtraParams {
    cache[lang.index()].get_or_init(|| ExtraParams::parse_bytes(sources[lang.index()]))
}

fn cli_bundle(lang: Language) -> &'static ExtraParams {
    static CACHE: [OnceLock<ExtraParams>; 6] = [const { OnceLock::new() }; 6];
    bundle(&CACHE, &CLI_BUNDLES, lang)
}

fn validation_bundle(lang: Language) -> &'static ExtraParams {
    static CACHE: [OnceLock<ExtraParams>; 6] = [const { OnceLock::new() }; 6];
    bundle(&CACHE, &VALIDATION_BUNDLES, lang)
}

/// Sustituye `%0`, `%1`... literalmente (como `CommandLineMessages.getString(key, params)`).
pub fn substitute(text: &str, params: &[&str]) -> String {
    let mut out = text.to_string();
    for (i, p) in params.iter().enumerate() {
        out = out.replace(&format!("%{i}"), p);
    }
    out
}

/// Catálogo de mensajes de un idioma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Messages {
    lang: Language,
}

impl Messages {
    /// Catálogo del idioma indicado.
    pub fn new(lang: Language) -> Self {
        Messages { lang }
    }

    /// Idioma del catálogo.
    pub fn language(&self) -> Language {
        self.lang
    }

    /// Indica si el catálogo del idioma activo tiene la clave
    /// `CommandLineLauncher.<n>` (sin recurrir al español).
    pub fn has_own(&self, n: u32) -> bool {
        cli_bundle(self.lang).contains(&format!("CommandLineLauncher.{n}"))
    }

    /// Texto de `CommandLineLauncher.<n>`, con el español como respaldo.
    pub fn get(&self, n: u32) -> String {
        let key = format!("CommandLineLauncher.{n}");
        cli_bundle(self.lang)
            .get(&key)
            .or_else(|| cli_bundle(Language::EsEs).get(&key))
            .map(str::to_string)
            .unwrap_or_else(|| format!("!{key}!"))
    }

    /// Texto de `CommandLineLauncher.<n>` con los parámetros `%0`, `%1`...
    pub fn fmt(&self, n: u32, params: &[&str]) -> String {
        substitute(&self.get(n), params)
    }

    /// Texto de una clave de validación (`SignValidationMessage.<n>`), con las
    /// entidades HTML resueltas.
    pub fn validation(&self, n: u32) -> String {
        let key = format!("SignValidationMessage.{n}");
        let raw = validation_bundle(self.lang)
            .get(&key)
            .or_else(|| validation_bundle(Language::EsEs).get(&key))
            .unwrap_or("");
        decode_html_entities(raw)
    }

    /// `SignValidity.toString()`: `<estado>` o `<estado>: <detalle>`.
    pub fn validity_text(&self, v: &SignValidity) -> String {
        let status = self.validation(validity_index(v.validity));
        match v.error {
            Some(e) => format!("{status}: {}", self.validation(error_index(e))),
            None => status,
        }
    }
}

fn validity_index(v: Validity) -> u32 {
    match v {
        Validity::Ok | Validity::Generated => 0,
        Validity::Unknown => 1,
        Validity::PendingConfirmByUser => 2,
        Validity::Ko => 3,
    }
}

fn error_index(e: ValidityError) -> u32 {
    use ValidityError::*;
    match e {
        NoData => 4,
        CorruptedSign => 5,
        NoMatchData => 6,
        NoSign => 7,
        CertificateProblem => 8,
        CertificateExpired => 9,
        CertificateNotValidYet => 10,
        CantValidateCert => 11,
        AlgorithmNotSupported => 12,
        CaNotSupported => 13,
        CrlProblem => 14,
        PdfUnknownValidity => 15,
        OoxmlUnknownValidity => 16,
        OdfUnknownValidity => 17,
        UnknownError => 18,
        UnknownSignatureFormat => 19,
        ModifiedDocument => 20,
        OverlappingSignature => 21,
        ModifiedForm => 22,
        SuspectedSignature => 23,
        SignProfileNotChecked => 24,
        CantValidateExternallyDetached => 25,
        BadBuildSign => 26,
        CertifiedSignRevision => 27,
    }
}

/// Resuelve las entidades HTML con nombre y numéricas más habituales de los
/// catálogos de AutoFirma (`&oacute;`, `&ntilde;`, `&#233;`...). Las
/// desconocidas se dejan tal cual.
pub fn decode_html_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let decoded = after
            .find(';')
            .filter(|&end| end <= 10)
            .and_then(|end| entity(&after[..end]).map(|c| (c, end)));
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn entity(name: &str) -> Option<char> {
    if let Some(num) = name.strip_prefix('#') {
        let code = match num.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok()?,
            None => num.parse().ok()?,
        };
        return char::from_u32(code);
    }
    Some(match name {
        "aacute" => 'á',
        "eacute" => 'é',
        "iacute" => 'í',
        "oacute" => 'ó',
        "uacute" => 'ú',
        "Aacute" => 'Á',
        "Eacute" => 'É',
        "Iacute" => 'Í',
        "Oacute" => 'Ó',
        "Uacute" => 'Ú',
        "agrave" => 'à',
        "egrave" => 'è',
        "ograve" => 'ò',
        "Agrave" => 'À',
        "Egrave" => 'È',
        "Ograve" => 'Ò',
        "ntilde" => 'ñ',
        "Ntilde" => 'Ñ',
        "uuml" => 'ü',
        "Uuml" => 'Ü',
        "iuml" => 'ï',
        "ccedil" => 'ç',
        "Ccedil" => 'Ç',
        "middot" => '·',
        "ordf" => 'ª',
        "ordm" => 'º',
        "iexcl" => '¡',
        "iquest" => '¿',
        "nbsp" => '\u{a0}',
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seleccion_de_idioma() {
        assert_eq!(
            Language::resolve(Some("en_US"), Some("es_ES")),
            Language::EnUs
        );
        assert_eq!(Language::resolve(None, Some("ca_ES.UTF-8")), Language::CaEs);
        assert_eq!(
            Language::resolve(Some(""), Some("gl_ES@euro")),
            Language::GlEs
        );
        assert_eq!(
            Language::resolve(None, Some("ca_ES@valencia")),
            Language::VaEs
        );
        assert_eq!(
            Language::resolve(None, Some("ca-ES-valencia")),
            Language::VaEs
        );
        assert_eq!(Language::resolve(None, Some("en_GB")), Language::EnUs);
        assert_eq!(
            Language::resolve(Some("fr_FR"), Some("en_US")),
            Language::EsEs
        );
        assert_eq!(Language::resolve(None, None), Language::EsEs);
        assert_eq!(Language::resolve(None, Some("de_DE")), Language::EsEs);
        assert_eq!(Language::from_locale("eu"), Some(Language::EuEs));
        assert_eq!(Language::from_locale("va_ES"), Some(Language::VaEs));
    }

    #[test]
    fn catalogos() {
        let es = Messages::new(Language::EsEs);
        assert_eq!(es.get(22), "La operacion ha terminado correctamente ");
        assert_eq!(es.get(127), "Error en los parámetros de entrada");
        assert_eq!(es.fmt(15, &["foo"]), "Comando no reconocido: foo");
        let en = Messages::new(Language::EnUs);
        assert_eq!(en.get(34), "Document signing tool.");
        assert!(!en.has_own(146));
        // Respaldo en español en lugar de `!CommandLineLauncher.148!`.
        assert_eq!(
            en.fmt(148, &["x"]),
            "No se hay ninguna entrada en el almacen con el alias indicado: x"
        );
        // El gallego está en ISO-8859-1.
        let gl = Messages::new(Language::GlEs);
        assert_eq!(gl.get(11), "lista os alias dispoñibles no almacen");
        for l in Language::ALL {
            let m = Messages::new(l);
            for n in [0, 5, 7, 22, 30, 34, 140] {
                assert!(!m.get(n).starts_with('!'), "{l:?} {n}");
            }
        }
    }

    #[test]
    fn validez() {
        let es = Messages::new(Language::EsEs);
        assert_eq!(es.validity_text(&SignValidity::ok()), "Firma válida");
        assert_eq!(
            es.validity_text(&SignValidity::ko(ValidityError::CorruptedSign)),
            "Firma no válida: la información contenida en la firma no es consistente (certificados corruptos, etc.)"
        );
        // Mismos textos que afirma-core en español.
        for e in [
            ValidityError::NoSign,
            ValidityError::CertificateProblem,
            ValidityError::SignProfileNotChecked,
        ] {
            assert_eq!(
                es.validity_text(&SignValidity::ko(e)),
                SignValidity::ko(e).to_string()
            );
        }
        let en = Messages::new(Language::EnUs);
        assert_eq!(
            en.validity_text(&SignValidity::ko(ValidityError::NoSign)),
            "Invalid signature: No signature found within document"
        );
    }

    #[test]
    fn entidades() {
        assert_eq!(
            decode_html_entities("v&aacute;lido &amp; m&aacute;s &#233; &x; a&b"),
            "válido & más é &x; a&b"
        );
    }
}
