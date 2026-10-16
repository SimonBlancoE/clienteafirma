//! Traducciones de la interfaz.
//!
//! Los textos se escriben en español en el código y se traducen con [`tr`],
//! que busca el texto en el catálogo del idioma activo (estilo gettext: la
//! clave es el propio texto en español). Los catálogos son ficheros
//! `locales/<idioma>.txt` incrustados en el ejecutable, con líneas
//! `texto en español = traducción` (`#` para comentarios; `\n` para saltos de
//! línea). Idiomas: los mismos que AutoFirma (`es_ES`, `ca_ES`, `gl_ES`,
//! `eu_ES`, `va_ES`, `en_US`).

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Idiomas disponibles: (código de AutoFirma, nombre nativo).
pub const LANGUAGES: [(&str, &str); 6] = [
    ("es_ES", "Español"),
    ("ca_ES", "Català"),
    ("gl_ES", "Galego"),
    ("eu_ES", "Euskara"),
    ("va_ES", "Valencià"),
    ("en_US", "English"),
];

fn catalog_source(locale: &str) -> Option<&'static str> {
    match locale {
        "ca_ES" => Some(include_str!("../locales/ca_ES.txt")),
        "gl_ES" => Some(include_str!("../locales/gl_ES.txt")),
        "eu_ES" => Some(include_str!("../locales/eu_ES.txt")),
        "va_ES" => Some(include_str!("../locales/va_ES.txt")),
        "en_US" => Some(include_str!("../locales/en_US.txt")),
        _ => None,
    }
}

type Catalog = HashMap<&'static str, &'static str>;

fn parse_catalog(src: &'static str) -> Catalog {
    let mut map = HashMap::new();
    for line in src.lines() {
        let line = line.trim_end();
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(" = ") {
            // Los saltos de línea se escriben como \n en el catálogo.
            let k: &'static str = Box::leak(k.trim().replace("\\n", "\n").into_boxed_str());
            let v: &'static str = Box::leak(v.trim().replace("\\n", "\n").into_boxed_str());
            map.insert(k, v);
        }
    }
    map
}

fn state() -> &'static RwLock<(String, Option<Catalog>)> {
    static STATE: OnceLock<RwLock<(String, Option<Catalog>)>> = OnceLock::new();
    STATE.get_or_init(|| RwLock::new(("es_ES".into(), None)))
}

/// Cambia el idioma activo (`es_ES`, `ca_ES`...). Los códigos desconocidos
/// dejan el español.
pub fn set_locale(locale: &str) {
    let catalog = catalog_source(locale).map(parse_catalog);
    if let Ok(mut s) = state().write() {
        *s = (locale.to_string(), catalog);
    }
}

/// Idioma activo.
pub fn locale() -> String {
    state().read().map(|s| s.0.clone()).unwrap_or_else(|_| "es_ES".into())
}

/// Idioma del sistema convertido a un código de AutoFirma.
pub fn system_locale() -> &'static str {
    let lang = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default()
        .to_lowercase();
    if lang.starts_with("ca") {
        if lang.contains("valencia") { "va_ES" } else { "ca_ES" }
    } else if lang.starts_with("gl") {
        "gl_ES"
    } else if lang.starts_with("eu") {
        "eu_ES"
    } else if lang.starts_with("en") {
        "en_US"
    } else {
        "es_ES"
    }
}

/// Traduce un texto (en español) al idioma activo.
pub fn tr(text: &'static str) -> &'static str {
    match state().read() {
        Ok(s) => s.1.as_ref().and_then(|c| c.get(text).copied()).unwrap_or(text),
        Err(_) => text,
    }
}

/// Traduce y sustituye `{0}`, `{1}`... por los argumentos.
pub fn trf(text: &'static str, args: &[&dyn std::fmt::Display]) -> String {
    let mut out = tr(text).to_string();
    for (i, a) in args.iter().enumerate() {
        out = out.replace(&format!("{{{i}}}"), &a.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_parse_and_translate() {
        for (code, _) in LANGUAGES {
            if let Some(src) = catalog_source(code) {
                let c = parse_catalog(src);
                for (k, v) in &c {
                    // Los marcadores {0}, {1}... deben conservarse.
                    for i in 0..5 {
                        let m = format!("{{{i}}}");
                        assert_eq!(k.contains(&m), v.contains(&m), "{code}: «{k}» → «{v}»");
                    }
                }
            }
        }
        set_locale("en_US");
        assert_eq!(tr("Firmar"), "Sign");
        assert_eq!(trf("Firmar {0} documentos", &[&3]), "Sign 3 documents");
        set_locale("es_ES");
        assert_eq!(tr("Firmar"), "Firmar");
    }
}
