//! Textos de la interfaz en los seis idiomas de Autofirma App 1.9.
//!
//! Los catálogos son los ficheros `locales/<idioma>.txt`, incrustados en la biblioteca, con
//! líneas `clave = texto` (`#` para comentarios, `\n` para los saltos de línea y `{0}`,
//! `{1}`… para los datos). Las claves son las de `res/values*/strings.xml` de la app original
//! (`docs/spec/09-android.md` §9), así que un texto se busca por la misma clave que cita la
//! especificación; a partir de la línea `# [autofirma-rs]` vienen los textos propios de esta
//! aplicación. Es el mismo formato de catálogo que el de la aplicación de escritorio
//! (`crates/autofirma/locales`), pero con claves en lugar del texto en español, porque la
//! fuente de los textos son los recursos de Android y no el código.
//!
//! El idioma activo es global (la interfaz tiene un único hilo): [`set_language`] lo cambia
//! y la siguiente pasada de egui ya dibuja con él. Si falta una clave en un idioma se usa la
//! española (no debería pasar: lo comprueba la prueba `catalogos_completos`).

use std::collections::HashMap;
use std::fmt::Display;
use std::sync::{OnceLock, PoisonError, RwLock};

/// Idiomas de la interfaz, en el orden de la lista de la pantalla «Idioma» del original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Language {
    #[default]
    Es,
    En,
    Ca,
    Gl,
    Eu,
    CaValencia,
}

impl Language {
    pub const ALL: [Language; 6] = [
        Language::Es,
        Language::En,
        Language::Ca,
        Language::Gl,
        Language::Eu,
        Language::CaValencia,
    ];

    /// Etiqueta que guarda la preferencia `localeConfig` (la misma que el original).
    pub fn tag(self) -> &'static str {
        match self {
            Language::Es => "es",
            Language::En => "en",
            Language::Ca => "ca",
            Language::Gl => "gl",
            Language::Eu => "eu",
            Language::CaValencia => "ca-ES-valencia",
        }
    }

    /// Idioma de una etiqueta guardada (`localeConfig`).
    pub fn from_tag(tag: &str) -> Option<Language> {
        Language::ALL.into_iter().find(|l| l.tag().eq_ignore_ascii_case(tag))
    }

    /// Idioma de la interfaz para el idioma del sistema (etiqueta BCP 47 de
    /// `Locale.toLanguageTag()`, p. ej. `ca-ES-valencia`, `gl-ES`, `en-GB`). Como en el
    /// original, un idioma sin traducción usa el español (los recursos de `values`).
    pub fn from_system_tag(tag: &str) -> Language {
        let tag = tag.to_ascii_lowercase().replace('_', "-");
        let mut parts = tag.split('-');
        match parts.next().unwrap_or_default() {
            "ca" if tag.split('-').any(|p| p == "valencia") => Language::CaValencia,
            "ca" => Language::Ca,
            "gl" => Language::Gl,
            "eu" => Language::Eu,
            "en" => Language::En,
            _ => Language::Es,
        }
    }

    /// Abreviatura que muestra Ajustes junto a «Idioma» (§2.6).
    pub fn abbreviation(self) -> &'static str {
        match self {
            Language::Es => "ES",
            Language::En => "EN",
            Language::Ca => "CA",
            Language::Gl => "GL",
            Language::Eu => "EU",
            Language::CaValencia => "VA",
        }
    }

    /// Nombre del idioma en ese mismo idioma (clave del catálogo; es igual en todos).
    pub fn name_key(self) -> &'static str {
        match self {
            Language::Es => "espanol",
            Language::En => "english",
            Language::Ca => "catala",
            Language::Gl => "galego",
            Language::Eu => "euskera",
            Language::CaValencia => "valenciano",
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    fn source(self) -> &'static str {
        match self {
            Language::Es => include_str!("../locales/es.txt"),
            Language::En => include_str!("../locales/en.txt"),
            Language::Ca => include_str!("../locales/ca.txt"),
            Language::Gl => include_str!("../locales/gl.txt"),
            Language::Eu => include_str!("../locales/eu.txt"),
            Language::CaValencia => include_str!("../locales/ca-valencia.txt"),
        }
    }
}

/// Línea que separa los textos del original de los propios.
const OWN_SECTION: &str = "# [autofirma-rs]";

type Catalog = HashMap<&'static str, &'static str>;

/// Entradas de un catálogo: (clave, texto, es propia de esta aplicación).
fn entries(src: &'static str) -> impl Iterator<Item = (&'static str, String, bool)> {
    let mut own = false;
    src.lines().filter_map(move |line| {
        let line = line.trim_end();
        if line == OWN_SECTION {
            own = true;
        }
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            return None;
        }
        let (key, value) = line.split_once(" = ")?;
        Some((key.trim(), value.trim().replace("\\n", "\n"), own))
    })
}

fn catalog(language: Language) -> &'static Catalog {
    static CATALOGS: [OnceLock<Catalog>; 6] = [const { OnceLock::new() }; 6];
    CATALOGS[language.index()].get_or_init(|| {
        entries(language.source())
            .map(|(key, value, _)| (key, &*Box::leak(value.into_boxed_str())))
            .collect()
    })
}

fn current() -> &'static RwLock<Language> {
    static CURRENT: RwLock<Language> = RwLock::new(Language::Es);
    &CURRENT
}

/// Cambia el idioma de la interfaz.
pub fn set_language(language: Language) {
    *current().write().unwrap_or_else(PoisonError::into_inner) = language;
}

/// Idioma de la interfaz.
pub fn language() -> Language {
    *current().read().unwrap_or_else(PoisonError::into_inner)
}

/// Texto de una clave en el idioma activo.
pub fn tr(key: &'static str) -> &'static str {
    tr_in(language(), key)
}

/// Texto de una clave en un idioma concreto.
pub fn tr_in(language: Language, key: &'static str) -> &'static str {
    catalog(language)
        .get(key)
        .or_else(|| catalog(Language::Es).get(key))
        .copied()
        .unwrap_or(key)
}

/// Texto de una clave con `{0}`, `{1}`… sustituidos por los argumentos.
pub fn trf(key: &'static str, args: &[&dyn Display]) -> String {
    let mut out = tr(key).to_string();
    for (i, arg) in args.iter().enumerate() {
        out = out.replace(&format!("{{{i}}}"), &arg.to_string());
    }
    out
}

/// Cerrojo para las pruebas que cambian el idioma o dependen de él (el idioma es global y
/// las pruebas se ejecutan en paralelo).
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

    use super::*;

    /// Número de claves de `res/values/strings.xml` de Autofirma App 1.9.
    const ORIGINAL_KEYS: usize = 272;

    #[test]
    fn idiomas_y_etiquetas() {
        for l in Language::ALL {
            assert_eq!(Language::from_tag(l.tag()), Some(l));
        }
        assert_eq!(Language::from_system_tag("ca-ES-valencia"), Language::CaValencia);
        assert_eq!(Language::from_system_tag("ca-ES"), Language::Ca);
        assert_eq!(Language::from_system_tag("gl_ES"), Language::Gl);
        assert_eq!(Language::from_system_tag("eu"), Language::Eu);
        assert_eq!(Language::from_system_tag("en-GB"), Language::En);
        assert_eq!(Language::from_system_tag("fr-FR"), Language::Es);
        assert_eq!(Language::from_system_tag(""), Language::Es);
        assert_eq!(Language::CaValencia.abbreviation(), "VA");
    }

    #[test]
    fn traduce_y_sustituye() {
        let _lock = test_lock();
        set_language(Language::En);
        assert_eq!(tr("sign_file"), "Sign local file");
        assert_eq!(trf("appversion", &[&"2.0"]), "Version v2.0");
        set_language(Language::Gl);
        assert_eq!(tr("operation_cancelled"), "Operación cancelada");
        assert_eq!(tr("app_name"), "AutoFirma");
        set_language(Language::Es);
        assert_eq!(tr("sign_file"), "Firmar fichero");
        assert_eq!(tr("clave_que_no_existe"), "clave_que_no_existe");
        assert_eq!(tr_in(Language::Eu, "app_name"), "AutoFirma");
        assert_eq!(tr_in(Language::Ca, "intro_title"), "Signatura fàcil i segura");
        assert!(tr("response_1").contains("\n\n"), "los <p> del original son párrafos");
    }

    /// Ficheros `.rs` de un directorio (recursivo).
    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .expect("directorio de fuentes")
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Claves que se usan en el código (`tr("…")`, `trf("…"`, `tr_in(…, "…")` y las que
    /// llegan por una variable, marcadas con `k!("…")`) con su posición, y las llamadas sin
    /// un literal (las que reciben una de esas claves marcadas).
    fn used_keys() -> (BTreeMap<String, String>, Vec<String>) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_sources(&root, &mut files);
        let mut keys = BTreeMap::new();
        let mut dynamic = Vec::new();
        for path in files {
            if path.ends_with("i18n.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("fuente legible");
            let name = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
            for (n, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                for call in ["tr(", "trf(", "tr_in(", "k!("] {
                    let mut rest = code;
                    while let Some(pos) = rest.find(call) {
                        let before = rest[..pos].chars().last();
                        rest = &rest[pos + call.len()..];
                        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                            continue; // otra función que acaba igual (p. ej. `str(`)
                        }
                        let arg = if call == "tr_in(" {
                            rest.split_once(',').map(|(_, a)| a).unwrap_or(rest)
                        } else {
                            rest
                        };
                        let arg = arg.trim_start();
                        match arg.strip_prefix('"').and_then(|a| a.split_once('"')) {
                            Some((key, _)) => {
                                keys.entry(key.to_string())
                                    .or_insert_with(|| format!("{name}:{}", n + 1));
                            }
                            None => dynamic.push(format!("{name}:{}", n + 1)),
                        }
                    }
                }
            }
        }
        (keys, dynamic)
    }

    fn placeholders(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (i, _) in text.match_indices('{') {
            if let Some(end) = text[i..].find('}') {
                out.insert(text[i..=i + end].to_string());
            }
        }
        let mut rest = text;
        while let Some(start) = rest.find("$$") {
            let Some(len) = rest[start + 2..].find("$$") else { break };
            out.insert(rest[start..start + len + 4].to_string());
            rest = &rest[start + len + 4..];
        }
        out
    }

    /// Los seis catálogos tienen las mismas claves (las 272 del original y las propias), sin
    /// textos vacíos ni marcadores distintos; todo texto que usa el código existe; y los
    /// textos propios se usan (los del original se conservan todos aunque algunos sean de
    /// fases posteriores).
    #[test]
    fn catalogos_completos() {
        let (used, dynamic) = used_keys();
        // Las llamadas con una variable reciben claves marcadas con k!(…), que sí se
        // comprueban; aquí solo se acota cuántas hay para que no crezcan sin control.
        assert!(
            dynamic.len() < 30,
            "demasiadas llamadas a tr/trf sin literal: {dynamic:?}"
        );
        assert!(
            used.len() > 80,
            "no se han encontrado los textos del código ({})",
            used.len()
        );
        let mut problems = Vec::new();
        let reference: Vec<_> = entries(Language::Es.source()).collect();
        let original = reference.iter().filter(|(_, _, own)| !own).count();
        if original != ORIGINAL_KEYS {
            problems.push(format!(
                "es: {original} claves del original, se esperaban {ORIGINAL_KEYS}"
            ));
        }
        for language in Language::ALL {
            let code = language.tag();
            let list: Vec<_> = entries(language.source()).collect();
            let mut seen = BTreeSet::new();
            for line in language.source().lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') && !line.contains(" = ") {
                    problems.push(format!("{code}: línea sin « = »: «{line}»"));
                }
            }
            for (key, value, _) in &list {
                if !seen.insert(*key) {
                    problems.push(format!("{code}: clave repetida «{key}»"));
                }
                if value.is_empty() {
                    problems.push(format!("{code}: texto vacío en «{key}»"));
                }
            }
            for (key, value, own) in &reference {
                match list.iter().find(|(k, _, _)| k == key) {
                    None => problems.push(format!("{code}: falta «{key}»")),
                    Some((_, text, other_own)) => {
                        if own != other_own {
                            problems.push(format!("{code}: «{key}» está en otra sección"));
                        }
                        if placeholders(value) != placeholders(text) {
                            problems.push(format!("{code}: marcadores distintos en «{key}»: «{text}»"));
                        }
                        if value.matches("**").count() % 2 != 0 || text.matches("**").count() % 2 != 0 {
                            problems.push(format!("{code}: negrita sin cerrar en «{key}»"));
                        }
                    }
                }
            }
            for (key, _, _) in &list {
                if !reference.iter().any(|(k, _, _)| k == key) {
                    problems.push(format!("{code}: clave que no está en español «{key}»"));
                }
            }
        }
        for (key, place) in &used {
            if !reference.iter().any(|(k, _, _)| k == key) {
                problems.push(format!("{place}: la clave «{key}» no está en los catálogos"));
            }
        }
        for (key, _, own) in &reference {
            if *own && !used.contains_key(*key) {
                problems.push(format!("texto propio que no se usa: «{key}»"));
            }
        }
        assert!(
            problems.is_empty(),
            "{} problemas en los catálogos:\n{}",
            problems.len(),
            problems.join("\n")
        );
    }
}
