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

    /// Ficheros `.rs` de un directorio (recursivo).
    fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("directorio de fuentes")
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                rust_sources(&p, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }

    /// Interpreta un literal de cadena de Rust (`chars[0]` es la comilla) como
    /// lo hace el compilador: escapes y continuación de línea con `\` (que
    /// elimina el salto y los espacios iniciales de la línea siguiente).
    /// Devuelve el valor y el número de caracteres consumidos.
    fn parse_literal(chars: &[char]) -> (String, usize) {
        let mut out = String::new();
        let mut i = 1;
        while i < chars.len() {
            match chars[i] {
                '"' => return (out, i + 1),
                '\\' => {
                    i += 1;
                    match chars[i] {
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        '0' => out.push('\0'),
                        '\\' => out.push('\\'),
                        '"' => out.push('"'),
                        '\'' => out.push('\''),
                        'x' => {
                            let hex: String = chars[i + 1..i + 3].iter().collect();
                            out.push(char::from(u8::from_str_radix(&hex, 16).expect("escape \\x")));
                            i += 2;
                        }
                        'u' => {
                            let end = i + chars[i..].iter().position(|&c| c == '}').expect("escape \\u{…}");
                            let hex: String = chars[i + 2..end].iter().collect();
                            out.push(
                                char::from_u32(u32::from_str_radix(&hex, 16).expect("escape \\u")).expect("carácter"),
                            );
                            i = end;
                        }
                        '\n' | '\r' => {
                            while i + 1 < chars.len() && chars[i + 1].is_whitespace() {
                                i += 1;
                            }
                        }
                        c => panic!("escape desconocido \\{c}"),
                    }
                }
                c => out.push(c),
            }
            i += 1;
        }
        panic!("literal sin cerrar");
    }

    /// Recorre el código de `src` y devuelve las claves pasadas a `tr(`/`trf(`
    /// (con el lugar donde se usan) y las llamadas cuyo primer argumento no
    /// es un literal (no se podrían comprobar).
    fn used_keys() -> (std::collections::BTreeMap<String, String>, Vec<String>) {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_sources(&root, &mut files);
        let mut keys = std::collections::BTreeMap::new();
        let mut dynamic = Vec::new();
        for path in files {
            // El propio mecanismo (definiciones y pruebas) no cuenta.
            if path.ends_with("i18n.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("fuente legible");
            let c: Vec<char> = src.chars().collect();
            let name = path.strip_prefix(&root).unwrap_or(&path).display().to_string();
            let line_at = |pos: usize| c[..pos].iter().filter(|&&ch| ch == '\n').count() + 1;
            let mut i = 0;
            while i < c.len() {
                let ch = c[i];
                if ch == '/' && c.get(i + 1) == Some(&'/') {
                    while i < c.len() && c[i] != '\n' {
                        i += 1;
                    }
                } else if ch == '/' && c.get(i + 1) == Some(&'*') {
                    i += 2;
                    while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                        i += 1;
                    }
                    i += 2;
                } else if ch == '"' {
                    i += parse_literal(&c[i..]).1;
                } else if ch == '\'' {
                    // Carácter (`'a'`, `'\n'`) o tiempo de vida (`'static`).
                    if c.get(i + 1) == Some(&'\\') {
                        i += 3;
                        while c[i] != '\'' {
                            i += 1;
                        }
                        i += 1;
                    } else if c.get(i + 2) == Some(&'\'') {
                        i += 3;
                    } else {
                        i += 1;
                    }
                } else if ch.is_alphabetic() || ch == '_' {
                    let start = i;
                    while i < c.len() && (c[i].is_alphanumeric() || c[i] == '_') {
                        i += 1;
                    }
                    let ident: String = c[start..i].iter().collect();
                    let hashes = c[i..].iter().take_while(|&&h| h == '#').count();
                    if matches!(ident.as_str(), "r" | "br") && c.get(i + hashes) == Some(&'"') {
                        // Cadena sin escapes: r"…", r#"…"#.
                        i += hashes + 1;
                        while !(c[i] == '"' && c[i + 1..].iter().take(hashes).filter(|&&h| h == '#').count() == hashes)
                        {
                            i += 1;
                        }
                        i += 1 + hashes;
                    } else if ident == "b" && c.get(i) == Some(&'"') {
                        i += parse_literal(&c[i..]).1;
                    } else if ident == "tr" || ident == "trf" {
                        let mut j = i;
                        while j < c.len() && c[j].is_whitespace() {
                            j += 1;
                        }
                        if c.get(j) != Some(&'(') {
                            continue;
                        }
                        j += 1;
                        while j < c.len() && c[j].is_whitespace() {
                            j += 1;
                        }
                        if c.get(j) == Some(&'"') {
                            let (key, len) = parse_literal(&c[j..]);
                            keys.entry(key).or_insert_with(|| format!("{name}:{}", line_at(start)));
                            i = j + len;
                        } else {
                            dynamic.push(format!("{name}:{}", line_at(start)));
                        }
                    }
                } else {
                    i += 1;
                }
            }
        }
        (keys, dynamic)
    }

    /// Marcadores que deben conservarse al traducir: `{0}`, `{1}`... y los
    /// de la firma visible (`$$SUBJECTCN$$`...).
    fn markers(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (i, _) in text.match_indices('{') {
            if let Some(end) = text[i..].find('}') {
                out.push(text[i..=i + end].to_string());
            }
        }
        let mut rest = text;
        while let Some(start) = rest.find("$$") {
            let Some(len) = rest[start + 2..].find("$$") else { break };
            out.push(rest[start..start + len + 4].to_string());
            rest = &rest[start + len + 4..];
        }
        out.sort();
        out
    }

    /// Todos los textos traducibles de la interfaz están en todos los
    /// catálogos (y los catálogos no tienen entradas que ya no se usan).
    #[test]
    fn catalogs_are_complete() {
        let (keys, dynamic) = used_keys();
        assert!(
            dynamic.is_empty(),
            "llamadas a tr/trf sin un literal (no se pueden comprobar): {dynamic:?}"
        );
        assert!(
            keys.len() > 100,
            "no se han encontrado los textos de la interfaz ({})",
            keys.len()
        );
        let mut problems = Vec::new();
        for (key, place) in &keys {
            if key.contains(" = ") || key.trim() != key || key.is_empty() || key.starts_with('#') {
                problems.push(format!("{place}: clave no representable en el catálogo: «{key}»"));
            }
        }
        for (code, _) in LANGUAGES {
            let Some(src) = catalog_source(code) else { continue };
            let catalog = parse_catalog(src);
            let mut seen = std::collections::HashSet::new();
            for line in src.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                match line.split_once(" = ") {
                    Some((k, _)) if !seen.insert(k.trim()) => problems.push(format!("{code}: clave repetida «{k}»")),
                    Some(_) => {}
                    None => problems.push(format!("{code}: línea sin « = »: «{line}»")),
                }
            }
            for (key, place) in &keys {
                match catalog.get(key.as_str()) {
                    None => problems.push(format!("{code}: falta «{}» ({place})", key.replace('\n', "\\n"))),
                    Some(&"") => problems.push(format!("{code}: traducción vacía de «{key}»")),
                    Some(v) if markers(key) != markers(v) => {
                        problems.push(format!("{code}: marcadores distintos en «{key}» → «{v}»"))
                    }
                    Some(_) => {}
                }
            }
            for k in catalog.keys() {
                if !keys.contains_key(*k) {
                    problems.push(format!("{code}: entrada que no se usa «{}»", k.replace('\n', "\\n")));
                }
            }
        }
        assert!(
            problems.is_empty(),
            "{} problemas en los catálogos:\n{}",
            problems.len(),
            problems.join("\n")
        );
    }

    #[test]
    fn source_literals_are_parsed_like_rustc() {
        let parse = |s: &str| parse_literal(&s.chars().collect::<Vec<_>>()).0;
        assert_eq!(parse("\"a \\\"b\\\" c\""), "a \"b\" c");
        assert_eq!(parse("\"uno\\ndos\""), "uno\ndos");
        assert_eq!(parse("\"uno \\\n     dos\""), "uno dos");
        assert_eq!(parse("\"\\u{e9}\\x41\""), "éA");
        assert_eq!(
            "uno \
                    dos",
            "uno dos"
        );
        assert_eq!(markers("Hola {0} y {1} $$SUBJECTCN$$"), ["$$SUBJECTCN$$", "{0}", "{1}"]);
    }
}
