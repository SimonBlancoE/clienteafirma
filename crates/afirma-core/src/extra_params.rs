//! Parámetros adicionales de las operaciones de firma (`extraParams`).
//!
//! En AutoFirma los parámetros adicionales son un `java.util.Properties`.
//! Desde la web llegan como texto en formato `.properties` (normalmente en
//! Base64), así que aquí se reproduce exactamente la gramática de
//! `Properties.load()` (JDK 17+): comentarios `#`/`!`, separadores `=`, `:` o
//! espacio, continuación de líneas con `\` (también con finales de línea
//! `\r\n` y `\r`) y secuencias de escape (`\uXXXX`, `\n`...). También se
//! reproduce `Properties.store(Writer, comentario)` (§3.6 de la
//! especificación), verificado contra el oráculo Java
//! (`testdata/core/load.golden` y `props.golden`).
//!
//! Además de los valores de texto, AutoFirma Java guarda en algunos casos
//! objetos que no son cadenas (p. ej. `Boolean.TRUE` en `confirmDifferentProfile`,
//! §3.5.7). Esos valores son invisibles para `getProperty`, no se serializan y
//! no pueden llegar desde la web; aquí se modelan como *marcas internas*
//! ([`ExtraParams::set_internal_flag`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine;

/// Parámetros adicionales (`java.util.Properties` de texto) más las marcas
/// internas no serializables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraParams(BTreeMap<String, String>, BTreeSet<String>);

/// Error al interpretar un `.properties` en modo estricto (como Java).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PropertiesError {
    /// `IllegalArgumentException("Malformed \uxxxx encoding.")`.
    #[error("Malformed \\uxxxx encoding.")]
    MalformedUnicodeEscape,
}

impl ExtraParams {
    pub fn new() -> Self {
        Self::default()
    }

    /// Interpreta texto en formato `.properties` de forma tolerante: una
    /// secuencia `\u` mal formada se conserva como texto en lugar de fallar.
    /// Para el comportamiento exacto de Java usa [`ExtraParams::load`].
    pub fn parse(text: &str) -> Self {
        let mut map = BTreeMap::new();
        for line in logical_lines(text) {
            let (k, v) = split_key_value(&line);
            map.insert(unescape_lenient(&k), unescape_lenient(&v));
        }
        ExtraParams(map, BTreeSet::new())
    }

    /// `Properties.load(Reader)`: como [`ExtraParams::parse`] pero con el
    /// error de Java ante `\uXXXX` mal formados.
    pub fn load(text: &str) -> Result<Self, PropertiesError> {
        let mut map = BTreeMap::new();
        for line in logical_lines(text) {
            let (k, v) = split_key_value(&line);
            map.insert(unescape_strict(&k)?, unescape_strict(&v)?);
        }
        Ok(ExtraParams(map, BTreeSet::new()))
    }

    /// `Properties.load(InputStream)`: los bytes se interpretan como
    /// ISO-8859-1.
    pub fn load_iso_8859_1(bytes: &[u8]) -> Result<Self, PropertiesError> {
        Self::load(&bytes.iter().map(|&b| b as char).collect::<String>())
    }

    /// `Properties.load(new InputStreamReader(..., UTF-8))`: los bytes se
    /// decodifican como UTF-8 sustituyendo las secuencias no válidas por
    /// U+FFFD, como hace Java.
    pub fn load_utf8(bytes: &[u8]) -> Result<Self, PropertiesError> {
        Self::load(&String::from_utf8_lossy(bytes))
    }

    /// Interpreta bytes en formato `.properties`: UTF-8 si son válidos y, si
    /// no, ISO-8859-1 (la codificación de `Properties.load(InputStream)`).
    pub fn parse_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(s) => Self::parse(s),
            Err(_) => Self::parse(&bytes.iter().map(|&b| b as char).collect::<String>()),
        }
    }

    /// Interpreta un `.properties` codificado en Base64 (normal o URL-safe,
    /// con o sin relleno, tolerando saltos de línea).
    pub fn from_base64(b64: &str) -> std::result::Result<Self, base64::DecodeError> {
        Ok(Self::parse_bytes(&crate::base64_decode_lenient(b64)?))
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Valor no vacío (tras recortar espacios).
    pub fn get_nonempty(&self, key: &str) -> Option<&str> {
        self.get(key).map(str::trim).filter(|v| !v.is_empty())
    }

    pub fn get_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.get(key).unwrap_or(default)
    }

    /// Valor booleano con la semántica de `Boolean.parseBoolean` de Java
    /// (`true` sin distinguir mayúsculas; cualquier otro valor es `false`).
    pub fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.get(key) {
            Some(v) => v.trim().eq_ignore_ascii_case("true"),
            None => default,
        }
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.trim().parse().ok())
    }

    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.trim().parse().ok())
    }

    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// Establece el valor solo si no existía.
    pub fn set_default(&mut self, key: &str, value: impl Into<String>) {
        self.0.entry(key.to_string()).or_insert_with(|| value.into());
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Mapa de valores de texto.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Añade (sobrescribiendo) todos los parámetros de `other`.
    pub fn extend(&mut self, other: &ExtraParams) {
        for (k, v) in &other.0 {
            self.0.insert(k.clone(), v.clone());
        }
        self.1.extend(other.1.iter().cloned());
    }

    /// Activa una marca interna no serializable (equivalente a guardar un
    /// objeto `Boolean.TRUE` en el `Properties` de Java, p. ej.
    /// `confirmDifferentProfile`). Las marcas no se ven con [`get`](Self::get),
    /// no se serializan y no pueden llegar desde la web.
    pub fn set_internal_flag(&mut self, name: impl Into<String>) {
        self.1.insert(name.into());
    }

    /// Indica si la marca interna está activa
    /// (`Boolean.TRUE.equals(extraParams.get(name))`).
    pub fn has_internal_flag(&self, name: &str) -> bool {
        self.1.contains(name)
    }

    /// Desactiva una marca interna.
    pub fn remove_internal_flag(&mut self, name: &str) -> bool {
        self.1.remove(name)
    }

    /// Serializa en formato `.properties` (como `Properties.store`, sin
    /// comentario de cabecera; los caracteres no ASCII se escriben como `\uXXXX`).
    pub fn to_properties_string(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.0 {
            out.push_str(&save_convert(k, true, true));
            out.push('=');
            out.push_str(&save_convert(v, false, true));
            out.push('\n');
        }
        out
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.to_properties_string())
    }

    /// `Properties.store(Writer, comments)`: línea de comentario (si
    /// `comments` no es `None`), línea con la fecha actual en el formato de
    /// `java.util.Date.toString()` y las entradas ordenadas por clave (como
    /// Java 18+), con el separador de línea de la plataforma (`\r\n` en
    /// Windows). Los caracteres no ASCII no se escapan (escritura con
    /// `Writer`).
    pub fn store(&self, comments: Option<&str>) -> String {
        let date = crate::javafmt::java_date_to_string(&chrono::Local::now());
        self.store_with(comments, &date, crate::platform::LINE_SEPARATOR, false)
    }

    /// `Properties.store` con todos los detalles explícitos: texto de la línea
    /// de fecha (sin `#`), separador de línea y si se escapan los caracteres
    /// no ASCII como `\uXXXX` (`true` = escritura con `OutputStream`).
    pub fn store_with(
        &self,
        comments: Option<&str>,
        date_line: &str,
        line_separator: &str,
        escape_unicode: bool,
    ) -> String {
        let mut out = String::new();
        if let Some(c) = comments {
            write_comments(&mut out, c, line_separator);
        }
        out.push('#');
        out.push_str(date_line);
        out.push_str(line_separator);
        for (k, v) in &self.0 {
            out.push_str(&save_convert(k, true, escape_unicode));
            out.push('=');
            out.push_str(&save_convert(v, false, escape_unicode));
            out.push_str(line_separator);
        }
        out
    }

    /// `AOUtil.propertiesAsString`: `clave=valor\n` por entrada, sin escapes
    /// ni comentarios.
    pub fn as_plain_string(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.0 {
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
        out
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for ExtraParams {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        ExtraParams(iter.into_iter().map(|(k, v)| (k.into(), v.into())).collect(), BTreeSet::new())
    }
}

impl fmt::Display for ExtraParams {
    /// Formato de depuración `{clave=valor, ...}` como `Properties.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("{")?;
        for (i, (k, v)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{k}={v}")?;
        }
        f.write_str("}")
    }
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\u{c}'
}

/// Divide el texto en líneas lógicas como `Properties.LineReader` de Java 17+
/// (uniendo continuaciones, descartando comentarios y líneas en blanco y
/// tratando `\n`, `\r` y `\r\n` como finales de línea).
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut skip_ws = true;
    let mut appended_line_begin = false;
    let mut preceding_backslash = false;
    let mut skip_lf = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if skip_lf {
            skip_lf = false;
            if c == '\n' {
                continue;
            }
        }
        if skip_ws {
            if is_ws(c) {
                continue;
            }
            if !appended_line_begin && (c == '\r' || c == '\n') {
                continue;
            }
            skip_ws = false;
            appended_line_begin = false;
        }
        if buf.is_empty() && (c == '#' || c == '!') {
            // Comentario: se consume hasta el final de línea (sin continuación).
            for cc in chars.by_ref() {
                if cc == '\r' {
                    skip_lf = true;
                    break;
                }
                if cc == '\n' {
                    break;
                }
            }
            skip_ws = true;
            continue;
        }
        if c != '\n' && c != '\r' {
            buf.push(c);
            preceding_backslash = if c == '\\' { !preceding_backslash } else { false };
        } else {
            if buf.is_empty() {
                skip_ws = true;
                continue;
            }
            if preceding_backslash {
                buf.pop();
                skip_ws = true;
                appended_line_begin = true;
                preceding_backslash = false;
                if c == '\r' {
                    skip_lf = true;
                }
            } else {
                out.push(std::mem::take(&mut buf));
                skip_ws = true;
                appended_line_begin = false;
                preceding_backslash = false;
            }
        }
    }
    if !buf.is_empty() {
        if preceding_backslash {
            buf.pop();
        }
        out.push(buf);
    }
    out
}

/// Separa clave y valor (aún escapados) de una línea lógica (`load0`).
fn split_key_value(line: &str) -> (String, String) {
    let chars: Vec<char> = line.chars().collect();
    let mut key_len = 0;
    let mut value_start = chars.len();
    let mut has_sep = false;
    let mut preceding_backslash = false;
    while key_len < chars.len() {
        let c = chars[key_len];
        if (c == '=' || c == ':') && !preceding_backslash {
            value_start = key_len + 1;
            has_sep = true;
            break;
        } else if is_ws(c) && !preceding_backslash {
            value_start = key_len + 1;
            break;
        }
        preceding_backslash = if c == '\\' { !preceding_backslash } else { false };
        key_len += 1;
    }
    while value_start < chars.len() {
        let c = chars[value_start];
        if !is_ws(c) {
            if !has_sep && (c == '=' || c == ':') {
                has_sep = true;
            } else {
                break;
            }
        }
        value_start += 1;
    }
    let key: String = chars[..key_len].iter().collect();
    let value: String = chars[value_start.min(chars.len())..].iter().collect();
    (key, value)
}

/// `loadConvert` de Java: resuelve los escapes trabajando en UTF-16 para que
/// los pares sustitutos escritos como `\uD83D\uDE00` se combinen.
fn unescape_strict(s: &str) -> Result<String, PropertiesError> {
    unescape(s, true)
}

fn unescape_lenient(s: &str) -> String {
    // En modo tolerante nunca se produce error.
    unescape(s, false).unwrap_or_default()
}

fn unescape(s: &str, strict: bool) -> Result<String, PropertiesError> {
    let mut units: Vec<u16> = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut buf = [0u16; 2];
    while let Some(c) = chars.next() {
        if c != '\\' {
            units.extend_from_slice(c.encode_utf16(&mut buf));
            continue;
        }
        let Some(e) = chars.next() else { break };
        match e {
            'u' => {
                let mut hex = String::new();
                for _ in 0..4 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(*h);
                            chars.next();
                        }
                        _ => break,
                    }
                }
                if hex.len() == 4 {
                    units.push(u16::from_str_radix(&hex, 16).unwrap_or(0xfffd));
                } else if strict {
                    return Err(PropertiesError::MalformedUnicodeEscape);
                } else {
                    // Tolerante: se conserva el texto tal cual.
                    units.extend("u".encode_utf16());
                    units.extend(hex.encode_utf16());
                }
            }
            't' => units.push(0x09),
            'n' => units.push(0x0a),
            'r' => units.push(0x0d),
            'f' => units.push(0x0c),
            other => units.extend_from_slice(other.encode_utf16(&mut buf)),
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

/// `saveConvert` de Java.
fn save_convert(s: &str, escape_space: bool, escape_unicode: bool) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    let mut buf = [0u16; 2];
    for (i, c) in s.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => {
                if i == 0 || escape_space {
                    out.push('\\');
                }
                out.push(' ');
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            c if ((c as u32) < 0x20 || (c as u32) > 0x7e) && escape_unicode => {
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04X}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// `writeComments` de Java.
fn write_comments(out: &mut String, comments: &str, line_separator: &str) {
    out.push('#');
    let units: Vec<u16> = comments.encode_utf16().collect();
    let len = units.len();
    let mut current = 0;
    let mut last = 0;
    while current < len {
        let c = units[current];
        if c > 0xff || c == u16::from(b'\n') || c == u16::from(b'\r') {
            if last != current {
                out.push_str(&String::from_utf16_lossy(&units[last..current]));
            }
            if c > 0xff {
                out.push_str(&format!("\\u{:04X}", c));
            } else {
                out.push_str(line_separator);
                if c == u16::from(b'\r') && current != len - 1 && units[current + 1] == u16::from(b'\n') {
                    current += 1;
                }
                if current == len - 1
                    || (units[current + 1] != u16::from(b'#') && units[current + 1] != u16::from(b'!'))
                {
                    out.push('#');
                }
            }
            last = current + 1;
        }
        current += 1;
    }
    if last != current {
        out.push_str(&String::from_utf16_lossy(&units[last..current]));
    }
    out.push_str(line_separator);
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{esc, golden, sorted, unesc};

    #[test]
    fn load_matches_java_oracle() {
        for line in golden("load.golden").lines() {
            let (input, expected) = line.split_once('\t').unwrap();
            let input = unesc(input);
            let got = match ExtraParams::load(&input) {
                Ok(p) => sorted(&p),
                Err(e) => format!("ERR:IllegalArgumentException:{}", esc(&e.to_string())),
            };
            assert_eq!(got, expected, "entrada {input:?}");
        }
    }

    #[test]
    fn store_matches_java_oracle() {
        let mut checked = 0;
        for line in golden("props.golden").lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            match cols[0] {
                "B642P" => continue,
                "ASSTRING" => {
                    // propertiesAsString de una propiedad: se reconstruye
                    // desde la línea anterior ya comprobada.
                    continue;
                }
                _ => {}
            }
            // Se carga la salida de Java, se comprueba el contenido y se
            // vuelve a serializar: debe salir idéntica.
            let stored = unesc(cols[1]);
            let p = ExtraParams::load(&stored).unwrap();
            assert_eq!(sorted(&p), cols[0]);
            assert_eq!(p.store_with(Some(""), "DATE", "\n", false), stored, "propiedades {}", cols[0]);
            checked += 1;
        }
        assert!(checked >= 9);
        // propertiesAsString
        let props = golden("props.golden");
        let lines: Vec<&str> = props.lines().collect();
        for w in lines.windows(2) {
            if let Some(expected) = w[1].strip_prefix("ASSTRING\t") {
                let p = ExtraParams::load(&unesc(w[0].split('\t').nth(1).unwrap())).unwrap();
                assert_eq!(esc(&p.as_plain_string()), expected);
            }
        }
    }

    #[test]
    fn java_properties_grammar() {
        let text = "# comentario\n! otro\n  mode=implicit\nformat : XAdES Detached\nsimple valor con espacios\nlarga=uno \\\n    dos\\\n tres\nescapes=a\\tb\\nc\\u00F1\\=\\:\nclave\\ con\\=raro=v\nvacia=\nsinvalor\n\r\nlayer2Text=Firmado por $$SUBJECTCN$$\\nel d\\u00EDa $$SIGNDATE=dd/MM/yyyy$$";
        let p = ExtraParams::parse(text);
        assert_eq!(p.get("mode"), Some("implicit"));
        assert_eq!(p.get("format"), Some("XAdES Detached"));
        assert_eq!(p.get("simple"), Some("valor con espacios"));
        assert_eq!(p.get("larga"), Some("uno dostres"));
        assert_eq!(p.get("escapes"), Some("a\tb\ncñ=:"));
        assert_eq!(p.get("clave con=raro"), Some("v"));
        assert_eq!(p.get("vacia"), Some(""));
        assert_eq!(p.get("sinvalor"), Some(""));
        assert_eq!(p.get("layer2Text"), Some("Firmado por $$SUBJECTCN$$\nel día $$SIGNDATE=dd/MM/yyyy$$"));
        assert!(!p.contains("# comentario"));
        // Continuación con CRLF (Windows).
        assert_eq!(ExtraParams::parse("a=b\\\r\n   c\r\nd=e").get("a"), Some("bc"));
        // Tolerante frente a estricto.
        assert_eq!(ExtraParams::parse("a=\\u00zz").get("a"), Some("u00zz"));
        assert_eq!(ExtraParams::load("a=\\u00zz").unwrap_err(), PropertiesError::MalformedUnicodeEscape);
    }

    #[test]
    fn roundtrip_and_base64() {
        let mut p = ExtraParams::new();
        p.set("signatureProductionCity", "Logroño");
        p.set("layer2Text", "línea1\nlínea2 = x");
        p.set(" rara", "#valor");
        let again = ExtraParams::parse(&p.to_properties_string());
        assert_eq!(again, p);
        let b64 = p.to_base64();
        assert_eq!(ExtraParams::from_base64(&b64).unwrap(), p);
        assert!(ExtraParams::parse("headless=TRUE").get_bool("headless", false));
        assert!(!ExtraParams::parse("headless=si").get_bool("headless", true));
        let stored = p.store_with(Some("comentario\nsegunda\n#tercera é€"), "fecha", "\r\n", false);
        assert!(stored.starts_with("#comentario\r\n#segunda\r\n#tercera é\\u20AC\r\n#fecha\r\n"));
        assert_eq!(ExtraParams::load(&stored).unwrap(), p);
        assert!(p.store(None).starts_with('#'));
    }

    #[test]
    fn internal_flags() {
        let mut p = ExtraParams::new();
        p.set_internal_flag("confirmDifferentProfile");
        assert!(p.has_internal_flag("confirmDifferentProfile"));
        assert_eq!(p.get("confirmDifferentProfile"), None);
        assert!(p.is_empty());
        assert_eq!(p.to_properties_string(), "");
        let mut q = ExtraParams::new();
        q.extend(&p);
        assert!(q.has_internal_flag("confirmDifferentProfile"));
        assert!(q.remove_internal_flag("confirmDifferentProfile"));
        assert_eq!(p.to_string(), "{}");
    }

    #[test]
    fn latin1_bytes() {
        let p = ExtraParams::parse_bytes(b"ciudad=Le\xf3n");
        assert_eq!(p.get("ciudad"), Some("León"));
        assert_eq!(ExtraParams::load_iso_8859_1(b"ciudad=Le\xf3n").unwrap().get("ciudad"), Some("León"));
        assert_eq!(ExtraParams::load_utf8(b"ciudad=Le\xf3n").unwrap().get("ciudad"), Some("Le\u{fffd}n"));
    }
}
