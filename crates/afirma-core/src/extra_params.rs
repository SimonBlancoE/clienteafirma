//! Parámetros adicionales de las operaciones de firma (`extraParams`).
//!
//! En AutoFirma los parámetros adicionales son un `java.util.Properties`.
//! Desde la web llegan como texto en formato `.properties` (normalmente en
//! Base64), así que aquí se reproduce exactamente la gramática de
//! `Properties.load()`: comentarios `#`/`!`, separadores `=`, `:` o espacio,
//! continuación de líneas con `\` y secuencias de escape (`\uXXXX`, `\n`...).

use std::collections::BTreeMap;

use base64::Engine;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraParams(BTreeMap<String, String>);

impl ExtraParams {
    pub fn new() -> Self {
        Self::default()
    }

    /// Interpreta texto en formato `.properties`.
    pub fn parse(text: &str) -> Self {
        let mut map = BTreeMap::new();
        for line in logical_lines(text) {
            let (k, v) = split_key_value(&line);
            map.insert(unescape(&k), unescape(&v));
        }
        ExtraParams(map)
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
    pub fn from_base64(b64: &str) -> Result<Self, base64::DecodeError> {
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

    /// Añade (sobrescribiendo) todos los parámetros de `other`.
    pub fn extend(&mut self, other: &ExtraParams) {
        for (k, v) in &other.0 {
            self.0.insert(k.clone(), v.clone());
        }
    }

    /// Serializa en formato `.properties` (como `Properties.store`, sin
    /// comentario de cabecera; los caracteres no ASCII se escriben como `\uXXXX`).
    pub fn to_properties_string(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.0 {
            escape_into(&mut out, k, true);
            out.push('=');
            escape_into(&mut out, v, false);
            out.push('\n');
        }
        out
    }

    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.to_properties_string())
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for ExtraParams {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        ExtraParams(iter.into_iter().map(|(k, v)| (k.into(), v.into())).collect())
    }
}

fn is_ws(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\u{c}'
}

/// Divide el texto en líneas lógicas (uniendo continuaciones y descartando
/// comentarios y líneas en blanco).
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    let natural = text.split('\n').flat_map(|l| l.split('\r'));
    for raw in natural {
        let line = raw.trim_start_matches(is_ws);
        if current.is_none() {
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
        }
        let trailing = line.chars().rev().take_while(|&c| c == '\\').count();
        let continues = trailing % 2 == 1;
        let piece = if continues { &line[..line.len() - 1] } else { line };
        let acc = current.get_or_insert_with(String::new);
        acc.push_str(piece);
        if !continues {
            out.push(current.take().unwrap());
        }
    }
    if let Some(c) = current {
        out.push(c);
    }
    out
}

fn split_key_value(line: &str) -> (String, String) {
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    let mut key_end = chars.len();
    let mut has_sep = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 2;
            continue;
        }
        if c == '=' || c == ':' {
            key_end = i;
            has_sep = true;
            break;
        }
        if is_ws(c) {
            key_end = i;
            break;
        }
        i += 1;
    }
    let key: String = chars[..key_end.min(chars.len())].iter().collect();
    let mut j = key_end;
    if !has_sep {
        while j < chars.len() && is_ws(chars[j]) {
            j += 1;
        }
        if j < chars.len() && (chars[j] == '=' || chars[j] == ':') {
            j += 1;
        }
    } else {
        j += 1;
    }
    while j < chars.len() && is_ws(chars[j]) {
        j += 1;
    }
    let value: String = if j < chars.len() { chars[j..].iter().collect() } else { String::new() };
    (key, value)
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    let mut pending_high: Option<u16> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            flush_high(&mut out, &mut pending_high);
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => push_flush(&mut out, &mut pending_high, '\t'),
            Some('n') => push_flush(&mut out, &mut pending_high, '\n'),
            Some('r') => push_flush(&mut out, &mut pending_high, '\r'),
            Some('f') => push_flush(&mut out, &mut pending_high, '\u{c}'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                match u16::from_str_radix(&hex, 16) {
                    Ok(unit) => {
                        if (0xd800..0xdc00).contains(&unit) {
                            flush_high(&mut out, &mut pending_high);
                            pending_high = Some(unit);
                        } else if (0xdc00..0xe000).contains(&unit) {
                            match pending_high.take() {
                                Some(h) => out.push_str(&String::from_utf16_lossy(&[h, unit])),
                                None => out.push('\u{fffd}'),
                            }
                        } else {
                            flush_high(&mut out, &mut pending_high);
                            out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}'));
                        }
                    }
                    Err(_) => {
                        // Java lanzaría una excepción; somos tolerantes.
                        flush_high(&mut out, &mut pending_high);
                        out.push_str(&hex);
                    }
                }
            }
            Some(other) => push_flush(&mut out, &mut pending_high, other),
            None => {}
        }
    }
    flush_high(&mut out, &mut pending_high);
    out
}

fn push_flush(out: &mut String, pending: &mut Option<u16>, c: char) {
    flush_high(out, pending);
    out.push(c);
}

fn flush_high(out: &mut String, pending: &mut Option<u16>) {
    if pending.take().is_some() {
        out.push('\u{fffd}');
    }
}

fn escape_into(out: &mut String, s: &str, is_key: bool) {
    for (i, c) in s.chars().enumerate() {
        match c {
            ' ' if is_key || i == 0 => out.push_str("\\ "),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{:04X}", unit));
                }
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn latin1_bytes() {
        let p = ExtraParams::parse_bytes(b"ciudad=Le\xf3n");
        assert_eq!(p.get("ciudad"), Some("León"));
    }
}
