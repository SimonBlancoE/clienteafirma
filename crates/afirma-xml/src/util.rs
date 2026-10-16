//! Utilidades comunes de los firmadores XML: identificadores, Base64 con las
//! reglas de AutoFirma, fechas, escapado de texto XML y codificaciones.

use base64::Engine;
use chrono::{DateTime, Local, TimeZone};

/// UUID aleatorio en minúsculas con guiones (`UUID.randomUUID().toString()`).
pub fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `UUID.nameUUIDFromBytes(bytes)` de Java (MD5, versión 3, sin espacio de nombres).
pub fn uuid_v3_from_bytes(bytes: &[u8]) -> String {
    use md5::Digest;
    let mut h: [u8; 16] = md5::Md5::digest(bytes).into();
    h[6] = (h[6] & 0x0f) | 0x30;
    h[8] = (h[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(h).to_string()
}

/// Base64 estándar con relleno y sin saltos de línea.
pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decodifica Base64 ignorando espacios en blanco (alfabeto estándar o URL-safe).
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Some(Vec::new());
    }
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
        .or_else(|| afirma_core::base64_decode_lenient(&cleaned).ok())
}

/// `Base64.isBase64(byte[])` de AutoFirma.
pub fn is_base64(data: &[u8]) -> bool {
    const SET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~";
    let len = data.len();
    let mut count = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if !SET.contains(&b) {
            return false;
        }
        if b == b'=' && i + 2 < len {
            return false;
        }
        if b != b'\n' && b != b'\r' {
            count += 1;
        }
    }
    count % 4 == 0
}

/// Fecha en el formato de `SigningTime` de jxades
/// (`yyyy-MM-dd'T'HH:mm:ssZ` con `:` antes de los dos últimos caracteres).
pub fn xades_time<Tz: TimeZone>(t: &DateTime<Tz>) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let s = t.format("%Y-%m-%dT%H:%M:%S%z").to_string();
    let (a, b) = s.split_at(s.len() - 2);
    format!("{a}:{b}")
}

/// Instante actual en la zona horaria local.
pub fn now() -> DateTime<Local> {
    Local::now()
}

/// Escapa texto para el contenido de un elemento (como el serializador de Java).
pub fn esc_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escapa el valor de un atributo delimitado por comillas dobles.
pub fn esc_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\r' => out.push_str("&#13;"),
            '\n' => out.push_str("&#10;"),
            '\t' => out.push_str("&#9;"),
            _ => out.push(c),
        }
    }
    out
}

/// Codificación de salida a partir de su nombre (`UTF-8`, `ISO-8859-1`...).
pub fn encoding_for(name: &str) -> Option<&'static encoding_rs::Encoding> {
    encoding_rs::Encoding::for_label(name.trim().as_bytes())
}

/// Indica si un texto es una URI con sintaxis válida (aproximación a
/// `new java.net.URI(s)`): sin espacios ni caracteres de control, y con un
/// esquema bien formado si lo tiene.
pub fn is_valid_uri(s: &str) -> bool {
    if s.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}')
    }) {
        return false;
    }
    if let Some(idx) = s.find(':') {
        let scheme = &s[..idx];
        if !scheme.is_empty()
            && !scheme.contains('/')
            && !scheme.contains('?')
            && !scheme.contains('#')
        {
            let mut chars = scheme.chars();
            let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
            let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
            if !first_ok || !rest_ok {
                return false;
            }
            // Un URI opaco necesita parte específica del esquema.
            if s.len() == idx + 1 {
                return false;
            }
        }
    }
    // '%' debe ir seguido de dos dígitos hexadecimales.
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'%'
            && !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
        {
            return false;
        }
    }
    true
}

/// Divide por `|` descartando los elementos vacíos o en blanco.
pub fn split_pipe(s: &str) -> Vec<String> {
    s.split('|')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v3_matches_java() {
        // UUID.nameUUIDFromBytes("Reference-x".getBytes()) calculado con Java.
        let u = uuid_v3_from_bytes(b"hola");
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "3");
        assert_eq!(
            uuid_v3_from_bytes(b""),
            "d41d8cd9-8f00-3204-a980-0998ecf8427e"
        );
    }

    #[test]
    fn base64_rules() {
        assert!(is_base64(b"QUJD"));
        assert!(is_base64(b""));
        assert!(!is_base64(b"hello world"));
        assert!(!is_base64(b"QQ==\n"));
        assert!(is_base64(b"QQ=="));
    }

    #[test]
    fn signing_time_format() {
        let t = chrono::FixedOffset::east_opt(7200)
            .unwrap()
            .with_ymd_and_hms(2026, 10, 16, 13, 39, 15)
            .unwrap();
        assert_eq!(xades_time(&t), "2026-10-16T13:39:15+02:00");
        let u = chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(xades_time(&u), "2026-01-02T03:04:05+00:00");
    }

    #[test]
    fn uris() {
        assert!(is_valid_uri("http://www.w3.org/2000/09/xmldsig#base64"));
        assert!(is_valid_uri("UTF-8"));
        assert!(!is_valid_uri("a b"));
        assert!(!is_valid_uri("1http:x"));
    }
}
