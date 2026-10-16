//! Análisis de las URL `afirma://` y de los mensajes recibidos por socket
//! (`ProtocolInvocationLauncher.extractParams`), con la semántica de
//! `java.net.URLDecoder.decode(valor, "UTF-8")`.
//!
//! Los valores se guardan sin decodificar y se decodifican al consultarlos:
//! - [`Params::get`] reproduce `URLDecoder` (`+` → espacio, `%HH` → byte UTF-8).
//! - [`Params::get_base64`] se usa para los parámetros que solo pueden
//!   contener Base64 (`properties`, `cipher`, `ksb64` y `dat` cuando su valor
//!   es Base64): ahí un `+` literal es siempre parte del Base64 estándar y
//!   Java lo corrompía al convertirlo en espacio (desviación documentada).

use std::collections::HashMap;

/// Secuencia de escape `%` mal formada (Java lanza `IllegalArgumentException`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("URLDecoder: {0}")]
pub struct MalformedEscape(pub String);

/// `URLDecoder.decode(text, UTF-8)`.
pub fn url_decode(text: &str) -> Result<String, MalformedEscape> {
    decode_impl(text, false)
}

/// Como [`url_decode`] pero dejando `+` como carácter literal.
pub fn url_decode_keep_plus(text: &str) -> Result<String, MalformedEscape> {
    decode_impl(text, true)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Valor de `Integer.parseInt(s, i+1, i+3, 16)` sobre dos caracteres
/// (admite signo, como Java).
fn parse_escape(a: u8, b: u8) -> Result<u8, MalformedEscape> {
    let illegal = || {
        MalformedEscape(format!(
            "Illegal hex characters in escape (%) pattern - {}{}",
            a as char, b as char
        ))
    };
    match a {
        b'+' => hex_val(b).ok_or_else(illegal),
        b'-' => match hex_val(b) {
            Some(0) => Ok(0),
            Some(_) => Err(MalformedEscape(
                "Illegal hex characters in escape (%) pattern - negative value".into(),
            )),
            None => Err(illegal()),
        },
        _ => match (hex_val(a), hex_val(b)) {
            (Some(h), Some(l)) => Ok(h * 16 + l),
            _ => Err(illegal()),
        },
    }
}

fn decode_impl(text: &str, keep_plus: bool) -> Result<String, MalformedEscape> {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    // Inicio del tramo literal pendiente de copiar.
    let mut lit_start = 0;
    while i < n {
        match bytes[i] {
            b'+' if !keep_plus => {
                out.push_str(&text[lit_start..i]);
                out.push(' ');
                i += 1;
                lit_start = i;
            }
            b'%' => {
                out.push_str(&text[lit_start..i]);
                let mut buf = Vec::new();
                while i + 2 < n && bytes[i] == b'%' {
                    buf.push(parse_escape(bytes[i + 1], bytes[i + 2])?);
                    i += 3;
                }
                if i < n && bytes[i] == b'%' {
                    return Err(MalformedEscape("Incomplete trailing escape (%) pattern".into()));
                }
                out.push_str(&String::from_utf8_lossy(&buf));
                lit_start = i;
            }
            _ => i += 1,
        }
    }
    out.push_str(&text[lit_start..]);
    Ok(out)
}

/// Codifica para el cuerpo `application/x-www-form-urlencoded` de las
/// subidas al servidor intermedio solo los caracteres que el servlet
/// corrompería al decodificar (`%`, `+`, `&`, controles y no ASCII). El resto
/// (Base64, `|`, `:`, `=`, espacios...) se envía tal cual, como Java.
pub fn encode_storage_payload(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b == b'%' || b == b'+' || b == b'&' || !(0x20..0x7f).contains(&b) {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// Parámetros de una petición (valores sin decodificar).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    raw: HashMap<String, String>,
}

impl Params {
    /// Extrae los parámetros de una URL o mensaje: todo lo que sigue al
    /// primer `?` (o el texto entero si no lo hay), separado por `&`; los
    /// elementos sin `=` o con la clave vacía se ignoran; si una clave se
    /// repite gana la última.
    pub fn from_query(url: &str) -> Params {
        let query = match url.find('?') {
            Some(i) => &url[i + 1..],
            None => url,
        };
        let mut raw = HashMap::new();
        for item in query.split('&') {
            match item.find('=') {
                Some(eq) if eq > 0 => {
                    raw.insert(item[..eq].to_string(), item[eq + 1..].to_string());
                }
                _ => {}
            }
        }
        Params { raw }
    }

    /// Construye los parámetros a partir de pares clave/valor sin decodificar
    /// (sobres XML/JSON del servidor intermedio).
    pub fn from_raw_pairs<I: IntoIterator<Item = (String, String)>>(pairs: I) -> Params {
        Params {
            raw: pairs.into_iter().collect(),
        }
    }

    pub fn contains(&self, key: &str) -> bool {
        self.raw.contains_key(key)
    }

    /// Valor sin decodificar.
    pub fn raw(&self, key: &str) -> Option<&str> {
        self.raw.get(key).map(String::as_str)
    }

    /// Valor decodificado como `URLDecoder.decode`.
    pub fn get(&self, key: &str) -> Result<Option<String>, MalformedEscape> {
        self.raw.get(key).map(|v| url_decode(v)).transpose()
    }

    /// Valor de un parámetro Base64: `%HH` se decodifica pero `+` se conserva.
    pub fn get_base64(&self, key: &str) -> Result<Option<String>, MalformedEscape> {
        self.raw.get(key).map(|v| url_decode_keep_plus(v)).transpose()
    }

    /// Valor del parámetro de datos `dat`: si conservando los `+` el valor
    /// es Base64 se devuelve así; si no, con la semántica de Java.
    pub fn get_data(&self, key: &str) -> Result<Option<String>, MalformedEscape> {
        let Some(raw) = self.raw.get(key) else { return Ok(None) };
        if raw.contains('+') {
            let kept = url_decode_keep_plus(raw)?;
            if crate::jbase64::is_base64(&kept) {
                return Ok(Some(kept));
            }
        }
        url_decode(raw).map(Some)
    }

    /// Booleano con `Boolean.parseBoolean` (ausente o mal codificado → `false`).
    pub fn get_bool(&self, key: &str) -> bool {
        matches!(self.get(key), Ok(Some(v)) if v.eq_ignore_ascii_case("true"))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.raw.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.raw.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Sustituye o añade un valor sin decodificar.
    pub fn insert_raw(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.raw.insert(key.into(), value.into());
    }
}

/// Nombre de la operación: texto entre `://` y `?` (o el final), sin la `/`
/// final y cortado en la primera `/`.
pub fn operation_name(url: &str) -> String {
    let rest = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let rest = match rest.find('?') {
        Some(i) => &rest[..i],
        None => rest,
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    match rest.find('/') {
        Some(i) => rest[..i].to_string(),
        None => rest.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decoder_semantics() {
        assert_eq!(url_decode("a+b%20c").unwrap(), "a b c");
        assert_eq!(url_decode("%C3%B1and%C3%BA").unwrap(), "ñandú");
        assert_eq!(url_decode("").unwrap(), "");
        assert_eq!(url_decode("ab%41").unwrap(), "abA");
        assert!(url_decode("ab%4").is_err());
        assert!(url_decode("ab%").is_err());
        assert!(url_decode("%zz").is_err());
        assert!(url_decode("100%.pdf").is_err());
        assert!(url_decode("%-1").is_err());
        assert_eq!(url_decode("%+1").unwrap(), "\u{1}");
        assert_eq!(url_decode_keep_plus("a+b%2B").unwrap(), "a+b+");
    }

    #[test]
    fn query_parsing() {
        let p = Params::from_query("afirma://sign?op=sign&format=CAdES&=x&noeq&dat=SG9sYQ==&op=cosign&empty=&");
        assert_eq!(p.get("op").unwrap().as_deref(), Some("cosign"));
        assert_eq!(p.get("format").unwrap().as_deref(), Some("CAdES"));
        assert_eq!(p.get("dat").unwrap().as_deref(), Some("SG9sYQ=="));
        assert_eq!(p.get("empty").unwrap().as_deref(), Some(""));
        assert!(!p.contains("noeq"));
        assert!(!p.contains(""));
        assert_eq!(p.len(), 4);
        // Las claves no se decodifican y distinguen mayúsculas.
        let p = Params::from_query("afirma://sign?Op%20x=1");
        assert!(p.contains("Op%20x"));
        // Sin '?': el texto entero.
        let p = Params::from_query("echo=-idsession=abc@EOF");
        assert_eq!(p.raw("echo"), Some("-idsession=abc@EOF"));
    }

    #[test]
    fn base64_plus_handling() {
        let p = Params::from_query("afirma://sign?properties=a+b/cd==&dat=ab+c&dat2=ab+/&txt=hello+world");
        assert_eq!(p.get("properties").unwrap().as_deref(), Some("a b/cd=="));
        assert_eq!(p.get_base64("properties").unwrap().as_deref(), Some("a+b/cd=="));
        // "ab+c" es Base64 válido → se conserva el '+'.
        assert_eq!(p.get_data("dat").unwrap().as_deref(), Some("ab+c"));
        assert_eq!(p.get_data("txt").unwrap().as_deref(), Some("hello world"));
    }

    #[test]
    fn op_names() {
        assert_eq!(operation_name("afirma://sign?op=sign"), "sign");
        assert_eq!(operation_name("afirma://sign/?op=sign"), "sign");
        assert_eq!(operation_name("afirma://websocket"), "websocket");
        assert_eq!(operation_name("afirma://a/b/?x"), "a");
    }

    #[test]
    fn storage_payload_encoding() {
        assert_eq!(encode_storage_payload("MIIB-_|0.ab=="), "MIIB-_|0.ab==");
        assert_eq!(
            encode_storage_payload("err-00:=AF1 - a+b&c%ñ"),
            "err-00:=AF1 - a%2Bb%26c%25%C3%B1"
        );
        assert_eq!(url_decode(&encode_storage_payload("x+y ñ%")).unwrap(), "x+y ñ%");
    }
}
