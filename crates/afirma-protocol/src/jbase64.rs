//! Base64 con la semántica exacta de `es.gob.afirma.core.misc.Base64`
//! (derivado de iHarder 2.3.7), que es la que usa AutoFirma en todo el
//! protocolo.
//!
//! Diferencias relevantes con un decodificador estricto:
//! - Se ignoran tabuladores, saltos de línea, retornos de carro y espacios.
//! - La decodificación se detiene en el primer cuarteto completo que acaba
//!   en `=` (lo que siga se ignora).
//! - Un cuarteto final incompleto (entrada sin relleno) se descarta en
//!   silencio.
//! - Una entrada de 1 a 3 caracteres es un error de argumento (no de E/S).
//! - El decodificador estándar rechaza `-` y `_`, y el URL-safe rechaza `+` y
//!   `/`. Casi todo el protocolo normaliza antes (`-`→`+`, `_`→`/`) y usa el
//!   estándar: [`decode_normalized`].

use base64::Engine;

/// Error de decodificación Base64.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    /// Equivale a `IllegalArgumentException` de Java (entrada de 1 a 3 caracteres).
    #[error("Base64-encoded string must have at least four characters, but length specified was {0}")]
    TooShort(usize),
    /// Equivale a `IOException("Bad Base64 input character ...")`.
    #[error("Bad Base64 input character decimal {byte} in array position {pos}")]
    BadCharacter { byte: u8, pos: usize },
}

const WHITE_SPACE: i8 = -5;
const EQUALS: i8 = -1;
const BAD: i8 = -9;

const fn decodabet(url_safe: bool) -> [i8; 256] {
    let mut t = [BAD; 256];
    let mut i = 0;
    while i < 26 {
        t[b'A' as usize + i] = i as i8;
        t[b'a' as usize + i] = (26 + i) as i8;
        i += 1;
    }
    let mut d = 0;
    while d < 10 {
        t[b'0' as usize + d] = (52 + d) as i8;
        d += 1;
    }
    if url_safe {
        t[b'-' as usize] = 62;
        t[b'_' as usize] = 63;
    } else {
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
    }
    t[b'\t' as usize] = WHITE_SPACE;
    t[b'\n' as usize] = WHITE_SPACE;
    t[b'\r' as usize] = WHITE_SPACE;
    t[b' ' as usize] = WHITE_SPACE;
    t[b'=' as usize] = EQUALS;
    t
}

static STANDARD_DECODABET: [i8; 256] = decodabet(false);
static URL_SAFE_DECODABET: [i8; 256] = decodabet(true);

/// Codifica con el alfabeto estándar y relleno `=` (`Base64.encode(data)`).
pub fn encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Codifica con el alfabeto URL-safe y relleno `=` (`Base64.encode(data, true)`).
pub fn encode_url_safe(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(data)
}

/// `Base64.decode(str)`: alfabeto estándar con la semántica de Java.
pub fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    decode_bytes(&to_us_ascii(text), false)
}

/// `Base64.decode(str, true)`: alfabeto URL-safe con la semántica de Java.
pub fn decode_url_safe(text: &str) -> Result<Vec<u8>, Base64Error> {
    decode_bytes(&to_us_ascii(text), true)
}

/// Idiom habitual del protocolo: `Base64.decode(s.replace("_", "/").replace("-", "+"))`.
pub fn decode_normalized(text: &str) -> Result<Vec<u8>, Base64Error> {
    decode(&normalize(text))
}

/// Sustituye el alfabeto URL-safe por el estándar (`_`→`/`, `-`→`+`).
pub fn normalize(text: &str) -> String {
    text.replace('_', "/").replace('-', "+")
}

/// `String.getBytes("US-ASCII")`: los caracteres no ASCII pasan a ser `?`.
fn to_us_ascii(text: &str) -> Vec<u8> {
    text.chars().map(|c| if c.is_ascii() { c as u8 } else { b'?' }).collect()
}

/// `Base64.decode(byte[], off, len, urlSafe)`.
pub fn decode_bytes(source: &[u8], url_safe: bool) -> Result<Vec<u8>, Base64Error> {
    let len = source.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if len < 4 {
        return Err(Base64Error::TooShort(len));
    }
    let table: &[i8; 256] = if url_safe { &URL_SAFE_DECODABET } else { &STANDARD_DECODABET };
    let mut out = Vec::with_capacity(len * 3 / 4);
    let mut b4 = [0u8; 4];
    let mut pos = 0usize;
    for (i, &byte) in source.iter().enumerate() {
        let v = table[byte as usize];
        if v >= WHITE_SPACE {
            if v >= EQUALS {
                b4[pos] = byte;
                pos += 1;
                if pos > 3 {
                    decode4to3(&b4, table, &mut out);
                    pos = 0;
                    if byte == b'=' {
                        break;
                    }
                }
            }
        } else {
            return Err(Base64Error::BadCharacter { byte, pos: i });
        }
    }
    Ok(out)
}

fn decode4to3(src: &[u8; 4], table: &[i8; 256], out: &mut Vec<u8>) {
    // `decodabet[x] & 0xFF` de Java: el `=` (valor -1) aporta 0xFF.
    let d = |b: u8| (table[b as usize] as u8) as u32;
    if src[2] == b'=' {
        let buf = (d(src[0]) << 18) | (d(src[1]) << 12);
        out.push((buf >> 16) as u8);
    } else if src[3] == b'=' {
        let buf = (d(src[0]) << 18) | (d(src[1]) << 12) | (d(src[2]) << 6);
        out.push((buf >> 16) as u8);
        out.push((buf >> 8) as u8);
    } else {
        let buf = (d(src[0]) << 18) | (d(src[1]) << 12) | (d(src[2]) << 6) | d(src[3]);
        out.push((buf >> 16) as u8);
        out.push((buf >> 8) as u8);
        out.push(buf as u8);
    }
}

const BASE_64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~";

/// `Base64.isBase64(String)`: todos los caracteres en el alfabeto ampliado
/// (incluye ambos alfabetos, `~`, tabulador y saltos de línea), `=` solo en
/// las dos últimas posiciones y número de caracteres (sin contar `\n` ni
/// `\r`) múltiplo de 4. La cadena vacía es Base64.
pub fn is_base64(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut count = 0usize;
    for (i, &c) in chars.iter().enumerate() {
        if !BASE_64_ALPHABET.contains(c) {
            return false;
        }
        if c == '=' && i + 2 < len {
            return false;
        }
        if c != '\n' && c != '\r' {
            count += 1;
        }
    }
    count % 4 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_keeps_padding_in_both_alphabets() {
        assert_eq!(encode(&[0xfb, 0xff]), "+/8=");
        assert_eq!(encode_url_safe(&[0xfb, 0xff]), "-_8=");
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn decode_java_quirks() {
        assert_eq!(decode("aG9sYQ==").unwrap(), b"hola");
        // Espacios y saltos ignorados.
        assert_eq!(decode("aG9s\r\n YQ==\n").unwrap(), b"hola");
        // Se detiene en el primer cuarteto con '='.
        assert_eq!(decode("aG9sYQ==aG9sYQ==").unwrap(), b"hola");
        // Cuarteto final incompleto descartado.
        assert_eq!(decode("aG9sYQ").unwrap(), b"hol");
        // Longitud 1-3: error de argumento.
        assert_eq!(decode("aG9"), Err(Base64Error::TooShort(3)));
        assert_eq!(decode("").unwrap(), b"");
        // El estándar rechaza el alfabeto URL-safe.
        assert!(matches!(decode("-_8="), Err(Base64Error::BadCharacter { byte: b'-', pos: 0 })));
        assert_eq!(decode_url_safe("-_8=").unwrap(), vec![0xfb, 0xff]);
        assert!(decode_url_safe("+/8=").is_err());
        assert_eq!(decode_normalized("-_8=").unwrap(), vec![0xfb, 0xff]);
        // No ASCII → '?' → error.
        assert!(decode("aG9sYQ==ñ").is_ok()); // se detiene antes
        assert!(decode("aG9sYQ=ñ").is_err());
        assert!(decode("ñG9sYQ==").is_err());
    }

    #[test]
    fn is_base64_rules() {
        assert!(is_base64(""));
        assert!(is_base64("aG9sYQ=="));
        assert!(is_base64("-_8="));
        assert!(is_base64("aG9s\r\nYQ=="));
        assert!(!is_base64("aG9sYQ"));
        assert!(!is_base64("aG9 sYQ=="));
        assert!(!is_base64("a=G9sYQ="));
        // Tabulador cuenta.
        assert!(!is_base64("aG9s\tYQ=="));
        // "...==\n": '=' en len-3.
        assert!(!is_base64("aG9sYQ==\n"));
        assert!(is_base64("~~~~"));
        assert!(!is_base64("hello+world"));
    }
}
