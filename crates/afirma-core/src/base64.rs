//! Base64 compatible con `es.gob.afirma.core.misc.Base64` (derivado de
//! iharder Base64 2.3.7) de AutoFirma.
//!
//! Comportamiento reproducido (verificado contra el oráculo Java, ver
//! `testdata/core/base64.golden`):
//!
//! * La codificación usa el alfabeto estándar (o el URL-safe con `-` y `_`),
//!   **siempre con relleno `=`** y sin saltos de línea.
//! * La decodificación (`decode`) rechaza entradas de longitud total 1 a 3
//!   (contando espacios) con el mensaje de Java, **ignora en silencio
//!   cualquier carácter que no sea del alfabeto elegido ni `=`** (espacios,
//!   saltos de línea, `-`/`_` en el modo estándar, `+`/`/` en el URL-safe,
//!   caracteres no ASCII...), agrupa el resto en cuartetos, se detiene tras
//!   el primer cuarteto que termina en `=` y descarta un cuarteto final
//!   incompleto. Un `=` en las posiciones 0 o 1 de un cuarteto produce bytes
//!   "basura" exactamente igual que en Java.
//! * `is_base64` aplica la heurística de Java (alfabeto ampliado con `-`, `_`,
//!   `~`, tabulador y saltos de línea; `=` solo en las dos últimas
//!   posiciones; número de caracteres sin contar `\n`/`\r` múltiplo de 4).
//!
//! NOTA: la especificación (`docs/spec/07-core.md` §7.1) dice que los
//! caracteres no válidos producen un error; en el código real
//! `WHITE_SPACE_ENC` vale `-9`, por lo que nunca se lanza ese error y los
//! caracteres desconocidos se ignoran. Aquí se reproduce el comportamiento
//! real.

const STANDARD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Alfabeto aceptado por `Base64.isBase64` de Java.
const IS_BASE64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=_-\t\n+/0123456789\r~";

/// Valor de decodificación de un byte (`-9` = no válido, `-1` = `=`), como las
/// tablas `*_DECODABET` de Java.
fn decodabet(b: u8, url_safe: bool) -> i8 {
    match b {
        b'A'..=b'Z' => (b - b'A') as i8,
        b'a'..=b'z' => (b - b'a' + 26) as i8,
        b'0'..=b'9' => (b - b'0' + 52) as i8,
        b'+' if !url_safe => 62,
        b'/' if !url_safe => 63,
        b'-' if url_safe => 62,
        b'_' if url_safe => 63,
        b'=' => -1,
        b'\t' | b'\n' | b'\r' | b' ' => -5,
        _ => -9,
    }
}

/// Error de decodificación Base64 (equivale a la `IllegalArgumentException`
/// que lanza Java con entradas de 1 a 3 caracteres).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Base64Error {
    /// `Base64-encoded string must have at least four characters, but length specified was N`
    #[error("Base64-encoded string must have at least four characters, but length specified was {0}")]
    TooShort(usize),
}

/// Codifica en Base64 estándar con relleno (`Base64.encode(byte[])`).
pub fn encode(data: &[u8]) -> String {
    encode_with(data, false)
}

/// Codifica en Base64 estándar o URL-safe, siempre con relleno
/// (`Base64.encode(byte[], boolean)`).
pub fn encode_with(data: &[u8], url_safe: bool) -> String {
    let alphabet = if url_safe { URL_SAFE_ALPHABET } else { STANDARD_ALPHABET };
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map(u32::from).unwrap_or(0);
        let b2 = chunk.get(2).copied().map(u32::from).unwrap_or(0);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[(n >> 18) as usize & 0x3f] as char);
        out.push(alphabet[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(n >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[n as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Codifica en Base64 URL-safe con relleno (`Base64.encode(data, true)`).
pub fn encode_url_safe(data: &[u8]) -> String {
    encode_with(data, true)
}

/// Decodifica con el alfabeto estándar (`Base64.decode(String)`).
pub fn decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with(s, false)
}

/// Decodifica con el alfabeto URL-safe (`Base64.decode(String, true)`).
pub fn decode_url_safe(s: &str) -> Result<Vec<u8>, Base64Error> {
    decode_with(s, true)
}

/// Decodifica un texto (`Base64.decode(String, boolean)`). El texto se
/// convierte a bytes como `String.getBytes(US-ASCII)`: cada carácter no ASCII
/// pasa a ser un `?` (que se ignora).
pub fn decode_with(s: &str, url_safe: bool) -> Result<Vec<u8>, Base64Error> {
    let bytes: Vec<u8> = s.chars().map(|c| if c.is_ascii() { c as u8 } else { b'?' }).collect();
    decode_bytes(&bytes, url_safe)
}

/// Decodifica bytes (`Base64.decode(byte[], 0, len, boolean)`).
pub fn decode_bytes(source: &[u8], url_safe: bool) -> Result<Vec<u8>, Base64Error> {
    let len = source.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if len < 4 {
        return Err(Base64Error::TooShort(len));
    }
    let mut out = Vec::with_capacity(len * 3 / 4);
    let mut b4 = [0u8; 4];
    let mut pos = 0;
    for &b in source {
        let d = decodabet(b, url_safe);
        // En Java WHITE_SPACE_ENC vale -9, así que todos los bytes pasan el
        // primer filtro y solo se guardan los del alfabeto y '='.
        if d >= -1 {
            b4[pos] = b;
            pos += 1;
            if pos > 3 {
                decode4to3(&b4, &mut out, url_safe);
                pos = 0;
                if b == b'=' {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// `decode4to3` de Java, incluido el tratamiento de `=` en posiciones no
/// finales (cuyo valor de tabla, `-1 & 0xFF`, es 255).
fn decode4to3(b4: &[u8; 4], out: &mut Vec<u8>, url_safe: bool) {
    let v = |i: usize| -> i32 { i32::from(decodabet(b4[i], url_safe) as u8) };
    if b4[2] == b'=' {
        let n = (v(0) << 18) | (v(1) << 12);
        out.push((n >> 16) as u8);
    } else if b4[3] == b'=' {
        let n = (v(0) << 18) | (v(1) << 12) | (v(2) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    } else {
        let n = (v(0) << 18) | (v(1) << 12) | (v(2) << 6) | v(3);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
}

/// `Base64.isBase64(String)` de Java.
pub fn is_base64(data: &str) -> bool {
    let chars: Vec<char> = data.chars().collect();
    is_base64_chars(&chars)
}

/// `Base64.isBase64(byte[])` de Java (los bytes no ASCII nunca son válidos).
pub fn is_base64_bytes(data: &[u8]) -> bool {
    // En Java `(char) byte` de un byte negativo da un carácter 0xFFxx, que no
    // pertenece al alfabeto.
    let chars: Vec<char> = data.iter().map(|&b| if b < 0x80 { b as char } else { '\u{ffff}' }).collect();
    is_base64_chars(&chars)
}

fn is_base64_chars(chars: &[char]) -> bool {
    let mut count = 0usize;
    for (i, &c) in chars.iter().enumerate() {
        if !IS_BASE64_ALPHABET.contains(c) {
            return false;
        }
        // Java: `i < data.length - 2` (con aritmética entera con signo).
        if c == '=' && (i as isize) < chars.len() as isize - 2 {
            return false;
        }
        if c != '\n' && c != '\r' {
            count += 1;
        }
    }
    count % 4 == 0
}

/// Decodificación tras cambiar el alfabeto URL-safe por el estándar
/// (`-`→`+`, `_`→`/`), modismo habitual en AutoFirma
/// (`AOUtil.base642Properties`, `DataDownloader`).
pub fn decode_url_safe_as_standard(s: &str) -> Result<Vec<u8>, Base64Error> {
    decode(&s.replace('-', "+").replace('_', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/core/base64.golden")).unwrap()
    }

    fn fmt_result(r: Result<Vec<u8>, Base64Error>) -> String {
        match r {
            Ok(v) => hex::encode(v),
            Err(e) => format!("ERR:IllegalArgumentException:{e}"),
        }
    }

    #[test]
    fn matches_java_oracle() {
        let g = golden();
        let mut n = 0;
        for line in g.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols[0] == "ENC" {
                let data = hex::decode(cols[1]).unwrap();
                assert_eq!(encode(&data), cols[2], "encode {}", cols[1]);
                assert_eq!(encode_url_safe(&data), cols[3], "encode url {}", cols[1]);
                n += 1;
                continue;
            }
            let input = String::from_utf8(hex::decode(cols[0]).unwrap()).unwrap();
            assert_eq!(fmt_result(decode(&input)), cols[1], "decode std {input:?}");
            assert_eq!(fmt_result(decode_url_safe(&input)), cols[2], "decode url {input:?}");
            assert_eq!(is_base64(&input).to_string(), cols[3], "isBase64 {input:?}");
            n += 1;
        }
        assert!(n > 50);
    }

    #[test]
    fn spec_edge_cases() {
        // "...==\n": el '=' queda en len-3 → no es Base64 para Java.
        assert!(!is_base64("QQ==\n"));
        assert!(is_base64(""));
        assert!(is_base64("QQ~~"));
        assert!(is_base64_bytes(b"QQ=="));
        assert!(!is_base64_bytes(&[b'Q', b'Q', 0xc3, 0xb1]));
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("Q").unwrap_err(), Base64Error::TooShort(1));
        // Cuarteto final incompleto descartado y parada tras '='.
        assert_eq!(decode("QUJDRA").unwrap(), b"ABC");
        assert_eq!(decode("QQ==QUJD").unwrap(), b"A");
        assert_eq!(decode_url_safe_as_standard("-_8=").unwrap(), vec![0xfb, 0xff]);
        // Ida y vuelta.
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
            assert_eq!(decode_url_safe(&encode_url_safe(&data)).unwrap(), data);
        }
    }
}
