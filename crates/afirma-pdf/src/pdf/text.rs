//! Cadenas de texto PDF (PDFDocEncoding / UTF-16BE) y codificación WinAnsi.

use lopdf::{Object, StringFormat};

/// Caracteres Unicode de los bytes 0x18..=0x1F de PDFDocEncoding.
const PDFDOC_18: [u16; 8] = [0x02D8, 0x02C7, 0x02C6, 0x02D9, 0x02DD, 0x02DB, 0x02DA, 0x02DC];
/// Caracteres Unicode de los bytes 0x80..=0xA0 de PDFDocEncoding (0 = sin definir).
const PDFDOC_80: [u16; 33] = [
    0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044, 0x2039, 0x203A, 0x2212, 0x2030, 0x201E, 0x201C,
    0x201D, 0x2018, 0x2019, 0x201A, 0x2122, 0xFB01, 0xFB02, 0x0141, 0x0152, 0x0160, 0x0178, 0x017D, 0x0131, 0x0142,
    0x0153, 0x0161, 0x017E, 0x0000, 0x20AC,
];

fn pdfdoc_byte(c: char) -> Option<u8> {
    let u = c as u32;
    if u < 0x18 || (0x20..0x7f).contains(&u) || ((0xa1..=0xff).contains(&u) && u != 0xad) {
        return Some(u as u8);
    }
    if let Some(i) = PDFDOC_18.iter().position(|&x| u32::from(x) == u) {
        return Some(0x18 + i as u8);
    }
    if u != 0
        && let Some(i) = PDFDOC_80.iter().position(|&x| u32::from(x) == u)
    {
        return Some(0x80 + i as u8);
    }
    None
}

fn pdfdoc_char(b: u8) -> char {
    match b {
        0x18..=0x1f => char::from_u32(u32::from(PDFDOC_18[usize::from(b - 0x18)])).unwrap_or('\u{fffd}'),
        0x80..=0xa0 => match PDFDOC_80[usize::from(b - 0x80)] {
            0 => '\u{fffd}',
            u => char::from_u32(u32::from(u)).unwrap_or('\u{fffd}'),
        },
        _ => char::from(b),
    }
}

/// Codifica un texto como cadena de texto PDF (`TEXT_UNICODE` de iText):
/// PDFDocEncoding si todos los caracteres son representables y UTF-16BE con
/// BOM en otro caso.
pub fn encode_text_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match pdfdoc_byte(c) {
            Some(b) => out.push(b),
            None => {
                let mut v = vec![0xfe, 0xff];
                for u in s.encode_utf16() {
                    v.extend_from_slice(&u.to_be_bytes());
                }
                return v;
            }
        }
    }
    out
}

/// Objeto cadena de texto PDF (literal).
pub fn text_object(s: &str) -> Object {
    Object::String(encode_text_string(s), StringFormat::Literal)
}

/// Decodifica una cadena de texto PDF.
pub fn decode_text_string(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff {
        let units: Vec<u16> = bytes[2..]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if bytes.len() >= 3 && bytes[..3] == [0xef, 0xbb, 0xbf] {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    bytes.iter().map(|&b| pdfdoc_char(b)).collect()
}

/// Texto de un objeto cadena (o nombre).
pub fn object_text(o: &Object) -> Option<String> {
    match o {
        Object::String(b, _) => Some(decode_text_string(b)),
        Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
        _ => None,
    }
}

/// Byte WinAnsi (Cp1252 de iText) de un carácter, o `None` si no se puede
/// representar (iText lo descarta).
pub fn winansi_byte(c: char) -> Option<u8> {
    let u = c as u32;
    if u < 128 || (160..=255).contains(&u) {
        return Some(u as u8);
    }
    crate::appearance::afm::WINANSI_HIGH
        .iter()
        .position(|&x| x != 0 && u32::from(x) == u)
        .map(|i| 0x80 + i as u8)
}

/// Codifica un texto en WinAnsi descartando los caracteres no
/// representables.
pub fn winansi_encode(s: &str) -> Vec<u8> {
    s.chars().filter_map(winansi_byte).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_strings() {
        assert_eq!(encode_text_string("ESPAÑOL"), b"ESPA\xd1OL");
        assert_eq!(encode_text_string("a€"), b"a\xa0");
        let u = encode_text_string("Łódź ж");
        assert_eq!(&u[..2], &[0xfe, 0xff]);
        assert_eq!(decode_text_string(&u), "Łódź ж");
        assert_eq!(decode_text_string(b"ESPA\xd1OL"), "ESPAÑOL");
        assert_eq!(winansi_encode("€uro ж"), b"\x80uro ");
    }
}
