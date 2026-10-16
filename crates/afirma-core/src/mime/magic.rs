//! Motor de reglas "mágicas" equivalente a JMimeMagic
//! (`net.sf.jmimemagic.Magic.getMagicMatch(byte[])`) tal y como lo usa
//! `MimeHelper`: se evalúan en orden las reglas de primer nivel del
//! `magic.xml` original ([`super::magic_table`]) y gana la primera que
//! coincide.
//!
//! Detalles reproducidos del original (comprobados con el oráculo Java):
//!
//! * Cada prueba trabaja sobre una "ventana" de los datos que empieza en el
//!   desplazamiento de la regla: 1 byte para `byte`, **4** para los `short`,
//!   8 para los `long`, la longitud del patrón para `string` y todos los datos
//!   **menos el último byte** para `regex` y el detector de texto. Si la
//!   ventana no cabe estrictamente dentro de los datos (`offset + len <
//!   data.len()`), la regla no coincide.
//! * Los comparadores son `=`, `!`, `>` y `<` (con signo); `&` nunca coincide.
//! * El detector de texto (`TextFileDetector`) considera texto la ventana
//!   decodificada como UTF-8 si todos sus caracteres son ASCII o espacios en
//!   blanco de Java (`Character.isWhitespace`) fuera del rango Latin-1.

use super::magic_table::MAGIC_RULES;

/// Regla de primer nivel de JMimeMagic.
#[derive(Debug)]
pub(crate) struct MagicRule {
    /// Tipo MIME (`???` = desconocido).
    pub mime: &'static str,
    /// Extensión (`???` = desconocida; puede ser cadena vacía).
    pub extension: &'static str,
    /// Descripción (`???` = desconocida).
    pub description: &'static str,
    pub test: MagicTest,
}

/// Prueba de una regla.
#[derive(Debug)]
pub(crate) enum MagicTest {
    String {
        offset: usize,
        value: &'static [u8],
    },
    /// Prueba de un byte (no hay ninguna de primer nivel en el `magic.xml`
    /// actual, pero el generador la admite).
    #[allow(dead_code)]
    Byte {
        offset: usize,
        mask: u8,
        value: u8,
        cmp: u8,
    },
    Short {
        offset: usize,
        big_endian: bool,
        mask: u16,
        value: u16,
        cmp: u8,
    },
    Long {
        offset: usize,
        big_endian: bool,
        mask: u64,
        value: u64,
        cmp: u8,
    },
    Regex {
        offset: usize,
        pattern: &'static str,
    },
    TextDetector,
}

/// Primera regla que coincide con los datos, como
/// `Magic.getMagicMatch(byte[])`. `None` equivale a
/// `MagicMatchNotFoundException`.
pub(crate) fn magic_match(data: &[u8]) -> Option<&'static MagicRule> {
    MAGIC_RULES.iter().find(|r| r.test.matches(data))
}

impl MagicTest {
    fn window(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
        // Java: `if (offset + length < data.length)`; con ventana vacía la
        // prueba falla (`testInternal` devuelve false para datos vacíos).
        if len == 0 || offset.checked_add(len)? >= data.len() {
            return None;
        }
        Some(&data[offset..offset + len])
    }

    fn matches(&self, data: &[u8]) -> bool {
        match *self {
            MagicTest::String { offset, value } => {
                if String::from_utf8_lossy(value)
                    .trim_matches(|c: char| c <= ' ')
                    .is_empty()
                {
                    return false;
                }
                Self::window(data, offset, value.len()).is_some_and(|w| w == value)
            }
            MagicTest::Byte {
                offset,
                mask,
                value,
                cmp,
            } => Self::window(data, offset, 1)
                .is_some_and(|w| compare(i64::from((w[0] & mask) as i8), i64::from(value as i8), cmp)),
            MagicTest::Short {
                offset,
                big_endian,
                mask,
                value,
                cmp,
            } => Self::window(data, offset, 4).is_some_and(|w| {
                let raw = if big_endian {
                    u16::from_be_bytes([w[0], w[1]])
                } else {
                    u16::from_le_bytes([w[0], w[1]])
                };
                compare(i64::from((raw & mask) as i16), i64::from(value as i16), cmp)
            }),
            MagicTest::Long {
                offset,
                big_endian,
                mask,
                value,
                cmp,
            } => Self::window(data, offset, 8).is_some_and(|w| {
                let raw = if big_endian {
                    i32::from_be_bytes([w[0], w[1], w[2], w[3]])
                } else {
                    i32::from_le_bytes([w[0], w[1], w[2], w[3]])
                };
                let v = (i64::from(raw) as u64) & mask;
                compare(v as i64, value as i64, cmp)
            }),
            MagicTest::Regex { offset, pattern } => {
                let len = data.len().saturating_sub(offset).saturating_sub(1);
                Self::window(data, offset, len).is_some_and(|w| regex_matches(pattern, &String::from_utf8_lossy(w)))
            }
            MagicTest::TextDetector => {
                let len = data.len().saturating_sub(1);
                Self::window(data, 0, len).is_some_and(is_ascii_text)
            }
        }
    }
}

fn compare(found: i64, test: i64, cmp: u8) -> bool {
    match cmp {
        b'=' => found == test,
        b'!' => found != test,
        b'>' => found > test,
        b'<' => found < test,
        _ => false,
    }
}

/// `TextFileDetector`: el patrón ORO `/[^[:ascii:][:space:]]/` no debe
/// coincidir con ningún carácter de los datos decodificados como UTF-8.
fn is_ascii_text(window: &[u8]) -> bool {
    let text = String::from_utf8_lossy(window);
    text.encode_utf16().all(|u| {
        u < 0x80 || matches!(u, 0x1680 | 0x2000..=0x2006 | 0x2008..=0x200a | 0x2028 | 0x2029 | 0x205f | 0x3000)
    })
}

/// Intérprete mínimo de los patrones Perl5 de las reglas `regex` del
/// `magic.xml` (todos de la forma `/^[\s*]literal/[m]`).
fn regex_matches(pattern: &str, text: &str) -> bool {
    let Some(body) = pattern.strip_prefix('/') else {
        return false;
    };
    let Some(end) = body.rfind('/') else { return false };
    let flags = &body[end + 1..];
    let mut expr = &body[..end];
    let multiline = flags.contains('m');
    let anchored = expr.starts_with('^');
    if anchored {
        expr = &expr[1..];
    }
    let ws_star = expr.starts_with("\\s*");
    if ws_star {
        expr = &expr[3..];
    }
    let literal = expr.replace("\\/", "/");
    let is_perl_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{c}');
    let matches_at = |s: &str| -> bool {
        let s = if ws_star {
            s.trim_start_matches(is_perl_space)
        } else {
            s
        };
        s.starts_with(&literal)
    };
    if !anchored {
        return text.contains(&literal);
    }
    if matches_at(text) {
        return true;
    }
    multiline && text.match_indices('\n').any(|(i, _)| matches_at(&text[i + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mt(data: &[u8]) -> Option<(&'static str, &'static str, &'static str)> {
        magic_match(data).map(|r| (r.mime, r.extension, r.description))
    }

    #[test]
    fn window_semantics() {
        // Igual que en Java: hace falta un byte más que la longitud de la prueba.
        assert_eq!(mt(b"PK\x03\x04").map(|m| m.0), Some("text/plain"));
        assert_eq!(mt(b"PK\x03\x04\x00").map(|m| m.0), Some("application/zip"));
        assert_eq!(mt(b"GIF8").map(|m| m.0), Some("text/plain"));
        assert_eq!(mt(b"GIF89"), Some(("image/gif", "", "GIF image data")));
        assert_eq!(mt(&[0xff, 0xd8, 0xff, 0xe0]), None);
        assert_eq!(mt(&[0xff, 0xd8, 0xff, 0xe0, 0x00]).map(|m| m.0), Some("image/jpeg"));
        assert_eq!(mt(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34]), None);
        assert_eq!(
            mt(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34, 0]).map(|m| m.0),
            Some("application/java")
        );
        assert_eq!(mt(b"MZ"), Some(("text/plain", "txt", "Texto plano")));
        assert_eq!(mt(b"MZ\x00"), Some(("???", "???", "MS-DOS executable (EXE)")));
        assert_eq!(mt(b"<?xml").map(|m| m.0), Some("text/plain"));
        assert_eq!(mt(b"<?xml ").map(|m| m.0), Some("text/xml"));
        // El detector de texto no mira el último byte.
        assert_eq!(mt(b"Hola \x80").map(|m| m.0), Some("text/plain"));
        assert_eq!(mt("abcñ".as_bytes()), None);
        assert_eq!(mt(b""), None);
        assert_eq!(mt(b"a"), None);
        assert_eq!(mt(b"ab").map(|m| m.0), Some("text/plain"));
        assert_eq!(mt("a\u{2003}b ".as_bytes()).map(|m| m.0), Some("text/plain"));
    }

    #[test]
    fn regex_rules() {
        assert!(regex_matches("/^\\s*package/", "  \n package x;"));
        assert!(!regex_matches("/^\\s*package/", "x package"));
        assert!(regex_matches("/^#include/m", "int a;\n#include <x>\n"));
        assert!(!regex_matches("/^#include/", "int a;\n#include <x>\n"));
        assert!(regex_matches("/^#!\\/bin\\/sh/", "#!/bin/sh\n"));
        assert_eq!(
            mt(b"#!/bin/bash\necho\n"),
            Some(("application/x-bash", ".sh", "bash script"))
        );
        assert_eq!(mt(b"#include <stdio.h>\n").map(|m| m.0), Some("text/x-c"));
    }
}
