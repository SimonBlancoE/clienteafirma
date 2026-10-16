//! Núcleo de AutoFirma-rs.
//!
//! Contiene los tipos compartidos por todos los módulos: algoritmos, la
//! abstracción de clave de firma, los parámetros adicionales de las
//! operaciones (`extraParams`), la interfaz de los firmadores, los códigos de
//! error de AutoFirma y utilidades comunes (constantes, tabla de formatos,
//! expansión de políticas, detección de tipos de datos, Base64 de Java,
//! utilidades de `AOUtil`, plataforma, registro y cliente HTTP).

// `AfirmaError` es un tipo público compartido por todos los crates con campos
// públicos; su tamaño (136 bytes) es aceptable y cambiarlo rompería la API.
#![allow(clippy::result_large_err)]

pub mod algorithms;
pub mod aoutil;
pub mod asic;
pub mod base64;
pub mod cert;
pub mod constants;
pub mod error;
pub mod extra_params;
pub mod formats;
pub mod http;
pub mod javafmt;
pub mod key;
pub mod logging;
pub mod mime;
pub mod pkcs1;
pub mod platform;
pub mod policy;
pub mod protocol_version;
pub mod signer;
pub mod triphase;
pub mod validity;

use ::base64::Engine;
pub use algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
pub use error::{AfirmaError, ErrorCode, ErrorKind, Result};
pub use extra_params::ExtraParams;
pub use formats::SignerKind;
pub use key::{KeyError, SigningKey};
pub use signer::{CounterSignTarget, SignInfo, Signer, SignerNode, SignersTree, SimpleSignInfo, TimestampInfo};

/// Decodifica Base64 de forma tolerante: alfabeto estándar o URL-safe, con o
/// sin relleno, ignorando espacios y saltos de línea (como hace AutoFirma con
/// los datos recibidos desde la web). Para el comportamiento exacto del
/// `Base64` de Java usa [`base64::decode`].
pub fn base64_decode_lenient(input: &str) -> std::result::Result<Vec<u8>, ::base64::DecodeError> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim_end_matches('=');
    ::base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed)
}

/// Codifica en Base64 estándar con relleno.
pub fn base64_encode(data: &[u8]) -> String {
    ::base64::engine::general_purpose::STANDARD.encode(data)
}

/// Codifica en Base64 URL-safe con relleno (como `Base64.encode(data, true)`
/// de AutoFirma).
pub fn base64_encode_url_safe(data: &[u8]) -> String {
    ::base64::engine::general_purpose::URL_SAFE.encode(data)
}

/// Utilidades comunes de las pruebas (lectura de ficheros golden y formato
/// de escape del oráculo Java `tools/oracle/CoreOracle.java`).
#[cfg(test)]
pub(crate) mod test_support {
    use crate::ExtraParams;

    /// Contenido de un fichero de `testdata/core`.
    pub fn golden(name: &str) -> String {
        std::fs::read_to_string(format!("{}/../../testdata/core/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// Escape del oráculo: `\\`, `\n`, `\r`, `\t` y `\uXXXX` fuera de ASCII imprimible.
    pub fn esc(s: &str) -> String {
        let mut out = String::new();
        for u in s.encode_utf16() {
            match u {
                0x5c => out.push_str("\\\\"),
                0x0a => out.push_str("\\n"),
                0x0d => out.push_str("\\r"),
                0x09 => out.push_str("\\t"),
                u if !(0x20..=0x7e).contains(&u) => out.push_str(&format!("\\u{u:04x}")),
                u => out.push(u as u8 as char),
            }
        }
        out
    }

    /// Inverso de [`esc`].
    pub fn unesc(s: &str) -> String {
        let mut units: Vec<u16> = Vec::new();
        let mut chars = s.chars();
        let mut buf = [0u16; 2];
        while let Some(c) = chars.next() {
            if c != '\\' {
                units.extend_from_slice(c.encode_utf16(&mut buf));
                continue;
            }
            match chars.next() {
                Some('n') => units.push(10),
                Some('r') => units.push(13),
                Some('t') => units.push(9),
                Some('\\') => units.push(u16::from(b'\\')),
                Some('u') => {
                    let h: String = chars.by_ref().take(4).collect();
                    units.push(u16::from_str_radix(&h, 16).unwrap());
                }
                other => panic!("escape {other:?}"),
            }
        }
        String::from_utf16_lossy(&units)
    }

    /// Formato `clave=valor|...` ordenado del oráculo.
    pub fn sorted(p: &ExtraParams) -> String {
        p.iter()
            .map(|(k, v)| format!("{}={}", esc(k), esc(v)))
            .collect::<Vec<_>>()
            .join("|")
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn lenient_base64() {
        assert_eq!(super::base64_decode_lenient("aG9s\nYQ==").unwrap(), b"hola");
        assert_eq!(super::base64_decode_lenient("aG9sYQ").unwrap(), b"hola");
        assert_eq!(super::base64_decode_lenient("-_8").unwrap(), vec![0xfb, 0xff]);
    }
}
