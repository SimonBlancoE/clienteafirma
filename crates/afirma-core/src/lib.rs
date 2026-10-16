//! Núcleo de AutoFirma-rs.
//!
//! Contiene los tipos compartidos por todos los módulos: algoritmos, la
//! abstracción de clave de firma, los parámetros adicionales de las
//! operaciones (`extraParams`) y utilidades comunes.

pub mod algorithms;
pub mod extra_params;
pub mod key;

pub use algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
pub use extra_params::ExtraParams;
pub use key::{KeyError, SigningKey};

use base64::Engine;

/// Decodifica Base64 de forma tolerante: alfabeto estándar o URL-safe, con o
/// sin relleno, ignorando espacios y saltos de línea (como hace AutoFirma con
/// los datos recibidos desde la web).
pub fn base64_decode_lenient(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
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
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed)
}

/// Codifica en Base64 estándar con relleno.
pub fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Codifica en Base64 URL-safe con relleno (como `Base64.encode(data, true)`
/// de AutoFirma).
pub fn base64_encode_url_safe(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(data)
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
