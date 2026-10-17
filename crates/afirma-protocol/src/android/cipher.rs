//! Cifrado de los datos del servidor intermedio en Autofirma App 1.9
//! (`CipherDataManager`, `docs/spec/09-android.md` §5.9) y codificaciones Base64
//! de las respuestas.
//!
//! - Cifrar: DES/ECB/NoPadding con los bytes de la clave `key` (8 caracteres)
//!   sobre los datos rellenos con ceros hasta múltiplo de 8; salida
//!   `<d>.<Base64 URL-safe con '='>` con `d = (8 − len % 8) % 8`. Es el mismo
//!   formato que el DES del escritorio (`01-protocol.md` §8.2).
//! - Descifrar (sobres descargados con `fileid`): texto UTF-8 con `_`→`/` y
//!   `-`→`+`; si hay un `.`, `d` es el número (Java `Integer.parseInt`) que hay
//!   antes del **primer** punto; el resto se vuelve a pasar a URL-safe y se
//!   decodifica con el Base64 de `afirma-core` (que ignora los saltos de
//!   línea); se descifra y se quitan `d` bytes.
//! - Sin clave, Java decodificaba el texto ya pasado al alfabeto estándar con el
//!   decodificador URL-safe, que descarta `+` y `/` y corrompe los datos
//!   (§10 n.º 39). Aquí se decodifica con el alfabeto correcto (corrección
//!   documentada).

use afirma_core::base64 as jb64;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::Des;

/// Error de cifrado o descifrado.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CipherError {
    /// Clave DES no válida (`InvalidKeyException`).
    #[error("clave DES no válida: {0}")]
    InvalidKey(String),
    /// Relleno no numérico (`NumberFormatException`).
    #[error("relleno no válido: {0}")]
    BadPadding(String),
    /// Base64 no válido (`IllegalArgumentException` de entradas de 1 a 3 caracteres).
    #[error("Base64 no válido: {0}")]
    BadBase64(String),
    /// Longitud que no es múltiplo de 8 (`IllegalBlockSizeException`).
    #[error("Input length not multiple of 8 bytes")]
    BadLength,
    /// Relleno mayor que los datos (`NegativeArraySizeException`).
    #[error("relleno mayor que los datos")]
    PaddingTooLarge,
}

fn des(key: &[u8]) -> Result<Des, CipherError> {
    // `SecretKeySpec` + DES de Java usa los 8 primeros bytes de la clave.
    if key.len() < 8 {
        return Err(CipherError::InvalidKey(format!("{} bytes", key.len())));
    }
    Des::new_from_slice(&key[..8]).map_err(|e| CipherError::InvalidKey(e.to_string()))
}

fn block(b: &mut [u8]) -> &mut cipher::Block<Des> {
    // Los trozos proceden de `as_chunks_mut::<8>`.
    <&mut cipher::Block<Des>>::try_from(b).expect("bloque DES de 8 bytes")
}

/// `CipherDataManager.cipherData(datos, clave)`.
pub fn cipher_data(data: &[u8], key: &[u8]) -> Result<String, CipherError> {
    let des = des(key)?;
    let pad = (8 - data.len() % 8) % 8;
    let mut buf = data.to_vec();
    buf.resize(data.len() + pad, 0);
    for chunk in buf.as_chunks_mut::<8>().0 {
        des.encrypt_block(block(chunk));
    }
    Ok(format!("{pad}.{}", jb64::encode_url_safe(&buf)))
}

/// `Integer.parseInt` (base 10, con signo `+`/`-` opcional).
fn java_parse_int(s: &str) -> Option<i32> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i32>().ok()
}

/// `CipherDataManager.decipherData(datos, clave)`. Sin clave (`None`) se
/// devuelven los datos decodificados de Base64 (ver la corrección del módulo).
pub fn decipher_data(ciphered: &[u8], key: Option<&[u8]>) -> Result<Vec<u8>, CipherError> {
    let recovered = String::from_utf8_lossy(ciphered).replace('_', "/").replace('-', "+");
    let Some(key) = key else {
        return jb64::decode(&recovered).map_err(|e| CipherError::BadBase64(e.to_string()));
    };
    let (padding, b64) = match recovered.find('.') {
        Some(dot) => {
            let head = &recovered[..dot];
            let pad = java_parse_int(head).ok_or_else(|| CipherError::BadPadding(head.to_string()))?;
            (pad, &recovered[dot + 1..])
        }
        None => (0, recovered.as_str()),
    };
    let url_safe = b64.replace('+', "-").replace('/', "_");
    let mut data = jb64::decode_url_safe(&url_safe).map_err(|e| CipherError::BadBase64(e.to_string()))?;
    if !data.len().is_multiple_of(8) {
        return Err(CipherError::BadLength);
    }
    let des = des(key)?;
    for chunk in data.as_chunks_mut::<8>().0 {
        des.decrypt_block(block(chunk));
    }
    if padding != 0 {
        let len = i64::try_from(data.len()).unwrap_or(i64::MAX) - i64::from(padding);
        let len = usize::try_from(len).map_err(|_| CipherError::PaddingTooLarge)?;
        // `Arrays.copyOf` con una longitud mayor rellenaría con ceros (relleno
        // negativo); se reproduce.
        data.resize(len, 0);
    }
    Ok(data)
}

/// `android.util.Base64.encodeToString(datos, Base64.URL_SAFE)`: alfabeto
/// URL-safe con relleno `=`, un salto de línea (`\n`) cada 76 caracteres y otro
/// al final (§5.4.5, §10 n.º 38). Vacío para datos vacíos.
pub fn android_base64_url_wrapped(data: &[u8]) -> String {
    let b64 = jb64::encode_url_safe(data);
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    for line in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out
}

/// Datos de una respuesta: cifrados con la clave DES si la hay o codificados
/// con `encode` si no.
pub(crate) fn encode_or_cipher(
    data: &[u8],
    key: Option<&[u8]>,
    encode: fn(&[u8]) -> String,
) -> Result<String, CipherError> {
    match key {
        Some(k) => cipher_data(data, k),
        None => Ok(encode(data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"12345678";

    #[test]
    fn cipher_like_desktop_des() {
        // Mismos vectores que el DES del escritorio (`crate::cipher`).
        assert_eq!(cipher_data(b"hello world", KEY).unwrap(), "5.KNugLrX23UdgQtrr-lloeg==");
        assert_eq!(cipher_data(b"abcdefgh", KEY).unwrap(), "0.lNRDa8O1tpM=");
        assert_eq!(cipher_data(b"", KEY).unwrap(), "0.");
        assert!(matches!(cipher_data(b"x", b"1234567"), Err(CipherError::InvalidKey(_))));
    }

    #[test]
    fn decipher_rules() {
        let k = Some(KEY);
        assert_eq!(decipher_data(b"5.KNugLrX23UdgQtrr-lloeg==", k).unwrap(), b"hello world");
        // Salto de línea final del Retriever (println).
        assert_eq!(
            decipher_data(b"5.KNugLrX23UdgQtrr-lloeg==\n", k).unwrap(),
            b"hello world"
        );
        // Alfabeto estándar también admitido (se normaliza).
        assert_eq!(decipher_data(b"5.KNugLrX23UdgQtrr+lloeg==", k).unwrap(), b"hello world");
        // Sin prefijo de relleno.
        assert_eq!(decipher_data(b"lNRDa8O1tpM=", k).unwrap(), b"abcdefgh");
        // El relleno es el número ANTES DEL PRIMER PUNTO (no solo de un dígito).
        assert_eq!(
            decipher_data(b"05.KNugLrX23UdgQtrr-lloeg==", k).unwrap(),
            b"hello world"
        );
        // `-` pasa a `+` antes de leer el relleno: "+5" es 5 para Java.
        assert_eq!(
            decipher_data(b"-5.KNugLrX23UdgQtrr-lloeg==", k).unwrap(),
            b"hello world"
        );
        assert!(matches!(
            decipher_data(b"x.lNRDa8O1tpM=", k),
            Err(CipherError::BadPadding(_))
        ));
        assert_eq!(decipher_data(b"99.lNRDa8O1tpM=", k), Err(CipherError::PaddingTooLarge));
        assert_eq!(decipher_data(b"0.QUJD", k), Err(CipherError::BadLength));
        assert!(matches!(decipher_data(b"0.QU", k), Err(CipherError::BadBase64(_))));
        // Sin clave: Base64 (corrección: con cualquiera de los dos alfabetos).
        assert_eq!(
            decipher_data(b"PD94-_8=", None).unwrap(),
            vec![0x3c, 0x3f, 0x78, 0xfb, 0xff]
        );
        assert_eq!(decipher_data(b"PHNpZ24-PC9zaWduPg==", None).unwrap(), b"<sign></sign>");
    }

    #[test]
    fn android_base64() {
        assert_eq!(android_base64_url_wrapped(b""), "");
        assert_eq!(android_base64_url_wrapped(&[0xfb, 0xff]), "-_8=\n");
        // 57 bytes = exactamente 76 caracteres: un único salto final.
        let s = android_base64_url_wrapped(&[0u8; 57]);
        assert_eq!(s.len(), 77);
        assert!(s.ends_with("A\n"));
        // 58 bytes: dos líneas.
        let s = android_base64_url_wrapped(&[0u8; 58]);
        assert_eq!(s, format!("{}\nAA==\n", "A".repeat(76)));
    }
}
