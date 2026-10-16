//! Cifrado de los datos que viajan por el servidor intermedio
//! (`DesServerCipher`, `AesServerCipher`, `ServerCipherFactory`).
//!
//! - DES: `DES/ECB/NoPadding` sobre los datos rellenos con ceros hasta
//!   múltiplo de 8; salida `<d>.<Base64 URL-safe>` con `d` el número de bytes
//!   de relleno.
//! - AES: `AES/CBC/PKCS5Padding` con la misma IV para todo; salida Base64
//!   URL-safe. Al descifrar, si AES falla se reintenta con la clave DES
//!   `legacydes` (AutoScript sube siempre el primer sobre con DES).

use aes::{Aes128, Aes192, Aes256};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::Des;

use crate::jbase64;
use crate::json_lenient::{self, JsonValue};

/// Error al construir o usar el cifrador.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CipherError {
    /// Configuración JSON no válida (`JSONException` en Java).
    #[error("configuración de cifrado no válida: {0}")]
    InvalidConfig(String),
    /// Error de cifrado o descifrado.
    #[error("error de cifrado: {0}")]
    Crypto(String),
}

/// Cifrador acordado con la página.
#[derive(Clone, PartialEq, Eq)]
pub enum ServerCipher {
    Des {
        key: Vec<u8>,
    },
    Aes {
        key: Vec<u8>,
        iv: Vec<u8>,
        legacy_des: Vec<u8>,
    },
}

impl std::fmt::Debug for ServerCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerCipher::Des { .. } => f.write_str("ServerCipher::Des"),
            ServerCipher::Aes { .. } => f.write_str("ServerCipher::Aes"),
        }
    }
}

/// Texto de configuración generado con solo la clave DES (`key`).
pub fn des_config(key: &str) -> Vec<u8> {
    format!("{{algo:\"DES\", key:\"{key}\"}}").into_bytes()
}

/// Añade la clave DES heredada a la configuración JSON recibida en `cipher`:
/// quita el último carácter y añade `,legacydes:"<clave>"}`.
pub fn add_legacy_des(config: &[u8], key: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(config);
    let mut chars: Vec<char> = text.chars().collect();
    chars.pop();
    let mut out: String = chars.into_iter().collect();
    out.push_str(&format!(",legacydes:\"{key}\"}}"));
    out.into_bytes()
}

impl ServerCipher {
    /// `ServerCipherFactory.newServerCipher`: `Ok(None)` si el algoritmo no
    /// es ni `AES` ni `DES` (Java no cifra en ese caso).
    pub fn from_config(config: &[u8]) -> Result<Option<ServerCipher>, CipherError> {
        let text = String::from_utf8_lossy(config);
        let obj = json_lenient::parse_object(&text).map_err(CipherError::InvalidConfig)?;
        let get_string = |k: &str| -> Result<String, CipherError> {
            match obj.get(k) {
                Some(JsonValue::Str(s)) => Ok(s.clone()),
                Some(_) => Err(CipherError::InvalidConfig(format!(
                    "JSONObject[\"{k}\"] is not a string"
                ))),
                None => Err(CipherError::InvalidConfig(format!("JSONObject[\"{k}\"] not found"))),
            }
        };
        let algo = get_string("algo")?;
        match algo.as_str() {
            "AES" => {
                let key =
                    jbase64::decode(&get_string("key")?).map_err(|e| CipherError::InvalidConfig(e.to_string()))?;
                let iv = jbase64::decode(&get_string("iv")?).map_err(|e| CipherError::InvalidConfig(e.to_string()))?;
                let legacy_des = get_string("legacydes")?.into_bytes();
                Ok(Some(ServerCipher::Aes { key, iv, legacy_des }))
            }
            "DES" => Ok(Some(ServerCipher::Des {
                key: get_string("key")?.into_bytes(),
            })),
            _ => Ok(None),
        }
    }

    /// Cifra unos datos (`cipherData`).
    pub fn cipher(&self, data: &[u8]) -> Result<String, CipherError> {
        match self {
            ServerCipher::Des { key } => des_cipher(key, data),
            ServerCipher::Aes { key, iv, .. } => Ok(jbase64::encode_url_safe(&aes_cbc_encrypt(key, iv, data)?)),
        }
    }

    /// Descifra un texto (`decipherData`).
    pub fn decipher(&self, text: &str) -> Result<Vec<u8>, CipherError> {
        match self {
            ServerCipher::Des { key } => des_decipher(key, text),
            ServerCipher::Aes { key, iv, legacy_des } => {
                let normalized = jbase64::normalize(text);
                let primary = jbase64::decode(&normalized)
                    .map_err(|e| CipherError::Crypto(e.to_string()))
                    .and_then(|ct| aes_cbc_decrypt(key, iv, &ct));
                match primary {
                    Ok(v) => Ok(v),
                    Err(e) => des_decipher(legacy_des, &normalized).map_err(|_| e),
                }
            }
        }
    }
}

/// Vista de un trozo de exactamente un bloque como bloque del cifrador.
fn blk<C: cipher::BlockSizeUser>(b: &mut [u8]) -> &mut cipher::Block<C> {
    // Los trozos proceden de `chunks_exact_mut` con el tamaño del bloque.
    <&mut cipher::Block<C>>::try_from(b).expect("trozo del tamaño del bloque")
}

fn des_from_key(key: &[u8]) -> Result<Des, CipherError> {
    if key.len() < 8 {
        return Err(CipherError::Crypto(format!("clave DES de {} bytes", key.len())));
    }
    Des::new_from_slice(&key[..8]).map_err(|e| CipherError::Crypto(e.to_string()))
}

fn des_cipher(key: &[u8], data: &[u8]) -> Result<String, CipherError> {
    let des = des_from_key(key)?;
    let pad = (8 - data.len() % 8) % 8;
    let mut buf = data.to_vec();
    buf.resize(data.len() + pad, 0);
    for chunk in buf.as_chunks_mut::<8>().0 {
        des.encrypt_block(blk::<Des>(chunk));
    }
    Ok(format!("{pad}.{}", jbase64::encode_url_safe(&buf)))
}

fn des_decipher(key: &[u8], text: &str) -> Result<Vec<u8>, CipherError> {
    let crypto = |e: String| CipherError::Crypto(e);
    let chars: Vec<char> = text.chars().collect();
    let (padding, b64) = if chars.len() > 2 && chars[1] == '.' {
        let d = chars[0]
            .to_digit(10)
            .ok_or_else(|| crypto(format!("relleno no válido: {}", chars[0])))? as usize;
        (d, chars[2..].iter().collect::<String>())
    } else {
        (0, text.to_string())
    };
    let mut data = jbase64::decode(&jbase64::normalize(&b64)).map_err(|e| crypto(e.to_string()))?;
    if data.len() % 8 != 0 {
        return Err(crypto("Input length not multiple of 8 bytes".into()));
    }
    let des = des_from_key(key)?;
    for chunk in data.as_chunks_mut::<8>().0 {
        des.decrypt_block(blk::<Des>(chunk));
    }
    if padding > data.len() {
        return Err(crypto("relleno mayor que los datos".into()));
    }
    data.truncate(data.len() - padding);
    Ok(data)
}

enum AesKey {
    K128(Aes128),
    K192(Aes192),
    K256(Aes256),
}

impl AesKey {
    fn new(key: &[u8]) -> Result<AesKey, CipherError> {
        let err = |e: cipher::InvalidLength| CipherError::Crypto(e.to_string());
        match key.len() {
            16 => Ok(AesKey::K128(Aes128::new_from_slice(key).map_err(err)?)),
            24 => Ok(AesKey::K192(Aes192::new_from_slice(key).map_err(err)?)),
            32 => Ok(AesKey::K256(Aes256::new_from_slice(key).map_err(err)?)),
            n => Err(CipherError::Crypto(format!("Invalid AES key length: {n} bytes"))),
        }
    }

    fn encrypt(&self, block: &mut [u8]) {
        match self {
            AesKey::K128(c) => c.encrypt_block(blk::<Aes128>(block)),
            AesKey::K192(c) => c.encrypt_block(blk::<Aes192>(block)),
            AesKey::K256(c) => c.encrypt_block(blk::<Aes256>(block)),
        }
    }

    fn decrypt(&self, block: &mut [u8]) {
        match self {
            AesKey::K128(c) => c.decrypt_block(blk::<Aes128>(block)),
            AesKey::K192(c) => c.decrypt_block(blk::<Aes192>(block)),
            AesKey::K256(c) => c.decrypt_block(blk::<Aes256>(block)),
        }
    }
}

fn check_iv(iv: &[u8]) -> Result<(), CipherError> {
    if iv.len() != 16 {
        return Err(CipherError::Crypto("Wrong IV length: must be 16 bytes long".into()));
    }
    Ok(())
}

/// AES-CBC con relleno PKCS#5/PKCS#7.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let aes = AesKey::new(key)?;
    check_iv(iv)?;
    let pad = 16 - data.len() % 16;
    let mut buf = data.to_vec();
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    for chunk in buf.as_chunks_mut::<16>().0 {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        aes.encrypt(chunk);
        prev.copy_from_slice(chunk);
    }
    Ok(buf)
}

/// AES-CBC con relleno PKCS#5/PKCS#7 (falla si el relleno no es válido).
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherError> {
    let aes = AesKey::new(key)?;
    check_iv(iv)?;
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(CipherError::Crypto(
            "Input length must be multiple of 16 when decrypting with padded cipher".into(),
        ));
    }
    let mut buf = data.to_vec();
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);
    for chunk in buf.as_chunks_mut::<16>().0 {
        let mut saved = [0u8; 16];
        saved.copy_from_slice(chunk);
        aes.decrypt(chunk);
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = saved;
    }
    let pad = *buf.last().unwrap_or(&0) as usize;
    if pad == 0 || pad > 16 || pad > buf.len() || !buf[buf.len() - pad..].iter().all(|&b| b as usize == pad) {
        return Err(CipherError::Crypto("Given final block not properly padded".into()));
    }
    buf.truncate(buf.len() - pad);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn des(key: &str) -> ServerCipher {
        ServerCipher::from_config(&des_config(key)).unwrap().unwrap()
    }

    #[test]
    fn des_worked_examples() {
        let c = des("12345678");
        assert_eq!(c.cipher(b"hello world").unwrap(), "5.KNugLrX23UdgQtrr-lloeg==");
        assert_eq!(c.cipher(b"abcdefgh").unwrap(), "0.lNRDa8O1tpM=");
        assert_eq!(c.decipher("5.KNugLrX23UdgQtrr-lloeg==").unwrap(), b"hello world");
        assert_eq!(c.decipher("0.lNRDa8O1tpM=").unwrap(), b"abcdefgh");
        // Sin prefijo de relleno.
        assert_eq!(c.decipher("lNRDa8O1tpM=").unwrap(), b"abcdefgh");
        // Con salto de línea final (Retriever) se tolera.
        assert_eq!(c.decipher("0.lNRDa8O1tpM=\n").unwrap(), b"abcdefgh");
        assert!(c.decipher("x.lNRDa8O1tpM=").is_err());
        assert_eq!(c.cipher(b"").unwrap(), "0.");
    }

    const AES_CIPHER_PARAM: &str = "eyJhbGdvIjoiQUVTIiwia2V5IjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0iLCJpdiI6IkR3NE5EQXNLQ1FnSEJnVUVBd0lCQUE9PSIsImxlZ0RlcyI6IjEyMzQ1Njc4In0=";

    #[test]
    fn aes_worked_example() {
        let json = jbase64::decode(AES_CIPHER_PARAM).unwrap();
        let config = add_legacy_des(&json, "12345678");
        assert!(String::from_utf8_lossy(&config).ends_with(r#""legDes":"12345678",legacydes:"12345678"}"#));
        let c = ServerCipher::from_config(&config).unwrap().unwrap();
        assert_eq!(c.cipher(b"hello world").unwrap(), "fpqXEo7wtKRZNTE7CEMP2g==");
        assert_eq!(c.decipher("fpqXEo7wtKRZNTE7CEMP2g==").unwrap(), b"hello world");
        // Respaldo DES con la clave heredada.
        assert_eq!(c.decipher("5.KNugLrX23UdgQtrr-lloeg==").unwrap(), b"hello world");
        // Sin legacydes AES no se puede instanciar.
        assert!(matches!(
            ServerCipher::from_config(&json),
            Err(CipherError::InvalidConfig(_))
        ));
    }

    #[test]
    fn factory_rules() {
        assert!(
            ServerCipher::from_config(b"{algo:\"RC4\", key:\"x\"}")
                .unwrap()
                .is_none()
        );
        assert!(ServerCipher::from_config(b"{key:\"x\"}").is_err());
        assert!(ServerCipher::from_config(b"no json").is_err());
        assert!(ServerCipher::from_config(b"{algo:DES}").is_err()); // falta key
        // Valor no textual.
        assert!(ServerCipher::from_config(b"{algo:\"DES\", key:12345678}").is_err());
        assert_eq!(des_config("00000001"), b"{algo:\"DES\", key:\"00000001\"}");
    }
}
