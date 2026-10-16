//! Cifrado reversible de la contraseña del proxy (`ProxyUtil.cipherPassword` /
//! `decipherPassword`), necesario para leer y migrar los valores existentes.
//!
//! Es una ofuscación con claves fijas públicas, no una protección real: AES-256-CBC con
//! PKCS#7 y salida en Base64 URL-safe con relleno; alternativa heredada DES/ECB sin relleno
//! con formato `<relleno>.<base64>`.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::Engine as _;
use des::cipher::{BlockCipherDecrypt, KeyInit};

const AES_KEY_B64: &str = "3zevqLjBQTqWKCDEev3kNyjRWQpeuKe3xYlcdGmBYZE=";
const AES_IV_B64: &str = "NKAe+g8shVCYWEEhLNPU0A==";
const DES_KEY: &[u8; 8] = b"8W{t2r,B";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn aes_key_iv() -> ([u8; 32], [u8; 16]) {
    let mut k = [0u8; 32];
    let mut iv = [0u8; 16];
    if let Ok(v) = b64().decode(AES_KEY_B64) {
        k.copy_from_slice(&v);
    }
    if let Ok(v) = b64().decode(AES_IV_B64) {
        iv.copy_from_slice(&v);
    }
    (k, iv)
}

/// Cifra la contraseña como Java (AES, Base64 URL-safe con relleno). `None` si está vacía.
pub fn cipher_password(password: &str) -> Option<String> {
    if password.is_empty() {
        return None;
    }
    let (k, iv) = aes_key_iv();
    let enc = cbc::Encryptor::<aes::Aes256>::new(&k.into(), &iv.into())
        .encrypt_padded_vec::<Pkcs7>(password.as_bytes());
    Some(base64::engine::general_purpose::URL_SAFE.encode(enc))
}

/// Descifra una contraseña guardada (AES y, si falla, el formato DES heredado).
pub fn decipher_password(ciphered: &str) -> Option<String> {
    if ciphered.is_empty() {
        return None;
    }
    let std_b64 = ciphered.replace('_', "/").replace('-', "+");
    if let Ok(data) = b64().decode(std_b64.trim()) {
        let (k, iv) = aes_key_iv();
        if let Ok(p) = cbc::Decryptor::<aes::Aes256>::new(&k.into(), &iv.into())
            .decrypt_padded_vec::<Pkcs7>(&data)
            && let Ok(s) = String::from_utf8(p)
        {
            return Some(s);
        }
    }
    decipher_des(ciphered)
}

fn decipher_des(ciphered: &str) -> Option<String> {
    let chars: Vec<char> = ciphered.chars().collect();
    let (padding, body) = if chars.len() > 2 && chars[1] == '.' {
        (chars[0].to_digit(10)? as usize, &ciphered[2..])
    } else {
        (0, ciphered)
    };
    let data = b64()
        .decode(body.replace('-', "+").replace('_', "/").trim())
        .ok()?;
    if data.is_empty() || data.len() % 8 != 0 {
        return None;
    }
    let cipher = des::Des::new_from_slice(DES_KEY).ok()?;
    let mut out = data.clone();
    for block in out.chunks_mut(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(block);
        cipher.decrypt_block((&mut b).into());
        block.copy_from_slice(&b);
    }
    out.truncate(out.len().checked_sub(padding)?);
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ida_y_vuelta_aes() {
        for p in ["secreto", "contraseña con ñ", "a", "0123456789abcdef0123"] {
            let c = cipher_password(p).unwrap();
            assert!(!c.contains('+') && !c.contains('/'));
            assert_eq!(decipher_password(&c).as_deref(), Some(p));
        }
        assert_eq!(cipher_password(""), None);
    }

    #[test]
    fn formato_des_heredado() {
        use des::cipher::BlockCipherEncrypt;
        let pwd = b"proxy1";
        let mut data = [0u8; 8];
        data[..pwd.len()].copy_from_slice(pwd);
        let c = des::Des::new_from_slice(DES_KEY).unwrap();
        c.encrypt_block((&mut data).into());
        let s = format!(
            "2.{}",
            base64::engine::general_purpose::URL_SAFE.encode(data)
        );
        assert_eq!(decipher_password(&s).as_deref(), Some("proxy1"));
    }
}
