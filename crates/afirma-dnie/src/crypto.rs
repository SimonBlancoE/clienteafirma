//! Primitivas simétricas de PACE y CWA-14890: AES-128 (ECB/CBC), AES-CMAC, 3DES de dos claves
//! (CBC con IV nulo), MAC «retail» ISO/IEC 9797-1 algoritmo 3, relleno ISO/IEC 9797-1 método 2
//! y derivación de claves SHA-1 (especificación 10 §4.3, §5, §6.3 y §6.4).
//!
//! Los modos (CBC, CMAC, MAC retail) se implementan aquí sobre los cifradores de bloque de
//! RustCrypto (`aes`, `des`): son pocas líneas y así el formato de cada operación queda a la
//! vista junto a la especificación.

use aes::Aes128;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::{Des, TdesEde2};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::DnieError;

/// Clave de sesión de 16 octetos (AES-128 o 3DES de dos claves). Se borra al liberarse.
pub type Key16 = Zeroizing<[u8; 16]>;

fn aes_cipher(key: &[u8; 16]) -> Aes128 {
    Aes128::new(key.into())
}

fn block16(b: &mut [u8]) -> &mut cipher::Block<Aes128> {
    <&mut cipher::Block<Aes128>>::try_from(b).expect("bloque de 16 octetos")
}

fn block8<C: cipher::BlockSizeUser<BlockSize = cipher::consts::U8>>(b: &mut [u8]) -> &mut cipher::Block<C> {
    <&mut cipher::Block<C>>::try_from(b).expect("bloque de 8 octetos")
}

/// AES-128-ECB de un único bloque.
pub fn aes_ecb_encrypt(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    aes_cipher(key).encrypt_block(block16(&mut out));
    out
}

/// AES-128-CBC sin relleno.
pub fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, DnieError> {
    if !data.len().is_multiple_of(16) {
        return Err(DnieError::SecureMessaging("Datos AES no alineados a 16 octetos".into()));
    }
    let c = aes_cipher(key);
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0 {
        let mut b = [0u8; 16];
        for i in 0..16 {
            b[i] = chunk[i] ^ prev[i];
        }
        c.encrypt_block(block16(&mut b));
        out.extend_from_slice(&b);
        prev = b;
    }
    Ok(out)
}

/// AES-128-CBC sin relleno, descifrado.
pub fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, DnieError> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(DnieError::SecureMessaging(
            "Criptograma AES con longitud no válida".into(),
        ));
    }
    let c = aes_cipher(key);
    let mut prev = *iv;
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    for chunk in data.as_chunks::<16>().0 {
        let mut b = [0u8; 16];
        b.copy_from_slice(chunk);
        c.decrypt_block(block16(&mut b));
        for i in 0..16 {
            b[i] ^= prev[i];
        }
        out.extend_from_slice(&b);
        b.zeroize();
        prev.copy_from_slice(chunk);
    }
    Ok(out)
}

/// AES-CMAC (NIST SP 800-38B) completo de 16 octetos.
pub fn aes_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let c = aes_cipher(key);
    let mut l = [0u8; 16];
    c.encrypt_block(block16(&mut l));
    let k1 = dbl(&l);
    let k2 = dbl(&k1);
    l.zeroize();
    let n = data.len().div_ceil(16).max(1);
    let complete = !data.is_empty() && data.len().is_multiple_of(16);
    let mut x = [0u8; 16];
    for i in 0..n {
        let mut m = [0u8; 16];
        let chunk = &data[(i * 16).min(data.len())..((i + 1) * 16).min(data.len())];
        m[..chunk.len()].copy_from_slice(chunk);
        if i + 1 == n {
            if complete {
                for j in 0..16 {
                    m[j] ^= k1[j];
                }
            } else {
                m[chunk.len()] = 0x80;
                for j in 0..16 {
                    m[j] ^= k2[j];
                }
            }
        }
        for j in 0..16 {
            x[j] ^= m[j];
        }
        c.encrypt_block(block16(&mut x));
    }
    x
}

/// Multiplicación por x en GF(2^128) (subclaves de CMAC).
fn dbl(b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        out[i] = (b[i] << 1) | carry;
        carry = b[i] >> 7;
    }
    // Reducción en tiempo constante.
    out[15] ^= 0x87 & 0u8.wrapping_sub(carry);
    out
}

/// AES-CMAC truncado a 8 octetos (el «CMAC de 64 bits» de Bouncy Castle).
pub fn aes_cmac8(key: &[u8; 16], data: &[u8]) -> [u8; 8] {
    let full = aes_cmac(key, data);
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

fn tdes(key: &[u8; 16]) -> TdesEde2 {
    TdesEde2::new(key.into())
}

/// 3DES-CBC de dos claves (K1‖K2‖K1) con IV nulo y sin relleno.
pub fn tdes_cbc_encrypt(key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, DnieError> {
    if !data.len().is_multiple_of(8) {
        return Err(DnieError::SecureMessaging("Datos 3DES no alineados a 8 octetos".into()));
    }
    let c = tdes(key);
    let mut prev = [0u8; 8];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<8>().0 {
        let mut b = [0u8; 8];
        for i in 0..8 {
            b[i] = chunk[i] ^ prev[i];
        }
        c.encrypt_block(block8::<TdesEde2>(&mut b));
        out.extend_from_slice(&b);
        prev = b;
    }
    Ok(out)
}

/// 3DES-CBC de dos claves con IV nulo, descifrado.
pub fn tdes_cbc_decrypt(key: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, DnieError> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(DnieError::SecureMessaging(
            "Criptograma 3DES con longitud no válida".into(),
        ));
    }
    let c = tdes(key);
    let mut prev = [0u8; 8];
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    for chunk in data.as_chunks::<8>().0 {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        c.decrypt_block(block8::<TdesEde2>(&mut b));
        for i in 0..8 {
            b[i] ^= prev[i];
        }
        out.extend_from_slice(&b);
        b.zeroize();
        prev.copy_from_slice(chunk);
    }
    Ok(out)
}

/// MAC «retail» (ISO/IEC 9797-1 algoritmo 3, DES, IV nulo) sobre `SSC ‖ datos`, con `datos`
/// ya rellenados a múltiplo de 8: `t = DES_K1(SSC)`, `t = DES_K1(t ⊕ Bi)` para cada bloque
/// salvo el último y `3DES_K1K2K1(t ⊕ B_último)`.
pub fn retail_mac(kmac: &[u8; 16], ssc: &[u8; 8], padded: &[u8]) -> Result<[u8; 8], DnieError> {
    if padded.is_empty() || !padded.len().is_multiple_of(8) {
        return Err(DnieError::SecureMessaging(
            "Datos del MAC no alineados a 8 octetos".into(),
        ));
    }
    let mut k1 = [0u8; 8];
    k1.copy_from_slice(&kmac[..8]);
    let d1 = Des::new((&k1).into());
    k1.zeroize();
    let mut t = *ssc;
    d1.encrypt_block(block8::<Des>(&mut t));
    let blocks = padded.as_chunks::<8>().0;
    for b in &blocks[..blocks.len() - 1] {
        for i in 0..8 {
            t[i] ^= b[i];
        }
        d1.encrypt_block(block8::<Des>(&mut t));
    }
    let last = blocks[blocks.len() - 1];
    for i in 0..8 {
        t[i] ^= last[i];
    }
    tdes(kmac).encrypt_block(block8::<TdesEde2>(&mut t));
    Ok(t)
}

/// Relleno ISO/IEC 9797-1 método 2 (`80 00…`) hasta múltiplo de `block`; siempre añade al
/// menos el `80`.
pub fn pad(data: &[u8], block: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + block);
    v.extend_from_slice(data);
    v.push(0x80);
    while v.len() % block != 0 {
        v.push(0);
    }
    v
}

/// Retira el relleno ISO/IEC 9797-1 método 2 (estricto: tras los datos debe haber `80` y solo
/// ceros).
pub fn unpad(data: &[u8]) -> Result<&[u8], DnieError> {
    let mut i = data.len();
    while i > 0 && data[i - 1] == 0 {
        i -= 1;
    }
    if i == 0 || data[i - 1] != 0x80 {
        return Err(DnieError::SecureMessaging(
            "Relleno ISO 7816-4 incorrecto en la respuesta".into(),
        ));
    }
    Ok(&data[..i - 1])
}

/// Derivación de claves `SHA-1(K ‖ c)[0..16]` con contador de 32 bits (`c = 1` cifrado, `2` MAC,
/// `3` contraseña PACE).
pub fn kdf_sha1(secret: &[u8], counter: u32) -> Key16 {
    let mut h = Sha1::new();
    h.update(secret);
    h.update(counter.to_be_bytes());
    let mut d = h.finalize();
    let mut k = Zeroizing::new([0u8; 16]);
    k.copy_from_slice(&d[..16]);
    d.as_mut_slice().zeroize();
    k
}

/// Comparación en tiempo constante.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    fn k16(s: &str) -> [u8; 16] {
        hx(s).try_into().unwrap()
    }

    #[test]
    fn cmac_rfc4493() {
        let k = k16("2b7e151628aed2a6abf7158809cf4f3c");
        assert_eq!(aes_cmac(&k, &[]).to_vec(), hx("bb1d6929e95937287fa37d129b756746"));
        assert_eq!(
            aes_cmac(&k, &hx("6bc1bee22e409f96e93d7e117393172a")).to_vec(),
            hx("070a16b46b4d4144f79bdd9dd04a287c")
        );
        assert_eq!(
            aes_cmac(
                &k,
                &hx("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")
            )
            .to_vec(),
            hx("dfa66747de9ae63030ca32611497c827")
        );
    }

    #[test]
    fn pace_kdf_can() {
        // §4.6: K_π("123456"), que coincide con el comentario de TestPaceDnie.testAesDec.
        assert_eq!(kdf_sha1(b"123456", 3).to_vec(), hx("591468CDA83D65219CCCB8560233600F"));
    }

    #[test]
    fn aes_cbc_roundtrip_and_sm_vector() {
        // §5.4 a (TestApduEncrypter.testPartialEncryptionAes): IV = AES-ECB(K_enc, SSC).
        let kenc = k16("F1B0D6449CEC48864C1EFABB4957D64B");
        let ssc = k16("3DE0C9658F836888BD352DBF46462F60");
        let iv = aes_ecb_encrypt(&kenc, &ssc);
        let ct = aes_cbc_encrypt(&kenc, &iv, &pad(b"Master.File", 16)).unwrap();
        assert_eq!(ct, hx("F5124EE2F53962E86E66A6D234827F0F"));
        let pt = aes_cbc_decrypt(&kenc, &iv, &ct).unwrap();
        assert_eq!(unpad(&pt).unwrap(), b"Master.File");
    }

    #[test]
    fn retail_mac_icao_bac() {
        // §6.4: MAC de la respuesta del ejemplo ICAO 9303-11 (BAC, SELECT EF.COM).
        let kmac = k16("F1CB1F1FB5ADF208806B89DC579DC1F8");
        let ssc: [u8; 8] = hx("887022120C06C228").try_into().unwrap();
        assert_eq!(
            retail_mac(&kmac, &ssc, &pad(&hx("99029000"), 8)).unwrap().to_vec(),
            hx("FA855A5D4C50A8ED")
        );
    }

    #[test]
    fn tdes_roundtrip() {
        let k = k16("598F26E36E11A8EC14B81E19BDA223CA");
        let ct = tdes_cbc_encrypt(&k, &pad(b"CRYPTOKI", 8)).unwrap();
        assert_eq!(ct, hx("CE1AB937C332F3FAEE43336D4311EF33"));
        assert_eq!(unpad(&tdes_cbc_decrypt(&k, &ct).unwrap()).unwrap(), b"CRYPTOKI");
    }

    #[test]
    fn padding() {
        assert_eq!(pad(&[], 8), hx("8000000000000000"));
        assert_eq!(pad(&[1; 8], 8).len(), 16);
        assert!(unpad(&hx("0102000000")).is_err());
        assert!(unpad(&hx("0000")).is_err());
        assert_eq!(unpad(&hx("01028000")).unwrap(), &[1, 2]);
        assert!(ct_eq(b"ab", b"ab") && !ct_eq(b"ab", b"ac") && !ct_eq(b"a", b"ab"));
    }
}
