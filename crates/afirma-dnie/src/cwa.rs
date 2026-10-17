//! Canal seguro CWA-14890 del DNIe 3.0/4.0: autenticación mutua de dispositivos con
//! certificados CV y RSA-1024 «crudo» (ISO 9796-2, SIGMIN), y derivación de las claves de la
//! mensajería segura 3DES (especificación 10 §6).
//!
//! El DNIe tiene dos terminales («PIN» para consultar intentos y verificar el PIN, «usuario»
//! para firmar) y dos juegos de constantes (r1/r2) elegidos por el IDESP.

use rsa::BigUint;
use rsa::traits::PublicKeyParts;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

use crate::apdu::CommandApdu;
use crate::certs;
use crate::consts;
use crate::crypto;
use crate::error::DnieError;
use crate::fs::{self, Sender};
use crate::rng::RandomSource;
use crate::sm::CwaSm;

/// Juego de constantes CWA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CwaSet {
    /// DNIe 3.0 con IDESP anterior a `BMP100001`.
    R1,
    /// Resto (incluido IDESP desconocido).
    R2,
}

/// Canal CWA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CwaChannel {
    /// Canal «de PIN»: consulta de intentos y `VERIFY`.
    Pin,
    /// Canal «de usuario»: `MSE:SET DST` y `PSO:CDS`.
    User,
}

/// IDESP a partir del cual se usan las constantes r2.
pub const DNIE3_R2_IDESP: &str = "BMP100001";

/// Elección del juego de constantes por IDESP (`DnieFactory.getDnie3*Cwa14890Constants`): r1 si
/// el IDESP es lexicográficamente menor que `BMP100001`, r2 en otro caso o si no se conoce. Se
/// compara la cadena tal cual (sin recortar), como `String.compareTo`.
pub fn cwa_set_for_idesp(idesp: Option<&str>) -> CwaSet {
    match idesp {
        Some(s) if !s.is_empty() && DNIE3_R2_IDESP > s => CwaSet::R1,
        _ => CwaSet::R2,
    }
}

/// Constantes de un terminal.
#[derive(Clone, Copy)]
pub struct Terminal {
    pub name: &'static str,
    /// Certificado CV de la CA intermedia de terminal.
    pub c_cv_ca: &'static [u8],
    pub chr_c_cv_ca: &'static [u8; 8],
    /// Certificado CV del terminal.
    pub c_cv_ifd: &'static [u8],
    /// CHR / número de serie del terminal.
    pub chr_c_cv_ifd: &'static [u8; 8],
    pub modulus: &'static [u8; 128],
    pub private_exponent: &'static [u8; 128],
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Terminal({} {})", self.name, hex::encode_upper(self.chr_c_cv_ifd))
    }
}

/// Exponente público de los terminales (al final de `5F38` de cada `C_CV_IFD`).
pub const IFD_PUBLIC_EXPONENT: u32 = 65537;

/// Constantes del terminal indicado.
pub fn terminal(set: CwaSet, channel: CwaChannel) -> Terminal {
    use consts::*;
    match (set, channel) {
        (CwaSet::R1, CwaChannel::Pin) => Terminal {
            name: "Dnie3PinCwa14890Constants",
            c_cv_ca: &R1_C_CV_CA,
            chr_c_cv_ca: &R1_CHR_C_CV_CA,
            c_cv_ifd: &R1_PIN_C_CV_IFD,
            chr_c_cv_ifd: &R1_PIN_CHR,
            modulus: &R1_PIN_MODULUS,
            private_exponent: &R1_PIN_PRIVATE_EXPONENT,
        },
        (CwaSet::R1, CwaChannel::User) => Terminal {
            name: "Dnie3UsrCwa14890Constants",
            c_cv_ca: &R1_C_CV_CA,
            chr_c_cv_ca: &R1_CHR_C_CV_CA,
            c_cv_ifd: &R1_USR_C_CV_IFD,
            chr_c_cv_ifd: &R1_USR_CHR,
            modulus: &R1_USR_MODULUS,
            private_exponent: &R1_USR_PRIVATE_EXPONENT,
        },
        (CwaSet::R2, CwaChannel::Pin) => Terminal {
            name: "Dnie3r2PinCwa14890Constants",
            c_cv_ca: &R2_C_CV_CA,
            chr_c_cv_ca: &R2_CHR_C_CV_CA,
            c_cv_ifd: &R2_PIN_C_CV_IFD,
            chr_c_cv_ifd: &R2_PIN_CHR,
            modulus: &R2_PIN_MODULUS,
            private_exponent: &R2_PIN_PRIVATE_EXPONENT,
        },
        (CwaSet::R2, CwaChannel::User) => Terminal {
            name: "Dnie3r2UsrCwa14890Constants",
            c_cv_ca: &R2_C_CV_CA,
            chr_c_cv_ca: &R2_CHR_C_CV_CA,
            c_cv_ifd: &R2_USR_C_CV_IFD,
            chr_c_cv_ifd: &R2_USR_CHR,
            modulus: &R2_USR_MODULUS,
            private_exponent: &R2_USR_PRIVATE_EXPONENT,
        },
    }
}

/// Todos los terminales (para el simulador).
pub fn all_terminals() -> [Terminal; 4] {
    [
        terminal(CwaSet::R1, CwaChannel::Pin),
        terminal(CwaSet::R1, CwaChannel::User),
        terminal(CwaSet::R2, CwaChannel::Pin),
        terminal(CwaSet::R2, CwaChannel::User),
    ]
}

/// RSA «crudo» `x^e mod n` como 128 octetos big-endian.
pub(crate) fn modpow128(x: &BigUint, e: &BigUint, n: &BigUint) -> [u8; 128] {
    let v = x.modpow(e, n).to_bytes_be();
    let mut out = [0u8; 128];
    if v.len() <= 128 {
        out[128 - v.len()..].copy_from_slice(&v);
    }
    out
}

/// Mensaje ISO 9796-2 `6A ‖ PRND(74) ‖ K(32) ‖ h(20) ‖ BC`.
pub(crate) fn message(prnd: &[u8], k: &[u8], h: &[u8]) -> Zeroizing<[u8; 128]> {
    let mut m = Zeroizing::new([0u8; 128]);
    m[0] = 0x6A;
    m[1..75].copy_from_slice(prnd);
    m[75..107].copy_from_slice(k);
    m[107..127].copy_from_slice(h);
    m[127] = 0xBC;
    m
}

fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Claves de sesión: `K = K.ICC ⊕ K.IFD`, `K_enc = SHA-1(K ‖ 1)[0..16]`,
/// `K_mac = SHA-1(K ‖ 2)[0..16]`, `SSC = RND.ICC[4..8] ‖ RND.IFD[4..8]`.
pub fn session_keys(kicc: &[u8], kifd: &[u8], rnd_icc: &[u8; 8], rnd_ifd: &[u8; 8]) -> CwaSm {
    let mut k = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        k[i] = kicc[i] ^ kifd[i];
    }
    let mut ssc = [0u8; 8];
    ssc[..4].copy_from_slice(&rnd_icc[4..]);
    ssc[4..].copy_from_slice(&rnd_ifd[4..]);
    CwaSm::new(crypto::kdf_sha1(&k[..], 1), crypto::kdf_sha1(&k[..], 2), ssc)
}

fn expect_ok(r: &crate::apdu::ResponseApdu, op: &str) -> Result<(), DnieError> {
    if r.is_ok() {
        Ok(())
    } else {
        Err(DnieError::SecureChannel(format!("{op} (respuesta {:04X})", r.sw)))
    }
}

/// Número de serie del chip (`GET CHIP INFO`, `90 B8 00 00 07`) con un `00` a la izquierda (8
/// octetos).
pub fn serial_number(send: &mut Sender<'_>) -> Result<[u8; 8], DnieError> {
    let r = send(&CommandApdu::new(0x90, 0xB8, 0x00, 0x00).with_le(7))?;
    if !r.is_ok() || r.data.is_empty() || r.data.len() > 8 {
        return Err(DnieError::card("lectura del número de serie del chip", r.sw));
    }
    let mut sn = [0u8; 8];
    sn[8 - r.data.len()..].copy_from_slice(&r.data);
    Ok(sn)
}

/// Establece un canal CWA-14890 enviando el handshake por el contexto actual (`send`). Si
/// termina bien devuelve el nuevo contexto, que **sustituye** al actual (§0.2, §6.3).
pub fn handshake(send: &mut Sender<'_>, term: &Terminal, rng: &mut dyn RandomSource) -> Result<CwaSm, DnieError> {
    // 1. Número de serie del chip.
    let sn_icc = serial_number(send)?;

    // 3. Clave pública del certificado de componente (601F).
    let icc_cert = fs::read_path(send, &fs::ICC_CERT_PATH)?;
    if certs::check_component_certificate(&icc_cert) {
        tracing::debug!("El certificado de componente está firmado por la CA de componentes del DNIe");
    } else {
        tracing::debug!("El certificado de componente no se verifica con la CA de componentes (no se exige)");
    }
    let icc_key = certs::rsa_public_key(&icc_cert)?;
    if icc_key.n().bits() != 1024 {
        return Err(DnieError::SecureChannel(format!(
            "clave de componente de {} bits (se esperaba RSA-1024)",
            icc_key.n().bits()
        )));
    }
    let n_icc = icc_key.n().clone();
    let e_icc = icc_key.e().clone();

    // 4. Cadena de certificados CV del terminal.
    let mut ref_root = vec![0x83, 0x02];
    ref_root.extend_from_slice(&consts::REF_C_CV_CA_PUBLIC_KEY);
    let r = send(&CommandApdu::new(0x00, 0x22, 0x81, 0xB6).with_data(ref_root))?;
    expect_ok(&r, "MSE:SET DST con la clave raíz CV")?;
    let r = send(&CommandApdu::new(0x00, 0x2A, 0x00, 0xAE).with_data(term.c_cv_ca.to_vec()))?;
    expect_ok(&r, "verificación del certificado CV de la CA")?;
    let mut ref_ca = vec![0x83, 0x08];
    ref_ca.extend_from_slice(term.chr_c_cv_ca);
    let r = send(&CommandApdu::new(0x00, 0x22, 0x81, 0xB6).with_data(ref_ca))?;
    expect_ok(&r, "MSE:SET DST con la CA CV")?;
    let r = send(&CommandApdu::new(0x00, 0x2A, 0x00, 0xAE).with_data(term.c_cv_ifd.to_vec()))?;
    expect_ok(&r, "verificación del certificado CV del terminal")?;

    // 5. Autenticación interna.
    let mut at = vec![0x83, 0x0C, 0x00, 0x00, 0x00, 0x00];
    at.extend_from_slice(term.chr_c_cv_ifd);
    at.extend_from_slice(&[0x84, 0x02]);
    at.extend_from_slice(&consts::REF_ICC_PRIVATE_KEY);
    let r = send(&CommandApdu::new(0x00, 0x22, 0xC1, 0xA4).with_data(at))?;
    expect_ok(&r, "MSE:SET AT para la autenticación interna")?;
    let mut rnd_ifd = [0u8; 8];
    rng.fill(&mut rnd_ifd)?;
    let mut ia = rnd_ifd.to_vec();
    ia.extend_from_slice(term.chr_c_cv_ifd);
    let r = send(&CommandApdu::new(0x00, 0x88, 0x00, 0x00).with_data(ia))?;
    expect_ok(&r, "autenticación interna")?;
    if r.data.len() != 128 {
        return Err(DnieError::SecureChannel(format!(
            "respuesta de autenticación interna de {} octetos",
            r.data.len()
        )));
    }
    let n_ifd = BigUint::from_bytes_be(term.modulus);
    let d_ifd = BigUint::from_bytes_be(term.private_exponent);
    let sigmin = BigUint::from_bytes_be(&r.data).modpow(&d_ifd, &n_ifd);
    let mut m = Zeroizing::new(modpow128(&sigmin, &e_icc, &n_icc));
    if m[0] != 0x6A || m[127] != 0xBC {
        // SIG era N.ICC − SIGMIN.
        if sigmin < n_icc {
            *m = modpow128(&(&n_icc - &sigmin), &e_icc, &n_icc);
        }
        if m[0] != 0x6A || m[127] != 0xBC {
            return Err(DnieError::SecureChannel(
                "la autenticación interna no tiene el formato ISO 9796-2 esperado".into(),
            ));
        }
    }
    let kicc = Zeroizing::new(m[75..107].to_vec());
    let h = sha1(&[&m[1..75], &kicc, &rnd_ifd, term.chr_c_cv_ifd]);
    if !crypto::ct_eq(&h, &m[107..127]) {
        return Err(DnieError::SecureChannel(
            "el resumen de la autenticación interna no es correcto".into(),
        ));
    }

    // 6. Reto de la tarjeta.
    let r = send(&CommandApdu::new(0x00, 0x84, 0x00, 0x00).with_le(8))?;
    if !r.is_ok() || r.data.len() != 8 {
        return Err(DnieError::SecureChannel(format!(
            "reto de la tarjeta (respuesta {:04X})",
            r.sw
        )));
    }
    let mut rnd_icc = [0u8; 8];
    rnd_icc.copy_from_slice(&r.data);

    // 7. Autenticación externa.
    let mut prnd2 = Zeroizing::new([0u8; 74]);
    rng.fill(&mut prnd2[..])?;
    let mut kifd = Zeroizing::new([0u8; 32]);
    rng.fill(&mut kifd[..])?;
    let h = sha1(&[&prnd2[..], &kifd[..], &rnd_icc, &sn_icc]);
    let msg = message(&prnd2[..], &kifd[..], &h);
    let sig = BigUint::from_bytes_be(&msg[..]).modpow(&d_ifd, &n_ifd);
    let alt = &n_ifd - &sig;
    let sigmin = if alt < sig { alt } else { sig };
    let data = modpow128(&sigmin, &e_icc, &n_icc);
    let r = send(&CommandApdu::new(0x00, 0x82, 0x00, 0x00).with_data(data.to_vec()))?;
    expect_ok(&r, "autenticación externa")?;

    // 8. Claves de sesión.
    let sm = session_keys(&kicc, &kifd[..], &rnd_icc, &rnd_ifd);
    rnd_ifd.zeroize();
    Ok(sm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idesp_selection() {
        // §14.2 punto 5.
        assert_eq!(cwa_set_for_idesp(Some("AAA000001")), CwaSet::R1);
        assert_eq!(cwa_set_for_idesp(Some("BMP100001")), CwaSet::R2);
        assert_eq!(cwa_set_for_idesp(Some("BMP100000")), CwaSet::R1);
        assert_eq!(cwa_set_for_idesp(Some("BMP100002\0")), CwaSet::R2);
        assert_eq!(cwa_set_for_idesp(Some("")), CwaSet::R2);
        assert_eq!(cwa_set_for_idesp(None), CwaSet::R2);
    }

    #[test]
    fn key_xor_vector() {
        // TestKeyGeneration de JMulticard (§6.3).
        let kifd = hex::decode("D8E25F213F58A31F38316AA922C48A93BAA93C8B1F7A1851D0EB746059B613FD").unwrap();
        let kicc = hex::decode("5AEF062AFD9F0DBAC9113A9E6D7AB288CC4E455DAA098DB8D18C8237E7726788").unwrap();
        let x: Vec<u8> = kifd.iter().zip(&kicc).map(|(a, b)| a ^ b).collect();
        assert_eq!(
            hex::encode_upper(x),
            "820D590BC2C7AEA5F12050374FBE381B76E779D6B57395E90167F657BEC47475"
        );
        let sm = session_keys(
            &kicc,
            &kifd,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[9, 10, 11, 12, 13, 14, 15, 16],
        );
        assert_eq!(sm.ssc(), [5, 6, 7, 8, 13, 14, 15, 16]);
    }

    #[test]
    fn terminal_constants_consistent() {
        for t in all_terminals() {
            // CV del terminal: 7F21 81CD …, termina en 00010001 (e) ‖ 42 08 CAR = CHR de la CA.
            assert_eq!(&t.c_cv_ifd[..4], &[0x7F, 0x21, 0x81, 0xCD]);
            assert_eq!(&t.c_cv_ifd[t.c_cv_ifd.len() - 10..t.c_cv_ifd.len() - 8], &[0x42, 0x08]);
            assert_eq!(&t.c_cv_ifd[t.c_cv_ifd.len() - 8..], t.chr_c_cv_ca);
            assert_eq!(
                &t.c_cv_ifd[t.c_cv_ifd.len() - 14..t.c_cv_ifd.len() - 10],
                &IFD_PUBLIC_EXPONENT.to_be_bytes()
            );
            // La clave privada corresponde al módulo: (m^d)^e = m.
            let n = BigUint::from_bytes_be(t.modulus);
            let d = BigUint::from_bytes_be(t.private_exponent);
            let m = BigUint::from_bytes_be(&[0x6A, 1, 2, 3, 0xBC]);
            let s = m.modpow(&d, &n);
            assert_eq!(s.modpow(&BigUint::from(IFD_PUBLIC_EXPONENT), &n), m, "{t:?}");
        }
    }
}
