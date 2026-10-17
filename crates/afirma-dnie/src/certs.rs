//! Certificados del DNIe: descompresión (cabecera de 8 octetos + zlib), análisis X.509 mínimo,
//! clave pública RSA, verificación de firmas de certificado y cadena con las raíces del DNIe
//! (especificación 10 §7.5 y §7.7).

use std::io::Read;

use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::DnieError;
use crate::tlv;

/// Raíz «AC RAIZ DNIE 2» (SHA-256 `C5C380EB…6C11`), primera en probarse.
pub const ROOT_DNIE_2: &[u8] = include_bytes!("../data/roots/ACRAIZ-SHA2-2.der");
/// Raíz «AC RAIZ DNIE» (SHA-256 `F5792110…30F5`).
pub const ROOT_DNIE: &[u8] = include_bytes!("../data/roots/ACRAIZ-SHA2.der");

/// Límite del certificado descomprimido.
const MAX_CERT: usize = 64 * 1024;

/// Descomprime un certificado del DNIe: zlib sobre `datos[8..]` (los 8 primeros octetos se
/// ignoran, como JMulticard); si no es zlib, se toman los datos como DER. El resultado debe ser
/// un único `Certificate` DER (en datos sin comprimir se admite relleno final `00`/`FF`).
pub fn decompress_certificate(data: &[u8]) -> Result<Vec<u8>, DnieError> {
    if data.is_empty() {
        return Err(DnieError::Read("Fichero de certificado vacío".into()));
    }
    if data.len() > 8 {
        let mut out = Vec::new();
        let dec = flate2::read::ZlibDecoder::new(&data[8..])
            .take(MAX_CERT as u64 + 1)
            .read_to_end(&mut out);
        if dec.is_ok() && !out.is_empty() {
            let declared = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if declared != out.len() {
                tracing::debug!(
                    "Cabecera del certificado comprimido: longitud declarada {declared}, real {}",
                    out.len()
                );
            }
            let (t, used) = tlv::parse_one(&out)?;
            if t.tag != 0x30 || used != out.len() {
                return Err(DnieError::Read(
                    "El certificado descomprimido no es un DER válido".into(),
                ));
            }
            return Ok(out);
        }
    }
    let (t, used) = tlv::parse_one(data)?;
    if t.tag != 0x30 || data[used..].iter().any(|b| *b != 0x00 && *b != 0xFF) {
        return Err(DnieError::Read("El fichero de certificado no es zlib ni DER".into()));
    }
    Ok(data[..used].to_vec())
}

/// Partes de un certificado X.509 necesarias aquí.
#[derive(Debug, Clone)]
pub struct ParsedCertificate<'a> {
    /// `tbsCertificate` codificado.
    pub tbs: &'a [u8],
    /// OID (valor) del algoritmo de firma.
    pub signature_algorithm: &'a [u8],
    /// Firma (sin el octeto de bits no usados).
    pub signature: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// `SubjectPublicKeyInfo` codificado.
    pub spki: &'a [u8],
}

/// Analiza un certificado X.509 DER.
pub fn parse_certificate(der: &[u8]) -> Result<ParsedCertificate<'_>, DnieError> {
    let bad = |m: &str| DnieError::Read(format!("Certificado X.509 no válido: {m}"));
    let (cert, used) = tlv::parse_one(der)?;
    if cert.tag != 0x30 || used != der.len() {
        return Err(bad("no es una SEQUENCE única"));
    }
    let parts = cert.children()?;
    if parts.len() != 3 || parts[0].tag != 0x30 || parts[1].tag != 0x30 || parts[2].tag != 0x03 {
        return Err(bad("estructura"));
    }
    let alg = parts[1].child(0x06)?.ok_or_else(|| bad("algoritmo de firma"))?;
    let sig = parts[2].value;
    if sig.first() != Some(&0) {
        return Err(bad("firma"));
    }
    let tbs = parts[0].children()?;
    let base = usize::from(tbs.first().is_some_and(|t| t.tag == 0xA0));
    let get = |i: usize| tbs.get(base + i).ok_or_else(|| bad("campos del tbsCertificate"));
    Ok(ParsedCertificate {
        tbs: parts[0].raw,
        signature_algorithm: alg.value,
        signature: &sig[1..],
        issuer: get(2)?.raw,
        subject: get(4)?.raw,
        spki: get(5)?.raw,
    })
}

/// Clave pública RSA de un certificado.
pub fn rsa_public_key(der: &[u8]) -> Result<RsaPublicKey, DnieError> {
    let c = parse_certificate(der)?;
    RsaPublicKey::from_public_key_der(c.spki)
        .map_err(|e| DnieError::Read(format!("El certificado no contiene una clave RSA válida: {e}")))
}

/// Longitud del módulo en bits.
pub fn modulus_bits(key: &RsaPublicKey) -> usize {
    key.n().bits()
}

const OID_SHA1_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
const OID_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_SHA384_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_SHA512_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

/// Verifica la firma RSA PKCS#1 v1.5 de `tbs` con la clave indicada.
pub fn verify_tbs(key: &RsaPublicKey, alg: &[u8], tbs: &[u8], sig: &[u8]) -> bool {
    let r = match alg {
        OID_SHA1_RSA => key.verify(Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(tbs), sig),
        OID_SHA256_RSA => key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(tbs), sig),
        OID_SHA384_RSA => key.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(tbs), sig),
        OID_SHA512_RSA => key.verify(Pkcs1v15Sign::new::<Sha512>(), &Sha512::digest(tbs), sig),
        _ => return false,
    };
    r.is_ok()
}

/// Indica si `cert` está firmado por la clave de `issuer` (y su emisor coincide con el titular de
/// `issuer`).
pub fn is_signed_by(cert: &[u8], issuer: &[u8]) -> bool {
    let (Ok(c), Ok(i)) = (parse_certificate(cert), parse_certificate(issuer)) else {
        return false;
    };
    if c.issuer != i.subject {
        return false;
    }
    let Ok(key) = RsaPublicKey::from_public_key_der(i.spki) else {
        return false;
    };
    verify_tbs(&key, c.signature_algorithm, c.tbs, c.signature)
}

/// Cadena como `DnieKeyStoreImpl.engineGetCertificateChain` (§7.7): el certificado, la CA
/// intermedia si existe y, si hay intermedia, la primera raíz del DNIe que la verifique
/// («AC RAIZ DNIE 2» y después «AC RAIZ DNIE»).
pub fn build_chain(cert: &[u8], intermediate: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut chain = vec![cert.to_vec()];
    if let Some(ca) = intermediate {
        chain.push(ca.to_vec());
        if let Some(root) = [ROOT_DNIE_2, ROOT_DNIE].into_iter().find(|r| is_signed_by(ca, r)) {
            chain.push(root.to_vec());
        }
    }
    chain
}

/// Mejora opcional C1: comprueba si el certificado de componente está firmado por la CA de
/// componentes del DNIe (`CA_COMPONENT_PUBLIC_KEY`). Solo se registra; nunca se rechaza
/// (JMulticard no lo comprueba).
pub fn check_component_certificate(der: &[u8]) -> bool {
    let Ok(c) = parse_certificate(der) else {
        return false;
    };
    let Ok(key) = RsaPublicKey::from_public_key_der(&crate::consts::CA_COMPONENT_PUBLIC_KEY) else {
        return false;
    };
    verify_tbs(&key, c.signature_algorithm, c.tbs, c.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tools/oracle/dnie/data/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn decompress_simulator_certs() {
        for fid in ["7001", "7002", "7003"] {
            let der = decompress_certificate(&data(&format!("cert_{fid}.bin"))).unwrap();
            assert_eq!(der, data(&format!("cert_{fid}.der")));
            let key = rsa_public_key(&der).unwrap();
            assert_eq!(modulus_bits(&key), 2048);
        }
        // Sin comprimir (certificado de componente) y con relleno.
        let icc = data("icc_cert.der");
        assert_eq!(decompress_certificate(&icc).unwrap(), icc);
        let mut padded = icc.clone();
        padded.extend_from_slice(&[0; 16]);
        assert_eq!(decompress_certificate(&padded).unwrap(), icc);
        assert_eq!(modulus_bits(&rsa_public_key(&icc).unwrap()), 1024);
        // Datos corruptos.
        assert!(decompress_certificate(&[0x30, 0x82, 0x01]).is_err());
        let mut bad = data("cert_7001.bin");
        bad.truncate(200);
        assert!(decompress_certificate(&bad).is_err());
        assert!(decompress_certificate(&[]).is_err());
    }

    #[test]
    fn chain_and_signatures() {
        let ca = data("cert_7003.der");
        let firma = data("cert_7002.der");
        assert!(is_signed_by(&firma, &ca));
        assert!(!is_signed_by(&ca, &firma));
        // La CA del simulador no la firma ninguna raíz del DNIe: cadena de dos.
        assert_eq!(build_chain(&firma, Some(&ca)).len(), 2);
        assert_eq!(build_chain(&firma, None).len(), 1);
        // Las raíces del DNIe son autofirmadas.
        assert!(is_signed_by(ROOT_DNIE, ROOT_DNIE));
        assert!(is_signed_by(ROOT_DNIE_2, ROOT_DNIE_2));
        assert!(!check_component_certificate(&data("icc_cert.der")));
    }
}
