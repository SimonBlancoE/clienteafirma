//! Operaciones criptográficas de las firmas XML: firma con [`SigningKey`]
//! (convirtiendo ECDSA a `r || s`), verificación de `SignatureValue` con la
//! clave del certificado o de un `KeyValue`, y datos de clave pública para
//! `KeyInfo`.

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::key::SigningKey;
use ecdsa::signature::hazmat::PrehashVerifier;
use x509_parser::prelude::*;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
pub const OID_P256: &str = "1.2.840.10045.3.1.7";
pub const OID_P384: &str = "1.3.132.0.34";
pub const OID_P521: &str = "1.3.132.0.35";

/// Clave pública de verificación.
#[derive(Clone)]
pub enum PublicKey {
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

/// Datos de la clave pública de un certificado para `KeyValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValueData {
    /// Módulo y exponente (big-endian sin ceros a la izquierda).
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// OID de la curva y punto sin comprimir.
    Ec { curve_oid: String, point: Vec<u8> },
}

fn strip_zeros(b: &[u8]) -> Vec<u8> {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len().saturating_sub(1));
    b[first..].to_vec()
}

/// Tipo de clave del certificado.
pub fn cert_key_algorithm(cert_der: &[u8]) -> Option<KeyAlgorithm> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    match cert.public_key().algorithm.algorithm.to_id_string().as_str() {
        OID_RSA => Some(KeyAlgorithm::Rsa),
        OID_EC => Some(KeyAlgorithm::Ec),
        "1.2.840.10040.4.1" => Some(KeyAlgorithm::Dsa),
        _ => None,
    }
}

/// OID de la curva de una clave EC del certificado.
pub fn cert_curve_oid(cert_der: &[u8]) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let params = cert.public_key().algorithm.parameters.as_ref()?;
    Some(params.as_oid().ok()?.to_id_string())
}

/// Longitud en bytes de cada mitad de una firma ECDSA en bruto.
pub fn ec_field_len(curve_oid: &str) -> Option<usize> {
    match curve_oid {
        OID_P256 => Some(32),
        OID_P384 => Some(48),
        OID_P521 => Some(66),
        _ => None,
    }
}

/// Datos de `KeyValue` de la clave pública del certificado.
pub fn key_value_data(cert_der: &[u8]) -> Option<KeyValueData> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let spki = cert.public_key();
    match spki.algorithm.algorithm.to_id_string().as_str() {
        OID_RSA => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts;
            let k = rsa::RsaPublicKey::from_pkcs1_der(&spki.subject_public_key.data).ok()?;
            Some(KeyValueData::Rsa {
                modulus: strip_zeros(&k.n().to_bytes_be()),
                exponent: strip_zeros(&k.e().to_bytes_be()),
            })
        }
        OID_EC => {
            let curve_oid = spki.algorithm.parameters.as_ref()?.as_oid().ok()?.to_id_string();
            Some(KeyValueData::Ec {
                curve_oid,
                point: spki.subject_public_key.data.to_vec(),
            })
        }
        _ => None,
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PublicKey::Rsa(_) => "PublicKey::Rsa",
            PublicKey::P256(_) => "PublicKey::P256",
            PublicKey::P384(_) => "PublicKey::P384",
            PublicKey::P521(_) => "PublicKey::P521",
        })
    }
}

impl PublicKey {
    /// Clave pública de un certificado DER.
    pub fn from_cert(cert_der: &[u8]) -> Option<PublicKey> {
        match key_value_data(cert_der)? {
            KeyValueData::Rsa { modulus, exponent } => PublicKey::from_rsa(&modulus, &exponent),
            KeyValueData::Ec { curve_oid, point } => PublicKey::from_ec(&curve_oid, &point),
        }
    }

    pub fn from_rsa(modulus: &[u8], exponent: &[u8]) -> Option<PublicKey> {
        let n = rsa::BigUint::from_bytes_be(modulus);
        let e = rsa::BigUint::from_bytes_be(exponent);
        rsa::RsaPublicKey::new(n, e).ok().map(PublicKey::Rsa)
    }

    pub fn from_ec(curve_oid: &str, point: &[u8]) -> Option<PublicKey> {
        match curve_oid {
            OID_P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .ok()
                .map(PublicKey::P256),
            OID_P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .ok()
                .map(PublicKey::P384),
            OID_P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .ok()
                .map(PublicKey::P521),
            _ => None,
        }
    }

    pub fn key_algorithm(&self) -> KeyAlgorithm {
        match self {
            PublicKey::Rsa(_) => KeyAlgorithm::Rsa,
            _ => KeyAlgorithm::Ec,
        }
    }

    /// Verifica un `SignatureValue` XMLDSig (PKCS#1 v1.5 o ECDSA `r || s`)
    /// sobre `data` con el algoritmo de huella `digest`.
    pub fn verify(&self, digest: DigestAlgorithm, data: &[u8], signature: &[u8]) -> bool {
        let hash = digest.digest(data);
        match self {
            PublicKey::Rsa(k) => {
                let scheme = match digest {
                    DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                    DigestAlgorithm::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
                    DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                    DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                    DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                };
                k.verify(scheme, &hash, signature).is_ok()
            }
            PublicKey::P256(k) => {
                p256::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verify_prehash(&hash, &s).is_ok())
            }
            PublicKey::P384(k) => {
                p384::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verify_prehash(&hash, &s).is_ok())
            }
            PublicKey::P521(k) => {
                p521::ecdsa::Signature::from_slice(signature).is_ok_and(|s| k.verify_prehash(&hash, &s).is_ok())
            }
        }
    }
}

/// Firma `data` con la clave y devuelve el valor para `SignatureValue`
/// (PKCS#1 v1.5 para RSA, `r || s` para ECDSA).
pub fn sign_xml(key: &dyn SigningKey, algorithm: SignatureAlgorithm, data: &[u8]) -> afirma_core::Result<Vec<u8>> {
    let sig = key.sign(data, algorithm).map_err(AfirmaError::from)?;
    if algorithm.key == KeyAlgorithm::Ec {
        let field = cert_curve_oid(key.certificate())
            .and_then(|o| ec_field_len(&o))
            .unwrap_or_else(|| afirma_core::key::ecdsa_format::guess_field_len(&sig));
        // Algunas claves (PKCS#11, CNG) ya devuelven r || s.
        if sig.len() == 2 * field && sig.first() != Some(&0x30) {
            return Ok(sig);
        }
        return afirma_core::key::ecdsa_format::der_to_raw(&sig, field)
            .ok_or_else(|| AfirmaError::new(codes::SIGNING_PKCS1_ERROR, "Firma ECDSA con formato no reconocido"));
    }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip() {
        assert_eq!(strip_zeros(&[0, 0, 1, 2]), vec![1, 2]);
        assert_eq!(strip_zeros(&[0]), vec![0]);
    }
}
