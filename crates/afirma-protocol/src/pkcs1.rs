//! Firma PKCS#1 con autoverificación (`AOPkcs1Signer.sign`), usada por la
//! firma trifásica y por lotes sobre las prefirmas (`PRE`) del servidor.

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm, compose_signature_algorithm};
use afirma_core::error::codes;
use afirma_core::{AfirmaError, SigningKey};
use x509_parser::prelude::*;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";

/// Resultado de verificar una firma con la clave pública de un certificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Valid,
    Invalid,
    /// No se pudo verificar (formato de clave o firma no soportado).
    Error(String),
}

/// Firma `data` (se calcula la huella internamente) con el algoritmo
/// compuesto a partir de `algorithm` y del tipo de la clave, y comprueba la
/// firma con el certificado de la clave (ETSI TS 119 102-1).
pub fn sign(key: &dyn SigningKey, algorithm: &str, data: &[u8]) -> Result<Vec<u8>, AfirmaError> {
    let alg = compose_signature_algorithm(algorithm, key.key_algorithm())?;
    let signature = key.sign(data, alg).map_err(AfirmaError::from)?;
    match verify(key.certificate(), alg, data, &signature) {
        Verification::Valid => Ok(signature),
        Verification::Invalid => Err(AfirmaError::new(
            codes::INVALID_PKCS1_VALUE,
            "El PKCS#1 de firma obtenido no se genero con el certificado indicado",
        )),
        Verification::Error(e) if e.starts_with("no soportado") => {
            tracing::warn!("No se ha podido comprobar la firma PKCS#1 generada: {e}");
            Ok(signature)
        }
        Verification::Error(e) => Err(AfirmaError::new(codes::VERIFING_PKCS1_ERROR, format!("No se pudo verificar la firma generada: {e}"))),
    }
}

/// Verifica una firma PKCS#1 v1.5 (RSA) o ECDSA DER con la clave pública de
/// un certificado.
pub fn verify(cert_der: &[u8], alg: SignatureAlgorithm, data: &[u8], signature: &[u8]) -> Verification {
    let cert = match X509Certificate::from_der(cert_der) {
        Ok((_, c)) => c,
        Err(e) => return Verification::Error(format!("certificado no válido: {e}")),
    };
    let spki = cert.public_key();
    let key_oid = spki.algorithm.algorithm.to_id_string();
    let hash = alg.digest.digest(data);
    match (key_oid.as_str(), alg.key) {
        (OID_RSA, KeyAlgorithm::Rsa) => verify_rsa(&spki.subject_public_key.data, alg.digest, &hash, signature),
        (OID_EC, KeyAlgorithm::Ec) => {
            let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.as_oid().ok()).map(|o| o.to_id_string());
            verify_ecdsa(curve.as_deref().unwrap_or(""), &spki.subject_public_key.data, &hash, signature)
        }
        (OID_RSA, _) | (OID_EC, _) => Verification::Invalid,
        (other, _) => Verification::Error(format!("no soportado: clave {other}")),
    }
}

fn verify_rsa(pkcs1_key: &[u8], digest: DigestAlgorithm, hash: &[u8], signature: &[u8]) -> Verification {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let key = match rsa::RsaPublicKey::from_pkcs1_der(pkcs1_key) {
        Ok(k) => k,
        Err(e) => return Verification::Error(format!("clave RSA no válida: {e}")),
    };
    let scheme = match digest {
        DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
        DigestAlgorithm::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
        DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
        DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
        DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
        #[allow(unreachable_patterns)]
        _ => return Verification::Error(format!("no soportado: huella {digest:?}")),
    };
    match key.verify(scheme, hash, signature) {
        Ok(()) => Verification::Valid,
        Err(_) => Verification::Invalid,
    }
}

fn verify_ecdsa(curve_oid: &str, point: &[u8], hash: &[u8], signature: &[u8]) -> Verification {
    use ecdsa::signature::hazmat::PrehashVerifier;
    macro_rules! check {
        ($c:ident) => {{
            let Ok(vk) = $c::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return Verification::Error("punto EC no válido".into());
            };
            let Ok(sig) = $c::ecdsa::Signature::from_der(signature) else { return Verification::Invalid };
            if vk.verify_prehash(hash, &sig).is_ok() { Verification::Valid } else { Verification::Invalid }
        }};
    }
    match curve_oid {
        OID_P256 => check!(p256),
        OID_P384 => check!(p384),
        OID_P521 => {
            let Ok(vk) = p521::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return Verification::Error("punto EC no válido".into());
            };
            let Ok(sig) = p521::ecdsa::Signature::from_der(signature) else { return Verification::Invalid };
            if vk.verify_prehash(hash, &sig).is_ok() { Verification::Valid } else { Verification::Invalid }
        }
        other => Verification::Error(format!("no soportado: curva {other}")),
    }
}
