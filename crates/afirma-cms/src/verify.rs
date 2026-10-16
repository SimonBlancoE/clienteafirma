//! Verificación criptográfica de firmas PKCS#1 v1.5 (RSA) y ECDSA con la
//! clave pública de un certificado.

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use ecdsa::signature::hazmat::PrehashVerifier;

use crate::asn1::der;
use crate::cert::CertView;
use crate::oids;

/// Error que impide verificar (clave o algoritmo no soportados, datos mal
/// formados). Una firma que no cuadra no es un error: devuelve `Ok(false)`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct VerifyError(pub String);

/// Verifica `signature` sobre `data` con la clave del certificado `cert_der`.
pub fn verify_with_certificate(
    cert_der: &[u8],
    alg: SignatureAlgorithm,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let hash = alg.digest.digest(data);
    verify_prehashed_with_certificate(cert_der, alg, &hash, signature)
}

/// Verifica una firma sobre una huella ya calculada con `alg.digest`.
pub fn verify_prehashed_with_certificate(
    cert_der: &[u8],
    alg: SignatureAlgorithm,
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let cert = CertView::parse(cert_der).map_err(|e| VerifyError(format!("certificado no válido: {e}")))?;
    let key_bits = cert.public_key_bits().ok_or_else(|| VerifyError("certificado sin clave pública".into()))?;
    match cert.key_algorithm() {
        Some(KeyAlgorithm::Rsa) => {
            if alg.key != KeyAlgorithm::Rsa {
                return Ok(false);
            }
            verify_rsa(key_bits, alg.digest, hash, signature)
        }
        Some(KeyAlgorithm::Ec) => {
            if alg.key != KeyAlgorithm::Ec {
                return Ok(false);
            }
            let curve = cert.ec_curve().map(|o| o.to_dotted()).unwrap_or_default();
            verify_ecdsa(&curve, key_bits, hash, signature)
        }
        Some(KeyAlgorithm::Dsa) => Err(VerifyError("no se soporta la verificación de firmas DSA".into())),
        None => Err(VerifyError("tipo de clave pública no soportado".into())),
    }
}

/// Verifica una firma RSA PKCS#1 v1.5 con la clave `RSAPublicKey` (PKCS#1).
pub fn verify_rsa(
    pkcs1_key: &[u8],
    digest: DigestAlgorithm,
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let key =
        rsa::RsaPublicKey::from_pkcs1_der(pkcs1_key).map_err(|e| VerifyError(format!("clave RSA no válida: {e}")))?;
    let scheme = || rsa::Pkcs1v15Sign::new_unprefixed();
    let with_null = digest.digest_info(hash);
    if key.verify(scheme(), &with_null, signature).is_ok() {
        return Ok(true);
    }
    // Algunas implementaciones omiten los parámetros NULL del DigestInfo.
    let without_null = der::sequence([der::sequence([der::oid_str(digest.oid())]), der::octet_string(hash)]);
    Ok(key.verify(scheme(), &without_null, signature).is_ok())
}

/// Verifica una firma ECDSA (DER `ECDSA-Sig-Value`) sobre una huella.
pub fn verify_ecdsa(curve_oid: &str, point: &[u8], hash: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
    let bad_key = |e: ecdsa::Error| VerifyError(format!("clave EC no válida: {e}"));
    match curve_oid {
        oids::CURVE_P256 => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(bad_key)?;
            let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else { return Ok(false) };
            Ok(vk.verify_prehash(hash, &sig).is_ok())
        }
        oids::CURVE_P384 => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(bad_key)?;
            let Ok(sig) = p384::ecdsa::Signature::from_der(signature) else { return Ok(false) };
            Ok(vk.verify_prehash(hash, &sig).is_ok())
        }
        oids::CURVE_P521 => {
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(bad_key)?;
            let Ok(sig) = p521::ecdsa::Signature::from_der(signature) else { return Ok(false) };
            Ok(vk.verify_prehash(hash, &sig).is_ok())
        }
        other => Err(VerifyError(format!("curva elíptica no soportada: {other}"))),
    }
}
