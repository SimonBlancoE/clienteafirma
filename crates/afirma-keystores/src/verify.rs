//! Verificación de la firma recién generada con el certificado (ETSI TS 119
//! 102-1), como hace `AOPkcs1Signer` de Java tras firmar con cualquier
//! almacén: si la firma no se verifica con la clave pública de `chain[0]` se
//! devuelve `INVALID_PKCS1_VALUE` (200112); si la verificación no puede
//! hacerse, `VERIFING_PKCS1_ERROR` (200113).

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::key::{KeyError, SigningKey};
use x509_parser::prelude::*;

/// Mensaje de Java cuando la firma no corresponde al certificado.
pub const MISMATCH_MESSAGE: &str = "El PKCS#1 de firma obtenido no se genero con el certificado indicado";

/// Resultado negativo de la verificación.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// La firma no se generó con la clave del certificado.
    #[error("El PKCS#1 de firma obtenido no se genero con el certificado indicado")]
    Mismatch,
    /// No se pudo verificar (certificado o algoritmo no soportado...).
    #[error("No se pudo verificar la firma generada: {0}")]
    Error(String),
}

impl From<VerifyError> for AfirmaError {
    fn from(e: VerifyError) -> Self {
        match e {
            VerifyError::Mismatch => AfirmaError::new(codes::INVALID_PKCS1_VALUE, MISMATCH_MESSAGE),
            VerifyError::Error(m) => AfirmaError::new(codes::VERIFING_PKCS1_ERROR, m),
        }
    }
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_DSA: &str = "1.2.840.10040.4.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";

/// Curva elíptica de una clave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// Longitud en bytes de cada mitad (`r`, `s`) de una firma en bruto.
    pub fn field_len(self) -> usize {
        match self {
            EcCurve::P256 => 32,
            EcCurve::P384 => 48,
            EcCurve::P521 => 66,
        }
    }

    pub fn from_oid(oid: &str) -> Option<EcCurve> {
        match oid {
            OID_P256 => Some(EcCurve::P256),
            OID_P384 => Some(EcCurve::P384),
            OID_P521 => Some(EcCurve::P521),
            _ => None,
        }
    }

    /// Tamaño de la clave en bits.
    pub fn bits(self) -> usize {
        match self {
            EcCurve::P256 => 256,
            EcCurve::P384 => 384,
            EcCurve::P521 => 521,
        }
    }
}

/// Tipo de clave pública del certificado.
pub fn certificate_key_algorithm(cert_der: &[u8]) -> Option<KeyAlgorithm> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    match cert.public_key().algorithm.algorithm.to_id_string().as_str() {
        OID_RSA => Some(KeyAlgorithm::Rsa),
        OID_EC => Some(KeyAlgorithm::Ec),
        OID_DSA => Some(KeyAlgorithm::Dsa),
        _ => None,
    }
}

/// Curva de la clave EC del certificado.
pub fn certificate_curve(cert_der: &[u8]) -> Option<EcCurve> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let params = cert.public_key().algorithm.parameters.as_ref()?;
    EcCurve::from_oid(&params.as_oid().ok()?.to_id_string())
}

/// Tamaño de la clave pública del certificado en bits (módulo RSA o curva).
pub fn certificate_key_bits(cert_der: &[u8]) -> Option<usize> {
    match certificate_key_algorithm(cert_der)? {
        KeyAlgorithm::Rsa => {
            use rsa::traits::PublicKeyParts;
            let k = rsa_public_key(cert_der).ok()?;
            Some(k.n().bits())
        }
        KeyAlgorithm::Ec => certificate_curve(cert_der).map(EcCurve::bits),
        KeyAlgorithm::Dsa => None,
    }
}

fn rsa_public_key(cert_der: &[u8]) -> Result<rsa::RsaPublicKey, VerifyError> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| VerifyError::Error(format!("certificado no válido: {e}")))?;
    rsa::RsaPublicKey::from_pkcs1_der(&cert.public_key().subject_public_key.data)
        .map_err(|e| VerifyError::Error(format!("clave pública RSA no válida: {e}")))
}

/// Verifica una firma PKCS#1 v1.5 (RSA) o ECDSA (DER) de `data` con la
/// clave pública del certificado.
pub fn verify_signature(cert_der: &[u8], algorithm: SignatureAlgorithm, data: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    let key_alg = certificate_key_algorithm(cert_der).ok_or_else(|| VerifyError::Error("tipo de clave del certificado no soportado".into()))?;
    if key_alg != algorithm.key {
        return Err(VerifyError::Mismatch);
    }
    let hash = algorithm.digest.digest(data);
    verify_prehashed(cert_der, algorithm, &hash, signature)
}

/// Igual que [`verify_signature`] pero recibiendo la huella ya calculada.
pub fn verify_prehashed(cert_der: &[u8], algorithm: SignatureAlgorithm, hash: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    match algorithm.key {
        KeyAlgorithm::Rsa => {
            let key = rsa_public_key(cert_der)?;
            let scheme = match algorithm.digest {
                DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                DigestAlgorithm::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
                DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            key.verify(scheme, hash, signature).map_err(|_| VerifyError::Mismatch)
        }
        KeyAlgorithm::Ec => {
            use ecdsa::signature::hazmat::PrehashVerifier;
            let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| VerifyError::Error(format!("certificado no válido: {e}")))?;
            let point = cert.public_key().subject_public_key.data.to_vec();
            let curve = certificate_curve(cert_der).ok_or_else(|| VerifyError::Error("curva elíptica no soportada".into()))?;
            let bad_key = |e: ecdsa::Error| VerifyError::Error(format!("clave pública EC no válida: {e}"));
            match curve {
                EcCurve::P256 => {
                    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(bad_key)?;
                    let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| VerifyError::Mismatch)?;
                    vk.verify_prehash(hash, &sig).map_err(|_| VerifyError::Mismatch)
                }
                EcCurve::P384 => {
                    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(bad_key)?;
                    let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| VerifyError::Mismatch)?;
                    vk.verify_prehash(hash, &sig).map_err(|_| VerifyError::Mismatch)
                }
                EcCurve::P521 => {
                    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(bad_key)?;
                    let sig = p521::ecdsa::Signature::from_der(signature).map_err(|_| VerifyError::Mismatch)?;
                    vk.verify_prehash(hash, &sig).map_err(|_| VerifyError::Mismatch)
                }
            }
        }
        KeyAlgorithm::Dsa => Err(VerifyError::Error("las firmas DSA no están soportadas".into())),
    }
}

/// Firma con la clave y verifica el resultado con su certificado
/// (contrato completo de `AOPkcs1Signer.sign`), devolviendo los errores con
/// los códigos de AutoFirma.
#[allow(clippy::result_large_err)] // `AfirmaError` es el error común del proyecto.
pub fn sign_and_verify(key: &dyn SigningKey, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, AfirmaError> {
    let sig = key.sign(data, algorithm).map_err(AfirmaError::from)?;
    verify_signature(key.certificate(), algorithm, data, &sig)?;
    Ok(sig)
}

/// Envoltorio que verifica cada firma producida por la clave interior.
/// Si la firma no se verifica devuelve
/// `KeyError::Other("El PKCS#1 de firma obtenido no se genero con el certificado indicado")`
/// (los firmadores que necesiten el código exacto 200112 deben usar
/// [`sign_and_verify`]).
pub struct VerifyingKey<K: SigningKey> {
    inner: K,
}

impl<K: SigningKey> VerifyingKey<K> {
    pub fn new(inner: K) -> Self {
        VerifyingKey { inner }
    }

    pub fn into_inner(self) -> K {
        self.inner
    }
}

impl<K: SigningKey> SigningKey for VerifyingKey<K> {
    fn certificate(&self) -> &[u8] {
        self.inner.certificate()
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.inner.certificate_chain()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.inner.key_algorithm()
    }

    fn alias(&self) -> Option<&str> {
        self.inner.alias()
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        let sig = self.inner.sign(data, algorithm)?;
        match verify_signature(self.inner.certificate(), algorithm, data, &sig) {
            Ok(()) => Ok(sig),
            Err(VerifyError::Mismatch) => Err(KeyError::Other(MISMATCH_MESSAGE.into())),
            Err(VerifyError::Error(m)) => Err(KeyError::Other(m)),
        }
    }
}

/// Convierte una firma ECDSA en bruto (`r || s`, formato PKCS#11/CNG) a DER.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, KeyError> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(KeyError::Other("firma ECDSA en bruto con longitud no válida".into()));
    }
    Ok(afirma_core::key::ecdsa_format::raw_to_der(raw))
}

/// Huella a firmar con ECDSA: la huella se trunca a la longitud en bits del
/// orden de la curva (FIPS 186-4), necesario para tokens que no lo hacen
/// (p. ej. SHA-512 con P-256).
pub fn ecdsa_truncate_hash(hash: &[u8], curve: Option<EcCurve>) -> Vec<u8> {
    let Some(curve) = curve else { return hash.to_vec() };
    let bits = curve.bits();
    if hash.len() * 8 <= bits {
        return hash.to_vec();
    }
    let bytes = bits.div_ceil(8);
    let mut out = hash[..bytes].to_vec();
    let extra = bytes * 8 - bits;
    if extra > 0 {
        // Desplazamiento a la derecha de los bits sobrantes (P-521).
        let mut carry = 0u8;
        for b in out.iter_mut() {
            let v = *b;
            *b = (v >> extra) | carry;
            carry = v << (8 - extra);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> crate::SoftwareKey {
        let data = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki").join(name)).unwrap();
        crate::pkcs12::open(&data, "12341234").unwrap().remove(0).signing_key().unwrap()
    }

    #[test]
    fn verifies_and_detects_mismatch() {
        let rsa = key("firmante-rsa.p12");
        let ec = key("firmante-ec.p12");
        let auth = key("autenticacion.p12");
        for d in DigestAlgorithm::ALL {
            let alg = SignatureAlgorithm::new(d, KeyAlgorithm::Rsa);
            let sig = rsa.sign(b"hola", alg).unwrap();
            verify_signature(rsa.certificate(), alg, b"hola", &sig).unwrap();
            assert_eq!(verify_signature(auth.certificate(), alg, b"hola", &sig), Err(VerifyError::Mismatch));
            assert_eq!(verify_signature(rsa.certificate(), alg, b"adios", &sig), Err(VerifyError::Mismatch));
            let alg = SignatureAlgorithm::new(d, KeyAlgorithm::Ec);
            let sig = ec.sign(b"hola", alg).unwrap();
            verify_signature(ec.certificate(), alg, b"hola", &sig).unwrap();
            assert_eq!(verify_signature(rsa.certificate(), alg, b"hola", &sig), Err(VerifyError::Mismatch));
        }
        let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
        let err = sign_and_verify(&VerifyingKey::new(rsa), b"x", alg);
        assert!(err.is_ok());
        let e: AfirmaError = VerifyError::Mismatch.into();
        assert_eq!(e.effective_code().code, 200112);
        assert_eq!(certificate_key_bits(ec.certificate()), Some(256));
        assert_eq!(certificate_curve(ec.certificate()), Some(EcCurve::P256));
    }

    #[test]
    fn truncation() {
        let h = [0xffu8; 64];
        assert_eq!(ecdsa_truncate_hash(&h, Some(EcCurve::P256)).len(), 32);
        assert_eq!(ecdsa_truncate_hash(&h[..32], Some(EcCurve::P384)).len(), 32);
        // SHA-512 (512 bits) cabe en el orden de P-521: no se trunca.
        assert_eq!(ecdsa_truncate_hash(&h, Some(EcCurve::P521)), h.to_vec());
    }
}
