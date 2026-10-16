//! Claves privadas en memoria (PKCS#12, PKCS#8).
//!
//! RSA se firma con `ring` (tiempo constante) siempre que el algoritmo y el
//! tamaño de clave lo permiten (SHA-256/384/512 y claves de 2048 a 8192
//! bits); en otro caso (SHA-1, claves de 1024 bits...) se usa el crate `rsa`.
//! ECDSA usa las curvas de RustCrypto (P-256, P-384 y P-521), que admiten
//! cualquier combinación de huella y curva.

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::key::{KeyError, SigningKey};

macro_rules! ecdsa_prehash_sign {
    ($key:expr, $sig:ty, $digest:expr, $data:expr) => {{
        use ecdsa::signature::hazmat::PrehashSigner;
        let hash = $digest.digest($data);
        let sig: $sig = $key
            .sign_prehash(&hash)
            .map_err(|e| KeyError::Other(format!("error en la firma ECDSA: {e}")))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }};
}

enum Inner {
    Rsa {
        pkcs8: Vec<u8>,
        ring: Option<ring::signature::RsaKeyPair>,
    },
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
}

/// Clave privada en memoria junto a su cadena de certificados.
pub struct SoftwareKey {
    inner: Inner,
    chain: Vec<Vec<u8>>,
    alias: Option<String>,
}

impl std::fmt::Debug for SoftwareKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareKey")
            .field("alias", &self.alias)
            .finish_non_exhaustive()
    }
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";

impl SoftwareKey {
    /// Crea la clave a partir de un PrivateKeyInfo (PKCS#8) en DER y de la
    /// cadena de certificados (el primero, el de firma).
    pub fn from_pkcs8(pkcs8: &[u8], chain: Vec<Vec<u8>>, alias: Option<String>) -> Result<Self, KeyError> {
        if chain.is_empty() {
            return Err(KeyError::Other("la clave no tiene certificado asociado".into()));
        }
        let (alg_oid, curve_oid) =
            pkcs8_algorithm(pkcs8).ok_or_else(|| KeyError::Other("clave PKCS#8 no válida".into()))?;
        let inner = match alg_oid.as_str() {
            OID_RSA => Inner::Rsa {
                pkcs8: pkcs8.to_vec(),
                ring: ring::signature::RsaKeyPair::from_pkcs8(pkcs8).ok(),
            },
            OID_EC => {
                use p256::pkcs8::DecodePrivateKey;
                let bad = |e: p256::pkcs8::Error| KeyError::Other(format!("clave EC no válida: {e}"));
                match curve_oid.as_deref() {
                    Some(OID_P256) => Inner::P256(p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8).map_err(bad)?),
                    Some(OID_P384) => Inner::P384(p384::ecdsa::SigningKey::from_pkcs8_der(pkcs8).map_err(bad)?),
                    Some(OID_P521) => {
                        let sk = p521::SecretKey::from_pkcs8_der(pkcs8).map_err(bad)?;
                        Inner::P521(
                            p521::ecdsa::SigningKey::from_slice(&sk.to_bytes())
                                .map_err(|e| KeyError::Other(format!("clave EC no válida: {e}")))?,
                        )
                    }
                    other => return Err(KeyError::Unsupported(format!("curva elíptica {other:?}"))),
                }
            }
            other => return Err(KeyError::Unsupported(format!("tipo de clave {other}"))),
        };
        Ok(SoftwareKey { inner, chain, alias })
    }
}

impl SigningKey for SoftwareKey {
    fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        match self.inner {
            Inner::Rsa { .. } => KeyAlgorithm::Rsa,
            _ => KeyAlgorithm::Ec,
        }
    }

    fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        if algorithm.key != self.key_algorithm() {
            return Err(KeyError::Unsupported(format!(
                "{} con una clave {}",
                algorithm.java_name(),
                self.key_algorithm().java_suffix()
            )));
        }
        let digest = algorithm.digest;
        match &self.inner {
            Inner::Rsa { pkcs8, ring: ring_key } => {
                let ring_padding: Option<&'static dyn ring::signature::RsaEncoding> = match digest {
                    DigestAlgorithm::Sha256 => Some(&ring::signature::RSA_PKCS1_SHA256),
                    DigestAlgorithm::Sha384 => Some(&ring::signature::RSA_PKCS1_SHA384),
                    DigestAlgorithm::Sha512 => Some(&ring::signature::RSA_PKCS1_SHA512),
                    _ => None,
                };
                if let (Some(kp), Some(padding)) = (ring_key, ring_padding) {
                    let mut sig = vec![0u8; kp.public().modulus_len()];
                    kp.sign(padding, &ring::rand::SystemRandom::new(), data, &mut sig)
                        .map_err(|_| KeyError::Other("error en la firma RSA".into()))?;
                    return Ok(sig);
                }
                rsa_fallback(pkcs8, digest, data)
            }
            Inner::P256(k) => ecdsa_prehash_sign!(k, p256::ecdsa::Signature, digest, data),
            Inner::P384(k) => ecdsa_prehash_sign!(k, p384::ecdsa::Signature, digest, data),
            Inner::P521(k) => ecdsa_prehash_sign!(k, p521::ecdsa::Signature, digest, data),
        }
    }
}

fn rsa_fallback(pkcs8: &[u8], digest: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, KeyError> {
    use rsa::pkcs8::DecodePrivateKey;
    let key =
        rsa::RsaPrivateKey::from_pkcs8_der(pkcs8).map_err(|e| KeyError::Other(format!("clave RSA no válida: {e}")))?;
    let hash = digest.digest(data);
    let scheme = match digest {
        DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
        DigestAlgorithm::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
        DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
        DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
        DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
    };
    key.sign_with_rng(&mut rsa::rand_core::OsRng, scheme, &hash)
        .map_err(|e| KeyError::Other(format!("error en la firma RSA: {e}")))
}

/// Extrae el OID de algoritmo (y el de curva si es EC) de un PrivateKeyInfo.
fn pkcs8_algorithm(pkcs8: &[u8]) -> Option<(String, Option<String>)> {
    use x509_parser::der_parser::ber::BerObjectContent;
    use x509_parser::der_parser::der::parse_der;
    let (_, obj) = parse_der(pkcs8).ok()?;
    let seq = obj.as_sequence().ok()?;
    let alg = seq.get(1)?.as_sequence().ok()?;
    let oid = alg.first()?.as_oid().ok()?.to_id_string();
    let curve = alg.get(1).and_then(|p| match &p.content {
        BerObjectContent::OID(o) => Some(o.to_id_string()),
        _ => None,
    });
    Some((oid, curve))
}
