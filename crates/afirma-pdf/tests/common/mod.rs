//! Utilidades comunes de las pruebas: claves de la PKI de pruebas.
#![allow(dead_code)]

use std::path::PathBuf;

use afirma_core::{DigestAlgorithm, KeyAlgorithm, KeyError, SignatureAlgorithm, SigningKey};

pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn pki(name: &str) -> PathBuf {
    repo().join("testdata/pki").join(name)
}

pub fn java_resource(name: &str) -> Vec<u8> {
    std::fs::read(repo().join("afirma-crypto-pdf/src/test/resources").join(name)).expect(name)
}

pub fn testdata(name: &str) -> PathBuf {
    repo().join("testdata/pades").join(name)
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    afirma_core::base64_decode_lenient(&b64).unwrap()
}

/// Clave de la PKI de pruebas (`firmante-rsa`, `firmante-ec`...).
pub struct TestKey {
    chain: Vec<Vec<u8>>,
    rsa: Option<rsa::RsaPrivateKey>,
    ec: Option<p256::ecdsa::SigningKey>,
}

impl TestKey {
    pub fn load(name: &str) -> TestKey {
        use rsa::pkcs8::DecodePrivateKey;
        let key_pem = std::fs::read_to_string(pki(&format!("{name}.key"))).unwrap();
        let cert = pem_to_der(&std::fs::read_to_string(pki(&format!("{name}.crt"))).unwrap());
        let ca = pem_to_der(&std::fs::read_to_string(pki("ca.crt")).unwrap());
        let rsa = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem).ok();
        let ec = if rsa.is_none() {
            p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem).ok()
        } else {
            None
        };
        assert!(rsa.is_some() || ec.is_some(), "clave no soportada");
        TestKey {
            chain: vec![cert, ca],
            rsa,
            ec,
        }
    }

    pub fn rsa() -> TestKey {
        Self::load("firmante-rsa")
    }
}

impl SigningKey for TestKey {
    fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        if self.rsa.is_some() {
            KeyAlgorithm::Rsa
        } else {
            KeyAlgorithm::Ec
        }
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        let hash = algorithm.digest.digest(data);
        if let Some(k) = &self.rsa {
            let scheme = match algorithm.digest {
                DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                DigestAlgorithm::Sha224 => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
                DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            };
            return k.sign(scheme, &hash).map_err(|e| KeyError::Other(e.to_string()));
        }
        use ecdsa::signature::hazmat::PrehashSigner;
        let k = self.ec.as_ref().unwrap();
        let sig: p256::ecdsa::Signature = k.sign_prehash(&hash).map_err(|e| KeyError::Other(e.to_string()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// Parámetros a partir de pares clave/valor.
pub fn params(pairs: &[(&str, &str)]) -> afirma_core::ExtraParams {
    pairs.iter().map(|(k, v)| (*k, *v)).collect()
}
