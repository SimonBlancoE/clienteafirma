//! Clave de firma de un alias del almacén KeyChain de Android.
//!
//! La clave privada no sale nunca de Android (puede estar en el TEE o en StrongBox): la
//! firma se hace en Java con `java.security.Signature` y la clave de
//! `KeyChain.getPrivateKey`. Los firmadores de `afirma-cms`, `afirma-xml` y `afirma-pdf`
//! solo ven el rasgo [`SigningKey`], igual que con PKCS#12, PKCS#11 o los almacenes de
//! Windows y macOS.

use std::sync::Arc;

use afirma_core::{KeyAlgorithm, KeyError, SignatureAlgorithm, SigningKey};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::bridge::{Platform, PlatformError};

/// Clave de un alias de KeyChain. Sus métodos bloquean (llaman a Java): se usan desde un
/// hilo de trabajo, nunca desde el de la interfaz.
pub struct KeyChainKey {
    alias: String,
    chain: Vec<Vec<u8>>,
    algorithm: KeyAlgorithm,
    platform: Arc<dyn Platform>,
}

impl KeyChainKey {
    /// Carga la cadena de certificados del alias y deduce el tipo de clave del certificado.
    pub fn load(platform: Arc<dyn Platform>, alias: &str) -> Result<Self, PlatformError> {
        let chain = platform.certificate_chain(alias)?;
        Self::with_chain(platform, alias, chain)
    }

    /// Clave con una cadena ya obtenida (la primera es la del firmante).
    pub fn with_chain(platform: Arc<dyn Platform>, alias: &str, chain: Vec<Vec<u8>>) -> Result<Self, PlatformError> {
        let leaf = chain
            .first()
            .ok_or_else(|| PlatformError::new(format!("el alias {alias} no tiene certificados")))?;
        let algorithm = key_algorithm(leaf)?;
        Ok(KeyChainKey {
            alias: alias.to_string(),
            chain,
            algorithm,
            platform,
        })
    }
}

/// Tipo de clave pública de un certificado DER.
pub fn key_algorithm(cert_der: &[u8]) -> Result<KeyAlgorithm, PlatformError> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| PlatformError::new(format!("certificado no válido: {e}")))?;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(_)) => Ok(KeyAlgorithm::Rsa),
        Ok(PublicKey::EC(_)) => Ok(KeyAlgorithm::Ec),
        Ok(PublicKey::DSA(_)) => Ok(KeyAlgorithm::Dsa),
        Ok(_) | Err(_) => Err(PlatformError::new("tipo de clave no soportado")),
    }
}

impl SigningKey for KeyChainKey {
    fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        if algorithm.key != self.algorithm {
            return Err(KeyError::Unsupported(algorithm.java_name()));
        }
        self.platform
            .sign(&self.alias, algorithm, data)
            .map_err(|e| KeyError::Other(e.0))
    }

    fn alias(&self) -> Option<&str> {
        Some(&self.alias)
    }
}

#[cfg(test)]
mod tests {
    use afirma_core::DigestAlgorithm;

    use super::*;
    use crate::testing::{FakePlatform, test_certificate};

    #[test]
    fn firma_con_el_alias_y_el_nombre_java_del_algoritmo() {
        let platform = Arc::new(FakePlatform {
            chain: vec![test_certificate("Firmante de prueba")],
            ..Default::default()
        });
        let key = KeyChainKey::load(platform.clone(), "firmante").unwrap();
        assert_eq!(key.key_algorithm(), KeyAlgorithm::Ec);
        assert_eq!(key.alias(), Some("firmante"));
        assert_eq!(afirma_core::cert::common_name(key.certificate()), "Firmante de prueba");

        let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Ec);
        assert_eq!(key.sign(b"datos", alg).unwrap(), vec![0x5a; 4]);
        let rsa = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
        assert!(matches!(key.sign(b"datos", rsa), Err(KeyError::Unsupported(_))));
        let calls = platform.calls.lock().unwrap();
        assert_eq!(
            *calls,
            ["certificate_chain firmante", "sign firmante SHA256withECDSA 5"]
        );
    }

    #[test]
    fn errores_de_alias() {
        let platform = Arc::new(FakePlatform::default());
        assert!(KeyChainKey::load(platform.clone(), "otro").is_err());
        // Alias sin certificados.
        assert!(KeyChainKey::load(platform, "firmante").is_err());
    }
}
