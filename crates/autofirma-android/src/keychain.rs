//! Clave de firma de un alias del almacén KeyChain de Android y textos de los avisos sobre el
//! certificado elegido (`docs/spec/09-android.md` §4.3 y §4.6). Los avisos se calculan como en
//! la firma web (`afirma_protocol::android::launcher::certificate_warnings`) y la caché de
//! certificado (§4.7) es la suya (`afirma_protocol::android::sticky::StickyKeyCache`).
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

pub use afirma_protocol::android::handler::CertificateWarning;
pub use afirma_protocol::android::launcher::{certificate_warnings, is_pseudonym_certificate};

/// Identificador estable de un aviso sobre el certificado (registros, pruebas y diálogo).
pub fn warning_id(warning: CertificateWarning) -> &'static str {
    match warning {
        CertificateWarning::Expired => "cert_expired",
        CertificateWarning::NotYetValid => "cert_not_yet_valid",
        CertificateWarning::ExpiresSoon => "cert_expiring_soon",
        CertificateWarning::Pseudonym => "cert_pseudonym",
    }
}

/// Claves del título y del texto de un aviso (§4.6). «Aún no válido» es propio: el original
/// lo trataba como un error genérico de selección (§10 n.º 13).
pub fn warning_texts(warning: CertificateWarning) -> (&'static str, &'static str) {
    match warning {
        CertificateWarning::Expired => (k!("expired_cert"), k!("not_valid_cert")),
        CertificateWarning::NotYetValid => (k!("not_yet_valid_cert"), k!("not_yet_valid_cert_desc")),
        CertificateWarning::ExpiresSoon => (k!("expired_cert_soon"), k!("expired_cert_soon_desc")),
        CertificateWarning::Pseudonym => (k!("pseudonym_cert"), k!("pseudonym_cert_desc")),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use afirma_core::DigestAlgorithm;
    use chrono::{DateTime, Utc};

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

    fn pki(name: &str) -> Vec<u8> {
        let pem = std::fs::read(format!("{}/../../testdata/pki/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        afirma_core::cert::decode_certificate(&pem).unwrap()
    }

    fn cert_valid(from: DateTime<Utc>, to: DateTime<Utc>, pseudonym: bool) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Prueba");
        if pseudonym {
            params
                .distinguished_name
                .push(rcgen::DnType::CustomDnType(vec![2, 5, 4, 65]), "Agente 007");
        }
        let secs = |t: DateTime<Utc>| Duration::from_secs(u64::try_from(t.timestamp()).unwrap());
        params.not_before = rcgen::date_time_ymd(1970, 1, 1) + secs(from);
        params.not_after = rcgen::date_time_ymd(1970, 1, 1) + secs(to);
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn avisos_de_caducidad_y_seudonimo() {
        let now = Utc::now();
        let day = chrono::Duration::days(1);
        assert!(certificate_warnings(&pki("firmante-rsa.crt"), now).is_empty());
        assert_eq!(
            certificate_warnings(&pki("caducado.crt"), now),
            [CertificateWarning::Expired]
        );
        let soon = cert_valid(now - day, now + day * 6, false);
        assert_eq!(certificate_warnings(&soon, now), [CertificateWarning::ExpiresSoon]);
        let ok = cert_valid(now - day, now + day * 8, false);
        assert!(certificate_warnings(&ok, now).is_empty());
        let future = cert_valid(now + day, now + day * 100, true);
        assert_eq!(
            certificate_warnings(&future, now),
            [CertificateWarning::NotYetValid, CertificateWarning::Pseudonym]
        );
        assert!(is_pseudonym_certificate(&future));
        assert!(!is_pseudonym_certificate(&pki("firmante-rsa.crt")));
        let expired_pseudonym = cert_valid(now - day * 10, now - day, true);
        assert_eq!(
            certificate_warnings(&expired_pseudonym, now),
            [CertificateWarning::Expired, CertificateWarning::Pseudonym]
        );
        assert_eq!(warning_texts(CertificateWarning::Expired).0, "expired_cert");
        assert_eq!(warning_id(CertificateWarning::ExpiresSoon), "cert_expiring_soon");
    }

    #[test]
    fn errores_de_alias() {
        let platform = Arc::new(FakePlatform::default());
        assert!(KeyChainKey::load(platform.clone(), "otro").is_err());
        // Alias sin certificados.
        assert!(KeyChainKey::load(platform, "firmante").is_err());
    }
}
