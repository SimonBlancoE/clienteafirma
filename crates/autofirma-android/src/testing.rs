//! Utilidades de las pruebas del anfitrión: una [`Platform`] falsa que registra las
//! llamadas (sin Java) y certificados de prueba.

use std::sync::Mutex;

use afirma_core::{SignatureAlgorithm, SigningKey};
use afirma_keystores::software::SoftwareKey;

use crate::bridge::{Platform, PlatformError, RequestId};
use crate::ime::{ImeRequest, ImeState};

/// Contraseña de los PKCS#12 de `testdata/pki`.
pub(crate) const TEST_P12_PASSWORD: &str = "12341234";

/// Plataforma de prueba: KeyChain con un alias (`firmante`), sin NFC; registra las llamadas.
/// Con `key`, el alias firma de verdad (como la clave de KeyChain, que no sale de Java); si
/// no, devuelve una firma fija.
#[derive(Default)]
pub(crate) struct FakePlatform {
    pub chain: Vec<Vec<u8>>,
    pub key: Option<SoftwareKey>,
    pub calls: Mutex<Vec<String>>,
}

/// PKCS#12 de `testdata/pki`.
pub(crate) fn test_p12(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../testdata/pki/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Clave de `testdata/pki/firmante-rsa.p12`.
pub(crate) fn software_key() -> SoftwareKey {
    let entries = afirma_keystores::pkcs12::open(&test_p12("firmante-rsa.p12"), TEST_P12_PASSWORD).unwrap();
    entries[0].signing_key().unwrap()
}

impl FakePlatform {
    /// KeyChain con el alias `firmante` de un PKCS#12 de `testdata/pki` que firma de verdad.
    pub fn with_p12(name: &str) -> FakePlatform {
        let entries = afirma_keystores::pkcs12::open(&test_p12(name), TEST_P12_PASSWORD).unwrap();
        FakePlatform {
            chain: entries[0].chain.clone(),
            key: Some(entries[0].signing_key().unwrap()),
            ..Default::default()
        }
    }

    fn record(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }

    /// Llamadas registradas hasta ahora.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// Llamadas que empiezan por un prefijo (`ime_`, `open_`...).
    pub fn calls_with(&self, prefix: &str) -> Vec<String> {
        self.calls().into_iter().filter(|c| c.starts_with(prefix)).collect()
    }
}

impl Platform for FakePlatform {
    fn open_document(&self, request: RequestId, mime_types: &[&str]) -> Result<(), PlatformError> {
        self.record(format!("open_document {request} {}", mime_types.join(",")));
        Ok(())
    }
    fn create_document(&self, request: RequestId, mime_type: &str, name: &str) -> Result<(), PlatformError> {
        self.record(format!("create_document {request} {mime_type} {name}"));
        Ok(())
    }
    fn install_certificate(&self, request: RequestId, pkcs12: &[u8]) -> Result<(), PlatformError> {
        self.record(format!("install_certificate {request} {}", pkcs12.len()));
        Ok(())
    }
    fn choose_certificate(&self, request: RequestId) -> Result<(), PlatformError> {
        self.record(format!("choose_certificate {request}"));
        Ok(())
    }
    fn certificate_chain(&self, alias: &str) -> Result<Vec<Vec<u8>>, PlatformError> {
        self.record(format!("certificate_chain {alias}"));
        if alias == "firmante" && !self.chain.is_empty() {
            Ok(self.chain.clone())
        } else {
            Err(PlatformError::new("java.security.KeyChainException: alias desconocido"))
        }
    }
    fn sign(&self, alias: &str, algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, PlatformError> {
        self.record(format!("sign {alias} {} {}", algorithm.java_name(), data.len()));
        match &self.key {
            Some(key) if alias == "firmante" => key
                .sign(data, algorithm)
                .map_err(|e| PlatformError::new(format!("java.security.SignatureException: {e}"))),
            Some(_) => Err(PlatformError::new(
                "android.security.KeyChainException: alias desconocido",
            )),
            None => Ok(vec![0x5a; 4]),
        }
    }
    fn start_nfc_reader(&self, request: RequestId) -> Result<(), PlatformError> {
        self.record(format!("start_nfc_reader {request}"));
        Err(PlatformError::new("sin NFC"))
    }
    fn nfc_transceive(&self, _apdu: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::new("sin NFC"))
    }
    fn stop_nfc_reader(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    fn leave_app(&self) -> Result<(), PlatformError> {
        self.record("leave_app".into());
        Ok(())
    }
    fn set_back_at_root(&self, at_root: bool) -> Result<(), PlatformError> {
        self.record(format!("set_back_at_root {at_root}"));
        Ok(())
    }
    fn open_url(&self, request: RequestId, url: &str) -> Result<(), PlatformError> {
        self.record(format!("open_url {request} {url}"));
        Ok(())
    }
    fn ime_show(&self, request: &ImeRequest) -> Result<(), PlatformError> {
        self.record(format!(
            "ime_show {:?} {:?} {:?}",
            request.kind, request.state.text, request.state.selection
        ));
        Ok(())
    }
    fn ime_update(&self, state: &ImeState) -> Result<(), PlatformError> {
        self.record(format!("ime_update {:?} {:?}", state.text, state.selection));
        Ok(())
    }
    fn ime_hide(&self) -> Result<(), PlatformError> {
        self.record("ime_hide".into());
        Ok(())
    }
}

/// Certificado autofirmado de prueba (P-256).
pub(crate) fn test_certificate(cn: &str) -> Vec<u8> {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, cn);
    params.self_signed(&key).unwrap().der().to_vec()
}
