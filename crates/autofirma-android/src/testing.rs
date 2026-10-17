//! Utilidades de las pruebas del anfitrión: una [`Platform`] falsa que registra las
//! llamadas (sin Java) y certificados de prueba.

use std::sync::Mutex;

use afirma_core::SignatureAlgorithm;

use crate::bridge::{Platform, PlatformError, RequestId};
use crate::ime::{ImeRequest, ImeState};

/// Plataforma de prueba: KeyChain con un alias (`firmante`), sin NFC; registra las llamadas.
#[derive(Default)]
pub(crate) struct FakePlatform {
    pub chain: Vec<Vec<u8>>,
    pub calls: Mutex<Vec<String>>,
}

impl FakePlatform {
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
    fn open_document(&self, request: RequestId) -> Result<(), PlatformError> {
        self.record(format!("open_document {request}"));
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
        Ok(vec![0x5a; 4])
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
