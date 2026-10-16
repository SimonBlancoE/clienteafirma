//! Utilidades comunes de las pruebas de integración: manejador y firmador
//! simulados, claves de la PKI de pruebas y servidor HTTP simulado.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use afirma_core::error::{ConfirmEffect, codes};
use afirma_core::http::{HttpClient as CoreHttp, HttpClientError, HttpMethod, HttpRequest};
use afirma_core::{AfirmaError, SigningKey};
use afirma_protocol::{
    CertificateRequest, ConfirmRequest, CryptoOperation, ErrorDialog, FileData, LoadRequest, LocalSignRequest, LocalSigner, OpenFileRequest,
    OperationHandler, PasswordRequest, RequestInfo, SaveFileRequest,
};

pub fn testdata(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata").join(path)
}

/// Clave de la PKI de pruebas (`firmante-rsa`, `firmante-ec`...).
pub fn key(name: &str) -> Arc<dyn SigningKey> {
    let data = std::fs::read(testdata(&format!("pki/{name}.p12"))).expect("p12 de pruebas");
    let entries = afirma_keystores::pkcs12::open(&data, "12341234").expect("abrir p12");
    Arc::new(entries[0].signing_key().expect("clave"))
}

/// Manejador simulado.
#[derive(Default)]
pub struct FakeHandler {
    pub keys: Mutex<VecDeque<Result<Arc<dyn SigningKey>, AfirmaError>>>,
    pub default_key: Mutex<Option<Arc<dyn SigningKey>>>,
    pub cert_requests: Mutex<Vec<(Option<Vec<u8>>, RequestInfo)>>,
    pub file_to_sign: Mutex<Option<FileData>>,
    pub saved: Mutex<Vec<(Option<String>, Vec<u8>)>>,
    pub load_result: Mutex<Option<Vec<FileData>>>,
    pub confirm_answer: Mutex<bool>,
    pub confirms: Mutex<Vec<ConfirmRequest>>,
    pub password: Mutex<Option<String>>,
    pub errors: Mutex<Vec<ErrorDialog>>,
}

impl FakeHandler {
    pub fn with_key(k: Arc<dyn SigningKey>) -> Arc<Self> {
        let h = FakeHandler::default();
        *h.default_key.lock().unwrap() = Some(k);
        Arc::new(h)
    }

    pub fn cert_dialogs(&self) -> usize {
        self.cert_requests.lock().unwrap().len()
    }

    pub fn error_codes(&self) -> Vec<u32> {
        self.errors.lock().unwrap().iter().map(|e| e.error.code.code).collect()
    }
}

impl OperationHandler for FakeHandler {
    fn select_certificate(&self, req: &CertificateRequest<'_>) -> Result<Arc<dyn SigningKey>, AfirmaError> {
        self.cert_requests.lock().unwrap().push((req.restrict_to_certificate.map(<[u8]>::to_vec), req.info.clone()));
        if let Some(r) = self.keys.lock().unwrap().pop_front() {
            return r;
        }
        self.default_key.lock().unwrap().clone().ok_or_else(|| AfirmaError::from_code(codes::CERTIFICATE_NEEDED))
    }

    fn choose_file_to_sign(&self, _req: &OpenFileRequest) -> Result<FileData, AfirmaError> {
        self.file_to_sign.lock().unwrap().clone().ok_or_else(AfirmaError::cancelled)
    }

    fn save_file(&self, req: &SaveFileRequest<'_>) -> Result<(), AfirmaError> {
        self.saved.lock().unwrap().push((req.proposed_name.clone(), req.data.to_vec()));
        Ok(())
    }

    fn load_files(&self, _req: &LoadRequest) -> Result<Vec<FileData>, AfirmaError> {
        self.load_result.lock().unwrap().clone().ok_or_else(AfirmaError::cancelled)
    }

    fn confirm(&self, req: &ConfirmRequest) -> bool {
        self.confirms.lock().unwrap().push(req.clone());
        *self.confirm_answer.lock().unwrap()
    }

    fn request_password(&self, _req: &PasswordRequest) -> Option<String> {
        self.password.lock().unwrap().clone()
    }

    fn show_error(&self, dialog: &ErrorDialog) {
        self.errors.lock().unwrap().push(dialog.clone());
    }
}

/// Comportamiento programado del firmador simulado.
pub enum Scripted {
    /// Error de PIN.
    WrongPin,
    /// Pide confirmación (`allowSignLTSignature`).
    NeedsConfirm,
    /// Error con código.
    Fail(afirma_core::ErrorCode),
}

/// Firmador local simulado: la "firma" es el PKCS#1 de los datos.
#[derive(Default)]
pub struct FakeSigner {
    pub script: Mutex<VecDeque<Scripted>>,
    pub calls: Mutex<Vec<(CryptoOperation, String, String, afirma_core::ExtraParams)>>,
}

impl LocalSigner for FakeSigner {
    fn supports_format(&self, format: &str) -> bool {
        ["cades", "xades", "pades", "facturae", "none", "xades detached"].contains(&format.to_ascii_lowercase().as_str())
    }

    fn sign(&self, req: &LocalSignRequest<'_>) -> Result<Vec<u8>, AfirmaError> {
        self.calls.lock().unwrap().push((req.operation, req.format.to_string(), req.algorithm.to_string(), req.extra_params.clone()));
        match self.script.lock().unwrap().pop_front() {
            Some(Scripted::WrongPin) => return Err(AfirmaError::new(codes::INVALID_SMARTCARD_PIN, "PIN incorrecto")),
            Some(Scripted::NeedsConfirm) if !req.extra_params.get_bool("allowSignLTSignature", false) => {
                return Err(AfirmaError::needs_confirmation(codes::SIGNING_LTS, "LTS", "signingLts", "allowSignLTSignature", ConfirmEffect::SetParamTrue));
            }
            Some(Scripted::Fail(c)) => return Err(AfirmaError::from_code(c)),
            _ => {}
        }
        afirma_protocol::pkcs1::sign(req.key, req.algorithm, req.data)
    }

    fn detect_format(&self, _operation: CryptoOperation, data: &[u8]) -> Option<String> {
        if data.starts_with(b"%PDF") {
            Some("PAdES".into())
        } else if data.starts_with(b"<") {
            Some("XAdES".into())
        } else if data.is_empty() {
            None
        } else {
            Some("CAdES".into())
        }
    }

    fn signed_file_name(&self, format: &str, original: &str) -> String {
        if format.eq_ignore_ascii_case("CAdES") { format!("{original}.csig") } else { format!("{original}.xsig") }
    }
}

/// Petición registrada por el servidor HTTP simulado.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: HttpMethod,
    pub url: String,
    pub body: String,
}

type Responder = Box<dyn Fn(&Seen) -> Result<(u16, Vec<u8>), HttpClientError> + Send + Sync>;

/// Gestor HTTP simulado.
pub struct MockHttp {
    pub seen: Mutex<Vec<Seen>>,
    responder: Responder,
}

impl MockHttp {
    pub fn new(f: impl Fn(&Seen) -> Result<(u16, Vec<u8>), HttpClientError> + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(MockHttp { seen: Mutex::new(Vec::new()), responder: Box::new(f) })
    }

    pub fn bodies_to(&self, url_part: &str) -> Vec<String> {
        self.seen.lock().unwrap().iter().filter(|s| s.url.contains(url_part)).map(|s| s.body.clone()).collect()
    }
}

impl CoreHttp for MockHttp {
    fn read_url(&self, req: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        let (url, body) = match req.method {
            HttpMethod::Get => (req.url.clone(), String::new()),
            _ => {
                let (u, b) = afirma_core::http::split_post_url(&req.url);
                (u, b.unwrap_or_default())
            }
        };
        let seen = Seen { method: req.method, url: url.clone(), body };
        self.seen.lock().unwrap().push(seen.clone());
        let (status, body) = (self.responder)(&seen)?;
        if status >= 400 {
            return Err(HttpClientError::Http(afirma_core::http::HttpError { status, reason: None, body, url }));
        }
        Ok(body)
    }
}

/// Valor de un parámetro de un cuerpo `k=v&...` (sin decodificar).
pub fn form_value<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
}
