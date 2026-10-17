//! Firma desde la web en la app Android: port del lado de protocolo del
//! «Cliente @firma móvil» (Autofirma App 1.9, `firma-android`;
//! `docs/spec/09-android.md` §5, §6, §8 y §10), sin interfaz ni dependencias
//! de Android.
//!
//! En Android solo existe el modo servidor intermedio: AutoScript abre
//! `afirma://<op>?…` y la app responde subiendo el resultado al StorageService
//! (o, si la invoca otra app, por el resultado de la actividad). Este módulo
//! reproduce ese flujo 1:1 (análisis con `afirma-core` 1.9, sobres `fileid`,
//! cifrado DES, formato de las respuestas y de los errores `ERR-NN:=AA…`,
//! correspondencia de formatos, lotes JSON) salvo los fallos que §10 manda
//! corregir, que se enumeran en cada submódulo y en
//! `docs/deviations/afirma-protocol.md`.
//!
//! Uso desde la app:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # fn demo(handler: Arc<dyn afirma_protocol::android::AndroidWebHandler>,
//! #         signer: Arc<dyn afirma_protocol::LocalSigner>, url: &str) {
//! use afirma_protocol::HttpClient;
//! use afirma_protocol::android::{AndroidWebConfig, AndroidWebLauncher, InvocationMode, WebLanguage};
//! let mut config = AndroidWebConfig::new(HttpClient::installed());
//! config.language = WebLanguage::from_tag("ca").unwrap_or_default();
//! // Una sola instancia por proceso: guarda la caché de certificado (sticky).
//! let launcher = AndroidWebLauncher::new(handler, signer, config);
//! let outcome = launcher.run(url, InvocationMode::Browser);
//! if let Some(record) = outcome.history { /* escribir signsRecord.txt */ }
//! # }
//! ```

pub mod batch;
pub mod cipher;
pub mod domains;
pub mod errors;
pub mod formats;
pub mod handler;
pub mod intermediate;
pub mod launcher;
pub mod request;
pub mod sticky;
pub mod texts;

pub use domains::{
    TrustedDomains, http_trust_overrides, is_trusted_domain, normalize_input as normalize_trusted_domains,
};
pub use errors::{ErrorCategory, ErrorId, WebError};
pub use handler::{
    AndroidWebHandler, CertificateWarning, ChooseFileRequest, ChosenFile, ErrorDialog, FileChoiceError, KeyPurpose,
    KeyRequest, KeySelectionError, KeySource, PdfPasswordRequest, ProgressEvent, SaveFileError, SaveFileRequest,
    SelectedKey, VisibleArea, VisibleSignatureRequest, VisibleSignatureResult,
};
pub use launcher::{
    AndroidWebConfig, AndroidWebLauncher, HistoryKind, HistoryRecord, IntentReply, InvocationMode, Reply, WebOutcome,
};
pub use request::{ParamError, ReplyTarget, WebOperation, WebRequest};
pub use sticky::StickyKeyCache;
pub use texts::{UserText, WebLanguage};
