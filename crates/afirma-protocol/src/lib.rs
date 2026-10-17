//! Protocolo de invocación web de AutoFirma-rs.
//!
//! Las páginas de las administraciones invocan a AutoFirma mediante
//! `autoscript.js`: URL `afirma://`, servidor WebSocket local, socket de
//! servicio heredado o servidor intermedio (StorageService/RetrieveService).
//! Este crate analiza y valida las peticiones, ejecuta los transportes y
//! reproduce el flujo de cada operación de AutoFirma, delegando en la
//! aplicación la interfaz de usuario ([`OperationHandler`]) y la firma
//! local con el registro de firmadores ([`LocalSigner`]).
//!
//! Uso típico desde la aplicación:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # fn demo(handler: Arc<dyn afirma_protocol::OperationHandler>, signer: Arc<dyn afirma_protocol::LocalSigner>, url: &str) -> i32 {
//! use afirma_protocol::{HttpClient, LauncherConfig, ProtocolLauncher, TlsSource};
//! let config = LauncherConfig::new(HttpClient::installed());
//! let launcher = Arc::new(ProtocolLauncher::new(handler, signer, config));
//! let pfx = afirma_protocol::channel::find_autofirma_pfx(None).unwrap_or_default();
//! launcher.run_url(url, &TlsSource::autofirma_pfx(pfx))
//! # }
//! ```

// `AfirmaError` (el error común de afirma-core) es grande; devolverlo por
// valor es la convención de todos los crates.
#![allow(clippy::result_large_err)]

pub mod android;
pub mod batch;
pub mod channel;
pub mod cipher;
pub mod envelope;
pub mod errors;
pub mod handler;
pub mod http;
pub mod intermediate;
pub mod javamap;
pub mod jbase64;
pub mod json_lenient;
pub mod launcher;
pub mod messages;
pub mod pkcs1;
pub mod properties;
pub mod query;
pub mod request;
pub mod response;
pub mod service;
pub mod triphase;
pub mod version;
pub mod websocket;

use std::sync::Arc;

pub use channel::{ChannelError, ChannelRequest, TlsSource};
pub use errors::{ErrorOrigin, ProtocolError};
pub use handler::{
    CertificateRequest, ConfirmRequest, ErrorDialog, FileData, LoadRequest, LocalSignRequest, LocalSigner,
    OpenFileRequest, OperationHandler, PasswordRequest, ProgressEvent, RequestInfo, RequestOrigin, SaveFileRequest,
    VisibleSignatureRequest,
};
pub use http::HttpClient;
pub use launcher::{LaunchOutcome, LauncherConfig, ProtocolLauncher};
pub use messages::Locale;
pub use request::{KeyStoreParam, OperationKind};
pub use triphase::{CryptoOperation, TriphaseClient, TriphaseFormat};
pub use version::ProtocolVersion;
pub use websocket::ServerExit;

impl ProtocolLauncher {
    /// Punto de entrada completo para la URL con la que el sistema invoca
    /// la aplicación: ejecuta la operación (invocación directa) o abre el
    /// canal WebSocket / socket de servicio y lo atiende hasta que termina.
    /// Devuelve el código de salida del proceso (como Java: 0, o -1 si los
    /// puertos están mal formados).
    pub fn run_url(self: &Arc<Self>, url: &str, tls: &TlsSource) -> i32 {
        match self.launch(url) {
            LaunchOutcome::Finished(_) => 0,
            LaunchOutcome::OpenWebSocket(req) => {
                let r = websocket::run_blocking(self.clone(), &req, tls, websocket::WebSocketOptions::default());
                self.channel_exit(r, req.version)
            }
            LaunchOutcome::OpenService(req) => {
                let r = service::run_blocking(self.clone(), &req, tls, service::ServiceOptions::default());
                self.channel_exit(r, req.version)
            }
        }
    }

    fn channel_exit(&self, r: Result<ServerExit, ChannelError>, version: ProtocolVersion) -> i32 {
        tracing::info!("Fin del canal con la página: {r:?}");
        match r {
            Ok(_) => 0,
            Err(e) => {
                if let Some(code) = e.code() {
                    let locale = self.config().locale;
                    self.handler().show_error(&ErrorDialog {
                        title: errors::dialog_title(Some(version), code, locale),
                        message: errors::dialog_text(code, locale, &[]),
                        error: ProtocolError::parameter(code, e.to_string()),
                        version: Some(version),
                    });
                }
                e.exit_code()
            }
        }
    }
}
