//! Integración del protocolo `afirma://` con la aplicación: firma local con
//! el registro de firmadores ([`AppLocalSigner`]) y peticiones de interfaz
//! que se envían a la ventana compacta ([`AppOperationHandler`]).

use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};

use afirma_core::error::codes;
use afirma_core::validity::Validity;
use afirma_core::{AfirmaError, ExtraParams, SigningKey};
use afirma_protocol::handler::{
    CertificateRequest, ConfirmRequest, ErrorDialog, FileData, LoadRequest, LocalSignRequest, LocalSigner,
    OpenFileRequest, OperationHandler, PasswordRequest, ProgressEvent, RequestInfo, SaveFileRequest,
    VisibleSignatureRequest,
};
use afirma_protocol::{CryptoOperation, KeyStoreParam};
use eframe::egui;

/// Firma local con los firmadores de `afirma-signers`.
pub struct AppLocalSigner;

impl LocalSigner for AppLocalSigner {
    fn supports_format(&self, format: &str) -> bool {
        afirma_signers::signer_for_format(format).is_some()
    }

    fn sign(&self, req: &LocalSignRequest<'_>) -> Result<Vec<u8>, AfirmaError> {
        let signer = afirma_signers::signer_for_format(req.format)
            .ok_or_else(|| AfirmaError::from_code(codes::UNSUPPORTED_SIGNATURE_FORMAT))?;
        match req.operation {
            CryptoOperation::Sign => signer.sign(req.data, req.algorithm, req.key, req.extra_params),
            CryptoOperation::CoSign => signer.cosign(None, req.data, req.algorithm, req.key, req.extra_params),
            CryptoOperation::CounterSign => {
                signer.countersign(req.data, req.algorithm, &req.target, req.key, req.extra_params)
            }
        }
    }

    fn detect_format(&self, operation: CryptoOperation, data: &[u8]) -> Option<String> {
        let op = match operation {
            CryptoOperation::Sign => afirma_signers::CryptoOp::Sign,
            CryptoOperation::CoSign => afirma_signers::CryptoOp::Cosign,
            CryptoOperation::CounterSign => afirma_signers::CryptoOp::Countersign,
        };
        afirma_signers::protocol_auto_format(op, data)
    }

    fn check_signatures(
        &self,
        operation: CryptoOperation,
        _format: &str,
        data: &[u8],
        extra: &ExtraParams,
    ) -> Result<(), AfirmaError> {
        if operation == CryptoOperation::Sign && afirma_signers::detect(data, extra).is_none() {
            return Ok(());
        }
        let v = afirma_signers::validate(data, extra);
        match v.first() {
            Some(first) if first.validity == Validity::Ko => Err(AfirmaError::new(
                first.error_code.unwrap_or(codes::INVALID_SIGNATURE),
                first.to_string(),
            )),
            _ => Ok(()),
        }
    }

    fn expand_extra_params(
        &self,
        extra: &ExtraParams,
        data: Option<&[u8]>,
        format: &str,
    ) -> Result<ExtraParams, AfirmaError> {
        afirma_core::policy::expand_properties(extra, data, Some(format))
    }

    fn signed_file_name(&self, format: &str, original: &str) -> String {
        match afirma_signers::signer_for_format(format) {
            Some(s) => s.signed_name(Some(original), None),
            None => format!("{original}.sig"),
        }
    }
}

/// Petición de la operación del protocolo a la interfaz.
pub enum ProtocolUiRequest {
    SelectCertificate {
        info: Option<RequestInfo>,
        extra: ExtraParams,
        keystore: Option<KeyStoreParam>,
        restrict_to: Option<Vec<u8>>,
        reply: Sender<Result<Arc<dyn SigningKey>, AfirmaError>>,
    },
    ChooseFile {
        req: OpenFileRequest,
        reply: Sender<Result<FileData, AfirmaError>>,
    },
    SaveFile {
        title: String,
        data: Vec<u8>,
        proposed_name: Option<String>,
        extensions: Option<Vec<String>>,
        reply: Sender<Result<(), AfirmaError>>,
    },
    LoadFiles {
        req: LoadRequest,
        reply: Sender<Result<Vec<FileData>, AfirmaError>>,
    },
    Confirm {
        message: String,
        reply: Sender<bool>,
    },
    Password {
        message: String,
        reply: Sender<Option<String>>,
    },
    VisibleSignature {
        data: Vec<u8>,
        custom: bool,
        mandatory: bool,
        reply: Sender<Result<Option<ExtraParams>, AfirmaError>>,
    },
    Error {
        title: String,
        message: String,
    },
    Progress(ProgressEvent),
    /// El lanzador ha terminado con este código de salida.
    Finished(i32),
}

/// Manejador de operaciones que delega en la ventana compacta.
pub struct AppOperationHandler {
    tx: Sender<ProtocolUiRequest>,
    ctx: egui::Context,
}

impl AppOperationHandler {
    pub fn new(tx: Sender<ProtocolUiRequest>, ctx: egui::Context) -> Self {
        AppOperationHandler { tx, ctx }
    }

    fn ask<T>(&self, build: impl FnOnce(Sender<T>) -> ProtocolUiRequest, default: T) -> T {
        let (reply, rx) = channel();
        if self.tx.send(build(reply)).is_err() {
            return default;
        }
        self.ctx.request_repaint();
        rx.recv().unwrap_or(default)
    }
}

impl OperationHandler for AppOperationHandler {
    fn select_certificate(&self, req: &CertificateRequest<'_>) -> Result<Arc<dyn SigningKey>, AfirmaError> {
        let info = Some(req.info.clone());
        let extra = req.extra_params.clone();
        let keystore = req.keystore.cloned();
        let restrict_to = req.restrict_to_certificate.map(|c| c.to_vec());
        self.ask(
            |reply| ProtocolUiRequest::SelectCertificate {
                info,
                extra,
                keystore,
                restrict_to,
                reply,
            },
            Err(AfirmaError::cancelled()),
        )
    }

    fn choose_file_to_sign(&self, req: &OpenFileRequest) -> Result<FileData, AfirmaError> {
        let req = req.clone();
        self.ask(
            |reply| ProtocolUiRequest::ChooseFile { req, reply },
            Err(AfirmaError::cancelled()),
        )
    }

    fn save_file(&self, req: &SaveFileRequest<'_>) -> Result<(), AfirmaError> {
        let (title, data, proposed_name, extensions) = (
            req.title.clone(),
            req.data.to_vec(),
            req.proposed_name.clone(),
            req.extensions.clone(),
        );
        self.ask(
            |reply| ProtocolUiRequest::SaveFile {
                title,
                data,
                proposed_name,
                extensions,
                reply,
            },
            Err(AfirmaError::cancelled()),
        )
    }

    fn load_files(&self, req: &LoadRequest) -> Result<Vec<FileData>, AfirmaError> {
        let req = req.clone();
        self.ask(
            |reply| ProtocolUiRequest::LoadFiles { req, reply },
            Err(AfirmaError::cancelled()),
        )
    }

    fn confirm(&self, req: &ConfirmRequest) -> bool {
        let message = super::messages::intervention_text(&req.requestor_text)
            .map(str::to_string)
            .unwrap_or_else(|| req.message.clone());
        self.ask(|reply| ProtocolUiRequest::Confirm { message, reply }, false)
    }

    fn request_password(&self, req: &PasswordRequest) -> Option<String> {
        let message = super::messages::intervention_text(&req.requestor_text)
            .map(str::to_string)
            .unwrap_or_else(|| req.message.clone());
        self.ask(|reply| ProtocolUiRequest::Password { message, reply }, None)
    }

    fn visible_signature(&self, req: &VisibleSignatureRequest<'_>) -> Result<Option<ExtraParams>, AfirmaError> {
        let (data, custom, mandatory) = (req.data.to_vec(), req.custom_appearance, req.mandatory);
        self.ask(
            |reply| ProtocolUiRequest::VisibleSignature {
                data,
                custom,
                mandatory,
                reply,
            },
            Ok(None),
        )
    }

    fn show_error(&self, dialog: &ErrorDialog) {
        let _ = self.tx.send(ProtocolUiRequest::Error {
            title: dialog.title.clone(),
            message: dialog.message.clone(),
        });
        self.ctx.request_repaint();
    }

    fn progress(&self, event: ProgressEvent, _info: Option<&RequestInfo>) {
        let _ = self.tx.send(ProtocolUiRequest::Progress(event));
        self.ctx.request_repaint();
    }
}

/// Arranca el lanzador del protocolo en un hilo. Al terminar envía
/// [`ProtocolUiRequest::Finished`].
pub fn spawn_launcher(url: String, ctx: egui::Context) -> std::sync::mpsc::Receiver<ProtocolUiRequest> {
    let (tx, rx) = channel();
    let handler: Arc<dyn OperationHandler> = Arc::new(AppOperationHandler::new(tx.clone(), ctx.clone()));
    let signer: Arc<dyn LocalSigner> = Arc::new(AppLocalSigner);
    let _ = std::thread::Builder::new().name("protocolo".into()).spawn(move || {
        let config = afirma_protocol::LauncherConfig::new(afirma_protocol::HttpClient::installed());
        let launcher = Arc::new(afirma_protocol::ProtocolLauncher::new(handler, signer, config));
        let pfx = find_local_pfx().unwrap_or_default();
        let code = launcher.run_url(&url, &afirma_protocol::TlsSource::autofirma_pfx(pfx));
        let _ = tx.send(ProtocolUiRequest::Finished(code));
        ctx.request_repaint();
    });
    rx
}

/// `autofirma.pfx` del servidor local, en los mismos sitios donde lo genera la
/// instalación (junto al ejecutable, en el directorio alternativo y, en macOS,
/// en el de sistema).
pub fn find_local_pfx() -> Option<std::path::PathBuf> {
    let ctx = afirma_system::Context::detect(afirma_system::AppIdentity::current());
    afirma_system::certs::search_dirs(&ctx)
        .into_iter()
        .map(|d| d.join(afirma_protocol::channel::AUTOFIRMA_PFX_NAME))
        .find(|p| p.is_file())
}
