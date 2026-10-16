//! Atención en la ventana compacta de las peticiones del protocolo
//! `afirma://` (ver [`crate::services::protocol`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use afirma_core::error::codes;
use afirma_core::{AfirmaError, ExtraParams, SigningKey};
use afirma_keystores::{CandidateOptions, CertEntry, CertFilterManager, KeyStore, KeyStoreKind, OpenOptions, StoreSpec, select_candidates};
use afirma_protocol::handler::{ProgressEvent, RequestInfo};
use afirma_protocol::{KeyStoreParam, OperationKind};
use eframe::egui;

use super::app::AutoFirmaApp;
use super::model::CertItem;
use super::request_view::{RequestEvent, RequestInfo as ViewInfo, RequestOp, RequestStage, RequestView};
use super::visible_sig::VisibleSigEvent;
use crate::i18n::tr;
use crate::services::protocol::ProtocolUiRequest;
use crate::services::task::{Job, JobEvent};

/// Código de salida del proceso en modo protocolo.
pub static EXIT_CODE: AtomicI32 = AtomicI32::new(0);

type CertReply = Sender<Result<Arc<dyn SigningKey>, AfirmaError>>;

struct LoadedCandidates {
    store: Arc<dyn KeyStore>,
    entries: Vec<CertEntry>,
    label: String,
    mandatory: bool,
}

/// Clave de firma obtenida (o el error).
type KeyResult = Result<Arc<dyn SigningKey>, AfirmaError>;

/// Estado del modo protocolo.
pub struct ProtocolState {
    rx: Receiver<ProtocolUiRequest>,
    pending: Option<ProtocolUiRequest>,
    cert_reply: Option<CertReply>,
    cert_request: Option<(ExtraParams, Option<Vec<u8>>)>,
    store_job: Option<Job<(), Result<LoadedCandidates, String>>>,
    key_job: Option<Job<(), KeyResult>>,
    candidates: Option<LoadedCandidates>,
    visible_reply: Option<Sender<Result<Option<ExtraParams>, AfirmaError>>>,
    finished_at: Option<Instant>,
    /// Momento en que terminó la última operación (para ocultar la ventana).
    done_at: Option<Instant>,
    shown: bool,
}

impl ProtocolState {
    pub fn new(rx: Receiver<ProtocolUiRequest>) -> Self {
        ProtocolState {
            rx,
            pending: None,
            cert_reply: None,
            cert_request: None,
            store_job: None,
            key_job: None,
            candidates: None,
            visible_reply: None,
            finished_at: None,
            done_at: None,
            shown: false,
        }
    }
}

fn view_info(info: Option<&RequestInfo>) -> ViewInfo {
    let op = match info.map(|i| i.operation) {
        Some(OperationKind::SelectCert) => RequestOp::SelectCert,
        Some(OperationKind::Batch) => RequestOp::Batch,
        Some(OperationKind::SignAndSave) => RequestOp::SignAndSave,
        Some(OperationKind::Save) => RequestOp::Save,
        Some(OperationKind::Load) => RequestOp::Load,
        _ => match info.and_then(|i| i.crypto_operation) {
            Some(afirma_protocol::CryptoOperation::CoSign) => RequestOp::Cosign,
            Some(afirma_protocol::CryptoOperation::CounterSign) => RequestOp::Countersign,
            _ => RequestOp::Sign,
        },
    };
    let doc_kind = info.and_then(|i| i.data.as_ref()).map(|d| {
        if afirma_core::mime::is_pdf_header(d) {
            "PDF".to_string()
        } else if afirma_core::mime::is_xml(d) {
            "XML".to_string()
        } else {
            tr("Documento").to_string()
        }
    });
    ViewInfo {
        origin: info.and_then(|i| i.origin.display()).map(|o| o.trim_start_matches("https://").trim_start_matches("http://").to_string()),
        op,
        format: info.and_then(|i| i.format.clone()),
        file_name: info.and_then(|i| i.file_name.clone()),
        data_len: info.and_then(|i| i.data_len),
        doc_kind,
        batch_count: info.and_then(|i| i.document_count),
    }
}

/// Almacén pedido por la web (o el predeterminado de la aplicación).
fn store_spec(param: Option<&KeyStoreParam>, default: StoreSpec) -> StoreSpec {
    let Some(p) = param else { return default };
    match p.resolved_constant().and_then(KeyStoreKind::from_id) {
        Some(kind) => StoreSpec { kind, lib: p.library.clone(), card_name: None },
        None => default,
    }
}

impl AutoFirmaApp {
    /// Atiende las peticiones del protocolo (se llama también con la ventana
    /// oculta).
    pub(crate) fn protocol_logic(&mut self, ctx: &egui::Context) {
        let Some(proto) = self.proto.as_mut() else { return };
        // Nuevas peticiones (una cada vez para las que necesitan respuesta).
        while proto.pending.is_none() {
            match proto.rx.try_recv() {
                Ok(ProtocolUiRequest::Progress(ev)) => {
                    if let Some(r) = self.request.as_mut() {
                        match ev {
                            ProgressEvent::Signing => r.stage = RequestStage::Working(tr("Firmando…").into()),
                            ProgressEvent::CheckingSignatures => r.stage = RequestStage::Working(tr("Comprobando las firmas del documento…").into()),
                            ProgressEvent::LoadingKeyStore => r.stage = RequestStage::Working(tr("Cargando los certificados…").into()),
                            ProgressEvent::Hide => {
                                if matches!(r.stage, RequestStage::Working(_)) {
                                    r.stage = RequestStage::Done(tr("Operación completada").into());
                                    proto.done_at = Some(Instant::now());
                                }
                            }
                        }
                    }
                }
                Ok(ProtocolUiRequest::Finished(code)) => {
                    EXIT_CODE.store(code, Ordering::SeqCst);
                    proto.finished_at = Some(Instant::now());
                    if let Some(r) = self.request.as_mut()
                        && !matches!(r.stage, RequestStage::Failed(_)) {
                            r.stage = RequestStage::Done(tr("Operación completada").into());
                        }
                }
                Ok(ProtocolUiRequest::Error { title, message }) => {
                    let mut r = self.request.take().unwrap_or_else(|| RequestView::new(view_info(None)));
                    r.stage = RequestStage::Failed(format!("{title}: {message}"));
                    self.request = Some(r);
                    show_window(ctx, proto);
                }
                Ok(other) => {
                    proto.done_at = None;
                    proto.pending = Some(other);
                    show_window(ctx, proto);
                }
                Err(_) => break,
            }
        }
        // Cierre automático tras terminar (si no hay un error a la vista).
        if let Some(t) = proto.finished_at {
            let failed = matches!(self.request.as_ref().map(|r| &r.stage), Some(RequestStage::Failed(_)));
            if !proto.shown || (!failed && t.elapsed() > Duration::from_millis(1600)) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
        }
        // Tras completar una operación la ventana se oculta: el proceso sigue
        // atendiendo a la página (WebSocket) por si pide más operaciones.
        if let Some(t) = proto.done_at {
            if proto.pending.is_none() && t.elapsed() > Duration::from_millis(1800) {
                proto.done_at = None;
                proto.shown = false;
                self.request = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
        }
        self.protocol_pending(ctx);
        self.protocol_jobs(ctx);
    }

    fn protocol_pending(&mut self, ctx: &egui::Context) {
        let Some(proto) = self.proto.as_mut() else { return };
        let Some(req) = proto.pending.take() else { return };
        match req {
            ProtocolUiRequest::SelectCertificate { info, extra, keystore, restrict_to, reply } => {
                let mut view = RequestView::new(view_info(info.as_ref()));
                view.picker.stores = crate::services::certs::store_options();
                view.picker.loading = true;
                let spec = store_spec(keystore.as_ref(), self.rt.store_spec.clone());
                view.picker.store_label = spec.display_name();
                self.request = Some(view);
                proto.cert_reply = Some(reply);
                proto.cert_request = Some((extra.clone(), restrict_to));
                let bridge = self.rt.bridge.clone();
                proto.store_job = Some(Job::spawn(ctx, "almacen-web", move |_| load_candidates(&spec, &extra, bridge)));
            }
            ProtocolUiRequest::ChooseFile { req, reply } => {
                let mut dlg = rfd::FileDialog::new().set_title(&req.title);
                if let Some(exts) = &req.extensions {
                    dlg = dlg.add_filter(&req.description, exts);
                }
                let r = match dlg.pick_file() {
                    Some(p) => std::fs::read(&p)
                        .map(|data| afirma_protocol::FileData {
                            name: p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                            data,
                        })
                        .map_err(|e| AfirmaError::new(codes::LOADING_LOCAL_FILE_ERROR, e.to_string())),
                    None => Err(AfirmaError::cancelled()),
                };
                let _ = reply.send(r);
            }
            ProtocolUiRequest::SaveFile { title, data, proposed_name, extensions, reply } => {
                let mut dlg = rfd::FileDialog::new().set_title(&title);
                if let Some(n) = &proposed_name {
                    dlg = dlg.set_file_name(n);
                }
                if let Some(exts) = &extensions {
                    dlg = dlg.add_filter(tr("Ficheros"), exts);
                }
                let r = match dlg.save_file() {
                    Some(p) => std::fs::write(&p, &data).map_err(|e| AfirmaError::new(codes::CANT_SAVE_FILE, e.to_string())),
                    None => Err(AfirmaError::cancelled()),
                };
                let _ = reply.send(r);
            }
            ProtocolUiRequest::LoadFiles { req, reply } => {
                let mut dlg = rfd::FileDialog::new();
                if let Some(t) = &req.title {
                    dlg = dlg.set_title(t);
                }
                if let Some(exts) = &req.extensions {
                    dlg = dlg.add_filter(req.description.as_deref().unwrap_or(tr("Ficheros")), exts);
                }
                let picked: Option<Vec<std::path::PathBuf>> =
                    if req.multiple { dlg.pick_files() } else { dlg.pick_file().map(|p| vec![p]) };
                let r = match picked {
                    Some(paths) => paths
                        .into_iter()
                        .map(|p| {
                            std::fs::read(&p).map(|data| afirma_protocol::FileData {
                                name: p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                                data,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| AfirmaError::new(codes::CANT_LOAD_FILE, e.to_string())),
                    None => Err(AfirmaError::cancelled()),
                };
                let _ = reply.send(r);
            }
            ProtocolUiRequest::Confirm { message, reply } => {
                // Se muestra en el siguiente fotograma con el diálogo modal.
                proto.pending = Some(ProtocolUiRequest::Confirm { message, reply });
            }
            ProtocolUiRequest::Password { message, reply } => {
                proto.pending = Some(ProtocolUiRequest::Password { message, reply });
            }
            ProtocolUiRequest::VisibleSignature { data, custom, mandatory, reply } => {
                match crate::services::pdf_pages::PdfPages::open(&data, None) {
                    Ok(pages) => {
                        self.visible_sig.custom_appearance = custom;
                        self.visible_sig.mandatory = mandatory;
                        self.visible_sig.multi_document = false;
                        self.visible_sig.empty_fields.clear();
                        self.visible_sig.open_with(tr("Documento PDF"), Arc::new(pages));
                        proto.visible_reply = Some(reply);
                    }
                    Err(_) => {
                        let _ = reply.send(Ok(None));
                    }
                }
            }
            other => proto.pending = Some(other),
        }
    }

    fn protocol_jobs(&mut self, ctx: &egui::Context) {
        let Some(proto) = self.proto.as_mut() else { return };
        if let Some(job) = &mut proto.store_job {
            for ev in job.poll() {
                if let JobEvent::Done(r) = ev {
                    let Some(view) = self.request.as_mut() else { continue };
                    view.picker.loading = false;
                    match r {
                        Ok(mut loaded) => {
                            if let Some((_, Some(only))) = &proto.cert_request {
                                loaded.entries.retain(|e| &e.certificate == only);
                            }
                            view.picker.store_label = loaded.label.clone();
                            let items: Vec<CertItem> =
                                loaded.entries.iter().filter_map(|e| CertItem::from_der(e.id.clone(), e.certificate.clone())).collect();
                            view.picker.open_with(loaded.label.clone(), items);
                            if loaded.entries.is_empty() {
                                if let Some(reply) = proto.cert_reply.take() {
                                    let _ = reply.send(Err(AfirmaError::from_code(codes::CERTIFICATE_NEEDED)));
                                }
                                view.stage = RequestStage::Failed(
                                    tr("No hay ningún certificado válido en el almacén para esta operación.").into(),
                                );
                            } else if loaded.mandatory && loaded.entries.len() == 1 {
                                let store = loaded.store.clone();
                                let id = loaded.entries[0].id.clone();
                                proto.key_job = Some(spawn_key_job(ctx, store, id));
                                view.stage = RequestStage::Working(tr("Accediendo a la clave…").into());
                            }
                            proto.candidates = Some(loaded);
                        }
                        Err(e) => view.picker.error = Some(e),
                    }
                }
            }
            if job.is_finished() {
                proto.store_job = None;
            }
        }
        if let Some(job) = &mut proto.key_job {
            for ev in job.poll() {
                if let JobEvent::Done(r) = ev {
                    let failed = r.as_ref().err().map(|e| e.to_string());
                    if let Some(reply) = proto.cert_reply.take() {
                        let _ = reply.send(r);
                    }
                    if let Some(view) = self.request.as_mut() {
                        view.stage = match failed {
                            Some(e) if !e.contains("cancel") => RequestStage::Failed(e),
                            Some(_) => RequestStage::Working(tr("Operación cancelada").into()),
                            None => RequestStage::Working(tr("Firmando…").into()),
                        };
                    }
                }
            }
            if job.is_finished() {
                proto.key_job = None;
            }
        }
    }

    /// Diálogos y eventos de la ventana compacta (se llama desde `ui`).
    pub(crate) fn protocol_ui(&mut self, ctx: &egui::Context, event: Option<RequestEvent>) {
        let p = self.palette();
        let Some(proto) = self.proto.as_mut() else { return };
        match event {
            Some(RequestEvent::Accept(i)) => {
                if let Some(c) = &proto.candidates
                    && let Some(e) = c.entries.get(i) {
                        proto.key_job = Some(spawn_key_job(ctx, c.store.clone(), e.id.clone()));
                        if let Some(v) = self.request.as_mut() {
                            v.stage = RequestStage::Working(tr("Accediendo a la clave…").into());
                        }
                    }
            }
            Some(RequestEvent::Cancel) => {
                if let Some(reply) = proto.cert_reply.take() {
                    let _ = reply.send(Err(AfirmaError::cancelled()));
                }
                if let Some(v) = self.request.as_mut() {
                    v.stage = RequestStage::Working(tr("Cancelando…").into());
                }
            }
            Some(RequestEvent::Close) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Some(RequestEvent::Preview) => {
                if let Some(c) = &proto.candidates {
                    let _ = c;
                }
            }
            Some(RequestEvent::Picker(super::cert_picker::PickerEvent::Refresh)) => {
                if let (Some(c), Some((extra, _))) = (&proto.candidates, &proto.cert_request) {
                    let spec = StoreSpec { kind: c.store.kind(), lib: c.store.lib_name(), card_name: None };
                    let bridge = self.rt.bridge.clone();
                    let extra = extra.clone();
                    let _ = c.store.refresh();
                    proto.store_job = Some(Job::spawn(ctx, "almacen-web", move |_| load_candidates(&spec, &extra, bridge)));
                    if let Some(v) = self.request.as_mut() {
                        v.picker.loading = true;
                    }
                }
            }
            Some(RequestEvent::Picker(super::cert_picker::PickerEvent::ChangeStore(id))) => {
                let lib = if id == "PKCS12" {
                    rfd::FileDialog::new().add_filter(tr("Almacenes de claves (*.p12, *.pfx)"), &["p12", "pfx"]).pick_file().map(|p| p.display().to_string())
                } else {
                    None
                };
                if (id != "PKCS12" || lib.is_some())
                    && let (Some(spec), Some((extra, _))) = (crate::services::certs::spec_for(&id, lib), &proto.cert_request) {
                        let bridge = self.rt.bridge.clone();
                        let extra = extra.clone();
                        proto.store_job = Some(Job::spawn(ctx, "almacen-web", move |_| load_candidates(&spec, &extra, bridge)));
                        if let Some(v) = self.request.as_mut() {
                            v.picker.loading = true;
                        }
                    }
            }
            _ => {}
        }
        // Confirmaciones y contraseñas pedidas por el protocolo.
        let (enter, esc) = ctx.input(|i| (i.key_pressed(egui::Key::Enter), i.key_pressed(egui::Key::Escape)));
        match proto.pending.take() {
            Some(ProtocolUiRequest::Confirm { message, reply }) => {
                match super::dialogs::confirm_modal(ctx, &p, tr("Confirmación necesaria"), &message, tr("Continuar"), false, esc) {
                    Some(b) => {
                        let _ = reply.send(b);
                    }
                    None => proto.pending = Some(ProtocolUiRequest::Confirm { message, reply }),
                }
            }
            Some(ProtocolUiRequest::Password { message, reply }) => {
                let mut done = None;
                egui::Modal::new(egui::Id::unique("proto_pw")).show(ctx, |ui| {
                    ui.set_width(400.0);
                    ui.label(&message);
                    let r = ui.add(egui::TextEdit::singleline(&mut self.rt.inbox.secret).password(true));
                    r.request_focus();
                    ui.horizontal(|ui| {
                        if ui.button(tr("Aceptar")).clicked() || enter {
                            done = Some(Some(self.rt.inbox.secret.clone()));
                        }
                        if ui.button(tr("Cancelar")).clicked() || esc {
                            done = Some(None);
                        }
                    });
                });
                match done {
                    Some(v) => {
                        self.rt.inbox.secret.clear();
                        let _ = reply.send(v);
                    }
                    None => proto.pending = Some(ProtocolUiRequest::Password { message, reply }),
                }
            }
            other => proto.pending = other,
        }
        // Firma visible.
        if proto.visible_reply.is_some() {
            match self.visible_sig.show(ctx, &p) {
                VisibleSigEvent::None => {}
                VisibleSigEvent::Accepted(params, _) => {
                    if let Some(r) = proto.visible_reply.take() {
                        let _ = r.send(Ok(Some(params)));
                    }
                }
                VisibleSigEvent::Cancelled if self.visible_sig.mandatory => {
                    // Firma visible obligatoria: cancelar cancela la operación.
                    if let Some(r) = proto.visible_reply.take() {
                        let _ = r.send(Err(AfirmaError::cancelled()));
                    }
                }
                VisibleSigEvent::Invisible | VisibleSigEvent::Cancelled => {
                    if let Some(r) = proto.visible_reply.take() {
                        let _ = r.send(Ok(None));
                    }
                }
            }
        }
    }
}

fn show_window(ctx: &egui::Context, proto: &mut ProtocolState) {
    if !proto.shown {
        proto.shown = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
}

fn spawn_key_job(ctx: &egui::Context, store: Arc<dyn KeyStore>, id: String) -> Job<(), Result<Arc<dyn SigningKey>, AfirmaError>> {
    Job::spawn(ctx, "clave", move |_| {
        store.signing_key(&id).map(|k| -> Arc<dyn SigningKey> { Arc::from(k) }).map_err(AfirmaError::from)
    })
}

fn load_candidates(spec: &StoreSpec, extra: &ExtraParams, bridge: crate::services::bridge::UiBridge) -> Result<LoadedCandidates, String> {
    let opts = OpenOptions { load_all_external_modules: true, dedup_all: true, ..OpenOptions::new(Arc::new(bridge)) };
    let store = afirma_keystores::open_store(spec, &opts).map_err(|e| e.to_string())?;
    let all = store.entries().map_err(|e| e.to_string())?;
    let manager = CertFilterManager::from_extra_params(extra).map_err(|e| e.to_string())?;
    let list = select_candidates(&all, manager.filters(), &CandidateOptions::protocol(chrono::Utc::now()));
    Ok(LoadedCandidates {
        label: spec.display_name(),
        mandatory: manager.is_mandatory_certificate(),
        entries: list.candidates,
        store,
    })
}
