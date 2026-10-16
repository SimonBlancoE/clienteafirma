//! Flujos de la aplicación de escritorio: carga de ficheros, almacenes,
//! firma con progreso y verificación. Las operaciones pesadas se hacen en
//! hilos de trabajo ([`crate::services::task::Job`]) y las peticiones al
//! usuario (PIN, confirmaciones) llegan por el puente
//! ([`crate::services::bridge`]).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use afirma_core::ExtraParams;
use afirma_core::formats::SignerKind;
use afirma_keystores::StoreSpec;
use eframe::egui;

use super::app::{AutoFirmaApp, Page};
use super::cert_picker::PickerEvent;
use super::pages::sign::{FileItem, FileStatus, SignAction, Stage};
use super::pages::verify::{SignatureReport, VerifyAction, VerifyPage};
use super::visible_sig::VisibleSigEvent;
use crate::services::bridge::{UiBridge, UiInbox};
use crate::services::certs::{self, LoadedStore};
use crate::services::signing::{self, SignJobInput, SignProgress};
use crate::services::task::{Job, JobEvent};

/// Paso pendiente del flujo de firma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignStep {
    Idle,
    Confirm,
    VisibleSignature,
    ChooseCertificate,
    Signing,
}

/// Estado de ejecución (tareas, almacén, puente con la interfaz).
pub struct Runtime {
    pub bridge: UiBridge,
    pub inbox: UiInbox,
    pub load_job: Option<Job<(), (Vec<FileItem>, Vec<String>)>>,
    pub store_job: Option<Job<(), Result<LoadedStore, String>>>,
    pub store: Option<Arc<LoadedStore>>,
    pub store_spec: StoreSpec,
    pub sign_job: Option<Job<SignProgress, Result<(), String>>>,
    pub verify_job: Option<Job<(), Result<SignatureReport, String>>>,
    pub tool_job: Option<Job<(), crate::services::tools::ToolOutcome>>,
    pub certs_job: Option<(usize, Job<(), Result<Vec<super::model::CertItem>, String>>)>,
    pub step: SignStep,
    pub visible_params: Option<ExtraParams>,
    pub toast: Option<(String, std::time::Instant)>,
}

impl Runtime {
    pub fn new(ctx: &egui::Context) -> Runtime {
        let (bridge, rx) = UiBridge::new(ctx);
        Runtime {
            bridge,
            inbox: UiInbox::new(rx),
            load_job: None,
            store_job: None,
            store: None,
            store_spec: certs::default_spec(),
            sign_job: None,
            verify_job: None,
            tool_job: None,
            certs_job: None,
            step: SignStep::Idle,
            visible_params: None,
            toast: None,
        }
    }
}

impl AutoFirmaApp {
    /// Copia de las preferencias para los hilos de trabajo.
    fn prefs_snapshot(&self) -> Arc<HashMap<String, String>> {
        let mut map = HashMap::new();
        for key in super::pages::settings::ALL_KEYS {
            if let Some(v) = self.prefs.get(key) {
                map.insert(key.to_string(), v);
            }
        }
        Arc::new(map)
    }

    fn notify(&mut self, msg: impl Into<String>) {
        self.rt.toast = Some((msg.into(), std::time::Instant::now()));
    }

    /// Carga ficheros (desde el selector o arrastrados) en la página de firma.
    pub(crate) fn load_files(&mut self, ctx: &egui::Context, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        let prefs = self.prefs_snapshot();
        self.rt.load_job = Some(Job::spawn(ctx, "carga", move |_| {
            let get = |k: &str| prefs.get(k).cloned();
            crate::services::files::load_files(&paths, &get)
        }));
    }

    /// Abre el almacén indicado en segundo plano.
    pub(crate) fn load_store(&mut self, ctx: &egui::Context, spec: StoreSpec, force: bool) {
        let prefs = self.prefs_snapshot();
        let bridge = self.rt.bridge.clone();
        self.picker.loading = true;
        self.picker.error = None;
        self.picker.store_label = spec.display_name();
        self.rt.store_spec = spec.clone();
        self.rt.store_job = Some(Job::spawn(ctx, "almacen", move |_| {
            let get = |k: &str| prefs.get(k).cloned();
            let filters = certs::local_filters(&get);
            certs::load(&spec, Arc::new(bridge), &filters, force)
        }));
    }

    /// Consulta las tareas en curso y aplica sus resultados.
    pub(crate) fn pump_jobs(&mut self, ctx: &egui::Context) {
        let (events, finished) = match &mut self.rt.load_job {
            Some(job) => (job.poll(), job.is_finished()),
            None => (Vec::new(), false),
        };
        if finished {
            self.rt.load_job = None;
        }
        for ev in events {
            if let JobEvent::Done((items, errors)) = ev {
                if items.is_empty() && !errors.is_empty() {
                    self.sign.last_error = Some(errors.join("\n"));
                } else if !errors.is_empty() {
                    self.notify(format!("{} fichero(s) no se han podido leer", errors.len()));
                }
                if !items.is_empty() {
                    if self.sign.stage != Stage::Ready {
                        self.sign.files.clear();
                    }
                    self.sign.files.extend(items);
                    self.sign.stage = Stage::Ready;
                    self.sign.last_error = None;
                    self.sign.visible_signature = self.pref_bool("padesVisibleSignature", false);
                }
            }
        }
        if let Some(job) = &mut self.rt.store_job {
            for ev in job.poll() {
                if let JobEvent::Done(result) = ev {
                    self.picker.loading = false;
                    match result {
                        Ok(store) => {
                            self.picker.store_label = store.label.clone();
                            self.sign.store_label = store.label.clone();
                            self.picker.set_certs(store.items.clone());
                            self.rt.store = Some(Arc::new(store));
                        }
                        Err(e) => {
                            self.picker.error = Some(e);
                            self.picker.certs.clear();
                        }
                    }
                }
            }
            if job.is_finished() {
                self.rt.store_job = None;
            }
        }
        if let Some(job) = &mut self.rt.sign_job {
            let mut events = Vec::new();
            events.extend(job.poll());
            for ev in events {
                match ev {
                    JobEvent::Progress(SignProgress::KeyReady) => {}
                    JobEvent::Progress(SignProgress::Started(i)) => {
                        if let Some(f) = self.sign.files.get_mut(i) {
                            f.status = FileStatus::Signing;
                        }
                        self.sign.stage = Stage::Signing { done: i, total: self.sign.files.len() };
                    }
                    JobEvent::Progress(SignProgress::Finished(i, r)) => {
                        if let Some(f) = self.sign.files.get_mut(i) {
                            f.status = match r {
                                Ok(p) => FileStatus::Done(p),
                                Err(e) => FileStatus::Failed(e),
                            };
                        }
                    }
                    JobEvent::Done(r) => {
                        self.rt.step = SignStep::Idle;
                        match r {
                            Ok(()) => self.sign.stage = Stage::Finished,
                            Err(e) => {
                                // Sin clave (PIN cancelado, tarjeta extraída...): se
                                // vuelve a la lista con el error.
                                for f in &mut self.sign.files {
                                    f.status = FileStatus::Pending;
                                }
                                self.sign.stage = Stage::Ready;
                                if !e.contains("cancelad") {
                                    self.sign.last_error = Some(e);
                                }
                            }
                        }
                    }
                }
            }
            if job.is_finished() {
                self.rt.sign_job = None;
            }
        }
        if let Some(job) = &mut self.rt.verify_job {
            for ev in job.poll() {
                if let JobEvent::Done(r) = ev {
                    self.verify.loading = None;
                    match r {
                        Ok(report) => {
                            self.verify.report = Some(report);
                            self.verify.error = None;
                        }
                        Err(e) => self.verify.error = Some(e),
                    }
                }
            }
            if job.is_finished() {
                self.rt.verify_job = None;
            }
        }
        self.pump_tool_job(ctx);
        self.pump_certs_job();
    }

    pub(crate) fn pref_bool(&self, key: &str, default: bool) -> bool {
        self.prefs.get(key).map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(default)
    }

    /// Ficheros arrastrados sobre la ventana.
    pub(crate) fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| { let p = f.path(); (!p.as_os_str().is_empty()).then(|| p.to_path_buf()) }).collect());
        if dropped.is_empty() {
            return;
        }
        match self.page {
            Page::Verify => self.verify_path(ctx, dropped[0].clone()),
            _ => {
                self.page = Page::Sign;
                if matches!(self.sign.stage, Stage::Finished) {
                    self.sign.files.clear();
                    self.sign.stage = Stage::Empty;
                }
                self.load_files(ctx, dropped);
            }
        }
    }

    pub(crate) fn verify_path(&mut self, ctx: &egui::Context, path: PathBuf) {
        self.page = Page::Verify;
        self.verify = VerifyPage { loading: Some(format!("Verificando {}…", path.display())), ..Default::default() };
        let mut params = ExtraParams::new();
        // `allowShadowAttack=true` en la preferencia significa "sí comprobar".
        if self.pref_bool("allowShadowAttack", false) {
            params.set("pagesToCheckShadowAttack", "all");
        } else {
            params.set("allowShadowAttack", "true");
        }
        self.rt.verify_job = Some(Job::spawn(ctx, "verificar", move |_| crate::services::verify::verify_file(&path, &params)));
    }

    /// Acciones de la página de firma.
    pub(crate) fn on_sign_actions(&mut self, ctx: &egui::Context, actions: Vec<SignAction>) {
        for a in actions {
            match a {
                SignAction::PickFiles => {
                    if let Some(files) = rfd::FileDialog::new().set_title("Selecciona los documentos que quieres firmar").pick_files() {
                        self.load_files(ctx, files);
                    }
                }
                SignAction::Clear => {
                    self.sign.files.clear();
                    self.sign.stage = Stage::Empty;
                    self.sign.last_error = None;
                    self.rt.visible_params = None;
                }
                SignAction::Remove(i) => {
                    if i < self.sign.files.len() {
                        self.sign.files.remove(i);
                    }
                    if self.sign.files.is_empty() {
                        self.sign.stage = Stage::Empty;
                    }
                }
                SignAction::ChooseOutputDir => {
                    if let Some(dir) = rfd::FileDialog::new().set_title("Carpeta donde guardar las firmas").pick_folder() {
                        self.sign.output_dir = Some(dir);
                    }
                }
                SignAction::ChangeStore => {
                    self.picker.accept_label = "Usar este almacén".into();
                    self.open_picker(ctx);
                    self.rt.step = SignStep::Idle;
                }
                SignAction::ConfigureVisibleSignature(i) => self.open_visible_editor(i),
                SignAction::StartSigning => {
                    self.sign.last_error = None;
                    if self.pref_bool("confirmToSign", true) {
                        self.rt.step = SignStep::Confirm;
                    } else {
                        self.after_confirm(ctx);
                    }
                }
                SignAction::OpenFolder(p) => {
                    let _ = crate::services::desktop::reveal(&p);
                }
                SignAction::OpenOutput(p) => {
                    let _ = crate::services::desktop::open(&p);
                }
                SignAction::VerifyOutput(p) => self.verify_path(ctx, p),
                SignAction::RepairIntegration => {
                    self.sign.integration_needed = false;
                    self.integration_needed = false;
                    self.notify("Integrando AutoFirma con los navegadores…");
                    self.rt.tool_job = Some(Job::spawn(ctx, "reparar", |_| crate::services::tools::repair()));
                }
            }
        }
    }

    fn open_visible_editor(&mut self, index: usize) {
        let Some(f) = self.sign.files.get(index) else { return };
        match crate::services::pdf_pages::PdfPages::open(&f.data, None) {
            Ok(pages) => {
                self.visible_sig.multi_document = self.sign.files.iter().filter(|f| f.format == "PAdES").count() > 1;
                self.visible_sig.empty_fields = afirma_pdf::info::empty_signature_fields(&f.data)
                    .into_iter()
                    .map(|e| super::visible_sig::EmptyField {
                        name: e.name.clone(),
                        page: e.page.saturating_sub(1),
                        rect: [e.llx as f32, e.lly as f32, e.urx as f32, e.ury as f32],
                    })
                    .collect();
                self.visible_sig.open_with(f.name.clone(), Arc::new(pages));
                self.rt.step = SignStep::VisibleSignature;
            }
            Err(e) => {
                self.notify(format!("No se puede previsualizar el PDF: {e}. Se firmará sin firma visible."));
            }
        }
    }

    fn after_confirm(&mut self, ctx: &egui::Context) {
        let needs_visible = self.sign.visible_signature
            && self.rt.visible_params.is_none()
            && self.sign.files.iter().any(|f| f.format == "PAdES" || f.format == "Adobe PDF");
        if needs_visible {
            if let Some(i) = self.sign.files.iter().position(|f| f.format == "PAdES" || f.format == "Adobe PDF") {
                self.open_visible_editor(i);
                if self.rt.step == SignStep::VisibleSignature {
                    return;
                }
            }
        }
        self.rt.step = SignStep::ChooseCertificate;
        self.picker.accept_label = "Firmar".into();
        self.open_picker(ctx);
    }

    fn open_picker(&mut self, ctx: &egui::Context) {
        self.picker.open = true;
        self.picker.allow_change_store = true;
        self.picker.stores = certs::store_options();
        self.picker.subtitle = None;
        match &self.rt.store {
            Some(s) if self.rt.store_job.is_none() => {
                self.picker.loading = false;
                self.picker.store_label = s.label.clone();
                self.picker.set_certs(s.items.clone());
            }
            _ => {
                if self.rt.store_job.is_none() {
                    let spec = self.rt.store_spec.clone();
                    self.load_store(ctx, spec, false);
                }
            }
        }
    }

    /// Eventos del selector de certificados.
    pub(crate) fn on_picker_event(&mut self, ctx: &egui::Context, ev: PickerEvent) {
        match ev {
            PickerEvent::None => {}
            PickerEvent::Cancelled => self.rt.step = SignStep::Idle,
            PickerEvent::Refresh => {
                let spec = self.rt.store_spec.clone();
                self.load_store(ctx, spec, true);
            }
            PickerEvent::ChangeStore(id) => {
                let lib = if id == "PKCS12" {
                    match rfd::FileDialog::new()
                        .set_title("Selecciona el almacén de certificados")
                        .add_filter("Almacenes de claves (*.p12, *.pfx)", &["p12", "pfx"])
                        .pick_file()
                    {
                        Some(p) => Some(p.display().to_string()),
                        None => return,
                    }
                } else {
                    None
                };
                if let Some(spec) = certs::spec_for(&id, lib) {
                    self.picker.open = true;
                    self.load_store(ctx, spec, false);
                }
            }
            PickerEvent::Accepted(i) => {
                if self.rt.step != SignStep::ChooseCertificate {
                    // Solo se cambiaba de almacén.
                    return;
                }
                self.start_signing(ctx, i);
            }
        }
    }

    fn start_signing(&mut self, ctx: &egui::Context, index: usize) {
        let Some(store) = self.rt.store.clone() else { return };
        let Some(entry) = store.entries.get(index).cloned() else { return };
        let prefs = self.prefs_snapshot();
        let params_prefs = prefs.clone();
        let input = SignJobInput {
            files: self.sign.files.clone(),
            store: store.store.clone(),
            entry_id: entry.id.clone(),
            algorithm: afirma_signers::params::desktop_algorithm(&|k| prefs.get(k).cloned()),
            params_for: Arc::new(move |kind: SignerKind| afirma_signers::params::from_preferences(kind, &|k| params_prefs.get(k).cloned())),
            visible_params: if self.sign.visible_signature { self.rt.visible_params.clone() } else { None },
            output_dir: self.sign.output_dir.clone(),
            overwrite: prefs.get("massiveOverride").is_some_and(|v| v == "true"),
            bridge: self.rt.bridge.clone(),
        };
        self.rt.step = SignStep::Signing;
        self.sign.stage = Stage::Signing { done: 0, total: self.sign.files.len() };
        self.rt.sign_job = Some(Job::spawn(ctx, "firma", move |progress| signing::run(input, progress)));
    }

    /// Diálogos del flujo de firma (confirmación y firma visible).
    pub(crate) fn sign_flow_dialogs(&mut self, ctx: &egui::Context) {
        let p = self.palette();
        if self.rt.step == SignStep::Confirm {
            let n = self.sign.files.len();
            let msg = if n == 1 {
                "Se va a firmar electrónicamente 1 documento con el certificado que elijas a continuación.".to_string()
            } else {
                format!("Se van a firmar electrónicamente {n} documentos con el certificado que elijas a continuación.")
            };
            if let Some(ok) = super::dialogs::confirm_modal(ctx, &p, "Autorizar la firma", &msg, "Continuar", false, false) {
                if ok {
                    self.after_confirm(ctx);
                } else {
                    self.rt.step = SignStep::Idle;
                }
            }
        }
        match self.visible_sig.show(ctx, &p) {
            VisibleSigEvent::None => {}
            VisibleSigEvent::Accepted(params, _remember) => {
                self.rt.visible_params = Some(params);
                if self.rt.step == SignStep::VisibleSignature {
                    self.rt.step = SignStep::ChooseCertificate;
                    self.picker.accept_label = "Firmar".into();
                    self.open_picker(ctx);
                }
            }
            VisibleSigEvent::Invisible => {
                self.sign.visible_signature = false;
                if self.rt.step == SignStep::VisibleSignature {
                    self.rt.step = SignStep::ChooseCertificate;
                    self.picker.accept_label = "Firmar".into();
                    self.open_picker(ctx);
                }
            }
            VisibleSigEvent::Cancelled => {
                if self.rt.step == SignStep::VisibleSignature {
                    self.rt.step = SignStep::Idle;
                }
            }
        }
    }

    /// Acciones de la página de verificación.
    pub(crate) fn on_verify_actions(&mut self, ctx: &egui::Context, actions: Vec<VerifyAction>) {
        for a in actions {
            match a {
                VerifyAction::PickFile => {
                    if let Some(p) = rfd::FileDialog::new().set_title("Selecciona la firma o el documento firmado").pick_file() {
                        self.verify_path(ctx, p);
                    }
                }
                VerifyAction::Clear => self.verify = VerifyPage::default(),
                VerifyAction::ExtractData => self.extract_signed_data(),
                VerifyAction::Cosign | VerifyAction::Countersign => {
                    if let Some(r) = &self.verify.report {
                        let path = r.path.clone();
                        let countersign = a == VerifyAction::Countersign;
                        self.page = Page::Sign;
                        self.sign.files.clear();
                        self.sign.stage = Stage::Empty;
                        self.load_files(ctx, vec![path]);
                        self.rt.toast = Some((
                            if countersign { "Elige \"Contrafirmar\" en la lista y pulsa Firmar" } else { "Pulsa Firmar para añadir tu firma" }
                                .into(),
                            std::time::Instant::now(),
                        ));
                    }
                }
                VerifyAction::ExportCertificate(i) => {
                    if let Some(der) = self.verify.report.as_ref().and_then(|r| r.signatures.get(i)).map(|s| s.cert_der.clone()) {
                        if let Some(path) = rfd::FileDialog::new().set_file_name("certificado.cer").save_file() {
                            if let Err(e) = std::fs::write(&path, der) {
                                self.notify(format!("No se ha podido guardar: {e}"));
                            }
                        }
                    }
                }
            }
        }
    }

    fn extract_signed_data(&mut self) {
        let Some(report) = &self.verify.report else { return };
        let Ok(data) = std::fs::read(&report.path) else { return };
        let params = ExtraParams::new();
        let Some((_, signer)) = afirma_signers::detect(&data, &params) else { return };
        match signer.get_data(&data, &params) {
            Ok(Some(content)) => {
                let stem = report.path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "datos".into());
                let ext = afirma_core::mime::MimeHelper::new(&content).extension().ok().flatten().unwrap_or_else(|| "bin".into());
                let name = if stem.contains('.') { stem.clone() } else { format!("{stem}.{ext}") };
                if let Some(path) = rfd::FileDialog::new().set_title("Guardar el documento firmado").set_file_name(name).save_file() {
                    match std::fs::write(&path, content) {
                        Ok(()) => self.notify("Documento guardado"),
                        Err(e) => self.notify(format!("No se ha podido guardar: {e}")),
                    }
                }
            }
            _ => self.notify("La firma no contiene el documento firmado"),
        }
    }

    fn pump_tool_job(&mut self, ctx: &egui::Context) {
        use crate::services::tools::ToolOutcome;
        use super::widgets::CalloutKind;
        let Some(job) = &mut self.rt.tool_job else { return };
        let events = job.poll();
        if job.is_finished() {
            self.rt.tool_job = None;
        }
        for ev in events {
            let JobEvent::Done(out) = ev else { continue };
            self.tools.running = false;
            match out {
                ToolOutcome::FileHash { content, proposed, ext, clipboard } => {
                    if self.tools.copy_clipboard {
                        ctx.copy_text(clipboard);
                    }
                    let dlg = rfd::FileDialog::new()
                        .set_title("Guardar huella digital")
                        .set_file_name(&proposed)
                        .add_filter(format!("Huella digital (*.{ext})"), &[ext.as_str()]);
                    let dlg = match self.tools.input.as_ref().and_then(|p| p.parent()) {
                        Some(d) => dlg.set_directory(d),
                        None => dlg,
                    };
                    if let Some(path) = dlg.save_file() {
                        self.tools.result = Some(match std::fs::write(&path, content) {
                            Ok(()) => (CalloutKind::Success, "Huella digital guardada".into(), Some(path.display().to_string())),
                            Err(e) => (CalloutKind::Error, "No se ha podido guardar la huella digital".into(), Some(e.to_string())),
                        });
                    } else if self.tools.copy_clipboard {
                        self.tools.result = Some((CalloutKind::Info, "Huella copiada al portapapeles".into(), None));
                    }
                }
                ToolOutcome::DirHash { document, proposed } => {
                    let dlg = rfd::FileDialog::new()
                        .set_title("Guardar huellas digitales")
                        .set_file_name(&proposed)
                        .add_filter("Huellas digitales en formato XML (*.hashfiles)", &["hashfiles"])
                        .add_filter("Huellas digitales en formato TXT (*.txthashfiles)", &["txthashfiles"]);
                    if let Some(path) = dlg.save_file() {
                        let format = crate::services::tools::dir_format_for(&path);
                        let r = document.generate(format).map_err(|e| e.to_string()).and_then(|b| std::fs::write(&path, b).map_err(|e| e.to_string()));
                        self.tools.result = Some(match r {
                            Ok(()) => (CalloutKind::Success, format!("Huellas de {} ficheros guardadas", document.entries.len()), Some(path.display().to_string())),
                            Err(e) => (CalloutKind::Error, "No se han podido guardar las huellas".into(), Some(e)),
                        });
                    }
                }
                ToolOutcome::Check { ok, title, detail, report_xml } => {
                    self.tools.result = Some((if ok { CalloutKind::Success } else { CalloutKind::Warning }, title, detail));
                    if let Some(xml) = report_xml {
                        if !ok {
                            if let Some(path) = rfd::FileDialog::new()
                                .set_title("Guardar informe de huellas digitales")
                                .set_file_name("informe.hashreport")
                                .save_file()
                            {
                                let _ = std::fs::write(path, xml);
                            }
                        }
                    }
                }
                ToolOutcome::Doctor(rows) => {
                    if self.page != Page::Tools {
                        let failed = rows.iter().filter(|r| r.ok == Some(false)).count();
                        self.notify(if failed == 0 {
                            "AutoFirma está integrado con tus navegadores".to_string()
                        } else {
                            format!("Integración incompleta: {failed} comprobaciones con problemas (ver Herramientas)")
                        });
                    }
                    self.tools.doctor = rows;
                }
                ToolOutcome::Error(e) => self.tools.result = Some((CalloutKind::Error, "No se ha podido completar la operación".into(), Some(e))),
            }
        }
    }

    /// Acciones de la página de herramientas.
    pub(crate) fn on_tools_actions(&mut self, ctx: &egui::Context, actions: Vec<super::pages::tools::ToolsAction>) {
        use super::pages::tools::{Tool, ToolsAction};
        use crate::services::tools;
        for a in actions {
            match a {
                ToolsAction::Open(t) => {
                    self.tools.open = Some(t);
                    self.tools.result = None;
                    self.tools.input = None;
                    self.tools.secondary = None;
                    if matches!(t, Tool::Doctor | Tool::RestoreBrowsers) && self.tools.doctor.is_empty() {
                        self.tools.running = true;
                        self.rt.tool_job = Some(Job::spawn(ctx, "doctor", |_| tools::doctor()));
                    }
                }
                ToolsAction::Close => self.tools.open = None,
                ToolsAction::PickInput => {
                    let dlg = rfd::FileDialog::new();
                    let picked = match self.tools.open {
                        Some(Tool::HashDir | Tool::CheckHashDir) => dlg.set_title("Selecciona la carpeta").pick_folder(),
                        _ => dlg.set_title("Selecciona el fichero").pick_file(),
                    };
                    if picked.is_some() {
                        self.tools.input = picked;
                        self.tools.result = None;
                    }
                }
                ToolsAction::PickSecondary => {
                    let exts: &[&str] = match self.tools.open {
                        Some(Tool::CheckHashDir) => &["hashfiles", "txthashfiles", "xml", "txt"],
                        _ => &["hexhash", "hashb64", "hash"],
                    };
                    if let Some(p) = rfd::FileDialog::new().set_title("Selecciona el fichero de huellas").add_filter("Huellas digitales", exts).pick_file() {
                        self.tools.secondary = Some(p);
                        self.tools.result = None;
                    }
                }
                ToolsAction::Run => {
                    let (Some(tool), Some(input)) = (self.tools.open, self.tools.input.clone()) else { continue };
                    let secondary = self.tools.secondary.clone();
                    let (alg, fmt, rec) = (self.tools.algorithm.clone(), self.tools.format.clone(), self.tools.recursive);
                    self.tools.running = true;
                    self.tools.result = None;
                    self.rt.tool_job = Some(Job::spawn(ctx, "herramienta", move |_| match tool {
                        Tool::HashFile => tools::hash_file(&input, &alg, &fmt),
                        Tool::CheckHashFile => tools::check_file(&input, secondary.as_deref().unwrap_or(&input)),
                        Tool::HashDir => tools::hash_dir(&input, &alg, rec),
                        Tool::CheckHashDir => tools::check_dir(&input, secondary.as_deref().unwrap_or(&input)),
                        _ => tools::ToolOutcome::Error("Herramienta no disponible todavía".into()),
                    }));
                }
                ToolsAction::RunDoctor => {
                    self.tools.running = true;
                    self.rt.tool_job = Some(Job::spawn(ctx, "doctor", |_| tools::doctor()));
                }
                ToolsAction::RepairAll => {
                    self.tools.running = true;
                    self.rt.tool_job = Some(Job::spawn(ctx, "reparar", |_| tools::repair()));
                }
            }
        }
    }

    /// Prepara la lista de almacenes de la página "Mis certificados".
    pub(crate) fn ensure_cert_stores(&mut self, ctx: &egui::Context) {
        use super::pages::certificates::StoreEntry;
        if !self.certificates.stores.is_empty() {
            return;
        }
        let default_id = self.rt.store_spec.kind.id().to_string();
        for o in crate::services::certs::store_options().into_iter().filter(|o| o.id != "PKCS12") {
            let description = match o.id.as_str() {
                "MOZ_UNI" => "Certificados de Mozilla Firefox (y sus dispositivos)",
                "DNIEJAVA" => "DNI electrónico y tarjetas criptográficas",
                _ => "Almacén de certificados del sistema operativo",
            };
            self.certificates.stores.push(StoreEntry {
                id: o.id.clone(),
                label: o.label.clone(),
                description: description.into(),
                icon: o.icon,
                available: true,
                certs: None,
                error: None,
                loading: false,
                removable: false,
            });
        }
        self.certificates.default_store = Some(default_id.clone());
        self.certificates.selected = self.certificates.stores.iter().position(|s| s.id == default_id).unwrap_or(0);
        let i = self.certificates.selected;
        self.load_cert_store(ctx, i);
    }

    fn load_cert_store(&mut self, ctx: &egui::Context, index: usize) {
        let Some(entry) = self.certificates.stores.get_mut(index) else { return };
        let (id, lib) = match entry.id.split_once(':') {
            Some((k, l)) => (k.to_string(), Some(l.to_string())),
            None => (entry.id.clone(), None),
        };
        let Some(spec) = crate::services::certs::spec_for(&id, lib) else { return };
        entry.loading = true;
        entry.error = None;
        let bridge = self.rt.bridge.clone();
        self.rt.certs_job = Some((
            index,
            Job::spawn(ctx, "mis-certificados", move |_| {
                let filters = afirma_keystores::LocalFilterPrefs {
                    use_only_signature_certificates: false,
                    skip_auth_cert_dnie: false,
                    use_only_alias_certificates: false,
                    show_expired_certs: true,
                };
                crate::services::certs::load(&spec, Arc::new(bridge), &filters, true).map(|l| l.items)
            }),
        ));
    }

    fn pump_certs_job(&mut self) {
        let Some((index, job)) = &mut self.rt.certs_job else { return };
        let index = *index;
        let events = job.poll();
        if job.is_finished() {
            self.rt.certs_job = None;
        }
        for ev in events {
            if let JobEvent::Done(r) = ev {
                if let Some(s) = self.certificates.stores.get_mut(index) {
                    s.loading = false;
                    match r {
                        Ok(items) => s.certs = Some(items),
                        Err(e) => {
                            s.error = Some(e);
                            s.certs = None;
                        }
                    }
                }
            }
        }
    }

    /// Acciones de la página "Mis certificados".
    pub(crate) fn on_certs_actions(&mut self, ctx: &egui::Context, actions: Vec<super::pages::certificates::CertsAction>) {
        use super::pages::certificates::{CertsAction, StoreEntry};
        for a in actions {
            match a {
                CertsAction::SelectStore(i) => {
                    self.certificates.selected = i;
                    self.certificates.expanded = None;
                    if self.certificates.stores.get(i).is_some_and(|s| s.certs.is_none() && !s.loading) {
                        self.load_cert_store(ctx, i);
                    }
                }
                CertsAction::LoadStore(i) => self.load_cert_store(ctx, i),
                CertsAction::OpenPkcs12 => {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Abrir almacén de certificados")
                        .add_filter("Almacenes de claves (*.p12, *.pfx)", &["p12", "pfx"])
                        .pick_file()
                    {
                        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        self.certificates.stores.push(StoreEntry {
                            id: format!("PKCS12:{}", p.display()),
                            label: name,
                            description: p.display().to_string(),
                            icon: super::icons::FILE_LOCK,
                            available: true,
                            certs: None,
                            error: None,
                            loading: false,
                            removable: true,
                        });
                        let i = self.certificates.stores.len() - 1;
                        self.certificates.selected = i;
                        self.load_cert_store(ctx, i);
                    }
                }
                CertsAction::RegisterPkcs11 => {
                    let exts: &[&str] = if cfg!(windows) { &["dll"] } else if cfg!(target_os = "macos") { &["dylib", "so"] } else { &["so"] };
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Selecciona el controlador PKCS#11 de la tarjeta")
                        .add_filter("Bibliotecas PKCS#11", exts)
                        .pick_file()
                    {
                        let name = p.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        self.certificates.stores.push(StoreEntry {
                            id: format!("PKCS11:{}", p.display()),
                            label: name,
                            description: p.display().to_string(),
                            icon: super::icons::CPU,
                            available: true,
                            certs: None,
                            error: None,
                            loading: false,
                            removable: true,
                        });
                        let i = self.certificates.stores.len() - 1;
                        self.certificates.selected = i;
                        self.load_cert_store(ctx, i);
                    }
                }
                CertsAction::RemoveStore(i) => {
                    if self.certificates.stores.get(i).is_some_and(|s| s.removable) {
                        self.certificates.stores.remove(i);
                        self.certificates.selected = 0;
                    }
                }
                CertsAction::SetDefault(i) => {
                    if let Some(s) = self.certificates.stores.get(i) {
                        let (id, lib) = match s.id.split_once(':') {
                            Some((k, l)) => (k.to_string(), Some(l.to_string())),
                            None => (s.id.clone(), None),
                        };
                        if let Some(kind) = afirma_keystores::KeyStoreKind::from_id(&id) {
                            let is_system = crate::services::certs::default_spec().kind == kind;
                            self.prefs.set("defaultKeystore", Some(if is_system { "default" } else { kind.display_name() }));
                            self.prefs.set("defaultLocalKeystorePath", lib.as_deref());
                            self.rt.store_spec = afirma_keystores::StoreSpec { kind, lib, card_name: None };
                            self.rt.store = None;
                            self.certificates.default_store = Some(s.id.clone());
                            self.notify("Almacén predeterminado actualizado");
                        }
                    }
                }
                CertsAction::Export(si, ci) => {
                    let der = self.certificates.stores.get(si).and_then(|s| s.certs.as_ref()).and_then(|c| c.get(ci)).map(|c| (c.der.clone(), c.info.subject_cn.clone()));
                    if let Some((der, cn)) = der {
                        if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{cn}.cer")).add_filter("Certificado (*.cer)", &["cer"]).save_file() {
                            if let Err(e) = std::fs::write(&path, der) {
                                self.notify(format!("No se ha podido guardar: {e}"));
                            }
                        }
                    }
                }
            }
        }
    }
}
