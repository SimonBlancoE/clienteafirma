//! Operaciones de varios pasos que encadenan actividades del sistema, hilos de trabajo y
//! diálogos: la firma local de un fichero (`LocalSignActivity`, `SignFragmentActivity` y
//! `LoadKeyStoreFragmentActivity`, `docs/spec/09-android.md` §3 y §4.1–§4.7) y la
//! importación de un certificado en KeyChain (§4.8).
//!
//! Firma local: selector de documentos → (vista previa de la firma visible si es un PDF y la
//! preferencia lo pide) → elección de almacén si el DNIe está habilitado → selector de
//! KeyChain → cadena del certificado → avisos (caducado, próximo a caducar, seudónimo) →
//! firma en un hilo de trabajo (con la contraseña del PDF si hace falta) → diálogo del
//! sistema para guardar → histórico → «Fichero firmado». Las cancelaciones cierran sin
//! mensaje (como el original) y los errores se muestran con su código `AA` (§3.7.4).
//!
//! No depende de egui más que para la textura de la vista previa ni de Android: las pruebas
//! usan la plataforma falsa. Cada paso que espera una respuesta guarda el identificador de su
//! petición y descarta las que no esperaba. Lo que hay que cambiar en la interfaz (diálogos y
//! pantalla de la vista previa) se devuelve como [`Effect`].

use std::collections::VecDeque;
use std::sync::Arc;

use afirma_core::{ExtraParams, SigningKey};
use afirma_protocol::android::sticky::StickyKeyCache;
use egui::TextureHandle;
use tracing::{error, info, warn};

use crate::bridge::{Bridge, DOCUMENT_TOO_LARGE, Platform, PlatformEvent, RequestId, Shared};
use crate::errors::{self, ErrorCategory, web};
use crate::history::{RecordKind, RecordOperation, SignRecord, SignsHistory};
use crate::i18n::tr;
use crate::keychain::{
    CertificateWarning, KeyChainKey, certificate_warnings, is_pseudonym_certificate, warning_id, warning_texts,
};
use crate::local_sign::{self, LocalFormat, SignFailure};
use crate::prefs::Prefs;
use crate::ui::icons;
use crate::ui::screens::{Action, Dialog, Prompt};
use crate::ui::widgets::Tone;
use crate::visible::{AreaCheck, PageImage, PreviewDocument, PreviewFailure, ViewSelection, check_area};

/// Tipos MIME de los almacenes que se pueden importar (`application/x-pkcs12`: `.p12`,
/// `.pfx`), como el selector del original.
pub const PKCS12_MIME: &str = "application/x-pkcs12";

/// Almacén elegido en «¿Con qué firmarás?».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// «Certificado electrónico»: KeyChain.
    Certificate,
    /// «DNI electrónico»: DNIe por NFC.
    Dnie,
}

/// Lo que piden los diálogos y pantallas de las operaciones.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowAction {
    /// «Firmar fichero».
    StartSign,
    /// «Añadir certificado» (y «Volver a intentarlo» tras un error).
    StartImport,
    /// Cancelar la operación en curso, sin mensaje.
    Cancel,
    /// Almacén elegido.
    CertType(CertType),
    /// Volver a «¿Con qué firmarás?» (tras el aviso de que el DNIe aún no está).
    ChooseStore,
    /// «Continuar» en un aviso sobre el certificado.
    WarningContinue,
    /// «Cancelar» en un aviso: se vuelve a elegir certificado.
    WarningCancel,
    /// «Aceptar» en el diálogo de la contraseña del PDF.
    PdfPassword(String),
    /// Página de la vista previa (desde 0).
    PreviewPage(usize),
    /// Dibujar una página de la vista previa con este ancho en píxeles.
    PreviewRender { page: usize, width: u32 },
    /// «Continuar» en la vista previa: área elegida (en unidades de la vista) y tamaño de la
    /// página en la vista.
    PreviewContinue {
        selection: Option<ViewSelection>,
        view: (f32, f32),
    },
    /// «Continuar» sin área o con un área demasiado pequeña: firma invisible.
    PreviewInvisible,
}

/// Cambio que la interfaz tiene que hacer.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Muestra un diálogo (sustituye al que haya).
    Dialog(Dialog),
    /// Cierra el diálogo.
    CloseDialog,
    /// Entra en la pantalla de la vista previa de la firma visible.
    OpenPreview,
    /// Sale de la vista previa.
    ClosePreview,
}

/// Paso de la firma local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    PickFile,
    Preview,
    StoreChoice,
    PickCertificate,
    LoadCertificate,
    Warning,
    Signing,
    Password,
    Saving,
}

/// Firma local en curso.
struct LocalSign {
    step: Step,
    /// Petición que se espera en este paso.
    request: RequestId,
    name: String,
    data: Arc<Vec<u8>>,
    format: LocalFormat,
    params: ExtraParams,
    key: Option<Arc<KeyChainKey>>,
    pseudonym: bool,
    warnings: VecDeque<CertificateWarning>,
}

/// Vista previa de la firma visible.
pub struct Preview {
    request: RequestId,
    /// Se está abriendo el documento (hilo de trabajo).
    opening: bool,
    /// Documento abierto (`None` mientras se abre).
    pub document: Option<Shared<PreviewDocument>>,
    /// Página visible (desde 0).
    pub page: usize,
    render_request: Option<(RequestId, usize, u32)>,
    image: Option<(usize, u32, Shared<PageImage>)>,
    /// Textura de la página dibujada: página y ancho en píxeles con el que se dibujó.
    pub texture: Option<(usize, u32, TextureHandle)>,
}

impl Preview {
    /// Se está abriendo el documento o dibujando la página visible.
    pub fn loading(&self) -> bool {
        self.document.is_none() || self.texture.as_ref().is_none_or(|(p, _, _)| *p != self.page)
    }
}

/// Importación en curso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportStep {
    PickFile,
    Install,
}

/// Operaciones de varios pasos.
pub struct Flows {
    platform: Arc<dyn Platform>,
    bridge: Arc<Bridge>,
    prefs: Prefs,
    history: SignsHistory,
    cache: StickyKeyCache,
    sign: Option<LocalSign>,
    preview: Option<Preview>,
    import: Option<(ImportStep, RequestId)>,
}

impl Flows {
    pub fn new(platform: Arc<dyn Platform>, bridge: Arc<Bridge>, prefs: Prefs, history: SignsHistory) -> Flows {
        Flows {
            platform,
            bridge,
            prefs,
            history,
            cache: StickyKeyCache::new(),
            sign: None,
            preview: None,
            import: None,
        }
    }

    /// Caché de certificado (§4.7) del proceso, la de la firma web: la firma local la vacía.
    pub fn cache(&self) -> &StickyKeyCache {
        &self.cache
    }

    /// Vista previa abierta.
    pub fn preview(&self) -> Option<&Preview> {
        self.preview.as_ref()
    }

    /// Hay una firma local en curso.
    pub fn signing(&self) -> bool {
        self.sign.is_some()
    }

    /// `true` mientras un hilo de trabajo de una operación no ha terminado.
    pub fn is_busy(&self) -> bool {
        let sign = self
            .sign
            .as_ref()
            .is_some_and(|s| matches!(s.step, Step::LoadCertificate | Step::Signing));
        let preview = self
            .preview
            .as_ref()
            .is_some_and(|p| p.opening || p.render_request.is_some());
        sign || preview
    }

    /// Ejecuta lo que pide la interfaz.
    pub fn apply(&mut self, action: FlowAction) -> Vec<Effect> {
        match action {
            FlowAction::StartSign => self.start_sign(),
            FlowAction::StartImport => self.start_import(),
            FlowAction::Cancel => self.cancel(),
            FlowAction::CertType(CertType::Certificate) => self.choose_keychain(),
            FlowAction::CertType(CertType::Dnie) => {
                // El DNIe por NFC llega en una fase posterior (crate afirma-dnie): de momento se
                // dice y se vuelve a la elección de almacén.
                info!("Firma local: DNIe elegido (todavía no disponible)");
                vec![Effect::Dialog(Dialog::Prompt(Box::new(Prompt {
                    id: "dnie_unavailable",
                    tone: Tone::Brand,
                    glyph: icons::IDENTIFICATION_CARD,
                    title: tr("dnie").into(),
                    body: tr("dnie_not_available").into(),
                    primary: (k!("understood"), Action::Flow(FlowAction::ChooseStore)),
                    secondary: None,
                    back: Some(Action::Flow(FlowAction::ChooseStore)),
                })))]
            }
            FlowAction::ChooseStore => self.store_choice(),
            FlowAction::WarningContinue => self.next_warning(),
            FlowAction::WarningCancel => {
                info!("Firma local: aviso del certificado cancelado; se vuelve a elegir");
                if let Some(sign) = &mut self.sign {
                    sign.warnings.clear();
                    sign.key = None;
                }
                self.store_choice()
            }
            FlowAction::PdfPassword(password) => self.pdf_password(password),
            FlowAction::PreviewPage(page) => {
                if let Some(preview) = &mut self.preview
                    && let Some(doc) = &preview.document
                    && page < doc.page_count()
                    && page != preview.page
                {
                    preview.page = page;
                    info!("Vista previa: página {} de {}", page + 1, doc.page_count());
                }
                Vec::new()
            }
            FlowAction::PreviewRender { page, width } => {
                self.render_page(page, width);
                Vec::new()
            }
            FlowAction::PreviewContinue { selection, view } => self.preview_continue(selection, view),
            FlowAction::PreviewInvisible => {
                info!("Firma visible: sin área; la firma será invisible");
                self.leave_preview(None)
            }
        }
    }

    /// Atiende un evento si es de una operación en curso; si no, lo devuelve.
    pub fn handle_event(&mut self, event: PlatformEvent) -> Result<Vec<Effect>, Box<PlatformEvent>> {
        match event {
            PlatformEvent::DocumentOpened {
                request, name, data, ..
            } if self.sign_waits(request, Step::PickFile) => {
                let name = name.unwrap_or_else(|| tr("default_saved_filename").to_string());
                Ok(self.document_opened(name, data))
            }
            PlatformEvent::DocumentOpened { request, data, .. } if self.import_waits(request, ImportStep::PickFile) => {
                Ok(self.install(data))
            }
            PlatformEvent::CertificateChosen { request, alias } if self.sign_waits(request, Step::PickCertificate) => {
                Ok(self.certificate_chosen(alias))
            }
            PlatformEvent::CertificateLoaded { request, alias, chain }
                if self.sign_waits(request, Step::LoadCertificate) =>
            {
                Ok(self.certificate_loaded(&alias, chain.map_err(|e| e.0)))
            }
            PlatformEvent::SignFinished { request, result } if self.sign_waits(request, Step::Signing) => {
                Ok(self.sign_finished(result))
            }
            PlatformEvent::DocumentSaved { request, uri, name } if self.sign_waits(request, Step::Saving) => {
                Ok(self.saved(&uri, name))
            }
            PlatformEvent::PreviewOpened { request, result }
                if self.preview.as_ref().is_some_and(|p| p.request == request) =>
            {
                Ok(self.preview_opened(result))
            }
            PlatformEvent::PageRendered { request, page, image }
                if self
                    .preview
                    .as_ref()
                    .is_some_and(|p| p.render_request.is_some_and(|(r, _, _)| r == request)) =>
            {
                self.page_rendered(page, image);
                Ok(Vec::new())
            }
            PlatformEvent::CertificateInstalled { request } if self.import_waits(request, ImportStep::Install) => {
                self.import = None;
                info!("Certificado instalado en KeyChain (petición {request})");
                Ok(vec![Effect::Dialog(Dialog::message(
                    Tone::Success,
                    icons::CHECK_CIRCLE,
                    tr("added_cert_title"),
                    tr("added_cert_message"),
                ))])
            }
            PlatformEvent::RequestFailed {
                request,
                cancelled,
                message,
            } if self.sign.as_ref().is_some_and(|s| s.request == request) => {
                Ok(self.sign_request_failed(cancelled, message))
            }
            PlatformEvent::RequestFailed {
                request,
                cancelled,
                message,
            } if self.import.is_some_and(|(_, r)| r == request) => Ok(self.import_failed(cancelled, message)),
            other => Err(Box::new(other)),
        }
    }

    fn sign_waits(&self, request: RequestId, step: Step) -> bool {
        self.sign
            .as_ref()
            .is_some_and(|s| s.request == request && s.step == step)
    }

    fn import_waits(&self, request: RequestId, step: ImportStep) -> bool {
        self.import == Some((step, request))
    }

    /// Sube a una textura la última página dibujada (hilo de la interfaz).
    pub fn upload_textures(&mut self, ctx: &egui::Context) {
        let Some(preview) = &mut self.preview else { return };
        let Some((page, width, image)) = preview.image.take() else {
            return;
        };
        let color =
            egui::ColorImage::from_rgba_unmultiplied([image.width as usize, image.height as usize], &image.rgba);
        let texture = ctx.load_texture("vista-previa", color, egui::TextureOptions::LINEAR);
        preview.texture = Some((page, width, texture));
    }

    // ------------------------------------------------------------------------------------
    // Firma local

    fn start_sign(&mut self) -> Vec<Effect> {
        if self.sign.is_some() {
            warn!("Ya hay una firma local en curso");
            return Vec::new();
        }
        let request = self.bridge.next_request_id();
        match self.platform.open_document(request, &["*/*"]) {
            Ok(()) => {
                info!("Selector de documentos abierto (petición {request})");
                self.sign = Some(LocalSign {
                    step: Step::PickFile,
                    request,
                    name: String::new(),
                    data: Arc::new(Vec::new()),
                    format: LocalFormat::Cades,
                    params: ExtraParams::new(),
                    key: None,
                    pseudonym: false,
                    warnings: VecDeque::new(),
                });
                Vec::new()
            }
            Err(e) => {
                warn!("No se pudo abrir el selector de documentos: {e}");
                error_effects(errors::shared(web::AA_LOADING_LOCAL_FILE))
            }
        }
    }

    fn document_opened(&mut self, name: String, data: Vec<u8>) -> Vec<Effect> {
        let visible = self.prefs.get().pades_visible_signature;
        let Some(sign) = &mut self.sign else { return Vec::new() };
        sign.format = LocalFormat::for_file(&name);
        info!(
            "Firma local: documento de {} bytes, formato {}",
            data.len(),
            sign.format.name()
        );
        sign.name = name;
        sign.data = Arc::new(data);
        sign.params = local_sign::base_params();
        if sign.format == LocalFormat::Pades && visible {
            sign.step = Step::Preview;
            let data = sign.data.clone();
            self.open_preview(data, None);
            return vec![Effect::OpenPreview];
        }
        self.store_choice()
    }

    /// Elección de almacén (§4.1): con el DNIe habilitado, «¿Con qué firmarás?»; si no,
    /// directamente KeyChain.
    fn store_choice(&mut self) -> Vec<Effect> {
        let Some(sign) = &mut self.sign else { return Vec::new() };
        if self.prefs.get().use_nfc {
            sign.step = Step::StoreChoice;
            info!("Firma local: elección de almacén");
            vec![Effect::Dialog(Dialog::ChooseCertType { auth: false })]
        } else {
            self.choose_keychain()
        }
    }

    fn choose_keychain(&mut self) -> Vec<Effect> {
        let Some(sign) = &mut self.sign else { return Vec::new() };
        let request = self.bridge.next_request_id();
        match self.platform.choose_certificate(request) {
            Ok(()) => {
                info!("Selector de certificados abierto (petición {request})");
                sign.step = Step::PickCertificate;
                sign.request = request;
                vec![Effect::CloseDialog]
            }
            Err(e) => {
                warn!("No se pudo abrir el selector de certificados: {e}");
                self.fail(errors::shared(web::AA_SOFTWARE_GENERAL))
            }
        }
    }

    fn certificate_chosen(&mut self, alias: Option<String>) -> Vec<Effect> {
        let Some(sign) = &mut self.sign else { return Vec::new() };
        let Some(alias) = alias else {
            info!(
                "Selector de certificados cerrado sin elegir (petición {})",
                sign.request
            );
            // Con el DNIe habilitado se vuelve a la elección de almacén; si no, se cancela.
            return if self.prefs.get().use_nfc {
                self.store_choice()
            } else {
                self.cancel()
            };
        };
        info!("Certificado elegido (petición {})", sign.request);
        let request = self.bridge.next_request_id();
        sign.step = Step::LoadCertificate;
        sign.request = request;
        let (platform, bridge) = (self.platform.clone(), self.bridge.clone());
        spawn_worker("keychain", move || {
            let chain = platform.certificate_chain(&alias);
            bridge.post(PlatformEvent::CertificateLoaded { request, alias, chain });
        });
        vec![Effect::Dialog(Dialog::Progress {
            text: k!("loading_cert"),
        })]
    }

    fn certificate_loaded(&mut self, alias: &str, chain: Result<Vec<Vec<u8>>, String>) -> Vec<Effect> {
        let key = chain.and_then(|chain| KeyChainKey::with_chain(self.platform.clone(), alias, chain).map_err(|e| e.0));
        let key = match key {
            Ok(key) => Arc::new(key),
            Err(e) => {
                warn!("No se pudo leer el certificado elegido: {e}");
                return self.fail(errors::shared(web::AA_SOFTWARE_GENERAL));
            }
        };
        // La firma local no usa la caché de certificado, pero la vacía (§4.7).
        self.cache.clear();
        let Some(sign) = &mut self.sign else { return Vec::new() };
        sign.pseudonym = is_pseudonym_certificate(key.certificate());
        sign.warnings = certificate_warnings(key.certificate(), chrono::Utc::now()).into();
        info!(
            "Cadena del certificado leída: {} certificados, avisos: {:?}",
            key.certificate_chain().len(),
            sign.warnings.iter().map(|w| warning_id(*w)).collect::<Vec<_>>()
        );
        sign.key = Some(key);
        self.next_warning()
    }

    /// Siguiente aviso sobre el certificado (§4.6) o, si no quedan, la firma.
    fn next_warning(&mut self) -> Vec<Effect> {
        let Some(sign) = &mut self.sign else { return Vec::new() };
        match sign.warnings.pop_front() {
            Some(warning) => {
                sign.step = Step::Warning;
                info!("Aviso sobre el certificado: {}", warning_id(warning));
                let (title, body) = warning_texts(warning);
                vec![Effect::Dialog(Dialog::Prompt(Box::new(Prompt {
                    id: warning_id(warning),
                    tone: Tone::Info,
                    glyph: icons::INFO,
                    title: tr(title).into(),
                    body: tr(body).into(),
                    primary: (k!("drag_on"), Action::Flow(FlowAction::WarningContinue)),
                    secondary: Some((k!("cancel_underline"), Action::Flow(FlowAction::WarningCancel))),
                    back: Some(Action::Flow(FlowAction::Cancel)),
                })))]
            }
            None => self.start_signing(),
        }
    }

    fn start_signing(&mut self) -> Vec<Effect> {
        let Some(sign) = &mut self.sign else { return Vec::new() };
        let Some(key) = sign.key.clone() else {
            return self.store_choice();
        };
        if sign.pseudonym {
            local_sign::use_pseudonym_template(&mut sign.params);
        }
        let request = self.bridge.next_request_id();
        sign.step = Step::Signing;
        sign.request = request;
        info!(
            "Firmando en {} con {} (petición {request})",
            sign.format.name(),
            local_sign::ALGORITHM
        );
        let (format, data, params, bridge) = (sign.format, sign.data.clone(), sign.params.clone(), self.bridge.clone());
        spawn_worker("firma", move || {
            let result = local_sign::sign(format, &data, key.as_ref(), &params);
            bridge.post(PlatformEvent::SignFinished { request, result });
        });
        vec![Effect::Dialog(Dialog::Progress { text: k!("signing") })]
    }

    fn sign_finished(&mut self, result: Result<Vec<u8>, SignFailure>) -> Vec<Effect> {
        let Some(sign) = &mut self.sign else { return Vec::new() };
        match result {
            Ok(signature) => {
                info!("Firma generada: {} bytes", signature.len());
                let signed_name = sign.format.signed_name(&sign.name);
                let mime = local_sign::mime_type(&signed_name);
                let request = self.bridge.next_request_id();
                self.bridge.stash_write(request, Arc::new(signature));
                match self.platform.create_document(request, &mime, &signed_name) {
                    Ok(()) => {
                        info!("Diálogo de guardado abierto: «{signed_name}» ({mime}, petición {request})");
                        sign.step = Step::Saving;
                        sign.request = request;
                        vec![Effect::CloseDialog]
                    }
                    Err(e) => {
                        self.bridge.take_write(request);
                        warn!("No se pudo abrir el diálogo de guardado: {e}");
                        self.fail(errors::shared(web::AA_SAVING_DATA_DISK))
                    }
                }
            }
            Err(failure @ (SignFailure::PasswordNeeded | SignFailure::BadPassword)) => {
                info!("El PDF necesita contraseña ({failure:?})");
                sign.step = Step::Password;
                vec![Effect::Dialog(Dialog::PdfPassword {
                    password: String::new(),
                    revealed: false,
                    error: (failure == SignFailure::BadPassword).then_some(k!("dialog_pdf_bad_password")),
                })]
            }
            Err(SignFailure::Failed(message)) => {
                error!("Error durante la firma: {message}");
                self.fail(errors::shared(web::AA_ERROR_SIGNING))
            }
        }
    }

    fn pdf_password(&mut self, password: String) -> Vec<Effect> {
        if password.is_empty() {
            return vec![Effect::Dialog(Dialog::PdfPassword {
                password,
                revealed: false,
                error: Some(k!("error_empty_pdf_password")),
            })];
        }
        let Some(sign) = &mut self.sign else { return Vec::new() };
        match sign.step {
            Step::Password => {
                local_sign::set_pdf_password(&mut sign.params, &password);
                self.start_signing()
            }
            Step::Preview => {
                let data = sign.data.clone();
                self.open_preview(data, Some(password));
                vec![Effect::Dialog(Dialog::Progress {
                    text: k!("dialog_msg_loading_data"),
                })]
            }
            _ => Vec::new(),
        }
    }

    fn saved(&mut self, uri: &str, name: Option<String>) -> Vec<Effect> {
        let Some(sign) = self.sign.take() else {
            return Vec::new();
        };
        info!(
            "Firma guardada: «{}» ({uri})",
            name.as_deref().unwrap_or(&sign.format.signed_name(&sign.name))
        );
        // El original lo registraba antes de guardar, aunque se cancelase (§10 n.º 21).
        let record = SignRecord::now(RecordKind::Local, RecordOperation::Sign, Some(&sign.name), None);
        match self.history.append(&record) {
            Ok(()) => info!("Histórico de firmas: firma local registrada"),
            Err(e) => warn!("{}: {e}", errors::shared(web::AA_CANT_SAVE_SIGN_RECORD).admin_message()),
        }
        vec![Effect::Dialog(Dialog::message(
            Tone::Success,
            icons::CHECK_CIRCLE,
            tr("signed_file_title"),
            tr("signed_file_message"),
        ))]
    }

    fn sign_request_failed(&mut self, cancelled: bool, message: Option<String>) -> Vec<Effect> {
        let Some(sign) = &self.sign else { return Vec::new() };
        let what = match sign.step {
            Step::PickFile => "Selector de documentos",
            Step::Saving => "Diálogo de guardado",
            _ => "Petición",
        };
        if cancelled {
            info!("{what} cancelado (petición {})", sign.request);
            if sign.step == Step::Saving {
                self.bridge.take_write(sign.request);
                info!("Firma no guardada: no se registra en el histórico");
            }
            return self.cancel();
        }
        let message = message.unwrap_or_default();
        warn!("{what}: error en la petición {}: {message}", sign.request);
        let category = match sign.step {
            Step::PickFile if message == DOCUMENT_TOO_LARGE => errors::shared(web::AA_OUT_OF_MEMORY),
            Step::PickFile => errors::shared(web::AA_LOADING_LOCAL_FILE),
            Step::Saving => errors::shared(web::AA_SAVING_DATA_DISK),
            _ => errors::shared(web::AA_SOFTWARE_GENERAL),
        };
        if sign.step == Step::Saving {
            self.bridge.take_write(sign.request);
        }
        self.fail(category)
    }

    /// Termina la operación en curso sin mensaje.
    fn cancel(&mut self) -> Vec<Effect> {
        if self.sign.take().is_some() {
            info!("Firma local cancelada");
        }
        let mut effects = vec![Effect::CloseDialog];
        if self.preview.take().is_some() {
            effects.push(Effect::ClosePreview);
        }
        effects
    }

    /// Termina la operación en curso con un error del catálogo.
    fn fail(&mut self, category: ErrorCategory) -> Vec<Effect> {
        error!("Firma local: {}", category.admin_message());
        self.sign = None;
        let mut effects = Vec::new();
        if self.preview.take().is_some() {
            effects.push(Effect::ClosePreview);
        }
        effects.extend(error_effects(category));
        effects
    }

    // ------------------------------------------------------------------------------------
    // Vista previa de la firma visible

    fn open_preview(&mut self, data: Arc<Vec<u8>>, password: Option<String>) {
        let request = self.bridge.next_request_id();
        match &mut self.preview {
            Some(preview) => {
                preview.request = request;
                preview.opening = true;
            }
            None => {
                self.preview = Some(Preview {
                    request,
                    opening: true,
                    document: None,
                    page: 0,
                    render_request: None,
                    image: None,
                    texture: None,
                })
            }
        }
        let bridge = self.bridge.clone();
        spawn_worker("vista-previa", move || {
            let result = PreviewDocument::open(&data, password.as_deref()).map(Shared::new);
            bridge.post(PlatformEvent::PreviewOpened { request, result });
        });
    }

    fn preview_opened(&mut self, result: Result<Shared<PreviewDocument>, PreviewFailure>) -> Vec<Effect> {
        if let Some(preview) = &mut self.preview {
            preview.opening = false;
        }
        match result {
            Ok(document) => {
                info!("Vista previa abierta: {} páginas", document.page_count());
                if let Some(preview) = &mut self.preview {
                    preview.page = 0;
                    preview.document = Some(document);
                }
                vec![Effect::CloseDialog]
            }
            Err(failure @ (PreviewFailure::NeedsPassword | PreviewFailure::BadPassword)) => {
                info!("Vista previa: el PDF necesita contraseña ({failure:?})");
                vec![Effect::Dialog(Dialog::PdfPassword {
                    password: String::new(),
                    revealed: false,
                    error: (failure == PreviewFailure::BadPassword).then_some(k!("dialog_pdf_bad_password")),
                })]
            }
            Err(PreviewFailure::Invalid(message)) => {
                warn!("Vista previa: no se pudo abrir el PDF: {message}");
                self.fail(errors::shared(web::AA_LOADING_LOCAL_FILE))
            }
        }
    }

    fn render_page(&mut self, page: usize, width: u32) {
        let Some(preview) = &mut self.preview else { return };
        let Some(document) = preview.document.clone() else {
            return;
        };
        let wanted = (page, width);
        let pending = preview.render_request.map(|(_, p, w)| (p, w));
        let done = preview.texture.as_ref().map(|(p, w, _)| (*p, *w));
        let ready = preview.image.as_ref().map(|(p, w, _)| (*p, *w));
        if [pending, done, ready].contains(&Some(wanted)) || page >= document.page_count() {
            return;
        }
        let request = self.bridge.next_request_id();
        preview.render_request = Some((request, page, width));
        let bridge = self.bridge.clone();
        spawn_worker("pagina", move || {
            let image = document.render(page, width).map(Shared::new);
            bridge.post(PlatformEvent::PageRendered { request, page, image });
        });
    }

    fn page_rendered(&mut self, page: usize, image: Option<Shared<PageImage>>) {
        let Some(preview) = &mut self.preview else { return };
        let width = preview.render_request.take().map_or(0, |(_, _, w)| w);
        match image {
            Some(image) => {
                info!(
                    "Vista previa: página {} dibujada ({}x{} px)",
                    page + 1,
                    image.width,
                    image.height
                );
                preview.image = Some((page, width, image));
            }
            None => warn!("Vista previa: no se pudo dibujar la página {}", page + 1),
        }
    }

    fn preview_continue(&mut self, selection: Option<ViewSelection>, view: (f32, f32)) -> Vec<Effect> {
        let Some(preview) = &self.preview else {
            return Vec::new();
        };
        let Some(document) = &preview.document else {
            return Vec::new();
        };
        let page = preview.page;
        let (id, title, body) = match selection {
            None => (
                "not_selected_area",
                k!("not_selected_area"),
                k!("not_selected_area_desc"),
            ),
            Some(selection) => match check_area(selection, view, document.page_size(page), page + 1) {
                AreaCheck::Ok(area) => {
                    info!(
                        "Firma visible: página {}, área ({}, {}) - ({}, {})",
                        area.page, area.llx, area.lly, area.urx, area.ury
                    );
                    return self.leave_preview(Some(area));
                }
                AreaCheck::TooSmall => ("small_area", k!("visible_sign_small"), k!("small_area_warning")),
            },
        };
        info!("Firma visible: {id}");
        // Firma visible opcional (firma local): «Continuar» firma sin área (§10 n.º 25,
        // «replicar») y «Volver a seleccionar un área» cierra el diálogo.
        vec![Effect::Dialog(Dialog::Prompt(Box::new(Prompt {
            id,
            tone: Tone::Info,
            glyph: icons::INFO,
            title: tr(title).into(),
            body: tr(body).into(),
            primary: (k!("drag_on"), Action::Flow(FlowAction::PreviewInvisible)),
            secondary: Some((k!("reselect_area"), Action::CloseDialog)),
            back: None,
        })))]
    }

    /// Sale de la vista previa con el área elegida (o sin ella) y sigue con el almacén.
    fn leave_preview(&mut self, area: Option<crate::local_sign::VisibleArea>) -> Vec<Effect> {
        let obfuscate = self.prefs.get().pades_obfuscate_cert_info;
        let preview = self.preview.take();
        let Some(sign) = &mut self.sign else {
            return vec![Effect::CloseDialog, Effect::ClosePreview];
        };
        if let Some(area) = area {
            local_sign::add_visible_params(&mut sign.params, &area, obfuscate);
        }
        // La contraseña de la vista previa se usa también en la firma invisible (el original
        // la perdía y la volvía a pedir, §10 n.º 26).
        if let Some(password) = preview
            .as_ref()
            .and_then(|p| p.document.as_ref())
            .and_then(|d| d.password())
        {
            local_sign::set_pdf_password(&mut sign.params, password);
        }
        let mut effects = vec![Effect::CloseDialog, Effect::ClosePreview];
        effects.extend(self.store_choice());
        effects
    }

    // ------------------------------------------------------------------------------------
    // Importación de certificados

    fn start_import(&mut self) -> Vec<Effect> {
        let request = self.bridge.next_request_id();
        match self.platform.open_document(request, &[PKCS12_MIME]) {
            Ok(()) => {
                info!("Selector de documentos abierto (petición {request})");
                self.import = Some((ImportStep::PickFile, request));
                vec![Effect::CloseDialog]
            }
            Err(e) => {
                warn!("No se pudo abrir el selector de documentos: {e}");
                vec![import_error_dialog()]
            }
        }
    }

    fn install(&mut self, data: Vec<u8>) -> Vec<Effect> {
        let request = self.bridge.next_request_id();
        info!("Almacén para importar: {} bytes", data.len());
        match self.platform.install_certificate(request, &data) {
            Ok(()) => {
                info!("Instalador de certificados abierto (petición {request})");
                self.import = Some((ImportStep::Install, request));
                Vec::new()
            }
            Err(e) => {
                warn!("No se pudo abrir el instalador de certificados: {e}");
                self.import = None;
                vec![import_error_dialog()]
            }
        }
    }

    fn import_failed(&mut self, cancelled: bool, message: Option<String>) -> Vec<Effect> {
        let Some((step, request)) = self.import.take() else {
            return Vec::new();
        };
        let what = match step {
            ImportStep::PickFile => "Selector de documentos",
            ImportStep::Install => "Instalación del certificado",
        };
        if cancelled {
            info!("{what} cancelado (petición {request})");
            return Vec::new();
        }
        warn!(
            "{what}: {} ({})",
            errors::LOAD_CERT_TO_IMPORT.admin_message(),
            message.unwrap_or_default()
        );
        vec![import_error_dialog()]
    }
}

/// «No hemos podido añadir tu certificado» con «Volver a intentarlo» (§4.8).
fn import_error_dialog() -> Effect {
    Effect::Dialog(Dialog::Prompt(Box::new(Prompt {
        id: "cant_add_cert",
        tone: Tone::Danger,
        glyph: icons::WARNING_CIRCLE,
        title: tr("cant_add_cert_title").into(),
        body: errors::LOAD_CERT_TO_IMPORT.user_message(),
        primary: (k!("try_again"), Action::Flow(FlowAction::StartImport)),
        secondary: Some((k!("cancel_underline"), Action::CloseDialog)),
        back: None,
    })))
}

/// «¡Algo salió mal!» con el código del error (§3.9).
fn error_effects(category: ErrorCategory) -> Vec<Effect> {
    vec![Effect::Dialog(Dialog::message(
        Tone::Danger,
        icons::WARNING_CIRCLE,
        tr("error_ocurred"),
        category.user_message(),
    ))]
}

fn spawn_worker(name: &str, job: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(format!("autofirma-{name}")).spawn(job) {
        error!("No se pudo crear el hilo de trabajo {name}: {e}");
    }
}
