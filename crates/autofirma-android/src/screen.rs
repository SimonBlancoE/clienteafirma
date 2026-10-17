//! Pantalla principal de la aplicación Android.
//!
//! De momento es la pantalla de la base técnica: muestra la versión, abre el selector de
//! documentos del sistema (SAF) y analiza el documento con `afirma-signers`, abre el
//! selector de certificados de KeyChain y lee la cadena del alias elegido, y muestra la
//! última petición `afirma://` recibida por un intent. Así se prueban las llamadas de Rust a
//! Java y de Java a Rust, y los hilos de trabajo.
//!
//! El estado no depende de Android: las pruebas del anfitrión usan una [`Platform`] falsa.

use std::collections::HashMap;
use std::sync::Arc;

use afirma_core::cert::CertInfo;
use afirma_protocol::request::{Dispatch, OperationKind, dispatch};
use egui::{Button, Color32, FontFamily, FontId, RichText, ScrollArea, TextStyle, Ui, UiBuilder, vec2};
use tracing::{error, info, warn};

use crate::bridge::{Bridge, Platform, PlatformError, PlatformEvent, RequestId};
use crate::document::{self, DocumentSummary};

/// Color principal de AutoFirma (el de la aplicación de escritorio).
const PRIMARY: Color32 = Color32::from_rgb(0xC2, 0x41, 0x0C);
const BACKGROUND: Color32 = Color32::from_rgb(0xF5, 0xF6, 0xF8);
const MUTED: Color32 = Color32::from_rgb(0x5B, 0x63, 0x70);
const DANGER: Color32 = Color32::from_rgb(0xB4, 0x23, 0x18);

/// Logotipo (el icono de la aplicación de escritorio).
const LOGO_PNG: &[u8] = include_bytes!("../../../packaging/icons/autofirma-256.png");

/// Qué se espera para cada petición en curso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    OpenDocument,
    AnalyzeDocument,
    ChooseCertificate,
    LoadCertificate,
}

/// Documento abierto.
#[derive(Debug, Clone, PartialEq)]
pub enum DocumentState {
    Analyzing { name: String, size: usize },
    Ready(DocumentSummary),
}

/// Certificado elegido en KeyChain.
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateState {
    Loading { alias: String },
    Ready(CertificateSummary),
    Failed { alias: String, message: String },
}

/// Datos del certificado del alias elegido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    pub alias: String,
    pub subject: String,
    pub issuer: String,
    /// Fin de la validez (`AAAA-MM-DD`).
    pub not_after: String,
    pub chain_len: usize,
}

/// Última petición web (`afirma://`) recibida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRequest {
    pub operation: String,
    pub supported: bool,
}

/// Aviso de la última operación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Info(String),
    Error(String),
}

/// Botones cuya posición se registra (la prueba en el emulador los pulsa con `adb`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    OpenDocument,
    ChooseCertificate,
}

impl Target {
    fn label(self) -> &'static str {
        match self {
            Target::OpenDocument => "Abrir documento",
            Target::ChooseCertificate => "Elegir certificado",
        }
    }
}

/// Pantalla principal.
pub struct MainScreen {
    platform: Arc<dyn Platform>,
    bridge: Arc<Bridge>,
    pending: HashMap<RequestId, Pending>,
    pub document: Option<DocumentState>,
    pub certificate: Option<CertificateState>,
    pub web_request: Option<WebRequest>,
    pub notice: Option<Notice>,
    logo: Option<egui::TextureHandle>,
    style_applied: bool,
    frames: u64,
    targets: Vec<(Target, egui::Rect)>,
    logged_targets: Vec<(Target, [i32; 2])>,
}

impl MainScreen {
    pub fn new(platform: Arc<dyn Platform>, bridge: Arc<Bridge>) -> Self {
        MainScreen {
            platform,
            bridge,
            pending: HashMap::new(),
            document: None,
            certificate: None,
            web_request: None,
            notice: None,
            logo: None,
            style_applied: false,
            frames: 0,
            targets: Vec::new(),
            logged_targets: Vec::new(),
        }
    }

    /// Atiende los eventos pendientes del puente.
    pub fn pump(&mut self) {
        for event in self.bridge.drain() {
            self.handle_event(event);
        }
    }

    /// `true` mientras haya alguna petición o tarea en curso.
    pub fn is_busy(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Rectángulo (en puntos) del botón en la última pasada.
    pub fn target_rect(&self, target: Target) -> Option<egui::Rect> {
        self.targets.iter().find(|(t, _)| *t == target).map(|(_, r)| *r)
    }

    /// Abre el selector de documentos del sistema.
    pub fn open_document(&mut self) {
        let request = self.bridge.next_request_id();
        match self.platform.open_document(request) {
            Ok(()) => {
                info!("Selector de documentos abierto (petición {request})");
                self.pending.insert(request, Pending::OpenDocument);
                self.notice = None;
            }
            Err(e) => self.request_error("No se pudo abrir el selector de documentos", &e),
        }
    }

    /// Abre el selector de certificados de KeyChain.
    pub fn choose_certificate(&mut self) {
        let request = self.bridge.next_request_id();
        match self.platform.choose_certificate(request) {
            Ok(()) => {
                info!("Selector de certificados abierto (petición {request})");
                self.pending.insert(request, Pending::ChooseCertificate);
                self.notice = None;
            }
            Err(e) => self.request_error("No se pudo abrir el selector de certificados", &e),
        }
    }

    fn request_error(&mut self, what: &str, e: &PlatformError) {
        warn!("{what}: {e}");
        self.notice = Some(Notice::Error(format!("{what}: {e}")));
    }

    /// Atiende un evento de Java o de un hilo de trabajo.
    pub fn handle_event(&mut self, event: PlatformEvent) {
        match event {
            PlatformEvent::ViewIntent { uri } => {
                let request = describe_web_request(&uri);
                info!("Petición web recibida: {}", request.operation);
                self.web_request = Some(request);
            }
            PlatformEvent::DocumentOpened {
                request, name, data, ..
            } => {
                if !self.take_pending(request, Pending::OpenDocument) {
                    return;
                }
                let name = name.unwrap_or_else(|| "documento".to_string());
                info!("Documento recibido: {} bytes (petición {request})", data.len());
                self.document = Some(DocumentState::Analyzing {
                    name: name.clone(),
                    size: data.len(),
                });
                self.pending.insert(request, Pending::AnalyzeDocument);
                let bridge = self.bridge.clone();
                spawn_worker("analisis", move || {
                    let summary = document::analyze(&name, &data);
                    bridge.post(PlatformEvent::DocumentAnalyzed { request, summary });
                });
            }
            PlatformEvent::DocumentAnalyzed { request, summary } => {
                if self.take_pending(request, Pending::AnalyzeDocument) {
                    info!(
                        "Documento analizado: {}, formato propuesto {}",
                        summary.kind, summary.format
                    );
                    self.document = Some(DocumentState::Ready(summary));
                }
            }
            PlatformEvent::CertificateChosen { request, alias } => {
                if !self.take_pending(request, Pending::ChooseCertificate) {
                    return;
                }
                let Some(alias) = alias else {
                    info!("Selector de certificados cerrado sin elegir (petición {request})");
                    self.notice = Some(Notice::Info("No se ha elegido ningún certificado.".to_string()));
                    return;
                };
                info!("Certificado elegido (petición {request})");
                self.certificate = Some(CertificateState::Loading { alias: alias.clone() });
                self.pending.insert(request, Pending::LoadCertificate);
                let (platform, bridge) = (self.platform.clone(), self.bridge.clone());
                spawn_worker("keychain", move || {
                    let chain = platform.certificate_chain(&alias);
                    bridge.post(PlatformEvent::CertificateLoaded { request, alias, chain });
                });
            }
            PlatformEvent::CertificateLoaded { request, alias, chain } => {
                if !self.take_pending(request, Pending::LoadCertificate) {
                    return;
                }
                self.certificate = Some(match chain.map_err(|e| e.0).and_then(|c| summarize_chain(&alias, &c)) {
                    Ok(summary) => {
                        info!("Cadena del certificado leída: {} certificados", summary.chain_len);
                        CertificateState::Ready(summary)
                    }
                    Err(message) => {
                        warn!("No se pudo leer el certificado: {message}");
                        CertificateState::Failed { alias, message }
                    }
                });
            }
            PlatformEvent::NfcTag { request, .. } => {
                info!("Tarjeta NFC detectada (petición {request}); esta pantalla no la usa");
            }
            PlatformEvent::RequestFailed {
                request,
                cancelled,
                message,
            } => {
                let what = match self.pending.remove(&request) {
                    Some(Pending::OpenDocument) => "Selector de documentos",
                    Some(Pending::ChooseCertificate) => "Selector de certificados",
                    _ => "Petición",
                };
                if cancelled {
                    info!("{what} cancelado (petición {request})");
                    self.notice = Some(Notice::Info("Operación cancelada.".to_string()));
                } else {
                    let message = message.unwrap_or_else(|| "error desconocido".to_string());
                    warn!("{what}: error en la petición {request}: {message}");
                    self.notice = Some(Notice::Error(format!("{what}: {message}")));
                }
            }
        }
    }

    /// Quita una petición pendiente si es del tipo esperado.
    fn take_pending(&mut self, request: RequestId, expected: Pending) -> bool {
        if self.pending.get(&request) == Some(&expected) {
            self.pending.remove(&request);
            true
        } else {
            warn!("Respuesta inesperada para la petición {request} (se esperaba {expected:?})");
            false
        }
    }

    /// Dibuja la pantalla.
    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if !self.style_applied {
            apply_style(&ctx);
            self.style_applied = true;
        }
        if self.logo.is_none() {
            self.logo = load_logo(&ctx);
        }
        ui.painter().rect_filled(ctx.viewport_rect(), 0.0, BACKGROUND);
        self.targets.clear();
        // La zona segura excluye las barras del sistema, los recortes y el teclado.
        let area = ctx.content_rect().shrink2(vec2(20.0, 16.0));
        ui.scope_builder(UiBuilder::new().max_rect(area), |ui| {
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| self.contents(ui));
        });
        self.after_frame(&ctx);
    }

    fn contents(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if let Some(logo) = &self.logo {
                ui.add(egui::Image::new(logo).fit_to_exact_size(vec2(64.0, 64.0)));
            }
            ui.vertical(|ui| {
                ui.label(RichText::new(crate::APP_NAME).heading().strong());
                ui.label(
                    RichText::new(format!(
                        "Versión {} · Android ({})",
                        crate::VERSION,
                        std::env::consts::ARCH
                    ))
                    .color(MUTED),
                );
            });
        });
        ui.add_space(4.0);
        ui.label(RichText::new("Firma electrónica de documentos y en trámites web.").color(MUTED));
        ui.add_space(12.0);

        let width = ui.available_width();
        let busy = self.is_busy();
        if self.action_button(ui, Target::OpenDocument, width, busy).clicked() {
            self.open_document();
        }
        if self.action_button(ui, Target::ChooseCertificate, width, busy).clicked() {
            self.choose_certificate();
        }
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Esperando…").color(MUTED));
            });
        }
        if let Some(notice) = &self.notice {
            let (text, color) = match notice {
                Notice::Info(t) => (t, MUTED),
                Notice::Error(t) => (t, DANGER),
            };
            ui.label(RichText::new(text).color(color));
        }

        if let Some(document) = &self.document {
            section(ui, "Documento", |ui| match document {
                DocumentState::Analyzing { name, size } => {
                    field(ui, "Nombre", name);
                    field(ui, "Tamaño", &document::human_size(*size));
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Analizando…");
                    });
                }
                DocumentState::Ready(d) => {
                    field(ui, "Nombre", &d.name);
                    field(ui, "Tamaño", &document::human_size(d.size));
                    field(ui, "Tipo", d.kind);
                    let operation = if d.already_signed { "cofirmar" } else { "firmar" };
                    field(ui, "Formato propuesto", &format!("{} ({operation})", d.format));
                    if d.alternatives.len() > 1 {
                        field(ui, "Otros formatos", &d.alternatives[1..].join(", "));
                    }
                }
            });
        }
        if let Some(certificate) = &self.certificate {
            section(ui, "Certificado", |ui| match certificate {
                CertificateState::Loading { alias } => {
                    field(ui, "Alias", alias);
                    ui.spinner();
                }
                CertificateState::Ready(c) => {
                    field(ui, "Alias", &c.alias);
                    field(ui, "Titular", &c.subject);
                    field(ui, "Emisor", &c.issuer);
                    field(ui, "Válido hasta", &c.not_after);
                    field(ui, "Cadena", &format!("{} certificados", c.chain_len));
                }
                CertificateState::Failed { alias, message } => {
                    field(ui, "Alias", alias);
                    ui.label(RichText::new(message).color(DANGER));
                }
            });
        }
        if let Some(request) = &self.web_request {
            section(ui, "Petición web", |ui| {
                let color = if request.supported { MUTED } else { DANGER };
                ui.label(RichText::new(&request.operation).color(color));
            });
        }
    }

    fn action_button(&mut self, ui: &mut Ui, target: Target, width: f32, busy: bool) -> egui::Response {
        let text = RichText::new(format!("{}…", target.label()))
            .color(Color32::WHITE)
            .strong();
        let response = ui.add_enabled(
            !busy,
            Button::new(text)
                .fill(PRIMARY)
                .min_size(vec2(width, 52.0))
                .corner_radius(10.0),
        );
        self.targets.push((target, response.rect));
        response
    }

    /// Registros para la prueba en el emulador: primer fotograma y posición de los botones
    /// en píxeles físicos (cuando cambia).
    fn after_frame(&mut self, ctx: &egui::Context) {
        self.frames += 1;
        let ppp = ctx.pixels_per_point();
        if self.frames == 1 {
            let size = ctx.viewport_rect().size() * ppp;
            info!(
                "Primer fotograma de la interfaz ({:.0}x{:.0} px, {ppp} px por punto)",
                size.x, size.y
            );
        }
        let positions: Vec<(Target, [i32; 2])> = self
            .targets
            .iter()
            .map(|(t, r)| {
                (
                    *t,
                    [(r.center().x * ppp).round() as i32, (r.center().y * ppp).round() as i32],
                )
            })
            .collect();
        if positions != self.logged_targets {
            for (target, [x, y]) in &positions {
                info!("Botón «{}» en x={x} y={y}", target.label());
            }
            self.logged_targets = positions;
        }
    }
}

fn spawn_worker(name: &str, job: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(format!("autofirma-{name}")).spawn(job) {
        error!("No se pudo crear el hilo de trabajo {name}: {e}");
    }
}

/// Describe una URL `afirma://` con el reparto del protocolo (`afirma-protocol`). En Android
/// AutoScript usa siempre el servidor intermedio y la app oficial solo atiende `sign`,
/// `cosign`, `countersign`, `selectcert`, `batch` y `save` (`docs/spec/09-android.md` §5).
pub fn describe_web_request(uri: &str) -> WebRequest {
    let (operation, supported) = match dispatch(uri) {
        Dispatch::Operation(kind @ (OperationKind::SignAndSave | OperationKind::Load)) => {
            (format!("Operación «{}» (no disponible en Android)", kind.name()), false)
        }
        Dispatch::Operation(kind) => (format!("Operación «{}»", kind.name()), true),
        Dispatch::WebSocket => ("Conexión por WebSocket (no disponible en Android)".to_string(), false),
        Dispatch::Service => ("Socket de servicio (no disponible en Android)".to_string(), false),
        Dispatch::UnsupportedScheme => ("Esquema no soportado".to_string(), false),
        Dispatch::UnsupportedOperation => ("Operación desconocida".to_string(), false),
    };
    WebRequest { operation, supported }
}

/// Resumen del certificado del firmante de una cadena DER.
pub fn summarize_chain(alias: &str, chain: &[Vec<u8>]) -> Result<CertificateSummary, String> {
    let leaf = chain.first().ok_or("el alias no tiene certificados")?;
    let info = CertInfo::parse(leaf).ok_or("el certificado no es válido")?;
    Ok(CertificateSummary {
        alias: alias.to_string(),
        subject: info.subject_cn,
        issuer: info.issuer_cn,
        not_after: info.not_after.format("%Y-%m-%d").to_string(),
        chain_len: chain.len(),
    })
}

fn section(ui: &mut Ui, title: &str, add_contents: impl FnOnce(&mut Ui)) {
    ui.add_space(12.0);
    egui::Frame::new()
        .fill(Color32::WHITE)
        .stroke(egui::Stroke::new(1.0, Color32::from_rgb(0xDD, 0xE1, 0xE6)))
        .corner_radius(10.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).strong().color(PRIMARY));
            add_contents(ui);
        });
}

fn field(ui: &mut Ui, name: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{name}:")).color(MUTED));
        ui.label(value);
    });
}

fn apply_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Light);
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::new(28.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(17.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(18.0, FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(15.0, FontFamily::Monospace)),
        ]
        .into();
        style.spacing.item_spacing = vec2(10.0, 10.0);
        style.spacing.button_padding = vec2(16.0, 12.0);
        style.spacing.interact_size.y = 44.0;
        style.visuals.panel_fill = BACKGROUND;
        style.visuals.override_text_color = Some(Color32::from_rgb(0x1F, 0x24, 0x2B));
    });
}

fn load_logo(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let image = match image::load_from_memory_with_format(LOGO_PNG, image::ImageFormat::Png) {
        Ok(image) => image.to_rgba8(),
        Err(e) => {
            warn!("No se pudo cargar el logotipo: {e}");
            return None;
        }
    };
    let size = [image.width() as usize, image.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
    Some(ctx.load_texture("logotipo", color, egui::TextureOptions::LINEAR))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::keychain::tests::{FakePlatform, test_certificate};

    fn screen() -> (MainScreen, Arc<FakePlatform>, Arc<Bridge>) {
        let platform = Arc::new(FakePlatform {
            chain: vec![test_certificate("Firmante de prueba"), test_certificate("CA de prueba")],
            ..Default::default()
        });
        let bridge = Arc::new(Bridge::new());
        (MainScreen::new(platform.clone(), bridge.clone()), platform, bridge)
    }

    /// Atiende eventos hasta que no quede trabajo pendiente (los hilos de trabajo publican
    /// sus resultados en el puente).
    fn settle(screen: &mut MainScreen) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while screen.is_busy() {
            assert!(Instant::now() < deadline, "tareas sin terminar");
            screen.pump();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Una pasada de egui (las texturas se descartan: no hay pintor).
    fn frame(ctx: &egui::Context, screen: &mut MainScreen, events: Vec<egui::Event>) {
        let mut output = ctx.run_ui(input(events), |ui| screen.ui(ui));
        output.textures_delta.clear();
    }

    fn input(events: Vec<egui::Event>) -> egui::RawInput {
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, vec2(412.0, 915.0))),
            events,
            ..Default::default()
        }
    }

    #[test]
    fn pulsar_el_boton_abre_el_selector_y_el_resultado_se_analiza() {
        let (mut screen, platform, bridge) = screen();
        let ctx = egui::Context::default();
        frame(&ctx, &mut screen, vec![]);
        let rect = screen.target_rect(Target::OpenDocument).expect("botón dibujado");
        let pos = rect.center();
        let click = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        frame(&ctx, &mut screen, vec![egui::Event::PointerMoved(pos), click(true)]);
        frame(&ctx, &mut screen, vec![click(false)]);
        assert_eq!(*platform.calls.lock().unwrap(), ["open_document 1"]);
        assert!(screen.is_busy());

        let pdf = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/pades/rotated_pages.pdf"
        ))
        .unwrap();
        bridge.post(PlatformEvent::DocumentOpened {
            request: 1,
            uri: "content://prueba/1".into(),
            name: Some("rotated_pages.pdf".into()),
            data: pdf,
        });
        settle(&mut screen);
        match &screen.document {
            Some(DocumentState::Ready(d)) => {
                assert_eq!(d.format, "PAdES");
                assert_eq!(d.name, "rotated_pages.pdf");
            }
            other => panic!("documento no analizado: {other:?}"),
        }
        // Se vuelve a dibujar con el resultado sin problemas.
        frame(&ctx, &mut screen, vec![]);
    }

    #[test]
    fn cancelar_y_respuestas_inesperadas() {
        let (mut screen, _, _) = screen();
        screen.open_document();
        screen.handle_event(PlatformEvent::RequestFailed {
            request: 1,
            cancelled: true,
            message: None,
        });
        assert_eq!(screen.notice, Some(Notice::Info("Operación cancelada.".into())));
        assert!(!screen.is_busy());
        // Una respuesta de una petición que no existe no cambia nada.
        screen.handle_event(PlatformEvent::DocumentOpened {
            request: 99,
            uri: String::new(),
            name: None,
            data: vec![],
        });
        assert_eq!(screen.document, None);
    }

    #[test]
    fn certificado_elegido_se_carga_en_un_hilo_de_trabajo() {
        let (mut screen, platform, _) = screen();
        screen.choose_certificate();
        screen.handle_event(PlatformEvent::CertificateChosen {
            request: 1,
            alias: Some("firmante".into()),
        });
        settle(&mut screen);
        match &screen.certificate {
            Some(CertificateState::Ready(c)) => {
                assert_eq!(c.subject, "Firmante de prueba");
                assert_eq!(c.chain_len, 2);
            }
            other => panic!("certificado no cargado: {other:?}"),
        }
        assert_eq!(
            *platform.calls.lock().unwrap(),
            ["choose_certificate 1", "certificate_chain firmante"]
        );

        // Alias desconocido: el error de Java se muestra.
        screen.choose_certificate();
        screen.handle_event(PlatformEvent::CertificateChosen {
            request: 2,
            alias: Some("otro".into()),
        });
        settle(&mut screen);
        assert!(
            matches!(&screen.certificate, Some(CertificateState::Failed { message, .. }) if message.contains("KeyChainException"))
        );

        // Sin elegir.
        screen.choose_certificate();
        screen.handle_event(PlatformEvent::CertificateChosen {
            request: 3,
            alias: None,
        });
        assert!(matches!(screen.notice, Some(Notice::Info(_))));
    }

    #[test]
    fn peticiones_web() {
        let (mut screen, _, _) = screen();
        screen.handle_event(PlatformEvent::ViewIntent {
            uri: "afirma://sign?op=sign&id=1234".into(),
        });
        assert_eq!(
            screen.web_request,
            Some(WebRequest {
                operation: "Operación «sign»".into(),
                supported: true
            })
        );
        assert!(!describe_web_request("afirma://service?ports=1").supported);
        assert!(!describe_web_request("afirma://websocket?v=4").supported);
        assert!(!describe_web_request("afirma://load?id=1").supported);
        assert!(describe_web_request("afirma://selectcert?id=1").supported);
        assert!(!describe_web_request("https://example.org").supported);
    }
}
