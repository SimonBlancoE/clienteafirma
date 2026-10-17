//! La aplicación: pila de pantallas, diálogo abierto, preferencias, histórico, teclado e
//! idioma, y los eventos que llegan de Android.
//!
//! Cada pasada de egui: [`Shell::pump`] atiende los eventos del puente (Atrás, configuración,
//! teclado, resultados de los selectores...) y [`Shell::ui`] dibuja la pantalla actual y el
//! diálogo; lo que piden las pantallas ([`Action`]) se ejecuta al terminar la pasada. No
//! depende de Android: las pruebas la manejan con una plataforma falsa y eventos simulados.

use std::path::Path;
use std::sync::Arc;

use egui::{Context, TextureHandle, Ui, UiBuilder};
use tracing::{info, warn};

use crate::bridge::{Bridge, DeviceConfig, Platform, PlatformEvent};
use crate::errors;
use crate::features::{Features, Outcome};
use crate::flow::{Effect, FlowAction, Flows};
use crate::history::SignsHistory;
use crate::i18n::{self, Language, tr, trf};
use crate::ime::ImeController;
use crate::nav::{BackOutcome, Navigator, Screen, route_after_splash};
use crate::prefs::{Preferences, Prefs, parse_trusted_domains};
use crate::ui::screens::{self, Action, Dialog, View};
use crate::ui::widgets::{Cx, Targets, Tone};
use crate::ui::{icons, theme};

/// Duración del arranque (el original esperaba 2 s; aquí se puede saltar tocando).
pub const SPLASH_SECS: f64 = 1.5;
/// Duración del fundido al cambiar de pantalla.
const FADE_SECS: f64 = 0.18;

/// Logotipo (el icono de la aplicación de escritorio).
const LOGO_PNG: &[u8] = include_bytes!("../../../packaging/icons/autofirma-256.png");

/// Estado de la aplicación.
pub struct Shell {
    platform: Arc<dyn Platform>,
    bridge: Arc<Bridge>,
    prefs: Prefs,
    history: SignsHistory,
    nav: Navigator,
    dialog: Option<Dialog>,
    ime: ImeController,
    features: Features,
    flows: Flows,
    device: DeviceConfig,
    configured: bool,
    language_logged: Option<Language>,
    back_at_root: Option<bool>,
    targets: Targets,
    logo: Option<TextureHandle>,
    fonts_installed: bool,
    style: Option<(bool, u32)>,
    splash_started: Option<f64>,
    shown_screen: &'static str,
    shown_at: f64,
    logged: String,
    last_content: Option<egui::Rect>,
    frames: u64,
}

impl Shell {
    /// Aplicación con las preferencias y el histórico del directorio privado (`None`: solo
    /// en memoria).
    pub fn new(platform: Arc<dyn Platform>, bridge: Arc<Bridge>, data_dir: Option<&Path>) -> Shell {
        let (prefs, history) = match data_dir {
            Some(dir) => (Prefs::open(dir), SignsHistory::open(dir)),
            None => (Prefs::in_memory(Preferences::default()), SignsHistory::disabled()),
        };
        Shell::with_storage(platform, bridge, prefs, history)
    }

    pub fn with_storage(
        platform: Arc<dyn Platform>,
        bridge: Arc<Bridge>,
        prefs: Prefs,
        history: SignsHistory,
    ) -> Shell {
        if let Some(language) = prefs.get().locale_config {
            i18n::set_language(language);
        }
        Shell {
            ime: ImeController::new(platform.clone()),
            features: Features::new(platform.clone(), bridge.clone()),
            flows: Flows::new(platform.clone(), bridge.clone(), prefs.clone(), history.clone()),
            platform,
            bridge,
            prefs,
            history,
            nav: Navigator::new(Screen::Splash),
            dialog: None,
            device: DeviceConfig::default(),
            configured: false,
            language_logged: None,
            back_at_root: None,
            targets: Targets::default(),
            logo: None,
            fonts_installed: false,
            style: None,
            splash_started: None,
            shown_screen: "",
            shown_at: f64::NEG_INFINITY,
            logged: String::new(),
            last_content: None,
            frames: 0,
        }
    }

    pub fn nav(&self) -> &Navigator {
        &self.nav
    }

    pub fn dialog(&self) -> Option<&Dialog> {
        self.dialog.as_ref()
    }

    pub fn prefs(&self) -> &Prefs {
        &self.prefs
    }

    pub fn features(&self) -> &Features {
        &self.features
    }

    pub fn flows(&self) -> &Flows {
        &self.flows
    }

    pub fn ime(&self) -> &ImeController {
        &self.ime
    }

    /// Rectángulo (puntos) de un elemento pulsable en la última pasada.
    pub fn target(&self, tid: &str) -> Option<egui::Rect> {
        self.targets.rect(tid)
    }

    /// Identificadores de los elementos pulsables visibles.
    pub fn target_ids(&self) -> Vec<&'static str> {
        self.targets.ids()
    }

    /// `true` mientras haya alguna petición o tarea en curso.
    pub fn is_busy(&self) -> bool {
        self.features.is_busy() || self.flows.is_busy()
    }

    /// Idioma de la interfaz: el elegido o el del sistema.
    pub fn effective_language(&self) -> Language {
        self.prefs
            .get()
            .locale_config
            .unwrap_or_else(|| Language::from_system_tag(&self.device.locale))
    }

    fn update_language(&mut self) {
        let language = self.effective_language();
        if self.language_logged != Some(language) {
            info!("Idioma de la interfaz: {}", language.tag());
            self.language_logged = Some(language);
        }
        i18n::set_language(language);
    }

    /// Atiende los eventos pendientes del puente.
    pub fn pump(&mut self, ctx: &Context) {
        let now = ctx.input(|i| i.time);
        for event in self.bridge.drain() {
            self.handle_event(event, now);
        }
    }

    /// Atiende un evento de Java o de un hilo de trabajo.
    pub fn handle_event(&mut self, event: PlatformEvent, now: f64) {
        match event {
            PlatformEvent::Back => self.back(),
            PlatformEvent::Configuration(config) => {
                info!(
                    "Configuración: idioma {}, tema {}, escala de texto {}, NFC {}",
                    config.locale,
                    if config.night { "oscuro" } else { "claro" },
                    config.font_scale,
                    if config.has_nfc { "sí" } else { "no" }
                );
                self.device = config;
                self.configured = true;
                self.update_language();
            }
            PlatformEvent::ImeState(state) => self.ime.on_state(state),
            PlatformEvent::ImeAction(_) => self.ime.on_editor_action(now),
            PlatformEvent::ImeVisibility(visible) => self.ime.on_visibility(visible, now),
            other => match self.flows.handle_event(other) {
                Ok(effects) => self.apply_effects(effects),
                Err(other) => self.feature_event(*other),
            },
        }
    }

    fn feature_event(&mut self, event: PlatformEvent) {
        match self.features.handle_event(event) {
            Some(Outcome::WebRequest) => {
                // Un enlace afirma:// salta el arranque y se abre sobre lo que haya.
                if self.nav.current() == &Screen::Splash {
                    self.nav.reset(route_after_splash(&self.prefs.get()));
                }
                if self.nav.current() != &Screen::WebRequest {
                    self.nav.push(Screen::WebRequest);
                }
                self.dialog = None;
            }
            Some(Outcome::Error(message)) => self.show_error(&message),
            None => {}
        }
    }

    /// Aplica lo que piden las operaciones de varios pasos.
    fn apply_effects(&mut self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Dialog(dialog) => self.dialog = Some(dialog),
                Effect::CloseDialog => self.dialog = None,
                Effect::OpenPreview => {
                    if !matches!(self.nav.current(), Screen::VisibleSignature { .. }) {
                        self.nav.push(Screen::VisibleSignature {
                            selection: None,
                            drag: None,
                        });
                    }
                }
                Effect::ClosePreview => {
                    self.nav.remove("visible_signature");
                }
            }
        }
    }

    fn show_error(&mut self, message: &str) {
        self.dialog = Some(Dialog::message(
            Tone::Danger,
            icons::WARNING_CIRCLE,
            tr("error_ocurred"),
            trf("operation_failed", &[&message]),
        ));
    }

    /// Botón «Atrás» del sistema.
    pub fn back(&mut self) {
        if let Some(dialog) = self.dialog.take() {
            match dialog {
                Dialog::Progress { .. } => {
                    // Una operación en curso que no se puede interrumpir.
                    info!("Atrás durante «{}»: no se hace nada", dialog.id());
                    self.dialog = Some(dialog);
                }
                Dialog::Prompt(prompt) => {
                    info!("Atrás: se cierra el diálogo «{}»", prompt.id);
                    if let Some(action) = prompt.back {
                        self.apply(action);
                    }
                }
                Dialog::ChooseCertType { .. } | Dialog::PdfPassword { .. } => {
                    info!("Atrás: se cierra el diálogo «{}»", dialog.id());
                    self.apply(Action::Flow(FlowAction::Cancel));
                }
                other => {
                    info!("Atrás: se cierra el diálogo «{}»", other.id());
                    if other == Dialog::ConfigNfc {
                        self.answer_nfc(false);
                    }
                }
            }
            return;
        }
        if matches!(self.nav.current(), Screen::VisibleSignature { .. }) {
            info!("Atrás en la vista previa de la firma visible");
            self.apply(Action::Flow(FlowAction::Cancel));
            return;
        }
        let from = self.nav.current().id();
        match self.nav.back() {
            BackOutcome::Handled => info!("Atrás: «{from}» → «{}»", self.nav.current().id()),
            BackOutcome::LeaveApp => {
                info!("Atrás en «{from}»: la aplicación pasa a segundo plano");
                if let Err(e) = self.platform.leave_app() {
                    warn!("No se pudo dejar la aplicación en segundo plano: {e}");
                }
            }
        }
    }

    fn answer_nfc(&mut self, yes: bool) {
        self.save(|p| {
            p.first_execution = false;
            if yes {
                p.use_nfc = true;
            }
        });
    }

    fn save(&self, change: impl FnOnce(&mut Preferences)) {
        if let Err(e) = self.prefs.update(change) {
            warn!("{e}");
        }
    }

    fn saved_dialog() -> Dialog {
        Dialog::message(
            Tone::Success,
            icons::CHECK_CIRCLE,
            tr("changes_saved"),
            tr("changes_saved_correctly"),
        )
    }

    /// Ejecuta lo que ha pedido una pantalla.
    pub fn apply(&mut self, action: Action) {
        match action {
            Action::Push(screen) => self.nav.push(screen),
            Action::Back => self.back(),
            Action::OpenDialog(dialog) => self.dialog = Some(dialog),
            Action::CloseDialog => self.dialog = None,
            Action::LeaveSplash => {
                if self.nav.current() == &Screen::Splash {
                    self.nav.reset(route_after_splash(&self.prefs.get()));
                }
            }
            Action::StartIntro => {
                self.save(|p| p.skip_intro_screen = true);
                self.nav.reset(route_after_splash(&self.prefs.get()));
            }
            Action::AcceptConditions => {
                self.save(|p| p.skip_conditions_screen = true);
                info!("Textos legales aceptados");
                self.nav.reset(Screen::Home);
            }
            Action::SetLanguage(language) => {
                self.save(|p| p.locale_config = language);
                self.update_language();
            }
            Action::SaveSignConfig(draft) => {
                self.save(|p| draft.apply(p));
                info!("Configuración de firma guardada");
                self.dialog = Some(Self::saved_dialog());
            }
            Action::SetCacheMinutes(minutes) => {
                if let Screen::SignConfiguration(draft) = self.nav.current_mut() {
                    draft.cache_minutes = minutes;
                }
                self.dialog = None;
            }
            Action::SetValidateSsl(validate) => {
                info!("Validar conexiones SSL: {validate}");
                self.save(|p| p.validate_ssl_checks = validate);
            }
            Action::SaveTrustedDomains(text) => match parse_trusted_domains(&text) {
                Ok(domains) => {
                    info!("Dominios de confianza guardados: {}", domains.len());
                    self.save(|p| p.secure_domains_list = domains);
                    self.dialog = Some(Self::saved_dialog());
                }
                Err(domain) => {
                    info!("Dominio de confianza no válido");
                    self.dialog = Some(Dialog::message(
                        Tone::Danger,
                        icons::WARNING_CIRCLE,
                        tr("error_ocurred"),
                        format!(
                            "{} - {}",
                            errors::DOMAIN_FORMAT_INCORRECT.code_str(),
                            trf("error_format_trusted_domains", &[&domain])
                        ),
                    ));
                }
            },
            Action::OpenHistory => {
                let records = self.history.load().unwrap_or_else(|e| {
                    warn!("No se pudo leer el histórico de firmas: {e}");
                    Vec::new()
                });
                info!("Histórico de firmas: {} registros", records.len());
                self.nav.push(Screen::SignsRecord { records });
            }
            Action::ClearHistory => {
                if let Err(e) = self.history.clear() {
                    warn!("No se pudo vaciar el histórico de firmas: {e}");
                }
                if let Screen::SignsRecord { records } = self.nav.current_mut() {
                    records.clear();
                }
                info!("Histórico de firmas eliminado");
                self.dialog = None;
            }
            Action::AnswerNfc(yes) => {
                self.answer_nfc(yes);
                self.dialog = None;
            }
            Action::Flow(action) => {
                let effects = self.flows.apply(action);
                self.apply_effects(effects);
            }
            Action::ImportCertificate => {
                // Se cierran las instrucciones y se abre el selector (el original abría además
                // un Inicio nuevo que lanzaba un segundo selector, §10 n.º 15).
                while matches!(self.nav.current(), Screen::ImportInstructions { .. }) && self.nav.depth() > 1 {
                    self.nav.pop();
                }
                let effects = self.flows.apply(FlowAction::StartImport);
                self.apply_effects(effects);
            }
            Action::ChooseCertificate => {
                if let Err(e) = self.features.choose_certificate() {
                    self.show_error(&e);
                }
            }
            Action::OpenUrl(url) => {
                if let Err(e) = self.features.open_url(&url) {
                    self.show_error(&e);
                }
            }
        }
    }

    fn palette(&self) -> theme::Palette {
        theme::Palette::for_night(self.device.night)
    }

    /// Fuentes, estilo, logotipo, temporizador del arranque y diálogo de primera ejecución.
    fn prepare(&mut self, ctx: &Context, now: f64) {
        if !self.fonts_installed {
            theme::install_fonts(ctx);
            self.fonts_installed = true;
        }
        let key = (self.device.night, (self.device.font_scale * 1000.0) as u32);
        if self.style != Some(key) {
            theme::apply(ctx, &self.palette(), self.device.font_scale);
            self.style = Some(key);
        }
        if self.logo.is_none() {
            self.logo = load_logo(ctx);
        }
        if self.nav.current() == &Screen::Splash {
            let started = *self.splash_started.get_or_insert(now);
            let left = SPLASH_SECS - (now - started);
            if left <= 0.0 {
                self.nav.reset(route_after_splash(&self.prefs.get()));
            } else {
                ctx.request_repaint_after(std::time::Duration::from_secs_f64(left));
            }
        }
        // Primera ejecución con NFC: se pregunta una vez si se quiere usar el DNIe (§2.5).
        if self.nav.current() == &Screen::Home
            && self.dialog.is_none()
            && self.configured
            && self.device.has_nfc
            && self.prefs.get().first_execution
        {
            self.save(|p| p.first_execution = false);
            self.dialog = Some(Dialog::ConfigNfc);
        }
        let screen = self.nav.current().id();
        if screen != self.shown_screen {
            self.shown_screen = screen;
            self.shown_at = now;
        }
    }

    /// Pantalla y diálogo visibles (para los registros).
    fn shown(&self) -> String {
        match &self.dialog {
            Some(dialog) => format!("{} + {}", self.nav.current().id(), dialog.id()),
            None => self.nav.current().id().to_string(),
        }
    }

    /// Dibuja la pantalla y el diálogo.
    pub fn ui(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        let now = ctx.input(|i| i.time);
        self.prepare(&ctx, now);
        let drawn = self.shown();
        let p = self.palette();
        ui.painter().rect_filled(ctx.viewport_rect(), 0.0, p.bg);
        let content = ctx.content_rect();
        if self.last_content != Some(content) {
            self.last_content = Some(content);
            self.ime.on_viewport_changed();
        }
        self.targets.clear();
        self.ime.begin_frame();
        let fade = ((now - self.shown_at) / FADE_SECS).clamp(0.0, 1.0) as f32;
        if fade < 1.0 {
            ctx.request_repaint();
        }
        let mut actions = Vec::new();
        {
            let prefs = self.prefs.get();
            let language = i18n::language();
            self.flows.upload_textures(&ctx);
            let Shell {
                nav,
                ime,
                targets,
                features,
                flows,
                device,
                logo,
                dialog,
                ..
            } = self;
            let view = View {
                prefs: &prefs,
                device,
                features,
                flows,
                logo: logo.as_ref(),
                language,
            };
            let mut cx = Cx {
                p,
                scale: device.font_scale,
                ime,
                targets,
            };
            ui.scope_builder(UiBuilder::new().max_rect(content), |ui| {
                ui.multiply_opacity(egui::emath::easing::cubic_out(fade));
                screens::draw(ui, &mut cx, nav.current_mut(), &view, &mut actions);
            });
            if let Some(dialog) = dialog.as_mut() {
                screens::draw_dialog(&ctx, &mut cx, dialog, &view, &mut actions);
            }
        }
        self.ime.end_frame();
        for action in actions {
            self.apply(action);
        }
        self.after_frame(&ctx, &drawn);
        let at_root = self.dialog.is_none() && self.nav.depth() == 1;
        if self.back_at_root != Some(at_root) {
            self.back_at_root = Some(at_root);
            if let Err(e) = self.platform.set_back_at_root(at_root) {
                warn!("No se pudo avisar a Java de la pantalla raíz: {e}");
            }
        }
        // El teclado lo abre y lo cierra ImeController: que eframe no llame a
        // `set_ime_allowed` (mostraría el teclado desde el hilo de Rust sin el tipo de campo).
        ctx.output_mut(|o| o.ime = None);
    }

    /// Registros para las pruebas: primer fotograma, pantalla visible y posición de los
    /// elementos pulsables en píxeles (cuando cambian).
    fn after_frame(&mut self, ctx: &Context, drawn: &str) {
        self.frames += 1;
        let ppp = ctx.pixels_per_point();
        if self.frames == 1 {
            let size = ctx.viewport_rect().size() * ppp;
            info!(
                "Primer fotograma de la interfaz ({:.0}x{:.0} px, {ppp} px por punto)",
                size.x, size.y
            );
        }
        let shown = self.shown();
        if shown != self.logged {
            info!("Pantalla «{shown}»");
            self.logged = shown.clone();
            self.targets.reset_log();
        }
        if shown != drawn {
            // Lo dibujado es de la pantalla anterior: las posiciones nuevas, en la próxima pasada.
            self.targets.clear();
            return;
        }
        let (changed, gone) = self.targets.changed_positions(ppp);
        for tid in gone {
            info!("Botón «{tid}» oculto");
        }
        for (tid, [x, y]) in changed {
            info!("Botón «{tid}» en x={x} y={y}");
        }
    }
}

fn load_logo(ctx: &Context) -> Option<TextureHandle> {
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
    use egui::{Event, PointerButton, Pos2, RawInput, Rect, vec2};

    use super::*;
    use crate::history::{RecordKind, RecordOperation, SignRecord};
    use crate::i18n::test_lock;
    use crate::ime::ImeState;
    use crate::prefs::CacheMinutes;
    use crate::testing::FakePlatform;
    use crate::ui::screens::Action;

    /// Aplicación con egui sin pintor y una plataforma falsa; el tiempo avanza 50 ms por
    /// pasada.
    struct Harness {
        ctx: Context,
        shell: Shell,
        platform: Arc<FakePlatform>,
        bridge: Arc<Bridge>,
        time: f64,
        size: egui::Vec2,
    }

    impl Harness {
        fn new(prefs: Prefs, history: SignsHistory) -> Harness {
            Harness::with_platform(FakePlatform::default(), prefs, history)
        }

        fn with_platform(platform: FakePlatform, prefs: Prefs, history: SignsHistory) -> Harness {
            let platform = Arc::new(platform);
            let bridge = Arc::new(Bridge::new());
            let shell = Shell::with_storage(platform.clone(), bridge.clone(), prefs, history);
            Harness {
                ctx: Context::default(),
                shell,
                platform,
                bridge,
                time: 0.0,
                size: vec2(412.0, 915.0),
            }
        }

        fn in_memory() -> Harness {
            Harness::new(Prefs::in_memory(Preferences::default()), SignsHistory::disabled())
        }

        /// Ya en Inicio (bienvenida y condiciones aceptadas).
        fn at_home() -> Harness {
            let prefs = Preferences {
                skip_intro_screen: true,
                skip_conditions_screen: true,
                ..Default::default()
            };
            let mut h = Harness::new(Prefs::in_memory(prefs), SignsHistory::disabled());
            h.configure("es-ES", false);
            h.wait(SPLASH_SECS + 0.2);
            assert_eq!(h.screen(), "home");
            h
        }

        fn configure(&mut self, locale: &str, has_nfc: bool) {
            self.bridge.post(PlatformEvent::Configuration(DeviceConfig {
                locale: locale.into(),
                night: false,
                font_scale: 1.0,
                has_nfc,
            }));
        }

        fn frame(&mut self, events: Vec<Event>) {
            self.time += 0.05;
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, self.size)),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            let shell = &mut self.shell;
            let mut output = self.ctx.run_ui(input, |ui| {
                shell.pump(ui.ctx());
                shell.ui(ui);
            });
            output.textures_delta.clear();
        }

        fn frames(&mut self, n: usize) {
            for _ in 0..n {
                self.frame(vec![]);
            }
        }

        fn wait(&mut self, secs: f64) {
            let until = self.time + secs;
            while self.time < until {
                self.frame(vec![]);
            }
        }

        fn screen(&self) -> &'static str {
            self.shell.nav().current().id()
        }

        fn has(&self, tid: &str) -> bool {
            self.shell.target(tid).is_some()
        }

        fn click_at(&mut self, pos: Pos2) {
            let button = |pressed| Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            self.frame(vec![Event::PointerMoved(pos), button(true)]);
            self.frame(vec![button(false)]);
            self.frame(vec![Event::PointerGone]);
            self.frames(2);
        }

        /// Desplaza la pantalla hasta que se vea un elemento.
        fn reveal(&mut self, tid: &str) {
            self.frames(3);
            for _ in 0..30 {
                if self.has(tid) {
                    return;
                }
                let center = (self.size / 2.0).to_pos2();
                self.frame(vec![
                    Event::PointerMoved(center),
                    Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: vec2(0.0, -120.0),
                        phase: egui::TouchPhase::Move,
                        source: egui::MouseWheelSource::Unknown,
                        modifiers: Default::default(),
                    },
                ]);
                self.frames(2);
            }
        }

        /// Pulsa un elemento por su identificador.
        fn tap(&mut self, tid: &str) {
            self.reveal(tid);
            let rect = self.shell.target(tid).unwrap_or_else(|| {
                panic!(
                    "«{tid}» no está visible en {}: {:?}",
                    self.screen(),
                    self.shell.target_ids()
                )
            });
            self.click_at(rect.center());
        }

        fn back(&mut self) {
            self.bridge.post(PlatformEvent::Back);
            self.frames(2);
        }
    }

    #[test]
    fn primera_ejecucion_bienvenida_condiciones_e_inicio() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let mut h = Harness::new(Prefs::open(dir.path()), SignsHistory::open(dir.path()));
        h.configure("es-ES", false);
        h.frames(2);
        assert_eq!(h.screen(), "splash");
        h.wait(SPLASH_SECS + 0.2);
        assert_eq!(h.screen(), "intro");
        // Atrás en una pantalla raíz deja la app en segundo plano.
        h.back();
        assert_eq!(h.platform.calls_with("leave_app"), ["leave_app"]);
        h.tap("intro.start");
        assert_eq!(h.screen(), "conditions");
        assert!(Prefs::open(dir.path()).get().skip_intro_screen, "se guarda enseguida");
        // «Aceptar» solo funciona con las dos casillas marcadas.
        h.tap("conditions.accept");
        assert_eq!(h.screen(), "conditions");
        h.tap("conditions.privacy");
        h.tap("conditions.accept");
        assert_eq!(h.screen(), "conditions");
        h.tap("conditions.legal");
        h.tap("conditions.accept");
        assert_eq!(h.screen(), "home");
        let saved = Prefs::open(dir.path()).get();
        assert!(saved.skip_intro_screen && saved.skip_conditions_screen);

        // Siguiente arranque: directamente a Inicio.
        let mut h = Harness::new(Prefs::open(dir.path()), SignsHistory::open(dir.path()));
        h.frames(1);
        h.tap_splash();
        assert_eq!(h.screen(), "home");
    }

    impl Harness {
        /// Toca el logotipo del arranque para saltarlo.
        fn tap_splash(&mut self) {
            self.frames(2);
            let center = (self.size / 2.0).to_pos2();
            self.click_at(center);
        }
    }

    #[test]
    fn ajustes_y_pila_de_atras() {
        let _lock = test_lock();
        let mut h = Harness::at_home();
        h.tap("home.settings");
        assert_eq!(h.screen(), "settings");
        assert_eq!(
            h.platform.calls_with("set_back_at_root").last().unwrap(),
            "set_back_at_root false"
        );
        h.tap("settings.language");
        assert_eq!(h.shell.nav().ids(), ["home", "settings", "language"]);
        h.back();
        assert_eq!(h.screen(), "settings");
        h.tap("settings.faq");
        h.tap("faq.2");
        assert_eq!(
            h.shell.nav().current(),
            &Screen::Faq {
                open: [false, true, false]
            }
        );
        h.back();
        // Pantallas de ayuda con acceso directo a su configuración.
        h.tap("settings.help_trusted_domains");
        h.tap("help.go_config");
        assert_eq!(
            h.shell.nav().ids(),
            ["home", "settings", "help_trusted_domains", "trusted_domains"]
        );
        h.back();
        h.back();
        h.tap("settings.help_certs");
        h.tap("help.import");
        assert_eq!(h.screen(), "import_instructions_1");
        h.tap("import.continue");
        assert_eq!(h.screen(), "import_instructions_2");
        h.back();
        assert_eq!(h.screen(), "import_instructions_1", "Atrás vuelve a la página 1");
        h.tap("import.continue");
        h.tap("import.add");
        assert_eq!(h.screen(), "help_import_certs", "se cierran las instrucciones");
        assert_eq!(
            h.platform.calls_with("open_document"),
            ["open_document 1 application/x-pkcs12"],
            "un solo selector (el original abría dos, §10 n.º 15)"
        );
        h.bridge.post(PlatformEvent::RequestFailed {
            request: 1,
            cancelled: true,
            message: None,
        });
        h.frames(2);
        assert_eq!(h.shell.dialog(), None, "cancelar no muestra nada");
        while h.screen() != "home" {
            h.back();
        }
        // En la raíz, Java deja la app en segundo plano sin pasar por Rust.
        assert_eq!(
            h.platform.calls_with("set_back_at_root").last().unwrap(),
            "set_back_at_root true"
        );
        h.back();
        assert_eq!(h.platform.calls_with("leave_app"), ["leave_app"]);
        // Información general.
        h.tap("home.settings");
        for (row, screen) in [
            ("settings.legal", "legal"),
            ("settings.privacy", "privacy"),
            ("settings.accessibility", "accessibility"),
            ("settings.version", "version"),
        ] {
            h.tap(row);
            assert_eq!(h.screen(), screen);
            h.back();
        }
        h.tap("settings.version");
        h.tap("version.license");
        assert_eq!(h.platform.calls_with("open_url"), ["open_url 2 https://eupl.eu/1.1/es"]);
    }

    #[test]
    fn idioma_inmediato_persistente_y_del_sistema() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let prefs = Prefs::open(dir.path());
        prefs
            .update(|p| {
                p.skip_intro_screen = true;
                p.skip_conditions_screen = true;
            })
            .unwrap();
        let mut h = Harness::new(prefs, SignsHistory::open(dir.path()));
        // Sin idioma elegido se sigue el del sistema.
        h.configure("gl-ES", false);
        h.frames(1);
        assert_eq!(i18n::language(), Language::Gl);
        assert_eq!(tr("settings"), "Axustes");
        h.tap_splash();
        h.tap("home.settings");
        h.tap("settings.language");
        h.tap("language.va");
        assert_eq!(i18n::language(), Language::CaValencia);
        assert_eq!(Prefs::open(dir.path()).get().locale_config, Some(Language::CaValencia));
        h.frames(2);
        assert!(
            h.has("language.va"),
            "la pantalla se vuelve a dibujar con el idioma nuevo"
        );
        // «Idioma del sistema» vuelve a seguir al sistema.
        h.tap("language.system");
        assert_eq!(i18n::language(), Language::Gl);
        assert_eq!(Prefs::open(dir.path()).get().locale_config, None);
        h.tap("language.en");
        // Al volver a abrir la aplicación se usa el idioma guardado.
        i18n::set_language(Language::Es);
        let _h = Harness::new(Prefs::open(dir.path()), SignsHistory::open(dir.path()));
        assert_eq!(i18n::language(), Language::En);
        i18n::set_language(Language::Es);
    }

    #[test]
    fn condiciones_cambian_de_idioma_sin_forzar_el_espanol() {
        let _lock = test_lock();
        let prefs = Preferences {
            skip_intro_screen: true,
            locale_config: Some(Language::Eu),
            ..Default::default()
        };
        let mut h = Harness::new(Prefs::in_memory(prefs), SignsHistory::disabled());
        h.configure("es-ES", false);
        h.tap_splash();
        assert_eq!(h.screen(), "conditions");
        assert_eq!(
            i18n::language(),
            Language::Eu,
            "el original volvía al español (§10 n.º 3)"
        );
        h.tap("conditions.language");
        assert_eq!(h.shell.dialog().map(Dialog::id), Some("language_picker"));
        h.tap("language.ca");
        assert_eq!(i18n::language(), Language::Ca);
        assert_eq!(h.shell.dialog(), None);
        i18n::set_language(Language::Es);
    }

    #[test]
    fn teclado_en_dominios_de_confianza() {
        let _lock = test_lock();
        let mut h = Harness::at_home();
        h.tap("home.settings");
        h.tap("settings.trusted_domains");
        h.tap("domains.field");
        let shown = h.platform.calls_with("ime_show");
        assert_eq!(shown, [r#"ime_show MultiLine "" (0, 0)"#], "abre el teclado multilínea");
        assert!(h.shell.ime().owner().is_some());
        // Lo que escribe el teclado (estado completo, índices UTF-16) llega al campo.
        h.bridge.post(PlatformEvent::ImeState(ImeState::from_java(
            "sede.ejemplo.es".into(),
            15,
            15,
            5,
            12,
        )));
        h.frames(1);
        assert_eq!(
            h.shell.nav().current(),
            &Screen::TrustedDomains {
                text: "sede.ejemplo.es".into()
            }
        );
        assert!(h.platform.calls_with("ime_update").is_empty(), "no se devuelve el eco");
        // Intro en un campo multilínea es un salto de línea (lo trata el teclado).
        h.bridge.post(PlatformEvent::ImeState(ImeState::from_java(
            "sede.ejemplo.es\nmal dominio".into(),
            27,
            27,
            -1,
            -1,
        )));
        h.frames(1);
        // Tocar fuera cierra el teclado.
        h.click_at(Pos2::new(200.0, 150.0));
        assert_eq!(h.platform.calls_with("ime_hide"), ["ime_hide"]);
        assert!(h.shell.ime().owner().is_none());
        h.tap("domains.save");
        match h.shell.dialog() {
            Some(Dialog::Message { body, .. }) => {
                assert_eq!(
                    body,
                    "AA200700 - El dominio \"mal dominio\" tiene un formato incorrecto."
                )
            }
            other => panic!("se esperaba el error de formato: {other:?}"),
        }
        assert!(h.shell.prefs().get().secure_domains_list.is_empty());
        h.tap("dialog.ok");
        // Corregido desde el teclado y guardado.
        h.tap("domains.field");
        h.bridge.post(PlatformEvent::ImeState(ImeState::new(
            "sede.ejemplo.es\n*.gob.es",
            (24, 24),
        )));
        h.frames(1);
        h.back(); // el teclado lo cierra el sistema; aquí Atrás llega a la app
        assert_eq!(h.screen(), "settings");
        h.tap("settings.trusted_domains");
        assert_eq!(
            h.shell.nav().current(),
            &Screen::TrustedDomains { text: String::new() },
            "sin «Guardar» no se guarda"
        );
        h.tap("domains.field");
        h.bridge.post(PlatformEvent::ImeState(ImeState::new(
            "sede.ejemplo.es\n*.gob.es",
            (24, 24),
        )));
        h.frames(1);
        h.tap("domains.save");
        assert_eq!(h.shell.dialog().map(Dialog::id), Some("message"));
        assert_eq!(
            h.shell.prefs().get().secure_domains_list,
            ["sede.ejemplo.es", "*.gob.es"]
        );
        // «Validar conexiones SSL» se guarda al momento.
        h.tap("dialog.ok");
        h.tap("domains.validate_ssl");
        assert!(!h.shell.prefs().get().validate_ssl_checks);
    }

    #[test]
    fn configuracion_de_firma_y_minutos_de_cache() {
        let _lock = test_lock();
        let mut h = Harness::at_home();
        h.tap("home.settings");
        h.tap("settings.sign_configuration");
        h.tap("signconf.visible");
        h.tap("signconf.nfc"); // sin NFC está deshabilitado
        h.tap("signconf.cache");
        assert_eq!(h.shell.dialog().map(Dialog::id), Some("cache_minutes"));
        h.tap("minutes.30");
        h.tap("dialog.select");
        assert_eq!(h.shell.dialog(), None);
        assert!(
            !h.shell.prefs().get().pades_visible_signature,
            "nada se guarda sin «Guardar»"
        );
        h.tap("signconf.save");
        let p = h.shell.prefs().get();
        assert!(p.pades_visible_signature && !p.use_nfc);
        assert_eq!(p.sticky_signature_timeout, CacheMinutes::Thirty);
        assert_eq!(h.shell.dialog().map(Dialog::id), Some("message"));
        // Atrás cierra primero el diálogo y luego la pantalla.
        h.back();
        assert_eq!((h.screen(), h.shell.dialog()), ("sign_configuration", None));
        h.back();
        assert_eq!(h.screen(), "settings");
    }

    #[test]
    fn pregunta_de_nfc_en_la_primera_ejecucion() {
        let _lock = test_lock();
        let prefs = Preferences {
            skip_intro_screen: true,
            skip_conditions_screen: true,
            ..Default::default()
        };
        let mut h = Harness::new(Prefs::in_memory(prefs), SignsHistory::disabled());
        h.configure("es-ES", true);
        h.tap_splash();
        h.frames(2);
        assert_eq!(h.shell.dialog(), Some(&Dialog::ConfigNfc));
        assert!(!h.shell.prefs().get().first_execution);
        h.tap("dialog.yes");
        assert!(h.shell.prefs().get().use_nfc);
        assert_eq!(h.shell.dialog(), None);
        h.frames(3);
        assert_eq!(h.shell.dialog(), None, "solo una vez");
    }

    #[test]
    fn historico_y_borrado() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let history = SignsHistory::open(dir.path());
        history
            .append(&SignRecord::now(
                RecordKind::Local,
                RecordOperation::Sign,
                Some("a.pdf"),
                None,
            ))
            .unwrap();
        let prefs = Preferences {
            skip_intro_screen: true,
            skip_conditions_screen: true,
            ..Default::default()
        };
        let mut h = Harness::new(Prefs::in_memory(prefs), history.clone());
        h.configure("es-ES", false);
        h.tap_splash();
        h.tap("home.history");
        assert!(matches!(h.shell.nav().current(), Screen::SignsRecord { records } if records.len() == 1));
        h.tap("history.delete");
        assert_eq!(h.shell.dialog(), Some(&Dialog::ConfirmClearHistory));
        h.tap("dialog.cancel");
        assert_eq!(history.load().unwrap().len(), 1);
        h.tap("history.delete");
        h.tap("dialog.delete");
        assert!(history.load().unwrap().is_empty());
        assert!(matches!(h.shell.nav().current(), Screen::SignsRecord { records } if records.is_empty()));
        h.tap("history.delete");
        assert_eq!(
            h.shell.dialog().map(Dialog::id),
            Some("message"),
            "«No se encuentran registros»"
        );
    }

    #[test]
    fn firmar_fichero_certificados_y_peticiones_web() {
        let _lock = test_lock();
        let mut h = Harness::at_home();
        h.tap("home.sign_file");
        assert_eq!(h.platform.calls_with("open_document"), ["open_document 1 */*"]);
        h.bridge.post(PlatformEvent::DocumentOpened {
            request: 1,
            uri: "content://prueba".into(),
            name: Some("datos.bin".into()),
            data: b"hola".to_vec(),
        });
        h.frames(2);
        // Sin el DNIe habilitado, directamente el selector de KeyChain.
        assert_eq!(h.platform.calls_with("choose_certificate"), ["choose_certificate 2"]);
        assert_eq!(h.screen(), "home");
        // Sin elegir certificado: se cancela sin mensaje.
        h.bridge.post(PlatformEvent::CertificateChosen {
            request: 2,
            alias: None,
        });
        h.frames(2);
        assert_eq!((h.screen(), h.shell.dialog()), ("home", None));
        assert!(!h.shell.flows().signing());
        h.tap("home.certificates");
        h.tap("certs.view");
        assert_eq!(
            h.platform.calls_with("choose_certificate"),
            ["choose_certificate 2", "choose_certificate 3"]
        );
        h.back();
        // Enlace afirma:// con la app abierta: se abre su pantalla encima.
        h.bridge.post(PlatformEvent::ViewIntent {
            uri: "afirma://selectcert?id=1".into(),
        });
        h.frames(2);
        assert_eq!(h.shell.nav().ids(), ["home", "web_request"]);
        h.back();
        assert_eq!(h.screen(), "home");
    }

    fn testdata(path: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../testdata/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    impl Harness {
        /// En Inicio con unas preferencias, el histórico en `dir` y una KeyChain falsa con el
        /// alias `firmante` del PKCS#12 de `testdata/pki`.
        fn signing(p12: &str, prefs: Preferences, dir: &std::path::Path) -> Harness {
            let prefs = Preferences {
                skip_intro_screen: true,
                skip_conditions_screen: true,
                ..prefs
            };
            let mut h = Harness::with_platform(
                FakePlatform::with_p12(p12),
                Prefs::in_memory(prefs),
                SignsHistory::open(dir),
            );
            h.configure("es-ES", false);
            h.tap_splash();
            assert_eq!(h.screen(), "home");
            h
        }

        /// Pasadas hasta que terminen los hilos de trabajo.
        fn settle(&mut self) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                self.frames(2);
                if !self.shell.is_busy() {
                    self.frames(2);
                    if !self.shell.is_busy() {
                        return;
                    }
                }
                assert!(std::time::Instant::now() < deadline, "tareas sin terminar");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        /// Petición de la última llamada a la plataforma que empieza por `call`.
        fn last_request(&self, call: &str) -> crate::bridge::RequestId {
            let calls = self.platform.calls_with(call);
            let last = calls.last().unwrap_or_else(|| panic!("sin llamadas a {call}"));
            last.split(' ').nth(1).unwrap().parse().unwrap()
        }

        /// Elige un documento en el selector de documentos (falso).
        fn open_document(&mut self, name: &str, data: Vec<u8>) {
            let request = self.last_request("open_document");
            self.bridge.post(PlatformEvent::DocumentOpened {
                request,
                uri: format!("content://descargas/{name}"),
                name: Some(name.into()),
                data,
            });
            self.frames(2);
        }

        /// Elige el alias en el selector de KeyChain y espera a la firma.
        fn choose_alias(&mut self, alias: Option<&str>) {
            let request = self.last_request("choose_certificate");
            self.bridge.post(PlatformEvent::CertificateChosen {
                request,
                alias: alias.map(Into::into),
            });
            self.settle();
        }

        /// Guarda con el diálogo del sistema (falso): devuelve el nombre propuesto, el tipo
        /// MIME y lo que se ha escrito.
        fn save_document(&mut self) -> (String, String, Vec<u8>) {
            let call = self.platform.calls_with("create_document").last().cloned().unwrap();
            let mut parts = call.splitn(4, ' ').skip(1);
            let request = parts.next().unwrap().parse().unwrap();
            let mime = parts.next().unwrap().to_string();
            let name = parts.next().unwrap().to_string();
            let mut out = Vec::new();
            self.bridge.complete_write(
                request,
                format!("content://descargas/{name}"),
                Some(name.clone()),
                &mut out,
            );
            self.frames(2);
            (name, mime, out)
        }

        fn drag(&mut self, from: Pos2, to: Pos2) {
            let button = |pos, pressed| Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            self.frame(vec![Event::PointerMoved(from), button(from, true)]);
            for i in 1..=8 {
                let t = i as f32 / 8.0;
                self.frame(vec![Event::PointerMoved(from + (to - from) * t)]);
            }
            self.frame(vec![button(to, false)]);
            self.frame(vec![Event::PointerGone]);
            self.frames(2);
        }

        fn dialog_id(&self) -> Option<&'static str> {
            self.shell.dialog().map(Dialog::id)
        }

        fn dialog_title(&self) -> String {
            match self.shell.dialog() {
                Some(Dialog::Message { title, .. }) => title.clone(),
                Some(Dialog::Prompt(p)) => p.title.clone(),
                other => panic!("sin diálogo de mensaje: {other:?}"),
            }
        }
    }

    fn assert_valid(signature: &[u8]) {
        let result = afirma_signers::validate(signature, &afirma_core::ExtraParams::new());
        assert_eq!(
            result[0].validity,
            afirma_core::validity::Validity::Ok,
            "firma no válida: {result:?}"
        );
    }

    /// Firma local completa con la KeyChain falsa (clave RSA de testdata/pki que firma de
    /// verdad): PDF con firma visible, fichero cualquiera en CAdES y XML en XAdES; las tres
    /// firmas se validan con afirma-signers (el verificador del escritorio) y quedan en el
    /// histórico. Guardar cancelado no se registra.
    #[test]
    fn firma_local_con_keychain_de_extremo_a_extremo() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let prefs = Preferences {
            pades_visible_signature: true,
            ..Default::default()
        };
        let mut h = Harness::signing("firmante-rsa.p12", prefs, dir.path());
        // Caché de certificado de la firma web con una entrada: la firma local la vacía (§4.7).
        let cached: Arc<dyn afirma_core::SigningKey> = Arc::new(crate::testing::software_key());
        h.shell
            .flows()
            .cache()
            .store(cached, std::time::Duration::from_secs(300));
        assert!(h.shell.flows().cache().get().is_some());

        // PDF: vista previa, área, certificado, firma y guardado.
        h.tap("home.sign_file");
        h.open_document("documento.pdf", testdata("cades/data/documento.pdf"));
        assert_eq!(h.screen(), "visible_signature");
        h.settle();
        let page = h.shell.target("preview.page").expect("página dibujada");
        let preview = h.shell.flows().preview().unwrap();
        assert!(preview.texture.is_some(), "página dibujada en una textura");
        assert!(!preview.loading());
        h.drag(
            page.min + vec2(page.width() * 0.1, page.height() * 0.6),
            page.min + vec2(page.width() * 0.7, page.height() * 0.8),
        );
        assert!(matches!(
            h.shell.nav().current(),
            Screen::VisibleSignature { selection: Some(_), .. }
        ));
        h.tap("preview.continue");
        assert_eq!(h.screen(), "home", "se sale de la vista previa");
        h.choose_alias(Some("firmante"));
        assert!(h.shell.flows().cache().get().is_none(), "la firma local vacía la caché");
        let (name, mime, pdf) = h.save_document();
        assert_eq!(
            (name.as_str(), mime.as_str()),
            ("documento_signed.pdf", "application/pdf")
        );
        assert_eq!(h.dialog_title(), "Fichero firmado");
        assert_valid(&pdf);
        let info = afirma_pdf::info::PdfInfo::open(&pdf, None).unwrap();
        let field = &info.signature_fields[0];
        assert_eq!(field.page, 1);
        assert!(
            field.urx - field.llx > 100 && field.ury - field.lly > 45,
            "firma visible: {field:?}"
        );
        assert!(
            h.platform.calls_with("sign firmante SHA256withRSA").len() == 1,
            "firmado con KeyChain: {:?}",
            h.platform.calls()
        );
        h.tap("dialog.ok");

        // Fichero cualquiera: CAdES implícita, sin vista previa.
        h.tap("home.sign_file");
        h.open_document("hola.txt", testdata("cades/data/hola.txt"));
        assert_eq!(h.screen(), "home");
        h.choose_alias(Some("firmante"));
        let (name, mime, cades) = h.save_document();
        assert_eq!((name.as_str(), mime.as_str()), ("hola.txt.csig", "application/csig"));
        assert_valid(&cades);
        let signer = afirma_signers::signer_for_format("CAdES").unwrap();
        assert_eq!(
            signer.get_data(&cades, &afirma_core::ExtraParams::new()).unwrap(),
            Some(testdata("cades/data/hola.txt")),
            "implícita: la firma contiene los datos"
        );
        h.tap("dialog.ok");

        // XML: XAdES.
        h.tap("home.sign_file");
        h.open_document("documento.xml", testdata("cades/data/documento.xml"));
        h.choose_alias(Some("firmante"));
        let (name, mime, xades) = h.save_document();
        assert_eq!(
            (name.as_str(), mime.as_str()),
            ("documento.xml.xsig", "application/xsig")
        );
        assert_valid(&xades);
        assert!(
            afirma_signers::signer_for_format("XAdES")
                .unwrap()
                .is_sign(&xades, &afirma_core::ExtraParams::new())
        );
        h.tap("dialog.ok");

        // Guardado cancelado: sin mensaje y sin registro (§10 n.º 21).
        h.tap("home.sign_file");
        h.open_document("otro.bin", vec![1, 2, 3]);
        h.choose_alias(Some("firmante"));
        let request = h.last_request("create_document");
        h.bridge.post(PlatformEvent::RequestFailed {
            request,
            cancelled: true,
            message: None,
        });
        h.frames(2);
        assert_eq!((h.screen(), h.dialog_id()), ("home", None));
        assert!(
            h.bridge.take_write(request).is_none(),
            "los datos pendientes se descartan"
        );

        let records = SignsHistory::open(dir.path()).load().unwrap();
        let mut files: Vec<_> = records.iter().map(|r| r.file.clone().unwrap()).collect();
        files.sort();
        assert_eq!(files, ["documento.pdf", "documento.xml", "hola.txt"]);
        assert!(
            records
                .iter()
                .all(|r| r.kind == RecordKind::Local && r.operation == RecordOperation::Sign)
        );
        h.tap("home.history");
        assert!(matches!(h.shell.nav().current(), Screen::SignsRecord { records } if records.len() == 3));
    }

    /// Vista previa: sin área y con un área pequeña se ofrece seguir sin firma visible (como
    /// el original); «Atrás» cancela sin mensaje.
    #[test]
    fn vista_previa_sin_area_area_pequena_y_atras() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let prefs = Preferences {
            pades_visible_signature: true,
            ..Default::default()
        };
        let mut h = Harness::signing("firmante-rsa.p12", prefs, dir.path());
        h.tap("home.sign_file");
        h.open_document("documento.pdf", testdata("cades/data/documento.pdf"));
        h.settle();
        h.tap("preview.continue");
        assert_eq!(h.dialog_id(), Some("not_selected_area"));
        h.tap("dialog.cancel");
        assert_eq!((h.screen(), h.dialog_id()), ("visible_signature", None));
        let page = h.shell.target("preview.page").unwrap();
        h.drag(page.min + vec2(10.0, 10.0), page.min + vec2(30.0, 25.0));
        h.tap("preview.continue");
        assert_eq!(h.dialog_id(), Some("small_area"));
        // «Continuar»: firma invisible.
        h.tap("dialog.ok");
        assert_eq!(h.screen(), "home");
        assert_eq!(h.platform.calls_with("choose_certificate").len(), 1);
        h.choose_alias(Some("firmante"));
        let (_, _, pdf) = h.save_document();
        assert_valid(&pdf);
        let info = afirma_pdf::info::PdfInfo::open(&pdf, None).unwrap();
        assert!(info.signature_fields.iter().all(|f| f.urx == f.llx), "firma invisible");
        h.tap("dialog.ok");

        // Atrás en la vista previa: se cancela sin mensaje.
        h.tap("home.sign_file");
        h.open_document("documento.pdf", testdata("cades/data/documento.pdf"));
        h.settle();
        h.back();
        assert_eq!((h.screen(), h.dialog_id()), ("home", None));
        assert!(!h.shell.flows().signing());
        assert!(h.shell.flows().preview().is_none());
    }

    /// PDF protegido: el diálogo de contraseña no acepta una vacía, avisa de la incorrecta y
    /// reintenta la firma con `ownerPassword`; con vista previa, la contraseña se pide antes
    /// y sirve también para firmar (§10 n.º 26).
    #[test]
    fn pdf_protegido_con_contrasena() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let mut h = Harness::signing("firmante-rsa.p12", Preferences::default(), dir.path());
        h.tap("home.sign_file");
        h.open_document("cifrado.pdf", testdata("pades/encrypted_aes128.pdf"));
        h.choose_alias(Some("firmante"));
        assert_eq!(h.dialog_id(), Some("pdf_password"));
        h.tap("dialog.ok");
        assert!(matches!(
            h.shell.dialog(),
            Some(Dialog::PdfPassword {
                error: Some("error_empty_pdf_password"),
                ..
            })
        ));
        h.shell.apply(Action::Flow(FlowAction::PdfPassword("mala".into())));
        h.settle();
        assert!(matches!(
            h.shell.dialog(),
            Some(Dialog::PdfPassword {
                error: Some("dialog_pdf_bad_password"),
                ..
            })
        ));
        h.shell.apply(Action::Flow(FlowAction::PdfPassword("owner".into())));
        h.settle();
        let (name, _, pdf) = h.save_document();
        assert_eq!(name, "cifrado_signed.pdf");
        assert_eq!(h.dialog_title(), "Fichero firmado");
        let params = afirma_core::ExtraParams::parse("ownerPassword=owner");
        let result = afirma_signers::validate(&pdf, &params);
        assert_eq!(result[0].validity, afirma_core::validity::Validity::Ok, "{result:?}");
        h.tap("dialog.ok");

        // Con vista previa: la contraseña del usuario abre el documento.
        h.shell.prefs().update(|p| p.pades_visible_signature = true).unwrap();
        h.tap("home.sign_file");
        h.open_document("usuario.pdf", testdata("pades/encrypted_aes128_user.pdf"));
        h.settle();
        assert_eq!(h.dialog_id(), Some("pdf_password"));
        h.shell.apply(Action::Flow(FlowAction::PdfPassword("user".into())));
        h.settle();
        assert_eq!((h.screen(), h.dialog_id()), ("visible_signature", None));
        h.tap("preview.continue");
        h.tap("dialog.ok"); // sin área: firma invisible
        h.choose_alias(Some("firmante"));
        // La de usuario no basta para firmar: se pide la del propietario sin volver a abrir.
        assert!(matches!(
            h.shell.dialog(),
            Some(Dialog::PdfPassword {
                error: Some("dialog_pdf_bad_password"),
                ..
            })
        ));
        h.back();
        assert_eq!((h.screen(), h.dialog_id()), ("home", None), "cancelar no muestra nada");
    }

    /// Avisos del certificado: «Cancelar» vuelve a elegir certificado y «Continuar» firma.
    #[test]
    fn avisos_del_certificado_caducado() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let mut h = Harness::signing("caducado.p12", Preferences::default(), dir.path());
        h.tap("home.sign_file");
        h.open_document("hola.txt", testdata("cades/data/hola.txt"));
        h.choose_alias(Some("firmante"));
        assert_eq!(h.dialog_id(), Some("cert_expired"));
        assert_eq!(h.dialog_title(), "Certificado caducado");
        h.tap("dialog.cancel");
        assert_eq!(
            h.platform.calls_with("choose_certificate").len(),
            2,
            "se vuelve a elegir"
        );
        h.choose_alias(Some("firmante"));
        assert_eq!(h.dialog_id(), Some("cert_expired"));
        h.tap("dialog.ok");
        h.settle();
        let (_, _, cades) = h.save_document();
        assert_eq!(h.dialog_title(), "Fichero firmado");
        assert!(!cades.is_empty());
        // Un alias que KeyChain no conoce: error de certificado (AA200000).
        h.tap("dialog.ok");
        h.tap("home.sign_file");
        h.open_document("hola.txt", testdata("cades/data/hola.txt"));
        h.choose_alias(Some("otro"));
        match h.shell.dialog() {
            Some(Dialog::Message { title, body, .. }) => {
                assert_eq!(title, "¡Algo salió mal!");
                assert!(body.starts_with("AA200000 - "), "{body}");
            }
            other => panic!("se esperaba el error: {other:?}"),
        }
    }

    /// Con el DNIe habilitado: «¿Con qué firmarás?»; el DNIe aún no está y se vuelve a
    /// elegir; sin elegir en KeyChain se vuelve a preguntar; la X cancela.
    #[test]
    fn eleccion_de_almacen_con_dnie_habilitado() {
        let _lock = test_lock();
        let dir = tempfile::tempdir().unwrap();
        let prefs = Preferences {
            use_nfc: true,
            first_execution: false,
            ..Default::default()
        };
        let mut h = Harness::signing("firmante-rsa.p12", prefs, dir.path());
        h.tap("home.sign_file");
        h.open_document("hola.txt", testdata("cades/data/hola.txt"));
        assert_eq!(h.dialog_id(), Some("cert_type"));
        h.tap("cert_type.dnie");
        assert_eq!(h.dialog_id(), Some("dnie_unavailable"));
        h.tap("dialog.ok");
        assert_eq!(h.dialog_id(), Some("cert_type"));
        h.tap("cert_type.certificate");
        assert_eq!(h.dialog_id(), None);
        assert_eq!(h.platform.calls_with("choose_certificate").len(), 1);
        h.choose_alias(None);
        assert_eq!(h.dialog_id(), Some("cert_type"), "sin elegir se vuelve a preguntar");
        h.tap("dialog.close");
        assert_eq!(h.dialog_id(), None);
        assert!(!h.shell.flows().signing());
    }

    /// Importación de un PKCS#12 en KeyChain (§4.8) con su error y «Volver a intentarlo».
    #[test]
    fn importar_certificado() {
        let _lock = test_lock();
        let mut h = Harness::at_home();
        h.tap("home.add_cert");
        h.tap("import.continue");
        h.tap("import.add");
        assert_eq!(h.screen(), "home");
        assert_eq!(
            h.platform.calls_with("open_document"),
            ["open_document 1 application/x-pkcs12"]
        );
        let p12 = crate::testing::test_p12("firmante-rsa.p12");
        h.open_document("firmante.p12", p12.clone());
        assert_eq!(
            h.platform.calls_with("install_certificate"),
            [format!("install_certificate 2 {}", p12.len())]
        );
        h.bridge.post(PlatformEvent::CertificateInstalled { request: 2 });
        h.frames(2);
        assert_eq!(h.dialog_title(), "Certificado añadido");
        h.tap("dialog.ok");
        // Error al leer el fichero: «No hemos podido añadir tu certificado».
        h.tap("home.add_cert");
        h.tap("import.continue");
        h.tap("import.add");
        h.bridge.post(PlatformEvent::RequestFailed {
            request: 3,
            cancelled: false,
            message: Some("java.io.IOException".into()),
        });
        h.frames(2);
        assert_eq!(h.dialog_id(), Some("cant_add_cert"));
        assert!(matches!(h.shell.dialog(), Some(Dialog::Prompt(p)) if p.body.starts_with("AA201100 - ")));
        h.tap("dialog.ok");
        assert_eq!(h.platform.calls_with("open_document").len(), 3, "«Volver a intentarlo»");
        // Instalación cancelada: nada.
        h.open_document("firmante.p12", p12);
        h.bridge.post(PlatformEvent::RequestFailed {
            request: 5,
            cancelled: true,
            message: None,
        });
        h.frames(2);
        assert_eq!(h.dialog_id(), None);
    }

    /// Documentos que no se pueden leer: demasiado grandes (AA200105) o con error (AA200102).
    #[test]
    fn errores_al_leer_el_documento() {
        let _lock = test_lock();
        let mut h = Harness::at_home();
        for (message, code) in [
            (crate::bridge::DOCUMENT_TOO_LARGE, "AA200105"),
            ("IOException", "AA200102"),
        ] {
            h.tap("home.sign_file");
            let request = h.last_request("open_document");
            h.bridge.post(PlatformEvent::RequestFailed {
                request,
                cancelled: false,
                message: Some(message.into()),
            });
            h.frames(2);
            match h.shell.dialog() {
                Some(Dialog::Message { body, .. }) => assert!(body.starts_with(code), "{body}"),
                other => panic!("se esperaba el error {code}: {other:?}"),
            }
            h.tap("dialog.ok");
        }
    }

    #[test]
    fn enlace_web_en_frio_salta_el_arranque() {
        let _lock = test_lock();
        let mut h = Harness::in_memory();
        h.bridge.post(PlatformEvent::ViewIntent {
            uri: "afirma://sign?op=sign&id=1".into(),
        });
        h.frames(2);
        assert_eq!(h.shell.nav().ids(), ["intro", "web_request"]);
        h.back();
        assert_eq!(h.screen(), "intro");
    }

    #[test]
    fn todas_las_pantallas_se_dibujan_en_todos_los_idiomas_y_tamanos() {
        let _lock = test_lock();
        let screens = [
            Screen::Splash,
            Screen::Intro,
            Screen::Conditions {
                privacy: true,
                legal: false,
            },
            Screen::Home,
            Screen::Settings,
            Screen::Language,
            Screen::SignConfiguration(crate::nav::SignConfigDraft::from_prefs(&Preferences::default())),
            Screen::TrustedDomains { text: "a.es".into() },
            Screen::SignsRecord {
                records: vec![SignRecord::now(
                    RecordKind::Web,
                    RecordOperation::Cosign,
                    None,
                    Some("sede"),
                )],
            },
            Screen::Faq { open: [true; 3] },
            Screen::HelpDnieNfc,
            Screen::HelpVisibleSign,
            Screen::HelpTrustedDomains,
            Screen::HelpImportCerts,
            Screen::AccessibilityStatement,
            Screen::LegalNotice,
            Screen::PrivacyPolicy,
            Screen::Version,
            Screen::ImportInstructions { page: 1 },
            Screen::Certificates,
            Screen::WebSigningInfo,
            Screen::VisibleSignature {
                selection: Some([0.1, 0.2, 0.5, 0.4]),
                drag: None,
            },
            Screen::WebRequest,
        ];
        let dialogs = [
            Dialog::Help,
            Dialog::ConfigNfc,
            Dialog::ConfirmClearHistory,
            Dialog::LanguagePicker,
            Dialog::CacheMinutes {
                selected: CacheMinutes::Sixty,
            },
        ];
        for (language, size, night, scale) in [
            (Language::Es, vec2(412.0, 915.0), false, 1.0),
            (Language::Eu, vec2(915.0, 412.0), true, 1.3),
            (Language::CaValencia, vec2(320.0, 640.0), false, 2.0),
        ] {
            let mut h = Harness::in_memory();
            h.size = size;
            h.bridge.post(PlatformEvent::Configuration(DeviceConfig {
                locale: language.tag().into(),
                night,
                font_scale: scale,
                has_nfc: true,
            }));
            for screen in &screens {
                h.shell.nav.reset(screen.clone());
                h.frames(2);
                assert!(
                    !h.shell.target_ids().is_empty() || matches!(screen, Screen::Splash),
                    "{}: sin elementos pulsables",
                    screen.id()
                );
            }
            h.shell.nav.reset(Screen::Home);
            for dialog in &dialogs {
                h.shell.dialog = Some(dialog.clone());
                h.frames(3);
            }
        }
        i18n::set_language(Language::Es);
    }
}
