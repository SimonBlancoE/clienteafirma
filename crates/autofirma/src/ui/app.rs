//! Ventana principal de AutoFirma-rs.

use eframe::egui::{self, Frame, Margin, RichText, ScrollArea, Stroke, Ui};

use super::cert_picker::CertPicker;
use super::pages::certificates::CertificatesPage;
use super::pages::sign::SignPage;
use super::pages::tools::ToolsPage;
use super::pages::verify::VerifyPage;
use super::theme::{self, Palette, ThemeChoice};
use super::{icons, widgets};
use crate::i18n::{tr, trf};

/// Páginas principales de la aplicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Sign,
    Verify,
    Certificates,
    Tools,
    Settings,
    Help,
}

impl Page {
    pub fn label(self) -> &'static str {
        match self {
            Page::Sign => tr("Firmar"),
            Page::Verify => tr("Verificar firmas"),
            Page::Certificates => tr("Mis certificados"),
            Page::Tools => tr("Herramientas"),
            Page::Settings => tr("Preferencias"),
            Page::Help => tr("Ayuda"),
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Page::Sign => icons::PEN_NIB,
            Page::Verify => icons::SEAL_CHECK,
            Page::Certificates => icons::IDENTIFICATION_CARD,
            Page::Tools => icons::WRENCH,
            Page::Settings => icons::GEAR_SIX,
            Page::Help => icons::QUESTION,
        }
    }
}

pub struct AutoFirmaApp {
    pub(crate) page: Page,
    pub(crate) theme: ThemeChoice,
    palette: Palette,
    applied: Option<Palette>,
    files_hovering: bool,
    pub(crate) sign: SignPage,
    pub(crate) verify: VerifyPage,
    pub(crate) certificates: CertificatesPage,
    pub(crate) tools: ToolsPage,
    pub(crate) picker: CertPicker,
    pub(crate) visible_sig: super::visible_sig::VisibleSigEditor,
    pub(crate) settings: super::pages::settings::SettingsPage,
    pub(crate) prefs: Box<dyn super::pages::settings::PrefStore>,
    /// Petición en curso desde la web (modo compacto).
    pub(crate) request: Option<super::request_view::RequestView>,
    pub(crate) rt: super::flows::Runtime,
    /// Modo protocolo (`afirma://`).
    pub(crate) proto: Option<super::protocol_flow::ProtocolState>,
    pending_zoom: Option<f32>,
    /// La integración con el navegador necesita reparación (aviso en "Firmar").
    pub(crate) integration_needed: bool,
    integration_job: Option<crate::services::task::Job<(), bool>>,
    asking_close: bool,
    prefs_close_now: bool,
    /// Versión nueva publicada (aviso en la barra lateral).
    update: Option<crate::services::updater::UpdateInfo>,
    update_job: Option<crate::services::task::Job<(), Option<crate::services::updater::UpdateInfo>>>,
    pending_import: Option<afirma_system::prefs::PreparedImport>,
    confirm_restore: bool,
    proxy_job: Option<crate::services::task::Job<(), Result<(), String>>>,
    /// macOS: ventana aún oculta a la espera de eventos de apertura del sistema.
    launch_grace: Option<std::time::Instant>,
    dont_ask_close: bool,
}

impl AutoFirmaApp {
    pub fn new(cc: &eframe::CreationContext<'_>, start: crate::launch::GuiStart) -> Self {
        theme::install_fonts(&cc.egui_ctx);
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let prefs: Box<dyn super::pages::settings::PrefStore> = if std::env::var_os("AF_DEMO").is_some() {
            Box::new(super::pages::settings::MemoryPrefs { defaults: super::pages::settings::default_values(), ..Default::default() })
        } else {
            crate::services::prefs::load()
        };
        // El idioma se fija antes de crear las páginas, que guardan algunos
        // textos iniciales. `AF_LOCALE` lo sustituye (capturas de pantalla).
        if let Some(loc) = prefs.get("default.locale") {
            crate::i18n::set_locale(&loc);
        }
        if let Ok(loc) = std::env::var("AF_LOCALE") {
            crate::i18n::set_locale(&loc);
        }
        let mut app = AutoFirmaApp {
            page: Page::Sign,
            theme: ThemeChoice::System,
            palette: Palette::LIGHT,
            applied: None,
            files_hovering: false,
            sign: SignPage::default(),
            verify: VerifyPage::default(),
            certificates: CertificatesPage::default(),
            tools: ToolsPage::default(),
            picker: CertPicker::default(),
            visible_sig: Default::default(),
            settings: Default::default(),
            request: None,
            rt: super::flows::Runtime::new(&cc.egui_ctx),
            proto: None,
            pending_zoom: None,
            integration_needed: false,
            integration_job: None,
            asking_close: false,
            prefs_close_now: false,
            update: None,
            update_job: None,
            pending_import: None,
            confirm_restore: false,
            proxy_job: None,
            launch_grace: None,
            dont_ask_close: false,
            prefs,
        };
        tracing::debug!("arranque: preferencias cargadas");
        app.theme = theme_from_pref(app.prefs.get("uiTheme").as_deref());
        {
            let prefs = &app.prefs;
            app.rt.store_spec = crate::services::certs::spec_from_prefs(&|k| prefs.get(k));
        }
        tracing::debug!("arranque: almacén por defecto {:?}", app.rt.store_spec);
        if let Some(scale) = app.prefs.get("uiScale").and_then(|v| v.parse::<f32>().ok()) {
            cc.egui_ctx.set_zoom_factor(scale.clamp(0.8, 1.6));
        }
        if let Ok(demo) = std::env::var("AF_DEMO") {
            super::demo::load(&mut app, &demo, &cc.egui_ctx);
        }
        if crate::platform::launch_events_by_message() && start.is_empty() && std::env::var_os("AF_DEMO").is_none() {
            app.launch_grace = Some(std::time::Instant::now());
        }
        crate::platform::init(&cc.egui_ctx);
        app.rt.cli_sign = start.cli_sign;
        if !start.sign_files.is_empty() {
            app.load_files(&cc.egui_ctx, start.sign_files);
        }
        if let Some(h) = start.hash {
            app.start_hash_request(&cc.egui_ctx, h);
        }
        if let Some(url) = start.protocol_url {
            let rx = crate::services::protocol::spawn_launcher(url, cc.egui_ctx.clone());
            app.proto = Some(super::protocol_flow::ProtocolState::new(rx));
        }
        if app.proto.is_none() && std::env::var_os("AF_DEMO").is_none() {
            crate::services::config_verifier::spawn_daily_update();
            let prefs = &app.prefs;
            if crate::services::updater::enabled(&|k| prefs.get(k)) {
                app.update_job = Some(crate::services::task::Job::spawn(&cc.egui_ctx, "version", |_| {
                    crate::services::updater::check_daily()
                }));
            }
            app.integration_job = Some(crate::services::task::Job::spawn(&cc.egui_ctx, "integracion", |_| {
                crate::services::tools::integration_needed()
            }));
        }
        if let Some(v) = start.verify_file {
            app.verify_path(&cc.egui_ctx, v);
        }
        // Almacén por defecto sustituible (pruebas y despliegues): `AF_STORE=pkcs12:/ruta` o `pkcs11:/ruta`.
        if let Ok(spec) = std::env::var("AF_STORE")
            && let Ok(parsed) = afirma_keystores::selection::parse_cli_store(Some(&spec), afirma_keystores::Os::current()) {
                app.rt.store_spec = parsed;
            }
        app
    }

    /// Modo compacto para peticiones desde la web.
    fn request_ui(&mut self, ui: &mut Ui) {
        let p = self.palette;
        let ctx = ui.ctx().clone();
        let event = egui::CentralPanel::no_frame()
            .frame(Frame::new().fill(p.surface).inner_margin(Margin::symmetric(26, 22)))
            .show(ui, |ui| self.request.as_mut().map(|r| r.ui(ui, &p)))
            .inner;
        if self.proto.is_some() {
            self.protocol_ui(&ctx, event);
        } else if let Some(super::request_view::RequestEvent::Close) = event {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        super::dialogs::show_inbox(&ctx, &p, &mut self.rt.inbox);
    }

    fn handle_settings_actions(&mut self, ctx: &egui::Context, actions: Vec<super::pages::settings::SettingsAction>) {
        use super::pages::settings::SettingsAction;
        for a in actions {
            match a {
                SettingsAction::Save => {
                    for (k, v) in std::mem::take(&mut self.settings.pending) {
                        self.prefs.set(&k, v.as_deref());
                    }
                    self.after_prefs_changed();
                }
                SettingsAction::Discard => self.settings.pending.clear(),
                SettingsAction::Export => {
                    let content = match self.prefs.export_config() {
                        Ok(c) => c,
                        Err(e) => {
                            self.settings.message = Some((widgets::CalloutKind::Error, e));
                            continue;
                        }
                    };
                    let Some(path) = rfd::FileDialog::new()
                        .set_title(tr("Exportar configuración"))
                        .set_file_name("configuracion.afconfig")
                        .add_filter(tr("Configuración de AutoFirma"), &["afconfig"])
                        .save_file()
                    else {
                        continue;
                    };
                    self.settings.message = Some(match std::fs::write(&path, content) {
                        Ok(()) => (widgets::CalloutKind::Success, trf("Configuración exportada a {0}", &[&path.display()])),
                        Err(e) => (widgets::CalloutKind::Error, trf("No se ha podido guardar el fichero: {0}", &[&e])),
                    });
                }
                SettingsAction::Import => {
                    let Some(path) = rfd::FileDialog::new()
                        .set_title(tr("Importar configuración"))
                        .add_filter(tr("Configuración de AutoFirma"), &["afconfig", "xml", "plist"])
                        .pick_file()
                    else {
                        continue;
                    };
                    let prepared = std::fs::read(&path).map_err(|e| e.to_string()).and_then(|d| self.prefs.prepare_import(&d));
                    match prepared {
                        Ok(p) => self.pending_import = Some(p),
                        Err(e) => {
                            self.settings.message = Some((widgets::CalloutKind::Error, trf("No se puede importar la configuración: {0}", &[&e])))
                        }
                    }
                }
                SettingsAction::RestoreDefaults => self.confirm_restore = true,
                SettingsAction::TestProxy => {
                    // Con los valores en pantalla, aunque no se hayan guardado.
                    let mut values = std::collections::HashMap::new();
                    for key in ["proxyType", "proxySelected", "proxyHost", "proxyPort", "proxyUsername", "proxyPassword", "proxyExcludedUrls", "secureConnections", "secureDomainsList"] {
                        let v = match self.settings.pending.get(key) {
                            Some(v) => v.clone(),
                            None => self.prefs.get(key),
                        };
                        if let Some(v) = v {
                            values.insert(key.to_string(), v);
                        }
                    }
                    self.settings.message = Some((widgets::CalloutKind::Info, tr("Comprobando la conexión…").into()));
                    self.proxy_job = Some(crate::services::task::Job::spawn(ctx, "proxy", move |_| {
                        crate::services::network::test(&|k| values.get(k).cloned())
                    }));
                }
            }
        }
    }

    /// Aplica las preferencias recién guardadas (tema, tamaño, idioma, almacén y red).
    fn after_prefs_changed(&mut self) {
        self.theme = theme_from_pref(self.prefs.get("uiTheme").as_deref());
        if let Some(scale) = self.prefs.get("uiScale").and_then(|v| v.parse::<f32>().ok()) {
            self.pending_zoom = Some(scale.clamp(0.8, 1.6));
        }
        if let Some(loc) = self.prefs.get("default.locale") {
            crate::i18n::set_locale(&loc);
        }
        // Cambiar el almacén por defecto obliga a recargarlo.
        let prefs = &self.prefs;
        let spec = crate::services::certs::spec_from_prefs(&|k| prefs.get(k));
        if spec != self.rt.store_spec {
            self.rt.store_spec = spec;
            self.rt.store = None;
        }
        crate::services::network::install(&|k| prefs.get(k));
    }

    /// Diálogos de Preferencias: confirmación de importación y de restauración,
    /// y resultado de la comprobación del proxy.
    fn settings_dialogs(&mut self, ctx: &egui::Context) {
        let p = self.palette;
        if let Some(job) = &mut self.proxy_job {
            for ev in job.poll() {
                if let crate::services::task::JobEvent::Done(r) = ev {
                    self.settings.message = Some(match r {
                        Ok(()) => (widgets::CalloutKind::Success, tr("Conexión correcta con la configuración de red indicada").into()),
                        Err(e) => (widgets::CalloutKind::Error, trf("No se ha podido conectar: {0}", &[&e])),
                    });
                }
            }
            if job.is_finished() {
                self.proxy_job = None;
            }
        }
        if let Some(prepared) = &self.pending_import {
            let text = prepared.confirmation_text();
            if let Some(yes) = super::dialogs::confirm_modal(ctx, &p, tr("Importar configuración"), &text, tr("Importar"), false, false) {
                let prepared = self.pending_import.take().expect("importación pendiente");
                if yes {
                    self.settings.pending.clear();
                    self.settings.message = Some(match self.prefs.apply_import(&prepared) {
                        Ok(summary) => (widgets::CalloutKind::Success, summary),
                        Err(e) => (widgets::CalloutKind::Error, trf("No se ha podido importar la configuración: {0}", &[&e])),
                    });
                    self.after_prefs_changed();
                }
            }
        }
        if self.confirm_restore {
            let text = tr("Se borrará tu configuración personalizada y se usarán los valores de fábrica (o los fijados por tu organización). Las tarjetas añadidas se conservan.");
            if let Some(yes) = super::dialogs::confirm_modal(ctx, &p, tr("Restaurar valores de fábrica"), text, tr("Restaurar"), false, false) {
                self.confirm_restore = false;
                if yes {
                    self.settings.pending.clear();
                    self.prefs.restore_defaults();
                    self.after_prefs_changed();
                    self.settings.message = Some((widgets::CalloutKind::Success, tr("Se han restaurado los valores de fábrica").into()));
                }
            }
        }
    }

    /// Confirmación al cerrar (`omitAskOnClose`) y aviso si hay una firma en curso.
    fn close_confirmation(&mut self, ctx: &egui::Context) {
        if self.proto.is_some() {
            return;
        }
        let busy = self.rt.sign_job.is_some();
        if ctx.input(|i| i.viewport().close_requested()) && !self.asking_close {
            let ask = !self.prefs_close_now && (busy || !self.pref_bool("omitAskOnClose", false));
            if ask {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.asking_close = true;
            }
        }
        if !self.asking_close {
            return;
        }
        let p = self.palette;
        let msg = if busy { tr("Hay una firma en curso. Si cierras ahora se interrumpirá.") } else { tr("¿Quieres cerrar AutoFirma?") };
        let mut decision = None;
        egui::Modal::new(egui::Id::unique("close_dialog")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.label(RichText::new(msg).size(14.5));
            if !busy {
                ui.checkbox(&mut self.dont_ask_close, tr("No volver a preguntar"));
            }
            ui.add_space(10.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button(ui, &p, widgets::ButtonKind::Primary, None, tr("Cerrar"), true).clicked() {
                    decision = Some(true);
                }
                if widgets::button(ui, &p, widgets::ButtonKind::Secondary, None, tr("Cancelar"), true).clicked() {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                if self.dont_ask_close {
                    self.prefs.set("omitAskOnClose", Some("true"));
                }
                self.asking_close = false;
                // Segunda petición: ya no se pregunta.
                self.prefs_close_now = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Some(false) => self.asking_close = false,
            None => {}
        }
    }

    /// Peticiones de apertura del sistema (macOS: URL afirma:// y ficheros
    /// abiertos desde el Finder o el Dock).
    fn pump_platform(&mut self, ctx: &egui::Context) {
        use crate::platform::Opened;
        for item in crate::platform::take_opened() {
            match item {
                Opened::Url(url) => {
                    // Cada invocación del navegador se atiende en su propio
                    // proceso, con su ventana compacta, como en la línea de
                    // comandos de los demás sistemas.
                    let spawned = std::env::current_exe().and_then(|exe| std::process::Command::new(exe).arg(&url).spawn());
                    if let Err(e) = spawned {
                        tracing::error!("No se ha podido atender la URL del navegador: {e}");
                    }
                    if self.launch_grace.take().is_some() {
                        // La aplicación se abrió solo para esta URL.
                        self.prefs_close_now = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        return;
                    }
                }
                Opened::Focus => {
                    self.launch_grace = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Opened::File(path) => {
                    if self.proto.is_some() {
                        continue;
                    }
                    self.launch_grace = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
                    if matches!(ext.as_str(), "csig" | "xsig") {
                        self.verify_path(ctx, path);
                    } else {
                        self.load_files(ctx, vec![path]);
                    }
                }
            }
        }
        if let Some(t) = self.launch_grace {
            if t.elapsed() >= std::time::Duration::from_millis(700) {
                self.launch_grace = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
        }
    }

    fn on_help_actions(&mut self, ctx: &egui::Context, actions: Vec<super::pages::help::HelpAction>) {
        use super::pages::help::HelpAction;
        for a in actions {
            match a {
                HelpAction::OpenUrl(u) => {
                    let _ = crate::services::desktop::open(std::path::Path::new(&u));
                }
                HelpAction::OpenLogs => {
                    let _ = crate::services::desktop::reveal(&crate::logging::log_path());
                }
                HelpAction::CopyDiagnostics => {
                    let info = trf(
                        "AutoFirma-rs {0}\nSistema: {1} {2}\nAlmacén por defecto: {3}\nIdioma: {4}",
                        &[
                            &env!("CARGO_PKG_VERSION"),
                            &std::env::consts::OS,
                            &std::env::consts::ARCH,
                            &self.rt.store_spec.display_name(),
                            &crate::i18n::locale(),
                        ],
                    );
                    ctx.copy_text(info);
                    self.rt.toast = Some((tr("Información copiada al portapapeles").into(), std::time::Instant::now()));
                }
            }
        }
    }

    /// Paleta activa.
    pub(crate) fn palette(&self) -> Palette {
        self.palette
    }

    /// Aviso temporal en la parte inferior.
    fn toast_ui(&mut self, ctx: &egui::Context) {
        let Some((msg, since)) = self.rt.toast.clone() else { return };
        if since.elapsed() > std::time::Duration::from_secs(5) {
            self.rt.toast = None;
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        let p = self.palette;
        egui::Area::new(egui::Id::unique("toast"))
            .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -24.0))
            .show(ctx, |ui| {
                Frame::new()
                    .fill(if p.dark { p.surface_alt } else { egui::Color32::from_rgb(0x1F, 0x24, 0x2C) })
                    .corner_radius(10)
                    .inner_margin(Margin::symmetric(16, 10))
                    .show(ui, |ui| {
                        ui.label(RichText::new(msg).color(egui::Color32::WHITE).size(13.5));
                    });
            });
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        let p = self.palette;
        egui::Panel::left("nav")
            .exact_size(232.0)
            .resizable(false)
            .frame(Frame::new().fill(p.sidebar).inner_margin(Margin::symmetric(14, 18)).stroke(Stroke::new(1.0, p.border)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    widgets::status_circle(ui, icons::PEN_NIB, 36.0, p.on_primary, p.primary);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.add_space(1.0);
                        ui.label(RichText::new("AutoFirma").font(egui::FontId::new(17.0, theme::bold())).color(p.text));
                        ui.label(RichText::new(tr("Firma electrónica")).size(12.0).color(p.text_faint));
                    });
                });
                ui.add_space(22.0);
                for page in [Page::Sign, Page::Verify, Page::Certificates, Page::Tools] {
                    if widgets::nav_item(ui, &p, page.icon(), page.label(), self.page == page).clicked() {
                        self.page = page;
                    }
                    ui.add_space(2.0);
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.label(RichText::new(trf("Versión {0}", &[&env!("CARGO_PKG_VERSION")])).size(11.5).color(p.text_faint));
                    if let Some(info) = &self.update {
                        let text = trf("Nueva versión {0} disponible", &[&info.version]);
                        let link = ui
                            .link(RichText::new(text).size(11.5).color(p.primary))
                            .on_hover_text(tr("Abre la página de descarga en el navegador"));
                        if link.clicked() {
                            let _ = crate::services::desktop::open(std::path::Path::new(&info.url));
                        }
                    }
                    ui.add_space(6.0);
                    for page in [Page::Help, Page::Settings] {
                        if widgets::nav_item(ui, &p, page.icon(), page.label(), self.page == page).clicked() {
                            self.page = page;
                        }
                        ui.add_space(2.0);
                    }
                });
            });
    }

}

impl eframe::App for AutoFirmaApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump_platform(ctx);
        // Con la ventana oculta (modo protocolo) también hay que atender las
        // peticiones de la página.
        if self.proto.is_some() {
            self.protocol_logic(ctx);
        }
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let system_dark = ctx.system_theme() == Some(egui::Theme::Dark);
        self.palette = self.theme.palette(system_dark);
        if self.applied != Some(self.palette) {
            theme::apply(&ctx, &self.palette, 1.0);
            self.applied = Some(self.palette);
        }
        self.files_hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if let Some(z) = self.pending_zoom.take() {
            ctx.set_zoom_factor(z);
        }
        self.pump_jobs(&ctx);
        if let Some(job) = &mut self.update_job {
            for ev in job.poll() {
                if let crate::services::task::JobEvent::Done(info) = ev {
                    self.update = info;
                }
            }
            if job.is_finished() {
                self.update_job = None;
            }
        }
        if let Some(job) = &mut self.integration_job {
            for ev in job.poll() {
                if let crate::services::task::JobEvent::Done(needed) = ev {
                    self.integration_needed = needed;
                }
            }
            if job.is_finished() {
                self.integration_job = None;
            }
        }
        self.close_confirmation(&ctx);
        self.handle_dropped_files(&ctx);
        if self.proto.is_some() {
            self.protocol_logic(&ctx);
        }
        if self.request.is_some() || self.proto.is_some() {
            if self.request.is_none() {
                // Esperando a la página: ventana mínima.
                let p = self.palette;
                egui::CentralPanel::no_frame().frame(Frame::new().fill(p.surface)).show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 2.0 - 30.0);
                        ui.spinner();
                        ui.label(tr("Atendiendo a la página web…"));
                    });
                });
                return;
            }
            self.request_ui(ui);
            return;
        }
        self.sidebar(ui);
        if self.page == Page::Settings && !self.settings.pending.is_empty() {
            let p = self.palette;
            let actions = egui::Panel::bottom("settings_bar")
                .frame(Frame::new().fill(p.surface).inner_margin(Margin::symmetric(36, 12)).stroke(Stroke::new(1.0, p.border)))
                .show(ui, |ui| self.settings.pending_bar(ui, &p))
                .inner;
            self.handle_settings_actions(&ctx, actions);
        }
        let p = self.palette;
        egui::CentralPanel::no_frame().frame(Frame::new().fill(p.bg).inner_margin(Margin::symmetric(36, 28))).show(ui, |ui| {
            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(900.0));
                match self.page {
                    Page::Sign => {
                        self.sign.integration_needed = self.integration_needed;
                        let actions = self.sign.ui(ui, &p, self.files_hovering);
                        self.on_sign_actions(&ctx, actions);
                    }
                    Page::Verify => {
                        let actions = self.verify.ui(ui, &p, self.files_hovering);
                        self.on_verify_actions(&ctx, actions);
                    }
                    Page::Certificates => {
                        self.ensure_cert_stores(&ctx);
                        let actions = self.certificates.ui(ui, &p);
                        self.on_certs_actions(&ctx, actions);
                    }
                    Page::Tools => {
                        let actions = self.tools.ui(ui, &p);
                        self.on_tools_actions(&ctx, actions);
                    }
                    Page::Settings => {
                        let actions = self.settings.ui(ui, &p, self.prefs.as_ref());
                        self.handle_settings_actions(&ctx, actions);
                    }
                    Page::Help => {
                        let actions = super::pages::help::ui(ui, &p);
                        self.on_help_actions(&ctx, actions);
                    }
                }
            });
        });
        self.sign_flow_dialogs(&ctx);
        let ev = self.picker.show(&ctx, &p);
        self.on_picker_event(&ctx, ev);
        super::dialogs::show_inbox(&ctx, &p, &mut self.rt.inbox);
        self.settings_dialogs(&ctx);
        self.toast_ui(&ctx);
    }
}

/// Tema según la preferencia `uiTheme`.
fn theme_from_pref(v: Option<&str>) -> ThemeChoice {
    match v {
        Some("light") => ThemeChoice::Light,
        Some("dark") => ThemeChoice::Dark,
        Some("contrast") => ThemeChoice::HighContrast,
        _ => ThemeChoice::System,
    }
}
