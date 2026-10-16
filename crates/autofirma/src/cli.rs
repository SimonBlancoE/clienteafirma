//! Línea de comandos (`sign`, `cosign`, `countersign`, `verify`,
//! `listaliases`, `batchsign`, `createdigest`, `checkdigest`, `install`,
//! `uninstall`, `doctor`, `restore-config`) con `afirma-cli`. Aquí se aportan
//! la contraseña por terminal, el selector gráfico de `-certgui`, las
//! preferencias, la consola de Windows y la apertura de la interfaz con `-gui`.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex};

use afirma_cli::{CertificateChoice, CertificateChooser, CertificateRequest, CliEnv, GuiOperation, GuiRequest};
use afirma_keystores::{PasswordCallback, PasswordRequest, PasswordResponse, Secret};
use eframe::egui;

use crate::launch::{CliSign, GuiStart};

/// Ejecuta la línea de comandos y devuelve el código de salida.
pub fn run(args: &[String]) -> i32 {
    attach_console();
    let prefs = preferences();
    let locale = prefs.get("default.locale").cloned();
    if let Some(l) = &locale {
        crate::i18n::set_locale(l);
    }
    let lookup = prefs.clone();
    let mut env = CliEnv::new("autofirma")
        .with_preferences(move |k| lookup.get(k).cloned())
        .with_password_callback(Arc::new(TerminalPassword))
        .with_certificate_chooser(Arc::new(GuiChooser))
        .with_system(Arc::new(afirma_cli::system_adapter::AfirmaSystemOps::detect()));
    env.version = format!("AutoFirma {}", env!("CARGO_PKG_VERSION"));
    env.os_locale = Some(crate::i18n::system_locale().to_string());
    let outcome = afirma_cli::run(args, &env);
    let print = |text: &str| {
        let mut out = std::io::stdout();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    };
    match outcome.gui {
        None => {
            print(&outcome.output);
            outcome.status
        }
        Some(GuiRequest::ErrorDialog { title, message }) => {
            let _ = rfd::MessageDialog::new()
                .set_level(rfd::MessageLevel::Error)
                .set_title(&title)
                .set_description(&message)
                .show();
            print(&outcome.output);
            outcome.status
        }
        Some(GuiRequest::Sign(req)) => {
            print(&outcome.output);
            let algorithm = req.algorithm_explicit.then(|| req.digest_algorithm.replace('-', ""));
            crate::run_gui(GuiStart {
                sign_files: vec![req.file],
                cli_sign: Some(CliSign {
                    format: req.format,
                    cosign: matches!(req.operation, GuiOperation::Cosign),
                    countersign: matches!(req.operation, GuiOperation::CountersignLeafs),
                    extra: req.extra_params,
                    algorithm,
                }),
                ..Default::default()
            })
        }
        Some(GuiRequest::Verify { file }) => {
            print(&outcome.output);
            crate::run_gui(GuiStart { verify_file: Some(file), ..Default::default() })
        }
        Some(GuiRequest::Hash(req)) => {
            print(&outcome.output);
            crate::run_gui(GuiStart { hash: Some(req), ..Default::default() })
        }
    }
}

/// Preferencias de la aplicación (incluidas las gestionadas por directivas).
fn preferences() -> Arc<HashMap<String, String>> {
    let store = crate::services::prefs::load();
    let mut map = HashMap::new();
    for key in crate::ui::pages::settings::ALL_KEYS.iter().copied().chain(["default.locale"]) {
        if let Some(v) = store.get(key) {
            map.insert(key.to_string(), v);
        }
    }
    Arc::new(map)
}

/// En Windows la aplicación es de ventana: la salida se envía a la consola
/// desde la que se lanzó (si la hay) y en UTF-8.
fn attach_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole, SetConsoleOutputCP};
        AttachConsole(ATTACH_PARENT_PROCESS);
        SetConsoleOutputCP(65001);
    }
}

/// Contraseñas y PIN por el terminal, sin eco. Sin terminal (scripts,
/// tareas programadas) no se pide nada, como la versión Java sin `-password`.
struct TerminalPassword;

impl PasswordCallback for TerminalPassword {
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse {
        if !std::io::stdin().is_terminal() {
            return PasswordResponse::NoPassword;
        }
        if let Some(retry) = &request.retry {
            eprintln!("{}", retry.message());
        }
        if let Some(n) = request.retries_left {
            eprintln!("Intentos restantes: {n}{}", if request.final_try { " (el siguiente fallo bloqueará la tarjeta)" } else { "" });
        }
        match rpassword::prompt_password(format!("{} ", request.prompt.trim_end())) {
            Ok(s) if !s.is_empty() => PasswordResponse::Provided { secret: Secret::new(s), remember: false },
            Ok(_) => PasswordResponse::NoPassword,
            Err(_) => PasswordResponse::Cancelled,
        }
    }

    fn is_interactive(&self) -> bool {
        std::io::stdin().is_terminal()
    }
}

/// Selector gráfico de certificados para `-certgui`: la misma lista que la
/// ventana principal, en una ventana propia.
struct GuiChooser;

impl CertificateChooser for GuiChooser {
    fn choose(&self, request: &CertificateRequest) -> Result<Option<CertificateChoice>, String> {
        let items: Vec<_> = request
            .candidates
            .iter()
            .filter_map(|e| crate::ui::model::CertItem::from_der(e.id.clone(), e.certificate.clone()))
            .collect();
        let result: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let out = result.clone();
        let mut picker = crate::ui::cert_picker::CertPicker { accept_label: "Seleccionar".into(), ..Default::default() };
        picker.open_with("Almacén indicado en -store", items);
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("Selección de certificado")
                .with_inner_size([620.0, 560.0])
                .with_app_id("autofirma"),
            persist_window: false,
            ..Default::default()
        };
        eframe::run_native(
            "AutoFirma",
            options,
            Box::new(move |cc| {
                crate::ui::theme::install_fonts(&cc.egui_ctx);
                Ok(Box::new(ChooserApp { picker, out, applied: None }))
            }),
        )
        .map_err(|e| format!("No se puede mostrar el dialogo de seleccion de certificado: {e}"))?;
        let alias = result.lock().ok().and_then(|g| g.clone());
        Ok(alias.map(|alias| CertificateChoice { store: request.store.clone(), alias }))
    }
}

struct ChooserApp {
    picker: crate::ui::cert_picker::CertPicker,
    out: Arc<Mutex<Option<String>>>,
    applied: Option<crate::ui::theme::Palette>,
}

impl eframe::App for ChooserApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        use crate::ui::cert_picker::PickerEvent;
        use crate::ui::widgets::{self, ButtonKind};
        let ctx = ui.ctx().clone();
        let p = crate::ui::theme::ThemeChoice::System.palette(ctx.system_theme() == Some(egui::Theme::Dark));
        if self.applied != Some(p) {
            crate::ui::theme::apply(&ctx, &p, 1.0);
            self.applied = Some(p);
        }
        let mut close = false;
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.bg).inner_margin(egui::Margin::same(18)))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Elige el certificado de firma").font(egui::FontId::new(18.0, crate::ui::theme::semibold())));
                ui.add_space(10.0);
                let h = ui.available_height() - 56.0;
                match self.picker.show_embedded(ui, &p, h) {
                    PickerEvent::Accepted(i) => {
                        if let (Some(c), Ok(mut out)) = (self.picker.certs.get(i), self.out.lock()) {
                            *out = Some(c.alias.clone());
                        }
                        close = true;
                    }
                    PickerEvent::Cancelled => close = true,
                    _ => {}
                }
                ui.add_space(10.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can = self.picker.selected.is_some();
                    if widgets::button(ui, &p, ButtonKind::Primary, None, "Seleccionar", can).clicked() {
                        if let (Some(c), Ok(mut out)) = (self.picker.selected.and_then(|i| self.picker.certs.get(i)), self.out.lock()) {
                            *out = Some(c.alias.clone());
                        }
                        close = true;
                    }
                    if widgets::button(ui, &p, ButtonKind::Secondary, None, "Cancelar", true).clicked() {
                        close = true;
                    }
                });
            });
        if close {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}
