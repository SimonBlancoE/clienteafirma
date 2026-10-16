//! Página "Herramientas": huellas digitales, validación de certificados,
//! diagnóstico del sistema y restauración de la integración con navegadores.

use eframe::egui::{self, CornerRadius, FontId, Frame, Margin, RichText, Stroke, Ui};

use crate::ui::icons;
use crate::ui::theme::{Palette, semibold};
use crate::ui::widgets::{self, ButtonKind, CalloutKind};

/// Herramientas disponibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    HashFile,
    CheckHashFile,
    HashDir,
    CheckHashDir,
    ValidateCert,
    Doctor,
    RestoreBrowsers,
}

impl Tool {
    pub fn title(self) -> &'static str {
        match self {
            Tool::HashFile => "Calcular huella digital",
            Tool::CheckHashFile => "Comprobar huella digital",
            Tool::HashDir => "Huellas de una carpeta",
            Tool::CheckHashDir => "Comprobar una carpeta",
            Tool::ValidateCert => "Validar un certificado",
            Tool::Doctor => "Diagnóstico del sistema",
            Tool::RestoreBrowsers => "Restaurar navegadores",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Tool::HashFile => "Obtén la huella (SHA-256, SHA-512…) de un fichero para comprobar más tarde que no ha cambiado.",
            Tool::CheckHashFile => "Comprueba que un fichero coincide con una huella digital guardada.",
            Tool::HashDir => "Genera un fichero con las huellas de todos los documentos de una carpeta.",
            Tool::CheckHashDir => "Verifica una carpeta contra su fichero de huellas e informa de cambios.",
            Tool::ValidateCert => "Consulta por OCSP o CRL si un certificado está revocado.",
            Tool::Doctor => "Comprueba que AutoFirma está bien integrado con tus navegadores y tarjetas.",
            Tool::RestoreBrowsers => "Reinstala el certificado local y el protocolo afirma:// en los navegadores.",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Tool::HashFile => icons::FINGERPRINT,
            Tool::CheckHashFile => icons::CHECK_SQUARE_OFFSET,
            Tool::HashDir => icons::FOLDER_SIMPLE_LOCK,
            Tool::CheckHashDir => icons::FOLDER_SIMPLE_STAR,
            Tool::ValidateCert => icons::SHIELD_CHECK,
            Tool::Doctor => icons::STETHOSCOPE,
            Tool::RestoreBrowsers => icons::BROWSERS,
        }
    }
}

/// Resultado de una comprobación del diagnóstico.
#[derive(Debug, Clone)]
pub struct CheckRow {
    pub ok: Option<bool>,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ToolsAction {
    Open(Tool),
    Close,
    PickInput,
    PickSecondary,
    Run,
    RunDoctor,
    RepairAll,
}

#[derive(Debug)]
pub struct ToolsPage {
    pub open: Option<Tool>,
    pub input: Option<std::path::PathBuf>,
    pub secondary: Option<std::path::PathBuf>,
    pub algorithm: String,
    pub format: String,
    pub recursive: bool,
    pub copy_clipboard: bool,
    pub running: bool,
    pub result: Option<(CalloutKind, String, Option<String>)>,
    pub doctor: Vec<CheckRow>,
}

impl Default for ToolsPage {
    fn default() -> Self {
        ToolsPage {
            open: None,
            input: None,
            secondary: None,
            algorithm: "SHA-256".into(),
            format: "Hexadecimal en ASCII (Base16)".into(),
            recursive: false,
            copy_clipboard: true,
            running: false,
            result: None,
            doctor: Vec::new(),
        }
    }
}

const SECTIONS: &[(&str, &[Tool])] = &[
    ("Huellas digitales", &[Tool::HashFile, Tool::CheckHashFile, Tool::HashDir, Tool::CheckHashDir]),
    ("Certificados", &[Tool::ValidateCert]),
    ("Integración con el sistema", &[Tool::Doctor, Tool::RestoreBrowsers]),
];

impl ToolsPage {
    pub fn ui(&mut self, ui: &mut Ui, p: &Palette) -> Vec<ToolsAction> {
        let mut actions = Vec::new();
        if let Some(tool) = self.open {
            self.tool_view(ui, p, tool, &mut actions);
            return actions;
        }
        widgets::page_header(ui, p, "Herramientas", Some("Utilidades para comprobar documentos, certificados y la instalación."));
        for (title, tools) in SECTIONS {
            widgets::section_title(ui, p, title);
            ui.add_space(6.0);
            let cols = if ui.available_width() > 640.0 { 2 } else { 1 };
            egui::Grid::new(("tools", *title)).num_columns(cols).spacing([12.0, 12.0]).show(ui, |ui| {
                let w = (ui.available_width() - 12.0 * (cols as f32 - 1.0)) / cols as f32;
                for (i, t) in tools.iter().enumerate() {
                    let r = Frame::new()
                        .fill(p.surface)
                        .stroke(Stroke::new(1.0, p.border))
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::same(16))
                        .show(ui, |ui| {
                            ui.set_width(w - 32.0);
                            ui.set_min_height(64.0);
                            ui.horizontal_top(|ui| {
                                widgets::status_circle(ui, t.icon(), 40.0, p.primary, p.primary_soft);
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(t.title()).font(FontId::new(14.5, semibold())));
                                    ui.add(egui::Label::new(RichText::new(t.description()).size(12.5).color(p.text_muted)).wrap());
                                });
                            });
                        });
                    let resp = ui.interact(r.response.rect, egui::Id::unique(("tool", *t as u8)), egui::Sense::click());
                    if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        actions.push(ToolsAction::Open(*t));
                    }
                    if (i + 1) % cols == 0 {
                        ui.end_row();
                    }
                }
            });
            ui.add_space(16.0);
        }
        actions
    }

    fn tool_view(&mut self, ui: &mut Ui, p: &Palette, tool: Tool, actions: &mut Vec<ToolsAction>) {
        if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::ARROW_LEFT), "Herramientas", true).clicked() {
            actions.push(ToolsAction::Close);
        }
        ui.add_space(6.0);
        widgets::page_header(ui, p, tool.title(), Some(tool.description()));
        widgets::card(ui, p, |ui| match tool {
            Tool::HashFile | Tool::CheckHashFile | Tool::HashDir | Tool::CheckHashDir | Tool::ValidateCert => {
                let (first, second) = match tool {
                    Tool::HashFile => ("Fichero", None),
                    Tool::CheckHashFile => ("Fichero de datos", Some("Fichero de huella (.hexhash, .hashb64, .hash)")),
                    Tool::HashDir => ("Carpeta", None),
                    Tool::CheckHashDir => ("Carpeta", Some("Fichero de huellas (.hashfiles, .txthashfiles)")),
                    _ => ("Certificado (.cer, .crt, .pem)", None),
                };
                path_row(ui, p, first, self.input.as_deref(), || actions.push(ToolsAction::PickInput));
                if let Some(label) = second {
                    path_row(ui, p, label, self.secondary.as_deref(), || actions.push(ToolsAction::PickSecondary));
                }
                if matches!(tool, Tool::HashFile | Tool::HashDir) {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Algoritmo").color(p.text_muted));
                        egui::ComboBox::from_id_salt("hash_alg").selected_text(&self.algorithm).show_ui(ui, |ui| {
                            for a in ["SHA-256", "SHA-1", "SHA-384", "SHA-512"] {
                                ui.selectable_value(&mut self.algorithm, a.to_string(), a);
                            }
                        });
                        if tool == Tool::HashFile {
                            ui.add_space(12.0);
                            ui.label(RichText::new("Formato").color(p.text_muted));
                            egui::ComboBox::from_id_salt("hash_fmt").selected_text(&self.format).show_ui(ui, |ui| {
                                for f in ["Hexadecimal en ASCII (Base16)", "Base64", "Binario"] {
                                    ui.selectable_value(&mut self.format, f.to_string(), f);
                                }
                            });
                        } else {
                            ui.add_space(12.0);
                            ui.checkbox(&mut self.recursive, "Incluir subcarpetas");
                        }
                    });
                    if tool == Tool::HashFile {
                        ui.checkbox(&mut self.copy_clipboard, "Copiar la huella al portapapeles");
                    }
                }
                ui.add_space(10.0);
                let ready = self.input.is_some() && (second.is_none() || self.secondary.is_some()) && !self.running;
                let label = match tool {
                    Tool::HashFile | Tool::HashDir => "Calcular y guardar",
                    Tool::ValidateCert => "Validar",
                    _ => "Comprobar",
                };
                ui.horizontal(|ui| {
                    if widgets::button(ui, p, ButtonKind::Primary, Some(icons::PLAY), label, ready).clicked() {
                        actions.push(ToolsAction::Run);
                    }
                    if self.running {
                        ui.spinner();
                    }
                });
            }
            Tool::Doctor | Tool::RestoreBrowsers => {
                if self.doctor.is_empty() && !self.running {
                    ui.label(RichText::new("Pulsa \"Comprobar\" para revisar la instalación.").color(p.text_muted));
                }
                for row in &self.doctor {
                    ui.horizontal_top(|ui| {
                        let (g, c) = match row.ok {
                            Some(true) => (icons::CHECK_CIRCLE, p.success),
                            Some(false) => (icons::X_CIRCLE, p.danger),
                            None => (icons::MINUS_CIRCLE, p.text_faint),
                        };
                        ui.label(RichText::new(g).family(crate::ui::theme::icons_fill()).size(18.0).color(c));
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&row.title).font(FontId::new(13.5, semibold())));
                            if !row.detail.is_empty() {
                                ui.label(RichText::new(&row.detail).size(12.5).color(p.text_muted));
                            }
                        });
                    });
                    ui.add_space(4.0);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::STETHOSCOPE), "Comprobar", !self.running).clicked() {
                        actions.push(ToolsAction::RunDoctor);
                    }
                    if widgets::button(ui, p, ButtonKind::Primary, Some(icons::WRENCH), "Reparar todo", !self.running).clicked() {
                        actions.push(ToolsAction::RepairAll);
                    }
                    if self.running {
                        ui.spinner();
                    }
                });
            }
        });
        if let Some((kind, title, body)) = &self.result {
            ui.add_space(12.0);
            widgets::callout(ui, p, *kind, title, body.as_deref());
        }
    }
}

fn path_row(ui: &mut Ui, p: &Palette, label: &str, value: Option<&std::path::Path>, mut on_pick: impl FnMut()) {
    ui.label(RichText::new(label).size(13.0).color(p.text_muted));
    ui.horizontal(|ui| {
        let text = value.map(|v| v.display().to_string()).unwrap_or_else(|| "Ninguno seleccionado".into());
        Frame::new().fill(p.surface_alt).corner_radius(CornerRadius::same(8)).inner_margin(Margin::symmetric(10, 8)).show(ui, |ui| {
            ui.set_width((ui.available_width() - 130.0).max(200.0));
            ui.label(RichText::new(text).size(13.0).color(if value.is_some() { p.text } else { p.text_faint }));
        });
        if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::FOLDER_OPEN), "Examinar", true).clicked() {
            on_pick();
        }
    });
    ui.add_space(4.0);
}
