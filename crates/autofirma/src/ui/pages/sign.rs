//! Página "Firmar": carga de documentos, opciones, firma y resultado.

use std::path::PathBuf;

use eframe::egui::{self, Align, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use crate::ui::icons;
use crate::ui::model::fmt_size;
use crate::ui::theme::{self, Palette, semibold};
use crate::ui::widgets::{self, ButtonKind, CalloutKind};

/// Tipo de documento detectado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    Pdf,
    Xml,
    FacturaE,
    Odf,
    Ooxml,
    /// Ya es una firma del formato indicado.
    Signature(String),
    Binary,
}

impl FileKind {
    pub fn label(&self) -> String {
        match self {
            FileKind::Pdf => "Documento PDF".into(),
            FileKind::Xml => "Documento XML".into(),
            FileKind::FacturaE => "Factura electrónica".into(),
            FileKind::Odf => "Documento OpenDocument".into(),
            FileKind::Ooxml => "Documento de Microsoft Office".into(),
            FileKind::Signature(f) => format!("Firma {f}"),
            FileKind::Binary => "Fichero".into(),
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            FileKind::Pdf => icons::FILE_PDF,
            FileKind::Xml => icons::FILE_CODE,
            FileKind::FacturaE => icons::RECEIPT,
            FileKind::Odf | FileKind::Ooxml => icons::FILE_DOC,
            FileKind::Signature(_) => icons::SEAL_CHECK,
            FileKind::Binary => icons::FILE,
        }
    }
}

/// Operación criptográfica sobre un fichero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Sign,
    Cosign,
    CountersignLeafs,
    CountersignTree,
}

impl Operation {
    pub fn label(self) -> &'static str {
        match self {
            Operation::Sign => "Firmar",
            Operation::Cosign => "Cofirmar (añadir una firma)",
            Operation::CountersignLeafs => "Contrafirmar las últimas firmas",
            Operation::CountersignTree => "Contrafirmar todas las firmas",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Pending,
    Signing,
    Done(PathBuf),
    Failed(String),
}

/// Documento cargado en la página de firma.
#[derive(Debug, Clone)]
pub struct FileItem {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub kind: FileKind,
    /// Formato de firma elegido (`PAdES`, `XAdES`, `CAdES`...).
    pub format: String,
    /// Formatos que el usuario puede elegir para este fichero.
    pub formats: Vec<String>,
    pub operation: Operation,
    pub status: FileStatus,
    /// Resumen de las firmas existentes (si ya estaba firmado).
    pub existing_signatures: Option<String>,
}

impl FileItem {
    pub fn is_signed(&self) -> bool {
        matches!(self.kind, FileKind::Signature(_)) || self.existing_signatures.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Empty,
    Ready,
    Signing { done: usize, total: usize },
    Finished,
}

/// Acciones que la página pide a la aplicación.
#[derive(Debug, Clone, PartialEq)]
pub enum SignAction {
    PickFiles,
    Remove(usize),
    Clear,
    ConfigureVisibleSignature(usize),
    StartSigning,
    ChangeStore,
    OpenOutput(PathBuf),
    OpenFolder(PathBuf),
    VerifyOutput(PathBuf),
    ChooseOutputDir,
}

#[derive(Debug)]
pub struct SignPage {
    pub stage: Stage,
    pub files: Vec<FileItem>,
    pub visible_signature: bool,
    pub output_dir: Option<PathBuf>,
    pub store_label: String,
    pub store_ready: bool,
    pub last_error: Option<String>,
}

impl Default for SignPage {
    fn default() -> Self {
        SignPage {
            stage: Stage::Empty,
            files: Vec::new(),
            visible_signature: false,
            output_dir: None,
            store_label: "Almacén del sistema".into(),
            store_ready: true,
            last_error: None,
        }
    }
}

impl SignPage {
    pub fn ui(&mut self, ui: &mut Ui, p: &Palette, files_hovering: bool) -> Vec<SignAction> {
        let mut actions = Vec::new();
        match self.stage {
            Stage::Empty => {
                widgets::page_header(ui, p, "Firmar documentos", Some("Firma electrónicamente cualquier documento con tu certificado o DNIe."));
                self.empty_view(ui, p, files_hovering, &mut actions);
            }
            Stage::Ready => {
                let n = self.files.len();
                let title = if n == 1 { "Revisa y firma".to_string() } else { format!("Revisa y firma {n} documentos") };
                widgets::page_header(ui, p, &title, Some("Comprueba el formato de firma elegido para cada documento y pulsa Firmar."));
                self.ready_view(ui, p, files_hovering, &mut actions);
            }
            Stage::Signing { done, total } => {
                widgets::page_header(ui, p, "Firmando…", None);
                widgets::card(ui, p, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.spinner();
                        ui.add_space(8.0);
                        ui.label(RichText::new(format!("Firmando documento {} de {}", (done + 1).min(total), total)).size(15.0));
                        ui.add_space(8.0);
                        ui.add(egui::ProgressBar::new(done as f32 / total.max(1) as f32).desired_width(360.0));
                        ui.add_space(20.0);
                    });
                });
                ui.add_space(12.0);
                self.file_list(ui, p, false, &mut actions);
            }
            Stage::Finished => self.finished_view(ui, p, &mut actions),
        }
        actions
    }

    fn empty_view(&mut self, ui: &mut Ui, p: &Palette, hovering: bool, actions: &mut Vec<SignAction>) {
        let r = widgets::drop_zone(ui, p, 270.0, hovering, |ui| {
            ui.add_space(26.0);
            widgets::status_circle(ui, icons::UPLOAD_SIMPLE, 64.0, p.primary, p.primary_soft);
            ui.add_space(10.0);
            ui.label(RichText::new("Arrastra aquí tus documentos o carpetas").font(FontId::new(18.0, semibold())).color(p.text));
            ui.label(
                RichText::new("PDF, XML, facturas electrónicas, documentos de Office o cualquier otro fichero")
                    .size(13.0)
                    .color(p.text_muted),
            );
            ui.add_space(12.0);
            if widgets::button(ui, p, ButtonKind::Primary, Some(icons::FOLDER_OPEN), "Seleccionar archivos", true).clicked() {
                actions.push(SignAction::PickFiles);
            }
        });
        if r.clicked() {
            actions.push(SignAction::PickFiles);
        }
        ui.add_space(16.0);
        self.store_card(ui, p, actions);
        ui.add_space(16.0);
        widgets::callout(
            ui,
            p,
            CalloutKind::Info,
            "Protege tus datos personales",
            Some(
                "Al firmar se pueden incorporar al documento datos personales como tu nombre, tu DNI o tu cargo. \
                 Consulta las políticas de protección de datos de los destinatarios antes de enviarlo.",
            ),
        );
    }

    fn store_card(&mut self, ui: &mut Ui, p: &Palette, actions: &mut Vec<SignAction>) {
        widgets::card(ui, p, |ui| {
            ui.horizontal(|ui| {
                widgets::status_circle(ui, icons::VAULT, 42.0, p.info, p.info_soft);
                ui.vertical(|ui| {
                    ui.label(RichText::new("Certificados de firma").size(12.5).color(p.text_muted));
                    let status = if self.store_ready { "" } else { " · cargando…" };
                    ui.label(
                        RichText::new(format!("{}{status}", self.store_label))
                            .font(FontId::new(14.5, semibold()))
                            .color(p.text),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::ARROWS_LEFT_RIGHT), "Cambiar almacén", true).clicked() {
                        actions.push(SignAction::ChangeStore);
                    }
                });
            });
        });
    }

    fn file_list(&mut self, ui: &mut Ui, p: &Palette, editable: bool, actions: &mut Vec<SignAction>) {
        for (i, f) in self.files.iter_mut().enumerate() {
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(12)
                .inner_margin(Margin::symmetric(16, 12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let (fg, bg) = match f.kind {
                            FileKind::Pdf => (p.danger, p.danger_soft),
                            FileKind::Xml | FileKind::FacturaE => (p.info, p.info_soft),
                            FileKind::Signature(_) => (p.success, p.success_soft),
                            _ => (p.text_muted, p.surface_alt),
                        };
                        widgets::status_circle(ui, f.kind.icon(), 42.0, fg, bg);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&f.name).font(FontId::new(14.5, semibold())).color(p.text));
                            let mut meta = format!("{} · {}", f.kind.label(), fmt_size(f.size));
                            if let Some(s) = &f.existing_signatures {
                                meta.push_str(" · ");
                                meta.push_str(s);
                            }
                            ui.label(RichText::new(meta).size(12.5).color(p.text_muted));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            match &f.status {
                                FileStatus::Done(_) => {
                                    widgets::chip(ui, "Firmado", p.success, p.success_soft);
                                }
                                FileStatus::Failed(_) => {
                                    widgets::chip(ui, "Error", p.danger, p.danger_soft);
                                }
                                FileStatus::Signing => {
                                    ui.spinner();
                                }
                                FileStatus::Pending if editable => {
                                    if ui
                                        .add(egui::Button::new(widgets::icon_text(icons::X, 16.0, p.text_faint)).frame(false))
                                        .on_hover_text("Quitar de la lista")
                                        .clicked()
                                    {
                                        actions.push(SignAction::Remove(i));
                                    }
                                    ui.add_space(6.0);
                                    egui::ComboBox::from_id_salt(("fmt", i))
                                        .selected_text(RichText::new(&f.format).font(FontId::new(13.0, semibold())))
                                        .width(120.0)
                                        .show_ui(ui, |ui| {
                                            for fmt in &f.formats {
                                                ui.selectable_value(&mut f.format, fmt.clone(), fmt);
                                            }
                                        })
                                        .response
                                        .on_hover_text("Formato de firma");
                                    if f.is_signed() {
                                        egui::ComboBox::from_id_salt(("op", i))
                                            .selected_text(RichText::new(f.operation.label()).size(13.0))
                                            .width(200.0)
                                            .show_ui(ui, |ui| {
                                                for op in [Operation::Cosign, Operation::CountersignLeafs, Operation::CountersignTree] {
                                                    ui.selectable_value(&mut f.operation, op, op.label());
                                                }
                                            });
                                    }
                                }
                                FileStatus::Pending => {
                                    widgets::chip(ui, &f.format, p.text_muted, p.surface_alt);
                                }
                            }
                        });
                    });
                    if let FileStatus::Failed(msg) = &f.status {
                        ui.add_space(6.0);
                        ui.label(RichText::new(msg).size(12.5).color(p.danger));
                    }
                });
            ui.add_space(8.0);
        }
    }

    fn ready_view(&mut self, ui: &mut Ui, p: &Palette, hovering: bool, actions: &mut Vec<SignAction>) {
        if hovering {
            widgets::callout(ui, p, CalloutKind::Info, "Suelta los ficheros para añadirlos a la lista", None);
            ui.add_space(8.0);
        }
        self.file_list(ui, p, true, actions);
        ui.horizontal(|ui| {
            if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::PLUS), "Añadir más documentos", true).clicked() {
                actions.push(SignAction::PickFiles);
            }
            if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::TRASH), "Vaciar lista", true).clicked() {
                actions.push(SignAction::Clear);
            }
        });
        ui.add_space(10.0);

        let has_pdf = self.files.iter().any(|f| f.format == "PAdES" || f.format == "Adobe PDF");
        widgets::card(ui, p, |ui| {
            widgets::section_title(ui, p, "Opciones de firma");
            ui.add_space(6.0);
            if has_pdf {
                ui.horizontal(|ui| {
                    toggle(ui, p, &mut self.visible_signature);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Firma visible en el PDF").font(FontId::new(14.0, semibold())));
                        ui.label(
                            RichText::new("Añade un recuadro con los datos del firmante en la página que elijas.")
                                .size(12.5)
                                .color(p.text_muted),
                        );
                    });
                    if self.visible_signature {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if let Some(i) = self.files.iter().position(|f| f.format == "PAdES" || f.format == "Adobe PDF") {
                                if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::SELECTION_PLUS), "Colocar firma", true).clicked() {
                                    actions.push(SignAction::ConfigureVisibleSignature(i));
                                }
                            }
                        });
                    }
                });
                ui.add_space(8.0);
            }
            if self.files.len() > 1 {
                ui.horizontal(|ui| {
                    widgets::icon_label(ui, p, icons::FOLDER, "Carpeta de destino:");
                    let label = self
                        .output_dir
                        .as_ref()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|| "Junto a cada documento original".into());
                    ui.label(RichText::new(label).font(FontId::new(13.5, semibold())));
                    if ui.link("Cambiar").clicked() {
                        actions.push(SignAction::ChooseOutputDir);
                    }
                });
                ui.add_space(4.0);
            }
            ui.horizontal(|ui| {
                widgets::icon_label(ui, p, icons::VAULT, "Certificados:");
                ui.label(RichText::new(&self.store_label).font(FontId::new(13.5, semibold())));
                if ui.link("Cambiar").clicked() {
                    actions.push(SignAction::ChangeStore);
                }
            });
        });
        ui.add_space(16.0);
        if let Some(e) = &self.last_error {
            widgets::callout(ui, p, CalloutKind::Error, "No se ha podido completar la firma", Some(e));
            ui.add_space(12.0);
        }
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            let n = self.files.len();
            let label = if n == 1 { "Firmar documento".to_string() } else { format!("Firmar {n} documentos") };
            let enabled = self.store_ready && n > 0;
            if widgets::button_sized(ui, p, ButtonKind::Primary, Some(icons::PEN_NIB), &label, enabled, 220.0, 46.0).clicked() {
                actions.push(SignAction::StartSigning);
            }
        });
    }

    fn finished_view(&mut self, ui: &mut Ui, p: &Palette, actions: &mut Vec<SignAction>) {
        let ok: Vec<&FileItem> = self.files.iter().filter(|f| matches!(f.status, FileStatus::Done(_))).collect();
        let failed = self.files.len() - ok.len();
        widgets::card(ui, p, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                if failed == 0 {
                    widgets::status_circle(ui, icons::CHECK_CIRCLE, 72.0, p.success, p.success_soft);
                    ui.add_space(10.0);
                    let title = if ok.len() == 1 { "Documento firmado correctamente".to_string() } else { format!("{} documentos firmados correctamente", ok.len()) };
                    ui.label(RichText::new(title).font(FontId::new(22.0, semibold())).color(p.text));
                } else {
                    widgets::status_circle(ui, icons::WARNING, 72.0, p.warning, p.warning_soft);
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(format!("{} firmados, {} con errores", ok.len(), failed))
                            .font(FontId::new(22.0, semibold()))
                            .color(p.text),
                    );
                }
                if let [only] = ok.as_slice() {
                    if let FileStatus::Done(path) = &only.status {
                        ui.add_space(4.0);
                        ui.label(RichText::new(path.display().to_string()).size(13.0).color(p.text_muted));
                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            let w = 3.0 * 170.0 + 16.0;
                            ui.add_space(((ui.available_width() - w) / 2.0).max(0.0));
                            if widgets::button_sized(ui, p, ButtonKind::Secondary, Some(icons::FOLDER_OPEN), "Abrir carpeta", true, 170.0, 40.0).clicked() {
                                actions.push(SignAction::OpenFolder(path.clone()));
                            }
                            if widgets::button_sized(ui, p, ButtonKind::Secondary, Some(icons::SEAL_CHECK), "Ver la firma", true, 170.0, 40.0).clicked() {
                                actions.push(SignAction::VerifyOutput(path.clone()));
                            }
                            if widgets::button_sized(ui, p, ButtonKind::Secondary, Some(icons::ARROW_SQUARE_OUT), "Abrir documento", true, 170.0, 40.0).clicked() {
                                actions.push(SignAction::OpenOutput(path.clone()));
                            }
                        });
                    }
                }
                ui.add_space(10.0);
            });
        });
        ui.add_space(14.0);
        if self.files.len() > 1 || failed > 0 {
            self.file_list(ui, p, false, actions);
        }
        ui.add_space(6.0);
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            if widgets::button(ui, p, ButtonKind::Primary, Some(icons::PLUS), "Firmar otros documentos", true).clicked() {
                actions.push(SignAction::Clear);
            }
        });
    }
}

/// Interruptor de encendido/apagado.
pub fn toggle(ui: &mut Ui, p: &Palette, on: &mut bool) -> egui::Response {
    let size = egui::vec2(40.0, 22.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Switch, true, *on, ""));
    let t = ui.ctx().animate_bool_responsive(response.id, *on);
    let off = if p.dark { egui::Color32::from_rgb(0x46, 0x4E, 0x5B) } else { egui::Color32::from_rgb(0xC3, 0xC9, 0xD2) };
    let bg = if *on { p.primary } else { off };
    let bg = if ui.is_enabled() { bg } else { bg.gamma_multiply(0.5) };
    ui.painter().rect_filled(rect, egui::CornerRadius::same(11), bg);
    let x = egui::lerp((rect.left() + 11.0)..=(rect.right() - 11.0), t);
    ui.painter().circle_filled(egui::pos2(x, rect.center().y), 8.0, egui::Color32::WHITE);
    let _ = theme::semibold;
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}
