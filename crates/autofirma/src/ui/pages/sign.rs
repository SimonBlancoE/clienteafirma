//! Página "Firmar": carga de documentos, opciones, firma y resultado.

use std::path::PathBuf;

use eframe::egui::{self, Align, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use crate::i18n::{tr, trf};
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
            FileKind::Pdf => tr("Documento PDF").into(),
            FileKind::Xml => tr("Documento XML").into(),
            FileKind::FacturaE => tr("Factura electrónica").into(),
            FileKind::Odf => tr("Documento OpenDocument").into(),
            FileKind::Ooxml => tr("Documento de Microsoft Office").into(),
            FileKind::Signature(f) => trf("Firma {0}", &[f]),
            FileKind::Binary => tr("Fichero").into(),
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
            Operation::Sign => tr("Firmar"),
            Operation::Cosign => tr("Cofirmar (añadir una firma)"),
            Operation::CountersignLeafs => tr("Contrafirmar las últimas firmas"),
            Operation::CountersignTree => tr("Contrafirmar todas las firmas"),
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
    /// Contenido del fichero (AutoFirma lee los ficheros completos).
    pub data: std::sync::Arc<Vec<u8>>,
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
    /// Elegir nombre y carpeta de la firma de un único documento.
    ChooseOutputFile,
    RepairIntegration,
    /// Botón «Validar certificado de firma» del resultado (complemento de Java).
    ValidateSigningCert,
}

#[derive(Debug)]
pub struct SignPage {
    pub stage: Stage,
    pub files: Vec<FileItem>,
    pub visible_signature: bool,
    /// Marca de imagen en el PDF (solo con un único PDF sin firmar, como Java).
    pub visible_stamp: bool,
    /// Validación del certificado de firma: `Some(None)` en curso.
    pub cert_validation: Option<Option<crate::services::certval::CertCheck>>,
    pub output_dir: Option<PathBuf>,
    /// Destino elegido para la firma de un único documento: (documento, firma).
    pub output_file: Option<(PathBuf, PathBuf)>,
    pub store_label: String,
    pub store_ready: bool,
    pub last_error: Option<String>,
    /// Falta integrar AutoFirma con el navegador (aviso).
    pub integration_needed: bool,
}

impl Default for SignPage {
    fn default() -> Self {
        SignPage {
            stage: Stage::Empty,
            files: Vec::new(),
            visible_signature: false,
            visible_stamp: false,
            cert_validation: None,
            output_dir: None,
            output_file: None,
            store_label: tr("Almacén del sistema").into(),
            store_ready: true,
            last_error: None,
            integration_needed: false,
        }
    }
}

impl SignPage {
    /// Destino de la firma de un único documento: el elegido por el usuario o el
    /// propuesto junto al original (como Java, que propone ese nombre al guardar).
    pub fn single_output(&self, file: &FileItem) -> Option<PathBuf> {
        if let Some((input, out)) = &self.output_file
            && *input == file.path
        {
            return Some(out.clone());
        }
        let signer = afirma_signers::signer_for_format(&file.format)?;
        Some(afirma_signers::naming::single_output_path(signer.as_ref(), &file.path))
    }

    pub fn ui(&mut self, ui: &mut Ui, p: &Palette, files_hovering: bool) -> Vec<SignAction> {
        let mut actions = Vec::new();
        match self.stage {
            Stage::Empty => {
                widgets::page_header(
                    ui,
                    p,
                    tr("Firmar documentos"),
                    Some(tr(
                        "Firma electrónicamente cualquier documento con tu certificado o DNIe.",
                    )),
                );
                self.empty_view(ui, p, files_hovering, &mut actions);
            }
            Stage::Ready => {
                let n = self.files.len();
                let title = if n == 1 {
                    tr("Revisa y firma").to_string()
                } else {
                    trf("Revisa y firma {0} documentos", &[&n])
                };
                widgets::page_header(
                    ui,
                    p,
                    &title,
                    Some(tr(
                        "Comprueba el formato de firma elegido para cada documento y pulsa Firmar.",
                    )),
                );
                self.ready_view(ui, p, files_hovering, &mut actions);
            }
            Stage::Signing { done, total } => {
                widgets::page_header(ui, p, tr("Firmando…"), None);
                widgets::card(ui, p, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.spinner();
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(trf("Firmando documento {0} de {1}", &[&(done + 1).min(total), &total]))
                                .size(15.0),
                        );
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
            ui.label(
                RichText::new(tr("Arrastra aquí tus documentos o carpetas"))
                    .font(FontId::new(18.0, semibold()))
                    .color(p.text),
            );
            ui.label(
                RichText::new(tr(
                    "PDF, XML, facturas electrónicas, documentos de Office o cualquier otro fichero",
                ))
                .size(13.0)
                .color(p.text_muted),
            );
            ui.add_space(12.0);
            if widgets::button(
                ui,
                p,
                ButtonKind::Primary,
                Some(icons::FOLDER_OPEN),
                tr("Seleccionar archivos"),
                true,
            )
            .clicked()
            {
                actions.push(SignAction::PickFiles);
            }
        });
        if r.clicked() {
            actions.push(SignAction::PickFiles);
        }
        ui.add_space(16.0);
        if self.integration_needed {
            widgets::card(ui, p, |ui| {
                ui.horizontal(|ui| {
                    widgets::status_circle(ui, icons::GLOBE, 42.0, p.warning, p.warning_soft);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(tr("Integra AutoFirma con tu navegador")).font(FontId::new(14.5, semibold())),
                        );
                        ui.label(
                            RichText::new(tr(
                                "Necesario para firmar en sedes electrónicas. Solo tarda unos segundos.",
                            ))
                            .size(12.5)
                            .color(p.text_muted),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::button(
                            ui,
                            p,
                            ButtonKind::Primary,
                            Some(icons::PLUGS_CONNECTED),
                            tr("Integrar ahora"),
                            true,
                        )
                        .clicked()
                        {
                            actions.push(SignAction::RepairIntegration);
                        }
                    });
                });
            });
            ui.add_space(16.0);
        }
        self.store_card(ui, p, actions);
        ui.add_space(16.0);
        widgets::callout(
            ui,
            p,
            CalloutKind::Info,
            tr("Protege tus datos personales"),
            Some(tr(
                "Al firmar se pueden incorporar al documento datos personales como tu nombre, tu DNI o tu cargo. \
                 Consulta las políticas de protección de datos de los destinatarios antes de enviarlo.",
            )),
        );
    }

    fn store_card(&mut self, ui: &mut Ui, p: &Palette, actions: &mut Vec<SignAction>) {
        widgets::card(ui, p, |ui| {
            ui.horizontal(|ui| {
                widgets::status_circle(ui, icons::VAULT, 42.0, p.info, p.info_soft);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr("Certificados de firma"))
                            .size(12.5)
                            .color(p.text_muted),
                    );
                    let label = if self.store_ready {
                        self.store_label.clone()
                    } else {
                        format!("{} · {}", self.store_label, tr("cargando…"))
                    };
                    ui.label(RichText::new(label).font(FontId::new(14.5, semibold())).color(p.text));
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Secondary,
                        Some(icons::ARROWS_LEFT_RIGHT),
                        tr("Cambiar almacén"),
                        true,
                    )
                    .clicked()
                    {
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
                                    widgets::chip(ui, tr("Firmado"), p.success, p.success_soft);
                                }
                                FileStatus::Failed(_) => {
                                    widgets::chip(ui, tr("Error"), p.danger, p.danger_soft);
                                }
                                FileStatus::Signing => {
                                    ui.spinner();
                                }
                                FileStatus::Pending if editable => {
                                    if ui
                                        .add(
                                            egui::Button::new(widgets::icon_text(icons::X, 16.0, p.text_faint))
                                                .frame(false),
                                        )
                                        .on_hover_text(tr("Quitar de la lista"))
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
                                        .on_hover_text(tr("Formato de firma"));
                                    if f.is_signed() {
                                        // Ancho fijo (el texto se recorta): en otros idiomas
                                        // la operación es más larga que en español.
                                        egui::ComboBox::from_id_salt(("op", i))
                                            .selected_text(RichText::new(f.operation.label()).size(13.0))
                                            .width(200.0)
                                            .truncate()
                                            .show_ui(ui, |ui| {
                                                for op in [
                                                    Operation::Cosign,
                                                    Operation::CountersignLeafs,
                                                    Operation::CountersignTree,
                                                ] {
                                                    ui.selectable_value(&mut f.operation, op, op.label());
                                                }
                                            })
                                            .response
                                            .on_hover_text(f.operation.label());
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
            widgets::callout(
                ui,
                p,
                CalloutKind::Info,
                tr("Suelta los ficheros para añadirlos a la lista"),
                None,
            );
            ui.add_space(8.0);
        }
        self.file_list(ui, p, true, actions);
        ui.horizontal(|ui| {
            if widgets::button(
                ui,
                p,
                ButtonKind::Ghost,
                Some(icons::PLUS),
                tr("Añadir más documentos"),
                true,
            )
            .clicked()
            {
                actions.push(SignAction::PickFiles);
            }
            if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::TRASH), tr("Vaciar lista"), true).clicked() {
                actions.push(SignAction::Clear);
            }
        });
        ui.add_space(10.0);

        let has_pdf = self
            .files
            .iter()
            .any(|f| f.format == "PAdES" || f.format == "Adobe PDF");
        widgets::card(ui, p, |ui| {
            widgets::section_title(ui, p, tr("Opciones de firma"));
            ui.add_space(6.0);
            if has_pdf {
                ui.horizontal(|ui| {
                    toggle(ui, p, &mut self.visible_signature, tr("Firma visible en el PDF"));
                    ui.vertical(|ui| {
                        ui.label(RichText::new(tr("Firma visible en el PDF")).font(FontId::new(14.0, semibold())));
                        ui.label(
                            RichText::new(tr(
                                "Añade un recuadro con los datos del firmante en la página que elijas.",
                            ))
                            .size(12.5)
                            .color(p.text_muted),
                        );
                    });
                    if self.visible_signature {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if let Some(i) = self
                                .files
                                .iter()
                                .position(|f| f.format == "PAdES" || f.format == "Adobe PDF")
                                && widgets::button(
                                    ui,
                                    p,
                                    ButtonKind::Secondary,
                                    Some(icons::SELECTION_PLUS),
                                    tr("Colocar firma"),
                                    true,
                                )
                                .clicked()
                            {
                                actions.push(SignAction::ConfigureVisibleSignature(i));
                            }
                        });
                    }
                });
                ui.add_space(8.0);
                // Marca de imagen: como en AutoFirma, solo al firmar un único PDF.
                if self.files.len() == 1 {
                    let signed = self.files[0].is_signed();
                    if signed {
                        self.visible_stamp = false;
                    }
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(!signed, |ui| {
                            toggle(ui, p, &mut self.visible_stamp, tr("Marca de imagen en el PDF"))
                        });
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(tr("Marca de imagen en el PDF")).font(FontId::new(14.0, semibold())),
                            );
                            let hint = if signed {
                                tr("No se pueden aplicar marcas visibles a documentos ya firmados.")
                            } else {
                                tr("Añade una imagen (logotipo, sello…) en una página o en todas.")
                            };
                            ui.label(RichText::new(hint).size(12.5).color(p.text_muted));
                        });
                        if self.visible_stamp && !self.visible_signature {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if widgets::button(
                                    ui,
                                    p,
                                    ButtonKind::Secondary,
                                    Some(icons::SELECTION_PLUS),
                                    tr("Colocar marca"),
                                    true,
                                )
                                .clicked()
                                {
                                    actions.push(SignAction::ConfigureVisibleSignature(0));
                                }
                            });
                        }
                    });
                    ui.add_space(8.0);
                } else {
                    self.visible_stamp = false;
                }
            }
            if let [only] = self.files.as_slice()
                && let Some(dest) = self.single_output(only)
            {
                ui.horizontal(|ui| {
                    widgets::icon_label(ui, p, icons::FOLDER, tr("Guardar como:"));
                    ui.label(RichText::new(dest.display().to_string()).font(FontId::new(13.5, semibold())));
                    if ui.link(tr("Cambiar")).clicked() {
                        actions.push(SignAction::ChooseOutputFile);
                    }
                });
                ui.add_space(4.0);
            }
            if self.files.len() > 1 {
                ui.horizontal(|ui| {
                    widgets::icon_label(ui, p, icons::FOLDER, tr("Carpeta de destino:"));
                    let label = self
                        .output_dir
                        .as_ref()
                        .map(|d| d.display().to_string())
                        .unwrap_or_else(|| tr("Junto a cada documento original").into());
                    ui.label(RichText::new(label).font(FontId::new(13.5, semibold())));
                    if ui.link(tr("Cambiar")).clicked() {
                        actions.push(SignAction::ChooseOutputDir);
                    }
                });
                ui.add_space(4.0);
            }
            ui.horizontal(|ui| {
                widgets::icon_label(ui, p, icons::VAULT, tr("Certificados:"));
                ui.label(RichText::new(&self.store_label).font(FontId::new(13.5, semibold())));
                if ui.link(tr("Cambiar")).clicked() {
                    actions.push(SignAction::ChangeStore);
                }
            });
        });
        ui.add_space(16.0);
        if let Some(e) = &self.last_error {
            widgets::callout(
                ui,
                p,
                CalloutKind::Error,
                tr("No se ha podido completar la firma"),
                Some(e),
            );
            ui.add_space(12.0);
        }
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            let n = self.files.len();
            let label = if n == 1 {
                tr("Firmar documento").to_string()
            } else {
                trf("Firmar {0} documentos", &[&n])
            };
            let enabled = self.store_ready && n > 0;
            if widgets::button_sized(
                ui,
                p,
                ButtonKind::Primary,
                Some(icons::PEN_NIB),
                &label,
                enabled,
                220.0,
                46.0,
            )
            .clicked()
            {
                actions.push(SignAction::StartSigning);
            }
        });
    }

    fn finished_view(&mut self, ui: &mut Ui, p: &Palette, actions: &mut Vec<SignAction>) {
        let ok: Vec<&FileItem> = self
            .files
            .iter()
            .filter(|f| matches!(f.status, FileStatus::Done(_)))
            .collect();
        let failed = self.files.len() - ok.len();
        widgets::card(ui, p, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                if failed == 0 {
                    widgets::status_circle(ui, icons::CHECK_CIRCLE, 72.0, p.success, p.success_soft);
                    ui.add_space(10.0);
                    let title = if ok.len() == 1 {
                        tr("Documento firmado correctamente").to_string()
                    } else {
                        trf("{0} documentos firmados correctamente", &[&ok.len()])
                    };
                    ui.label(RichText::new(title).font(FontId::new(22.0, semibold())).color(p.text));
                } else {
                    widgets::status_circle(ui, icons::WARNING, 72.0, p.warning, p.warning_soft);
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(trf("{0} firmados, {1} con errores", &[&ok.len(), &failed]))
                            .font(FontId::new(22.0, semibold()))
                            .color(p.text),
                    );
                }
                if let [only] = ok.as_slice()
                    && let FileStatus::Done(path) = &only.status
                {
                    ui.add_space(4.0);
                    ui.label(RichText::new(path.display().to_string()).size(13.0).color(p.text_muted));
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        let w = 3.0 * 170.0 + 16.0;
                        ui.add_space(((ui.available_width() - w) / 2.0).max(0.0));
                        if widgets::button_sized(
                            ui,
                            p,
                            ButtonKind::Secondary,
                            Some(icons::FOLDER_OPEN),
                            tr("Abrir carpeta"),
                            true,
                            170.0,
                            40.0,
                        )
                        .clicked()
                        {
                            actions.push(SignAction::OpenFolder(path.clone()));
                        }
                        if widgets::button_sized(
                            ui,
                            p,
                            ButtonKind::Secondary,
                            Some(icons::SEAL_CHECK),
                            tr("Ver la firma"),
                            true,
                            170.0,
                            40.0,
                        )
                        .clicked()
                        {
                            actions.push(SignAction::VerifyOutput(path.clone()));
                        }
                        if widgets::button_sized(
                            ui,
                            p,
                            ButtonKind::Secondary,
                            Some(icons::ARROW_SQUARE_OUT),
                            tr("Abrir documento"),
                            true,
                            170.0,
                            40.0,
                        )
                        .clicked()
                        {
                            actions.push(SignAction::OpenOutput(path.clone()));
                        }
                    });
                }
                if ok.len() > 1
                    && let FileStatus::Done(first) = &ok[0].status
                {
                    // Dónde han quedado las firmas: una carpeta común o junto a cada original.
                    let dir = first.parent();
                    let same = ok
                        .iter()
                        .all(|f| matches!(&f.status, FileStatus::Done(o) if o.parent() == dir));
                    ui.add_space(4.0);
                    let text = match dir {
                        Some(d) if same => trf("Guardados en {0}", &[&d.display()]),
                        _ => tr("Guardados junto a cada documento original").to_string(),
                    };
                    ui.label(RichText::new(text).size(13.0).color(p.text_muted));
                    if same {
                        ui.add_space(10.0);
                        if widgets::button_sized(
                            ui,
                            p,
                            ButtonKind::Secondary,
                            Some(icons::FOLDER_OPEN),
                            tr("Abrir carpeta"),
                            true,
                            170.0,
                            40.0,
                        )
                        .clicked()
                        {
                            actions.push(SignAction::OpenFolder(first.clone()));
                        }
                    }
                }
                ui.add_space(10.0);
            });
        });
        ui.add_space(14.0);
        if !ok.is_empty() {
            match &self.cert_validation {
                None => {
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Ghost,
                        Some(icons::SHIELD_CHECK),
                        tr("Validar certificado de firma"),
                        true,
                    )
                    .on_hover_text(tr("Validar el certificado con el que se ha realizado la firma"))
                    .clicked()
                    {
                        actions.push(SignAction::ValidateSigningCert);
                    }
                }
                Some(None) => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new(tr("Validando certificado…")).color(p.text_muted));
                    });
                }
                Some(Some(r)) => {
                    let kind = if r.ok { CalloutKind::Success } else { CalloutKind::Error };
                    widgets::callout(ui, p, kind, &r.title, r.detail.as_deref());
                }
            }
            ui.add_space(10.0);
        }
        if self.files.len() > 1 || failed > 0 {
            self.file_list(ui, p, false, actions);
        }
        ui.add_space(6.0);
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            if widgets::button(
                ui,
                p,
                ButtonKind::Primary,
                Some(icons::PLUS),
                tr("Firmar otros documentos"),
                true,
            )
            .clicked()
            {
                actions.push(SignAction::Clear);
            }
        });
    }
}

/// Interruptor de encendido/apagado.
/// Interruptor. `label` es el nombre accesible (lectores de pantalla); el
/// texto visible va al lado.
pub fn toggle(ui: &mut Ui, p: &Palette, on: &mut bool, label: &str) -> egui::Response {
    let size = egui::vec2(40.0, 22.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let enabled = ui.is_enabled();
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Switch, enabled, *on, label));
    let t = ui.ctx().animate_bool_responsive(response.id, *on);
    let off = if p.dark {
        egui::Color32::from_rgb(0x46, 0x4E, 0x5B)
    } else {
        egui::Color32::from_rgb(0xC3, 0xC9, 0xD2)
    };
    let bg = if *on { p.primary } else { off };
    let bg = if ui.is_enabled() { bg } else { bg.gamma_multiply(0.5) };
    ui.painter().rect_filled(rect, egui::CornerRadius::same(11), bg);
    let x = egui::lerp((rect.left() + 11.0)..=(rect.right() - 11.0), t);
    ui.painter()
        .circle_filled(egui::pos2(x, rect.center().y), 8.0, egui::Color32::WHITE);
    let _ = theme::semibold;
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}
