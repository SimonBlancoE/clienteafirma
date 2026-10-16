//! Ventana de peticiones desde la web (protocolo `afirma://`).
//!
//! Cuando una sede electrónica invoca AutoFirma, en lugar de diálogos sueltos
//! se muestra una ventana compacta que dice quién pide qué (origen de la
//! petición, operación y documento) y permite elegir el certificado en la
//! misma pantalla.

use eframe::egui::{self, Align, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use super::cert_picker::{CertPicker, PickerEvent};
use super::icons;
use crate::i18n::{tr, trf};
use super::model::fmt_size;
use super::theme::{Palette, semibold};
use super::widgets::{self, ButtonKind, CalloutKind};

/// Operación pedida por la web.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOp {
    Sign,
    Cosign,
    Countersign,
    Batch,
    SelectCert,
    SignAndSave,
    Save,
    Load,
}

impl RequestOp {
    pub fn verb(self) -> &'static str {
        match self {
            RequestOp::Sign | RequestOp::SignAndSave => tr("solicita tu firma electrónica"),
            RequestOp::Cosign => tr("solicita que añadas tu firma"),
            RequestOp::Countersign => tr("solicita tu contrafirma"),
            RequestOp::Batch => tr("solicita que firmes un lote de documentos"),
            RequestOp::SelectCert => tr("solicita que te identifiques con tu certificado"),
            RequestOp::Save => tr("quiere guardar un fichero en tu equipo"),
            RequestOp::Load => tr("quiere que elijas un fichero de tu equipo"),
        }
    }

    pub fn action_label(self) -> &'static str {
        match self {
            RequestOp::SelectCert => tr("Usar este certificado"),
            RequestOp::Batch => tr("Firmar el lote"),
            _ => tr("Firmar"),
        }
    }
}

/// Información de la petición para mostrar al usuario.
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub origin: Option<String>,
    pub op: RequestOp,
    pub format: Option<String>,
    pub file_name: Option<String>,
    pub data_len: Option<usize>,
    pub doc_kind: Option<String>,
    pub batch_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestStage {
    ChooseCertificate,
    Working(String),
    Done(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestEvent {
    None,
    Accept(usize),
    Cancel,
    Preview,
    Picker(PickerEvent),
    Close,
}

#[derive(Debug)]
pub struct RequestView {
    pub info: RequestInfo,
    pub stage: RequestStage,
    pub picker: CertPicker,
}

impl RequestView {
    pub fn new(info: RequestInfo) -> Self {
        let mut picker = CertPicker { show_remember: true, allow_change_store: true, ..Default::default() };
        picker.accept_label = info.op.action_label().into();
        RequestView { info, stage: RequestStage::ChooseCertificate, picker }
    }

    pub fn ui(&mut self, ui: &mut Ui, p: &Palette) -> RequestEvent {
        let mut ev = RequestEvent::None;
        let origin = self.info.origin.clone().unwrap_or_else(|| tr("Una página web").into());
        // Cabecera: quién lo pide.
        ui.horizontal(|ui| {
            widgets::status_circle(ui, icons::GLOBE_HEMISPHERE_WEST, 46.0, p.primary, p.primary_soft);
            ui.vertical(|ui| {
                ui.label(RichText::new(&origin).font(FontId::new(18.0, semibold())).color(p.text));
                ui.label(RichText::new(self.info.op.verb()).size(14.0).color(p.text_muted));
            });
        });
        ui.add_space(14.0);

        // Qué se firma.
        if self.info.op != RequestOp::SelectCert {
            Frame::new()
                .fill(p.surface_alt)
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::symmetric(14, 12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let icon = match self.info.doc_kind.as_deref() {
                            Some("PDF") => icons::FILE_PDF,
                            Some("XML") | Some("Factura electrónica") => icons::FILE_CODE,
                            _ if self.info.batch_count.is_some() => icons::FILES,
                            _ => icons::FILE,
                        };
                        widgets::status_circle(ui, icon, 38.0, p.text_muted, p.surface);
                        ui.vertical(|ui| {
                            let title = match (self.info.batch_count, &self.info.file_name) {
                                (Some(n), _) => trf("{0} documentos", &[&n]),
                                (None, Some(f)) => f.clone(),
                                (None, None) => self.info.doc_kind.clone().unwrap_or_else(|| tr("Documento").into()),
                            };
                            ui.label(RichText::new(title).font(FontId::new(14.5, semibold())));
                            let mut meta = Vec::new();
                            if let Some(k) = &self.info.doc_kind {
                                meta.push(k.clone());
                            }
                            if let Some(n) = self.info.data_len {
                                meta.push(fmt_size(n as u64));
                            }
                            if let Some(f) = &self.info.format {
                                meta.push(trf("Firma {0}", &[f]));
                            }
                            ui.label(RichText::new(meta.join(" · ")).size(12.5).color(p.text_muted));
                        });
                        if self.info.data_len.is_some() && self.info.batch_count.is_none() {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::EYE), tr("Ver"), true).clicked() {
                                    ev = RequestEvent::Preview;
                                }
                            });
                        }
                    });
                });
            ui.add_space(14.0);
        }

        match self.stage.clone() {
            RequestStage::ChooseCertificate => {
                ui.label(RichText::new(tr("Elige tu certificado")).font(FontId::new(15.5, semibold())));
                ui.add_space(6.0);
                // La lista se desplaza; quedan siempre visibles la barra del
                // selector (almacén, búsqueda, vistas: ~90 px), el aviso de
                // caducados y el pie con los botones (~70 px).
                let max_h = (ui.available_height() - 160.0).max(120.0);
                let pe = self.picker.show_embedded(ui, p, max_h);
                if let PickerEvent::Accepted(i) = pe {
                    ev = RequestEvent::Accept(i);
                } else if pe == PickerEvent::Cancelled {
                    ev = RequestEvent::Cancel;
                } else if pe != PickerEvent::None {
                    ev = RequestEvent::Picker(pe);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.picker.remember, RichText::new(tr("Recordar durante la sesión")).size(13.0));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let can = self.picker.selected.is_some() && !self.picker.loading;
                        if widgets::button(ui, p, ButtonKind::Primary, Some(icons::PEN_NIB), self.info.op.action_label(), can).clicked()
                            && let Some(i) = self.picker.selected {
                                ev = RequestEvent::Accept(i);
                            }
                        if widgets::button(ui, p, ButtonKind::Secondary, None, tr("Cancelar"), true).clicked() {
                            ev = RequestEvent::Cancel;
                        }
                    });
                });
            }
            RequestStage::Working(msg) => {
                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.add(egui::Spinner::new().size(36.0).color(p.primary));
                    ui.add_space(12.0);
                    ui.label(RichText::new(msg).size(15.0));
                    ui.label(RichText::new(tr("Si se solicita, introduce el PIN de tu tarjeta.")).size(12.5).color(p.text_muted));
                });
            }
            RequestStage::Done(msg) => {
                ui.vertical_centered(|ui| {
                    ui.add_space(30.0);
                    widgets::status_circle(ui, icons::CHECK_CIRCLE, 68.0, p.success, p.success_soft);
                    ui.add_space(10.0);
                    ui.label(RichText::new(msg).font(FontId::new(18.0, semibold())));
                    ui.label(RichText::new(tr("Ya puedes volver a la página web.")).color(p.text_muted));
                    ui.add_space(14.0);
                    if widgets::button(ui, p, ButtonKind::Secondary, None, tr("Cerrar"), true).clicked() {
                        ev = RequestEvent::Close;
                    }
                });
            }
            RequestStage::Failed(msg) => {
                widgets::callout(ui, p, CalloutKind::Error, tr("No se ha podido completar la operación"), Some(&msg));
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if widgets::button(ui, p, ButtonKind::Secondary, None, tr("Cerrar"), true).clicked() {
                        ev = RequestEvent::Close;
                    }
                });
            }
        }
        let _ = Stroke::NONE;
        ev
    }
}
