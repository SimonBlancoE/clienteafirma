//! Página "Verificar firmas": validación y detalle de firmas electrónicas
//! (equivale al visor de firmas y al diálogo de detalles de AutoFirma).

use std::path::PathBuf;

use afirma_core::validity::{SignValidity, Validity};
use chrono::{DateTime, Utc};
use eframe::egui::{self, Align, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use crate::i18n::{tr, trf};
use crate::ui::icons;
use crate::ui::model::fmt_datetime;
use crate::ui::theme::{Palette, semibold};
use crate::ui::widgets::{self, ButtonKind, CalloutKind};

/// Política de firma declarada.
#[derive(Debug, Clone, Default)]
pub struct PolicyInfo {
    /// Nombre conocido ("Política de firma de la AGE v1.9"), si se reconoce.
    pub name: Option<String>,
    pub identifier: String,
    pub hash: Option<String>,
    pub hash_algorithm: Option<String>,
    pub qualifier: Option<String>,
}

/// Detalle de una firma (equivale a `SignDetails`).
#[derive(Debug, Clone, Default)]
pub struct SignatureDetail {
    /// Profundidad en el árbol (0 = firma o cofirma; >0 = contrafirma).
    pub depth: usize,
    pub signer: String,
    pub signer_id: Option<String>,
    pub issuer: String,
    pub cert_not_after: Option<DateTime<Utc>>,
    /// Texto de validación del certificado.
    pub cert_status: String,
    pub cert_der: Vec<u8>,
    pub profile: Option<String>,
    pub algorithm: Option<String>,
    pub signing_time: Option<DateTime<Utc>>,
    /// Sellos de tiempo: (emisor, fecha).
    pub timestamps: Vec<(String, DateTime<Utc>)>,
    pub validity: Vec<SignValidity>,
    pub policy: Option<PolicyInfo>,
    /// Metadatos (razón, lugar, contacto, roles...).
    pub metadata: Vec<(String, String)>,
    /// Nivel de certificación en PDF (1, 2 o 3).
    pub certification_level: Option<u8>,
}

impl SignatureDetail {
    pub fn verdict(&self) -> Validity {
        self.validity.first().map(|v| v.validity).unwrap_or(Validity::Ok)
    }
}

/// Informe completo de un fichero de firma.
#[derive(Debug, Clone, Default)]
pub struct SignatureReport {
    pub path: PathBuf,
    pub file_name: String,
    pub format: String,
    pub data_location: Option<String>,
    /// Objetos de datos firmados: (descripción, tipo, codificación).
    pub data_objects: Vec<(String, String, String)>,
    pub overall: Option<SignValidity>,
    pub global_issues: Vec<String>,
    pub signatures: Vec<SignatureDetail>,
    pub has_embedded_data: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyAction {
    PickFile,
    ExtractData,
    Cosign,
    Countersign,
    ExportCertificate(usize),
    /// Abrir VALIDe (servicio oficial de validación) en el navegador.
    OpenValide,
    Clear,
}

#[derive(Debug, Default)]
pub struct VerifyPage {
    pub loading: Option<String>,
    pub report: Option<SignatureReport>,
    pub error: Option<String>,
    pub expanded: Option<usize>,
}

fn verdict_style(v: Validity, p: &Palette) -> (&'static str, egui::Color32, egui::Color32, &'static str) {
    match v {
        Validity::Ok | Validity::Generated => (icons::SEAL_CHECK, p.success, p.success_soft, tr("Firma válida")),
        Validity::Ko => (icons::X_CIRCLE, p.danger, p.danger_soft, tr("Firma no válida")),
        Validity::Unknown => (icons::WARNING, p.warning, p.warning_soft, tr("Validación incompleta")),
        Validity::PendingConfirmByUser => (icons::QUESTION, p.warning, p.warning_soft, tr("Validez a confirmar")),
    }
}

impl VerifyPage {
    pub fn ui(&mut self, ui: &mut Ui, p: &Palette, hovering: bool) -> Vec<VerifyAction> {
        let mut actions = Vec::new();
        if let Some(msg) = &self.loading {
            widgets::page_header(ui, p, tr("Verificar firmas"), None);
            widgets::card(ui, p, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(30.0);
                    ui.spinner();
                    ui.label(RichText::new(msg).color(p.text_muted));
                    ui.add_space(30.0);
                });
            });
            return actions;
        }
        let Some(report) = self.report.as_ref() else {
            widgets::page_header(
                ui,
                p,
                tr("Verificar firmas"),
                Some(tr("Comprueba la validez de una firma electrónica y consulta quién firmó, cuándo y con qué certificado.")),
            );
            let r = widgets::drop_zone(ui, p, 240.0, hovering, |ui| {
                ui.add_space(26.0);
                widgets::status_circle(ui, icons::SEAL_CHECK, 60.0, p.success, p.success_soft);
                ui.add_space(10.0);
                ui.label(RichText::new(tr("Arrastra aquí una firma o un documento firmado")).font(FontId::new(17.0, semibold())));
                ui.label(RichText::new(tr("PDF firmados, .csig, .xsig, .p7s, facturas electrónicas, ASiC…")).size(13.0).color(p.text_muted));
                ui.add_space(12.0);
                if widgets::button(ui, p, ButtonKind::Primary, Some(icons::FOLDER_OPEN), tr("Seleccionar firma"), true).clicked() {
                    actions.push(VerifyAction::PickFile);
                }
            });
            if r.clicked() {
                actions.push(VerifyAction::PickFile);
            }
            if let Some(e) = &self.error {
                ui.add_space(14.0);
                widgets::callout(ui, p, CalloutKind::Error, tr("No se ha podido verificar el fichero"), Some(e));
            }
            return actions;
        };

        // Resumen.
        let overall = report.overall.clone().unwrap_or_else(SignValidity::ok);
        let (glyph, fg, bg, title) = verdict_style(overall.validity, p);
        widgets::card(ui, p, |ui| {
            ui.horizontal(|ui| {
                widgets::status_circle(ui, glyph, 64.0, fg, bg);
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).font(FontId::new(22.0, semibold())).color(fg));
                    let n = report.signatures.len();
                    let summary = match overall.error {
                        Some(e) => e.message().to_string(),
                        None if n == 1 => tr("Contiene 1 firma correcta.").into(),
                        None => trf("Contiene {0} firmas correctas.", &[&n]),
                    };
                    ui.label(RichText::new(summary).size(13.5).color(p.text_muted));
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        widgets::chip(ui, &report.format, p.text_muted, p.surface_alt);
                        widgets::chip(ui, &report.file_name, p.text_muted, p.surface_alt);
                    });
                });
            });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if report.has_embedded_data
                    && widgets::button(ui, p, ButtonKind::Secondary, Some(icons::DOWNLOAD_SIMPLE), tr("Extraer documento"), true).clicked()
                {
                    actions.push(VerifyAction::ExtractData);
                }
                if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::PLUS_CIRCLE), tr("Añadir mi firma"), true).clicked() {
                    actions.push(VerifyAction::Cosign);
                }
                if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::TREE_STRUCTURE), tr("Contrafirmar"), true).clicked() {
                    actions.push(VerifyAction::Countersign);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::ARROW_COUNTER_CLOCKWISE), tr("Verificar otra"), true).clicked() {
                        actions.push(VerifyAction::Clear);
                    }
                });
            });
        });
        for issue in &report.global_issues {
            ui.add_space(10.0);
            widgets::callout(ui, p, CalloutKind::Warning, issue, None);
        }
        // Como la pantalla de resultado de AutoFirma: la validez legal completa
        // (revocación de los certificados) se puede comprobar en VALIDe.
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(tr("Para comprobar también la revocación de los certificados puedes usar el servicio oficial"))
                    .size(12.5)
                    .color(p.text_muted),
            );
            if ui.link(RichText::new("VALIDe").size(12.5).color(p.primary)).clicked() {
                actions.push(VerifyAction::OpenValide);
            }
        });

        ui.add_space(18.0);
        widgets::section_title(ui, p, &trf("Firmantes ({0})", &[&report.signatures.len()]));
        ui.add_space(8.0);
        let expanded = self.expanded;
        let mut toggle = None;
        for (i, s) in report.signatures.iter().enumerate() {
            let indent = s.depth as f32 * 28.0;
            ui.horizontal(|ui| {
                ui.add_space(indent);
                if s.depth > 0 {
                    ui.label(widgets::icon_text(icons::ARROW_ELBOW_DOWN_RIGHT, 18.0, p.text_faint));
                }
                ui.vertical(|ui| {
                    if signature_card(ui, p, s, expanded == Some(i), &mut actions, i) {
                        toggle = Some(i);
                    }
                });
            });
            ui.add_space(8.0);
        }
        if let Some(i) = toggle {
            self.expanded = if self.expanded == Some(i) { None } else { Some(i) };
        }

        ui.add_space(10.0);
        widgets::card(ui, p, |ui| {
            widgets::section_title(ui, p, tr("Datos firmados"));
            ui.add_space(6.0);
            widgets::kv_row(ui, p, tr("Formato"), &report.format);
            if let Some(l) = &report.data_location {
                widgets::kv_row(ui, p, tr("Ubicación de los datos"), l);
            }
            for (desc, kind, enc) in &report.data_objects {
                let mut v = kind.clone();
                if !desc.is_empty() {
                    v = format!("{v} · {desc}");
                }
                if !enc.is_empty() {
                    v = format!("{v} · {enc}");
                }
                widgets::kv_row(ui, p, tr("Documento"), &v);
            }
        });
        actions
    }
}

fn initials(name: &str) -> String {
    name.split_whitespace()
        .filter(|w| w.chars().next().is_some_and(char::is_alphabetic))
        .take(2)
        .filter_map(|w| w.chars().next())
        .collect::<String>()
        .to_uppercase()
}

/// Tarjeta de un firmante. Devuelve `true` si se pulsó "detalles".
fn signature_card(ui: &mut Ui, p: &Palette, s: &SignatureDetail, expanded: bool, actions: &mut Vec<VerifyAction>, idx: usize) -> bool {
    let (glyph, fg, bg, label) = verdict_style(s.verdict(), p);
    let mut toggled = false;
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(16, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                // Avatar con iniciales.
                let (rect, _) = ui.allocate_exact_size(egui::vec2(42.0, 42.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 21.0, p.primary_soft);
                ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, initials(&s.signer), FontId::new(15.0, semibold()), p.primary);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&s.signer).font(FontId::new(15.0, semibold())).color(p.text));
                        if s.depth > 0 {
                            widgets::chip(ui, tr("Contrafirma"), p.info, p.info_soft);
                        }
                    });
                    let mut when = match s.signing_time {
                        Some(t) => trf("Firmado el {0}", &[&fmt_datetime(t)]),
                        None => tr("Fecha de firma no declarada").into(),
                    };
                    if let Some((tsa, t)) = s.timestamps.first() {
                        when = format!("{when} · {}", trf("Sello de tiempo de {0} ({1})", &[tsa, &fmt_datetime(*t)]));
                    }
                    ui.label(RichText::new(when).size(12.5).color(p.text_muted));
                    ui.horizontal_wrapped(|ui| {
                        widgets::chip_icon(ui, glyph, label, fg, bg);
                        if let Some(prof) = &s.profile {
                            widgets::chip(ui, prof, p.text_muted, p.surface_alt);
                        }
                        if let Some(pol) = &s.policy {
                            widgets::chip(ui, pol.name.as_deref().unwrap_or(tr("Política de firma")), p.info, p.info_soft);
                        }
                    });
                });
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if ui.link(if expanded { tr("Ocultar detalles") } else { tr("Detalles") }).clicked() {
                        toggled = true;
                    }
                });
            });
            for v in s.validity.iter().filter(|v| v.validity != Validity::Ok) {
                ui.add_space(6.0);
                ui.label(RichText::new(v.to_string()).size(12.5).color(p.danger));
            }
            if expanded {
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);
                widgets::kv_row(ui, p, tr("Certificado"), &s.signer);
                if let Some(id) = &s.signer_id {
                    widgets::kv_row(ui, p, tr("Identificador"), id);
                }
                widgets::kv_row(ui, p, tr("Emitido por"), &s.issuer);
                if let Some(t) = s.cert_not_after {
                    widgets::kv_row(ui, p, tr("Caduca"), &fmt_datetime(t));
                }
                widgets::kv_row(ui, p, tr("Estado del certificado"), &s.cert_status);
                if let Some(a) = &s.algorithm {
                    widgets::kv_row(ui, p, tr("Algoritmo"), a);
                }
                if let Some(l) = s.certification_level {
                    let text = match l {
                        1 => tr("Documento certificado: no se admiten cambios"),
                        2 => tr("Documento certificado: se permite rellenar formularios y firmar"),
                        _ => tr("Documento certificado: se permiten formularios, anotaciones y firmas"),
                    };
                    widgets::kv_row(ui, p, tr("Certificación"), text);
                }
                if let Some(pol) = &s.policy {
                    widgets::kv_row(ui, p, tr("Política"), pol.name.as_deref().unwrap_or(&pol.identifier));
                    if pol.name.is_none() {
                        if let Some(h) = &pol.hash {
                            let text = match &pol.hash_algorithm {
                                Some(a) => format!("{h} ({a})"),
                                None => h.clone(),
                            };
                            widgets::kv_row(ui, p, tr("Huella de la política"), &text);
                        }
                        if let Some(q) = &pol.qualifier {
                            widgets::kv_row(ui, p, tr("Calificador"), q);
                        }
                    }
                }
                for (k, v) in &s.metadata {
                    widgets::kv_row(ui, p, k, v);
                }
                for (tsa, t) in &s.timestamps {
                    widgets::kv_row(ui, p, tr("Sello de tiempo"), &format!("{tsa} · {}", fmt_datetime(*t)));
                }
                ui.add_space(6.0);
                if !s.cert_der.is_empty()
                    && widgets::button(ui, p, ButtonKind::Ghost, Some(icons::EXPORT), tr("Exportar certificado"), true).clicked()
                {
                    actions.push(VerifyAction::ExportCertificate(idx));
                }
            }
        });
    toggled
}
