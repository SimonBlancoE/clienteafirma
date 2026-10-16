//! Página "Mis certificados": almacenes disponibles, sus certificados y su
//! gestión (abrir PKCS#12, registrar tarjetas PKCS#11, exportar).

use eframe::egui::{self, Align, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use crate::i18n::{tr, trf};
use crate::ui::cert_picker::cert_details;
use crate::ui::icons;
use crate::ui::model::{CertItem, CertState, fmt_date, state_colors};
use crate::ui::theme::{Palette, semibold};
use crate::ui::widgets::{self, ButtonKind, CalloutKind};

/// Almacén mostrado en la página.
#[derive(Debug, Clone)]
pub struct StoreEntry {
    pub id: String,
    pub label: String,
    pub description: String,
    pub icon: &'static str,
    pub available: bool,
    /// Certificados cargados (`None` = aún no cargado).
    pub certs: Option<Vec<CertItem>>,
    pub error: Option<String>,
    pub loading: bool,
    /// Se puede quitar (PKCS#12 abierto o tarjeta registrada).
    pub removable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertsAction {
    SelectStore(usize),
    LoadStore(usize),
    OpenPkcs12,
    RegisterPkcs11,
    RemoveStore(usize),
    Export(usize, usize),
    SetDefault(usize),
}

#[derive(Debug, Default)]
pub struct CertificatesPage {
    pub stores: Vec<StoreEntry>,
    pub selected: usize,
    pub expanded: Option<usize>,
    pub show_expired: bool,
    pub default_store: Option<String>,
}

impl CertificatesPage {
    pub fn ui(&mut self, ui: &mut Ui, p: &Palette) -> Vec<CertsAction> {
        let mut actions = Vec::new();
        widgets::page_header(
            ui,
            p,
            tr("Mis certificados"),
            Some(tr(
                "Consulta los certificados de tus almacenes, tarjetas y DNIe, y gestiona los almacenes adicionales.",
            )),
        );

        // Selector de almacenes en forma de tarjetas horizontales.
        ui.horizontal_wrapped(|ui| {
            for (i, s) in self.stores.iter().enumerate() {
                let selected = i == self.selected;
                let fill = if selected { p.primary_soft } else { p.surface };
                let stroke = if selected {
                    Stroke::new(1.5, p.primary)
                } else {
                    Stroke::new(1.0, p.border)
                };
                let r = ui.allocate_ui(egui::vec2(218.0, 64.0), |ui| {
                    Frame::new()
                        .fill(fill)
                        .stroke(stroke)
                        .corner_radius(CornerRadius::same(12))
                        .inner_margin(Margin::symmetric(14, 10))
                        .show(ui, |ui| {
                            ui.set_width(190.0);
                            ui.set_height(42.0);
                            ui.horizontal(|ui| {
                                let (fg, bg) = if s.available {
                                    (p.primary, p.primary_soft)
                                } else {
                                    (p.text_faint, p.surface_alt)
                                };
                                widgets::status_circle(ui, s.icon, 34.0, fg, if selected { p.surface } else { bg });
                                ui.vertical(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&s.label)
                                                .font(FontId::new(13.5, semibold()))
                                                .color(p.text),
                                        )
                                        .truncate(),
                                    );
                                    let sub = match (&s.certs, s.loading, s.available) {
                                        (_, true, _) => tr("Cargando…").to_string(),
                                        (_, _, false) => tr("No disponible").to_string(),
                                        (Some(c), _, _) if c.len() == 1 => tr("1 certificado").to_string(),
                                        (Some(c), _, _) => trf("{0} certificados", &[&c.len()]),
                                        (None, _, _) => s.description.clone(),
                                    };
                                    ui.add(
                                        egui::Label::new(RichText::new(sub).size(12.0).color(p.text_muted)).truncate(),
                                    );
                                });
                            });
                        })
                });
                let resp = ui.interact(
                    r.inner.response.rect,
                    egui::Id::unique(("store", i)),
                    egui::Sense::click(),
                );
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() && !selected {
                    actions.push(CertsAction::SelectStore(i));
                }
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if widgets::button(
                ui,
                p,
                ButtonKind::Ghost,
                Some(icons::FILE_LOCK),
                tr("Abrir fichero .p12 / .pfx"),
                true,
            )
            .clicked()
            {
                actions.push(CertsAction::OpenPkcs12);
            }
            if widgets::button(
                ui,
                p,
                ButtonKind::Ghost,
                Some(icons::CPU),
                tr("Añadir tarjeta (módulo PKCS#11)"),
                true,
            )
            .clicked()
            {
                actions.push(CertsAction::RegisterPkcs11);
            }
        });
        ui.add_space(12.0);

        let Some(store) = self.stores.get(self.selected).cloned() else {
            return actions;
        };
        widgets::card(ui, p, |ui| {
            ui.horizontal(|ui| {
                widgets::section_title(ui, p, &store.label);
                if self.default_store.as_deref() == Some(store.id.as_str()) {
                    widgets::chip(ui, tr("Predeterminado"), p.success, p.success_soft);
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if store.removable
                        && widgets::button(ui, p, ButtonKind::Ghost, Some(icons::TRASH), tr("Quitar"), true).clicked()
                    {
                        actions.push(CertsAction::RemoveStore(self.selected));
                    }
                    if self.default_store.as_deref() != Some(store.id.as_str())
                        && widgets::button(
                            ui,
                            p,
                            ButtonKind::Ghost,
                            Some(icons::STAR),
                            tr("Usar por defecto"),
                            true,
                        )
                        .clicked()
                    {
                        actions.push(CertsAction::SetDefault(self.selected));
                    }
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Ghost,
                        Some(icons::ARROWS_CLOCKWISE),
                        tr("Recargar"),
                        !store.loading,
                    )
                    .clicked()
                    {
                        actions.push(CertsAction::LoadStore(self.selected));
                    }
                    ui.checkbox(
                        &mut self.show_expired,
                        RichText::new(tr("Mostrar caducados")).size(13.0),
                    );
                });
            });
            ui.label(RichText::new(&store.description).size(12.5).color(p.text_muted));
            ui.add_space(10.0);
            if store.loading {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.spinner();
                    ui.add_space(20.0);
                });
            } else if let Some(err) = &store.error {
                widgets::callout(
                    ui,
                    p,
                    CalloutKind::Error,
                    tr("No se ha podido abrir el almacén"),
                    Some(err),
                );
            } else if let Some(certs) = &store.certs {
                let visible: Vec<(usize, &CertItem)> = certs
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| self.show_expired || !matches!(c.state(), CertState::Expired))
                    .collect();
                if visible.is_empty() {
                    ui.label(
                        RichText::new(tr("Este almacén no contiene certificados con clave privada."))
                            .color(p.text_muted),
                    );
                }
                for (ci, c) in visible {
                    let expanded = self.expanded == Some(ci);
                    let (fg, bg) = state_colors(c.state(), p);
                    Frame::new()
                        .fill(p.surface)
                        .stroke(Stroke::new(1.0, p.border))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(12, 10))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                widgets::status_circle(ui, c.family_icon(), 36.0, fg, bg);
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(&c.info.subject_cn).font(FontId::new(14.0, semibold())));
                                    ui.label(
                                        RichText::new(trf(
                                            "{0} · {1} · hasta el {2}",
                                            &[&c.info.issuer_cn, &c.usage_text(), &fmt_date(c.info.not_after)],
                                        ))
                                        .size(12.5)
                                        .color(p.text_muted),
                                    );
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui
                                        .add(
                                            egui::Button::new(widgets::icon_text(icons::EXPORT, 16.0, p.text_muted))
                                                .frame(false),
                                        )
                                        .on_hover_text(tr("Exportar certificado (.cer)"))
                                        .clicked()
                                    {
                                        actions.push(CertsAction::Export(self.selected, ci));
                                    }
                                    if ui.link(if expanded { tr("Ocultar") } else { tr("Detalles") }).clicked() {
                                        self.expanded = if expanded { None } else { Some(ci) };
                                    }
                                });
                            });
                            if expanded {
                                ui.separator();
                                cert_details(ui, p, c);
                            }
                        });
                    ui.add_space(6.0);
                }
            } else {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(tr("Los certificados de este almacén aún no se han cargado."))
                            .color(p.text_muted),
                    );
                    if ui.link(tr("Cargar ahora")).clicked() {
                        actions.push(CertsAction::LoadStore(self.selected));
                    }
                });
            }
        });
        actions
    }
}
