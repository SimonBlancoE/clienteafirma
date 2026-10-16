//! Diálogo de selección de certificado.
//!
//! Sustituye al `CertificateSelectionDialog` de AutoFirma con la misma
//! funcionalidad (vistas personal/representante/seudónimo, recarga, cambio de
//! almacén, detalle del certificado, selección con doble clic o Intro) y
//! añade búsqueda, avisos claros de caducidad y detalles integrados.

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Frame, Key, Layout, Margin, Pos2, Rect, RichText, ScrollArea,
    Sense, Stroke, StrokeKind, Ui, Vec2,
};

use super::icons;
use super::model::{CertItem, CertListView, CertState, fmt_date, state_colors};
use super::theme::{self, Palette, semibold};
use super::widgets::{self, ButtonKind};
use crate::i18n::{tr, trf};

/// Almacén que el usuario puede elegir desde el diálogo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreOption {
    pub id: String,
    pub label: String,
    pub icon: &'static str,
}

/// Resultado de una interacción con el diálogo en un fotograma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerEvent {
    None,
    Accepted(usize),
    Cancelled,
    Refresh,
    ChangeStore(String),
}

#[derive(Debug, Default)]
pub struct CertPicker {
    pub open: bool,
    /// Texto bajo el título (p. ej. el origen de una petición web).
    pub subtitle: Option<String>,
    pub store_label: String,
    pub stores: Vec<StoreOption>,
    pub allow_change_store: bool,
    pub certs: Vec<CertItem>,
    pub loading: bool,
    pub error: Option<String>,
    pub search: String,
    pub selected: Option<usize>,
    pub expanded: Option<usize>,
    pub view: CertListView,
    /// Mostrar la casilla de "recordar durante la sesión".
    pub show_remember: bool,
    pub remember: bool,
    pub accept_label: String,
    /// Certificados caducados que el filtro de las preferencias oculta.
    pub hidden_expired: usize,
}

impl CertPicker {
    pub fn open_with(&mut self, store_label: impl Into<String>, certs: Vec<CertItem>) {
        self.open = true;
        self.loading = false;
        self.error = None;
        self.store_label = store_label.into();
        self.search.clear();
        self.expanded = None;
        self.set_certs(certs);
        if self.accept_label.is_empty() {
            self.accept_label = tr("Usar este certificado").into();
        }
    }

    pub fn set_certs(&mut self, mut certs: Vec<CertItem>) {
        // Orden alfabético sin distinguir mayúsculas, como AutoFirma.
        certs.sort_by_key(|c| c.info.subject_cn.to_lowercase());
        self.selected = if certs.is_empty() { None } else { Some(0) };
        self.certs = certs;
    }

    fn visible(&self) -> Vec<usize> {
        let q = self.search.trim().to_lowercase();
        (0..self.certs.len())
            .filter(|&i| q.is_empty() || self.certs[i].search_text().contains(&q))
            .collect()
    }

    /// Dibuja el diálogo si está abierto.
    pub fn show(&mut self, ctx: &egui::Context, p: &Palette) -> PickerEvent {
        if !self.open {
            return PickerEvent::None;
        }
        let mut event = PickerEvent::None;
        let visible = self.visible();
        if let Some(sel) = self.selected
            && !visible.contains(&sel)
        {
            self.selected = visible.first().copied();
        }

        self.handle_keys(ctx, &visible, &mut event);

        let modal = egui::Modal::new(egui::Id::unique("cert_picker"))
            .backdrop_color(Color32::from_black_alpha(if p.dark { 150 } else { 90 }))
            .frame(
                Frame::new()
                    .fill(p.surface)
                    .corner_radius(CornerRadius::same(16))
                    .stroke(Stroke::new(1.0, p.border))
                    .inner_margin(Margin::same(24)),
            );
        let response = modal.show(ctx, |ui| {
            ui.set_width(600.0);
            // Cabecera.
            ui.horizontal(|ui| {
                widgets::status_circle(ui, icons::SIGNATURE, 40.0, p.primary, p.primary_soft);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr("Elige tu certificado"))
                            .font(FontId::new(19.0, semibold()))
                            .color(p.text),
                    );
                    let sub = self
                        .subtitle
                        .clone()
                        .unwrap_or_else(|| tr("Selecciona el certificado con el que quieres firmar").into());
                    ui.label(RichText::new(sub).size(13.0).color(p.text_muted));
                });
            });
            ui.add_space(14.0);

            self.list_section(ui, p, &visible, &mut event, 380.0);

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if self.show_remember {
                    ui.checkbox(
                        &mut self.remember,
                        RichText::new(tr("Recordar durante la sesión")).size(13.0),
                    );
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let can_accept = self.selected.is_some() && !self.loading;
                    let label = if self.accept_label.is_empty() {
                        tr("Usar este certificado")
                    } else {
                        &self.accept_label
                    };
                    if widgets::button(ui, p, ButtonKind::Primary, Some(icons::CHECK), label, can_accept).clicked()
                        && let Some(sel) = self.selected
                    {
                        event = PickerEvent::Accepted(sel);
                    }
                    if widgets::button(ui, p, ButtonKind::Secondary, None, tr("Cancelar"), true).clicked() {
                        event = PickerEvent::Cancelled;
                    }
                });
            });
        });
        if response.should_close() && event == PickerEvent::None {
            event = PickerEvent::Cancelled;
        }
        if matches!(event, PickerEvent::Accepted(_) | PickerEvent::Cancelled) {
            self.open = false;
        }
        event
    }

    /// Atiende el teclado (flechas, Intro, Esc, F5).
    fn handle_keys(&mut self, ctx: &egui::Context, visible: &[usize], event: &mut PickerEvent) {
        ctx.input(|i| {
            if i.key_pressed(Key::Escape) {
                *event = PickerEvent::Cancelled;
            }
            if i.key_pressed(Key::F5) {
                *event = PickerEvent::Refresh;
            }
            if let Some(sel) = self.selected {
                let pos = visible.iter().position(|&v| v == sel).unwrap_or(0);
                if i.key_pressed(Key::ArrowDown) && pos + 1 < visible.len() {
                    self.selected = Some(visible[pos + 1]);
                }
                if i.key_pressed(Key::ArrowUp) && pos > 0 {
                    self.selected = Some(visible[pos - 1]);
                }
                if i.key_pressed(Key::Enter) {
                    *event = PickerEvent::Accepted(sel);
                }
            }
        });
    }

    /// Barra de herramientas y lista de certificados (reutilizable fuera del
    /// diálogo, p. ej. en la ventana de peticiones desde la web).
    pub fn list_section(
        &mut self,
        ui: &mut Ui,
        p: &Palette,
        visible: &[usize],
        event: &mut PickerEvent,
        max_height: f32,
    ) {
        // Barra: almacén, vista, búsqueda, recargar.
        ui.horizontal(|ui| {
            if self.allow_change_store && !self.stores.is_empty() {
                egui::ComboBox::from_id_salt("picker_store")
                    .selected_text(widgets::icon_job(
                        icons::VAULT,
                        &self.store_label,
                        13.5,
                        p.text_muted,
                        p.text,
                    ))
                    .width(230.0)
                    .show_ui(ui, |ui| {
                        for s in &self.stores {
                            if ui
                                .selectable_label(
                                    false,
                                    widgets::icon_job(s.icon, &s.label, 13.5, p.text_muted, p.text),
                                )
                                .clicked()
                            {
                                *event = PickerEvent::ChangeStore(s.id.clone());
                            }
                        }
                    });
            } else {
                widgets::icon_label(ui, p, icons::VAULT, &self.store_label);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(widgets::icon_text(icons::ARROWS_CLOCKWISE, 16.0, p.text_muted)).frame(false),
                    )
                    .on_hover_text(tr("Recargar la lista de certificados (F5)"))
                    .clicked()
                {
                    *event = PickerEvent::Refresh;
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.search)
                        .hint_text(widgets::icon_job(
                            icons::MAGNIFYING_GLASS,
                            tr("Buscar por nombre, NIF o emisor"),
                            13.0,
                            p.text_faint,
                            p.text_faint,
                        ))
                        .desired_width(230.0),
                );
            });
        });
        ui.add_space(6.0);
        segmented(ui, p, &mut self.view);
        ui.add_space(10.0);

        if self.loading {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.spinner();
                ui.label(RichText::new(tr("Cargando certificados…")).color(p.text_muted));
                ui.add_space(40.0);
            });
        } else if let Some(err) = &self.error {
            widgets::callout(
                ui,
                p,
                widgets::CalloutKind::Error,
                tr("No se ha podido cargar el almacén"),
                Some(err),
            );
        } else if self.certs.is_empty() {
            empty_state(ui, p);
        } else if visible.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(30.0);
                ui.label(RichText::new(tr("Ningún certificado coincide con la búsqueda")).color(p.text_muted));
                ui.add_space(30.0);
            });
        } else {
            ScrollArea::vertical()
                .max_height(max_height)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for &i in visible {
                        let selected = self.selected == Some(i);
                        let expanded = self.expanded == Some(i);
                        let r = cert_row(ui, p, &self.certs[i], self.view, selected, expanded);
                        if r.clicked {
                            self.selected = Some(i);
                        }
                        if r.double_clicked {
                            *event = PickerEvent::Accepted(i);
                        }
                        if r.toggle_details {
                            self.expanded = if expanded { None } else { Some(i) };
                        }
                        ui.add_space(6.0);
                    }
                });
        }
        if self.hidden_expired > 0 && !self.loading {
            let n = self.hidden_expired;
            let text = if n == 1 {
                tr("1 certificado caducado oculto. Puedes mostrar los caducados en Preferencias.").to_string()
            } else {
                trf(
                    "{0} certificados caducados ocultos. Puedes mostrar los caducados en Preferencias.",
                    &[&n],
                )
            };
            ui.label(RichText::new(text).size(12.0).color(p.text_faint));
        }
    }

    /// Lista embebida: devuelve el evento producido (selección, doble clic…).
    pub fn show_embedded(&mut self, ui: &mut Ui, p: &Palette, max_height: f32) -> PickerEvent {
        let mut event = PickerEvent::None;
        let visible = self.visible();
        if let Some(sel) = self.selected
            && !visible.contains(&sel)
        {
            self.selected = visible.first().copied();
        }
        self.handle_keys(ui.ctx(), &visible, &mut event);
        self.list_section(ui, p, &visible, &mut event, max_height);
        event
    }
}

struct RowResult {
    clicked: bool,
    double_clicked: bool,
    toggle_details: bool,
}

fn cert_row(ui: &mut Ui, p: &Palette, c: &CertItem, view: CertListView, selected: bool, expanded: bool) -> RowResult {
    let state = c.state();
    let (state_fg, state_bg) = state_colors(state, p);
    let fill = if selected { p.primary_soft } else { p.surface };
    let stroke = if selected {
        Stroke::new(1.5, p.primary)
    } else {
        Stroke::new(1.0, p.border)
    };
    let mut toggle_details = false;
    let inner = Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                widgets::status_circle(ui, c.family_icon(), 40.0, state_fg, state_bg);
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(c.title(view))
                                .font(FontId::new(14.5, semibold()))
                                .color(p.text),
                        );
                        match state {
                            CertState::ExpiringSoon => {
                                widgets::chip(
                                    ui,
                                    &trf("Caduca en {0} días", &[&c.days_left().max(0)]),
                                    p.warning,
                                    p.warning_soft,
                                );
                            }
                            CertState::Expired => {
                                widgets::chip(ui, tr("Caducado"), p.danger, p.danger_soft);
                            }
                            CertState::NotYetValid => {
                                widgets::chip(ui, tr("Aún no válido"), p.danger, p.danger_soft);
                            }
                            CertState::Valid => {}
                        }
                    });
                    let second = match view {
                        CertListView::Representative => trf("Representante: {0}", &[&c.info.subject_cn]),
                        CertListView::Pseudonym if c.pseudonym.is_some() => trf(
                            "Organismo: {0} · {1}",
                            &[
                                &c.subject_ou.clone().or(c.subject_o.clone()).unwrap_or_default(),
                                &c.usage_text(),
                            ],
                        ),
                        _ => format!("{} · {}", c.info.issuer_cn, c.usage_text()),
                    };
                    ui.label(RichText::new(second).size(12.5).color(p.text_muted));
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(trf(
                                "Válido del {0} al {1}",
                                &[&fmt_date(c.info.not_before), &fmt_date(c.info.not_after)],
                            ))
                            .size(12.5)
                            .color(p.text_faint),
                        );
                        let link = ui.add(
                            egui::Label::new(
                                RichText::new(if expanded {
                                    tr("Ocultar detalles")
                                } else {
                                    tr("Ver detalles")
                                })
                                .size(12.5)
                                .color(p.primary)
                                .underline(),
                            )
                            .sense(Sense::click()),
                        );
                        if link.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                            toggle_details = true;
                        }
                    });
                });
            });
            if expanded {
                ui.add_space(8.0);
                ui.separator();
                cert_details(ui, p, c);
            }
        });
    let rect = inner.response.rect;
    radio_dot(ui, p, Pos2::new(rect.right() - 26.0, rect.top() + 34.0), selected);
    let resp = ui.interact(rect, ui.scope_id().with(("cert_row", &c.alias)), Sense::click());
    RowResult {
        clicked: resp.clicked() && !toggle_details,
        double_clicked: resp.double_clicked() && !toggle_details,
        toggle_details,
    }
}

/// Ficha detallada de un certificado.
pub fn cert_details(ui: &mut Ui, p: &Palette, c: &CertItem) {
    widgets::kv_row(ui, p, tr("Titular"), &c.info.subject_dn);
    widgets::kv_row(ui, p, tr("Emisor"), &c.info.issuer_dn);
    if let Some(n) = &c.info.subject_serial_number {
        widgets::kv_row(ui, p, tr("Nº de serie del titular"), n);
    }
    widgets::kv_row(ui, p, tr("Nº de serie"), &c.info.serial_hex.to_uppercase());
    widgets::kv_row(ui, p, tr("Uso de la clave"), c.usage_text());
    if !c.info.policies.is_empty() {
        widgets::kv_row(ui, p, tr("Políticas"), &c.info.policies.join(", "));
    }
    widgets::kv_row(ui, p, tr("Huella SHA-256"), &group_hex(&c.info.sha256_hex));
    widgets::kv_row(ui, p, tr("Alias"), &c.alias);
}

/// Huella en grupos de 4 bytes separados por espacios (para que pueda partirse
/// en varias líneas).
fn group_hex(h: &str) -> String {
    let upper = h.to_uppercase();
    let bytes: Vec<String> = upper
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    bytes.chunks(4).map(|g| g.join(":")).collect::<Vec<_>>().join(" ")
}

fn radio_dot(ui: &mut Ui, p: &Palette, c: Pos2, on: bool) {
    ui.painter()
        .circle_stroke(c, 9.0, Stroke::new(1.6, if on { p.primary } else { p.text_faint }));
    if on {
        ui.painter().circle_filled(c, 5.0, p.primary);
    }
}

fn segmented(ui: &mut Ui, p: &Palette, view: &mut CertListView) {
    let options = [
        (CertListView::Personal, tr("Personales")),
        (CertListView::Representative, tr("De representante")),
        (CertListView::Pseudonym, tr("De seudónimo")),
    ];
    let height = 30.0;
    let widths: Vec<f32> = options
        .iter()
        .map(|(_, l)| {
            ui.painter()
                .layout_no_wrap(l.to_string(), FontId::new(13.0, semibold()), p.text)
                .size()
                .x
                + 28.0
        })
        .collect();
    let total: f32 = widths.iter().sum::<f32>() + 6.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(total, height), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(8), p.surface_alt);
    let mut x = rect.left() + 3.0;
    for ((opt, label), w) in options.iter().zip(widths) {
        let r = Rect::from_min_size(Pos2::new(x, rect.top() + 3.0), Vec2::new(w, height - 6.0));
        let resp = ui.interact(r, ui.scope_id().with(("seg", label)), Sense::click());
        let on = *view == *opt;
        if on {
            ui.painter().rect_filled(r, CornerRadius::same(6), p.surface);
            ui.painter()
                .rect_stroke(r, CornerRadius::same(6), Stroke::new(1.0, p.border), StrokeKind::Inside);
        }
        ui.painter().text(
            r.center(),
            Align2::CENTER_CENTER,
            label,
            FontId::new(13.0, if on { semibold() } else { egui::FontFamily::Proportional }),
            if on { p.text } else { p.text_muted },
        );
        if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            *view = *opt;
        }
        x += w;
    }
}

fn empty_state(ui: &mut Ui, p: &Palette) {
    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        widgets::status_circle(ui, icons::IDENTIFICATION_CARD, 56.0, p.text_faint, p.surface_alt);
        ui.add_space(8.0);
        ui.label(
            RichText::new(tr("No hay certificados válidos en este almacén"))
                .font(FontId::new(15.0, theme::semibold()))
                .color(p.text),
        );
        ui.label(
            RichText::new(tr(
                "Inserta tu tarjeta o DNIe en el lector y pulsa Recargar, o elige otro almacén.",
            ))
            .size(13.0)
            .color(p.text_muted),
        );
        ui.add_space(24.0);
    });
}
