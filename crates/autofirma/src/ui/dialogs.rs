//! Diálogos de PIN/contraseña, confirmación y texto que piden los hilos de
//! trabajo a través del puente ([`crate::services::bridge`]).

use afirma_keystores::{PasswordResponse, Secret};
use eframe::egui::{self, Color32, CornerRadius, FontId, Frame, Key, Layout, Margin, RichText, Stroke};

use super::icons;
use super::theme::{Palette, semibold};
use super::widgets::{self, ButtonKind};
use crate::services::bridge::{UiInbox, UiRequest};

fn modal_frame(p: &Palette) -> Frame {
    Frame::new()
        .fill(p.surface)
        .corner_radius(CornerRadius::same(16))
        .stroke(Stroke::new(1.0, p.border))
        .inner_margin(Margin::same(22))
}

/// Muestra el diálogo de la petición pendiente, si la hay.
pub fn show_inbox(ctx: &egui::Context, p: &Palette, inbox: &mut UiInbox) {
    inbox.pump();
    let Some(req) = inbox.current.take() else { return };
    let backdrop = Color32::from_black_alpha(if p.dark { 150 } else { 90 });
    let (enter, esc) = ctx.input(|i| (i.key_pressed(Key::Enter), i.key_pressed(Key::Escape)));
    match req {
        UiRequest::Password { request, reply } => {
            let mut done: Option<PasswordResponse> = None;
            egui::Modal::new(egui::Id::unique("pin_dialog")).backdrop_color(backdrop).frame(modal_frame(p)).show(ctx, |ui| {
                ui.set_width(420.0);
                ui.horizontal(|ui| {
                    let glyph = if request.smartcard { icons::IDENTIFICATION_BADGE } else { icons::LOCK_KEY };
                    widgets::status_circle(ui, glyph, 40.0, p.primary, p.primary_soft);
                    ui.vertical(|ui| {
                        let title = request.title.clone().unwrap_or_else(|| {
                            if request.smartcard { "PIN de la tarjeta".into() } else { "Contraseña".into() }
                        });
                        ui.label(RichText::new(title).font(FontId::new(18.0, semibold())));
                        if let Some(d) = &request.device_label {
                            ui.label(RichText::new(d).size(12.5).color(p.text_muted));
                        }
                    });
                });
                ui.add_space(10.0);
                if let Some(r) = &request.retry {
                    widgets::callout(ui, p, widgets::CalloutKind::Error, r.message(), None);
                    ui.add_space(6.0);
                }
                ui.label(RichText::new(&request.prompt).size(13.5));
                if let Some(n) = request.retries_left {
                    let txt = if request.final_try {
                        "Último intento: si fallas, el PIN quedará bloqueado.".to_string()
                    } else {
                        format!("Intentos restantes: {n}")
                    };
                    ui.label(RichText::new(txt).size(12.5).color(p.warning));
                }
                ui.add_space(8.0);
                let edit = ui.add(egui::TextEdit::singleline(&mut inbox.secret).password(true).desired_width(f32::INFINITY));
                edit.request_focus();
                if request.allow_remember {
                    ui.checkbox(&mut inbox.remember, "Recordar durante la sesión");
                }
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    let len_ok = request.min_len.is_none_or(|m| inbox.secret.chars().count() >= m)
                        && request.max_len.is_none_or(|m| inbox.secret.chars().count() <= m);
                    if (widgets::button(ui, p, ButtonKind::Primary, Some(icons::CHECK), "Aceptar", len_ok).clicked() || (enter && len_ok))
                        && done.is_none()
                    {
                        done = Some(PasswordResponse::Provided { secret: Secret::new(inbox.secret.clone()), remember: inbox.remember });
                    }
                    if widgets::button(ui, p, ButtonKind::Secondary, None, "Cancelar", true).clicked() || esc {
                        done = Some(PasswordResponse::Cancelled);
                    }
                });
            });
            match done {
                Some(resp) => {
                    inbox.secret.clear();
                    let _ = reply.send(resp);
                }
                None => inbox.current = Some(UiRequest::Password { request, reply }),
            }
        }
        UiRequest::ConfirmSignature { message, reply } => {
            match confirm_modal(ctx, p, "Confirmar la firma", &message, "Firmar", enter, esc) {
                Some(b) => {
                    let _ = reply.send(b);
                }
                None => inbox.current = Some(UiRequest::ConfirmSignature { message, reply }),
            }
        }
        UiRequest::Confirm { title, message, reply } => match confirm_modal(ctx, p, &title, &message, "Continuar", false, esc) {
            Some(b) => {
                let _ = reply.send(b);
            }
            None => inbox.current = Some(UiRequest::Confirm { title, message, reply }),
        },
        UiRequest::Text { prompt, secret, reply } => {
            let mut done: Option<Option<String>> = None;
            egui::Modal::new(egui::Id::unique("text_dialog")).backdrop_color(backdrop).frame(modal_frame(p)).show(ctx, |ui| {
                ui.set_width(420.0);
                ui.label(RichText::new(&prompt).size(14.0));
                ui.add_space(8.0);
                let r = ui.add(egui::TextEdit::singleline(&mut inbox.secret).password(secret).desired_width(f32::INFINITY));
                r.request_focus();
                ui.add_space(12.0);
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::button(ui, p, ButtonKind::Primary, None, "Aceptar", true).clicked() || enter {
                        done = Some(Some(inbox.secret.clone()));
                    }
                    if widgets::button(ui, p, ButtonKind::Secondary, None, "Cancelar", true).clicked() || esc {
                        done = Some(None);
                    }
                });
            });
            match done {
                Some(v) => {
                    inbox.secret.clear();
                    let _ = reply.send(v);
                }
                None => inbox.current = Some(UiRequest::Text { prompt, secret, reply }),
            }
        }
    }
}

/// Diálogo sí/no. Devuelve `Some(respuesta)` cuando el usuario decide.
pub fn confirm_modal(ctx: &egui::Context, p: &Palette, title: &str, message: &str, yes: &str, enter: bool, esc: bool) -> Option<bool> {
    let mut out = None;
    egui::Modal::new(egui::Id::unique(("confirm", title)))
        .backdrop_color(Color32::from_black_alpha(if p.dark { 150 } else { 90 }))
        .frame(modal_frame(p))
        .show(ctx, |ui| {
            ui.set_width(460.0);
            ui.horizontal(|ui| {
                widgets::status_circle(ui, icons::QUESTION, 40.0, p.warning, p.warning_soft);
                ui.label(RichText::new(title).font(FontId::new(17.0, semibold())));
            });
            ui.add_space(10.0);
            ui.add(egui::Label::new(RichText::new(message).size(13.5)).wrap());
            ui.add_space(14.0);
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button(ui, p, ButtonKind::Primary, None, yes, true).clicked() || enter {
                    out = Some(true);
                }
                if widgets::button(ui, p, ButtonKind::Secondary, None, "Cancelar", true).clicked() || esc {
                    out = Some(false);
                }
            });
        });
    out
}
