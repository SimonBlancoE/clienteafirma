#![allow(dead_code)]
//! Componentes visuales propios (tarjetas, botones, navegación, zona de
//! arrastre...), dibujados a mano para tener un aspecto coherente y moderno.

use eframe::egui::{
    self, Align2, Color32, CornerRadius, FontFamily, FontId, Frame, Margin, Pos2, Rect, Response, RichText, Sense,
    Shadow, Shape, Stroke, StrokeKind, Ui, UiBuilder, Vec2, WidgetInfo, Role,
};

use super::icons;
use super::theme::{Palette, semibold};

/// Marco de tarjeta: superficie con borde suave y sombra ligera.
pub fn card_frame(p: &Palette) -> Frame {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(20))
        .shadow(Shadow {
            offset: [0, 1],
            blur: 3,
            spread: 0,
            color: Color32::from_black_alpha(if p.dark { 60 } else { 10 }),
        })
}

/// Muestra contenido dentro de una tarjeta que ocupa todo el ancho.
pub fn card<R>(ui: &mut Ui, p: &Palette, add: impl FnOnce(&mut Ui) -> R) -> R {
    card_frame(p)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Icono de la fuente Phosphor.
pub fn icon_text(glyph: &str, size: f32, color: Color32) -> RichText {
    RichText::new(glyph).family(super::theme::icons()).size(size).color(color)
}

/// Título de página con subtítulo opcional.
pub fn page_header(ui: &mut Ui, p: &Palette, title: &str, subtitle: Option<&str>) {
    ui.label(RichText::new(title).font(FontId::new(26.0, semibold())).color(p.text));
    if let Some(s) = subtitle {
        ui.add_space(2.0);
        ui.label(RichText::new(s).size(14.5).color(p.text_muted));
    }
    ui.add_space(18.0);
}

/// Título de sección dentro de una página o tarjeta.
pub fn section_title(ui: &mut Ui, p: &Palette, title: &str) {
    ui.label(RichText::new(title).font(FontId::new(15.5, semibold())).color(p.text));
}

/// Tipo visual de botón.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Ghost,
    Danger,
}

/// Botón con icono opcional. `min_width` 0 = ajustado al contenido.
pub fn button(ui: &mut Ui, p: &Palette, kind: ButtonKind, icon: Option<&str>, label: &str, enabled: bool) -> Response {
    button_sized(ui, p, kind, icon, label, enabled, 0.0, 40.0)
}

#[allow(clippy::too_many_arguments)]
pub fn button_sized(
    ui: &mut Ui,
    p: &Palette,
    kind: ButtonKind,
    icon: Option<&str>,
    label: &str,
    enabled: bool,
    min_width: f32,
    height: f32,
) -> Response {
    let font = FontId::new(14.5, semibold());
    let text_galley = ui.painter().layout_no_wrap(label.to_owned(), font.clone(), Color32::WHITE);
    let icon_size = 17.0;
    let icon_w = if icon.is_some() { icon_size + 8.0 } else { 0.0 };
    let pad = if kind == ButtonKind::Ghost { 10.0 } else { 18.0 };
    let width = (text_galley.size().x + icon_w + pad * 2.0).max(min_width);
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), sense);
    response.widget_info(|| WidgetInfo::labeled(Role::Button, enabled, label));

    if ui.is_rect_visible(rect) {
        let hovered = enabled && response.hovered();
        let pressed = enabled && response.is_pointer_button_down_on();
        let (fill, stroke, fg) = match kind {
            ButtonKind::Primary => {
                let fill = if hovered || pressed { p.primary_hover } else { p.primary };
                (fill, Stroke::NONE, p.on_primary)
            }
            ButtonKind::Danger => {
                let fill = if hovered { p.danger.gamma_multiply(0.9) } else { p.danger };
                (fill, Stroke::NONE, Color32::WHITE)
            }
            ButtonKind::Secondary => {
                let fill = if hovered { p.surface_alt } else { p.surface };
                (fill, Stroke::new(1.0, if hovered { p.text_faint } else { p.border }), p.text)
            }
            ButtonKind::Ghost => {
                let fill = if hovered { p.surface_alt } else { Color32::TRANSPARENT };
                (fill, Stroke::NONE, p.primary)
            }
        };
        let (fill, fg) = if enabled { (fill, fg) } else { (fill.gamma_multiply(0.45), fg.gamma_multiply(0.7)) };
        let painter = ui.painter();
        let radius = CornerRadius::same(8);
        let rect = if pressed { rect.shrink(0.5) } else { rect };
        painter.rect_filled(rect, radius, fill);
        if stroke != Stroke::NONE {
            painter.rect_stroke(rect, radius, stroke, StrokeKind::Inside);
        }
        if response.has_focus() {
            painter.rect_stroke(rect.expand(3.0), CornerRadius::same(10), Stroke::new(2.0, p.primary.gamma_multiply(0.6)), StrokeKind::Inside);
        }
        let content_w = text_galley.size().x + icon_w;
        let mut x = rect.center().x - content_w / 2.0;
        if let Some(icon) = icon {
            painter.text(Pos2::new(x, rect.center().y), Align2::LEFT_CENTER, icon, FontId::new(icon_size, super::theme::icons()), fg);
            x += icon_w;
        }
        let galley = painter.layout_no_wrap(label.to_owned(), font, fg);
        painter.galley(Pos2::new(x, rect.center().y - galley.size().y / 2.0), galley, fg);
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// Elemento de navegación de la barra lateral.
pub fn nav_item(ui: &mut Ui, p: &Palette, icon: &str, label: &str, selected: bool) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 40.0), Sense::click());
    response.widget_info(|| WidgetInfo::selected(Role::Tab, true, selected, label));
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let hovered = response.hovered();
        if selected {
            painter.rect_filled(rect, CornerRadius::same(8), p.primary_soft);
            let bar = Rect::from_min_size(Pos2::new(rect.left(), rect.top() + 9.0), Vec2::new(3.0, rect.height() - 18.0));
            painter.rect_filled(bar, CornerRadius::same(2), p.primary);
        } else if hovered {
            painter.rect_filled(rect, CornerRadius::same(8), p.surface_alt);
        }
        if response.has_focus() {
            painter.rect_stroke(rect, CornerRadius::same(8), Stroke::new(2.0, p.primary.gamma_multiply(0.6)), StrokeKind::Inside);
        }
        let color = if selected { p.primary } else { p.text_muted };
        let text_color = if selected { p.text } else { p.text_muted };
        painter.text(
            Pos2::new(rect.left() + 16.0, rect.center().y),
            Align2::LEFT_CENTER,
            icon,
            FontId::new(19.0, if selected { super::theme::icons_fill() } else { super::theme::icons() }),
            color,
        );
        painter.text(
            Pos2::new(rect.left() + 46.0, rect.center().y),
            Align2::LEFT_CENTER,
            label,
            FontId::new(14.5, if selected { semibold() } else { FontFamily::Proportional }),
            text_color,
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Etiqueta redondeada (formato, estado...).
pub fn chip(ui: &mut Ui, text: &str, fg: Color32, bg: Color32) -> Response {
    let font = FontId::new(12.0, semibold());
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, fg);
    let size = galley.size() + Vec2::new(18.0, 8.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().rect_filled(rect, CornerRadius::same(255), bg);
        ui.painter().galley(rect.center() - galley.size() / 2.0, galley, fg);
    }
    response
}

/// Puntos de un rectángulo redondeado (para trazos discontinuos).
fn rounded_rect_points(rect: Rect, r: f32) -> Vec<Pos2> {
    let mut pts = Vec::new();
    let corners = [
        (Pos2::new(rect.right() - r, rect.top() + r), -90.0f32),
        (Pos2::new(rect.right() - r, rect.bottom() - r), 0.0),
        (Pos2::new(rect.left() + r, rect.bottom() - r), 90.0),
        (Pos2::new(rect.left() + r, rect.top() + r), 180.0),
    ];
    for (c, start) in corners {
        for i in 0..=8 {
            let a = (start + 90.0 * i as f32 / 8.0).to_radians();
            pts.push(Pos2::new(c.x + r * a.cos(), c.y + r * a.sin()));
        }
    }
    pts.push(pts[0]);
    pts
}

/// Zona para arrastrar ficheros. Devuelve el `Rect` ocupado para que el
/// llamante coloque contenido encima.
pub fn drop_zone(ui: &mut Ui, p: &Palette, height: f32, highlighted: bool, add: impl FnOnce(&mut Ui)) -> Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        let fill = if highlighted { p.primary_soft } else { p.surface };
        painter.rect_filled(rect, CornerRadius::same(16), fill);
        let color = if highlighted { p.primary } else if response.hovered() { p.text_faint } else { p.border.gamma_multiply(1.6) };
        let pts = rounded_rect_points(rect.shrink(1.0), 16.0);
        painter.extend(Shape::dashed_line(&pts, Stroke::new(1.6, color), 8.0, 6.0));
    }
    let mut child = ui.new_child(UiBuilder::new().max_rect(rect.shrink(24.0)).layout(egui::Layout::top_down(egui::Align::Center)));
    add(&mut child);
    response
}

/// Indicador circular con icono (resultado de validación, pasos...).
pub fn status_circle(ui: &mut Ui, glyph: &str, size: f32, fg: Color32, bg: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    ui.painter().circle_filled(rect.center(), size / 2.0, bg);
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        glyph,
        FontId::new(size * 0.52, super::theme::icons_fill()),
        fg,
    );
}

/// Fila "etiqueta: valor" para fichas de detalle.
pub fn kv_row(ui: &mut Ui, p: &Palette, key: &str, value: &str) {
    ui.horizontal_top(|ui| {
        ui.allocate_ui_with_layout(Vec2::new(150.0, 18.0), egui::Layout::left_to_right(egui::Align::Min), |ui| {
            ui.set_min_width(150.0);
            ui.label(RichText::new(key).color(p.text_muted).size(13.0));
        });
        ui.add(egui::Label::new(RichText::new(value).color(p.text).size(13.5)).wrap().selectable(true));
    });
}

/// Mensaje destacado (informativo, aviso, error o éxito).
pub fn callout(ui: &mut Ui, p: &Palette, kind: CalloutKind, title: &str, body: Option<&str>) {
    let (fg, bg, glyph) = match kind {
        CalloutKind::Info => (p.info, p.info_soft, icons::INFO),
        CalloutKind::Success => (p.success, p.success_soft, icons::CHECK_CIRCLE),
        CalloutKind::Warning => (p.warning, p.warning_soft, icons::WARNING),
        CalloutKind::Error => (p.danger, p.danger_soft, icons::X_CIRCLE),
    };
    Frame::new().fill(bg).corner_radius(CornerRadius::same(10)).inner_margin(Margin::symmetric(14, 12)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_top(|ui| {
            ui.label(RichText::new(glyph).family(super::theme::icons_fill()).size(18.0).color(fg));
            ui.vertical(|ui| {
                ui.label(RichText::new(title).font(FontId::new(14.0, semibold())).color(if p.dark { fg } else { p.text }));
                if let Some(b) = body {
                    ui.label(RichText::new(b).size(13.0).color(p.text_muted));
                }
            });
        });
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalloutKind {
    Info,
    Success,
    Warning,
    Error,
}

/// Texto con un icono delante (cada parte con su fuente), utilizable como
/// `WidgetText` en etiquetas, combos y textos de ayuda.
pub fn icon_job(icon: &str, text: &str, size: f32, icon_color: Color32, text_color: Color32) -> egui::text::LayoutJob {
    use egui::text::{LayoutJob, TextFormat};
    let mut job = LayoutJob::default();
    job.append(icon, 0.0, TextFormat { font_id: FontId::new(size + 2.0, super::theme::icons()), color: icon_color, valign: egui::Align::Center, ..Default::default() });
    job.append(text, 7.0, TextFormat { font_id: FontId::new(size, FontFamily::Proportional), color: text_color, valign: egui::Align::Center, ..Default::default() });
    job
}

/// Etiqueta con icono.
pub fn icon_label(ui: &mut Ui, p: &Palette, icon: &str, text: &str) -> Response {
    ui.label(icon_job(icon, text, 13.5, p.text_muted, p.text_muted))
}

/// Etiqueta redondeada con icono.
pub fn chip_icon(ui: &mut Ui, icon: &str, text: &str, fg: Color32, bg: Color32) -> Response {
    let mut job = icon_job(icon, text, 12.0, fg, fg);
    if let Some(s) = job.sections.get_mut(1) {
        s.format.font_id = FontId::new(12.0, semibold());
    }
    let galley = ui.painter().layout_job(job);
    let size = galley.size() + Vec2::new(18.0, 8.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().rect_filled(rect, CornerRadius::same(255), bg);
        ui.painter().galley(rect.center() - galley.size() / 2.0, galley, fg);
    }
    response
}
