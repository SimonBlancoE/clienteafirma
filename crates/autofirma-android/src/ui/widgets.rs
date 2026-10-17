//! Componentes táctiles dibujados a mano con el aspecto del escritorio: botones, filas de
//! lista, interruptores, casillas, campos de texto con el teclado de Android, tarjetas y
//! hojas inferiores. Todos miden al menos 48 dp de alto (pautas de Android y WCAG 2.5.5),
//! declaran su función y su texto para la accesibilidad (`WidgetInfo`, que egui pasa a
//! AccessKit) y se registran en [`Targets`] con un identificador estable, que la prueba del
//! emulador usa para pulsarlos.

use egui::text::LayoutJob;
use egui::{
    Align, Align2, Color32, Context, CornerRadius, FontFamily, FontId, Frame, Id, Margin, Order, Rect, Response, Role,
    Sense, Stroke, StrokeKind, TextEdit, TextFormat, Ui, UiBuilder, Vec2, WidgetInfo, pos2, vec2,
};

use super::icons;
use super::theme::{Palette, icons as icon_font, semibold, size};
use crate::ime::{FieldEvents, FieldSpec, ImeController};

/// Altura mínima de un elemento táctil.
pub const TOUCH: f32 = 48.0;

/// Elementos pulsables visibles en la última pasada y su posición.
#[derive(Default)]
pub struct Targets {
    current: Vec<(&'static str, Rect)>,
    logged: Vec<(&'static str, [i32; 2])>,
}

impl Targets {
    pub fn clear(&mut self) {
        self.current.clear();
    }

    /// Registra un elemento si su centro se ve (se puede pulsar).
    pub fn add(&mut self, tid: &'static str, rect: Rect, clip: Rect) {
        if clip.contains(rect.center()) {
            self.current.retain(|(t, _)| *t != tid);
            self.current.push((tid, rect));
        }
    }

    /// Rectángulo (puntos) de un elemento en la última pasada.
    pub fn rect(&self, tid: &str) -> Option<Rect> {
        self.current.iter().find(|(t, _)| *t == tid).map(|(_, r)| *r)
    }

    /// Identificadores visibles.
    pub fn ids(&self) -> Vec<&'static str> {
        self.current.iter().map(|(t, _)| *t).collect()
    }

    /// Olvida lo registrado (al cambiar de pantalla se vuelven a registrar todos).
    pub fn reset_log(&mut self) {
        self.logged.clear();
    }

    /// Centros en píxeles de los elementos nuevos o movidos desde la última llamada, y los
    /// que han dejado de verse (desplazamiento).
    pub fn changed_positions(&mut self, pixels_per_point: f32) -> (Vec<(&'static str, [i32; 2])>, Vec<&'static str>) {
        let now: Vec<_> = self
            .current
            .iter()
            .map(|(t, r)| {
                let c = r.center() * pixels_per_point;
                (*t, [c.x.round() as i32, c.y.round() as i32])
            })
            .collect();
        let changed = now.iter().filter(|e| !self.logged.contains(e)).copied().collect();
        let gone = self
            .logged
            .iter()
            .filter(|(t, _)| !now.iter().any(|(n, _)| n == t))
            .map(|(t, _)| *t)
            .collect();
        self.logged = now;
        (changed, gone)
    }
}

/// Lo que necesitan los componentes para dibujarse.
pub struct Cx<'a> {
    pub p: Palette,
    /// Escala del texto del sistema.
    pub scale: f32,
    pub ime: &'a mut ImeController,
    pub targets: &'a mut Targets,
}

impl Cx<'_> {
    pub fn font(&self, size: f32) -> FontId {
        FontId::new(size * self.scale, FontFamily::Proportional)
    }

    pub fn bold(&self, size: f32) -> FontId {
        FontId::new(size * self.scale, semibold())
    }

    pub fn icon(&self, size: f32) -> FontId {
        FontId::new(size, icon_font())
    }

    fn register(&mut self, ui: &Ui, tid: &'static str, rect: Rect) {
        self.targets.add(tid, rect, ui.clip_rect());
    }
}

fn layout(ui: &Ui, text: &str, font: FontId, color: Color32, wrap: f32) -> std::sync::Arc<egui::Galley> {
    ui.painter().layout(text.to_owned(), font, color, wrap.max(1.0))
}

fn paint_icon(ui: &Ui, cx: &Cx, center: egui::Pos2, glyph: &str, size: f32, color: Color32) {
    ui.painter()
        .text(center, Align2::CENTER_CENTER, glyph, cx.icon(size), color);
}

/// Zona pulsable con su información de accesibilidad.
fn touch(ui: &mut Ui, cx: &mut Cx, tid: &'static str, rect: Rect, info: WidgetInfo, enabled: bool) -> Response {
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let response = ui.interact(rect, Id::unique(tid), sense);
    response.widget_info(|| info.clone());
    cx.register(ui, tid, rect);
    response
}

/// Tipo de botón.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Text,
    Danger,
}

/// Botón a todo el ancho, con icono opcional.
pub fn button(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    kind: ButtonKind,
    glyph: Option<&str>,
    label: &str,
    enabled: bool,
) -> Response {
    let p = cx.p;
    let width = ui.available_width();
    let font = cx.bold(size::BUTTON);
    let (fg, fill, stroke) = match (kind, enabled) {
        (_, false) => (p.text_faint, p.surface_alt, Stroke::NONE),
        (ButtonKind::Primary, _) => (p.on_primary, p.primary, Stroke::NONE),
        (ButtonKind::Danger, _) => (Color32::WHITE, p.danger, Stroke::NONE),
        (ButtonKind::Secondary, _) => (p.primary, p.surface, Stroke::new(1.5, p.primary)),
        (ButtonKind::Text, _) => (p.primary, Color32::TRANSPARENT, Stroke::NONE),
    };
    let icon_w = if glyph.is_some() { 30.0 } else { 0.0 };
    let galley = layout(ui, label, font, fg, width - 40.0 - icon_w);
    let height = (galley.size().y + 26.0).max(52.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let response = touch(
        ui,
        cx,
        tid,
        rect,
        WidgetInfo::labeled(Role::Button, enabled, label),
        enabled,
    );
    let pressed = response.is_pointer_button_down_on();
    let fill = match (kind, pressed) {
        (ButtonKind::Primary, true) => p.primary_hover,
        (ButtonKind::Secondary | ButtonKind::Text, true) => p.primary_soft,
        (ButtonKind::Danger, true) => p.danger.linear_multiply(0.85),
        _ => fill,
    };
    let painter = ui.painter();
    painter.rect(rect, CornerRadius::same(14), fill, stroke, StrokeKind::Inside);
    let content_w = galley.size().x + icon_w;
    let left = rect.center().x - content_w / 2.0;
    if let Some(glyph) = glyph {
        paint_icon(ui, cx, pos2(left + 11.0, rect.center().y), glyph, 22.0, fg);
    }
    let pos = pos2(left + icon_w, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, fg);
    response
}

/// Botón redondo de icono (barra superior).
pub fn icon_button(ui: &mut Ui, cx: &mut Cx, tid: &'static str, rect: Rect, glyph: &str, label: &str) -> Response {
    let response = touch(ui, cx, tid, rect, WidgetInfo::labeled(Role::Button, true, label), true);
    if response.is_pointer_button_down_on() {
        ui.painter()
            .circle_filled(rect.center(), rect.width() / 2.0, cx.p.primary_soft);
    }
    paint_icon(ui, cx, rect.center(), glyph, 24.0, cx.p.text);
    response
}

/// Resultado de la barra superior.
#[derive(Debug, Default, Clone, Copy)]
pub struct TopBar {
    pub back: bool,
    pub action: Option<&'static str>,
}

/// Altura de la barra superior.
pub const TOP_BAR: f32 = 64.0;

/// Barra superior: flecha atrás, título y acciones (identificador, icono, texto accesible).
pub fn top_bar(
    ui: &mut Ui,
    cx: &mut Cx,
    rect: Rect,
    title: &str,
    back: bool,
    actions: &[(&'static str, &str, &str)],
) -> TopBar {
    let mut out = TopBar::default();
    let mut left = rect.left() + 4.0;
    if back {
        let r = Rect::from_center_size(pos2(left + 24.0, rect.center().y), Vec2::splat(TOUCH));
        out.back = icon_button(ui, cx, "back", r, icons::ARROW_LEFT, crate::i18n::tr("back")).clicked();
        left += 52.0;
    } else {
        left += 12.0;
    }
    let mut right = rect.right() - 4.0;
    for (tid, glyph, label) in actions.iter().rev() {
        let r = Rect::from_center_size(pos2(right - 24.0, rect.center().y), Vec2::splat(TOUCH));
        if icon_button(ui, cx, tid, r, glyph, label).clicked() {
            out.action = Some(tid);
        }
        right -= 48.0;
    }
    let font = cx.bold(size::TITLE);
    let mut job = LayoutJob::simple_singleline(title.to_owned(), font, cx.p.text);
    job.wrap.max_width = (right - left - 8.0).max(10.0);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let galley = ui.painter().layout_job(job);
    ui.painter()
        .galley(pos2(left, rect.center().y - galley.size().y / 2.0), galley, cx.p.text);
    let heading = ui.interact(rect.shrink2(vec2(60.0, 0.0)), Id::unique("titulo"), Sense::hover());
    heading.widget_info(|| WidgetInfo::labeled(Role::Heading, true, title));
    out
}

/// Título de sección (mayúsculas, como en Ajustes del original).
pub fn section_title(ui: &mut Ui, cx: &Cx, text: &str) {
    ui.add_space(14.0);
    let galley = layout(
        ui,
        text,
        cx.bold(size::SECTION),
        cx.p.text_muted,
        ui.available_width() - 8.0,
    );
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), galley.size().y + 8.0), Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(Role::Heading, true, text));
    ui.painter()
        .galley(pos2(rect.left() + 4.0, rect.top()), galley, cx.p.text_muted);
}

/// Marco de tarjeta.
pub fn card_frame(p: &Palette) -> Frame {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::same(18))
}

/// Tarjeta a todo el ancho.
pub fn card<R>(ui: &mut Ui, cx: &mut Cx, add: impl FnOnce(&mut Ui, &mut Cx) -> R) -> R {
    card_frame(&cx.p)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui, cx)
        })
        .inner
}

/// Grupo de filas de lista dentro de una tarjeta, separadas por líneas finas.
pub fn group<R>(ui: &mut Ui, cx: &mut Cx, add: impl FnOnce(&mut Ui, &mut Cx) -> R) -> R {
    Frame::new()
        .fill(cx.p.surface)
        .stroke(Stroke::new(1.0, cx.p.border))
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::symmetric(0, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            add(ui, cx)
        })
        .inner
}

/// Parte derecha de una fila.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Trailing<'a> {
    None,
    Chevron,
    /// Valor y flecha (p. ej. la abreviatura del idioma).
    Value(&'a str),
    /// Se abre fuera de la aplicación.
    External,
    /// Marca de elegido.
    Check(bool),
}

/// Fila de lista con icono, texto (y subtítulo) y parte derecha.
pub fn list_row(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    glyph: Option<&str>,
    label: &str,
    subtitle: Option<&str>,
    trailing: Trailing,
) -> Response {
    let p = cx.p;
    let first = ui.cursor().top() <= ui.min_rect().top() + 0.5;
    let width = ui.available_width();
    let left_pad = if glyph.is_some() { 16.0 + 40.0 + 14.0 } else { 18.0 };
    let value_galley = match trailing {
        Trailing::Value(v) => Some(layout(ui, v, cx.bold(size::SMALL), p.primary, 120.0)),
        _ => None,
    };
    let trailing_w = match trailing {
        Trailing::None => 8.0,
        Trailing::Check(_) | Trailing::Chevron | Trailing::External => 44.0,
        Trailing::Value(_) => 44.0 + value_galley.as_ref().map_or(0.0, |g| g.size().x + 6.0),
    };
    let text_w = width - left_pad - trailing_w;
    let title = layout(ui, label, cx.font(size::BODY), p.text, text_w);
    let sub = subtitle.map(|s| layout(ui, s, cx.font(size::SMALL), p.text_muted, text_w));
    let text_h = title.size().y + sub.as_ref().map_or(0.0, |s| s.size().y + 2.0);
    let height = (text_h + 24.0).max(56.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let info = match trailing {
        Trailing::Check(selected) => WidgetInfo::selected(Role::RadioButton, true, selected, label),
        Trailing::External => WidgetInfo::labeled(Role::Link, true, label),
        _ => WidgetInfo::labeled(Role::Button, true, label),
    };
    let response = touch(ui, cx, tid, rect, info, true);
    let painter = ui.painter();
    if response.is_pointer_button_down_on() || matches!(trailing, Trailing::Check(true)) {
        painter.rect_filled(rect.shrink2(vec2(4.0, 1.0)), CornerRadius::same(12), p.primary_soft);
    }
    if !first {
        let y = rect.top();
        painter.hline(
            rect.left() + left_pad..=rect.right() - 16.0,
            y,
            Stroke::new(1.0, p.border),
        );
    }
    if let Some(glyph) = glyph {
        let icon_rect = Rect::from_min_size(pos2(rect.left() + 16.0, rect.center().y - 20.0), Vec2::splat(40.0));
        painter.rect_filled(icon_rect, CornerRadius::same(12), p.primary_soft);
        paint_icon(ui, cx, icon_rect.center(), glyph, 22.0, p.primary);
    }
    let top = rect.center().y - text_h / 2.0;
    let x = rect.left() + left_pad;
    let title_h = title.size().y;
    ui.painter().galley(pos2(x, top), title, p.text);
    if let Some(sub) = sub {
        ui.painter().galley(pos2(x, top + title_h + 2.0), sub, p.text_muted);
    }
    let cx_right = rect.right() - 30.0;
    match trailing {
        Trailing::None => {}
        Trailing::Chevron => paint_icon(
            ui,
            cx,
            pos2(cx_right, rect.center().y),
            icons::CARET_RIGHT,
            20.0,
            p.text_faint,
        ),
        Trailing::External => paint_icon(
            ui,
            cx,
            pos2(cx_right, rect.center().y),
            icons::ARROW_SQUARE_OUT,
            20.0,
            p.text_faint,
        ),
        Trailing::Check(true) => paint_icon(
            ui,
            cx,
            pos2(cx_right, rect.center().y),
            icons::CHECK_CIRCLE,
            24.0,
            p.primary,
        ),
        Trailing::Check(false) => {}
        Trailing::Value(_) => {
            paint_icon(
                ui,
                cx,
                pos2(cx_right, rect.center().y),
                icons::CARET_RIGHT,
                20.0,
                p.text_faint,
            );
            if let Some(g) = value_galley {
                let pos = pos2(cx_right - 16.0 - g.size().x, rect.center().y - g.size().y / 2.0);
                let chip = Rect::from_min_size(pos, g.size()).expand2(vec2(8.0, 4.0));
                ui.painter().rect_filled(chip, CornerRadius::same(8), p.primary_soft);
                ui.painter().galley(pos, g, p.primary);
            }
        }
    }
    response
}

/// Fila informativa (no pulsable) con icono, texto y subtítulo.
pub fn info_row(ui: &mut Ui, cx: &mut Cx, glyph: &str, label: &str, subtitle: &str) {
    let p = cx.p;
    let first = ui.cursor().top() <= ui.min_rect().top() + 0.5;
    let width = ui.available_width();
    let left_pad = 16.0 + 40.0 + 14.0;
    let text_w = width - left_pad - 16.0;
    let title = layout(ui, label, cx.font(size::BODY), p.text, text_w);
    let sub = layout(ui, subtitle, cx.font(size::SMALL), p.text_muted, text_w);
    let text_h = title.size().y + 2.0 + sub.size().y;
    let (rect, response) = ui.allocate_exact_size(vec2(width, (text_h + 24.0).max(64.0)), Sense::hover());
    let text = format!("{label}. {subtitle}");
    response.widget_info(|| WidgetInfo::labeled(Role::Label, true, &text));
    let painter = ui.painter();
    if !first {
        painter.hline(
            rect.left() + left_pad..=rect.right() - 16.0,
            rect.top(),
            Stroke::new(1.0, p.border),
        );
    }
    let icon_rect = Rect::from_min_size(pos2(rect.left() + 16.0, rect.center().y - 20.0), Vec2::splat(40.0));
    painter.rect_filled(icon_rect, CornerRadius::same(12), p.primary_soft);
    paint_icon(ui, cx, icon_rect.center(), glyph, 22.0, p.primary);
    let top = rect.center().y - text_h / 2.0;
    let title_h = title.size().y;
    ui.painter().galley(pos2(rect.left() + left_pad, top), title, p.text);
    ui.painter()
        .galley(pos2(rect.left() + left_pad, top + title_h + 2.0), sub, p.text_muted);
}

fn paint_switch(ui: &Ui, cx: &Cx, rect: Rect, on: f32, enabled: bool) {
    let p = cx.p;
    let track = Rect::from_center_size(rect.center(), vec2(52.0, 32.0));
    let fill = if enabled {
        lerp_color(p.surface_alt, p.primary, on)
    } else {
        p.surface_alt
    };
    let stroke = Stroke::new(2.0, lerp_color(p.text_faint, p.primary, on));
    ui.painter()
        .rect(track, CornerRadius::same(16), fill, stroke, StrokeKind::Inside);
    let knob_r = 8.0 + 4.0 * on;
    let x = egui::lerp(track.left() + 16.0..=track.right() - 16.0, on);
    let knob = if on > 0.5 { p.on_primary } else { p.text_faint };
    ui.painter().circle_filled(pos2(x, track.center().y), knob_r, knob);
}

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// Fila con interruptor; toda la fila lo cambia. Devuelve la respuesta (`changed()` si ha
/// cambiado).
pub fn switch_row(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    label: &str,
    note: Option<&str>,
    value: &mut bool,
    enabled: bool,
) -> Response {
    let p = cx.p;
    let first = ui.cursor().top() <= ui.min_rect().top() + 0.5;
    let width = ui.available_width();
    let text_w = width - 18.0 - 84.0;
    let color = if enabled { p.text } else { p.text_faint };
    let title = layout(ui, label, cx.font(size::BODY), color, text_w);
    let sub = note.map(|s| layout(ui, s, cx.font(size::SMALL), p.text_muted, text_w));
    let text_h = title.size().y + sub.as_ref().map_or(0.0, |s| s.size().y + 2.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, (text_h + 24.0).max(60.0)), Sense::hover());
    let mut response = touch(
        ui,
        cx,
        tid,
        rect,
        WidgetInfo::selected(Role::Switch, enabled, *value, label),
        enabled,
    );
    if response.clicked() {
        *value = !*value;
        response.mark_changed();
    }
    if !first {
        ui.painter().hline(
            rect.left() + 18.0..=rect.right() - 16.0,
            rect.top(),
            Stroke::new(1.0, p.border),
        );
    }
    let top = rect.center().y - text_h / 2.0;
    let title_h = title.size().y;
    ui.painter().galley(pos2(rect.left() + 18.0, top), title, color);
    if let Some(sub) = sub {
        ui.painter()
            .galley(pos2(rect.left() + 18.0, top + title_h + 2.0), sub, p.text_muted);
    }
    let on = ui.ctx().animate_bool_responsive(Id::unique((tid, "anim")), *value);
    let knob_rect = Rect::from_center_size(pos2(rect.right() - 46.0, rect.center().y), vec2(60.0, 40.0));
    paint_switch(ui, cx, knob_rect, on, enabled);
    response
}

/// Casilla con texto; toda la fila la marca.
pub fn checkbox_row(ui: &mut Ui, cx: &mut Cx, tid: &'static str, label: &str, value: &mut bool) -> Response {
    let p = cx.p;
    let width = ui.available_width();
    let galley = layout(ui, label, cx.font(size::BODY), p.text, width - 56.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, (galley.size().y + 20.0).max(TOUCH)), Sense::hover());
    let mut response = touch(
        ui,
        cx,
        tid,
        rect,
        WidgetInfo::selected(Role::CheckBox, true, *value, label),
        true,
    );
    if response.clicked() {
        *value = !*value;
        response.mark_changed();
    }
    let boxr = Rect::from_min_size(pos2(rect.left() + 4.0, rect.center().y - 13.0), Vec2::splat(26.0));
    if *value {
        ui.painter().rect_filled(boxr, CornerRadius::same(7), p.primary);
        paint_icon(ui, cx, boxr.center(), icons::CHECK, 18.0, p.on_primary);
    } else {
        ui.painter().rect(
            boxr,
            CornerRadius::same(7),
            p.surface,
            Stroke::new(2.0, p.text_faint),
            StrokeKind::Inside,
        );
    }
    ui.painter().galley(
        pos2(rect.left() + 46.0, rect.center().y - galley.size().y / 2.0),
        galley,
        p.text,
    );
    response
}

/// Fila de opción única con marca y etiqueta opcional («Por defecto»).
pub fn radio_row(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    label: &str,
    badge: Option<&str>,
    selected: bool,
) -> Response {
    let text = match badge {
        Some(b) => format!("{label}  ·  {b}"),
        None => label.to_string(),
    };
    list_row(ui, cx, tid, None, &text, None, Trailing::Check(selected))
}

/// Icono dentro de un círculo de color (decorativo).
pub fn icon_badge(ui: &mut Ui, cx: &Cx, glyph: &str, diameter: f32, fg: Color32, bg: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(diameter), Sense::hover());
    ui.painter().circle_filled(rect.center(), diameter / 2.0, bg);
    paint_icon(ui, cx, rect.center(), glyph, diameter * 0.5, fg);
}

/// Acción principal grande (Inicio: «Firmar fichero»).
pub fn hero_action(ui: &mut Ui, cx: &mut Cx, tid: &'static str, glyph: &str, title: &str, subtitle: &str) -> Response {
    let p = cx.p;
    let width = ui.available_width();
    let text_w = width - 40.0 - 64.0 - 16.0 - 30.0;
    let t = layout(ui, title, cx.bold(size::TITLE), p.on_primary, text_w);
    let s = layout(ui, subtitle, cx.font(size::SMALL), p.on_primary, text_w);
    let text_h = t.size().y + 4.0 + s.size().y;
    let (rect, _) = ui.allocate_exact_size(vec2(width, (text_h + 44.0).max(112.0)), Sense::hover());
    let response = touch(ui, cx, tid, rect, WidgetInfo::labeled(Role::Button, true, title), true);
    let fill = if response.is_pointer_button_down_on() {
        p.primary_hover
    } else {
        p.primary
    };
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(24), fill);
    // Círculos decorativos, recortados por los bordes rectos (lejos de las esquinas).
    let deco = Color32::from_white_alpha(if p.dark { 18 } else { 26 });
    let clipped = ui.painter_at(rect);
    clipped.circle_filled(pos2(rect.right() - 96.0, rect.top() - 8.0), 54.0, deco);
    clipped.circle_filled(pos2(rect.right() - 74.0, rect.bottom() + 8.0), 36.0, deco);
    let painter = ui.painter();
    let icon_c = pos2(rect.left() + 20.0 + 32.0, rect.center().y);
    painter.circle_filled(icon_c, 32.0, Color32::from_white_alpha(if p.dark { 30 } else { 40 }));
    paint_icon(ui, cx, icon_c, glyph, 32.0, p.on_primary);
    let x = rect.left() + 20.0 + 64.0 + 16.0;
    let top = rect.center().y - text_h / 2.0;
    let th = t.size().y;
    ui.painter().galley(pos2(x, top), t, p.on_primary);
    ui.painter().galley(pos2(x, top + th + 4.0), s, p.on_primary);
    paint_icon(
        ui,
        cx,
        pos2(rect.right() - 24.0, rect.center().y),
        icons::CARET_RIGHT,
        22.0,
        p.on_primary,
    );
    response
}

/// Altura que necesita una baldosa (para igualar las de una fila).
pub fn tile_height(ui: &Ui, cx: &Cx, title: &str, width: f32) -> f32 {
    let t = layout(ui, title, cx.bold(size::BODY), cx.p.text, width - 32.0);
    (16.0 + 44.0 + 12.0 + t.size().y + 16.0).max(116.0)
}

/// Baldosa de acción (cuadrícula de Inicio).
pub fn tile(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    glyph: &str,
    title: &str,
    width: f32,
    height: f32,
) -> Response {
    let p = cx.p;
    let t = layout(ui, title, cx.bold(size::BODY), p.text, width - 32.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let response = touch(ui, cx, tid, rect, WidgetInfo::labeled(Role::Button, true, title), true);
    let pressed = response.is_pointer_button_down_on();
    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::same(20),
        if pressed { p.primary_soft } else { p.surface },
        Stroke::new(1.0, if pressed { p.primary } else { p.border }),
        StrokeKind::Inside,
    );
    let icon_rect = Rect::from_min_size(rect.min + vec2(16.0, 16.0), Vec2::splat(44.0));
    painter.rect_filled(icon_rect, CornerRadius::same(14), p.primary_soft);
    paint_icon(ui, cx, icon_rect.center(), glyph, 24.0, p.primary);
    ui.painter()
        .galley(pos2(rect.left() + 16.0, icon_rect.bottom() + 12.0), t, p.text);
    response
}

/// Tipo de aviso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Info,
    Success,
    Warning,
    Danger,
    Brand,
}

impl Tone {
    pub fn colors(self, p: &Palette) -> (Color32, Color32) {
        match self {
            Tone::Info => (p.info, p.info_soft),
            Tone::Success => (p.success, p.success_soft),
            Tone::Warning => (p.warning, p.warning_soft),
            Tone::Danger => (p.danger, p.danger_soft),
            Tone::Brand => (p.primary, p.primary_soft),
        }
    }
}

/// Recuadro de aviso con icono.
pub fn notice(ui: &mut Ui, cx: &Cx, tone: Tone, glyph: &str, text: &str) {
    let (fg, bg) = tone.colors(&cx.p);
    Frame::new()
        .fill(bg)
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(egui::RichText::new(glyph).font(cx.icon(22.0)).color(fg));
                ui.add(egui::Label::new(egui::RichText::new(text).font(cx.font(size::SMALL)).color(cx.p.text)).wrap());
            });
        });
}

/// Enlace (abre una URL fuera de la aplicación).
pub fn link(ui: &mut Ui, cx: &mut Cx, tid: &'static str, text: &str) -> Response {
    let p = cx.p;
    let width = ui.available_width();
    let galley = layout(ui, text, cx.font(size::BODY), p.primary, width - 30.0);
    let (rect, _) = ui.allocate_exact_size(vec2(width, (galley.size().y + 12.0).max(TOUCH)), Sense::hover());
    let response = touch(ui, cx, tid, rect, WidgetInfo::labeled(Role::Link, true, text), true);
    let top = rect.center().y - galley.size().y / 2.0;
    let text_rect = Rect::from_min_size(pos2(rect.left(), top), galley.size());
    ui.painter().galley(text_rect.min, galley, p.primary);
    ui.painter().hline(
        text_rect.x_range(),
        text_rect.bottom() + 1.0,
        Stroke::new(1.0, p.primary),
    );
    paint_icon(
        ui,
        cx,
        pos2(text_rect.right() + 14.0, text_rect.bottom() - 9.0),
        icons::ARROW_SQUARE_OUT,
        16.0,
        p.primary,
    );
    response
}

/// Pregunta desplegable (Preguntas frecuentes).
pub fn expandable(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    title: &str,
    open: &mut bool,
    add_body: impl FnOnce(&mut Ui, &mut Cx),
) {
    let p = cx.p;
    card_frame(&p).inner_margin(Margin::same(0)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let width = ui.available_width();
        let galley = layout(ui, title, cx.bold(size::BODY), p.text, width - 18.0 - 54.0);
        let (rect, _) = ui.allocate_exact_size(vec2(width, (galley.size().y + 28.0).max(60.0)), Sense::hover());
        let response = touch(
            ui,
            cx,
            tid,
            rect,
            WidgetInfo::selected(Role::Button, true, *open, title),
            true,
        );
        if response.clicked() {
            *open = !*open;
        }
        ui.painter().galley(
            pos2(rect.left() + 18.0, rect.center().y - galley.size().y / 2.0),
            galley,
            p.text,
        );
        let glyph = if *open { icons::CARET_UP } else { icons::CARET_DOWN };
        paint_icon(
            ui,
            cx,
            pos2(rect.right() - 30.0, rect.center().y),
            glyph,
            20.0,
            p.primary,
        );
        if *open {
            Frame::new()
                .inner_margin(Margin {
                    left: 18,
                    right: 18,
                    top: 0,
                    bottom: 16,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    add_body(ui, cx);
                });
        }
    });
}

/// Campo de texto con el teclado de Android ([`ImeController`]). `rows` > 1 para varias
/// líneas.
pub fn text_field(
    ui: &mut Ui,
    cx: &mut Cx,
    tid: &'static str,
    text: &mut String,
    spec: FieldSpec,
    hint: &str,
    rows: usize,
) -> FieldEvents {
    let p = cx.p;
    let id = Id::unique(tid);
    let ctx = ui.ctx().clone();
    let changed_by_ime = cx.ime.apply_incoming(&ctx, id, text, spec);
    let focused = ui.memory(|m| m.has_focus(id));
    let frame = Frame::new()
        .fill(p.surface)
        .stroke(if focused {
            Stroke::new(2.0, p.primary)
        } else {
            Stroke::new(1.5, p.border)
        })
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::symmetric(16, 14));
    let hint_text = egui::RichText::new(hint).color(p.text_faint);
    let edit = if spec.kind.is_multiline() {
        TextEdit::multiline(text).desired_rows(rows.max(2))
    } else {
        TextEdit::singleline(text)
    };
    let output = edit
        .id(id)
        .password(spec.kind.is_secret())
        .font(cx.font(size::BODY + 1.0))
        .text_color(p.text)
        .hint_text(hint_text)
        .frame(frame)
        .desired_width(f32::INFINITY)
        .min_size(vec2(0.0, 54.0))
        .show(ui);
    cx.register(ui, tid, output.response.rect);
    let cursor = output.cursor_range.map(|r| {
        let range = r.as_sorted_char_range();
        (range.start.0, range.end.0)
    });
    let mut events = cx.ime.after_field(&ctx, id, &output.response, text, cursor, spec);
    events.changed |= changed_by_ime || output.response.changed();
    events
}

/// Fila de puntos de un paginador (`page` de `pages`).
pub fn page_dots(ui: &mut Ui, cx: &Cx, page: usize, pages: usize) {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 20.0), Sense::hover());
    let label = crate::i18n::trf("page_number", &[&(page + 1), &pages]);
    response.widget_info(|| WidgetInfo::labeled(Role::Label, true, &label));
    let total = pages as f32 * 22.0;
    for i in 0..pages {
        let c = pos2(rect.center().x - total / 2.0 + 11.0 + i as f32 * 22.0, rect.center().y);
        if i == page {
            ui.painter().rect_filled(
                Rect::from_center_size(c, vec2(22.0, 8.0)),
                CornerRadius::same(4),
                cx.p.primary,
            );
        } else {
            ui.painter().circle_filled(c, 4.0, cx.p.border);
        }
    }
}

/// Hoja inferior modal sobre un fondo oscurecido. Devuelve `true` si se ha tocado fuera
/// (solo si `dismissable`).
pub fn sheet(ctx: &Context, cx: &mut Cx, id: &str, dismissable: bool, add: impl FnOnce(&mut Ui, &mut Cx)) -> bool {
    let viewport = ctx.viewport_rect();
    let content = ctx.content_rect();
    let dim = egui::Area::new(Id::unique((id, "fondo")))
        .order(Order::Middle)
        .fixed_pos(viewport.min)
        .constrain(false)
        .show(ctx, |ui| {
            // También sobre las barras del sistema (de borde a borde).
            ui.set_clip_rect(viewport);
            let response = ui.allocate_rect(viewport, Sense::click());
            ui.painter().rect_filled(
                viewport,
                0.0,
                Color32::from_black_alpha(if cx.p.dark { 150 } else { 110 }),
            );
            response.clicked()
        })
        .inner;
    let width = content.width().min(560.0);
    let bottom_inset = (viewport.bottom() - content.bottom()).max(0.0);
    // Se coloca a mano pegada al borde inferior con la altura de la pasada anterior: con
    // `anchor` y `constrain` el área limita la altura disponible para su propio contenido y
    // se queda más baja de lo que necesita.
    let area_id = Id::unique(id);
    let height = ctx.memory(|m| m.area_rect(area_id)).map_or(0.0, |r| r.height());
    let pos = pos2(viewport.center().x - width / 2.0, viewport.bottom() - height);
    egui::Area::new(area_id)
        .order(Order::Foreground)
        .constrain(false)
        .fixed_pos(pos)
        .show(ctx, |ui| {
            ui.set_clip_rect(viewport);
            ui.set_width(width);
            Frame::new()
                .fill(cx.p.surface)
                .corner_radius(CornerRadius {
                    nw: 28,
                    ne: 28,
                    sw: 0,
                    se: 0,
                })
                .inner_margin(Margin {
                    left: 24,
                    right: 24,
                    top: 12,
                    bottom: (20.0 + bottom_inset).min(120.0) as i8,
                })
                .show(ui, |ui| {
                    ui.set_width(width - 48.0);
                    // Asa de la hoja.
                    let (handle, _) = ui.allocate_exact_size(vec2(ui.available_width(), 16.0), Sense::hover());
                    ui.painter().rect_filled(
                        Rect::from_center_size(handle.center(), vec2(40.0, 4.0)),
                        CornerRadius::same(2),
                        cx.p.border,
                    );
                    // El contenido del área solo puede ocupar el rectángulo de la pasada
                    // anterior: se le da una zona con la altura máxima para que crezca.
                    let max_height = (content.height() * 0.85 - 40.0).max(120.0);
                    let zone = Rect::from_min_size(ui.cursor().min, vec2(ui.available_width(), max_height));
                    ui.scope_builder(UiBuilder::new().max_rect(zone), |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(max_height)
                            .auto_shrink([false, true])
                            .show(ui, |ui| add(ui, cx));
                    });
                });
        });
    dismissable && dim
}

/// Texto alineado al centro que ocupa todo el ancho.
pub fn centered_text(ui: &mut Ui, text: &str, font: FontId, color: Color32) {
    ui.with_layout(egui::Layout::top_down(Align::Center), |ui| {
        ui.add(
            egui::Label::new(egui::RichText::new(text).font(font).color(color))
                .wrap()
                .halign(Align::Center),
        );
    });
}

/// Contenido centrado con un ancho máximo (tabletas y horizontal).
pub fn centered_column<R>(ui: &mut Ui, max_width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    let avail = ui.available_rect_before_wrap();
    let width = avail.width().min(max_width);
    let rect = Rect::from_min_size(
        pos2(avail.center().x - width / 2.0, avail.top()),
        vec2(width, avail.height()),
    );
    ui.scope_builder(UiBuilder::new().max_rect(rect), add).inner
}

/// Formato de texto de un trozo del marcado.
pub fn text_format(font: FontId, color: Color32) -> TextFormat {
    TextFormat {
        font_id: font,
        color,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use egui::{Event, PointerButton, Pos2, RawInput};

    use super::*;
    use crate::ime::{ImeState, InputKind};
    use crate::testing::FakePlatform;

    /// Un campo de PIN (cifras ocultas, máximo 8) y nada más.
    struct Field {
        ctx: Context,
        ime: ImeController,
        targets: Targets,
        platform: Arc<FakePlatform>,
        text: String,
        time: f64,
        last: FieldEvents,
    }

    impl Field {
        fn new() -> Field {
            let platform = Arc::new(FakePlatform::default());
            Field {
                ctx: Context::default(),
                ime: ImeController::new(platform.clone()),
                targets: Targets::default(),
                platform,
                text: String::new(),
                time: 0.0,
                last: FieldEvents::default(),
            }
        }

        fn frame(&mut self, events: Vec<Event>) {
            self.time += 0.05;
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(400.0, 800.0))),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            let Field {
                ctx,
                ime,
                targets,
                text,
                last,
                ..
            } = self;
            let mut output = ctx.clone().run_ui(input, |ui| {
                ime.begin_frame();
                targets.clear();
                let mut cx = Cx {
                    p: Palette::LIGHT,
                    scale: 1.0,
                    ime,
                    targets,
                };
                ui.add_space(100.0);
                *last = text_field(
                    ui,
                    &mut cx,
                    "pin",
                    text,
                    FieldSpec::new(InputKind::NumberPassword).max_chars(8),
                    "PIN",
                    1,
                );
                cx.ime.end_frame();
            });
            output.textures_delta.clear();
        }

        fn click(&mut self, pos: Pos2) {
            let button = |pressed| Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            };
            self.frame(vec![Event::PointerMoved(pos), button(true)]);
            self.frame(vec![button(false)]);
            self.frame(vec![]);
        }

        fn field_center(&self) -> Pos2 {
            self.targets.rect("pin").expect("campo dibujado").center()
        }
    }

    #[test]
    fn campo_secreto_con_el_teclado_de_android() {
        let mut f = Field::new();
        f.frame(vec![]);
        f.click(f.field_center());
        assert_eq!(
            f.platform.calls_with("ime_show"),
            [r#"ime_show NumberPassword "" (0, 0)"#]
        );
        // El teclado escribe algo que el campo no admite: se filtra y se le devuelve.
        f.ime.on_state(ImeState::from_java("12a3456789".into(), 10, 10, -1, -1));
        f.frame(vec![]);
        assert_eq!(f.text, "12345678");
        assert!(f.last.changed);
        assert_eq!(f.platform.calls_with("ime_update"), [r#"ime_update "12345678" (8, 8)"#]);
        // «Hecho» llega dos veces (al pulsar y al soltar Intro): una sola acción.
        let now = f.time;
        f.ime.on_editor_action(now);
        f.ime.on_editor_action(now + 0.05);
        f.frame(vec![]);
        assert!(f.last.submitted);
        f.frame(vec![]);
        assert!(!f.last.submitted);
        // El usuario cierra el teclado: el campo suelta el foco sin volver a cerrarlo.
        f.ime.on_visibility(true, f.time);
        f.ime.on_visibility(false, f.time + 1.0);
        f.frame(vec![]);
        f.frame(vec![]);
        assert_eq!(f.ime.owner(), None);
        assert!(f.platform.calls_with("ime_hide").is_empty());
        // Tocarlo otra vez vuelve a abrir el teclado con el texto que tiene.
        f.click(f.field_center());
        assert_eq!(
            f.platform.calls_with("ime_show").last().map(String::as_str),
            Some(r#"ime_show NumberPassword "12345678" (8, 8)"#)
        );
        // Tocar fuera cierra el teclado.
        f.click(Pos2::new(200.0, 700.0));
        assert_eq!(f.platform.calls_with("ime_hide"), ["ime_hide"]);
        assert_eq!(f.ime.owner(), None);
    }
}
