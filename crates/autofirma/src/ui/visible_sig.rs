//! Editor de firma visible en PDF.
//!
//! Reúne en una sola ventana lo que en AutoFirma eran tres diálogos
//! (posición, apariencia y marca): a la izquierda se ve la página y se dibuja
//! el recuadro con el ratón; a la derecha se eligen las páginas, el texto,
//! la tipografía y la imagen, con vista previa en vivo sobre la página.
//! Produce exactamente los mismos `extraParams` que el original (§3.8).

use std::collections::HashMap;
use std::sync::Arc;

use afirma_core::ExtraParams;
use eframe::egui::{
    self, Align, Align2, Color32, ColorImage, CornerRadius, FontFamily, FontId, Frame, Key, Layout, Margin, Pos2, Rect,
    RichText, ScrollArea, Sense, Stroke, StrokeKind, TextureHandle, TextureOptions, Ui, Vec2,
};

use super::icons;
use super::theme::{Palette, semibold};
use super::widgets::{self, ButtonKind};
use crate::i18n::{tr, trf};

/// Origen de las páginas del PDF (renderizado y tamaños en puntos).
pub trait PageSource: Send + Sync {
    fn page_count(&self) -> usize;
    /// Tamaño de la página (con la rotación aplicada) en puntos PDF.
    fn page_size(&self, index: usize) -> (f32, f32);
    /// Renderiza la página con `scale` píxeles por punto.
    fn render(&self, index: usize, scale: f32) -> Option<ColorImage>;
}

/// Campo de firma vacío existente en el PDF.
#[derive(Debug, Clone)]
pub struct EmptyField {
    pub name: String,
    pub page: usize,
    /// Rectángulo en puntos PDF (origen abajo a la izquierda): llx, lly, urx, ury.
    pub rect: [f32; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageMode {
    Current,
    All,
    Custom(String),
}

/// Colores de texto admitidos (`layer2FontColor`).
const COLORS: [(&str, Color32); 7] = [
    ("black", Color32::from_rgb(0, 0, 0)),
    ("white", Color32::from_rgb(255, 255, 255)),
    ("lightGray", Color32::from_rgb(192, 192, 192)),
    ("gray", Color32::from_rgb(128, 128, 128)),
    ("darkGray", Color32::from_rgb(64, 64, 64)),
    ("red", Color32::from_rgb(255, 0, 0)),
    ("pink", Color32::from_rgb(255, 175, 175)),
];

/// Nombre visible de un color de [`COLORS`].
fn color_name(index: usize) -> &'static str {
    match index {
        0 => tr("Negro"),
        1 => tr("Blanco"),
        2 => tr("Gris claro"),
        3 => tr("Gris"),
        4 => tr("Gris oscuro"),
        5 => tr("Rojo"),
        _ => tr("Rosa"),
    }
}

const FONTS: [&str; 3] = ["Courier", "Helvetica", "Times Roman"];

/// Marcadores que se pueden insertar en el texto (etiqueta y marcador).
fn tokens() -> [(&'static str, &'static str); 6] {
    [
        (tr("Nombre"), "$$SUBJECTCN$$"),
        (tr("Emisor"), "$$ISSUERCN$$"),
        (tr("Fecha"), "$$SIGNDATE=dd/MM/yyyy$$"),
        (tr("Nº de serie"), "$$CERTSERIAL$$"),
        (tr("Razón"), "$$REASON$$"),
        (tr("Lugar"), "$$LOCATION$$"),
    ]
}

/// Texto por defecto de la firma visible, en el idioma de la interfaz (como
/// en AutoFirma).
pub fn default_text() -> &'static str {
    tr("Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$")
}

#[derive(Debug, Clone, PartialEq)]
pub enum VisibleSigEvent {
    None,
    /// Parámetros de la firma visible (y si hay que recordar la apariencia).
    Accepted(ExtraParams, bool),
    /// Firmar sin firma visible.
    Invisible,
    Cancelled,
}

pub struct VisibleSigEditor {
    pub open: bool,
    pub title: String,
    source: Option<Arc<dyn PageSource>>,
    page: usize,
    textures: HashMap<usize, TextureHandle>,
    /// Recuadro en puntos PDF con origen arriba a la izquierda.
    rect: Option<Rect>,
    drag_start: Option<Pos2>,
    pub page_mode: PageMode,
    pub multi_document: bool,
    /// Firma visible obligatoria (`visibleSignature=want` desde la web): no
    /// se ofrece firmar sin ella.
    pub mandatory: bool,
    pub empty_fields: Vec<EmptyField>,
    pub selected_field: Option<usize>,
    // Apariencia.
    pub custom_appearance: bool,
    pub text: String,
    pub font_family: usize,
    pub font_size: u32,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
    pub color: usize,
    pub rotation: u16,
    pub image: Option<(String, Vec<u8>)>,
    image_tex: Option<TextureHandle>,
    pub remember: bool,
    pub error: Option<String>,
    /// Se coloca la firma visible (falso si solo se pide la marca de imagen).
    pub signature_enabled: bool,
    /// Marca de imagen independiente de la firma (`image`, `imagePage`...):
    /// casilla «Insertar una marca visible» de AutoFirma.
    pub stamp_enabled: bool,
    stamp_image: Option<(String, Vec<u8>)>,
    stamp_tex: Option<TextureHandle>,
    /// Recuadro de la marca en puntos PDF (origen arriba a la izquierda) y su página.
    stamp_rect: Option<Rect>,
    stamp_page: usize,
    pub stamp_all_pages: bool,
    /// El arrastre sobre la página coloca la marca (si no, la firma).
    editing_stamp: bool,
}

impl Default for VisibleSigEditor {
    fn default() -> Self {
        VisibleSigEditor {
            open: false,
            title: String::new(),
            source: None,
            page: 0,
            textures: HashMap::new(),
            rect: None,
            drag_start: None,
            page_mode: PageMode::Current,
            multi_document: false,
            mandatory: false,
            empty_fields: Vec::new(),
            selected_field: None,
            custom_appearance: true,
            text: default_text().into(),
            font_family: 1,
            font_size: 12,
            bold: false,
            italic: false,
            underline: false,
            strike: false,
            color: 0,
            rotation: 0,
            image: None,
            image_tex: None,
            remember: true,
            error: None,
            signature_enabled: true,
            stamp_enabled: false,
            stamp_image: None,
            stamp_tex: None,
            stamp_rect: None,
            stamp_page: 0,
            stamp_all_pages: false,
            editing_stamp: false,
        }
    }
}

impl VisibleSigEditor {
    /// Abre el editor sobre un documento.
    pub fn open_with(&mut self, title: impl Into<String>, source: Arc<dyn PageSource>) {
        self.title = title.into();
        self.page = 0;
        self.source = Some(source);
        self.textures.clear();
        self.rect = None;
        self.drag_start = None;
        self.selected_field = None;
        self.error = None;
        self.stamp_rect = None;
        self.stamp_page = 0;
        self.editing_stamp = !self.signature_enabled;
        self.open = true;
    }

    /// Establece un recuadro inicial en puntos PDF (origen abajo a la izquierda).
    pub fn set_rect_pdf(&mut self, page: usize, llx: f32, lly: f32, urx: f32, ury: f32) {
        if let Some(src) = &self.source {
            let (_, h) = src.page_size(page);
            self.page = page;
            self.rect = Some(Rect::from_min_max(Pos2::new(llx, h - ury), Pos2::new(urx, h - lly)));
        }
    }

    fn style_code(&self) -> u8 {
        if self.underline {
            4
        } else if self.strike {
            8
        } else {
            u8::from(self.bold) | (u8::from(self.italic) << 1)
        }
    }

    /// Construye los parámetros de la firma visible y de la marca (`extraParams`).
    pub fn build_params(&self) -> Result<ExtraParams, String> {
        let mut params = if self.signature_enabled {
            self.signature_params()?
        } else {
            ExtraParams::new()
        };
        if self.stamp_enabled {
            let Some(src) = &self.source else {
                return Err(tr("No hay documento").into());
            };
            let (_, bytes) = self.stamp_image.as_ref().ok_or(tr("Elige la imagen de la marca."))?;
            let rect = self
                .stamp_rect
                .ok_or(tr("Dibuja en la página el recuadro donde quieres la marca."))?;
            let (_, h) = src.page_size(self.stamp_page);
            params.set("image", afirma_core::base64_encode(bytes));
            params.set(
                "imagePage",
                if self.stamp_all_pages {
                    "0".to_string()
                } else {
                    (self.stamp_page + 1).to_string()
                },
            );
            params.set(
                "imagePositionOnPageLowerLeftX",
                (rect.left().round() as i64).to_string(),
            );
            params.set(
                "imagePositionOnPageLowerLeftY",
                ((h - rect.bottom()).round() as i64).to_string(),
            );
            params.set(
                "imagePositionOnPageUpperRightX",
                (rect.right().round() as i64).to_string(),
            );
            params.set(
                "imagePositionOnPageUpperRightY",
                ((h - rect.top()).round() as i64).to_string(),
            );
        }
        Ok(params)
    }

    fn signature_params(&self) -> Result<ExtraParams, String> {
        let mut params = ExtraParams::new();
        if let Some(fi) = self.selected_field {
            let f = &self.empty_fields[fi];
            params.set("signatureField", f.name.clone());
        } else {
            let Some(src) = &self.source else {
                return Err(tr("No hay documento").into());
            };
            let rect = self
                .rect
                .ok_or(tr("Dibuja en la página el recuadro donde quieres la firma."))?;
            if rect.width() < 30.0 || rect.height() < 45.0 || rect.width() * rect.height() < 1350.0 {
                return Err(tr("El recuadro es demasiado pequeño para mostrar la firma.").into());
            }
            let pages = match &self.page_mode {
                PageMode::Current => (self.page + 1).to_string(),
                PageMode::All => "all".into(),
                PageMode::Custom(s) => {
                    if !check_pages_range(s) {
                        return Err(tr("El formato de la selección de páginas no es correcto (ej.: 1,3-5,-1).").into());
                    }
                    s.trim().to_string()
                }
            };
            params.set("signaturePages", pages);
            let (_, h) = src.page_size(self.page);
            params.set(
                "signaturePositionOnPageLowerLeftX",
                (rect.left().round() as i64).to_string(),
            );
            params.set(
                "signaturePositionOnPageLowerLeftY",
                ((h - rect.bottom()).round() as i64).to_string(),
            );
            params.set(
                "signaturePositionOnPageUpperRightX",
                (rect.right().round() as i64).to_string(),
            );
            params.set(
                "signaturePositionOnPageUpperRightY",
                ((h - rect.top()).round() as i64).to_string(),
            );
        }
        if self.custom_appearance {
            let text = self.text.trim();
            params.set("layer2Text", text);
            if !text.is_empty() {
                params.set("layer2FontFamily", self.font_family.to_string());
                params.set("layer2FontSize", self.font_size.to_string());
                params.set("layer2FontStyle", self.style_code().to_string());
                params.set("layer2FontColor", COLORS[self.color].0);
            }
            if self.rotation != 0 {
                params.set("signatureRotation", self.rotation.to_string());
            }
            if let Some((_, bytes)) = &self.image {
                params.set("signatureRubricImage", afirma_core::base64_encode(bytes));
            }
        }
        Ok(params)
    }

    pub fn set_image(&mut self, ctx: &egui::Context, name: String, bytes: Vec<u8>) -> Result<(), String> {
        let img = image::load_from_memory(&bytes)
            .map_err(|_| tr("No se ha podido cargar la imagen seleccionada.").to_string())?;
        let rgba = img.to_rgba8();
        let ci = ColorImage::from_rgba_unmultiplied([rgba.width() as usize, rgba.height() as usize], rgba.as_raw());
        self.image_tex = Some(ctx.load_texture("rubric", ci, TextureOptions::LINEAR));
        self.image = Some((name, bytes));
        Ok(())
    }

    pub fn clear_image(&mut self) {
        self.image = None;
        self.image_tex = None;
    }

    /// Imagen de la marca visible (se valida decodificándola, como Java).
    pub fn set_stamp_image(&mut self, ctx: &egui::Context, name: String, bytes: Vec<u8>) -> Result<(), String> {
        let img = image::load_from_memory(&bytes)
            .map_err(|_| tr("No se ha podido cargar la imagen seleccionada.").to_string())?;
        let rgba = img.to_rgba8();
        let ci = ColorImage::from_rgba_unmultiplied([rgba.width() as usize, rgba.height() as usize], rgba.as_raw());
        self.stamp_tex = Some(ctx.load_texture("stamp", ci, TextureOptions::LINEAR));
        self.stamp_image = Some((name, bytes));
        Ok(())
    }

    fn texture(&mut self, ctx: &egui::Context, index: usize) -> Option<TextureHandle> {
        if let Some(t) = self.textures.get(&index) {
            return Some(t.clone());
        }
        let src = self.source.as_ref()?;
        // Se renderiza a 1,5 píxeles por punto (≈108 ppp) para que se vea nítida.
        let img = src.render(index, 1.5)?;
        let tex = ctx.load_texture(format!("pdf-page-{index}"), img, TextureOptions::LINEAR);
        // Se conservan como mucho 8 páginas en memoria.
        if self.textures.len() >= 8 {
            let far = *self.textures.keys().max_by_key(|k| k.abs_diff(index)).unwrap();
            self.textures.remove(&far);
        }
        self.textures.insert(index, tex.clone());
        Some(tex)
    }

    /// Muestra el editor. Devuelve el resultado cuando el usuario termina.
    pub fn show(&mut self, ctx: &egui::Context, p: &Palette) -> VisibleSigEvent {
        if !self.open {
            return VisibleSigEvent::None;
        }
        let Some(source) = self.source.clone() else {
            self.open = false;
            return VisibleSigEvent::Cancelled;
        };
        let mut event = VisibleSigEvent::None;
        let n = source.page_count();
        let typing = ctx.memory(|m| m.focused().is_some());
        ctx.input(|i| {
            if i.key_pressed(Key::Escape) {
                event = VisibleSigEvent::Cancelled;
            }
            if !typing {
                if i.key_pressed(Key::ArrowRight) && self.page + 1 < n {
                    self.page += 1;
                }
                if i.key_pressed(Key::ArrowLeft) && self.page > 0 {
                    self.page -= 1;
                }
            }
        });
        let screen = ctx.content_rect();
        let width = (screen.width() - 80.0).clamp(760.0, 1180.0);
        let height = (screen.height() - 80.0).clamp(520.0, 820.0);
        let modal = egui::Modal::new(egui::Id::unique("visible_sig"))
            .backdrop_color(Color32::from_black_alpha(if p.dark { 150 } else { 90 }))
            .frame(
                Frame::new()
                    .fill(p.surface)
                    .corner_radius(CornerRadius::same(16))
                    .inner_margin(Margin::same(20)),
            );
        modal.show(ctx, |ui| {
            ui.set_width(width - 40.0);
            ui.set_height(height - 40.0);
            ui.horizontal(|ui| {
                widgets::status_circle(ui, icons::SIGNATURE, 38.0, p.primary, p.primary_soft);
                ui.vertical(|ui| {
                    let title = if self.signature_enabled {
                        tr("Firma visible")
                    } else {
                        tr("Marca de imagen")
                    };
                    ui.label(RichText::new(title).font(FontId::new(19.0, semibold())));
                    let sub = if self.multi_document {
                        tr("La posición y la apariencia se aplicarán a todos los PDF").to_string()
                    } else {
                        self.title.clone()
                    };
                    ui.label(RichText::new(sub).size(13.0).color(p.text_muted));
                });
            });
            ui.add_space(10.0);
            let side_w = 340.0;
            let canvas_w = ui.available_width() - side_w - 16.0;
            let body_h = ui.available_height() - 56.0;
            ui.horizontal_top(|ui| {
                // Página.
                ui.allocate_ui_with_layout(Vec2::new(canvas_w, body_h), Layout::top_down(Align::Center), |ui| {
                    self.page_canvas(ui, p, &source, Vec2::new(canvas_w, body_h - 44.0));
                    ui.add_space(6.0);
                    self.pager(ui, p, n);
                });
                ui.add_space(16.0);
                // Opciones.
                ui.allocate_ui_with_layout(Vec2::new(side_w, body_h), Layout::top_down(Align::Min), |ui| {
                    ScrollArea::vertical().id_salt("vs_side").show(ui, |ui| {
                        ui.set_width(side_w - 12.0);
                        self.side_panel(ui, p, ctx);
                    });
                });
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if let Some(e) = &self.error {
                    ui.label(RichText::new(e).color(p.danger).size(13.0));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::button(ui, p, ButtonKind::Primary, Some(icons::CHECK), tr("Aceptar"), true).clicked() {
                        match self.build_params() {
                            Ok(params) => event = VisibleSigEvent::Accepted(params, self.remember),
                            Err(e) => self.error = Some(e),
                        }
                    }
                    let skip = if self.signature_enabled {
                        tr("Firmar sin firma visible")
                    } else {
                        tr("Firmar sin marca")
                    };
                    if !self.mandatory && widgets::button(ui, p, ButtonKind::Secondary, None, skip, true).clicked() {
                        event = VisibleSigEvent::Invisible;
                    }
                    if widgets::button(ui, p, ButtonKind::Ghost, None, tr("Cancelar"), true).clicked() {
                        event = VisibleSigEvent::Cancelled;
                    }
                });
            });
        });
        if event != VisibleSigEvent::None {
            self.open = false;
        }
        event
    }

    fn page_canvas(&mut self, ui: &mut Ui, p: &Palette, source: &Arc<dyn PageSource>, max: Vec2) {
        let (pw, ph) = source.page_size(self.page);
        let scale = (max.x / pw).min(max.y / ph);
        let size = Vec2::new(pw * scale, ph * scale);
        let (outer, response) = ui.allocate_exact_size(max, Sense::click_and_drag());
        let page_rect = Rect::from_center_size(outer.center(), size);
        let painter = ui.painter_at(outer);
        painter.rect_filled(outer, CornerRadius::same(10), p.surface_alt);
        painter.rect_filled(
            page_rect.translate(Vec2::new(0.0, 2.0)),
            CornerRadius::ZERO,
            Color32::from_black_alpha(30),
        );
        match self.texture(ui.ctx(), self.page) {
            Some(tex) => {
                painter.image(
                    tex.id(),
                    page_rect,
                    Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                    Color32::WHITE,
                );
            }
            None => {
                painter.rect_filled(page_rect, CornerRadius::ZERO, Color32::WHITE);
                painter.text(
                    page_rect.center(),
                    Align2::CENTER_CENTER,
                    tr("No se puede previsualizar la página"),
                    FontId::proportional(13.0),
                    Color32::GRAY,
                );
            }
        }
        // Campos vacíos de la página.
        for (i, f) in self.empty_fields.iter().enumerate() {
            if f.page != self.page {
                continue;
            }
            let r = Rect::from_min_max(
                page_rect.min + Vec2::new(f.rect[0], ph - f.rect[3]) * scale,
                page_rect.min + Vec2::new(f.rect[2], ph - f.rect[1]) * scale,
            );
            let sel = self.selected_field == Some(i);
            painter.rect_stroke(
                r,
                CornerRadius::same(2),
                Stroke::new(if sel { 2.0 } else { 1.0 }, p.info),
                StrokeKind::Inside,
            );
            painter.text(
                r.left_top() + Vec2::new(4.0, 2.0),
                Align2::LEFT_TOP,
                &f.name,
                FontId::proportional(11.0),
                p.info,
            );
        }
        // Interacción: arrastrar para dibujar el recuadro.
        let to_pt = |pos: Pos2| -> Pos2 {
            let v = (pos - page_rect.min) / scale;
            Pos2::new(v.x.clamp(0.0, pw), v.y.clamp(0.0, ph))
        };
        if response.drag_started()
            && let Some(pos) = response.interact_pointer_pos()
        {
            self.drag_start = Some(to_pt(pos));
            if !self.editing_stamp {
                self.selected_field = None;
            }
            self.error = None;
        }
        if let (Some(start), Some(pos)) = (self.drag_start, response.interact_pointer_pos())
            && response.dragged()
        {
            let r = Rect::from_two_pos(start, to_pt(pos));
            if self.editing_stamp {
                self.stamp_rect = Some(r);
                self.stamp_page = self.page;
            } else {
                self.rect = Some(r);
            }
        }
        if response.drag_stopped() {
            self.drag_start = None;
            if self.rect.is_some_and(|r| r.width() < 2.0 || r.height() < 2.0) {
                self.rect = None;
            }
            if self.stamp_rect.is_some_and(|r| r.width() < 2.0 || r.height() < 2.0) {
                self.stamp_rect = None;
            }
        }
        // Marca de imagen (estirada al recuadro, como la dibuja AutoFirma).
        if self.stamp_enabled
            && let Some(r) = self
                .stamp_rect
                .filter(|_| self.stamp_all_pages || self.stamp_page == self.page)
        {
            let screen = Rect::from_min_max(
                page_rect.min + r.min.to_vec2() * scale,
                page_rect.min + r.max.to_vec2() * scale,
            );
            match &self.stamp_tex {
                Some(tex) => {
                    painter.image(
                        tex.id(),
                        screen,
                        Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                        Color32::WHITE,
                    );
                }
                None => {
                    painter.rect_filled(screen, CornerRadius::ZERO, p.info.gamma_multiply(0.15));
                }
            }
            painter.rect_stroke(
                screen,
                CornerRadius::ZERO,
                Stroke::new(2.0, p.info),
                StrokeKind::Outside,
            );
            painter.text(
                screen.left_bottom() + Vec2::new(0.0, 4.0),
                Align2::LEFT_TOP,
                tr("Marca"),
                FontId::proportional(11.0),
                p.info,
            );
        }
        let response = response.on_hover_cursor(egui::CursorIcon::Crosshair);
        if let Some(r) = self
            .rect
            .filter(|_| self.signature_enabled && self.selected_field.is_none())
        {
            let screen = Rect::from_min_max(
                page_rect.min + r.min.to_vec2() * scale,
                page_rect.min + r.max.to_vec2() * scale,
            );
            // Oscurece el resto de la página.
            let shade = Color32::from_black_alpha(55);
            for s in [
                Rect::from_min_max(page_rect.min, Pos2::new(page_rect.max.x, screen.min.y)),
                Rect::from_min_max(Pos2::new(page_rect.min.x, screen.max.y), page_rect.max),
                Rect::from_min_max(
                    Pos2::new(page_rect.min.x, screen.min.y),
                    Pos2::new(screen.min.x, screen.max.y),
                ),
                Rect::from_min_max(
                    Pos2::new(screen.max.x, screen.min.y),
                    Pos2::new(page_rect.max.x, screen.max.y),
                ),
            ] {
                painter.rect_filled(s, CornerRadius::ZERO, shade);
            }
            painter.rect_filled(screen, CornerRadius::ZERO, Color32::from_white_alpha(235));
            self.paint_preview(&painter, screen, scale);
            painter.rect_stroke(
                screen,
                CornerRadius::ZERO,
                Stroke::new(2.0, p.primary),
                StrokeKind::Outside,
            );
            painter.text(
                screen.left_bottom() + Vec2::new(0.0, 4.0),
                Align2::LEFT_TOP,
                format!("{:.0} × {:.0} pt", r.width(), r.height()),
                FontId::proportional(11.0),
                p.primary,
            );
        } else if self.editing_stamp && self.stamp_rect.is_none() {
            painter.text(
                page_rect.center_bottom() - Vec2::new(0.0, 18.0),
                Align2::CENTER_CENTER,
                tr("Arrastra sobre la página para colocar la marca"),
                FontId::new(13.0, semibold()),
                p.info,
            );
        } else if self.signature_enabled && !self.editing_stamp && self.selected_field.is_none() {
            painter.text(
                page_rect.center_bottom() - Vec2::new(0.0, 18.0),
                Align2::CENTER_CENTER,
                tr("Arrastra sobre la página para colocar la firma"),
                FontId::new(13.0, semibold()),
                p.primary,
            );
        }
        let _ = response;
    }

    /// Vista previa aproximada de la apariencia dentro del recuadro.
    fn paint_preview(&self, painter: &egui::Painter, rect: Rect, scale: f32) {
        if !self.custom_appearance {
            return;
        }
        if let Some(tex) = &self.image_tex {
            let [w, h] = tex.size();
            let k = (rect.width() / w as f32).min(rect.height() / h as f32);
            let r = Rect::from_center_size(rect.center(), Vec2::new(w as f32 * k, h as f32 * k));
            painter.image(
                tex.id(),
                r,
                Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                Color32::WHITE,
            );
        }
        let family = match self.font_family {
            0 => FontFamily::Monospace,
            _ => FontFamily::Proportional,
        };
        let size = (self.font_size as f32 * scale).max(4.0);
        let text = self
            .text
            .replace("$$SUBJECTCN$$", tr("NOMBRE APELLIDOS - 00000000T"))
            .replace(
                "$$SIGNDATE=dd/MM/yyyy$$",
                &chrono::Local::now().format("%d/%m/%Y").to_string(),
            );
        let text = text
            .replace("$$ISSUERCN$$", tr("AC EMISORA"))
            .replace("$$CERTSERIAL$$", "0123ABCD");
        let wrap = if self.rotation == 90 || self.rotation == 270 {
            rect.height()
        } else {
            rect.width()
        } - 6.0;
        let galley = painter.layout(text, FontId::new(size, family), COLORS[self.color].1, wrap.max(10.0));
        let painter = painter.with_clip_rect(rect);
        match self.rotation {
            0 => painter.galley(rect.min + Vec2::new(3.0, 2.0), galley, COLORS[self.color].1),
            r => {
                let angle = match r {
                    90 => -std::f32::consts::FRAC_PI_2,
                    180 => std::f32::consts::PI,
                    _ => std::f32::consts::FRAC_PI_2,
                };
                let origin = match r {
                    90 => rect.left_bottom() + Vec2::new(2.0, -3.0),
                    180 => rect.right_bottom() - Vec2::new(3.0, 2.0),
                    _ => rect.right_top() + Vec2::new(-2.0, 3.0),
                };
                let mut shape = egui::epaint::TextShape::new(origin, galley, COLORS[self.color].1);
                shape.angle = angle;
                painter.add(shape);
            }
        }
    }

    fn pager(&mut self, ui: &mut Ui, p: &Palette, n: usize) {
        ui.horizontal(|ui| {
            let w = 330.0;
            ui.add_space(((ui.available_width() - w) / 2.0).max(0.0));
            let nav = |ui: &mut Ui, glyph: &str, enabled: bool| {
                ui.add_enabled(
                    enabled,
                    egui::Button::new(widgets::icon_text(glyph, 16.0, p.text)).min_size(Vec2::splat(32.0)),
                )
                .clicked()
            };
            if nav(ui, icons::CARET_DOUBLE_LEFT, self.page > 0) {
                self.page = 0;
            }
            if nav(ui, icons::CARET_LEFT, self.page > 0) {
                self.page -= 1;
            }
            ui.label(
                RichText::new(trf("Página {0} de {1}", &[&(self.page + 1), &n])).font(FontId::new(13.5, semibold())),
            );
            if nav(ui, icons::CARET_RIGHT, self.page + 1 < n) {
                self.page += 1;
            }
            if nav(ui, icons::CARET_DOUBLE_RIGHT, self.page + 1 < n) {
                self.page = n - 1;
            }
        });
    }

    fn side_panel(&mut self, ui: &mut Ui, p: &Palette, ctx: &egui::Context) {
        if self.stamp_enabled {
            self.stamp_section(ui, p, ctx);
            if !self.signature_enabled {
                return;
            }
            ui.add_space(14.0);
        }
        if !self.empty_fields.is_empty() {
            widgets::section_title(ui, p, tr("Campos de firma del documento"));
            ui.label(
                RichText::new(tr("Puedes firmar en un campo ya preparado o dibujar uno nuevo."))
                    .size(12.5)
                    .color(p.text_muted),
            );
            for i in 0..self.empty_fields.len() {
                let f = &self.empty_fields[i];
                let label = trf("{0} (página {1})", &[&f.name, &(f.page + 1)]);
                if ui.radio(self.selected_field == Some(i), label).clicked() {
                    self.selected_field = Some(i);
                    self.page = self.empty_fields[i].page;
                }
            }
            if ui.radio(self.selected_field.is_none(), tr("Nuevo recuadro")).clicked() {
                self.selected_field = None;
            }
            ui.add_space(12.0);
        }
        if self.selected_field.is_none() {
            widgets::section_title(ui, p, tr("Páginas"));
            ui.horizontal_wrapped(|ui| {
                if ui
                    .radio(self.page_mode == PageMode::Current, tr("Esta página"))
                    .clicked()
                {
                    self.page_mode = PageMode::Current;
                }
                if ui.radio(self.page_mode == PageMode::All, tr("Todas")).clicked() {
                    self.page_mode = PageMode::All;
                }
                let custom = matches!(self.page_mode, PageMode::Custom(_));
                if ui.radio(custom, tr("Selección")).clicked() && !custom {
                    self.page_mode = PageMode::Custom(String::new());
                }
            });
            if let PageMode::Custom(s) = &mut self.page_mode {
                ui.add(
                    egui::TextEdit::singleline(s)
                        .hint_text(tr("Ej.: 1,3-5,-1 (última)"))
                        .desired_width(f32::INFINITY),
                );
            }
            ui.add_space(12.0);
        }
        if !self.custom_appearance {
            return;
        }
        widgets::section_title(ui, p, tr("Texto"));
        ui.add(
            egui::TextEdit::multiline(&mut self.text)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(tr("Insertar:")).size(12.0).color(p.text_muted));
            for (label, token) in tokens() {
                if ui.small_button(label).on_hover_text(token).clicked() {
                    if !self.text.ends_with(' ') && !self.text.is_empty() {
                        self.text.push(' ');
                    }
                    self.text.push_str(token);
                }
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("vs_font")
                .selected_text(FONTS[self.font_family])
                .width(120.0)
                .show_ui(ui, |ui| {
                    for (i, f) in FONTS.iter().enumerate() {
                        ui.selectable_value(&mut self.font_family, i, *f);
                    }
                });
            ui.add(egui::DragValue::new(&mut self.font_size).range(1..=50).suffix(" pt"));
            egui::ComboBox::from_id_salt("vs_color")
                .selected_text(color_name(self.color))
                .width(110.0)
                .show_ui(ui, |ui| {
                    for i in 0..COLORS.len() {
                        ui.selectable_value(&mut self.color, i, color_name(i));
                    }
                });
        });
        ui.horizontal(|ui| {
            let toggle = |ui: &mut Ui, on: bool, text: RichText, tip: &str| -> bool {
                ui.add(egui::Button::selectable(on, text).min_size(Vec2::new(32.0, 28.0)))
                    .on_hover_text(tip)
                    .clicked()
            };
            if toggle(ui, self.bold, RichText::new(tr("N")).strong(), tr("Negrita")) {
                self.bold = !self.bold;
                self.underline = false;
                self.strike = false;
            }
            if toggle(ui, self.italic, RichText::new(tr("K")).italics(), tr("Cursiva")) {
                self.italic = !self.italic;
                self.underline = false;
                self.strike = false;
            }
            if toggle(ui, self.underline, RichText::new(tr("S")).underline(), tr("Subrayado")) {
                self.underline = !self.underline;
                self.bold = false;
                self.italic = false;
                self.strike = false;
            }
            if toggle(ui, self.strike, RichText::new(tr("T")).strikethrough(), tr("Tachado")) {
                self.strike = !self.strike;
                self.bold = false;
                self.italic = false;
                self.underline = false;
            }
            ui.add_space(8.0);
            egui::ComboBox::from_id_salt("vs_rot")
                .selected_text(if self.rotation == 0 {
                    tr("Sin rotar").to_string()
                } else {
                    trf("Rotar {0}º", &[&self.rotation])
                })
                .width(100.0)
                .show_ui(ui, |ui| {
                    for r in [0u16, 90, 180, 270] {
                        let label = if r == 0 {
                            tr("Sin rotar").to_string()
                        } else {
                            trf("Rotar {0}º", &[&r])
                        };
                        ui.selectable_value(&mut self.rotation, r, label);
                    }
                });
        });
        ui.add_space(12.0);
        widgets::section_title(ui, p, tr("Imagen"));
        match self.image.as_ref().map(|(n, _)| n.clone()) {
            Some(name) => {
                let mut remove = false;
                ui.horizontal(|ui| {
                    widgets::icon_label(ui, p, icons::IMAGE, &name);
                    remove = ui.link(tr("Quitar")).clicked();
                });
                if remove {
                    self.clear_image();
                }
            }
            None => {
                ui.label(
                    RichText::new(tr("Puedes añadir tu rúbrica o el sello de tu organización."))
                        .size(12.5)
                        .color(p.text_muted),
                );
                if widgets::button(
                    ui,
                    p,
                    ButtonKind::Secondary,
                    Some(icons::IMAGE),
                    tr("Elegir imagen…"),
                    true,
                )
                .clicked()
                    && let Some(path) = crate::services::desktop::file_dialog()
                        .set_title(tr("Selecciona la imagen de la firma"))
                        .add_filter(tr("Imágenes"), &["jpg", "jpeg", "png", "gif", "bmp"])
                        .pick_file()
                {
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            if let Err(e) = self.set_image(ctx, name, bytes) {
                                self.error = Some(e);
                            }
                        }
                        Err(e) => self.error = Some(trf("No se ha podido leer la imagen: {0}", &[&e])),
                    }
                }
            }
        }
        ui.add_space(12.0);
        ui.checkbox(&mut self.remember, tr("Recordar esta apariencia para próximas firmas"));
        if ui.link(tr("Restaurar la apariencia por defecto")).clicked() {
            self.text = default_text().into();
            self.font_family = 1;
            self.font_size = 12;
            self.bold = false;
            self.italic = false;
            self.underline = false;
            self.strike = false;
            self.color = 0;
            self.rotation = 0;
            self.clear_image();
        }
    }
}

impl VisibleSigEditor {
    /// Opciones de la marca de imagen (`SignPdfUiPanelStamp` de AutoFirma).
    fn stamp_section(&mut self, ui: &mut Ui, p: &Palette, ctx: &egui::Context) {
        if self.signature_enabled {
            widgets::section_title(ui, p, tr("Qué colocas en la página"));
            ui.horizontal(|ui| {
                if ui.radio(!self.editing_stamp, tr("Firma")).clicked() {
                    self.editing_stamp = false;
                }
                if ui.radio(self.editing_stamp, tr("Marca de imagen")).clicked() {
                    self.editing_stamp = true;
                }
            });
            ui.add_space(10.0);
        }
        widgets::section_title(ui, p, tr("Marca de imagen"));
        ui.label(
            RichText::new(tr(
                "Una imagen (logotipo, sello…) que se añade al documento antes de firmarlo.",
            ))
            .size(12.5)
            .color(p.text_muted),
        );
        match self.stamp_image.as_ref().map(|(n, _)| n.clone()) {
            Some(name) => {
                ui.horizontal(|ui| {
                    widgets::icon_label(ui, p, icons::IMAGE, &name);
                    if ui.link(tr("Cambiar")).clicked() {
                        self.pick_stamp_image(ctx);
                    }
                });
            }
            None => {
                if widgets::button(
                    ui,
                    p,
                    ButtonKind::Secondary,
                    Some(icons::IMAGE),
                    tr("Elegir imagen…"),
                    true,
                )
                .clicked()
                {
                    self.pick_stamp_image(ctx);
                }
            }
        }
        ui.add_space(4.0);
        ui.checkbox(&mut self.stamp_all_pages, tr("Incluir la imagen en todas las páginas"));
    }

    /// Marca de ejemplo para las capturas de demostración.
    pub fn set_stamp_demo(&mut self, ctx: &egui::Context, png: Vec<u8>) -> Result<(), String> {
        self.set_stamp_image(ctx, "logo.png".into(), png)?;
        self.stamp_rect = Some(Rect::from_min_max(Pos2::new(470.0, 40.0), Pos2::new(555.0, 125.0)));
        self.stamp_page = 0;
        self.editing_stamp = false;
        Ok(())
    }

    fn pick_stamp_image(&mut self, ctx: &egui::Context) {
        let Some(path) = crate::services::desktop::file_dialog()
            .set_title(tr("Selecciona la imagen de la marca"))
            .add_filter(tr("Imágenes"), &["jpg", "jpeg", "png", "gif", "bmp"])
            .pick_file()
        else {
            return;
        };
        match std::fs::read(&path) {
            Ok(bytes) => {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                match self.set_stamp_image(ctx, name, bytes) {
                    Ok(()) => self.editing_stamp = true,
                    Err(e) => self.error = Some(e),
                }
            }
            Err(e) => self.error = Some(trf("No se ha podido leer la imagen: {0}", &[&e])),
        }
    }
}

/// Valida un rango de páginas como `PdfUtil.checkPagesRangeInputFormat`.
pub fn check_pages_range(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ',') {
        return false;
    }
    if s.ends_with(',') || s.contains(",,") || s.contains("---") {
        return false;
    }
    s.split(',')
        .all(|item| !(item.ends_with('-') || item.starts_with("--") || item == "-"))
}

/// Página de ejemplo para la demostración (simula un documento).
pub struct DemoPages;

impl PageSource for DemoPages {
    fn page_count(&self) -> usize {
        3
    }

    fn page_size(&self, _index: usize) -> (f32, f32) {
        (595.0, 842.0)
    }

    fn render(&self, index: usize, scale: f32) -> Option<ColorImage> {
        let (w, h) = ((595.0 * scale) as usize, (842.0 * scale) as usize);
        let mut img = ColorImage::new([w, h], vec![Color32::WHITE; w * h]);
        let line = |img: &mut ColorImage, y: usize, x0: usize, x1: usize, c: Color32, t: usize| {
            for yy in y..(y + t).min(h) {
                for xx in x0..x1.min(w) {
                    img.pixels[yy * w + xx] = c;
                }
            }
        };
        let s = |v: f32| (v * scale) as usize;
        line(
            &mut img,
            s(60.0),
            s(60.0),
            s(300.0),
            Color32::from_rgb(40, 40, 40),
            s(10.0),
        );
        for i in 0..28 {
            let len = if i % 6 == 5 {
                300.0
            } else {
                475.0 - ((i * 37 + index * 11) % 60) as f32
            };
            line(
                &mut img,
                s(110.0 + i as f32 * 22.0),
                s(60.0),
                s(60.0 + len),
                Color32::from_gray(185),
                s(5.0),
            );
        }
        Some(img)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_ranges() {
        for ok in ["1", "1,3-5", "-1", "-3--1", "1-2,4"] {
            assert!(check_pages_range(ok), "{ok}");
        }
        for bad in ["", "1,", "1,,2", "1---2", "3-", "--1", "-", "a"] {
            assert!(!check_pages_range(bad), "{bad}");
        }
    }

    #[test]
    fn stamp_params() {
        let mut e = VisibleSigEditor {
            source: Some(Arc::new(DemoPages)),
            signature_enabled: false,
            stamp_enabled: true,
            stamp_image: Some(("logo.png".into(), vec![1, 2, 3])),
            stamp_rect: Some(Rect::from_min_max(Pos2::new(10.0, 20.0), Pos2::new(110.0, 70.0))),
            stamp_page: 1,
            ..Default::default()
        };
        let (_, h) = DemoPages.page_size(1);
        let p = e.build_params().unwrap();
        assert_eq!(p.get("imagePage"), Some("2"));
        assert_eq!(p.get("image"), Some("AQID"));
        assert_eq!(p.get("imagePositionOnPageLowerLeftX"), Some("10"));
        assert_eq!(
            p.get("imagePositionOnPageLowerLeftY"),
            Some(((h - 70.0) as i64).to_string().as_str())
        );
        assert_eq!(
            p.get("imagePositionOnPageUpperRightY"),
            Some(((h - 20.0) as i64).to_string().as_str())
        );
        assert!(p.get("signaturePages").is_none());
        e.stamp_all_pages = true;
        assert_eq!(e.build_params().unwrap().get("imagePage"), Some("0"));
    }

    #[test]
    fn params_from_rectangle() {
        let mut e = VisibleSigEditor {
            source: Some(Arc::new(DemoPages)),
            ..Default::default()
        };
        e.set_rect_pdf(0, 100.0, 50.0, 300.0, 150.0);
        let p = e.build_params().unwrap();
        assert_eq!(p.get("signaturePages"), Some("1"));
        assert_eq!(p.get("signaturePositionOnPageLowerLeftX"), Some("100"));
        assert_eq!(p.get("signaturePositionOnPageLowerLeftY"), Some("50"));
        assert_eq!(p.get("signaturePositionOnPageUpperRightX"), Some("300"));
        assert_eq!(p.get("signaturePositionOnPageUpperRightY"), Some("150"));
        assert_eq!(p.get("layer2FontFamily"), Some("1"));
        assert_eq!(p.get("layer2FontColor"), Some("black"));
        e.set_rect_pdf(0, 100.0, 50.0, 110.0, 60.0);
        assert!(e.build_params().is_err());
    }
}
