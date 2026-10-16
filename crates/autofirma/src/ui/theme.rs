//! Tema visual de AutoFirma-rs: paleta (clara y oscura), tipografía e iconos.
//!
//! El color de marca procede del logotipo original de AutoFirma (plumín rojo
//! anaranjado). La tipografía es Inter (licencia OFL) y los iconos, Phosphor
//! (licencia MIT).

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow, Stroke, TextStyle,
    Visuals,
};

/// Paleta de colores semánticos.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub dark: bool,
    /// Fondo de la ventana.
    pub bg: Color32,
    /// Fondo de la barra lateral.
    pub sidebar: Color32,
    /// Superficie de tarjetas.
    pub surface: Color32,
    /// Superficie elevada (hover, campos).
    pub surface_alt: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_muted: Color32,
    pub text_faint: Color32,
    pub primary: Color32,
    pub primary_hover: Color32,
    pub primary_soft: Color32,
    pub on_primary: Color32,
    pub success: Color32,
    pub success_soft: Color32,
    pub warning: Color32,
    pub warning_soft: Color32,
    pub danger: Color32,
    pub danger_soft: Color32,
    pub info: Color32,
    pub info_soft: Color32,
}

impl Palette {
    pub const LIGHT: Palette = Palette {
        dark: false,
        bg: Color32::from_rgb(0xF5, 0xF6, 0xF8),
        sidebar: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
        surface_alt: Color32::from_rgb(0xF0, 0xF2, 0xF5),
        border: Color32::from_rgb(0xE2, 0xE5, 0xEA),
        text: Color32::from_rgb(0x14, 0x1B, 0x26),
        text_muted: Color32::from_rgb(0x55, 0x5F, 0x6D),
        text_faint: Color32::from_rgb(0x8A, 0x93, 0xA0),
        primary: Color32::from_rgb(0xC2, 0x41, 0x0C),
        primary_hover: Color32::from_rgb(0xA3, 0x36, 0x09),
        primary_soft: Color32::from_rgb(0xFD, 0xEE, 0xE6),
        on_primary: Color32::WHITE,
        success: Color32::from_rgb(0x16, 0x7A, 0x4C),
        success_soft: Color32::from_rgb(0xE7, 0xF6, 0xEE),
        warning: Color32::from_rgb(0xA8, 0x5A, 0x00),
        warning_soft: Color32::from_rgb(0xFE, 0xF4, 0xE2),
        danger: Color32::from_rgb(0xB4, 0x23, 0x18),
        danger_soft: Color32::from_rgb(0xFD, 0xEC, 0xEA),
        info: Color32::from_rgb(0x1D, 0x4E, 0xD8),
        info_soft: Color32::from_rgb(0xEA, 0xF1, 0xFE),
    };

    pub const DARK: Palette = Palette {
        dark: true,
        bg: Color32::from_rgb(0x0F, 0x12, 0x17),
        sidebar: Color32::from_rgb(0x13, 0x17, 0x1E),
        surface: Color32::from_rgb(0x18, 0x1D, 0x25),
        surface_alt: Color32::from_rgb(0x20, 0x26, 0x30),
        border: Color32::from_rgb(0x2B, 0x32, 0x3D),
        text: Color32::from_rgb(0xE8, 0xEC, 0xF1),
        text_muted: Color32::from_rgb(0xA3, 0xAC, 0xB8),
        text_faint: Color32::from_rgb(0x6E, 0x77, 0x84),
        primary: Color32::from_rgb(0xF0, 0x6E, 0x2E),
        primary_hover: Color32::from_rgb(0xF5, 0x8A, 0x52),
        primary_soft: Color32::from_rgb(0x3A, 0x21, 0x15),
        on_primary: Color32::from_rgb(0x14, 0x0B, 0x06),
        success: Color32::from_rgb(0x4A, 0xC2, 0x86),
        success_soft: Color32::from_rgb(0x12, 0x2B, 0x20),
        warning: Color32::from_rgb(0xF2, 0xB1, 0x4C),
        warning_soft: Color32::from_rgb(0x33, 0x26, 0x10),
        danger: Color32::from_rgb(0xF4, 0x70, 0x67),
        danger_soft: Color32::from_rgb(0x37, 0x17, 0x15),
        info: Color32::from_rgb(0x6E, 0x9C, 0xF7),
        info_soft: Color32::from_rgb(0x15, 0x22, 0x3D),
    };

    /// Paleta de alto contraste (accesibilidad).
    pub const HIGH_CONTRAST: Palette = Palette {
        dark: true,
        bg: Color32::BLACK,
        sidebar: Color32::BLACK,
        surface: Color32::BLACK,
        surface_alt: Color32::from_rgb(0x1A, 0x1A, 0x1A),
        border: Color32::WHITE,
        text: Color32::WHITE,
        text_muted: Color32::from_rgb(0xF0, 0xF0, 0xF0),
        text_faint: Color32::from_rgb(0xD0, 0xD0, 0xD0),
        primary: Color32::from_rgb(0xFF, 0xD6, 0x00),
        primary_hover: Color32::from_rgb(0xFF, 0xE6, 0x5C),
        primary_soft: Color32::from_rgb(0x33, 0x2B, 0x00),
        on_primary: Color32::BLACK,
        success: Color32::from_rgb(0x5C, 0xFF, 0x8F),
        success_soft: Color32::BLACK,
        warning: Color32::from_rgb(0xFF, 0xC0, 0x40),
        warning_soft: Color32::BLACK,
        danger: Color32::from_rgb(0xFF, 0x6B, 0x6B),
        danger_soft: Color32::BLACK,
        info: Color32::from_rgb(0x7F, 0xB2, 0xFF),
        info_soft: Color32::BLACK,
    };
}

/// Preferencia de tema del usuario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ThemeChoice {
    /// Seguir al sistema operativo.
    #[default]
    System,
    Light,
    Dark,
    HighContrast,
}

impl ThemeChoice {
    pub fn palette(self, system_dark: bool) -> Palette {
        match self {
            ThemeChoice::System => {
                if system_dark {
                    Palette::DARK
                } else {
                    Palette::LIGHT
                }
            }
            ThemeChoice::Light => Palette::LIGHT,
            ThemeChoice::Dark => Palette::DARK,
            ThemeChoice::HighContrast => Palette::HIGH_CONTRAST,
        }
    }
}

/// Familias tipográficas propias.
pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn bold() -> FontFamily {
    FontFamily::Name("bold".into())
}

/// Familia exclusiva de iconos (Phosphor normal). Se usa una familia propia
/// porque Inter define glifos en la zona de uso privado que taparían iconos.
pub fn icons() -> FontFamily {
    FontFamily::Name("icons".into())
}

pub fn icons_fill() -> FontFamily {
    FontFamily::Name("icons-fill".into())
}

/// Instala las fuentes (Inter + iconos Phosphor).
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let add = |fonts: &mut FontDefinitions, name: &str, bytes: &'static [u8]| {
        fonts.font_data.insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    };
    add(&mut fonts, "inter", include_bytes!("../../assets/fonts/Inter-Regular.ttf"));
    add(&mut fonts, "inter-semibold", include_bytes!("../../assets/fonts/Inter-SemiBold.ttf"));
    add(&mut fonts, "inter-bold", include_bytes!("../../assets/fonts/Inter-Bold.ttf"));
    add(&mut fonts, "phosphor", include_bytes!("../../assets/fonts/Phosphor.ttf"));
    add(&mut fonts, "phosphor-fill", include_bytes!("../../assets/fonts/Phosphor-Fill.ttf"));

    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    proportional.insert(0, "inter".to_owned());
    fonts.families.insert(semibold(), vec!["inter-semibold".into(), "inter".into()]);
    fonts.families.insert(bold(), vec!["inter-bold".into(), "inter".into()]);
    fonts.families.insert(icons(), vec!["phosphor".into(), "inter".into()]);
    fonts.families.insert(icons_fill(), vec!["phosphor-fill".into(), "inter".into()]);
    // Las familias por defecto de egui (emoji, monoespaciada) quedan como respaldo.
    for fam in [semibold(), bold(), icons(), icons_fill()] {
        if let Some(defaults) = FontDefinitions::default().families.get(&FontFamily::Proportional) {
            fonts.families.get_mut(&fam).unwrap().extend(defaults.iter().cloned());
        }
    }
    ctx.set_fonts(fonts);
}

/// Aplica la paleta y el estilo general a egui.
pub fn apply(ctx: &egui::Context, p: &Palette, scale: f32) {
    let mut style = (*ctx.global_style()).clone();
    style.animation_time = 0.12;
    style.text_styles = [
        (TextStyle::Heading, FontId::new(24.0 * scale, semibold())),
        (TextStyle::Body, FontId::new(14.0 * scale, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(14.0 * scale, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(12.0 * scale, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0 * scale, FontFamily::Monospace)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size = egui::vec2(36.0, 30.0);
    style.spacing.window_margin = Margin::same(18);
    style.spacing.menu_margin = Margin::same(8);
    style.spacing.combo_height = 300.0;

    let mut v = if p.dark { Visuals::dark() } else { Visuals::light() };
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(14);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_shadow = Shadow { offset: [0, 8], blur: 28, spread: 0, color: Color32::from_black_alpha(if p.dark { 120 } else { 40 }) };
    v.popup_shadow = Shadow { offset: [0, 4], blur: 16, spread: 0, color: Color32::from_black_alpha(if p.dark { 110 } else { 30 }) };
    v.extreme_bg_color = p.surface;
    v.faint_bg_color = p.surface_alt;
    v.code_bg_color = p.surface_alt;
    v.hyperlink_color = p.primary;
    v.warn_fg_color = p.warning;
    v.error_fg_color = p.danger;
    v.override_text_color = Some(p.text);
    v.selection.bg_fill = p.primary.linear_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, p.primary);
    v.text_edit_bg_color = Some(p.surface);

    let radius = CornerRadius::same(8);
    let w = &mut v.widgets;
    w.noninteractive.bg_fill = p.surface;
    w.noninteractive.weak_bg_fill = p.surface;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = radius;

    w.inactive.bg_fill = p.surface_alt;
    w.inactive.weak_bg_fill = p.surface_alt;
    w.inactive.bg_stroke = Stroke::new(1.0, p.border);
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.inactive.corner_radius = radius;

    w.hovered.bg_fill = p.surface_alt;
    w.hovered.weak_bg_fill = p.surface_alt;
    w.hovered.bg_stroke = Stroke::new(1.0, p.primary.linear_multiply(0.6));
    w.hovered.fg_stroke = Stroke::new(1.5, p.text);
    w.hovered.corner_radius = radius;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = p.primary_soft;
    w.active.weak_bg_fill = p.primary_soft;
    w.active.bg_stroke = Stroke::new(1.0, p.primary);
    w.active.fg_stroke = Stroke::new(1.5, p.text);
    w.active.corner_radius = radius;
    w.active.expansion = 0.0;

    w.open = w.active;

    style.visuals = v;
    let theme = if p.dark { egui::Theme::Dark } else { egui::Theme::Light };
    ctx.set_theme(theme);
    ctx.set_style_of(theme, style);
}
