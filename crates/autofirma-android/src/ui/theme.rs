//! Tema visual: la misma paleta, tipografía (Inter) e iconos (Phosphor) que la aplicación
//! de escritorio (`crates/autofirma/src/ui/theme.rs`), con tamaños para pantalla táctil
//! (puntos de egui = dp de Android) y la escala de texto de accesibilidad del sistema.

use std::sync::Arc;

use egui::{
    Color32, Context, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Shadow, Stroke, TextStyle,
    Visuals,
};

/// Paleta de colores semánticos (idéntica a la del escritorio).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    pub dark: bool,
    pub bg: Color32,
    pub surface: Color32,
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

    pub fn for_night(night: bool) -> Palette {
        if night { Palette::DARK } else { Palette::LIGHT }
    }
}

/// Familia seminegrita (Inter SemiBold).
pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

/// Familia de los iconos (Phosphor).
pub fn icons() -> FontFamily {
    FontFamily::Name("icons".into())
}

/// Instala Inter (normal y seminegrita) y Phosphor, las fuentes del escritorio. Las de egui
/// quedan de respaldo (símbolos y monoespaciada).
pub fn install_fonts(ctx: &Context) {
    let mut fonts = FontDefinitions::default();
    let add = |fonts: &mut FontDefinitions, name: &str, bytes: &'static [u8]| {
        fonts
            .font_data
            .insert(name.to_owned(), Arc::new(FontData::from_static(bytes)));
    };
    add(
        &mut fonts,
        "inter",
        include_bytes!("../../../autofirma/assets/fonts/Inter-Regular.ttf"),
    );
    add(
        &mut fonts,
        "inter-semibold",
        include_bytes!("../../../autofirma/assets/fonts/Inter-SemiBold.ttf"),
    );
    add(
        &mut fonts,
        "phosphor",
        include_bytes!("../../../autofirma/assets/fonts/Phosphor.ttf"),
    );
    let defaults = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "inter".to_owned());
    let mut semibold_list = vec!["inter-semibold".to_owned(), "inter".to_owned()];
    semibold_list.extend(defaults.iter().cloned());
    fonts.families.insert(semibold(), semibold_list);
    // Familia propia para los iconos: Inter tiene glifos en la zona de uso privado.
    let mut icon_list = vec!["phosphor".to_owned()];
    icon_list.extend(defaults);
    fonts.families.insert(icons(), icon_list);
    ctx.set_fonts(fonts);
}

/// Tamaños de texto (dp) antes de la escala del sistema.
pub mod size {
    pub const BODY: f32 = 16.0;
    pub const SMALL: f32 = 14.0;
    pub const BUTTON: f32 = 16.5;
    pub const HEADING: f32 = 24.0;
    pub const TITLE: f32 = 20.0;
    pub const DISPLAY: f32 = 30.0;
    pub const SECTION: f32 = 13.0;
}

/// Aplica la paleta y el estilo. `scale` es la escala de texto del sistema (acotada).
pub fn apply(ctx: &Context, p: &Palette, scale: f32) {
    let s = scale.clamp(0.85, 2.0);
    let mut style = (*ctx.global_style()).clone();
    style.animation_time = 0.15;
    style.text_styles = [
        (TextStyle::Heading, FontId::new(size::HEADING * s, semibold())),
        (TextStyle::Body, FontId::new(size::BODY * s, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(size::BUTTON * s, semibold())),
        (TextStyle::Small, FontId::new(size::SMALL * s, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(14.0 * s, FontFamily::Monospace)),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(18.0, 12.0);
    style.spacing.interact_size = egui::vec2(48.0, 48.0);
    style.spacing.window_margin = Margin::same(20);
    style.spacing.scroll = egui::style::ScrollStyle::floating();
    // Desplazamiento con el dedo sin inercia artificial ni barras gruesas.
    style.interaction.selectable_labels = false;
    style.interaction.tooltip_delay = f32::INFINITY;

    let mut v = if p.dark { Visuals::dark() } else { Visuals::light() };
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(20);
    v.window_shadow = Shadow {
        offset: [0, 8],
        blur: 28,
        spread: 0,
        color: Color32::from_black_alpha(if p.dark { 120 } else { 40 }),
    };
    v.extreme_bg_color = p.surface;
    v.faint_bg_color = p.surface_alt;
    v.code_bg_color = p.surface_alt;
    v.hyperlink_color = p.primary;
    v.warn_fg_color = p.warning;
    v.error_fg_color = p.danger;
    v.override_text_color = Some(p.text);
    v.selection.bg_fill = p.primary.linear_multiply(0.35);
    v.selection.stroke = Stroke::new(1.5, p.primary);
    v.text_cursor.stroke = Stroke::new(2.0, p.primary);
    v.text_edit_bg_color = Some(p.surface);

    let radius = CornerRadius::same(12);
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
    w.hovered = w.inactive;
    w.hovered.bg_stroke = Stroke::new(1.0, p.primary.linear_multiply(0.6));
    w.active.bg_fill = p.primary_soft;
    w.active.weak_bg_fill = p.primary_soft;
    w.active.bg_stroke = Stroke::new(1.0, p.primary);
    w.active.fg_stroke = Stroke::new(1.5, p.text);
    w.active.corner_radius = radius;
    w.open = w.active;

    style.visuals = v;
    let theme = if p.dark { egui::Theme::Dark } else { egui::Theme::Light };
    ctx.set_theme(theme);
    ctx.set_style_of(theme, style);
}
