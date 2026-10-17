//! Pantallas y diálogos de la aplicación (`docs/spec/09-android.md` §2), con los textos del
//! original. Cada pantalla dibuja su estado ([`Screen`]) y devuelve lo que el usuario ha
//! pedido como [`Action`]; la aplicación ([`crate::shell::Shell`]) las ejecuta después de
//! dibujar (navegación, preferencias, llamadas a Android).

use egui::{Align, Color32, Layout, Margin, Rect, RichText, ScrollArea, TextureHandle, Ui, UiBuilder, pos2, vec2};

use super::icons;
use super::markup;
use super::theme::size;
use super::widgets::{
    self, ButtonKind, Cx, TOP_BAR, Tone, Trailing, button, card, centered_column, centered_text, checkbox_row, group,
    hero_action, icon_badge, link, list_row, notice, section_title, sheet, switch_row, text_field, tile, top_bar,
};
use crate::bridge::DeviceConfig;
use crate::features::{CertificateState, Features};
use crate::flow::{CertType, FlowAction, Flows};
use crate::history::{RecordKind, SignRecord};
use crate::i18n::{Language, tr, trf};
use crate::ime::{FieldSpec, InputKind};
use crate::keychain::{CertificateWarning, warning_texts};
use crate::nav::{Screen, SignConfigDraft};
use crate::prefs::{CacheMinutes, Preferences};
use crate::visible::ViewSelection;

/// Lo que el usuario pide en una pantalla o diálogo.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Push(Screen),
    Back,
    OpenDialog(Dialog),
    CloseDialog,
    /// Salir del arranque (o tocar el logotipo).
    LeaveSplash,
    /// «Comenzar» en la bienvenida.
    StartIntro,
    /// «Aceptar» en las condiciones.
    AcceptConditions,
    /// Idioma elegido (`None`: el del sistema).
    SetLanguage(Option<Language>),
    SaveSignConfig(SignConfigDraft),
    /// Minutos elegidos en el diálogo (se copian al borrador de la configuración).
    SetCacheMinutes(CacheMinutes),
    SetValidateSsl(bool),
    SaveTrustedDomains(String),
    OpenHistory,
    ClearHistory,
    /// Respuesta a la pregunta de primera ejecución sobre el NFC.
    AnswerNfc(bool),
    /// Paso de una operación de varios pasos (firma local, importación).
    Flow(FlowAction),
    /// «Añadir certificado» al final de las instrucciones: se cierran y se abre el selector.
    ImportCertificate,
    /// Selector de certificados de KeyChain («Ver un certificado»).
    ChooseCertificate,
    OpenUrl(String),
}

/// Diálogo genérico con uno o dos botones que ejecutan acciones (`CustomDialog`).
#[derive(Debug, Clone, PartialEq)]
pub struct Prompt {
    /// Identificador estable (registros y pruebas).
    pub id: &'static str,
    pub tone: Tone,
    pub glyph: &'static str,
    pub title: String,
    pub body: String,
    /// Botón principal: clave del texto y acción.
    pub primary: (&'static str, Action),
    /// Botón secundario (subrayado): clave del texto y acción.
    pub secondary: Option<(&'static str, Action)>,
    /// Lo que hace «Atrás»: `None` cierra el diálogo.
    pub back: Option<Action>,
}

/// Diálogos (hojas inferiores, como los `BottomSheetDialog` del original).
#[derive(Debug, Clone, PartialEq)]
pub enum Dialog {
    /// «¿Para qué sirve AutoFirma?» (`HelpDialog`, §2.5).
    Help,
    /// Pregunta de la primera ejecución sobre el NFC (`ConfigNfcDialog`).
    ConfigNfc,
    /// Mensaje genérico (`CustomDialog`).
    Message {
        tone: Tone,
        glyph: &'static str,
        title: String,
        body: String,
        /// Clave del texto del botón.
        button: &'static str,
    },
    /// «Selecciona un valor en minutos» (`SelectCacheMinutesDialog`).
    CacheMinutes { selected: CacheMinutes },
    /// «Eliminar histórico».
    ConfirmClearHistory,
    /// Idioma (desde las condiciones).
    LanguagePicker,
    /// Diálogo con acciones (avisos del certificado, firma visible, importación...).
    Prompt(Box<Prompt>),
    /// Progreso modal sin botones (`ProgressDialog`): «Realizando firma», «Cargando
    /// certificado»... «Atrás» no lo cierra.
    Progress {
        /// Clave del texto.
        text: &'static str,
    },
    /// «¿Con qué firmarás?» (`ChooseCertTypeDialog`).
    ChooseCertType {
        /// Selección de certificado web («¿Con qué te identificarás?»).
        auth: bool,
    },
    /// Contraseña de un PDF protegido (`PDFPasswordDialog`, `PDFPasswordVisibleSignDialog`).
    PdfPassword {
        password: String,
        /// Se ve la contraseña (icono del ojo).
        revealed: bool,
        /// Clave del texto de error («Contraseña incorrecta:»...).
        error: Option<&'static str>,
    },
}

impl Dialog {
    pub fn id(&self) -> &'static str {
        match self {
            Dialog::Help => "help",
            Dialog::ConfigNfc => "config_nfc",
            Dialog::Message { .. } => "message",
            Dialog::CacheMinutes { .. } => "cache_minutes",
            Dialog::ConfirmClearHistory => "confirm_clear_history",
            Dialog::LanguagePicker => "language_picker",
            Dialog::Prompt(prompt) => prompt.id,
            Dialog::Progress { .. } => "progress",
            Dialog::ChooseCertType { .. } => "cert_type",
            Dialog::PdfPassword { .. } => "pdf_password",
        }
    }

    /// Se cierra al tocar fuera (las hojas del original que lo permitían).
    fn dismissable(&self) -> bool {
        !matches!(
            self,
            Dialog::ConfigNfc
                | Dialog::Prompt(_)
                | Dialog::Progress { .. }
                | Dialog::ChooseCertType { .. }
                | Dialog::PdfPassword { .. }
        )
    }

    /// Mensaje informativo con el botón «Entendido».
    pub fn message(tone: Tone, glyph: &'static str, title: impl Into<String>, body: impl Into<String>) -> Dialog {
        Dialog::Message {
            tone,
            glyph,
            title: title.into(),
            body: body.into(),
            button: k!("understood"),
        }
    }
}

/// Datos de solo lectura para dibujar.
pub struct View<'a> {
    pub prefs: &'a Preferences,
    pub device: &'a DeviceConfig,
    pub features: &'a Features,
    pub flows: &'a Flows,
    pub logo: Option<&'a TextureHandle>,
    /// Idioma con el que se dibuja.
    pub language: Language,
}

/// Ancho máximo del contenido (tabletas y horizontal).
const MAX_WIDTH: f32 = 720.0;

/// Dibuja la pantalla actual en `ui` (la zona segura).
pub fn draw(ui: &mut Ui, cx: &mut Cx, screen: &mut Screen, view: &View, actions: &mut Vec<Action>) {
    match screen {
        Screen::Splash => splash(ui, cx, view, actions),
        Screen::Intro => intro(ui, cx, actions),
        Screen::Conditions { privacy, legal } => conditions(ui, cx, view, privacy, legal, actions),
        Screen::Home => home(ui, cx, view, actions),
        Screen::Settings => settings(ui, cx, view, actions),
        Screen::Language => language(ui, cx, view, actions),
        Screen::SignConfiguration(draft) => sign_configuration(ui, cx, view, draft, actions),
        Screen::TrustedDomains { text } => trusted_domains(ui, cx, view, text, actions),
        Screen::SignsRecord { records } => signs_record(ui, cx, records, actions),
        Screen::Faq { open } => faq(ui, cx, open, actions),
        Screen::HelpDnieNfc => help_page(
            ui,
            cx,
            actions,
            tr("activate_use_dnie_with_nfc_1"),
            icons::CONTACTLESS_PAYMENT,
            &[k!("dnie_with_nfc_help_text_1")],
            Some((
                "help.go_config",
                k!("go_to_configuration"),
                Screen::SignConfiguration(SignConfigDraft::from_prefs(view.prefs)),
            )),
            &[k!("dnie_with_nfc_help_text_2")],
        ),
        Screen::HelpVisibleSign => help_page(
            ui,
            cx,
            actions,
            tr("how_to_do_visible_sign"),
            icons::SIGNATURE,
            &[k!("visible_sign_help_text_1"), k!("visible_sign_help_text_2")],
            Some((
                "help.go_config",
                k!("go_to_configuration"),
                Screen::SignConfiguration(SignConfigDraft::from_prefs(view.prefs)),
            )),
            &[k!("visible_sign_help_text_3"), k!("visible_sign_help_text_4")],
        ),
        Screen::HelpTrustedDomains => help_page(
            ui,
            cx,
            actions,
            tr("how_to_configure_trusted_domains"),
            icons::SHIELD_CHECK,
            &[k!("trusted_domains_help_text_1"), k!("trusted_domains_help_text_2")],
            Some((
                "help.go_config",
                k!("go_to_configuration"),
                trusted_domains_screen(view.prefs),
            )),
            &[],
        ),
        Screen::HelpImportCerts => help_page(
            ui,
            cx,
            actions,
            tr("how_to_install_certs"),
            icons::TRAY,
            &[
                k!("import_certs_help_text_1"),
                k!("import_certs_help_text_2"),
                k!("import_certs_help_text_3"),
            ],
            Some((
                "help.import",
                k!("go_to_import_cert"),
                Screen::ImportInstructions { page: 0 },
            )),
            &[],
        ),
        Screen::AccessibilityStatement => text_page(
            ui,
            cx,
            actions,
            tr("accessibility_statement"),
            k!("accessibility_statement_body"),
            Some(("accessibility.repo", crate::REPOSITORY)),
        ),
        Screen::LegalNotice => text_page(ui, cx, actions, tr("legal_announcement"), k!("legal_notice_body"), None),
        Screen::PrivacyPolicy => text_page(ui, cx, actions, tr("privacy_policy"), k!("privacy_policy_body"), None),
        Screen::Version => version(ui, cx, view, actions),
        Screen::ImportInstructions { page } => import_instructions(ui, cx, page, actions),
        Screen::Certificates => certificates(ui, cx, view, actions),
        Screen::WebSigningInfo => web_signing(ui, cx, actions),
        Screen::VisibleSignature { selection, drag } => visible_signature(ui, cx, view, selection, drag, actions),
        Screen::WebRequest => web_request(ui, cx, view, actions),
    }
}

/// Pantalla de Dominios de confianza con la lista guardada en el campo.
pub fn trusted_domains_screen(prefs: &Preferences) -> Screen {
    Screen::TrustedDomains {
        text: prefs.secure_domains_list.join("\n"),
    }
}

type Body<'b> = Box<dyn FnOnce(&mut Ui, &mut Cx, &mut Vec<Action>) + 'b>;

/// Estructura común: barra superior, contenido desplazable y, si hay, botones fijos abajo.
#[allow(clippy::too_many_arguments)] // las partes de la página, sin estructura intermedia
fn page(
    ui: &mut Ui,
    cx: &mut Cx,
    actions: &mut Vec<Action>,
    title: &str,
    back: bool,
    top_actions: &[(&'static str, &str, &str)],
    body: Body,
    bottom: Option<Body>,
) -> Option<&'static str> {
    let full = ui.max_rect();
    let bar = Rect::from_min_size(full.min, vec2(full.width(), TOP_BAR));
    let top = top_bar(ui, cx, bar, title, back, top_actions);
    if top.back {
        actions.push(Action::Back);
    }
    let mut body_bottom = full.bottom();
    if let Some(bottom) = bottom {
        let width = full.width().min(MAX_WIDTH);
        let area = Rect::from_center_size(
            pos2(full.center().x, full.center().y),
            vec2(width - 40.0, full.height() - 16.0),
        );
        let used = ui
            .scope_builder(
                UiBuilder::new().max_rect(area).layout(Layout::bottom_up(Align::Center)),
                |ui| {
                    ui.spacing_mut().item_spacing.y = 10.0;
                    bottom(ui, cx, actions);
                },
            )
            .response
            .rect;
        body_bottom = used.top() - 10.0;
        ui.painter().hline(
            full.x_range(),
            body_bottom + 2.0,
            egui::Stroke::new(1.0, cx.p.border.linear_multiply(0.6)),
        );
    }
    let body_rect = Rect::from_min_max(pos2(full.left(), bar.bottom()), pos2(full.right(), body_bottom));
    ui.scope_builder(UiBuilder::new().max_rect(body_rect), |ui| {
        ui.set_clip_rect(body_rect.intersect(ui.clip_rect()));
        ScrollArea::vertical()
            .id_salt(("desplazamiento", title))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                centered_column(ui, MAX_WIDTH, |ui| {
                    egui::Frame::new()
                        .inner_margin(Margin {
                            left: 20,
                            right: 20,
                            top: 4,
                            bottom: 28,
                        })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            body(ui, cx, actions);
                        });
                });
            });
    });
    top.action
}

fn heading(ui: &mut Ui, cx: &Cx, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).font(cx.bold(size::HEADING)).color(cx.p.text)).wrap());
}

fn muted(ui: &mut Ui, cx: &Cx, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).font(cx.font(size::BODY)).color(cx.p.text_muted)).wrap());
}

fn small(ui: &mut Ui, cx: &Cx, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).font(cx.font(size::SMALL)).color(cx.p.text_muted)).wrap());
}

fn logo(ui: &mut Ui, view: &View, size: f32) {
    match view.logo {
        Some(texture) => {
            ui.add(
                egui::Image::new(texture)
                    .fit_to_exact_size(vec2(size, size))
                    .alt_text(crate::APP_NAME),
            );
        }
        None => {
            ui.allocate_space(vec2(size, size));
        }
    }
}

// ----------------------------------------------------------------------------------------
// Arranque, bienvenida y condiciones

fn splash(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    let rect = ui.max_rect();
    let column = Rect::from_center_size(rect.center(), vec2(rect.width().min(360.0), 260.0));
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(column)
            .layout(Layout::top_down(Align::Center)),
        |ui| {
            logo(ui, view, 112.0);
            ui.add_space(16.0);
            ui.label(
                RichText::new(crate::APP_NAME)
                    .font(cx.bold(size::DISPLAY))
                    .color(cx.p.text),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("v{}", crate::VERSION))
                    .font(cx.font(size::SMALL))
                    .color(cx.p.text_muted),
            );
            ui.add_space(24.0);
            ui.add(egui::Spinner::new().size(28.0).color(cx.p.primary));
        },
    );
    // Tocar en cualquier sitio salta la espera (encima de lo dibujado).
    if ui
        .interact(rect, egui::Id::unique("arranque"), egui::Sense::click())
        .clicked()
    {
        actions.push(Action::LeaveSplash);
    }
}

/// Ilustración de la bienvenida: un sello con iconos alrededor.
fn illustration(ui: &mut Ui, cx: &Cx, glyph: &str, satellites: &[&str]) {
    let p = cx.p;
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 264.0), egui::Sense::hover());
    let c = rect.center();
    let painter = ui.painter();
    painter.circle_filled(c, 96.0, p.primary_soft);
    painter.circle_stroke(c, 104.0, egui::Stroke::new(1.5, p.primary.linear_multiply(0.25)));
    painter.circle_filled(c, 58.0, p.primary);
    painter.text(c, egui::Align2::CENTER_CENTER, glyph, cx.icon(56.0), p.on_primary);
    let n = satellites.len().max(1) as f32;
    for (i, s) in satellites.iter().enumerate() {
        let angle = -2.4 + i as f32 * (1.9 / (n - 1.0).max(1.0));
        let pos = c + vec2(angle.cos(), angle.sin()) * 104.0;
        painter.circle_filled(pos, 24.0, p.surface);
        painter.circle_stroke(pos, 24.0, egui::Stroke::new(1.0, p.border));
        painter.text(pos, egui::Align2::CENTER_CENTER, *s, cx.icon(22.0), p.primary);
    }
}

fn intro(ui: &mut Ui, cx: &mut Cx, actions: &mut Vec<Action>) {
    let full = ui.max_rect();
    let width = full.width().min(560.0) - 48.0;
    let area = Rect::from_center_size(full.center(), vec2(width, full.height() - 32.0));
    ui.scope_builder(
        UiBuilder::new().max_rect(area).layout(Layout::bottom_up(Align::Center)),
        |ui| {
            if button(ui, cx, "intro.start", ButtonKind::Primary, None, tr("start"), true).clicked() {
                actions.push(Action::StartIntro);
            }
            ui.add_space(12.0);
            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.with_layout(Layout::top_down(Align::Center), |ui| {
                    ui.add_space((ui.available_height() - 520.0).max(0.0) / 2.0);
                    illustration(
                        ui,
                        cx,
                        icons::SEAL_CHECK,
                        &[icons::PEN_NIB, icons::IDENTIFICATION_CARD, icons::LOCK],
                    );
                    ui.add_space(24.0);
                    centered_text(ui, tr("intro_title"), cx.bold(size::DISPLAY), cx.p.text);
                    ui.add_space(12.0);
                    centered_text(ui, tr("intro_text"), cx.font(size::BODY + 1.0), cx.p.text_muted);
                });
            });
        },
    );
}

fn conditions(ui: &mut Ui, cx: &mut Cx, view: &View, privacy: &mut bool, legal: &mut bool, actions: &mut Vec<Action>) {
    let both = *privacy && *legal;
    // En pantallas bajas (horizontal) las casillas van al final del texto y abajo solo queda
    // el botón; si no, el texto apenas se vería.
    let compact = ui.max_rect().height() < 560.0;
    let privacy_cell = std::cell::Cell::new(*privacy);
    let legal_cell = std::cell::Cell::new(*legal);
    let checkboxes = |ui: &mut Ui, cx: &mut Cx| {
        let mut p = privacy_cell.get();
        checkbox_row(ui, cx, "conditions.privacy", tr("read_and_accept_privacy"), &mut p);
        privacy_cell.set(p);
        let mut l = legal_cell.get();
        checkbox_row(ui, cx, "conditions.legal", tr("read_and_accept_legal"), &mut l);
        legal_cell.set(l);
    };
    page(
        ui,
        cx,
        actions,
        tr("acceptance_conditions"),
        false,
        &[],
        Box::new(|ui, cx, actions| {
            group(ui, cx, |ui, cx| {
                let name = tr(view.language.name_key());
                if list_row(
                    ui,
                    cx,
                    "conditions.language",
                    Some(icons::TRANSLATE),
                    tr("language"),
                    None,
                    Trailing::Value(name),
                )
                .clicked()
                {
                    actions.push(Action::OpenDialog(Dialog::LanguagePicker));
                }
            });
            ui.add_space(14.0);
            card(ui, cx, |ui, cx| {
                heading(ui, cx, tr("privacy_policy"));
                ui.add_space(4.0);
                markup::show(ui, cx, tr("privacy_policy_body"));
                ui.add_space(14.0);
                heading(ui, cx, tr("legal_announcement"));
                ui.add_space(4.0);
                markup::show(ui, cx, tr("legal_notice_body"));
            });
            if compact {
                ui.add_space(10.0);
                checkboxes(ui, cx);
            }
        }),
        Some(Box::new(|ui, cx, actions| {
            if button(ui, cx, "conditions.accept", ButtonKind::Primary, None, tr("ok"), both).clicked() {
                actions.push(Action::AcceptConditions);
            }
            if !compact {
                // Disposición de abajo arriba: se añaden en orden inverso.
                let mut l = legal_cell.get();
                checkbox_row(ui, cx, "conditions.legal", tr("read_and_accept_legal"), &mut l);
                legal_cell.set(l);
                let mut p = privacy_cell.get();
                checkbox_row(ui, cx, "conditions.privacy", tr("read_and_accept_privacy"), &mut p);
                privacy_cell.set(p);
            }
        })),
    );
    *privacy = privacy_cell.get();
    *legal = legal_cell.get();
}

// ----------------------------------------------------------------------------------------
// Inicio

fn home(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    let action = page(
        ui,
        cx,
        actions,
        tr("app_name"),
        false,
        &[
            ("home.help", icons::INFO, tr("menu_information")),
            ("home.settings", icons::GEAR_SIX, tr("settings")),
        ],
        Box::new(|ui, cx, actions| {
            ui.add_space(4.0);
            ui.horizontal_top(|ui| {
                logo(ui, view, 56.0);
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    heading(ui, cx, tr("presentation_title"));
                });
            });
            ui.add_space(6.0);
            muted(ui, cx, tr("presentation_text"));
            section_title(ui, cx, &tr("accesibility_select_option").to_uppercase());
            if hero_action(
                ui,
                cx,
                "home.sign_file",
                icons::PEN_NIB,
                tr("sign_file"),
                tr("sign_file_desc"),
            )
            .clicked()
            {
                actions.push(Action::Flow(FlowAction::StartSign));
            }
            ui.add_space(12.0);
            let tiles: [(&'static str, &str, &str, Action); 4] = [
                (
                    "home.add_cert",
                    icons::PLUS,
                    tr("add_new_cert"),
                    Action::Push(Screen::ImportInstructions { page: 0 }),
                ),
                (
                    "home.web_signing",
                    icons::GLOBE,
                    tr("web_signing"),
                    Action::Push(Screen::WebSigningInfo),
                ),
                (
                    "home.certificates",
                    icons::CERTIFICATE,
                    tr("certificates"),
                    Action::Push(Screen::Certificates),
                ),
                (
                    "home.history",
                    icons::CLOCK_COUNTER_CLOCKWISE,
                    tr("sign_record"),
                    Action::OpenHistory,
                ),
            ];
            let columns = if ui.available_width() > 560.0 { 4 } else { 2 };
            let gap = 12.0;
            let width = (ui.available_width() - gap * (columns as f32 - 1.0)) / columns as f32;
            for row in tiles.chunks(columns) {
                let height = row
                    .iter()
                    .map(|(_, _, title, _)| widgets::tile_height(ui, cx, title, width))
                    .fold(0.0, f32::max);
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    for (tid, glyph, title, action) in row {
                        if tile(ui, cx, tid, glyph, title, width, height).clicked() {
                            actions.push(action.clone());
                        }
                    }
                });
                ui.add_space(gap - ui.spacing().item_spacing.y);
            }
        }),
        None,
    );
    match action {
        Some("home.help") => actions.push(Action::OpenDialog(Dialog::Help)),
        Some("home.settings") => actions.push(Action::Push(Screen::Settings)),
        _ => {}
    }
}

// ----------------------------------------------------------------------------------------
// Ajustes

fn settings(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    page(
        ui,
        cx,
        actions,
        tr("settings"),
        true,
        &[],
        Box::new(|ui, cx, actions| {
            let row = |ui: &mut Ui,
                       cx: &mut Cx,
                       actions: &mut Vec<Action>,
                       tid: &'static str,
                       glyph: &str,
                       label: &str,
                       trailing: Trailing,
                       action: Action| {
                if list_row(ui, cx, tid, Some(glyph), label, None, trailing).clicked() {
                    actions.push(action);
                }
            };
            section_title(ui, cx, tr("my_settings"));
            group(ui, cx, |ui, cx| {
                row(
                    ui,
                    cx,
                    actions,
                    "settings.language",
                    icons::TRANSLATE,
                    tr("language"),
                    Trailing::Value(view.language.abbreviation()),
                    Action::Push(Screen::Language),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.sign_configuration",
                    icons::PEN_NIB,
                    tr("sign_configuration"),
                    Trailing::Chevron,
                    Action::Push(Screen::SignConfiguration(SignConfigDraft::from_prefs(view.prefs))),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.trusted_domains",
                    icons::SHIELD_CHECK,
                    tr("trusted_domains"),
                    Trailing::Chevron,
                    Action::Push(trusted_domains_screen(view.prefs)),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.history",
                    icons::CLOCK_COUNTER_CLOCKWISE,
                    tr("sign_record"),
                    Trailing::Chevron,
                    Action::OpenHistory,
                );
            });
            section_title(ui, cx, tr("help"));
            group(ui, cx, |ui, cx| {
                row(
                    ui,
                    cx,
                    actions,
                    "settings.faq",
                    icons::QUESTION,
                    tr("faq"),
                    Trailing::Chevron,
                    Action::Push(Screen::Faq { open: [false; 3] }),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.help_nfc",
                    icons::CONTACTLESS_PAYMENT,
                    tr("activate_use_dnie_with_nfc_1"),
                    Trailing::Chevron,
                    Action::Push(Screen::HelpDnieNfc),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.help_visible_sign",
                    icons::SIGNATURE,
                    tr("how_to_do_visible_sign"),
                    Trailing::Chevron,
                    Action::Push(Screen::HelpVisibleSign),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.help_trusted_domains",
                    icons::GLOBE,
                    tr("how_to_configure_trusted_domains"),
                    Trailing::Chevron,
                    Action::Push(Screen::HelpTrustedDomains),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.help_certs",
                    icons::TRAY,
                    tr("how_to_install_certs"),
                    Trailing::Chevron,
                    Action::Push(Screen::HelpImportCerts),
                );
            });
            section_title(ui, cx, tr("general_info"));
            group(ui, cx, |ui, cx| {
                row(
                    ui,
                    cx,
                    actions,
                    "settings.accessibility",
                    icons::PERSON_ARMS_SPREAD,
                    tr("accessibility_statement"),
                    Trailing::Chevron,
                    Action::Push(Screen::AccessibilityStatement),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.legal",
                    icons::SCALES,
                    tr("legal_announcement"),
                    Trailing::Chevron,
                    Action::Push(Screen::LegalNotice),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.privacy",
                    icons::LOCK,
                    tr("privacy_policy"),
                    Trailing::Chevron,
                    Action::Push(Screen::PrivacyPolicy),
                );
                row(
                    ui,
                    cx,
                    actions,
                    "settings.version",
                    icons::TAG,
                    &trf("appversion", &[&crate::VERSION]),
                    Trailing::Chevron,
                    Action::Push(Screen::Version),
                );
            });
        }),
        None,
    );
}

/// Filas de idioma: el del sistema y los seis. Devuelve el elegido.
fn language_rows(ui: &mut Ui, cx: &mut Cx, view: &View) -> Option<Option<Language>> {
    let mut chosen = None;
    let current = view.prefs.locale_config;
    group(ui, cx, |ui, cx| {
        let system = Language::from_system_tag(&view.device.locale);
        if list_row(
            ui,
            cx,
            "language.system",
            None,
            tr("system_language"),
            Some(tr(system.name_key())),
            Trailing::Check(current.is_none()),
        )
        .clicked()
        {
            chosen = Some(None);
        }
        for language in Language::ALL {
            let tid = match language {
                Language::Es => "language.es",
                Language::En => "language.en",
                Language::Ca => "language.ca",
                Language::Gl => "language.gl",
                Language::Eu => "language.eu",
                Language::CaValencia => "language.va",
            };
            if list_row(
                ui,
                cx,
                tid,
                None,
                tr(language.name_key()),
                None,
                Trailing::Check(current == Some(language)),
            )
            .clicked()
            {
                chosen = Some(Some(language));
            }
        }
    });
    chosen
}

fn language(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    page(
        ui,
        cx,
        actions,
        tr("language"),
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(8.0);
            if let Some(choice) = language_rows(ui, cx, view) {
                actions.push(Action::SetLanguage(choice));
            }
        }),
        None,
    );
}

fn sign_configuration(ui: &mut Ui, cx: &mut Cx, view: &View, draft: &mut SignConfigDraft, actions: &mut Vec<Action>) {
    let saved = *draft;
    page(
        ui,
        cx,
        actions,
        tr("sign_configuration"),
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(8.0);
            group(ui, cx, |ui, cx| {
                let has_nfc = view.device.has_nfc;
                let note = (!has_nfc).then(|| tr("nfc_not_available"));
                switch_row(
                    ui,
                    cx,
                    "signconf.nfc",
                    tr("allow_dni3_0_NFC"),
                    note,
                    &mut draft.use_nfc,
                    has_nfc,
                );
                switch_row(
                    ui,
                    cx,
                    "signconf.visible",
                    tr("do_visible_sign"),
                    None,
                    &mut draft.visible_signature,
                    true,
                );
                switch_row(
                    ui,
                    cx,
                    "signconf.obfuscate",
                    tr("hide_user_id"),
                    None,
                    &mut draft.obfuscate_cert_info,
                    true,
                );
            });
            ui.add_space(14.0);
            group(ui, cx, |ui, cx| {
                let value = trf("minutes_short", &[&draft.cache_minutes.minutes()]);
                if list_row(
                    ui,
                    cx,
                    "signconf.cache",
                    Some(icons::HOURGLASS_MEDIUM),
                    tr("delete_cache_minutes"),
                    None,
                    Trailing::Value(&value),
                )
                .clicked()
                {
                    actions.push(Action::OpenDialog(Dialog::CacheMinutes {
                        selected: draft.cache_minutes,
                    }));
                }
            });
        }),
        Some(Box::new(move |ui, cx, actions| {
            if button(
                ui,
                cx,
                "signconf.save",
                ButtonKind::Primary,
                None,
                tr("save_changes"),
                true,
            )
            .clicked()
            {
                actions.push(Action::SaveSignConfig(saved));
            }
        })),
    );
}

fn trusted_domains(ui: &mut Ui, cx: &mut Cx, view: &View, text: &mut String, actions: &mut Vec<Action>) {
    let mut validate = view.prefs.validate_ssl_checks;
    let snapshot = text.clone();
    page(
        ui,
        cx,
        actions,
        tr("trusted_domains"),
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(8.0);
            group(ui, cx, |ui, cx| {
                if switch_row(
                    ui,
                    cx,
                    "domains.validate_ssl",
                    tr("validate_SSL_connections"),
                    None,
                    &mut validate,
                    true,
                )
                .changed()
                {
                    actions.push(Action::SetValidateSsl(validate));
                }
            });
            ui.add_space(16.0);
            muted(ui, cx, tr("trusted_domains_desc"));
            ui.add_space(8.0);
            ui.label(
                RichText::new(tr("trusted_domains"))
                    .font(cx.bold(size::SMALL))
                    .color(cx.p.text),
            );
            text_field(
                ui,
                cx,
                "domains.field",
                text,
                FieldSpec::new(InputKind::MultiLine),
                tr("enter_trusted_domains"),
                5,
            );
            small(ui, cx, tr("use_asterisk"));
        }),
        Some(Box::new(move |ui, cx, actions| {
            if button(
                ui,
                cx,
                "domains.save",
                ButtonKind::Primary,
                None,
                tr("save_changes"),
                true,
            )
            .clicked()
            {
                actions.push(Action::SaveTrustedDomains(snapshot));
            }
        })),
    );
}

fn record_icon(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Local => icons::FILE_TEXT,
        RecordKind::Web | RecordKind::Batch => icons::GLOBE,
        RecordKind::App | RecordKind::BatchApp => icons::DEVICE_MOBILE,
    }
}

fn signs_record(ui: &mut Ui, cx: &mut Cx, records: &[SignRecord], actions: &mut Vec<Action>) {
    let empty = records.is_empty();
    let action = page(
        ui,
        cx,
        actions,
        tr("sign_record"),
        true,
        &[("history.delete", icons::TRASH, tr("menu_delete"))],
        Box::new(|ui, cx, _| {
            if empty {
                empty_state(ui, cx, icons::CLOCK_COUNTER_CLOCKWISE, tr("no_records"), None);
                return;
            }
            ui.add_space(8.0);
            group(ui, cx, |ui, cx| {
                for record in records {
                    widgets::info_row(ui, cx, record_icon(record.kind), &record.describe(), &record.date);
                }
            });
        }),
        None,
    );
    if action == Some("history.delete") {
        actions.push(Action::OpenDialog(if empty {
            Dialog::Message {
                tone: Tone::Danger,
                glyph: icons::TRASH,
                title: tr("no_records").into(),
                body: tr("no_records_desc").into(),
                button: k!("ok"),
            }
        } else {
            Dialog::ConfirmClearHistory
        }));
    }
}

fn empty_state(ui: &mut Ui, cx: &mut Cx, glyph: &str, title: &str, body: Option<&str>) {
    ui.add_space(48.0);
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        icon_badge(ui, cx, glyph, 96.0, cx.p.primary, cx.p.primary_soft);
        ui.add_space(16.0);
        centered_text(ui, title, cx.bold(size::TITLE), cx.p.text);
        if let Some(body) = body {
            ui.add_space(8.0);
            centered_text(ui, body, cx.font(size::BODY), cx.p.text_muted);
        }
    });
}

// ----------------------------------------------------------------------------------------
// Ayuda e información

fn faq(ui: &mut Ui, cx: &mut Cx, open: &mut [bool; 3], actions: &mut Vec<Action>) {
    page(
        ui,
        cx,
        actions,
        tr("faq"),
        true,
        &[],
        Box::new(|ui, cx, _| {
            ui.add_space(8.0);
            let items = [
                ("faq.1", k!("question_1"), k!("response_1")),
                ("faq.2", k!("question_2"), k!("response_2")),
                ("faq.3", k!("question_3"), k!("response_3")),
            ];
            for (i, (tid, question, answer)) in items.into_iter().enumerate() {
                widgets::expandable(ui, cx, tid, tr(question), &mut open[i], |ui, cx| {
                    markup::show(ui, cx, tr(answer));
                });
                ui.add_space(4.0);
            }
        }),
        None,
    );
}

#[allow(clippy::too_many_arguments)] // textos antes y después del botón, como el original
fn help_page(
    ui: &mut Ui,
    cx: &mut Cx,
    actions: &mut Vec<Action>,
    title: &str,
    glyph: &str,
    before: &[&'static str],
    go: Option<(&'static str, &'static str, Screen)>,
    after: &[&'static str],
) {
    page(
        ui,
        cx,
        actions,
        title,
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(12.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, glyph, 88.0, cx.p.primary, cx.p.primary_soft);
            });
            ui.add_space(12.0);
            for key in before {
                markup::show(ui, cx, tr(key));
                ui.add_space(6.0);
            }
            if let Some((tid, label, screen)) = go {
                ui.add_space(4.0);
                if button(
                    ui,
                    cx,
                    tid,
                    ButtonKind::Secondary,
                    Some(icons::GEAR_SIX),
                    tr(label),
                    true,
                )
                .clicked()
                {
                    actions.push(Action::Push(screen));
                }
                ui.add_space(10.0);
            }
            for key in after {
                markup::show(ui, cx, tr(key));
                ui.add_space(6.0);
            }
        }),
        None,
    );
}

fn text_page(
    ui: &mut Ui,
    cx: &mut Cx,
    actions: &mut Vec<Action>,
    title: &str,
    body_key: &'static str,
    link_to: Option<(&'static str, &'static str)>,
) {
    page(
        ui,
        cx,
        actions,
        title,
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(8.0);
            card(ui, cx, |ui, cx| {
                markup::show(ui, cx, tr(body_key));
                if let Some((tid, url)) = link_to
                    && link(ui, cx, tid, url).clicked()
                {
                    actions.push(Action::OpenUrl(url.to_string()));
                }
            });
        }),
        None,
    );
}

fn version(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    page(
        ui,
        cx,
        actions,
        &trf("appversion", &[&crate::VERSION]),
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(16.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                logo(ui, view, 88.0);
                ui.add_space(8.0);
                ui.label(
                    RichText::new(crate::APP_NAME)
                        .font(cx.bold(size::DISPLAY))
                        .color(cx.p.text),
                );
                ui.label(
                    RichText::new(format!("v{} · Android", crate::VERSION))
                        .font(cx.font(size::SMALL))
                        .color(cx.p.text_muted),
                );
            });
            ui.add_space(16.0);
            card(ui, cx, |ui, cx| {
                markup::show(ui, cx, tr("about_body"));
                ui.add_space(8.0);
                markup::show(ui, cx, tr("about_license"));
                let eupl = tr("eupl_url");
                if link(ui, cx, "version.license", eupl).clicked() {
                    actions.push(Action::OpenUrl(eupl.to_string()));
                }
                ui.add_space(8.0);
                markup::show(ui, cx, tr("version_desc_p3"));
                if link(ui, cx, "version.source", crate::REPOSITORY).clicked() {
                    actions.push(Action::OpenUrl(crate::REPOSITORY.to_string()));
                }
                ui.add_space(8.0);
                small(ui, cx, tr("third_party_licenses"));
            });
        }),
        None,
    );
}

// ----------------------------------------------------------------------------------------
// Certificados, firma local y web (marcadores de las fases siguientes)

fn import_instructions(ui: &mut Ui, cx: &mut Cx, page_index: &mut usize, actions: &mut Vec<Action>) {
    let current = *page_index;
    let (glyph, title, message) = if current == 0 {
        (icons::FOLDER_OPEN, k!("locate_file_title"), k!("locate_file_message"))
    } else {
        (
            icons::ENVELOPE_SIMPLE,
            k!("send_to_device_title"),
            k!("send_to_device_message"),
        )
    };
    let mut next = false;
    page(
        ui,
        cx,
        actions,
        tr("title_activity_cert_chooser"),
        true,
        &[],
        Box::new(|ui, cx, _| {
            ui.add_space(12.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                illustration(ui, cx, glyph, &[icons::CERTIFICATE, icons::KEY, icons::LOCK]);
                ui.add_space(20.0);
                centered_text(ui, tr(title), cx.bold(size::HEADING), cx.p.text);
                ui.add_space(10.0);
                centered_text(ui, tr(message), cx.font(size::BODY), cx.p.text_muted);
            });
        }),
        Some(Box::new(|ui, cx, actions| {
            let (tid, label) = if current == 0 {
                ("import.continue", k!("drag_on"))
            } else {
                ("import.add", k!("add_cert"))
            };
            if button(ui, cx, tid, ButtonKind::Primary, None, tr(label), true).clicked() {
                if current == 0 {
                    next = true;
                } else {
                    actions.push(Action::ImportCertificate);
                }
            }
            widgets::page_dots(ui, cx, current, 2);
        })),
    );
    if next {
        *page_index = 1;
    }
}

fn certificates(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    let busy = view.features.is_busy();
    page(
        ui,
        cx,
        actions,
        tr("certificates"),
        true,
        &[],
        Box::new(|ui, cx, actions| {
            ui.add_space(8.0);
            card(ui, cx, |ui, cx| {
                ui.horizontal_top(|ui| {
                    icon_badge(ui, cx, icons::CERTIFICATE, 52.0, cx.p.primary, cx.p.primary_soft);
                    ui.vertical(|ui| muted(ui, cx, tr("device_certificates_desc")));
                });
                ui.add_space(12.0);
                if button(
                    ui,
                    cx,
                    "certs.view",
                    ButtonKind::Primary,
                    Some(icons::KEY),
                    tr("view_certificate"),
                    !busy,
                )
                .clicked()
                {
                    actions.push(Action::ChooseCertificate);
                }
                if button(
                    ui,
                    cx,
                    "certs.add",
                    ButtonKind::Secondary,
                    Some(icons::PLUS),
                    tr("add_new_cert"),
                    true,
                )
                .clicked()
                {
                    actions.push(Action::Push(Screen::ImportInstructions { page: 0 }));
                }
            });
            if let Some(certificate) = &view.features.certificate {
                ui.add_space(14.0);
                card(ui, cx, |ui, cx| match certificate {
                    CertificateState::Loading { alias } => {
                        ui.label(RichText::new(alias).font(cx.bold(size::BODY)).color(cx.p.text));
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().color(cx.p.primary));
                            muted(ui, cx, tr("loading_cert"));
                        });
                    }
                    CertificateState::Ready(c) => {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(icons::SEAL_CHECK).font(cx.icon(24.0)).color(cx.p.success));
                            ui.label(RichText::new(&c.alias).font(cx.bold(size::BODY)).color(cx.p.text));
                        });
                        muted(
                            ui,
                            cx,
                            &trf(
                                "dialog_alias_cert_text",
                                &[&c.subject, &c.not_before, &c.not_after, &c.issuer],
                            ),
                        );
                        small(ui, cx, &trf("cert_chain_len", &[&c.chain_len]));
                        for warning in &c.warnings {
                            let (title, body) = warning_texts(*warning);
                            let tone = match warning {
                                CertificateWarning::Pseudonym => Tone::Info,
                                _ => Tone::Warning,
                            };
                            ui.add_space(6.0);
                            notice(ui, cx, tone, icons::WARNING, &format!("{}. {}", tr(title), tr(body)));
                        }
                    }
                    CertificateState::Failed { alias, message } => {
                        ui.label(RichText::new(alias).font(cx.bold(size::BODY)).color(cx.p.text));
                        notice(
                            ui,
                            cx,
                            Tone::Danger,
                            icons::WARNING_CIRCLE,
                            &format!("{}: {message}", tr("error_loading_cert")),
                        );
                    }
                });
            }
        }),
        None,
    );
}

fn coming_soon(ui: &mut Ui, cx: &Cx) {
    notice(
        ui,
        cx,
        Tone::Brand,
        icons::HOURGLASS_MEDIUM,
        &format!("{}. {}", tr("not_available_title"), tr("not_available_desc")),
    );
}

fn web_signing(ui: &mut Ui, cx: &mut Cx, actions: &mut Vec<Action>) {
    page(
        ui,
        cx,
        actions,
        tr("web_signing"),
        true,
        &[],
        Box::new(|ui, cx, _| {
            ui.add_space(12.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, icons::GLOBE, 88.0, cx.p.primary, cx.p.primary_soft);
            });
            ui.add_space(12.0);
            heading(ui, cx, tr("question_1"));
            ui.add_space(4.0);
            markup::show(ui, cx, tr("response_1"));
            ui.add_space(12.0);
            coming_soon(ui, cx);
        }),
        None,
    );
}

/// Vista previa de la firma visible (`PdfSelectPreviewActivity`, §3.5): una página que
/// ocupa el espacio disponible, el área se dibuja arrastrando el dedo (sin zoom ni
/// desplazamiento, como el original), botones de página y «Continuar».
fn visible_signature(
    ui: &mut Ui,
    cx: &mut Cx,
    view: &View,
    selection: &mut Option<[f32; 4]>,
    drag: &mut Option<[f32; 2]>,
    actions: &mut Vec<Action>,
) {
    let full = ui.max_rect();
    let bar = Rect::from_min_size(full.min, vec2(full.width(), TOP_BAR));
    if top_bar(ui, cx, bar, tr("visible_sign"), true, &[]).back {
        actions.push(Action::Back);
    }
    let preview = view.flows.preview();
    let document = preview.and_then(|p| p.document.as_ref());
    let page_index = preview.map_or(0, |p| p.page);
    let pages = document.map_or(0, |d| d.page_count());
    let width = full.width().min(MAX_WIDTH) - 32.0;
    let column = Rect::from_min_max(
        pos2(full.center().x - width / 2.0, bar.bottom()),
        pos2(full.center().x + width / 2.0, full.bottom() - 12.0),
    );
    // Abajo, de abajo arriba: «Continuar» y la barra de páginas.
    let mut go_to = None;
    let mut continue_clicked = false;
    let used = ui
        .scope_builder(
            UiBuilder::new()
                .max_rect(column)
                .layout(Layout::bottom_up(Align::Center)),
            |ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                continue_clicked = button(
                    ui,
                    cx,
                    "preview.continue",
                    ButtonKind::Primary,
                    None,
                    tr("drag_on"),
                    document.is_some(),
                )
                .clicked();
                let (row, _) = ui.allocate_exact_size(vec2(ui.available_width(), 52.0), egui::Sense::hover());
                let loading = preview.is_none_or(|p| p.loading());
                let pager: [(&'static str, &str, &'static str, usize, bool); 4] = [
                    ("preview.first", icons::CARET_DOUBLE_LEFT, k!("first_page"), 0, true),
                    (
                        "preview.prev",
                        icons::CARET_LEFT,
                        k!("previous_page"),
                        page_index.saturating_sub(1),
                        !loading,
                    ),
                    (
                        "preview.next",
                        icons::CARET_RIGHT,
                        k!("next_page"),
                        (page_index + 1).min(pages.saturating_sub(1)),
                        !loading,
                    ),
                    (
                        "preview.last",
                        icons::CARET_DOUBLE_RIGHT,
                        k!("last_page"),
                        pages.saturating_sub(1),
                        true,
                    ),
                ];
                for (i, (tid, glyph, label, target, enabled)) in pager.into_iter().enumerate() {
                    let x = match i {
                        0 => row.left() + 24.0,
                        1 => row.left() + 76.0,
                        2 => row.right() - 76.0,
                        _ => row.right() - 24.0,
                    };
                    let r = Rect::from_center_size(pos2(x, row.center().y), vec2(48.0, 48.0));
                    if widgets::icon_button(ui, cx, tid, r, glyph, tr(label)).clicked() && enabled && document.is_some()
                    {
                        go_to = Some(target);
                    }
                }
                if pages > 0 {
                    let text = trf("page_number", &[&(page_index + 1), &pages]);
                    ui.painter().text(
                        row.center(),
                        egui::Align2::CENTER_CENTER,
                        &text,
                        cx.font(size::BODY),
                        cx.p.text,
                    );
                    let label = ui.interact(
                        row.shrink2(vec2(110.0, 0.0)),
                        egui::Id::unique("pagina"),
                        egui::Sense::hover(),
                    );
                    label.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, &text));
                }
            },
        )
        .response
        .rect;
    // Arriba: «Seleccione el área de firma».
    let galley = ui.painter().layout(
        tr("select_sign_area").to_string(),
        cx.font(size::BODY),
        cx.p.text_muted,
        column.width(),
    );
    let text_pos = pos2(column.center().x - galley.size().x / 2.0, column.top() + 4.0);
    let text_bottom = text_pos.y + galley.size().y;
    ui.painter().galley(text_pos, galley, cx.p.text_muted);
    let canvas = Rect::from_min_max(
        pos2(column.left(), text_bottom + 10.0),
        pos2(column.right(), used.top() - 8.0),
    );
    if canvas.height() < 40.0 {
        return;
    }
    let Some(document) = document else {
        ui.scope_builder(UiBuilder::new().max_rect(canvas), |ui| {
            ui.centered_and_justified(|ui| ui.add(egui::Spinner::new().size(36.0).color(cx.p.primary)));
        });
        return;
    };
    // La página entera dentro del lienzo (`FitPolicy.BOTH`).
    let (pw, ph) = document.page_size(page_index);
    let scale = (canvas.width() / pw).min(canvas.height() / ph);
    let page_rect = Rect::from_center_size(canvas.center(), vec2(pw * scale, ph * scale));
    let painter = ui.painter_at(canvas);
    painter.rect_filled(page_rect.translate(vec2(0.0, 2.0)), 0.0, Color32::from_black_alpha(40));
    let ppp = ui.ctx().pixels_per_point();
    let wanted = (page_rect.width() * ppp).round() as u32;
    match preview
        .and_then(|p| p.texture.as_ref())
        .filter(|(p, _, _)| *p == page_index)
    {
        Some((_, rendered, texture)) => {
            painter.image(
                texture.id(),
                page_rect,
                Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                Color32::WHITE,
            );
            painter.rect_stroke(
                page_rect,
                egui::CornerRadius::ZERO,
                egui::Stroke::new(1.0, cx.p.border),
                egui::StrokeKind::Outside,
            );
            // Se vuelve a dibujar si ha cambiado mucho el tamaño (giro de la pantalla).
            if (*rendered as f32 - wanted as f32).abs() > wanted as f32 * 0.15 {
                actions.push(Action::Flow(FlowAction::PreviewRender {
                    page: page_index,
                    width: wanted,
                }));
            }
        }
        None => {
            painter.rect_filled(page_rect, 0.0, Color32::WHITE);
            painter.text(
                page_rect.center(),
                egui::Align2::CENTER_CENTER,
                icons::FILE_TEXT,
                cx.icon(40.0),
                cx.p.text_faint,
            );
            actions.push(Action::Flow(FlowAction::PreviewRender {
                page: page_index,
                width: wanted,
            }));
        }
    }
    // Área: se dibuja arrastrando; en fracciones de la página para que sobreviva a un giro.
    let response = ui.interact(page_rect, egui::Id::unique("area-de-firma"), egui::Sense::drag());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Image, true, tr("select_sign_area")));
    cx.targets.add("preview.page", page_rect, ui.clip_rect());
    let to_fraction = |pos: egui::Pos2| {
        [
            ((pos.x - page_rect.left()) / page_rect.width()).clamp(0.0, 1.0),
            ((pos.y - page_rect.top()) / page_rect.height()).clamp(0.0, 1.0),
        ]
    };
    if response.drag_started()
        && let Some(pos) = response.interact_pointer_pos()
    {
        *drag = Some(to_fraction(pos));
    }
    if let (Some(start), Some(pos)) = (*drag, response.interact_pointer_pos())
        && (response.dragged() || response.drag_stopped())
    {
        let end = to_fraction(pos);
        *selection = Some([
            start[0].min(end[0]),
            start[1].min(end[1]),
            start[0].max(end[0]),
            start[1].max(end[1]),
        ]);
    }
    if response.drag_stopped() {
        *drag = None;
    }
    if let Some([x0, y0, x1, y1]) = *selection {
        let r = Rect::from_min_max(
            page_rect.min + vec2(x0 * page_rect.width(), y0 * page_rect.height()),
            page_rect.min + vec2(x1 * page_rect.width(), y1 * page_rect.height()),
        );
        // Relleno y borde negros al 50 % (#80000000), como el original.
        painter.rect(
            r,
            egui::CornerRadius::ZERO,
            Color32::from_black_alpha(64),
            egui::Stroke::new(2.5, Color32::from_black_alpha(128)),
            egui::StrokeKind::Inside,
        );
    }
    if continue_clicked {
        let view_size = (page_rect.width(), page_rect.height());
        let selection = selection.map(|[x0, y0, x1, y1]| ViewSelection {
            start_x: x0 * view_size.0,
            start_y: y0 * view_size.1,
            end_x: x1 * view_size.0,
            end_y: y1 * view_size.1,
        });
        actions.push(Action::Flow(FlowAction::PreviewContinue {
            selection,
            view: view_size,
        }));
    }
    if let Some(target) = go_to
        && target != page_index
    {
        // Cambiar de página borra la selección.
        *selection = None;
        *drag = None;
        actions.push(Action::Flow(FlowAction::PreviewPage(target)));
    }
}

fn web_request(ui: &mut Ui, cx: &mut Cx, view: &View, actions: &mut Vec<Action>) {
    let request = view.features.web_request.as_ref();
    let operation = request.and_then(|r| r.operation);
    let title = match operation {
        Some("sign") => tr("title_activity_sign_data"),
        Some("batch") => tr("title_activity_sign_batch"),
        Some("selectcert") => tr("title_activity_select_certificate"),
        Some("save") => tr("title_activity_save_data"),
        _ => tr("web_signing"),
    };
    page(
        ui,
        cx,
        actions,
        title,
        true,
        &[],
        Box::new(|ui, cx, _| {
            ui.add_space(12.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, icons::GLOBE, 88.0, cx.p.primary, cx.p.primary_soft);
            });
            ui.add_space(12.0);
            match (request, operation) {
                (Some(r), Some(op)) if r.supported => {
                    muted(ui, cx, &trf("web_request_received", &[&op]));
                    ui.add_space(8.0);
                    coming_soon(ui, cx);
                }
                _ => notice(ui, cx, Tone::Warning, icons::WARNING, tr("web_request_unsupported")),
            }
        }),
        None,
    );
}

// ----------------------------------------------------------------------------------------
// Diálogos

/// Cabecera de diálogo: título y botón X (que ejecuta `close`).
fn dialog_title(ui: &mut Ui, cx: &mut Cx, title: &str, close_action: Action, actions: &mut Vec<Action>) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(vec2(width, 52.0), egui::Sense::hover());
    let close = Rect::from_center_size(pos2(rect.right() - 20.0, rect.center().y), vec2(48.0, 48.0));
    if widgets::icon_button(ui, cx, "dialog.close", close, icons::X, tr("close")).clicked() {
        actions.push(close_action);
    }
    let text_rect = Rect::from_min_max(rect.min, pos2(close.left() - 8.0, rect.max.y));
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(text_rect)
            .layout(Layout::left_to_right(Align::Center)),
        |ui| {
            ui.add(egui::Label::new(RichText::new(title).font(cx.bold(size::TITLE)).color(cx.p.text)).wrap());
        },
    );
}

/// Dibuja el diálogo abierto.
pub fn draw_dialog(ctx: &egui::Context, cx: &mut Cx, dialog: &mut Dialog, view: &View, actions: &mut Vec<Action>) {
    let id = dialog.id();
    let dismissable = dialog.dismissable();
    let outside = sheet(ctx, cx, id, dismissable, |ui, cx| match dialog {
        Dialog::Help => {
            dialog_title(ui, cx, tr("what_is_autofirma_for_title"), Action::CloseDialog, actions);
            muted(ui, cx, tr("what_is_autofirma_for_desc"));
            ui.add_space(10.0);
            ui.label(
                RichText::new(tr("how_install_certs"))
                    .font(cx.bold(size::BODY))
                    .color(cx.p.text),
            );
            for (glyph, key) in [
                (icons::DOWNLOAD_SIMPLE, k!("load_cert")),
                (icons::FILE_TEXT, k!("allowed_extensions")),
            ] {
                ui.horizontal_top(|ui| {
                    icon_badge(ui, cx, glyph, 36.0, cx.p.primary, cx.p.primary_soft);
                    ui.vertical(|ui| muted(ui, cx, tr(key)));
                });
            }
            ui.add_space(12.0);
            if button(ui, cx, "dialog.ok", ButtonKind::Primary, None, tr("understood"), true).clicked() {
                actions.push(Action::CloseDialog);
            }
        }
        Dialog::ConfigNfc => {
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(
                    ui,
                    cx,
                    icons::CONTACTLESS_PAYMENT,
                    64.0,
                    cx.p.primary,
                    cx.p.primary_soft,
                );
            });
            ui.add_space(12.0);
            centered_text(ui, tr("enable_nfc_question"), cx.font(size::BODY + 1.0), cx.p.text);
            ui.add_space(16.0);
            if button(ui, cx, "dialog.yes", ButtonKind::Primary, None, tr("yes"), true).clicked() {
                actions.push(Action::AnswerNfc(true));
            }
            if button(ui, cx, "dialog.no", ButtonKind::Secondary, None, tr("no"), true).clicked() {
                actions.push(Action::AnswerNfc(false));
            }
        }
        Dialog::Message {
            tone,
            glyph,
            title,
            body,
            button: label,
        } => {
            let (fg, bg) = tone.colors(&cx.p);
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, glyph, 64.0, fg, bg);
            });
            ui.add_space(12.0);
            centered_text(ui, title, cx.bold(size::TITLE), cx.p.text);
            ui.add_space(6.0);
            centered_text(ui, body, cx.font(size::BODY), cx.p.text_muted);
            ui.add_space(18.0);
            if button(ui, cx, "dialog.ok", ButtonKind::Primary, None, tr(label), true).clicked() {
                actions.push(Action::CloseDialog);
            }
        }
        Dialog::CacheMinutes { selected } => {
            dialog_title(ui, cx, tr("select_minutes_value"), Action::CloseDialog, actions);
            group(ui, cx, |ui, cx| {
                for minutes in CacheMinutes::ALL {
                    let tid = match minutes {
                        CacheMinutes::Five => "minutes.5",
                        CacheMinutes::Fifteen => "minutes.15",
                        CacheMinutes::Thirty => "minutes.30",
                        CacheMinutes::Sixty => "minutes.60",
                        CacheMinutes::OneHundredTwenty => "minutes.120",
                    };
                    let badge = (minutes == CacheMinutes::default()).then(|| tr("by_default"));
                    let label = trf("minutes_short", &[&minutes.minutes()]);
                    if widgets::radio_row(ui, cx, tid, &label, badge, *selected == minutes).clicked() {
                        *selected = minutes;
                    }
                }
            });
            ui.add_space(14.0);
            if button(ui, cx, "dialog.select", ButtonKind::Primary, None, tr("select"), true).clicked() {
                actions.push(Action::SetCacheMinutes(*selected));
            }
        }
        Dialog::ConfirmClearHistory => {
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, icons::TRASH, 64.0, cx.p.danger, cx.p.danger_soft);
            });
            ui.add_space(12.0);
            centered_text(ui, tr("eliminate_history"), cx.bold(size::TITLE), cx.p.text);
            ui.add_space(6.0);
            centered_text(ui, tr("eliminate_history_desc"), cx.font(size::BODY), cx.p.text_muted);
            ui.add_space(18.0);
            if button(
                ui,
                cx,
                "dialog.delete",
                ButtonKind::Danger,
                None,
                tr("eliminate_history"),
                true,
            )
            .clicked()
            {
                actions.push(Action::ClearHistory);
            }
            if button(ui, cx, "dialog.cancel", ButtonKind::Text, None, tr("cancel"), true).clicked() {
                actions.push(Action::CloseDialog);
            }
        }
        Dialog::LanguagePicker => {
            dialog_title(ui, cx, tr("language"), Action::CloseDialog, actions);
            if let Some(choice) = language_rows(ui, cx, view) {
                actions.push(Action::SetLanguage(choice));
                actions.push(Action::CloseDialog);
            }
        }
        Dialog::Prompt(prompt) => {
            let (fg, bg) = prompt.tone.colors(&cx.p);
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, prompt.glyph, 64.0, fg, bg);
            });
            ui.add_space(12.0);
            centered_text(ui, &prompt.title, cx.bold(size::TITLE), cx.p.text);
            ui.add_space(6.0);
            centered_text(ui, &prompt.body, cx.font(size::BODY), cx.p.text_muted);
            ui.add_space(18.0);
            let (label, action) = &prompt.primary;
            if button(ui, cx, "dialog.ok", ButtonKind::Primary, None, tr(label), true).clicked() {
                actions.push(action.clone());
            }
            if let Some((label, action)) = &prompt.secondary
                && button(ui, cx, "dialog.cancel", ButtonKind::Text, None, tr(label), true).clicked()
            {
                actions.push(action.clone());
            }
        }
        Dialog::Progress { text } => {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(32.0).color(cx.p.primary));
                ui.add_space(12.0);
                ui.label(RichText::new(tr(text)).font(cx.font(size::BODY + 1.0)).color(cx.p.text));
            });
            ui.add_space(16.0);
        }
        Dialog::ChooseCertType { auth } => {
            let title = if *auth {
                tr("choose_cert_type_auth_title")
            } else {
                tr("choose_cert_type_sign_title")
            };
            dialog_title(ui, cx, title, Action::Flow(FlowAction::Cancel), actions);
            ui.add_space(4.0);
            group(ui, cx, |ui, cx| {
                for (tid, glyph, label, kind) in [
                    (
                        "cert_type.certificate",
                        icons::CERTIFICATE,
                        k!("certificate"),
                        CertType::Certificate,
                    ),
                    ("cert_type.dnie", icons::IDENTIFICATION_CARD, k!("dnie"), CertType::Dnie),
                ] {
                    if list_row(ui, cx, tid, Some(glyph), tr(label), None, Trailing::Chevron).clicked() {
                        actions.push(Action::Flow(FlowAction::CertType(kind)));
                    }
                }
            });
            ui.add_space(8.0);
        }
        Dialog::PdfPassword {
            password,
            revealed,
            error,
        } => {
            ui.add_space(8.0);
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                icon_badge(ui, cx, icons::INFO, 64.0, cx.p.info, cx.p.info_soft);
            });
            ui.add_space(12.0);
            centered_text(ui, tr("encrypted_document"), cx.bold(size::TITLE), cx.p.text);
            ui.add_space(6.0);
            centered_text(ui, tr("encrypted_document_desc"), cx.font(size::BODY), cx.p.text_muted);
            ui.add_space(12.0);
            if let Some(error) = error {
                ui.label(RichText::new(tr(error)).font(cx.bold(size::SMALL)).color(cx.p.danger));
            }
            let width = ui.available_width();
            let mut submitted = false;
            ui.allocate_ui_with_layout(vec2(width, 60.0), Layout::left_to_right(Align::Center), |ui| {
                ui.allocate_ui(vec2(width - 56.0, 60.0), |ui| {
                    let spec = FieldSpec::new(InputKind::Password).revealed(*revealed);
                    submitted = text_field(ui, cx, "dialog.password", password, spec, tr("password"), 1).submitted;
                });
                let (eye, _) = ui.allocate_exact_size(vec2(48.0, 48.0), egui::Sense::hover());
                let (glyph, label) = if *revealed {
                    (icons::EYE_SLASH, tr("hide_password"))
                } else {
                    (icons::EYE, tr("show_password"))
                };
                if widgets::icon_button(ui, cx, "dialog.reveal", eye, glyph, label).clicked() {
                    *revealed = !*revealed;
                }
            });
            ui.add_space(14.0);
            if button(ui, cx, "dialog.ok", ButtonKind::Primary, None, tr("ok"), true).clicked() || submitted {
                actions.push(Action::Flow(FlowAction::PdfPassword(password.clone())));
            }
            if button(
                ui,
                cx,
                "dialog.cancel",
                ButtonKind::Text,
                None,
                tr("cancel_underline"),
                true,
            )
            .clicked()
            {
                actions.push(Action::Flow(FlowAction::Cancel));
            }
        }
    });
    if outside {
        actions.push(Action::CloseDialog);
    }
}
