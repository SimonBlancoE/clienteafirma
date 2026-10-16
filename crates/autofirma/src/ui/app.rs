//! Ventana principal de AutoFirma-rs.

use eframe::egui::{self, Frame, Margin, RichText, ScrollArea, Stroke, Ui};

use super::cert_picker::{CertPicker, PickerEvent};
use super::pages::certificates::{CertificatesPage, CertsAction};
use super::pages::sign::{SignAction, SignPage, Stage};
use super::pages::tools::{ToolsAction, ToolsPage};
use super::pages::verify::{VerifyAction, VerifyPage};
use super::theme::{self, Palette, ThemeChoice};
use super::{icons, widgets};

/// Páginas principales de la aplicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Sign,
    Verify,
    Certificates,
    Tools,
    Settings,
    Help,
}

impl Page {
    pub fn label(self) -> &'static str {
        match self {
            Page::Sign => "Firmar",
            Page::Verify => "Verificar firmas",
            Page::Certificates => "Mis certificados",
            Page::Tools => "Herramientas",
            Page::Settings => "Preferencias",
            Page::Help => "Ayuda",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Page::Sign => icons::PEN_NIB,
            Page::Verify => icons::SEAL_CHECK,
            Page::Certificates => icons::IDENTIFICATION_CARD,
            Page::Tools => icons::WRENCH,
            Page::Settings => icons::GEAR_SIX,
            Page::Help => icons::QUESTION,
        }
    }
}

pub struct AutoFirmaApp {
    pub(crate) page: Page,
    pub(crate) theme: ThemeChoice,
    palette: Palette,
    applied: Option<Palette>,
    files_hovering: bool,
    pub(crate) sign: SignPage,
    pub(crate) verify: VerifyPage,
    pub(crate) certificates: CertificatesPage,
    pub(crate) tools: ToolsPage,
    pub(crate) picker: CertPicker,
    pub(crate) visible_sig: super::visible_sig::VisibleSigEditor,
}

impl AutoFirmaApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install_fonts(&cc.egui_ctx);
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let mut app = AutoFirmaApp {
            page: Page::Sign,
            theme: ThemeChoice::System,
            palette: Palette::LIGHT,
            applied: None,
            files_hovering: false,
            sign: SignPage::default(),
            verify: VerifyPage::default(),
            certificates: CertificatesPage::default(),
            tools: ToolsPage::default(),
            picker: CertPicker::default(),
            visible_sig: Default::default(),
        };
        if let Ok(demo) = std::env::var("AF_DEMO") {
            super::demo::load(&mut app, &demo);
        }
        app
    }

    fn handle_certs_actions(&mut self, actions: Vec<CertsAction>) {
        for a in actions {
            if let CertsAction::SelectStore(i) = a {
                self.certificates.selected = i;
                self.certificates.expanded = None;
            }
        }
    }

    fn handle_tools_actions(&mut self, actions: Vec<ToolsAction>) {
        for a in actions {
            match a {
                ToolsAction::Open(t) => {
                    self.tools.open = Some(t);
                    self.tools.result = None;
                }
                ToolsAction::Close => self.tools.open = None,
                _ => {}
            }
        }
    }

    fn handle_verify_actions(&mut self, actions: Vec<VerifyAction>) {
        for a in actions {
            if a == VerifyAction::Clear {
                self.verify = VerifyPage::default();
            }
        }
    }

    fn handle_sign_actions(&mut self, actions: Vec<SignAction>) {
        for a in actions {
            match a {
                SignAction::Clear => {
                    self.sign.files.clear();
                    self.sign.stage = Stage::Empty;
                }
                SignAction::Remove(i) => {
                    if i < self.sign.files.len() {
                        self.sign.files.remove(i);
                    }
                    if self.sign.files.is_empty() {
                        self.sign.stage = Stage::Empty;
                    }
                }
                SignAction::StartSigning => {
                    self.picker.accept_label = "Firmar".into();
                    self.picker.open = true;
                }
                _ => {}
            }
        }
    }

    fn sidebar(&mut self, ui: &mut Ui) {
        let p = self.palette;
        egui::Panel::left("nav")
            .exact_size(232.0)
            .resizable(false)
            .frame(Frame::new().fill(p.sidebar).inner_margin(Margin::symmetric(14, 18)).stroke(Stroke::new(1.0, p.border)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    widgets::status_circle(ui, icons::PEN_NIB, 36.0, p.on_primary, p.primary);
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.add_space(1.0);
                        ui.label(RichText::new("AutoFirma").font(egui::FontId::new(17.0, theme::bold())).color(p.text));
                        ui.label(RichText::new("Firma electrónica").size(12.0).color(p.text_faint));
                    });
                });
                ui.add_space(22.0);
                for page in [Page::Sign, Page::Verify, Page::Certificates, Page::Tools] {
                    if widgets::nav_item(ui, &p, page.icon(), page.label(), self.page == page).clicked() {
                        self.page = page;
                    }
                    ui.add_space(2.0);
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.label(RichText::new(format!("Versión {}", env!("CARGO_PKG_VERSION"))).size(11.5).color(p.text_faint));
                    ui.add_space(6.0);
                    for page in [Page::Help, Page::Settings] {
                        if widgets::nav_item(ui, &p, page.icon(), page.label(), self.page == page).clicked() {
                            self.page = page;
                        }
                        ui.add_space(2.0);
                    }
                });
            });
    }

}

impl eframe::App for AutoFirmaApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let system_dark = ctx.system_theme() == Some(egui::Theme::Dark);
        self.palette = self.theme.palette(system_dark);
        if self.applied != Some(self.palette) {
            theme::apply(&ctx, &self.palette, 1.0);
            self.applied = Some(self.palette);
        }
        self.files_hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        self.sidebar(ui);
        let p = self.palette;
        egui::CentralPanel::no_frame().frame(Frame::new().fill(p.bg).inner_margin(Margin::symmetric(36, 28))).show(ui, |ui| {
            ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.set_max_width(ui.available_width().min(900.0));
                match self.page {
                    Page::Sign => {
                        let actions = self.sign.ui(ui, &p, self.files_hovering);
                        self.handle_sign_actions(actions);
                    }
                    Page::Verify => {
                        let actions = self.verify.ui(ui, &p, self.files_hovering);
                        self.handle_verify_actions(actions);
                    }
                    Page::Certificates => {
                        let actions = self.certificates.ui(ui, &p);
                        self.handle_certs_actions(actions);
                    }
                    Page::Tools => {
                        let actions = self.tools.ui(ui, &p);
                        self.handle_tools_actions(actions);
                    }
                    other => widgets::page_header(ui, &p, other.label(), Some("En construcción")),
                }
            });
        });
        let _ = self.visible_sig.show(&ctx, &p);
        match self.picker.show(&ctx, &p) {
            PickerEvent::None => {}
            _ => {}
        }
    }
}
