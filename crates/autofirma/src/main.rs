//! AutoFirma-rs: cliente de firma electrónica.

mod i18n;
mod ui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("AutoFirma")
            .with_inner_size([1100.0, 740.0])
            .with_min_inner_size([760.0, 560.0])
            .with_app_id("autofirma")
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../../../packaging/icons/autofirma-256.png"))
                    .unwrap_or_default(),
            ),
        ..Default::default()
    };
    eframe::run_native("AutoFirma", options, Box::new(|cc| Ok(Box::new(ui::AutoFirmaApp::new(cc)))))
}
