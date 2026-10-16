//! AutoFirma-rs: cliente de firma electrónica.

// En Windows la aplicación es de ventana (sin consola); la línea de comandos
// se engancha a la consola del proceso padre si existe.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod i18n;
mod launch;
mod services;
mod ui;

use launch::{GuiStart, Launch};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match launch::classify(&args) {
        Launch::Gui(start) => run_gui(start),
        Launch::Protocol(url) => {
            let code = run_gui(GuiStart { protocol_url: Some(url), ..Default::default() });
            if code == 0 { ui::protocol_flow::EXIT_CODE.load(std::sync::atomic::Ordering::SeqCst) } else { code }
        }
        Launch::Cli(args) => {
            eprintln!("Línea de comandos aún no conectada: {args:?}");
            1
        }
    };
    std::process::exit(code);
}

fn native_options(renderer: eframe::Renderer, compact: bool) -> eframe::NativeOptions {
    let (size, min) = if compact { ([560.0, 700.0], [460.0, 520.0]) } else { ([1100.0, 740.0], [760.0, 560.0]) };
    let mut viewport = eframe::egui::ViewportBuilder::default();
    if compact {
        // Como los diálogos de AutoFirma invocada desde el navegador: delante
        // de la ventana del navegador.
        viewport = viewport.with_always_on_top();
    }
    eframe::NativeOptions {
        renderer,
        viewport: viewport
            .with_title("AutoFirma")
            .with_inner_size(size)
            .with_min_inner_size(min)
            // En modo protocolo la ventana solo aparece si hace falta al usuario.
            .with_visible(!compact)
            .with_app_id("autofirma")
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../../../packaging/icons/autofirma-256.png"))
                    .unwrap_or_default(),
            ),
        // La ventana compacta no recuerda posición ni tamaño y guarda su
        // estado aparte para no heredar el de la ventana principal.
        persist_window: !compact,
        persistence_path: compact.then(|| {
            directories::ProjectDirs::from("io.github", "autofirma-rs", "autofirma")
                .map(|d| d.data_dir().join("ventana-web.ron"))
                .unwrap_or_else(|| std::env::temp_dir().join("autofirma-ventana-web.ron"))
        }),
        ..Default::default()
    }
}

/// Arranca la interfaz. Si el renderizado OpenGL no está disponible (p. ej.
/// escritorios virtuales sin aceleración en Windows), se reintenta con wgpu
/// (DirectX 12/Vulkan/Metal, con su adaptador por software).
fn run_gui(start: GuiStart) -> i32 {
    let mut last_err = None;
    for renderer in [eframe::Renderer::Glow, eframe::Renderer::Wgpu] {
        let start = start.clone();
        let result = eframe::run_native(
            "AutoFirma",
            native_options(renderer, start.protocol_url.is_some()),
            Box::new(move |cc| Ok(Box::new(ui::AutoFirmaApp::new(cc, start)))),
        );
        match result {
            Ok(()) => return 0,
            Err(e) => {
                eprintln!("No se ha podido iniciar la interfaz con {renderer:?}: {e}");
                last_err = Some(e);
            }
        }
    }
    eprintln!("No se ha podido iniciar la interfaz gráfica: {last_err:?}");
    1
}
