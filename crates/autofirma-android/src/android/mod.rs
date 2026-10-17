//! Punto de entrada en Android: `android_on_create` y `android_main` (los llama
//! `android-activity` desde la `GameActivity` de la capa Java).

mod java;
mod logcat;

use std::sync::{Arc, Once};

use android_activity::{AndroidApp, OnCreateState};
use tracing::{error, info};

use crate::bridge::{Bridge, safe_area_points};
use crate::screen::MainScreen;

/// Hilo principal de Java, dentro de `Activity.onCreate` y antes de `android_main`.
#[unsafe(no_mangle)]
fn android_on_create(state: &OnCreateState) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        logcat::init();
        std::panic::set_hook(Box::new(|panic| {
            let backtrace = std::backtrace::Backtrace::force_capture();
            error!("Error interno (pánico): {panic}\n{backtrace}");
        }));
    });
    // Con onCreate en la pila, el cargador de clases de la aplicación está disponible.
    if let Err(e) = java::init_tls_verifier(state) {
        error!("No se pudo iniciar la verificación TLS del sistema: {e}");
    }
}

/// Hilo nativo de la actividad: interfaz egui hasta que la actividad se destruye.
#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    info!(
        "AutoFirma-rs {} para Android iniciado (ABI {}, API {})",
        crate::VERSION,
        std::env::consts::ARCH,
        AndroidApp::sdk_version()
    );
    #[cfg(debug_assertions)]
    tls_self_check();
    let platform = Arc::new(java::JavaPlatform::new(app.clone()));
    let bridge = Bridge::global().clone();
    let options = eframe::NativeOptions {
        android_app: Some(app),
        // OpenGL ES 2/3 con EGL: disponible en todos los dispositivos con API 23 y en el
        // emulador (SwiftShader); wgpu añadiría varios MB sin ventaja para esta interfaz.
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    let result = eframe::run_native(
        crate::APP_NAME,
        options,
        Box::new(move |cc| {
            bridge.set_repaint_context(cc.egui_ctx.clone());
            Ok(Box::new(App {
                screen: MainScreen::new(platform, bridge.clone()),
                bridge,
            }))
        }),
    );
    match result {
        Ok(()) => info!("Actividad terminada"),
        Err(e) => error!("La interfaz terminó con error: {e}"),
    }
    // winit no permite crear otro bucle de eventos en este proceso: si Android vuelve a
    // crear la actividad, tiene que hacerlo en un proceso nuevo.
    std::process::exit(0);
}

/// Comprobación de la verificación TLS del sistema para las pruebas (solo en compilaciones
/// de depuración): si la propiedad `debug.autofirma.tls_check` contiene una URL
/// (`adb shell setprop debug.autofirma.tls_check https://...`), se descarga al arrancar con
/// el cliente HTTP de afirma-core y se registra el resultado.
#[cfg(debug_assertions)]
fn tls_self_check() {
    let Some(url) = android_properties::getprop("debug.autofirma.tls_check")
        .value()
        .filter(|url| !url.is_empty())
    else {
        return;
    };
    std::thread::spawn(move || {
        let client = afirma_core::http::installed_http_client();
        match client.read(&url, afirma_core::http::HttpMethod::Get) {
            Ok(body) => info!("Comprobación TLS correcta: {url} ({} bytes)", body.len()),
            Err(e) => error!("Comprobación TLS fallida: {url}: {e}"),
        }
    });
}

struct App {
    screen: MainScreen,
    bridge: Arc<Bridge>,
}

impl eframe::App for App {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.screen.pump();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.screen.ui(ui);
    }

    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        // winit no da a egui la zona segura en Android: la envía la capa Java
        // (WindowInsets de las barras del sistema, recortes y teclado).
        if let Some(insets) = self.bridge.safe_area_px() {
            let ppp = raw_input
                .viewport()
                .native_pixels_per_point
                .unwrap_or_else(|| ctx.pixels_per_point());
            raw_input.safe_area_insets = Some(safe_area_points(insets, ppp));
        }
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }
}
