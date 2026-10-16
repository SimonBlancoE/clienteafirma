//! Integración específica de cada sistema que no cubre la biblioteca de
//! ventanas.

/// Lo que el sistema pide abrir a la aplicación ya arrancada.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub enum Opened {
    /// URL `afirma://` (invocación desde el navegador).
    Url(String),
    /// Fichero ("Abrir con", arrastrar al icono del Dock).
    File(std::path::PathBuf),
}

#[cfg(target_os = "macos")]
pub mod macos;

/// Instala los receptores de eventos del sistema antes de crear la ventana.
pub fn early_init() {
    #[cfg(target_os = "macos")]
    macos::install_url_handler();
}

/// Instala los receptores que necesitan la aplicación ya creada.
pub fn init(ctx: &eframe::egui::Context) {
    #[cfg(target_os = "macos")]
    macos::install(ctx);
    #[cfg(not(target_os = "macos"))]
    let _ = ctx;
}

/// Peticiones de apertura recibidas desde la última llamada.
pub fn take_opened() -> Vec<Opened> {
    #[cfg(target_os = "macos")]
    return macos::take();
    #[cfg(not(target_os = "macos"))]
    Vec::new()
}

/// En macOS el navegador y el Finder no pasan la URL ni los ficheros por la
/// línea de comandos sino como eventos, que llegan poco después de arrancar.
pub const fn launch_events_by_message() -> bool {
    cfg!(target_os = "macos")
}
