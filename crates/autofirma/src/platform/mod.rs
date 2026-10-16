//! Integración específica de cada sistema que no cubre la biblioteca de
//! ventanas, y peticiones de apertura que llegan con la aplicación ya
//! arrancada (eventos de macOS y segundas ejecuciones, ver
//! [`crate::services::instance`]).

use std::sync::{Mutex, OnceLock};

use eframe::egui;

/// Lo que se pide abrir a la aplicación ya arrancada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    /// URL `afirma://` (invocación desde el navegador; solo llega así en macOS).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Url(String),
    /// Fichero ("Abrir con", arrastrar al icono del Dock, segunda ejecución).
    File(std::path::PathBuf),
    /// Traer la ventana al frente (segunda ejecución sin ficheros).
    Focus,
}

#[cfg(target_os = "macos")]
pub mod macos;

static QUEUE: Mutex<Vec<Opened>> = Mutex::new(Vec::new());
static CTX: OnceLock<egui::Context> = OnceLock::new();

/// Encola una petición y despierta la interfaz.
pub fn push(item: Opened) {
    tracing::info!("Petición de apertura: {item:?}");
    if let Ok(mut q) = QUEUE.lock() {
        q.push(item);
    }
    if let Some(ctx) = CTX.get() {
        ctx.request_repaint();
    }
}

/// Instala los receptores de eventos del sistema antes de crear la ventana.
pub fn early_init() {
    #[cfg(target_os = "macos")]
    macos::install_url_handler();
}

/// Instala los receptores que necesitan la aplicación ya creada.
pub fn init(ctx: &egui::Context) {
    let _ = CTX.set(ctx.clone());
    // Lo recibido antes de existir la ventana se atiende ahora.
    ctx.request_repaint();
    #[cfg(target_os = "macos")]
    macos::install();
}

/// Peticiones de apertura recibidas desde la última llamada.
pub fn take_opened() -> Vec<Opened> {
    QUEUE.lock().map(|mut q| std::mem::take(&mut *q)).unwrap_or_default()
}

/// En macOS el navegador y el Finder no pasan la URL ni los ficheros por la
/// línea de comandos sino como eventos, que llegan poco después de arrancar.
pub const fn launch_events_by_message() -> bool {
    cfg!(target_os = "macos")
}
