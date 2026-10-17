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

/// Atiende una URL `afirma://` en una instancia nueva de la aplicación, que no
/// depende de esta: en macOS se abre con LaunchServices (`open -n`), porque al
/// salir una aplicación `launchd` termina todo su grupo de procesos y un hijo
/// normal moriría con ella; en los demás casos, en su propio grupo de procesos.
pub fn spawn_protocol_instance(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    if let Some(bundle) = afirma_system::AppIdentity::current().macos_bundle {
        tracing::info!("Nueva instancia para la petición web con LaunchServices");
        return std::process::Command::new("/usr/bin/open")
            .arg("-n")
            .arg(&bundle)
            .arg("--args")
            .arg(url)
            .spawn()
            .map(|_| ());
    }
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg(url);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().map(|_| ())
}

/// En macOS el navegador y el Finder no pasan la URL ni los ficheros por la
/// línea de comandos sino como eventos, que llegan poco después de arrancar.
pub const fn launch_events_by_message() -> bool {
    cfg!(target_os = "macos")
}
