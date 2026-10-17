//! Registro de la aplicación en `~/.afirma/AutoFirma-rs.log` (texto; se
//! vacía al superar 2 MiB, como el registro de AutoFirma).

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Mutex;

/// Tamaño máximo del registro antes de vaciarlo.
const MAX_LOG: u64 = 2 * 1024 * 1024;

/// Ruta del fichero de registro.
pub fn log_path() -> PathBuf {
    afirma_core::platform::afirma_dir().join("AutoFirma-rs.log")
}

/// Inicia el registro. El nivel se puede cambiar con `AUTOFIRMA_LOG`
/// (`info`, `debug`...). Nunca se registran contraseñas ni datos firmados.
/// Lleva al registro los errores internos (pánicos), también los de hilos y
/// tareas secundarias: abierta desde el navegador o el Finder, la aplicación no
/// tiene salida de errores visible.
fn log_panics() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(
            "Error interno en el hilo {}: {info}\n{backtrace}",
            thread.name().unwrap_or("sin nombre")
        );
        default(info);
    }));
}

pub fn init() {
    let path = log_path();
    // Como root con el HOME de otro usuario (instalador, sudo) no se crea el registro
    // allí (quedaría con propietario root): se escribe en la salida de errores.
    if afirma_system::fsutil::root_in_foreign_home(&path) {
        let filter = tracing_subscriber::EnvFilter::try_from_env("AUTOFIRMA_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init();
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let too_big = std::fs::metadata(&path).map(|m| m.len() > MAX_LOG).unwrap_or(false);
    let file = OpenOptions::new()
        .create(true)
        .append(!too_big)
        .write(true)
        .truncate(too_big)
        .open(&path);
    let filter = tracing_subscriber::EnvFilter::try_from_env("AUTOFIRMA_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(true);
    let _ = match file {
        Ok(f) => builder.with_writer(Mutex::new(f)).try_init(),
        Err(_) => builder.with_writer(std::io::stderr).try_init(),
    };
    log_panics();
    tracing::info!(
        "AutoFirma-rs {} ({} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
}
