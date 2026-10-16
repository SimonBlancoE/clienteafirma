//! Integración con el escritorio: abrir ficheros y carpetas con la
//! aplicación del sistema.

use std::path::Path;
use std::process::Command;

/// Abre un fichero o una URL con la aplicación predeterminada.
pub fn open(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .spawn()
            .map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(path).spawn().map(|_| ())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Command::new("xdg-open").arg(path).spawn().map(|_| ())
    }
}

/// Muestra un fichero en el explorador de archivos (seleccionándolo cuando
/// el sistema lo permite).
pub fn reveal(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn()
            .map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg("-R").arg(path).spawn().map(|_| ())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let dir = if path.is_dir() {
            path
        } else {
            path.parent().unwrap_or(path)
        };
        Command::new("xdg-open").arg(dir).spawn().map(|_| ())
    }
}

/// Diálogo de ficheros que empieza en la última carpeta usada (preferencia
/// auxiliar `currentDir`, la misma que usa AutoFirma Java).
pub fn file_dialog() -> rfd::FileDialog {
    let dialog = rfd::FileDialog::new();
    match last_dir() {
        Some(dir) => dialog.set_directory(dir),
        None => dialog,
    }
}

/// Recuerda la carpeta de un fichero (o la propia carpeta) elegido por el usuario.
pub fn remember_dir(path: &Path) {
    let dir = if path.is_dir() { Some(path) } else { path.parent() };
    let Some(dir) = dir.filter(|d| !d.as_os_str().is_empty()) else {
        return;
    };
    if let Some(mut prefs) = load_prefs() {
        let _ = prefs.put_aux(afirma_system::prefs::keys::AUX_CURRENT_DIR, &dir.to_string_lossy());
    }
}

fn last_dir() -> Option<std::path::PathBuf> {
    load_prefs()?
        .get_aux(afirma_system::prefs::keys::AUX_CURRENT_DIR)
        .map(std::path::PathBuf::from)
        .filter(|d| d.is_dir())
}

fn load_prefs() -> Option<afirma_system::prefs::Preferences> {
    let ctx = afirma_system::Context::detect(afirma_system::AppIdentity::current());
    afirma_system::prefs::Preferences::load(&ctx, afirma_system::prefs::ResolutionMode::Strict).ok()
}
