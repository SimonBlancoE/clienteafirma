//! Integración con el escritorio: abrir ficheros y carpetas con la
//! aplicación del sistema.

use std::path::Path;
use std::process::Command;

/// Abre un fichero o una URL con la aplicación predeterminada.
pub fn open(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd").args(["/C", "start", ""]).arg(path).spawn().map(|_| ())
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
        Command::new("explorer").arg(format!("/select,{}", path.display())).spawn().map(|_| ())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg("-R").arg(path).spawn().map(|_| ())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let dir = if path.is_dir() { path } else { path.parent().unwrap_or(path) };
        Command::new("xdg-open").arg(dir).spawn().map(|_| ())
    }
}
