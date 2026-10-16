//! Errores de la línea de comandos con la clasificación de Java
//! (`processCommandLine`, §5.11), que decide qué se imprime y cómo.

use std::path::Path;

/// Error de un comando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// `CommandLineParameterException`: se imprime el mensaje seguido de la
    /// ayuda del comando y **nunca** se envuelve en XML.
    Syntax {
        /// Mensaje.
        message: String,
        /// `-gui` visto (muestra además un diálogo de error).
        using_gui: bool,
    },
    /// `CommandLineException`: se imprime el mensaje (ya resuelto como lo
    /// imprime Java: el de la causa si la hay), en XML si se pidió `-xml`.
    /// `None` reproduce el caso de Java en que la causa no tiene mensaje y no
    /// se imprime nada.
    Command {
        /// Mensaje.
        message: Option<String>,
        /// `-gui` visto (muestra además un diálogo de error).
        using_gui: bool,
    },
    /// `UnsupportedOperationException`/`PluginControlledException`: el
    /// mensaje tal cual (en XML si se pidió).
    Unsupported(String),
    /// Cualquier otra excepción: `Error no reconocido: <mensaje>` (en XML si
    /// se pidió).
    Unexpected(String),
}

impl CliError {
    /// `CommandLineException` con mensaje.
    pub fn command(message: String, using_gui: bool) -> Self {
        CliError::Command {
            message: Some(message),
            using_gui,
        }
    }

    /// `CommandLineException` sin `-gui`.
    pub fn plain(message: impl Into<String>) -> Self {
        CliError::Command {
            message: Some(message.into()),
            using_gui: false,
        }
    }

    /// `CommandLineParameterException`.
    pub fn syntax(message: String, using_gui: bool) -> Self {
        CliError::Syntax { message, using_gui }
    }

    /// `CommandLineParameterException` sin `-gui`.
    pub fn syntax_plain(message: impl Into<String>) -> Self {
        CliError::Syntax {
            message: message.into(),
            using_gui: false,
        }
    }
}

/// Mensaje de una `IOException` de Java al abrir un fichero
/// (`FileNotFoundException`: `<ruta> (<motivo>)`), p. ej.
/// `salida (Is a directory)`.
pub fn java_io_message(path: &Path, err: &std::io::Error) -> String {
    let reason = match err.raw_os_error() {
        Some(_) => {
            let text = err.to_string();
            match text.find(" (os error") {
                Some(i) => text[..i].to_string(),
                None => text,
            }
        }
        None => err.to_string(),
    };
    format!("{} ({reason})", path.display())
}

/// Ruta absoluta sin canonicalizar (`File.getAbsolutePath()`).
pub fn absolute_path(path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mensajes_io() {
        let e = std::io::Error::from_raw_os_error(21);
        if cfg!(target_os = "linux") {
            assert_eq!(java_io_message(Path::new("testdata"), &e), "testdata (Is a directory)");
        }
        let e = std::io::Error::other("fallo");
        assert_eq!(java_io_message(Path::new("x"), &e), "x (fallo)");
        assert!(absolute_path(Path::new("a")).is_absolute());
    }
}
