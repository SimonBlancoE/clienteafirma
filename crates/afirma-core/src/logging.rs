//! Ubicación y parámetros del fichero de registro de AutoFirma
//! (`LogManager`) y utilidades de `LoggerUtil` (§8.2-8.3).
//!
//! La configuración real del registro (`tracing`) la hace la aplicación; aquí
//! solo se ofrecen las rutas, los límites y las funciones de saneado de
//! cadenas que usa AutoFirma en sus mensajes.

use std::path::{Path, PathBuf};

/// Nombre del registrador raíz de AutoFirma (`Logger.getLogger("es.gob.afirma")`).
pub const LOGGER_NAME: &str = "es.gob.afirma";
/// Nombre del registrador al que `LogManager` añade el fichero (`"es.gob"`).
pub const LOG_MANAGER_LOGGER_NAME: &str = "es.gob";
/// Sufijo del nombre del fichero de registro (`<APP>.afirma.log.xml`).
pub const LOG_FILE_SUFFIX: &str = ".afirma.log.xml";
/// Tamaño máximo del fichero de registro (2 MiB); hay una sola generación y se
/// sobrescribe en cada arranque.
pub const LOG_MAX_SIZE: u64 = 1024 * 1024 * 2;
/// Número de ficheros de registro que se conservan.
pub const LOG_FILE_COUNT: u32 = 1;
/// El fichero se trunca al arrancar (no se añade al existente).
pub const LOG_APPEND: bool = false;
/// Longitud a partir de la que se recortan las cadenas en el registro.
pub const TRIM_LENGTH: usize = 200;
/// Marcador con el que se sustituye el directorio del usuario en el registro.
pub const USER_HOME_MARKER: &str = "USERHOME";

/// Aplicación que escribe el registro (`LogManager.App`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum App {
    MiniApplet,
    Applet,
    Autofirma,
    AutofirmaConfigurator,
    Standalone,
    Android,
    Handwritten,
    Dninb,
    Other,
}

impl App {
    /// Nombre de la constante Java, que es también el prefijo del fichero de
    /// registro (`AUTOFIRMA.afirma.log.xml`).
    pub fn java_name(self) -> &'static str {
        match self {
            Self::MiniApplet => "MINIAPPLET",
            Self::Applet => "APPLET",
            Self::Autofirma => "AUTOFIRMA",
            Self::AutofirmaConfigurator => "AUTOFIRMA_CONFIGURATOR",
            Self::Standalone => "STANDALONE",
            Self::Android => "ANDROID",
            Self::Handwritten => "HANDWRITTEN",
            Self::Dninb => "DNINB",
            Self::Other => "OTHER",
        }
    }

    /// Nombre del fichero de registro de la aplicación.
    pub fn log_file_name(self) -> String {
        format!("{}{}", self.java_name(), LOG_FILE_SUFFIX)
    }
}

/// Ruta del fichero de registro (`LogManager.install(app, logDir)`): por
/// defecto `~/.afirma/<APP>.afirma.log.xml`; si se indica un directorio, se
/// cambian `\` por `/`, se añade `/` si falta y se sustituye `%h` por el
/// directorio del usuario.
pub fn log_file_path(app: App, log_dir: Option<&str>) -> PathBuf {
    let home = crate::platform::user_home();
    log_file_path_with_home(app, log_dir, &home)
}

/// Como [`log_file_path`] con un directorio de usuario explícito.
pub fn log_file_path_with_home(app: App, log_dir: Option<&str>, home: &Path) -> PathBuf {
    let home = home.to_string_lossy();
    match log_dir {
        None => PathBuf::from(format!("{home}/{}/{}", crate::constants::AFIRMA_SUBDIR, app.log_file_name())),
        Some(dir) => {
            let dir = dir.replace('\\', "/");
            let sep = if dir.ends_with('/') { "" } else { "/" };
            PathBuf::from(format!("{dir}{sep}{}", app.log_file_name()).replace("%h", &home))
        }
    }
}

/// `LoggerUtil.getCleanUserHomePath`: sustituye el directorio del usuario
/// por `USERHOME` (todas las apariciones).
pub fn clean_user_home_path(path: &str) -> String {
    let home = crate::platform::user_home();
    clean_user_home_path_with(path, &home.to_string_lossy())
}

/// Como [`clean_user_home_path`] con el directorio del usuario explícito.
pub fn clean_user_home_path_with(path: &str, home: &str) -> String {
    if home.is_empty() {
        return path.to_string();
    }
    path.replace(home, USER_HOME_MARKER)
}

/// Indica si están permitidos los registros extendidos (propiedad Java
/// `allow.extended.logs`; aquí, variable de entorno `AFIRMA_ALLOW_EXTENDED_LOGS`).
pub fn allow_extended_logs() -> bool {
    std::env::var("AFIRMA_ALLOW_EXTENDED_LOGS").is_ok_and(|v| v.eq_ignore_ascii_case("true"))
}

/// `LoggerUtil.getTrimStr`: si la cadena tiene 200 caracteres o más, se
/// recorta a 200 y se añade `...` (salvo registros extendidos).
pub fn trim_str(s: &str) -> String {
    trim_str_with(s, allow_extended_logs())
}

/// Como [`trim_str`] indicando si se permiten registros extendidos.
pub fn trim_str_with(s: &str, extended: bool) -> String {
    // Java cuenta unidades UTF-16.
    let units: Vec<u16> = s.encode_utf16().collect();
    if !extended && units.len() >= TRIM_LENGTH {
        return format!("{}...", String::from_utf16_lossy(&units[..TRIM_LENGTH]));
    }
    s.to_string()
}

/// `LoggerUtil.getTrimBytes`: si hay más de 200 bytes, se toman los 200
/// primeros (como texto) y se añade `...`.
pub fn trim_bytes(b: &[u8]) -> String {
    trim_bytes_with(b, allow_extended_logs())
}

/// Como [`trim_bytes`] indicando si se permiten registros extendidos.
pub fn trim_bytes_with(b: &[u8], extended: bool) -> String {
    if !extended && b.len() > TRIM_LENGTH {
        return format!("{}...", String::from_utf8_lossy(&b[..TRIM_LENGTH]));
    }
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let home = Path::new("/home/u");
        assert_eq!(
            log_file_path_with_home(App::Autofirma, None, home),
            PathBuf::from("/home/u/.afirma/AUTOFIRMA.afirma.log.xml")
        );
        assert_eq!(
            log_file_path_with_home(App::Standalone, Some("%h\\logs"), home),
            PathBuf::from("/home/u/logs/STANDALONE.afirma.log.xml")
        );
        assert_eq!(
            log_file_path_with_home(App::Other, Some("/var/log/"), home),
            PathBuf::from("/var/log/OTHER.afirma.log.xml")
        );
        assert_eq!(App::AutofirmaConfigurator.log_file_name(), "AUTOFIRMA_CONFIGURATOR.afirma.log.xml");
        assert!(log_file_path(App::Autofirma, None).ends_with(".afirma/AUTOFIRMA.afirma.log.xml"));
    }

    #[test]
    fn trimming() {
        assert_eq!(clean_user_home_path_with("/home/u/a:/home/u/b", "/home/u"), "USERHOME/a:USERHOME/b");
        let s199 = "a".repeat(199);
        assert_eq!(trim_str_with(&s199, false), s199);
        let s200 = "a".repeat(200);
        assert_eq!(trim_str_with(&s200, false), format!("{s200}..."));
        assert_eq!(trim_str_with(&"b".repeat(300), true).len(), 300);
        assert_eq!(trim_bytes_with(&[b'x'; 200], false).len(), 200);
        assert_eq!(trim_bytes_with(&[b'x'; 201], false), format!("{}...", "x".repeat(200)));
    }
}
