//! Errores de la integración con el sistema.

use std::io;
use std::path::{Path, PathBuf};

use crate::prefs::afconfig::ConfigError;

/// Error de una operación de integración con el sistema.
#[derive(Debug, thiserror::Error)]
pub enum SystemError {
    /// Error de entrada/salida sobre una ruta concreta.
    #[error("error de E/S en «{path}»: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Error de entrada/salida sin ruta asociada.
    #[error("error de E/S: {0}")]
    IoPlain(#[from] io::Error),
    /// La preferencia está fijada por una directiva del administrador.
    #[error("la preferencia «{0}» está gestionada por su organización y no puede modificarse")]
    Locked(String),
    /// Valor no admitido para una preferencia.
    #[error("el valor «{value}» no es válido para la preferencia «{key}»")]
    InvalidValue { key: String, value: String },
    /// La operación requiere privilegios de administrador.
    #[error("se requieren privilegios de administrador: {0}")]
    NotElevated(String),
    /// La operación no está disponible en este sistema operativo.
    #[error("operación no soportada en este sistema: {0}")]
    Unsupported(String),
    /// Error al ejecutar un mandato externo.
    #[error("error al ejecutar «{program}»: {detail}")]
    Command { program: String, detail: String },
    /// Error del registro de Windows.
    #[error("error en el registro de Windows ({key}): {detail}")]
    Registry { key: String, detail: String },
    /// Error al generar o leer los certificados locales.
    #[error("error en los certificados locales: {0}")]
    Certificate(String),
    /// Error del almacén de confianza (sistema, NSS...).
    #[error("error en el almacén de confianza {store}: {detail}")]
    TrustStore { store: String, detail: String },
    /// Error al importar/exportar ficheros de configuración (`.afconfig`), con código de AutoFirma.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Fichero de datos con formato no válido.
    #[error("formato no válido en «{path}»: {detail}")]
    Format { path: PathBuf, detail: String },
    /// Otros errores.
    #[error("{0}")]
    Other(String),
}

/// Resultado de las operaciones de este crate.
pub type Result<T> = std::result::Result<T, SystemError>;

/// Construye un adaptador de `io::Error` que añade la ruta.
pub(crate) fn io_at(path: &Path) -> impl FnOnce(io::Error) -> SystemError + '_ {
    move |source| SystemError::Io {
        path: path.to_path_buf(),
        source,
    }
}
