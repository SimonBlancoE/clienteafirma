//! Huellas digitales de ficheros y directorios: reimplementación del plugin
//! «Huellas digitales» de AutoFirma (`afirma-simple-plugin-hash`, especificación
//! `docs/spec/06-app-ui-cli-installer.md` §7.5).
//!
//! Biblioteca independiente de la interfaz: la interfaz gráfica y la línea de
//! comandos de la aplicación la usan para:
//!
//! - calcular la huella de un fichero y codificarla en hexadecimal
//!   (`.hexhash`), Base64 (`.hashb64`) o binario (`.hash`) — [`single`];
//! - comprobar un fichero contra su fichero de huella — [`single::check_file_hash`];
//! - calcular las huellas de un directorio en paralelo — [`dir::hash_directory`] —
//!   y guardarlas como XML (`.hashfiles`) o texto (`.txthashfiles`) — [`document`];
//! - comprobar un directorio contra un documento de huellas y generar el
//!   informe `.hashreport` — [`dir::check_directory`];
//! - ejecutar los comandos `createdigest` y `checkdigest` — [`cli`];
//! - modelar las preferencias de los diálogos — [`prefs`].
//!
//! Las diferencias con la versión Java están en `docs/deviations/afirma-hash.md`.

pub mod algorithm;
pub mod cli;
pub mod dir;
pub mod document;
pub mod messages;
pub mod prefs;
pub mod single;
pub mod walk;
mod xmlout;

use std::path::{Path, PathBuf};

pub use afirma_core::DigestAlgorithm;
pub use algorithm::{
    CHUNK_SIZE, DEFAULT_ALGORITHM, GUI_ALGORITHMS, XML_ALGORITHMS, algorithm_for_digest_len,
    digest_file, digest_file_cancellable, digest_reader, parse_algorithm,
};
pub use cli::{
    CliError, CliOptions, CliOutcome, CommandResponse, GuiRequest, HashCommand, HashParameters,
    dispatch, run,
};
pub use dir::{
    DEFAULT_REPORT_NAME, HashOptions, HashReport, REPORT_EXTENSION, check_directory,
    check_directory_with_file, default_directory_document_name, default_report_dir, hash_directory,
};
pub use document::{DirDocumentFormat, DocumentError, HashDocument};
pub use prefs::HashPreferences;
pub use single::{
    DecodedFileHash, FileHashCheck, FileHashFormat, MAX_HASH_FILE_LEN, check_file_hash,
    check_file_hash_file, clipboard_text, decode_file_hash, default_file_hash_name,
    encode_file_hash, hash_file, hex_upper, hex_with_suffix, read_hash_file,
};
pub use walk::{SKIPPED_FILE_NAMES, is_skipped_file_name};

/// Error de las operaciones de huellas.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Algoritmo de huella no soportado.
    #[error("Algoritmo de huella digital no soportado: {0}")]
    UnsupportedAlgorithm(String),
    /// Error de lectura o escritura.
    #[error("Error de entrada/salida en {}: {source}", path.display())]
    Io {
        /// Fichero o directorio afectado.
        path: PathBuf,
        /// Error original.
        #[source]
        source: std::io::Error,
    },
    /// Operación cancelada por el usuario.
    #[error("Operación cancelada")]
    Cancelled,
    /// La longitud de la huella de un fichero de huella no corresponde a
    /// ningún algoritmo soportado.
    #[error(
        "La huella tiene una longitud ({0} bytes) que no corresponde a ningún algoritmo soportado"
    )]
    UnknownDigestLength(usize),
    /// Documento de huellas no válido o corrupto.
    #[error(transparent)]
    Document(#[from] DocumentError),
    /// Una ruta no se puede escribir en el formato de documento elegido.
    #[error("No se puede guardar la ruta {name:?}: {reason}")]
    UnrepresentableName {
        /// Ruta relativa.
        name: String,
        /// Motivo.
        reason: String,
    },
    /// Dos ficheros darían la misma ruta relativa (nombres no UTF-8).
    #[error("Hay varios ficheros con la ruta {0:?}")]
    DuplicateName(String),
    /// No se puede generar el documento.
    #[error("No se puede generar el documento de huellas: {0}")]
    Generation(String),
}

/// Nombre del fichero o directorio en su forma canónica
/// (`FileUtils.getCanonicalFile(file).getName()`), o la ruta tal cual si no
/// se puede obtener.
pub(crate) fn canonical_file_name(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    canonical
        .file_name()
        .or_else(|| path.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
