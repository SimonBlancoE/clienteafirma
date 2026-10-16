//! Firmas XML para AutoFirma-rs.
//!
//! El tratamiento de XML se apoya en un DOM propio ([`dom`]) que conserva los
//! prefijos y la posición de cada nodo en el texto original. Así las firmas se
//! insertan en el documento sin reserializarlo (no se altera nada de lo que el
//! usuario firmó) y la canonicalización ([`c14n`]) trabaja con los nombres
//! cualificados exactos.

pub mod c14n;
pub mod dom;

/// Error de tratamiento XML.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlError {
    #[error("XML mal formado (posición {pos}): {msg}")]
    Malformed { pos: usize, msg: String },
    #[error("prefijo de espacio de nombres no declarado: {0}")]
    UndeclaredPrefix(String),
    #[error("codificación de caracteres no soportada: {0}")]
    Encoding(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, XmlError>;
