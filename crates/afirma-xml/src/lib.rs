//! Firmas XML para AutoFirma-rs.
//!
//! El tratamiento de XML se apoya en un DOM propio ([`dom`]) que conserva los
//! prefijos y la posición de cada nodo en el texto original. Así las firmas se
//! insertan en el documento sin reserializarlo (no se altera nada de lo que el
//! usuario firmó) y la canonicalización ([`c14n`]) trabaja con los nombres
//! cualificados exactos.

// `AfirmaError` es grande, pero es el tipo de error común del espacio de
// trabajo (mismo criterio que afirma-core y afirma-cms).
#![allow(clippy::result_large_err)]

pub mod asic;
pub mod c14n;
pub mod crypto;
pub mod dn;
pub mod dom;
pub mod dsig;
pub mod facturae;
pub mod mime;
pub mod office;
pub mod splice;
pub mod util;
pub mod validation;
pub mod xades;
pub mod xmldsig;
pub mod xpath;
pub mod xslt;

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

/// Firmador para un nombre corto de formato (`xades`, `xmldsig`, `facturae`,
/// `asic`, `odf`, `ooxml`), sin distinguir mayúsculas.
pub fn signer_for(name: &str) -> Option<Box<dyn afirma_core::signer::Signer>> {
    match name.to_ascii_lowercase().as_str() {
        "xades" => Some(Box::new(xades::XadesSigner::new())),
        "facturae" => Some(Box::new(facturae::FacturaeSigner::new())),
        "asic" | "xades-asic-s" => Some(Box::new(asic::XadesAsicSigner::new())),
        "xmldsig" => Some(Box::new(xmldsig::XmldsigSigner::new())),
        "odf" => Some(Box::new(office::odf::OdfSigner::new())),
        "odf-java" => Some(Box::new(office::odf::OdfSigner::java_parity())),
        "ooxml" => Some(Box::new(office::ooxml::OoxmlSigner::new())),
        _ => None,
    }
}
