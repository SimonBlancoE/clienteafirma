//! Utilidades ASN.1 mínimas y sin dependencias externas.
//!
//! - [`Tlv`]: lector BER/DER que conserva los bytes originales de cada
//!   elemento (imprescindible para cofirmar y contrafirmar sin alterar las
//!   firmas existentes, que deben copiarse byte a byte).
//! - [`der`]: funciones para construir estructuras DER.
//! - [`Oid`]: identificadores de objeto.

pub mod der;
mod oid;
mod reader;

pub use oid::Oid;
pub use reader::{Class, Tag, Tlv};

/// Error de codificación o decodificación ASN.1.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Asn1Error {
    #[error("datos ASN.1 truncados")]
    Truncated,
    #[error("longitud ASN.1 no válida")]
    BadLength,
    #[error("se esperaba la etiqueta {expected}, encontrada {found}")]
    UnexpectedTag { expected: String, found: String },
    #[error("valor ASN.1 no válido: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Asn1Error>;

/// Etiquetas universales más habituales.
pub mod tags {
    use super::Tag;
    pub const BOOLEAN: Tag = Tag::universal(1, false);
    pub const INTEGER: Tag = Tag::universal(2, false);
    pub const BIT_STRING: Tag = Tag::universal(3, false);
    pub const OCTET_STRING: Tag = Tag::universal(4, false);
    pub const OCTET_STRING_CONSTRUCTED: Tag = Tag::universal(4, true);
    pub const NULL: Tag = Tag::universal(5, false);
    pub const OID: Tag = Tag::universal(6, false);
    pub const ENUMERATED: Tag = Tag::universal(10, false);
    pub const UTF8_STRING: Tag = Tag::universal(12, false);
    pub const SEQUENCE: Tag = Tag::universal(16, true);
    pub const SET: Tag = Tag::universal(17, true);
    pub const NUMERIC_STRING: Tag = Tag::universal(18, false);
    pub const PRINTABLE_STRING: Tag = Tag::universal(19, false);
    pub const T61_STRING: Tag = Tag::universal(20, false);
    pub const IA5_STRING: Tag = Tag::universal(22, false);
    pub const UTC_TIME: Tag = Tag::universal(23, false);
    pub const GENERALIZED_TIME: Tag = Tag::universal(24, false);
    pub const VISIBLE_STRING: Tag = Tag::universal(26, false);
    pub const UNIVERSAL_STRING: Tag = Tag::universal(28, false);
    pub const BMP_STRING: Tag = Tag::universal(30, false);
}

#[cfg(test)]
mod tests;
