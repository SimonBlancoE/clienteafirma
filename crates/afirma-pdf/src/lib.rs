//! Firmas PDF (PAdES) para AutoFirma-rs (`AOPDFSigner` y compañía).
//!
//! - [`pades`]: firmador `PAdES`/`Adobe PDF` ([`PadesSigner`], implementa
//!   [`afirma_core::Signer`]), parámetros adicionales y prefirma/postfirma.
//! - [`appearance`]: apariencia de la firma visible como iText 2.1.7 (texto
//!   con etiquetas `$$…$$`, ofuscación, fuentes estándar, rúbrica, giro).
//! - [`validate`]: validación (`ValidatePdfSignature`), cambios en
//!   formularios y ataques de sombra.
//! - [`info`] (y [`render`] con la característica `render`): datos para la
//!   interfaz gráfica: páginas, tamaños, campos de firma, renderizado de
//!   páginas y vista previa exacta de la apariencia.
//! - [`triphase`]: piezas de la firma trifásica PAdES.
//! - [`pdf`]: lectura (con `lopdf`) y escritura incremental de PDF.
//! - [`cms`]: lectura y verificación de los CMS de las firmas (la generación
//!   usa `afirma_cms::SignedDataBuilder`); [`tsp`]: sellos de tiempo.
//! - [`xmp`]: metadatos XMP.
//!
//! Las desviaciones respecto a Java están en `docs/deviations/afirma-pdf.md`.

// `AfirmaError` (de afirma-core) es el tipo de error común de todos los
// firmadores; su tamaño no depende de este crate.
#![allow(clippy::result_large_err)]

pub mod appearance;
pub mod cms;
pub mod info;
pub mod pades;
pub mod pdf;
#[cfg(feature = "render")]
pub mod render;
pub mod triphase;
pub mod tsp;
pub mod validate;
pub mod xmp;

pub use pades::{FORMAT_PADES, FORMAT_PDF, PadesPreSign, PadesSigner};
