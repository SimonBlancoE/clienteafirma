//! Registro de firmadores de AutoFirma-rs (equivalente a `AOSignerFactory`,
//! `SignValiderFactory` y a la lógica de selección de formato de la
//! aplicación).

pub mod auto;
pub mod naming;
pub mod params;
pub mod pkcs1;
pub mod registry;
pub mod validate;

pub use auto::{CryptoOp, FileAnalysis, ProposedOperation, analyze_for_desktop, protocol_auto_format};
pub use registry::{detect, detect_format_name, signer, signer_for_format};
pub use validate::validate;
