//! Firma trifásica (cliente): datos de sesión, protocolo con
//! `SignatureService` y errores del servidor.

pub mod client;
pub mod data;

pub use client::{CryptoOperation, TriphaseClient, TriphaseFormat};
pub use data::{TriSign, TriphaseData};
