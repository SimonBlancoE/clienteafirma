//! Firmas CMS (PKCS#7) y CAdES para AutoFirma-rs.
//!
//! * [`cades::CadesSigner`] (`CAdES`), [`cms_signer::CmsSigner`]
//!   (`CMS/PKCS#7`) y [`asics::CadesAsicsSigner`] (`CAdES-ASiC-S`)
//!   implementan [`afirma_core::Signer`] con paridad con AutoFirma.
//! * [`tsp`]: cliente RFC 3161 y CAdES-T.
//! * [`validation`]: validación (`ValidateBinarySignature`).
//! * [`builder`] e [`inspect`]: API para PAdES, XAdES, trifásica y la
//!   interfaz de validación.
//! * [`asn1`], [`cms`], [`cert`]: utilidades ASN.1/DER de bajo nivel.

// `AfirmaError` (de afirma-core) es grande por diseño: lo comparten todos los crates.
#![allow(clippy::result_large_err)]

pub mod alg;
pub mod asics;
pub mod asn1;
pub mod builder;
pub mod cades;
pub mod cert;
pub mod cms;
pub mod cms_signer;
pub mod detect;
pub mod inspect;
pub mod mime;
pub mod oids;
pub mod pkcs1;
pub mod tree;
pub mod tsp;
pub mod validation;
pub mod verify;

pub use asics::CadesAsicsSigner;
pub use builder::SignedDataBuilder;
pub use cades::CadesSigner;
pub use cms_signer::CmsSigner;
