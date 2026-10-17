//! DNIe 3.0/4.0 por NFC (o lector sin contacto) en Rust puro.
//!
//! Implementa la especificación `docs/spec/10-dnie-nfc.md`: detección de la tarjeta, PACE con
//! CAN (ECDH-GM sobre brainpoolP256r1, mensajería segura AES), canales seguros CWA-14890 «de PIN»
//! y «de usuario» (3DES), lectura de certificados (PKCS#15, certificados comprimidos con zlib),
//! verificación del PIN con intentos restantes y firma RSA-2048 (`PSO:CDS` sobre un `DigestInfo`
//! calculado en el equipo).
//!
//! Uso:
//!
//! 1. La plataforma implementa [`CardTransport`] (Android: `IsoDep` por JNI; escritorio: PC/SC)
//!    y [`DnieInteraction`] (petición de CAN y PIN).
//! 2. [`DnieSession::open`] detecta la tarjeta, abre PACE con el CAN y lee los certificados.
//! 3. [`DnieSession::sign`] firma con una de las claves ([`CERT_FIRMA_DIGITAL`] en la app):
//!    abre los canales CWA, pide el PIN, lo verifica, firma y descarta la mensajería segura
//!    (cada firma vuelve a empezar desde PACE, como JMulticard).
//!
//! Capas de mensajería segura (§0.2): la tarjeta tiene un único contexto activo y cada canal
//! nuevo se negocia dentro del actual y lo **sustituye**; [`session`] lo modela con un único
//! contexto (`Plain`, `Pace`, `CwaPin`, `CwaUser`, `Broken`) y nunca envuelve dos veces.
//!
//! Con la característica `signing-key` la sesión se ofrece como
//! `afirma_core::key::SigningKey` (firmadores CAdES/PAdES/XAdES sin cambios) y con `keystore`
//! como `afirma_keystores::KeyStore`. Con `sim` se incluye un simulador software de la tarjeta.

pub mod apdu;
pub mod atr;
pub mod certs;
pub mod consts;
pub mod crypto;
pub mod cwa;
pub mod ec;
pub mod error;
pub mod fs;
mod hexconst;
pub mod interaction;
pub mod pace;
pub mod pkcs15;
pub mod rng;
pub mod session;
pub mod sm;
pub mod tlv;
pub mod transport;

#[cfg(feature = "signing-key")]
pub mod signing;

#[cfg(feature = "keystore")]
pub mod keystore;

#[cfg(feature = "sim")]
pub mod sim;

pub use apdu::{CommandApdu, ResponseApdu};
pub use atr::{DetectionEvidence, DetectionPolicy};
pub use error::{Cancelled, DnieError, ErrorCategory, TransportError};
pub use interaction::{CanRequest, DnieInteraction, FixedInteraction, PinRequest, SignatureRequest};
pub use pace::PacePassword;
pub use rng::{OsRandom, RandomSource, ScriptedRandom};
pub use session::{
    CERT_AUTENTICACION, CERT_FIRMA_DIGITAL, CardInfo, CwaSet, DigestAlgorithm, DnieKey, DnieSession, SessionOptions,
};
pub use transport::{CardIdentification, CardTransport};
