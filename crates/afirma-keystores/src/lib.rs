//! Almacenes de certificados de AutoFirma-rs.
//!
//! Punto de entrada habitual (interfaz gráfica, línea de comandos y
//! protocolo):
//!
//! 1. Elegir el almacén con [`selection`] ([`selection::protocol_store`] y
//!    [`selection::protocol_store_choice`] para `afirma://`,
//!    [`selection::parse_cli_store`] para `-store`,
//!    [`selection::local_default_store`] para la aplicación).
//! 2. Abrirlo con [`factory::open_store`] (o
//!    [`factory::open_with_fallback`]) pasando un [`PasswordCallback`] que
//!    muestre los diálogos de contraseña/PIN.
//! 3. Obtener las entradas ([`KeyStore::entries`]), filtrarlas y ordenarlas
//!    con [`filters::CertFilterManager`] y [`candidates::select_candidates`],
//!    y mostrarlas con los datos de [`display`].
//! 4. Obtener la clave de la entrada elegida ([`KeyStore::signing_key`]) y
//!    firmar; [`verify::sign_and_verify`] hace además la verificación
//!    obligatoria de la firma con el certificado.
//!
//! Módulos:
//! - [`kind`]: tipos de almacén (`AOKeyStore`) y sistema operativo.
//! - [`store`]: interfaz [`KeyStore`], entradas [`CertEntry`] y almacén
//!   agregado ([`AggregateStore`]).
//! - [`callback`]: peticiones de contraseña/PIN ([`PasswordCallback`],
//!   caché de PIN de tarjetas [`PinCache`]).
//! - [`selection`], [`registered`]: selección del almacén y tarjetas
//!   registradas en preferencias.
//! - [`factory`], [`smartcard`]: apertura de almacenes y tarjetas
//!   preferentes (DNIe/CERES sobre controladores PKCS#11).
//! - Implementaciones: [`pkcs12_store`], [`pkcs11`], [`nss`], [`single`],
//!   `capi` (Windows) y `keychain` (macOS).
//! - [`filters`], [`candidates`], [`display`], [`dn`]: filtros de
//!   certificados, lista de candidatos y datos para el diálogo.
//! - [`verify`]: verificación de la firma producida con el certificado.
//! - [`error`]: errores y su correspondencia con los códigos de AutoFirma.

pub mod callback;
pub mod candidates;
#[cfg(windows)]
pub mod capi;
pub mod display;
pub mod dn;
pub mod error;
pub mod factory;
pub mod filters;
// Fuera de macOS solo se compila en pruebas (lógica pura: alias, números de
// serie, algoritmos y errores).
#[cfg(any(target_os = "macos", test))]
pub mod keychain;
pub mod kind;
pub mod nss;
pub mod pkcs11;
pub mod pkcs12;
pub mod pkcs12_store;
pub mod registered;
pub mod selection;
pub mod single;
pub mod smartcard;
pub mod software;
pub mod store;
pub mod verify;

pub use callback::{
    ConfirmRequest, FixedPassword, NoPassword, PasswordCallback, PasswordKind, PasswordRequest, PasswordResponse, PinCache, PinProvider,
    RetryReason, Secret,
};
pub use candidates::{CandidateList, CandidateOptions, auto_select, candidates_with_manager, select_candidates};
pub use display::{CertificateView, RowText, entry_row_text, row_text};
pub use error::KeyStoreError;
pub use factory::{OpenOptions, open_default_store, open_store, open_with_fallback};
pub use filters::{CertFilter, CertFilterManager, FilterError, LocalFilterPrefs};
pub use kind::{KeyStoreKind, Os};
pub use registered::{RegisteredCard, RegisteredCards};
pub use selection::StoreSpec;
pub use software::SoftwareKey;
pub use store::{AggregateStore, CertEntry, EntryCapabilities, KeyStore};
pub use verify::{VerifyError, VerifyingKey, sign_and_verify, verify_signature};

/// Las pruebas que inicializan `softokn3` (NSS) no pueden ejecutarse a la
/// vez: NSS solo admite un perfil por proceso.
#[cfg(test)]
pub(crate) static NSS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
