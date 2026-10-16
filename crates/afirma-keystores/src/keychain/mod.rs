//! Llavero de macOS (`APPLE`, Security.framework).
//!
//! Comportamiento (especificación 05, §3.3 y §5.3):
//!
//! - Se enumeran las identidades (certificado + clave privada) de la lista
//!   de búsqueda de llaveros por defecto con
//!   `SecItemCopyMatching({kSecClass: kSecClassIdentity, kSecMatchLimit: All,
//!   kSecReturnRef, kSecReturnAttributes})`, como el `KeychainStore` de Java
//!   (`SecIdentitySearchCreate`).
//! - Si [`KeychainOptions::include_tokens`] está activo se hace además la
//!   misma consulta con `kSecAttrAccessGroup = kSecAttrAccessGroupToken`, que
//!   devuelve las identidades de tarjetas inteligentes y tokens de
//!   CryptoTokenKit (PIV, tarjetas con controlador CTK, Secure Enclave). Java
//!   no las ve. Las aplicaciones sin *sandbox* no necesitan derechos
//!   (*entitlements*) especiales para esta consulta.
//! - Alias: etiqueta del certificado (`kSecAttrLabel`; si falta, el resumen
//!   del titular), con las reglas de unicidad del `KeychainStore` de Java
//!   (sufijo `" 1"`, `" 2"`… y alias en minúsculas) y después la
//!   eliminación de duplicados por número de serie de AutoFirma (se conserva
//!   la primera identidad de cada número de serie).
//! - Cadena: la que construye `SecTrust` con la política X.509 básica y sin
//!   acceso a red (los intermedios se buscan en los llaveros del usuario); si
//!   falla, solo el certificado.
//! - Firma: se calcula la huella en el proceso y se firma con
//!   `SecKeyCreateSignature` y los algoritmos `…SignatureDigest…`
//!   (`kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA*`,
//!   `kSecKeyAlgorithmECDSASignatureDigestX962SHA*`, que ya devuelve DER).
//!   **Nunca se exporta la clave privada** (Java la exporta y firma en
//!   software, lo que falla con claves no exportables y muestra avisos de
//!   exportación): los diálogos de acceso al llavero o de PIN de la tarjeta
//!   los muestra macOS.

mod logic;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::KeychainStore;

/// Opciones de apertura del llavero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainOptions {
    /// Incluir las identidades de tarjetas inteligentes y tokens de
    /// CryptoTokenKit (mejora sobre Java, activa por defecto).
    pub include_tokens: bool,
}

impl Default for KeychainOptions {
    fn default() -> Self {
        KeychainOptions { include_tokens: true }
    }
}
