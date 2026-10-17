//! Clave de firma `afirma_core::key::SigningKey` sobre una sesión de DNIe: los firmadores de
//! AutoFirma-rs (CAdES, PAdES, XAdES…) firman con el DNIe sin cambios.

use std::sync::{Arc, Mutex};

use afirma_core::algorithms::{DigestAlgorithm as CoreDigest, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::key::{KeyError, SigningKey};

use crate::error::DnieError;
use crate::interaction::DnieInteraction;
use crate::session::{DigestAlgorithm, DnieSession};
use crate::transport::CardTransport;

/// Sesión compartida entre las claves de un mismo DNIe (las operaciones se serializan).
pub type SharedSession = Arc<Mutex<DnieSession<Box<dyn CardTransport>>>>;

/// Convierte un error del DNIe en error de clave.
pub fn to_key_error(e: &DnieError) -> KeyError {
    match e {
        DnieError::Cancelled => KeyError::Cancelled,
        DnieError::WrongPin { .. } | DnieError::InvalidPinFormat(_) => KeyError::WrongPin,
        DnieError::PinBlocked => KeyError::PinLocked,
        DnieError::Transport(_) => KeyError::DeviceUnavailable,
        DnieError::UnsupportedAlgorithm(m) => KeyError::Unsupported(m.clone()),
        other => KeyError::Other(other.to_string()),
    }
}

/// Huella de AutoFirma admitida por el DNIe (SHA-224 no: JMulticard no la admite).
pub fn digest_from_core(d: CoreDigest) -> Option<DigestAlgorithm> {
    match d {
        CoreDigest::Sha1 => Some(DigestAlgorithm::Sha1),
        CoreDigest::Sha256 => Some(DigestAlgorithm::Sha256),
        CoreDigest::Sha384 => Some(DigestAlgorithm::Sha384),
        CoreDigest::Sha512 => Some(DigestAlgorithm::Sha512),
        CoreDigest::Sha224 => None,
    }
}

/// Clave RSA-2048 del DNIe.
pub struct DnieSigningKey {
    session: SharedSession,
    ui: Arc<dyn DnieInteraction>,
    alias: String,
    certificate: Vec<u8>,
    chain: Vec<Vec<u8>>,
    last_error: Mutex<Option<DnieError>>,
}

impl DnieSigningKey {
    /// Clave `alias` de la sesión. Falla si no existe.
    pub fn new(session: SharedSession, alias: &str, ui: Arc<dyn DnieInteraction>) -> Result<Self, DnieError> {
        let (certificate, chain) = {
            let s = session
                .lock()
                .map_err(|_| DnieError::Read("Sesión del DNIe envenenada".into()))?;
            let k = s.key(alias)?;
            (k.certificate.clone(), k.chain.clone())
        };
        Ok(DnieSigningKey {
            session,
            ui,
            alias: alias.to_string(),
            certificate,
            chain,
            last_error: Mutex::new(None),
        })
    }

    /// Último error del DNIe (con su categoría para la interfaz: intentos restantes, CAN…),
    /// ya que [`KeyError`] no conserva el detalle.
    pub fn last_error(&self) -> Option<DnieError> {
        self.last_error.lock().ok().and_then(|e| e.clone())
    }
}

impl SigningKey for DnieSigningKey {
    fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        if algorithm.key != KeyAlgorithm::Rsa {
            return Err(KeyError::Unsupported(algorithm.java_name()));
        }
        let digest = digest_from_core(algorithm.digest).ok_or_else(|| KeyError::Unsupported(algorithm.java_name()))?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| KeyError::Other("Sesión del DNIe envenenada".into()))?;
        let r = session.sign(&self.alias, digest, data, self.ui.as_ref());
        if let Ok(mut last) = self.last_error.lock() {
            *last = r.as_ref().err().cloned();
        }
        r.map_err(|e| to_key_error(&e))
    }

    fn alias(&self) -> Option<&str> {
        Some(&self.alias)
    }
}
