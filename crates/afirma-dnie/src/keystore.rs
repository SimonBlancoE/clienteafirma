//! Almacén `afirma_keystores::KeyStore` sobre un DNIe sin contacto (tipo `DnieJava`, el almacén
//! «DNI» de JMulticard), y adaptador de los diálogos de contraseña de AutoFirma
//! ([`PasswordCallback`]) a [`DnieInteraction`].

use std::sync::{Arc, Mutex, RwLock};

use afirma_core::algorithms::KeyAlgorithm;
use afirma_core::key::SigningKey;
use afirma_keystores::callback::{ConfirmRequest, PasswordCallback, PasswordKind, PasswordRequest, PasswordResponse};
use afirma_keystores::error::KeyStoreError;
use afirma_keystores::kind::KeyStoreKind;
use afirma_keystores::store::{CertEntry, EntryCapabilities, KeyStore, find_entry};
use zeroize::Zeroizing;

use crate::error::{Cancelled, DnieError, ErrorCategory};
use crate::interaction::{self, CanRequest, DnieInteraction, PinRequest, SignatureRequest};
use crate::session::DnieSession;
use crate::signing::{DnieSigningKey, SharedSession};
use crate::transport::CardTransport;

/// Nombre del almacén.
pub const STORE_NAME: &str = "DNIe (NFC)";

/// Convierte un error del DNIe en error de almacén.
pub fn to_keystore_error(e: DnieError) -> KeyStoreError {
    match e {
        DnieError::Cancelled => KeyStoreError::Cancelled,
        DnieError::WrongPin { retries_left } => KeyStoreError::WrongPin {
            retries_left: retries_left.map(u32::from),
        },
        DnieError::InvalidPinFormat(_) => KeyStoreError::PinLengthInvalid,
        DnieError::PinBlocked => KeyStoreError::Locked { smartcard: true },
        DnieError::CardNotSupported(_) => KeyStoreError::InvalidCard,
        DnieError::AliasNotFound(a) => KeyStoreError::AliasNotFound(a),
        other => {
            let message = match other.category() {
                ErrorCategory::Other => other.to_string(),
                c => format!("{} ({other})", c.message()),
            };
            KeyStoreError::load(KeyStoreKind::DnieJava, message)
        }
    }
}

/// Almacén de claves del DNIe.
pub struct DnieKeyStore {
    session: SharedSession,
    ui: Arc<dyn DnieInteraction>,
    entries: RwLock<Vec<CertEntry>>,
}

impl DnieKeyStore {
    /// Abre el DNIe (detección, CAN, PACE y lectura de certificados).
    pub fn open(transport: Box<dyn CardTransport>, ui: Arc<dyn DnieInteraction>) -> Result<Self, KeyStoreError> {
        let session = DnieSession::open(transport, ui.as_ref()).map_err(to_keystore_error)?;
        Ok(Self::from_session(Arc::new(Mutex::new(session)), ui))
    }

    /// Almacén sobre una sesión ya abierta.
    pub fn from_session(session: SharedSession, ui: Arc<dyn DnieInteraction>) -> Self {
        let store = DnieKeyStore {
            session,
            ui,
            entries: RwLock::new(Vec::new()),
        };
        store.rebuild_entries();
        store
    }

    /// Sesión subyacente.
    pub fn session(&self) -> SharedSession {
        self.session.clone()
    }

    fn rebuild_entries(&self) {
        let entries: Vec<CertEntry> = match self.session.lock() {
            Ok(s) => s
                .keys()
                .iter()
                .map(|k| {
                    CertEntry::new(
                        k.alias.clone(),
                        k.certificate.clone(),
                        k.chain.clone(),
                        EntryCapabilities {
                            has_private_key: true,
                            key_algorithm: Some(KeyAlgorithm::Rsa),
                            hardware: true,
                            pin_at_sign: true,
                        },
                        STORE_NAME,
                    )
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        if let Ok(mut e) = self.entries.write() {
            *e = entries;
        }
    }
}

impl KeyStore for DnieKeyStore {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::DnieJava
    }

    fn name(&self) -> String {
        STORE_NAME.to_string()
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        Ok(self.entries.read().map(|e| e.clone()).unwrap_or_default())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let entries = self.entries()?;
        let entry = find_entry(&entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let key =
            DnieSigningKey::new(self.session.clone(), &entry.alias, self.ui.clone()).map_err(to_keystore_error)?;
        Ok(Box::new(key))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        {
            let mut s = self
                .session
                .lock()
                .map_err(|_| KeyStoreError::load(KeyStoreKind::DnieJava, "Sesión del DNIe envenenada"))?;
            s.reload().map_err(to_keystore_error)?;
        }
        self.rebuild_entries();
        Ok(())
    }

    fn is_preferred(&self) -> bool {
        true
    }
}

/// Adaptador de los diálogos de AutoFirma: CAN con el diálogo «DNI Electrónico: Introducción de
/// CAN», PIN con el de PIN de DNIe (con intentos restantes) y confirmación de firma.
pub struct PasswordCallbackInteraction<C: PasswordCallback> {
    callback: C,
}

impl<C: PasswordCallback> PasswordCallbackInteraction<C> {
    pub fn new(callback: C) -> Self {
        PasswordCallbackInteraction { callback }
    }
}

fn provided(r: PasswordResponse) -> Result<Zeroizing<String>, Cancelled> {
    match r {
        PasswordResponse::Provided { secret, .. } => Ok(Zeroizing::new(secret.as_str().to_string())),
        PasswordResponse::NoPassword | PasswordResponse::Cancelled => Err(Cancelled),
    }
}

impl<C: PasswordCallback> DnieInteraction for PasswordCallbackInteraction<C> {
    fn request_can(&self, request: &CanRequest) -> Result<Zeroizing<String>, Cancelled> {
        let mut r = PasswordRequest::new(PasswordKind::Pin, KeyStoreKind::DnieJava, request.prompt);
        r.title = Some(request.title.to_string());
        r.smartcard = true;
        r.min_len = Some(6);
        r.max_len = Some(6);
        provided(self.callback.request_password(&r))
    }

    fn request_pin(&self, request: &PinRequest) -> Result<Zeroizing<String>, Cancelled> {
        let r = PasswordRequest::card_pin(KeyStoreKind::DnieJava, true, request.retries_left.map(u32::from));
        debug_assert_eq!(r.prompt, request.prompt());
        provided(self.callback.request_password(&r))
    }

    fn confirm_signature(&self, request: &SignatureRequest) -> Result<bool, Cancelled> {
        Ok(self
            .callback
            .confirm_signature(&ConfirmRequest::dnie(request.alias.clone())))
    }
}

/// Texto de petición del CAN reexportado para las interfaces.
pub use interaction::PROMPT_CAN;
