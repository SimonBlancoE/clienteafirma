//! Almacenes de tarjeta "preferentes" (`DNIEJAVA`, `CERES_430`, `CERES`,
//! `SMARTCAFE`) sobre controladores PKCS#11 y su sondeo al abrir los
//! almacenes del sistema y de Firefox
//! (`KeyStoreUtilities.addPreferredKeyStoreManagers`, §3.7.2).
//!
//! Ver la decisión de diseño en [`crate::pkcs11::known`]: en lugar de
//! jmulticard se usan los módulos PKCS#11 instalados (OpenSC, FNMT, DNIe).

use std::path::PathBuf;
use std::sync::Arc;

use crate::callback::PasswordCallback;
use crate::error::KeyStoreError;
use crate::kind::{KeyStoreKind, Os};
use crate::pkcs11::known::{CardFamily, detect_smartcard_modules, windows_known_smartcard_paths};
use crate::pkcs11::{Pkcs11Config, Pkcs11Store};
use crate::store::KeyStore;

/// Opciones de los controladores de tarjeta.
#[derive(Debug, Clone)]
pub struct SmartcardOptions {
    /// Preferencia `enabledJmulticard` (por defecto, verdadera): usar el
    /// DNIe/CERES como almacenes preferentes.
    pub enabled: bool,
    /// `AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER`.
    pub disable_dnie: bool,
    /// `AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER`.
    pub disable_ceres: bool,
    /// `AFIRMA_NSS_ENABLE_GYDSC_NATIVE_DRIVER`.
    pub enable_smartcafe: bool,
    /// Bibliotecas PKCS#11 de tarjeta a probar; `None` = detección
    /// automática en las rutas conocidas del sistema.
    pub modules: Option<Vec<PathBuf>>,
}

impl Default for SmartcardOptions {
    fn default() -> Self {
        SmartcardOptions {
            enabled: true,
            disable_dnie: false,
            disable_ceres: false,
            enable_smartcafe: false,
            modules: None,
        }
    }
}

impl SmartcardOptions {
    fn module_paths(&self) -> Vec<PathBuf> {
        self.modules.clone().unwrap_or_else(|| {
            detect_smartcard_modules(Os::current())
                .into_iter()
                .map(|m| m.path)
                .collect()
        })
    }
}

/// Familia de token que acepta cada tipo de almacén de tarjeta.
pub fn family_for(kind: KeyStoreKind) -> Option<CardFamily> {
    match kind {
        KeyStoreKind::DnieJava => Some(CardFamily::Dnie),
        // CERES 4.30+ ("allowAnotherCards") y CERES antiguas: tarjetas FNMT.
        KeyStoreKind::Ceres | KeyStoreKind::Ceres430 => Some(CardFamily::Fnmt),
        KeyStoreKind::SmartCafe => Some(CardFamily::Other),
        _ => None,
    }
}

/// Abre el almacén de tarjeta del tipo indicado con el primer controlador
/// que tenga un token de esa familia. Sin tarjeta →
/// [`KeyStoreError::CardNotPresent`].
pub fn open_card_store(
    kind: KeyStoreKind,
    opts: &SmartcardOptions,
    callback: Arc<dyn PasswordCallback>,
) -> Result<Pkcs11Store, KeyStoreError> {
    let family = family_for(kind).ok_or_else(|| kind.unsupported_error(Os::current()))?;
    let mut last = KeyStoreError::CardNotPresent;
    for lib in opts.module_paths() {
        let config = Pkcs11Config::card_driver(kind, family).with_name(kind.display_name());
        match Pkcs11Store::open(&lib, config, callback.clone()) {
            Ok(s) if !s.tokens().is_empty() => {
                tracing::info!("Detectada tarjeta {} mediante {}", kind.display_name(), lib.display());
                return Ok(s);
            }
            Ok(_) => {}
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => {
                tracing::debug!(
                    "No se ha podido usar {} para {}: {e}",
                    lib.display(),
                    kind.display_name()
                );
                last = e;
            }
        }
    }
    Err(match last {
        KeyStoreError::LibraryNotFound(_) | KeyStoreError::Load { .. } | KeyStoreError::Pkcs11 { .. } => {
            KeyStoreError::CardNotPresent
        }
        other => other,
    })
}

/// Resultado del sondeo de tarjetas preferentes.
pub enum Preferred {
    /// Se encontró una tarjeta.
    Found(Arc<dyn KeyStore>),
    /// No hay tarjeta (o los controladores están desactivados).
    None,
    /// El usuario canceló un diálogo de la tarjeta: no se sigue sondeando y
    /// se excluyen los módulos nativos del DNIe en Firefox.
    Cancelled,
}

/// Sondeo de tarjetas preferentes: DNIe → CERES 4.30 → CERES → SmartCafe
/// (este último solo si está habilitado). Se para en la primera que se abre.
pub fn probe_preferred(opts: &SmartcardOptions, callback: Arc<dyn PasswordCallback>) -> Preferred {
    if !opts.enabled {
        return Preferred::None;
    }
    let mut kinds = Vec::new();
    if !opts.disable_dnie {
        kinds.push(KeyStoreKind::DnieJava);
    }
    if !opts.disable_ceres {
        // CERES y CERES 4.30 comparten familia de token: un solo intento.
        kinds.push(KeyStoreKind::Ceres430);
    }
    if opts.enable_smartcafe {
        kinds.push(KeyStoreKind::SmartCafe);
    }
    if kinds.is_empty() {
        return Preferred::None;
    }
    // Se detectan los módulos una sola vez para todos los tipos.
    let opts = SmartcardOptions {
        modules: Some(opts.module_paths()),
        ..opts.clone()
    };
    for kind in kinds {
        match open_card_store(kind, &opts, callback.clone()) {
            Ok(s) if !s.entries().map(|e| e.is_empty()).unwrap_or(true) => return Preferred::Found(Arc::new(s)),
            Ok(_) => {}
            Err(e) if e.is_cancelled() => return Preferred::Cancelled,
            Err(e) => tracing::debug!("No se ha detectado {}: {e}", kind.display_name()),
        }
    }
    Preferred::None
}

/// Tarjetas conocidas del perfil temporal de Windows (`KNOWN_SMARTCARDS`,
/// §3.8): se prueban las bibliotecas en orden y se usa la primera que se
/// abre (cancelar el PIN pasa a la siguiente).
pub fn open_known_smartcards(callback: Arc<dyn PasswordCallback>, skip_fnmt: bool) -> Option<Pkcs11Store> {
    let env = |k: &str| std::env::var(k).ok();
    for (name, lib) in windows_known_smartcard_paths(&env) {
        if skip_fnmt && name == "FNMT-CERES" {
            continue;
        }
        if !lib.is_file() {
            continue;
        }
        let config = Pkcs11Config::new(KeyStoreKind::KnownSmartcards)
            .with_name(name)
            .with_pin_prompt(crate::kind::prompts::known_card(name));
        match Pkcs11Store::open(&lib, config, callback.clone()) {
            Ok(s) => return Some(s),
            Err(e) => tracing::info!("No se ha podido cargar la tarjeta {name} ({}): {e}", lib.display()),
        }
    }
    None
}
