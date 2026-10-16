//! Almacén PKCS#12 / PFX en fichero (`Pkcs12KeyStoreManager`).
//!
//! - La contraseña se pide con "Introduzca la contraseña del almacén
//!   `<fichero>`." (`AOKeyStore.15`) y se guarda en memoria mientras vive el
//!   almacén para [`KeyStore::refresh`] (que vuelve a leer el fichero).
//! - Una contraseña errónea devuelve
//!   [`KeyStoreError::WrongPassword`] ("La contrasena del almacen PKCS#12 /
//!   PFX no es valida"); solo si se pide con
//!   [`Pkcs12Options::retry_on_wrong_password`] (flujos interactivos: cambio
//!   de almacén en el diálogo, almacén por defecto de la aplicación) se
//!   vuelve a preguntar mostrando "Contraseña incorrecta.".
//! - Se admiten cifrados antiguos (RC2/3DES, PBES1) y modernos (PBES2/AES,
//!   MAC SHA-256), a través de `p12-keystore`.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use afirma_core::key::SigningKey;

use crate::callback::{PasswordCallback, PasswordKind, PasswordRequest, PasswordResponse, RetryReason, Secret};
use crate::error::KeyStoreError;
use crate::kind::KeyStoreKind;
use crate::pkcs12::{Pkcs12Entry, Pkcs12Error};
use crate::store::{CertEntry, EntryCapabilities, KeyStore, find_entry};

/// Mensaje de Java para contraseña errónea.
pub const WRONG_PASSWORD_MESSAGE: &str = "La contrasena del almacen PKCS#12 / PFX no es valida";
/// Mensaje de Java para fichero no válido.
pub const INVALID_MESSAGE: &str = "El almacen PKCS#12 / PFX no es valido o no pudo cargarse";

/// Opciones de apertura.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs12Options {
    /// Volver a pedir la contraseña si es errónea (solo con un
    /// [`PasswordCallback`] interactivo). Java solo reintenta en la
    /// interfaz local; en el protocolo falla a la primera.
    pub retry_on_wrong_password: bool,
}

struct Loaded {
    entries: Vec<CertEntry>,
    keys: Vec<Pkcs12Entry>,
}

/// Almacén PKCS#12 abierto.
pub struct Pkcs12Store {
    path: Option<PathBuf>,
    data: Option<Vec<u8>>,
    password: Mutex<Secret>,
    loaded: RwLock<Loaded>,
}

impl std::fmt::Debug for Pkcs12Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs12Store").field("path", &self.path).finish_non_exhaustive()
    }
}

impl Pkcs12Store {
    /// Abre un fichero PKCS#12 pidiendo la contraseña con `callback`.
    pub fn open(path: &Path, callback: &dyn PasswordCallback, options: Pkcs12Options) -> Result<Self, KeyStoreError> {
        let data = std::fs::read(path).map_err(|_| KeyStoreError::FileNotFound(path.to_path_buf()))?;
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let prompt = KeyStoreKind::Pkcs12.store_password_prompt(file_name.as_deref()).unwrap_or_default();
        let mut retry = None;
        loop {
            let mut req = PasswordRequest::new(PasswordKind::StorePassword, KeyStoreKind::Pkcs12, prompt.clone());
            req.retry = retry;
            let password = match callback.request_password(&req) {
                PasswordResponse::Provided { secret, .. } => secret,
                // Java carga con contraseña nula; aquí se intenta la vacía.
                PasswordResponse::NoPassword => Secret::empty(),
                PasswordResponse::Cancelled => return Err(KeyStoreError::Cancelled),
            };
            match load(&data, &password) {
                Ok(loaded) => {
                    return Ok(Pkcs12Store {
                        path: Some(path.to_path_buf()),
                        data: None,
                        password: Mutex::new(password),
                        loaded: RwLock::new(loaded),
                    });
                }
                Err(KeyStoreError::WrongPassword { .. }) if options.retry_on_wrong_password && callback.is_interactive() => {
                    retry = Some(RetryReason::WrongPassword);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Abre un PKCS#12 en memoria con una contraseña conocida.
    pub fn from_bytes(data: Vec<u8>, password: impl Into<Secret>) -> Result<Self, KeyStoreError> {
        let password = password.into();
        let loaded = load(&data, &password)?;
        Ok(Pkcs12Store { path: None, data: Some(data), password: Mutex::new(password), loaded: RwLock::new(loaded) })
    }

    /// Fichero del almacén, si se abrió desde fichero.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

fn load(data: &[u8], password: &Secret) -> Result<Loaded, KeyStoreError> {
    let keys = crate::pkcs12::open_entries(data, password.as_str()).map_err(|e| match e {
        Pkcs12Error::WrongPassword => KeyStoreError::WrongPassword { message: WRONG_PASSWORD_MESSAGE.into() },
        other => KeyStoreError::load(KeyStoreKind::Pkcs12, format!("{INVALID_MESSAGE}: {other}")),
    })?;
    let entries = keys
        .iter()
        .map(|k| {
            let caps = EntryCapabilities { has_private_key: true, ..Default::default() };
            CertEntry::new(k.alias.clone(), k.certificate().to_vec(), k.chain.clone(), caps, KeyStoreKind::Pkcs12.display_name())
        })
        .collect();
    Ok(Loaded { entries, keys })
}

impl KeyStore for Pkcs12Store {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Pkcs12
    }

    fn lib_name(&self) -> Option<String> {
        self.path.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned())
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        Ok(self.loaded.read().map(|l| l.entries.clone()).unwrap_or_default())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let loaded = self.loaded.read().map_err(|_| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let entry = find_entry(&loaded.entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let key = loaded
            .keys
            .iter()
            .find(|k| k.alias == entry.alias)
            .ok_or_else(|| KeyStoreError::NoPrivateKey(alias.to_string()))?;
        Ok(Box::new(key.signing_key()?))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        let data = match (&self.path, &self.data) {
            (Some(p), _) => std::fs::read(p).map_err(|_| KeyStoreError::FileNotFound(p.clone()))?,
            (None, Some(d)) => d.clone(),
            (None, None) => return Ok(()),
        };
        let password = self.password.lock().map(|p| p.clone()).unwrap_or_else(|_| Secret::empty());
        let result = load(&data, &password);
        if let Ok(mut l) = self.loaded.write() {
            match result {
                Ok(new) => *l = new,
                Err(e) => {
                    // Como Java: si falla la recarga, se ocultan sus entradas.
                    *l = Loaded { entries: Vec::new(), keys: Vec::new() };
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::{FixedPassword, FnPasswordCallback};
    use afirma_core::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pki(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki").join(name)
    }

    #[test]
    fn opens_signs_and_refreshes() {
        for (file, key) in [
            ("firmante-rsa.p12", KeyAlgorithm::Rsa),
            ("firmante-rsa-legacy.p12", KeyAlgorithm::Rsa),
            ("firmante-ec.p12", KeyAlgorithm::Ec),
            ("firmante-ec-legacy.p12", KeyAlgorithm::Ec),
        ] {
            let store = Pkcs12Store::open(&pki(file), &FixedPassword::new("12341234"), Pkcs12Options::default()).unwrap();
            assert_eq!(store.lib_name().as_deref(), Some(file));
            let entries = store.entries().unwrap();
            assert_eq!(entries.len(), 1);
            let e = &entries[0];
            assert_eq!(e.alias, file.trim_end_matches(".p12").trim_end_matches("-legacy"));
            assert_eq!(e.chain.len(), 2);
            assert_eq!(e.capabilities.key_algorithm, Some(key));
            assert!(e.capabilities.has_private_key);
            let k = store.signing_key(&e.alias).unwrap();
            let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, key);
            crate::verify::sign_and_verify(k.as_ref(), b"datos", alg).unwrap();
            store.refresh().unwrap();
            assert_eq!(store.entries().unwrap().len(), 1);
            assert_eq!(store.aliases().unwrap(), vec![e.alias.clone()]);
        }
    }

    #[test]
    fn wrong_password_and_retry() {
        let r = Pkcs12Store::open(&pki("firmante-rsa.p12"), &FixedPassword::new("mala"), Pkcs12Options { retry_on_wrong_password: true });
        assert_eq!(r.unwrap_err(), KeyStoreError::WrongPassword { message: WRONG_PASSWORD_MESSAGE.into() });

        let calls = AtomicUsize::new(0);
        let cb = FnPasswordCallback(|req: &PasswordRequest| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(req.prompt, "Introduzca la contraseña del almacén firmante-rsa.p12.");
            if n == 0 {
                assert!(req.retry.is_none());
                PasswordResponse::provided("mala")
            } else {
                assert_eq!(req.retry, Some(RetryReason::WrongPassword));
                PasswordResponse::provided("12341234")
            }
        });
        let s = Pkcs12Store::open(&pki("firmante-rsa.p12"), &cb, Pkcs12Options { retry_on_wrong_password: true }).unwrap();
        assert_eq!(s.entries().unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Sin reintento (protocolo): falla a la primera.
        let calls2 = AtomicUsize::new(0);
        let cb2 = FnPasswordCallback(|_: &PasswordRequest| {
            calls2.fetch_add(1, Ordering::SeqCst);
            PasswordResponse::provided("mala")
        });
        assert!(Pkcs12Store::open(&pki("firmante-rsa.p12"), &cb2, Pkcs12Options::default()).is_err());
        assert_eq!(calls2.load(Ordering::SeqCst), 1);

        let cancel = FnPasswordCallback(|_: &PasswordRequest| PasswordResponse::Cancelled);
        assert_eq!(Pkcs12Store::open(&pki("firmante-rsa.p12"), &cancel, Pkcs12Options::default()).unwrap_err(), KeyStoreError::Cancelled);
        assert!(matches!(
            Pkcs12Store::open(Path::new("/no/existe.p12"), &cancel, Pkcs12Options::default()),
            Err(KeyStoreError::FileNotFound(_))
        ));
    }

    #[test]
    fn java_alias_rules() {
        // friendlyName en minúsculas (comprobado con el oráculo Java:
        // "Mi Certificado RSA" → "mi certificado rsa"; sin nombre → "1").
        let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/keystores");
        let s = Pkcs12Store::open(&golden.join("alias-mayusculas.p12"), &FixedPassword::new("12341234"), Pkcs12Options::default()).unwrap();
        assert_eq!(s.aliases().unwrap(), vec!["mi certificado rsa".to_string()]);
        let s = Pkcs12Store::open(&golden.join("alias-sin-nombre.p12"), &FixedPassword::new("12341234"), Pkcs12Options::default()).unwrap();
        assert_eq!(s.aliases().unwrap(), vec!["1".to_string()]);
    }
}
