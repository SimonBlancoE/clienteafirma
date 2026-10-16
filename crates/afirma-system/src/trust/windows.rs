//! Almacén de confianza de Windows (`ROOT`).
//!
//! * Con privilegios (instalador): `LocalMachine\ROOT`, sin ningún aviso; Chrome y Edge lo
//!   usan directamente y Firefox mediante las raíces de empresa.
//! * Sin privilegios: `CurrentUser\ROOT`. **Windows muestra su propio diálogo de seguridad**
//!   al añadir (y al borrar) una raíz en este almacén; no se puede evitar. Por eso el
//!   instalador debe usar el almacén de equipo y la restauración sin privilegios omite el
//!   almacén de usuario cuando la CA ya está en el de equipo.
//!
//! La API de CryptoAPI se abstrae tras [`WinCertStore`] para poder probar con
//! [`MemoryCertStore`].

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::{Change, TrustCheck, TrustScope, is_autofirma_cert};
use crate::certs::CA_CN;
use crate::ctx::Context;
use crate::error::{Result, SystemError};
use crate::registry::Hive;

/// Certificado de un almacén de Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCert {
    pub der: Vec<u8>,
    pub friendly_name: Option<String>,
}

/// Operaciones sobre el almacén `ROOT`.
pub trait WinCertStore: Send + Sync {
    /// Certificados del almacén.
    fn list(&self, scope: TrustScope) -> Result<Vec<StoreCert>>;
    /// Añade (o reemplaza) un certificado con nombre descriptivo.
    fn add(&self, scope: TrustScope, der: &[u8], friendly_name: &str) -> Result<()>;
    /// Borra un certificado; `true` si existía.
    fn delete(&self, scope: TrustScope, der: &[u8]) -> Result<bool>;
}

/// Almacén en memoria para pruebas.
#[derive(Debug, Default)]
pub struct MemoryCertStore {
    certs: Mutex<Vec<(TrustScope, StoreCert)>>,
}

impl WinCertStore for MemoryCertStore {
    fn list(&self, scope: TrustScope) -> Result<Vec<StoreCert>> {
        Ok(self
            .certs
            .lock()
            .map_err(|_| SystemError::Other("bloqueo".into()))?
            .iter()
            .filter(|(s, _)| *s == scope)
            .map(|(_, c)| c.clone())
            .collect())
    }
    fn add(&self, scope: TrustScope, der: &[u8], friendly_name: &str) -> Result<()> {
        let mut c = self
            .certs
            .lock()
            .map_err(|_| SystemError::Other("bloqueo".into()))?;
        c.retain(|(s, x)| !(*s == scope && x.der == der));
        c.push((
            scope,
            StoreCert {
                der: der.to_vec(),
                friendly_name: Some(friendly_name.into()),
            },
        ));
        Ok(())
    }
    fn delete(&self, scope: TrustScope, der: &[u8]) -> Result<bool> {
        let mut c = self
            .certs
            .lock()
            .map_err(|_| SystemError::Other("bloqueo".into()))?;
        let n = c.len();
        c.retain(|(s, x)| !(*s == scope && x.der == der));
        Ok(c.len() != n)
    }
}

/// Almacén no disponible (sistemas que no son Windows).
#[derive(Debug, Default)]
pub struct UnsupportedCertStore;

impl WinCertStore for UnsupportedCertStore {
    fn list(&self, _: TrustScope) -> Result<Vec<StoreCert>> {
        Err(SystemError::Unsupported(
            "almacén de certificados de Windows".into(),
        ))
    }
    fn add(&self, _: TrustScope, _: &[u8], _: &str) -> Result<()> {
        Err(SystemError::Unsupported(
            "almacén de certificados de Windows".into(),
        ))
    }
    fn delete(&self, _: TrustScope, _: &[u8]) -> Result<bool> {
        Err(SystemError::Unsupported(
            "almacén de certificados de Windows".into(),
        ))
    }
}

/// Almacén de sistema de Windows con otro nombre (p. ej. para pruebas).
#[cfg(windows)]
pub fn named_cert_store(name: &str) -> Arc<dyn WinCertStore> {
    Arc::new(cryptoapi::CryptoApiStore::named(name))
}

/// Almacén del sistema actual.
pub fn system_cert_store() -> Arc<dyn WinCertStore> {
    #[cfg(windows)]
    {
        Arc::new(cryptoapi::CryptoApiStore::default())
    }
    #[cfg(not(windows))]
    {
        Arc::new(UnsupportedCertStore)
    }
}

/// Comprueba la CA en el almacén.
pub fn check(store: &dyn WinCertStore, scope: TrustScope, ca_der: &[u8]) -> TrustCheck {
    match store.list(scope) {
        Ok(certs) => {
            if certs.iter().any(|c| c.der == ca_der) {
                TrustCheck::Trusted
            } else if certs.iter().any(|c| super::is_autofirma_ca(&c.der)) {
                TrustCheck::Mismatch("hay una CA de AutoFirma distinta (antigua)".into())
            } else {
                TrustCheck::Missing
            }
        }
        Err(e) => TrustCheck::Unknown(e.to_string()),
    }
}

/// Instala la CA en el almacén (retirando antes las de AutoFirma anteriores). Idempotente.
pub fn install(store: &dyn WinCertStore, scope: TrustScope, ca_der: &[u8]) -> Result<Change> {
    let certs = store.list(scope)?;
    let mut changed = false;
    for c in certs
        .iter()
        .filter(|c| c.der != ca_der && is_autofirma_cert(&c.der))
    {
        changed |= store.delete(scope, &c.der)?;
    }
    if !certs.iter().any(|c| c.der == ca_der) {
        store.add(scope, ca_der, CA_CN)?;
        changed = true;
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

/// Retira todas las CA (y certificados emitidos por ellas) de AutoFirma del almacén.
pub fn remove(store: &dyn WinCertStore, scope: TrustScope) -> Result<Change> {
    let mut changed = false;
    for c in store
        .list(scope)?
        .iter()
        .filter(|c| is_autofirma_cert(&c.der))
    {
        changed |= store.delete(scope, &c.der)?;
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

/// Directorios de instalación de Firefox (registro de Mozilla y rutas por defecto).
pub fn firefox_install_dirs(ctx: &Context) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for base in [
        r"SOFTWARE\Mozilla\Mozilla Firefox",
        r"SOFTWARE\Mozilla\Mozilla Firefox ESR",
        r"SOFTWARE\WOW6432Node\Mozilla\Mozilla Firefox",
    ] {
        for hive in [Hive::LocalMachine, Hive::CurrentUser] {
            for v in ctx
                .registry
                .subkeys(hive, base)
                .ok()
                .flatten()
                .unwrap_or_default()
            {
                if let Ok(Some(d)) = ctx.registry.read_string(
                    hive,
                    &format!(r"{base}\{v}\Main"),
                    "Install Directory",
                ) {
                    let p = PathBuf::from(d);
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
        }
    }
    for pf in &ctx.paths.program_files {
        let p = pf.join("Mozilla Firefox");
        if p.is_dir() && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

#[cfg(windows)]
mod cryptoapi {
    //! Implementación con CryptoAPI (`crypt32`). **FFI**: llamadas `unsafe` a
    //! `CertOpenStore`, `CertEnumCertificatesInStore`, `CertAddEncodedCertificateToStore`,
    //! `CertSetCertificateContextProperty`, `CertDuplicateCertificateContext`,
    //! `CertDeleteCertificateFromStore` y `CertCloseStore`; los contextos se liberan siempre.
    use super::*;
    use windows::Win32::Security::Cryptography::*;
    use windows::core::PCSTR;

    const CERT_STORE_PROV_SYSTEM_W: PCSTR = PCSTR(10 as *const u8);
    const CERT_STORE_PROV_SYSTEM_REGISTRY_W: PCSTR = PCSTR(13 as *const u8);
    const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 1 << 16;
    const CERT_SYSTEM_STORE_LOCAL_MACHINE: u32 = 2 << 16;

    /// Almacén real (por defecto `ROOT`).
    #[derive(Debug)]
    pub struct CryptoApiStore {
        name: String,
    }

    impl Default for CryptoApiStore {
        fn default() -> Self {
            Self {
                name: "ROOT".into(),
            }
        }
    }

    impl CryptoApiStore {
        /// Almacén de sistema con otro nombre (pruebas).
        pub fn named(name: &str) -> Self {
            Self { name: name.into() }
        }
    }

    struct Store(HCERTSTORE);

    impl Drop for Store {
        fn drop(&mut self) {
            // SAFETY: manejador abierto por `open`.
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }

    fn open(scope: TrustScope, store: &str) -> Result<Store> {
        open_with(CERT_STORE_PROV_SYSTEM_W, scope, store)
    }

    fn open_with(provider: PCSTR, scope: TrustScope, store: &str) -> Result<Store> {
        let loc = match scope {
            TrustScope::Machine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            TrustScope::User => CERT_SYSTEM_STORE_CURRENT_USER,
        };
        let name: Vec<u16> = store.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: proveedor de sistema con nombre UTF-16 terminado en NUL que vive durante la llamada.
        let h = unsafe {
            CertOpenStore(
                provider,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                CERT_OPEN_STORE_FLAGS(loc),
                Some(name.as_ptr() as *const _),
            )
        }
        .map_err(|e| SystemError::TrustStore {
            store: format!("{scope:?}\\{store}"),
            detail: e.message(),
        })?;
        Ok(Store(h))
    }

    fn der_of(ctx: *const CERT_CONTEXT) -> Vec<u8> {
        // SAFETY: contexto válido devuelto por la enumeración.
        unsafe {
            std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize).to_vec()
        }
    }

    /// Borra del almacén abierto el certificado con ese DER; `true` si lo encontró.
    fn delete_in(s: &Store, der: &[u8]) -> std::result::Result<bool, String> {
        let mut prev: Option<*const CERT_CONTEXT> = None;
        loop {
            // SAFETY: enumeración estándar; el contexto anterior se libera en la llamada.
            let c = unsafe { CertEnumCertificatesInStore(s.0, prev) };
            if c.is_null() {
                return Ok(false);
            }
            if der_of(c) == der {
                // SAFETY: CertDeleteCertificateFromStore libera el duplicado; el original de la
                // enumeración se libera aparte.
                unsafe {
                    let dup = CertDuplicateCertificateContext(Some(c));
                    let r = CertDeleteCertificateFromStore(dup);
                    let _ = CertFreeCertificateContext(Some(c));
                    r.map_err(|e| e.message())?;
                }
                return Ok(true);
            }
            prev = Some(c);
        }
    }

    impl WinCertStore for CryptoApiStore {
        fn list(&self, scope: TrustScope) -> Result<Vec<StoreCert>> {
            let s = open(scope, &self.name)?;
            let mut out = Vec::new();
            let mut prev: Option<*const CERT_CONTEXT> = None;
            loop {
                // SAFETY: enumeración estándar; el contexto anterior se libera en la llamada.
                let c = unsafe { CertEnumCertificatesInStore(s.0, prev) };
                if c.is_null() {
                    break;
                }
                out.push(StoreCert {
                    der: der_of(c),
                    friendly_name: None,
                });
                prev = Some(c);
            }
            Ok(out)
        }

        fn add(&self, scope: TrustScope, der: &[u8], friendly_name: &str) -> Result<()> {
            let s = open(scope, &self.name)?;
            let mut ctx: *mut CERT_CONTEXT = std::ptr::null_mut();
            // SAFETY: DER válido durante la llamada; contexto de salida que se libera abajo.
            unsafe {
                CertAddEncodedCertificateToStore(
                    Some(s.0),
                    X509_ASN_ENCODING,
                    der,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    Some(&mut ctx),
                )
            }
            .map_err(|e| SystemError::TrustStore {
                store: format!("{scope:?}\\{}", self.name),
                detail: e.message(),
            })?;
            let name: Vec<u16> = friendly_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let blob = CRYPT_INTEGER_BLOB {
                cbData: (name.len() * 2) as u32,
                pbData: name.as_ptr() as *mut u8,
            };
            // SAFETY: contexto válido; `blob` apunta a `name`, vivo durante la llamada.
            unsafe {
                let _ = CertSetCertificateContextProperty(
                    ctx,
                    CERT_FRIENDLY_NAME_PROP_ID,
                    0,
                    Some(&blob as *const _ as *const _),
                );
                let _ = CertFreeCertificateContext(Some(ctx));
            }
            Ok(())
        }

        fn delete(&self, scope: TrustScope, der: &[u8]) -> Result<bool> {
            // Primero con el almacén lógico del sistema; si el certificado sigue presente
            // (almacenes físicos que no propagan el borrado), con el almacén del registro.
            let mut found = false;
            for provider in [CERT_STORE_PROV_SYSTEM_W, CERT_STORE_PROV_SYSTEM_REGISTRY_W] {
                let s = match open_with(provider, scope, &self.name) {
                    Ok(s) => s,
                    Err(e) if found => return Err(e),
                    Err(_) => continue,
                };
                found |= delete_in(&s, der).map_err(|e| SystemError::TrustStore {
                    store: format!("{scope:?}\\{}", self.name),
                    detail: e,
                })?;
                drop(s);
                if !self.list(scope)?.iter().any(|c| c.der == der) {
                    return Ok(found);
                }
            }
            if found {
                return Err(SystemError::TrustStore {
                    store: format!("{scope:?}\\{}", self.name),
                    detail: "el certificado sigue en el almacén tras borrarlo".into(),
                });
            }
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instala_idempotente_y_limpia_antiguas() {
        let s = MemoryCertStore::default();
        let old = crate::certs::generate(&Default::default()).unwrap();
        let new = crate::certs::generate(&Default::default()).unwrap();
        s.add(TrustScope::Machine, &old.ca_der, "Autofirma ROOT")
            .unwrap();
        s.add(TrustScope::Machine, &old.ssl_der, "x").unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["otra.example".into()]).unwrap();
        s.add(TrustScope::Machine, other.cert.der(), "Otra")
            .unwrap();
        assert!(matches!(
            check(&s, TrustScope::Machine, &new.ca_der),
            TrustCheck::Mismatch(_)
        ));
        assert_eq!(
            install(&s, TrustScope::Machine, &new.ca_der).unwrap(),
            Change::Changed
        );
        assert_eq!(
            install(&s, TrustScope::Machine, &new.ca_der).unwrap(),
            Change::Unchanged
        );
        let l = s.list(TrustScope::Machine).unwrap();
        assert_eq!(l.len(), 2, "solo la nueva CA y la ajena");
        assert_eq!(
            check(&s, TrustScope::Machine, &new.ca_der),
            TrustCheck::Trusted
        );
        assert_eq!(remove(&s, TrustScope::Machine).unwrap(), Change::Changed);
        assert_eq!(
            s.list(TrustScope::Machine).unwrap().len(),
            1,
            "la ajena se conserva"
        );
    }
}
