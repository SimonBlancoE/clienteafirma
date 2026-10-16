//! Almacenes NSS: Firefox (`MOZ_UNI`, `MOZ_UNI_WITH_OS`) y base de datos
//! NSS compartida (`SHARED_NSS`, `~/.pki/nssdb`).
//!
//! Se usa la opción A de la especificación (paridad con Java): `softokn3`
//! se carga como módulo PKCS#11 y se inicializa con la cadena de
//! configuración de NSS en `pReserved` de `C_Initialize`
//! (`configdir='sql:<perfil>' certPrefix='' keyPrefix='' flags='readOnly'`),
//! usando la ranura 2 ("NSS Certificate DB"). Los módulos externos
//! registrados en el perfil (`pkcs11.txt`/`secmod.db`) se cargan por
//! separado como almacenes PKCS#11.
//!
//! Limitación (igual que Java): `softokn3` solo puede inicializarse con un
//! directorio de perfil a la vez en el proceso; para cambiar de perfil hay
//! que liberar antes todos los almacenes y claves del anterior.

pub mod libdir;
pub mod modules;
pub mod profiles;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::callback::PasswordCallback;
use crate::error::KeyStoreError;
use crate::kind::{KeyStoreKind, Os};
use crate::pkcs11::{Pkcs11Config, Pkcs11Module, Pkcs11Store, SlotSelection, TokenDescription};

pub use modules::{ExternalModule, ModuleFilter};
pub use profiles::{MozEnv, firefox_profile_dir, shared_nss_dir};

/// Propiedad Java (y variable de entorno equivalente) para abrir NSS en
/// lectura y escritura.
pub const ENABLE_NSS_WRITE: &str = "es.gob.afirma.keystores.mozilla.EnableNssWrite";
/// Alias con nombre de variable de entorno convencional.
pub const ENABLE_NSS_WRITE_ALT: &str = "AFIRMA_NSS_ENABLE_WRITE";

/// Opciones de apertura de NSS.
#[derive(Debug, Clone, Default)]
pub struct NssOptions {
    /// No añadir `flags='readOnly'`.
    pub enable_write: bool,
    /// `NSS_DEFAULT_DB_TYPE=sql`.
    pub nss_default_db_sql: bool,
}

impl NssOptions {
    pub fn from_env(env: &MozEnv) -> NssOptions {
        NssOptions {
            enable_write: env.flag(ENABLE_NSS_WRITE) || env.flag(ENABLE_NSS_WRITE_ALT),
            nss_default_db_sql: env.var("NSS_DEFAULT_DB_TYPE") == Some("sql"),
        }
    }
}

/// Escapa un valor para una cadena de parámetros de NSS entre comillas
/// simples.
fn nss_quote(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Cadena de inicialización de `softokn3` (`nssArgs` de SunPKCS11).
pub fn nss_init_string(profile_dir: &Path, sql: bool, enable_write: bool) -> String {
    let dir = profile_dir.to_string_lossy();
    let dir = if cfg!(windows) { dir.replace('\\', "/") } else { dir.to_string() };
    format!(
        "configdir='{}{}' certPrefix='' keyPrefix='' {}",
        if sql { "sql:" } else { "" },
        nss_quote(&dir),
        if enable_write { "" } else { "flags='readOnly'" }
    )
}

/// Indica si un perfil debe abrirse en modo SQLite (`sql:`).
pub fn use_sql_db(profile_dir: &Path, opts: &NssOptions) -> bool {
    opts.nss_default_db_sql || profile_dir.join("pkcs11.txt").exists()
}

/// Precarga las dependencias de `softokn3` del directorio de NSS (solo las
/// que existan).
fn preload_dependencies(lib_dir: &Path, os: Os) {
    for dep in libdir::softokn_dependencies(os) {
        let p = lib_dir.join(dep);
        if p.is_file() && !crate::pkcs11::raw::preload_global(&p) {
            tracing::warn!("Error al cargar la biblioteca {} para el acceso al almacen de claves de Mozilla", p.display());
        }
    }
}

/// Configuración PKCS#11 del módulo interno de NSS.
fn internal_config(kind: KeyStoreKind) -> Pkcs11Config {
    let prompt = match kind {
        KeyStoreKind::SharedNss => crate::kind::prompts::SHARED_NSS_STORE,
        _ => crate::kind::prompts::MOZILLA_STORE,
    };
    Pkcs11Config {
        slots: SlotSelection::AllTokens,
        // Ranura 2 ("NSS User Private Key and Certificate Services") o el
        // token de certificados en modo FIPS.
        token_filter: Some(Arc::new(|t: &TokenDescription| t.slot_id == 2 || t.label.contains("Certificate DB"))),
        hardware: false,
        try_empty_pin_first: true,
        retry_wrong_pin: false,
        source: Some(if kind == KeyStoreKind::SharedNss { "NSS".into() } else { "Mozilla Firefox".into() }),
        ..Pkcs11Config::new(kind).with_pin_prompt(prompt)
    }
}

/// Abre la base de datos de certificados y claves de un perfil NSS a
/// través de `softokn3` (§3.6.5): intento con el modo detectado, tras
/// precargar dependencias, y sin `sql:` (bases Berkeley antiguas).
pub fn open_internal(
    lib_dir: &Path,
    profile_dir: &Path,
    kind: KeyStoreKind,
    opts: &NssOptions,
    callback: Arc<dyn PasswordCallback>,
) -> Result<Pkcs11Store, KeyStoreError> {
    let os = Os::current();
    let softokn = lib_dir.join(libdir::softokn_file_name(os));
    let sql = use_sql_db(profile_dir, opts);
    let mut attempts: Vec<(String, bool)> = vec![(nss_init_string(profile_dir, sql, opts.enable_write), false)];
    attempts.push((nss_init_string(profile_dir, sql, opts.enable_write), true));
    if sql {
        attempts.push((nss_init_string(profile_dir, false, opts.enable_write), true));
    }
    let mut last_err = None;
    for (init, preload) in attempts {
        if preload {
            preload_dependencies(lib_dir, os);
        }
        let module = match Pkcs11Module::load_with_init(&softokn, Some(&init)) {
            Ok(m) => m,
            Err(e) => {
                tracing::info!("No se ha podido cargar NSS ({}): {e}", init.replace(&*profile_dir.to_string_lossy(), "USERHOME"));
                last_err = Some(e);
                continue;
            }
        };
        let mut config = internal_config(kind);
        config.nss_init = Some(init);
        return Pkcs11Store::open_module(module, config, callback);
    }
    Err(match last_err {
        Some(KeyStoreError::LibraryNotFound(p)) => KeyStoreError::LibraryNotFound(p),
        Some(e) => KeyStoreError::load(KeyStoreKind::MozUni, format!("Ocurrio un error al configurar el proveedor de acceso a NSS: {e}")),
        None => KeyStoreError::load(KeyStoreKind::MozUni, "Ocurrio un error al configurar el proveedor de acceso a NSS"),
    })
}

/// Indica si Firefox está disponible (perfil y bibliotecas NSS
/// localizables), como `MozillaKeyStoreUtilities.isFirefoxAvailable`.
pub fn is_firefox_available(env: &MozEnv) -> bool {
    match firefox_profile_dir(env) {
        Ok(p) => libdir::nss_lib_dir(env, Some(&p)).is_ok(),
        Err(_) => false,
    }
}

/// Módulos PKCS#11 externos de un perfil, filtrados.
pub fn external_modules(profile_dir: &Path, env: &MozEnv, filter: &ModuleFilter) -> Vec<ExternalModule> {
    let opts = NssOptions::from_env(env);
    let mods = modules::read_profile_modules(profile_dir, env.os, opts.nss_default_db_sql);
    modules::filter_modules(mods, filter, env.os)
}

/// Directorio de bibliotecas del sistema de Windows para los módulos
/// conocidos (`System32`, o `SysWOW64` en un proceso de 32 bits).
pub fn windows_system_dir(env: &MozEnv) -> Option<PathBuf> {
    let root = env.var("SystemRoot").or_else(|| env.var("SYSTEMROOT"))?;
    let sub = if cfg!(target_pointer_width = "32") && env.var("ProgramFiles(x86)").is_some() { "SysWOW64" } else { "System32" };
    Some(Path::new(root).join(sub))
}

/// Abre módulos externos de Firefox en orden; por defecto (paridad con
/// Java) se detiene en el primero que se abre con algún token. Cancelar el
/// PIN de un módulo pasa al siguiente; en Linux cada módulo se reintenta una
/// vez si falla.
pub fn open_external_modules(
    modules: &[ExternalModule],
    kind: KeyStoreKind,
    callback: Arc<dyn PasswordCallback>,
    load_all: bool,
) -> Vec<Pkcs11Store> {
    let mut out = Vec::new();
    for m in modules {
        let config = Pkcs11Config::new(kind).with_name(m.description.clone()).with_pin_prompt(crate::kind::prompts::firefox_module(&m.description));
        let lib = PathBuf::from(&m.lib);
        let mut result = Pkcs11Store::open(&lib, config.clone(), callback.clone());
        if matches!(result, Err(ref e) if !e.is_cancelled()) && Os::current() == Os::Linux {
            result = Pkcs11Store::open(&lib, config, callback.clone());
        }
        match result {
            Ok(s) if !s.tokens().is_empty() => {
                tracing::info!("Cargado el modulo PKCS#11 externo de Mozilla '{}'", m.description);
                out.push(s);
                if !load_all {
                    break;
                }
            }
            Ok(_) => tracing::info!("El modulo PKCS#11 '{}' no tiene ningun token", m.description),
            Err(e) if e.is_cancelled() => tracing::info!("Cancelada la carga del modulo PKCS#11 '{}'", m.description),
            Err(e) => tracing::warn!("No se ha podido cargar el modulo PKCS#11 '{}': {e}", m.description),
        }
    }
    out
}

#[cfg(test)]
mod tests;
