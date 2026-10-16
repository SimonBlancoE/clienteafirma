//! Apertura de almacenes por tipo (`AOKeyStoreManagerFactory`, §1.3) con la
//! composición de los almacenes agregados (§3.1, §3.3, §3.6) y la caché de
//! almacenes abiertos.
//!
//! El selector de ficheros que muestra Java cuando falta el fichero PKCS#12
//! o la biblioteca PKCS#11 es responsabilidad de la interfaz: aquí se
//! devuelve [`KeyStoreError::FileNotFound`] / [`KeyStoreError::LibraryNotFound`].

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use crate::callback::PasswordCallback;
use crate::error::KeyStoreError;
use crate::kind::{KeyStoreKind, Os};
use crate::nss::{self, ModuleFilter, MozEnv, NssOptions};
use crate::pkcs11::{Pkcs11Config, Pkcs11Store};
use crate::pkcs12_store::{Pkcs12Options, Pkcs12Store};
use crate::selection::StoreSpec;
use crate::smartcard::{self, Preferred, SmartcardOptions};
use crate::store::{AggregateStore, KeyStore};

/// Interruptores por variables de entorno (§1.5). Java lee además
/// propiedades del sistema; aquí solo variables de entorno (las que en Java
/// eran solo propiedades tienen un nombre de variable nuevo).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvSwitches {
    /// `AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER`
    pub disable_dnie_native_driver: bool,
    /// `AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER`
    pub disable_ceres_native_driver: bool,
    /// `AFIRMA_NSS_ENABLE_GYDSC_NATIVE_DRIVER`
    pub enable_gydsc_native_driver: bool,
    /// `AFIRMA_NSS_LOAD_SSCD_ONLY`: en los almacenes de Mozilla, omitir el
    /// almacén interno de NSS.
    pub load_sscd_only: bool,
    /// `AFIRMA_FORCE_STORE_RESET` (Java: `es.gob.afirma.keystores.ForceReset`).
    pub force_reset: bool,
    /// `AFIRMA_DO_NOT_REUSE_PKCS11_PROVIDER` (Java:
    /// `es.gob.afirma.keystores.DoNotReusePkcs11Provider`).
    pub do_not_reuse_pkcs11: bool,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v.eq_ignore_ascii_case("true"))
}

impl EnvSwitches {
    pub fn from_env() -> EnvSwitches {
        EnvSwitches {
            disable_dnie_native_driver: env_flag("AFIRMA_NSS_DISABLE_DNIE_NATIVE_DRIVER")
                || env_flag("es.gob.afirma.keystores.mozilla.disableDnieNativeDriver"),
            disable_ceres_native_driver: env_flag("AFIRMA_NSS_DISABLE_CERES_NATIVE_DRIVER")
                || env_flag("es.gob.afirma.keystores.mozilla.disableCeresNativeDriver"),
            enable_gydsc_native_driver: env_flag("AFIRMA_NSS_ENABLE_GYDSC_NATIVE_DRIVER"),
            load_sscd_only: env_flag("AFIRMA_NSS_LOAD_SSCD_ONLY"),
            force_reset: env_flag("AFIRMA_FORCE_STORE_RESET") || env_flag("es.gob.afirma.keystores.ForceReset"),
            do_not_reuse_pkcs11: env_flag("AFIRMA_DO_NOT_REUSE_PKCS11_PROVIDER") || env_flag("es.gob.afirma.keystores.DoNotReusePkcs11Provider"),
        }
    }
}

/// Opciones de apertura.
#[derive(Clone)]
pub struct OpenOptions {
    /// Proveedor de contraseñas y PIN.
    pub callback: Arc<dyn PasswordCallback>,
    /// No reutilizar almacenes abiertos antes (Java `forceReset`).
    pub force_reset: bool,
    /// Preferencia `enabledJmulticard` (por defecto, verdadera).
    pub enabled_smartcard_drivers: bool,
    pub switches: EnvSwitches,
    pub pkcs12: Pkcs12Options,
    /// Bibliotecas de tarjeta a probar (`None` = detección automática).
    pub smartcard_modules: Option<Vec<PathBuf>>,
    /// Mejora opcional: cargar todos los módulos PKCS#11 externos de
    /// Firefox con token (Java solo carga el primero que funciona).
    pub load_all_external_modules: bool,
    /// Mejora opcional: eliminar duplicados entre todos los subalmacenes.
    pub dedup_all: bool,
    /// Entorno para localizar Firefox/NSS (`None` = el del proceso).
    pub moz_env: Option<MozEnv>,
    /// Descripción del llamante (Java: `"CommandLine"`, etc.), solo para el
    /// registro.
    pub description: Option<String>,
}

impl std::fmt::Debug for OpenOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenOptions")
            .field("force_reset", &self.force_reset)
            .field("enabled_smartcard_drivers", &self.enabled_smartcard_drivers)
            .field("switches", &self.switches)
            .finish_non_exhaustive()
    }
}

impl OpenOptions {
    pub fn new(callback: Arc<dyn PasswordCallback>) -> Self {
        OpenOptions {
            callback,
            force_reset: false,
            enabled_smartcard_drivers: true,
            switches: EnvSwitches::from_env(),
            pkcs12: Pkcs12Options::default(),
            smartcard_modules: None,
            load_all_external_modules: false,
            dedup_all: false,
            moz_env: None,
            description: None,
        }
    }

    fn smartcard(&self) -> SmartcardOptions {
        SmartcardOptions {
            enabled: self.enabled_smartcard_drivers,
            disable_dnie: self.switches.disable_dnie_native_driver,
            disable_ceres: self.switches.disable_ceres_native_driver,
            enable_smartcafe: self.switches.enable_gydsc_native_driver,
            modules: self.smartcard_modules.clone(),
        }
    }

    fn env(&self) -> MozEnv {
        self.moz_env.clone().unwrap_or_else(MozEnv::current)
    }
}

type CacheKey = (KeyStoreKind, Option<String>, Option<String>);
type StoreCache = Mutex<Vec<(CacheKey, Arc<dyn KeyStore>)>>;

fn cache() -> &'static StoreCache {
    static C: OnceLock<StoreCache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Vec::new()))
}

/// Vacía la caché de almacenes abiertos (las sesiones PKCS#11 y NSS se
/// cierran cuando no queden otras referencias).
pub fn clear_store_cache() {
    if let Ok(mut c) = cache().lock() {
        c.clear();
    }
}

/// Tipos que se reutilizan entre operaciones (mantienen el PIN o la
/// inicialización de NSS, como los proveedores cacheados de Java).
fn cacheable(kind: KeyStoreKind, switches: &EnvSwitches) -> bool {
    match kind {
        KeyStoreKind::Pkcs11 => !switches.do_not_reuse_pkcs11,
        KeyStoreKind::MozUni | KeyStoreKind::MozUniWithOs | KeyStoreKind::SharedNss => true,
        KeyStoreKind::DnieJava | KeyStoreKind::Ceres | KeyStoreKind::Ceres430 | KeyStoreKind::SmartCafe => true,
        _ => false,
    }
}

/// Abre el almacén indicado.
pub fn open_store(spec: &StoreSpec, opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    let key: CacheKey = (spec.kind, spec.lib.clone(), spec.card_name.clone());
    let force = opts.force_reset || opts.switches.force_reset;
    if let Ok(mut c) = cache().lock() {
        if force {
            c.retain(|(k, _)| *k != key);
        } else if let Some((_, s)) = c.iter().find(|(k, _)| *k == key) {
            return Ok(s.clone());
        }
        if spec.kind.is_mozilla() {
            // NSS solo admite un perfil por proceso: se liberan los demás
            // almacenes NSS de la caché para poder reinicializarlo.
            c.retain(|(k, _)| !k.0.is_mozilla() || k.0 == spec.kind);
        }
    }
    let store = open_uncached(spec, opts)?;
    if cacheable(spec.kind, &opts.switches) {
        if let Ok(mut c) = cache().lock() {
            c.retain(|(k, _)| *k != key);
            c.push((key, store.clone()));
        }
    }
    Ok(store)
}

fn open_uncached(spec: &StoreSpec, opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    let os = Os::current();
    tracing::info!("Apertura del almacén {} ({})", spec.kind.id(), opts.description.as_deref().unwrap_or("AutoFirma"));
    match spec.kind {
        KeyStoreKind::Pkcs12 => {
            let path = spec.lib.as_deref().filter(|l| !l.is_empty()).map(PathBuf::from).ok_or_else(|| KeyStoreError::FileNotFound(PathBuf::new()))?;
            Ok(Arc::new(Pkcs12Store::open(&path, opts.callback.as_ref(), opts.pkcs12)?))
        }
        KeyStoreKind::Pkcs11 => {
            let lib = spec.lib.as_deref().filter(|l| !l.is_empty()).map(PathBuf::from).ok_or_else(|| KeyStoreError::LibraryNotFound(PathBuf::new()))?;
            if !lib.is_file() {
                return Err(KeyStoreError::LibraryNotFound(lib));
            }
            let mut config = Pkcs11Config::new(KeyStoreKind::Pkcs11);
            if let Some(n) = &spec.card_name {
                config = config.with_name(n.clone());
            }
            Ok(Arc::new(Pkcs11Store::open(&lib, config, opts.callback.clone())?))
        }
        KeyStoreKind::Single => {
            let path = spec.lib.as_deref().filter(|l| !l.is_empty()).map(PathBuf::from).ok_or_else(|| KeyStoreError::FileNotFound(PathBuf::new()))?;
            Ok(Arc::new(crate::single::SingleCertStore::open(&path)?))
        }
        KeyStoreKind::Windows if os == Os::Windows => open_windows(opts),
        KeyStoreKind::WinAddressBook | KeyStoreKind::WinCa if os == Os::Windows => open_windows_public(spec.kind),
        KeyStoreKind::MozUni | KeyStoreKind::MozUniWithOs => open_mozilla(spec.kind, opts),
        KeyStoreKind::SharedNss if os == Os::Linux => open_shared_nss(opts),
        KeyStoreKind::Apple if os == Os::MacOs => open_apple(opts),
        KeyStoreKind::DnieJava | KeyStoreKind::Ceres430 | KeyStoreKind::Ceres | KeyStoreKind::SmartCafe => {
            Ok(Arc::new(smartcard::open_card_store(spec.kind, &opts.smartcard(), opts.callback.clone())?))
        }
        other => Err(other.unsupported_error(os)),
    }
}

/// Añade al agregado la tarjeta preferente, si la hay. Devuelve si se
/// encontró y si el usuario canceló.
fn add_preferred(agg: &AggregateStore, opts: &OpenOptions) -> (bool, bool) {
    match smartcard::probe_preferred(&opts.smartcard(), opts.callback.clone()) {
        Preferred::Found(s) => {
            agg.add(s);
            (true, false)
        }
        Preferred::None => (false, false),
        Preferred::Cancelled => (false, true),
    }
}

#[cfg(windows)]
fn open_windows(opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    use crate::capi::{CapiStore, SystemStore};
    let agg = AggregateStore::new(KeyStoreKind::Windows).with_dedup_all(opts.dedup_all);
    let temporary = crate::selection::is_current_temporary_profile();
    let capi: Option<Arc<CapiStore>> = if temporary {
        tracing::info!("Perfil temporal de Windows: se omite el almacen de Windows");
        None
    } else {
        match CapiStore::open(SystemStore::My) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                tracing::warn!("No se ha podido cargar el almacen de Windows: {e}");
                None
            }
        }
    };
    if let Some(c) = &capi {
        agg.add(c.clone());
    }
    let (preferred, cancelled) = add_preferred(&agg, opts);
    if temporary && !preferred {
        if let Some(s) = smartcard::open_known_smartcards(opts.callback.clone(), cancelled) {
            agg.add(Arc::new(s));
        }
    }
    if let (Some(c), false) = (&capi, preferred) {
        // El sondeo de la tarjeta puede quitar el lector al minidriver de
        // Windows: se vuelve a abrir el almacén.
        if let Err(e) = c.refresh() {
            tracing::warn!("Error al resfrescar el almacén de claves de Windows: {e}");
        }
    }
    Ok(Arc::new(agg))
}

#[cfg(not(windows))]
fn open_windows(_opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    Err(KeyStoreKind::Windows.unsupported_error(Os::current()))
}

#[cfg(windows)]
fn open_windows_public(kind: KeyStoreKind) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    use crate::capi::{CapiStore, SystemStore};
    let store = if kind == KeyStoreKind::WinAddressBook { SystemStore::AddressBook } else { SystemStore::Ca };
    Ok(Arc::new(CapiStore::open(store)?))
}

#[cfg(not(windows))]
fn open_windows_public(kind: KeyStoreKind) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    Err(kind.unsupported_error(Os::current()))
}

#[cfg(target_os = "macos")]
fn open_apple(opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    use crate::keychain::{KeychainOptions, KeychainStore};
    let agg = AggregateStore::new(KeyStoreKind::Apple).with_dedup_all(opts.dedup_all);
    agg.add(Arc::new(KeychainStore::open(KeychainOptions::default())?));
    // La cancelación del sondeo de tarjetas se registra y se ignora.
    add_preferred(&agg, opts);
    Ok(Arc::new(agg))
}

#[cfg(not(target_os = "macos"))]
fn open_apple(_opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    Err(KeyStoreKind::Apple.unsupported_error(Os::current()))
}

/// Firefox (`MozillaUnifiedKeyStoreManager`, `MozillaUnifiedWithOSKeyStoreManager`):
/// NSS interno, (almacén del sistema), tarjeta preferente y, si no la hay,
/// el primer módulo PKCS#11 externo del perfil que funcione.
fn open_mozilla(kind: KeyStoreKind, opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    let env = opts.env();
    let agg = AggregateStore::new(kind).with_dedup_all(opts.dedup_all);
    let profile = nss::firefox_profile_dir(&env);
    let mut nss_error = None;
    if !opts.switches.load_sscd_only {
        let result = profile.clone().and_then(|p| {
            let lib_dir = nss::libdir::nss_lib_dir(&env, Some(&p))?;
            nss::open_internal(&lib_dir, &p, kind, &NssOptions::from_env(&env), opts.callback.clone())
        });
        match result {
            Ok(s) => agg.add(Arc::new(s)),
            Err(KeyStoreError::Cancelled) => return Err(KeyStoreError::Cancelled),
            Err(e) => {
                tracing::warn!("No se ha podido cargar el almacen interno de Mozilla: {e}");
                nss_error = Some(e);
            }
        }
    }
    if kind == KeyStoreKind::MozUniWithOs {
        let os_store = match Os::current() {
            Os::Windows => Some(open_windows(&OpenOptions { force_reset: true, ..opts.clone() })),
            Os::MacOs => Some(open_apple(opts)),
            _ => None,
        };
        match os_store {
            // Como en Java, la tarjeta se sondea también después (dentro del
            // almacén del sistema y en el de Mozilla); al ser preferente, la
            // segunda oculta los duplicados de la primera y de NSS.
            Some(Ok(s)) => agg.add(s),
            Some(Err(e)) => tracing::warn!("No se ha podido cargar el almacen del sistema operativo: {e}"),
            None => {}
        }
    }
    let (preferred, exclude_native_dnie) = add_preferred(&agg, opts);
    if !preferred {
        if let Ok(p) = &profile {
            let filter = ModuleFilter {
                exclude_native_dnie,
                disable_dnie_native_driver: opts.switches.disable_dnie_native_driver,
                include_known_modules: true,
                windows_system_dir: nss::windows_system_dir(&env),
            };
            let modules = nss::external_modules(p, &env, &filter);
            for s in nss::open_external_modules(&modules, kind, opts.callback.clone(), opts.load_all_external_modules) {
                agg.add(Arc::new(s));
            }
        }
    }
    if agg.is_empty() {
        if let Some(e) = nss_error {
            return Err(match e {
                KeyStoreError::Firefox(m) => KeyStoreError::Firefox(m),
                other => KeyStoreError::load(kind, other.to_string()),
            });
        }
    }
    Ok(Arc::new(agg))
}

/// NSS compartido de Linux (`SharedNssKeyStoreManager`): base de datos
/// `~/.pki/nssdb` (o equivalentes), tarjeta preferente y módulos externos
/// del `pkcs11.txt` de esa base de datos (corrección: Java leía el del
/// perfil de Firefox).
fn open_shared_nss(opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    let env = opts.env();
    let agg = AggregateStore::new(KeyStoreKind::SharedNss).with_dedup_all(opts.dedup_all);
    let dir = nss::shared_nss_dir(&env);
    if !opts.switches.load_sscd_only {
        let result = dir.clone().and_then(|d| {
            let lib_dir = nss::libdir::nss_lib_dir(&env, None)?;
            nss::open_internal(&lib_dir, &d, KeyStoreKind::SharedNss, &NssOptions::from_env(&env), opts.callback.clone())
        });
        match result {
            Ok(s) => agg.add(Arc::new(s)),
            Err(KeyStoreError::Cancelled) => return Err(KeyStoreError::Cancelled),
            Err(e) => tracing::warn!("No se ha podido cargar el almacen NSS compartido: {e}"),
        }
    }
    let (preferred, cancelled) = add_preferred(&agg, opts);
    if !preferred {
        if let Ok(d) = &dir {
            let filter = ModuleFilter {
                exclude_native_dnie: cancelled,
                disable_dnie_native_driver: opts.switches.disable_dnie_native_driver,
                include_known_modules: false,
                windows_system_dir: None,
            };
            let modules = nss::external_modules(d, &env, &filter);
            for s in nss::open_external_modules(&modules, KeyStoreKind::SharedNss, opts.callback.clone(), opts.load_all_external_modules) {
                agg.add(Arc::new(s));
            }
        }
    }
    Ok(Arc::new(agg))
}

/// Abre el almacén por defecto del sistema operativo actual.
pub fn open_default_store(opts: &OpenOptions) -> Result<Arc<dyn KeyStore>, KeyStoreError> {
    open_store(&StoreSpec::new(KeyStoreKind::default_for_current_os()?), opts)
}

/// Abre el almacén pedido y, si falla por algo distinto de una cancelación
/// o de una contraseña errónea, el del sistema (comportamiento de los
/// flujos del protocolo y de la aplicación). Devuelve también el error
/// original, si lo hubo, para que la interfaz pueda informar
/// ("No se ha podido obtener el almacén de claves por defecto…").
pub fn open_with_fallback(spec: &StoreSpec, opts: &OpenOptions) -> Result<(Arc<dyn KeyStore>, Option<KeyStoreError>), KeyStoreError> {
    match open_store(spec, opts) {
        Ok(s) => Ok((s, None)),
        Err(e) if e.is_cancelled() || matches!(e, KeyStoreError::WrongPassword { .. }) => Err(e),
        Err(e) => {
            let default = KeyStoreKind::default_for_current_os()?;
            if default == spec.kind {
                return Err(e);
            }
            tracing::warn!("No se ha podido abrir el almacen {}: {e}. Se cargara el del sistema", spec.kind.id());
            let s = open_store(&StoreSpec::new(default), opts)?;
            Ok((s, Some(e)))
        }
    }
}

/// Comprueba que una biblioteca PKCS#11 se puede cargar e inicializar
/// (botón "Conectar" de las tarjetas registradas en preferencias).
pub fn test_pkcs11_library(lib: &Path, name: &str, callback: Arc<dyn PasswordCallback>) -> Result<usize, KeyStoreError> {
    let store = Pkcs11Store::open(lib, Pkcs11Config::new(KeyStoreKind::Pkcs11).with_name(name), callback)?;
    Ok(store.entries()?.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::callback::{FixedPassword, NoPassword};
    use std::sync::Mutex;

    #[test]
    fn dispatch_and_unsupported() {
        let opts = OpenOptions::new(Arc::new(FixedPassword::new("12341234")));
        let p12 = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki/firmante-ec.p12");
        let s = open_store(&StoreSpec::with_lib(KeyStoreKind::Pkcs12, p12.to_string_lossy()), &opts).unwrap();
        assert_eq!(s.aliases().unwrap(), vec!["firmante-ec".to_string()]);
        assert!(matches!(open_store(&StoreSpec::new(KeyStoreKind::Pkcs12), &opts), Err(KeyStoreError::FileNotFound(_))));
        assert!(matches!(
            open_store(&StoreSpec::with_lib(KeyStoreKind::Pkcs11, "/no/existe.so"), &opts),
            Err(KeyStoreError::LibraryNotFound(_))
        ));
        for k in [KeyStoreKind::Temd, KeyStoreKind::Other, KeyStoreKind::KnownSmartcards, KeyStoreKind::Java] {
            let e = open_store(&StoreSpec::new(k), &opts).err().unwrap();
            assert_eq!(e.code().code, 600011, "{k:?}");
        }
        if Os::current() != Os::Windows {
            let e = open_store(&StoreSpec::new(KeyStoreKind::Windows), &opts).err().unwrap();
            assert!(matches!(e, KeyStoreError::Unsupported { alternative: Some(_), .. }));
        }
    }

    #[test]
    fn card_store_without_card_or_modules() {
        let mut opts = OpenOptions::new(Arc::new(NoPassword));
        opts.smartcard_modules = Some(vec![]);
        assert!(matches!(open_store(&StoreSpec::new(KeyStoreKind::DnieJava), &opts), Err(KeyStoreError::CardNotPresent)));
        assert!(matches!(smartcard::probe_preferred(&opts.smartcard(), opts.callback.clone()), Preferred::None));
        opts.enabled_smartcard_drivers = false;
        assert!(matches!(smartcard::probe_preferred(&opts.smartcard(), opts.callback.clone()), Preferred::None));
    }

    /// Firefox de extremo a extremo (requiere SoftHSM2 y las herramientas de
    /// NSS: ver `tools/oracle/keystores-softhsm.sh`): perfil con base de
    /// datos NSS propia y SoftHSM registrado como módulo externo en
    /// `pkcs11.txt`; después, con un token "DNIe" en SoftHSM como tarjeta
    /// preferente, que oculta los duplicados y evita cargar los módulos
    /// externos.
    #[test]
    fn softhsm_firefox_unified_with_external_module_and_preferred_card() {
        use crate::pkcs11::tests::{DNIE_TOKEN_LABEL, SOFTHSM, USER_PIN, prepare_dnie_token, prepare_token, softhsm_lib};
        use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
        use std::process::Command;
        let Some(lib) = softhsm_lib() else { return };
        if Command::new("modutil").arg("-help").output().is_err() || Command::new("pk12util").arg("-h").output().is_err() {
            eprintln!("modutil/pk12util no disponibles: se omite la prueba");
            return;
        }
        let _s = SOFTHSM.lock().unwrap_or_else(|e| e.into_inner());
        let _n = crate::NSS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_store_cache();
        let _module = prepare_token(&lib);
        // Perfil de Firefox en un directorio personal ficticio.
        let home = tempfile::tempdir().unwrap();
        let ff = home.path().join(".mozilla/firefox");
        let profile = ff.join("p.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        let db = format!("sql:{}", profile.display());
        assert!(Command::new("certutil").args(["-N", "-d", &db, "--empty-password"]).status().unwrap().success());
        let p12 = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki/firmante-rsa.p12");
        assert!(Command::new("pk12util").args(["-i"]).arg(&p12).args(["-d", &db, "-W", "12341234", "-K", ""]).status().unwrap().success());
        assert!(
            Command::new("modutil")
                .args(["-dbdir", &db, "-add", "SoftHSM pruebas", "-libfile"])
                .arg(&lib)
                .arg("-force")
                .status()
                .unwrap()
                .success()
        );
        for i in 0..10 {
            std::fs::write(profile.join(format!("relleno{i}")), b"x").unwrap();
        }
        std::fs::write(ff.join("profiles.ini"), "[Profile0]\nName=default-release\nIsRelative=1\nPath=p.default-release\nDefault=1\n").unwrap();
        let prompts = Arc::new(Mutex::new(Vec::<String>::new()));
        let p2 = prompts.clone();
        let cb = Arc::new(crate::callback::FnPasswordCallback(move |r: &crate::PasswordRequest| {
            p2.lock().unwrap().push(r.prompt.clone());
            crate::PasswordResponse::provided(USER_PIN)
        }));
        let mut opts = OpenOptions::new(cb);
        opts.moz_env = Some(MozEnv { os: Os::current(), home: home.path().to_path_buf(), user_name: None, vars: Default::default() });
        opts.smartcard_modules = Some(vec![]);
        opts.force_reset = true;
        // 1) Sin tarjeta preferente: NSS + primer módulo externo (SoftHSM).
        let store = open_store(&StoreSpec::new(KeyStoreKind::MozUni), &opts).unwrap();
        assert_eq!(store.kind(), KeyStoreKind::MozUni);
        assert!(prompts.lock().unwrap().iter().all(|p| p == "Introduzca la contraseña de SoftHSM pruebas"), "{prompts:?}");
        let entries = store.entries().unwrap();
        let ids: Vec<&str> = entries.iter().filter(|e| e.capabilities.has_private_key).map(|e| e.id.as_str()).collect();
        // El mismo certificado en NSS y en SoftHSM: sin eliminar duplicados
        // (paridad con Java), con identificadores distintos.
        assert!(ids.contains(&"0:firmante-rsa") && ids.contains(&"1:firmante-rsa") && ids.contains(&"1:firmante-ec"), "{ids:?}");
        let k = store.signing_key("1:firmante-ec").unwrap();
        crate::verify::sign_and_verify(k.as_ref(), b"x", SignatureAlgorithm::new(DigestAlgorithm::Sha384, KeyAlgorithm::Ec)).unwrap();
        // La caché devuelve el mismo almacén.
        let again = open_store(&StoreSpec::new(KeyStoreKind::MozUni), &OpenOptions { force_reset: false, ..opts.clone() }).unwrap();
        assert!(Arc::ptr_eq(&store, &again));
        drop((store, again, k));
        // 2) Con un "DNIe" en SoftHSM como tarjeta preferente.
        let _ = prepare_dnie_token(&lib);
        prompts.lock().unwrap().clear();
        opts.smartcard_modules = Some(vec![lib.clone()]);
        let store = open_store(&StoreSpec::new(KeyStoreKind::MozUni), &opts).unwrap();
        let keyed: Vec<CertEntryView> = store
            .entries()
            .unwrap()
            .into_iter()
            .filter(|e| e.capabilities.has_private_key)
            .map(|e| CertEntryView { id: e.id, alias: e.alias, pin_at_sign: e.capabilities.pin_at_sign })
            .collect();
        // El certificado de NSS queda oculto por la tarjeta y no se cargan
        // módulos externos.
        assert_eq!(keyed.len(), 1, "{keyed:?}");
        assert_eq!(keyed[0].alias, "CertFirmaDigital");
        assert!(keyed[0].pin_at_sign);
        assert!(prompts.lock().unwrap().is_empty(), "sin PIN al abrir");
        let k = store.signing_key("CertFirmaDigital").unwrap();
        crate::verify::sign_and_verify(k.as_ref(), b"x", SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa)).unwrap();
        assert_eq!(*prompts.lock().unwrap(), vec!["Por favor, introduzca el PIN del DNIe.".to_string()]);
        let _ = DNIE_TOKEN_LABEL;
        drop((store, k));
        clear_store_cache();
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct CertEntryView {
        id: String,
        alias: String,
        pin_at_sign: bool,
    }

    #[test]
    fn fallback_to_system_store() {
        let _g = crate::NSS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut opts = OpenOptions::new(Arc::new(NoPassword));
        opts.smartcard_modules = Some(vec![]);
        // Fichero inexistente → se abre el del sistema (si está disponible
        // en este equipo) y se devuelve el error original.
        if let Ok((s, err)) = open_with_fallback(&StoreSpec::with_lib(KeyStoreKind::Pkcs12, "/no/existe.p12"), &opts) {
            assert_eq!(Some(s.kind()), KeyStoreKind::default_for(Os::current()));
            assert!(matches!(err, Some(KeyStoreError::FileNotFound(_))));
        }
        clear_store_cache();
    }
}
