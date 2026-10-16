//! Almacenes PKCS#11 (`PKCS11`, tarjetas registradas, módulos externos de
//! Firefox, DNIe/CERES a través de controladores PKCS#11 y el módulo interno
//! de NSS).
//!
//! Comportamiento (especificación §3.5):
//! - La biblioteca se inicializa una vez por proceso mientras esté en uso
//!   ([`Pkcs11Module`], caché por ruta) y se reintenta una vez si
//!   `C_Initialize` o el primer `C_GetSlotList` fallan.
//! - Se recorren todas las ranuras con token (mejora; Java usa solo la
//!   primera ranura, disponible con [`SlotSelection::FirstSlot`]).
//! - El PIN se pide al abrir el almacén ([`PinTiming::AtOpen`], PKCS#11
//!   genérico y módulos de Firefox) o al firmar ([`PinTiming::AtSign`],
//!   DNIe/CERES, con los textos de jmulticard, caché opcional de 1 h y
//!   confirmación de firma del DNIe). Si el token tiene ruta de autenticación
//!   protegida (teclado del lector) se llama a `C_Login` sin PIN.
//! - PIN erróneo → se vuelve a preguntar mostrando "La contraseña
//!   introducida no es correcta." (solo con un llamante interactivo);
//!   longitud errónea → "La longitud de la contraseña introducida no es
//!   válida."; PIN bloqueado → [`KeyStoreError::Locked`]; cancelación →
//!   [`KeyStoreError::Cancelled`].
//! - Entradas: certificados `CKO_CERTIFICATE`/`CKC_X_509` emparejados con
//!   claves privadas por `CKA_ID`; alias = `CKA_LABEL` del certificado (o de
//!   la clave, o el `CKA_ID`), únicos con `" (n)"`.
//! - Firma RSA con `CKM_SHA*_RSA_PKCS` si el token lo admite (salvo
//!   `CKM_SHA1_RSA_PKCS` en las bibliotecas FNMT de la tabla 1.4) o con
//!   `CKM_RSA_PKCS` sobre `DigestInfo`; ECDSA con `CKM_ECDSA` sobre la huella
//!   (truncada al orden de la curva) y conversión de `r‖s` a DER.
//! - La sesión (y el inicio de sesión) se mantiene mientras viva el almacén o
//!   alguna clave obtenida de él; si se extrae la tarjeta, la firma devuelve
//!   `DeviceUnavailable` y la siguiente operación abre una sesión nueva.

pub mod known;
pub(crate) mod raw;

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::key::{KeyError, SigningKey};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::callback::{ConfirmRequest, PasswordCallback, PasswordKind, PasswordRequest, PasswordResponse, PinCache, RetryReason};
use crate::error::KeyStoreError;
use crate::kind::{KeyStoreKind, prompts};
use crate::store::{AliasSet, CertEntry, EntryCapabilities, KeyStore, find_entry};
use crate::verify::{EcCurve, certificate_curve, certificate_key_algorithm, ecdsa_raw_to_der, ecdsa_truncate_hash};

pub use known::CardFamily;

/// Momento en que se pide el PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinTiming {
    /// Al abrir el almacén (PKCS#11 genérico, módulos de Firefox, NSS).
    AtOpen,
    /// Al firmar, en cada firma salvo que el usuario pida recordarlo
    /// (DNIe/CERES, como jmulticard).
    AtSign,
}

/// Ranuras que se usan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotSelection {
    /// Todas las ranuras con token presente (mejora sobre Java).
    AllTokens,
    /// Solo la primera ranura de `C_GetSlotList(FALSE)` (paridad con
    /// SunPKCS11 `slotListIndex=0`).
    FirstSlot,
    /// Ranura concreta por identificador (`slot=` de SunPKCS11).
    SlotId(u64),
}

/// Textos de diálogo de tarjeta (jmulticard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardDialogs {
    /// DNIe: "Por favor, introduzca el PIN del DNIe." + confirmación de firma.
    Dnie,
    /// Otras tarjetas (CERES): "Por favor, introduzca el PIN de la tarjeta."
    Card,
}

/// Datos de un token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenDescription {
    pub slot_id: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub family: CardFamily,
    pub login_required: bool,
    pub protected_authentication_path: bool,
    /// Token inicializado y con PIN de usuario (los no inicializados, p. ej.
    /// la ranura libre de SoftHSM, se omiten).
    pub initialized: bool,
}

/// Filtro de tokens (p. ej. solo DNIe).
pub type TokenFilter = Arc<dyn Fn(&TokenDescription) -> bool + Send + Sync>;

/// Configuración de un almacén PKCS#11.
#[derive(Clone)]
pub struct Pkcs11Config {
    /// Tipo que se informa (`PKCS11`, `DNIEJAVA`, `CERES`, `MOZ_UNI`...).
    pub kind: KeyStoreKind,
    /// Nombre del almacén (tarjeta registrada o descripción del módulo de
    /// Firefox); se usa en el título del diálogo y en el texto del PIN.
    pub name: Option<String>,
    /// Texto de petición de PIN personalizado.
    pub pin_prompt: Option<String>,
    pub pin_timing: PinTiming,
    /// Diálogos de tarjeta de jmulticard (solo con [`PinTiming::AtSign`]).
    pub card_dialogs: Option<CardDialogs>,
    pub slots: SlotSelection,
    pub token_filter: Option<TokenFilter>,
    /// Almacén preferente (oculta duplicados en un agregado).
    pub preferred: bool,
    /// Las claves están en hardware (falso para el módulo interno de NSS).
    pub hardware: bool,
    /// Probar primero un PIN vacío (contraseña maestra de NSS).
    pub try_empty_pin_first: bool,
    /// Volver a pedir el PIN si es erróneo (con un llamante interactivo).
    /// NSS no reintenta la contraseña maestra.
    pub retry_wrong_pin: bool,
    /// Etiqueta de origen de las entradas (por defecto, el nombre del fichero).
    pub source: Option<String>,
    /// Cadena de inicialización de NSS (`pReserved`).
    pub(crate) nss_init: Option<String>,
}

impl std::fmt::Debug for Pkcs11Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Config")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("pin_timing", &self.pin_timing)
            .field("slots", &self.slots)
            .field("preferred", &self.preferred)
            .finish_non_exhaustive()
    }
}

impl Pkcs11Config {
    /// Configuración de un PKCS#11 genérico (PIN al abrir, todas las
    /// ranuras con token).
    pub fn new(kind: KeyStoreKind) -> Self {
        Pkcs11Config {
            kind,
            name: None,
            pin_prompt: None,
            pin_timing: PinTiming::AtOpen,
            card_dialogs: None,
            slots: SlotSelection::AllTokens,
            token_filter: None,
            preferred: false,
            hardware: true,
            try_empty_pin_first: false,
            retry_wrong_pin: true,
            source: None,
            nss_init: None,
        }
    }

    /// Configuración para una tarjeta "preferente" (DNIe/CERES): PIN al
    /// firmar con los diálogos de jmulticard y solo los tokens de la familia
    /// indicada.
    pub fn card_driver(kind: KeyStoreKind, family: CardFamily) -> Self {
        let dialogs = if family == CardFamily::Dnie { CardDialogs::Dnie } else { CardDialogs::Card };
        Pkcs11Config {
            pin_timing: PinTiming::AtSign,
            card_dialogs: Some(dialogs),
            token_filter: Some(Arc::new(move |t: &TokenDescription| t.family == family)),
            preferred: true,
            ..Pkcs11Config::new(kind)
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_pin_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.pin_prompt = Some(prompt.into());
        self
    }

    pub fn with_slots(mut self, slots: SlotSelection) -> Self {
        self.slots = slots;
        self
    }
}

// ---------------------------------------------------------------------------
// Módulo (biblioteca) PKCS#11
// ---------------------------------------------------------------------------

/// Biblioteca PKCS#11 cargada e inicializada. Se comparte por proceso
/// mientras esté en uso (`C_Finalize` al liberarse la última referencia).
pub struct Pkcs11Module {
    path: PathBuf,
    nss_init: Option<String>,
    // Orden de destrucción: primero el contexto (C_Finalize) y después la
    // biblioteca cargada en `raw`.
    ctx: Pkcs11,
    raw: raw::RawModule,
}

impl std::fmt::Debug for Pkcs11Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Module").field("path", &self.path).finish_non_exhaustive()
    }
}

type ModuleCache = Mutex<Vec<(PathBuf, Weak<Pkcs11Module>)>>;

fn module_cache() -> &'static ModuleCache {
    static CACHE: OnceLock<ModuleCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

impl Pkcs11Module {
    /// Carga (o reutiliza) e inicializa una biblioteca PKCS#11.
    pub fn load(path: &Path) -> Result<Arc<Pkcs11Module>, KeyStoreError> {
        Self::load_with_init(path, None)
    }

    pub(crate) fn load_with_init(path: &Path, nss_init: Option<&str>) -> Result<Arc<Pkcs11Module>, KeyStoreError> {
        if !path.is_file() {
            return Err(KeyStoreError::LibraryNotFound(path.to_path_buf()));
        }
        let key = canonical(path);
        let mut cache = module_cache().lock().map_err(|_| KeyStoreError::load(KeyStoreKind::Pkcs11, "caché de módulos PKCS#11 inutilizable"))?;
        cache.retain(|(_, w)| w.strong_count() > 0);
        if let Some(m) = cache.iter().find(|(p, _)| *p == key).and_then(|(_, w)| w.upgrade()) {
            if m.nss_init.as_deref() == nss_init {
                return Ok(m);
            }
            return Err(KeyStoreError::load(
                KeyStoreKind::Pkcs11,
                format!("La biblioteca '{}' ya está inicializada con otra configuración en este proceso", path.display()),
            ));
        }
        // "El PKCS#11 del DNIe a veces falla a la primera": un reintento.
        let module = match Self::init(path, nss_init) {
            Ok(m) => m,
            Err(first) => {
                tracing::warn!("Error inicializando el PKCS#11 '{}', se reintenta: {first}", path.display());
                Self::init(path, nss_init)?
            }
        };
        let module = Arc::new(module);
        cache.push((key, Arc::downgrade(&module)));
        Ok(module)
    }

    fn init(path: &Path, nss_init: Option<&str>) -> Result<Pkcs11Module, KeyStoreError> {
        let load_err = |m: String| KeyStoreError::load(KeyStoreKind::Pkcs11, format!("No se ha podido cargar la biblioteca PKCS#11 '{}': {m}", path.display()));
        let raw = raw::RawModule::load(path).map_err(load_err)?;
        let ctx = Pkcs11::new(path).map_err(|e| load_err(e.to_string()))?;
        match nss_init {
            Some(args) => {
                let c = CString::new(args).map_err(|_| load_err("cadena de inicialización no válida".into()))?;
                match raw.initialize(Some(&c)) {
                    Ok(()) => {}
                    Err(rv) if rv == cryptoki_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED => {}
                    Err(rv) => return Err(load_err(format!("C_Initialize devolvió {rv:#x}"))),
                }
            }
            None => match ctx.initialize(CInitializeArgs::OsThreads) {
                Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) | Err(CkError::AlreadyInitialized) => {}
                Err(e) => return Err(load_err(e.to_string())),
            },
        }
        let m = Pkcs11Module { path: path.to_path_buf(), nss_init: nss_init.map(str::to_string), ctx, raw };
        // Primer C_GetSlotList: algunos lectores PC/SC fallan la primera vez.
        if m.ctx.get_all_slots().is_err() {
            m.ctx.get_all_slots().map_err(|e| load_err(e.to_string()))?;
        }
        Ok(m)
    }

    /// Ruta de la biblioteca.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Contexto `cryptoki`.
    pub fn context(&self) -> &Pkcs11 {
        &self.ctx
    }

    /// Descripción de los tokens presentes.
    pub fn tokens(&self) -> Result<Vec<TokenDescription>, KeyStoreError> {
        let slots = self.ctx.get_slots_with_token().map_err(|e| pkcs11_error("C_GetSlotList", &e))?;
        Ok(slots.into_iter().filter_map(|s| describe_token(&self.ctx, s)).collect())
    }
}

fn describe_token(ctx: &Pkcs11, slot: Slot) -> Option<TokenDescription> {
    let info = ctx.get_token_info(slot).ok()?;
    let label = info.label().trim().to_string();
    let manufacturer = info.manufacturer_id().trim().to_string();
    let model = info.model().trim().to_string();
    Some(TokenDescription {
        slot_id: slot.id(),
        family: known::classify_token(&label, &manufacturer, &model),
        label,
        manufacturer,
        model,
        serial: info.serial_number().trim().to_string(),
        login_required: info.login_required(),
        protected_authentication_path: info.protected_authentication_path(),
        initialized: info.token_initialized() && info.user_pin_initialized(),
    })
}

fn rv_name(rv: &RvError) -> String {
    format!("{rv:?}")
}

fn pkcs11_error(function: &str, e: &CkError) -> KeyStoreError {
    match e {
        CkError::Pkcs11(rv, _) => KeyStoreError::Pkcs11 { function: function.to_string(), rv: rv_name(rv) },
        other => KeyStoreError::Pkcs11 { function: function.to_string(), rv: other.to_string() },
    }
}

// ---------------------------------------------------------------------------
// Tokens, sesiones e inicio de sesión
// ---------------------------------------------------------------------------

struct Token {
    slot: Slot,
    desc: TokenDescription,
    mechanisms: Vec<MechanismType>,
    session: Mutex<Option<Session>>,
}

impl Token {
    fn open_session(&self, ctx: &Pkcs11) -> Result<Session, KeyStoreError> {
        ctx.open_ro_session(self.slot).map_err(|e| match &e {
            CkError::Pkcs11(RvError::TokenNotPresent | RvError::DeviceRemoved | RvError::SlotIdInvalid, _) => KeyStoreError::CardNotPresent,
            _ => pkcs11_error("C_OpenSession", &e),
        })
    }
}

fn is_logged_in(session: &Session) -> bool {
    session
        .get_session_info()
        .map(|i| matches!(i.session_state(), SessionState::RoUser | SessionState::RwUser))
        .unwrap_or(false)
}

/// Resultado de un intento de inicio de sesión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Login {
    LoggedIn,
    /// El llamante no dio contraseña (`NoPassword`): no se inicia sesión.
    Skipped,
}

/// Datos compartidos por el almacén y sus claves.
struct Shared {
    module: Arc<Pkcs11Module>,
    config: Pkcs11Config,
    callback: Arc<dyn PasswordCallback>,
    sha1_disabled: bool,
}

impl Shared {
    fn store_name(&self) -> String {
        self.config.name.clone().unwrap_or_else(|| self.config.kind.display_name().to_string())
    }

    fn pin_request(&self, token: &TokenDescription, flags: &PinFlags) -> PasswordRequest {
        let retries = if flags.final_try { Some(1) } else { None };
        let mut req = match self.config.card_dialogs {
            Some(d) => PasswordRequest::card_pin(self.config.kind, d == CardDialogs::Dnie, retries),
            None => {
                let prompt = self.config.pin_prompt.clone().unwrap_or_else(|| {
                    if self.config.kind.is_mozilla() && self.config.name.is_none() {
                        self.config.kind.store_password_prompt(None).unwrap_or_default()
                    } else {
                        prompts::store_with_name(&self.store_name())
                    }
                });
                let kind = if self.config.try_empty_pin_first { PasswordKind::MasterPassword } else { PasswordKind::Pin };
                let mut r = PasswordRequest::new(kind, self.config.kind, prompt);
                r.retries_left = retries;
                r.smartcard = self.config.hardware;
                r
            }
        };
        req.final_try = flags.final_try;
        req.device_label = Some(token.label.clone());
        req
    }

    /// Inicia sesión de usuario en `session`, pidiendo el PIN con `callback`.
    fn login(&self, token: &Token, session: &Session, callback: &dyn PasswordCallback, force: bool) -> Result<Login, KeyStoreError> {
        if !force && is_logged_in(session) {
            return Ok(Login::LoggedIn);
        }
        let flags = PinFlags::read(&self.module.ctx, token.slot);
        if flags.locked {
            return Err(KeyStoreError::Locked { smartcard: true });
        }
        if token.desc.protected_authentication_path {
            return match session.login(UserType::User, None) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(Login::LoggedIn),
                Err(e) => Err(map_login_error(&e)),
            };
        }
        if self.config.try_empty_pin_first {
            let empty = AuthPin::new(String::new());
            if matches!(session.login(UserType::User, Some(&empty)), Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _))) {
                return Ok(Login::LoggedIn);
            }
        }
        let mut retry: Option<RetryReason> = None;
        let mut flags = flags;
        loop {
            let mut req = self.pin_request(&token.desc, &flags);
            req.retry = retry;
            let pin = match callback.request_password(&req) {
                PasswordResponse::Provided { secret, .. } => secret,
                PasswordResponse::NoPassword => return Ok(Login::Skipped),
                PasswordResponse::Cancelled => return Err(KeyStoreError::Cancelled),
            };
            let auth = AuthPin::new(pin.as_str().to_string());
            match session.login(UserType::User, Some(&auth)) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => return Ok(Login::LoggedIn),
                Err(e) => {
                    let err = map_login_error(&e);
                    flags = PinFlags::read(&self.module.ctx, token.slot);
                    let reason = match &err {
                        KeyStoreError::WrongPin { .. } => RetryReason::WrongPassword,
                        KeyStoreError::PinLengthInvalid => RetryReason::WrongLength,
                        KeyStoreError::Locked { .. } | KeyStoreError::Cancelled | KeyStoreError::CardNotPresent => return Err(err),
                        // Java vuelve a pedir el PIN ante cualquier otro
                        // LoginException; aquí solo con PIN erróneo o de
                        // longitud no válida (otro error se repetiría siempre).
                        _ => return Err(err),
                    };
                    if flags.locked {
                        return Err(KeyStoreError::Locked { smartcard: true });
                    }
                    if !callback.is_interactive() || !self.config.retry_wrong_pin {
                        return Err(match err {
                            KeyStoreError::WrongPin { .. } => KeyStoreError::WrongPin { retries_left: flags.final_try.then_some(1) },
                            other => other,
                        });
                    }
                    retry = Some(reason);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PinFlags {
    final_try: bool,
    locked: bool,
}

impl PinFlags {
    fn read(ctx: &Pkcs11, slot: Slot) -> PinFlags {
        ctx.get_token_info(slot)
            .map(|i| PinFlags { final_try: i.user_pin_final_try(), locked: i.user_pin_locked() })
            .unwrap_or_default()
    }
}

fn map_login_error(e: &CkError) -> KeyStoreError {
    match e {
        CkError::Pkcs11(RvError::PinIncorrect, _) => KeyStoreError::WrongPin { retries_left: None },
        CkError::Pkcs11(RvError::PinLenRange, _) => KeyStoreError::PinLengthInvalid,
        CkError::Pkcs11(RvError::PinLocked, _) => KeyStoreError::Locked { smartcard: true },
        CkError::Pkcs11(RvError::FunctionCanceled, _) => KeyStoreError::Cancelled,
        CkError::Pkcs11(RvError::TokenNotPresent | RvError::DeviceRemoved, _) => KeyStoreError::CardNotPresent,
        other => pkcs11_error("C_Login", other),
    }
}

// ---------------------------------------------------------------------------
// Almacén
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct KeyRef {
    alias: String,
    token: Arc<Token>,
    cka_id: Option<Vec<u8>>,
    label: Option<Vec<u8>>,
    chain: Vec<Vec<u8>>,
}

#[derive(Default)]
struct State {
    tokens: Vec<Arc<Token>>,
    entries: Vec<CertEntry>,
    keys: Vec<KeyRef>,
}

/// Almacén sobre una biblioteca PKCS#11.
pub struct Pkcs11Store {
    shared: Arc<Shared>,
    /// Caché de PIN (DNIe/CERES), una por almacén abierto como en jmulticard.
    pin_cache: Option<Arc<PinCache>>,
    state: RwLock<State>,
}

impl std::fmt::Debug for Pkcs11Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Store").field("lib", &self.shared.module.path).field("config", &self.shared.config).finish_non_exhaustive()
    }
}

impl Pkcs11Store {
    /// Abre el almacén sobre la biblioteca `lib`.
    pub fn open(lib: &Path, config: Pkcs11Config, callback: Arc<dyn PasswordCallback>) -> Result<Pkcs11Store, KeyStoreError> {
        let module = Pkcs11Module::load_with_init(lib, config.nss_init.as_deref())?;
        Self::open_module(module, config, callback)
    }

    /// Abre el almacén sobre un módulo ya cargado.
    pub fn open_module(module: Arc<Pkcs11Module>, config: Pkcs11Config, callback: Arc<dyn PasswordCallback>) -> Result<Pkcs11Store, KeyStoreError> {
        let sha1_disabled = known::sha1_rsa_pkcs_disabled(&module.path);
        let pin_cache = (config.pin_timing == PinTiming::AtSign).then(|| Arc::new(PinCache::new(callback.clone())));
        let store = Pkcs11Store { shared: Arc::new(Shared { module, config, callback, sha1_disabled }), pin_cache, state: RwLock::new(State::default()) };
        store.load()?;
        Ok(store)
    }

    /// Biblioteca del almacén.
    pub fn module(&self) -> &Arc<Pkcs11Module> {
        &self.shared.module
    }

    /// Tokens usados por el almacén.
    pub fn tokens(&self) -> Vec<TokenDescription> {
        self.state.read().map(|s| s.tokens.iter().map(|t| t.desc.clone()).collect()).unwrap_or_default()
    }

    /// Vacía la caché de PIN (p. ej. al extraer la tarjeta).
    pub fn clear_pin_cache(&self) {
        if let Some(c) = &self.pin_cache {
            c.clear();
        }
    }

    fn selected_slots(&self) -> Result<Vec<Slot>, KeyStoreError> {
        let ctx = &self.shared.module.ctx;
        let slots = match &self.shared.config.slots {
            SlotSelection::AllTokens => ctx.get_slots_with_token().map_err(|e| pkcs11_error("C_GetSlotList", &e))?,
            SlotSelection::FirstSlot => ctx.get_all_slots().map_err(|e| pkcs11_error("C_GetSlotList", &e))?.into_iter().take(1).collect(),
            SlotSelection::SlotId(id) => ctx.get_all_slots().map_err(|e| pkcs11_error("C_GetSlotList", &e))?.into_iter().filter(|s| s.id() == *id).collect(),
        };
        Ok(slots)
    }

    fn load(&self) -> Result<(), KeyStoreError> {
        let shared = &self.shared;
        let ctx = &shared.module.ctx;
        let mut tokens = Vec::new();
        for slot in self.selected_slots()? {
            let Some(desc) = describe_token(ctx, slot) else { continue };
            if !desc.initialized {
                tracing::info!("Se omite el token no inicializado de la ranura {}", desc.slot_id);
                continue;
            }
            if let Some(f) = &shared.config.token_filter {
                if !f(&desc) {
                    continue;
                }
            }
            let mechanisms = ctx.get_mechanism_list(slot).unwrap_or_default();
            tokens.push(Arc::new(Token { slot, desc, mechanisms, session: Mutex::new(None) }));
        }
        let mut aliases = AliasSet::new();
        let mut entries = Vec::new();
        let mut keys = Vec::new();
        let source = shared
            .config
            .source
            .clone()
            .unwrap_or_else(|| shared.module.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
        for token in &tokens {
            let session = match token.open_session(ctx) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("No se ha podido abrir sesion en el token '{}': {e}", token.desc.label);
                    continue;
                }
            };
            let mut logged_in = is_logged_in(&session);
            if !logged_in && shared.config.pin_timing == PinTiming::AtOpen && token.desc.login_required {
                match shared.login(token, &session, shared.callback.as_ref(), false) {
                    Ok(l) => logged_in = l == Login::LoggedIn,
                    // Cancelación y errores de PIN: falla todo el almacén
                    // (como Java).
                    Err(
                        e @ (KeyStoreError::Cancelled
                        | KeyStoreError::WrongPin { .. }
                        | KeyStoreError::PinLengthInvalid
                        | KeyStoreError::Locked { .. }),
                    ) => return Err(e),
                    Err(e) => {
                        tracing::warn!("Se omite el token '{}' por un error al iniciar sesion: {e}", token.desc.label);
                        continue;
                    }
                }
            }
            let objects = list_objects(&session)?;
            let token_certs: Vec<Vec<u8>> = objects.certs.iter().map(|c| c.value.clone()).collect();
            for cert in &objects.certs {
                let key = objects.keys.iter().find(|k| k.id.is_some() && k.id == cert.id).or_else(|| {
                    // Mejora: si el certificado no tiene CKA_ID, por etiqueta.
                    if cert.id.is_none() { objects.keys.iter().find(|k| k.label.is_some() && k.label == cert.label) } else { None }
                });
                let is_ca = afirma_core::cert::CertInfo::parse(&cert.value).is_some_and(|i| i.is_ca);
                // Antes de iniciar sesión las claves privadas suelen ser
                // invisibles: se supone que existen para los certificados de
                // entidad final con CKA_ID (se comprueba al firmar).
                let assumed = key.is_none() && !logged_in && token.desc.login_required && cert.id.is_some() && !is_ca;
                let has_key = key.is_some() || assumed;
                let alias_src = label_string(cert.label.as_deref())
                    .or_else(|| key.and_then(|k| label_string(k.label.as_deref())))
                    .or_else(|| cert.id.as_deref().map(id_string))
                    .unwrap_or_else(|| afirma_core::cert::common_name(&cert.value));
                let alias = aliases.unique(&alias_src);
                let chain = crate::pkcs12::build_chain(&cert.value, token_certs.iter().map(Vec::as_slice));
                let caps = EntryCapabilities {
                    has_private_key: has_key,
                    key_algorithm: certificate_key_algorithm(&cert.value),
                    hardware: shared.config.hardware,
                    pin_at_sign: shared.config.pin_timing == PinTiming::AtSign,
                };
                entries.push(CertEntry::new(alias.clone(), cert.value.clone(), chain.clone(), caps, source.clone()));
                if has_key {
                    keys.push(KeyRef { alias, token: token.clone(), cka_id: cert.id.clone(), label: cert.label.clone(), chain });
                }
            }
            if let Ok(mut s) = token.session.lock() {
                *s = Some(session);
            }
        }
        let mut st = self.state.write().map_err(|_| KeyStoreError::load(shared.config.kind, "estado del almacén inutilizable"))?;
        *st = State { tokens, entries, keys };
        Ok(())
    }
}

struct CertObject {
    value: Vec<u8>,
    id: Option<Vec<u8>>,
    label: Option<Vec<u8>>,
}

struct KeyObject {
    id: Option<Vec<u8>>,
    label: Option<Vec<u8>>,
}

struct TokenObjects {
    certs: Vec<CertObject>,
    keys: Vec<KeyObject>,
}

fn list_objects(session: &Session) -> Result<TokenObjects, KeyStoreError> {
    let handles = session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)]).map_err(|e| pkcs11_error("C_FindObjects", &e))?;
    let mut certs = Vec::new();
    for h in handles {
        let attrs = match session.get_attributes(h, &[AttributeType::CertificateType, AttributeType::Value, AttributeType::Id, AttributeType::Label]) {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!("Se omite un certificado PKCS#11 ilegible: {e}");
                continue;
            }
        };
        let mut c = CertObject { value: Vec::new(), id: None, label: None };
        let mut x509 = true;
        for a in attrs {
            match a {
                Attribute::CertificateType(t) => x509 = t == CertificateType::X_509,
                Attribute::Value(v) => c.value = v,
                Attribute::Id(v) if !v.is_empty() => c.id = Some(v),
                Attribute::Label(v) if !v.is_empty() => c.label = Some(v),
                _ => {}
            }
        }
        if x509 && !c.value.is_empty() && afirma_core::cert::CertInfo::parse(&c.value).is_some() {
            certs.push(c);
        }
    }
    let mut keys = Vec::new();
    if let Ok(handles) = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)]) {
        for h in handles {
            let Ok(attrs) = session.get_attributes(h, &[AttributeType::Id, AttributeType::Label]) else { continue };
            let mut k = KeyObject { id: None, label: None };
            for a in attrs {
                match a {
                    Attribute::Id(v) if !v.is_empty() => k.id = Some(v),
                    Attribute::Label(v) if !v.is_empty() => k.label = Some(v),
                    _ => {}
                }
            }
            keys.push(k);
        }
    }
    Ok(TokenObjects { certs, keys })
}

/// Etiqueta PKCS#11 como texto (UTF-8, sin NUL ni espacios finales).
fn label_string(label: Option<&[u8]>) -> Option<String> {
    let s = String::from_utf8_lossy(label?).trim_end_matches(['\0', ' ']).to_string();
    (!s.is_empty()).then_some(s)
}

/// `CKA_ID` como alias: texto si es ASCII imprimible, si no hexadecimal.
fn id_string(id: &[u8]) -> String {
    if id.iter().all(|b| (0x20..0x7f).contains(b)) { String::from_utf8_lossy(id).into_owned() } else { hex::encode(id) }
}

impl KeyStore for Pkcs11Store {
    fn kind(&self) -> KeyStoreKind {
        self.shared.config.kind
    }

    fn name(&self) -> String {
        self.shared.store_name()
    }

    fn lib_name(&self) -> Option<String> {
        self.shared.module.path.file_name().map(|n| n.to_string_lossy().into_owned())
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        Ok(self.state.read().map(|s| s.entries.clone()).unwrap_or_default())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let st = self.state.read().map_err(|_| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let entry = find_entry(&st.entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let key = st.keys.iter().find(|k| k.alias == entry.alias).ok_or_else(|| KeyStoreError::NoPrivateKey(alias.to_string()))?;
        let cert = key.chain[0].clone();
        let key_algorithm = certificate_key_algorithm(&cert).ok_or_else(|| KeyStoreError::NoPrivateKey(alias.to_string()))?;
        let callback: Arc<dyn PasswordCallback> = match &self.pin_cache {
            Some(c) => c.clone(),
            None => self.shared.callback.clone(),
        };
        Ok(Box::new(Pkcs11Key {
            shared: self.shared.clone(),
            callback,
            token: key.token.clone(),
            cka_id: key.cka_id.clone(),
            label: key.label.clone(),
            alias: key.alias.clone(),
            curve: certificate_curve(&cert),
            chain: key.chain.clone(),
            key_algorithm,
        }))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        self.clear_pin_cache();
        // Se cierran las sesiones (el token cierra la sesión de usuario) y se
        // vuelven a enumerar las ranuras.
        if let Ok(mut st) = self.state.write() {
            *st = State::default();
        }
        self.load()
    }

    fn is_preferred(&self) -> bool {
        self.shared.config.preferred
    }
}

// ---------------------------------------------------------------------------
// Clave
// ---------------------------------------------------------------------------

/// Clave privada en un token PKCS#11.
pub struct Pkcs11Key {
    shared: Arc<Shared>,
    callback: Arc<dyn PasswordCallback>,
    token: Arc<Token>,
    cka_id: Option<Vec<u8>>,
    label: Option<Vec<u8>>,
    alias: String,
    curve: Option<EcCurve>,
    chain: Vec<Vec<u8>>,
    key_algorithm: KeyAlgorithm,
}

impl std::fmt::Debug for Pkcs11Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Key").field("alias", &self.alias).field("token", &self.token.desc.label).finish_non_exhaustive()
    }
}

fn key_error(e: KeyStoreError) -> KeyError {
    KeyError::from(e)
}

fn sign_error(e: &CkError) -> KeyError {
    match e {
        CkError::Pkcs11(RvError::PinIncorrect, _) => KeyError::WrongPin,
        CkError::Pkcs11(RvError::PinLocked, _) => KeyError::PinLocked,
        CkError::Pkcs11(RvError::FunctionCanceled, _) => KeyError::Cancelled,
        CkError::Pkcs11(RvError::DeviceRemoved | RvError::TokenNotPresent | RvError::DeviceError, _) => KeyError::DeviceUnavailable,
        CkError::Pkcs11(rv, f) => KeyError::Other(format!("{f}: {}", rv_name(rv))),
        other => KeyError::Other(other.to_string()),
    }
}

fn raw_error(rv: cryptoki_sys::CK_RV) -> KeyError {
    match rv {
        cryptoki_sys::CKR_PIN_INCORRECT | cryptoki_sys::CKR_PIN_LEN_RANGE => KeyError::WrongPin,
        cryptoki_sys::CKR_PIN_LOCKED => KeyError::PinLocked,
        cryptoki_sys::CKR_FUNCTION_CANCELED => KeyError::Cancelled,
        cryptoki_sys::CKR_DEVICE_REMOVED | cryptoki_sys::CKR_TOKEN_NOT_PRESENT | cryptoki_sys::CKR_DEVICE_ERROR => KeyError::DeviceUnavailable,
        other => KeyError::Other(format!("error PKCS#11 {other:#x}")),
    }
}

/// Necesidad de reintentar tras un error.
enum Retry {
    Login,
    Session,
}

impl Pkcs11Key {
    fn find_private_key(&self, session: &Session) -> Result<Option<(ObjectHandle, bool)>, CkError> {
        let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        match (&self.cka_id, &self.label) {
            (Some(id), _) => template.push(Attribute::Id(id.clone())),
            (None, Some(l)) => template.push(Attribute::Label(l.clone())),
            (None, None) => {}
        }
        let handles = session.find_objects(&template)?;
        let Some(h) = handles.first().copied() else { return Ok(None) };
        let always_auth = session
            .get_attributes(h, &[AttributeType::AlwaysAuthenticate])
            .ok()
            .and_then(|a| {
                a.into_iter().find_map(|x| match x {
                    Attribute::AlwaysAuthenticate(b) => Some(b),
                    _ => None,
                })
            })
            .unwrap_or(false);
        Ok(Some((h, always_auth)))
    }

    /// Mecanismo y datos de entrada para el algoritmo pedido.
    fn mechanism(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<(Mechanism<'static>, Vec<u8>), KeyError> {
        let mechs = &self.token.mechanisms;
        let supports = |m: MechanismType| mechs.is_empty() || mechs.contains(&m);
        let digest = algorithm.digest;
        match self.key_algorithm {
            KeyAlgorithm::Rsa => {
                let combined = match digest {
                    DigestAlgorithm::Sha1 if !self.shared.sha1_disabled => Some((MechanismType::SHA1_RSA_PKCS, Mechanism::Sha1RsaPkcs)),
                    DigestAlgorithm::Sha1 => None,
                    DigestAlgorithm::Sha224 => Some((MechanismType::SHA224_RSA_PKCS, Mechanism::Sha224RsaPkcs)),
                    DigestAlgorithm::Sha256 => Some((MechanismType::SHA256_RSA_PKCS, Mechanism::Sha256RsaPkcs)),
                    DigestAlgorithm::Sha384 => Some((MechanismType::SHA384_RSA_PKCS, Mechanism::Sha384RsaPkcs)),
                    DigestAlgorithm::Sha512 => Some((MechanismType::SHA512_RSA_PKCS, Mechanism::Sha512RsaPkcs)),
                };
                if let Some((t, m)) = combined {
                    if !mechs.is_empty() && mechs.contains(&t) {
                        return Ok((m, data.to_vec()));
                    }
                }
                if supports(MechanismType::RSA_PKCS) {
                    return Ok((Mechanism::RsaPkcs, digest.digest_info(&digest.digest(data))));
                }
                Err(KeyError::Unsupported(format!("{} (el token no admite CKM_RSA_PKCS)", algorithm.java_name())))
            }
            KeyAlgorithm::Ec => {
                if supports(MechanismType::ECDSA) {
                    return Ok((Mechanism::Ecdsa, ecdsa_truncate_hash(&digest.digest(data), self.curve)));
                }
                let combined = match digest {
                    DigestAlgorithm::Sha1 => (MechanismType::ECDSA_SHA1, Mechanism::EcdsaSha1),
                    DigestAlgorithm::Sha224 => (MechanismType::ECDSA_SHA224, Mechanism::EcdsaSha224),
                    DigestAlgorithm::Sha256 => (MechanismType::ECDSA_SHA256, Mechanism::EcdsaSha256),
                    DigestAlgorithm::Sha384 => (MechanismType::ECDSA_SHA384, Mechanism::EcdsaSha384),
                    DigestAlgorithm::Sha512 => (MechanismType::ECDSA_SHA512, Mechanism::EcdsaSha512),
                };
                if mechs.contains(&combined.0) {
                    return Ok((combined.1, data.to_vec()));
                }
                Err(KeyError::Unsupported(format!("{} (el token no admite CKM_ECDSA)", algorithm.java_name())))
            }
            KeyAlgorithm::Dsa => Err(KeyError::Unsupported("DSA".into())),
        }
    }

    fn sign_once(&self, session: &Session, mechanism: &Mechanism<'static>, input: &[u8]) -> Result<Result<Vec<u8>, Retry>, KeyError> {
        let shared = &self.shared;
        let (key, always_auth) = match self.find_private_key(session) {
            Ok(Some(k)) => k,
            Ok(None) => {
                if !is_logged_in(session) && self.token.desc.login_required {
                    return Ok(Err(Retry::Login));
                }
                return Err(KeyError::Other(format!("No se ha podido obtener la referencia a la clave privada ({})", self.alias)));
            }
            Err(CkError::Pkcs11(RvError::SessionHandleInvalid | RvError::SessionClosed, _)) => return Ok(Err(Retry::Session)),
            Err(e) => return Err(sign_error(&e)),
        };
        let result = if always_auth {
            // Clave con CKA_ALWAYS_AUTHENTICATE: PIN en cada operación.
            let flags = PinFlags::read(&shared.module.ctx, self.token.slot);
            let pin = if self.token.desc.protected_authentication_path {
                None
            } else {
                match self.callback.request_password(&shared.pin_request(&self.token.desc, &flags)) {
                    PasswordResponse::Provided { secret, .. } => Some(secret),
                    PasswordResponse::NoPassword | PasswordResponse::Cancelled => return Err(KeyError::Cancelled),
                }
            };
            let (Some(sh), Some(kh)) = (raw::session_handle(session), raw::object_handle(&key)) else {
                return Err(KeyError::Other("identificadores PKCS#11 no válidos".into()));
            };
            shared.module.raw.sign_with_context_login(sh, mechanism, kh, pin.as_ref().map(|p| p.as_bytes()), input).map_err(raw_error)
        } else {
            match session.sign(mechanism, key, input) {
                Ok(s) => Ok(s),
                Err(CkError::Pkcs11(RvError::UserNotLoggedIn, _)) => return Ok(Err(Retry::Login)),
                Err(CkError::Pkcs11(RvError::SessionHandleInvalid | RvError::SessionClosed, _)) => return Ok(Err(Retry::Session)),
                Err(e) => Err(sign_error(&e)),
            }
        };
        result.map(Ok)
    }
}

impl SigningKey for Pkcs11Key {
    fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.key_algorithm
    }

    fn alias(&self) -> Option<&str> {
        Some(&self.alias)
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        if algorithm.key != self.key_algorithm {
            return Err(KeyError::Unsupported(format!("{} con una clave {}", algorithm.java_name(), self.key_algorithm.java_suffix())));
        }
        let (mechanism, input) = self.mechanism(data, algorithm)?;
        let shared = &self.shared;
        let ctx = &shared.module.ctx;
        let mut guard = self.token.session.lock().map_err(|_| KeyError::Other("sesión PKCS#11 inutilizable".into()))?;
        let at_sign = shared.config.pin_timing == PinTiming::AtSign;
        if at_sign && shared.config.card_dialogs == Some(CardDialogs::Dnie) && !self.callback.confirm_signature(&ConfirmRequest::dnie(self.alias.clone())) {
            return Err(KeyError::Cancelled);
        }
        // PIN en cada firma solo si el token lo exige.
        let mut force_login = at_sign && self.token.desc.login_required;
        for _attempt in 0..3 {
            if guard.is_none() {
                *guard = Some(self.token.open_session(ctx).map_err(|e| match e {
                    KeyStoreError::CardNotPresent => KeyError::DeviceUnavailable,
                    other => key_error(other),
                })?);
            }
            let Some(session) = guard.as_ref() else { return Err(KeyError::DeviceUnavailable) };
            if force_login {
                // PIN en cada firma (DNIe/CERES): se cierra la sesión de
                // usuario anterior y se vuelve a autenticar (PIN de la caché
                // si el usuario pidió recordarlo).
                let _ = session.logout();
                match shared.login(&self.token, session, self.callback.as_ref(), true) {
                    Ok(Login::LoggedIn) => {}
                    Ok(Login::Skipped) => return Err(KeyError::Cancelled),
                    Err(KeyStoreError::CardNotPresent) => {
                        *guard = None;
                        return Err(KeyError::DeviceUnavailable);
                    }
                    Err(e) => return Err(key_error(e)),
                }
                force_login = false;
            }
            match self.sign_once(session, &mechanism, &input)? {
                Ok(sig) => {
                    if self.key_algorithm != KeyAlgorithm::Ec {
                        return Ok(sig);
                    }
                    // PKCS#11 devuelve `r‖s`; algunos módulos devuelven DER.
                    let raw_len = self.curve.map(|c| 2 * c.field_len());
                    return if Some(sig.len()) == raw_len || !looks_like_der(&sig) { ecdsa_raw_to_der(&sig) } else { Ok(sig) };
                }
                Err(Retry::Login) => {
                    match shared.login(&self.token, session, self.callback.as_ref(), false) {
                        Ok(Login::LoggedIn) => {}
                        Ok(Login::Skipped) => {
                            return Err(KeyError::Other(format!("No se ha podido obtener la referencia a la clave privada ({})", self.alias)));
                        }
                        Err(e) => return Err(key_error(e)),
                    }
                }
                Err(Retry::Session) => {
                    // Sesión cerrada (tarjeta extraída y reinsertada): se
                    // abre otra.
                    *guard = None;
                    force_login = at_sign && self.token.desc.login_required;
                }
            }
        }
        Err(KeyError::DeviceUnavailable)
    }
}

/// Algunos módulos devuelven la firma ECDSA ya en DER pese a la norma.
fn looks_like_der(sig: &[u8]) -> bool {
    if sig.len() < 8 || sig[0] != 0x30 {
        return false;
    }
    let (len, hdr) = match sig[1] {
        l if l < 0x80 => (usize::from(l), 2),
        0x81 => (usize::from(sig[2]), 3),
        _ => return false,
    };
    hdr + len == sig.len() && sig.get(hdr) == Some(&0x02)
}

#[cfg(test)]
pub(crate) mod tests;
