//! Peticiones de contraseña y PIN.
//!
//! Los almacenes no muestran diálogos: piden las contraseñas a través de un
//! [`PasswordCallback`] que implementan la interfaz gráfica, la línea de
//! comandos o el protocolo. La respuesta puede ser una contraseña o una
//! cancelación (que los almacenes convierten en
//! [`KeyStoreError::Cancelled`](crate::KeyStoreError::Cancelled)).
//!
//! Equivalencias con Java:
//! - `NullPasswordCallback` → [`NoPassword`],
//! - `CachePasswordCallback` → [`FixedPassword`],
//! - `UIPasswordCallback` → implementación de la interfaz gráfica,
//! - caché de PIN de jmulticard (`DnieCacheCallbackHandler`,
//!   `SmartcardCacheCallbackHandler`, 1 h desde la primera petición) →
//!   [`PinCache`].

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::kind::KeyStoreKind;

/// Contraseña o PIN. Se borra de memoria al liberarse.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(Zeroizing::new(s.into()))
    }

    /// Contraseña vacía.
    pub fn empty() -> Self {
        Secret::new(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.chars().count()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret::new(s)
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret::new(s)
    }
}

/// Qué se pide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordKind {
    /// Contraseña del almacén (PKCS#12, JKS).
    StorePassword,
    /// Contraseña de una entrada concreta dentro del almacén (PKCS#12 con
    /// contraseña de clave distinta a la del almacén).
    EntryPassword,
    /// PIN de una tarjeta o dispositivo PKCS#11 (incluido DNIe y CERES).
    Pin,
    /// Contraseña maestra de NSS (Firefox o base de datos compartida).
    MasterPassword,
}

/// Motivo de una nueva petición tras un intento fallido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryReason {
    /// `CKR_PIN_INCORRECT` o contraseña errónea: "La contraseña introducida no es correcta."
    WrongPassword,
    /// `CKR_PIN_LEN_RANGE`: "La longitud de la contraseña introducida no es válida."
    WrongLength,
}

impl RetryReason {
    /// Mensaje a mostrar antes de volver a pedir la contraseña
    /// (`KeyStoreUtilities.5` / `.8`, título `KeyStoreUtilities.6`).
    pub fn message(self) -> &'static str {
        match self {
            RetryReason::WrongPassword => crate::kind::prompts::WRONG_PIN,
            RetryReason::WrongLength => crate::kind::prompts::PIN_LENGTH,
        }
    }
}

/// Petición de contraseña o PIN.
#[derive(Debug, Clone)]
pub struct PasswordRequest {
    pub kind: PasswordKind,
    /// Tipo de almacén que la pide.
    pub store: KeyStoreKind,
    /// Texto que se debe mostrar (ya localizado, `es_ES`), p. ej.
    /// "Introduzca la contraseña del almacén PKCS#11.".
    pub prompt: String,
    /// Título sugerido para el diálogo.
    pub title: Option<String>,
    /// Intentos restantes si el dispositivo los informa
    /// (`CKF_USER_PIN_COUNT_LOW`/`CKF_USER_PIN_FINAL_TRY`).
    pub retries_left: Option<u32>,
    /// El siguiente fallo bloqueará el PIN (`CKF_USER_PIN_FINAL_TRY`).
    pub final_try: bool,
    /// Si es un reintento, el motivo (el diálogo debe mostrar
    /// [`RetryReason::message`] antes de volver a pedir).
    pub retry: Option<RetryReason>,
    /// Es el PIN de una tarjeta inteligente (DNIe, CERES, PKCS#11).
    pub smartcard: bool,
    /// Ofrecer la casilla "Recordar contraseña durante la sesión" (DNIe y
    /// CERES).
    pub allow_remember: bool,
    /// Longitud mínima y máxima aceptadas (el diálogo de PIN del DNIe acepta
    /// de 4 a 16 caracteres).
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    /// Etiqueta del dispositivo (etiqueta del token PKCS#11) si se conoce.
    pub device_label: Option<String>,
}

impl PasswordRequest {
    pub fn new(kind: PasswordKind, store: KeyStoreKind, prompt: impl Into<String>) -> Self {
        PasswordRequest {
            kind,
            store,
            prompt: prompt.into(),
            title: None,
            retries_left: None,
            final_try: false,
            retry: None,
            smartcard: false,
            allow_remember: false,
            min_len: None,
            max_len: None,
            device_label: None,
        }
    }

    /// Petición de PIN de tarjeta con los textos de jmulticard
    /// (`CommonPasswordCallback`): DNIe o tarjeta genérica, con intentos
    /// restantes si se conocen.
    pub fn card_pin(store: KeyStoreKind, dnie: bool, retries_left: Option<u32>) -> Self {
        use crate::kind::prompts;
        let prompt = match (dnie, retries_left) {
            (true, Some(n)) => prompts::DNIE_PIN_RETRIES.replace("%0", &n.to_string()),
            (true, None) => prompts::DNIE_PIN.to_string(),
            (false, Some(n)) => prompts::CARD_PIN_RETRIES.replace("%0", &n.to_string()),
            (false, None) => prompts::CARD_PIN.to_string(),
        };
        PasswordRequest {
            title: Some(if dnie { prompts::DNIE_PIN_TITLE } else { prompts::CARD_PIN_TITLE }.to_string()),
            retries_left,
            smartcard: true,
            allow_remember: true,
            min_len: Some(4),
            max_len: Some(16),
            ..PasswordRequest::new(PasswordKind::Pin, store, prompt)
        }
    }
}

/// Petición de confirmación de firma (DNIe: "¿Desea realizar una firma
/// electrónica con su clave privada?").
#[derive(Debug, Clone)]
pub struct ConfirmRequest {
    pub store: KeyStoreKind,
    pub title: String,
    pub message: String,
    /// Alias del certificado con el que se va a firmar.
    pub alias: String,
}

impl ConfirmRequest {
    /// Textos de jmulticard para el DNIe.
    pub fn dnie(alias: impl Into<String>) -> Self {
        ConfirmRequest {
            store: KeyStoreKind::DnieJava,
            title: "DNI Electrónico: Firma electrónica".into(),
            message: "¿Desea realizar una firma electrónica con su clave privada?".into(),
            alias: alias.into(),
        }
    }
}

/// Respuesta a una petición de contraseña.
#[derive(Debug, Clone)]
pub enum PasswordResponse {
    /// Contraseña introducida. `remember` indica que el usuario marcó
    /// "Recordar contraseña durante la sesión".
    Provided { secret: Secret, remember: bool },
    /// No hay contraseña (equivale a `null` en Java: p. ej. la línea de
    /// comandos sin `-password`). Los almacenes PKCS#11 no inician sesión.
    NoPassword,
    /// El usuario canceló el diálogo.
    Cancelled,
}

impl PasswordResponse {
    pub fn provided(secret: impl Into<Secret>) -> Self {
        PasswordResponse::Provided { secret: secret.into(), remember: false }
    }
}

/// Proveedor de contraseñas y PIN (lo implementan la GUI y la CLI).
pub trait PasswordCallback: Send + Sync {
    /// Pide una contraseña o PIN.
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse;

    /// Pide confirmación antes de firmar (DNIe). Por defecto se acepta.
    fn confirm_signature(&self, _request: &ConfirmRequest) -> bool {
        true
    }

    /// Indica si detrás hay un usuario: si no lo hay (contraseña fija de la
    /// línea de comandos), los almacenes no reintentan tras un PIN erróneo
    /// para no bloquear la tarjeta.
    fn is_interactive(&self) -> bool {
        true
    }
}

/// Alias para la terminología de tarjetas.
pub use PasswordCallback as PinProvider;

/// Sin contraseña (`NullPasswordCallback`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPassword;

impl PasswordCallback for NoPassword {
    fn request_password(&self, _request: &PasswordRequest) -> PasswordResponse {
        PasswordResponse::NoPassword
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

/// Contraseña fija (`CachePasswordCallback`), p. ej. `-password` de la CLI,
/// que se usa como contraseña del almacén y de las entradas.
#[derive(Debug, Clone)]
pub struct FixedPassword(pub Secret);

impl FixedPassword {
    pub fn new(secret: impl Into<Secret>) -> Self {
        FixedPassword(secret.into())
    }
}

impl PasswordCallback for FixedPassword {
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse {
        if request.retry.is_some() {
            // La contraseña fija ya falló: no se reintenta.
            return PasswordResponse::Cancelled;
        }
        PasswordResponse::provided(self.0.clone())
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

/// Siempre cancela (útil para pruebas y para abrir almacenes "sin
/// interacción").
#[derive(Debug, Clone, Copy, Default)]
pub struct CancelAll;

impl PasswordCallback for CancelAll {
    fn request_password(&self, _request: &PasswordRequest) -> PasswordResponse {
        PasswordResponse::Cancelled
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

/// Adaptador para usar un cierre como [`PasswordCallback`].
pub struct FnPasswordCallback<F>(pub F);

impl<F> PasswordCallback for FnPasswordCallback<F>
where
    F: Fn(&PasswordRequest) -> PasswordResponse + Send + Sync,
{
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse {
        (self.0)(request)
    }
}

impl<T: PasswordCallback + ?Sized> PasswordCallback for Arc<T> {
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse {
        (**self).request_password(request)
    }
    fn confirm_signature(&self, request: &ConfirmRequest) -> bool {
        (**self).confirm_signature(request)
    }
    fn is_interactive(&self) -> bool {
        (**self).is_interactive()
    }
}

/// Duración de la caché de PIN de jmulticard (3600 s desde la primera
/// petición).
pub const PIN_CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct PinCacheState {
    /// Instante de la primera petición de PIN (inicio del temporizador).
    first_request: Option<Instant>,
    pin: Option<Secret>,
    confirmed: bool,
}

/// Caché de PIN por almacén abierto, con la semántica de jmulticard
/// (`DnieCacheCallbackHandler`): si el usuario marca "Recordar contraseña
/// durante la sesión", el PIN se reutiliza sin mostrar diálogos hasta que
/// pasa una hora desde la **primera** petición (el temporizador no se
/// reinicia con el uso). La confirmación de firma del DNIe se pide una sola
/// vez por almacén abierto (también sin marcar la casilla) y se olvida con el
/// mismo temporizador. Un reintento por PIN erróneo olvida el PIN;
/// [`PinCache::clear`] (al recargar el almacén o extraer la tarjeta) lo
/// olvida todo.
pub struct PinCache {
    inner: Arc<dyn PasswordCallback>,
    ttl: Duration,
    state: Mutex<PinCacheState>,
}

impl PinCache {
    pub fn new(inner: Arc<dyn PasswordCallback>) -> Self {
        Self::with_ttl(inner, PIN_CACHE_TTL)
    }

    pub fn with_ttl(inner: Arc<dyn PasswordCallback>, ttl: Duration) -> Self {
        PinCache { inner, ttl, state: Mutex::new(PinCacheState::default()) }
    }

    /// Vacía la caché (PIN y confirmación) y reinicia el temporizador.
    pub fn clear(&self) {
        if let Ok(mut s) = self.state.lock() {
            *s = PinCacheState::default();
        }
    }

    /// Indica si hay un PIN guardado y vigente.
    pub fn has_pin(&self) -> bool {
        let mut s = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.expire(&mut s);
        s.pin.is_some()
    }

    fn expire(&self, s: &mut PinCacheState) {
        if let Some(t) = s.first_request {
            if t.elapsed() >= self.ttl {
                *s = PinCacheState::default();
            }
        }
    }
}

impl PasswordCallback for PinCache {
    fn request_password(&self, request: &PasswordRequest) -> PasswordResponse {
        {
            let Ok(mut s) = self.state.lock() else {
                return self.inner.request_password(request);
            };
            self.expire(&mut s);
            if request.retry.is_some() {
                // PIN erróneo: se olvida el guardado y se pregunta de nuevo.
                s.pin = None;
            } else if let Some(pin) = &s.pin {
                return PasswordResponse::Provided { secret: pin.clone(), remember: true };
            }
            if s.first_request.is_none() {
                s.first_request = Some(Instant::now());
            }
        }
        let response = self.inner.request_password(request);
        if let PasswordResponse::Provided { secret, remember: true } = &response {
            if let Ok(mut s) = self.state.lock() {
                s.pin = Some(secret.clone());
            }
        }
        response
    }

    fn confirm_signature(&self, request: &ConfirmRequest) -> bool {
        if let Ok(mut s) = self.state.lock() {
            self.expire(&mut s);
            if s.confirmed {
                return true;
            }
        }
        let ok = self.inner.confirm_signature(request);
        if ok {
            if let Ok(mut s) = self.state.lock() {
                // Como `DnieCacheCallbackHandler`: una vez autorizada, no se
                // vuelve a preguntar mientras viva la caché (se vacía con el
                // temporizador de 1 h o al recargar el almacén).
                s.confirmed = true;
            }
        }
        ok
    }

    fn is_interactive(&self) -> bool {
        self.inner.is_interactive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        calls: AtomicUsize,
        remember: bool,
    }

    impl PasswordCallback for Counting {
        fn request_password(&self, _r: &PasswordRequest) -> PasswordResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            PasswordResponse::Provided { secret: "1234".into(), remember: self.remember }
        }
    }

    #[test]
    fn pin_cache_remembers_only_when_asked() {
        let inner = Arc::new(Counting { calls: AtomicUsize::new(0), remember: true });
        let cache = PinCache::new(inner.clone());
        let req = PasswordRequest::card_pin(KeyStoreKind::DnieJava, true, None);
        assert!(matches!(cache.request_password(&req), PasswordResponse::Provided { .. }));
        assert!(matches!(cache.request_password(&req), PasswordResponse::Provided { .. }));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        // Reintento por PIN erróneo: vuelve a preguntar.
        let mut retry = req.clone();
        retry.retry = Some(RetryReason::WrongPassword);
        cache.request_password(&retry);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);

        let inner2 = Arc::new(Counting { calls: AtomicUsize::new(0), remember: false });
        let cache2 = PinCache::new(inner2.clone());
        cache2.request_password(&req);
        cache2.request_password(&req);
        assert_eq!(inner2.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pin_cache_expires_from_first_request() {
        let inner = Arc::new(Counting { calls: AtomicUsize::new(0), remember: true });
        let cache = PinCache::with_ttl(inner.clone(), Duration::from_millis(30));
        let req = PasswordRequest::card_pin(KeyStoreKind::Ceres, false, Some(3));
        assert_eq!(req.prompt, "Por favor, introduzca el PIN de la tarjeta.\nIntentos restantes: 3");
        cache.request_password(&req);
        assert!(cache.has_pin());
        std::thread::sleep(Duration::from_millis(40));
        assert!(!cache.has_pin());
        cache.request_password(&req);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn fixed_password_does_not_retry() {
        let f = FixedPassword::new("x");
        let mut req = PasswordRequest::new(PasswordKind::Pin, KeyStoreKind::Pkcs11, "p");
        assert!(matches!(f.request_password(&req), PasswordResponse::Provided { .. }));
        req.retry = Some(RetryReason::WrongPassword);
        assert!(matches!(f.request_password(&req), PasswordResponse::Cancelled));
        assert!(!f.is_interactive());
    }
}
