//! Caché de certificado (*sticky*) de Autofirma App 1.9 (`KeyEntryCache`,
//! `DeleteCertCacheService`; `docs/spec/09-android.md` §4.7).
//!
//! - Una sola entrada (clave privada + cadena) por proceso, que sobrevive entre
//!   invocaciones web.
//! - Se usa en `sign`/`cosign`/`countersign`, `selectcert` y `batch` si
//!   `sticky=true`, `resetsticky≠true` y hay entrada (sin mostrar nada).
//! - Tras elegir certificado: con `sticky=true` y sin DNIe se guarda; en
//!   cualquier otro caso (incluida la firma local) se borra.
//! - Al guardar se (re)inicia un temporizador de `stickySignatureTimeout`
//!   minutos (5 por defecto); al vencer la entrada se borra. Borrar no detiene
//!   el temporizador (al vencer borra otra vez, sin efecto), lo que equivale a
//!   que cada entrada caduque a los N minutos de guardarse.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afirma_core::SigningKey;

/// Minutos que admite la configuración (5, 15, 30, 60 o 120).
pub const STICKY_TIMEOUT_CHOICES: [u64; 5] = [5, 15, 30, 60, 120];
/// Valor por defecto de `stickySignatureTimeout`.
pub const DEFAULT_STICKY_TIMEOUT: Duration = Duration::from_secs(5 * 60);

struct Entry {
    key: Arc<dyn SigningKey>,
    expires: Instant,
}

/// Caché de certificado del proceso. Se comparte entre invocaciones (la
/// aplicación mantiene una sola instancia del lanzador o la pasa al crearlo).
#[derive(Clone, Default)]
pub struct StickyKeyCache {
    inner: Arc<Mutex<Option<Entry>>>,
}

impl std::fmt::Debug for StickyKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StickyKeyCache")
            .field("has_entry", &self.get().is_some())
            .finish()
    }
}

impl StickyKeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Entrada vigente.
    pub fn get(&self) -> Option<Arc<dyn SigningKey>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.as_ref().is_some_and(|e| Instant::now() >= e.expires) {
            *g = None;
        }
        g.as_ref().map(|e| e.key.clone())
    }

    /// Guarda una entrada que caduca a los `ttl`.
    pub fn store(&self, key: Arc<dyn SigningKey>, ttl: Duration) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(Entry {
            key,
            expires: Instant::now() + ttl,
        });
    }

    /// Borra la entrada (también lo hace la firma local).
    pub fn clear(&self) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Actualización tras elegir certificado: guarda si `sticky` y no es DNIe;
    /// si no, borra.
    pub fn update_after_selection(&self, key: &Arc<dyn SigningKey>, sticky: bool, is_dnie: bool, ttl: Duration) {
        if sticky && !is_dnie {
            self.store(key.clone(), ttl);
        } else {
            self.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afirma_core::{KeyAlgorithm, KeyError, SignatureAlgorithm};

    struct K;
    impl SigningKey for K {
        fn certificate(&self) -> &[u8] {
            b"cert"
        }
        fn key_algorithm(&self) -> KeyAlgorithm {
            KeyAlgorithm::Rsa
        }
        fn sign(&self, _d: &[u8], _a: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
            Ok(vec![])
        }
    }

    #[test]
    fn rules() {
        let c = StickyKeyCache::new();
        let k: Arc<dyn SigningKey> = Arc::new(K);
        assert!(c.get().is_none());
        c.update_after_selection(&k, true, false, Duration::from_secs(60));
        assert!(c.get().is_some());
        // DNIe: nunca se guarda (y borra la anterior).
        c.update_after_selection(&k, true, true, Duration::from_secs(60));
        assert!(c.get().is_none());
        c.update_after_selection(&k, true, false, Duration::from_secs(60));
        c.update_after_selection(&k, false, false, Duration::from_secs(60));
        assert!(c.get().is_none());
        // Caducidad.
        c.store(k, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get().is_none());
    }
}
