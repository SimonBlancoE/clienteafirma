//! Preferencias reales (afirma-system) para la interfaz: capas de usuario,
//! sistema y directivas corporativas con bloqueo efectivo.

use afirma_system::prefs::{Preferences, ResolutionMode};
use afirma_system::{AppIdentity, Context};

use crate::ui::pages::settings::{MemoryPrefs, PrefStore, default_values};

/// Nodo propio para las preferencias de la interfaz nueva (tema, tamaño...).
const UI_NODE: &str = "autofirma-rs/ui";
const UI_KEYS: [&str; 2] = ["uiTheme", "uiScale"];

/// Preferencias del sistema adaptadas a la interfaz.
pub struct SystemPrefStore {
    prefs: Preferences,
}

impl PrefStore for SystemPrefStore {
    fn get(&self, key: &str) -> Option<String> {
        if UI_KEYS.contains(&key) {
            return self.prefs.get_node_value(UI_NODE, key).or_else(|| default_values().get(key).cloned());
        }
        self.prefs.get(key)
    }

    fn set(&mut self, key: &str, value: Option<&str>) {
        let r = if UI_KEYS.contains(&key) {
            self.prefs.put_node_value(UI_NODE, key, value.unwrap_or_default())
        } else {
            match value {
                Some(v) => self.prefs.put(key, v),
                None => self.prefs.remove(key),
            }
        };
        if let Err(e) = r {
            tracing::warn!("No se ha podido guardar la preferencia {key}: {e}");
        }
    }

    fn is_locked(&self, key: &str) -> bool {
        !UI_KEYS.contains(&key) && self.prefs.lock(key).is_some()
    }

    fn default_value(&self, key: &str) -> Option<String> {
        afirma_system::prefs::keys::default_value(key).map(str::to_string).or_else(|| default_values().get(key).cloned())
    }
}

/// Carga las preferencias del sistema; si no es posible, preferencias en
/// memoria con los valores por defecto (la aplicación sigue funcionando).
pub fn load() -> Box<dyn PrefStore> {
    let ctx = Context::detect(AppIdentity::current());
    match Preferences::load(&ctx, ResolutionMode::Strict) {
        Ok(prefs) => Box::new(SystemPrefStore { prefs }),
        Err(e) => {
            tracing::warn!("No se han podido cargar las preferencias: {e}");
            Box::new(MemoryPrefs { defaults: default_values(), ..Default::default() })
        }
    }
}
