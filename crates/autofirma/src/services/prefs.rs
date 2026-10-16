//! Preferencias reales (afirma-system) para la interfaz: capas de usuario,
//! sistema y directivas corporativas con bloqueo efectivo.

use afirma_system::prefs::{PreparedImport, Preferences, ResolutionMode};
use afirma_system::{AppIdentity, Context};

use crate::i18n::trf;
use crate::ui::pages::settings::{MemoryPrefs, PrefStore, default_values};

/// Nodo propio para las preferencias de la interfaz nueva (tema, tamaño...).
const UI_NODE: &str = "autofirma-rs/ui";
const UI_KEYS: [&str; 2] = ["uiTheme", "uiScale"];
const PROXY_PASSWORD: &str = "proxyPassword";

/// Preferencias del sistema adaptadas a la interfaz.
pub struct SystemPrefStore {
    prefs: Preferences,
}

impl PrefStore for SystemPrefStore {
    fn get(&self, key: &str) -> Option<String> {
        if UI_KEYS.contains(&key) {
            return self.prefs.get_node_value(UI_NODE, key).filter(|v| !v.is_empty()).or_else(|| default_values().get(key).cloned());
        }
        let value = self.prefs.get(key);
        if key == PROXY_PASSWORD {
            // Se guarda cifrada como en AutoFirma (`ProxyUtil.cipherPassword`).
            return value.and_then(|v| afirma_system::prefs::proxy::decipher_password(&v));
        }
        value
    }

    fn set(&mut self, key: &str, value: Option<&str>) {
        let r = if UI_KEYS.contains(&key) {
            self.prefs.put_node_value(UI_NODE, key, value.unwrap_or_default())
        } else {
            match value {
                Some(v) if key == PROXY_PASSWORD => match afirma_system::prefs::proxy::cipher_password(v) {
                    Some(c) => self.prefs.put(key, &c),
                    None => self.prefs.remove(key),
                },
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

    fn export_config(&self) -> Result<String, String> {
        Ok(self.prefs.export_afconfig())
    }

    fn prepare_import(&self, data: &[u8]) -> Result<PreparedImport, String> {
        self.prefs.prepare_import(data, afirma_system::prefs::afconfig::default_verifier()).map_err(|e| e.to_string())
    }

    fn apply_import(&mut self, prepared: &PreparedImport) -> Result<String, String> {
        let rep = self.prefs.apply_import(prepared).map_err(|e| e.to_string())?;
        let mut text = if rep.cards_added.is_empty() {
            trf("Se han importado {0} preferencias", &[&rep.applied.len()])
        } else {
            trf("Se han importado {0} preferencias y {1} tarjetas", &[&rep.applied.len(), &rep.cards_added.len()])
        };
        if !rep.skipped.is_empty() {
            text.push_str(". ");
            text.push_str(&trf("{0} no se han aplicado (bloqueadas o no válidas)", &[&rep.skipped.len()]));
        }
        Ok(text)
    }

    fn restore_defaults(&mut self) {
        if let Err(e) = self.prefs.restore_general() {
            tracing::warn!("No se han podido restaurar las preferencias: {e}");
        }
        for key in UI_KEYS {
            let _ = self.prefs.put_node_value(UI_NODE, key, "");
        }
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
