//! Registro de las entradas de configuración ajena (directivas de navegadores compartidas,
//! `policies.json`...) que **creó** AutoFirma, para que la desinstalación solo retire lo
//! propio y nunca valores que el administrador ya tuviera.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ctx::Context;
use crate::error::Result;
use crate::fsutil;

/// Nombre del fichero de estado.
pub const STATE_FILE: &str = "managed-entries.json";

/// Entradas propias.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedEntries {
    pub entries: BTreeSet<String>,
}

/// Ruta del fichero de estado (sistema si hay privilegios; usuario si no).
pub fn state_path(ctx: &Context) -> PathBuf {
    if ctx.elevated {
        ctx.paths.system_config_dir.join(STATE_FILE)
    } else {
        ctx.paths.user_config_dir.join(STATE_FILE)
    }
}

impl OwnedEntries {
    /// Carga el estado (vacío si no existe).
    pub fn load(ctx: &Context) -> Self {
        fsutil::read_opt(&state_path(ctx))
            .ok()
            .flatten()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default()
    }

    /// Guarda el estado (o lo borra si queda vacío).
    pub fn save(&self, ctx: &Context) -> Result<()> {
        let p = state_path(ctx);
        if self.entries.is_empty() {
            fsutil::remove_file_if_exists(&p)?;
            return Ok(());
        }
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| crate::error::SystemError::Other(e.to_string()))?;
        fsutil::write_atomic(&p, &data, Some(0o644))
    }

    /// Marca una entrada como propia.
    pub fn add(&mut self, id: impl Into<String>) {
        self.entries.insert(id.into());
    }

    /// `true` si la entrada es propia.
    pub fn owns(&self, id: &str) -> bool {
        self.entries.contains(id)
    }

    /// Olvida una entrada.
    pub fn forget(&mut self, id: &str) {
        self.entries.remove(id);
    }
}
