//! Almacén nativo de preferencias de **sistema** (escrito por el instalador con
//! `-config_path`/`-default_language` y por la actualización remota) y su escritor.
//!
//! Ubicación: `<system_config_dir>/system-preferences.json` (Linux `/etc/autofirma`,
//! Windows `%ProgramData%\AutoFirma`, macOS `/Library/Application Support/AutoFirma`).
//! Como en Java, si el proceso no puede escribir en él, las escrituras van a la copia de
//! usuario (`systempreferences`, `internalpreferences`, `systemkeystores` del almacén de
//! usuario), que solo se usa como capa de sistema si `allowUpdateConfig` es `true`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::tree::{
    JsonTreeStore, NODE_INTERNAL, NODE_KEYSTORES, NODE_MAIN, NODE_UPDATED_SYSTEM,
    NODE_UPDATED_SYSTEM_KEYSTORES, PrefsFile, PrefsTree,
};
use crate::ctx::Context;
use crate::error::Result;
use crate::fsutil;

/// Nombre del fichero nativo de preferencias de sistema.
pub const SYSTEM_PREFS_FILE: &str = "system-preferences.json";

/// Almacén nativo de sistema.
#[derive(Debug, Clone)]
pub struct SystemStore {
    /// Ruta del fichero.
    pub path: PathBuf,
}

impl SystemStore {
    /// Almacén del contexto.
    pub fn new(ctx: &Context) -> Self {
        Self {
            path: ctx.paths.system_config_dir.join(SYSTEM_PREFS_FILE),
        }
    }

    /// Árbol (vacío si no existe o no se puede leer).
    pub fn load_tree(&self) -> PrefsTree {
        match JsonTreeStore::new(&self.path).load() {
            Ok(Some(f)) => f.nodes,
            Ok(None) => PrefsTree::new(),
            Err(e) => {
                tracing::warn!("Preferencias de sistema no válidas: {e}");
                PrefsTree::new()
            }
        }
    }

    /// `true` si se puede escribir (el fichero o su directorio).
    pub fn writable(&self) -> bool {
        if self.path.exists() {
            return std::fs::OpenOptions::new()
                .append(true)
                .open(&self.path)
                .is_ok();
        }
        let mut dir = self.path.parent().map(PathBuf::from);
        while let Some(d) = dir {
            if d.exists() {
                return fsutil::dir_is_writable(&d);
            }
            dir = d.parent().map(PathBuf::from);
        }
        false
    }
}

/// Destino de las escrituras de sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemTarget {
    /// Almacén nativo de sistema.
    Native,
    /// Copia en el almacén de usuario (sin privilegios).
    UserFallback,
}

/// Escritor de preferencias de sistema (`putSystemPref`, `clearAllSystemPrefs`...).
#[derive(Debug)]
pub struct SystemPrefsWriter {
    target: SystemTarget,
    store: JsonTreeStore,
    file: PrefsFile,
}

impl SystemPrefsWriter {
    /// Abre el destino adecuado según los permisos.
    pub fn open(ctx: &Context) -> Result<Self> {
        let sys = SystemStore::new(ctx);
        if sys.writable() {
            let store = JsonTreeStore::new(&sys.path);
            let file = store.load()?.unwrap_or_default();
            return Ok(Self {
                target: SystemTarget::Native,
                store,
                file,
            });
        }
        tracing::info!(
            "Sin permisos sobre {}: se usa la copia de usuario de las preferencias de sistema",
            sys.path.display()
        );
        let store = JsonTreeStore::new(super::user_prefs_path(ctx));
        let file = store.load()?.unwrap_or_default();
        Ok(Self {
            target: SystemTarget::UserFallback,
            store,
            file,
        })
    }

    /// Destino efectivo.
    pub fn target(&self) -> &SystemTarget {
        &self.target
    }

    fn main_node(&self) -> &'static str {
        match self.target {
            SystemTarget::Native => NODE_MAIN,
            SystemTarget::UserFallback => NODE_UPDATED_SYSTEM,
        }
    }

    fn cards_node(&self) -> &'static str {
        match self.target {
            SystemTarget::Native => NODE_KEYSTORES,
            SystemTarget::UserFallback => NODE_UPDATED_SYSTEM_KEYSTORES,
        }
    }

    /// Borra todas las preferencias principales de sistema.
    pub fn clear_main(&mut self) {
        let n = self.main_node();
        self.file.nodes.0.remove(n);
        // Un nodo vacío existente indica «hay capa de sistema» (actualización remota).
        self.file.nodes.node_mut(n);
    }

    /// Escribe una preferencia principal de sistema.
    pub fn put(&mut self, key: &str, value: &str) {
        let n = self.main_node();
        self.file.nodes.put(n, key, value);
    }

    /// Borra una preferencia principal de sistema.
    pub fn remove(&mut self, key: &str) {
        let n = self.main_node();
        self.file.nodes.remove(n, key);
    }

    /// Escribe una clave del nodo interno.
    pub fn put_internal(&mut self, key: &str, value: &str) {
        self.file.nodes.put(NODE_INTERNAL, key, value);
    }

    /// Borra una clave del nodo interno.
    pub fn remove_internal(&mut self, key: &str) {
        self.file.nodes.remove(NODE_INTERNAL, key);
    }

    /// Sustituye todas las tarjetas de sistema.
    pub fn replace_smartcards(&mut self, cards: &BTreeMap<String, String>) {
        let n = self.cards_node();
        self.file.nodes.remove_subtree(n);
        for (i, (name, lib)) in cards.iter().enumerate() {
            self.file.nodes.put(&format!("{n}/{}", i + 1), name, lib);
        }
    }

    /// Guarda (permisos 0644: legible por todos los usuarios).
    pub fn flush(&self) -> Result<()> {
        let mode = if self.target == SystemTarget::Native {
            0o644
        } else {
            0o600
        };
        // Los nodos vacíos se conservan como marca de existencia en la copia de usuario.
        let mut f = self.file.clone();
        let keep_empty = self.target == SystemTarget::UserFallback;
        if keep_empty {
            let data = serde_json::to_vec_pretty(&f)
                .map_err(|e| crate::error::SystemError::Other(e.to_string()))?;
            return fsutil::write_atomic(&self.store.path, &data, Some(mode));
        }
        f.nodes.prune();
        self.store.save(&f, Some(mode))
    }

    /// Elimina las preferencias de sistema nativas (desinstalación, `removeSystemPrefs`).
    pub fn remove_all(ctx: &Context) -> Result<bool> {
        fsutil::remove_file_if_exists(&SystemStore::new(ctx).path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;

    #[test]
    fn escribe_en_sistema_o_en_copia_de_usuario() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let mut w = SystemPrefsWriter::open(&ctx).unwrap();
        assert_eq!(w.target(), &SystemTarget::Native);
        w.clear_main();
        w.put("signatureHashAlgorithm", "SHA512");
        let mut cards = BTreeMap::new();
        cards.insert("Corp".to_string(), "/usr/lib/corp.so".to_string());
        w.replace_smartcards(&cards);
        w.put_internal("configFileUrl", "https://intra/af.afconfig");
        w.flush().unwrap();
        let tree = SystemStore::new(&ctx).load_tree();
        assert_eq!(
            tree.get(NODE_MAIN, "signatureHashAlgorithm"),
            Some("SHA512")
        );
        assert_eq!(
            tree.get(&format!("{NODE_KEYSTORES}/1"), "Corp"),
            Some("/usr/lib/corp.so")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if crate::ctx::detect_elevated() {
                return; // root puede escribir igualmente
            }
            let dir = ctx.paths.system_config_dir.clone();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
            std::fs::set_permissions(
                dir.join(SYSTEM_PREFS_FILE),
                std::fs::Permissions::from_mode(0o444),
            )
            .unwrap();
            let mut w = SystemPrefsWriter::open(&ctx).unwrap();
            assert_eq!(w.target(), &SystemTarget::UserFallback);
            w.clear_main();
            w.put("signatureHashAlgorithm", "SHA384");
            w.flush().unwrap();
            let user = JsonTreeStore::new(super::super::user_prefs_path(&ctx))
                .load()
                .unwrap()
                .unwrap();
            assert_eq!(
                user.nodes
                    .get(NODE_UPDATED_SYSTEM, "signatureHashAlgorithm"),
                Some("SHA384")
            );
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}
