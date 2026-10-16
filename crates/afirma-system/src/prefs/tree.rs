//! Árbol de preferencias con la misma estructura de nodos que `java.util.prefs`
//! (ruta absoluta del nodo → claves), y su almacén nativo en JSON.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, SystemError};
use crate::fsutil;

/// Nodo principal de preferencias.
pub const NODE_MAIN: &str = "/es/gob/afirma/standalone/ui/preferences";
/// Copia de usuario de las preferencias de sistema descargadas (actualización remota).
pub const NODE_UPDATED_SYSTEM: &str = "/es/gob/afirma/standalone/ui/systempreferences";
/// Nodo interno (URL de configuración, huella, fecha, claves de administración).
pub const NODE_INTERNAL: &str = "/es/gob/afirma/standalone/ui/internalpreferences";
/// Tarjetas inteligentes registradas (un hijo `1`, `2`... por tarjeta).
pub const NODE_KEYSTORES: &str = "/es/gob/afirma/core/keystores";
/// Copia de usuario de las tarjetas del sistema (actualización remota).
pub const NODE_UPDATED_SYSTEM_KEYSTORES: &str = "/es/gob/afirma/core/systemkeystores";
/// Nodo del actualizador (`lastCheckDate`).
pub const NODE_UPDATER: &str = "/es/gob/afirma/standalone";
/// Nodo de los diálogos de ficheros (`currentDir`).
pub const NODE_JSE: &str = "/es/gob/afirma/ui/core/jse";
/// Nodo del diálogo de selección de certificados (`certView`).
pub const NODE_CERT_SELECTION: &str = "/es/gob/afirma/ui/core/jse/certificateselection";
/// Nodo de los diálogos de PIN de DNIe/CERES (`useCacheDni`, `useCacheCeres`).
pub const NODE_JMULTICARD_UI: &str = "/es/gob/afirma/keystores/jmulticard/ui";
/// Nodo de configuración del complemento de huellas (`createHash*`).
pub const NODE_PLUGIN_HASH: &str = "/es/gob/afirma/plugin/hash";
/// Raíz de todos los nodos de AutoFirma (lo que se migra desde Java).
pub const NODE_AFIRMA_ROOT: &str = "/es/gob/afirma";

/// Árbol de preferencias: ruta absoluta de nodo → (clave → valor).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrefsTree(pub BTreeMap<String, BTreeMap<String, String>>);

impl PrefsTree {
    /// Árbol vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Valores de un nodo (si existe).
    pub fn node(&self, path: &str) -> Option<&BTreeMap<String, String>> {
        self.0.get(path)
    }

    /// Valores de un nodo, creándolo si no existe.
    pub fn node_mut(&mut self, path: &str) -> &mut BTreeMap<String, String> {
        self.0.entry(path.to_string()).or_default()
    }

    /// `true` si existe el nodo (aunque esté vacío) o algún descendiente.
    pub fn node_exists(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        self.0.keys().any(|k| k == path || k.starts_with(&prefix))
    }

    /// Lee un valor.
    pub fn get(&self, node: &str, key: &str) -> Option<&str> {
        self.0
            .get(node)
            .and_then(|m| m.get(key))
            .map(String::as_str)
    }

    /// Escribe un valor.
    pub fn put(&mut self, node: &str, key: &str, value: &str) {
        self.node_mut(node)
            .insert(key.to_string(), value.to_string());
    }

    /// Borra un valor; `true` si existía.
    pub fn remove(&mut self, node: &str, key: &str) -> bool {
        self.0
            .get_mut(node)
            .is_some_and(|m| m.remove(key).is_some())
    }

    /// Nombres de los hijos directos de un nodo.
    pub fn children(&self, path: &str) -> Vec<String> {
        let prefix = format!("{path}/");
        let mut out: Vec<String> = self
            .0
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
            .collect();
        out.dedup();
        out
    }

    /// Elimina un nodo y todos sus descendientes.
    pub fn remove_subtree(&mut self, path: &str) {
        let prefix = format!("{path}/");
        self.0.retain(|k, _| k != path && !k.starts_with(&prefix));
    }

    /// Subárbol bajo `path` (incluido).
    pub fn subtree(&self, path: &str) -> PrefsTree {
        let prefix = format!("{path}/");
        PrefsTree(
            self.0
                .iter()
                .filter(|(k, _)| *k == path || k.starts_with(&prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }

    /// Incorpora los nodos de `other` (sus valores ganan).
    pub fn merge_from(&mut self, other: &PrefsTree) {
        for (n, m) in &other.0 {
            let dst = self.node_mut(n);
            for (k, v) in m {
                dst.insert(k.clone(), v.clone());
            }
        }
    }

    /// `true` si no hay ningún valor.
    pub fn is_empty(&self) -> bool {
        self.0.values().all(BTreeMap::is_empty)
    }

    /// Elimina los nodos vacíos.
    pub fn prune(&mut self) {
        self.0.retain(|_, m| !m.is_empty());
    }
}

/// Formato del fichero nativo de preferencias.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefsFile {
    /// Identificador de formato.
    #[serde(default = "PrefsFile::format_id")]
    pub format: String,
    /// Versión del formato.
    #[serde(default = "PrefsFile::version_id")]
    pub version: u32,
    /// Origen de la migración inicial (`java-registry`, `java-xml`, `java-plist`) si la hubo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<String>,
    /// Nodos.
    #[serde(default)]
    pub nodes: PrefsTree,
}

impl PrefsFile {
    fn format_id() -> String {
        "autofirma-rs-preferences".into()
    }
    fn version_id() -> u32 {
        1
    }
}

/// Almacén nativo de preferencias en un fichero JSON.
#[derive(Debug, Clone)]
pub struct JsonTreeStore {
    /// Ruta del fichero.
    pub path: PathBuf,
}

impl JsonTreeStore {
    /// Almacén en la ruta indicada.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `true` si el fichero existe.
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// Carga el fichero (`Ok(None)` si no existe).
    pub fn load(&self) -> Result<Option<PrefsFile>> {
        let Some(data) = fsutil::read_opt(&self.path)? else {
            return Ok(None);
        };
        let f: PrefsFile = serde_json::from_slice(&data).map_err(|e| SystemError::Format {
            path: self.path.clone(),
            detail: e.to_string(),
        })?;
        Ok(Some(f))
    }

    /// Carga solo el árbol (vacío si no existe o está dañado; un fichero dañado se conserva
    /// con extensión `.corrupto` y se registra un aviso).
    pub fn load_tree_lenient(&self) -> PrefsTree {
        match self.load() {
            Ok(Some(f)) => f.nodes,
            Ok(None) => PrefsTree::new(),
            Err(e) => {
                tracing::warn!("Preferencias dañadas en {}: {e}", self.path.display());
                let _ = std::fs::rename(&self.path, self.path.with_extension("json.corrupto"));
                PrefsTree::new()
            }
        }
    }

    /// Guarda el fichero de forma atómica. `mode` (Unix) para los permisos.
    pub fn save(&self, file: &PrefsFile, mode: Option<u32>) -> Result<()> {
        let mut f = file.clone();
        f.nodes.prune();
        f.format = PrefsFile::format_id();
        f.version = PrefsFile::version_id();
        let data = serde_json::to_vec_pretty(&f).map_err(|e| SystemError::Other(e.to_string()))?;
        fsutil::write_atomic(&self.path, &data, mode)
    }

    /// Directorio del fichero.
    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hijos_y_subarboles() {
        let mut t = PrefsTree::new();
        t.put(NODE_KEYSTORES, "x", "1");
        t.put(&format!("{NODE_KEYSTORES}/1"), "Tarjeta", "/usr/lib/a.so");
        t.put(&format!("{NODE_KEYSTORES}/2"), "Otra", "/usr/lib/b.so");
        t.put(NODE_MAIN, "omitAskOnClose", "true");
        assert_eq!(t.children(NODE_KEYSTORES), vec!["1", "2"]);
        assert!(t.node_exists("/es/gob/afirma/core"));
        assert_eq!(t.subtree(NODE_KEYSTORES).0.len(), 3);
        t.remove_subtree(NODE_KEYSTORES);
        assert!(!t.node_exists(NODE_KEYSTORES));
        assert_eq!(t.get(NODE_MAIN, "omitAskOnClose"), Some("true"));
    }

    #[test]
    fn json_ida_y_vuelta() {
        let d = tempfile::tempdir().unwrap();
        let s = JsonTreeStore::new(d.path().join("sub/preferences.json"));
        let mut f = PrefsFile::default();
        f.nodes.put(NODE_MAIN, "default.locale", "ca_ES");
        s.save(&f, Some(0o600)).unwrap();
        let back = s.load().unwrap().unwrap();
        assert_eq!(back.nodes.get(NODE_MAIN, "default.locale"), Some("ca_ES"));
        assert_eq!(back.format, "autofirma-rs-preferences");
    }
}
