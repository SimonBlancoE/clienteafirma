//! Preferencias de las huellas digitales (`HashPreferences`, §7.5.9).
//!
//! Java las guarda en el nodo de preferencias del plugin
//! (`/es/gob/afirma/plugin/hash`); aquí solo se modelan y la aplicación se
//! encarga de leerlas y guardarlas.

use afirma_core::DigestAlgorithm;

use crate::algorithm::{DEFAULT_ALGORITHM, GUI_ALGORITHMS};
use crate::single::FileHashFormat;

/// Clave del algoritmo del diálogo de huella de fichero.
pub const KEY_CREATE_HASH_ALGORITHM: &str = "createHashAlgorithm";
/// Clave del formato del diálogo de huella de fichero.
pub const KEY_CREATE_HASH_FORMAT: &str = "createHashFormat";
/// Clave de la casilla «Copiar huella digital al portapapeles».
pub const KEY_CREATE_HASH_COPY_TO_CLIPBOARD: &str = "createHashCopyToClipBoard";
/// Clave del algoritmo del diálogo de huellas de directorio.
pub const KEY_CREATE_HASH_DIRECTORY_ALGORITHM: &str = "createHashDirectoryAlgorithm";
/// Clave de la casilla «Recursivo» del diálogo de huellas de directorio.
pub const KEY_CREATE_HASH_DIRECTORY_RECURSIVE: &str = "createHashDirectoryRecursive";

/// Preferencias de los diálogos de creación de huellas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashPreferences {
    /// `createHashAlgorithm` (predeterminado SHA-256).
    pub create_hash_algorithm: DigestAlgorithm,
    /// `createHashFormat` (predeterminado hexadecimal).
    pub create_hash_format: FileHashFormat,
    /// `createHashCopyToClipBoard` (predeterminado `true`).
    pub create_hash_copy_to_clipboard: bool,
    /// `createHashDirectoryAlgorithm` (predeterminado SHA-256).
    pub create_hash_directory_algorithm: DigestAlgorithm,
    /// `createHashDirectoryRecursive` (predeterminado `false`).
    pub create_hash_directory_recursive: bool,
}

impl Default for HashPreferences {
    fn default() -> Self {
        Self {
            create_hash_algorithm: DEFAULT_ALGORITHM,
            create_hash_format: FileHashFormat::Hex,
            create_hash_copy_to_clipboard: true,
            create_hash_directory_algorithm: DEFAULT_ALGORITHM,
            create_hash_directory_recursive: false,
        }
    }
}

impl HashPreferences {
    /// Lee las preferencias con una función de consulta de claves, aplicando
    /// las reglas de Java:
    /// - algoritmos: solo los del desplegable (`SHA-256`, `SHA-1`, `SHA-384`,
    ///   `SHA-512`, nombre exacto); cualquier otro valor deja el primero;
    /// - formato: texto del desplegable o `hex`/`b64`/`bin`; si no, hexadecimal;
    /// - casillas: `Boolean.parseBoolean` (solo `true`, sin distinguir
    ///   mayúsculas, es verdadero), con `true` como valor ausente del
    ///   portapapeles y `false` de la recursión.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let alg = |key| {
            get(key)
                .and_then(|v| GUI_ALGORITHMS.into_iter().find(|a| a.name() == v))
                .unwrap_or(DEFAULT_ALGORITHM)
        };
        let boolean = |key, default: bool| get(key).map_or(default, |v| v.eq_ignore_ascii_case("true"));
        Self {
            create_hash_algorithm: alg(KEY_CREATE_HASH_ALGORITHM),
            create_hash_format: FileHashFormat::from_preference(get(KEY_CREATE_HASH_FORMAT).as_deref()),
            create_hash_copy_to_clipboard: boolean(KEY_CREATE_HASH_COPY_TO_CLIPBOARD, true),
            create_hash_directory_algorithm: alg(KEY_CREATE_HASH_DIRECTORY_ALGORITHM),
            create_hash_directory_recursive: boolean(KEY_CREATE_HASH_DIRECTORY_RECURSIVE, false),
        }
    }

    /// Pares clave/valor a guardar, con los valores que escribe Java (el
    /// formato como texto del desplegable, los booleanos como `true`/`false`).
    pub fn to_entries(&self) -> [(&'static str, String); 5] {
        [
            (KEY_CREATE_HASH_ALGORITHM, self.create_hash_algorithm.name().to_string()),
            (
                KEY_CREATE_HASH_FORMAT,
                self.create_hash_format.display_name().to_string(),
            ),
            (
                KEY_CREATE_HASH_COPY_TO_CLIPBOARD,
                self.create_hash_copy_to_clipboard.to_string(),
            ),
            (
                KEY_CREATE_HASH_DIRECTORY_ALGORITHM,
                self.create_hash_directory_algorithm.name().to_string(),
            ),
            (
                KEY_CREATE_HASH_DIRECTORY_RECURSIVE,
                self.create_hash_directory_recursive.to_string(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn valores_por_defecto() {
        let p = HashPreferences::from_lookup(|_| None);
        assert_eq!(p, HashPreferences::default());
        assert_eq!(p.create_hash_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(p.create_hash_format, FileHashFormat::Hex);
        assert!(p.create_hash_copy_to_clipboard);
        assert!(!p.create_hash_directory_recursive);
    }

    #[test]
    fn lectura_y_escritura() {
        let p = HashPreferences {
            create_hash_algorithm: DigestAlgorithm::Sha512,
            create_hash_format: FileHashFormat::Binary,
            create_hash_copy_to_clipboard: false,
            create_hash_directory_algorithm: DigestAlgorithm::Sha1,
            create_hash_directory_recursive: true,
        };
        let map: HashMap<&str, String> = p.to_entries().into_iter().collect();
        assert_eq!(map[KEY_CREATE_HASH_FORMAT], "Binario");
        assert_eq!(map[KEY_CREATE_HASH_COPY_TO_CLIPBOARD], "false");
        assert_eq!(HashPreferences::from_lookup(|k| map.get(k).cloned()), p);
    }

    #[test]
    fn valores_extranos() {
        let map: HashMap<&str, &str> = [
            (KEY_CREATE_HASH_ALGORITHM, "SHA-224"),
            (KEY_CREATE_HASH_FORMAT, "b64"),
            (KEY_CREATE_HASH_COPY_TO_CLIPBOARD, "sí"),
            (KEY_CREATE_HASH_DIRECTORY_ALGORITHM, "sha-1"),
            (KEY_CREATE_HASH_DIRECTORY_RECURSIVE, "TRUE"),
        ]
        .into_iter()
        .collect();
        let p = HashPreferences::from_lookup(|k| map.get(k).map(|v| v.to_string()));
        assert_eq!(p.create_hash_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(p.create_hash_format, FileHashFormat::Base64);
        assert!(!p.create_hash_copy_to_clipboard);
        assert_eq!(p.create_hash_directory_algorithm, DigestAlgorithm::Sha256);
        assert!(p.create_hash_directory_recursive);
    }
}
