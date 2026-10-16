//! Recorrido de directorios (`CreateHashAction`, `CheckHashAction`, §7.5.4).
//!
//! Reglas de Java que se conservan:
//! - Sin recursión solo se procesan los ficheros que están directamente en el
//!   directorio; con recursión, también los de todos los subdirectorios.
//! - Los enlaces simbólicos se siguen (`File.isFile()`/`listFiles()`).
//! - Se omiten los **ficheros** cuyo nombre contiene `~$` o es exactamente
//!   (distinguiendo mayúsculas) uno de [`SKIPPED_FILE_NAMES`]. Los
//!   directorios con esos nombres sí se recorren.
//!
//! Diferencias (ver `docs/deviations/afirma-hash.md`):
//! - Las rutas relativas se escriben siempre con `/` (Java usa el separador
//!   del sistema).
//! - Los enlaces rotos y los ficheros especiales (FIFO, sockets,
//!   dispositivos) se omiten; los ciclos de enlaces a directorios se cortan.
//! - Un directorio ilegible es un error (como en Java) y dos ficheros cuyo
//!   nombre da la misma ruta relativa (nombres no UTF-8) también.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crate::HashError;

/// Nombres de fichero que nunca se procesan (además de los que contienen `~$`).
pub const SKIPPED_FILE_NAMES: [&str; 8] = [
    ".fseventsd",
    ".Spotlight-V100",
    ".Trashes",
    "._.Trashes",
    ".DS_Store",
    ".desktop",
    "thumbs.db",
    "$Recycle.Bin",
];

/// Indica si un **fichero** con este nombre se omite en el cálculo de huellas.
pub fn is_skipped_file_name(name: &str) -> bool {
    name.contains("~$") || SKIPPED_FILE_NAMES.contains(&name)
}

/// Fichero encontrado en el recorrido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Ruta relativa al directorio raíz, con `/` como separador.
    pub relative: String,
    /// Ruta en disco.
    pub path: PathBuf,
}

/// Recorre un directorio y devuelve sus ficheros ordenados por ruta relativa.
pub fn collect_files(root: &Path, recursive: bool) -> Result<Vec<WalkEntry>, HashError> {
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut ancestors = Vec::new();
    if let Ok(c) = fs::canonicalize(root) {
        ancestors.push(c);
    }
    walk_dir(root, "", recursive, &mut ancestors, &mut found)?;
    Ok(found
        .into_iter()
        .map(|(relative, path)| WalkEntry { relative, path })
        .collect())
}

fn walk_dir(
    dir: &Path,
    prefix: &str,
    recursive: bool,
    ancestors: &mut Vec<PathBuf>,
    found: &mut BTreeMap<String, PathBuf>,
) -> Result<(), HashError> {
    let io_err = |source| HashError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        entries.push((os_name(&entry.file_name()), entry.path()));
    }
    entries.sort();
    for (name, path) in entries {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        // Se sigue el enlace simbólico, como `File.isFile()` / `isDirectory()`.
        let Ok(meta) = fs::metadata(&path) else {
            tracing::warn!("Se omite la entrada {} (enlace roto o inaccesible)", path.display());
            continue;
        };
        if meta.is_file() {
            if is_skipped_file_name(&name) {
                continue;
            }
            if found.contains_key(&relative) {
                return Err(HashError::DuplicateName(relative));
            }
            found.insert(relative, path);
        } else if meta.is_dir() {
            if !recursive {
                continue;
            }
            let canonical = fs::canonicalize(&path).map_err(|source| HashError::Io {
                path: path.clone(),
                source,
            })?;
            if ancestors.contains(&canonical) {
                tracing::warn!("Se omite {} porque crea un ciclo de enlaces simbólicos", path.display());
                continue;
            }
            ancestors.push(canonical);
            let result = walk_dir(&path, &relative, recursive, ancestors, found);
            ancestors.pop();
            result?;
        } else {
            tracing::warn!("Se omite {} porque no es un fichero regular", path.display());
        }
    }
    Ok(())
}

/// Nombre de fichero como texto (los nombres no UTF-8 se convierten con
/// sustitución, como hace la JVM).
fn os_name(name: &OsStr) -> String {
    name.to_string_lossy().into_owned()
}

/// Normaliza una ruta relativa leída de un documento de huellas: los `\` de
/// los documentos generados por la versión Java en Windows pasan a `/`.
pub fn normalize_relative(name: &str) -> String {
    name.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nombres_omitidos() {
        for n in SKIPPED_FILE_NAMES {
            assert!(is_skipped_file_name(n));
        }
        assert!(is_skipped_file_name("~$documento.docx"));
        assert!(is_skipped_file_name("a~$b"));
        assert!(!is_skipped_file_name("Thumbs.db"));
        assert!(!is_skipped_file_name(".ds_store"));
        assert!(!is_skipped_file_name("fichero.txt"));
    }

    #[test]
    fn recorrido_recursivo_y_no_recursivo() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("sub/deep")).unwrap();
        fs::create_dir_all(root.join(".Trashes")).unwrap();
        for f in [
            "b.txt",
            "a.txt",
            "sub/c.txt",
            "sub/deep/d.txt",
            ".Trashes/e.txt",
            ".DS_Store",
            "~$x.docx",
            "thumbs.db",
        ] {
            fs::write(root.join(f), f).unwrap();
        }
        let names = |rec| {
            collect_files(root, rec)
                .unwrap()
                .into_iter()
                .map(|e| e.relative)
                .collect::<Vec<_>>()
        };
        assert_eq!(names(false), ["a.txt", "b.txt"]);
        assert_eq!(
            names(true),
            [".Trashes/e.txt", "a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn enlaces_simbolicos() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/a.txt"), "a").unwrap();
        std::os::unix::fs::symlink(root.join("sub/a.txt"), root.join("enlace.txt")).unwrap();
        std::os::unix::fs::symlink(root.join("no-existe"), root.join("roto.txt")).unwrap();
        // Ciclo: sub/padre -> raíz.
        std::os::unix::fs::symlink(root, root.join("sub/padre")).unwrap();
        let names: Vec<_> = collect_files(root, true)
            .unwrap()
            .into_iter()
            .map(|e| e.relative)
            .collect();
        assert_eq!(names, ["enlace.txt", "sub/a.txt"]);
    }

    #[test]
    fn directorio_inexistente() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            collect_files(&tmp.path().join("nada"), false),
            Err(HashError::Io { .. })
        ));
    }

    #[test]
    fn normalizacion() {
        assert_eq!(normalize_relative("sub\\hola.txt"), "sub/hola.txt");
    }
}
