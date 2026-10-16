//! Nombres de los ficheros firmados en la firma de varios ficheros
//! (spec 06 §6.1): `getSignedName(nombre, "_signed")` y, si ya existe y no
//! se sobrescribe, `nombre(1).ext`, `nombre(2).ext`...

use std::path::{Path, PathBuf};

use afirma_core::Signer;

/// Texto que AutoFirma inserta en los nombres de las firmas múltiples.
pub const SIGNED_SUFFIX: &str = "_signed";

/// Ruta de salida para un fichero firmado en `out_dir`.
pub fn output_path(signer: &dyn Signer, input: &Path, out_dir: &Path, overwrite: bool) -> PathBuf {
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let signed = signer.signed_name(Some(&name), Some(SIGNED_SUFFIX));
    let candidate = out_dir.join(&signed);
    if overwrite || !candidate.exists() {
        return candidate;
    }
    unique_path(out_dir, &signed)
}

/// Primera ruta libre añadiendo `(n)` antes de la extensión.
pub fn unique_path(dir: &Path, file_name: &str) -> PathBuf {
    let (stem, ext) = match file_name.rfind('.') {
        Some(i) if i > 0 => (&file_name[..i], &file_name[i..]),
        _ => (file_name, ""),
    };
    (1..)
        .map(|n| dir.join(format!("{stem}({n}){ext}")))
        .find(|p| !p.exists())
        .expect("siempre hay un nombre libre")
}

/// Ruta de salida para la firma de un único fichero en el escritorio: el
/// nombre que propone el firmador, junto al original.
pub fn single_output_path(signer: &dyn Signer, input: &Path) -> PathBuf {
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir = input.parent().unwrap_or_else(|| Path::new("."));
    dir.join(signer.signed_name(Some(&name), Some(SIGNED_SUFFIX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_names() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a(1).csig"), b"x").unwrap();
        assert_eq!(unique_path(dir.path(), "a.csig"), dir.path().join("a(2).csig"));
        assert_eq!(unique_path(dir.path(), "sinext"), dir.path().join("sinext(1)"));
    }
}
