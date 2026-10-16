//! Utilidades de ficheros: escritura atómica, lectura opcional y propiedad de ficheros.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::error::{Result, io_at};

/// Lee un fichero; `Ok(None)` si no existe.
pub fn read_opt(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_at(path)(e)),
    }
}

/// Lee un fichero de texto (UTF-8 con pérdidas); `Ok(None)` si no existe.
pub fn read_text_opt(path: &Path) -> Result<Option<String>> {
    Ok(read_opt(path)?.map(|d| String::from_utf8_lossy(&d).into_owned()))
}

/// Escribe un fichero de forma atómica (fichero temporal en el mismo directorio + `rename`),
/// creando los directorios intermedios. Si `mode` se indica (Unix), se aplica al fichero.
pub fn write_atomic(path: &Path, data: &[u8], mode: Option<u32>) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(io_at(dir))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp).map_err(io_at(&tmp))?;
        f.write_all(data).map_err(io_at(&tmp))?;
        f.sync_all().map_err(io_at(&tmp))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = match mode {
            Some(m) => Some(m),
            // Conserva los permisos del fichero que se reemplaza.
            None => fs::metadata(path)
                .ok()
                .map(|md| md.permissions().mode() & 0o7777),
        };
        if let Some(m) = m {
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(m));
        }
        // Conserva el propietario del fichero que se reemplaza (p. ej. user.js de otro usuario).
        if let Ok(md) = fs::metadata(path) {
            use std::os::unix::fs::MetadataExt;
            chown(&tmp, md.uid(), md.gid());
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_at(path)(e)
    })
}

/// Elimina un fichero; devuelve `true` si existía.
pub fn remove_file_if_exists(path: &Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_at(path)(e)),
    }
}

/// Comprueba si se puede escribir en un directorio (creando y borrando un fichero de prueba).
pub fn dir_is_writable(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".afirma-wtest-{}", std::process::id()));
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Cambia el propietario de un fichero (Unix). Errores ignorados (operación de cortesía).
#[cfg(unix)]
pub fn chown(path: &Path, uid: u32, gid: u32) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: FFI con libc; `c` es una cadena C válida que vive durante la llamada.
    unsafe {
        libc::chown(c.as_ptr(), uid, gid);
    }
}

/// Tras modificar como `root` ficheros dentro del directorio de otro usuario (perfiles de
/// Firefox, `~/.pki/nssdb`), devuelve a ese usuario la propiedad de los ficheros indicados
/// que hayan quedado a nombre de `root`.
#[cfg(unix)]
pub fn restore_owner_in_dir(dir: &Path, names: &[&str]) {
    use std::os::unix::fs::MetadataExt;
    let Ok(dmd) = fs::metadata(dir) else { return };
    if dmd.uid() == 0 {
        return;
    }
    for n in names {
        let p = dir.join(n);
        if let Ok(md) = fs::symlink_metadata(&p)
            && md.uid() == 0
            && md.is_file()
        {
            chown(&p, dmd.uid(), dmd.gid());
        }
    }
}

/// Versión vacía para sistemas no Unix.
#[cfg(not(unix))]
pub fn restore_owner_in_dir(_dir: &Path, _names: &[&str]) {}

/// Normaliza los finales de línea de un texto a `\n`.
pub fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}
