//! Utilidades comunes de las pruebas diferenciales con la versión Java.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

/// Directorio `testdata/hash`.
pub fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/hash")
}

/// Lee un fichero de `testdata/hash`.
pub fn golden(name: &str) -> Vec<u8> {
    fs::read(testdata().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Crea en `root` el árbol descrito en `testdata/hash/tree.manifest`.
pub fn make_tree(root: &Path) {
    let manifest = fs::read_to_string(testdata().join("tree.manifest")).unwrap();
    for line in manifest.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (path, spec) = line.split_once('\t').unwrap();
        let data: Vec<u8> = if let Some(h) = spec.strip_prefix("hex:") {
            hex::decode(h).unwrap()
        } else {
            let n: usize = spec.strip_prefix("pattern:").unwrap().parse().unwrap();
            (0..n).map(|i| (i % 251) as u8).collect()
        };
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, data).unwrap();
    }
}

/// Aplica al árbol las mismas modificaciones que `hash_oracle.sh` antes de
/// generar los informes de referencia.
pub fn modify_tree(root: &Path) {
    fs::write(root.join("sub/hola.txt"), b"adios\n").unwrap();
    fs::remove_file(root.join("vacio.txt")).unwrap();
    fs::write(root.join("nuevo.txt"), b"n").unwrap();
}

/// Normaliza un documento para compararlo con el de Java (cuyo orden de
/// entradas es arbitrario): en XML ordena los grupos de líneas `<entry`
/// consecutivas; en TXT, las líneas de datos.
pub fn normalize(doc: &[u8]) -> String {
    let text = String::from_utf8(doc.to_vec()).unwrap();
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut out: Vec<String> = Vec::new();
    if text.starts_with(';') {
        let (headers, data): (Vec<&str>, Vec<&str>) =
            lines.iter().partition(|l| l.starts_with(';'));
        let mut data = data;
        data.sort_unstable();
        return headers.concat() + &data.concat();
    }
    let mut run: Vec<&str> = Vec::new();
    for l in lines {
        if l.trim_start().starts_with("<entry ") {
            run.push(l);
            continue;
        }
        run.sort_unstable();
        out.extend(run.drain(..).map(str::to_string));
        out.push(l.to_string());
    }
    run.sort_unstable();
    out.extend(run.drain(..).map(str::to_string));
    out.concat()
}

/// Copia recursivamente un directorio.
pub fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            fs::copy(e.path(), target).unwrap();
        }
    }
}
