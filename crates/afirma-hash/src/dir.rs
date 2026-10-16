//! Huellas de directorio: cálculo en paralelo (`CreateHashDirDialog.calculateHashes`)
//! y comprobación con informe (`CheckHashDirDialog.checkHash`, §7.5.8).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use afirma_core::DigestAlgorithm;

use crate::HashError;
use crate::algorithm::digest_file_with_buffer;
use crate::document::{DirDocumentFormat, HashDocument};
use crate::walk::{WalkEntry, collect_files, normalize_relative};
use crate::xmlout::{XML_DECLARATION, push_attr};

/// Número máximo de hilos de cálculo (Java usa un `ForkJoinPool` de 10).
pub const MAX_THREADS: usize = 10;

/// Nombre propuesto para el informe de comprobación.
pub const DEFAULT_REPORT_NAME: &str = "informe.hashreport";

/// Extensión (sin punto) de los informes de comprobación.
pub const REPORT_EXTENSION: &str = "hashreport";

/// Opciones del cálculo de huellas de directorio.
#[derive(Clone, Copy, Default)]
pub struct HashOptions<'a> {
    /// Hilos de cálculo (0 = número de procesadores, hasta [`MAX_THREADS`]).
    pub threads: usize,
    /// Marca de cancelación: si pasa a `true` el cálculo se detiene con
    /// [`HashError::Cancelled`].
    pub cancel: Option<&'a AtomicBool>,
    /// Función de progreso: recibe (ficheros procesados, total).
    pub progress: Option<&'a (dyn Fn(usize, usize) + Sync)>,
}

impl std::fmt::Debug for HashOptions<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashOptions")
            .field("threads", &self.threads)
            .field("cancel", &self.cancel)
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

impl HashOptions<'_> {
    fn thread_count(&self, jobs: usize) -> usize {
        let wanted = if self.threads == 0 {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(MAX_THREADS)
        } else {
            self.threads
        };
        wanted.clamp(1, jobs.max(1))
    }
}

/// Calcula las huellas de los ficheros de un directorio.
///
/// A diferencia de Java, cualquier error de lectura o de algoritmo interrumpe
/// el proceso y se devuelve, en lugar de generar un documento incompleto.
pub fn hash_directory(
    dir: &Path,
    recursive: bool,
    algorithm: DigestAlgorithm,
    options: &HashOptions<'_>,
) -> Result<HashDocument, HashError> {
    let files = collect_files(dir, recursive)?;
    let digests = hash_parallel(&files, algorithm, options)?;
    let mut doc = HashDocument::new(algorithm, recursive);
    doc.entries = files.into_iter().map(|e| e.relative).zip(digests).collect();
    Ok(doc)
}

/// Calcula las huellas de una lista de ficheros en paralelo, conservando el orden.
fn hash_parallel(
    files: &[WalkEntry],
    algorithm: DigestAlgorithm,
    options: &HashOptions<'_>,
) -> Result<Vec<Vec<u8>>, HashError> {
    let total = files.len();
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results: Mutex<Vec<Option<Vec<u8>>>> = Mutex::new(vec![None; total]);
    let errors: Mutex<Vec<(usize, HashError)>> = Mutex::new(Vec::new());
    let threads = options.thread_count(total);

    let worker = || {
        let mut buf = Vec::new();
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if options.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                stop.store(true, Ordering::Relaxed);
                lock(&errors).push((usize::MAX, HashError::Cancelled));
                break;
            }
            let i = next.fetch_add(1, Ordering::Relaxed);
            if i >= total {
                break;
            }
            match digest_file_with_buffer(&files[i].path, algorithm, &mut buf, options.cancel) {
                Ok(d) => {
                    lock(&results)[i] = Some(d);
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if let Some(p) = options.progress {
                        p(n, total);
                    }
                }
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    lock(&errors).push((i, e));
                    break;
                }
            }
        }
    };

    if threads <= 1 {
        worker();
    } else {
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(worker);
            }
        });
    }

    let mut errors = errors.into_inner().unwrap_or_else(|e| e.into_inner());
    if !errors.is_empty() {
        // Error determinista: el del primer fichero (la cancelación va al final).
        errors.sort_by_key(|(i, _)| *i);
        return Err(errors.swap_remove(0).1);
    }
    let results = results.into_inner().unwrap_or_else(|e| e.into_inner());
    results.into_iter().map(|r| r.ok_or(HashError::Cancelled)).collect()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Nombre propuesto para guardar el documento de huellas de un directorio:
/// `<nombre canónico del directorio>.<extensión del formato>`.
pub fn default_directory_document_name(dir: &Path, format: DirDocumentFormat) -> String {
    format!("{}.{}", crate::canonical_file_name(dir), format.extension())
}

/// Directorio propuesto para guardar el informe: el padre del directorio comprobado.
pub fn default_report_dir(checked_dir: &Path) -> Option<PathBuf> {
    std::path::absolute(checked_dir).ok()?.parent().map(Path::to_path_buf)
}

/// Informe de comprobación de las huellas de un directorio (`HashReport`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashReport {
    /// Algoritmo del documento de huellas.
    pub algorithm: DigestAlgorithm,
    /// Recursión del documento de huellas.
    pub recursive: bool,
    /// Ficheros cuya huella coincide (`matching_hash`).
    pub matching_hash: Vec<String>,
    /// Ficheros cuya huella no coincide (`not_matching_hash`).
    pub not_matching_hash: Vec<String>,
    /// Entradas del documento sin fichero (`hash_without_file`).
    pub hash_without_file: Vec<String>,
    /// Ficheros sin entrada en el documento (`file_without_hash`).
    pub file_without_hash: Vec<String>,
}

impl HashReport {
    /// Informe vacío.
    pub fn new(algorithm: DigestAlgorithm, recursive: bool) -> Self {
        Self {
            algorithm,
            recursive,
            matching_hash: Vec::new(),
            not_matching_hash: Vec::new(),
            hash_without_file: Vec::new(),
            file_without_hash: Vec::new(),
        }
    }

    /// `true` si alguna huella no coincide o falta algún fichero o huella.
    pub fn has_errors(&self) -> bool {
        !self.not_matching_hash.is_empty() || !self.hash_without_file.is_empty() || !self.file_without_hash.is_empty()
    }

    /// Ficheros cuya huella se ha comprobado (coincida o no).
    pub fn processed_files_count(&self) -> usize {
        self.matching_hash.len() + self.not_matching_hash.len()
    }

    /// Informe XML (`.hashreport`) con el formato de `generateXMLReport`:
    /// las secciones solo aparecen si no están vacías, en el orden
    /// `matching_hash`, `not_matching_hash`, `hash_without_file`, `file_without_hash`.
    pub fn to_xml(&self) -> Result<Vec<u8>, HashError> {
        let mut out = String::with_capacity(256);
        out.push_str(XML_DECLARATION);
        out.push_str("<entries hashAlgorithm=\"");
        out.push_str(self.algorithm.name());
        out.push_str("\" recursive=\"");
        out.push_str(if self.recursive { "true" } else { "false" });
        out.push('"');
        let sections = [
            ("matching_hash", &self.matching_hash),
            ("not_matching_hash", &self.not_matching_hash),
            ("hash_without_file", &self.hash_without_file),
            ("file_without_hash", &self.file_without_hash),
        ];
        if sections.iter().all(|(_, v)| v.is_empty()) {
            out.push_str("/>\n");
            return Ok(out.into_bytes());
        }
        out.push_str(">\n");
        for (tag, names) in sections {
            if names.is_empty() {
                continue;
            }
            out.push_str("    <");
            out.push_str(tag);
            out.push_str(">\n");
            for name in names {
                out.push_str("        <entry name=\"");
                push_attr(&mut out, name).map_err(|c| HashError::UnrepresentableName {
                    name: name.clone(),
                    reason: format!("contiene el carácter U+{:04X}, no admitido en XML", u32::from(c)),
                })?;
                out.push_str("\"/>\n");
            }
            out.push_str("    </");
            out.push_str(tag);
            out.push_str(">\n");
        }
        out.push_str("</entries>\n");
        Ok(out.into_bytes())
    }
}

/// Comprueba un directorio contra un documento de huellas.
///
/// El algoritmo y la recursión se toman del documento. Las rutas del
/// documento se comparan tal cual y, si no coinciden, cambiando `\` por `/`
/// (documentos generados por Java en Windows). Las listas del informe salen
/// ordenadas alfabéticamente.
pub fn check_directory(
    dir: &Path,
    document: &HashDocument,
    options: &HashOptions<'_>,
) -> Result<HashReport, HashError> {
    let files = collect_files(dir, document.recursive)?;

    // Índice secundario para las rutas con `\` (solo si no hay ambigüedad).
    let mut normalized: HashMap<String, Option<&str>> = HashMap::new();
    for name in document.entries.keys().filter(|n| n.contains('\\')) {
        normalized
            .entry(normalize_relative(name))
            .and_modify(|v| *v = None)
            .or_insert(Some(name.as_str()));
    }

    let mut report = HashReport::new(document.algorithm, document.recursive);
    let mut pending: BTreeMap<&str, &[u8]> = document
        .entries
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    let mut to_hash: Vec<WalkEntry> = Vec::new();
    let mut expected: Vec<&[u8]> = Vec::new();
    for file in files {
        let key = if pending.contains_key(file.relative.as_str()) {
            Some(file.relative.as_str())
        } else {
            normalized
                .get(&file.relative)
                .copied()
                .flatten()
                .filter(|k| pending.contains_key(k))
        };
        match key.and_then(|k| pending.remove_entry(k)) {
            Some((_, digest)) => {
                expected.push(digest);
                to_hash.push(file);
            }
            None => report.file_without_hash.push(file.relative),
        }
    }
    let computed = hash_parallel(&to_hash, document.algorithm, options)?;
    for ((file, exp), got) in to_hash.into_iter().zip(expected).zip(computed) {
        if exp == got.as_slice() {
            report.matching_hash.push(file.relative);
        } else {
            report.not_matching_hash.push(file.relative);
        }
    }
    report.hash_without_file = pending.into_keys().map(str::to_string).collect();
    report.file_without_hash.sort();
    Ok(report)
}

/// Carga un documento de huellas de disco y comprueba el directorio con él.
pub fn check_directory_with_file(
    dir: &Path,
    hash_document: &Path,
    options: &HashOptions<'_>,
) -> Result<HashReport, HashError> {
    let content = std::fs::read(hash_document).map_err(|source| HashError::Io {
        path: hash_document.to_path_buf(),
        source,
    })?;
    let doc = HashDocument::parse(&content)?;
    check_directory(dir, &doc, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("sub/deep")).unwrap();
        fs::write(root.join("vacio.txt"), b"").unwrap();
        fs::write(root.join("sub/hola.txt"), b"hola\n").unwrap();
        fs::write(root.join("sub/deep/datos.bin"), [0u8, 1, 2, 255]).unwrap();
        fs::write(root.join(".DS_Store"), b"x").unwrap();
        fs::write(root.join("~$bloqueo.docx"), b"x").unwrap();
        tmp
    }

    #[test]
    fn calculo_recursivo_y_no_recursivo() {
        let tmp = tree();
        let doc = hash_directory(tmp.path(), true, DigestAlgorithm::Sha256, &HashOptions::default()).unwrap();
        assert_eq!(
            doc.entries.keys().collect::<Vec<_>>(),
            ["sub/deep/datos.bin", "sub/hola.txt", "vacio.txt"]
        );
        assert_eq!(doc.entries["vacio.txt"], DigestAlgorithm::Sha256.digest(b""));
        assert_eq!(doc.entries["sub/hola.txt"], DigestAlgorithm::Sha256.digest(b"hola\n"));
        let doc = hash_directory(tmp.path(), false, DigestAlgorithm::Sha1, &HashOptions::default()).unwrap();
        assert_eq!(doc.entries.keys().collect::<Vec<_>>(), ["vacio.txt"]);
        assert!(!doc.recursive);
        assert_eq!(doc.algorithm, DigestAlgorithm::Sha1);
    }

    #[test]
    fn paralelo_igual_que_secuencial() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..57 {
            fs::write(tmp.path().join(format!("f{i:03}")), vec![i as u8; i * 1000]).unwrap();
        }
        let seq = hash_directory(
            tmp.path(),
            false,
            DigestAlgorithm::Sha512,
            &HashOptions {
                threads: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let count = AtomicUsize::new(0);
        let progress = |_: usize, total: usize| {
            assert_eq!(total, 57);
            count.fetch_add(1, Ordering::Relaxed);
        };
        let par = hash_directory(
            tmp.path(),
            false,
            DigestAlgorithm::Sha512,
            &HashOptions {
                threads: 8,
                progress: Some(&progress),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(seq, par);
        assert_eq!(count.load(Ordering::Relaxed), 57);
    }

    #[test]
    fn cancelacion() {
        let tmp = tree();
        let cancel = AtomicBool::new(true);
        let r = hash_directory(
            tmp.path(),
            true,
            DigestAlgorithm::Sha256,
            &HashOptions {
                cancel: Some(&cancel),
                ..Default::default()
            },
        );
        assert!(matches!(r, Err(HashError::Cancelled)));
    }

    #[cfg(unix)]
    #[test]
    fn fichero_ilegible_es_un_error() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tree();
        let f = tmp.path().join("secreto.txt");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&f).is_ok() {
            return; // Ejecutando como root.
        }
        let r = hash_directory(tmp.path(), false, DigestAlgorithm::Sha256, &HashOptions::default());
        assert!(matches!(r, Err(HashError::Io { ref path, .. }) if path == &f), "{r:?}");
    }

    #[test]
    fn comprobacion_e_informe() {
        let tmp = tree();
        let root = tmp.path();
        let doc = hash_directory(root, true, DigestAlgorithm::Sha256, &HashOptions::default()).unwrap();
        let report = check_directory(root, &doc, &HashOptions::default()).unwrap();
        assert!(!report.has_errors());
        assert_eq!(report.processed_files_count(), 3);
        assert_eq!(
            String::from_utf8(report.to_xml().unwrap()).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n\
<entries hashAlgorithm=\"SHA-256\" recursive=\"true\">\n    <matching_hash>\n        \
<entry name=\"sub/deep/datos.bin\"/>\n        <entry name=\"sub/hola.txt\"/>\n        \
<entry name=\"vacio.txt\"/>\n    </matching_hash>\n</entries>\n"
        );

        fs::write(root.join("sub/hola.txt"), b"adios\n").unwrap();
        fs::remove_file(root.join("sub/deep/datos.bin")).unwrap();
        fs::write(root.join("nuevo.txt"), b"n").unwrap();
        let report = check_directory(root, &doc, &HashOptions::default()).unwrap();
        assert!(report.has_errors());
        assert_eq!(report.matching_hash, ["vacio.txt"]);
        assert_eq!(report.not_matching_hash, ["sub/hola.txt"]);
        assert_eq!(report.hash_without_file, ["sub/deep/datos.bin"]);
        assert_eq!(report.file_without_hash, ["nuevo.txt"]);
        assert_eq!(
            String::from_utf8(report.to_xml().unwrap()).unwrap(),
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n",
                "<entries hashAlgorithm=\"SHA-256\" recursive=\"true\">\n",
                "    <matching_hash>\n        <entry name=\"vacio.txt\"/>\n    </matching_hash>\n",
                "    <not_matching_hash>\n        <entry name=\"sub/hola.txt\"/>\n    </not_matching_hash>\n",
                "    <hash_without_file>\n        <entry name=\"sub/deep/datos.bin\"/>\n    </hash_without_file>\n",
                "    <file_without_hash>\n        <entry name=\"nuevo.txt\"/>\n    </file_without_hash>\n",
                "</entries>\n"
            )
        );
    }

    #[test]
    fn comprobacion_no_recursiva_segun_documento() {
        let tmp = tree();
        let root = tmp.path();
        let doc = hash_directory(root, false, DigestAlgorithm::Sha384, &HashOptions::default()).unwrap();
        let report = check_directory(root, &doc, &HashOptions::default()).unwrap();
        assert!(!report.has_errors());
        assert_eq!(report.matching_hash, ["vacio.txt"]);
        assert_eq!(report.algorithm, DigestAlgorithm::Sha384);
        assert!(!report.recursive);
    }

    #[test]
    fn rutas_de_windows() {
        let tmp = tree();
        let root = tmp.path();
        let mut doc = HashDocument::new(DigestAlgorithm::Sha256, true);
        doc.entries
            .insert("sub\\hola.txt".into(), DigestAlgorithm::Sha256.digest(b"hola\n"));
        doc.entries
            .insert("sub\\deep\\datos.bin".into(), DigestAlgorithm::Sha256.digest(b"otro"));
        doc.entries
            .insert("vacio.txt".into(), DigestAlgorithm::Sha256.digest(b""));
        doc.entries
            .insert("falta\\x.txt".into(), DigestAlgorithm::Sha256.digest(b""));
        let report = check_directory(root, &doc, &HashOptions::default()).unwrap();
        assert_eq!(report.matching_hash, ["sub/hola.txt", "vacio.txt"]);
        assert_eq!(report.not_matching_hash, ["sub/deep/datos.bin"]);
        assert_eq!(report.hash_without_file, ["falta\\x.txt"]);
        assert!(report.file_without_hash.is_empty());
    }

    #[test]
    fn informe_vacio() {
        let report = HashReport::new(DigestAlgorithm::Sha1, false);
        assert_eq!(
            String::from_utf8(report.to_xml().unwrap()).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n\
<entries hashAlgorithm=\"SHA-1\" recursive=\"false\"/>\n"
        );
    }

    #[test]
    fn el_documento_dentro_del_directorio_no_tiene_huella() {
        let tmp = tree();
        let root = tmp.path();
        let doc = hash_directory(root, false, DigestAlgorithm::Sha256, &HashOptions::default()).unwrap();
        let path = root.join("dir.hashfiles");
        fs::write(&path, doc.to_xml().unwrap()).unwrap();
        let report = check_directory_with_file(root, &path, &HashOptions::default()).unwrap();
        assert_eq!(report.file_without_hash, ["dir.hashfiles"]);
        assert!(report.has_errors());
    }

    #[test]
    fn nombres_por_defecto() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mis datos");
        fs::create_dir(&dir).unwrap();
        assert_eq!(
            default_directory_document_name(&dir, DirDocumentFormat::Xml),
            "mis datos.hashfiles"
        );
        assert_eq!(
            default_directory_document_name(&dir.join("."), DirDocumentFormat::Txt),
            "mis datos.txthashfiles"
        );
        assert_eq!(default_report_dir(&dir).unwrap(), tmp.path());
    }
}
