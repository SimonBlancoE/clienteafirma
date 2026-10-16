//! Pruebas diferenciales en vivo con el plugin de huellas de Java: Java
//! comprueba los documentos y huellas generados aquí y viceversa.
//!
//! Solo se ejecutan si `AFIRMA_HASH_ORACLE` apunta al lanzador que deja
//! `tools/oracle/hash_oracle.sh` (`$W/run.sh`); si no, no hacen nada.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use afirma_hash::{
    DigestAlgorithm, DirDocumentFormat, FileHashFormat, GUI_ALGORITHMS, HashDocument, HashOptions,
    check_directory, encode_file_hash, hash_directory, hash_file,
};
use common::{make_tree, normalize};

const OK: &str = "Comprobacion de huella digital finalizada sin errores\n";

fn oracle() -> Option<PathBuf> {
    std::env::var_os("AFIRMA_HASH_ORACLE").map(PathBuf::from)
}

fn java(oracle: &Path, args: &[&Path]) -> (i32, String) {
    let out = Command::new(oracle)
        .args(args)
        .output()
        .expect("ejecutar el oráculo Java");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

/// Java verifica los documentos de directorio que generamos (y su informe es
/// igual al nuestro).
fn java_checks_our_documents(
    oracle: &Path,
    tree: &Path,
    out: &Path,
    formats: &[DirDocumentFormat],
) {
    for alg in GUI_ALGORITHMS {
        for recursive in [false, true] {
            for &format in formats {
                let doc = hash_directory(tree, recursive, alg, &HashOptions::default()).unwrap();
                let file = out.join(format!("rust-{alg}-{recursive}.{}", format.extension()));
                fs::write(&file, doc.generate(format).unwrap()).unwrap();
                let report = out.join("java.hashreport");
                let (status, stdout) = java(
                    oracle,
                    &[&p("checkdigest"), tree, &p("-i"), &file, &p("-o"), &report],
                );
                assert_eq!((status, stdout.as_str()), (0, OK), "{}", file.display());
                let ours = check_directory(tree, &doc, &HashOptions::default()).unwrap();
                assert_eq!(
                    normalize(&ours.to_xml().unwrap()),
                    normalize(&fs::read(&report).unwrap())
                );
            }
        }
    }
}

/// Nosotros verificamos los documentos que genera Java y producimos el mismo texto.
fn we_check_java_documents(oracle: &Path, tree: &Path, out: &Path, formats: &[DirDocumentFormat]) {
    for alg in GUI_ALGORITHMS {
        for recursive in [false, true] {
            for &format in formats {
                let file = out.join(format!("java-{alg}-{recursive}.{}", format.extension()));
                let mut args = vec![
                    p("createdigest"),
                    tree.to_path_buf(),
                    p("-halgorithm"),
                    p(alg.name()),
                ];
                args.extend([p("-hformat"), p(format.cli_name()), p("-o"), file.clone()]);
                if recursive {
                    args.push(p("-r"));
                }
                let refs: Vec<&Path> = args.iter().map(PathBuf::as_path).collect();
                let (status, _) = java(oracle, &refs);
                assert_eq!(status, 0);
                let java_doc = fs::read(&file).unwrap();
                let doc = HashDocument::parse(&java_doc).unwrap();
                assert_eq!((doc.algorithm, doc.recursive), (alg, recursive));
                let report = check_directory(tree, &doc, &HashOptions::default()).unwrap();
                assert!(!report.has_errors(), "{report:?}");
                let ours = hash_directory(tree, recursive, alg, &HashOptions::default()).unwrap();
                assert_eq!(
                    normalize(&ours.generate(format).unwrap()),
                    normalize(&java_doc),
                    "{}",
                    file.display()
                );
            }
        }
    }
}

#[test]
fn java_y_rust_se_verifican_mutuamente() {
    let Some(oracle) = oracle() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    make_tree(&tree);
    let both = [DirDocumentFormat::Xml, DirDocumentFormat::Txt];
    java_checks_our_documents(&oracle, &tree, &out, &both);
    we_check_java_documents(&oracle, &tree, &out, &both);

    // Huellas de fichero.
    let hola = tree.join("sub/hola.txt");
    for alg in GUI_ALGORITHMS.into_iter().chain([DigestAlgorithm::Sha224]) {
        for format in FileHashFormat::ALL {
            let file = out.join(format!("hola-{alg}.{}", format.extension()));
            fs::write(
                &file,
                encode_file_hash(&hash_file(&hola, alg).unwrap(), format),
            )
            .unwrap();
            let (status, stdout) = java(&oracle, &[&p("checkdigest"), &hola, &p("-i"), &file]);
            assert_eq!((status, stdout.as_str()), (0, OK), "{}", file.display());
        }
    }
}

#[cfg(unix)]
#[test]
fn nombres_especiales() {
    let Some(oracle) = oracle() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    fs::create_dir_all(&out).unwrap();
    // XML: todos los caracteres que hay que escapar.
    let tree = tmp.path().join("xml");
    fs::create_dir_all(tree.join("sub dir")).unwrap();
    for name in [
        "a&b<c>d\"e'f.txt",
        "tab\tx.txt",
        "nl\nx.txt",
        "cr\rx.txt",
        "back\\slash.txt",
        "semi;colon.txt",
        "sub dir/ñ ü €.txt",
    ] {
        fs::write(tree.join(name), name).unwrap();
    }
    java_checks_our_documents(&oracle, &tree, &out, &[DirDocumentFormat::Xml]);
    we_check_java_documents(&oracle, &tree, &out, &[DirDocumentFormat::Xml]);
    // TXT: Java separa por el primer `;` y no admite saltos de línea.
    let tree = tmp.path().join("txt");
    fs::create_dir_all(tree.join("sub dir")).unwrap();
    for name in [
        "a&b<c>d\"e'f.txt",
        "tab\tx.txt",
        "back\\slash.txt",
        "sub dir/ñ ü €.txt",
    ] {
        fs::write(tree.join(name), name).unwrap();
    }
    java_checks_our_documents(&oracle, &tree, &out, &[DirDocumentFormat::Txt]);
    we_check_java_documents(&oracle, &tree, &out, &[DirDocumentFormat::Txt]);
}
