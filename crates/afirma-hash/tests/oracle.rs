//! Pruebas diferenciales con los ficheros de referencia generados por el
//! plugin de huellas de Java (`tools/oracle/hash_oracle.sh`).

mod common;

use afirma_hash::{
    DigestAlgorithm, DirDocumentFormat, DocumentError, FileHashFormat, HashDocument, HashOptions,
    check_directory, decode_file_hash, encode_file_hash, hash_directory, hash_file,
};
use common::{golden, make_tree, modify_tree, normalize};

const DOCS: [(&str, DigestAlgorithm, bool, DirDocumentFormat); 4] = [
    (
        "java-sha256-rec.hashfiles",
        DigestAlgorithm::Sha256,
        true,
        DirDocumentFormat::Xml,
    ),
    (
        "java-sha1-norec.hashfiles",
        DigestAlgorithm::Sha1,
        false,
        DirDocumentFormat::Xml,
    ),
    (
        "java-sha512-rec.txthashfiles",
        DigestAlgorithm::Sha512,
        true,
        DirDocumentFormat::Txt,
    ),
    (
        "java-sha384-norec.txthashfiles",
        DigestAlgorithm::Sha384,
        false,
        DirDocumentFormat::Txt,
    ),
];

#[test]
fn documentos_de_directorio_identicos_a_java() {
    let tmp = tempfile::tempdir().unwrap();
    make_tree(tmp.path());
    for (name, alg, recursive, format) in DOCS {
        let doc = hash_directory(tmp.path(), recursive, alg, &HashOptions::default()).unwrap();
        let ours = doc.generate(format).unwrap();
        let java = golden(name);
        assert_eq!(normalize(&ours), normalize(&java), "{name}");
        // Nuestro lector entiende el documento de Java y el árbol lo verifica.
        let parsed = HashDocument::parse(&java).unwrap();
        assert_eq!(parsed, doc, "{name}");
        let report = check_directory(tmp.path(), &parsed, &HashOptions::default()).unwrap();
        assert!(!report.has_errors(), "{name}: {report:?}");
        assert_eq!(report.matching_hash.len(), doc.entries.len());
    }
}

#[test]
fn entradas_omitidas_como_en_java() {
    let doc = HashDocument::parse(&golden("java-sha256-rec.hashfiles")).unwrap();
    let names: Vec<&str> = doc.entries.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            ".Trashes/papelera.txt",
            ".oculto",
            "Thumbs.db",
            "a&b'c (1).txt",
            "sub/deep/datos.bin",
            "sub/deep/grande.bin",
            "sub/hola.txt",
            "vacio.txt",
            "ñandú é.txt",
        ]
    );
}

#[test]
fn huellas_de_fichero_identicas_a_java() {
    let tmp = tempfile::tempdir().unwrap();
    make_tree(tmp.path());
    let hola = tmp.path().join("sub/hola.txt");
    for (name, alg, format) in [
        (
            "java-hola-sha256.hexhash",
            DigestAlgorithm::Sha256,
            FileHashFormat::Hex,
        ),
        (
            "java-hola-sha256.hashb64",
            DigestAlgorithm::Sha256,
            FileHashFormat::Base64,
        ),
        (
            "java-hola-sha256.hash",
            DigestAlgorithm::Sha256,
            FileHashFormat::Binary,
        ),
        (
            "java-hola-sha1.hexhash",
            DigestAlgorithm::Sha1,
            FileHashFormat::Hex,
        ),
        (
            "java-hola-sha384.hash",
            DigestAlgorithm::Sha384,
            FileHashFormat::Binary,
        ),
        (
            "java-hola-sha512.hashb64",
            DigestAlgorithm::Sha512,
            FileHashFormat::Base64,
        ),
    ] {
        let digest = hash_file(&hola, alg).unwrap();
        let java = golden(name);
        assert_eq!(encode_file_hash(&digest, format), java, "{name}");
        let decoded = decode_file_hash(&java).unwrap();
        assert_eq!(
            (decoded.digest, decoded.encoding, decoded.algorithm),
            (digest, format, alg),
            "{name}"
        );
    }
    // Fichero de 300 000 bytes (varias lecturas).
    let digest = hash_file(
        &tmp.path().join("sub/deep/grande.bin"),
        DigestAlgorithm::Sha512,
    )
    .unwrap();
    assert_eq!(
        encode_file_hash(&digest, FileHashFormat::Hex),
        golden("java-grande-sha512.hexhash")
    );
}

#[test]
fn informes_identicos_a_java() {
    let tmp = tempfile::tempdir().unwrap();
    make_tree(tmp.path());
    modify_tree(tmp.path());
    for (doc, report) in [
        (
            "java-sha256-rec.hashfiles",
            "java-report-sha256-rec.hashreport",
        ),
        (
            "java-sha384-norec.txthashfiles",
            "java-report-sha384-norec.hashreport",
        ),
    ] {
        let doc = HashDocument::parse(&golden(doc)).unwrap();
        let ours = check_directory(tmp.path(), &doc, &HashOptions::default()).unwrap();
        assert!(ours.has_errors());
        assert_eq!(
            normalize(&ours.to_xml().unwrap()),
            normalize(&golden(report)),
            "{report}"
        );
    }
}

#[test]
fn documento_corrupto() {
    assert!(matches!(
        HashDocument::parse(&golden("corrupto.hashfiles")),
        Err(DocumentError::Corrupted(_))
    ));
}
