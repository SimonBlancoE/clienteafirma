//! Comparación con ficheros de referencia generados por la AutoFirma Java / el JDK
//! (`tools/oracle/system/JPrefsGolden.java`).

use std::path::PathBuf;

use afirma_system::prefs::proxy;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/system")
        .join(name)
}

// Los nombres de directorio alt-base64 del JDK contienen «"», no válido en Windows.
#[cfg(unix)]
#[test]
fn lee_el_arbol_java_util_prefs_del_jdk() {
    use afirma_system::prefs::legacy;
    use afirma_system::prefs::tree::{NODE_AFIRMA_ROOT, NODE_MAIN};
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(testdata("java-userprefs.json")).unwrap()).unwrap();
    let t = tempfile::tempdir().unwrap();
    for (rel, xml) in doc["files"].as_object().unwrap() {
        let dir = t.path().join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("prefs.xml"), xml.as_str().unwrap()).unwrap();
    }
    let tree = legacy::read_unix_tree(t.path(), NODE_AFIRMA_ROOT).unwrap();
    assert_eq!(tree.get(NODE_MAIN, "preferencesBlocked"), Some("true"));
    assert_eq!(
        tree.get(NODE_MAIN, "signatureHashAlgorithm"),
        Some("SHA512")
    );
    assert_eq!(
        tree.get(NODE_MAIN, "pdfLayer2Text"),
        Some("Firmado por $$SUBJECTCN$$ el día <hoy> & \"mañana\"")
    );
    assert_eq!(
        tree.get("/es/gob/afirma/core/keystores/1", "Tarjeta España"),
        Some("/usr/lib/libpkcs11-españa.so")
    );
    // Nodo con «.»: el JDK usa «_» + alt-base64 de UTF-16BE como nombre de directorio.
    assert_eq!(
        tree.get("/es/gob/afirma/plugin/hash.v2", "createHashAlgorithm"),
        Some("SHA-256")
    );
    assert_eq!(legacy::unix_dir_name("hash.v2"), "_!'g!}@\"z!'g!.g\"2!$)=");
}

#[test]
fn cifrado_de_la_contrasena_del_proxy_igual_que_java() {
    let text = std::fs::read_to_string(testdata("java-proxy-cipher.tsv")).unwrap();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (plain, ciphered) = line.split_once('\t').unwrap();
        assert_eq!(
            proxy::cipher_password(plain).as_deref(),
            Some(ciphered),
            "{plain}"
        );
        assert_eq!(proxy::decipher_password(ciphered).as_deref(), Some(plain));
    }
}
