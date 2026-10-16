//! Interoperabilidad del almacén JKS con Java: ficheros creados por
//! `keytool` y por `TrustStoreManager` de AutoFirma Java
//! (`testdata/keystores/jks`, regenerables con su `gen.sh`) y, si `keytool`
//! está instalado, comprobaciones en vivo en ambos sentidos.

use std::path::{Path, PathBuf};
use std::process::Command;

use afirma_keystores::jks::{
    JKS_VERSION_1, JKS_VERSION_2, JksEntryKind, JksError, JksKeyStore, TrustStore, parse_certificate_file,
};
use sha2::{Digest, Sha256};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/keystores/jks")
}

fn cert(name: &str) -> Vec<u8> {
    parse_certificate_file(&std::fs::read(dir().join(name)).unwrap())
        .unwrap()
        .remove(0)
}

fn sha256_hex(d: &[u8]) -> String {
    hex::encode(Sha256::digest(d))
}

#[test]
fn reads_keytool_store_and_skips_private_keys() {
    let data = std::fs::read(dir().join("keytool.jks")).unwrap();
    let ks = JksKeyStore::parse(&data, Some("changeit")).unwrap();
    assert!(matches!(
        JksKeyStore::parse(&data, Some("otra")),
        Err(JksError::Integrity)
    ));
    let mut aliases: Vec<&str> = ks.entries.iter().map(|e| e.alias.as_str()).collect();
    aliases.sort();
    assert_eq!(aliases, ["clave", "mi raíz", "otra"]);
    let key = ks.entries.iter().find(|e| e.alias == "clave").unwrap();
    let JksEntryKind::PrivateKey { chain, protected_key } = &key.kind else {
        panic!("entrada de clave")
    };
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].0, "X.509");
    assert!(!protected_key.is_empty());

    let ts = TrustStore::open_or_create(dir().join("keytool.jks"), "changeit").unwrap();
    let mut certs = ts.certificates();
    certs.sort_by(|a, b| a.alias.cmp(&b.alias));
    assert_eq!(certs.len(), 2);
    assert_eq!((certs[0].alias.as_str(), &certs[0].der), ("mi raíz", &cert("a.crt")));
    assert_eq!((certs[1].alias.as_str(), &certs[1].der), ("otra", &cert("b.crt")));

    // Reescribir el fichero de keytool reproduce los mismos bytes.
    assert_eq!(ks.to_bytes("changeit").unwrap().len(), data.len());
    let back = JksKeyStore::parse(&ks.to_bytes("changeit").unwrap(), Some("changeit")).unwrap();
    assert_eq!(back, ks);
}

/// `TrustStoreManager.importCerts` de Java con a, a2 (mismo titular), b,
/// emoji y a (repetido): mismos alias y certificados que nuestra
/// implementación.
#[test]
fn alias_rules_match_java_truststore_manager() {
    let listing: Vec<(String, String)> = std::fs::read_to_string(dir().join("java-truststore.txt"))
        .unwrap()
        .lines()
        .map(|l| {
            let (a, h) = l.split_once('\t').unwrap();
            (a.to_string(), h.to_string())
        })
        .collect();
    assert_eq!(listing.len(), 4);

    let java = TrustStore::open_or_create(dir().join("java-truststore.jks"), "changeit").unwrap();
    let mut read: Vec<(String, String)> = java
        .certificates()
        .into_iter()
        .map(|c| (c.alias, sha256_hex(&c.der)))
        .collect();
    read.sort();
    assert_eq!(read, listing);

    let tmp = tempfile::tempdir().unwrap();
    let mut ours = TrustStore::open_or_create(tmp.path().join("ts.jks"), "changeit").unwrap();
    let certs: Vec<Vec<u8>> = ["a.crt", "a2.crt", "b.crt", "emoji.crt", "a.crt"]
        .iter()
        .map(|c| cert(c))
        .collect();
    assert_eq!(ours.import(&certs).unwrap(), 4);
    let mut mine: Vec<(String, String)> = ours
        .certificates()
        .into_iter()
        .map(|c| (c.alias, sha256_hex(&c.der)))
        .collect();
    mine.sort();
    assert_eq!(mine, listing);
}

fn keytool() -> Option<Command> {
    let ok = Command::new("keytool")
        .arg("-help")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("keytool no disponible: prueba omitida");
        return None;
    }
    let mut c = Command::new("keytool");
    c.args([
        "-J-Duser.language=en",
        "-J-Dfile.encoding=UTF-8",
        "-J-Dstdout.encoding=UTF-8",
    ]);
    Some(c)
}

fn run(mut c: Command) -> (bool, Vec<u8>, String) {
    let o = c.output().unwrap();
    (
        o.status.success(),
        o.stdout,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// `keytool -exportcert` de un alias (DER).
fn export(store: &Path, alias: &str) -> Option<Vec<u8>> {
    let mut c = keytool()?;
    c.args(["-exportcert", "-keystore"])
        .arg(store)
        .args(["-storepass", "changeit", "-alias", alias]);
    let (ok, out, _) = run(c);
    ok.then_some(out)
}

#[test]
fn keytool_reads_what_we_write() {
    let Some(mut list) = keytool() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(".afirma").join("TrustedCertsKeystore.jks");
    let mut ts = TrustStore::open_or_create(&path, "changeit").unwrap();
    for c in ["a.crt", "a2.crt", "b.crt", "emoji.crt"] {
        assert!(ts.add(&cert(c)).unwrap());
    }
    ts.save().unwrap();

    list.args(["-list", "-keystore"])
        .arg(&path)
        .args(["-storepass", "changeit"]);
    let (ok, out, err) = run(list);
    assert!(ok, "keytool -list: {err}");
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Your keystore contains 4 entries"), "{text}");
    assert_eq!(text.matches("trustedCertEntry").count(), 4, "{text}");
    for c in ts.certificates() {
        // En Windows Java decodifica los argumentos con la página de códigos ANSI: un
        // alias con emoji no llega íntegro a keytool (el almacén sí es correcto: -list
        // ve las 4 entradas).
        if cfg!(windows) && !c.alias.is_ascii() {
            continue;
        }
        assert_eq!(
            export(&path, &c.alias).as_deref(),
            Some(c.der.as_slice()),
            "alias {}",
            c.alias
        );
    }

    // Contraseña incorrecta: keytool lo detecta.
    let mut bad = keytool().unwrap();
    bad.args(["-list", "-keystore"]).arg(&path).args(["-storepass", "otra"]);
    let (ok, _, _) = run(bad);
    assert!(!ok);

    // También la versión 1 del formato.
    let v1 = tmp.path().join("v1.jks");
    std::fs::write(
        &v1,
        ts.keystore().to_bytes_with_version("changeit", JKS_VERSION_1).unwrap(),
    )
    .unwrap();
    let alias = &ts.certificates()[2].alias;
    assert_eq!(export(&v1, alias), Some(cert("b.crt")));
}

#[test]
fn keytool_store_round_trip_keeps_private_key() {
    let Some(mut gen_key) = keytool() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("k.jks");
    gen_key
        .args(["-genkeypair", "-keystore"])
        .arg(&path)
        .args([
            "-storetype",
            "JKS",
            "-storepass",
            "changeit",
            "-keypass",
            "changeit",
            "-alias",
            "Clave Uno",
        ])
        .args([
            "-keyalg",
            "EC",
            "-groupname",
            "secp256r1",
            "-dname",
            "CN=Clave Uno, C=ES",
            "-validity",
            "30",
        ]);
    let (ok, _, err) = run(gen_key);
    assert!(ok, "{err}");
    let mut import = keytool().unwrap();
    import
        .args(["-importcert", "-noprompt", "-keystore"])
        .arg(&path)
        .args(["-storetype", "JKS", "-storepass", "changeit", "-alias", "CA B"])
        .arg("-file")
        .arg(dir().join("b.crt"));
    let (ok, _, err) = run(import);
    assert!(ok, "{err}");

    // Lectura en Rust, alta de un certificado y escritura.
    let mut ts = TrustStore::open_or_create(&path, "changeit").unwrap();
    assert_eq!(ts.certificates().len(), 1);
    assert_eq!(ts.certificates()[0].alias, "ca b");
    assert!(!ts.add(&cert("b.crt")).unwrap());
    assert!(ts.add(&cert("a.crt")).unwrap());
    ts.save().unwrap();
    let data = std::fs::read(&path).unwrap();
    assert_eq!(&data[..8], [0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, JKS_VERSION_2 as u8]);

    // keytool sigue pudiendo usar la clave privada (bytes protegidos intactos).
    let mut req = keytool().unwrap();
    req.args(["-certreq", "-keystore"]).arg(&path).args([
        "-storepass",
        "changeit",
        "-keypass",
        "changeit",
        "-alias",
        "clave uno",
    ]);
    let (ok, out, err) = run(req);
    assert!(ok, "keytool -certreq: {err}");
    assert!(String::from_utf8_lossy(&out).contains("BEGIN NEW CERTIFICATE REQUEST"));
    assert_eq!(
        export(&path, "cn=raíz pruebas jks, o=autofirma-rs pruebas, c=es"),
        Some(cert("a.crt"))
    );
}
