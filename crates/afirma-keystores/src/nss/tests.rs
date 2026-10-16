//! Pruebas reales con NSS del sistema: se crean bases de datos NSS
//! temporales con `certutil`/`pk12util`, se importan los PKCS#12 de
//! `testdata/pki` y se firma a través de `softokn3`. Si NSS o sus
//! herramientas no están instalados, las pruebas se omiten.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};

use super::*;
use crate::callback::{CancelAll, FixedPassword, NoPassword};
use crate::store::KeyStore;

use crate::NSS_TEST_LOCK as NSS;

fn pki(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pki")
        .join(name)
}

fn tool(name: &str) -> bool {
    Command::new(name).arg("-H").output().is_ok()
}

/// Crea una base de datos NSS (SQLite) con los PKCS#12 indicados.
fn make_db(dir: &Path, password: Option<&str>, p12s: &[&str]) -> bool {
    let pwfile = dir.join("pw.txt");
    std::fs::write(&pwfile, password.unwrap_or("")).unwrap();
    let db = format!("sql:{}", dir.display());
    let mut cmd = Command::new("certutil");
    cmd.args(["-N", "-d", &db]);
    match password {
        Some(_) => cmd.args(["-f", &pwfile.to_string_lossy()]),
        None => cmd.arg("--empty-password"),
    };
    if !cmd.output().map(|o| o.status.success()).unwrap_or(false) {
        return false;
    }
    for p in p12s {
        let ok = Command::new("pk12util")
            .args([
                "-i",
                &pki(p).to_string_lossy(),
                "-d",
                &db,
                "-W",
                "12341234",
                "-k",
                &pwfile.to_string_lossy(),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            return false;
        }
    }
    true
}

fn setup() -> Option<PathBuf> {
    if !tool("certutil") || !tool("pk12util") {
        eprintln!("certutil/pk12util no disponibles: se omite la prueba NSS");
        return None;
    }
    match libdir::nss_lib_dir(&MozEnv::current(), None) {
        Ok(d) => Some(d),
        Err(e) => {
            eprintln!("NSS no disponible: {e}");
            None
        }
    }
}

fn sign_all(store: &dyn KeyStore) {
    for (alias, key) in [("firmante-rsa", KeyAlgorithm::Rsa), ("firmante-ec", KeyAlgorithm::Ec)] {
        let k = store.signing_key(alias).unwrap_or_else(|e| panic!("{alias}: {e}"));
        for d in [
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let alg = SignatureAlgorithm::new(d, key);
            let sig = k
                .sign(b"datos NSS", alg)
                .unwrap_or_else(|e| panic!("{alias} {alg}: {e}"));
            crate::verify::verify_signature(k.certificate(), alg, b"datos NSS", &sig)
                .unwrap_or_else(|e| panic!("{alias} {alg}: {e}"));
        }
    }
}

#[test]
fn init_string() {
    assert_eq!(
        nss_init_string(Path::new("/home/u/.pki/nssdb"), true, false),
        "configdir='sql:/home/u/.pki/nssdb' certPrefix='' keyPrefix='' flags='readOnly'"
    );
    assert_eq!(
        nss_init_string(Path::new("/a b/c'd"), false, true),
        "configdir='/a b/c\\'d' certPrefix='' keyPrefix='' "
    );
}

#[test]
fn nss_db_without_password() {
    let Some(lib_dir) = setup() else { return };
    let _g = NSS.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    assert!(
        make_db(tmp.path(), None, &["firmante-rsa.p12", "firmante-ec.p12"]),
        "no se pudo crear la base de datos NSS"
    );
    assert!(use_sql_db(tmp.path(), &NssOptions::default()));
    let store = open_internal(
        &lib_dir,
        tmp.path(),
        KeyStoreKind::SharedNss,
        &NssOptions::default(),
        Arc::new(NoPassword),
    )
    .unwrap();
    assert_eq!(store.kind(), KeyStoreKind::SharedNss);
    let entries = store.entries().unwrap();
    let mut aliases = store.aliases().unwrap();
    aliases.sort();
    assert_eq!(
        aliases,
        vec!["firmante-ec".to_string(), "firmante-rsa".to_string()],
        "{entries:?}"
    );
    // La CA importada aparece sin clave.
    assert!(
        entries
            .iter()
            .any(|e| !e.capabilities.has_private_key && e.friendly_name == "AC Raiz de Pruebas AutoFirma-rs")
    );
    let rsa = entries.iter().find(|e| e.alias == "firmante-rsa").unwrap();
    assert!(!rsa.capabilities.hardware);
    assert_eq!(rsa.source, "NSS");
    assert_eq!(rsa.chain.len(), 2);
    sign_all(&store);
}

#[test]
fn nss_db_with_master_password() {
    let Some(lib_dir) = setup() else { return };
    let _g = NSS.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    assert!(make_db(
        tmp.path(),
        Some("maestra"),
        &["firmante-rsa.p12", "firmante-ec.p12"]
    ));
    // Contraseña errónea (sin reintentos en NSS).
    let r = open_internal(
        &lib_dir,
        tmp.path(),
        KeyStoreKind::MozUni,
        &NssOptions::default(),
        Arc::new(FixedPassword::new("mala")),
    );
    assert!(matches!(r, Err(KeyStoreError::WrongPin { .. })), "{:?}", r.err());
    let r = open_internal(
        &lib_dir,
        tmp.path(),
        KeyStoreKind::MozUni,
        &NssOptions::default(),
        Arc::new(CancelAll),
    );
    assert!(matches!(r, Err(KeyStoreError::Cancelled)), "{:?}", r.err());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let a2 = asked.clone();
    let cb = Arc::new(crate::callback::FnPasswordCallback(
        move |r: &crate::PasswordRequest| {
            a2.lock().unwrap().push(r.prompt.clone());
            crate::PasswordResponse::provided("maestra")
        },
    ));
    let store = open_internal(&lib_dir, tmp.path(), KeyStoreKind::MozUni, &NssOptions::default(), cb).unwrap();
    assert_eq!(
        *asked.lock().unwrap(),
        vec!["Introduzca la contraseña del almacén de claves de Mozilla Firefox.".to_string()]
    );
    assert_eq!(store.aliases().unwrap().len(), 2);
    sign_all(&store);
}

#[test]
fn firefox_profile_end_to_end() {
    let Some(lib_dir) = setup() else { return };
    let _g = NSS.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let ff = home.path().join(".mozilla/firefox");
    let profile = ff.join("abcd.default-release");
    std::fs::create_dir_all(&profile).unwrap();
    assert!(make_db(&profile, None, &["firmante-rsa.p12"]));
    // Un perfil real tiene muchos ficheros (si no, se descarta).
    for i in 0..10 {
        std::fs::write(profile.join(format!("relleno{i}.json")), b"{}").unwrap();
    }
    std::fs::write(
        ff.join("profiles.ini"),
        "[Install4F96D1932A9F858E]\nDefault=abcd.default-release\nLocked=1\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=abcd.default-release\n\n[General]\nStartWithLastProfile=1\nVersion=2\n",
    )
    .unwrap();
    let env = MozEnv {
        os: Os::current(),
        home: home.path().to_path_buf(),
        user_name: None,
        vars: BTreeMap::new(),
    };
    let dir = firefox_profile_dir(&env).unwrap();
    assert_eq!(dir, profile);
    assert!(is_firefox_available(&env));
    assert_eq!(libdir::nss_lib_dir(&env, Some(&dir)).unwrap(), lib_dir);
    // pkcs11.txt creado por certutil: solo el módulo interno (se ignora).
    assert!(external_modules(&dir, &env, &ModuleFilter::default()).is_empty());
    let store = open_internal(
        &lib_dir,
        &dir,
        KeyStoreKind::MozUni,
        &NssOptions::default(),
        Arc::new(NoPassword),
    )
    .unwrap();
    assert_eq!(store.aliases().unwrap(), vec!["firmante-rsa".to_string()]);
    let k = store.signing_key("firmante-rsa").unwrap();
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    crate::verify::sign_and_verify(k.as_ref(), b"x", alg).unwrap();
}
