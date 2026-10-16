//! Pruebas reales contra NSS (Linux): crea perfiles de Firefox y una base `~/.pki/nssdb`
//! en un HOME temporal con `certutil -N` e instala/comprueba/retira la CA con `certutil` y
//! con `softokn3` vía PKCS#11. Se omiten si no hay `certutil` o `libsoftokn3`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use afirma_system::certs::{self, CertProfile, Regenerate};
use afirma_system::ctx::{Context, Os};
use afirma_system::exec::{Cmd, CommandRunner, SystemRunner};
use afirma_system::trust::nss::{self, Backend, NssPurpose};
use afirma_system::trust::{Change, TrustCheck};

fn certutil() -> Option<PathBuf> {
    SystemRunner.which("certutil")
}

fn softokn() -> Option<PathBuf> {
    [
        "/usr/lib64/libsoftokn3.so",
        "/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
        "/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so",
        "/usr/lib/libsoftokn3.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

fn new_db(certutil: &Path, dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let o = SystemRunner
        .run(&Cmd::new(certutil.to_string_lossy().into_owned()).args([
            "-N",
            "-d",
            &format!("sql:{}", dir.display()),
            "--empty-password",
        ]))
        .unwrap();
    assert!(o.success(), "certutil -N: {}", o.message());
}

fn list(certutil: &Path, dir: &Path) -> String {
    SystemRunner
        .run(&Cmd::new(certutil.to_string_lossy().into_owned()).args(["-L", "-d", &format!("sql:{}", dir.display())]))
        .unwrap()
        .stdout
}

fn setup() -> Option<(tempfile::TempDir, Context, PathBuf)> {
    let cu = certutil()?;
    let t = tempfile::tempdir().unwrap();
    let mut ctx = Context::for_tests(Os::Linux, t.path());
    ctx.runner = Arc::new(SystemRunner);
    let home = ctx.paths.home.clone();
    // Firefox clásico y snap, más la base compartida de Chrome.
    for (root, prof) in [
        (".mozilla/firefox", "abcd.default-release"),
        ("snap/firefox/common/.mozilla/firefox", "snap.default"),
    ] {
        let r = home.join(root);
        new_db(&cu, &r.join(prof));
        std::fs::write(
            r.join("profiles.ini"),
            format!("[Profile0]\nName=default\nIsRelative=1\nPath={prof}\nDefault=1\n\n[General]\nVersion=2\n"),
        )
        .unwrap();
    }
    // Perfil sin base de datos: no se debe crear.
    std::fs::create_dir_all(home.join(".mozilla/firefox/vacio")).unwrap();
    let ini = home.join(".mozilla/firefox/profiles.ini");
    let mut text = std::fs::read_to_string(&ini).unwrap();
    text.push_str("\n[Profile1]\nName=vacio\nIsRelative=1\nPath=vacio\n");
    std::fs::write(&ini, text).unwrap();
    new_db(&cu, &home.join(".pki/nssdb"));
    Some((t, ctx, cu))
}

fn run_backend(ctx: &Context, cu: &Path, backend: &Backend) {
    let dir = ctx.paths.root.join("certs");
    let local = certs::ensure(ctx, &dir, Regenerate::IfInvalid, None, &CertProfile::default())
        .unwrap()
        .certs;
    let users = ctx.user_homes(false);
    let dbs = nss::discover(ctx, &users, true, true);
    assert_eq!(dbs.len(), 3, "{dbs:#?}");
    assert!(!ctx.paths.home.join(".mozilla/firefox/vacio/cert9.db").exists());
    // Una CA antigua instalada previamente (como dejaría la versión Java) se sustituye.
    let old = certs::generate(&CertProfile::default()).unwrap();
    let old_file = ctx.paths.root.join("old.cer");
    std::fs::write(&old_file, &old.ca_der).unwrap();
    for db in &dbs {
        assert_eq!(nss::check(ctx, db, backend, &local.ca_der), TrustCheck::Missing);
        assert_eq!(
            nss::install(ctx, db, backend, &old.ca_der, &old_file).unwrap(),
            Change::Changed
        );
        assert!(matches!(
            nss::check(ctx, db, backend, &local.ca_der),
            TrustCheck::Mismatch(_)
        ));
        assert_eq!(
            nss::install(ctx, db, backend, &local.ca_der, &local.ca_path()).unwrap(),
            Change::Changed
        );
        assert_eq!(
            nss::check(ctx, db, backend, &local.ca_der),
            TrustCheck::Trusted,
            "{}",
            db.description
        );
        assert_eq!(
            nss::install(ctx, db, backend, &local.ca_der, &local.ca_path()).unwrap(),
            Change::Unchanged
        );
        // Verificación independiente con certutil: un único SocketAutoFirma con la confianza de Java.
        let l = list(cu, &db.dir);
        assert_eq!(l.matches("SocketAutoFirma").count(), 1, "{l}");
        // certutil normaliza «TCP,TCP,TCP» de una CA como «CT,C,C»; el módulo PKCS#11 debe
        // producir exactamente la misma confianza.
        let expected = if db.purpose == NssPurpose::Firefox {
            "C,,"
        } else {
            "CT,C,C"
        };
        let line = l.lines().find(|x| x.starts_with("SocketAutoFirma")).unwrap();
        assert_eq!(line.split_whitespace().last().unwrap(), expected, "{l}");
        assert_eq!(nss::remove(ctx, db, backend).unwrap(), Change::Changed);
        assert_eq!(nss::check(ctx, db, backend, &local.ca_der), TrustCheck::Missing);
        assert!(!list(cu, &db.dir).contains("SocketAutoFirma"));
    }
}

#[test]
fn nss_con_certutil() {
    let Some((_t, ctx, cu)) = setup() else {
        eprintln!("certutil no disponible: prueba omitida");
        return;
    };
    run_backend(&ctx, &cu, &Backend::Certutil(cu.clone()));
}

#[test]
fn nss_con_softokn_pkcs11() {
    let (Some((_t, ctx, cu)), Some(lib)) = (setup(), softokn()) else {
        eprintln!("certutil o libsoftokn3 no disponibles: prueba omitida");
        return;
    };
    run_backend(&ctx, &cu, &Backend::Softokn(lib));
}

#[test]
fn instalacion_diagnostico_y_desinstalacion_reales() {
    use afirma_system::doctor::{self, CheckStatus, DoctorOptions};
    use afirma_system::install::{self, InstallOptions, UninstallOptions};
    let Some((_t, ctx, cu)) = setup() else {
        eprintln!("certutil no disponible: prueba omitida");
        return;
    };
    let rep = install::install(&ctx, &InstallOptions::default(), false);
    assert!(rep.ok(), "{}", rep.to_text());
    let users = ctx.user_homes(false);
    for db in nss::discover(&ctx, &users, true, true) {
        assert!(list(&cu, &db.dir).contains("SocketAutoFirma"), "{}", db.description);
    }
    let d = doctor::run(
        &ctx,
        &DoctorOptions {
            ports: vec![],
            ..Default::default()
        },
    );
    let nss_checks: Vec<_> = d.checks.iter().filter(|c| c.id == "trust.nss").collect();
    assert_eq!(nss_checks.len(), 3);
    assert!(
        nss_checks.iter().all(|c| c.status == CheckStatus::Ok),
        "{}",
        d.to_text()
    );
    assert!(
        d.checks
            .iter()
            .any(|c| c.id == "protocol" && c.status == CheckStatus::Ok),
        "{}",
        d.to_text()
    );
    assert!(
        d.checks
            .iter()
            .any(|c| c.id == "certs.files" && c.status == CheckStatus::Ok),
        "{}",
        d.to_text()
    );
    // Idempotente.
    let again = install::install(&ctx, &InstallOptions::default(), false);
    assert!(
        again
            .outcomes
            .iter()
            .all(|o| o.status == install::Status::Done(Change::Unchanged)),
        "{}",
        again.to_text()
    );
    let un = install::uninstall(&ctx, &UninstallOptions::default(), false);
    assert!(un.ok(), "{}", un.to_text());
    for db in nss::discover(&ctx, &users, true, true) {
        assert!(!list(&cu, &db.dir).contains("SocketAutoFirma"));
    }
    let d = doctor::run(
        &ctx,
        &DoctorOptions {
            ports: vec![],
            ..Default::default()
        },
    );
    assert_eq!(d.worst(), CheckStatus::Error);
}
