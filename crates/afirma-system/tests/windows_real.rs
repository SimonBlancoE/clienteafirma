//! Pruebas con el registro y CryptoAPI reales de Windows (se ejecutan en Windows o con Wine
//! en la imagen de compilación cruzada). Usan claves de prueba en `HKCU` y el almacén
//! `CurrentUser\ROOT`.

#![cfg(windows)]

use std::sync::Arc;

use afirma_system::ctx::{Context, Os};
use afirma_system::prefs::legacy::{self, WIN_PREFS_BASE};
use afirma_system::prefs::tree::NODE_MAIN;
use afirma_system::protocol::{self, ProtocolOptions};
use afirma_system::registry::{Hive, RegValue, Registry, WindowsRegistry};
use afirma_system::trust::windows::{self as wtrust, named_cert_store, system_cert_store};
use afirma_system::trust::{Change, TrustCheck, TrustScope};

#[test]
fn registro_real() {
    let r = WindowsRegistry;
    let base = format!(r"Software\AutoFirmaRsTest\{}", std::process::id());
    r.write(
        Hive::CurrentUser,
        &format!(r"{base}\a\b"),
        "Valor",
        &RegValue::Sz("x".into()),
    )
    .unwrap();
    r.write(Hive::CurrentUser, &format!(r"{base}\a"), "", &RegValue::Dword(7))
        .unwrap();
    r.write(
        Hive::CurrentUser,
        &format!(r"{base}\a"),
        "m",
        &RegValue::MultiSz(vec!["uno".into(), "dos".into()]),
    )
    .unwrap();
    assert_eq!(
        r.read_string(Hive::CurrentUser, &format!(r"{base}\a\b"), "valor")
            .unwrap()
            .as_deref(),
        Some("x")
    );
    assert_eq!(
        r.read(Hive::CurrentUser, &format!(r"{base}\a"), "").unwrap(),
        Some(RegValue::Dword(7))
    );
    assert_eq!(
        r.read(Hive::CurrentUser, &format!(r"{base}\a"), "m").unwrap(),
        Some(RegValue::MultiSz(vec!["uno".into(), "dos".into()]))
    );
    assert_eq!(
        r.subkeys(Hive::CurrentUser, &format!(r"{base}\a")).unwrap(),
        Some(vec!["b".to_string()])
    );
    assert!(r.delete_value(Hive::CurrentUser, &format!(r"{base}\a"), "m").unwrap());
    assert!(!r.delete_value(Hive::CurrentUser, &format!(r"{base}\a"), "m").unwrap());
    assert_eq!(
        r.read(Hive::CurrentUser, &format!(r"{base}\noexiste"), "x").unwrap(),
        None
    );
    // Preferencias Java escapadas.
    let k = legacy::win_node_key(&format!(r"{base}\{WIN_PREFS_BASE}"), NODE_MAIN);
    r.write(
        Hive::CurrentUser,
        &k,
        "signature/Hash/Algorithm",
        &RegValue::Sz("/S/H/A512".into()),
    )
    .unwrap();
    let t = legacy::read_windows_tree(
        &r,
        Hive::CurrentUser,
        &format!(r"{base}\{WIN_PREFS_BASE}"),
        "/es/gob/afirma",
    )
    .unwrap();
    assert_eq!(t.get(NODE_MAIN, "signatureHashAlgorithm"), Some("SHA512"));
    assert!(r.delete_tree(Hive::CurrentUser, &base).unwrap());
    assert!(!r.key_exists(Hive::CurrentUser, &base).unwrap());
}

#[test]
fn almacen_root_del_usuario_y_protocolo_reales() {
    let t = tempfile::tempdir().unwrap();
    let mut ctx = Context::for_tests(Os::Windows, t.path());
    ctx.registry = Arc::new(WindowsRegistry);
    ctx.win_certs = system_cert_store();
    let pack = afirma_system::certs::generate(&Default::default()).unwrap();
    // Lógica completa de CryptoAPI sobre un almacén de sistema propio (Wine trata ROOT de
    // forma especial: lo construye con las raíces del anfitrión y no admite borrados).
    let test_store = named_cert_store("AutoFirmaRsTest");
    let ts = test_store.as_ref();
    assert_eq!(
        wtrust::install(ts, TrustScope::User, &pack.ca_der).unwrap(),
        Change::Changed
    );
    assert_eq!(wtrust::check(ts, TrustScope::User, &pack.ca_der), TrustCheck::Trusted);
    assert_eq!(
        wtrust::install(ts, TrustScope::User, &pack.ca_der).unwrap(),
        Change::Unchanged
    );
    let newer = afirma_system::certs::generate(&Default::default()).unwrap();
    assert_eq!(
        wtrust::install(ts, TrustScope::User, &newer.ca_der).unwrap(),
        Change::Changed
    );
    assert_eq!(
        wtrust::check(ts, TrustScope::User, &pack.ca_der),
        TrustCheck::Mismatch("hay una CA de AutoFirma distinta (antigua)".into())
    );
    assert_eq!(wtrust::remove(ts, TrustScope::User).unwrap(), Change::Changed);
    assert_eq!(wtrust::check(ts, TrustScope::User, &newer.ca_der), TrustCheck::Missing);
    // En Windows real, añadir una raíz a CurrentUser\ROOT abre el aviso de seguridad
    // de Windows y la prueba esperaría a que alguien lo acepte: solo se hace si se
    // pide expresamente (en Wine no hay aviso). El almacén del equipo, que no avisa,
    // lo comprueba el trabajo de integración de la CI con `install --system`.
    if std::env::var_os("AUTOFIRMA_TEST_USER_ROOT").is_none() && std::env::var_os("WINEPREFIX").is_none() {
        eprintln!("CurrentUser\\ROOT real omitido (AUTOFIRMA_TEST_USER_ROOT=1 para probarlo)");
    } else {
        user_root_round_trip(&ctx, &pack.ca_der);
    }
    let opts = ProtocolOptions::default();
    assert_eq!(protocol::register(&ctx, &opts).unwrap(), Change::Changed);
    let st = protocol::status(&ctx);
    assert!(st.registered && st.points_to_current, "{st:?}");
    assert_eq!(protocol::unregister(&ctx, &opts).unwrap(), Change::Changed);
    assert!(!protocol::status(&ctx).registered);
}

#[test]
fn borrado_cryptoapi_persistente() {
    let pack = afirma_system::certs::generate(&Default::default()).unwrap();
    let s = named_cert_store("AutoFirmaRsDiag");
    let st = s.as_ref();
    st.add(TrustScope::User, &pack.ca_der, "x").unwrap();
    assert!(st.list(TrustScope::User).unwrap().iter().any(|c| c.der == pack.ca_der));
    assert!(st.delete(TrustScope::User, &pack.ca_der).unwrap());
    assert!(!st.list(TrustScope::User).unwrap().iter().any(|c| c.der == pack.ca_der));
    assert!(!st.delete(TrustScope::User, &pack.ca_der).unwrap());
}

/// Instala y retira la CA en el `CurrentUser\ROOT` real.
fn user_root_round_trip(ctx: &Context, ca_der: &[u8]) {
    let store = ctx.win_certs.as_ref();
    match wtrust::install(store, TrustScope::User, ca_der) {
        Ok(Change::Changed) => {
            assert_eq!(wtrust::check(store, TrustScope::User, ca_der), TrustCheck::Trusted);
            assert_eq!(
                wtrust::install(store, TrustScope::User, ca_der).unwrap(),
                Change::Unchanged
            );
            let _ = wtrust::remove(store, TrustScope::User);
        }
        other => eprintln!("CurrentUser\\ROOT no disponible en este entorno: {other:?}"),
    }
}
