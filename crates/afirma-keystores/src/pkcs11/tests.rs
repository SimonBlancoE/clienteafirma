//! Pruebas del almacén PKCS#11.
//!
//! Las pruebas con un token real usan SoftHSM2 y solo se ejecutan si la
//! variable `AFIRMA_TEST_SOFTHSM_LIB` apunta a `libsofthsm2.so` (y
//! `SOFTHSM2_CONF` a una configuración con un directorio de tokens vacío y
//! escribible). `tools/oracle/keystores-softhsm.sh` lo prepara todo en un
//! contenedor Docker y las ejecuta.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use super::*;
use crate::callback::{FixedPassword, FnPasswordCallback, NoPassword};

pub(crate) const USER_PIN: &str = "1234";
const SO_PIN: &str = "4321";

fn pki(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/pki")
            .join(name),
    )
    .unwrap()
}

#[test]
fn helpers() {
    assert_eq!(label_string(Some(b"abc  \0")), Some("abc".to_string()));
    assert_eq!(label_string(Some(b"   ")), None);
    assert_eq!(id_string(b"01"), "01");
    assert_eq!(id_string(&[1, 2, 0xff]), "0102ff");
    let mut raw = vec![0u8; 64];
    raw[0] = 0x30;
    raw[1] = 62;
    raw[2] = 2;
    assert!(looks_like_der(&raw));
    let der = afirma_core::key::ecdsa_format::raw_to_der(&[1u8; 64]);
    assert!(looks_like_der(&der));
    assert!(!looks_like_der(&[1u8; 64]));
}

#[test]
fn missing_library() {
    let r = Pkcs11Store::open(
        Path::new("/no/existe/libpkcs11.so"),
        Pkcs11Config::new(KeyStoreKind::Pkcs11),
        Arc::new(NoPassword),
    );
    assert!(matches!(r, Err(KeyStoreError::LibraryNotFound(_))));
}

/// Serializa las pruebas SoftHSM (comparten el módulo y los tokens).
pub(crate) static SOFTHSM: Mutex<()> = Mutex::new(());

pub(crate) fn softhsm_lib() -> Option<PathBuf> {
    match std::env::var("AFIRMA_TEST_SOFTHSM_LIB") {
        Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => {
            eprintln!(
                "AFIRMA_TEST_SOFTHSM_LIB no definida: se omite la prueba con SoftHSM2 (ver tools/oracle/keystores-softhsm.sh)"
            );
            None
        }
    }
}

/// Etiqueta del token de SoftHSM que simula un DNIe (lo clasifica como
/// [`CardFamily::Dnie`]).
pub(crate) const DNIE_TOKEN_LABEL: &str = "DNI electronico (pruebas)";

/// Inicializa (una vez) un token con etiqueta de DNIe con la clave RSA de
/// pruebas.
pub(crate) fn prepare_dnie_token(lib: &Path) -> Arc<Pkcs11Module> {
    let module = prepare_token(lib);
    let ctx = module.context();
    if module.tokens().unwrap().iter().any(|t| t.label == DNIE_TOKEN_LABEL) {
        return module;
    }
    let slot = ctx
        .get_all_slots()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).map(|i| !i.token_initialized()).unwrap_or(false))
        .expect("ranura libre en SoftHSM2");
    ctx.init_token(slot, &AuthPin::new(SO_PIN.into()), DNIE_TOKEN_LABEL)
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(UserType::So, Some(&AuthPin::new(SO_PIN.into()))).unwrap();
    session.init_pin(&AuthPin::new(USER_PIN.into())).unwrap();
    session.logout().unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();
    import_p12(&session, "firmante-rsa.p12", b"CertFirmaDigital", "CertFirmaDigital");
    drop(session);
    module
}

/// Inicializa (una vez) un token "afirma" e importa las claves de prueba.
pub(crate) fn prepare_token(lib: &Path) -> Arc<Pkcs11Module> {
    let module = Pkcs11Module::load(lib).expect("cargar SoftHSM2");
    let ctx = module.context();
    if module.tokens().unwrap().iter().any(|t| t.label == "afirma") {
        return module;
    }
    let slot = ctx
        .get_all_slots()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).map(|i| !i.token_initialized()).unwrap_or(false))
        .expect("ranura libre en SoftHSM2");
    ctx.init_token(slot, &AuthPin::new(SO_PIN.into()), "afirma").unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(UserType::So, Some(&AuthPin::new(SO_PIN.into()))).unwrap();
    session.init_pin(&AuthPin::new(USER_PIN.into())).unwrap();
    session.logout().unwrap();
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .unwrap();
    import_p12(&session, "firmante-rsa.p12", b"01", "firmante-rsa");
    import_p12(&session, "firmante-ec.p12", b"02", "firmante-ec");
    // Certificado de la CA sin clave.
    let ca = afirma_core::cert::decode_certificate(&pki("ca.crt")).unwrap();
    create_cert(&session, &ca, b"ca", "AC de pruebas");
    drop(session);
    module
}

fn create_cert(session: &Session, der: &[u8], id: &[u8], label: &str) {
    use x509_parser::prelude::*;
    let (_, c) = X509Certificate::from_der(der).unwrap();
    session
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Value(der.to_vec()),
            Attribute::Subject(c.subject().as_raw().to_vec()),
            Attribute::Issuer(c.issuer().as_raw().to_vec()),
            Attribute::Id(id.to_vec()),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .unwrap();
}

fn import_p12(session: &Session, file: &str, id: &[u8], label: &str) {
    let entry = crate::pkcs12::open(&pki(file), "12341234").unwrap().remove(0);
    let pkcs8 = entry_pkcs8(&entry);
    let mut template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
        Attribute::Id(id.to_vec()),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    use rsa::pkcs8::DecodePrivateKey;
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_der(&pkcs8) {
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        let p = k.primes();
        template.extend([
            Attribute::KeyType(KeyType::RSA),
            Attribute::Modulus(k.n().to_bytes_be()),
            Attribute::PublicExponent(k.e().to_bytes_be()),
            Attribute::PrivateExponent(k.d().to_bytes_be()),
            Attribute::Prime1(p[0].to_bytes_be()),
            Attribute::Prime2(p[1].to_bytes_be()),
            Attribute::Exponent1(k.dp().unwrap().to_bytes_be()),
            Attribute::Exponent2(k.dq().unwrap().to_bytes_be()),
            Attribute::Coefficient(k.crt_coefficient().unwrap().to_bytes_be()),
        ]);
    } else {
        let k = p256::SecretKey::from_pkcs8_der(&pkcs8).unwrap();
        template.extend([
            Attribute::KeyType(KeyType::EC),
            // OID de P-256 en DER.
            Attribute::EcParams(vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            Attribute::Value(k.to_bytes().to_vec()),
        ]);
    }
    session.create_object(&template).unwrap();
    create_cert(session, entry.certificate(), id, label);
}

/// PKCS#8 de una entrada (solo para importar en las pruebas).
fn entry_pkcs8(e: &crate::pkcs12::Pkcs12Entry) -> Vec<u8> {
    e.pkcs8_for_tests().to_vec()
}

fn algs(key: KeyAlgorithm) -> Vec<SignatureAlgorithm> {
    let digests: &[DigestAlgorithm] = match key {
        KeyAlgorithm::Rsa => &[
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ],
        _ => &[
            DigestAlgorithm::Sha1,
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ],
    };
    digests.iter().map(|d| SignatureAlgorithm::new(*d, key)).collect()
}

fn afirma_only() -> TokenFilter {
    Arc::new(|t: &TokenDescription| t.label == "afirma")
}

#[test]
fn softhsm_pin_at_open_sign_and_verify() {
    let Some(lib) = softhsm_lib() else { return };
    let _g = SOFTHSM.lock().unwrap_or_else(|e| e.into_inner());
    let _module = prepare_token(&lib);
    let config = Pkcs11Config {
        token_filter: Some(afirma_only()),
        ..Pkcs11Config::new(KeyStoreKind::Pkcs11).with_name("Mi tarjeta")
    };
    let asked = Arc::new(Mutex::new(Vec::<PasswordRequest>::new()));
    let a2 = asked.clone();
    let cb = Arc::new(FnPasswordCallback(move |r: &PasswordRequest| {
        a2.lock().unwrap().push(r.clone());
        PasswordResponse::provided(USER_PIN)
    }));
    let store = Pkcs11Store::open(&lib, config, cb).unwrap();
    // El PIN se pide al abrir con el nombre de la tarjeta registrada.
    {
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].prompt, "Introduzca la contraseña del almacén Mi tarjeta.");
        assert_eq!(asked[0].kind, PasswordKind::Pin);
        assert_eq!(asked[0].device_label.as_deref(), Some("afirma"));
    }
    assert_eq!(store.name(), "Mi tarjeta");
    assert_eq!(store.lib_name().as_deref(), Some("libsofthsm2.so"));
    let entries = store.entries().unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.alias.as_str()).collect();
    assert!(
        names.contains(&"firmante-rsa") && names.contains(&"firmante-ec") && names.contains(&"AC de pruebas"),
        "{names:?}"
    );
    let ca = entries.iter().find(|e| e.alias == "AC de pruebas").unwrap();
    assert!(!ca.capabilities.has_private_key);
    // Mismos alias que lista Java (SunPKCS11) con el mismo token.
    let golden = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/keystores/pkcs11-softhsm-java-aliases.txt"),
    )
    .unwrap();
    let mut java: Vec<&str> = golden
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    java.sort();
    let mut ours = store.aliases().unwrap();
    ours.sort();
    assert_eq!(ours, java);
    for (alias, key) in [("firmante-rsa", KeyAlgorithm::Rsa), ("firmante-ec", KeyAlgorithm::Ec)] {
        let e = entries.iter().find(|e| e.alias == alias).unwrap();
        assert!(e.capabilities.has_private_key && e.capabilities.hardware);
        assert_eq!(e.chain.len(), 2, "cadena construida con la CA del token");
        let k = store.signing_key(alias).unwrap();
        for alg in algs(key) {
            let sig = k
                .sign(b"datos de prueba", alg)
                .unwrap_or_else(|e| panic!("{alias} {alg}: {e}"));
            crate::verify::verify_signature(k.certificate(), alg, b"datos de prueba", &sig)
                .unwrap_or_else(|e| panic!("{alias} {alg}: {e}"));
        }
        // Firma con la huella de un fichero grande (sin problema de tamaño).
        let big = vec![7u8; 1 << 20];
        let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, key);
        let sig = k.sign(&big, alg).unwrap();
        crate::verify::verify_signature(k.certificate(), alg, &big, &sig).unwrap();
    }
    // No se volvió a pedir el PIN al firmar.
    assert_eq!(asked.lock().unwrap().len(), 1);
    // Sesiones invalidadas (como al extraer y volver a insertar la tarjeta):
    // la firma abre otra sesión y, si el módulo cerró la sesión de usuario,
    // vuelve a pedir el PIN (SoftHSM la conserva).
    let slot_id = store.tokens()[0].slot_id;
    store
        .shared
        .module
        .raw
        .close_all_sessions(slot_id as cryptoki_sys::CK_SLOT_ID)
        .unwrap();
    let k = store.signing_key("firmante-rsa").unwrap();
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    let sig = k.sign(b"otra vez", alg).unwrap();
    crate::verify::verify_signature(k.certificate(), alg, b"otra vez", &sig).unwrap();
    assert!(asked.lock().unwrap().len() <= 2);
    asked.lock().unwrap().truncate(1);
    // Mientras viva una clave, su sesión mantiene iniciada la sesión de
    // usuario del token.
    drop(k);
    // Recarga: vuelve a pedir el PIN (como Java al reinicializar el proveedor).
    store.refresh().unwrap();
    assert_eq!(asked.lock().unwrap().len(), 2);
    assert_eq!(store.aliases().unwrap().len(), 2);
}

#[test]
fn softhsm_raw_mechanisms_digest_info_path() {
    let Some(lib) = softhsm_lib() else { return };
    let _g = SOFTHSM.lock().unwrap_or_else(|e| e.into_inner());
    let module = prepare_token(&lib);
    let store = Pkcs11Store::open_module(
        module,
        Pkcs11Config {
            token_filter: Some(afirma_only()),
            ..Pkcs11Config::new(KeyStoreKind::Pkcs11)
        },
        Arc::new(FixedPassword::new(USER_PIN)),
    )
    .unwrap();
    for (alias, key) in [("firmante-rsa", KeyAlgorithm::Rsa), ("firmante-ec", KeyAlgorithm::Ec)] {
        let k = store.signing_key(alias).unwrap();
        // Se fuerza el camino CKM_RSA_PKCS + DigestInfo / CKM_ECDSA vaciando
        // la lista de mecanismos combinados.
        let pk = Pkcs11Key {
            shared: store.shared.clone(),
            callback: Arc::new(FixedPassword::new(USER_PIN)),
            token: Arc::new(Token {
                slot: store.state.read().unwrap().tokens[0].slot,
                desc: store.tokens()[0].clone(),
                mechanisms: vec![MechanismType::RSA_PKCS, MechanismType::ECDSA],
                session: Mutex::new(None),
            }),
            cka_id: Some(if key == KeyAlgorithm::Rsa {
                b"01".to_vec()
            } else {
                b"02".to_vec()
            }),
            label: None,
            alias: alias.into(),
            curve: certificate_curve(k.certificate()),
            chain: k.certificate_chain(),
            key_algorithm: key,
        };
        for alg in algs(key) {
            let (m, _) = pk.mechanism(b"x", alg).unwrap();
            assert!(matches!(m, Mechanism::RsaPkcs | Mechanism::Ecdsa));
            let sig = pk.sign(b"datos", alg).unwrap_or_else(|e| panic!("{alias} {alg}: {e}"));
            crate::verify::verify_signature(pk.certificate(), alg, b"datos", &sig).unwrap();
        }
    }
}

#[test]
fn softhsm_wrong_pin_retry_cancel_and_no_password() {
    let Some(lib) = softhsm_lib() else { return };
    let _g = SOFTHSM.lock().unwrap_or_else(|e| e.into_inner());
    let module = prepare_token(&lib);
    let config = || Pkcs11Config {
        token_filter: Some(afirma_only()),
        ..Pkcs11Config::new(KeyStoreKind::Pkcs11)
    };

    // PIN fijo erróneo (CLI): error sin reintentar.
    let r = Pkcs11Store::open_module(module.clone(), config(), Arc::new(FixedPassword::new("0000")));
    assert!(matches!(r, Err(KeyStoreError::WrongPin { .. })), "{r:?}");

    // Interactivo: primero erróneo, después correcto; el segundo intento
    // indica el motivo.
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = calls.clone();
    let cb = Arc::new(FnPasswordCallback(move |r: &PasswordRequest| {
        let n = c2.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            assert!(r.retry.is_none());
            PasswordResponse::provided("0000")
        } else {
            assert_eq!(r.retry, Some(RetryReason::WrongPassword));
            assert_eq!(r.retry.unwrap().message(), "La contraseña introducida no es correcta.");
            PasswordResponse::provided(USER_PIN)
        }
    }));
    let store = Pkcs11Store::open_module(module.clone(), config(), cb).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(store.aliases().unwrap().len(), 2);
    drop(store);

    // Cancelación.
    let r = Pkcs11Store::open_module(module.clone(), config(), Arc::new(crate::callback::CancelAll));
    assert!(matches!(r, Err(KeyStoreError::Cancelled)), "{r:?}");

    // Sin contraseña (CLI sin -password): no se inicia sesión; los
    // certificados de entidad final se ofrecen y la firma falla al no poder
    // autenticar.
    let store = Pkcs11Store::open_module(module.clone(), config(), Arc::new(NoPassword)).unwrap();
    let e = store.entries().unwrap();
    assert!(
        e.iter()
            .find(|e| e.alias == "firmante-rsa")
            .unwrap()
            .capabilities
            .has_private_key
    );
    assert!(
        !e.iter()
            .find(|e| e.alias == "AC de pruebas")
            .unwrap()
            .capabilities
            .has_private_key
    );
    let k = store.signing_key("firmante-rsa").unwrap();
    assert!(
        k.sign(
            b"x",
            SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa)
        )
        .is_err()
    );
}

#[test]
fn softhsm_pin_at_sign_with_cache_like_dnie() {
    let Some(lib) = softhsm_lib() else { return };
    let _g = SOFTHSM.lock().unwrap_or_else(|e| e.into_inner());
    let module = prepare_token(&lib);
    // Configuración de tarjeta preferente (como DNIe) aceptando el token de
    // pruebas.
    let mut config = Pkcs11Config::card_driver(KeyStoreKind::DnieJava, CardFamily::Dnie);
    config.token_filter = Some(afirma_only());
    let pin_calls = Arc::new(AtomicUsize::new(0));
    let confirms = Arc::new(AtomicUsize::new(0));
    struct Ui {
        pin_calls: Arc<AtomicUsize>,
        confirms: Arc<AtomicUsize>,
    }
    impl PasswordCallback for Ui {
        fn request_password(&self, r: &PasswordRequest) -> PasswordResponse {
            self.pin_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(r.prompt, "Por favor, introduzca el PIN del DNIe.");
            assert_eq!(r.title.as_deref(), Some("DNI Electrónico: Introducción de PIN"));
            assert!(r.allow_remember && r.smartcard);
            PasswordResponse::Provided {
                secret: USER_PIN.into(),
                remember: true,
            }
        }
        fn confirm_signature(&self, r: &ConfirmRequest) -> bool {
            self.confirms.fetch_add(1, Ordering::SeqCst);
            assert_eq!(r.message, "¿Desea realizar una firma electrónica con su clave privada?");
            true
        }
    }
    let store = Pkcs11Store::open_module(
        module,
        config,
        Arc::new(Ui {
            pin_calls: pin_calls.clone(),
            confirms: confirms.clone(),
        }),
    )
    .unwrap();
    assert!(store.is_preferred());
    assert_eq!(store.kind(), KeyStoreKind::DnieJava);
    // Sin PIN al abrir; las claves se suponen presentes.
    assert_eq!(pin_calls.load(Ordering::SeqCst), 0);
    let e = store.entries().unwrap();
    let rsa = e.iter().find(|e| e.alias == "firmante-rsa").unwrap();
    assert!(rsa.capabilities.has_private_key && rsa.capabilities.pin_at_sign);
    let k = store.signing_key("firmante-rsa").unwrap();
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    for _ in 0..3 {
        let sig = k.sign(b"hola", alg).unwrap();
        crate::verify::verify_signature(k.certificate(), alg, b"hola", &sig).unwrap();
    }
    // PIN pedido una vez (recordado) y confirmación una vez (como
    // `DnieCacheCallbackHandler`).
    assert_eq!(pin_calls.load(Ordering::SeqCst), 1);
    assert_eq!(confirms.load(Ordering::SeqCst), 1);
    // Tras recargar, la caché se vacía.
    store.refresh().unwrap();
    let k = store.signing_key("firmante-ec").unwrap();
    k.sign(
        b"hola",
        SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Ec),
    )
    .unwrap();
    assert_eq!(pin_calls.load(Ordering::SeqCst), 2);
}
