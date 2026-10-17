//! Integración con los almacenes y firmadores de AutoFirma-rs: el DNIe como
//! `afirma_keystores::KeyStore` y `afirma_core::key::SigningKey`, y una firma CAdES hecha con
//! el firmador de `afirma-cms` sin cambios.

mod common;

use std::sync::{Arc, Mutex};

use afirma_core::algorithms::{DigestAlgorithm as CoreDigest, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::KeyError;
use afirma_core::signer::Signer;
use afirma_core::validity::Validity;
use afirma_dnie::interaction::DnieInteraction;
use afirma_dnie::keystore::{DnieKeyStore, PasswordCallbackInteraction, to_keystore_error};
use afirma_dnie::signing::DnieSigningKey;
use afirma_dnie::{CERT_FIRMA_DIGITAL, DnieError, DnieSession};
use afirma_keystores::callback::{FnPasswordCallback, PasswordKind, PasswordResponse};
use afirma_keystores::{KeyStore, KeyStoreError, KeyStoreKind};
use common::*;

fn store(seed: u64, ui: Arc<dyn DnieInteraction>) -> DnieKeyStore {
    DnieKeyStore::open(Box::new(sim(seed)), ui).unwrap()
}

#[test]
fn keystore_entries_and_signing() {
    let ui: Arc<dyn DnieInteraction> = Arc::new(Recorder::new(CAN, &[PIN]));
    let ks = store(20, ui);
    assert_eq!(ks.kind(), KeyStoreKind::DnieJava);
    assert!(ks.is_preferred());
    let entries = ks.entries().unwrap();
    let aliases: Vec<&str> = entries.iter().map(|e| e.alias.as_str()).collect();
    assert_eq!(aliases, vec!["CertAutenticacion", "CertFirmaDigital"]);
    let e = &entries[1];
    assert!(e.capabilities.has_private_key && e.capabilities.hardware && e.capabilities.pin_at_sign);
    assert_eq!(e.capabilities.key_algorithm, Some(KeyAlgorithm::Rsa));
    assert_eq!(e.chain.len(), 2);
    assert_eq!(e.friendly_name, "SIM (FIRMA)");
    assert_eq!(ks.aliases().unwrap(), vec!["CertAutenticacion", "CertFirmaDigital"]);

    let key = ks.signing_key(CERT_FIRMA_DIGITAL).unwrap();
    assert_eq!(key.alias(), Some(CERT_FIRMA_DIGITAL));
    assert_eq!(key.certificate(), e.certificate.as_slice());
    for d in [
        CoreDigest::Sha1,
        CoreDigest::Sha256,
        CoreDigest::Sha384,
        CoreDigest::Sha512,
    ] {
        let alg = SignatureAlgorithm::new(d, KeyAlgorithm::Rsa);
        afirma_keystores::sign_and_verify(key.as_ref(), b"datos", alg).unwrap();
    }
    // SHA-224 y ECDSA no los admite el DNIe.
    let e224 = key
        .sign(b"x", SignatureAlgorithm::new(CoreDigest::Sha224, KeyAlgorithm::Rsa))
        .unwrap_err();
    assert!(matches!(e224, KeyError::Unsupported(_)));
    assert!(ks.signing_key("NoExiste").is_err());
    ks.refresh().unwrap();
    assert_eq!(ks.entries().unwrap().len(), 2);
}

#[test]
fn cades_signature_with_dnie_key() {
    let ui = Arc::new(Recorder::new(CAN, &[PIN]));
    let session = DnieSession::open(Box::new(sim(21)) as Box<dyn afirma_dnie::CardTransport>, ui.as_ref()).unwrap();
    let session = Arc::new(Mutex::new(session));
    let key = DnieSigningKey::new(session.clone(), CERT_FIRMA_DIGITAL, ui.clone()).unwrap();
    let data = b"Documento firmado con el DNIe por NFC";
    let sig = afirma_cms::CadesSigner
        .sign(data, "SHA256withRSA", &key, &ExtraParams::new())
        .unwrap();
    let v = afirma_cms::validation::validate(&sig, Some(data), false);
    assert_eq!(v[0].validity, Validity::Ok, "{v:?}");
    assert_eq!(ui.prompts().len(), 1);
    assert!(key.last_error().is_none());
}

#[test]
fn error_mapping() {
    // PIN incorrecto: KeyError::WrongPin y el detalle (intentos) en last_error.
    let ui = Arc::new(Recorder::new(CAN, &["0000wxyz"]));
    let ks = store(22, ui);
    let key = ks.signing_key(CERT_FIRMA_DIGITAL).unwrap();
    let e = key
        .sign(b"x", SignatureAlgorithm::new(CoreDigest::Sha256, KeyAlgorithm::Rsa))
        .unwrap_err();
    assert_eq!(e, KeyError::WrongPin);
    assert_eq!(
        to_keystore_error(DnieError::WrongPin { retries_left: Some(2) }),
        KeyStoreError::WrongPin { retries_left: Some(2) }
    );
    assert_eq!(
        to_keystore_error(DnieError::PinBlocked),
        KeyStoreError::Locked { smartcard: true }
    );
    assert_eq!(to_keystore_error(DnieError::Cancelled), KeyStoreError::Cancelled);
    assert!(matches!(
        to_keystore_error(DnieError::WrongCan { sw: Some(0x6300) }),
        KeyStoreError::Load { kind: KeyStoreKind::DnieJava, message } if message.contains("CAN")
    ));
    // CAN incorrecto al abrir el almacén.
    let bad: Arc<dyn DnieInteraction> = Arc::new(Recorder::new("000000", &[PIN]));
    assert!(matches!(
        DnieKeyStore::open(Box::new(sim(23)), bad).err(),
        Some(KeyStoreError::Load { .. })
    ));
}

#[test]
fn password_callback_adapter() {
    // Diálogos de AutoFirma: CAN y PIN por PasswordCallback, con los textos del DNIe.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let cb = FnPasswordCallback(move |r: &afirma_keystores::PasswordRequest| {
        seen2.lock().unwrap().push((r.kind, r.title.clone(), r.prompt.clone()));
        let v = if r.prompt.contains("CAN") { CAN } else { PIN };
        PasswordResponse::provided(v)
    });
    let ui: Arc<dyn DnieInteraction> = Arc::new(PasswordCallbackInteraction::new(cb));
    let ks = store(24, ui);
    let key = ks.signing_key(CERT_FIRMA_DIGITAL).unwrap();
    key.sign(b"x", SignatureAlgorithm::new(CoreDigest::Sha256, KeyAlgorithm::Rsa))
        .unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].1.as_deref(), Some("DNI Electrónico: Introducción de CAN"));
    assert_eq!(seen[1].0, PasswordKind::Pin);
    assert_eq!(seen[1].1.as_deref(), Some("DNI Electrónico: Introducción de PIN"));
    assert_eq!(
        seen[1].2,
        "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: 3"
    );
}
