//! Validación (`ValidateBinarySignature`) con los veredictos que da la
//! AutoFirma Java para los mismos casos (comprobados con
//! `tools/oracle/cms_cross.py`).

mod common;

use afirma_cms::validation::{self, resolve_asn1_format};
use afirma_cms::{CadesSigner, CmsSigner, cms::SignedData, inspect};
use afirma_core::validity::{SignValidity, Validity, ValidityError};
use afirma_core::{CounterSignTarget, ExtraParams, Signer};
use common::*;

fn verdicts(v: &[SignValidity]) -> Vec<(Validity, Option<ValidityError>)> {
    v.iter().map(|x| (x.validity, x.error)).collect()
}

const OK: (Validity, Option<ValidityError>) = (Validity::Ok, None);

fn implicit() -> ExtraParams {
    let mut p = ExtraParams::new();
    p.set("mode", "implicit");
    p
}

#[test]
fn verdicts_match_java() {
    let data = read("cades/data/hola.txt");
    let other = read("cades/data/binario.bin");
    // Firmas Java de referencia.
    let impl_sig = read("cades/cades_impl_sha256.java.csig");
    let expl_sig = read("cades/cades_expl_sha256.java.csig");
    assert_eq!(verdicts(&validation::validate(&impl_sig, None, true)), vec![OK]);
    assert_eq!(
        verdicts(&validation::validate(&expl_sig, None, true)),
        vec![(Validity::Unknown, Some(ValidityError::NoData)), OK]
    );
    assert_eq!(verdicts(&validation::validate(&expl_sig, Some(&data), true)), vec![OK]);
    assert_eq!(
        verdicts(&validation::validate(&expl_sig, Some(&other), true)),
        vec![(Validity::Ko, Some(ValidityError::NoMatchData))]
    );
    // Firma alterada: implícita -> KO; explícita sin datos -> no se comprueba (como Java).
    let mut bad = impl_sig.clone();
    let n = bad.len();
    bad[n - 5] ^= 1;
    assert_eq!(
        verdicts(&validation::validate(&bad, None, true)),
        vec![(Validity::Ko, Some(ValidityError::CantValidateCert))]
    );
    let mut bad = expl_sig.clone();
    let n = bad.len();
    bad[n - 5] ^= 1;
    assert_eq!(
        verdicts(&validation::validate(&bad, None, true)),
        vec![(Validity::Unknown, Some(ValidityError::NoData)), OK]
    );
    assert_eq!(
        verdicts(&validation::validate(&bad, Some(&data), true)),
        vec![(Validity::Ko, Some(ValidityError::CantValidateCert))]
    );
    // Certificado caducado.
    let cad = read("cades/cades_caducado.java.csig");
    assert_eq!(
        verdicts(&validation::validate(&cad, None, true)),
        vec![(Validity::Ko, Some(ValidityError::CertificateExpired))]
    );
    // Sin comprobar fechas: el certificado no era válido en la fecha de firma.
    assert_eq!(
        verdicts(&validation::validate(&cad, None, false)),
        vec![(Validity::Ko, Some(ValidityError::CantValidateCert))]
    );
    // No es una firma.
    assert_eq!(
        verdicts(&validation::validate(b"no es una firma", None, true)),
        vec![(Validity::Ko, Some(ValidityError::NoSign))]
    );
}

#[test]
fn countersignatures_are_not_validated() {
    // Como en Java, solo se validan los firmantes de primer nivel.
    let sig = read("cades/cades_counter_tree.java.csig");
    assert_eq!(verdicts(&validation::validate(&sig, None, true)), vec![OK, OK]);
}

#[test]
fn profiles() {
    let check = |file: &str, expected: &[&str]| {
        let s = read(file);
        let sd = SignedData::parse(&s).unwrap();
        let p: Vec<&str> = sd.signer_infos.iter().map(|si| resolve_asn1_format(&sd, si)).collect();
        assert_eq!(p, expected, "{file}");
    };
    check("cades/cades_impl_sha256.java.csig", &["CAdES B-Level"]);
    check("cades/cades_no_time.java.csig", &["CAdES-BES"]);
    check("cades/cades_epes_age.java.csig", &["CAdES B-Level"]);
    check("cades/cms_impl.java.csig", &["CMS"]);
    let s = read("cades/cades_epes_age.java.csig");
    assert_eq!(
        inspect::signers(&s).unwrap()[0].policy_oid.as_deref(),
        Some("2.16.724.1.3.1.1.2.1.9")
    );
}

#[test]
fn ecdsa_and_rust_multisign_validate() {
    let rsa = key("firmante-rsa");
    let ec = key("firmante-ec");
    let s = CadesSigner.sign(b"Hola", "SHA384withECDSA", &ec, &implicit()).unwrap();
    assert_eq!(verdicts(&validation::validate(&s, None, true)), vec![OK]);
    let s = CadesSigner
        .cosign(None, &s, "SHA512withRSA", &rsa, &ExtraParams::new())
        .unwrap();
    let s = CadesSigner
        .countersign(
            &s,
            "SHA256withECDSA",
            &CounterSignTarget::Tree,
            &ec,
            &ExtraParams::new(),
        )
        .unwrap();
    assert_eq!(verdicts(&validation::validate(&s, None, true)), vec![OK, OK]);
    if let Some((ok, msg)) = openssl_verify("ec_multi", &s, None) {
        assert!(ok, "{msg}");
    }
    let c = CmsSigner.sign(b"Hola", "SHA256withECDSA", &ec, &implicit()).unwrap();
    assert_eq!(verdicts(&validation::validate(&c, None, true)), vec![OK]);
}
