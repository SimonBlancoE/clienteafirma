//! Las multifirmas no alteran las firmas existentes y aceptan entradas BER.

mod common;

use afirma_cms::cms::SignedData;
use afirma_cms::{CadesSigner, CmsSigner, validation};
use afirma_core::error::{ErrorKind, codes};
use afirma_core::validity::Validity;
use afirma_core::{CounterSignTarget, ExtraParams, Signer};
use common::*;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn allow_lts() -> ExtraParams {
    let mut p = ExtraParams::new();
    p.set("allowSignLTSignature", "true");
    p
}

/// Firmas de AutoFirma (pruebas de afirma-crypto-cades*) y un CAdES-T en BER
/// generado por `CMSTimestamper.addTimestamp`.
const FIXTURES: [&str; 4] = [
    "cades/fixtures/afirma_cades_t.csig",
    "cades/fixtures/afirma_cades_a.csig",
    "cades/fixtures/afirma_claimed_role.csig",
    "cades/fixtures/java_cmstimestamper_ber.csig",
];

#[test]
fn cosign_keeps_existing_signer_infos() {
    let k = key("firmante-rsa");
    for f in FIXTURES {
        let orig = read(f);
        let sd = SignedData::parse(&orig).unwrap();
        let alg = afirma_cms::alg::tree_signature_algorithm_name(
            &sd.signer_infos[0].digest_oid.to_dotted(),
            &sd.signer_infos[0].signature_oid.to_dotted(),
        );
        for signer in [&CadesSigner as &dyn Signer, &CmsSigner] {
            let out = signer.cosign(None, &orig, &alg, &k, &allow_lts());
            let Ok(out) = out else { continue }; // CMS no cofirma firmas con política
            for si in &sd.signer_infos {
                let original = afirma_cms::cms::to_der_preserving(&si.raw);
                assert!(contains(&out, &original), "{f}: SignerInfo alterado");
            }
            let new_sd = SignedData::parse(&out).unwrap();
            assert_eq!(new_sd.signer_infos.len(), sd.signer_infos.len() + 1);
            assert!(!new_sd.signed_data.indefinite, "{f}: la salida es DER");
        }
    }
}

#[test]
fn countersign_keeps_signed_parts() {
    let k = key("firmante-rsa");
    for f in FIXTURES {
        let orig = read(f);
        let sd = SignedData::parse(&orig).unwrap();
        for target in [CounterSignTarget::Tree, CounterSignTarget::Leafs] {
            let out = CadesSigner.countersign(&orig, "SHA256withRSA", &target, &k, &allow_lts()).unwrap();
            for si in sd.all_signer_infos() {
                let signed = afirma_cms::cms::to_der_preserving(si.signed_attrs.as_ref().unwrap());
                assert!(contains(&out, &signed), "{f}: atributos firmados alterados");
                assert!(contains(&out, &si.signature_value()), "{f}: valor de firma alterado");
            }
            // Los firmantes de primer nivel siguen validando (fechas aparte).
            for v in validation::validate(&out, None, false) {
                assert_ne!(v.validity, Validity::Ko, "{f}: {v:?}");
            }
        }
    }
}

#[test]
fn long_term_signatures_need_confirmation() {
    let k = key("firmante-rsa");
    let cades_a = read("cades/fixtures/afirma_cades_a.csig");
    for p in [ExtraParams::new(), {
        let mut p = ExtraParams::new();
        p.set("allowSignLTSignature", "false");
        p
    }] {
        let e = CadesSigner.cosign(None, &cades_a, "SHA512withRSA", &k, &p).unwrap_err();
        assert_eq!(e.code, Some(codes::SIGNING_LTS));
        match e.kind {
            ErrorKind::NeedsIntervention { denied, .. } => assert_eq!(denied, p.contains("allowSignLTSignature")),
            other => panic!("{other:?}"),
        }
        let e = CadesSigner.countersign(&cades_a, "SHA256withRSA", &CounterSignTarget::Tree, &k, &p).unwrap_err();
        assert_eq!(e.code, Some(codes::SIGNING_LTS));
    }
    assert!(CadesSigner.countersign(&cades_a, "SHA256withRSA", &CounterSignTarget::Leafs, &k, &allow_lts()).is_ok());
}
