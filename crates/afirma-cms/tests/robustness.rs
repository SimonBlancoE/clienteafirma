//! Las operaciones de lectura no deben entrar en pánico con datos mal formados.

mod common;

use afirma_cms::{CadesAsicsSigner, CadesSigner, CmsSigner, inspect, validation};
use afirma_core::{CounterSignTarget, ExtraParams, Signer};
use common::*;

fn exercise(data: &[u8]) {
    let p = ExtraParams::new();
    for s in [&CadesSigner as &dyn Signer, &CmsSigner, &CadesAsicsSigner] {
        let _ = s.is_sign(data, &p);
        let _ = s.get_data(data, &p);
        let _ = s.signers_structure(data, &p);
        let _ = s.sign_info(data, &p);
    }
    let _ = validation::validate(data, None, true);
    let _ = validation::validate(data, Some(b"x"), false);
    let _ = inspect::signers(data);
    let _ = inspect::structure_summary(data);
}

#[test]
fn truncated_and_corrupted_inputs() {
    let k = key("firmante-rsa");
    for file in [
        "cades/cades_counter_tree.java.csig",
        "cades/fixtures/java_cmstimestamper_ber.csig",
        "cades/asics_sign.java.asics",
    ] {
        let sig = read(file);
        let step = (sig.len() / 97).max(1);
        for len in (0..sig.len()).step_by(step) {
            exercise(&sig[..len]);
        }
        for pos in (0..sig.len()).step_by(step) {
            let mut bad = sig.clone();
            bad[pos] ^= 0x5a;
            exercise(&bad);
            // Las multifirmas sobre datos corruptos deben fallar limpiamente o funcionar.
            let _ = CadesSigner.cosign(None, &bad, "SHA256withRSA", &k, &ExtraParams::new());
            let _ = CmsSigner.countersign(
                &bad,
                "SHA256withRSA",
                &CounterSignTarget::Leafs,
                &k,
                &ExtraParams::new(),
            );
        }
    }
    // Anidamiento profundo e indefinido.
    let mut deep = Vec::new();
    for _ in 0..200 {
        deep.extend([0x30, 0x80]);
    }
    exercise(&deep);
    exercise(&[]);
    exercise(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]);
}
