//! Prueba de extremo a extremo: firma con cada formato disponible en el
//! registro usando una clave PKCS#12 real y valida el resultado.

use afirma_core::validity::Validity;
use afirma_core::{CounterSignTarget, ExtraParams, SigningKey};

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn key(name: &str) -> Box<dyn SigningKey> {
    let p12 = std::fs::read(root().join(format!("testdata/pki/{name}.p12"))).unwrap();
    let entry = afirma_keystores::pkcs12::open(&p12, "12341234").unwrap().remove(0);
    Box::new(entry.signing_key().unwrap())
}

fn check(label: &str, signed: &[u8]) {
    let v = afirma_signers::validate(signed, &ExtraParams::new());
    assert!(
        matches!(v[0].validity, Validity::Ok | Validity::Unknown),
        "{label}: validación inesperada {v:?}"
    );
    let detected = afirma_signers::detect_format_name(signed, &ExtraParams::new());
    assert!(detected.is_some(), "{label}: no se detecta como firma");
}

#[test]
fn sign_cosign_countersign_all_formats() {
    let pdf = std::fs::read(root().join("testdata/cades/data/documento.pdf")).unwrap();
    let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><documento><dato>Hola</dato></documento>".to_vec();
    let bin = b"Datos binarios de prueba".to_vec();
    let rsa = key("firmante-rsa");
    let ec = key("firmante-ec");
    let empty = ExtraParams::new();
    let odt = std::fs::read(root().join("testdata/office/inputs/in.odt")).unwrap();
    let docx = std::fs::read(root().join("testdata/office/inputs/in.docx")).unwrap();
    for (format, data) in [
        ("CAdES", &bin),
        ("XAdES", &xml),
        ("XAdES", &bin),
        ("XMLDSig", &xml),
        ("PAdES", &pdf),
        ("Adobe PDF", &pdf),
        ("CAdES-ASiC-S", &bin),
        ("XAdES-ASiC-S", &bin),
        ("ODF", &odt),
        ("OOXML", &docx),
    ] {
        let signer = afirma_signers::signer_for_format(format).unwrap_or_else(|| panic!("sin firmador {format}"));
        for (kname, k) in [("rsa", &rsa), ("ec", &ec)] {
            let label = format!("{format}/{kname}");
            let signed = signer
                .sign(data, "SHA256withRSA", k.as_ref(), &empty)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            check(&label, &signed);
            let tree = signer
                .signers_structure(&signed, &empty)
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(tree.signers.len(), 1, "{label}");
            let multi_ok = !matches!(format, "PAdES" | "Adobe PDF" | "ODF" | "OOXML") && !format.contains("ASiC");
            if multi_ok {
                let co = signer
                    .cosign(Some(data), &signed, "SHA512withRSA", ec.as_ref(), &empty)
                    .unwrap_or_else(|e| panic!("{label} cofirma: {e}"));
                assert_eq!(
                    signer.signers_structure(&co, &empty).unwrap().signers.len(),
                    2,
                    "{label} cofirma"
                );
                let cs = signer
                    .countersign(&co, "SHA256", &CounterSignTarget::Leafs, rsa.as_ref(), &empty)
                    .unwrap_or_else(|e| panic!("{label} contrafirma: {e}"));
                let t = signer.signers_structure(&cs, &empty).unwrap();
                assert_eq!(t.preorder().len(), 4, "{label} contrafirma");
            }
            if matches!(format, "PAdES" | "ODF" | "OOXML") {
                let co = signer
                    .cosign(None, &signed, "SHA256", ec.as_ref(), &empty)
                    .unwrap_or_else(|e| panic!("{label} cofirma: {e}"));
                assert_eq!(
                    signer.signers_structure(&co, &empty).unwrap().signers.len(),
                    2,
                    "{label} cofirma"
                );
                check(&format!("{label} cofirma"), &co);
            }
        }
    }
}
