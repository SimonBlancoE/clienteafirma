//! Contenedores CAdES-ASiC-S.

mod common;

use std::io::Cursor;

use afirma_cms::asics::{self, CadesAsicsSigner};
use afirma_cms::{detect, validation};
use afirma_core::validity::Validity;
use afirma_core::{CounterSignTarget, ExtraParams, Signer};
use common::*;

#[test]
fn container_layout_and_multisign() {
    let pdf = read("cades/data/documento.pdf");
    let mut extra = ExtraParams::new();
    extra.set("mode", "implicit"); // se fuerza explícita
    let asic = CadesAsicsSigner.sign(&pdf, "SHA256withRSA", &key("firmante-rsa"), &extra).unwrap();
    assert_eq!(extra.get("mode"), Some("implicit"), "no se modifican los parámetros del llamante");

    // mimetype primero, sin comprimir y sin campo extra (ETSI EN 319 162-1).
    assert_eq!(&asic[..4], b"PK\x03\x04");
    assert_eq!(u16::from_le_bytes([asic[8], asic[9]]), 0, "mimetype STORED");
    assert_eq!(u16::from_le_bytes([asic[28], asic[29]]), 0, "sin campo extra");
    assert_eq!(&asic[30..38], b"mimetype");
    assert_eq!(&asic[38..38 + asics::ASIC_S_MIMETYPE.len()], asics::ASIC_S_MIMETYPE.as_bytes());
    let z = zip::ZipArchive::new(Cursor::new(&asic)).unwrap();
    assert_eq!(z.comment(), format!("mimetype={}", asics::ASIC_S_MIMETYPE).as_bytes());
    let names: Vec<String> = asics::read_entries(&asic).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["mimetype", "dataobject.pdf", "META-INF/signature.p7s"]);

    let p = ExtraParams::new();
    assert!(CadesAsicsSigner.is_sign(&asic, &p), "a diferencia de Java, se detecta");
    assert_eq!(CadesAsicsSigner.get_data(&asic, &p).unwrap().unwrap(), pdf);
    assert_eq!(CadesAsicsSigner.sign_info(&asic, &p).unwrap().format, "CAdES");
    let inner = asics::get_binary_signature(&asic).unwrap();
    assert!(detect::obtain_data(&inner).unwrap().is_none(), "firma interna explícita");
    assert_eq!(validation::validate(&inner, Some(&pdf), true)[0].validity, Validity::Ok);

    // Cofirma y contrafirma: las entradas conservan sus nombres.
    let asic = CadesAsicsSigner.cosign(None, &asic, "SHA256withECDSA", &key("firmante-ec"), &p).unwrap();
    let asic = CadesAsicsSigner
        .countersign(&asic, "SHA256withRSA", &CounterSignTarget::Leafs, &key("firmante-rsa"), &p)
        .unwrap();
    let names: Vec<String> = asics::read_entries(&asic).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["mimetype", "dataobject.pdf", "META-INF/signature.p7s"]);
    let tree = CadesAsicsSigner.signers_structure(&asic, &p).unwrap();
    assert_eq!(tree.signers.len(), 2);
    assert!(tree.signers.iter().all(|s| s.countersigners.len() == 1));
    let inner = asics::get_binary_signature(&asic).unwrap();
    let v = validation::validate(&inner, Some(&pdf), true);
    assert!(v.iter().all(|x| x.validity == Validity::Ok), "{v:?}");
    assert_eq!(CadesAsicsSigner.signed_name(Some("doc.pdf"), None), "doc.pdf.asics");
}

#[test]
fn custom_name_and_java_container() {
    let mut extra = ExtraParams::new();
    extra.set("asicsFilename", "hola.txt");
    let asic = CadesAsicsSigner.sign(b"Hola mundo", "SHA256withRSA", &key("firmante-rsa"), &extra).unwrap();
    assert_eq!(asics::get_data(&asic).unwrap(), ("hola.txt".to_string(), b"Hola mundo".to_vec()));
    // Contenedor generado por la AutoFirma Java (mimetype comprimido).
    let java = read("cades/asics_sign.java.asics");
    let p = ExtraParams::new();
    assert!(CadesAsicsSigner.is_sign(&java, &p));
    assert_eq!(CadesAsicsSigner.get_data(&java, &p).unwrap().unwrap(), read("cades/data/documento.pdf"));
    assert!(!CadesAsicsSigner.is_sign(b"PK\x03\x04", &p));
    assert!(asics::create_s_container(b"", b"x", None, None).is_err());
}
