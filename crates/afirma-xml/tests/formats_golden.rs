//! Pruebas de XMLDSig, FacturaE, XAdES-ASiC-S, XAdES-T, ODF y OOXML contra
//! salidas de referencia del oráculo Java (`testdata/xmldsig/java`,
//! `testdata/xades/java`, `testdata/office/java`, generadas con
//! `tools/oracle/xml_differential.py`).

mod common;

use std::sync::Arc;

use afirma_core::error::codes;
use afirma_core::extra_params::ExtraParams;
use afirma_core::signer::{CounterSignTarget, Signer};
use afirma_core::validity::{SignValidity, Validity, ValidityError};
use afirma_xml::dsig::NoResolver;
use afirma_xml::office::{odf, ooxml, read_zip};
use afirma_xml::{asic, validation};
use common::*;

/// Caso de multiformato: nombre, operación, entrada y parámetros.
type Case = (&'static str, Op, Vec<u8>, Params);
type Params = &'static [(&'static str, &'static str)];

const RSA: &str = "firmante-rsa";
const EC: &str = "firmante-ec";

#[derive(Clone, Copy)]
enum Op {
    Sign,
    Cosign,
    CounterTree,
    CounterLeafs,
}

fn alg(key: &str) -> &'static str {
    if key == EC {
        "SHA256withECDSA"
    } else {
        "SHA256withRSA"
    }
}

fn run(signer: &dyn Signer, op: Op, input: &[u8], key_name: &str, p: &[(&str, &str)]) -> Vec<u8> {
    let key = key(key_name);
    let p = params(p);
    let a = alg(key_name);
    match op {
        Op::Sign => signer.sign(input, a, &key, &p),
        Op::Cosign => signer.cosign(None, input, a, &key, &p),
        Op::CounterTree => signer.countersign(input, a, &CounterSignTarget::Tree, &key, &p),
        Op::CounterLeafs => signer.countersign(input, a, &CounterSignTarget::Leafs, &key, &p),
    }
    .unwrap_or_else(|e| panic!("{e}"))
}

fn none() -> ExtraParams {
    ExtraParams::new()
}

// ---------------------------------------------------------------- XMLDSig

type XCase = (
    &'static str,
    Op,
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
);

const XMLDSIG: &[XCase] = &[
    ("xmldsig-enveloping-xml", Op::Sign, "doc.xml", &[], EC),
    ("xmldsig-enveloping-bin", Op::Sign, "hello.txt", &[], RSA),
    ("xmldsig-enveloping-b64", Op::Sign, "b64.txt", &[], RSA),
    (
        "xmldsig-enveloping-explicit",
        Op::Sign,
        "hello.txt",
        &[("mode", "explicit")],
        RSA,
    ),
    (
        "xmldsig-detached-xml",
        Op::Sign,
        "doc.xml",
        &[("format", "XMLDSig Detached")],
        RSA,
    ),
    (
        "xmldsig-detached-bin",
        Op::Sign,
        "hello.txt",
        &[("format", "XMLDSig Detached")],
        RSA,
    ),
    (
        "xmldsig-enveloped",
        Op::Sign,
        "doc.xml",
        &[("format", "XMLDSig Enveloped")],
        RSA,
    ),
    (
        "xmldsig-enveloped-dsig",
        Op::Sign,
        "doc.xml",
        &[
            ("format", "XMLDSig Enveloped"),
            ("xmlSignaturePrefix", "dsig"),
            (
                "canonicalizationAlgorithm",
                "http://www.w3.org/2001/10/xml-exc-c14n#",
            ),
            (
                "referencesDigestMethod",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            ),
        ],
        RSA,
    ),
    (
        "xmldsig-enveloped-latin1",
        Op::Sign,
        "latin1.xml",
        &[("format", "XMLDSig Enveloped")],
        RSA,
    ),
    (
        "xmldsig-extdet-hash",
        Op::Sign,
        "hello.txt",
        &[
            ("format", "XMLDSig Externally Detached"),
            ("mode", "explicit"),
            ("precalculatedHashAlgorithm", "SHA-256"),
        ],
        RSA,
    ),
    (
        "xmldsig-xpath2",
        Op::Sign,
        "doc.xml",
        &[
            ("xmlTransforms", "1"),
            (
                "xmlTransform0Type",
                "http://www.w3.org/2002/06/xmldsig-filter2",
            ),
            ("xmlTransform0Subtype", "subtract"),
            ("xmlTransform0Body", "/doc/a"),
        ],
        RSA,
    ),
    (
        "xmldsig-cosign-enveloping",
        Op::Cosign,
        "@xmldsig-enveloping-xml",
        &[],
        RSA,
    ),
    (
        "xmldsig-cosign-detached",
        Op::Cosign,
        "@xmldsig-detached-xml",
        &[],
        RSA,
    ),
    (
        "xmldsig-cosign-enveloped",
        Op::Cosign,
        "@xmldsig-enveloped",
        &[],
        RSA,
    ),
    (
        "xmldsig-countersign-tree",
        Op::CounterTree,
        "@xmldsig-cosign-enveloping",
        &[],
        RSA,
    ),
    (
        "xmldsig-countersign-leafs",
        Op::CounterLeafs,
        "@xmldsig-countersign-tree",
        &[],
        RSA,
    ),
];

fn xmldsig_golden(name: &str) -> Vec<u8> {
    read(&format!("testdata/xmldsig/java/{name}.xml"))
}

fn input(rel: &str, golden: fn(&str) -> Vec<u8>) -> Vec<u8> {
    match rel.strip_prefix('@') {
        Some(base) => golden(base),
        None => read(&format!("testdata/xades/inputs/{rel}")),
    }
}

#[test]
fn xmldsig_matches_java_and_validates() {
    let signer = afirma_xml::xmldsig::XmldsigSigner::new();
    for &(name, op, inp, p, k) in XMLDSIG {
        let out = run(&signer, op, &input(inp, xmldsig_golden), k, p);
        let golden = xmldsig_golden(name);
        assert_same_structure(name, &golden, &out);
        // Mismo veredicto que Java para las dos salidas.
        let vr = validation::validate(&out, false, &NoResolver);
        let vj = validation::validate(&golden, false, &NoResolver);
        if name == "xmldsig-extdet-hash" {
            assert_eq!(vr[0].validity, Validity::Ko, "{name}: {vr:?}");
        } else {
            assert_eq!(vr, vec![SignValidity::ok()], "{name}");
            assert_eq!(vj, vec![SignValidity::ok()], "{name} (Java)");
        }
        assert!(signer.is_sign(&out, &none()), "{name}");
        assert!(signer.is_sign(&golden, &none()), "{name} (Java)");
        signer
            .signers_structure(&golden, &none())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    // Árbol: cofirma (2 firmantes) + contrafirma de árbol + de hojas.
    let tree = signer
        .signers_structure(&xmldsig_golden("xmldsig-countersign-leafs"), &none())
        .unwrap();
    assert_eq!(tree.signers.len(), 2);
    for s in &tree.signers {
        assert_eq!(s.countersigners.len(), 1);
        assert_eq!(s.countersigners[0].countersigners.len(), 1);
    }
}

#[test]
fn xmldsig_get_data() {
    let signer = afirma_xml::xmldsig::XmldsigSigner::new();
    let hello = read("testdata/xades/inputs/hello.txt");
    for name in ["xmldsig-enveloping-bin", "xmldsig-detached-bin"] {
        assert_eq!(
            signer.get_data(&xmldsig_golden(name), &none()).unwrap(),
            Some(hello.clone()),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------- FacturaE

#[test]
fn facturae_matches_java_and_validates() {
    let signer = afirma_xml::facturae::FacturaeSigner::new();
    let cases: &[(&str, &str, Params)] = &[
        ("facturae", "facturae_32v1.xml", &[]),
        (
            "facturae-30",
            "sample-facturae.xml",
            &[
                ("signerClaimedRoles", "receptor"),
                ("signatureProductionCity", "Madrid"),
            ],
        ),
    ];
    for &(name, inp, p) in cases {
        let out = run(
            &signer,
            Op::Sign,
            &read(&format!("testdata/xades/inputs/{inp}")),
            RSA,
            p,
        );
        let golden = read(&format!("testdata/xades/java/{name}.xml"));
        assert_same_structure(name, &golden, &out);
        assert_eq!(
            validation::validate(&out, false, &NoResolver),
            vec![SignValidity::ok()],
            "{name}"
        );
        assert_eq!(
            validation::validate(&golden, false, &NoResolver),
            vec![SignValidity::ok()],
            "{name} (Java)"
        );
        assert!(signer.is_sign(&out, &none()));
        // Una factura firmada no admite una segunda firma.
        let key = key(RSA);
        let err = signer
            .sign(&out, "SHA256withRSA", &key, &none())
            .unwrap_err();
        assert_eq!(
            err.code,
            Some(codes::FACTURAE_ALREADY_SIGNED),
            "{name}: {err}"
        );
    }
    // Datos que no son factura.
    let key = key(RSA);
    assert!(
        signer
            .sign(
                &read("testdata/xades/inputs/doc.xml"),
                "SHA256withRSA",
                &key,
                &none()
            )
            .is_err()
    );
}

// ---------------------------------------------------------------- ASiC-S

fn asic_xml(container: &[u8]) -> Vec<u8> {
    asic::xml_signature(container).unwrap()
}

#[test]
fn asic_matches_java_and_validates() {
    let signer = asic::XadesAsicSigner::new();
    let hello = read("testdata/xades/inputs/hello.txt");
    let java = |n: &str| read(&format!("testdata/xades/java/{n}.asics"));
    let cases: &[(&str, Op, Vec<u8>, &str)] = &[
        ("asic", Op::Sign, hello.clone(), RSA),
        ("asic-cosign", Op::Cosign, java("asic"), EC),
        ("asic-countersign", Op::CounterTree, java("asic"), RSA),
    ];
    for (name, op, inp, k) in cases {
        let out = run(&signer, *op, inp, k, &[]);
        let golden = java(name);
        assert_same_structure(name, &asic_xml(&golden), &asic_xml(&out));
        let expected = if *name == "asic-cosign" { 2 } else { 1 };
        let v = asic::validate_container(&out, false).unwrap();
        assert_eq!(v, vec![SignValidity::ok()], "{name}");
        let v = asic::validate_container(&golden, false).unwrap();
        assert_eq!(v, vec![SignValidity::ok()], "{name} (Java)");
        assert_eq!(
            signer
                .signers_structure(&out, &none())
                .unwrap()
                .signers
                .len(),
            expected,
            "{name}"
        );
        assert_eq!(
            signer.get_data(&out, &none()).unwrap(),
            Some(hello.clone()),
            "{name}"
        );
        // `mimetype` es la primera entrada y se almacena sin comprimir.
        let first = &out[30..30 + 8];
        assert_eq!(first, b"mimetype", "{name}");
        assert_eq!(
            u16::from_le_bytes([out[8], out[9]]),
            0,
            "{name}: mimetype comprimido"
        );
    }
}

// ---------------------------------------------------------------- XAdES-T

#[test]
fn xades_t_with_mock_tsa() {
    let tsa_key = key("tsa");
    let tsa = Arc::new(afirma_cms::tsp::mock::MockTsa::new(Box::new(tsa_key)));
    let (url, handle) = tsa.serve_http(1, None);
    let signer = afirma_xml::xades::XadesSigner::new();
    let out = run(
        &signer,
        Op::Sign,
        &read("testdata/xades/inputs/hello.txt"),
        RSA,
        &[("tsaURL", &url)],
    );
    handle.join().unwrap();
    let golden = read("testdata/xades/java/xades-t.xml");
    assert_same_structure("xades-t", &golden, &out);
    // Java: XAdES-T no es un perfil que se compruebe.
    let expected = vec![SignValidity::new(
        Validity::Unknown,
        Some(ValidityError::SignProfileNotChecked),
    )];
    assert_eq!(validation::validate(&out, false, &NoResolver), expected);
    assert_eq!(validation::validate(&golden, false, &NoResolver), expected);
    assert_eq!(validation::signature_format(&out), "XAdES T-Level");
    // El sello marca el valor de firma: el sellado posterior no invalida la firma.
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("<xades:SignatureTimeStamp"), "{s}");
}

#[test]
fn xades_t_unreachable_tsa_fails() {
    // Java (`XAdESTspUtil.timestampXAdES`): un fallo de conexión con la TSA
    // es un error de la operación (TSA_CONNECTION_ERROR), no una firma sin sello.
    let signer = afirma_xml::xades::XadesSigner::new();
    let key = key(RSA);
    let p = params(&[("tsaURL", "http://127.0.0.1:9/tsa")]);
    let err = signer
        .sign(
            &read("testdata/xades/inputs/hello.txt"),
            "SHA256withRSA",
            &key,
            &p,
        )
        .unwrap_err();
    assert_eq!(err.code, Some(codes::TSA_CONNECTION_ERROR), "{err}");
}

// ---------------------------------------------------------------- expPolicy

#[test]
fn exp_policy_age_expanded_by_caller() {
    let data = read("testdata/xades/inputs/hello.txt");
    let p = params(&[("expPolicy", "FirmaAGE"), ("format", "XAdES Enveloping")]);
    let expanded = afirma_core::policy::expand_properties(&p, Some(&data), Some("XAdES")).unwrap();
    let signer = afirma_xml::xades::XadesSigner::new();
    let key = key(RSA);
    let out = signer
        .sign(&data, "SHA256withRSA", &key, &expanded)
        .unwrap();
    let s = String::from_utf8(out.clone()).unwrap();
    assert!(s.contains("urn:oid:2.16.724.1.3.1.1.2.1.9"), "{s}");
    assert!(s.contains("G7roucf600+f03r/o0bAOQ6WAs0="), "{s}");
    assert_eq!(
        validation::validate(&out, false, &NoResolver),
        vec![SignValidity::ok()]
    );
    // Firma avanzada con SigningCertificate: el detector Java la clasifica como B-Level.
    assert_eq!(validation::signature_format(&out), "XAdES B-Level");
}

// ---------------------------------------------------------------- ODF

fn office_golden(name: &str) -> Vec<u8> {
    read(&format!("testdata/office/java/{name}.zip"))
}

fn entry(package: &[u8], name: &str) -> Vec<u8> {
    read_zip(package, codes::INVALID_SIGNATURE)
        .unwrap()
        .into_iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("falta {name}"))
        .data
}

#[test]
fn odf_matches_java_and_verifies() {
    let parity = odf::OdfSigner::java_parity();
    let cases: &[Case] = &[
        (
            "odf-odt",
            Op::Sign,
            read("testdata/office/inputs/in.odt"),
            &[],
        ),
        (
            "odf-ods-sha256",
            Op::Sign,
            read("testdata/office/inputs/in.ods"),
            &[(
                "referencesDigestMethod",
                "http://www.w3.org/2001/04/xmlenc#sha256",
            )],
        ),
        (
            "odf-odp",
            Op::Sign,
            read("testdata/office/inputs/in.odp"),
            &[],
        ),
        ("odf-cosign", Op::Cosign, office_golden("odf-odt"), &[]),
    ];
    for (name, op, inp, p) in cases {
        let out = run(&parity, *op, inp, RSA, p);
        let golden = office_golden(name);
        assert_same_structure(
            name,
            &entry(&golden, odf::SIGNATURES_PATH),
            &entry(&out, odf::SIGNATURES_PATH),
        );
        let n = if *name == "odf-cosign" { 2 } else { 1 };
        assert_eq!(odf::verify_package(&out).unwrap(), vec![true; n], "{name}");
        assert_eq!(
            odf::verify_package(&golden).unwrap(),
            vec![true; n],
            "{name} (Java)"
        );
        assert!(parity.is_sign(&out, &none()));
        assert_eq!(
            parity
                .signers_structure(&out, &none())
                .unwrap()
                .signers
                .len(),
            n,
            "{name}"
        );
        // Todas las entradas del original se conservan con el mismo contenido.
        for e in read_zip(inp, codes::INVALID_SIGNATURE).unwrap() {
            if e.name != odf::SIGNATURES_PATH && e.name != odf::MANIFEST_PATH && !e.is_dir {
                assert_eq!(entry(&out, &e.name), e.data, "{name}: {}", e.name);
            }
        }
    }
}

#[test]
fn odf_requested_algorithm_and_ec() {
    // Por defecto se usa el algoritmo pedido (LibreOffice 25.2 lo valida).
    let signer = odf::OdfSigner::new();
    let doc = read("testdata/office/inputs/in.odt");
    for (k, uri) in [
        (RSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        (EC, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
    ] {
        let out = run(&signer, Op::Sign, &doc, k, &[]);
        let sig = String::from_utf8(entry(&out, odf::SIGNATURES_PATH)).unwrap();
        assert!(sig.contains(uri), "{k}: {sig}");
        assert_eq!(odf::verify_package(&out).unwrap(), vec![true]);
        // `mimetype` primero y sin comprimir (requisito de ODF).
        assert_eq!(&out[30..38], b"mimetype");
        assert_eq!(u16::from_le_bytes([out[8], out[9]]), 0);
    }
}

#[test]
fn odf_tampered_content_fails() {
    let signer = odf::OdfSigner::new();
    let out = run(
        &signer,
        Op::Sign,
        &read("testdata/office/inputs/in.odt"),
        RSA,
        &[],
    );
    let mut b = afirma_xml::office::ZipBuilder::new(codes::INVALID_SIGNATURE);
    for e in read_zip(&out, codes::INVALID_SIGNATURE).unwrap() {
        let mut data = e.data.clone();
        if e.name == "content.xml" {
            let s = String::from_utf8(data).unwrap().replacen(
                "<office:text>",
                "<office:text><text:p>X</text:p>",
                1,
            );
            data = s.into_bytes();
        }
        b.add(&e.name, &data, e.name == "mimetype", e.is_dir)
            .unwrap();
    }
    assert_eq!(
        odf::verify_package(&b.finish().unwrap()).unwrap(),
        vec![false]
    );
}

// ---------------------------------------------------------------- OOXML

fn ooxml_structure(package: &[u8]) -> Vec<String> {
    // Las cofirmas se ordenan por estructura (los nombres llevan UUID).
    let mut sigs: Vec<Vec<String>> = ooxml::ooxml_signatures(package)
        .iter()
        .map(|x| structure(x))
        .collect();
    sigs.sort();
    sigs.concat()
}

#[test]
fn ooxml_matches_java_and_verifies() {
    let signer = ooxml::OoxmlSigner::new();
    let cases: &[Case] = &[
        (
            "ooxml-docx",
            Op::Sign,
            read("testdata/office/inputs/in.docx"),
            &[],
        ),
        (
            "ooxml-docx-params",
            Op::Sign,
            read("testdata/office/inputs/in.docx"),
            &[
                ("signatureProductionCity", "Madrid"),
                ("signatureProductionCountry", "ES"),
                ("signerClaimedRoles", "Rol|Uno"),
                ("signatureComments", "Prueba"),
                ("signatureAddress1", "Dir 1"),
                ("signatureAddress2", "Dir 2"),
                ("commitmentTypeIndications", "1"),
                ("commitmentTypeIndication0Identifier", "5"),
                ("commitmentTypeIndication0Description", "Aprobado"),
            ],
        ),
        (
            "ooxml-xlsx",
            Op::Sign,
            read("testdata/office/inputs/in.xlsx"),
            &[],
        ),
        ("ooxml-cosign", Op::Cosign, office_golden("ooxml-docx"), &[]),
    ];
    for (name, op, inp, p) in cases {
        let out = run(&signer, *op, inp, RSA, p);
        let golden = office_golden(name);
        assert_same_lines(name, &ooxml_structure(&golden), &ooxml_structure(&out));
        let n = if *name == "ooxml-cosign" { 2 } else { 1 };
        let rv = ooxml::verify_package(&out).unwrap();
        assert_eq!(rv.len(), n, "{name}");
        assert!(
            rv.iter().all(|(ok, bad)| *ok && bad.is_empty()),
            "{name}: {rv:?}"
        );
        let jv = ooxml::verify_package(&golden).unwrap();
        assert!(jv.iter().all(|(ok, _)| *ok), "{name} (Java): {jv:?}");
        assert!(signer.is_sign(&out, &none()), "{name}");
        assert_eq!(
            signer
                .signers_structure(&out, &none())
                .unwrap()
                .signers
                .len(),
            n,
            "{name}"
        );
    }
}

#[test]
fn ooxml_pptx_and_word_signed_sample() {
    let signer = ooxml::OoxmlSigner::new();
    // PowerPoint: se firman también las partes de `ppt/` (desviación).
    let out = run(
        &signer,
        Op::Sign,
        &read("testdata/office/inputs/in.pptx"),
        RSA,
        &[],
    );
    let sig = String::from_utf8(ooxml::ooxml_signatures(&out).remove(0)).unwrap();
    assert!(sig.contains("/ppt/presentation.xml?"), "{sig}");
    assert!(sig.contains("/ppt/slides/slide1.xml?"), "{sig}");
    // Como Office: las propiedades de presentación no se firman.
    assert!(!sig.contains("presProps.xml?"), "{sig}");
    assert!(
        ooxml::verify_package(&out)
            .unwrap()
            .iter()
            .all(|(ok, _)| *ok)
    );
    // Documento firmado con Microsoft Word: se reconoce, se valida y se cofirma.
    let word = read("testdata/office/inputs/word-signed.docx");
    assert!(signer.is_sign(&word, &none()));
    assert!(
        ooxml::verify_package(&word)
            .unwrap()
            .iter()
            .all(|(ok, _)| *ok)
    );
    let co = run(&signer, Op::Cosign, &word, EC, &[]);
    let v = ooxml::verify_package(&co).unwrap();
    assert_eq!(v.len(), 2);
    assert!(v.iter().all(|(ok, _)| *ok), "{v:?}");
}

#[test]
fn ooxml_tampered_part_fails() {
    let signer = ooxml::OoxmlSigner::new();
    let out = run(
        &signer,
        Op::Sign,
        &read("testdata/office/inputs/in.docx"),
        RSA,
        &[],
    );
    let mut b = afirma_xml::office::ZipBuilder::new(codes::INVALID_SIGNATURE);
    for e in read_zip(&out, codes::INVALID_SIGNATURE).unwrap() {
        let mut data = e.data.clone();
        if e.name == "word/document.xml" {
            let s = String::from_utf8(data).unwrap().replacen(
                "<w:body>",
                "<w:body><w:p><w:r><w:t>X</w:t></w:r></w:p>",
                1,
            );
            data = s.into_bytes();
        }
        b.add(&e.name, &data, false, e.is_dir).unwrap();
    }
    let v = ooxml::verify_package(&b.finish().unwrap()).unwrap();
    assert_eq!(v.len(), 1);
    assert!(!v[0].0);
    assert!(
        v[0].1.iter().any(|u| u.contains("/word/document.xml")),
        "{v:?}"
    );
}

// ---------------------------------------------------------------- signer_for

#[test]
fn signer_for_names() {
    for n in [
        "xades",
        "XAdES",
        "facturae",
        "asic",
        "xades-asic-s",
        "xmldsig",
        "odf",
        "odf-java",
        "ooxml",
    ] {
        assert!(afirma_xml::signer_for(n).is_some(), "{n}");
    }
    assert!(afirma_xml::signer_for("cades").is_none());
}

// ---------------------------------------------------------------- validación

/// `NoMatchData` -> `NO_MATCH_DATA` (con las erratas de los nombres Java).
fn java_name(v: &SignValidity) -> String {
    let validity = format!("{:?}", v.validity).to_uppercase();
    let err = match v.error {
        None => "null".to_string(),
        Some(e) => {
            let s = format!("{e:?}");
            let mut out = String::new();
            for (i, c) in s.chars().enumerate() {
                if c.is_uppercase() && i > 0 {
                    out.push('_');
                }
                out.push(c.to_ascii_uppercase());
            }
            out.replace("UNKNOWN_ERROR", "UNKOWN_ERROR")
        }
    };
    format!("{validity} {err}")
}

#[test]
fn validation_verdicts_match_java() {
    // `testdata/xades/validation/java-verdicts.tsv`: veredictos de
    // `ValidateXMLSignature.validate(firma, true)` (Java) para las firmas del
    // repositorio Java, los golden y variantes con algoritmos no estándar.
    let table = String::from_utf8(read("testdata/xades/validation/java-verdicts.tsv")).unwrap();
    let mut n = 0;
    for line in table.lines().filter(|l| !l.trim().is_empty()) {
        let (path, expected) = line.split_once('\t').unwrap();
        let got: Vec<String> = validation::validate(&read(path), true, &NoResolver)
            .iter()
            .map(java_name)
            .collect();
        assert_eq!(got.join(";"), expected, "{path}");
        n += 1;
    }
    assert!(n > 100);
}
