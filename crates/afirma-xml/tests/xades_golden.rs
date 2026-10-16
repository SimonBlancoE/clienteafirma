//! Pruebas de XAdES contra salidas de referencia del oráculo Java
//! (`testdata/xades/java/`, generadas con `tools/oracle/xml_differential.py`):
//!
//! - la estructura de cada firma generada en Rust (nombres, atributos,
//!   transformadas, algoritmos...) es idéntica a la de Java, salvo UUID,
//!   huellas, valores de firma y fechas;
//! - las firmas Java se validan, se analizan (árbol de firmantes, variante,
//!   datos) y se cofirman/contrafirman con el código Rust;
//! - todas las firmas Rust se validan con el validador Rust.

mod common;

use afirma_core::signer::{CounterSignTarget, Signer};
use afirma_core::validity::{Validity, ValidityError};
use afirma_xml::dsig::NoResolver;
use afirma_xml::validation;
use afirma_xml::xades::XadesSigner;
use common::*;

#[derive(Clone, Copy)]
enum Op {
    Sign,
    Cosign,
    CounterTree,
    CounterLeafs,
}

struct Case {
    name: &'static str,
    op: Op,
    /// Fichero de entrada (`testdata/xades/inputs`) o caso base (`@caso`).
    input: &'static str,
    params: &'static [(&'static str, &'static str)],
    key: &'static str,
}

const POLICY: &[(&str, &str)] = &[
    ("profile", "baseline"),
    ("policyIdentifier", "urn:oid:2.16.724.1.3.1.1.2.1.9"),
    ("policyIdentifierHash", "G7roucf600+f03r/o0bAOQ6WAs0="),
    (
        "policyIdentifierHashAlgorithm",
        "http://www.w3.org/2000/09/xmldsig#sha1",
    ),
    (
        "policyQualifier",
        "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
    ),
    ("signatureProductionCity", "Madrid"),
    ("signatureProductionStreetAddress", "Calle 1"),
    ("signatureProductionProvince", "Madrid"),
    ("signatureProductionPostalCode", "28001"),
    ("signatureProductionCountry", "ES"),
    ("signerClaimedRoles", "Firmante|Revisor"),
    ("commitmentTypeIndications", "1"),
    ("commitmentTypeIndication0Identifier", "1"),
    ("commitmentTypeIndication0Description", "desc"),
    (
        "commitmentTypeIndication0DocumentationReferences",
        "http://a.es/x|http://b.es/y",
    ),
    ("commitmentTypeIndication0CommitmentTypeQualifiers", "Q1|Q2"),
];

const EPES_FULL: &[(&str, &str)] = &[
    ("policyIdentifier", "urn:oid:2.16.724.1.3.1.1.2.1.9"),
    ("policyIdentifierHash", "G7roucf600+f03r/o0bAOQ6WAs0="),
    (
        "policyIdentifierHashAlgorithm",
        "http://www.w3.org/2000/09/xmldsig#sha1",
    ),
    ("policyDescription", "Politica AGE"),
    (
        "policyQualifier",
        "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
    ),
    ("signatureProductionCity", "Madrid"),
    ("signatureProductionProvince", "Madrid"),
    ("signatureProductionPostalCode", "28001"),
    ("signatureProductionCountry", "ES"),
    ("signerClaimedRoles", "Firmante|Revisor"),
    ("commitmentTypeIndications", "1"),
    ("commitmentTypeIndication0Identifier", "1"),
    ("commitmentTypeIndication1Identifier", "5"),
    ("addKeyInfoKeyName", "true"),
    ("addKeyInfoX509IssuerSerial", "true"),
    ("includeOnlySignningCertificate", "true"),
    ("keepKeyInfoUnsigned", "true"),
    ("contentTypeOid", "1.2.3.4"),
    ("mimeType", "application/x-foo"),
];

const RSA: &str = "firmante-rsa";
const EC: &str = "firmante-ec";

const CASES: &[Case] = &[
    Case {
        name: "xades-enveloping-bin",
        op: Op::Sign,
        input: "hello.txt",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-enveloping-xml",
        op: Op::Sign,
        input: "doc.xml",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-enveloping-b64",
        op: Op::Sign,
        input: "b64.txt",
        params: &[("encoding", "base64")],
        key: RSA,
    },
    Case {
        name: "xades-enveloping-avoidb64",
        op: Op::Sign,
        input: "hello.txt",
        params: &[("avoidBase64Transforms", "true")],
        key: RSA,
    },
    Case {
        name: "xades-enveloped",
        op: Op::Sign,
        input: "doc.xml",
        params: &[("format", "XAdES Enveloped")],
        key: RSA,
    },
    Case {
        name: "xades-enveloped-ids",
        op: Op::Sign,
        input: "xml_with_ids.xml",
        params: &[("format", "XAdES Enveloped")],
        key: RSA,
    },
    Case {
        name: "xades-enveloped-node",
        op: Op::Sign,
        input: "xml_with_ids.xml",
        params: &[("format", "XAdES Enveloped"), ("nodeToSign", "1")],
        key: RSA,
    },
    Case {
        name: "xades-enveloped-xpath",
        op: Op::Sign,
        input: "xpathnodenveloped.xml",
        params: &[
            ("format", "XAdES Enveloped"),
            ("insertEnvelopedSignatureOnNodeByXPath", "/bookstore/book[1]/title"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-enveloped-xpathns",
        op: Op::Sign,
        input: "xpathnodenvelopedwithns.xml",
        params: &[
            ("format", "XAdES Enveloped"),
            (
                "insertEnvelopedSignatureOnNodeByXPath",
                "//*[namespace-uri()='http://www.facturae.es/Facturae/2007/v3.0/Facturae'][local-name()='Facturae']",
            ),
        ],
        key: RSA,
    },
    Case {
        name: "xades-enveloped-noxpath",
        op: Op::Sign,
        input: "doc.xml",
        params: &[
            ("format", "XAdES Enveloped"),
            ("avoidXpathExtraTransformsOnEnveloped", "true"),
            ("canonicalizationAlgorithm", "none"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-enveloped-latin1",
        op: Op::Sign,
        input: "latin1.xml",
        params: &[("format", "XAdES Enveloped")],
        key: RSA,
    },
    Case {
        name: "xades-detached-xml",
        op: Op::Sign,
        input: "doc.xml",
        params: &[("format", "XAdES Detached")],
        key: RSA,
    },
    Case {
        name: "xades-detached-bin",
        op: Op::Sign,
        input: "hello.txt",
        params: &[("format", "XAdES Detached")],
        key: RSA,
    },
    Case {
        name: "xades-detached-node",
        op: Op::Sign,
        input: "internally_detached_node_sibling.xml",
        params: &[("format", "XAdES Detached"), ("nodeToSign", "IDN")],
        key: RSA,
    },
    Case {
        name: "xades-detached-noderoot",
        op: Op::Sign,
        input: "internally_detached_node_sibling.xml",
        params: &[("format", "XAdES Detached"), ("nodeToSign", "ROOT")],
        key: RSA,
    },
    Case {
        name: "xades-extdet",
        op: Op::Sign,
        input: "hello.txt",
        params: &[
            ("format", "XAdES Externally Detached"),
            ("uri", "https://example.org/doc.bin"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-manifest",
        op: Op::Sign,
        input: "hello.txt",
        params: &[
            ("useManifest", "true"),
            ("uri1", "urn:id:1"),
            ("md1", "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
            ("mimeType1", "text/plain"),
            ("uri2", "https://example.org/2"),
            ("md2", "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="),
            ("precalculatedHashAlgorithm", "SHA-256"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-baseline-policy",
        op: Op::Sign,
        input: "hello.txt",
        params: POLICY,
        key: RSA,
    },
    Case {
        name: "xades-epes-full",
        op: Op::Sign,
        input: "hello.txt",
        params: EPES_FULL,
        key: RSA,
    },
    Case {
        name: "xades-ec",
        op: Op::Sign,
        input: "hello.txt",
        params: &[],
        key: EC,
    },
    Case {
        name: "xades-exc-sha1",
        op: Op::Sign,
        input: "doc.xml",
        params: &[
            ("canonicalizationAlgorithm", "http://www.w3.org/2001/10/xml-exc-c14n#"),
            ("referencesDigestMethod", "http://www.w3.org/2000/09/xmldsig#sha1"),
            ("xadesNamespace", "http://uri.etsi.org/01903/v1.2.2#"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-xpath2",
        op: Op::Sign,
        input: "doc.xml",
        params: &[
            ("xmlTransforms", "1"),
            ("xmlTransform0Type", "http://www.w3.org/2002/06/xmldsig-filter2"),
            ("xmlTransform0Subtype", "subtract"),
            ("xmlTransform0Body", "/doc"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-dtd",
        op: Op::Sign,
        input: "sample-internal-dtd.xml",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-asic-root",
        op: Op::Sign,
        input: "hello.txt",
        params: &[
            ("format", "XAdES Detached"),
            ("RootXmlNodeName", "asic:XAdESSignatures"),
            ("RootXmlNodeNamespace", "http://uri.etsi.org/02918/v1.2.1#"),
            ("RootXmlNodeNamespacePrefix", "xmlns:asic"),
        ],
        key: RSA,
    },
    Case {
        name: "xades-cosign-enveloping-bin",
        op: Op::Cosign,
        input: "@xades-enveloping-bin",
        params: &[],
        key: EC,
    },
    Case {
        name: "xades-cosign-enveloping-xml",
        op: Op::Cosign,
        input: "@xades-enveloping-xml",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-cosign-enveloped",
        op: Op::Cosign,
        input: "@xades-enveloped",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-cosign-enveloped-ids",
        op: Op::Cosign,
        input: "@xades-enveloped-ids",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-cosign-detached-xml",
        op: Op::Cosign,
        input: "@xades-detached-xml",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-cosign-detached-bin",
        op: Op::Cosign,
        input: "@xades-detached-bin",
        params: &[("includeOnlySignningCertificate", "true")],
        key: RSA,
    },
    Case {
        name: "xades-cosign-manifest",
        op: Op::Cosign,
        input: "@xades-manifest",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-cosign-baseline",
        op: Op::Cosign,
        input: "@xades-baseline-policy",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-cosign-noxpath",
        op: Op::Cosign,
        input: "@xades-enveloped-noxpath",
        params: &[("allowXadesEnvelopedWithoutXPath", "true")],
        key: RSA,
    },
    Case {
        name: "xades-countersign-tree",
        op: Op::CounterTree,
        input: "@xades-enveloping-bin",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-countersign-tree-enveloped",
        op: Op::CounterTree,
        input: "@xades-cosign-enveloped",
        params: &[],
        key: RSA,
    },
    Case {
        name: "xades-countersign-leafs",
        op: Op::CounterLeafs,
        input: "@xades-countersign-tree",
        params: &[],
        key: EC,
    },
    Case {
        name: "xades-countersign-detached",
        op: Op::CounterTree,
        input: "@xades-detached-xml",
        params: &[("includeOnlySignningCertificate", "true")],
        key: RSA,
    },
    Case {
        name: "xades-countersign-baseline",
        op: Op::CounterTree,
        input: "@xades-baseline-policy",
        params: &[],
        key: RSA,
    },
];

/// Firmas cuya validación no puede dar "válida" (referencia externa o
/// primera firma invalidada por la cofirma sin transformada XPath).
fn expected_invalid(name: &str) -> bool {
    name == "xades-extdet" || name == "xades-cosign-noxpath"
}

fn golden(name: &str) -> Vec<u8> {
    read(&format!("testdata/xades/java/{name}.xml"))
}

fn run(case: &Case) -> Vec<u8> {
    let signer = XadesSigner::new();
    let key = key(case.key);
    let p = params(case.params);
    let input = match case.input.strip_prefix('@') {
        Some(base) => golden(base),
        None => read(&format!("testdata/xades/inputs/{}", case.input)),
    };
    let alg = if case.key == EC {
        "SHA256withECDSA"
    } else {
        "SHA256withRSA"
    };
    let r = match case.op {
        Op::Sign => signer.sign(&input, alg, &key, &p),
        Op::Cosign => signer.cosign(None, &input, alg, &key, &p),
        Op::CounterTree => signer.countersign(&input, alg, &CounterSignTarget::Tree, &key, &p),
        Op::CounterLeafs => signer.countersign(&input, alg, &CounterSignTarget::Leafs, &key, &p),
    };
    r.unwrap_or_else(|e| panic!("{}: {e}", case.name))
}

#[test]
fn rust_output_matches_java_structure_and_validates() {
    for case in CASES {
        let out = run(case);
        assert_same_structure(case.name, &golden(case.name), &out);
        let v = validation::validate(&out, false, &NoResolver);
        if expected_invalid(case.name) {
            assert_ne!(v[0].validity, Validity::Ok, "{}", case.name);
        } else {
            assert_eq!(v.len(), 1, "{}: {v:?}", case.name);
            assert_eq!(v[0].validity, Validity::Ok, "{}: {v:?}", case.name);
        }
    }
}

#[test]
fn java_signatures_validate_with_rust() {
    for case in CASES {
        let v = validation::validate(&golden(case.name), false, &NoResolver);
        if case.name == "xades-extdet" {
            assert_eq!(v[0].error, Some(ValidityError::BadBuildSign), "{}: {v:?}", case.name);
        } else if case.name == "xades-cosign-noxpath" {
            assert_eq!(v[0].error, Some(ValidityError::NoMatchData), "{}: {v:?}", case.name);
        } else {
            assert_eq!(v, vec![afirma_core::validity::SignValidity::ok()], "{}", case.name);
        }
    }
}

#[test]
fn java_signatures_are_recognised() {
    let signer = XadesSigner::new();
    let none = afirma_core::extra_params::ExtraParams::new();
    for case in CASES {
        let g = golden(case.name);
        assert!(signer.is_sign(&g, &none), "{}", case.name);
        let info = signer.sign_info(&g, &none).unwrap();
        let expected = match case.name {
            n if n.contains("enveloped") || n.contains("noxpath") => Some("XAdES Enveloped"),
            "xades-extdet" => Some("XAdES Externally Detached"),
            n if n.contains("detached") || n == "xades-asic-root" => Some("XAdES Detached"),
            _ => Some("XAdES Enveloping"),
        };
        assert_eq!(info.variant.as_deref(), expected, "{}", case.name);
        let tree = signer.signers_structure(&g, &none).unwrap();
        let expected_tops = match case.op {
            Op::Sign | Op::CounterTree | Op::CounterLeafs => {
                if case.input.contains("cosign") {
                    2
                } else {
                    1
                }
            }
            Op::Cosign => 2,
        };
        assert_eq!(tree.signers.len(), expected_tops, "{}", case.name);
    }
    // Árbol de contrafirmas: sign + TREE + LEAFS => Datos -> S1 -> CS1 -> CS1'
    let tree = signer
        .signers_structure(&golden("xades-countersign-leafs"), &none)
        .unwrap();
    assert_eq!(tree.signers[0].countersigners.len(), 1);
    assert_eq!(tree.signers[0].countersigners[0].countersigners.len(), 1);
    assert!(tree.signers[0].info.signing_time.is_some());
    assert_eq!(
        tree.signers[0].info.sign_algorithm.as_deref(),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
}

#[test]
fn get_data_returns_original_content() {
    let signer = XadesSigner::new();
    let none = afirma_core::extra_params::ExtraParams::new();
    let hello = read("testdata/xades/inputs/hello.txt");
    for name in [
        "xades-enveloping-bin",
        "xades-detached-bin",
        "xades-ec",
        "xades-cosign-enveloping-bin",
        "xades-countersign-tree",
    ] {
        assert_eq!(
            signer.get_data(&golden(name), &none).unwrap(),
            Some(hello.clone()),
            "{name}"
        );
    }
    // Base64 declarado por el usuario: se devuelve el texto Base64.
    assert_eq!(
        signer.get_data(&golden("xades-enveloping-b64"), &none).unwrap(),
        Some(b"QUJD".to_vec())
    );
    for name in ["xades-enveloping-xml", "xades-detached-xml", "xades-enveloped"] {
        let data = signer.get_data(&golden(name), &none).unwrap().unwrap();
        let s = String::from_utf8(data).unwrap();
        assert!(
            s.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc"),
            "{name}: {s}"
        );
        assert!(!s.contains("Signature"), "{name}: {s}");
    }
    assert_eq!(signer.get_data(&golden("xades-extdet"), &none).unwrap(), None);
    assert_eq!(signer.get_data(&golden("xades-manifest"), &none).unwrap(), None);
}

#[test]
fn repository_samples() {
    // Firmas de terceros y antiguas del repositorio Java.
    let signer = XadesSigner::new();
    let none = afirma_core::extra_params::ExtraParams::new();
    for f in [
        "afirma-crypto-xades/src/test/resources/firmaIgae.xsig",
        "afirma-crypto-xades/src/test/resources/firmaMinetad.xsig",
        "afirma-crypto-xades/src/test/resources/xades_con_manifest.xsig",
        "afirma-crypto-xades/src/test/resources/XAdES-Detached-SHA1withRSA-B64.xml",
        "afirma-crypto-xades/src/test/resources/XAdES-Enveloping-SHA1withRSA-XML.xml",
        "afirma-crypto-xades/src/test/resources/78353__XAdES_A_Enveloping.xml",
        "afirma-crypto-xades/src/test/resources/XAdES-XL_con_sello_xml.xml",
    ] {
        let data = read(f);
        assert!(signer.is_sign(&data, &none), "{f}");
        signer
            .signers_structure(&data, &none)
            .unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}
