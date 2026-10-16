//! Comparación con los resultados de AutoFirma Java guardados en
//! `testdata/certval/java-*.txt` (regenerables con
//! `tools/oracle/certval_oracle.sh`).

mod common;

use afirma_certval::{SelectionMode, ValidationResult, testing, validate_certificate, validate_certificate_report};
use common::*;

fn lines(name: &str) -> Vec<String> {
    String::from_utf8(raw(name))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn by_name(name: &str) -> ValidationResult {
    *ValidationResult::ALL
        .iter()
        .find(|r| r.name() == name)
        .unwrap_or_else(|| panic!("resultado {name}"))
}

#[test]
fn messages_and_json() {
    for line in lines("java-messages.txt") {
        let (left, json) = line.split_once(" | ").unwrap();
        let mut parts = left.splitn(3, ' ');
        let code: u8 = parts.next().unwrap().parse().unwrap();
        let name = parts.next().unwrap();
        let text = parts.next().unwrap();
        let r = ValidationResult::from_code(code).unwrap();
        assert_eq!(r.name(), name);
        assert_eq!(r.java_description(), text);
        assert_eq!(r.to_json_string().replace('\n', "\\n"), json);
    }
}

#[test]
fn issuer_identifiers() {
    let plugin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../afirma-simple-plugin-validatecerts/src/main/resources/es/gob/afirma/plugin/certvalidation/validation",
    );
    for line in lines("java-ids.txt") {
        let f: Vec<&str> = line.split(' ').collect();
        let (file, id, alg) = (f[0], f[1], f[2]);
        let path = ["camerfirma", "dnie", "fnmt/componentes"]
            .iter()
            .map(|d| plugin.join(d).join(file))
            .find(|p| p.exists())
            .unwrap_or_else(|| data_dir().join(file));
        let der = afirma_certval::parse_certificates(&std::fs::read(&path).unwrap()).remove(0);
        assert_eq!(afirma_certval::java_issuer_identifier(&der).unwrap(), id, "{file}");
        assert_eq!(testing::jca_signature_name(&der).unwrap(), alg, "{file}");
    }
}

#[test]
fn ocsp_request_is_byte_identical() {
    let java = hex::decode(raw("java-ocspreq-good.txt").trim_ascii()).unwrap();
    assert_eq!(testing::ocsp_request(&cert("good"), Some(&cert("ca"))).unwrap(), java);
    // La de OpenSSL (`-no_nonce`) también coincide.
    assert_eq!(raw("req_good_openssl.der"), java);
}

#[test]
fn ocsp_analysis_like_java() {
    for line in lines("java-analyze.txt") {
        let (file, expected) = line.split_once(' ').unwrap();
        assert_eq!(testing::java_analyze_ocsp(&raw(file)), by_name(expected), "{file}");
    }
}

#[test]
fn validation_without_network_like_java() {
    let s = Server::start();
    let mut o = options(MappingFetcher::new(&s));
    o.selection = SelectionMode::JavaFactory;
    for line in lines("java-validate.txt").into_iter().chain(lines("java-period.txt")) {
        let (file, expected) = line.split_once(' ').unwrap();
        let name = file.trim_end_matches(".crt");
        if name == "good" {
            continue; // necesita red
        }
        let r = validate_certificate_report(&cert(name), &o);
        if expected.starts_with("ERROR") {
            assert!(r.no_mechanism, "{file}: {r:?}");
        } else {
            assert_eq!(r.result, by_name(expected), "{file}");
        }
    }
    assert!(s.requests().is_empty());
}

/// `CrlHelper.verifyCertificateCRLs` de Java con cada CRL, con y sin la
/// clave del emisor. Única diferencia: Java acepta CRL caducadas.
#[test]
fn crl_results_like_java() {
    let s = Server::start();
    for line in lines("java-crl.txt") {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, issuer, crl, java) = (f[0], f[1], f[2], by_name(f[3]));
        if crl == "noexiste.crl" {
            s.status("/crl.certval.test/ca.crl", 404);
        } else {
            s.file("/crl.certval.test/ca.crl", raw(crl));
        }
        let mut o = options(MappingFetcher::new(&s));
        o.selection = SelectionMode::JavaFactory;
        o.download_issuer = false;
        if issuer == "ca" {
            o.chain = vec![cert("ca")];
        } else {
            o.require_verified_revocation = false;
        }
        let ours = validate_certificate(&cert(name), &o);
        let expected = if crl == "ca_stale.crl" {
            ValidationResult::ServerError
        } else {
            java
        };
        assert_eq!(ours, expected, "{line}");
    }
}
