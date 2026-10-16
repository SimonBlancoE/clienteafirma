//! Pruebas diferenciales contra las salidas *golden* de la AutoFirma Java
//! (`testdata/cades/*.java.*`, generadas con `tools/oracle/cms_diff.py`).
//!
//! Para cada caso del manifiesto se repite la operación en Rust con los
//! mismos datos, parámetros y clave, y se compara el resumen estructural
//! (algoritmos, versiones, orden y valor de los atributos, certificados...)
//! enmascarando solo las fechas y los valores de firma. Las firmas Rust se
//! verifican además con OpenSSL y con el validador propio.
#![allow(clippy::result_large_err)]

mod common;

use afirma_cms::inspect::structure_summary;
use afirma_cms::{CadesAsicsSigner, CadesSigner, CmsSigner, asics, validation};
use afirma_core::validity::Validity;
use afirma_core::{CounterSignTarget, Signer};
use common::*;

fn signer(format: &str) -> Box<dyn Signer> {
    match format {
        "CAdES" => Box::new(CadesSigner),
        "CMS/PKCS#7" => Box::new(CmsSigner),
        "CAdES-ASiC-S" => Box::new(CadesAsicsSigner),
        other => panic!("formato desconocido: {other}"),
    }
}

fn inner(format: &str, sign: &[u8]) -> Vec<u8> {
    if format == "CAdES-ASiC-S" {
        asics::get_binary_signature(sign).unwrap()
    } else {
        sign.to_vec()
    }
}

fn run_case(case: &Case, cases: &[Case]) -> afirma_core::Result<Vec<u8>> {
    let key = key(&case.store);
    let extra = params(&case.params);
    let data = (case.data != "-").then(|| read(&format!("cades/data/{}", case.data)));
    let sign_input = case.sign_input.strip_prefix('@').map(|base| {
        let fmt = &cases.iter().find(|c| c.name == base).expect("caso base").format;
        read(&golden_name(base, fmt))
    });
    let s = signer(&case.format);
    match case.op.as_str() {
        "sign" => s.sign(data.as_deref().unwrap(), &case.algorithm, &key, &extra),
        "cosign" => s.cosign(
            data.as_deref(),
            sign_input.as_deref().unwrap(),
            &case.algorithm,
            &key,
            &extra,
        ),
        "countersign" => {
            let target = match case.target.as_str() {
                "nodes" => {
                    CounterSignTarget::Nodes(case.targets.split(',').map(|n| n.trim().parse().unwrap()).collect())
                }
                "signers" => CounterSignTarget::Signers(case.targets.split('|').map(String::from).collect()),
                t => CounterSignTarget::from_name(t).unwrap(),
            };
            s.countersign(sign_input.as_deref().unwrap(), &case.algorithm, &target, &key, &extra)
        }
        other => panic!("operación desconocida: {other}"),
    }
}

/// Desviación documentada: en las cofirmas se añade al SET
/// `digestAlgorithms` la huella del nuevo firmante si no estaba (Java no lo
/// hace). Si esa es la única diferencia, se acepta.
fn normalize_digest_algorithms(java: &str, rust: &str, case: &Case) -> String {
    let line = |s: &str| {
        s.lines()
            .find(|l| l.starts_with(" digestAlgorithms:"))
            .unwrap_or_default()
            .to_string()
    };
    let (jl, rl) = (line(java), line(rust));
    if jl == rl || case.op != "cosign" {
        return rust.to_string();
    }
    let items = |l: &str| -> Vec<String> {
        l.trim_start_matches(" digestAlgorithms:")
            .split_whitespace()
            .map(String::from)
            .collect()
    };
    let (ji, ri) = (items(&jl), items(&rl));
    let new_alg = hex::encode(afirma_cms::alg::digest_alg_id(
        afirma_cms::alg::digest_from_java_name(&case.algorithm).unwrap(),
    ));
    let extra: Vec<&String> = ri.iter().filter(|x| !ji.contains(x)).collect();
    if ji.iter().all(|x| ri.contains(x)) && extra.len() == 1 && *extra[0] == new_alg {
        rust.replace(&rl, &jl)
    } else {
        rust.to_string()
    }
}

/// Instante de firma de los firmantes nuevos de la salida Java (los que no
/// estaban en la firma de entrada).
fn new_signing_time(java: &[u8], input: Option<&[u8]>) -> Option<chrono::DateTime<chrono::Utc>> {
    let old: Vec<Vec<u8>> = input
        .and_then(|i| {
            afirma_cms::cms::SignedData::parse(i)
                .ok()
                .map(|sd| sd.all_signer_infos().iter().map(|s| s.signature_value()).collect())
        })
        .unwrap_or_default();
    let sd = afirma_cms::cms::SignedData::parse(java).ok()?;
    sd.all_signer_infos()
        .iter()
        .filter(|s| !old.contains(&s.signature_value()))
        .find_map(|s| s.signing_time())
}

/// Repite el caso con el mismo instante de firma que la salida Java.
fn run_case_at(case: &Case, cases: &[Case], now: chrono::DateTime<chrono::Utc>) -> afirma_core::Result<Vec<u8>> {
    use afirma_cms::{cades, cms_signer};
    let key = key(&case.store);
    let extra = params(&case.params);
    let data = (case.data != "-").then(|| read(&format!("cades/data/{}", case.data)));
    let input = case.sign_input.strip_prefix('@').map(|base| {
        let fmt = &cases.iter().find(|c| c.name == base).expect("caso base").format;
        read(&golden_name(base, fmt))
    });
    let target = || match case.target.as_str() {
        "nodes" => CounterSignTarget::Nodes(case.targets.split(',').map(|n| n.trim().parse().unwrap()).collect()),
        "signers" => CounterSignTarget::Signers(case.targets.split('|').map(String::from).collect()),
        t => CounterSignTarget::from_name(t).unwrap(),
    };
    match (case.format.as_str(), case.op.as_str()) {
        ("CAdES", "sign") => cades::sign_at(data.as_deref().unwrap(), &case.algorithm, &key, &extra, now),
        ("CAdES", "cosign") => cades::cosign_at(
            data.as_deref(),
            input.as_deref().unwrap(),
            &case.algorithm,
            &key,
            &extra,
            now,
        ),
        ("CAdES", "countersign") => {
            cades::countersign_at(input.as_deref().unwrap(), &case.algorithm, &target(), &key, &extra, now)
        }
        ("CMS/PKCS#7", "sign") => cms_signer::sign_at(data.as_deref().unwrap(), &case.algorithm, &key, &extra, now),
        ("CMS/PKCS#7", "cosign") => match data.as_deref() {
            Some(d) => {
                cms_signer::cosign_with_data_at(d, input.as_deref().unwrap(), &case.algorithm, &key, &extra, now)
            }
            None => cms_signer::cosign_at(input.as_deref().unwrap(), &case.algorithm, &key, now),
        },
        ("CMS/PKCS#7", "countersign") => {
            cms_signer::countersign_at(input.as_deref().unwrap(), &case.algorithm, &target(), &key, now)
        }
        _ => unreachable!(),
    }
}

/// Con claves RSA (firma determinista) y el mismo instante de firma, la
/// salida Rust es idéntica byte a byte a la de Java.
#[test]
fn java_golden_byte_identity() {
    let cases = load_cases();
    let mut identical = 0;
    let mut failures = Vec::new();
    for case in &cases {
        let golden = testdata(&golden_name(&case.name, &case.format));
        if !golden.exists() || case.store == "firmante-ec" || case.format == "CAdES-ASiC-S" {
            continue;
        }
        let java = std::fs::read(&golden).unwrap();
        let input = case.sign_input.strip_prefix('@').map(|base| {
            let fmt = &cases.iter().find(|c| c.name == base).unwrap().format;
            read(&golden_name(base, fmt))
        });
        if input.as_deref().is_some_and(|i| {
            afirma_cms::cms::SignedData::parse(i)
                .unwrap()
                .all_signer_infos()
                .iter()
                .any(|s| s.signature_oid.to_dotted().starts_with("1.2.840.10045"))
        }) {
            continue; // la entrada contiene firmas ECDSA (no deterministas)
        }
        let now = new_signing_time(&java, input.as_deref()).unwrap_or_else(chrono::Utc::now);
        let ours = run_case_at(case, &cases, now).unwrap();
        if ours == java {
            identical += 1;
        } else {
            let js = structure_summary(&java).unwrap();
            let rs = normalize_digest_algorithms(&js, &structure_summary(&ours).unwrap(), case);
            // Única diferencia admitida: digestAlgorithms de las cofirmas (desviación documentada).
            if js != rs || case.op != "cosign" {
                failures.push(case.name.clone());
            }
        }
    }
    assert!(failures.is_empty(), "salidas distintas de Java: {failures:?}");
    assert!(identical >= 40, "solo {identical} casos idénticos");
    eprintln!("{identical} firmas idénticas byte a byte a las de Java");
}

#[test]
fn java_golden_parity() {
    let cases = load_cases();
    assert!(cases.len() >= 60, "manifiesto incompleto");
    let mut failures = Vec::new();
    for case in &cases {
        let golden = testdata(&golden_name(&case.name, &case.format));
        let result = run_case(case, &cases);
        if !golden.exists() {
            // Java falló en este caso: Rust también debe fallar.
            if result.is_ok() {
                failures.push(format!("{}: Java falla pero Rust no", case.name));
            }
            continue;
        }
        let ours = match result {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!("{}: error en Rust: {e}", case.name));
                continue;
            }
        };
        let java = std::fs::read(&golden).unwrap();
        let js = structure_summary(&inner(&case.format, &java)).unwrap();
        let rs = normalize_digest_algorithms(&js, &structure_summary(&inner(&case.format, &ours)).unwrap(), case);
        if js != rs {
            failures.push(format!(
                "{}: resumen distinto\n--- java\n{js}\n--- rust\n{rs}",
                case.name
            ));
            continue;
        }
        // La firma Rust debe validar (salvo las que Java también genera inválidas).
        let data =
            (case.data != "-" && case.op == "sign" && !case.params.iter().any(|p| p.starts_with("precalculated")))
                .then(|| read(&format!("cades/data/{}", case.data)));
        let inner_sig = inner(&case.format, &ours);
        let v = validation::validate(&inner_sig, data.as_deref(), true);
        let expected_invalid = case.name == "cades_precalc_mismatch" || case.name.contains("caducado");
        if !expected_invalid && v[0].validity == Validity::Ko {
            failures.push(format!("{}: la firma Rust no valida: {:?}", case.name, v));
        }
        // OpenSSL (las firmas sin datos o con atributos no estándar se omiten).
        let skip_openssl = case.op == "sign" && case.params.iter().any(|p| p.starts_with("precalculated"));
        if !skip_openssl {
            let content = data.clone().or_else(|| {
                (afirma_cms::detect::obtain_data(&inner_sig).ok().flatten().is_none())
                    .then(|| read("cades/data/hola.txt"))
            });
            let content = if afirma_cms::detect::obtain_data(&inner_sig).ok().flatten().is_some() {
                None
            } else {
                content
            };
            if let Some((ok, msg)) = openssl_verify(&case.name, &inner_sig, content.as_deref())
                && !ok
                && !expected_invalid
            {
                failures.push(format!("{}: OpenSSL no verifica la firma Rust: {msg}", case.name));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} fallos:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
