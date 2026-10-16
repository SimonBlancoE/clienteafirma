//! Herramienta de pruebas: valida firmas XML con el validador Rust.
//! Uso: `xvalidate [--certs] fichero...`; imprime `VALIDEZ ERROR` por línea
//! (mismo formato que `XmlOracle validate`).
fn main() {
    let mut certs = false;
    for a in std::env::args().skip(1) {
        if a == "--certs" {
            certs = true;
            continue;
        }
        let data = std::fs::read(&a).expect("fichero");
        println!("== {a}");
        for v in afirma_xml::validation::validate(&data, certs, &afirma_xml::dsig::NoResolver) {
            let validity = format!("{:?}", v.validity).to_uppercase();
            let err = v
                .error
                .map(|e| java_name(&format!("{e:?}")))
                .unwrap_or_else(|| "null".into());
            println!("{validity} {err}");
        }
    }
}

/// `NoMatchData` -> `NO_MATCH_DATA` (con las erratas de los nombres Java).
fn java_name(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out.replace("UNKNOWN_ERROR", "UNKOWN_ERROR")
}
