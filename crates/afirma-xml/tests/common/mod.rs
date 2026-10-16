//! Utilidades comunes de las pruebas de integración.
#![allow(dead_code)]

use afirma_core::extra_params::ExtraParams;
use afirma_keystores::software::SoftwareKey;
use afirma_xml::dom::{Document, NodeId, NodeKind};

pub fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn read(rel: &str) -> Vec<u8> {
    std::fs::read(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

pub fn key(name: &str) -> SoftwareKey {
    let p12 = read(&format!("testdata/pki/{name}.p12"));
    afirma_keystores::pkcs12::open(&p12, "12341234").unwrap()[0]
        .signing_key()
        .unwrap()
}

pub fn params(pairs: &[(&str, &str)]) -> ExtraParams {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn is_uuid_at(s: &[u8], i: usize) -> bool {
    const PAT: &[u8] = b"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
    if i + PAT.len() > s.len() {
        return false;
    }
    PAT.iter().enumerate().all(|(k, &p)| {
        let c = s[i + k];
        if p == b'-' {
            c == b'-'
        } else {
            c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
        }
    })
}

/// Sustituye los UUID por `U`.
pub fn norm(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if is_uuid_at(b, i) {
            out.push('U');
            i += 36;
        } else {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

const B64_ELEMS: &[&str] = &[
    "DigestValue",
    "SignatureValue",
    "X509Certificate",
    "Modulus",
    "EncapsulatedTimeStamp",
    "PublicKey",
];
const TIME_ELEMS: &[&str] = &["SigningTime", "Value", "date"];
/// Datos del entorno gráfico de OOXML (Java los toma de AWT).
const ENV_ELEMS: &[&str] = &[
    "Monitors",
    "HorizontalResolutionElement",
    "VerticalResolutionElement",
    "ColorDepth",
    "WindowsVersion",
];

fn walk(doc: &Document, n: NodeId, depth: usize, out: &mut Vec<String>) {
    let Some(e) = doc.element(n) else { return };
    let mut attrs: Vec<String> = e
        .attrs
        .iter()
        .map(|a| {
            format!(
                "{{{}}}{}=\"{}\"",
                a.ns.clone().unwrap_or_default(),
                a.local,
                norm(&a.value)
            )
        })
        .collect();
    attrs.sort();
    let mut decls: Vec<String> = e
        .ns_decls
        .iter()
        .map(|d| d.prefix.clone().unwrap_or_default())
        .collect();
    decls.sort();
    let text = match doc.children(n).first().map(|&c| doc.kind(c)) {
        Some(NodeKind::Text { text, .. }) => text.trim().to_string(),
        _ => String::new(),
    };
    let text = if !text.is_empty() && B64_ELEMS.contains(&e.local.as_str()) {
        "B64".to_string()
    } else if !text.is_empty() && TIME_ELEMS.contains(&e.local.as_str()) {
        "T".to_string()
    } else if ENV_ELEMS.contains(&e.local.as_str()) {
        "ENV".to_string()
    } else if text.len() > 120 {
        format!("LONG({})", text.len())
    } else {
        norm(&text)
    };
    out.push(format!(
        "{}{} {{{}}} [{}] {} |{}|",
        "  ".repeat(depth),
        e.qname(),
        e.ns.clone().unwrap_or_default(),
        decls.join(" "),
        attrs.join(" "),
        text
    ));
    for &c in doc.children(n) {
        walk(doc, c, depth + 1, out);
    }
}

/// Estructura normalizada de un documento XML firmado.
pub fn structure(xml: &[u8]) -> Vec<String> {
    let (doc, _) = Document::parse_bytes(xml).expect("XML");
    let mut out = Vec::new();
    walk(&doc, doc.document_element().unwrap(), 0, &mut out);
    out
}

/// Compara dos estructuras mostrando la primera diferencia.
pub fn assert_same_structure(name: &str, expected: &[u8], got: &[u8]) {
    let mut got = structure(got);
    if cfg!(windows) {
        // OOXML añade WindowsVersion al ejecutarse en Windows, como Java; las
        // referencias de Java se generaron en Linux.
        got.retain(|l| {
            !l.trim_start()
                .starts_with("WindowsVersion {http://schemas.microsoft.com/office/2006/digsig}")
        });
    }
    assert_same_lines(name, &structure(expected), &got);
}

/// Compara dos listas de líneas de estructura.
pub fn assert_same_lines(name: &str, a: &[String], b: &[String]) {
    if a != b {
        let pos = a
            .iter()
            .zip(b.iter())
            .position(|(x, y)| x != y)
            .unwrap_or(a.len().min(b.len()));
        panic!(
            "{name}: estructura distinta en la línea {pos}\n  java: {:?}\n  rust: {:?}\n(longitudes {} / {})",
            a.get(pos),
            b.get(pos),
            a.len(),
            b.len()
        );
    }
}
