//! Transformada XSLT de XMLDSig frente al JDK: cada caso de
//! `testdata/xslt/cases/*.cases` se ha ejecutado con `TransformXSLT` de
//! Santuario sobre XSLTC (`tools/oracle/xslt/XsltOracle.java`) y su salida
//! está en `testdata/xslt/expected/`. La salida de Rust debe ser idéntica
//! octeto a octeto (o fallar si Java falla).

use afirma_xml::dom::Document;
use afirma_xml::xslt::{Limits, transform_stylesheet};

mod common;

struct Case {
    file: String,
    name: String,
    xsl: String,
    input: String,
}

/// Mismo formato que `XsltOracle.parseCases`.
fn parse_cases(file: &str, text: &str) -> Vec<Case> {
    let mut out = Vec::new();
    let mut default_input = "<doc/>".to_string();
    let lines: Vec<&str> = text.split('\n').collect();
    let trim_end = |s: String| s.trim_end_matches('\n').to_string();
    let mut i = 0;
    while i < lines.len() {
        let Some(name) = lines[i].strip_prefix("#### ") else {
            i += 1;
            continue;
        };
        let name = name.trim().to_string();
        i += 1;
        let mut xsl = String::new();
        let mut input: Option<String> = None;
        while i < lines.len() && !lines[i].starts_with("#### ") {
            if input.is_none() && lines[i] == "====" {
                input = Some(String::new());
            } else {
                let sb = input.as_mut().unwrap_or(&mut xsl);
                if !sb.is_empty() {
                    sb.push('\n');
                }
                sb.push_str(lines[i]);
            }
            i += 1;
        }
        let xsl = trim_end(xsl);
        if name == "@input" {
            default_input = xsl;
            continue;
        }
        out.push(Case {
            file: file.to_string(),
            name,
            xsl,
            input: input.map(trim_end).unwrap_or_else(|| default_input.clone()),
        });
    }
    out
}

fn run(case: &Case) -> Result<Vec<u8>, String> {
    let doc = Document::parse(&case.xsl).map_err(|e| e.to_string())?;
    let root = doc.document_element().ok_or("sin raíz")?;
    let ns = afirma_xml::xslt::XSLT_NS;
    let is_sheet = doc
        .element(root)
        .is_some_and(|e| e.is(ns, "stylesheet") || e.is(ns, "transform"));
    if !is_sheet {
        // `TransformXSLT` solo acepta xsl:stylesheet o xsl:transform.
        return Err("xml.WrongContent".into());
    }
    transform_stylesheet(&doc, root, case.input.as_bytes(), &Limits::default()).map_err(|e| e.to_string())
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).escape_debug().to_string()
}

#[test]
fn matches_jdk_xsltc() {
    let root = common::root();
    let dir = root.join("testdata/xslt/cases");
    let exp = root.join("testdata/xslt/expected");
    let filter = std::env::var("XSLT_CASE").unwrap_or_default();
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "cases"))
        .collect();
    files.sort();
    let (mut ok, mut failures) = (0, Vec::new());
    let mut seen = std::collections::HashSet::new();
    for f in files {
        let stem = f.file_stem().unwrap().to_string_lossy().to_string();
        let text = std::fs::read_to_string(&f).unwrap();
        for case in parse_cases(&stem, &text) {
            let id = format!("{}.{}", case.file, case.name);
            assert!(seen.insert(id.clone()), "caso repetido: {id}");
            if !filter.is_empty() && !id.contains(&filter) {
                continue;
            }
            let out_path = exp.join(format!("{id}.out"));
            let err_path = exp.join(format!("{id}.err"));
            let got = run(&case);
            let verdict = if out_path.exists() {
                let want = std::fs::read(&out_path).unwrap();
                match &got {
                    Ok(g) if *g == want => None,
                    Ok(g) => Some(format!("{id}:\n  java: {}\n  rust: {}", show(&want), show(g))),
                    Err(e) => Some(format!("{id}:\n  java: {}\n  rust: ERROR {e}", show(&want))),
                }
            } else if err_path.exists() {
                match &got {
                    Err(_) => None,
                    Ok(g) => {
                        let msg = std::fs::read_to_string(&err_path).unwrap();
                        Some(format!(
                            "{id}:\n  java: ERROR {}\n  rust: {}",
                            msg.lines().next().unwrap_or(""),
                            show(g)
                        ))
                    }
                }
            } else {
                Some(format!("{id}: falta la salida de referencia"))
            };
            match verdict {
                None => ok += 1,
                Some(v) => failures.push(v),
            }
        }
    }
    for f in &failures {
        eprintln!("{f}");
    }
    eprintln!("casos correctos: {ok}, diferencias: {}", failures.len());
    assert!(ok > 0, "no hay casos");
    if filter.is_empty() {
        // Ninguna salida de referencia sin su caso.
        let refs = std::fs::read_dir(&exp).unwrap().count();
        assert_eq!(refs, seen.len(), "salidas de referencia sin caso en {}", exp.display());
    }
    assert!(failures.is_empty(), "{} casos distintos de Java", failures.len());
}
