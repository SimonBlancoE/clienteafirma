//! Utilidades comunes de las pruebas de integración de afirma-cms.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use afirma_keystores::SoftwareKey;

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn testdata(rel: &str) -> PathBuf {
    root().join("testdata").join(rel)
}

pub fn read(rel: &str) -> Vec<u8> {
    std::fs::read(testdata(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Clave de `testdata/pki/<nombre>.p12`.
pub fn key(name: &str) -> SoftwareKey {
    let entries = afirma_keystores::pkcs12::open(&read(&format!("pki/{name}.p12")), "12341234").expect("p12");
    entries[0].signing_key().expect("clave")
}

/// Directorio temporal propio de la prueba.
pub fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("afirma-cms-tests-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Indica si hay un `openssl` utilizable.
pub fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `openssl cms -verify` de una firma (con los datos si es explícita).
/// Devuelve `None` si no hay openssl.
pub fn openssl_verify(name: &str, sign: &[u8], data: Option<&[u8]>) -> Option<(bool, String)> {
    if !have_openssl() {
        eprintln!("openssl no disponible: se omite la verificación externa");
        return None;
    }
    let dir = tmpdir("openssl");
    let sp = dir.join(format!("{name}.p7s"));
    std::fs::write(&sp, sign).unwrap();
    let mut cmd = Command::new("openssl");
    cmd.args([
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-purpose",
        "any",
        "-no_check_time",
        "-in",
    ])
    .arg(&sp)
    .arg("-CAfile")
    .arg(testdata("pki/ca.crt"))
    .args(["-out", if cfg!(windows) { "NUL" } else { "/dev/null" }]);
    if let Some(d) = data {
        let dp = dir.join(format!("{name}.data"));
        std::fs::write(&dp, d).unwrap();
        cmd.arg("-content").arg(dp);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    Some((out.status.success(), text))
}

/// Separa parámetros como la shell (comillas dobles para valores con espacios).
pub fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut has = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                has = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

pub fn params(list: &[String]) -> afirma_core::ExtraParams {
    let mut p = afirma_core::ExtraParams::new();
    for a in list {
        let (k, v) = a.split_once('=').expect("clave=valor");
        p.set(k, v.replace("\\n", "\n"));
    }
    p
}

/// Caso del manifiesto `testdata/cades/cases.txt`.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub op: String,
    pub format: String,
    pub algorithm: String,
    pub store: String,
    pub sign_input: String,
    pub data: String,
    pub target: String,
    pub targets: String,
    pub params: Vec<String>,
}

pub fn load_cases() -> Vec<Case> {
    let text = String::from_utf8(read("cades/cases.txt")).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| {
            let p: Vec<String> = l.splitn(10, '|').map(|s| s.trim().to_string()).collect();
            Case {
                name: p[0].clone(),
                op: p[1].clone(),
                format: p[2].clone(),
                algorithm: p[3].clone(),
                store: p[4].clone(),
                sign_input: p[5].clone(),
                data: p[6].clone(),
                target: p[7].clone(),
                targets: p[8].clone(),
                params: shell_split(&p[9]),
            }
        })
        .collect()
}

pub fn golden_name(case: &str, format: &str) -> String {
    let ext = if format == "CAdES-ASiC-S" { "asics" } else { "csig" };
    format!("cades/{case}.java.{ext}")
}
