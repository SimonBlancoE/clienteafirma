//! Utilidades comunes de las pruebas de afirma-cli: casos de
//! `testdata/cli/cases.tsv`, ficheros golden del oráculo Java y comparación
//! estructural de firmas.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use afirma_cli::{CliEnv, CliOutcome};
use afirma_core::{ExtraParams, Signer};

/// Directorio `testdata`.
pub fn td() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .canonicalize()
        .unwrap()
}

/// Directorio de las firmas de Java (`testdata/cli/java`).
pub fn java_dir() -> PathBuf {
    td().join("cli/java")
}

/// Caso de `cases.tsv`.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub flags: HashMap<String, String>,
    pub args: Vec<String>,
}

impl Case {
    pub fn flag(&self, k: &str) -> Option<&str> {
        self.flags.get(k).map(String::as_str)
    }

    pub fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }
}

fn macro_args(name: &str) -> Vec<String> {
    vec![
        "-store".into(),
        format!("pkcs12:@TD@/pki/firmante-{name}.p12"),
        "-password".into(),
        "12341234".into(),
        "-alias".into(),
        format!("firmante-{name}"),
    ]
}

/// Casos del fichero.
pub fn load_cases() -> Vec<Case> {
    let text = std::fs::read_to_string(td().join("cli/cases.tsv")).unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split('\t');
        let name = parts.next().unwrap().to_string();
        let flags = parts
            .next()
            .unwrap()
            .split(',')
            .filter(|f| !f.is_empty() && *f != "-")
            .map(|f| match f.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (f.to_string(), String::new()),
            })
            .collect();
        let mut args = Vec::new();
        for a in parts {
            match a {
                "@RSA@" => args.extend(macro_args("rsa")),
                "@EC@" => args.extend(macro_args("ec")),
                _ => args.push(a.to_string()),
            }
        }
        out.push(Case { name, flags, args });
    }
    out
}

/// Caso por nombre.
pub fn case(name: &str) -> Case {
    load_cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("caso {name}"))
}

/// Golden de Java: `(estado, salida)`.
pub fn golden(name: &str) -> (i32, String) {
    let text = std::fs::read_to_string(td().join(format!("cli/golden/{name}.txt"))).unwrap();
    let (first, rest) = text.split_once('\n').unwrap();
    let status: i32 = first.strip_prefix("status: ").unwrap().parse().unwrap();
    (status, rest.to_string())
}

/// Entorno de las pruebas: nombre `autofirma.jar` (como el oráculo), sin
/// configuración regional del sistema y con la preferencia de idioma del caso.
pub fn env_for(locale: Option<&str>) -> CliEnv {
    let locale = locale.map(str::to_string);
    let mut env = CliEnv::new("autofirma.jar")
        .with_preferences(move |k| if k == "default.locale" { locale.clone() } else { None });
    env.os_locale = None;
    env
}

/// Sustituye los marcadores de los argumentos.
pub fn expand(args: &[String], out: &Path) -> Vec<String> {
    let td = td();
    let j = java_dir();
    args.iter()
        .map(|a| {
            a.replace("@J@", &j.to_string_lossy())
                .replace("@TD@", &td.to_string_lossy())
                .replace("@OUT@", &out.to_string_lossy())
        })
        .collect()
}

/// Devuelve los marcadores a la salida.
pub fn normalize(text: &str, out: &Path) -> String {
    text.replace(&*out.to_string_lossy(), "@OUT@")
        .replace(&*java_dir().to_string_lossy(), "@J@")
        .replace(&*td().to_string_lossy(), "@TD@")
}

/// Ejecuta un caso en un directorio de salida nuevo.
pub fn run_case(c: &Case) -> (CliOutcome, String, tempfile::TempDir) {
    let out = tempfile::tempdir().unwrap();
    let env = env_for(c.flag("locale"));
    let outcome = afirma_cli::run(&expand(&c.args, out.path()), &env);
    let text = normalize(&outcome.output, out.path());
    (outcome, text, out)
}

/// Estado tal y como lo ve el sistema (−1 → 255).
pub fn os_status(s: i32) -> i32 {
    s & 0xff
}

/// Firmador que reconoce unos datos (incluidos ODF y OOXML, que el registro
/// puede no tener aún).
pub fn signer_of(data: &[u8]) -> Option<(String, Box<dyn Signer>)> {
    let xp = ExtraParams::new();
    if let Some((k, s)) = afirma_signers::detect(data, &xp) {
        return Some((format!("{k:?}"), s));
    }
    for n in ["ooxml", "odf"] {
        if let Some(s) = afirma_xml::signer_for(n)
            && s.is_sign(data, &xp)
        {
            return Some((n.to_string(), s));
        }
    }
    None
}

/// Estructura comparable de una firma: formato, árbol (profundidad y
/// firmante) y formato de `sign_info`.
pub fn structure(data: &[u8]) -> (String, Vec<(usize, String)>, Option<String>) {
    let xp = ExtraParams::new();
    let (kind, signer) = signer_of(data).expect("no es una firma reconocida");
    let tree = signer.signers_structure(data, &xp).expect("árbol de firmantes");
    let shape = tree
        .preorder()
        .into_iter()
        .map(|(d, n)| (d, n.info.signer_name()))
        .collect();
    let info = signer.sign_info(data, &xp).ok().map(|i| i.format);
    (kind, shape, info)
}

/// Compara una firma de Rust con la de Java para la misma orden.
pub fn compare_signatures(name: &str, java: &[u8], rust: &[u8]) {
    let (jk, jt, ji) = structure(java);
    let (rk, rt, ri) = structure(rust);
    assert_eq!(rk, jk, "{name}: formato");
    assert_eq!(rt, jt, "{name}: árbol de firmantes");
    assert_eq!(ri, ji, "{name}: formato de la firma");
    let xp = ExtraParams::new();
    let jv = afirma_signers::validate(java, &xp);
    let rv = afirma_signers::validate(rust, &xp);
    assert_eq!(
        rv.first().map(|v| v.validity),
        jv.first().map(|v| v.validity),
        "{name}: validez {rv:?} / {jv:?}"
    );
    assert_eq!(
        rv.first().map(|v| v.error),
        jv.first().map(|v| v.error),
        "{name}: causa {rv:?} / {jv:?}"
    );
}

/// Copia una firma de Rust a `AFIRMA_CLI_DUMP` (para validarla con Java:
/// `tools/oracle/cli_goldens.py --verify DIR`).
pub fn dump(name: &str, ext: &str, data: &[u8]) {
    if let Ok(dir) = std::env::var("AFIRMA_CLI_DUMP") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}{ext}")), data).unwrap();
    }
}

/// Contenido de `<sign>` de una respuesta XML.
pub fn xml_sign(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let start = text.find("<sign>")? + 6;
    let end = text.find("</sign>")?;
    base64::engine::general_purpose::STANDARD.decode(&text[start..end]).ok()
}

/// Sustituye el contenido de `<sign>` por `@SIGN@`.
pub fn mask_sign(text: &str) -> String {
    match (text.find("<sign>"), text.find("</sign>")) {
        (Some(s), Some(e)) => format!("{}<sign>@SIGN@{}", &text[..s], &text[e..]),
        _ => text.to_string(),
    }
}
