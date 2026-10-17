//! Comparación con el oráculo Java de la firma web de Autofirma App 1.9
//! (`tools/oracle/AndroidWebOracle.java`, que ejecuta `afirma-core` 1.9 y las
//! clases `CipherDataManager`, `ErrorManager` e `IntermediateServerUtil` de la
//! app). Cada línea de `testdata/android-web/oracle.golden` es un caso de
//! `cases.txt` seguido del resultado de Java; aquí se repite con la
//! implementación Rust y se exige el mismo resultado (los errores se comparan
//! solo como «ERR»: en Java son excepciones de varias clases).
//!
//! Regenerar el fichero golden: `tools/oracle/android_web_oracle.sh`.

use std::io::Write;
use std::sync::Arc;

use afirma_core::http::{HttpClient as CoreHttp, HttpClientError, HttpRequest};
use afirma_protocol::HttpClient;
use afirma_protocol::android::cipher::{cipher_data, decipher_data};
use afirma_protocol::android::errors::{ALL_ERROR_IDS, ErrorId, GENERIC_ERROR_TEXT, gen_error, java_url_encode};
use afirma_protocol::android::intermediate::{Payload, retrieve_body, store_body};
use afirma_protocol::android::request::{self, CommonParams, WebOperation, WebParams, WebRequest};

/// Sin red: ningún caso descarga `dat` por URL.
struct NoNet;
impl CoreHttp for NoNet {
    fn read_url(&self, r: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        panic!("petición inesperada: {}", r.url)
    }
}

fn esc(s: Option<&str>) -> String {
    let Some(s) = s else { return "<null>".into() };
    let mut out = String::new();
    for c in s.encode_utf16() {
        match c {
            0x5c => out.push_str("\\\\"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x3b => out.push_str("\\;"),
            0x3d => out.push_str("\\="),
            c if !(0x20..=0x7e).contains(&c) => out.push_str(&format!("\\u{c:04x}")),
            c => out.push(char::from_u32(u32::from(c)).unwrap()),
        }
    }
    out
}

fn unesc(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('u') => {
                let h: String = it.by_ref().take(4).collect();
                out.push(char::from_u32(u32::from_str_radix(&h, 16).unwrap()).unwrap());
            }
            Some(o) => out.push(o),
            None => out.push('\\'),
        }
    }
    out
}

fn hex(b: Option<&[u8]>) -> String {
    match b {
        None => "<null>".into(),
        Some(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn props(p: &afirma_core::ExtraParams) -> String {
    let items: Vec<String> = p
        .iter()
        .map(|(k, v)| format!("{}:{}", esc(Some(k)), esc(Some(v))))
        .collect();
    format!("{{{}}}", items.join(","))
}

fn common(c: &CommonParams) -> String {
    format!(
        "key={};data={};fileid={};rtservlet={};id={};stservlet={};aw={};mcv={}",
        esc(c.des_key.as_deref().map(|k| std::str::from_utf8(k).unwrap())),
        hex(c.data.as_deref()),
        esc(c.file_id.as_deref()),
        esc(c.retrieve_servlet.as_deref()),
        esc(c.id.as_deref()),
        esc(c.storage_servlet.as_deref()),
        c.active_waiting,
        esc(c.min_client_version.as_deref()),
    )
}

fn describe(r: &WebRequest) -> String {
    match r {
        WebRequest::Sign(p) => format!(
            "op={};{};ver={};format={};algorithm={};props={};sticky={};resetsticky={};appname={}",
            esc(Some(&p.operation)),
            common(&p.common),
            esc(Some(&p.common.min_protocol_version)),
            esc(p.format.as_deref()),
            esc(p.algorithm.as_deref()),
            props(&p.extra_params),
            p.sticky,
            p.reset_sticky,
            esc(p.app_name.as_deref()),
        ),
        WebRequest::SelectCert(p) => format!(
            "{};ver={};props={};sticky={};resetsticky={}",
            common(&p.common),
            esc(Some(&p.common.min_protocol_version)),
            props(&p.extra_params),
            p.sticky,
            p.reset_sticky,
        ),
        WebRequest::Save(p) => format!(
            "{};ver={};title={};filename={};exts={};desc={}",
            common(&p.common),
            esc(Some(&p.common.min_protocol_version)),
            esc(Some(&p.title)),
            esc(p.filename.as_deref()),
            esc(p.extensions.as_deref()),
            esc(p.description.as_deref()),
        ),
        WebRequest::Batch(p) => format!(
            "{};ver={};appname={};local={};pre={};post={};props={};sticky={};resetsticky={};needcert={};jsonbatch={}",
            common(&p.common),
            esc(Some(&p.common.min_protocol_version)),
            esc(p.app_name.as_deref()),
            p.local_batch_process,
            esc(p.presigner_url.as_deref()),
            esc(p.postsigner_url.as_deref()),
            props(&p.extra_params),
            p.sticky,
            p.reset_sticky,
            p.need_cert,
            p.json_batch,
        ),
    }
}

fn op_of(kind: &str) -> WebOperation {
    match kind {
        "sign" => WebOperation::Sign,
        "selectcert" => WebOperation::SelectCert,
        "save" => WebOperation::Save,
        "batch" => WebOperation::Batch,
        k => panic!("{k}"),
    }
}

fn gzip_b64(text: &str) -> String {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(text.as_bytes()).unwrap();
    afirma_core::base64::encode_url_safe(&enc.finish().unwrap())
}

fn rust_result(f: &[&str], http: &HttpClient) -> Result<String, ()> {
    match f[0] {
        "url" => {
            let url = unesc(f[2]).replace("@GZIP@", &gzip_b64("comprimido"));
            request::parse_url(op_of(f[1]), &url, http)
                .map(|r| describe(&r))
                .map_err(|_| ())
        }
        "xml" => {
            let p = WebParams::from_envelope(unesc(f[2]).as_bytes()).map_err(|_| ())?;
            request::parse(op_of(f[1]), &p, http)
                .map(|r| describe(&r))
                .map_err(|_| ())
        }
        "cipher" => cipher_data(&unhex(f[2]), f[1].as_bytes()).map_err(|_| ()),
        "decipher" => decipher_data(unesc(f[2]).as_bytes(), Some(f[1].as_bytes()))
            .map(|d| hex(Some(&d)))
            .map_err(|_| ()),
        "error" => {
            let id = ALL_ERROR_IDS.iter().copied().find(|e| e.id == f[1]).unwrap_or(ErrorId {
                id: Box::leak(f[1].to_string().into_boxed_str()),
                text: GENERIC_ERROR_TEXT,
            });
            let msg = (f[3] != "-").then(|| unesc(f[3]));
            let text = gen_error(id, f[2].parse().unwrap(), msg.as_deref());
            Ok(format!("{} {}", esc(Some(&text)), esc(Some(&java_url_encode(&text)))))
        }
        "upload" => {
            let data = unesc(f[3]);
            let payload = if data.contains('%') {
                Payload::Encoded(data)
            } else {
                Payload::Result(data)
            };
            Ok(format!(
                "{} {}",
                esc(Some(f[1])),
                esc(Some(&store_body(f[2], &payload)))
            ))
        }
        "download" => Ok(format!("{} {}", esc(Some(f[1])), esc(Some(&retrieve_body(f[2]))))),
        "b64std" => afirma_core::base64::decode(&unesc(f[1]))
            .map(|d| hex(Some(&d)))
            .map_err(|_| ()),
        k => panic!("caso desconocido {k}"),
    }
}

#[test]
fn matches_java_oracle() {
    let golden = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/android-web/oracle.golden"
    ))
    .expect("oracle.golden");
    let http = HttpClient::new(Arc::new(NoNet));
    let mut n = 0;
    let mut failures = Vec::new();
    for line in golden.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (input, java) = f.split_at(f.len() - 1);
        let java = java[0];
        let rust = match rust_result(input, &http) {
            Ok(s) => format!("OK {s}"),
            Err(()) => "ERR".to_string(),
        };
        let same = if java.starts_with("ERR ") {
            rust == "ERR"
        } else {
            rust == java
        };
        if !same {
            failures.push(format!("{}\n  java: {java}\n  rust: {rust}", input.join(" | ")));
        }
        n += 1;
    }
    assert!(n >= 80, "solo {n} casos");
    assert!(
        failures.is_empty(),
        "{} diferencias:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
