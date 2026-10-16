//! Pruebas de integración contra los servidores Java REALES de este
//! repositorio (StorageService, RetrieveService y el servicio de firma
//! trifásica y de lotes) desplegados en un Tomcat 9 de Docker.
//!
//! Son opcionales: solo se ejecutan con `AFIRMA_IT=1` y `AFIRMA_IT_BASE`
//! (URL base de los servicios, p. ej. `http://172.17.0.6:8080`):
//!
//! ```sh
//! tools/protocol-it/run.sh start
//! AFIRMA_IT=1 AFIRMA_IT_BASE=$(tools/protocol-it/run.sh url) \
//!   CARGO_TARGET_DIR=target/agents/afirma-protocol \
//!   cargo test -p afirma-protocol --test java_servers -- --test-threads=1
//! tools/protocol-it/run.sh stop
//! ```

mod common;

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::http::{HttpSettings, ProxyMode, UreqHttpClient};
use afirma_protocol::cipher::{ServerCipher, des_config};
use afirma_protocol::intermediate::{self, PollOutcome};
use afirma_protocol::{HttpClient, LaunchOutcome, LauncherConfig, ProtocolLauncher, ProtocolVersion, jbase64};
use common::*;

const V41: ProtocolVersion = ProtocolVersion::V4_1;

fn base() -> Option<String> {
    if std::env::var("AFIRMA_IT").ok().as_deref() != Some("1") {
        eprintln!("Prueba omitida: defina AFIRMA_IT=1 y AFIRMA_IT_BASE (tools/protocol-it/run.sh)");
        return None;
    }
    Some(std::env::var("AFIRMA_IT_BASE").expect("AFIRMA_IT_BASE").trim_end_matches('/').to_string())
}

fn http() -> HttpClient {
    let settings = HttpSettings { proxy: ProxyMode::None, ..Default::default() };
    HttpClient::new(Arc::new(UreqHttpClient::new(settings)))
}

fn storage(b: &str) -> String {
    format!("{b}/afirma-signature-storage/StorageService")
}

fn retriever(b: &str) -> String {
    format!("{b}/afirma-signature-retriever/RetrieveService")
}

fn signature_service(b: &str) -> String {
    format!("{b}/afirma-server-triphase-signer/SignatureService")
}

fn launcher(handler: Arc<FakeHandler>) -> ProtocolLauncher {
    let mut cfg = LauncherConfig::new(http());
    cfg.active_waiting_interval = Duration::from_millis(500);
    ProtocolLauncher::new(handler, Arc::new(FakeSigner::default()), cfg)
}

fn enc(s: &str) -> String {
    afirma_protocol::query::encode_storage_payload(s).replace(':', "%3A").replace('/', "%2F").replace('=', "%3D")
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("afirma-protocol-it");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn storage_and_retriever_roundtrip() {
    let Some(b) = base() else { return };
    let h = http();
    // Resultados, errores con caracteres especiales y la espera activa.
    for (id, payload) in [
        ("rt1", "MIIBxx-_==|5.KNugLrX23UdgQtrr-lloeg=="),
        ("rt2", "err-00:=AF600104 - Texto con + y % y & y acentos: ñáé"),
        ("rt3", "#WAIT"),
    ] {
        intermediate::store(&h, &storage(&b), id, payload).unwrap();
        let got = intermediate::retrieve(&h, &retriever(&b), id).unwrap();
        assert_eq!(String::from_utf8(got).unwrap().trim_end_matches(['\r', '\n']), payload);
        // Lectura única: la segunda vez el servidor devuelve ERR-06.
        let again = intermediate::retrieve(&h, &retriever(&b), id).unwrap();
        assert!(intermediate::is_error_response(&again));
        assert!(String::from_utf8_lossy(&again).starts_with("ERR-06:="));
    }
    // Identificador no válido para el servidor.
    let r = intermediate::retrieve(&h, &retriever(&b), "a.b").unwrap();
    assert!(String::from_utf8_lossy(&r).starts_with("ERR-06:="));
}

#[test]
fn direct_invocation_with_real_intermediate_servers() {
    let Some(b) = base() else { return };
    let k = key("firmante-rsa");
    let l = launcher(FakeHandler::with_key(k.clone()));
    // Invocación directa de AutoScript (servidor intermedio) con espera activa.
    let url = format!(
        "afirma://selectcert?jvc=4&op=selectcert&ver=4&id=RIDSEL1&key=04719233&stservlet={}&aw=true",
        enc(&storage(&b))
    );
    let LaunchOutcome::Finished(sent) = l.launch(&url) else { panic!() };
    // La página sondea el RetrieveService.
    let got = intermediate::poll_like_autoscript(&http(), &retriever(&b), "RIDSEL1", Duration::from_millis(200), 20).unwrap();
    let PollOutcome::Data(text) = got else { panic!("sin resultado") };
    assert_eq!(text.trim_end(), sent);
    let des = ServerCipher::from_config(&des_config("04719233")).unwrap().unwrap();
    assert_eq!(des.decipher(&text).unwrap(), k.certificate());

    // Petición en el servidor intermedio (fileid): AutoScript sube el sobre
    // XML cifrado con DES y lanza la URL corta.
    let envelope = format!(
        r#"<sign><e k="format" v="CAdES"/><e k="algorithm" v="SHA256withRSA"/><e k="properties" v="bW9kZT1pbXBsaWNpdA=="/><e k="dat" v="SG9sYQ=="/><e k="ver" v="4"/><e k="op" v="sign"/><e k="id" v="RIDSIGN1"/><e k="appname" v="www.example.org"/><e k="key" v="11223344"/><e k="stservlet" v="{}"/></sign>"#,
        storage(&b)
    );
    let des2 = ServerCipher::from_config(&des_config("11223344")).unwrap().unwrap();
    intermediate::store(&http(), &storage(&b), "FIDSIGN1", &des2.cipher(envelope.as_bytes()).unwrap()).unwrap();
    let url = format!(
        "afirma://sign?jvc=4&fileid=FIDSIGN1&rid=RIDSIGN1&rtservlet={}&stservlet={}&key=11223344",
        enc(&retriever(&b)),
        enc(&storage(&b))
    );
    l.launch(&url);
    let PollOutcome::Data(text) = intermediate::poll_like_autoscript(&http(), &retriever(&b), "RIDSIGN1", Duration::from_millis(200), 20).unwrap()
    else {
        panic!()
    };
    let fields: Vec<&str> = text.trim_end().split('|').collect();
    assert_eq!(fields.len(), 2, "{text}");
    assert_eq!(des2.decipher(fields[0]).unwrap(), k.certificate());
    let sig = des2.decipher(fields[1]).unwrap();
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    assert_eq!(afirma_protocol::pkcs1::verify(k.certificate(), alg, b"Hola", &sig), afirma_protocol::pkcs1::Verification::Valid);

    // Error de parámetros subido (mejora): la página lo recibe en vez de agotar la espera.
    let url = format!("afirma://sign?jvc=4&op=sign&ver=4&id=RIDERR1&algorithm=SHA256&dat=SG9sYQ%3D%3D&stservlet={}", enc(&storage(&b)));
    l.launch(&url);
    let PollOutcome::Data(text) = intermediate::poll_like_autoscript(&http(), &retriever(&b), "RIDERR1", Duration::from_millis(200), 20).unwrap() else {
        panic!()
    };
    assert_eq!(text.trim_end(), "err-00:=AF600104 - No se ha recibido el formato de firma para la operacion de firma");
}

fn sign_tri(format: &str, op: &str, data: &[u8], extra: &str, key_name: &str) -> (String, Arc<dyn afirma_core::SigningKey>, Arc<FakeHandler>) {
    let b = base().unwrap();
    let k = key(key_name);
    let h = FakeHandler::with_key(k.clone());
    let l = launcher(h.clone());
    let props = jbase64::encode(format!("serverUrl={}\n{extra}", signature_service(&b)).as_bytes());
    let msg = format!(
        "afirma://sign?op={op}&format={format}&algorithm=SHA256withRSA&properties={props}&dat={}",
        jbase64::encode_url_safe(data)
    );
    (l.process_socket_message(&msg, V41), k, h)
}

fn signature_of(result: &str) -> Vec<u8> {
    let parts: Vec<&str> = result.split('|').collect();
    assert!(parts.len() >= 2, "{result}");
    jbase64::decode_url_safe(parts[1]).unwrap()
}

#[test]
fn triphase_cades_against_real_server() {
    if base().is_none() {
        return;
    }
    let (r, _, _) = sign_tri("CAdEStri", "sign", b"Datos de prueba trifasica", "mode=implicit", "firmante-rsa");
    let sig = signature_of(&r);
    let f = scratch("tri-cades.p7s");
    std::fs::write(&f, &sig).unwrap();
    let out = Command::new("openssl")
        .args(["cms", "-verify", "-inform", "DER", "-in"])
        .arg(&f)
        .arg("-CAfile")
        .arg(testdata("pki/ca.crt"))
        .args(["-purpose", "any"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"Datos de prueba trifasica");
    // Cofirma trifásica de la firma anterior (dos firmantes).
    let (r2, _, _) = sign_tri("CAdEStri", "cosign", &sig, "", "firmante-ec");
    let co = signature_of(&r2);
    std::fs::write(&f, &co).unwrap();
    let out = Command::new("openssl").args(["cms", "-cmsout", "-print", "-inform", "DER", "-in"]).arg(&f).output().unwrap();
    let printed = String::from_utf8_lossy(&out.stdout);
    let signers = printed.lines().filter(|l| l.contains("d.issuerAndSerialNumber") || l.contains("d.subjectKeyIdentifier")).count();
    assert_eq!(signers, 2, "{printed}");
    let out = Command::new("openssl")
        .args(["cms", "-verify", "-inform", "DER", "-in"])
        .arg(&f)
        .arg("-CAfile")
        .arg(testdata("pki/ca.crt"))
        .args(["-purpose", "any"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn triphase_xades_against_real_server() {
    if base().is_none() {
        return;
    }
    let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc><a>Hola</a></doc>";
    let (r, _, _) = sign_tri("XAdEStri", "sign", xml, "format=XAdES Enveloped", "firmante-rsa");
    let sig = signature_of(&r);
    let text = String::from_utf8(sig.clone()).unwrap();
    assert!(text.contains("SignatureValue") && text.contains("<a>Hola</a>"), "{text}");
    let f = scratch("tri-xades.xml");
    std::fs::write(&f, &sig).unwrap();
    let verifier = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/protocol-it/verify_xml.sh");
    if let Ok(out) = Command::new(&verifier).arg(&f).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && stdout.contains("valid=true"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
    }
    // FacturaE y XAdES con clave EC (PK1_DECODED en el servidor).
    let (r, _, _) = sign_tri("XAdEStri", "sign", xml, "format=XAdES Enveloping", "firmante-ec");
    let sig = signature_of(&r);
    std::fs::write(&f, &sig).unwrap();
    if let Ok(out) = Command::new(&verifier).arg(&f).output() {
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    }
}

#[test]
fn triphase_pades_against_real_server() {
    if base().is_none() {
        return;
    }
    let pdf = std::fs::read(testdata("protocol/plain.pdf")).unwrap();
    let (r, _, _) = sign_tri("PAdEStri", "sign", &pdf, "", "firmante-rsa");
    let signed = signature_of(&r);
    assert!(signed.starts_with(b"%PDF") && signed.len() > pdf.len());
    let f = scratch("tri-pades.pdf");
    std::fs::write(&f, &signed).unwrap();
    let out = Command::new("pdfsig").arg(&f).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Signature is Valid"), "{stdout}");
    // PDF certificado: ERR-21 signingCertifiedPdf → confirmación → reintento.
    let pdf = std::fs::read(testdata("protocol/certified.pdf")).unwrap();
    let b = base().unwrap();
    let h = FakeHandler::with_key(key("firmante-rsa"));
    *h.confirm_answer.lock().unwrap() = true;
    let l = launcher(h.clone());
    let props = jbase64::encode(format!("serverUrl={}", signature_service(&b)).as_bytes());
    let msg = format!("afirma://sign?op=sign&format=PAdEStri&algorithm=SHA256&properties={props}&dat={}", jbase64::encode_url_safe(&pdf));
    let r = l.process_socket_message(&msg, V41);
    let confirms = h.confirms.lock().unwrap().clone();
    assert_eq!(confirms.first().map(|c| c.requestor_text.as_str()), Some("signingCertifiedPdf"), "{r}");
    assert!(signature_of(&r).starts_with(b"%PDF"));
    // Rechazo de la confirmación → cancelación; headless → error 212007.
    *h.confirm_answer.lock().unwrap() = false;
    assert!(l.process_socket_message(&msg, V41).starts_with("err-11:="));
    let props = jbase64::encode(format!("serverUrl={}\nheadless=true", signature_service(&b)).as_bytes());
    let msg = format!("afirma://sign?op=sign&format=PAdEStri&algorithm=SHA256&properties={props}&dat={}", jbase64::encode_url_safe(&pdf));
    assert!(l.process_socket_message(&msg, V41).starts_with("err-00:=AF212007"));
}

#[test]
fn triphase_none_and_errors_against_real_server() {
    let Some(b) = base() else { return };
    let (r, k, _) = sign_tri("NONEtri", "sign", b"datos pkcs1", "", "firmante-rsa");
    let sig = signature_of(&r);
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
    assert_eq!(afirma_protocol::pkcs1::verify(k.certificate(), alg, b"datos pkcs1", &sig), afirma_protocol::pkcs1::Verification::Valid);
    // Cofirma CAdES de algo que no es una firma → ERR-9 del servidor (300417).
    let (r, _, _) = sign_tri("CAdEStri", "cosign", b"no es una firma", "", "firmante-rsa");
    assert!(r.starts_with("err-00:=AF3004"), "{r}");
    // Servicio inexistente → error HTTP 404 (401301).
    let h = FakeHandler::with_key(key("firmante-rsa"));
    let l = launcher(h);
    let props = jbase64::encode(format!("serverUrl={b}/afirma-server-triphase-signer/NoExiste").as_bytes());
    let r = l.process_socket_message(&format!("afirma://sign?op=sign&format=CAdEStri&algorithm=SHA256&properties={props}&dat=SG9sYQ=="), V41);
    assert!(r.starts_with("err-00:=AF401301"), "{r}");
}

#[test]
fn json_batch_against_real_server() {
    let Some(b) = base() else { return };
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let l = launcher(h);
    let xml = jbase64::encode(b"<doc>XML</doc>");
    let props = jbase64::encode(b"mode=implicit");
    let batch = format!(
        r#"{{"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","extraparams":"{props}","stoponerror":false,"singlesigns":[{{"id":"doc1","datareference":"{}"}},{{"id":"doc2","datareference":"{xml}","format":"XAdES"}}]}}"#,
        jbase64::encode(b"Documento 1")
    );
    let url = format!(
        "afirma://batch?op=batch&batchpresignerurl={}&batchpostsignerurl={}&needcert=true&jsonbatch=true&dat={}",
        enc(&format!("{b}/afirma-server-triphase-signer/presign")),
        enc(&format!("{b}/afirma-server-triphase-signer/postsign")),
        jbase64::encode_url_safe(batch.as_bytes())
    );
    let r = l.process_socket_message(&url, V41);
    let (res, cert) = r.split_once('|').expect(&r);
    let json = String::from_utf8(jbase64::decode(res).unwrap()).unwrap();
    if std::env::var("AFIRMA_IT_HMAC").ok().as_deref() == Some("1") {
        // Fallo del servidor Java (también con el cliente Java): con
        // `verification.key` comprueba el PK1 de las firmas del lote contra
        // los datos del documento en lugar de contra la prefirma.
        assert_eq!(json.matches("ERROR_POST").count(), 2, "{json}");
        assert!(json.contains("Error en la verificacion de los PKCS#1 de las firmas recibidas"));
        return;
    }
    assert_eq!(json.matches("DONE_AND_SAVED").count(), 2, "{json}");
    assert_eq!(jbase64::decode(cert).unwrap(), k.certificate());
    // stoponerror: un PAdES sobre datos que no son PDF falla en la prefirma.
    let batch = format!(
        r#"{{"algorithm":"SHA256withRSA","format":"CAdES","stoponerror":true,"singlesigns":[{{"id":"ok1","datareference":"{}"}},{{"id":"mal","datareference":"{}","format":"PAdES"}},{{"id":"ok2","datareference":"{}"}}]}}"#,
        jbase64::encode(b"uno"),
        jbase64::encode(b"no es un pdf"),
        jbase64::encode(b"dos")
    );
    let url = format!(
        "afirma://batch?op=batch&batchpresignerurl={}&batchpostsignerurl={}&jsonbatch=true&dat={}",
        enc(&format!("{b}/afirma-server-triphase-signer/presign")),
        enc(&format!("{b}/afirma-server-triphase-signer/postsign")),
        jbase64::encode_url_safe(batch.as_bytes())
    );
    let r = l.process_socket_message(&url, V41);
    let json = String::from_utf8(jbase64::decode(&r).unwrap()).unwrap();
    assert!(json.contains("ERROR_PRE") && json.contains("SKIPPED"), "{json}");
    // Lote mal formado para el servidor (sin formato) → HTTP 400 → 600417.
    let batch = r#"{"algorithm":"SHA256withRSA","singlesigns":[{"id":"x","datareference":"AA=="}]}"#;
    let url = format!(
        "afirma://batch?op=batch&batchpresignerurl={}&batchpostsignerurl={}&jsonbatch=true&dat={}",
        enc(&format!("{b}/afirma-server-triphase-signer/presign")),
        enc(&format!("{b}/afirma-server-triphase-signer/postsign")),
        jbase64::encode_url_safe(batch.as_bytes())
    );
    let r = l.process_socket_message(&url, V41);
    assert!(r.starts_with("err-00:=AF600417") || r.starts_with("err-00:=AF300601"), "{r}");
}
