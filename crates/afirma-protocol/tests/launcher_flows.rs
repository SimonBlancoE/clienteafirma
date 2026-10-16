//! Pruebas de los flujos completos de las operaciones (como las haría
//! AutoScript) con un manejador, un firmador y servidores simulados.

mod common;

use std::sync::Arc;

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::error::codes;
use afirma_protocol::cipher::{ServerCipher, des_config};
use afirma_protocol::jbase64;
use afirma_protocol::triphase::TriphaseData;
use afirma_protocol::{FileData, HttpClient, LaunchOutcome, LauncherConfig, ProtocolLauncher, ProtocolVersion, RequestOrigin};
use common::*;

const V41: ProtocolVersion = ProtocolVersion::V4_1;

fn launcher(handler: Arc<FakeHandler>, signer: Arc<FakeSigner>, http: Arc<MockHttp>) -> ProtocolLauncher {
    let mut cfg = LauncherConfig::new(HttpClient::new(http));
    cfg.active_waiting_interval = std::time::Duration::from_millis(30);
    ProtocolLauncher::new(handler, signer, cfg)
}

fn no_http() -> Arc<MockHttp> {
    MockHttp::new(|_| Ok((404, b"no".to_vec())))
}

fn split3(r: &str) -> Vec<Vec<u8>> {
    r.split('|').map(|p| jbase64::decode_url_safe(p).unwrap()).collect()
}

#[test]
fn websocket_style_sign_message() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let s = Arc::new(FakeSigner::default());
    let l = launcher(h.clone(), s.clone(), no_http());
    // Mensaje copiado de la especificación (§5.1.3).
    let msg = "afirma://sign?op=sign&idsession=Q3k9aZ0bT1cL2mN4pX7r&algorithm=SHA512withRSA&format=CAdES&properties=bW9kZT1pbXBsaWNpdA==&ksb64=TU9aX1VOSQ==&sticky=false&dat=SG9sYQ==";
    let r = l.process_socket_message_from(msg, V41, RequestOrigin::WebSocket { origin: Some("https://sede.gob.es".into()) });
    let parts = split3(&r);
    assert_eq!(parts.len(), 2, "{r}");
    assert_eq!(parts[0], k.certificate());
    let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha512, KeyAlgorithm::Rsa);
    assert_eq!(afirma_protocol::pkcs1::verify(k.certificate(), alg, b"Hola", &parts[1]), afirma_protocol::pkcs1::Verification::Valid);
    let calls = s.calls.lock().unwrap();
    assert_eq!(calls[0].1, "CAdES");
    assert_eq!(calls[0].2, "SHA512withRSA");
    assert_eq!(calls[0].3.get("mode"), Some("implicit"));
    let reqs = h.cert_requests.lock().unwrap();
    let info = &reqs[0].1;
    assert_eq!(info.origin.display(), Some("https://sede.gob.es"));
    assert_eq!(info.format.as_deref(), Some("CAdES"));
    assert_eq!(info.data_len, Some(4));
    assert_eq!(info.data.as_deref(), Some(&b"Hola"[..]));
}

#[test]
fn sign_without_data_uses_file_dialog_and_returns_filename() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    *h.file_to_sign.lock().unwrap() = Some(FileData { name: "contrato 1.pdf".into(), data: b"%PDF-1.4 x".to_vec() });
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), no_http());
    let r = l.process_socket_message("afirma://sign?op=sign&format=AUTO&algorithm=SHA256&idsession=x", V41);
    let parts = split3(&r);
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2], b"{\"filename\": \"contrato 1.pdf\"}");
    let info = h.cert_requests.lock().unwrap()[0].1.clone();
    assert_eq!(info.format.as_deref(), Some("PAdES"));
    assert_eq!(info.file_name.as_deref(), Some("contrato 1.pdf"));
    // Versión 2: sin el campo extra.
    let r = l.process_socket_message("afirma://sign?op=sign&format=AUTO&algorithm=SHA256", ProtocolVersion::V2);
    assert_eq!(r.split('|').count(), 2);
    // Cancelación del diálogo.
    *h.file_to_sign.lock().unwrap() = None;
    assert_eq!(l.process_socket_message("afirma://sign?op=sign&format=CAdES&algorithm=SHA256", V41), "err-11:=AF500001 - Operacion cancelada por el usuario");
    assert_eq!(l.process_socket_message("afirma://sign?op=sign&format=CAdES&algorithm=SHA256", ProtocolVersion::V3), "CANCEL");
}

#[test]
fn error_formats_and_codes() {
    let h = FakeHandler::with_key(key("firmante-rsa"));
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), no_http());
    let r = l.process_socket_message("afirma://sign?op=sign&format=Raro&algorithm=SHA256&dat=SG9sYQ==", V41);
    assert_eq!(r, "err-00:=AF600105 - El formato de firma indicado en la operacion de firma no esta soportado");
    let r = l.process_socket_message("afirma://sign?op=sign&format=Raro&algorithm=SHA256&dat=SG9sYQ==", ProtocolVersion::V3);
    assert_eq!(r, "SAF_06: Formato de firma no soportado");
    // Error de parámetros: diálogo y respuesta.
    let r = l.process_socket_message("afirma://sign?op=sign&algorithm=SHA256&dat=SG9sYQ==", V41);
    assert_eq!(r, "err-00:=AF600104 - No se ha recibido el formato de firma para la operacion de firma");
    assert_eq!(h.error_codes(), vec![600104]);
    // Operación y esquema desconocidos.
    assert_eq!(l.process_socket_message("afirma://getversion?x=1", V41), "err-00:=AF600002 - La operacion no esta soportada");
    assert_eq!(l.process_socket_message("getresult?idsession=x", V41), "err-00:=AF600002 - La operacion no esta soportada");
    assert_eq!(l.process_socket_message("http://x", ProtocolVersion::V3), "SAF_02: Protocolo no soportado");
    // Versión no soportada por las operaciones.
    let r = l.process_socket_message("afirma://selectcert?op=selectcert", ProtocolVersion::V0);
    assert!(r.starts_with("SAF_21: La versión de Autofirma instalada no es compatible"), "{r}");
    // Versión mínima.
    assert_eq!(l.process_socket_message("afirma://selectcert?mcv=1.11", V41), "err-00:=AF500005 - La web solicito una version posterior de Autofirma");
    assert!(l.process_socket_message("afirma://selectcert?mcv=1.9", V41).starts_with("MII"));
    assert!(l.process_socket_message("afirma://selectcert?mcv=uno.dos", V41).starts_with("err-00:=AF200201"));
    // Sin certificados.
    *h.default_key.lock().unwrap() = None;
    assert!(l.process_socket_message("afirma://selectcert?op=selectcert", V41).starts_with("err-00:=AF502001"));
    assert!(l.process_socket_message("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==", V41).starts_with("err-00:=AF501001"));
    // Operación criptográfica ausente.
    *h.default_key.lock().unwrap() = Some(key("firmante-rsa"));
    assert!(l.process_socket_message("afirma://sign?format=CAdES&algorithm=SHA256&dat=SG9sYQ==", V41).starts_with("err-00:=AF200115"));
}

#[test]
fn sticky_signatory_semantics() {
    let h = FakeHandler::with_key(key("firmante-rsa"));
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), no_http());
    let sc = |extra: &str| l.process_socket_message(&format!("afirma://selectcert?op=selectcert{extra}"), V41);
    assert!(sc("&sticky=true").starts_with("MII"));
    assert_eq!(h.cert_dialogs(), 1);
    assert!(sc("&sticky=true").starts_with("MII"));
    assert_eq!(h.cert_dialogs(), 1, "se reutiliza el firmante persistente");
    sc("&sticky=true&resetsticky=true");
    assert_eq!(h.cert_dialogs(), 2);
    // La firma sin sticky limpia la ranura.
    l.process_socket_message("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==&sticky=true", V41);
    assert_eq!(h.cert_dialogs(), 2, "sticky reutilizado en la firma");
    l.process_socket_message("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==", V41);
    assert_eq!(h.cert_dialogs(), 3);
    assert!(l.sticky_key().is_none());
    sc("&sticky=true");
    assert_eq!(h.cert_dialogs(), 4);
}

#[test]
fn wrong_pin_retries_with_same_certificate() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let s = Arc::new(FakeSigner::default());
    s.script.lock().unwrap().push_back(Scripted::WrongPin);
    let l = launcher(h.clone(), s, no_http());
    let r = l.process_socket_message("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==", V41);
    assert_eq!(split3(&r).len(), 2, "{r}");
    let reqs = h.cert_requests.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[1].0.as_deref(), Some(k.certificate()));
}

#[test]
fn user_interventions() {
    let h = FakeHandler::with_key(key("firmante-rsa"));
    let s = Arc::new(FakeSigner::default());
    let l = launcher(h.clone(), s.clone(), no_http());
    let url = "afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==";
    // Sí → reintento con el parámetro.
    *h.confirm_answer.lock().unwrap() = true;
    s.script.lock().unwrap().push_back(Scripted::NeedsConfirm);
    assert_eq!(split3(&l.process_socket_message(url, V41)).len(), 2);
    assert_eq!(h.confirms.lock().unwrap()[0].requestor_text, "signingLts");
    assert!(s.calls.lock().unwrap().last().unwrap().3.get_bool("allowSignLTSignature", false));
    // No → cancelación.
    *h.confirm_answer.lock().unwrap() = false;
    s.script.lock().unwrap().push_back(Scripted::NeedsConfirm);
    assert!(l.process_socket_message(url, V41).starts_with("err-11:="));
    // headless → error del firmador sin preguntar.
    s.script.lock().unwrap().push_back(Scripted::NeedsConfirm);
    let n = h.confirms.lock().unwrap().len();
    let r = l.process_socket_message(&format!("{url}&properties={}", jbase64::encode(b"headless=true")), V41);
    assert!(r.starts_with("err-00:=AF501007"), "{r}");
    assert_eq!(h.confirms.lock().unwrap().len(), n);
    // Almacén bloqueado → limpia el firmante persistente.
    l.process_socket_message("afirma://selectcert?sticky=true", V41);
    assert!(l.sticky_key().is_some());
    s.script.lock().unwrap().push_back(Scripted::Fail(codes::SMARTCARD_LOCKED));
    assert!(l.process_socket_message(&format!("{url}&sticky=true"), V41).starts_with("err-00:=AF511004"));
    assert!(l.sticky_key().is_none());
}

/// Servidor trifásico simulado: devuelve una prefirma con `PRE` y comprueba
/// el `PK1` en la postfirma.
fn tri_server(s: &Seen) -> Result<(u16, Vec<u8>), afirma_core::http::HttpClientError> {
    match form_value(&s.body, "op") {
        Some("pre") => {
            let xml = format!(
                "<xml>\n <firmas>\n  <firma Id=\"S1\">\n   <param n=\"PRE\">{}</param>\n   <param n=\"NEED_PRE\">true</param>\n   <param n=\"TIME\">1</param>\n  </firma>\n </firmas>\n</xml>",
                jbase64::encode(b"atributos firmados")
            );
            Ok((200, jbase64::encode_url_safe(xml.as_bytes()).into_bytes()))
        }
        Some("post") => {
            let session = jbase64::decode_url_safe(form_value(&s.body, "session").unwrap()).unwrap();
            let td = TriphaseData::parse_xml(&session).unwrap();
            let cert = jbase64::decode_url_safe(form_value(&s.body, "cert").unwrap().split(',').next().unwrap()).unwrap();
            let algo = form_value(&s.body, "algo").unwrap();
            let alg = SignatureAlgorithm::parse(algo, KeyAlgorithm::Rsa).unwrap();
            let pre = jbase64::decode(td.signs[0].get("PRE").unwrap()).unwrap();
            let pk1 = jbase64::decode(td.signs[0].get("PK1").unwrap()).unwrap();
            assert_eq!(td.signs[0].get("TIME"), Some("1"));
            if afirma_protocol::pkcs1::verify(&cert, alg, &pre, &pk1) != afirma_protocol::pkcs1::Verification::Valid {
                return Ok((200, b"ERR-18: Error de integridad en la firma".to_vec()));
            }
            Ok((200, format!("OK NEWID={}\r\n", jbase64::encode_url_safe(b"FIRMA-TRIFASICA")).into_bytes()))
        }
        _ => Ok((200, b"ERR-11: Operacion desconocida".to_vec())),
    }
}

#[test]
fn triphase_cades_bodies_and_result() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let http = MockHttp::new(tri_server);
    let l = launcher(h, Arc::new(FakeSigner::default()), http.clone());
    let props = jbase64::encode(b"serverUrl=https://tri.example/afirma-server-triphase-signer/SignatureService\nmode=implicit\n");
    let r = l.process_socket_message(&format!("afirma://sign?op=sign&format=CAdEStri&algorithm=SHA256withRSA&properties={props}&dat=SG9sYQ=="), V41);
    let parts = split3(&r);
    assert_eq!(parts[1], b"FIRMA-TRIFASICA", "{r}");
    let bodies = http.bodies_to("SignatureService");
    let chain = k.certificate_chain().iter().map(|c| jbase64::encode_url_safe(c)).collect::<Vec<_>>().join(",");
    assert!(bodies[0].starts_with(&format!("op=pre&cop=sign&format=CAdES&algo=SHA256withRSA&cert={chain}&doc=SG9sYQ==&params=")), "{}", bodies[0]);
    let params = jbase64::decode_url_safe(form_value(&bodies[0], "params").unwrap()).unwrap();
    let params = String::from_utf8(params).unwrap();
    assert!(params.contains("mode=implicit") && !params.contains("serverUrl"), "{params}");
    assert!(bodies[1].starts_with(&format!("op=post&cop=sign&format=CAdES&algo=SHA256withRSA&cert={chain}&params=")));
    assert!(bodies[1].contains("&session=") && bodies[1].ends_with("&doc=SG9sYQ=="), "{}", bodies[1]);
}

#[test]
fn triphase_other_formats() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let http = MockHttp::new(tri_server);
    let l = launcher(h, Arc::new(FakeSigner::default()), http.clone());
    let props = jbase64::encode(b"serverUrl=https://tri.example/SignatureService\nincludeOnlySignningCertificate=true");
    let leaf = jbase64::encode_url_safe(k.certificate());
    for (format, op, server_format) in [("PAdEStri", "sign", "pades"), ("XAdEStri", "cosign", "XAdES"), ("NONEtri", "sign", "NONE"), ("CAdES-ASiC-S-tri", "sign", "CAdES-ASiC-S")] {
        http.seen.lock().unwrap().clear();
        let r = l.process_socket_message(&format!("afirma://sign?op={op}&format={format}&algorithm=SHA256&properties={props}&dat=SG9sYQ=="), V41);
        assert_eq!(split3(&r)[1], b"FIRMA-TRIFASICA", "{format}: {r}");
        let b = http.bodies_to("SignatureService");
        assert!(b[0].starts_with(&format!("op=pre&cop={op}&format={server_format}&algo=SHA256withRSA&cert={leaf}")), "{format}: {}", b[0]);
        match format {
            "PAdEStri" => {
                let p = String::from_utf8(jbase64::decode_url_safe(form_value(&b[0], "params").unwrap()).unwrap()).unwrap();
                assert!(p.contains("serverUrl"), "PAdES envía serverUrl en params");
                assert!(b[1].starts_with(&format!("op=post&cop=sign&format=pades&algo=SHA256withRSA&cert={leaf}&doc=SG9sYQ==&session=")));
            }
            "XAdEStri" => {
                assert!(b[1].starts_with(&format!("op=post&cop=cosign&format=XAdES&algo=SHA256withRSA&cert={leaf}&session=")));
                assert!(b[1].contains("&doc=SG9sYQ==&params="));
            }
            "NONEtri" => {
                assert_eq!(b[0], format!("op=pre&cop=sign&format=NONE&algo=SHA256withRSA&cert={leaf}&doc=SG9sYQ=="));
                assert!(!b[1].contains("params="));
            }
            _ => {}
        }
    }
    // Operación no soportada por el formato → 600002.
    let r = l.process_socket_message(&format!("afirma://sign?op=countersign&format=PAdEStri&algorithm=SHA256&properties={props}&dat=SG9sYQ=="), V41);
    assert!(r.starts_with("err-00:=AF600002"), "{r}");
    // Sin serverUrl → 600121.
    let r = l.process_socket_message("afirma://sign?op=sign&format=XAdEStri&algorithm=SHA256&dat=SG9sYQ==", V41);
    assert!(r.starts_with("err-00:=AF600121"), "{r}");
}

#[test]
fn triphase_server_errors() {
    let props = jbase64::encode(b"serverUrl=https://tri.example/SignatureService");
    let url = format!("afirma://sign?op=sign&format=CAdEStri&algorithm=SHA256&properties={props}&dat=SG9sYQ==");
    type Responder = fn(&Seen) -> Result<(u16, Vec<u8>), afirma_core::http::HttpClientError>;
    let run = |resp: Responder| {
        let l = launcher(FakeHandler::with_key(key("firmante-rsa")), Arc::new(FakeSigner::default()), MockHttp::new(resp));
        l.process_socket_message(&url, V41)
    };
    assert!(run(|_| Ok((200, b"ERR-9: Error realizando la prefirma: java.lang.IllegalArgumentException: x".to_vec()))).starts_with("err-00:=AF300417"));
    assert!(run(|_| Ok((400, vec![]))).starts_with("err-00:=AF600701"));
    assert!(run(|_| Ok((404, vec![]))).starts_with("err-00:=AF401301"));
    assert!(run(|_| Ok((503, vec![]))).starts_with("err-00:=AF300400"));
    assert!(run(|_| Err(afirma_core::http::HttpClientError::Timeout { url: "u".into(), message: "t".into() })).starts_with("err-00:=AF401302"));
    assert!(run(|_| Ok((200, b"corto".to_vec()))).starts_with("err-00:=AF300401"));
    assert!(run(|s| if form_value(&s.body, "op") == Some("pre") { tri_server(s) } else { Ok((200, b"ERR-12: Error realizando la postfirma".to_vec())) })
        .starts_with("err-00:=AF300441"));
    assert!(run(|s| if form_value(&s.body, "op") == Some("pre") { tri_server(s) } else { Ok((200, b"KO resultado raro".to_vec())) })
        .starts_with("err-00:=AF300405"));
}

#[test]
fn triphase_err21_confirmation_retries_whole_operation() {
    let h = FakeHandler::with_key(key("firmante-rsa"));
    *h.confirm_answer.lock().unwrap() = true;
    let http = MockHttp::new(|s| {
        let params = form_value(&s.body, "params").and_then(|p| jbase64::decode_url_safe(p).ok()).map(|p| String::from_utf8_lossy(&p).into_owned());
        if form_value(&s.body, "op") == Some("pre") && !params.unwrap_or_default().contains("allowSignLTSignature=true") {
            return Ok((200, b"ERR-21:signingLts: Se requiere intervencion del usuario: es.gob.afirma.core.SigningLTSException: LTS".to_vec()));
        }
        tri_server(s)
    });
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), http.clone());
    let props = jbase64::encode(b"serverUrl=https://tri.example/SignatureService");
    let r = l.process_socket_message(&format!("afirma://sign?op=sign&format=CAdEStri&algorithm=SHA256&properties={props}&dat=SG9sYQ=="), V41);
    assert_eq!(split3(&r)[1], b"FIRMA-TRIFASICA", "{r}");
    assert_eq!(h.confirms.lock().unwrap()[0].requestor_text, "signingLts");
    assert_eq!(http.bodies_to("SignatureService").len(), 3);
}

#[test]
fn json_batch_against_server() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let http = MockHttp::new(|s| {
        if s.url.ends_with("/presign") {
            let td = format!(
                r#"{{"td":{{"format":"XAdES","signs":[{{"signinfo":[{{"id":"a1","params":{{"PRE":"{}","NEED_PRE":"true"}}}}]}}]}},"results":[{{"id":"a2","result":"ERROR_PRE","description":"mal"}}]}}"#,
                jbase64::encode(b"pre-a1")
            );
            Ok((200, td.into_bytes()))
        } else {
            Ok((200, br#"{"signs":[{"id":"a1", "result":"DONE_AND_SAVED"},{"id":"a2", "result":"ERROR_PRE", "description":"mal"}]}"#.to_vec()))
        }
    });
    let l = launcher(h, Arc::new(FakeSigner::default()), http.clone());
    let batch = br#"{"algorithm":"SHA256withRSA","format":"XAdES","suboperation":"sign","stoponerror":false,"singlesigns":[{"id":"a1","datareference":"SG9sYQ=="},{"id":"a2","datareference":"SG9sYQ=="}]}"#;
    let url = format!(
        "afirma://batch?op=batch&batchpresignerurl=https%3A%2F%2Fb.example%2Fpresign&batchpostsignerurl=https%3A%2F%2Fb.example%2Fpostsign&needcert=true&jsonbatch=true&dat={}",
        jbase64::encode_url_safe(batch)
    );
    let r = l.process_socket_message(&url, V41);
    let (res, cert) = r.split_once('|').unwrap();
    assert!(String::from_utf8(jbase64::decode(res).unwrap()).unwrap().contains("DONE_AND_SAVED"));
    assert_eq!(jbase64::decode(cert).unwrap(), k.certificate());
    let pre = &http.bodies_to("/presign")[0];
    let certs = k.certificate_chain().iter().map(|c| jbase64::encode_url_safe(c)).collect::<Vec<_>>().join(";");
    assert_eq!(pre, &format!("json={}&certs={certs}", jbase64::encode_url_safe(batch)));
    let post = &http.bodies_to("/postsign")[0];
    // El lote se reescribe con el resultado parcial de a2.
    let json = String::from_utf8(jbase64::decode_url_safe(form_value(post, "json").unwrap()).unwrap()).unwrap();
    assert!(json.contains(r#""result":"ERROR_PRE""#) && json.contains(r#""description":"mal""#), "{json}");
    let tridata = String::from_utf8(jbase64::decode_url_safe(form_value(post, "tridata").unwrap()).unwrap()).unwrap();
    assert!(tridata.contains("\"PK1\"") && tridata.contains("\"PRE\""), "{tridata}");
    assert_eq!(form_value(post, "certs"), Some(certs.as_str()));
}

#[test]
fn local_batch() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let s = Arc::new(FakeSigner::default());
    let l = launcher(h, s.clone(), no_http());
    let batch = br#"{"algorithm":"SHA256","format":"CAdES","singlesigns":[{"id":"d1","datareference":"SG9sYQ=="},{"id":"d2","datareference":"QWRpb3M=","format":"Raro"}]}"#;
    let url = format!("afirma://batch?op=batch&localBatchProcess=true&jsonbatch=true&needcert=true&dat={}", jbase64::encode_url_safe(batch));
    let r = l.process_socket_message(&url, V41);
    let json = String::from_utf8(jbase64::decode(r.split('|').next().unwrap()).unwrap()).unwrap();
    assert!(json.starts_with(r#"{"signs":[{"result":"DONE_AND_SAVED","signature":""#), "{json}");
    assert!(json.contains(r#"{"result":"ERROR_PRE","description":"El formato de firma indicado en la operacion de firma no esta soportado","id":"d2"}"#), "{json}");
    assert!(s.calls.lock().unwrap()[0].3.get_bool("headless", false));
    // JSON no válido → 200412; estructura incorrecta → 600419.
    let r = l.process_socket_message(&format!("afirma://batch?localBatchProcess=true&jsonbatch=true&dat={}", jbase64::encode_url_safe(b"{x")), V41);
    assert!(r.starts_with("err-00:=AF200412"), "{r}");
    let r = l.process_socket_message(&format!("afirma://batch?localBatchProcess=true&jsonbatch=true&dat={}", jbase64::encode_url_safe(b"{\"algorithm\":\"SHA256\"}")), V41);
    assert!(r.starts_with("err-00:=AF600419"), "{r}");
}

#[test]
fn save_load_signandsave() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), no_http());
    assert_eq!(l.process_socket_message("afirma://save?op=save&dat=SG9sYQ==&filename=a.txt&idsession=x", V41), "OK");
    assert_eq!(h.saved.lock().unwrap()[0], (Some("a.txt".into()), b"Hola".to_vec()));
    *h.load_result.lock().unwrap() = Some(vec![FileData { name: "a.txt".into(), data: b"A".to_vec() }, FileData { name: "b".into(), data: vec![0xfb] }]);
    assert_eq!(l.process_socket_message("afirma://load?op=load&multiload=true&key=12345678", V41), "a.txt:QQ==|b:+w==");
    *h.load_result.lock().unwrap() = None;
    assert!(l.process_socket_message("afirma://load?op=load", V41).starts_with("err-11:"));
    // signandsave: guarda con el nombre derivado y devuelve la firma.
    *h.file_to_sign.lock().unwrap() = Some(FileData { name: "informe.odt".into(), data: b"datos".to_vec() });
    let r = l.process_socket_message("afirma://signandsave?op=signandsave&cop=sign&format=CAdES&algorithm=SHA256&sticky=true", V41);
    assert_eq!(split3(&r).len(), 3, "{r}");
    let saved = h.saved.lock().unwrap();
    assert_eq!(saved[1].0.as_deref(), Some("informe.csig"));
    assert!(l.sticky_key().is_some());
}

#[test]
fn direct_invocation_uploads_ciphered_result() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let http = MockHttp::new(|_| Ok((200, b"OK".to_vec())));
    let l = launcher(h, Arc::new(FakeSigner::default()), http.clone());
    // URL de servidor intermedio de AutoScript (percent-encoded).
    let url = "afirma://sign?jvc=4&format=CAdES&algorithm=SHA256withRSA&properties=bW9kZT1pbXBsaWNpdA%3D%3D&dat=SG9sYQ%3D%3D&ver=4&op=sign&id=RID123&appname=www.example.org&key=04719233&stservlet=https%3A%2F%2Fst.example%2Fafirma-signature-storage%2FStorageService&aw=true";
    let LaunchOutcome::Finished(r) = l.launch(url) else { panic!() };
    let bodies = http.bodies_to("StorageService");
    assert!(bodies.iter().any(|b| b == "op=put&v=1_0&id=RID123&dat=#WAIT"), "{bodies:?}");
    let last = bodies.last().unwrap();
    assert_eq!(last, &format!("op=put&v=1_0&id=RID123&dat={r}"));
    let des = ServerCipher::from_config(&des_config("04719233")).unwrap().unwrap();
    let fields: Vec<&str> = r.split('|').collect();
    assert!(fields[0].starts_with(|c: char| c.is_ascii_digit()) && &fields[0][1..2] == ".");
    assert_eq!(des.decipher(fields[0]).unwrap(), k.certificate());
}

#[test]
fn direct_invocation_parameter_error_is_uploaded() {
    let h = FakeHandler::with_key(key("firmante-rsa"));
    let http = MockHttp::new(|_| Ok((200, b"OK".to_vec())));
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), http.clone());
    let url = "afirma://sign?jvc=4&algorithm=SHA256&dat=SG9sYQ%3D%3D&ver=4&op=sign&id=RID1&key=04719233&stservlet=https%3A%2F%2Fst.example%2FStorageService";
    let LaunchOutcome::Finished(r) = l.launch(url) else { panic!() };
    // La respuesta devuelta (como Java, sin versión aún) y la subida en 4.1.
    assert_eq!(r, "SAF_03: Error en los parámetros de entrada");
    assert_eq!(
        http.bodies_to("StorageService"),
        vec!["op=put&v=1_0&id=RID1&dat=err-00:=AF600104 - No se ha recibido el formato de firma para la operacion de firma".to_string()]
    );
    assert_eq!(h.error_codes(), vec![600104]);
    // stservlet local: no se sube nada.
    http.seen.lock().unwrap().clear();
    l.launch("afirma://sign?jvc=4&op=sign&id=RID1&stservlet=http%3A%2F%2Flocalhost%2FStorageService&dat=SG9sYQ%3D%3D");
    assert!(http.seen.lock().unwrap().is_empty());
}

#[test]
fn direct_invocation_with_fileid_envelope() {
    let k = key("firmante-rsa");
    let h = FakeHandler::with_key(k.clone());
    let envelope = r#"<selectcert><e k="ver" v="4"/><e k="op" v="selectcert"/><e k="id" v="RIDENV"/><e k="key" v="11112222"/><e k="stservlet" v="https://st.example/StorageService"/></selectcert>"#;
    let des = ServerCipher::from_config(&des_config("11112222")).unwrap().unwrap();
    let ciphered = format!("{}\n", des.cipher(envelope.as_bytes()).unwrap());
    let http = MockHttp::new(move |s| if s.url.contains("RetrieveService") { Ok((200, ciphered.clone().into_bytes())) } else { Ok((200, b"OK".to_vec())) });
    let l = launcher(h, Arc::new(FakeSigner::default()), http.clone());
    let url = "afirma://selectcert?jvc=4&fileid=FID99&rid=RIDENV&rtservlet=https%3A%2F%2Frt.example%2FRetrieveService&stservlet=https%3A%2F%2Fst.example%2FStorageService&key=11112222";
    let LaunchOutcome::Finished(r) = l.launch(url) else { panic!() };
    assert_eq!(http.bodies_to("RetrieveService"), vec!["op=get&v=1_0&id=FID99".to_string()]);
    let up = http.bodies_to("StorageService");
    assert_eq!(up, vec![format!("op=put&v=1_0&id=RIDENV&dat={r}")]);
    assert_eq!(des.decipher(&r).unwrap(), k.certificate());
    // Error del servidor intermedio → 220003, subido a `rid`.
    let http = MockHttp::new(|s| if s.url.contains("RetrieveService") { Ok((200, b"ERR-06:=El identificador para los datos es inv\xc3\xa1lido\n".to_vec())) } else { Ok((200, b"OK".to_vec())) });
    let l = launcher(FakeHandler::with_key(k), Arc::new(FakeSigner::default()), http.clone());
    l.launch(url);
    assert_eq!(
        http.bodies_to("StorageService"),
        vec!["op=put&v=1_0&id=RIDENV&dat=err-00:=AF220003 - El servicio cliente ya notifico un error durante la peticion".to_string()]
    );
}

#[test]
fn direct_load_is_not_available() {
    let h = FakeHandler::with_key(key("firmante-rsa"));
    let l = launcher(h.clone(), Arc::new(FakeSigner::default()), no_http());
    let LaunchOutcome::Finished(r) = l.launch("afirma://load?jvc=4&ver=4&op=load&id=abc") else { panic!() };
    assert!(r.starts_with("SAF_03"), "{r}");
    assert_eq!(h.error_codes(), vec![200600]);
}

#[test]
fn channel_urls() {
    let l = launcher(FakeHandler::with_key(key("firmante-rsa")), Arc::new(FakeSigner::default()), no_http());
    let LaunchOutcome::OpenWebSocket(req) = l.launch("afirma://websocket?ports=50001,50002&v=4&jvc=4&idsession=ABC123") else { panic!() };
    assert_eq!(req.version, V41);
    assert_eq!(req.session_id.as_deref(), Some("ABC123"));
    assert!(matches!(l.launch("afirma://service/?ports=1&v=3"), LaunchOutcome::OpenService(_)));
    let LaunchOutcome::Finished(r) = l.launch("afirma://SIGN?op=sign") else { panic!() };
    assert_eq!(r, "SAF_04: Operación no soportada. Compruebe que dispone de la última versión de Autofirma.");
}
