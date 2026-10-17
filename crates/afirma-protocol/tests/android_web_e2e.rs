//! Pruebas de extremo a extremo de la firma web Android
//! (`afirma_protocol::android`) contra un servidor intermedio simulado real
//! (HTTP sobre TCP local con la semántica de StorageService/RetrieveService,
//! `01-protocol.md` §6) y un servicio de lotes simulado, con el cliente HTTP
//! común (`UreqHttpClient`) y los firmadores reales de `afirma-signers`.
//!
//! Los cuerpos esperados de las peticiones son los que construye la app Java
//! (`IntermediateServerUtil`, `ErrorManager.genError` + `URLEncoder`,
//! `CipherDataManager`, `BatchSigner`); los del servidor intermedio y los
//! errores están además contrastados con el oráculo Java
//! (`tests/android_oracle.rs`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afirma_core::http::{
    HttpClient as CoreHttp, HttpClientError, HttpRequest, HttpSettings, ProxyMode, UreqHttpClient,
};
use afirma_core::{AfirmaError, ExtraParams, SigningKey};
use afirma_protocol::android::cipher::{cipher_data, decipher_data};
use afirma_protocol::android::*;
use afirma_protocol::{CryptoOperation, HttpClient, LocalSignRequest, LocalSigner};

// ---------------------------------------------------------------------------
// Servidor simulado
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Received {
    method: String,
    path: String,
    content_type: Option<String>,
    body: String,
}

type Script = Box<dyn Fn(&str, &str) -> Option<(u16, Vec<u8>)> + Send + Sync>;

#[derive(Default)]
struct ServerState {
    /// Ficheros del servidor intermedio (texto ya decodificado, como el servlet).
    files: HashMap<String, String>,
    /// Respuestas `ERR-06` que se dan antes de entregar un fichero.
    err06_before: HashMap<String, usize>,
    requests: Vec<Received>,
    /// Estado HTTP del StorageService (200 normalmente).
    storage_status: Option<u16>,
    /// Respuestas del resto de rutas (servicio de lotes, descargas).
    script: Option<Script>,
}

struct Server {
    port: u16,
    state: Arc<Mutex<ServerState>>,
}

/// `URLDecoder.decode` del servlet.
fn form_decode(v: &str) -> String {
    afirma_protocol::query::url_decode(v).unwrap_or_else(|_| v.to_string())
}

fn form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

impl Server {
    fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(ServerState::default()));
        let st = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let st = st.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let mut len = 0usize;
                    let mut ct = None;
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        let (k, v) = h.split_once(':').unwrap();
                        if k.eq_ignore_ascii_case("content-length") {
                            len = v.trim().parse().unwrap();
                        }
                        if k.eq_ignore_ascii_case("content-type") {
                            ct = Some(v.trim().to_string());
                        }
                    }
                    let mut body = vec![0u8; len];
                    reader.read_exact(&mut body).unwrap();
                    let body = String::from_utf8(body).unwrap();
                    let (status, resp) = Server::respond(&st, &method, &path, ct, body);
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&resp);
                });
            }
        });
        Server { port, state }
    }

    fn respond(
        st: &Arc<Mutex<ServerState>>,
        method: &str,
        path: &str,
        content_type: Option<String>,
        body: String,
    ) -> (u16, Vec<u8>) {
        let mut s = st.lock().unwrap();
        s.requests.push(Received {
            method: method.into(),
            path: path.into(),
            content_type,
            body: body.clone(),
        });
        let f = form(&body);
        match path {
            "/afirma-signature-storage/StorageService" => {
                if let Some(code) = s.storage_status {
                    return (code, b"error".to_vec());
                }
                let id = f.get("id").cloned().unwrap_or_default();
                let dat = form_decode(f.get("dat").map(String::as_str).unwrap_or(""));
                s.files.insert(id, dat);
                (200, b"OK".to_vec())
            }
            "/afirma-signature-retriever/RetrieveService" => {
                let id = f.get("id").cloned().unwrap_or_default();
                if let Some(n) = s.err06_before.get_mut(&id)
                    && *n > 0
                {
                    *n -= 1;
                    return (200, "ERR-06:=El identificador para los datos es inválido\n".into());
                }
                match s.files.remove(&id) {
                    Some(c) => (200, format!("{c}\n").into_bytes()),
                    None => (200, "ERR-06:=El identificador para los datos es inválido\n".into()),
                }
            }
            _ => {
                let script = s.script.take();
                drop(s);
                let r = script.as_ref().and_then(|f| f(path, &body));
                st.lock().unwrap().script = script;
                r.unwrap_or((404, b"no existe".to_vec()))
            }
        }
    }

    fn requests(&self) -> Vec<Received> {
        self.state.lock().unwrap().requests.clone()
    }

    fn uploads(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .filter(|r| r.path.ends_with("/StorageService"))
            .map(|r| r.body)
            .collect()
    }

    fn put_file(&self, id: &str, content: &str, err06: usize) {
        let mut s = self.state.lock().unwrap();
        s.files.insert(id.into(), content.into());
        s.err06_before.insert(id.into(), err06);
    }

    fn file(&self, id: &str) -> Option<String> {
        self.state.lock().unwrap().files.get(id).cloned()
    }

    fn set_script(&self, f: impl Fn(&str, &str) -> Option<(u16, Vec<u8>)> + Send + Sync + 'static) {
        self.state.lock().unwrap().script = Some(Box::new(f));
    }

    fn http(&self) -> HttpClient {
        HttpClient::new(Arc::new(Loopback {
            inner: UreqHttpClient::new(HttpSettings {
                proxy: ProxyMode::None,
                ..Default::default()
            }),
            port: self.port,
        }))
    }
}

/// Dirige `servidor.example` y `lotes.example` al servidor simulado (la
/// validación de URL de servicio rechaza las direcciones locales).
struct Loopback {
    inner: UreqHttpClient,
    port: u16,
}

impl CoreHttp for Loopback {
    fn read_url(&self, r: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        let mut r2 = r.clone();
        for h in ["servidor.example", "lotes.example", "tri.example"] {
            r2.url = r2
                .url
                .replace(&format!("://{h}"), &format!("://127.0.0.1:{}", self.port));
        }
        self.inner.read_url(&r2)
    }
}

const ST: &str = "http%3A%2F%2Fservidor.example%2Fafirma-signature-storage%2FStorageService";
const ST_DEC: &str = "http://servidor.example/afirma-signature-storage/StorageService";
const RT: &str = "http%3A%2F%2Fservidor.example%2Fafirma-signature-retriever%2FRetrieveService";
const KEY: &str = "12345678";

fn enc(s: &str) -> String {
    afirma_protocol::android::errors::java_url_encode(s)
}

fn generic_es() -> &'static str {
    UserText::NotCompletedRequest.text(WebLanguage::Es)
}

/// Texto subido para un error localizado en español.
fn err_upload(id: &str, code: u32, msg: &str) -> String {
    enc(&format!("{id}:=AA{code} - {msg}"))
}

// ---------------------------------------------------------------------------
// Interfaz y firmador simulados
// ---------------------------------------------------------------------------

fn testdata(p: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(p)
}

fn key(name: &str) -> Arc<dyn SigningKey> {
    let data = std::fs::read(testdata(&format!("pki/{name}.p12"))).unwrap();
    let entries = afirma_keystores::pkcs12::open(&data, "12341234").unwrap();
    Arc::new(entries[0].signing_key().unwrap())
}

#[derive(Default)]
struct UiState {
    keys: Vec<Result<SelectedKey, KeySelectionError>>,
    key_requests: Vec<(KeyPurpose, bool)>,
    warnings: Vec<CertificateWarning>,
    file: Option<Result<ChosenFile, FileChoiceError>>,
    visible: Option<VisibleSignatureResult>,
    visible_requests: Vec<(usize, bool, Option<String>)>,
    pdf_password: Option<String>,
    pdf_requests: Vec<bool>,
    save: Option<Result<(), SaveFileError>>,
    saved: Vec<(String, Vec<u8>, String)>,
    errors: Vec<u32>,
}

#[derive(Default)]
struct Ui(Mutex<UiState>);

impl Ui {
    fn with_key(k: Arc<dyn SigningKey>, source: KeySource) -> Arc<Ui> {
        let ui = Ui::default();
        ui.0.lock().unwrap().keys.push(Ok(SelectedKey { key: k, source }));
        Arc::new(ui)
    }
    fn errors(&self) -> Vec<u32> {
        self.0.lock().unwrap().errors.clone()
    }
    fn key_requests(&self) -> usize {
        self.0.lock().unwrap().key_requests.len()
    }
}

impl AndroidWebHandler for Ui {
    fn select_key(&self, req: &KeyRequest<'_>) -> Result<SelectedKey, KeySelectionError> {
        let mut s = self.0.lock().unwrap();
        s.key_requests.push((req.purpose, req.bad_pin_retry));
        if s.keys.len() > 1 {
            s.keys.remove(0)
        } else {
            s.keys.first().cloned().unwrap_or(Err(KeySelectionError::Cancelled))
        }
    }
    fn confirm_certificate_warning(&self, w: CertificateWarning, _c: &[u8]) -> bool {
        self.0.lock().unwrap().warnings.push(w);
        true
    }
    fn choose_file(&self, _req: &ChooseFileRequest<'_>) -> Result<ChosenFile, FileChoiceError> {
        self.0
            .lock()
            .unwrap()
            .file
            .clone()
            .unwrap_or(Err(FileChoiceError::Cancelled))
    }
    fn visible_signature(&self, req: &VisibleSignatureRequest<'_>) -> VisibleSignatureResult {
        let mut s = self.0.lock().unwrap();
        s.visible_requests
            .push((req.data.len(), req.mandatory, req.file_name.map(str::to_string)));
        s.visible.clone().unwrap_or(VisibleSignatureResult::Cancelled)
    }
    fn pdf_password(&self, req: &PdfPasswordRequest) -> Option<String> {
        let mut s = self.0.lock().unwrap();
        s.pdf_requests.push(req.bad_password);
        s.pdf_password.clone()
    }
    fn save_file(&self, req: &SaveFileRequest<'_>) -> Result<(), SaveFileError> {
        let mut s = self.0.lock().unwrap();
        s.saved
            .push((req.proposed_name.clone(), req.data.to_vec(), req.title.to_string()));
        s.save.clone().unwrap_or(Ok(()))
    }
    fn show_error(&self, d: &ErrorDialog) {
        assert!(d.message.starts_with(&format!("AA{} - ", d.category.code)));
        self.0.lock().unwrap().errors.push(d.category.code);
    }
}

/// Firmador local con `afirma-signers` que registra lo que recibe.
#[derive(Default)]
struct RealSigner {
    seen: Mutex<Vec<(CryptoOperation, String, ExtraParams)>>,
}

impl LocalSigner for RealSigner {
    fn supports_format(&self, format: &str) -> bool {
        afirma_signers::signer_for_format(format).is_some()
    }
    fn sign(&self, req: &LocalSignRequest<'_>) -> Result<Vec<u8>, AfirmaError> {
        self.seen
            .lock()
            .unwrap()
            .push((req.operation, req.format.to_string(), req.extra_params.clone()));
        let signer = afirma_signers::signer_for_format(req.format).unwrap();
        match req.operation {
            CryptoOperation::Sign => signer.sign(req.data, req.algorithm, req.key, req.extra_params),
            CryptoOperation::CoSign => signer.cosign(None, req.data, req.algorithm, req.key, req.extra_params),
            CryptoOperation::CounterSign => {
                signer.countersign(req.data, req.algorithm, &req.target, req.key, req.extra_params)
            }
        }
    }
    fn detect_format(&self, op: CryptoOperation, data: &[u8]) -> Option<String> {
        let op = match op {
            CryptoOperation::Sign => afirma_signers::CryptoOp::Sign,
            CryptoOperation::CoSign => afirma_signers::CryptoOp::Cosign,
            CryptoOperation::CounterSign => afirma_signers::CryptoOp::Countersign,
        };
        afirma_signers::protocol_auto_format(op, data)
    }
}

fn launcher(server: &Server, ui: Arc<Ui>, signer: Arc<RealSigner>) -> AndroidWebLauncher {
    let mut cfg = AndroidWebConfig::new(server.http());
    cfg.download.retry_delay = Duration::from_millis(5);
    cfg.active_waiting_interval = Duration::from_millis(20);
    AndroidWebLauncher::new(ui, signer, cfg)
}

fn uploaded_to(outcome: &WebOutcome, id: &str) -> String {
    match &outcome.reply {
        Reply::Uploaded { target, payload } => {
            assert_eq!(target.id, id);
            assert_eq!(target.storage_servlet, ST_DEC);
            payload.clone()
        }
        r => panic!("respuesta inesperada: {r:?}"),
    }
}

fn split_pair(payload: &str) -> (String, String) {
    let (a, b) = payload
        .split_once('|')
        .unwrap_or_else(|| panic!("se esperaba cert|firma: {payload}"));
    (a.to_string(), b.to_string())
}

// ---------------------------------------------------------------------------
// Firma
// ---------------------------------------------------------------------------

#[test]
fn sign_cades_des_reply_bytes() {
    let server = Server::start();
    let k = key("firmante-rsa");
    let ui = Ui::with_key(k.clone(), KeySource::SystemKeyStore);
    let signer = Arc::new(RealSigner::default());
    let l = launcher(&server, ui.clone(), signer.clone());
    let url = format!(
        "afirma://sign?ver=4&id=AbC123&stservlet={ST}&format=CAdES&algorithm=SHA256withRSA&key={KEY}\
         &properties=bW9kZT1pbXBsaWNpdA%3D%3D&dat=SG9sYSBtdW5kbw%3D%3D&appname=sede.example"
    );
    let out = l.run(&url, InvocationMode::Browser);
    let payload = uploaded_to(&out, "AbC123");
    // Una sola petición: POST al StorageService con el cuerpo de la app.
    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/afirma-signature-storage/StorageService");
    assert_eq!(
        reqs[0].content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(reqs[0].body, format!("op=put&v=1_0&id=AbC123&dat={payload}"));
    // Lo guardado por el servlet es exactamente lo enviado (sin `+`, `%` ni `&`).
    assert_eq!(server.file("AbC123").as_deref(), Some(payload.as_str()));
    let (c, s) = split_pair(&payload);
    assert!(c.split_once('.').unwrap().0.parse::<u8>().unwrap() < 8);
    assert_eq!(
        decipher_data(c.as_bytes(), Some(KEY.as_bytes())).unwrap(),
        k.certificate()
    );
    let sig = decipher_data(s.as_bytes(), Some(KEY.as_bytes())).unwrap();
    let cades = afirma_signers::signer_for_format("CAdES").unwrap();
    assert!(cades.is_sign(&sig, &ExtraParams::new()));
    // CAdES exacto: política expandida (sin expPolicy no cambia) y `mode` de la página.
    let seen = signer.seen.lock().unwrap();
    assert_eq!(seen[0].1, "CAdES");
    assert_eq!(seen[0].2.get("mode"), Some("implicit"));
    assert_eq!(
        out.history,
        Some(HistoryRecord {
            kind: HistoryKind::Web,
            operation: "sign".into(),
            file_name: None,
            app_name: Some("sede.example".into()),
        })
    );
    assert!(ui.errors().is_empty());
}

#[test]
fn sign_without_key_android_base64_with_line_breaks() {
    let server = Server::start();
    let k = key("firmante-ec");
    let ui = Ui::with_key(k.clone(), KeySource::SmartCard);
    let l = launcher(&server, ui, Arc::new(RealSigner::default()));
    let url = format!("afirma://sign?id=ID2&stservlet={ST}&format=CAdES&algorithm=SHA256&dat=SG9sYQ%3D%3D");
    let out = l.run(&url, InvocationMode::Browser);
    let payload = uploaded_to(&out, "ID2");
    let (c, s) = split_pair(&payload);
    for part in [&c, &s] {
        assert!(part.ends_with('\n'));
        assert!(part.lines().all(|l| l.len() <= 76));
        assert!(!part.contains('+') && !part.contains('/'));
    }
    assert_eq!(afirma_core::base64::decode_url_safe(&c).unwrap(), k.certificate());
    assert!(afirma_core::base64::decode_url_safe(&s).unwrap().len() > 100);
    assert_eq!(server.file("ID2").as_deref(), Some(payload.as_str()));
}

#[test]
fn sign_from_envelope_with_err06_retries() {
    let server = Server::start();
    let k = key("firmante-rsa");
    let ui = Ui::with_key(k.clone(), KeySource::SystemKeyStore);
    let l = launcher(&server, ui, Arc::new(RealSigner::default()));
    // Sobre de AutoScript: cosign sobre una firma CAdES previa.
    let first = l.run(
        &format!(
            "afirma://sign?id=PREV&stservlet={ST}&format=CAdES&algorithm=SHA256&dat=SG9sYQ%3D%3D&properties={}",
            enc(&afirma_core::base64::encode(b"mode=implicit\n"))
        ),
        InvocationMode::Browser,
    );
    let (_, s) = split_pair(&uploaded_to(&first, "PREV"));
    let sig = afirma_core::base64::decode_url_safe(&s).unwrap();
    let xml = format!(
        "<cosign><e k=\"format\" v=\"AUTO\"/><e k=\"algorithm\" v=\"SHA512withRSA\"/><e k=\"dat\" v=\"{}\"/>\
         <e k=\"op\" v=\"cosign\"/><e k=\"id\" v=\"RID77\"/><e k=\"key\" v=\"{KEY}\"/><e k=\"stservlet\" v=\"{ST_DEC}\"/></cosign>",
        afirma_core::base64::encode_url_safe(&sig)
    );
    let envelope = cipher_data(xml.as_bytes(), KEY.as_bytes()).unwrap();
    server.put_file("FID77", &envelope, 3);
    let url = format!("afirma://cosign?jvc=4&fileid=FID77&rid=RID77&rtservlet={RT}&stservlet={ST}&key={KEY}");
    let out = l.run(&url, InvocationMode::Browser);
    let payload = uploaded_to(&out, "RID77");
    let gets: Vec<Received> = server
        .requests()
        .into_iter()
        .filter(|r| r.path.ends_with("RetrieveService"))
        .collect();
    assert_eq!(gets.len(), 4, "3 ERR-06 y la descarga");
    assert!(gets.iter().all(|r| r.body == "op=get&v=1_0&id=FID77"));
    let (_, s) = split_pair(&payload);
    let cosig = decipher_data(s.as_bytes(), Some(KEY.as_bytes())).unwrap();
    let tree = afirma_signers::signer_for_format("CAdES")
        .unwrap()
        .signers_structure(&cosig, &ExtraParams::new())
        .unwrap();
    assert_eq!(tree.node_count(), 2, "dos firmantes");
    assert_eq!(out.history.unwrap().operation, "cosign");
}

#[test]
fn countersign_tree_and_unsupported_formats() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let signer = Arc::new(RealSigner::default());
    let l = launcher(&server, ui.clone(), signer.clone());
    let first = l.run(
        &format!("afirma://sign?id=P1&stservlet={ST}&format=CAdES&algorithm=SHA256&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    let (_, s) = split_pair(&uploaded_to(&first, "P1"));
    let sig = afirma_core::base64::encode_url_safe(&afirma_core::base64::decode_url_safe(&s).unwrap());
    // target=tree exacto.
    let props = afirma_core::base64::encode(b"target=tree\n");
    let out = l.run(
        &format!(
            "afirma://countersign?id=P2&stservlet={ST}&format=CAdES&algorithm=SHA256&dat={sig}&properties={}",
            enc(&props)
        ),
        InvocationMode::Browser,
    );
    uploaded_to(&out, "P2");
    assert_eq!(signer.seen.lock().unwrap()[1].0, CryptoOperation::CounterSign);

    // CMS no está en la app: diálogo AA600105 y ERR-10.
    let out = l.run(
        &format!("afirma://sign?id=P3&stservlet={ST}&format=CMS/PKCS%237&algorithm=SHA256&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "P3"), err_upload("ERR-10", 600105, generic_es()));
    assert_eq!(ui.errors(), vec![600105]);

    // AUTO en firma: sin firmador.
    let out = l.run(
        &format!("afirma://sign?id=P4&stservlet={ST}&format=AUTO&algorithm=SHA256&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "P4"), err_upload("ERR-10", 600105, generic_es()));

    // XAdES se fuerza a trifásica y sin serverUrl falla con ERR-14 (§5.14).
    let out = l.run(
        &format!("afirma://sign?id=P5&stservlet={ST}&format=XAdES&algorithm=SHA256&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "P5"), err_upload("ERR-14", 200002, generic_es()));
    assert!(out.history.is_none());
}

#[test]
fn xades_goes_triphase_with_server_url() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let l = launcher(&server, ui, Arc::new(RealSigner::default()));
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let s2 = seen.clone();
    server.set_script(move |path, body| {
        s2.lock().unwrap().push(format!("{path} {body}"));
        Some((200, b"ERR-01:=Error en la prefirma".to_vec()))
    });
    let props =
        afirma_core::base64::encode(b"serverUrl=http://tri.example/afirma-server-triphase-signer/SignatureService\n");
    let out = l.run(
        &format!(
            "afirma://sign?id=X1&stservlet={ST}&format=XAdES%20Enveloped&algorithm=SHA256&dat=PGEvPg%3D%3D&properties={}",
            enc(&props)
        ),
        InvocationMode::Browser,
    );
    let pre = seen.lock().unwrap().clone();
    assert_eq!(pre.len(), 1);
    assert!(pre[0].starts_with(
        "/afirma-server-triphase-signer/SignatureService op=pre&cop=sign&format=XAdES&algo=SHA256withRSA&cert="
    ));
    assert_eq!(uploaded_to(&out, "X1"), err_upload("ERR-14", 200002, generic_es()));
}

#[test]
fn pades_checks_and_visible_signature_with_dat() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let signer = Arc::new(RealSigner::default());
    let l = launcher(&server, ui.clone(), signer.clone());
    // No PDF: ERR-07 AA200107 y NO se firma (corrección §10 n.º 32).
    let out = l.run(
        &format!("afirma://sign?id=V0&stservlet={ST}&format=PAdES&algorithm=SHA256&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "V0"), err_upload("ERR-07", 200107, generic_es()));
    assert_eq!(ui.key_requests(), 0);
    assert!(signer.seen.lock().unwrap().is_empty());

    // Firma visible con los datos en `dat` (Java se cerraba, §10 n.º 33).
    let pdf = std::fs::read(testdata("pades/xref_stream.pdf")).unwrap();
    let dat = enc(&afirma_core::base64::encode(&pdf));
    let props = enc(&afirma_core::base64::encode(
        b"visibleSignature=want\nlayer2Text=de la pagina\n",
    ));
    ui.0.lock().unwrap().visible = Some(VisibleSignatureResult::Selected {
        owner_password: None,
        area: Some(VisibleArea {
            page: 1,
            lower_left_x: 100,
            lower_left_y: 100,
            upper_right_x: 300,
            upper_right_y: 200,
        }),
    });
    let out = l.run(
        &format!("afirma://sign?id=V1&stservlet={ST}&format=PAdES&algorithm=SHA256&dat={dat}&properties={props}"),
        InvocationMode::Browser,
    );
    uploaded_to(&out, "V1");
    {
        let s = ui.0.lock().unwrap();
        assert_eq!(s.visible_requests, vec![(pdf.len(), true, None)]);
    }
    let seen = signer.seen.lock().unwrap();
    let extra = &seen.last().unwrap().2;
    assert_eq!(extra.get("signaturePages"), Some("1"));
    assert_eq!(extra.get("obfuscateCertText"), Some("true"));
    assert_eq!(extra.get("signaturePositionOnPageUpperRightY"), Some("200"));
    // La plantilla de la app sustituye la de la página (§10 n.º 34).
    assert_eq!(
        extra.get("layer2Text"),
        UserText::PdfVisibleSignTemplate.text(WebLanguage::Es).into()
    );
    drop(seen);

    // `want` sin área: cancelación.
    ui.0.lock().unwrap().visible = Some(VisibleSignatureResult::Selected {
        owner_password: None,
        area: None,
    });
    let out = l.run(
        &format!("afirma://sign?id=V2&stservlet={ST}&format=PAdES&algorithm=SHA256&dat={dat}&properties={props}"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "V2"),
        err_upload("ERR-11", 500001, "Operacion cancelada")
    );
    // `headless=true` evita la vista previa.
    let props_h = enc(&afirma_core::base64::encode(b"visibleSignature=want\nheadless=true\n"));
    let n = ui.0.lock().unwrap().visible_requests.len();
    let out = l.run(
        &format!("afirma://sign?id=V3&stservlet={ST}&format=PAdES&algorithm=SHA256&dat={dat}&properties={props_h}"),
        InvocationMode::Browser,
    );
    uploaded_to(&out, "V3");
    assert_eq!(ui.0.lock().unwrap().visible_requests.len(), n);
    // Error al cargar el PDF en la vista previa: AA200102 + ERR-07.
    ui.0.lock().unwrap().visible = Some(VisibleSignatureResult::LoadError("roto".into()));
    let out = l.run(
        &format!("afirma://sign?id=V4&stservlet={ST}&format=PAdES&algorithm=SHA256&dat={dat}&properties={props}"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "V4"), err_upload("ERR-07", 200102, generic_es()));
}

#[test]
fn pdf_password_retry() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let signer = Arc::new(RealSigner::default());
    let l = launcher(&server, ui.clone(), signer.clone());
    let pdf = std::fs::read(testdata("pades/encrypted_aes128_user.pdf")).unwrap();
    let dat = enc(&afirma_core::base64::encode(&pdf));
    ui.0.lock().unwrap().pdf_password = Some("owner".into());
    let out = l.run(
        &format!("afirma://sign?id=W1&stservlet={ST}&format=PAdES&algorithm=SHA256&dat={dat}"),
        InvocationMode::Browser,
    );
    uploaded_to(&out, "W1");
    assert_eq!(ui.0.lock().unwrap().pdf_requests, vec![false]);
    assert_eq!(
        signer.seen.lock().unwrap().last().unwrap().2.get("ownerPassword"),
        Some("owner")
    );
    // Cancelado: ERR-11.
    ui.0.lock().unwrap().pdf_password = None;
    let out = l.run(
        &format!("afirma://sign?id=W2&stservlet={ST}&format=PAdES&algorithm=SHA256&dat={dat}"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "W2"),
        err_upload("ERR-11", 500001, "Operacion cancelada")
    );
}

#[test]
fn file_chosen_by_user_and_cancellations() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SystemKeyStore);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    ui.0.lock().unwrap().file = Some(Ok(ChosenFile {
        name: "contrato.txt".into(),
        data: b"contenido".to_vec(),
    }));
    let url = format!("afirma://sign?id=F1&stservlet={ST}&format=CAdES&algorithm=SHA256&appname=x.example");
    let out = l.run(&url, InvocationMode::Browser);
    uploaded_to(&out, "F1");
    assert_eq!(out.history.unwrap().file_name.as_deref(), Some("contrato.txt"));
    // PAdES con fichero no PDF elegido por el usuario: AA200106.
    let out = l.run(
        &format!("afirma://sign?id=F2&stservlet={ST}&format=PAdES&algorithm=SHA256"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "F2"),
        err_upload("ERR-07", 200106, UserText::NecessaryPdfFile.text(WebLanguage::Es))
    );
    ui.0.lock().unwrap().file = Some(Err(FileChoiceError::Cancelled));
    let out = l.run(&url.replace("F1", "F3"), InvocationMode::Browser);
    assert_eq!(uploaded_to(&out, "F3"), "ERR-11%3A%3DAA500001+-+Operacion+cancelada");
    // Errores de certificado: almacén (ERR-23), KeyChain (ERR-13) y cancelación.
    ui.0.lock().unwrap().file = Some(Ok(ChosenFile {
        name: "a.txt".into(),
        data: b"x".to_vec(),
    }));
    for (e, expected) in [
        (
            KeySelectionError::KeyStore("x".into()),
            err_upload("ERR-23", 201101, "Error al cargar el almacen de certificados"),
        ),
        (
            KeySelectionError::KeyChain("x".into()),
            err_upload("ERR-13", 201103, "Error al cargar el certificado"),
        ),
        (
            KeySelectionError::Other("x".into()),
            err_upload("ERR-13", 201105, "Error al cargar el certificado"),
        ),
        (
            KeySelectionError::Cancelled,
            err_upload("ERR-11", 500001, "Operacion cancelada"),
        ),
    ] {
        ui.0.lock().unwrap().keys = vec![Err(e)];
        let out = l.run(&url.replace("F1", "F4"), InvocationMode::Browser);
        assert_eq!(uploaded_to(&out, "F4"), expected);
    }
}

#[test]
fn parameter_errors_are_replied() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    let expected = format!("ERR-22%3A%3DAA600006+-+{}", enc(generic_es()));
    // Sin algoritmo.
    let out = l.run(
        &format!("afirma://sign?id=E1&stservlet={ST}&format=CAdES&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "E1"), expected);
    assert_eq!(ui.errors(), vec![600006]);
    // Clave de longitud incorrecta.
    let out = l.run(
        &format!("afirma://sign?id=E2&stservlet={ST}&format=CAdES&algorithm=SHA256&key=123&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "E2"), expected);
    // `%` mal formado: se responde igualmente.
    let out = l.run(
        &format!("afirma://selectcert?id=E3&stservlet={ST}&x=%zz"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "E3"), expected);
    // Sin `stservlet` no hay a quién responder (Java se cerraba).
    let out = l.run("afirma://sign?id=E4&format=CAdES", InvocationMode::Browser);
    assert_eq!(out.reply, Reply::NotSent);
    // Desde otra app: `ERR-22` por el intent, sin codificar.
    let out = l.run(
        "afirma://sign?format=CAdES",
        InvocationMode::App {
            calling_package: Some("es.ejemplo".into()),
        },
    );
    assert_eq!(
        out.reply,
        Reply::Intent(IntentReply::Error {
            error_id: "ERR-22".into(),
            error_msg: format!("ERR-22:=AA600006 - {}", generic_es()),
        })
    );
}

#[test]
fn envelope_errors_reply_to_rid() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    // Fichero inexistente: tras los reintentos, ERR-14 AA401100 a `rid`.
    let out = l.run(
        &format!("afirma://sign?fileid=NOEXISTE&rid=RIDA&rtservlet={RT}&stservlet={ST}&key={KEY}"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "RIDA"), err_upload("ERR-14", 401100, generic_es()));
    assert_eq!(
        server
            .requests()
            .iter()
            .filter(|r| r.path.ends_with("RetrieveService"))
            .count(),
        11
    );
    // Sobre que no se descifra: ERR-22 AA600006.
    server.put_file("FIDB", "0.QUJD", 0);
    let out = l.run(
        &format!("afirma://selectcert?fileid=FIDB&rid=RIDB&rtservlet={RT}&stservlet={ST}&key={KEY}"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "RIDB"), err_upload("ERR-22", 600006, generic_es()));
    assert_eq!(ui.errors(), vec![401100, 600006]);
}

// ---------------------------------------------------------------------------
// Selección de certificado
// ---------------------------------------------------------------------------

#[test]
fn select_cert_formats_and_sticky_cache() {
    let server = Server::start();
    let k = key("autenticacion");
    let ui = Ui::with_key(k.clone(), KeySource::SystemKeyStore);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    // Con clave: C(cert).
    let out = l.run(
        &format!("afirma://selectcert?id=S1&stservlet={ST}&key={KEY}&sticky=true"),
        InvocationMode::Browser,
    );
    let p = uploaded_to(&out, "S1");
    assert_eq!(p, cipher_data(k.certificate(), KEY.as_bytes()).unwrap());
    assert_eq!(server.requests()[0].body, format!("op=put&v=1_0&id=S1&dat={p}"));
    assert!(out.history.is_none());
    // Sin clave: Base64 URL-safe de afirma-core, sin saltos.
    let out = l.run(
        &format!("afirma://selectcert?id=S2&stservlet={ST}&sticky=true"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "S2"),
        afirma_core::base64::encode_url_safe(k.certificate())
    );
    // La segunda vez con sticky usó la caché (un solo diálogo).
    assert_eq!(ui.key_requests(), 1);
    // `resetsticky` vuelve a preguntar.
    l.run(
        &format!("afirma://selectcert?id=S3&stservlet={ST}&sticky=true&resetsticky=true"),
        InvocationMode::Browser,
    );
    assert_eq!(ui.key_requests(), 2);
    // Sin sticky se borra la caché.
    l.run(
        &format!("afirma://selectcert?id=S4&stservlet={ST}"),
        InvocationMode::Browser,
    );
    assert!(l.sticky_cache().get().is_none());
    // Cancelado: ERR-11 con AA201104 «Certificado no seleccionado».
    ui.0.lock().unwrap().keys = vec![Err(KeySelectionError::Cancelled)];
    let out = l.run(
        &format!("afirma://selectcert?id=S5&stservlet={ST}"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "S5"),
        err_upload("ERR-11", 201104, "Certificado no seleccionado")
    );
    // DNIe: nunca se guarda en la caché.
    ui.0.lock().unwrap().keys = vec![Ok(SelectedKey {
        key: k,
        source: KeySource::DnieNfc,
    })];
    l.run(
        &format!("afirma://selectcert?id=S6&stservlet={ST}&sticky=true"),
        InvocationMode::Browser,
    );
    assert!(l.sticky_cache().get().is_none());
}

#[test]
fn sticky_cache_shared_with_sign_and_warnings() {
    let server = Server::start();
    // Certificado caducado de `KeyChain`: aviso (y se continúa).
    let ui = Ui::with_key(key("caducado"), KeySource::SystemKeyStore);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    let url = format!("afirma://sign?id=K1&stservlet={ST}&format=CAdES&algorithm=SHA256&dat=SG9sYQ%3D%3D&sticky=true");
    uploaded_to(&l.run(&url, InvocationMode::Browser), "K1");
    assert_eq!(ui.0.lock().unwrap().warnings, vec![CertificateWarning::Expired]);
    // Segunda firma con sticky: sin diálogo ni avisos.
    uploaded_to(&l.run(&url.replace("K1", "K2"), InvocationMode::Browser), "K2");
    assert_eq!(ui.key_requests(), 1);
    assert_eq!(ui.0.lock().unwrap().warnings.len(), 1);
}

// ---------------------------------------------------------------------------
// Guardado
// ---------------------------------------------------------------------------

#[test]
fn save_flows() {
    let server = Server::start();
    let ui = Arc::new(Ui::default());
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    let out = l.run(
        &format!("afirma://save?id=G1&stservlet={ST}&dat=SG9sYQ%3D%3D&title=T%C3%ADtulo"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "G1"), "OK");
    {
        let s = ui.0.lock().unwrap();
        assert_eq!(s.saved[0].1, b"Hola");
        assert_eq!(s.saved[0].2, "Título");
        assert!(s.saved[0].0.starts_with("datos"));
        assert!(!s.saved[0].0.starts_with("datosdatos"));
    }
    // Cancelado y error de escritura con los textos fijos de ERR-NN.
    ui.0.lock().unwrap().save = Some(Err(SaveFileError::Cancelled));
    let out = l.run(
        &format!("afirma://save?id=G2&stservlet={ST}&dat=SG9sYQ%3D%3D"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "G2"), "ERR-11%3A%3DAA500001+-+Operacion+cancelada");
    ui.0.lock().unwrap().save = Some(Err(SaveFileError::Write("disco".into())));
    let out = l.run(
        &format!("afirma://save?id=G3&stservlet={ST}&dat=SG9sYQ%3D%3D&filename=a.txt"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "G3"),
        "ERR-26%3A%3DAA200305+-+Error+al+guardar+los+datos+en+el+dispositivo"
    );
    assert_eq!(ui.errors(), vec![200305]);
    // Sobre que no existe: ERR-18 AA400001 a `rid` (Java lo enviaba a `fileid`).
    ui.0.lock().unwrap().save = None;
    let out = l.run(
        &format!("afirma://save?fileid=NOHAY&rid=RIDS&rtservlet={RT}&stservlet={ST}&key={KEY}"),
        InvocationMode::Browser,
    );
    assert_eq!(
        uploaded_to(&out, "RIDS"),
        "ERR-18%3A%3DAA400001+-+Error+de+comunicacion+con+el+servicio"
    );
    // Sobre correcto con nombre.
    let xml = format!(
        "<save><e k=\"dat\" v=\"SG9sYQ==\"/><e k=\"filename\" v=\"nota.txt\"/><e k=\"id\" v=\"RIDT\"/><e k=\"stservlet\" v=\"{ST_DEC}\"/></save>"
    );
    server.put_file("FT", &cipher_data(xml.as_bytes(), KEY.as_bytes()).unwrap(), 1);
    let out = l.run(
        &format!("afirma://save?fileid=FT&rid=RIDT&rtservlet={RT}&stservlet={ST}&key={KEY}"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "RIDT"), "OK");
    assert_eq!(ui.0.lock().unwrap().saved.last().unwrap().0, "nota.txt");
    // Errores de parámetros: ERR-22 con el texto fijo.
    let out = l.run(&format!("afirma://save?id=G9&stservlet={ST}"), InvocationMode::Browser);
    assert_eq!(
        uploaded_to(&out, "G9"),
        "ERR-22%3A%3DAA600006+-+No+se+ha+realizado+correctamente+la+invocacion+de+la+aplicacion"
    );
}

// ---------------------------------------------------------------------------
// Lotes
// ---------------------------------------------------------------------------

const BATCH: &str = r#"{"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","singlesigns":[{"id":"1","datareference":"SG9sYQ=="},{"id":"2","datareference":"QWRpb3M="}]}"#;

fn batch_server(server: &Server, presign: String) -> Arc<Mutex<Vec<(String, String)>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    server.set_script(move |path, body| {
        s2.lock().unwrap().push((path.to_string(), body.to_string()));
        match path {
            "/batch/presign" => {
                std::thread::sleep(Duration::from_millis(120));
                Some((200, presign.clone().into_bytes()))
            }
            "/batch/postsign" => Some((200, br#"{"signs":[{"id":"1","result":"DONE_AND_SAVED"}]}"#.to_vec())),
            "/batch/notfound" => Some((404, b"x".to_vec())),
            "/batch/bad" => Some((400, b"x".to_vec())),
            _ => None,
        }
    });
    seen
}

fn presign_td() -> String {
    let pre = afirma_core::base64::encode(b"datos a firmar en PKCS#1 por el cliente");
    format!(
        r#"{{"td":{{"format":"CAdES","signs":[{{"signinfo":[{{"id":"1","signid":"S-1","params":{{"PRE":"{pre}","NEED_PRE":"true"}}}}]}}]}},"results":[{{"id":"2","result":"ERROR_PRE","description":"fallo/2"}}]}}"#
    )
}

#[test]
fn batch_json_envelope_with_active_waiting() {
    let server = Server::start();
    let k = key("firmante-rsa");
    let ui = Ui::with_key(k.clone(), KeySource::SystemKeyStore);
    let l = launcher(&server, ui, Arc::new(RealSigner::default()));
    let seen = batch_server(&server, presign_td());
    let xml = format!(
        "<batch><e k=\"dat\" v=\"{}\"/><e k=\"batchpresignerurl\" v=\"http://lotes.example/batch/presign\"/>\
         <e k=\"batchpostsignerurl\" v=\"http://lotes.example/batch/postsign\"/><e k=\"jsonbatch\" v=\"true\"/>\
         <e k=\"needcert\" v=\"true\"/><e k=\"id\" v=\"RIDL\"/><e k=\"stservlet\" v=\"{ST_DEC}\"/>\
         <e k=\"aw\" v=\"true\"/><e k=\"key\" v=\"{KEY}\"/><e k=\"appname\" v=\"lotes.example\"/></batch>",
        afirma_core::base64::encode_url_safe(BATCH.as_bytes())
    );
    server.put_file("FL", &cipher_data(xml.as_bytes(), KEY.as_bytes()).unwrap(), 0);
    let out = l.run(
        &format!("afirma://batch?fileid=FL&rid=RIDL&rtservlet={RT}&stservlet={ST}&key={KEY}"),
        InvocationMode::Browser,
    );
    let payload = uploaded_to(&out, "RIDL");
    // Espera activa: `#WAIT` antes del resultado, ninguno después.
    let uploads = server.uploads();
    assert!(uploads.len() >= 2, "{uploads:?}");
    assert!(
        uploads[..uploads.len() - 1]
            .iter()
            .all(|b| b == "op=put&v=1_0&id=RIDL&dat=#WAIT")
    );
    assert_eq!(uploads.last().unwrap(), &format!("op=put&v=1_0&id=RIDL&dat={payload}"));
    // Resultado: C(resultado)|C(cert).
    let (r, c) = split_pair(&payload);
    assert_eq!(
        decipher_data(r.as_bytes(), Some(KEY.as_bytes())).unwrap(),
        br#"{"signs":[{"id":"1","result":"DONE_AND_SAVED"}]}"#
    );
    assert_eq!(
        decipher_data(c.as_bytes(), Some(KEY.as_bytes())).unwrap(),
        k.certificate()
    );
    // Peticiones al servicio de lotes.
    let seen = seen.lock().unwrap();
    let chain = afirma_protocol::batch::batch_cert_chain(&k.certificate_chain());
    assert_eq!(
        seen[0],
        (
            "/batch/presign".into(),
            format!(
                "json={}&certs={chain}",
                afirma_core::base64::encode_url_safe(BATCH.as_bytes())
            )
        )
    );
    let post = form(&seen[1].1);
    // Lote reescrito con el resultado parcial (org.json de Android).
    let rewritten = afirma_core::base64::decode_url_safe(&post["json"]).unwrap();
    assert_eq!(
        String::from_utf8(rewritten).unwrap(),
        r#"{"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","singlesigns":[{"id":"1","datareference":"SG9sYQ=="},{"id":"2","result":"ERROR_PRE","description":"fallo\/2"}]}"#
    );
    assert_eq!(post["certs"], chain);
    let tridata = String::from_utf8(afirma_core::base64::decode_url_safe(&post["tridata"]).unwrap()).unwrap();
    assert!(
        tridata.starts_with(r#"{"format":"CAdES","signinfo":[{"id":"1","signid":"S-1","params":{"#),
        "{tridata}"
    );
    assert!(tridata.contains(r#""PK1":"#) && tridata.contains(r#""PRE":"#));
    assert_eq!(
        out.history,
        Some(HistoryRecord {
            kind: HistoryKind::Batch,
            operation: "sign".into(),
            file_name: None,
            app_name: Some("lotes.example".into()),
        })
    );
}

#[test]
fn batch_direct_errors_and_formats() {
    let server = Server::start();
    let k = key("firmante-rsa");
    let ui = Ui::with_key(k.clone(), KeySource::SmartCard);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    batch_server(&server, presign_td());
    let dat = enc(&afirma_core::base64::encode(BATCH.as_bytes()));
    let url = |id: &str, pre: &str, post: &str| {
        format!(
            "afirma://batch?id={id}&stservlet={ST}&dat={dat}&batchpresignerurl=http%3A%2F%2Flotes.example%2Fbatch%2F{pre}\
             &batchpostsignerurl=http%3A%2F%2Flotes.example%2Fbatch%2F{post}&jsonbatch=true"
        )
    };
    // Sin clave: Base64 estándar del resultado, sin certificado.
    // (El servlet guarda exactamente el Base64: el `+` va protegido como `%2B`.)
    let out = l.run(&url("L1", "presign", "postsign"), InvocationMode::Browser);
    uploaded_to(&out, "L1");
    assert_eq!(
        server.file("L1"),
        Some(afirma_core::base64::encode(
            br#"{"signs":[{"id":"1","result":"DONE_AND_SAVED"}]}"#
        ))
    );
    // HTTP 404 en la prefirma: ERR-18 AA400001; 400: ERR-14 AA200002.
    let out = l.run(&url("L2", "notfound", "postsign"), InvocationMode::Browser);
    assert_eq!(uploaded_to(&out, "L2"), err_upload("ERR-18", 400001, generic_es()));
    let out = l.run(&url("L3", "bad", "postsign"), InvocationMode::Browser);
    assert_eq!(uploaded_to(&out, "L3"), err_upload("ERR-14", 200002, generic_es()));
    // Desde otra app: resultado por intent.
    let out = l.run(
        &url("L4", "presign", "postsign"),
        InvocationMode::App {
            calling_package: Some("es.llamante".into()),
        },
    );
    assert_eq!(
        out.reply,
        Reply::Intent(IntentReply::Batch {
            cert: None,
            result: br#"{"signs":[{"id":"1","result":"DONE_AND_SAVED"}]}"#.to_vec()
        })
    );
    assert_eq!(out.history.unwrap().kind, HistoryKind::BatchApp);
    // Lote local (corrección §10 n.º 53).
    let local = r#"{"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","singlesigns":[{"id":"a","datareference":"SG9sYQ=="}]}"#;
    let out = l.run(
        &format!(
            "afirma://batch?id=L5&stservlet={ST}&dat={}&localBatchProcess=true&jsonbatch=true",
            enc(&afirma_core::base64::encode(local.as_bytes()))
        ),
        InvocationMode::Browser,
    );
    let result = afirma_core::base64::decode(&uploaded_to(&out, "L5")).unwrap();
    let text = String::from_utf8(result).unwrap();
    assert!(
        text.contains("\"id\":\"a\"") && text.contains("DONE_AND_SAVED"),
        "{text}"
    );
    // Descarga del lote imposible: ERR-14 AA401100 a `rid` (Java se cerraba).
    let out = l.run(
        &format!("afirma://batch?fileid=NADA&rid=RIDN&rtservlet={RT}&stservlet={ST}&key={KEY}"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "RIDN"), err_upload("ERR-14", 401100, generic_es()));
}

// ---------------------------------------------------------------------------
// Subida, cancelación e idioma
// ---------------------------------------------------------------------------

#[test]
fn upload_failure_shows_dialog() {
    let server = Server::start();
    server.state.lock().unwrap().storage_status = Some(500);
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let l = launcher(&server, ui.clone(), Arc::new(RealSigner::default()));
    let out = l.run(
        &format!("afirma://selectcert?id=U1&stservlet={ST}"),
        InvocationMode::Browser,
    );
    assert!(matches!(out.reply, Reply::UploadFailed { .. }));
    assert_eq!(ui.errors(), vec![401200]);
    // Una cancelación (no crítica) que no se puede subir no muestra diálogo.
    ui.0.lock().unwrap().keys = vec![Err(KeySelectionError::Cancelled)];
    l.run(
        &format!("afirma://selectcert?id=U2&stservlet={ST}"),
        InvocationMode::Browser,
    );
    assert_eq!(ui.errors(), vec![401200]);
}

#[test]
fn back_during_download_replies_once() {
    let server = Server::start();
    let ui = Ui::with_key(key("firmante-rsa"), KeySource::SmartCard);
    let mut cfg = AndroidWebConfig::new(server.http());
    cfg.download.retry_delay = Duration::from_millis(200);
    let l = Arc::new(AndroidWebLauncher::new(ui, Arc::new(RealSigner::default()), cfg));
    let l2 = l.clone();
    let t = std::thread::spawn(move || {
        l2.run(
            &format!("afirma://sign?fileid=TARDE&rid=RIDC&rtservlet={RT}&stservlet={ST}&key={KEY}"),
            InvocationMode::Browser,
        )
    });
    std::thread::sleep(Duration::from_millis(300));
    l.request_cancel();
    let out = t.join().unwrap();
    assert_eq!(uploaded_to(&out, "RIDC"), "ERR-11%3A%3DAA500001+-+Operacion+cancelada");
    assert_eq!(server.uploads().len(), 1);
}

#[test]
fn error_texts_follow_app_language() {
    let server = Server::start();
    let ui = Arc::new(Ui::default());
    let mut cfg = AndroidWebConfig::new(server.http());
    cfg.language = WebLanguage::En;
    let l = AndroidWebLauncher::new(ui, Arc::new(RealSigner::default()), cfg);
    let out = l.run(
        &format!("afirma://selectcert?id=I1&stservlet={ST}"),
        InvocationMode::Browser,
    );
    assert_eq!(uploaded_to(&out, "I1"), "ERR-11%3A%3DAA201104+-+Unselected+certificate");
}

#[test]
fn unregistered_operations() {
    let server = Server::start();
    let l = launcher(&server, Arc::new(Ui::default()), Arc::new(RealSigner::default()));
    for op in ["signandsave", "load", "websocket", "service"] {
        let out = l.run(&format!("afirma://{op}?id=Z1&stservlet={ST}"), InvocationMode::Browser);
        assert_eq!(out.operation, None);
        assert_eq!(out.reply, Reply::NotSent);
    }
    assert!(server.requests().is_empty());
}

#[test]
fn batch_xml_against_server() {
    // Lote XML (`jsonbatch` ausente): Java respondía ERR-14; aquí va al servidor (§10 n.º 53).
    let server = Server::start();
    let k = key("firmante-rsa");
    let ui = Ui::with_key(k.clone(), KeySource::SmartCard);
    let l = launcher(&server, ui, Arc::new(RealSigner::default()));
    let pre = afirma_core::base64::encode(b"prefirma XML");
    let td =
        format!("<xml><firmas format=\"CAdES\"><firma Id=\"1\"><param n=\"PRE\">{pre}</param></firma></firmas></xml>");
    let seen = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let s2 = seen.clone();
    server.set_script(move |path, body| {
        s2.lock().unwrap().push((path.to_string(), body.to_string()));
        match path {
            "/batch/xpre" => Some((200, td.clone().into_bytes())),
            "/batch/xpost" => Some((
                200,
                b"<signs><sign id=\"1\" result=\"DONE_AND_SAVED\"/></signs>".to_vec(),
            )),
            _ => None,
        }
    });
    let batch = "<signbatch algorithm=\"SHA256withRSA\"><singlesign Id=\"1\"><datasource>SG9sYQ==</datasource></singlesign></signbatch>";
    let out = l.run(
        &format!(
            "afirma://batch?id=XB1&stservlet={ST}&key={KEY}&dat={}&batchpresignerurl=http%3A%2F%2Flotes.example%2Fbatch%2Fxpre\
             &batchpostsignerurl=http%3A%2F%2Flotes.example%2Fbatch%2Fxpost",
            enc(&afirma_core::base64::encode(batch.as_bytes()))
        ),
        InvocationMode::Browser,
    );
    let payload = uploaded_to(&out, "XB1");
    assert_eq!(
        decipher_data(payload.as_bytes(), Some(KEY.as_bytes())).unwrap(),
        b"<signs><sign id=\"1\" result=\"DONE_AND_SAVED\"/></signs>"
    );
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].0, "/batch/xpre");
    assert!(seen[0].1.starts_with(&format!(
        "xml={}&certs=",
        afirma_core::base64::encode_url_safe(batch.as_bytes())
    )));
    assert!(seen[1].1.contains("&tridata="));
}
