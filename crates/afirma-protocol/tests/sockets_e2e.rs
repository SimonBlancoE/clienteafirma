//! Pruebas de extremo a extremo de los canales locales: un cliente que se
//! comporta como `autoscript.js` (WebSocket seguro con una CA de pruebas en
//! la que confía, mensajes reales de AutoScript) y el socket de servicio.

mod common;

use std::sync::Arc;
use std::time::Duration;

use afirma_protocol::channel::ChannelRequest;
use afirma_protocol::query::Params;
use afirma_protocol::service::{ServiceOptions, ServiceServer};
use afirma_protocol::websocket::{ServerExit, WebSocketOptions, WebSocketServer};
use afirma_protocol::{HttpClient, LauncherConfig, ProtocolLauncher, TlsSource, jbase64};
use common::*;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

const SESSION: &str = "Q3k9aZ0bT1cL2mN4pX7r";

/// CA de pruebas y PKCS#12 del socket (como `autofirma.pfx`, alias
/// `SocketAutoFirma`, contraseña `654321`).
fn test_tls() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "AutoFirma ROOT");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut lp = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    lp.distinguished_name.push(DnType::CommonName, "127.0.0.1");
    let leaf = lp.signed_by(&leaf_key, &ca).unwrap();
    let chain = p12_keystore::PrivateKeyChain::new(
        b"socket".to_vec(),
        p12_keystore::PrivateKey::from_der(&leaf_key.serialize_der()).unwrap(),
        vec![p12_keystore::Certificate::from_der(leaf.der()).unwrap(), p12_keystore::Certificate::from_der(ca.der()).unwrap()],
    );
    let mut ks = p12_keystore::KeyStore::new();
    ks.add_entry("SocketAutoFirma", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
    (ks.writer("654321").write().unwrap(), ca.der().to_vec())
}

fn tls_connector(ca: &[u8]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(ca.to_vec())).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

fn make_launcher(handler: Arc<FakeHandler>) -> Arc<ProtocolLauncher> {
    let http = MockHttp::new(|_| Ok((404, vec![])));
    Arc::new(ProtocolLauncher::new(handler, Arc::new(FakeSigner::default()), LauncherConfig::new(HttpClient::new(http))))
}

fn channel(url: &str) -> ChannelRequest {
    let p = Params::from_query(url);
    let jvc = afirma_protocol::version::parse_jvc(p.get("jvc").unwrap().as_deref());
    ChannelRequest::from_params(&p, jvc)
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

async fn connect(port: u16, ca: &[u8]) -> Ws {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let tls = tls_connector(ca).connect(ServerName::try_from("127.0.0.1").unwrap(), tcp).await.unwrap();
    let mut req = format!("wss://127.0.0.1:{port}").into_client_request().unwrap();
    req.headers_mut().insert("Origin", "https://sede.ejemplo.gob.es".parse().unwrap());
    let (ws, _) = tokio_tungstenite::client_async(req, tls).await.unwrap();
    ws
}

async fn ask(ws: &mut Ws, text: &str) -> String {
    ws.send(Message::Text(text.into())).await.unwrap();
    loop {
        match ws.next().await.unwrap().unwrap() {
            Message::Text(t) => return t.to_string(),
            _ => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn autoscript_async_websocket_session() {
    let (pfx, ca) = test_tls();
    let k = key("firmante-rsa");
    let handler = FakeHandler::with_key(k.clone());
    let launcher = make_launcher(handler.clone());
    // URL de lanzamiento de AutoScript 1.10 (puerto 0 = cualquiera libre).
    let req = channel(&format!("afirma://websocket?ports=0&v=4&jvc=4&idsession={SESSION}"));
    let tls = TlsSource::Pkcs12Bytes { data: pfx, password: "654321".into() };
    let server = WebSocketServer::bind(&req, &tls, WebSocketOptions::default()).await.unwrap();
    let port = server.port();
    let serve = tokio::spawn(server.serve(launcher));

    let mut ws = connect(port, &ca).await;
    assert_eq!(ask(&mut ws, &format!("echo=-idsession={SESSION}@EOF")).await, "OK");
    // Mensaje de firma tal como lo envía AutoScript por WebSocket.
    let msg = format!(
        "afirma://sign?op=sign&idsession={SESSION}&algorithm=SHA512withRSA&format=CAdES&properties=bW9kZT1pbXBsaWNpdA==&ksb64=TU9aX1VOSQ==&sticky=false&dat=SG9sYQ=="
    );
    assert_eq!(ask(&mut ws, &msg).await, "#wait");
    let mut result = String::from("#wait");
    for _ in 0..200 {
        result = ask(&mut ws, &format!("getresult?idsession={SESSION}")).await;
        if result != "#wait" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let parts: Vec<&str> = result.split('|').collect();
    assert_eq!(parts.len(), 2, "{result}");
    assert_eq!(jbase64::decode_url_safe(parts[0]).unwrap(), k.certificate());
    // El resultado ya se entregó: vuelve a "#wait".
    assert_eq!(ask(&mut ws, &format!("getresult?idsession={SESSION}")).await, "#wait");
    // El origen de la página llega al manejador.
    let info = handler.cert_requests.lock().unwrap()[0].1.clone();
    assert_eq!(info.origin.display(), Some("https://sede.ejemplo.gob.es"));
    // Sesión incorrecta.
    assert_eq!(
        ask(&mut ws, "afirma://selectcert?op=selectcert&idsession=OTRA").await,
        "err-00:=AF620010 - El identificador de sesion del websocket es incorrecto"
    );
    assert_eq!(ask(&mut ws, "echo=-@EOF").await, "err-00:=AF620010 - El identificador de sesion del websocket es incorrecto");
    // Una segunda conexión que se cierra no termina el servidor.
    let mut ws2 = connect(port, &ca).await;
    assert_eq!(ask(&mut ws2, &format!("echo=-idsession={SESSION}@EOF")).await, "OK");
    ws2.close(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!serve.is_finished());
    // Cerrar la primera conexión termina el servidor.
    ws.close(None).await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(5), serve).await.unwrap().unwrap();
    assert_eq!(exit, ServerExit::ClientClosed);
}

#[tokio::test(flavor = "multi_thread")]
async fn synchronous_and_legacy_websocket() {
    let (pfx, ca) = test_tls();
    let tls = TlsSource::Pkcs12Bytes { data: pfx, password: "654321".into() };
    // jvc ≤ 3: síncrono y versión 4 (errores antiguos).
    let req = channel("afirma://websocket?ports=0&v=4&jvc=3&idsession=ABC");
    let server = WebSocketServer::bind(&req, &tls, WebSocketOptions::default()).await.unwrap();
    let port = server.port();
    let serve = tokio::spawn(server.serve(make_launcher(FakeHandler::with_key(key("firmante-rsa")))));
    let mut ws = connect(port, &ca).await;
    assert!(ask(&mut ws, "afirma://selectcert?op=selectcert&idsession=ABC").await.starts_with("MII"));
    assert_eq!(ask(&mut ws, "afirma://save?op=save&idsession=ABC").await, "SAF_03: Error en los parámetros de entrada");
    ws.close(None).await.unwrap();
    assert_eq!(serve.await.unwrap(), ServerExit::ClientClosed);
    // Versión 3: sin comprobación de sesión.
    let req = channel("afirma://websocket?ports=0&v=3");
    let server = WebSocketServer::bind(&req, &tls, WebSocketOptions::default()).await.unwrap();
    let port = server.port();
    tokio::spawn(server.serve(make_launcher(FakeHandler::with_key(key("firmante-rsa")))));
    let mut ws = connect(port, &ca).await;
    assert_eq!(ask(&mut ws, "echo=").await, "OK");
    assert!(ask(&mut ws, "afirma://selectcert?op=selectcert").await.starts_with("MII"));
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_startup_errors_and_idle_timeout() {
    let (pfx, _) = test_tls();
    let tls = TlsSource::Pkcs12Bytes { data: pfx.clone(), password: "654321".into() };
    let err = WebSocketServer::bind(&channel("afirma://websocket?ports=0&v=2"), &tls, WebSocketOptions::default()).await.err().unwrap();
    assert_eq!(err.code().unwrap().code, 620011);
    let bad = TlsSource::Pkcs12Bytes { data: pfx.clone(), password: "otra".into() };
    let err = WebSocketServer::bind(&channel("afirma://websocket?ports=0&v=4"), &bad, WebSocketOptions::default()).await.err().unwrap();
    assert_eq!(err.code().unwrap().code, 220008);
    // Puerto ocupado → siguiente; ninguno libre → 220001.
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    let err = WebSocketServer::bind(&channel(&format!("afirma://websocket?ports={busy_port}&v=4")), &tls, WebSocketOptions::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.code().unwrap().code, 220001);
    let s = WebSocketServer::bind(&channel(&format!("afirma://websocket?ports={busy_port},0&v=4")), &tls, WebSocketOptions::default())
        .await
        .unwrap();
    assert_ne!(s.port(), busy_port);
    // Sin mensajes válidos: termina por inactividad.
    let opts = WebSocketOptions { idle_timeout: Duration::from_millis(300), ..Default::default() };
    let s = WebSocketServer::bind(&channel("afirma://websocket?ports=0&v=4&jvc=4"), &tls, opts).await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(5), s.serve(make_launcher(FakeHandler::with_key(key("firmante-rsa"))))).await.unwrap();
    assert_eq!(exit, ServerExit::IdleTimeout);
}

async fn service_call(port: u16, ca: &[u8], body: &str) -> String {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut tls = tls_connector(ca).connect(ServerName::try_from("127.0.0.1").unwrap(), tcp).await.unwrap();
    let req = format!(
        "POST /afirma HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://sede.ejemplo.gob.es\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let text = String::from_utf8(out).unwrap();
    let (head, b64) = text.split_once("\n\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\nConnection: close\n"), "{head}");
    String::from_utf8(jbase64::decode_url_safe(b64).unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn service_socket_commands() {
    let (pfx, ca) = test_tls();
    let tls = TlsSource::Pkcs12Bytes { data: pfx, password: "654321".into() };
    let k = key("firmante-rsa");
    let handler = FakeHandler::with_key(k.clone());
    // AutoScript 1.10 envía v=4 (Java lo rechazaba).
    let req = channel(&format!("afirma://service?ports=0&v=4&jvc=4&idsession={SESSION}"));
    let server = ServiceServer::bind(&req, &tls, ServiceOptions::default()).await.unwrap();
    let port = server.port();
    tokio::spawn(server.serve(make_launcher(handler.clone())));
    assert_eq!(service_call(port, &ca, &format!("echo=-idsession={SESSION}@EOF")).await, "OK");
    let url = "afirma://selectcert?op=selectcert";
    let parts = service_call(port, &ca, &format!("cmd={}idsession={SESSION}@EOF", jbase64::encode_url_safe(url.as_bytes()))).await;
    assert_eq!(parts, "1");
    let cert = service_call(port, &ca, &format!("send=@1@1idsession={SESSION}@EOF")).await;
    assert_eq!(jbase64::decode_url_safe(&cert).unwrap(), k.certificate());
    assert_eq!(handler.cert_requests.lock().unwrap()[0].1.origin.display(), Some("https://sede.ejemplo.gob.es"));
    // Fragmentos.
    service_call(port, &ca, &format!("echo=-idsession={SESSION}@EOF")).await;
    let sign = "afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==";
    let (a, b) = sign.split_at(20);
    assert_eq!(service_call(port, &ca, &format!("fragment=@1@2@{}idsession={SESSION}@EOF", jbase64::encode_url_safe(a.as_bytes()))).await, "MORE_DATA_NEED");
    assert_eq!(service_call(port, &ca, &format!("fragment=@2@2@{}idsession={SESSION}@EOF", jbase64::encode_url_safe(b.as_bytes()))).await, "OK");
    assert_eq!(service_call(port, &ca, &format!("firm=idsession={SESSION}@EOF")).await, "1");
    let r = service_call(port, &ca, &format!("send=@1@1idsession={SESSION}@EOF")).await;
    assert_eq!(r.split('|').count(), 2, "{r}");
    // Guardado.
    service_call(port, &ca, &format!("echo=-idsession={SESSION}@EOF")).await;
    let save = jbase64::encode_url_safe(b"afirma://save?op=save&dat=SG9sYQ==");
    assert_eq!(service_call(port, &ca, &format!("cmd={save}idsession={SESSION}@EOF")).await, "SAVE_OK");
    // Errores.
    let wrong = "err-00:=AF620010 - El identificador de sesion del websocket es incorrecto";
    assert_eq!(service_call(port, &ca, "echo=-idsession=OTRA@EOF").await, wrong);
    assert!(service_call(port, &ca, &format!("nada=1idsession={SESSION}@EOF")).await.starts_with("err-00:=AF620016"));
    assert!(service_call(port, &ca, &format!("send=@5@1idsession={SESSION}@EOF")).await.starts_with("err-00:=AF401200"));
    let svc = jbase64::encode_url_safe(b"afirma://service?ports=1");
    assert!(service_call(port, &ca, &format!("cmd={svc}idsession={SESSION}@EOF")).await.starts_with("err-00:=AF401200"));
}

#[tokio::test(flavor = "multi_thread")]
async fn service_socket_startup_and_idle() {
    let (pfx, _) = test_tls();
    let tls = TlsSource::Pkcs12Bytes { data: pfx, password: "654321".into() };
    let err = ServiceServer::bind(&channel("afirma://service?v=3"), &tls, ServiceOptions::default()).await.err().unwrap();
    assert_eq!(err.code().unwrap().code, 620013);
    let err = ServiceServer::bind(&channel("afirma://service?ports=0&v=5"), &tls, ServiceOptions::default()).await.err().unwrap();
    assert_eq!(err.code().unwrap().code, 620011);
    let opts = ServiceOptions { idle_timeout: Duration::from_millis(300), ..Default::default() };
    let s = ServiceServer::bind(&channel("afirma://service?ports=0&v=3"), &tls, opts).await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(5), s.serve(make_launcher(FakeHandler::with_key(key("firmante-rsa"))))).await.unwrap();
    assert_eq!(exit, ServerExit::IdleTimeout);
}
