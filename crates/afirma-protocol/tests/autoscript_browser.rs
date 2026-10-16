//! Prueba con el `autoscript.js` REAL (AutoScript 1.10.1) en un Chromium sin
//! interfaz: una página mínima llama a `AutoScript.sign` y
//! `AutoScript.selectCertificate` y nuestro servidor WebSocket atiende las
//! peticiones (eco, `#wait`/`getresult`, respuesta).
//!
//! Opcional: `AFIRMA_BROWSER_IT=1` (y `CHROMIUM`, por defecto `chromium`).
//! El navegador no puede lanzar `afirma://websocket`, así que el servidor se
//! arranca antes, en el puerto que la página fija con `setPortRange`, sin
//! identificador de sesión (Java tampoco lo comprueba en ese caso).

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use afirma_protocol::channel::ChannelRequest;
use afirma_protocol::query::Params;
use afirma_protocol::websocket::{WebSocketOptions, WebSocketServer};
use afirma_protocol::{HttpClient, LauncherConfig, ProtocolLauncher, TlsSource, jbase64};
use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_pfx() -> Vec<u8> {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    p.distinguished_name.push(DnType::CommonName, "127.0.0.1");
    let cert = p.self_signed(&key).unwrap();
    let chain = p12_keystore::PrivateKeyChain::new(
        b"socket".to_vec(),
        p12_keystore::PrivateKey::from_der(&key.serialize_der()).unwrap(),
        vec![p12_keystore::Certificate::from_der(cert.der()).unwrap()],
    );
    let mut ks = p12_keystore::KeyStore::new();
    ks.add_entry("SocketAutoFirma", p12_keystore::KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer("654321").write().unwrap()
}

const PAGE: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><script src="autoscript.js"></script></head><body><script>
function report(o) { return fetch('/result', { method: 'POST', body: JSON.stringify(o) }); }
AutoScript.setPortRange(__PORT__, __PORT__);
AutoScript.cargarAppAfirma();
AutoScript.sign('SG9sYQ==', 'SHA256withRSA', 'CAdES', 'mode=implicit',
  function (sig, cert, extra) {
    report({ op: 'sign', ok: true, sig: sig, cert: cert }).then(function () {
      AutoScript.selectCertificate('', function (cert2) { report({ op: 'selectcert', ok: true, cert: cert2 }); },
        function (t, m) { report({ op: 'selectcert', ok: false, type: t, msg: m }); });
    });
  },
  function (t, m) { report({ op: 'sign', ok: false, type: t, msg: m }); });
</script></body></html>"#;

async fn http_server(
    listener: tokio::net::TcpListener,
    page: String,
    script: Vec<u8>,
    results: Arc<Mutex<Vec<String>>>,
) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        let page = page.clone();
        let script = script.clone();
        let results = results.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let (head_end, len) = loop {
                let n = s.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    break (p + 4, len);
                }
            };
            while buf.len() < head_end + len {
                let n = s.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let line = String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == b'\r').unwrap_or(0)]).to_string();
            let (ctype, body): (&str, Vec<u8>) = if line.starts_with("GET /page.html") {
                ("text/html; charset=utf-8", page.into_bytes())
            } else if line.starts_with("GET /autoscript.js") {
                ("application/javascript", script)
            } else if line.starts_with("POST /result") {
                results
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[head_end..]).into_owned());
                ("text/plain", b"ok".to_vec())
            } else {
                ("text/plain", Vec::new())
            };
            let status = if body.is_empty() && !line.starts_with("POST") {
                "404 Not Found"
            } else {
                "200 OK"
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
        });
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn real_autoscript_in_headless_chromium() {
    if std::env::var("AFIRMA_BROWSER_IT").ok().as_deref() != Some("1") {
        eprintln!("Prueba omitida: defina AFIRMA_BROWSER_IT=1");
        return;
    }
    let k = key("firmante-rsa");
    let handler = FakeHandler::with_key(k.clone());
    let http = MockHttp::new(|_| Ok((404, vec![])));
    let launcher = Arc::new(ProtocolLauncher::new(
        handler.clone(),
        Arc::new(FakeSigner::default()),
        LauncherConfig::new(HttpClient::new(http)),
    ));
    // Servidor WebSocket como lo abriría `afirma://websocket?ports=P&v=4&jvc=4`.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let req = ChannelRequest::from_params(
        &Params::from_query(&format!("afirma://websocket?ports={port}&v=4&jvc=4")),
        4,
    );
    let tls = TlsSource::Pkcs12Bytes {
        data: test_pfx(),
        password: "654321".into(),
    };
    let opts = WebSocketOptions {
        idle_timeout: Duration::from_secs(90),
        ..Default::default()
    };
    let server = WebSocketServer::bind(&req, &tls, opts).await.unwrap();
    let serve = tokio::spawn(server.serve(launcher));
    // Página y autoscript.js.
    let script = std::fs::read(testdata(
        "../afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js",
    ))
    .unwrap();
    let web = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_port = web.local_addr().unwrap().port();
    let results = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(http_server(
        web,
        PAGE.replace("__PORT__", &port.to_string()),
        script,
        results.clone(),
    ));
    let profile = tempfile::tempdir().unwrap();
    let chromium = std::env::var("CHROMIUM").unwrap_or_else(|_| "chromium".into());
    let mut browser = tokio::process::Command::new(chromium)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--ignore-certificate-errors",
            "--no-first-run",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg(format!("http://127.0.0.1:{web_port}/page.html"))
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("chromium");
    let mut done = false;
    for _ in 0..600 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if results.lock().unwrap().len() >= 2 {
            done = true;
            break;
        }
    }
    let _ = browser.kill().await;
    let results = results.lock().unwrap().clone();
    assert!(done, "resultados recibidos: {results:?}");
    let sign: serde_json::Value = serde_json::from_str(&results[0]).unwrap();
    assert_eq!(sign["op"], "sign");
    assert_eq!(sign["ok"], true, "{sign}");
    // AutoScript devuelve el certificado y la firma en Base64 estándar.
    assert_eq!(
        jbase64::decode(sign["cert"].as_str().unwrap()).unwrap(),
        k.certificate()
    );
    let sig = jbase64::decode(sign["sig"].as_str().unwrap()).unwrap();
    let alg =
        afirma_core::SignatureAlgorithm::new(afirma_core::DigestAlgorithm::Sha256, afirma_core::KeyAlgorithm::Rsa);
    assert_eq!(
        afirma_protocol::pkcs1::verify(k.certificate(), alg, b"Hola", &sig),
        afirma_protocol::pkcs1::Verification::Valid
    );
    let sel: serde_json::Value = serde_json::from_str(&results[1]).unwrap();
    assert_eq!(sel["ok"], true, "{sel}");
    assert_eq!(jbase64::decode(sel["cert"].as_str().unwrap()).unwrap(), k.certificate());
    // El origen de la página llegó al manejador.
    let origin = handler.cert_requests.lock().unwrap()[0]
        .1
        .origin
        .display()
        .map(str::to_string);
    assert_eq!(origin.as_deref(), Some(format!("http://127.0.0.1:{web_port}").as_str()));
    serve.abort();
}
