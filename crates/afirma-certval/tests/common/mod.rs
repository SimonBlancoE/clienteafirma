//! Infraestructura de las pruebas: servidor HTTP en 127.0.0.1, respondedor
//! OCSP de OpenSSL (una ejecución de `openssl ocsp -reqin` por petición, sin
//! abrir puertos), `HttpFetcher` que redirige los servidores `*.certval.test`
//! de los certificados de prueba al servidor local y servidor LDAP mínimo.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afirma_certval::{AfirmaHttpFetcher, FetchError, HttpFetcher, Timeouts, ValidationOptions};

/// Directorio `testdata/certval`.
pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certval")
}

/// Contenido de un fichero de `testdata/certval`.
pub fn raw(name: &str) -> Vec<u8> {
    std::fs::read(data_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Certificado de `testdata/certval` en DER.
pub fn cert(name: &str) -> Vec<u8> {
    afirma_certval::parse_certificates(&raw(&format!("{name}.crt")))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{name}.crt no es un certificado"))
}

/// Indica si hay un `openssl` utilizable.
pub fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Petición recibida por el servidor.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Ruta completa (`/<servidor original>/<ruta>`).
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub type Handler = Arc<dyn Fn(&Request) -> (u16, Vec<u8>) + Send + Sync>;

/// Servidor HTTP/1.1 mínimo en 127.0.0.1 (una petición por conexión).
pub struct Server {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Request>>>,
    routes: Arc<Mutex<Vec<(String, Handler)>>>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).ok()? == 0 || buf.len() > 64 * 1024 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

impl Server {
    pub fn start() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let routes: Arc<Mutex<Vec<(String, Handler)>>> = Arc::new(Mutex::new(Vec::new()));
        let (reqs, rts) = (requests.clone(), routes.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (reqs, rts) = (reqs.clone(), rts.clone());
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let Some(req) = read_request(&mut stream) else { return };
                    reqs.lock().unwrap().push(req.clone());
                    let handler = {
                        let routes = rts.lock().unwrap();
                        routes
                            .iter()
                            .filter(|(p, _)| req.path.starts_with(p.as_str()))
                            .max_by_key(|(p, _)| p.len())
                            .map(|(_, h)| h.clone())
                    };
                    let (status, body) = match handler {
                        Some(h) => h(&req),
                        None => (404, b"no encontrado".to_vec()),
                    };
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                });
            }
        });
        Server { addr, requests, routes }
    }

    /// Asocia un manejador a las rutas que empiezan por `prefix`.
    pub fn route(&self, prefix: &str, handler: Handler) {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|(p, _)| p != prefix);
        routes.push((prefix.to_string(), handler));
    }

    /// Sirve un contenido fijo.
    pub fn file(&self, path: &str, data: Vec<u8>) {
        self.route(path, Arc::new(move |_| (200, data.clone())));
    }

    /// Responde siempre con un código de estado.
    pub fn status(&self, path: &str, status: u16) {
        self.route(path, Arc::new(move |_| (status, Vec::new())));
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    pub fn requests_to(&self, prefix: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|r| r.path.starts_with(prefix))
            .collect()
    }
}

fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Petición OCSP DER de una petición HTTP (cuerpo del POST o último
/// segmento de la ruta del GET, RFC 6960 A.1).
pub fn ocsp_request_of(req: &Request) -> Vec<u8> {
    if req.method == "POST" {
        return req.body.clone();
    }
    let last = req.path.rsplit('/').next().unwrap_or("");
    let b64 = String::from_utf8(percent_decode(last)).unwrap();
    afirma_core::base64::decode(&b64).expect("base64 de la peticion OCSP")
}

/// Manejador que responde cada petición OCSP con `openssl ocsp` como
/// respondedor (`index`, CA, firmante y clave de `testdata/certval`).
pub fn openssl_responder(index: &'static str, ca: &'static str, signer: &'static str, key: &'static str) -> Handler {
    Arc::new(move |req| {
        let dir = tempfile::tempdir().unwrap();
        let (reqf, respf) = (dir.path().join("req.der"), dir.path().join("resp.der"));
        std::fs::write(&reqf, ocsp_request_of(req)).unwrap();
        let out = Command::new("openssl")
            .current_dir(data_dir())
            .args([
                "ocsp", "-index", index, "-CA", ca, "-rsigner", signer, "-rkey", key, "-ndays", "1", "-reqin",
            ])
            .arg(&reqf)
            .arg("-respout")
            .arg(&respf)
            .output()
            .expect("openssl ocsp");
        match std::fs::read(&respf) {
            Ok(r) if out.status.success() => (200, r),
            _ => (500, out.stderr),
        }
    })
}

/// Puerto local sin servidor (conexión rechazada).
pub fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// `HttpFetcher` de pruebas: reescribe `http://<servidor>/<ruta>` como
/// `http://127.0.0.1:<puerto>/<servidor>/<ruta>` y descarga con el cliente
/// HTTP real de AutoFirma. Los servidores de `down` van a un puerto cerrado.
/// Con `post` admite POST binario (cliente HTTP/1.1 mínimo). Las URL LDAP
/// se dirigen a `ldap_port`.
pub struct MappingFetcher {
    pub server: SocketAddr,
    pub down: Vec<String>,
    pub closed: u16,
    pub post: bool,
    pub ldap_port: Option<u16>,
    inner: AfirmaHttpFetcher,
}

impl MappingFetcher {
    pub fn new(server: &Server) -> Self {
        MappingFetcher {
            server: server.addr,
            down: vec!["down.certval.test".into()],
            closed: closed_port(),
            post: false,
            ldap_port: None,
            inner: AfirmaHttpFetcher::new(),
        }
    }

    pub fn map(&self, url: &str) -> String {
        let u = url::Url::parse(url).unwrap();
        let host = u.host_str().unwrap_or("").to_string();
        let query = u.query().map(|q| format!("?{q}")).unwrap_or_default();
        if self.down.contains(&host) {
            format!("http://127.0.0.1:{}{}{query}", self.closed, u.path())
        } else {
            format!("http://{}/{host}{}{query}", self.server, u.path())
        }
    }
}

impl HttpFetcher for MappingFetcher {
    fn get(&self, url: &str, accept: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError> {
        self.inner.get(&self.map(url), accept, timeouts)
    }

    fn post(
        &self,
        url: &str,
        content_type: &str,
        accept: &str,
        body: &[u8],
        _timeouts: Timeouts,
    ) -> Result<Vec<u8>, FetchError> {
        if !self.post {
            return Err(FetchError::Unsupported("POST".into()));
        }
        let mapped = url::Url::parse(&self.map(url)).unwrap();
        let addr = format!("{}:{}", mapped.host_str().unwrap(), mapped.port().unwrap());
        let mut s = TcpStream::connect(&addr).map_err(|e| FetchError::Io(e.to_string()))?;
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\nAccept: {accept}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            mapped.path(),
            body.len()
        );
        s.write_all(head.as_bytes())
            .map_err(|e| FetchError::Io(e.to_string()))?;
        s.write_all(body).map_err(|e| FetchError::Io(e.to_string()))?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).map_err(|e| FetchError::Io(e.to_string()))?;
        let split = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(FetchError::Io("respuesta".into()))?;
        let status: u16 = String::from_utf8_lossy(&resp[..split])
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        if status / 100 != 2 {
            return Err(FetchError::Status {
                url: url.into(),
                status,
            });
        }
        Ok(resp[split + 4..].to_vec())
    }

    fn ldap(&self, url: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError> {
        let port = self.ldap_port.unwrap_or(self.closed);
        let rest = url.split_once("://").map(|x| x.1).unwrap_or("");
        let path = rest.split_once('/').map(|x| x.1).unwrap_or("");
        afirma_certval::ldap::fetch_crl(&format!("ldap://127.0.0.1:{port}/{path}"), timeouts)
    }
}

/// Opciones de prueba con el `fetcher` indicado y tiempos cortos.
pub fn options(fetcher: MappingFetcher) -> ValidationOptions {
    ValidationOptions {
        fetcher: Some(Arc::new(fetcher)),
        connect_timeout: Duration::from_secs(3),
        read_timeout: Duration::from_secs(20),
        ..Default::default()
    }
}

/// Servidor con el escenario completo de la CA `ca`: respondedor OCSP en
/// vivo, CRL, certificado del emisor (DER y PKCS#7) y CA EC.
pub fn full_server() -> Server {
    let s = Server::start();
    s.route(
        "/ocsp.certval.test/",
        openssl_responder("index.txt", "ca.crt", "ocsp.crt", "ocsp.key"),
    );
    s.route(
        "/ecocsp.certval.test/",
        openssl_responder("ec_index.txt", "ec_ca.crt", "ec_ca.crt", "ec_ca.key"),
    );
    s.file("/crl.certval.test/ca.crl", raw("ca.crl"));
    s.file("/crl.certval.test/ec_ca.crl", raw("ec_ca.crl"));
    s.file("/aia.certval.test/ca.cer", cert("ca"));
    s.file("/aia.certval.test/ec_ca.cer", cert("ec_ca"));
    s.file("/aia.certval.test/ca.p7c", raw("ca.p7c"));
    s
}

// ---------------------------------------------------------------------------
// Servidor LDAP mínimo
// ---------------------------------------------------------------------------

fn ber_read(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).ok()?;
    let mut msg = head.to_vec();
    let len = if head[1] < 0x80 {
        usize::from(head[1])
    } else {
        let mut lb = vec![0u8; usize::from(head[1] & 0x7f)];
        stream.read_exact(&mut lb).ok()?;
        msg.extend_from_slice(&lb);
        lb.iter().fold(0usize, |a, b| (a << 8) | usize::from(*b))
    };
    let start = msg.len();
    msg.resize(start + len, 0);
    stream.read_exact(&mut msg[start..]).ok()?;
    Some(msg)
}

/// Peticiones de búsqueda recibidas: (DN base, atributos).
pub type LdapLog = Arc<Mutex<Vec<(String, Vec<String>)>>>;

/// Servidor LDAP que devuelve `values` (atributo → valor) para el DN `dn`
/// y `noSuchObject` para cualquier otro.
pub fn ldap_server(dn: &'static str, values: HashMap<String, Vec<u8>>) -> (u16, LdapLog) {
    use afirma_cms::asn1::{Class, Tag, Tlv, der};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: LdapLog = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    let app = |n: u32, c: bool| Tag {
        class: Class::Application,
        constructed: c,
        number: n,
    };
    let result = move |n: u32, id: &[u8], code: u8| {
        let r = der::tlv(
            app(n, true),
            &[
                der::tlv(Tag::universal(10, false), &[code]),
                der::octet_string(b""),
                der::octet_string(b""),
            ]
            .concat(),
        );
        der::sequence([id.to_vec(), r])
    };
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let values = values.clone();
            let log = log2.clone();
            std::thread::spawn(move || {
                while let Some(msg) = ber_read(&mut stream) {
                    let Ok(top) = Tlv::parse_single(&msg) else { return };
                    let Ok(parts) = top.children() else { return };
                    let id = parts[0].raw.to_vec();
                    let op = parts[1];
                    match op.tag.number {
                        0 => {
                            let _ = stream.write_all(&result(1, &id, 0));
                        }
                        3 => {
                            let f = op.children().unwrap();
                            let base = String::from_utf8_lossy(f[0].value).into_owned();
                            let attrs: Vec<String> = f[7]
                                .children()
                                .unwrap()
                                .iter()
                                .map(|a| String::from_utf8_lossy(a.value).into_owned())
                                .collect();
                            log.lock().unwrap().push((base.clone(), attrs.clone()));
                            if base == dn {
                                let pas: Vec<Vec<u8>> = attrs
                                    .iter()
                                    .filter_map(|a| values.get(a).map(|v| (a, v)))
                                    .map(|(a, v)| {
                                        der::sequence([
                                            der::octet_string(a.as_bytes()),
                                            der::set_of([der::octet_string(v)]),
                                        ])
                                    })
                                    .collect();
                                let entry = der::tlv(
                                    app(4, true),
                                    &[der::octet_string(base.as_bytes()), der::sequence(pas)].concat(),
                                );
                                let _ = stream.write_all(&der::sequence([id.clone(), entry]));
                                let _ = stream.write_all(&result(5, &id, 0));
                            } else {
                                let _ = stream.write_all(&result(5, &id, 32));
                            }
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    (port, log)
}
