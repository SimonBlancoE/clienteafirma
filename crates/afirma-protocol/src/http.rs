//! Acceso HTTP del protocolo sobre el gestor HTTP común de AutoFirma-rs
//! ([`afirma_core::http::HttpClient`], equivalente a `UrlHttpManager`).
//!
//! El gestor común reproduce `UrlHttpManagerImpl.readUrl` (cuerpo POST
//! tomado de la consulta de la URL, cookies de proceso, proxy, confianza
//! TLS, diálogo de importación de certificados...). Aquí solo se añade:
//! - tiempos de espera por operación (no se fijan en el gestor compartido
//!   como hacía Java, para que no afecten a operaciones posteriores);
//! - el tratamiento interactivo de errores TLS cuando Java lo usaba;
//! - un tipo de error propio con la clasificación que necesitan los códigos
//!   de error del protocolo.

use std::sync::Arc;
use std::time::Duration;

use afirma_core::http::{HttpClient as CoreHttpClient, HttpClientError, HttpMethod, HttpRequest, SslErrorHandling};

/// Método HTTP.
pub type Method = HttpMethod;

/// Error de una llamada HTTP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// Estado 4xx/5xx (`HttpError` de Java).
    #[error("Error HTTP con codigo  {code}{} y descripcion '{reason}' para la direccion: {url}", body_suffix(.body))]
    Status {
        code: u16,
        reason: String,
        body: Vec<u8>,
        url: String,
    },
    /// Tiempo de espera agotado (`SocketTimeoutException`).
    #[error("tiempo de espera agotado: {0}")]
    Timeout(String),
    /// El certificado SSL del servidor no está expedido para el host
    /// (`InvalidDomainSSLCertificateException`, código 400004).
    #[error("el certificado SSL no está expedido para el dominio {host}: {detail}")]
    CertificateHostMismatch { host: String, detail: String },
    /// Error en la negociación TLS (`SSLHandshakeException`).
    #[error("error TLS: {0}")]
    Tls(String),
    /// URL no válida.
    #[error("URL no válida: {0}")]
    InvalidUrl(String),
    /// Otro error de E/S.
    #[error("error de E/S: {0}")]
    Io(String),
}

fn body_suffix(body: &[u8]) -> String {
    let t = String::from_utf8_lossy(body);
    let t = t.trim();
    if t.is_empty() {
        String::new()
    } else {
        format!(", cuerpo '{t}'")
    }
}

impl HttpError {
    pub fn is_timeout(&self) -> bool {
        matches!(self, HttpError::Timeout(_))
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            HttpError::Status { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl From<HttpClientError> for HttpError {
    fn from(e: HttpClientError) -> Self {
        match e {
            HttpClientError::Http(h) => HttpError::Status {
                code: h.status,
                reason: h.reason.unwrap_or_default(),
                body: h.body,
                url: h.url,
            },
            HttpClientError::Timeout { url, message } => HttpError::Timeout(format!("{url}: {message}")),
            HttpClientError::InvalidDomainCertificate { url, host } => {
                HttpError::CertificateHostMismatch { host, detail: url }
            }
            HttpClientError::Tls { url, message, .. } => HttpError::Tls(format!("{url}: {message}")),
            HttpClientError::InvalidUrl(m) => HttpError::InvalidUrl(m),
            HttpClientError::Io { url, message } => HttpError::Io(format!("{url}: {message}")),
        }
    }
}

/// Host de una URL `esquema://[usuario@]host[:puerto]/...`.
pub fn host_of(url: &str) -> Option<String> {
    let rest = &url[url.find("://")? + 3..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        format!("[{}]", stripped.split(']').next().unwrap_or(""))
    } else {
        hostport.split(':').next().unwrap_or("").to_string()
    };
    Some(host)
}

/// Cliente HTTP del protocolo (gestor común + opciones de la operación).
#[derive(Clone)]
pub struct HttpClient {
    inner: Arc<dyn CoreHttpClient>,
    /// Tiempo de espera de lectura (`servicetimeout`); `None` = el del gestor.
    pub read_timeout: Option<Duration>,
    /// Tiempo de espera de conexión; `None` = sin límite.
    pub connect_timeout: Option<Duration>,
    /// Tratamiento de errores TLS (`SSLErrorProcessor`).
    pub ssl_error_handling: SslErrorHandling,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("read_timeout", &self.read_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new(inner: Arc<dyn CoreHttpClient>) -> Self {
        HttpClient {
            inner,
            read_timeout: None,
            connect_timeout: None,
            ssl_error_handling: SslErrorHandling::None,
        }
    }

    /// Cliente sobre el gestor instalado en el proceso
    /// ([`afirma_core::http::installed_http_client`]).
    pub fn installed() -> Self {
        Self::new(afirma_core::http::installed_http_client())
    }

    pub fn inner(&self) -> &Arc<dyn CoreHttpClient> {
        &self.inner
    }

    /// Copia con otro tiempo de espera de lectura.
    pub fn with_read_timeout(&self, t: Option<Duration>) -> Self {
        let mut c = self.clone();
        c.read_timeout = t;
        c
    }

    /// Copia con otro tiempo de espera de conexión.
    pub fn with_connect_timeout(&self, t: Option<Duration>) -> Self {
        let mut c = self.clone();
        c.connect_timeout = t;
        c
    }

    /// Copia con otro tratamiento de errores TLS.
    pub fn with_ssl_error_handling(&self, h: SslErrorHandling) -> Self {
        let mut c = self.clone();
        c.ssl_error_handling = h;
        c
    }

    /// `readUrl(url, method)`: en POST/PUT la consulta de la URL es el cuerpo.
    /// Los estados 4xx/5xx se devuelven como [`HttpError::Status`].
    pub fn read_url(&self, url: &str, method: Method) -> Result<Vec<u8>, HttpError> {
        let mut req = HttpRequest::new(url, method).ssl_error_handling(self.ssl_error_handling);
        req.connect_timeout = self.connect_timeout;
        req.read_timeout = self.read_timeout;
        self.inner.read_url(&req).map_err(HttpError::from)
    }

    /// POST de un cuerpo ya construido (`readUrl(url + "?" + body, POST)`).
    pub fn post(&self, url: &str, body: &str) -> Result<Vec<u8>, HttpError> {
        self.read_url(&format!("{url}?{body}"), Method::Post)
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Gestor HTTP simulado para las pruebas.
    use super::*;
    use std::sync::Mutex;

    /// Petición registrada por el simulador (URL sin consulta y cuerpo).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Recorded {
        pub method: Method,
        pub url: String,
        pub body: Option<Vec<u8>>,
        pub connect_timeout: Option<Duration>,
        pub read_timeout: Option<Duration>,
        pub ssl: SslErrorHandling,
    }

    pub struct Reply {
        pub status: u16,
        pub body: Vec<u8>,
    }

    type Handler = Box<dyn Fn(&Recorded) -> Result<Reply, HttpClientError> + Send + Sync>;

    pub struct MockTransport {
        pub requests: Mutex<Vec<Recorded>>,
        handler: Handler,
    }

    impl MockTransport {
        pub fn new(handler: impl Fn(&Recorded) -> Result<Reply, HttpClientError> + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(MockTransport {
                requests: Mutex::new(Vec::new()),
                handler: Box::new(handler),
            })
        }

        pub fn bodies(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| String::from_utf8_lossy(r.body.as_deref().unwrap_or(&[])).into_owned())
                .collect()
        }
    }

    impl CoreHttpClient for MockTransport {
        fn read_url(&self, req: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
            let (url, body) = match (req.method, &req.body) {
                (HttpMethod::Get, _) => (req.url.clone(), None),
                // Cuerpo explícito (peticiones de Android).
                (_, Some(b)) => (req.url.clone(), Some(b.clone())),
                _ => {
                    let (u, b) = afirma_core::http::split_post_url(&req.url);
                    (u, Some(b.unwrap_or_default().into_bytes()))
                }
            };
            let rec = Recorded {
                method: req.method,
                url,
                body,
                connect_timeout: req.connect_timeout,
                read_timeout: req.read_timeout,
                ssl: req.ssl_error_handling,
            };
            self.requests.lock().unwrap().push(rec.clone());
            let reply = (self.handler)(&rec)?;
            if reply.status >= 400 {
                return Err(HttpClientError::Http(afirma_core::http::HttpError {
                    status: reply.status,
                    reason: Some("X".into()),
                    body: reply.body,
                    url: rec.url,
                }));
            }
            Ok(reply.body)
        }
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> Result<Reply, HttpClientError> {
        Ok(Reply {
            status: 200,
            body: body.into(),
        })
    }

    pub fn status(code: u16) -> Result<Reply, HttpClientError> {
        Ok(Reply {
            status: code,
            body: b"err".to_vec(),
        })
    }

    pub fn timeout() -> Result<Reply, HttpClientError> {
        Err(HttpClientError::Timeout {
            url: "u".into(),
            message: "t".into(),
        })
    }

    #[allow(dead_code)]
    pub fn io_error() -> Result<Reply, HttpClientError> {
        Err(HttpClientError::Io {
            url: "u".into(),
            message: "conexion rehusada".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn post_body_from_query() {
        let t = MockTransport::new(|_| ok("R"));
        let c = HttpClient::new(t.clone());
        assert_eq!(
            c.read_url("https://h/s?op=put&v=1_0?ignored", Method::Post).unwrap(),
            b"R"
        );
        let reqs = t.requests.lock().unwrap();
        assert_eq!(reqs[0].url, "https://h/s");
        assert_eq!(reqs[0].body.as_deref(), Some(&b"op=put&v=1_0"[..]));
    }

    #[test]
    fn status_errors() {
        let t = MockTransport::new(|_| status(503));
        let c = HttpClient::new(t);
        let e = c.read_url("https://h/s?x", Method::Post).unwrap_err();
        assert_eq!(e.status(), Some(503));
        assert!(e.to_string().starts_with("Error HTTP con codigo  503, cuerpo 'err'"));
        let c = HttpClient::new(MockTransport::new(|_| timeout()));
        assert!(c.read_url("https://h/s", Method::Get).unwrap_err().is_timeout());
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://user:pw@www.a.es:8443/x?y").as_deref(),
            Some("www.a.es")
        );
        assert_eq!(host_of("http://[::1]:80/").as_deref(), Some("[::1]"));
        assert_eq!(host_of("nada"), None);
    }
}
