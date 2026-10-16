//! Implementación de [`HttpClient`] sobre `ureq` (`UrlHttpManagerImpl`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use ureq::tls::{Certificate, RootCerts, TlsConfig};

use super::proxy::resolve_proxy;
use super::{
    HttpClient, HttpClientError, HttpError, HttpMethod, HttpRequest, HttpSettings, SslErrorHandling, TlsOverride,
    TrustPrompt, UntrustedServer, extract_url_credentials, is_loopback_host, is_secure_domain, split_post_url,
};

/// Número máximo de redirecciones (`http.maxRedirects` de Java).
const MAX_REDIRECTS: usize = 20;

/// Cabeceras que `HttpURLConnection` no permite fijar (se descartan).
const RESTRICTED_HEADERS: [&str; 12] = [
    "access-control-request-headers",
    "access-control-request-method",
    "connection",
    "content-length",
    "content-transfer-encoding",
    "host",
    "keep-alive",
    "origin",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TlsMode {
    /// Verificación con el almacén del sistema (incluidas CA corporativas).
    Platform,
    /// Sin verificación (`disableSslChecks`, dominio seguro, `TrustAll`).
    TrustAll,
    /// Verificación con los certificados de confianza propios de AutoFirma.
    ExtraRoots,
}

/// Cliente HTTP de AutoFirma-rs sobre `ureq`.
///
/// Todas las peticiones del proceso (de cualquier cliente) comparten un
/// almacén de cookies en memoria (como el
/// `CookieManager` con `ACCEPT_ALL` que instala AutoFirma Java), que nunca se
/// guarda en disco. Las conexiones verificadas y no verificadas usan agentes
/// distintos para no reutilizar conexiones TLS no verificadas.
pub struct UreqHttpClient {
    settings: RwLock<HttpSettings>,
    read_timeout: RwLock<Option<Duration>>,
    agents: Mutex<HashMap<TlsMode, ureq::Agent>>,
    prompt: RwLock<Option<Arc<dyn TrustPrompt>>>,
}

/// Almacén de cookies del proceso (`CookieHandler.setDefault(new
/// CookieManager(ACCEPT_ALL))`): común a todos los clientes y nunca persistido.
static COOKIES: OnceLock<Mutex<cookie_store::CookieStore>> = OnceLock::new();
/// El usuario rechazó importar un certificado (estático en `SSLErrorProcessor`).
static PREVIOUSLY_CANCELLED: AtomicBool = AtomicBool::new(false);
/// Hay un diálogo de confianza visible (estático en `SSLErrorProcessor`).
static SHOWING_DIALOG: AtomicBool = AtomicBool::new(false);

fn cookie_jar() -> &'static Mutex<cookie_store::CookieStore> {
    COOKIES.get_or_init(|| Mutex::new(cookie_store::CookieStore::default()))
}

/// Vacía el almacén de cookies del proceso.
pub fn clear_process_cookies() {
    if let Ok(mut c) = cookie_jar().lock() {
        c.clear();
    }
}

impl std::fmt::Debug for UreqHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UreqHttpClient").field("settings", &self.settings()).finish_non_exhaustive()
    }
}

fn lock_read<T: Clone>(l: &RwLock<T>) -> T {
    match l.read() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    }
}

impl UreqHttpClient {
    /// Crea un cliente con la configuración indicada.
    pub fn new(settings: HttpSettings) -> Self {
        UreqHttpClient {
            settings: RwLock::new(settings),
            read_timeout: RwLock::new(None),
            agents: Mutex::new(HashMap::new()),
            prompt: RwLock::new(None),
        }
    }

    /// Configuración actual.
    pub fn settings(&self) -> HttpSettings {
        lock_read(&self.settings)
    }

    /// Cambia la configuración (proxy, TLS...). Se descartan las conexiones
    /// abiertas.
    pub fn set_settings(&self, settings: HttpSettings) {
        if let Ok(mut s) = self.settings.write() {
            *s = settings;
        }
        if let Ok(mut a) = self.agents.lock() {
            a.clear();
        }
    }

    /// Instala el diálogo de confianza en servidores no confiables.
    pub fn set_trust_prompt(&self, prompt: Option<Arc<dyn TrustPrompt>>) {
        if let Ok(mut p) = self.prompt.write() {
            *p = prompt;
        }
    }

    /// Añade certificados de confianza (DER) a los del sistema.
    pub fn add_trusted_certificates(&self, certs: &[Vec<u8>]) {
        if let Ok(mut s) = self.settings.write() {
            for c in certs {
                if !s.extra_trusted_certs.contains(c) {
                    s.extra_trusted_certs.push(c.clone());
                }
            }
        }
        if let Ok(mut a) = self.agents.lock() {
            a.remove(&TlsMode::ExtraRoots);
        }
    }

    /// Vacía el almacén de cookies (común a todo el proceso).
    pub fn clear_cookies(&self) {
        clear_process_cookies();
    }

    /// Valor de la cabecera `Cookie` que se enviaría a una URL.
    pub fn cookie_header(&self, url: &str) -> Option<String> {
        let url = url::Url::parse(url).ok()?;
        let store = cookie_jar().lock().ok()?;
        let v: Vec<String> = store.get_request_values(&url).map(|(n, v)| format!("{n}={v}")).collect();
        (!v.is_empty()).then(|| v.join("; "))
    }

    fn store_cookies<'a>(&self, url: &url::Url, set_cookie: impl Iterator<Item = &'a str>) {
        let cookies: Vec<cookie_store::RawCookie<'static>> =
            set_cookie.filter_map(|v| cookie_store::RawCookie::parse(v.to_string()).ok()).collect();
        if cookies.is_empty() {
            return;
        }
        if let Ok(mut store) = cookie_jar().lock() {
            store.store_response_cookies(cookies.into_iter(), url);
        }
    }

    fn agent(&self, mode: TlsMode) -> ureq::Agent {
        let mut agents = match self.agents.lock() {
            Ok(a) => a,
            Err(p) => p.into_inner(),
        };
        if let Some(a) = agents.get(&mode) {
            return a.clone();
        }
        let settings = self.settings();
        let tls = match mode {
            TlsMode::Platform => TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build(),
            TlsMode::TrustAll => TlsConfig::builder().disable_verification(true).build(),
            TlsMode::ExtraRoots => {
                let certs: Vec<Certificate<'static>> =
                    settings.extra_trusted_certs.iter().map(|d| Certificate::from_der(d).to_owned()).collect();
                TlsConfig::builder().root_certs(RootCerts::new_with_certs(&certs)).build()
            }
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .proxy(None)
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(settings.user_agent.as_str())
            .accept_encoding(ureq::config::AutoHeaderValue::None)
            .build()
            .into();
        agents.insert(mode, agent.clone());
        agent
    }

    /// Envía una petición sin seguir redirecciones.
    #[allow(clippy::too_many_arguments)]
    fn send_once(
        &self,
        mode: TlsMode,
        url: &url::Url,
        method: HttpMethod,
        headers: &[(String, String)],
        body: Option<&str>,
        proxy: Option<ureq::Proxy>,
        connect_timeout: Option<Duration>,
        read_timeout: Option<Duration>,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        let agent = self.agent(mode);
        let uri = url.as_str();
        macro_rules! configure {
            ($b:expr) => {{
                let mut b = $b;
                for (k, v) in headers {
                    b = b.header(k.as_str(), v.as_str());
                }
                b.config()
                    .proxy(proxy)
                    .timeout_connect(connect_timeout)
                    .timeout_recv_response(read_timeout)
                    .timeout_recv_body(read_timeout)
                    .build()
            }};
        }
        match method {
            HttpMethod::Get => configure!(agent.get(uri)).call(),
            HttpMethod::Post => {
                let b = configure!(agent.post(uri));
                match body {
                    Some(d) => b.send(d.as_bytes()),
                    None => b.send_empty(),
                }
            }
            HttpMethod::Put => {
                let b = configure!(agent.put(uri));
                match body {
                    Some(d) => b.send(d.as_bytes()),
                    None => b.send_empty(),
                }
            }
        }
    }

    /// `readUrl` sin el tratamiento de errores TLS.
    fn execute(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        if request.url.is_empty() {
            return Err(HttpClientError::InvalidUrl("La URL a leer no puede ser nula".into()));
        }
        let (url, auth) = extract_url_credentials(&request.url)?;
        let (target, mut body) = match request.method {
            HttpMethod::Post | HttpMethod::Put => split_post_url(&url),
            HttpMethod::Get => (url.clone(), None),
        };
        let settings = self.settings();
        let read_timeout = request.read_timeout.or_else(|| lock_read(&self.read_timeout));
        let mut current = url::Url::parse(&target)
            .map_err(|e| HttpClientError::InvalidUrl(format!("URL no valida ({e}): {target}")))?;
        if current.scheme() != "http" && current.scheme() != "https" {
            return Err(HttpClientError::InvalidUrl(format!("Protocolo no soportado: {}", current.scheme())));
        }
        let mut method = request.method;
        let mut headers_base: Vec<(String, String)> = Vec::new();
        let has = |name: &str| request.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
        if let Some(a) = &auth
            && !has("Authorization") {
                headers_base.push(("Authorization".into(), format!("Basic {a}")));
            }
        if !has("Accept") {
            headers_base.push(("Accept".into(), "*/*".into()));
        }
        for (k, v) in &request.headers {
            if RESTRICTED_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
                continue;
            }
            headers_base.push((k.clone(), v.clone()));
        }
        let original_host = current.host_str().unwrap_or("").to_string();

        for _ in 0..=MAX_REDIRECTS {
            let host = current.host_str().unwrap_or("").to_string();
            let https = current.scheme() == "https";
            let mode = if https
                && (request.tls == TlsOverride::TrustAll
                    || is_secure_domain(&host, &settings.secure_domains)
                    || (settings.disable_ssl_checks && request.tls == TlsOverride::Default))
            {
                TlsMode::TrustAll
            } else {
                TlsMode::Platform
            };
            let proxy = if is_loopback_host(&host) {
                None
            } else {
                resolve_proxy(&settings.proxy, current.scheme(), &host).and_then(|p| p.to_ureq())
            };
            let mut headers: Vec<(String, String)> = headers_base
                .iter()
                .filter(|(k, _)| host == original_host || !k.eq_ignore_ascii_case("Authorization"))
                .cloned()
                .collect();
            if body.is_some() && !has("Content-Type") {
                headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
            }
            if !has("Cookie")
                && let Some(c) = self.cookie_header(current.as_str()) {
                    headers.push(("Cookie".into(), c));
                }
            let send = |m: TlsMode| {
                self.send_once(
                    m,
                    &current,
                    method,
                    &headers,
                    body.as_deref(),
                    proxy.clone(),
                    request.connect_timeout,
                    read_timeout,
                )
            };
            let mut result = send(mode);
            // MultiX509TrustManager: si el sistema no confía en el servidor
            // se prueba con los certificados de confianza propios.
            if mode == TlsMode::Platform
                && !settings.extra_trusted_certs.is_empty()
                && matches!(&result, Err(e) if is_untrusted_certificate(e))
            {
                result = send(TlsMode::ExtraRoots);
            }
            let mut resp = result.map_err(|e| map_ureq_error(e, &url))?;
            self.store_cookies(&current, resp.headers().get_all("set-cookie").iter().filter_map(|v| v.to_str().ok()));
            let status = resp.status().as_u16();
            if is_followed_redirect(status)
                && let Some(next) =
                    resp.headers().get("location").and_then(|l| l.to_str().ok()).and_then(|l| current.join(l).ok())
                {
                    // Java no sigue redirecciones que cambian de protocolo.
                    if next.scheme() == current.scheme() {
                        if matches!(method, HttpMethod::Post | HttpMethod::Put) && status != 307 {
                            method = HttpMethod::Get;
                            body = None;
                        }
                        current = next;
                        continue;
                    }
                }
            let data = resp.body_mut().with_config().limit(u64::MAX).read_to_vec();
            let status_str = status.to_string();
            if status_str.starts_with('4') || status_str.starts_with('5') {
                return Err(HttpClientError::Http(HttpError {
                    status,
                    reason: resp.status().canonical_reason().map(str::to_string),
                    body: data.unwrap_or_default(),
                    url: url.clone(),
                }));
            }
            return data.map_err(|e| map_ureq_error(e, &url));
        }
        Err(HttpClientError::Io { url, message: format!("Server redirected too many times ({MAX_REDIRECTS})") })
    }

    /// `SSLErrorProcessor.processHttpError`.
    fn process_ssl_error(
        &self,
        request: &HttpRequest,
        cause: HttpClientError,
        headless: bool,
    ) -> Result<Vec<u8>, HttpClientError> {
        let settings = self.settings();
        let prompt = lock_read(&self.prompt);
        let Some(prompt) = prompt else { return Err(cause) };
        if settings.block_auto_import_trusted_certs || headless || SHOWING_DIALOG.load(Ordering::SeqCst) {
            return Err(cause);
        }
        let (url, _) = extract_url_credentials(&request.url)?;
        let host = url::Url::parse(&url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
        let chain = super::fetch_server_certificates(&url, &settings.proxy, request.connect_timeout)
            .map_err(|message| HttpClientError::Io { url: url.clone(), message })?;
        if !super::certificate_matches_host(&chain[0], &host) {
            return Err(HttpClientError::InvalidDomainCertificate { url, host });
        }
        let to_import = super::certs_to_import(&chain);
        let all_known = to_import.iter().all(|c| settings.extra_trusted_certs.contains(c));
        if !all_known {
            if PREVIOUSLY_CANCELLED.load(Ordering::SeqCst) {
                return Err(cause);
            }
            SHOWING_DIALOG.store(true, Ordering::SeqCst);
            let server =
                UntrustedServer { url: url.clone(), host, chain: chain.clone(), certs_to_import: to_import.clone() };
            let accepted = prompt.confirm_trust(&server);
            SHOWING_DIALOG.store(false, Ordering::SeqCst);
            if !accepted {
                PREVIOUSLY_CANCELLED.store(true, Ordering::SeqCst);
                return Err(cause);
            }
            self.add_trusted_certificates(&to_import);
            prompt.store_trusted(&to_import);
        }
        // Un único reintento, sin tratamiento de errores ni configuración TLS.
        let mut retry = request.clone();
        retry.ssl_error_handling = SslErrorHandling::None;
        retry.tls = TlsOverride::Default;
        self.execute(&retry)
    }

    /// Indica si el usuario rechazó antes importar un certificado
    /// (`SSLErrorProcessor.isCancelled`).
    pub fn trust_previously_cancelled(&self) -> bool {
        PREVIOUSLY_CANCELLED.load(Ordering::SeqCst)
    }
}

impl HttpClient for UreqHttpClient {
    fn read_url(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        match self.execute(request) {
            Err(e @ HttpClientError::Tls { untrusted_certificate: true, .. }) => match request.ssl_error_handling {
                SslErrorHandling::Interactive { headless } => self.process_ssl_error(request, e, headless),
                SslErrorHandling::None => Err(e),
            },
            r => r,
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) {
        if let Ok(mut t) = self.read_timeout.write() {
            *t = timeout;
        }
    }

    fn read_timeout(&self) -> Option<Duration> {
        lock_read(&self.read_timeout)
    }
}

/// Redirecciones que sigue `HttpURLConnection`: 300-307 salvo 304, 305 y 306.
fn is_followed_redirect(status: u16) -> bool {
    (300..=307).contains(&status) && !matches!(status, 304..=306)
}

fn rustls_error(e: &ureq::Error) -> Option<&rustls::Error> {
    match e {
        ureq::Error::Rustls(r) => Some(r),
        ureq::Error::Io(io) => io.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()),
        _ => None,
    }
}

fn is_untrusted_certificate(e: &ureq::Error) -> bool {
    matches!(rustls_error(e), Some(rustls::Error::InvalidCertificate(_)))
}

fn map_ureq_error(e: ureq::Error, url: &str) -> HttpClientError {
    let url = url.to_string();
    if let Some(r) = rustls_error(&e) {
        return HttpClientError::Tls {
            url,
            message: r.to_string(),
            untrusted_certificate: matches!(r, rustls::Error::InvalidCertificate(_)),
        };
    }
    match e {
        ureq::Error::Timeout(t) => HttpClientError::Timeout { url, message: t.to_string() },
        ureq::Error::Io(io) if matches!(io.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => {
            HttpClientError::Timeout { url, message: io.to_string() }
        }
        ureq::Error::Tls(m) => HttpClientError::Tls { url, message: m.to_string(), untrusted_certificate: false },
        ureq::Error::BadUri(m) => HttpClientError::InvalidUrl(m),
        ureq::Error::HostNotFound => HttpClientError::Io { url, message: "No se encuentra el servidor".into() },
        other => HttpClientError::Io { url, message: other.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// Petición recibida por el servidor de pruebas.
    #[derive(Debug, Clone)]
    struct Received {
        line: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Received {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
    }

    /// Servidor HTTP mínimo: atiende `n` conexiones con las respuestas dadas
    /// (una por conexión) y devuelve las peticiones recibidas.
    fn serve(responses: Vec<String>) -> (String, std::thread::JoinHandle<Vec<Received>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut out = Vec::new();
            for resp in responses {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end().to_string();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    headers.push((k.trim().to_string(), v.trim().to_string()));
                }
                let len: usize = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.parse().unwrap())
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                reader.read_exact(&mut body).unwrap();
                let mut s = stream;
                s.write_all(resp.as_bytes()).unwrap();
                s.flush().unwrap();
                out.push(Received {
                    line: line.trim_end().to_string(),
                    headers,
                    body: String::from_utf8(body).unwrap(),
                });
            }
            out
        });
        (addr, handle)
    }

    fn resp(status: &str, extra: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len())
    }

    #[test]
    fn post_query_as_form_body_and_cookies() {
        let (base, h) = serve(vec![
            resp("200 OK", "Set-Cookie: JSESSIONID=abc123; Path=/\r\n", "OK NEWID=1"),
            resp("200 OK", "", "segunda"),
        ]);
        let client =
            UreqHttpClient::new(HttpSettings { proxy: super::super::ProxyMode::None, ..HttpSettings::default() });
        let r = client.read_url(&HttpRequest::post(format!("{base}/tri?op=pre&doc=QUJD&x=1?ignorado"))).unwrap();
        assert_eq!(r, b"OK NEWID=1");
        let r = client.read_url(&HttpRequest::get(format!("{base}/otro?a=b"))).unwrap();
        assert_eq!(r, b"segunda");
        let reqs = h.join().unwrap();
        assert_eq!(reqs[0].line, "POST /tri HTTP/1.1");
        assert_eq!(reqs[0].body, "op=pre&doc=QUJD&x=1");
        assert_eq!(reqs[0].header("Content-Type"), Some("application/x-www-form-urlencoded"));
        assert_eq!(reqs[0].header("Accept"), Some("*/*"));
        assert_eq!(reqs[1].line, "GET /otro?a=b HTTP/1.1");
        assert_eq!(reqs[1].header("Cookie"), Some("JSESSIONID=abc123"));
        assert!(client.cookie_header(&format!("{base}/")).is_some());
        client.clear_cookies();
        assert!(client.cookie_header(&format!("{base}/")).is_none());
    }

    #[test]
    fn http_errors_redirects_and_headers() {
        let (base, h) = serve(vec![
            resp("302 Found", "Location: /destino\r\n", ""),
            resp("200 OK", "", "fin"),
            resp("404 Not Found", "", "no existe"),
        ]);
        let client =
            UreqHttpClient::new(HttpSettings { proxy: super::super::ProxyMode::None, ..HttpSettings::default() });
        let req = HttpRequest::post(format!("{base}/inicio?a=1"))
            .header("Content-Type", "text/plain")
            .header("Host", "ignorado")
            .header("X-Prueba", "1");
        assert_eq!(client.read_url(&req).unwrap(), b"fin");
        let auth_url = base.replace("http://", "http://usuario:clave@");
        let err = client.read_url(&HttpRequest::get(format!("{auth_url}/falta"))).unwrap_err();
        let reqs = h.join().unwrap();
        assert_eq!(reqs[0].line, "POST /inicio HTTP/1.1");
        assert_eq!(reqs[0].header("Content-Type"), Some("text/plain"));
        assert_eq!(reqs[0].header("X-Prueba"), Some("1"));
        assert_ne!(reqs[0].header("Host"), Some("ignorado"));
        // 302 tras POST → GET sin cuerpo.
        assert_eq!(reqs[1].line, "GET /destino HTTP/1.1");
        assert_eq!(reqs[1].body, "");
        assert_eq!(
            reqs[2].header("Authorization"),
            Some(format!("Basic {}", crate::base64::encode(b"usuario:clave")).as_str())
        );
        let HttpClientError::Http(e) = err else { panic!("{err:?}") };
        assert_eq!(e.status, 404);
        assert_eq!(e.body, b"no existe");
        assert_eq!(e.reason.as_deref(), Some("Not Found"));
        assert_eq!(e.url, format!("{base}/falta"));
    }

    #[test]
    fn timeouts_and_invalid_urls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}/lento", listener.local_addr().unwrap());
        let t = std::thread::spawn(move || {
            let (_s, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(800));
        });
        let client =
            UreqHttpClient::new(HttpSettings { proxy: super::super::ProxyMode::None, ..HttpSettings::default() });
        client.set_read_timeout(Some(Duration::from_millis(200)));
        assert_eq!(client.read_timeout(), Some(Duration::from_millis(200)));
        let err = client.read_url(&HttpRequest::get(addr)).unwrap_err();
        assert!(err.is_timeout(), "{err:?}");
        t.join().unwrap();
        assert!(matches!(client.read_url(&HttpRequest::get("")), Err(HttpClientError::InvalidUrl(_))));
        assert!(matches!(client.read_url(&HttpRequest::get("ftp://x/y")), Err(HttpClientError::InvalidUrl(_))));
        assert!(matches!(client.read_url(&HttpRequest::get("no es una url")), Err(HttpClientError::InvalidUrl(_))));
        super::super::apply_connection_config(&client, -1);
        assert_eq!(client.read_timeout(), Some(Duration::from_millis(200)));
        super::super::apply_connection_config(&client, 5000);
        assert_eq!(client.read_timeout(), Some(Duration::from_millis(5000)));
    }

    /// Servidor HTTPS de pruebas con un certificado autofirmado para
    /// `localhost`. Atiende conexiones hasta que termina el proceso.
    fn tls_server() -> (u16, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = ck.cert.der().to_vec();
        let key_der = ck.signing_key.serialize_der();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = config.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let Ok(conn) = rustls::ServerConnection::new(config) else { return };
                    let mut tls = rustls::StreamOwned::new(conn, stream);
                    let mut reader = BufReader::new(&mut tls);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => return,
                            Ok(_) if line.trim_end().is_empty() => break,
                            Ok(_) => {}
                        }
                    }
                    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsegura");
                    let _ = tls.flush();
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        (port, cert_der)
    }

    struct Prompt {
        accept: bool,
        asked: Mutex<Vec<UntrustedServer>>,
        stored: Mutex<Vec<Vec<u8>>>,
    }

    impl TrustPrompt for Prompt {
        fn confirm_trust(&self, server: &UntrustedServer) -> bool {
            self.asked.lock().unwrap().push(server.clone());
            self.accept
        }
        fn store_trusted(&self, certs: &[Vec<u8>]) {
            self.stored.lock().unwrap().extend_from_slice(certs);
        }
    }

    #[test]
    fn tls_trust_modes_and_prompt() {
        let (port, cert) = tls_server();
        let url = format!("https://localhost:{port}/servicio");
        let base = HttpSettings { proxy: super::super::ProxyMode::None, ..HttpSettings::default() };
        let client = UreqHttpClient::new(base.clone());
        // Certificado autofirmado: el almacén del sistema no confía en él.
        let err = client.read_url(&HttpRequest::get(url.clone())).unwrap_err();
        assert!(matches!(err, HttpClientError::Tls { untrusted_certificate: true, .. }), "{err:?}");
        // Sin diálogo instalado, el tratamiento interactivo devuelve el error.
        let interactive =
            HttpRequest::get(url.clone()).ssl_error_handling(SslErrorHandling::Interactive { headless: false });
        assert!(client.read_url(&interactive).is_err());
        // Confianza total, dominio seguro y disableSslChecks.
        assert_eq!(client.read_url(&HttpRequest::get(url.clone()).tls(TlsOverride::TrustAll)).unwrap(), b"segura");
        let secure = UreqHttpClient::new(HttpSettings { secure_domains: vec!["local*".into()], ..base.clone() });
        assert_eq!(secure.read_url(&HttpRequest::get(url.clone())).unwrap(), b"segura");
        let disabled = UreqHttpClient::new(HttpSettings { disable_ssl_checks: true, ..base.clone() });
        assert_eq!(disabled.read_url(&HttpRequest::get(url.clone())).unwrap(), b"segura");
        // Certificados de confianza propios (MultiX509TrustManager).
        let extra = UreqHttpClient::new(HttpSettings { extra_trusted_certs: vec![cert.clone()], ..base.clone() });
        assert_eq!(extra.read_url(&HttpRequest::get(url.clone())).unwrap(), b"segura");
        // Cadena del servidor sin verificar.
        let chain = super::super::fetch_server_certificates(&url, &super::super::ProxyMode::None, None).unwrap();
        assert_eq!(chain, vec![cert.clone()]);
        assert!(super::super::certificate_matches_host(&cert, "localhost"));
        assert!(!super::super::certificate_matches_host(&cert, "otro.es"));
        // Diálogo de confianza aceptado: se importa el certificado y se reintenta.
        let prompt = Arc::new(Prompt { accept: true, asked: Mutex::new(Vec::new()), stored: Mutex::new(Vec::new()) });
        client.set_trust_prompt(Some(prompt.clone()));
        let headless =
            HttpRequest::get(url.clone()).ssl_error_handling(SslErrorHandling::Interactive { headless: true });
        assert!(client.read_url(&headless).is_err());
        assert!(prompt.asked.lock().unwrap().is_empty());
        assert_eq!(client.read_url(&interactive).unwrap(), b"segura");
        assert_eq!(prompt.asked.lock().unwrap()[0].host, "localhost");
        assert_eq!(prompt.asked.lock().unwrap()[0].certs_to_import, vec![cert.clone()]);
        assert_eq!(*prompt.stored.lock().unwrap(), vec![cert.clone()]);
        assert!(client.settings().extra_trusted_certs.contains(&cert));
        // Ya es de confianza: sin diálogo.
        assert_eq!(client.read_url(&HttpRequest::get(url.clone())).unwrap(), b"segura");
        // Dominio que no corresponde al certificado (127.0.0.1): error 400004.
        let by_ip = HttpRequest::get(format!("https://127.0.0.1:{port}/"))
            .ssl_error_handling(SslErrorHandling::Interactive { headless: false });
        let other = UreqHttpClient::new(base.clone());
        other.set_trust_prompt(Some(prompt.clone()));
        assert!(matches!(other.read_url(&by_ip), Err(HttpClientError::InvalidDomainCertificate { .. })));
        // Rechazo: se recuerda para todo el proceso.
        let reject = Arc::new(Prompt { accept: false, asked: Mutex::new(Vec::new()), stored: Mutex::new(Vec::new()) });
        let fresh = UreqHttpClient::new(base);
        fresh.set_trust_prompt(Some(reject.clone()));
        assert!(fresh.read_url(&interactive).is_err());
        assert!(fresh.trust_previously_cancelled());
        assert!(fresh.read_url(&interactive).is_err());
        assert_eq!(reject.asked.lock().unwrap().len(), 1);
    }

    #[test]
    fn redirect_rules() {
        assert!(is_followed_redirect(301));
        assert!(is_followed_redirect(307));
        assert!(!is_followed_redirect(304));
        assert!(!is_followed_redirect(305));
        assert!(!is_followed_redirect(308));
        assert!(!is_followed_redirect(200));
    }
}
