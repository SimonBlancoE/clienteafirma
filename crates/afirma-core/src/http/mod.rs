//! Cliente HTTP de AutoFirma (`es.gob.afirma.core.misc.http`, §9).
//!
//! * [`HttpClient`]: interfaz (equivalente a `UrlHttpManager`) que pueden
//!   implementar otros crates para simular el servidor en sus pruebas.
//! * [`UreqHttpClient`]: implementación real sobre `ureq` que reproduce
//!   `UrlHttpManagerImpl.readUrl`: credenciales en la URL, POST/PUT con la
//!   consulta de la URL como cuerpo `application/x-www-form-urlencoded`,
//!   cabeceras por defecto, tiempos de espera opcionales, almacén de cookies
//!   común a todo el proceso (los servidores trifásicos dependen de la cookie
//!   de sesión), conexión directa para direcciones locales, proxy (del
//!   sistema o configurado), verificación TLS con el almacén del sistema
//!   (incluidas las CA corporativas), certificados de confianza adicionales
//!   (`~/.afirma/TrustedCertsKeystore.jks`), `disableSslChecks` y
//!   `secureDomainsList`, redirecciones como `HttpURLConnection` y
//!   [`HttpError`] para las respuestas 4xx/5xx.
//! * [`install_http_client`] / [`installed_http_client`]: gestor instalado
//!   en el proceso (`UrlHttpManagerFactory`).
//! * [`TrustPrompt`]: gancho para el diálogo interactivo "¿confiar en este
//!   servidor?" (`SSLErrorProcessor`); la interfaz la implementa la aplicación.
//! * `DataDownloader.downloadData` en [`download_data()`].

mod client;
mod proxy;
mod tls;

use std::fmt;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub use client::{UreqHttpClient, clear_process_cookies};
pub use proxy::{CustomProxy, ProxyMode, non_proxy_host_matches, system_proxy};
pub use tls::{certificate_matches_host, certs_to_import, fetch_server_certificates, is_ip_literal};

/// Método HTTP (`UrlHttpMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

impl HttpMethod {
    /// Nombre del método.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuración TLS particular de una petición (`SSLConfig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TlsOverride {
    /// Configuración del cliente (verificación con el almacén del sistema,
    /// salvo `disableSslChecks` o dominio seguro).
    #[default]
    Default,
    /// Se confía en cualquier certificado y nombre de servidor (por ejemplo,
    /// `DataDownloader` con `ignoreSSLSecurity`). Si se indica, la opción
    /// global `disableSslChecks` no se aplica, igual que en Java.
    TrustAll,
}

/// Tratamiento de los errores de confianza TLS (`HttpErrorProcessor` /
/// `SSLErrorProcessor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SslErrorHandling {
    /// El error se devuelve sin más.
    #[default]
    None,
    /// Se intenta recuperar con el diálogo de confianza ([`TrustPrompt`]).
    /// `headless` (parámetros `headless` o `sslOmitImportationDialog`) impide
    /// mostrarlo.
    Interactive { headless: bool },
}

impl SslErrorHandling {
    /// Tratamiento según los parámetros adicionales de la operación
    /// (`new SSLErrorProcessor(extraParams)`).
    pub fn from_extra_params(params: &crate::ExtraParams) -> Self {
        SslErrorHandling::Interactive {
            headless: params.get_bool(crate::constants::EXTRA_PARAM_HEADLESS, false)
                || params.get_bool(crate::constants::EXTRA_PARAM_SSL_OMIT_IMPORTATION_DIALOG, false),
        }
    }
}

/// Petición HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// URL. En POST/PUT, la consulta (`?a=b&c=d`) se envía como cuerpo.
    pub url: String,
    pub method: HttpMethod,
    /// Cabeceras adicionales (se añaden tras las de por defecto).
    pub headers: Vec<(String, String)>,
    /// Tiempo máximo de conexión (`None` = el de la plataforma, sin límite).
    pub connect_timeout: Option<Duration>,
    /// Tiempo máximo de lectura; `None` usa el del cliente
    /// ([`HttpClient::set_read_timeout`]).
    pub read_timeout: Option<Duration>,
    pub tls: TlsOverride,
    pub ssl_error_handling: SslErrorHandling,
}

impl HttpRequest {
    /// Petición sin cabeceras adicionales ni tiempos de espera.
    pub fn new(url: impl Into<String>, method: HttpMethod) -> Self {
        HttpRequest {
            url: url.into(),
            method,
            headers: Vec::new(),
            connect_timeout: None,
            read_timeout: None,
            tls: TlsOverride::Default,
            ssl_error_handling: SslErrorHandling::None,
        }
    }

    /// Petición GET.
    pub fn get(url: impl Into<String>) -> Self {
        Self::new(url, HttpMethod::Get)
    }

    /// Petición POST (la consulta de la URL es el cuerpo).
    pub fn post(url: impl Into<String>) -> Self {
        Self::new(url, HttpMethod::Post)
    }

    /// Añade una cabecera.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Cabeceras `Content-Type` y `Accept` (sobrecargas
    /// `readUrl(url, timeout, contentType, accept, method)`).
    pub fn content_type_and_accept(mut self, content_type: Option<&str>, accept: Option<&str>) -> Self {
        if let Some(ct) = content_type {
            self.headers.push(("Content-Type".into(), ct.into()));
        }
        if let Some(a) = accept {
            self.headers.push(("Accept".into(), a.into()));
        }
        self
    }

    /// Tiempo máximo de conexión. Un valor negativo (`-1`, `DEFAULT_TIMEOUT`)
    /// equivale a no fijarlo.
    pub fn connect_timeout_millis(mut self, millis: i64) -> Self {
        self.connect_timeout = (millis >= 0).then(|| Duration::from_millis(millis as u64));
        self
    }

    /// Tiempo máximo de lectura para esta petición.
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Configuración TLS de la petición.
    pub fn tls(mut self, tls: TlsOverride) -> Self {
        self.tls = tls;
        self
    }

    /// Tratamiento de los errores de confianza TLS.
    pub fn ssl_error_handling(mut self, handling: SslErrorHandling) -> Self {
        self.ssl_error_handling = handling;
        self
    }
}

/// Respuesta HTTP con código de error (`HttpError`, una `IOException`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    /// Código de estado.
    pub status: u16,
    /// Descripción del estado (frase de razón), si la hay.
    pub reason: Option<String>,
    /// Cuerpo de la respuesta de error.
    pub body: Vec<u8>,
    /// URL solicitada (sin credenciales).
    pub url: String,
}

impl fmt::Display for HttpError {
    /// Mensaje de Java: `Error HTTP con codigo  <code>[, cuerpo '<cuerpo>'] y
    /// descripcion '<razón>' para la direccion: <url>` (con dos espacios tras
    /// "codigo" y el cuerpo y la URL recortados a 200 caracteres).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error HTTP con codigo  {}", self.status)?;
        if !self.body.is_empty() {
            write!(f, ", cuerpo '{}'", crate::logging::trim_bytes(&self.body))?;
        }
        write!(
            f,
            " y descripcion '{}' para la direccion: {}",
            self.reason.as_deref().unwrap_or("null"),
            crate::logging::trim_str(&self.url)
        )
    }
}

impl std::error::Error for HttpError {}

/// Error de una petición HTTP.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpClientError {
    /// URL nula, mal formada o con un protocolo no HTTP
    /// (`IllegalArgumentException`/`MalformedURLException`).
    #[error("{0}")]
    InvalidUrl(String),
    /// El servidor respondió con un código 4xx o 5xx.
    #[error("{0}")]
    Http(HttpError),
    /// Tiempo de espera agotado (`SocketTimeoutException`).
    #[error("Tiempo de espera agotado accediendo a {url}: {message}")]
    Timeout { url: String, message: String },
    /// Error en la negociación TLS (`SSLHandshakeException`).
    /// `untrusted_certificate` indica que el certificado del servidor no es de
    /// confianza (y que, por tanto, se puede ofrecer importarlo).
    #[error("Error en la conexion segura con {url}: {message}")]
    Tls { url: String, message: String, untrusted_certificate: bool },
    /// El certificado del servidor no corresponde al dominio
    /// (`InvalidDomainSSLCertificateException`, error 400004).
    #[error("El certificado SSL no se corresponde con el dominio {host} ({url})")]
    InvalidDomainCertificate { url: String, host: String },
    /// Cualquier otro error de entrada/salida (`IOException`).
    #[error("Error de conexion con {url}: {message}")]
    Io { url: String, message: String },
}

impl HttpClientError {
    /// Error HTTP, si lo es.
    pub fn http_error(&self) -> Option<&HttpError> {
        match self {
            Self::Http(e) => Some(e),
            _ => None,
        }
    }

    /// Indica si es un agotamiento del tiempo de espera.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    /// Indica si es un error de negociación TLS.
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls { .. } | Self::InvalidDomainCertificate { .. })
    }
}

/// Gestor de conexiones HTTP (`UrlHttpManager`).
pub trait HttpClient: Send + Sync {
    /// Lee el contenido de una URL (`readUrl`). Las respuestas 4xx/5xx
    /// devuelven [`HttpClientError::Http`].
    fn read_url(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpClientError>;

    /// Fija el tiempo de lectura por defecto del gestor
    /// (`setReadTimeout`). Como en Java, se mantiene para las peticiones
    /// posteriores del proceso.
    fn set_read_timeout(&self, _timeout: Option<Duration>) {}

    /// Tiempo de lectura por defecto del gestor (`getReadTimeout`).
    fn read_timeout(&self) -> Option<Duration> {
        None
    }

    /// Atajo de `readUrl(url, method)`.
    fn read(&self, url: &str, method: HttpMethod) -> Result<Vec<u8>, HttpClientError> {
        self.read_url(&HttpRequest::new(url, method))
    }
}

impl<T: HttpClient + ?Sized> HttpClient for Arc<T> {
    fn read_url(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
        (**self).read_url(request)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) {
        (**self).set_read_timeout(timeout)
    }
    fn read_timeout(&self) -> Option<Duration> {
        (**self).read_timeout()
    }
}

/// `ConnectionConfig.apply`: aplica el tiempo de lectura del parámetro
/// `servicetimeout` (en milisegundos; `-1` = no cambiar) al gestor.
pub fn apply_connection_config(client: &dyn HttpClient, read_timeout_millis: i64) {
    if read_timeout_millis != i64::from(crate::constants::DEFAULT_TIMEOUT) {
        client.set_read_timeout(u64::try_from(read_timeout_millis).ok().map(Duration::from_millis));
    }
}

/// Servidor cuyo certificado no es de confianza (información para el
/// diálogo de confirmación).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedServer {
    /// URL solicitada.
    pub url: String,
    /// Nombre del servidor (para el texto `SSLRequestPermissionDialog.2`).
    pub host: String,
    /// Cadena de certificados presentada por el servidor (DER, primero el
    /// del servidor).
    pub chain: Vec<Vec<u8>>,
    /// Certificados que se importarían: los emisores si la cadena tiene más
    /// de un certificado y, si no, el único certificado.
    pub certs_to_import: Vec<Vec<u8>>,
}

/// Gancho del diálogo "El certificado SSL del dominio %0 no es de confianza.
/// ¿Desea importarlo en su almacén de confianza?" (`SSLErrorProcessor`). La
/// aplicación lo implementa con su interfaz gráfica.
pub trait TrustPrompt: Send + Sync {
    /// Pregunta al usuario. `true` = importar y reintentar.
    fn confirm_trust(&self, server: &UntrustedServer) -> bool;

    /// Guarda de forma persistente los certificados aceptados (por defecto no
    /// hace nada; el cliente los añade a su lista en memoria).
    fn store_trusted(&self, _certs: &[Vec<u8>]) {}
}

/// Configuración del cliente HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSettings {
    /// Proxy a usar.
    pub proxy: ProxyMode,
    /// `disableSslChecks`: no verificar los certificados TLS (preferencia
    /// `secureConnections=false`).
    pub disable_ssl_checks: bool,
    /// `secureDomainsList`: dominios en los que no se verifica TLS (entradas
    /// sin recortar, con `*` al principio y/o al final).
    pub secure_domains: Vec<String>,
    /// Certificados de confianza adicionales a los del sistema (contenido de
    /// `~/.afirma/TrustedCertsKeystore.jks`), en DER.
    pub extra_trusted_certs: Vec<Vec<u8>>,
    /// `blockAutoImportTrustedCerts`: no ofrecer la importación de
    /// certificados de servidores no confiables.
    pub block_auto_import_trusted_certs: bool,
    /// Cabecera `User-Agent`.
    pub user_agent: String,
}

/// `User-Agent` por defecto (Java envía `Java/<versión>`).
pub const DEFAULT_USER_AGENT: &str = concat!("AutoFirma-rs/", env!("CARGO_PKG_VERSION"));

impl Default for HttpSettings {
    fn default() -> Self {
        HttpSettings {
            proxy: ProxyMode::System,
            disable_ssl_checks: false,
            secure_domains: Vec::new(),
            extra_trusted_certs: Vec::new(),
            block_auto_import_trusted_certs: false,
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }
}

impl HttpSettings {
    /// Interpreta el valor de la preferencia/propiedad `secureDomainsList`
    /// (separado por comas, sin recortar; vacío = ninguno).
    pub fn parse_secure_domains(list: &str) -> Vec<String> {
        if list.is_empty() {
            return Vec::new();
        }
        // `String.split(",")` de Java descarta las cadenas vacías finales.
        let mut parts: Vec<String> = list.split(',').map(str::to_string).collect();
        while parts.last().is_some_and(|p| p.is_empty()) {
            parts.pop();
        }
        parts
    }
}

/// `checkIsSecureDomain`: `*x*` → el servidor contiene `x`; `*x` → termina en
/// `x`; `x*` → empieza por `x`; `x` → es igual a `x` (siempre distinguiendo
/// mayúsculas y quitando todos los `*` del patrón).
pub fn is_secure_domain(host: &str, secure_domains: &[String]) -> bool {
    secure_domains.iter().any(|domain| {
        let bare = domain.replace('*', "");
        if domain.starts_with('*') && domain.ends_with('*') {
            host.contains(&bare)
        } else if domain.starts_with('*') {
            host.ends_with(&bare)
        } else if domain.ends_with('*') {
            host.starts_with(&bare)
        } else {
            host == bare
        }
    })
}

/// Separa la URL de destino y el cuerpo de una petición POST/PUT como
/// `StringTokenizer(url, "?")`: el destino es el primer fragmento y el cuerpo
/// el **segundo** (un segundo `?` corta el cuerpo). `None` si no hay `?`.
pub fn split_post_url(url: &str) -> (String, Option<String>) {
    let mut tokens = url.split('?').filter(|t| !t.is_empty());
    let target = tokens.next().unwrap_or("").to_string();
    if url.contains('?') { (target, Some(tokens.next().unwrap_or("").to_string())) } else { (target, None) }
}

/// Credenciales incluidas en la URL (`URLName`): devuelve la URL sin ellas
/// (`proto://host[:puerto]/fichero`, sin el fragmento) y el valor de la
/// cabecera `Authorization: Basic`. Si no hay credenciales, la URL no cambia.
pub fn extract_url_credentials(url: &str) -> Result<(String, Option<String>), HttpClientError> {
    let Some(proto_end) = url.find(':') else { return Ok((url.to_string(), None)) };
    if url.get(proto_end + 1..proto_end + 3) != Some("//") {
        return Ok((url.to_string(), None));
    }
    let protocol = &url[..proto_end];
    let after = &url[proto_end + 3..];
    let (full_host, file) = match after.find('/') {
        Some(i) => (&after[..i], Some(&after[i + 1..])),
        None => (after, None),
    };
    let Some(at) = full_host.find('@') else { return Ok((url.to_string(), None)) };
    let userpass = &full_host[..at];
    let hostport = &full_host[at + 1..];
    let (user, pass) = match userpass.find(':') {
        Some(i) => (Some(&userpass[..i]), Some(&userpass[i + 1..])),
        None => (Some(userpass), None),
    };
    let decode =
        |s: &str| -> Result<String, HttpClientError> { url_name_decode(s).map_err(HttpClientError::InvalidUrl) };
    let user = user.map(decode).transpose()?;
    let pass = pass.map(decode).transpose()?;
    let creds = match (&user, &pass) {
        (Some(u), Some(p)) => format!("{u}:{p}"),
        (Some(u), None) => u.clone(),
        (None, Some(p)) => p.clone(),
        (None, None) => return Ok((url.to_string(), None)),
    };
    let auth = crate::base64::encode(creds.as_bytes());
    // Puerto: tras ']' en IPv6.
    let port_idx = if hostport.starts_with('[') {
        hostport.find(']').and_then(|b| hostport[b..].find(':').map(|i| b + i))
    } else {
        hostport.find(':')
    };
    let (host, port) = match port_idx {
        Some(i) => (&hostport[..i], hostport[i + 1..].parse::<u16>().ok()),
        None => (hostport, None),
    };
    let file = file.map(|f| f.split('#').next().unwrap_or("")).unwrap_or("");
    let port = port.map(|p| format!(":{p}")).unwrap_or_default();
    Ok((format!("{protocol}://{host}{port}/{file}"), Some(auth)))
}

/// `URLName.decode`: `+` → espacio, `%XX` → carácter; el resultado se
/// reinterpreta de ISO-8859-1 a UTF-8.
fn url_name_decode(s: &str) -> Result<String, String> {
    if !s.contains(['+', '%']) {
        return Ok(s.to_string());
    }
    let mut bytes = Vec::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '+' => bytes.push(b' '),
            '%' => {
                let hex = s.get(i + 1..i + 3).ok_or_else(|| format!("Escape no valido en la URL: {s}"))?;
                let v = u8::from_str_radix(hex, 16).map_err(|e| format!("Escape no valido en la URL: {e}"))?;
                bytes.push(v);
                chars.next();
                chars.next();
            }
            c => {
                let mut buf = [0u8; 4];
                // Caracteres no Latin-1: Java los convertiría a '?'.
                if (c as u32) < 0x100 {
                    bytes.push(c as u32 as u8);
                } else {
                    bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Indica si un nombre de servidor es la interfaz local
/// (`InetAddress.getByName(host).isLoopbackAddress()`; si no se puede
/// resolver, no es local).
pub fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    use std::net::ToSocketAddrs;
    (bare, 0u16).to_socket_addrs().ok().and_then(|mut a| a.next()).is_some_and(|a| a.ip().is_loopback())
}

static INSTALLED: OnceLock<RwLock<Option<Arc<dyn HttpClient>>>> = OnceLock::new();

/// Instala el gestor HTTP del proceso (`UrlHttpManagerFactory.install`).
pub fn install_http_client(client: Arc<dyn HttpClient>) {
    let lock = INSTALLED.get_or_init(|| RwLock::new(None));
    if let Ok(mut guard) = lock.write() {
        *guard = Some(client);
    }
}

/// Gestor HTTP instalado; si no hay ninguno se crea (una sola vez) un
/// [`UreqHttpClient`] con la configuración por defecto
/// (`UrlHttpManagerFactory.getInstalledManager`).
pub fn installed_http_client() -> Arc<dyn HttpClient> {
    let lock = INSTALLED.get_or_init(|| RwLock::new(None));
    if let Some(c) = lock.read().ok().and_then(|g| g.as_ref().cloned()) {
        return c;
    }
    let mut guard = match lock.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.get_or_insert_with(|| Arc::new(UreqHttpClient::new(HttpSettings::default()))).clone()
}

/// Error de [`download_data`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DownloadError {
    #[error("La fuente de datos no puede ser nula")]
    NullSource,
    #[error(transparent)]
    Http(#[from] HttpClientError),
    #[error("{0}")]
    Io(String),
}

/// `DataDownloader.downloadData(dataSource, gzipped, ignoreSSLSecurity)`:
///
/// 1. `gzipped` y Base64 → se descomprime (gzip) el Base64 decodificado
///    (alfabeto URL-safe convertido al estándar).
/// 2. `http://`/`https://` (tras recortar) → GET con tratamiento interactivo
///    de errores TLS (y confianza total si `ignore_ssl_security`).
/// 3. `ftp://` → no soportado en esta versión (error).
/// 4. `file:/` → lectura del fichero ([`crate::aoutil::load_file`]).
/// 5. Base64 → datos decodificados (si falla, se sigue).
/// 6. En otro caso, los bytes UTF-8 del propio texto.
pub fn download_data(
    client: &dyn HttpClient,
    data_source: Option<&str>,
    gzipped: bool,
    ignore_ssl_security: bool,
) -> Result<Vec<u8>, DownloadError> {
    let ds = data_source.ok_or(DownloadError::NullSource)?;
    if gzipped && crate::base64::is_base64(ds) {
        let compressed = crate::base64::decode(&ds.replace('_', "/").replace('-', "+"))
            .map_err(|e| DownloadError::Io(e.to_string()))?;
        let mut out = Vec::new();
        use std::io::Read;
        flate2::read::GzDecoder::new(compressed.as_slice())
            .read_to_end(&mut out)
            .map_err(|e| DownloadError::Io(format!("Error descomprimiendo los datos: {e}")))?;
        return Ok(out);
    }
    let trimmed = ds.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let mut req = HttpRequest::get(trimmed).ssl_error_handling(SslErrorHandling::Interactive { headless: false });
        if ignore_ssl_security {
            req = req.tls(TlsOverride::TrustAll);
        }
        return Ok(client.read_url(&req)?);
    }
    if trimmed.starts_with("ftp://") {
        return Err(DownloadError::Io("No se soporta la descarga de datos por FTP".into()));
    }
    if trimmed.starts_with("file:/") {
        let uri = crate::aoutil::create_uri(trimmed).map_err(|e| DownloadError::Io(e.to_string()))?;
        return crate::aoutil::load_file(&uri, client).map_err(|e| DownloadError::Io(e.to_string()));
    }
    if crate::base64::is_base64(ds)
        && let Ok(d) = crate::base64::decode(&ds.replace('_', "/").replace('-', "+")) {
            return Ok(d);
        }
    Ok(ds.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_domains() {
        let d = HttpSettings::parse_secure_domains("*.redsara.*,*.gob.es,intranet*,exacto.es,,");
        assert_eq!(d.len(), 4);
        assert!(is_secure_domain("www.redsara.es", &d));
        assert!(is_secure_domain("sede.gob.es", &d));
        assert!(is_secure_domain("intranet.local", &d));
        assert!(is_secure_domain("exacto.es", &d));
        assert!(!is_secure_domain("EXACTO.es", &d));
        assert!(!is_secure_domain("otro.es", &d));
        // Las entradas no se recortan.
        assert!(!is_secure_domain("exacto.es", &HttpSettings::parse_secure_domains(" exacto.es")));
        assert!(is_secure_domain("cualquiera", &HttpSettings::parse_secure_domains("*")));
        assert!(HttpSettings::parse_secure_domains("").is_empty());
    }

    #[test]
    fn post_splitting() {
        assert_eq!(split_post_url("https://s/tri?op=pre&doc=x"), ("https://s/tri".into(), Some("op=pre&doc=x".into())));
        assert_eq!(split_post_url("https://s/tri?a=1?b=2"), ("https://s/tri".into(), Some("a=1".into())));
        assert_eq!(split_post_url("https://s/tri??a=1"), ("https://s/tri".into(), Some("a=1".into())));
        assert_eq!(split_post_url("https://s/tri"), ("https://s/tri".into(), None));
        assert_eq!(split_post_url("https://s/tri?"), ("https://s/tri".into(), Some(String::new())));
    }

    #[test]
    fn url_credentials() {
        let (u, a) = extract_url_credentials("https://user:p%40ss@host:8443/path/x?y=1#frag").unwrap();
        assert_eq!(u, "https://host:8443/path/x?y=1");
        assert_eq!(a.unwrap(), crate::base64::encode(b"user:p@ss"));
        let (u, a) = extract_url_credentials("http://solo+usuario@host").unwrap();
        assert_eq!(u, "http://host/");
        assert_eq!(a.unwrap(), crate::base64::encode(b"solo usuario"));
        let (u, a) = extract_url_credentials("https://host/a#b").unwrap();
        assert_eq!((u.as_str(), a), ("https://host/a#b", None));
        assert!(extract_url_credentials("http://u:%zz@h/").is_err());
    }

    #[test]
    fn http_error_message() {
        let e = HttpError {
            status: 404,
            reason: Some("Not Found".into()),
            body: b"no existe".to_vec(),
            url: "https://x/y".into(),
        };
        assert_eq!(
            e.to_string(),
            "Error HTTP con codigo  404, cuerpo 'no existe' y descripcion 'Not Found' para la direccion: https://x/y"
        );
        let e = HttpError { status: 500, reason: None, body: Vec::new(), url: "u".into() };
        assert_eq!(e.to_string(), "Error HTTP con codigo  500 y descripcion 'null' para la direccion: u");
    }

    #[test]
    fn loopback() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("localhost"));
        assert!(!is_loopback_host("192.0.2.1"));
        assert!(!is_loopback_host("nombre-que-no-existe.invalid"));
    }

    struct Mock;
    impl HttpClient for Mock {
        fn read_url(&self, request: &HttpRequest) -> Result<Vec<u8>, HttpClientError> {
            Ok(format!("{} {}", request.method, request.url).into_bytes())
        }
    }

    #[test]
    fn data_downloader() {
        let m = Mock;
        assert_eq!(download_data(&m, None, false, false).unwrap_err(), DownloadError::NullSource);
        assert_eq!(download_data(&m, Some(" https://x/d "), false, false).unwrap(), b"GET https://x/d");
        assert_eq!(download_data(&m, Some("aG9sYQ=="), false, false).unwrap(), b"hola");
        assert_eq!(download_data(&m, Some("texto plano!"), false, false).unwrap(), b"texto plano!");
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            enc.write_all(b"comprimido").unwrap();
            enc.finish().unwrap();
        }
        let b64 = crate::base64::encode_url_safe(&gz);
        assert_eq!(download_data(&m, Some(&b64), true, false).unwrap(), b"comprimido");
        assert_eq!(m.read("http://a", HttpMethod::Post).unwrap(), b"POST http://a");
        let dir = std::env::temp_dir().join(format!("afirma-core-dl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("datos.txt");
        std::fs::write(&f, b"fichero").unwrap();
        let url = format!("file://{}", f.to_string_lossy());
        assert_eq!(download_data(&m, Some(&url), false, false).unwrap(), b"fichero");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
