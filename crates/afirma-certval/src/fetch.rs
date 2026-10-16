//! Descarga de respuestas OCSP, CRL y certificados de emisor.
//!
//! [`HttpFetcher`] se puede sustituir (por ejemplo, en pruebas) a través de
//! [`crate::ValidationOptions::fetcher`]. La implementación por defecto,
//! [`AfirmaHttpFetcher`], usa el cliente HTTP instalado en el proceso
//! ([`afirma_core::http::installed_http_client`]), de modo que se aplican el
//! proxy, la verificación TLS y los certificados de confianza configurados
//! por el usuario.

use std::sync::Arc;
use std::time::Duration;

use afirma_core::http::{HttpClient, HttpClientError, HttpRequest};

/// Tiempos máximos de una descarga.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Tiempo máximo para establecer la conexión.
    pub connect: Duration,
    /// Tiempo máximo de espera de datos.
    pub read: Duration,
}

/// Error de una descarga.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// El cliente no admite la operación (por ejemplo, POST con cuerpo
    /// binario): se puede intentar otra forma.
    #[error("Operacion no soportada: {0}")]
    Unsupported(String),
    /// El servidor respondió con un código de error.
    #[error("El servidor respondio con el codigo HTTP {status} ({url})")]
    Status { url: String, status: u16 },
    /// Tiempo de espera agotado.
    #[error("Tiempo de espera agotado accediendo a {0}")]
    Timeout(String),
    /// Cualquier otro error (red, TLS, protocolo, fichero...).
    #[error("{0}")]
    Io(String),
}

impl From<HttpClientError> for FetchError {
    fn from(e: HttpClientError) -> Self {
        match e {
            HttpClientError::Http(h) => FetchError::Status {
                url: h.url,
                status: h.status,
            },
            HttpClientError::Timeout { url, .. } => FetchError::Timeout(url),
            other => FetchError::Io(other.to_string()),
        }
    }
}

/// Acceso a la red para la validación.
pub trait HttpFetcher: Send + Sync {
    /// Descarga una URL `http`/`https` con GET, con la cabecera `Accept`
    /// indicada.
    fn get(&self, url: &str, accept: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError>;

    /// Envía un POST con cuerpo binario (petición OCSP como hace Java). Por
    /// defecto no está soportado ([`FetchError::Unsupported`]) y la consulta
    /// OCSP usa GET (RFC 6960, apéndice A.1).
    fn post(
        &self,
        url: &str,
        _content_type: &str,
        _accept: &str,
        _body: &[u8],
        _timeouts: Timeouts,
    ) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::Unsupported(format!("POST binario a {url}")))
    }

    /// Obtiene una CRL de un servidor LDAP (`ldap://`). Por defecto usa el
    /// cliente LDAP mínimo de este crate ([`crate::ldap::fetch_crl`]).
    fn ldap(&self, url: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError> {
        crate::ldap::fetch_crl(url, timeouts)
    }
}

/// [`HttpFetcher`] sobre el cliente HTTP de AutoFirma.
#[derive(Clone, Default)]
pub struct AfirmaHttpFetcher {
    client: Option<Arc<dyn HttpClient>>,
}

impl std::fmt::Debug for AfirmaHttpFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AfirmaHttpFetcher")
            .field("installed", &self.client.is_none())
            .finish()
    }
}

impl AfirmaHttpFetcher {
    /// Usa el cliente instalado en el proceso en el momento de cada descarga
    /// ([`afirma_core::http::installed_http_client`]).
    pub fn new() -> Self {
        AfirmaHttpFetcher { client: None }
    }

    /// Usa un cliente concreto.
    pub fn with_client(client: Arc<dyn HttpClient>) -> Self {
        AfirmaHttpFetcher { client: Some(client) }
    }

    fn client(&self) -> Arc<dyn HttpClient> {
        self.client
            .clone()
            .unwrap_or_else(afirma_core::http::installed_http_client)
    }
}

impl HttpFetcher for AfirmaHttpFetcher {
    fn get(&self, url: &str, accept: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError> {
        let request = HttpRequest::get(url)
            .header("Accept", accept)
            .connect_timeout_millis(i64::try_from(timeouts.connect.as_millis()).unwrap_or(i64::MAX))
            .read_timeout(timeouts.read);
        Ok(self.client().read_url(&request)?)
    }
}

/// Lee un fichero local de una URL `file:` (solo rutas locales: se rechazan
/// los nombres de servidor para no abrir rutas UNC de red).
pub(crate) fn read_file_url(url: &str) -> Result<Vec<u8>, FetchError> {
    let parsed = url::Url::parse(url).map_err(|e| FetchError::Io(format!("URL no valida {url}: {e}")))?;
    if parsed
        .host_str()
        .is_some_and(|h| !h.is_empty() && !h.eq_ignore_ascii_case("localhost"))
    {
        return Err(FetchError::Io(format!("No se admiten ficheros remotos: {url}")));
    }
    let path = parsed
        .to_file_path()
        .map_err(|_| FetchError::Io(format!("Ruta de fichero no valida: {url}")))?;
    std::fs::read(&path).map_err(|e| FetchError::Io(format!("No se ha podido leer {}: {e}", path.display())))
}

/// Codificación `%XX` de los caracteres reservados de Base64 para la URL de
/// una petición OCSP por GET (RFC 6960, apéndice A.1).
pub(crate) fn ocsp_get_url(responder: &str, request: &[u8]) -> String {
    let b64 = afirma_core::base64::encode(request);
    let mut encoded = String::with_capacity(b64.len() + 16);
    for c in b64.chars() {
        match c {
            '+' => encoded.push_str("%2B"),
            '/' => encoded.push_str("%2F"),
            '=' => encoded.push_str("%3D"),
            c => encoded.push(c),
        }
    }
    if responder.ends_with('/') {
        format!("{responder}{encoded}")
    } else {
        format!("{responder}/{encoded}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_url() {
        assert_eq!(
            ocsp_get_url("http://o.example/", &[0xfb, 0xff, 0x00]),
            "http://o.example/%2B%2F8A"
        );
        assert_eq!(
            ocsp_get_url("http://o.example/ocsp", &[0x30, 0x00]),
            "http://o.example/ocsp/MAA%3D"
        );
    }

    #[test]
    fn file_urls() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.crl");
        std::fs::write(&f, b"datos").unwrap();
        let url = url::Url::from_file_path(&f).unwrap().to_string();
        assert_eq!(read_file_url(&url).unwrap(), b"datos");
        assert!(read_file_url("file://servidor/compartido/x.crl").is_err());
        assert!(read_file_url("file:///no/existe/x.crl").is_err());
    }
}
