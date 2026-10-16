//! Apertura de los canales locales (`afirma://websocket` y
//! `afirma://service`): parámetros, material TLS (`autofirma.pfx`) y
//! errores de arranque.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use afirma_core::ErrorCode;
use afirma_core::error::codes;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::query::Params;
use crate::version::{self, ProtocolVersion};

/// Nombre del almacén TLS local.
pub const AUTOFIRMA_PFX_NAME: &str = "autofirma.pfx";
/// Contraseña del almacén y de la clave.
pub const AUTOFIRMA_PFX_PASSWORD: &str = "654321";
/// Alias de la clave del socket.
pub const AUTOFIRMA_PFX_ALIAS: &str = "SocketAutoFirma";
/// Puerto WebSocket por defecto si no se indican puertos.
pub const DEFAULT_WEBSOCKET_PORT: u16 = 63117;

/// Parámetros de apertura de un canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRequest {
    /// Puertos candidatos en orden (`ports`). `None` si no se indicaron.
    pub ports: Option<Vec<i64>>,
    /// El parámetro `ports` contenía elementos no numéricos (Java lanzaba
    /// una excepción no controlada y terminaba con -1).
    pub ports_invalid: bool,
    /// Versión del canal ya revisada (4 + jvc>3 → 4.1).
    pub version: ProtocolVersion,
    pub jvc: i32,
    /// Identificador de sesión válido (`idsession`); `None` desactiva las
    /// comprobaciones de sesión, como en Java.
    pub session_id: Option<String>,
    /// `dlgload=false`.
    pub progress_dialogs: bool,
}

impl ChannelRequest {
    pub fn from_params(params: &Params, jvc: i32) -> ChannelRequest {
        let get = |k: &str| params.get(k).ok().flatten();
        let version = ProtocolVersion::from_param(get("v").as_deref()).reviewed(jvc);
        let mut ports_invalid = false;
        let ports = get("ports").map(|p| {
            let mut out = Vec::new();
            for item in p.split(',') {
                match version::java_parse_int(item) {
                    Some(v) => out.push(i64::from(v).abs()),
                    None => ports_invalid = true,
                }
            }
            out
        });
        let session_id = get("idsession").filter(|s| !s.is_empty() && s.chars().all(char::is_alphanumeric));
        ChannelRequest {
            ports,
            ports_invalid,
            version,
            jvc,
            session_id,
            progress_dialogs: !get("dlgload").is_some_and(|v| v.eq_ignore_ascii_case("false")),
        }
    }

    /// Puertos utilizables (los fuera de rango se descartan, como los fallos
    /// de `new InetSocketAddress(port)` en Java).
    pub fn candidate_ports(&self, default: Option<u16>) -> Vec<u16> {
        match &self.ports {
            Some(p) => p.iter().filter_map(|&v| u16::try_from(v).ok()).collect(),
            None => default.into_iter().collect(),
        }
    }

    /// Modo asíncrono del WebSocket (`#wait`/`getresult`): `jvc > 3`.
    pub fn asynchronous(&self) -> bool {
        self.jvc > 3
    }
}

/// Error al abrir un canal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// Versión de protocolo no soportada por el canal (620011).
    #[error("Version de protocolo no soportada: {0}")]
    UnsupportedVersion(ProtocolVersion),
    /// No se pudo cargar el almacén TLS (220008).
    #[error("No se ha podido cargar el almacen de claves SSL: {0}")]
    Tls(String),
    /// No se pudo abrir ningún puerto (220001).
    #[error("No se ha podido abrir el socket en ninguno de los puertos indicados")]
    NoPortAvailable,
    /// No se indicaron puertos (620013, socket de servicio).
    #[error("No se han proporcionado los puertos de conexion")]
    PortsNotFound,
    /// Puertos mal formados (Java terminaba con estado -1).
    #[error("Puertos mal formados")]
    InvalidPorts,
}

impl ChannelError {
    /// Código de error para el diálogo (`None` si Java no mostraba ninguno).
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ChannelError::UnsupportedVersion(_) => Some(codes::UNSUPPORTED_PROTOCOL_VERSION),
            ChannelError::Tls(_) => Some(codes::LOADING_SSL_KEYSTORE_ERROR),
            ChannelError::NoPortAvailable => Some(codes::SOCKET_INITIALIZING_ERROR),
            ChannelError::PortsNotFound => Some(codes::PORTS_NOT_FOUND),
            ChannelError::InvalidPorts => None,
        }
    }

    /// Código de salida del proceso que usaba Java.
    pub fn exit_code(&self) -> i32 {
        match self {
            ChannelError::InvalidPorts => -1,
            _ => 0,
        }
    }
}

/// Material TLS de los canales locales.
#[derive(Clone)]
pub enum TlsSource {
    /// PKCS#12 en disco (normalmente `autofirma.pfx`).
    Pkcs12File { path: PathBuf, password: String },
    /// PKCS#12 en memoria.
    Pkcs12Bytes { data: Vec<u8>, password: String },
    /// Configuración ya construida.
    Config(Arc<ServerConfig>),
}

impl std::fmt::Debug for TlsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsSource::Pkcs12File { path, .. } => write!(f, "TlsSource::Pkcs12File({})", path.display()),
            TlsSource::Pkcs12Bytes { .. } => f.write_str("TlsSource::Pkcs12Bytes"),
            TlsSource::Config(_) => f.write_str("TlsSource::Config"),
        }
    }
}

impl TlsSource {
    /// `autofirma.pfx` en la ruta indicada con la contraseña `654321`.
    pub fn autofirma_pfx(path: impl Into<PathBuf>) -> Self {
        TlsSource::Pkcs12File { path: path.into(), password: AUTOFIRMA_PFX_PASSWORD.into() }
    }

    /// Construye la configuración del servidor TLS (rustls con `ring`,
    /// TLS 1.2 y 1.3, sin autenticación de cliente).
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, ChannelError> {
        match self {
            TlsSource::Config(c) => Ok(c.clone()),
            TlsSource::Pkcs12File { path, password } => {
                let data = std::fs::read(path).map_err(|e| ChannelError::Tls(format!("{}: {e}", path.display())))?;
                server_config_from_pkcs12(&data, password)
            }
            TlsSource::Pkcs12Bytes { data, password } => server_config_from_pkcs12(data, password),
        }
    }
}

/// Configuración TLS a partir de un PKCS#12: la entrada `SocketAutoFirma`
/// o, si no existe, la primera con clave privada.
pub fn server_config_from_pkcs12(data: &[u8], password: &str) -> Result<Arc<ServerConfig>, ChannelError> {
    let ks = p12_keystore::KeyStore::from_pkcs12(data, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(|e| ChannelError::Tls(e.to_string()))?;
    let chain = ks
        .entries()
        .find_map(|(alias, e)| match e {
            p12_keystore::KeyStoreEntry::PrivateKeyChain(c) if alias.eq_ignore_ascii_case(AUTOFIRMA_PFX_ALIAS) => Some(c.clone()),
            _ => None,
        })
        .or_else(|| ks.private_key_chain().map(|(_, c)| c.clone()))
        .ok_or_else(|| ChannelError::Tls("el almacen no contiene ninguna clave privada".into()))?;
    if chain.certs().is_empty() {
        return Err(ChannelError::Tls("la clave del almacen no tiene certificado".into()));
    }
    let certs: Vec<CertificateDer<'static>> = chain.certs().iter().map(|c| CertificateDer::from(c.as_der().to_vec())).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ChannelError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ChannelError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Directorio "alternativo" donde se busca `autofirma.pfx` si no está junto
/// al ejecutable: Windows `%ALLUSERSPROFILE%\Autofirma`, Linux
/// `~/.afirma/Autofirma`, macOS `~/Library/Application Support/Autofirma`.
pub fn alternative_directory() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("ALLUSERSPROFILE").map(|p| PathBuf::from(p).join("Autofirma"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/Autofirma"))
    } else {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".afirma/Autofirma"))
    }
}

/// Busca `autofirma.pfx` en el directorio de la aplicación y después en el
/// alternativo (`SecureSocketUtils`).
pub fn find_autofirma_pfx(app_dir: Option<&Path>) -> Option<PathBuf> {
    app_dir
        .map(|d| d.join(AUTOFIRMA_PFX_NAME))
        .into_iter()
        .chain(alternative_directory().map(|d| d.join(AUTOFIRMA_PFX_NAME)))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_params() {
        let url = "afirma://websocket?ports=50001,-50002,x,70000&v=4&jvc=4&idsession=Q3k9aZ0bT1cL2mN4pX7r&dlgload=false";
        let r = ChannelRequest::from_params(&Params::from_query(url), 4);
        assert_eq!(r.version, ProtocolVersion::V4_1);
        assert!(r.ports_invalid);
        assert_eq!(r.candidate_ports(None), vec![50001, 50002]);
        assert_eq!(r.session_id.as_deref(), Some("Q3k9aZ0bT1cL2mN4pX7r"));
        assert!(!r.progress_dialogs);
        assert!(r.asynchronous());
        let r = ChannelRequest::from_params(&Params::from_query("afirma://websocket?v=3&idsession=a-b"), 1);
        assert_eq!(r.version, ProtocolVersion::V3);
        assert_eq!(r.candidate_ports(Some(DEFAULT_WEBSOCKET_PORT)), vec![63117]);
        assert_eq!(r.session_id, None);
        assert!(!r.asynchronous());
        let r = ChannelRequest::from_params(&Params::from_query("afirma://service?ports=1&v=x"), 1);
        assert_eq!(r.version, ProtocolVersion::V0);
        assert_eq!(ChannelError::InvalidPorts.exit_code(), -1);
        assert_eq!(ChannelError::NoPortAvailable.code().unwrap().code, 220001);
    }
}
