//! Servidor WebSocket local (`AfirmaWebSocketServerManager`,
//! `AfirmaWebSocketServerV4Sup`, `WebSocketServerOperationHandler`).
//!
//! - Escucha **solo en 127.0.0.1** (Java escuchaba en todas las interfaces)
//!   en el primer puerto libre de la lista recibida, con TLS (rustls).
//! - Protocolo 4: comprobación de origen local, de `idsession`, eco
//!   (`echo=` → `OK`) y operaciones síncronas o asíncronas (`#wait` /
//!   `getresult?idsession=`).
//! - El servidor termina cuando se cierra la primera conexión WebSocket
//!   abierta (la de la página) o si en 30 s no llega ningún mensaje válido.
//! - Las operaciones se ejecutan de una en una (Java las lanzaba en hilos
//!   concurrentes; el resultado observable por la página es el mismo).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afirma_core::error::codes;
use futures_util::{SinkExt, StreamExt};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::channel::{ChannelError, ChannelRequest, DEFAULT_WEBSOCKET_PORT, TlsSource};
use crate::errors::format_error;
use crate::handler::RequestOrigin;
use crate::launcher::ProtocolLauncher;
use crate::version::ProtocolVersion;

/// Respuesta de espera del modo asíncrono.
pub const WAIT_RESPONSE: &str = "#wait";
/// Prefijo de las consultas de resultado.
pub const GET_RESULT_PREFIX: &str = "getresult?";

/// Opciones del servidor.
#[derive(Debug, Clone)]
pub struct WebSocketOptions {
    /// Tiempo sin mensajes válidos tras el que el servidor termina (30 s).
    pub idle_timeout: Duration,
    /// Tamaño máximo de un mensaje (Java no tenía límite).
    pub max_message_size: usize,
    /// Dirección de escucha (127.0.0.1).
    pub bind_address: IpAddr,
}

impl Default for WebSocketOptions {
    fn default() -> Self {
        WebSocketOptions {
            idle_timeout: Duration::from_secs(30),
            max_message_size: 512 << 20,
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}

/// Motivo de fin del servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerExit {
    /// La página cerró la conexión (la aplicación debe terminar).
    ClientClosed,
    /// No llegó ningún mensaje válido a tiempo.
    IdleTimeout,
}

/// Servidor ya ligado a un puerto.
pub struct WebSocketServer {
    listener: TcpListener,
    port: u16,
    tls: Arc<ServerConfig>,
    request: ChannelRequest,
    options: WebSocketOptions,
}

/// Comprueba la versión del canal WebSocket (versión principal 3 o 4).
pub fn check_version(v: ProtocolVersion) -> Result<(), ChannelError> {
    if v.major == 3 || v.major == 4 {
        Ok(())
    } else {
        Err(ChannelError::UnsupportedVersion(v))
    }
}

/// Liga el primer puerto disponible de la lista (en orden).
pub(crate) async fn bind_first(addr: IpAddr, ports: &[u16]) -> Result<(TcpListener, u16), ChannelError> {
    for &p in ports {
        match TcpListener::bind(SocketAddr::new(addr, p)).await {
            Ok(l) => {
                let port = l.local_addr().map(|a| a.port()).unwrap_or(p);
                tracing::info!("Servidor WebSocket local escuchando en {addr}:{port}");
                return Ok((l, port));
            }
            Err(e) => tracing::info!("El puerto {p} no esta disponible: {e}"),
        }
    }
    Err(ChannelError::NoPortAvailable)
}

impl WebSocketServer {
    /// Comprueba la versión, carga el material TLS y liga el puerto (en el
    /// orden de Java: versión, almacén TLS, puertos).
    pub async fn bind(
        request: &ChannelRequest,
        tls: &TlsSource,
        options: WebSocketOptions,
    ) -> Result<WebSocketServer, ChannelError> {
        check_version(request.version)?;
        if request.ports_invalid {
            return Err(ChannelError::InvalidPorts);
        }
        let tls = tls.server_config()?;
        let ports = request.candidate_ports(Some(DEFAULT_WEBSOCKET_PORT));
        let (listener, port) = bind_first(options.bind_address, &ports).await?;
        Ok(WebSocketServer {
            listener,
            port,
            tls,
            request: request.clone(),
            options,
        })
    }

    /// Puerto en el que escucha.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Atiende conexiones hasta que termina.
    pub async fn serve(self, launcher: Arc<ProtocolLauncher>) -> ServerExit {
        let state = Arc::new(State {
            launcher,
            session_id: self.request.session_id.clone(),
            version: self.request.version,
            legacy: self.request.version.major == 3,
            asynchronous: self.request.asynchronous(),
            working: AtomicBool::new(false),
            first_client: Mutex::new(None),
            ops: Mutex::new(HashMap::new()),
            op_lock: Arc::new(Mutex::new(())),
            closed: Notify::new(),
            working_notify: Notify::new(),
        });
        let acceptor = TlsAcceptor::from(self.tls.clone());
        let mut config = WebSocketConfig::default();
        config = config
            .max_message_size(Some(self.options.max_message_size))
            .max_frame_size(Some(self.options.max_message_size));
        let next_id = AtomicU64::new(1);
        let idle = tokio::time::sleep(self.options.idle_timeout);
        tokio::pin!(idle);
        let mut idle_active = true;
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let Ok((tcp, peer)) = accepted else { continue };
                    let id = next_id.fetch_add(1, Ordering::SeqCst);
                    let st = state.clone();
                    let acc = acceptor.clone();
                    tokio::spawn(async move {
                        // Un fallo aquí suele ser que el navegador no confía en el
                        // certificado local (CA no instalada o rechazada).
                        let tls = match acc.accept(tcp).await {
                            Ok(t) => t,
                            Err(e) => {
                                tracing::warn!("Conexión TLS rechazada con {peer}: {e}");
                                return;
                            }
                        };
                        let origin_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
                        let slot = origin_slot.clone();
                        #[allow(clippy::result_large_err)]
                        let callback = move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                             resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                            if let Some(o) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
                                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(o.to_string());
                            }
                            Ok(resp)
                        };
                        let ws = match tokio_tungstenite::accept_hdr_async_with_config(tls, callback, Some(config)).await {
                            Ok(ws) => ws,
                            Err(e) => {
                                tracing::warn!("Negociación WebSocket fallida con {peer}: {e}");
                                return;
                            }
                        };
                        tracing::info!("Página conectada desde {peer}");
                        let origin = origin_slot.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        {
                            let mut fc = st.first_client.lock().unwrap_or_else(|e| e.into_inner());
                            if fc.is_none() {
                                *fc = Some(id);
                            }
                        }
                        handle_connection(ws, peer, origin, st.clone()).await;
                        let first = *st.first_client.lock().unwrap_or_else(|e| e.into_inner());
                        if first == Some(id) {
                            st.closed.notify_one();
                        }
                    });
                }
                _ = &mut idle, if idle_active => {
                    if !state.working.load(Ordering::SeqCst) {
                        return ServerExit::IdleTimeout;
                    }
                    idle_active = false;
                }
                _ = state.working_notify.notified(), if idle_active => {
                    idle_active = false;
                }
                _ = state.closed.notified() => return ServerExit::ClientClosed,
            }
        }
    }
}

/// Ejecuta el servidor WebSocket en un runtime propio hasta que termina
/// (punto de entrada para `afirma://websocket`).
pub fn run_blocking(
    launcher: Arc<ProtocolLauncher>,
    request: &ChannelRequest,
    tls: &TlsSource,
    options: WebSocketOptions,
) -> Result<ServerExit, ChannelError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| ChannelError::NoPortAvailable)?;
    let result = rt.block_on(async move {
        let server = WebSocketServer::bind(request, tls, options).await?;
        Ok(server.serve(launcher).await)
    });
    // Si la página se ha ido con una operación en curso no se espera a que
    // termine (Java terminaba el proceso inmediatamente).
    rt.shutdown_timeout(std::time::Duration::from_millis(200));
    result
}

struct OpSlot {
    result: Mutex<Option<String>>,
}

struct State {
    launcher: Arc<ProtocolLauncher>,
    session_id: Option<String>,
    version: ProtocolVersion,
    legacy: bool,
    asynchronous: bool,
    working: AtomicBool,
    first_client: Mutex<Option<u64>>,
    /// Operaciones asíncronas por identificador de sesión.
    ops: Mutex<HashMap<Option<String>, Arc<OpSlot>>>,
    /// Una operación cada vez.
    op_lock: Arc<Mutex<()>>,
    closed: Notify,
    working_notify: Notify,
}

/// Identificador de sesión de un mensaje: tras el primer `idsession=` hasta
/// el siguiente `&` o hasta el final (sin el `@EOF` final).
pub fn message_session_id(message: &str) -> Option<String> {
    let idx = message.find("idsession=")?;
    let rest = &message[idx + "idsession=".len()..];
    Some(match rest.find('&') {
        Some(e) => rest[..e].to_string(),
        None => rest.strip_suffix("@EOF").unwrap_or(rest).to_string(),
    })
}

async fn handle_connection<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    peer: SocketAddr,
    origin: Option<String>,
    st: Arc<State>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = ws.split();
    while let Some(msg) = stream.next().await {
        let text = match msg {
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        let reply = handle_message(&text, peer, &origin, &st).await;
        if let Some(r) = reply
            && sink.send(Message::Text(r.into())).await.is_err()
        {
            break;
        }
    }
}

fn mark_working(st: &State) {
    if !st.working.swap(true, Ordering::SeqCst) {
        st.working_notify.notify_one();
    }
}

async fn run_op(st: &Arc<State>, message: String, origin: Option<String>) -> String {
    let launcher = st.launcher.clone();
    let lock = st.op_lock.clone();
    let version = st.version;
    let task = tokio::task::spawn_blocking(move || {
        let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        launcher.process_socket_message_from(&message, version, RequestOrigin::WebSocket { origin })
    });
    match task.await {
        Ok(r) => r,
        // Java dejaba a la página esperando indefinidamente.
        Err(_) => format_error(
            Some(version),
            codes::UNKNOWN_SIGNING_BY_SOCKETS_ERROR,
            st.launcher.config().locale,
        ),
    }
}

async fn handle_message(message: &str, peer: SocketAddr, origin: &Option<String>, st: &Arc<State>) -> Option<String> {
    let locale = st.launcher.config().locale;
    if st.legacy {
        // Servidor de la versión 3: sin comprobaciones y síncrono. Java
        // pasaba la versión 0 (todas las operaciones fallaban con 620011);
        // aquí se usa la versión del canal.
        mark_working(st);
        if message.starts_with("echo=") {
            return Some("OK".into());
        }
        return Some(run_op(st, message.to_string(), origin.clone()).await);
    }
    let local = match peer.ip() {
        IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(v6) => v6.to_ipv4_mapped() == Some(Ipv4Addr::LOCALHOST),
    };
    if !local {
        return Some(format_error(Some(st.version), codes::EXTERNAL_REQUEST, locale));
    }
    if let Some(expected) = &st.session_id
        && message_session_id(message).as_deref() != Some(expected.as_str())
    {
        return Some(format_error(Some(st.version), codes::INVALID_SESSION_ID, locale));
    }
    mark_working(st);
    if message.starts_with("echo=") {
        return Some("OK".into());
    }
    if !st.asynchronous {
        return Some(run_op(st, message.to_string(), origin.clone()).await);
    }
    let key = st.session_id.clone();
    if message.starts_with(GET_RESULT_PREFIX) {
        let mut ops = st.ops.lock().unwrap_or_else(|e| e.into_inner());
        let done = ops
            .get(&key)
            .and_then(|slot| slot.result.lock().unwrap_or_else(|e| e.into_inner()).take());
        return Some(match done {
            Some(r) => {
                ops.remove(&key);
                r
            }
            None => WAIT_RESPONSE.into(),
        });
    }
    let slot = Arc::new(OpSlot {
        result: Mutex::new(None),
    });
    st.ops
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, slot.clone());
    let st2 = st.clone();
    let message = message.to_string();
    let origin = origin.clone();
    tokio::spawn(async move {
        let r = run_op(&st2, message, origin).await;
        *slot.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
    });
    Some(WAIT_RESPONSE.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_extraction() {
        assert_eq!(message_session_id("echo=-idsession=ABC@EOF").as_deref(), Some("ABC"));
        assert_eq!(
            message_session_id("afirma://sign?op=sign&idsession=ABC&dat=x").as_deref(),
            Some("ABC")
        );
        assert_eq!(message_session_id("getresult?idsession=ABC").as_deref(), Some("ABC"));
        assert_eq!(message_session_id("afirma://sign?op=sign"), None);
        assert!(check_version(ProtocolVersion::V4_1).is_ok());
        assert!(check_version(ProtocolVersion::V3).is_ok());
        assert!(check_version(ProtocolVersion::V2).is_err());
    }
}
