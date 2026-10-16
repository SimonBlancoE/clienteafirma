//! Socket de servicio local heredado (`ServiceInvocationManager`,
//! `CommandProcessorThread`): HTTP mínimo sobre TLS con los comandos
//! `echo=`, `cmd=`, `fragment=`, `firm=` y `send=`.
//!
//! Diferencias con Java (documentadas): escucha solo en 127.0.0.1; acepta
//! también la versión 4 que envía AutoScript 1.10 (Java solo aceptaba 1, 2
//! y 3, así que este modo no funcionaba); las operaciones se ejecutan de
//! una en una.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afirma_core::ErrorCode;
use afirma_core::error::codes;
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;

use crate::channel::{ChannelError, ChannelRequest, TlsSource};
use crate::errors::format_error;
use crate::handler::RequestOrigin;
use crate::jbase64;
use crate::launcher::ProtocolLauncher;
use crate::version::ProtocolVersion;
use crate::websocket::{ServerExit, bind_first};

/// Tamaño de cada parte de la respuesta (en caracteres).
pub const RESPONSE_MAX_SIZE: usize = 1_000_000;

/// Opciones del servidor.
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    /// Inactividad tras la que la aplicación termina (90 s).
    pub idle_timeout: Duration,
    /// Tamaño máximo de una petición.
    pub max_request_size: usize,
    /// Tiempo máximo para recibir una petición completa.
    pub read_timeout: Duration,
    pub bind_address: IpAddr,
}

impl Default for ServiceOptions {
    fn default() -> Self {
        ServiceOptions {
            idle_timeout: Duration::from_secs(90),
            max_request_size: 64 << 20,
            read_timeout: Duration::from_secs(120),
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}

/// Comprueba la versión del canal (1, 2, 3 y, a diferencia de Java, 4).
pub fn check_version(v: ProtocolVersion) -> Result<(), ChannelError> {
    if (1..=4).contains(&v.major) { Ok(()) } else { Err(ChannelError::UnsupportedVersion(v)) }
}

/// Respuesta HTTP del socket (saltos `\n`, sin `Content-Length`; el cuerpo
/// es el Base64 URL-safe del texto).
pub fn http_response(text: &str) -> Vec<u8> {
    let mut s = String::from(
        "HTTP/1.1 200 OK\nConnection: close\nPragma: no-cache\nServer: Cliente @firma\nContent-Type: text/html; charset=utf-8\nAccess-Control-Allow-Origin: *\n\n",
    );
    s.push_str(&jbase64::encode_url_safe(text.as_bytes()));
    s.into_bytes()
}

/// Estado global de los comandos (compartido por todas las conexiones).
#[derive(Default)]
struct Commands {
    request: Vec<String>,
    to_send: Vec<String>,
}

/// Temporizador de inactividad: se detiene al procesar un comando y se
/// reinicia al responder si estaba detenido.
struct Timer {
    running: bool,
    deadline: Instant,
}

struct State {
    launcher: Arc<ProtocolLauncher>,
    session_id: Option<String>,
    version: ProtocolVersion,
    commands: Mutex<Commands>,
    timer: Mutex<Timer>,
    op_lock: Arc<Mutex<()>>,
    idle: Duration,
}

impl State {
    fn stop_timer(&self) {
        self.timer.lock().unwrap_or_else(|e| e.into_inner()).running = false;
    }

    fn restart_if_stopped(&self) {
        let mut t = self.timer.lock().unwrap_or_else(|e| e.into_inner());
        if !t.running {
            t.running = true;
            t.deadline = Instant::now() + self.idle;
        }
    }

    fn error(&self, code: ErrorCode) -> String {
        format_error(Some(self.version), code, self.launcher.config().locale)
    }
}

/// Servidor ligado a un puerto.
pub struct ServiceServer {
    listener: TcpListener,
    port: u16,
    tls: Arc<ServerConfig>,
    request: ChannelRequest,
    options: ServiceOptions,
}

impl ServiceServer {
    /// Comprueba versión y puertos, carga el TLS y liga el puerto.
    pub async fn bind(request: &ChannelRequest, tls: &TlsSource, options: ServiceOptions) -> Result<ServiceServer, ChannelError> {
        check_version(request.version)?;
        if request.ports_invalid {
            return Err(ChannelError::InvalidPorts);
        }
        if request.ports.is_none() {
            return Err(ChannelError::PortsNotFound);
        }
        let tls = tls.server_config()?;
        let (listener, port) = bind_first(options.bind_address, &request.candidate_ports(None)).await?;
        Ok(ServiceServer { listener, port, tls, request: request.clone(), options })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Atiende peticiones hasta que vence el temporizador de inactividad.
    pub async fn serve(self, launcher: Arc<ProtocolLauncher>) -> ServerExit {
        let state = Arc::new(State {
            launcher,
            session_id: self.request.session_id.clone(),
            version: self.request.version,
            commands: Mutex::new(Commands::default()),
            timer: Mutex::new(Timer { running: true, deadline: Instant::now() + self.options.idle_timeout }),
            op_lock: Arc::new(Mutex::new(())),
            idle: self.options.idle_timeout,
        });
        let acceptor = TlsAcceptor::from(self.tls.clone());
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let Ok((tcp, _peer)) = accepted else { continue };
                    let st = state.clone();
                    let acc = acceptor.clone();
                    let opts = self.options.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acc.accept(tcp).await else { return };
                        let Ok(Ok(Some(text))) = tokio::time::timeout(opts.read_timeout, read_request(&mut tls, opts.max_request_size)).await else {
                            return;
                        };
                        let response = process_request(&text, &st).await;
                        let _ = tls.write_all(&http_response(&response)).await;
                        let _ = tls.shutdown().await;
                        st.restart_if_stopped();
                    });
                }
                _ = tick.tick() => {
                    let t = state.timer.lock().unwrap_or_else(|e| e.into_inner());
                    if t.running && Instant::now() >= t.deadline {
                        return ServerExit::IdleTimeout;
                    }
                }
            }
        }
    }
}

/// Ejecuta el socket de servicio en un runtime propio (punto de entrada
/// para `afirma://service`).
pub fn run_blocking(launcher: Arc<ProtocolLauncher>, request: &ChannelRequest, tls: &TlsSource, options: ServiceOptions) -> Result<ServerExit, ChannelError> {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|_| ChannelError::NoPortAvailable)?;
    let result = rt.block_on(async move {
        let server = ServiceServer::bind(request, tls, options).await?;
        Ok(server.serve(launcher).await)
    });
    // Si la página se ha ido con una operación en curso no se espera a que
    // termine (Java terminaba el proceso inmediatamente).
    rt.shutdown_timeout(std::time::Duration::from_millis(200));
    result
}

/// Lee hasta encontrar `@EOF`. `None` si la conexión se cierra antes.
async fn read_request<S: tokio::io::AsyncRead + Unpin>(s: &mut S, max: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        let start = buf.len().saturating_sub(4);
        buf.extend_from_slice(&chunk[..n]);
        if buf[start..].windows(4).any(|w| w == b"@EOF") {
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if buf.len() > max {
            return Ok(None);
        }
    }
}

const COMMANDS: [&str; 5] = ["cmd=", "echo=", "fragment=", "firm=", "send="];

/// Procesa una petición completa y devuelve el texto de respuesta (antes
/// del Base64).
async fn process_request(text: &str, st: &Arc<State>) -> String {
    let eof = text.find("@EOF").unwrap_or(text.len());
    let head = &text[..eof];
    let id_pos = head.find("idsession");
    let session = id_pos.map(|i| head.get(i + "idsession".len() + 1..).unwrap_or("").to_string());
    if let Some(expected) = &st.session_id {
        if session.as_deref() != Some(expected.as_str()) {
            return st.error(codes::INVALID_SESSION_ID);
        }
    }
    let data = &head[..id_pos.unwrap_or(eof)];
    let Some((cmd, pos)) = COMMANDS.iter().find_map(|c| data.find(c).map(|p| (*c, p))) else {
        return st.error(codes::MALFORMED_REQUEST_TO_SOCKET);
    };
    let arg = &data[pos + cmd.len()..];
    let origin = request_origin(text);
    match run_command(cmd, arg, st, origin).await {
        Ok(r) => r,
        Err(()) => st.error(codes::SENDING_RESULT_OPERATION),
    }
}

fn split_parts(result: &str) -> Vec<String> {
    let chars: Vec<char> = result.chars().collect();
    chars.chunks(RESPONSE_MAX_SIZE).map(|c| c.iter().collect()).collect()
}

/// Cabecera `Origin` de la petición HTTP (si viene).
pub fn request_origin(text: &str) -> Option<String> {
    let head = text.split("\r\n\r\n").next().unwrap_or(text);
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("origin").then(|| v.trim().to_string())
    })
}

async fn launch(st: &Arc<State>, url: String, origin: Option<String>) -> String {
    let launcher = st.launcher.clone();
    let lock = st.op_lock.clone();
    let version = st.version;
    match tokio::task::spawn_blocking(move || {
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        launcher.process_socket_message_from(&url, version, RequestOrigin::ServiceSocket { origin })
    })
    .await
    {
        Ok(r) => r,
        Err(_) => st.error(codes::UNKNOWN_SIGNING_BY_SOCKETS_ERROR),
    }
}

/// Resultado de `save` en este canal: `SAVE_OK`, `CANCEL` (o el error en
/// formato 4.1, que Java no podía producir aquí).
fn save_response(result: String) -> Result<String, ()> {
    if result == "OK" {
        Ok("SAVE_OK".into())
    } else if result == "CANCEL" || result.to_ascii_lowercase().starts_with("err-") {
        Ok(result)
    } else {
        Err(())
    }
}

fn is_save(url: &str) -> bool {
    url.starts_with("afirma://save?") || url.starts_with("afirma://save/?")
}

async fn run_command(cmd: &str, arg: &str, st: &Arc<State>, origin: Option<String>) -> Result<String, ()> {
    match cmd {
        "echo=" => {
            st.stop_timer();
            if arg.contains('-') {
                let mut c = st.commands.lock().unwrap_or_else(|e| e.into_inner());
                c.request.clear();
                c.to_send.clear();
            }
            Ok("OK".into())
        }
        "cmd=" => {
            let url = String::from_utf8_lossy(&jbase64::decode_url_safe(arg.trim()).map_err(|_| ())?).into_owned();
            if !url.starts_with("afirma://") || url.starts_with("afirma://service?") || url.starts_with("afirma://service/?") {
                return Err(());
            }
            st.stop_timer();
            if is_save(&url) {
                return save_response(launch(st, url, origin.clone()).await);
            }
            if st.commands.lock().unwrap_or_else(|e| e.into_inner()).to_send.is_empty() {
                let result = launch(st, url, origin.clone()).await;
                st.commands.lock().unwrap_or_else(|e| e.into_inner()).to_send = split_parts(&result);
            }
            Ok(st.commands.lock().unwrap_or_else(|e| e.into_inner()).to_send.len().to_string())
        }
        "fragment=" => {
            st.stop_timer();
            let parts: Vec<&str> = arg.split('@').collect();
            let part: usize = parts.get(1).and_then(|p| p.trim().parse().ok()).ok_or(())?;
            let total: usize = parts.get(2).and_then(|p| p.trim().parse().ok()).ok_or(())?;
            let chunk = String::from_utf8_lossy(&jbase64::decode_url_safe(parts.get(3).ok_or(())?.trim()).map_err(|_| ())?).into_owned();
            let mut c = st.commands.lock().unwrap_or_else(|e| e.into_inner());
            if part == 0 {
                return Err(());
            }
            if c.request.len() == part {
                c.request[part - 1] = chunk;
            } else if part - 1 <= c.request.len() {
                c.request.insert(part - 1, chunk);
            } else {
                return Err(());
            }
            Ok(if part == total { "OK".into() } else { "MORE_DATA_NEED".into() })
        }
        "firm=" => {
            st.stop_timer();
            let (pending, url) = {
                let c = st.commands.lock().unwrap_or_else(|e| e.into_inner());
                (c.to_send.is_empty(), c.request.concat())
            };
            if pending {
                if is_save(&url) {
                    return save_response(launch(st, url, origin.clone()).await);
                }
                let result = launch(st, url, origin.clone()).await;
                st.commands.lock().unwrap_or_else(|e| e.into_inner()).to_send = split_parts(&result);
            }
            Ok(st.commands.lock().unwrap_or_else(|e| e.into_inner()).to_send.len().to_string())
        }
        "send=" => {
            st.stop_timer();
            let parts: Vec<&str> = arg.split('@').collect();
            let part: usize = parts.get(1).and_then(|p| p.trim().parse().ok()).ok_or(())?;
            let total: usize = parts.get(2).and_then(|p| p.trim().parse().ok()).ok_or(())?;
            if part < 1 || part > total {
                return Err(());
            }
            st.commands.lock().unwrap_or_else(|e| e.into_inner()).to_send.get(part - 1).cloned().ok_or(())
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_format() {
        let r = String::from_utf8(http_response("OK")).unwrap();
        assert!(r.starts_with("HTTP/1.1 200 OK\nConnection: close\n"));
        assert!(r.ends_with("\n\nT0s="));
        assert!(!r.contains("\r\n"));
        assert!(check_version(ProtocolVersion::V4_1).is_ok());
        assert!(check_version(ProtocolVersion::V0).is_err());
        assert_eq!(split_parts(&"a".repeat(RESPONSE_MAX_SIZE + 1)).len(), 2);
        assert_eq!(save_response("OK".into()), Ok("SAVE_OK".into()));
        assert_eq!(save_response("CANCEL".into()), Ok("CANCEL".into()));
        assert_eq!(save_response("SAF_05: x".into()), Err(()));
        assert_eq!(
            request_origin("POST /afirma HTTP/1.1\r\nHost: 127.0.0.1:5\r\norigin: https://sede.gob.es\r\n\r\necho=-idsession=x@EOF").as_deref(),
            Some("https://sede.gob.es")
        );
        assert_eq!(request_origin("echo=-idsession=x@EOF"), None);
    }
}
