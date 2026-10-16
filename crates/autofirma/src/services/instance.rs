//! Instancia única de la ventana principal (en Java, `~/.afirma/Autofirma/.lock`).
//!
//! Mejora sobre Java, que solo avisaba de que «La aplicación ya se está
//! ejecutando en otra ventana»: una segunda ejecución entrega sus ficheros a
//! la ventana abierta y la trae al frente. La comunicación es por un socket en
//! 127.0.0.1 protegido con un testigo aleatorio que solo puede leer el usuario.
//! El modo protocolo y la línea de comandos no toman el bloqueo (como Java).

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::platform::{self, Opened};

const LOCK_NAME: &str = "autofirma-rs.lock";
const INFO_NAME: &str = "autofirma-rs.instance";
/// Peticiones de una segunda ejecución como mucho (ficheros por mensaje).
const MAX_LINES: usize = 10_000;

/// Bloqueo de la instancia principal; al soltarse se borra el fichero de contacto.
pub struct PrimaryGuard {
    _lock: File,
    info: PathBuf,
}

impl Drop for PrimaryGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.info);
    }
}

pub enum Instance {
    /// Esta es la ventana principal.
    Primary(PrimaryGuard),
    /// Ya había una ventana abierta y se le han entregado los ficheros.
    Forwarded,
    /// No se ha podido determinar (se abre una ventana normal).
    Unknown,
}

fn app_dir() -> PathBuf {
    afirma_core::platform::afirma_dir().join("Autofirma")
}

/// Toma el bloqueo o, si otra ventana lo tiene, le entrega `files`.
pub fn acquire(files: &[PathBuf]) -> Instance {
    let dir = app_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return Instance::Unknown;
    }
    let Ok(lock) = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join(LOCK_NAME))
    else {
        return Instance::Unknown;
    };
    match lock.try_lock() {
        Ok(()) => match serve(&dir) {
            Some(info) => Instance::Primary(PrimaryGuard { _lock: lock, info }),
            None => Instance::Primary(PrimaryGuard {
                _lock: lock,
                info: PathBuf::new(),
            }),
        },
        Err(TryLockError::WouldBlock) => {
            if forward(&dir, files) {
                Instance::Forwarded
            } else {
                Instance::Unknown
            }
        }
        Err(TryLockError::Error(e)) => {
            tracing::debug!("Sin bloqueo de instancia única: {e}");
            Instance::Unknown
        }
    }
}

fn new_token() -> String {
    let bytes: [u8; 24] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Abre el socket de contacto y escribe `puerto testigo` en el fichero de contacto.
fn serve(dir: &Path) -> Option<PathBuf> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).ok()?;
    let port = listener.local_addr().ok()?.port();
    let token = new_token();
    let info = dir.join(INFO_NAME);
    write_private(&info, format!("{port} {token}\n").as_bytes()).ok()?;
    std::thread::Builder::new()
        .name("instancia".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                handle(stream, &token);
            }
        })
        .ok()?;
    Some(info)
}

fn handle(stream: TcpStream, token: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut lines = BufReader::new(stream).lines();
    match lines.next() {
        Some(Ok(t)) if t.trim() == token => {}
        _ => return,
    }
    let mut any_file = false;
    for line in lines.take(MAX_LINES).map_while(Result::ok) {
        if let Some(path) = line.strip_prefix("F ") {
            let path = PathBuf::from(path);
            if path.exists() {
                platform::push(Opened::File(path));
                any_file = true;
            }
        }
    }
    if !any_file {
        platform::push(Opened::Focus);
    }
}

fn forward(dir: &Path, files: &[PathBuf]) -> bool {
    let Ok(info) = std::fs::read_to_string(dir.join(INFO_NAME)) else {
        return false;
    };
    let mut parts = info.split_whitespace();
    let (Some(port), Some(token)) = (parts.next().and_then(|p| p.parse::<u16>().ok()), parts.next()) else {
        return false;
    };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let mut msg = format!("{token}\n");
    for f in files {
        let abs = std::path::absolute(f).unwrap_or_else(|_| f.clone());
        msg.push_str(&format!("F {}\n", abs.display()));
    }
    stream.write_all(msg.as_bytes()).is_ok() && stream.flush().is_ok()
}

/// Escribe un fichero legible solo por el usuario.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)
}
