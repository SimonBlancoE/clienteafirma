//! Cliente del servidor intermedio: subida al StorageService
//! (`op=put`), descarga del RetrieveService (`op=get`), espera activa
//! (`#WAIT`) y sondeo como lo hace la página (para pruebas e integraciones).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use afirma_core::error::codes;

use crate::errors::ProtocolError;
use crate::http::{HttpClient, HttpError};
use crate::query::encode_storage_payload;

/// Versión de la sintaxis de los servicios intermedios.
pub const SYNTAX_VERSION: &str = "1_0";
/// Texto de espera activa subido al StorageService.
pub const WAIT_TOKEN: &str = "#WAIT";
/// Intervalo de la espera activa.
pub const ACTIVE_WAITING_INTERVAL: Duration = Duration::from_millis(10_000);

/// Descarga `op=get&v=1_0&id=<id>` (POST).
pub fn retrieve(http: &HttpClient, retrieve_servlet: &str, id: &str) -> Result<Vec<u8>, HttpError> {
    http.post(retrieve_servlet, &format!("op=get&v={SYNTAX_VERSION}&id={id}"))
}

/// Indica si la respuesta es un error de los servicios intermedios: más de
/// 8 bytes cuyos 8 primeros, en minúsculas, empiezan por `err-`.
pub fn is_error_response(body: &[u8]) -> bool {
    body.len() > 8 && String::from_utf8_lossy(&body[..8]).to_lowercase().starts_with("err-")
}

/// Sube un texto: `op=put&v=1_0&id=<id>&dat=<texto>`. El StorageService
/// decodifica `dat` como `application/x-www-form-urlencoded`, así que se
/// codifican los caracteres que se corromperían (`%`, `+`, `&`, no ASCII).
pub fn store(http: &HttpClient, storage_servlet: &str, id: &str, payload: &str) -> Result<(), HttpError> {
    http.post(storage_servlet, &format!("op=put&v={SYNTAX_VERSION}&id={id}&dat={}", encode_storage_payload(payload))).map(|_| ())
}

/// Error de subida del resultado según Java: tiempo de espera 401201,
/// certificado SSL de otro dominio 400004 (con el host), otros 401200.
pub fn store_error(e: &HttpError) -> ProtocolError {
    match e {
        HttpError::Timeout(_) => ProtocolError::operation(codes::SENDING_RESULT_TIMEOUT, e.to_string()),
        HttpError::CertificateHostMismatch { host, .. } => {
            ProtocolError::operation(codes::INVALID_DOMAIN_SSL_CERTIFICATE_ERROR, e.to_string()).with_dialog_params(vec![host.clone()])
        }
        _ => ProtocolError::operation(codes::SENDING_RESULT_OPERATION, e.to_string()),
    }
}

/// Subidas serializadas por proceso (la espera activa y el resultado nunca
/// se intercalan).
#[derive(Debug, Clone, Default)]
pub struct Uploader {
    lock: Arc<Mutex<()>>,
}

impl Uploader {
    pub fn store(&self, http: &HttpClient, storage_servlet: &str, id: &str, payload: &str) -> Result<(), HttpError> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        store(http, storage_servlet, id, payload)
    }

    /// Inicia la espera activa (`ActiveWaitingThread`): sube `#WAIT` cada
    /// 10 s hasta que se detenga. Los errores se ignoran.
    pub fn start_active_waiting(&self, http: HttpClient, storage_servlet: String, id: String, interval: Duration) -> ActiveWaiting {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let running = Arc::new(AtomicBool::new(true));
        let uploader = self.clone();
        let stop2 = stop.clone();
        let running2 = running.clone();
        let handle = std::thread::Builder::new()
            .name("afirma-active-waiting".into())
            .spawn(move || {
                loop {
                    if let Err(e) = uploader.store(&http, &storage_servlet, &id, WAIT_TOKEN) {
                        tracing::warn!("Error en la espera activa: {e}");
                    }
                    let (lock, cv) = &*stop2;
                    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    let (guard, _) = cv.wait_timeout_while(guard, interval, |stopped| !*stopped).unwrap_or_else(|e| e.into_inner());
                    if *guard {
                        break;
                    }
                }
                running2.store(false, Ordering::SeqCst);
            })
            .ok();
        ActiveWaiting { stop, handle, running }
    }
}

/// Hilo de espera activa en marcha.
pub struct ActiveWaiting {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl ActiveWaiting {
    /// Detiene la espera activa y espera a que termine su subida en curso.
    pub fn stop(mut self) {
        self.stop_inner();
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn stop_inner(&mut self) {
        let (lock, cv) = &*self.stop;
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ActiveWaiting {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Resultado del sondeo de la página.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Texto definitivo (resultado o error `err-`/`SAF_`/`CANCEL`).
    Data(String),
    /// Se agotó el número de intentos sin `#WAIT`.
    TimedOut,
}

/// Sondea el RetrieveService como AutoScript (`op=get&v=1_0&id=<id>&it=<n>`):
/// `ERR-06` = aún no hay datos; `#WAIT` reinicia el contador; cualquier otra
/// respuesta es definitiva.
pub fn poll_like_autoscript(
    http: &HttpClient,
    retrieve_servlet: &str,
    id: &str,
    interval: Duration,
    max_polls_without_wait: u32,
) -> Result<PollOutcome, HttpError> {
    let mut it = 0u32;
    let mut misses = 0u32;
    loop {
        std::thread::sleep(interval);
        let body = http.post(retrieve_servlet, &format!("op=get&v={SYNTAX_VERSION}&id={id}&it={it}"))?;
        it += 1;
        let text = String::from_utf8_lossy(&body).into_owned();
        let lower = text.to_lowercase();
        if lower.starts_with("err-06") {
            misses += 1;
            if misses > max_polls_without_wait {
                return Ok(PollOutcome::TimedOut);
            }
            continue;
        }
        if lower.starts_with("#wait") {
            misses = 0;
            continue;
        }
        return Ok(PollOutcome::Data(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{MockTransport, ok};

    #[test]
    fn store_and_retrieve_bodies() {
        let t = MockTransport::new(|_| ok("OK"));
        let http = HttpClient::new(t.clone());
        store(&http, "https://h/StorageService", "abc", "MIIB|0.x-_==").unwrap();
        store(&http, "https://h/StorageService", "abc", "err-00:=AF600104 - No se ha recibido el formato de firma").unwrap();
        retrieve(&http, "https://h/RetrieveService", "abc").unwrap();
        assert_eq!(
            t.bodies(),
            vec![
                "op=put&v=1_0&id=abc&dat=MIIB|0.x-_==".to_string(),
                "op=put&v=1_0&id=abc&dat=err-00:=AF600104 - No se ha recibido el formato de firma".to_string(),
                "op=get&v=1_0&id=abc".to_string(),
            ]
        );
        assert!(is_error_response(b"ERR-06:=El identificador"));
        assert!(is_error_response(b"err-00:=AF1234567"));
        assert!(!is_error_response(b"ERR-06:="));
        assert!(!is_error_response(b"MIIBxxxxxx"));
        assert_eq!(store_error(&HttpError::Timeout("x".into())).code.code, 401201);
        assert_eq!(store_error(&HttpError::Io("x".into())).code.code, 401200);
        assert_eq!(
            store_error(&HttpError::CertificateHostMismatch { host: "h".into(), detail: "d".into() }).dialog_params,
            vec!["h".to_string()]
        );
    }

    #[test]
    fn active_waiting_posts_wait() {
        let t = MockTransport::new(|_| ok("OK"));
        let http = HttpClient::new(t.clone());
        let up = Uploader::default();
        let aw = up.start_active_waiting(http.clone(), "https://h/s".into(), "id1".into(), Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(70));
        aw.stop();
        let n = t.bodies().len();
        assert!(n >= 2, "{n}");
        assert!(t.bodies().iter().all(|b| b == "op=put&v=1_0&id=id1&dat=#WAIT"));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(t.bodies().len(), n);
    }

    #[test]
    fn polling() {
        let responses = Mutex::new(vec!["ERR-06:=x\n", "#WAIT\n", "ERR-06:=x\n", "RESULTADO\n"]);
        let http = HttpClient::new(MockTransport::new(move |_| ok(responses.lock().unwrap().remove(0))));
        assert_eq!(
            poll_like_autoscript(&http, "https://h/r", "id", Duration::from_millis(1), 3).unwrap(),
            PollOutcome::Data("RESULTADO\n".into())
        );
        let http = HttpClient::new(MockTransport::new(|_| ok("ERR-06:=x\n")));
        assert_eq!(poll_like_autoscript(&http, "https://h/r", "id", Duration::from_millis(1), 2).unwrap(), PollOutcome::TimedOut);
    }
}
