//! Intercambio con el servidor intermedio tal y como lo hace Autofirma App 1.9
//! (`IntermediateServerUtil`, `SendDataTask`, `DownloadFileTask`,
//! `ActiveWaitingThread`; `docs/spec/09-android.md` §5.8).
//!
//! - Subida: `POST <stservlet>` con cuerpo `op=put&v=1_0&id=<id>&dat=<datos>`.
//!   Los resultados se concatenan tal cual y los errores van antes por
//!   `URLEncoder` ([`super::errors::WebError::upload_text`]). Éxito solo si la
//!   respuesta, recortada, es exactamente `OK`.
//! - Descarga: `POST <rtservlet>` con cuerpo `op=get&v=1_0&id=<fileid>`; ante
//!   `ERR-06` se reintenta cada 2000 ms hasta 10 veces.
//! - Espera activa: cada 10 000 ms se sube `#WAIT` (la primera tras esperar),
//!   bajo un cerrojo común con la subida del resultado.
//!
//! Diferencias con Java (correcciones documentadas):
//! - El cuerpo se envía como cuerpo explícito y no partiendo la URL con
//!   `StringTokenizer("?")`, que perdía lo que siguiera a un segundo `?`
//!   (§10 n.º 44). Los bytes enviados son los mismos.
//! - En los resultados (no en los errores, que ya van codificados) se codifican
//!   `%`, `+` y `&`, que el servlet corrompería al decodificar el formulario
//!   (Java los mandaba crudos: el resultado de un lote sin clave, en Base64
//!   estándar, llegaba a la página con espacios en lugar de `+`). Ningún otro
//!   resultado contiene esos caracteres, así que los bytes coinciden con Java.
//! - La subida del resultado espera a que termine un `#WAIT` en curso (en Java
//!   podían cruzarse y el `#WAIT` llegar después del resultado).

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use afirma_core::http::HttpRequest;

use crate::http::{HttpClient, HttpError};

/// Versión de la sintaxis de los servicios intermedios.
pub const SYNTAX_VERSION: &str = "1_0";
/// Respuesta de éxito del StorageService.
pub const OK_SERVER_RESULT: &str = "OK";
/// Texto de espera activa.
pub const WAIT_TOKEN: &str = "#WAIT";
/// Intervalo de la espera activa (`ActiveWaitingThread.SLEEP_PERIOD`).
pub const ACTIVE_WAITING_INTERVAL: Duration = Duration::from_millis(10_000);
/// Espera entre reintentos de descarga (`DOWNLOAD_TRIES_TIME_LEAP`).
pub const DOWNLOAD_RETRY_DELAY: Duration = Duration::from_millis(2000);
/// Reintentos de descarga ante `ERR-06` (`MAX_DOWNLOAD_TRIES`).
pub const DOWNLOAD_MAX_RETRIES: u32 = 10;

/// Datos que se suben.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Resultado (`cert|firma`, `OK`, `#WAIT`...): se concatena tal cual salvo
    /// `%`, `+` y `&` (ver el módulo).
    Result(String),
    /// Error ya codificado con `URLEncoder`: se concatena tal cual.
    Encoded(String),
}

impl Payload {
    /// Texto que se concatena en `dat=`.
    pub fn wire(&self) -> String {
        match self {
            Payload::Result(s) => {
                let mut out = String::with_capacity(s.len());
                for c in s.chars() {
                    match c {
                        '%' => out.push_str("%25"),
                        '+' => out.push_str("%2B"),
                        '&' => out.push_str("%26"),
                        c => out.push(c),
                    }
                }
                out
            }
            Payload::Encoded(s) => s.clone(),
        }
    }
}

/// Cuerpo de una subida.
pub fn store_body(id: &str, payload: &Payload) -> String {
    format!("op=put&v={SYNTAX_VERSION}&id={id}&dat={}", payload.wire())
}

/// Cuerpo de una descarga.
pub fn retrieve_body(id: &str) -> String {
    format!("op=get&v={SYNTAX_VERSION}&id={id}")
}

/// POST con cuerpo explícito (`AndroidHttpManager.readUrl`).
pub(crate) fn post(http: &HttpClient, url: &str, body: &str) -> Result<Vec<u8>, HttpError> {
    let mut req = HttpRequest::post(url).with_body(body.as_bytes().to_vec());
    req.connect_timeout = http.connect_timeout;
    req.read_timeout = http.read_timeout;
    req.ssl_error_handling = http.ssl_error_handling;
    http.inner().read_url(&req).map_err(HttpError::from)
}

/// Fallo de una subida (`SendDataTask`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UploadError {
    /// Error de red o HTTP.
    #[error("no se pudo conectar con el servidor intermedio: {0}")]
    Http(HttpError),
    /// El servidor no respondió `OK`.
    #[error("el servidor intermedio respondió: {0}")]
    NotOk(String),
}

/// Sube unos datos al StorageService.
pub fn send(http: &HttpClient, storage_servlet: &str, id: &str, payload: &Payload) -> Result<(), UploadError> {
    let body = post(http, storage_servlet, &store_body(id, payload)).map_err(UploadError::Http)?;
    let text = String::from_utf8_lossy(&body);
    if text.trim() == OK_SERVER_RESULT {
        Ok(())
    } else {
        Err(UploadError::NotOk(text.into_owned()))
    }
}

/// Fallo de una descarga (`DownloadFileTask`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DownloadError {
    /// Error de red o HTTP («No se pudo conectar con el servidor intermedio»).
    #[error("No se pudo conectar con el servidor intermedio: {0}")]
    Http(HttpError),
    /// El servidor devolvió `ERR-…` (o `ERR-06` tras agotar los reintentos).
    #[error("El servidor devolvio el siguiente error al descargar los datos: {0}")]
    Server(String),
    /// Respuesta de menos de 4 bytes (en Java, excepción al leer el prefijo).
    #[error("Error desconocido durante la descarga de datos: respuesta de {0} bytes")]
    TooShort(usize),
    /// Se canceló la operación.
    #[error("Se ha cancelado la tarea de descarga")]
    Cancelled,
}

/// Opciones de la descarga.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadOptions {
    pub retry_delay: Duration,
    pub max_retries: u32,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        DownloadOptions {
            retry_delay: DOWNLOAD_RETRY_DELAY,
            max_retries: DOWNLOAD_MAX_RETRIES,
        }
    }
}

/// Descarga el sobre de `fileid` con los reintentos de la app. `cancelled` se
/// consulta antes de cada intento y durante las esperas.
pub fn download(
    http: &HttpClient,
    retrieve_servlet: &str,
    file_id: &str,
    opts: DownloadOptions,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, DownloadError> {
    let mut tries = 0u32;
    loop {
        if cancelled() {
            return Err(DownloadError::Cancelled);
        }
        let data = post(http, retrieve_servlet, &retrieve_body(file_id)).map_err(DownloadError::Http)?;
        if data.len() < 4 {
            return Err(DownloadError::TooShort(data.len()));
        }
        // `ERROR_PREFIX.equalsIgnoreCase(new String(data, 0, 4, UTF-8))`.
        if String::from_utf8_lossy(&data[..4]).eq_ignore_ascii_case("ERR-") {
            let text = String::from_utf8_lossy(&data).into_owned();
            if text.starts_with("ERR-06") && tries < opts.max_retries {
                tries += 1;
                if !sleep_unless(opts.retry_delay, cancelled) {
                    return Err(DownloadError::Cancelled);
                }
                continue;
            }
            return Err(DownloadError::Server(text));
        }
        if cancelled() {
            return Err(DownloadError::Cancelled);
        }
        return Ok(data);
    }
}

/// Espera `d` comprobando la cancelación cada poco. `false` si se canceló.
fn sleep_unless(d: Duration, cancelled: &dyn Fn() -> bool) -> bool {
    let step = Duration::from_millis(50);
    let mut left = d;
    while !left.is_zero() {
        if cancelled() {
            return false;
        }
        let s = left.min(step);
        std::thread::sleep(s);
        left -= s;
    }
    !cancelled()
}

/// Subidas de una invocación: serializa la espera activa y el resultado.
#[derive(Debug, Clone, Default)]
pub struct Uploader {
    lock: Arc<Mutex<()>>,
}

impl Uploader {
    /// Sube unos datos bajo el cerrojo.
    pub fn send(
        &self,
        http: &HttpClient,
        storage_servlet: &str,
        id: &str,
        payload: &Payload,
    ) -> Result<(), UploadError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        send(http, storage_servlet, id, payload)
    }

    /// Arranca la espera activa: espera `interval`, sube `#WAIT` y repite
    /// hasta que se detenga. Los errores se ignoran (como en Java).
    pub fn start_active_waiting(
        &self,
        http: HttpClient,
        storage_servlet: String,
        id: String,
        interval: Duration,
    ) -> ActiveWaiting {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
        let lock = self.lock.clone();
        let st = state.clone();
        let handle = std::thread::Builder::new()
            .name("afirma-android-espera-activa".into())
            .spawn(move || {
                let (stopped, cv) = &*st;
                loop {
                    let guard = stopped.lock().unwrap_or_else(|e| e.into_inner());
                    let (guard, _) = cv
                        .wait_timeout_while(guard, interval, |s| !*s)
                        .unwrap_or_else(|e| e.into_inner());
                    if *guard {
                        break;
                    }
                    drop(guard);
                    let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
                    if *stopped.lock().unwrap_or_else(|e| e.into_inner()) {
                        break;
                    }
                    if let Err(e) = send(&http, &storage_servlet, &id, &Payload::Result(WAIT_TOKEN.into())) {
                        tracing::warn!("No se ha podido enviar la peticion de espera: {e}");
                    }
                }
            })
            .ok();
        ActiveWaiting { state, handle }
    }
}

/// Espera activa en marcha (`ActiveWaitingThread`).
pub struct ActiveWaiting {
    state: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl ActiveWaiting {
    /// Detiene la espera activa (`interrupt`) y espera a que termine el hilo.
    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        let (stopped, cv) = &*self.state;
        *stopped.lock().unwrap_or_else(|e| e.into_inner()) = true;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{MockTransport, Recorded, ok};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn body_of(r: &Recorded) -> String {
        String::from_utf8_lossy(r.body.as_deref().unwrap_or_default()).into_owned()
    }

    #[test]
    fn bodies() {
        assert_eq!(
            store_body("abc", &Payload::Result("0.AA==|5.B-_=".into())),
            "op=put&v=1_0&id=abc&dat=0.AA==|5.B-_="
        );
        assert_eq!(
            store_body(
                "abc",
                &Payload::Encoded("ERR-11%3A%3DAA500001+-+Operacion+cancelada".into())
            ),
            "op=put&v=1_0&id=abc&dat=ERR-11%3A%3DAA500001+-+Operacion+cancelada"
        );
        // Base64 estándar con saltos de línea (firma sin clave) y `+` protegido.
        assert_eq!(Payload::Result("a+b/c\n".into()).wire(), "a%2Bb/c\n");
        assert_eq!(retrieve_body("FID1"), "op=get&v=1_0&id=FID1");
    }

    #[test]
    fn upload_result() {
        let t = MockTransport::new(|_| ok("OK\r\n"));
        let http = HttpClient::new(t.clone());
        send(&http, "https://h/StorageService", "id1", &Payload::Result("X".into())).unwrap();
        let t = MockTransport::new(|_| ok("ERR-05:=x"));
        let http = HttpClient::new(t.clone());
        assert!(matches!(
            send(&http, "https://h/s", "id1", &Payload::Result("X".into())),
            Err(UploadError::NotOk(_))
        ));
    }

    #[test]
    fn download_retries_err06() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let t = MockTransport::new(move |r| {
            assert_eq!(body_of(r), "op=get&v=1_0&id=F");
            if n2.fetch_add(1, Ordering::SeqCst) < 3 {
                ok("ERR-06:=El identificador para los datos es inválido\n")
            } else {
                ok("0.lNRDa8O1tpM=\n")
            }
        });
        let http = HttpClient::new(t.clone());
        let opts = DownloadOptions {
            retry_delay: Duration::from_millis(1),
            max_retries: 10,
        };
        assert_eq!(
            download(&http, "https://h/r", "F", opts, &|| false).unwrap(),
            b"0.lNRDa8O1tpM=\n"
        );
        assert_eq!(n.load(Ordering::SeqCst), 4);

        // Agotados los reintentos: 11 peticiones y error.
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let http = HttpClient::new(MockTransport::new(move |_| {
            n2.fetch_add(1, Ordering::SeqCst);
            ok("ERR-06:=x")
        }));
        assert!(matches!(
            download(&http, "https://h/r", "F", opts, &|| false),
            Err(DownloadError::Server(_))
        ));
        assert_eq!(n.load(Ordering::SeqCst), 11);

        // `err-` en minúsculas es error (sin reintento: `ERR-06` distingue mayúsculas).
        let http = HttpClient::new(MockTransport::new(|_| ok("err-06:=x")));
        assert!(matches!(
            download(&http, "https://h/r", "F", opts, &|| false),
            Err(DownloadError::Server(_))
        ));
        let http = HttpClient::new(MockTransport::new(|_| ok("OK")));
        assert_eq!(
            download(&http, "https://h/r", "F", opts, &|| false),
            Err(DownloadError::TooShort(2))
        );
        let http = HttpClient::new(MockTransport::new(|_| ok("datos")));
        assert_eq!(
            download(&http, "https://h/r", "F", opts, &|| true),
            Err(DownloadError::Cancelled)
        );
    }

    #[test]
    fn explicit_body_is_sent() {
        let t = MockTransport::new(|_| ok("OK"));
        let http = HttpClient::new(t.clone());
        // Un segundo `?` ya no corta el cuerpo (§10 n.º 44).
        post(&http, "https://h/s", "op=put&v=1_0&id=a&dat=x?y").unwrap();
        let reqs = t.requests.lock().unwrap();
        assert_eq!(reqs[0].url, "https://h/s");
        assert_eq!(body_of(&reqs[0]), "op=put&v=1_0&id=a&dat=x?y");
    }

    #[test]
    fn active_waiting_waits_first_and_stops() {
        let t = MockTransport::new(|_| ok("OK"));
        let http = HttpClient::new(t.clone());
        let up = Uploader::default();
        let aw = up.start_active_waiting(
            http.clone(),
            "https://h/s".into(),
            "id1".into(),
            Duration::from_secs(60),
        );
        std::thread::sleep(Duration::from_millis(50));
        // La primera subida llega tras el primer intervalo.
        assert!(t.requests.lock().unwrap().is_empty());
        aw.stop();
        let aw = up.start_active_waiting(http, "https://h/s".into(), "id1".into(), Duration::from_millis(5));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while t.requests.lock().unwrap().len() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        aw.stop();
        let n = t.requests.lock().unwrap().len();
        assert!(n >= 2);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(t.requests.lock().unwrap().len(), n);
    }
}
