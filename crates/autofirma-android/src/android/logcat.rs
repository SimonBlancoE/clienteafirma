//! Registro en logcat: los eventos de `tracing` (y los de `log` de winit, eframe y egui, a
//! través de `tracing-log`) se escriben con `__android_log_write` y la etiqueta
//! [`crate::LOG_TAG`].

use std::ffi::{CString, c_char, c_int};
use std::io;

use tracing::{Level, Metadata};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

// Prioridades de android/log.h.
const ANDROID_LOG_DEBUG: c_int = 3;
const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_WARN: c_int = 5;
const ANDROID_LOG_ERROR: c_int = 6;

/// logcat corta los mensajes de más de ~4 KB: se parten en trozos.
const MAX_CHUNK: usize = 3000;

/// Filtro por defecto (la variable de entorno `AUTOFIRMA_LOG` lo sustituye, con la sintaxis de
/// `EnvFilter`; las aplicaciones de Android no suelen tenerla). winit avisa con «TODO» de los
/// eventos de ciclo de vida que no reenvía: solo se registran sus errores.
const DEFAULT_FILTER: &str = "info,winit=error,eframe=warn,egui_glow=warn,glutin=warn";

pub fn init() {
    let filter = std::env::var("AUTOFIRMA_LOG")
        .ok()
        .and_then(|f| EnvFilter::try_new(f).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_FILTER));
    let result = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(Logcat)
        .with_ansi(false)
        .without_time()
        .with_level(false)
        .with_target(false)
        .try_init();
    if let Err(e) = result {
        write(ANDROID_LOG_WARN, &format!("El registro ya estaba iniciado: {e}"));
    }
}

fn write(priority: c_int, text: &str) {
    let tag = CString::new(crate::LOG_TAG).unwrap_or_default();
    let mut rest = text.trim_end();
    while !rest.is_empty() {
        let mut end = rest.len().min(MAX_CHUNK);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (chunk, tail) = rest.split_at(end);
        let message = CString::new(chunk.replace('\0', "\u{fffd}")).unwrap_or_default();
        // SAFETY: las dos cadenas terminan en NUL y viven hasta que vuelve la llamada.
        unsafe {
            __android_log_write(priority, tag.as_ptr(), message.as_ptr());
        }
        rest = tail;
    }
}

struct Logcat;

/// Acumula un mensaje formateado y lo escribe en logcat al soltarse.
struct LogcatLine {
    priority: c_int,
    buffer: Vec<u8>,
}

impl io::Write for LogcatLine {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogcatLine {
    fn drop(&mut self) {
        write(self.priority, &String::from_utf8_lossy(&self.buffer));
    }
}

impl<'a> MakeWriter<'a> for Logcat {
    type Writer = LogcatLine;

    fn make_writer(&'a self) -> Self::Writer {
        LogcatLine {
            priority: ANDROID_LOG_INFO,
            buffer: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        let priority = match *meta.level() {
            Level::ERROR => ANDROID_LOG_ERROR,
            Level::WARN => ANDROID_LOG_WARN,
            Level::INFO => ANDROID_LOG_INFO,
            Level::DEBUG | Level::TRACE => ANDROID_LOG_DEBUG,
        };
        LogcatLine {
            priority,
            buffer: Vec::new(),
        }
    }
}
