//! Puente entre la interfaz, los hilos de trabajo y la capa Java.
//!
//! # Modelo de hilos
//!
//! - **Hilo de la interfaz** (`android_main`): ejecuta el bucle de eventos de winit y egui.
//!   Nunca se bloquea: las llamadas a Java que solo *inician* algo (abrir el selector de
//!   documentos, el de certificados) vuelven enseguida y el resultado llega después como un
//!   [`PlatformEvent`].
//! - **Hilo principal de Java**: ciclo de vida de la actividad, intents y resultados de las
//!   actividades del sistema. La capa Java no ejecuta código de Rust largo en él: los
//!   métodos nativos de `NativeBridge` solo copian los datos y encolan un evento.
//! - **Hilos de trabajo** (Rust, `std::thread`) y el ejecutor de E/S de la capa Java:
//!   lectura de ficheros, análisis y firma, y las llamadas bloqueantes a Java (cadena de
//!   certificados y firma con KeyChain, intercambio de APDU por NFC). Los hilos de Rust se
//!   enganchan a la JVM la primera vez que llaman a Java.
//!
//! Los eventos se encolan en un [`Bridge`] y despiertan la interfaz con
//! [`egui::Context::request_repaint`], que se puede llamar desde cualquier hilo.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use afirma_core::SignatureAlgorithm;

use crate::ime::{ImeRequest, ImeState};

/// Identificador de una petición a la capa Java (para casar la respuesta con su petición).
pub type RequestId = i64;

/// Error de una llamada a la plataforma (excepción de Java, error de JNI...).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PlatformError(pub String);

impl PlatformError {
    pub fn new(message: impl Into<String>) -> Self {
        PlatformError(message.into())
    }
}

/// Operaciones que la parte de Rust pide a la capa Java.
///
/// Los métodos que abren una actividad del sistema no bloquean: devuelven en cuanto la
/// petición se ha enviado al hilo principal de Java y el resultado llega como
/// [`PlatformEvent`] con el mismo [`RequestId`]. Los métodos bloqueantes no se deben llamar
/// desde el hilo de la interfaz ni desde el hilo principal de Java.
pub trait Platform: Send + Sync {
    /// Abre el selector de documentos del sistema (`ACTION_OPEN_DOCUMENT`). Respuesta:
    /// [`PlatformEvent::DocumentOpened`] o [`PlatformEvent::RequestFailed`].
    fn open_document(&self, request: RequestId) -> Result<(), PlatformError>;

    /// Abre el selector de certificados de KeyChain (`KeyChain.choosePrivateKeyAlias`).
    /// Respuesta: [`PlatformEvent::CertificateChosen`].
    fn choose_certificate(&self, request: RequestId) -> Result<(), PlatformError>;

    /// Cadena de certificados (DER) de un alias de KeyChain. Bloqueante.
    fn certificate_chain(&self, alias: &str) -> Result<Vec<Vec<u8>>, PlatformError>;

    /// Firma `data` con la clave privada de un alias de KeyChain
    /// (`java.security.Signature` con el nombre Java del algoritmo). Bloqueante.
    fn sign(&self, alias: &str, algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, PlatformError>;

    /// Activa el modo lector NFC (`NfcAdapter.enableReaderMode`) para tarjetas ISO 14443-4
    /// (DNIe). Respuesta: [`PlatformEvent::NfcTag`] al acercar una tarjeta, o
    /// [`PlatformEvent::RequestFailed`] si el dispositivo no tiene NFC o está desactivado.
    fn start_nfc_reader(&self, request: RequestId) -> Result<(), PlatformError>;

    /// Envía una APDU a la tarjeta NFC detectada y devuelve la respuesta (con SW1 SW2).
    /// Bloqueante.
    fn nfc_transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, PlatformError>;

    /// Desactiva el modo lector NFC y cierra la conexión con la tarjeta.
    fn stop_nfc_reader(&self) -> Result<(), PlatformError>;

    /// Deja la aplicación en segundo plano (`moveTaskToBack`): «Atrás» en la pantalla
    /// principal. La actividad no se destruye (winit no puede crear otro bucle de eventos).
    fn leave_app(&self) -> Result<(), PlatformError>;

    /// Indica si «Atrás» dejaría ahora la app en segundo plano (pantalla raíz sin diálogo).
    /// Entonces Java llama a `moveTaskToBack` en el mismo gesto, sin pasar por Rust: hecho
    /// después, desde otro mensaje del hilo principal, el sistema a veces no mueve la tarea.
    fn set_back_at_root(&self, at_root: bool) -> Result<(), PlatformError>;

    /// Abre una URL en el navegador (`ACTION_VIEW`). Si no hay ninguna aplicación que la
    /// abra, responde [`PlatformEvent::RequestFailed`].
    fn open_url(&self, request: RequestId, url: &str) -> Result<(), PlatformError>;

    /// Abre el teclado en pantalla con el tipo de entrada y el estado de un campo.
    fn ime_show(&self, request: &ImeRequest) -> Result<(), PlatformError>;

    /// Cambia el texto o la selección que conoce el teclado (cambios hechos en egui).
    fn ime_update(&self, state: &ImeState) -> Result<(), PlatformError>;

    /// Cierra el teclado en pantalla.
    fn ime_hide(&self) -> Result<(), PlatformError>;
}

/// Configuración del dispositivo que interesa a la interfaz (la envía Java al crear la
/// actividad y en cada `onConfigurationChanged`).
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceConfig {
    /// Idioma del sistema (`Locale.toLanguageTag()`, p. ej. `ca-ES-valencia`).
    pub locale: String,
    /// Tema oscuro del sistema (`UI_MODE_NIGHT_YES`).
    pub night: bool,
    /// Escala del texto de accesibilidad (`Configuration.fontScale`).
    pub font_scale: f32,
    /// El dispositivo tiene NFC (`NfcAdapter.getDefaultAdapter() != null`).
    pub has_nfc: bool,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            locale: String::new(),
            night: false,
            font_scale: 1.0,
            has_nfc: false,
        }
    }
}

/// Evento para la interfaz.
#[derive(Debug, Clone, PartialEq)]
pub enum PlatformEvent {
    /// Intent `VIEW` con una URL (`afirma://...`), al arrancar o con la actividad abierta.
    ViewIntent { uri: String },
    /// Documento elegido en el selector del sistema, ya leído.
    DocumentOpened {
        request: RequestId,
        uri: String,
        name: Option<String>,
        data: Vec<u8>,
    },
    /// Análisis terminado de un documento (hilo de trabajo).
    DocumentAnalyzed {
        request: RequestId,
        summary: crate::document::DocumentSummary,
    },
    /// Alias elegido en el selector de KeyChain (`None` si el usuario no eligió ninguno).
    CertificateChosen { request: RequestId, alias: Option<String> },
    /// Cadena de certificados de un alias (hilo de trabajo).
    CertificateLoaded {
        request: RequestId,
        alias: String,
        chain: Result<Vec<Vec<u8>>, PlatformError>,
    },
    /// Tarjeta ISO-DEP detectada y conectada por el lector NFC.
    NfcTag { request: RequestId, tag: NfcTagInfo },
    /// La petición no terminó: cancelada por el usuario o con error.
    RequestFailed {
        request: RequestId,
        cancelled: bool,
        message: Option<String>,
    },
    /// Botón o gesto «Atrás» del sistema (`OnBackPressedDispatcher`).
    Back,
    /// Configuración del dispositivo (al arrancar y cuando cambia).
    Configuration(DeviceConfig),
    /// Nuevo estado del editor del teclado en pantalla (`stateChanged`).
    ImeState(ImeState),
    /// Tecla de acción del teclado (`onEditorAction`, con el `actionId`).
    ImeAction(i32),
    /// El teclado en pantalla se ha mostrado u ocultado.
    ImeVisibility(bool),
}

/// Datos de una tarjeta ISO-DEP detectada: los que necesita la identificación del DNIe
/// (`docs/spec/10-dnie-nfc.md` §3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NfcTagInfo {
    /// Identificador de la etiqueta (`Tag.getId`: UID o PUPI, a menudo aleatorio).
    pub id: Vec<u8>,
    /// `IsoDep.getHistoricalBytes()` (NFC-A).
    pub historical_bytes: Option<Vec<u8>>,
    /// `IsoDep.getHiLayerResponse()` (NFC-B).
    pub hi_layer_response: Option<Vec<u8>>,
    /// `NfcB.getApplicationData()` (NFC-B).
    pub nfcb_application_data: Option<Vec<u8>>,
    /// `NfcB.getProtocolInfo()` (NFC-B).
    pub nfcb_protocol_info: Option<Vec<u8>>,
}

/// Márgenes de la zona segura en píxeles físicos (barras del sistema, recortes de la
/// pantalla y teclado en pantalla), en el orden izquierda, arriba, derecha, abajo.
pub type SafeAreaPx = [f32; 4];

/// Cola de eventos para la interfaz y estado compartido con la capa Java.
#[derive(Default)]
pub struct Bridge {
    events: Mutex<VecDeque<PlatformEvent>>,
    repaint: Mutex<Option<egui::Context>>,
    next_request: AtomicI64,
    safe_area: Mutex<Option<SafeAreaPx>>,
}

impl Bridge {
    pub fn new() -> Self {
        Bridge::default()
    }

    /// Puente del proceso, el que usan los métodos nativos llamados desde Java.
    pub fn global() -> &'static Arc<Bridge> {
        static GLOBAL: OnceLock<Arc<Bridge>> = OnceLock::new();
        GLOBAL.get_or_init(|| Arc::new(Bridge::new()))
    }

    /// Contexto de egui al que se pide repintar cuando llega un evento.
    pub fn set_repaint_context(&self, ctx: egui::Context) {
        *self.repaint.lock().unwrap_or_else(PoisonError::into_inner) = Some(ctx);
    }

    fn request_repaint(&self) {
        if let Some(ctx) = self.repaint.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            ctx.request_repaint();
        }
    }

    /// Encola un evento y despierta la interfaz. Se puede llamar desde cualquier hilo.
    pub fn post(&self, event: PlatformEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(event);
        self.request_repaint();
    }

    /// Saca todos los eventos pendientes, en orden de llegada.
    pub fn drain(&self) -> Vec<PlatformEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect()
    }

    /// Nuevo identificador de petición (positivo y creciente).
    pub fn next_request_id(&self) -> RequestId {
        self.next_request.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Actualiza la zona segura (píxeles físicos) y repinta.
    pub fn set_safe_area_px(&self, insets: SafeAreaPx) {
        *self.safe_area.lock().unwrap_or_else(PoisonError::into_inner) = Some(insets);
        self.request_repaint();
    }

    /// Última zona segura recibida de Java.
    pub fn safe_area_px(&self) -> Option<SafeAreaPx> {
        *self.safe_area.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Zona segura de egui (puntos) a partir de los márgenes en píxeles físicos.
pub fn safe_area_points(insets: SafeAreaPx, pixels_per_point: f32) -> egui::SafeAreaInsets {
    let ppp = if pixels_per_point > 0.0 { pixels_per_point } else { 1.0 };
    let [left, top, right, bottom] = insets.map(|v| v.max(0.0) / ppp);
    egui::SafeAreaInsets(egui::epaint::MarginF32 {
        left,
        right,
        top,
        bottom,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eventos_en_orden_y_ids_crecientes() {
        let bridge = Bridge::new();
        let a = bridge.next_request_id();
        let b = bridge.next_request_id();
        assert!(a > 0 && b > a);
        bridge.post(PlatformEvent::ViewIntent {
            uri: "afirma://a".into(),
        });
        bridge.post(PlatformEvent::CertificateChosen {
            request: a,
            alias: None,
        });
        let events = bridge.drain();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            PlatformEvent::ViewIntent {
                uri: "afirma://a".into()
            }
        );
        assert!(bridge.drain().is_empty());
    }

    #[test]
    fn post_despierta_la_interfaz() {
        let bridge = Bridge::new();
        let ctx = egui::Context::default();
        bridge.set_repaint_context(ctx.clone());
        // Tras una pasada sin peticiones de repintado, el evento pide otra.
        ctx.run_ui(egui::RawInput::default(), |_| {}).textures_delta.clear();
        bridge.post(PlatformEvent::ViewIntent {
            uri: "afirma://b".into(),
        });
        assert!(ctx.has_requested_repaint());
    }

    #[test]
    fn zona_segura_en_puntos() {
        let bridge = Bridge::new();
        assert_eq!(bridge.safe_area_px(), None);
        bridge.set_safe_area_px([0.0, 63.0, 0.0, 126.0]);
        let insets = safe_area_points(bridge.safe_area_px().unwrap(), 2.625);
        assert_eq!(insets.0.top, 24.0);
        assert_eq!(insets.0.bottom, 48.0);
        assert_eq!(safe_area_points([-5.0, 10.0, 0.0, 0.0], 0.0).0.left, 0.0);
    }
}
