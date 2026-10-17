//! Peticiones sueltas a la plataforma: «Ver un certificado» (selector de KeyChain y cadena del
//! alias), abrir enlaces y recibir peticiones `afirma://`. Las operaciones de varios pasos
//! (firma local, importación de certificados) están en [`crate::flow`].
//!
//! No depende de Android: las pruebas usan la [`Platform`] falsa. Los mensajes de registro
//! («Selector de certificados abierto»...) los busca la prueba del emulador.

use std::collections::HashMap;
use std::sync::Arc;

use afirma_core::cert::CertInfo;
use afirma_protocol::request::{Dispatch, OperationKind, dispatch};
use tracing::{error, info, warn};

use crate::bridge::{Bridge, Platform, PlatformError, PlatformEvent, RequestId};

/// Qué se espera de cada petición en curso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    ChooseCertificate,
    LoadCertificate,
    OpenUrl,
}

/// Certificado elegido en KeyChain.
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateState {
    Loading { alias: String },
    Ready(CertificateSummary),
    Failed { alias: String, message: String },
}

/// Datos del certificado del alias elegido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    pub alias: String,
    pub subject: String,
    pub issuer: String,
    /// Inicio de la validez (`dd/MM/yyyy`).
    pub not_before: String,
    /// Fin de la validez (`dd/MM/yyyy`).
    pub not_after: String,
    pub chain_len: usize,
    /// Avisos sobre el certificado (caducado, próximo a caducar, seudónimo).
    pub warnings: Vec<crate::keychain::CertificateWarning>,
}

/// Última petición web (`afirma://`) recibida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRequest {
    /// Operación (`sign`, `selectcert`, `batch`, `save`...), si se ha reconocido.
    pub operation: Option<&'static str>,
    /// La app de Android la atiende (§5.3: ni WebSocket, ni servicio, ni `signandsave`/`load`).
    pub supported: bool,
    /// Descripción para el registro.
    pub description: String,
}

/// Lo que la interfaz tiene que hacer tras un evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Ha llegado una petición web (ir a su pantalla).
    WebRequest,
    /// Error que hay que mostrar.
    Error(String),
}

/// Estado de las funciones de plataforma.
pub struct Features {
    platform: Arc<dyn Platform>,
    bridge: Arc<Bridge>,
    pending: HashMap<RequestId, Pending>,
    pub certificate: Option<CertificateState>,
    pub web_request: Option<WebRequest>,
}

impl Features {
    pub fn new(platform: Arc<dyn Platform>, bridge: Arc<Bridge>) -> Features {
        Features {
            platform,
            bridge,
            pending: HashMap::new(),
            certificate: None,
            web_request: None,
        }
    }

    /// `true` mientras haya alguna petición o tarea en curso.
    pub fn is_busy(&self) -> bool {
        self.pending.values().any(|p| !matches!(p, Pending::OpenUrl))
    }

    /// Abre el selector de certificados de KeyChain.
    pub fn choose_certificate(&mut self) -> Result<(), String> {
        let request = self.bridge.next_request_id();
        match self.platform.choose_certificate(request) {
            Ok(()) => {
                info!("Selector de certificados abierto (petición {request})");
                self.pending.insert(request, Pending::ChooseCertificate);
                Ok(())
            }
            Err(e) => Err(request_error("No se pudo abrir el selector de certificados", &e)),
        }
    }

    /// Abre una URL en el navegador.
    pub fn open_url(&mut self, url: &str) -> Result<(), String> {
        let request = self.bridge.next_request_id();
        match self.platform.open_url(request, url) {
            Ok(()) => {
                info!("Enlace abierto en el navegador: {url}");
                self.pending.insert(request, Pending::OpenUrl);
                Ok(())
            }
            Err(e) => Err(request_error("No se pudo abrir el enlace", &e)),
        }
    }

    /// Atiende un evento de Java o de un hilo de trabajo. Los eventos de la interfaz
    /// (Atrás, configuración, teclado) no son de aquí y se ignoran.
    pub fn handle_event(&mut self, event: PlatformEvent) -> Option<Outcome> {
        match event {
            PlatformEvent::ViewIntent { uri } => {
                let request = describe_web_request(&uri);
                info!("Petición web recibida: {}", request.description);
                self.web_request = Some(request);
                Some(Outcome::WebRequest)
            }
            PlatformEvent::CertificateChosen { request, alias } => {
                if !self.take_pending(request, Pending::ChooseCertificate) {
                    return None;
                }
                let Some(alias) = alias else {
                    info!("Selector de certificados cerrado sin elegir (petición {request})");
                    return None;
                };
                info!("Certificado elegido (petición {request})");
                self.certificate = Some(CertificateState::Loading { alias: alias.clone() });
                self.pending.insert(request, Pending::LoadCertificate);
                let (platform, bridge) = (self.platform.clone(), self.bridge.clone());
                spawn_worker("keychain", move || {
                    let chain = platform.certificate_chain(&alias);
                    bridge.post(PlatformEvent::CertificateLoaded { request, alias, chain });
                });
                None
            }
            PlatformEvent::CertificateLoaded { request, alias, chain } => {
                if !self.take_pending(request, Pending::LoadCertificate) {
                    return None;
                }
                self.certificate = Some(match chain.map_err(|e| e.0).and_then(|c| summarize_chain(&alias, &c)) {
                    Ok(summary) => {
                        info!("Cadena del certificado leída: {} certificados", summary.chain_len);
                        CertificateState::Ready(summary)
                    }
                    Err(message) => {
                        warn!("No se pudo leer el certificado: {message}");
                        CertificateState::Failed { alias, message }
                    }
                });
                None
            }
            PlatformEvent::NfcTag { request, .. } => {
                info!("Tarjeta NFC detectada (petición {request}); aún no se usa");
                None
            }
            PlatformEvent::RequestFailed {
                request,
                cancelled,
                message,
            } => {
                let what = match self.pending.remove(&request) {
                    Some(Pending::ChooseCertificate) => "Selector de certificados",
                    Some(Pending::OpenUrl) => "Enlace",
                    _ => "Petición",
                };
                if cancelled {
                    info!("{what} cancelado (petición {request})");
                    None
                } else {
                    let message = message.unwrap_or_else(|| "error desconocido".to_string());
                    warn!("{what}: error en la petición {request}: {message}");
                    Some(Outcome::Error(message))
                }
            }
            PlatformEvent::DocumentOpened { request, .. }
            | PlatformEvent::DocumentSaved { request, .. }
            | PlatformEvent::CertificateInstalled { request }
            | PlatformEvent::SignFinished { request, .. }
            | PlatformEvent::PreviewOpened { request, .. }
            | PlatformEvent::PageRendered { request, .. } => {
                warn!("Respuesta inesperada para la petición {request}");
                None
            }
            PlatformEvent::Back
            | PlatformEvent::Configuration(_)
            | PlatformEvent::ImeState(_)
            | PlatformEvent::ImeAction(_)
            | PlatformEvent::ImeVisibility(_) => None,
        }
    }

    /// Quita una petición pendiente si es del tipo esperado.
    fn take_pending(&mut self, request: RequestId, expected: Pending) -> bool {
        if self.pending.get(&request) == Some(&expected) {
            self.pending.remove(&request);
            true
        } else {
            warn!("Respuesta inesperada para la petición {request} (se esperaba {expected:?})");
            false
        }
    }
}

fn request_error(what: &str, e: &PlatformError) -> String {
    warn!("{what}: {e}");
    e.to_string()
}

fn spawn_worker(name: &str, job: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(format!("autofirma-{name}")).spawn(job) {
        error!("No se pudo crear el hilo de trabajo {name}: {e}");
    }
}

/// Describe una URL `afirma://` con el reparto del protocolo (`afirma-protocol`). En Android
/// AutoScript usa siempre el servidor intermedio y la app oficial solo atiende `sign`,
/// `cosign`, `countersign`, `selectcert`, `batch` y `save` (`docs/spec/09-android.md` §5).
pub fn describe_web_request(uri: &str) -> WebRequest {
    let (operation, supported, description) = match dispatch(uri) {
        Dispatch::Operation(kind @ (OperationKind::SignAndSave | OperationKind::Load)) => (
            Some(kind.name()),
            false,
            format!("Operación «{}» (no disponible en Android)", kind.name()),
        ),
        Dispatch::Operation(kind) => (Some(kind.name()), true, format!("Operación «{}»", kind.name())),
        Dispatch::WebSocket => (None, false, "Conexión por WebSocket (no disponible en Android)".into()),
        Dispatch::Service => (None, false, "Socket de servicio (no disponible en Android)".into()),
        Dispatch::UnsupportedScheme => (None, false, "Esquema no soportado".into()),
        Dispatch::UnsupportedOperation => (None, false, "Operación desconocida".into()),
    };
    WebRequest {
        operation,
        supported,
        description,
    }
}

/// Resumen del certificado del firmante de una cadena DER.
pub fn summarize_chain(alias: &str, chain: &[Vec<u8>]) -> Result<CertificateSummary, String> {
    let leaf = chain.first().ok_or("el alias no tiene certificados")?;
    let info = CertInfo::parse(leaf).ok_or("el certificado no es válido")?;
    Ok(CertificateSummary {
        alias: alias.to_string(),
        subject: info.subject_cn,
        issuer: info.issuer_cn,
        not_before: info.not_before.format("%d/%m/%Y").to_string(),
        not_after: info.not_after.format("%d/%m/%Y").to_string(),
        chain_len: chain.len(),
        warnings: crate::keychain::certificate_warnings(leaf, chrono::Utc::now()),
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::testing::{FakePlatform, test_certificate};

    fn features() -> (Features, Arc<FakePlatform>, Arc<Bridge>) {
        let platform = Arc::new(FakePlatform {
            chain: vec![test_certificate("Firmante de prueba"), test_certificate("CA de prueba")],
            ..Default::default()
        });
        let bridge = Arc::new(Bridge::new());
        (Features::new(platform.clone(), bridge.clone()), platform, bridge)
    }

    /// Atiende eventos hasta que no quede trabajo pendiente.
    fn settle(features: &mut Features, bridge: &Bridge) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while features.is_busy() {
            assert!(Instant::now() < deadline, "tareas sin terminar");
            for event in bridge.drain() {
                features.handle_event(event);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn cancelar_errores_y_respuestas_inesperadas() {
        let (mut f, _, _) = features();
        f.choose_certificate().unwrap();
        let cancelled = PlatformEvent::RequestFailed {
            request: 1,
            cancelled: true,
            message: None,
        };
        assert_eq!(f.handle_event(cancelled), None);
        assert!(!f.is_busy());
        // Una respuesta de una petición que no existe no cambia nada.
        f.handle_event(PlatformEvent::CertificateChosen {
            request: 99,
            alias: Some("firmante".into()),
        });
        assert_eq!(f.certificate, None);
        f.open_url("https://ejemplo.es").unwrap();
        assert!(!f.is_busy(), "abrir un enlace no bloquea la interfaz");
        let failed = PlatformEvent::RequestFailed {
            request: 2,
            cancelled: false,
            message: Some("sin navegador".into()),
        };
        assert_eq!(f.handle_event(failed), Some(Outcome::Error("sin navegador".into())));
    }

    #[test]
    fn certificado_elegido_se_carga_en_un_hilo_de_trabajo() {
        let (mut f, platform, bridge) = features();
        f.choose_certificate().unwrap();
        f.handle_event(PlatformEvent::CertificateChosen {
            request: 1,
            alias: Some("firmante".into()),
        });
        settle(&mut f, &bridge);
        match &f.certificate {
            Some(CertificateState::Ready(c)) => {
                assert_eq!(c.subject, "Firmante de prueba");
                assert_eq!(c.chain_len, 2);
                assert_eq!(c.not_after.len(), 10);
            }
            other => panic!("certificado no cargado: {other:?}"),
        }
        assert_eq!(platform.calls(), ["choose_certificate 1", "certificate_chain firmante"]);

        // Alias desconocido: el error de Java se muestra.
        f.choose_certificate().unwrap();
        f.handle_event(PlatformEvent::CertificateChosen {
            request: 2,
            alias: Some("otro".into()),
        });
        settle(&mut f, &bridge);
        assert!(
            matches!(&f.certificate, Some(CertificateState::Failed { message, .. }) if message.contains("KeyChainException"))
        );
        // Sin elegir: no cambia nada.
        f.choose_certificate().unwrap();
        assert_eq!(
            f.handle_event(PlatformEvent::CertificateChosen {
                request: 3,
                alias: None
            }),
            None
        );
    }

    #[test]
    fn peticiones_web() {
        let (mut f, _, _) = features();
        let outcome = f.handle_event(PlatformEvent::ViewIntent {
            uri: "afirma://sign?op=sign&id=1234".into(),
        });
        assert_eq!(outcome, Some(Outcome::WebRequest));
        let request = f.web_request.clone().unwrap();
        assert_eq!(request.operation, Some("sign"));
        assert!(request.supported);
        assert_eq!(request.description, "Operación «sign»");
        assert!(!describe_web_request("afirma://service?ports=1").supported);
        assert!(!describe_web_request("afirma://websocket?v=4").supported);
        assert!(!describe_web_request("afirma://load?id=1").supported);
        assert_eq!(
            describe_web_request("afirma://selectcert?id=1").operation,
            Some("selectcert")
        );
        assert!(!describe_web_request("https://example.org").supported);
    }
}
