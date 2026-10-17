//! Flujo de las operaciones web de Autofirma App 1.9 (`WebSignActivity`,
//! `WebSelectCertificateActivity`, `WebSaveDataActivity`,
//! `WebSignBatchActivity`, `SignFragmentActivity`, `SignTask`,
//! `SignBatchFragmentActivity`; `docs/spec/09-android.md` §5 y §6) sin
//! interfaz: la app aporta los diálogos ([`AndroidWebHandler`]) y la firma
//! monofásica ([`LocalSigner`]).
//!
//! Correcciones respecto a la app original (todas documentadas en
//! `docs/deviations/afirma-protocol.md`, sección Android):
//! - Los errores de parámetros (y los de un sobre que no se puede descargar o
//!   leer) se responden a la web con `ERR-22`/`ERR-14`… en lugar de no llegar
//!   nunca (Java lo intentaba sin `stservlet` y fallaba con
//!   `NullPointerException`, a veces cerrando la app): §10 n.º 35 y 36.
//! - Una petición válida sin `stservlet` ya no cierra la app al responder: no
//!   hay a quién responder ([`Reply::NotSent`]).
//! - La firma visible funciona con los datos en `dat` y en el sobre (§10
//!   n.º 33); con el sobre también se expande la política y se comprueba el
//!   PDF (n.º 64); PAdES sobre datos no PDF responde `ERR-07` y **no** sigue
//!   firmando (n.º 32).
//! - Los errores tras elegir el fichero y los de lectura se responden (n.º 56).
//! - Error al cifrar el certificado: `ERR-16` en vez de `null|<firma>`
//!   (n.º 37); en `selectcert`, `ERR-16` con AA200200 en vez de
//!   `NullPointerException` (n.º 62).
//! - `save`: textos de error siempre disponibles (n.º 2), nombre propuesto sin
//!   duplicar (n.º 49), errores de parámetros respondidos (n.º 50).
//! - Una sola respuesta final por invocación: «Atrás» tras un error ya subido
//!   no sube además `ERR-11` (n.º 42).
//! - Lotes XML y locales soportados con los firmadores del núcleo (n.º 53);
//!   un fallo de subida no crítico no deja la operación abierta (n.º 52).
//!
//! Como en la app, `sign`, `selectcert` y `save` no envían `#WAIT` aunque
//! llegue `aw=true`: la espera activa solo se usa en lotes con sobre (§10
//! n.º 41 permitiría enviarlo; se mantiene el comportamiento observable).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use afirma_core::error::{ErrorKind, UserIntervention, codes};
use afirma_core::{AfirmaError, CounterSignTarget, ExtraParams, SigningKey};

use super::batch::{BatchFailure, sign_json_batch};
use super::cipher::{android_base64_url_wrapped, decipher_data, encode_or_cipher};
use super::errors::*;
use super::formats::{
    AndroidSigner, PDF_FILTER_FORMATS, PDF_FORMATS, POLICY_EXPANSION_FORMATS, auto_signer, is_auto_detection,
    is_pdf_file, signer_for_format,
};
use super::handler::*;
use super::intermediate::{self, DownloadOptions, Payload, Uploader};
use super::request::{
    self, BatchRequest, CommonParams, ReplyTarget, SaveRequest, SelectCertRequest, SignRequest, WebOperation,
    WebParams, reply_hint, reply_hint_lenient,
};
use super::sticky::{DEFAULT_STICKY_TIMEOUT, StickyKeyCache};
use super::texts::{UserText, WebLanguage};
use crate::handler::{LocalSignRequest, LocalSigner};
use crate::http::HttpClient;
use crate::triphase::{CryptoOperation, TriphaseClient};

/// Configuración (preferencias de la app que afectan a las operaciones web).
#[derive(Debug, Clone)]
pub struct AndroidWebConfig {
    /// Cliente HTTP (servidor intermedio, descargas de `dat`, trifásica y
    /// lotes). Para reproducir la app: sin proxy, sin tiempos de espera y con
    /// la confianza TLS de [`super::domains::http_trust_overrides`].
    pub http: HttpClient,
    /// Idioma de la app (`localeConfig`): textos de los errores.
    pub language: WebLanguage,
    /// `padesObfuscateCertInfo` (por defecto `true`).
    pub obfuscate_cert_text: bool,
    /// `stickySignatureTimeout` (por defecto 5 minutos).
    pub sticky_timeout: Duration,
    /// Reintentos de la descarga del sobre.
    pub download: DownloadOptions,
    /// Intervalo de la espera activa (10 s).
    pub active_waiting_interval: Duration,
}

impl AndroidWebConfig {
    pub fn new(http: HttpClient) -> Self {
        AndroidWebConfig {
            http,
            language: WebLanguage::Es,
            obfuscate_cert_text: true,
            sticky_timeout: DEFAULT_STICKY_TIMEOUT,
            download: DownloadOptions::default(),
            active_waiting_interval: intermediate::ACTIVE_WAITING_INTERVAL,
        }
    }
}

/// Cómo se invocó la app (§5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationMode {
    /// `afirma://…` desde el navegador: la respuesta se sube al servidor
    /// intermedio.
    Browser,
    /// Otra app con `es.gob.afirma.android.SIGN_SERVICE` o
    /// `SIGN_BATCH_SERVICE`: la respuesta vuelve por el resultado de la
    /// actividad. Solo firma y lotes (`selectcert` y `save` no tienen esta
    /// modalidad y se tratan como navegador).
    App { calling_package: Option<String> },
}

/// Resultado para la app llamante (extras del `Intent` de resultado).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentReply {
    /// `RESULT_OK` con `cert` (DER, si se pudo codificar) y `signature`.
    Signature { cert: Option<Vec<u8>>, signature: Vec<u8> },
    /// `RESULT_OK` con `cert` (o `null` sin `needcert`) y `batchresult`.
    Batch { cert: Option<Vec<u8>>, result: Vec<u8> },
    /// `RESULT_CANCELED` con `errorId` (`ERR-NN`) y `errorMsg`
    /// (`ERR-NN:=AA… - …`, sin codificar).
    Error { error_id: String, error_msg: String },
}

/// Respuesta de la invocación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// Subida correcta al StorageService (`dat` tal cual se envió).
    Uploaded { target: ReplyTarget, payload: String },
    /// La subida falló (si era crítica, ya se mostró el diálogo AA401200).
    UploadFailed {
        target: ReplyTarget,
        payload: String,
        error: String,
    },
    /// Resultado para la app llamante.
    Intent(IntentReply),
    /// No hay a quién responder (la petición no trae `stservlet` o `id`).
    NotSent,
}

/// Tipo de registro del histórico (`signsRecord.txt`, §3.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryKind {
    Web,
    App,
    Batch,
    BatchApp,
}

impl HistoryKind {
    /// Texto del campo «tipo».
    pub fn tag(self) -> &'static str {
        match self {
            HistoryKind::Web => "WEB",
            HistoryKind::App => "APP",
            HistoryKind::Batch => "BATCH",
            HistoryKind::BatchApp => "BATCH_APP",
        }
    }
}

/// Registro del histórico que la app debe escribir tras una firma correcta
/// (la app original lo escribe tras lanzar la subida, sin esperar a que
/// termine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRecord {
    pub kind: HistoryKind,
    /// `sign`, `cosign` o `countersign` (en lotes, `sign`).
    pub operation: String,
    /// Nombre del fichero si lo eligió el usuario en la app.
    pub file_name: Option<String>,
    /// `appname` o, desde otra app, el paquete llamante.
    pub app_name: Option<String>,
}

/// Resultado de [`AndroidWebLauncher::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebOutcome {
    /// Operación (`None` si la URL no es de una operación registrada).
    pub operation: Option<WebOperation>,
    pub reply: Reply,
    /// Registro del histórico (solo firmas y lotes correctos).
    pub history: Option<HistoryRecord>,
}

/// Lanzador de las operaciones web de la app Android.
pub struct AndroidWebLauncher {
    handler: Arc<dyn AndroidWebHandler>,
    signer: Arc<dyn LocalSigner>,
    config: AndroidWebConfig,
    sticky: StickyKeyCache,
    cancel: AtomicBool,
}

/// Estado de una invocación.
struct Session {
    mode: InvocationMode,
    op: WebOperation,
    target: Option<ReplyTarget>,
    reply: Option<Reply>,
    history: Option<HistoryRecord>,
    uploader: Uploader,
    active_waiting: Option<intermediate::ActiveWaiting>,
}

impl Session {
    /// Modalidad por intent (solo firma y lotes).
    fn app_mode(&self) -> bool {
        (matches!(self.mode, InvocationMode::App { .. }) && self.op == WebOperation::Batch) || self.sign_app()
    }

    fn sign_app(&self) -> bool {
        matches!(self.mode, InvocationMode::App { .. }) && self.op.is_sign_family()
    }

    fn calling_package(&self) -> Option<String> {
        match &self.mode {
            InvocationMode::App { calling_package } => calling_package.clone(),
            InvocationMode::Browser => None,
        }
    }
}

/// Fin anticipado de una operación (la respuesta ya se envió).
struct Done;

type Step<T> = Result<T, Done>;

fn target_of(c: &CommonParams) -> Option<ReplyTarget> {
    Some(ReplyTarget {
        id: c.id.clone()?,
        storage_servlet: c.storage_servlet.clone()?,
    })
}

/// Avisos del certificado (§4.6): caducidad (o aún no válido) y seudónimo.
pub fn certificate_warnings(cert_der: &[u8], now: chrono::DateTime<chrono::Utc>) -> Vec<CertificateWarning> {
    let mut out = Vec::new();
    if let Some(info) = afirma_core::cert::CertInfo::parse(cert_der) {
        if now > info.not_after {
            out.push(CertificateWarning::Expired);
        } else if now < info.not_before {
            out.push(CertificateWarning::NotYetValid);
        } else if (info.not_after - now).num_milliseconds() < 604_800_000 {
            out.push(CertificateWarning::ExpiresSoon);
        }
    }
    if is_pseudonym_certificate(cert_der) {
        out.push(CertificateWarning::Pseudonym);
    }
    out
}

/// `AOUtil.isPseudonymCert`: el sujeto tiene el atributo `2.5.4.65`.
pub fn is_pseudonym_certificate(cert_der: &[u8]) -> bool {
    x509_parser::parse_x509_certificate(cert_der).is_ok_and(|(_, c)| {
        c.subject()
            .iter_attributes()
            .any(|a| a.attr_type().to_id_string() == "2.5.4.65")
    })
}

/// Nombre propuesto en `save` (§5.7): `filename` o el nombre por defecto con
/// la extensión detectada (corrección del «datosdatos.pdf»).
pub fn proposed_save_name(filename: Option<&str>, data: &[u8], lang: WebLanguage) -> String {
    if let Some(f) = filename {
        return f.to_string();
    }
    let base = UserText::DefaultSavedFilename.text(lang);
    match afirma_core::mime::MimeHelper::new(data).extension() {
        Ok(Some(ext)) => format!("{base}.{ext}"),
        _ => base.to_string(),
    }
}

/// Cadena del tipo de clave (`Key.getAlgorithm()`).
fn key_type(key: &dyn SigningKey) -> &'static str {
    match key.key_algorithm() {
        afirma_core::KeyAlgorithm::Rsa => "RSA",
        afirma_core::KeyAlgorithm::Ec => "EC",
        afirma_core::KeyAlgorithm::Dsa => "DSA",
    }
}

impl AndroidWebLauncher {
    pub fn new(handler: Arc<dyn AndroidWebHandler>, signer: Arc<dyn LocalSigner>, config: AndroidWebConfig) -> Self {
        AndroidWebLauncher {
            handler,
            signer,
            config,
            sticky: StickyKeyCache::new(),
            cancel: AtomicBool::new(false),
        }
    }

    /// Usa una caché de certificado compartida (por ejemplo, con la firma
    /// local, que la vacía).
    pub fn with_sticky_cache(mut self, cache: StickyKeyCache) -> Self {
        self.sticky = cache;
        self
    }

    /// Caché de certificado del proceso.
    pub fn sticky_cache(&self) -> &StickyKeyCache {
        &self.sticky
    }

    pub fn config(&self) -> &AndroidWebConfig {
        &self.config
    }

    /// Botón «Atrás» mientras no hay un diálogo abierto (descarga o firma en
    /// curso): la operación responde `ERR-11` en cuanto puede. Si ya se envió
    /// la respuesta no hace nada (§10 n.º 42). Mientras un diálogo está
    /// abierto, la cancelación es la respuesta de ese diálogo.
    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    fn lang(&self) -> WebLanguage {
        self.config.language
    }

    /// Ejecuta la invocación de una URL `afirma://…` (bloquea hasta terminar;
    /// llamar desde un hilo de trabajo).
    pub fn run(&self, url: &str, mode: InvocationMode) -> WebOutcome {
        self.cancel.store(false, Ordering::SeqCst);
        let Some(op) = WebOperation::from_url(url) else {
            tracing::warn!("AA600002 - La operacion no esta soportada");
            return WebOutcome {
                operation: None,
                reply: Reply::NotSent,
                history: None,
            };
        };
        let mut s = Session {
            mode,
            op,
            target: None,
            reply: None,
            history: None,
            uploader: Uploader::default(),
            active_waiting: None,
        };
        let _ = match op {
            WebOperation::Sign | WebOperation::CoSign | WebOperation::CounterSign => self.run_sign(&mut s, url),
            WebOperation::SelectCert => self.run_select_cert(&mut s, url),
            WebOperation::Save => self.run_save(&mut s, url),
            WebOperation::Batch => self.run_batch(&mut s, url),
        };
        if let Some(aw) = s.active_waiting.take() {
            aw.stop();
        }
        self.handler.progress(ProgressEvent::Hide);
        WebOutcome {
            operation: Some(op),
            reply: s.reply.take().unwrap_or(Reply::NotSent),
            history: s.history.take(),
        }
    }

    // ---------------------------------------------------------------------
    // Respuestas
    // ---------------------------------------------------------------------

    fn dialog(&self, cat: ErrorCategory) {
        self.handler.show_error(&ErrorDialog {
            category: cat,
            message: cat.user_msg(self.lang()),
        });
    }

    /// Envía la respuesta final (una sola por invocación).
    fn send(&self, s: &mut Session, payload: Payload, critical: bool) {
        if s.reply.is_some() {
            tracing::info!("Ya se envio la respuesta de la operacion; se omite otra");
            return;
        }
        if let Some(aw) = s.active_waiting.take() {
            aw.stop();
        }
        let Some(target) = s.target.clone() else {
            tracing::warn!("No se ha indicado servidor intermedio o identificador: no se puede responder");
            s.reply = Some(Reply::NotSent);
            return;
        };
        let wire = payload.wire();
        match s
            .uploader
            .send(&self.config.http, &target.storage_servlet, &target.id, &payload)
        {
            Ok(()) => {
                s.reply = Some(Reply::Uploaded { target, payload: wire });
            }
            Err(e) => {
                tracing::error!("Error en el envio al servidor intermedio: {e}");
                if critical {
                    self.handler.progress(ProgressEvent::Hide);
                    self.dialog(AA_UPLOAD_DATA);
                }
                s.reply = Some(Reply::UploadFailed {
                    target,
                    payload: wire,
                    error: e.to_string(),
                });
            }
        }
    }

    /// Responde un error (con diálogo si `dialog`) y termina la operación.
    fn fail<T>(&self, s: &mut Session, err: WebError, dialog: bool) -> Step<T> {
        tracing::error!("{}", err.category.admin_msg());
        if dialog {
            self.handler.progress(ProgressEvent::Hide);
            self.dialog(err.category);
        }
        if s.reply.is_some() {
            return Err(Done);
        }
        if s.app_mode() {
            s.reply = Some(Reply::Intent(IntentReply::Error {
                error_id: err.id.id.to_string(),
                error_msg: err.text(self.lang()),
            }));
            return Err(Done);
        }
        let critical = !err.is_cancellation() && err.localized;
        self.send(s, Payload::Encoded(err.upload_text(self.lang())), critical);
        Err(Done)
    }

    fn cancel_error(&self, s: &Session) -> WebError {
        match s.op {
            WebOperation::Save => WebError::fixed(ERR_CANCELLED_OPERATION, AA_CANCELED_BY_USER),
            _ => WebError::cancelled(),
        }
    }

    fn check_cancel(&self, s: &mut Session) -> Step<()> {
        if self.cancelled() {
            let e = self.cancel_error(s);
            return self.fail(s, e, false);
        }
        Ok(())
    }

    /// Error de parámetros: diálogo AA600006 y `ERR-22` (corrección: Java no
    /// llegaba a responder).
    fn param_error<T>(&self, s: &mut Session, e: &request::ParamError, target: Option<ReplyTarget>) -> Step<T> {
        tracing::error!("{} - {e}", AA_REQUEST_PARAM_NOT_VALID.admin_msg());
        if s.target.is_none() {
            s.target = target;
        }
        let err = if s.op == WebOperation::Save {
            WebError::fixed(ERR_BAD_PARAMETERS, AA_REQUEST_PARAM_NOT_VALID)
        } else {
            WebError::new(ERR_BAD_PARAMETERS, AA_REQUEST_PARAM_NOT_VALID)
        };
        self.fail(s, err, true)
    }

    // ---------------------------------------------------------------------
    // Sobres (`fileid`)
    // ---------------------------------------------------------------------

    /// Descarga, descifra y analiza el sobre. Los errores ya están
    /// respondidos.
    fn fetch_envelope(&self, s: &mut Session, common: &CommonParams, download_error: WebError) -> Step<WebParams> {
        let (Some(rt), Some(fid)) = (common.retrieve_servlet.as_deref(), common.file_id.as_deref()) else {
            // Inalcanzable: el análisis exige `rtservlet` con `fileid`.
            let e = WebError::new(ERR_BAD_PARAMETERS, AA_NO_DATA_NO_ID);
            return self.fail(s, e, false);
        };
        let data = match intermediate::download(&self.config.http, rt, fid, self.config.download, &|| self.cancelled())
        {
            Ok(d) => d,
            Err(intermediate::DownloadError::Cancelled) => {
                let e = self.cancel_error(s);
                return self.fail(s, e, false);
            }
            Err(e) => {
                tracing::error!("{e}");
                return self.fail(s, download_error, true);
            }
        };
        let bad_params = if s.op == WebOperation::Save {
            WebError::fixed(ERR_BAD_PARAMETERS, AA_REQUEST_PARAM_NOT_VALID)
        } else {
            WebError::new(ERR_BAD_PARAMETERS, AA_REQUEST_PARAM_NOT_VALID)
        };
        let xml = match decipher_data(&data, common.des_key.as_deref()) {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("Error al descifrar los datos recuperados del servidor: {e}");
                return self.fail(s, bad_params, true);
            }
        };
        match WebParams::from_envelope(&xml) {
            Ok(p) => Ok(p),
            Err(e) => {
                tracing::error!("Error en los parametros XML de configuracion: {e}");
                self.fail(s, bad_params, true)
            }
        }
    }

    // ---------------------------------------------------------------------
    // Certificado
    // ---------------------------------------------------------------------

    /// Elige la clave: caché *sticky*, diálogo y avisos (solo `KeyChain` y no
    /// en `selectcert`). Devuelve la clave y su origen.
    fn select_key(
        &self,
        s: &mut Session,
        purpose: KeyPurpose,
        sticky: bool,
        reset_sticky: bool,
        bad_pin_retry: bool,
        app_name: Option<&str>,
    ) -> Step<SelectedKey> {
        if !bad_pin_retry
            && sticky
            && !reset_sticky
            && let Some(key) = self.sticky.get()
        {
            return Ok(SelectedKey {
                key,
                source: KeySource::SmartCard,
            });
        }
        loop {
            self.check_cancel(s)?;
            if purpose == KeyPurpose::Authenticate {
                self.handler.progress(ProgressEvent::LoadingKeyStore);
            }
            let r = self.handler.select_key(&KeyRequest {
                operation: s.op,
                purpose,
                bad_pin_retry,
                app_name,
            });
            if purpose == KeyPurpose::Authenticate {
                self.handler.progress(ProgressEvent::Hide);
            }
            let selected = match r {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Error en la seleccion de certificado: {e}");
                    let err = self.key_error(s.op, &e);
                    return self.fail(s, err, false);
                }
            };
            if selected.source == KeySource::SystemKeyStore && purpose == KeyPurpose::Sign {
                let cert = selected.key.certificate().to_vec();
                let warnings = certificate_warnings(&cert, chrono::Utc::now());
                if warnings
                    .iter()
                    .any(|w| !self.handler.confirm_certificate_warning(*w, &cert))
                {
                    tracing::info!("El usuario cancela el uso del certificado debido a una advertencia");
                    continue;
                }
            }
            return Ok(selected);
        }
    }

    /// Respuesta de un error de selección (§5.12, §6.6).
    fn key_error(&self, op: WebOperation, e: &KeySelectionError) -> WebError {
        let sc = op == WebOperation::SelectCert;
        match e {
            KeySelectionError::Cancelled if sc => WebError::new(ERR_CANCELLED_OPERATION, AA_USER_NOT_SELECT_CERT),
            KeySelectionError::Cancelled => WebError::cancelled(),
            KeySelectionError::KeyStore(_) => WebError::new(ERR_ESTABLISHING_KEYSTORE, AA_LOAD_KEYSTORE),
            KeySelectionError::InvalidAlias(_) if sc => WebError::new(ERR_PKE_ANDROID_4_1, AA_LOAD_KEY),
            KeySelectionError::InvalidAlias(_) => WebError::new(ERR_PKE_ANDROID_4_1, AA_ALIAS_NOT_VALID),
            KeySelectionError::KeyChain(_) => WebError::new(ERR_PKE, AA_LOAD_KEY),
            KeySelectionError::Other(_) if sc => WebError::new(ERR_PKE, AA_LOAD_CERT),
            KeySelectionError::Other(_) => WebError::new(ERR_PKE, AA_UNEXPECTED_RECOVERING_KEY),
        }
    }

    // ---------------------------------------------------------------------
    // Firma, cofirma y contrafirma
    // ---------------------------------------------------------------------

    fn run_sign(&self, s: &mut Session, url: &str) -> Step<()> {
        let params = match WebParams::from_url(url) {
            Ok(p) => p,
            Err(e) => return self.param_error(s, &e, reply_hint_lenient(url)),
        };
        let mut req = match request::parse_sign(&params, &self.config.http) {
            Ok(r) => r,
            Err(e) => return self.param_error(s, &e, reply_hint(&params)),
        };
        s.target = target_of(&req.common);
        let mut chosen_name = None;
        if req.common.data.is_none() && req.common.file_id.is_some() {
            s.target = reply_hint(&params);
            let common = req.common.clone();
            let env = self.fetch_envelope(s, &common, WebError::new(ERR_SIGNING, AA_DOWNLOAD_SIGN))?;
            req = match request::parse_sign(&env, &self.config.http) {
                Ok(r) => r,
                Err(e) => return self.param_error(s, &e, reply_hint(&env)),
            };
            s.target = target_of(&req.common).or(s.target.take());
        }
        self.check_cancel(s)?;
        let data = match req.common.data.take() {
            Some(d) => d,
            None => {
                let format = req.format.clone().unwrap_or_default();
                let f = match self.handler.choose_file(&ChooseFileRequest {
                    operation: s.op,
                    format: &format,
                    pdf_only: PDF_FILTER_FORMATS.contains(&format.as_str()),
                }) {
                    Ok(f) => f,
                    Err(e) => {
                        let (err, dialog) = match e {
                            FileChoiceError::Cancelled => (WebError::cancelled(), false),
                            FileChoiceError::PermissionDenied => (WebError::new(ERR_SIGNING, AA_ERROR_SIGNING), false),
                            FileChoiceError::TooLarge => (WebError::new(ERR_SIGNING, AA_OUT_OF_MEMORY), true),
                            FileChoiceError::Read(_) => (WebError::new(ERR_SIGNING, AA_LOADING_LOCAL_FILE), true),
                        };
                        return self.fail(s, err, dialog);
                    }
                };
                chosen_name = Some(f.name);
                f.data
            }
        };
        self.process_sign(s, req, data, chosen_name)
    }

    /// `processSignRequest` con los datos ya obtenidos.
    fn process_sign(&self, s: &mut Session, req: SignRequest, data: Vec<u8>, chosen_name: Option<String>) -> Step<()> {
        self.handler.progress(ProgressEvent::Signing);
        let generic = WebError::new(ERR_SIGNING, AA_ERROR_SIGNING);
        let (Some(format), Some(algorithm), Some(op)) =
            (req.format.clone(), req.algorithm.clone(), req.crypto_operation())
        else {
            tracing::error!("Operacion, formato o algoritmo de firma no validos: {}", req.operation);
            return self.fail(s, generic, true);
        };
        let mut extra = req.extra_params.clone();
        // 2. Expansión de la política (solo `CAdES` y `PAdES` exactos).
        if POLICY_EXPANSION_FORMATS.contains(&format.as_str()) {
            match afirma_core::policy::expand_properties(&extra, Some(&data), Some(&format)) {
                Ok(e) => extra = e,
                Err(e) if e.code == Some(codes::SIGNING_WITH_POLICY_INCOMPATIBILITY) => {
                    let err = WebError::new(ERR_BAD_PARAMETERS, AA_PARAM_NOT_COMPATIBLE_POLICY);
                    return self.fail(s, err, true);
                }
                Err(e) => {
                    tracing::error!("Error al expandir la politica: {e}");
                    return self.fail(s, generic, true);
                }
            }
        }
        // 3. PAdES sobre datos no PDF (corrección: no se sigue firmando).
        let pdf_format = PDF_FORMATS.contains(&format.as_str());
        if pdf_format && !is_pdf_file(&data) {
            let cat = if chosen_name.is_some() {
                AA_USER_SELECT_NOT_PDF
            } else {
                AA_PADES_NO_PDF_SIGN
            };
            return self.fail(s, WebError::new(ERR_INVALID_DATA, cat), true);
        }
        // 4. Firma visible.
        if pdf_format {
            let visible = extra.get("visibleSignature").map(str::to_string);
            let want = visible.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("want"));
            let optional = visible.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("optional"));
            let headless = extra.get("headless").is_some_and(|h| h.eq_ignore_ascii_case("true"));
            if (want || optional) && !headless {
                match self.handler.visible_signature(&VisibleSignatureRequest {
                    data: &data,
                    file_name: chosen_name.as_deref(),
                    mandatory: want,
                    extra_params: &extra,
                }) {
                    VisibleSignatureResult::Selected { owner_password, area } => {
                        if let Some(p) = owner_password {
                            extra.set("ownerPassword", p);
                        }
                        match area {
                            Some(a) => {
                                extra.set("obfuscateCertText", self.config.obfuscate_cert_text.to_string());
                                extra.set("signaturePages", a.page.to_string());
                                extra.set("layer2Text", UserText::PdfVisibleSignTemplate.text(self.lang()));
                                extra.set("signaturePositionOnPageLowerLeftX", a.lower_left_x.to_string());
                                extra.set("signaturePositionOnPageLowerLeftY", a.lower_left_y.to_string());
                                extra.set("signaturePositionOnPageUpperRightX", a.upper_right_x.to_string());
                                extra.set("signaturePositionOnPageUpperRightY", a.upper_right_y.to_string());
                            }
                            None if want => return self.fail(s, WebError::cancelled(), false),
                            None => {}
                        }
                    }
                    VisibleSignatureResult::Cancelled => return self.fail(s, WebError::cancelled(), false),
                    VisibleSignatureResult::LoadError(e) => {
                        tracing::error!("Error al cargar el PDF para la firma visible: {e}");
                        return self.fail(s, WebError::new(ERR_INVALID_DATA, AA_LOADING_LOCAL_FILE), true);
                    }
                }
            }
        }
        // 5. Certificado y firma.
        let mut bad_pin = false;
        let (key, signature) = loop {
            let selected = self.select_key(
                s,
                KeyPurpose::Sign,
                req.sticky,
                req.reset_sticky,
                bad_pin,
                req.app_name.as_deref(),
            )?;
            self.sticky.update_after_selection(
                &selected.key,
                req.sticky,
                selected.source == KeySource::DnieNfc,
                self.config.sticky_timeout,
            );
            self.check_cancel(s)?;
            match self.execute_sign(op, &format, &algorithm, &data, selected.key.as_ref(), &mut extra) {
                Ok(sig) => break (selected.key, sig),
                Err(SignFailure::BadPin) => {
                    bad_pin = true;
                    self.sticky.clear();
                }
                Err(SignFailure::Unsupported) => {
                    let err = WebError::new(ERR_NOT_SUPPORTED_FORMAT, AA_FORMAT_NOT_VALID);
                    return self.fail(s, err, true);
                }
                Err(SignFailure::Cancelled) => return self.fail(s, WebError::cancelled(), false),
                Err(SignFailure::Error(e)) => {
                    tracing::error!("Error durante la operacion de firma: {e}");
                    return self.fail(s, generic, false);
                }
            }
        };
        self.handler.progress(ProgressEvent::Hide);
        // Respuesta.
        let cert = key.certificate().to_vec();
        let key_bytes = req.common.des_key.as_deref();
        if s.sign_app() {
            s.reply = Some(Reply::Intent(IntentReply::Signature {
                cert: Some(cert),
                signature,
            }));
        } else {
            let Ok(sig_part) = encode_or_cipher(&signature, key_bytes, android_base64_url_wrapped) else {
                return self.fail(s, WebError::new(ERR_CIPHERING, AA_CYPHERING_SIGN), false);
            };
            let Ok(cert_part) = encode_or_cipher(&cert, key_bytes, android_base64_url_wrapped) else {
                return self.fail(s, WebError::new(ERR_CIPHERING, AA_ENCRYPTING_CERT), false);
            };
            self.send(s, Payload::Result(format!("{cert_part}|{sig_part}")), true);
        }
        let (kind, app_name) = if s.sign_app() {
            (HistoryKind::App, req.app_name.clone().or_else(|| s.calling_package()))
        } else {
            (HistoryKind::Web, req.app_name.clone())
        };
        s.history = Some(HistoryRecord {
            kind,
            operation: req.operation.to_lowercase(),
            file_name: chosen_name.map(|n| n.rsplit('/').next().unwrap_or(&n).to_string()),
            app_name,
        });
        Ok(())
    }

    /// `SignTask`: firmador según el formato, operación y contraseña de PDF.
    fn execute_sign(
        &self,
        op: CryptoOperation,
        format: &str,
        algorithm: &str,
        data: &[u8],
        key: &dyn SigningKey,
        extra: &mut ExtraParams,
    ) -> Result<Vec<u8>, SignFailure> {
        let composed = afirma_core::algorithms::compose_signature_algorithm_name(Some(algorithm), Some(key_type(key)))
            .map_err(|e| SignFailure::Error(e.to_string()))?;
        let signer = if is_auto_detection(format, op) {
            auto_signer(self.signer.detect_format(op, data).as_deref())
        } else {
            signer_for_format(format)
        }
        .ok_or(SignFailure::Unsupported)?;
        let target = match extra.get("target") {
            Some(t) if crate::triphase::data::java_trim(t) == "tree" => CounterSignTarget::Tree,
            _ => CounterSignTarget::Leafs,
        };
        let mut asked = false;
        loop {
            let r = match signer {
                AndroidSigner::Local(f) => self.signer.sign(&LocalSignRequest {
                    operation: op,
                    format: f,
                    data,
                    algorithm: &composed,
                    key,
                    extra_params: &*extra,
                    target: target.clone(),
                }),
                AndroidSigner::Triphase(tf) => TriphaseClient::new(self.config.http.clone()).sign(
                    tf,
                    op,
                    Some(data),
                    &composed,
                    key,
                    &*extra,
                    Some(&target),
                ),
            };
            match r {
                Ok(sig) => return Ok(sig),
                Err(e) => {
                    if let Some(bad) = pdf_password_retry(&e) {
                        let req = PdfPasswordRequest {
                            bad_password: bad || asked,
                        };
                        let Some(pwd) = self.handler.pdf_password(&req) else {
                            return Err(SignFailure::Cancelled);
                        };
                        extra.set("ownerPassword", pwd);
                        extra.remove("userPassword");
                        asked = true;
                        continue;
                    }
                    return Err(SignFailure::from_afirma(e));
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Selección de certificado
    // ---------------------------------------------------------------------

    fn run_select_cert(&self, s: &mut Session, url: &str) -> Step<()> {
        let params = match WebParams::from_url(url) {
            Ok(p) => p,
            Err(e) => return self.param_error(s, &e, reply_hint_lenient(url)),
        };
        let mut req: SelectCertRequest = match request::parse_select_cert(&params, &self.config.http) {
            Ok(r) => r,
            Err(e) => return self.param_error(s, &e, reply_hint(&params)),
        };
        s.target = target_of(&req.common);
        if !(req.sticky && !req.reset_sticky && self.sticky.get().is_some()) && req.common.file_id.is_some() {
            s.target = reply_hint(&params);
            let common = req.common.clone();
            let env = self.fetch_envelope(
                s,
                &common,
                WebError::new(ERR_COMMUNICATING_WITH_WEB, AA_DOWNLOAD_CONFIG_CERT),
            )?;
            req = match request::parse_select_cert(&env, &self.config.http) {
                Ok(r) => r,
                Err(e) => return self.param_error(s, &e, reply_hint(&env)),
            };
            s.target = target_of(&req.common).or(s.target.take());
        }
        let selected = self.select_key(s, KeyPurpose::Authenticate, req.sticky, req.reset_sticky, false, None)?;
        let cert = selected.key.certificate().to_vec();
        if cert.is_empty() {
            return self.fail(s, WebError::new(ERR_PKE, AA_LOAD_CERT), false);
        }
        self.sticky.update_after_selection(
            &selected.key,
            req.sticky,
            selected.source == KeySource::DnieNfc,
            self.config.sticky_timeout,
        );
        let Ok(payload) = encode_or_cipher(
            &cert,
            req.common.des_key.as_deref(),
            afirma_core::base64::encode_url_safe,
        ) else {
            return self.fail(s, WebError::new(ERR_CIPHERING, AA_CYPHERING_CERT), false);
        };
        self.send(s, Payload::Result(payload), true);
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Guardado
    // ---------------------------------------------------------------------

    fn run_save(&self, s: &mut Session, url: &str) -> Step<()> {
        let params = match WebParams::from_url(url) {
            Ok(p) => p,
            Err(e) => return self.param_error(s, &e, reply_hint_lenient(url)),
        };
        let mut req: SaveRequest = match request::parse_save(&params, &self.config.http) {
            Ok(r) => r,
            Err(e) => return self.param_error(s, &e, reply_hint(&params)),
        };
        s.target = target_of(&req.common);
        if req.common.data.is_none() && req.common.file_id.is_some() {
            s.target = reply_hint(&params).or(s.target.take());
            let common = req.common.clone();
            let env = self.fetch_envelope(
                s,
                &common,
                WebError::fixed(ERR_COMMUNICATING_WITH_WEB, AA_COMMUNICATION_WITH_SERVICE),
            )?;
            req = match request::parse_save(&env, &self.config.http) {
                Ok(r) => r,
                Err(e) => return self.param_error(s, &e, reply_hint(&env)),
            };
            s.target = target_of(&req.common).or(s.target.take());
        }
        let Some(data) = req.common.data.clone() else {
            // Sobre sin datos: Java fallaba al escribir (`NullPointerException`).
            return self.fail(s, WebError::fixed(ERR_BAD_PARAMETERS, AA_REQUEST_PARAM_NOT_VALID), true);
        };
        let proposed = proposed_save_name(req.filename.as_deref(), &data, self.lang());
        match self.handler.save_file(&SaveFileRequest {
            data: &data,
            proposed_name: proposed,
            title: &req.title,
            extensions: req.extensions.as_deref(),
            description: req.description.as_deref(),
        }) {
            Ok(()) => {
                self.send(s, Payload::Result(intermediate::OK_SERVER_RESULT.into()), true);
                Ok(())
            }
            Err(SaveFileError::Cancelled) => {
                self.fail(s, WebError::fixed(ERR_CANCELLED_OPERATION, AA_CANCELED_BY_USER), false)
            }
            Err(SaveFileError::Write(e)) => {
                tracing::error!("Error al guardar los datos: {e}");
                self.fail(s, WebError::fixed(ERR_SAVING_DATA, AA_SAVING_DATA_OP), true)
            }
        }
    }

    // ---------------------------------------------------------------------
    // Lotes
    // ---------------------------------------------------------------------

    fn run_batch(&self, s: &mut Session, url: &str) -> Step<()> {
        let params = match WebParams::from_batch_url(url) {
            Ok(p) => p,
            Err(e) => return self.param_error(s, &e, reply_hint_lenient(url)),
        };
        let mut req: BatchRequest = match request::parse_batch(&params, &self.config.http) {
            Ok(r) => r,
            Err(e) => return self.param_error(s, &e, reply_hint(&params)),
        };
        s.target = target_of(&req.common);
        if req.common.file_id.is_some() && req.common.data.is_none() {
            s.target = reply_hint(&params);
            let common = req.common.clone();
            let env = self.fetch_envelope(s, &common, WebError::new(ERR_SIGNING, AA_DOWNLOAD_SIGN))?;
            req = match request::parse_batch(&env, &self.config.http) {
                Ok(r) => r,
                Err(e) => return self.param_error(s, &e, reply_hint(&env)),
            };
            s.target = target_of(&req.common).or(s.target.take());
            if req.common.active_waiting
                && !s.app_mode()
                && let Some(t) = &s.target
            {
                s.active_waiting = Some(s.uploader.start_active_waiting(
                    self.config.http.clone(),
                    t.storage_servlet.clone(),
                    t.id.clone(),
                    self.config.active_waiting_interval,
                ));
            }
        }
        self.handler.progress(ProgressEvent::Signing);
        let mut bad_pin = false;
        let (key, result) = loop {
            let selected = self.select_key(
                s,
                KeyPurpose::Sign,
                req.sticky,
                req.reset_sticky,
                bad_pin,
                req.app_name.as_deref(),
            )?;
            self.sticky.update_after_selection(
                &selected.key,
                req.sticky,
                selected.source == KeySource::DnieNfc,
                self.config.sticky_timeout,
            );
            self.check_cancel(s)?;
            match self.sign_batch(&req, selected.key.as_ref()) {
                Ok(r) => break (selected.key, r),
                Err(BatchFailure::BadPin(_)) => {
                    bad_pin = true;
                    self.sticky.clear();
                }
                Err(BatchFailure::Cancelled) => return self.fail(s, WebError::cancelled(), false),
                Err(BatchFailure::HttpClientError(e)) => {
                    tracing::error!("{}: {e}", AA_COMMUNICATION_WITH_SERVICE.admin_msg());
                    return self.fail(
                        s,
                        WebError::new(ERR_COMMUNICATING_WITH_WEB, AA_COMMUNICATION_WITH_SERVICE),
                        false,
                    );
                }
                Err(e) => {
                    tracing::error!("Error en la firma del lote: {e}");
                    return self.fail(s, WebError::new(ERR_SIGNING, AA_ERROR_SIGNING), false);
                }
            }
        };
        self.handler.progress(ProgressEvent::Hide);
        let cert = req.need_cert.then(|| key.certificate().to_vec());
        if s.app_mode() {
            s.reply = Some(Reply::Intent(IntentReply::Batch { cert, result }));
        } else {
            let des = req.common.des_key.as_deref();
            let mut payload = match encode_or_cipher(&result, des, afirma_core::base64::encode) {
                Ok(p) => p,
                Err(_) => return self.fail(s, WebError::new(ERR_SIGNING, AA_CYPHERING_SIGN_INFO_TO_SEND), false),
            };
            if let Some(c) = &cert {
                match encode_or_cipher(c, des, afirma_core::base64::encode) {
                    Ok(p) => {
                        payload.push('|');
                        payload.push_str(&p);
                    }
                    Err(_) => {
                        return self.fail(s, WebError::new(ERR_SIGNING, AA_CYPHERING_SIGN_INFO_TO_SEND), false);
                    }
                }
            }
            self.send(s, Payload::Result(payload), true);
        }
        let (kind, app_name) = if s.app_mode() {
            (
                HistoryKind::BatchApp,
                req.app_name.clone().or_else(|| s.calling_package()),
            )
        } else {
            (HistoryKind::Batch, req.app_name.clone())
        };
        s.history = Some(HistoryRecord {
            kind,
            operation: "sign".into(),
            file_name: None,
            app_name,
        });
        Ok(())
    }

    /// Firma del lote: JSON contra servidor (como la app), XML contra servidor
    /// y lote local (corrección: Java no los soportaba).
    fn sign_batch(&self, req: &BatchRequest, key: &dyn SigningKey) -> Result<Vec<u8>, BatchFailure> {
        let data = req.common.data.as_deref().unwrap_or_default();
        if req.local_batch_process {
            let lb = crate::batch::parse_local_batch(data).map_err(|e| BatchFailure::Other(format!("{e:?}")))?;
            let results = crate::batch::run_local_batch(&lb, |item| {
                let Some(op) = item.operation else {
                    return Err(codes::INTERNAL_LOCAL_BATCH_ERROR.code_str());
                };
                let mut extra = item.extra_params.clone();
                extra.set("headless", "true");
                self.execute_sign(op, &item.format, &item.algorithm, &item.data, key, &mut extra)
                    .map_err(|e| e.description())
            });
            return Ok(crate::batch::local_batch_result_json(&results).into_bytes());
        }
        if req.json_batch {
            return sign_json_batch(
                &self.config.http,
                data,
                req.presigner_url.as_deref(),
                req.postsigner_url.as_deref(),
                key,
            );
        }
        let (Some(pre), Some(post)) = (req.presigner_url.as_deref(), req.postsigner_url.as_deref()) else {
            return Err(BatchFailure::InvalidArgument(
                "Faltan las URL del servicio de lotes".into(),
            ));
        };
        crate::batch::sign_xml_batch(&self.config.http, data, pre, post, key, &req.extra_params)
            .map(String::into_bytes)
            .map_err(|e| match e {
                crate::batch::BatchError::Afirma(a) => BatchFailure::from_afirma(a),
                crate::batch::BatchError::InvalidArgument(m) => BatchFailure::InvalidArgument(m),
                crate::batch::BatchError::Internal(m) => BatchFailure::Other(m),
            })
    }
}

/// Fallo de `SignTask`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SignFailure {
    /// `AOUnsupportedSignFormatException`.
    Unsupported,
    /// PIN incorrecto de la tarjeta (`MSCBadPinException`).
    BadPin,
    Cancelled,
    Error(String),
}

impl SignFailure {
    fn from_afirma(e: AfirmaError) -> Self {
        if e.is_cancelled() {
            SignFailure::Cancelled
        } else if e.code == Some(codes::INVALID_SMARTCARD_PIN) {
            SignFailure::BadPin
        } else {
            SignFailure::Error(e.to_string())
        }
    }

    fn description(&self) -> String {
        match self {
            SignFailure::Unsupported => codes::UNSUPPORTED_SIGNATURE_FORMAT.code_str(),
            SignFailure::BadPin => codes::INVALID_SMARTCARD_PIN.code_str(),
            SignFailure::Cancelled => codes::CANCELLED_OPERATION.code_str(),
            SignFailure::Error(m) => m.clone(),
        }
    }
}

/// Si el error pide la contraseña de un PDF (`PdfIsPasswordProtectedException`
/// o `BadPdfPasswordException` de tipo contraseña), indica si la anterior era
/// incorrecta. Las demás intervenciones (confirmaciones) son errores de firma
/// en la app (`AOException` → `ERR-14`).
fn pdf_password_retry(e: &AfirmaError) -> Option<bool> {
    match &e.kind {
        ErrorKind::NeedsIntervention {
            intervention: UserIntervention::Password { requestor_text, .. },
            denied: false,
        } => match requestor_text.as_str() {
            "pdfpasswordprotected" => Some(false),
            "pdfbadpassword" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_names() {
        let pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n";
        assert_eq!(proposed_save_name(Some("x.bin"), pdf, WebLanguage::Es), "x.bin");
        assert_eq!(proposed_save_name(None, pdf, WebLanguage::Es), "datos.pdf");
        assert!(proposed_save_name(None, b"texto", WebLanguage::En).starts_with("data"));
    }

    fn cert(pseudonym: bool, from: (i32, u8, u8), to: (i32, u8, u8)) -> Vec<u8> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name = DistinguishedName::new();
        if pseudonym {
            p.distinguished_name
                .push(DnType::CustomDnType(vec![2, 5, 4, 65]), "SEUDO");
        }
        p.distinguished_name.push(DnType::CommonName, "Prueba");
        p.not_before = rcgen::date_time_ymd(from.0, from.1, from.2);
        p.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
        p.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn certificate_warning_rules() {
        use chrono::TimeZone;
        let now = chrono::Utc.with_ymd_and_hms(2030, 6, 15, 12, 0, 0).unwrap();
        let w = |c: &[u8]| certificate_warnings(c, now);
        assert!(w(&cert(false, (2029, 1, 1), (2031, 1, 1))).is_empty());
        assert_eq!(
            w(&cert(false, (2029, 1, 1), (2030, 6, 1))),
            vec![CertificateWarning::Expired]
        );
        assert_eq!(
            w(&cert(false, (2030, 7, 1), (2031, 1, 1))),
            vec![CertificateWarning::NotYetValid]
        );
        assert_eq!(
            w(&cert(false, (2029, 1, 1), (2030, 6, 20))),
            vec![CertificateWarning::ExpiresSoon]
        );
        assert_eq!(
            w(&cert(true, (2029, 1, 1), (2030, 6, 20))),
            vec![CertificateWarning::ExpiresSoon, CertificateWarning::Pseudonym]
        );
        assert!(is_pseudonym_certificate(&cert(true, (2029, 1, 1), (2031, 1, 1))));
        assert!(!is_pseudonym_certificate(b"no es un certificado"));
    }

    #[test]
    fn history_tags() {
        assert_eq!(HistoryKind::BatchApp.tag(), "BATCH_APP");
        assert_eq!(HistoryKind::Web.tag(), "WEB");
    }

    #[test]
    fn password_interventions() {
        let e = AfirmaError::needs_password(codes::UNKNOWN_SIGNING_ERROR, "x", "pdfbadpassword", "ownerPassword");
        assert_eq!(pdf_password_retry(&e), Some(true));
        assert_eq!(pdf_password_retry(&AfirmaError::cancelled()), None);
    }
}
