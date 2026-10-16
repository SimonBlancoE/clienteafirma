//! Lanzador del protocolo (`ProtocolInvocationLauncher` y los
//! `ProtocolInvocationLauncher*` de cada operación).
//!
//! [`ProtocolLauncher::launch`] atiende la URL con la que el sistema
//! operativo arranca la aplicación (invocación directa por servidor
//! intermedio o apertura de los canales WebSocket/socket de servicio) y
//! [`ProtocolLauncher::process_socket_message`] cada petición recibida por
//! los canales locales.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afirma_core::error::{ConfirmEffect, UserIntervention, codes};
use afirma_core::{AfirmaError, CounterSignTarget, ErrorCode, ErrorKind, ExtraParams, SigningKey};

use crate::batch::{self, BatchError, LocalBatchParseError};
use crate::cipher::ServerCipher;
use crate::envelope;
use crate::errors::{self, ErrorOrigin, ProtocolError};
use crate::handler::{
    CertificateRequest, ConfirmRequest, ErrorDialog, FileData, LoadRequest, LocalSignRequest, LocalSigner, OpenFileRequest, OperationHandler,
    PasswordRequest, ProgressEvent, RequestInfo, RequestOrigin, SaveFileRequest, VisibleSignatureRequest,
};
use crate::http::HttpClient;
use crate::intermediate::{self, ActiveWaiting, Uploader};
use crate::messages::{self, Locale};
use crate::query::Params;
use crate::request::{
    self, BatchParams, Dispatch, KeyStoreParam, LoadParams, OperationKind, ParseContext, ReplyChannel, Request, SaveParams, SelectCertParams,
    SignParams,
};
use crate::response;
use crate::triphase::{CryptoOperation, TriphaseClient, TriphaseFormat};
use crate::version::{self, ProtocolVersion};

/// Versión de AutoFirma que se compara con `mcv`.
pub const DEFAULT_APP_VERSION: &str = "1.10";

/// Configuración del lanzador.
#[derive(Clone)]
pub struct LauncherConfig {
    /// Versión legible de la aplicación (`mcv` se compara con ella).
    pub app_version: String,
    /// Idioma de los mensajes (errores `SAF_NN` y diálogos).
    pub locale: Locale,
    /// Acceso HTTP (servidor intermedio, servidores trifásicos y de lotes,
    /// descarga de `dat`).
    pub http: HttpClient,
    /// Subir al servidor intermedio también los errores de parámetros y de
    /// descarga del sobre cuando se conocen el identificador y el servlet de
    /// guardado (Java no lo hacía y la página agotaba su espera).
    pub upload_all_errors: bool,
    /// Intervalo de la espera activa (`#WAIT`).
    pub active_waiting_interval: Duration,
}

impl LauncherConfig {
    pub fn new(http: HttpClient) -> Self {
        LauncherConfig {
            app_version: DEFAULT_APP_VERSION.to_string(),
            locale: Locale::Es,
            http,
            upload_all_errors: true,
            active_waiting_interval: intermediate::ACTIVE_WAITING_INTERVAL,
        }
    }
}

/// Resultado de una invocación por URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchOutcome {
    /// Operación terminada (invocación directa o error); el texto es la
    /// respuesta (ya subida al servidor intermedio si procedía).
    Finished(String),
    /// La URL pide abrir el canal WebSocket.
    OpenWebSocket(crate::channel::ChannelRequest),
    /// La URL pide abrir el socket de servicio.
    OpenService(crate::channel::ChannelRequest),
}

/// Lanzador del protocolo.
pub struct ProtocolLauncher {
    pub(crate) handler: Arc<dyn OperationHandler>,
    pub(crate) signer: Arc<dyn LocalSigner>,
    pub(crate) config: LauncherConfig,
    /// Firmante persistente (`stickyKeyEntry`), común a todo el proceso.
    sticky: Mutex<Option<Arc<dyn SigningKey>>>,
    uploader: Uploader,
    /// `dlgload=false` desactiva los avisos de progreso.
    progress_dialogs: AtomicBool,
}

/// Opciones de selección de certificado de una operación.
struct KeySelection<'a> {
    info: &'a RequestInfo,
    kind: OperationKind,
    extra: &'a ExtraParams,
    keystore: Option<&'a KeyStoreParam>,
    sticky: bool,
    reset_sticky: bool,
}

impl ProtocolLauncher {
    pub fn new(handler: Arc<dyn OperationHandler>, signer: Arc<dyn LocalSigner>, config: LauncherConfig) -> Self {
        ProtocolLauncher {
            handler,
            signer,
            config,
            sticky: Mutex::new(None),
            uploader: Uploader::default(),
            progress_dialogs: AtomicBool::new(true),
        }
    }

    pub fn config(&self) -> &LauncherConfig {
        &self.config
    }

    pub fn handler(&self) -> &Arc<dyn OperationHandler> {
        &self.handler
    }

    /// Clave del firmante persistente actual.
    pub fn sticky_key(&self) -> Option<Arc<dyn SigningKey>> {
        self.sticky.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Fija o borra el firmante persistente.
    pub fn set_sticky_key(&self, key: Option<Arc<dyn SigningKey>>) {
        *self.sticky.lock().unwrap_or_else(|e| e.into_inner()) = key;
    }

    fn progress(&self, extra: &ExtraParams, e: ProgressEvent, info: Option<&RequestInfo>) {
        if e == ProgressEvent::Hide || (self.progress_dialogs.load(Ordering::Relaxed) && !extra.get_bool("headless", false)) {
            self.handler.progress(e, info);
        }
    }

    fn show_error(&self, err: &ProtocolError, version: Option<ProtocolVersion>) {
        let locale = self.config.locale;
        self.handler.show_error(&ErrorDialog {
            title: errors::dialog_title(version, err.code, locale),
            message: errors::dialog_text(err.code, locale, &err.dialog_params),
            error: err.clone(),
            version,
        });
    }

    /// Respuesta de error: muestra el diálogo si Java lo hacía y devuelve el
    /// texto para la web.
    fn error_response(&self, err: &ProtocolError, version: Option<ProtocolVersion>) -> String {
        if err.shows_dialog() {
            self.show_error(err, version);
        }
        err.response(version, self.config.locale)
    }

    /// Atiende la URL con la que el sistema operativo invoca la aplicación.
    pub fn launch(&self, url: &str) -> LaunchOutcome {
        let params = Params::from_query(url);
        let jvc = version::parse_jvc(params.get("jvc").ok().flatten().as_deref());
        if jvc < 1 {
            self.handler.warn_insecure_javascript();
        }
        if params.get("dlgload").ok().flatten().is_some_and(|v| v.eq_ignore_ascii_case("false")) {
            self.progress_dialogs.store(false, Ordering::Relaxed);
        }
        match request::dispatch(url) {
            Dispatch::UnsupportedScheme => {
                LaunchOutcome::Finished(self.error_response(&ProtocolError::parameter(codes::UNSUPPORTED_REQUEST_SCHEME, "Esquema no soportado"), None))
            }
            Dispatch::UnsupportedOperation => {
                LaunchOutcome::Finished(self.error_response(&ProtocolError::parameter(codes::UNSUPPORTED_OPERATION, "Operacion no soportada"), None))
            }
            Dispatch::WebSocket => LaunchOutcome::OpenWebSocket(crate::channel::ChannelRequest::from_params(&params, jvc)),
            Dispatch::Service => LaunchOutcome::OpenService(crate::channel::ChannelRequest::from_params(&params, jvc)),
            Dispatch::Operation(kind) => {
                let host = ["stservlet", "rtservlet"].iter().find_map(|k| {
                    params.get(k).ok().flatten().and_then(|u| crate::query::url_decode(&u).ok()).and_then(|u| crate::http::host_of(&u))
                });
                LaunchOutcome::Finished(self.run_operation(kind, &params, None, jvc, false, RequestOrigin::IntermediateServer { host }))
            }
        }
    }

    /// Atiende una petición recibida por WebSocket o por el socket de
    /// servicio (`launch(message, version, bySocket=true)`) sin origen
    /// conocido.
    pub fn process_socket_message(&self, message: &str, version: ProtocolVersion) -> String {
        self.process_socket_message_from(message, version, RequestOrigin::WebSocket { origin: None })
    }

    /// Como [`Self::process_socket_message`], indicando el origen de la
    /// petición (cabecera `Origin` del WebSocket o de la petición HTTP).
    pub fn process_socket_message_from(&self, message: &str, version: ProtocolVersion, origin: RequestOrigin) -> String {
        let v = Some(version);
        match request::dispatch(message) {
            Dispatch::UnsupportedScheme => {
                self.error_response(&ProtocolError::parameter(codes::UNSUPPORTED_REQUEST_SCHEME, "Esquema no soportado"), v)
            }
            // Una petición de apertura de canal por un canal ya abierto no
            // tiene sentido (Java intentaba abrir otro servidor).
            Dispatch::UnsupportedOperation | Dispatch::WebSocket | Dispatch::Service => {
                self.error_response(&ProtocolError::parameter(codes::UNSUPPORTED_OPERATION, "Operacion no soportada"), v)
            }
            Dispatch::Operation(kind) => {
                let params = Params::from_query(message);
                let jvc = version::parse_jvc(params.get("jvc").ok().flatten().as_deref());
                if jvc < 1 {
                    self.handler.warn_insecure_javascript();
                }
                self.run_operation(kind, &params, v, jvc, true, origin)
            }
        }
    }

    /// Versión para formatear los errores que se suben antes de conocer la
    /// versión de la operación: la de `ver` (con la regla de 4.1), o 4.1
    /// si falta `ver` y el JavaScript es de AutoScript 1.10 o posterior.
    fn hint_version(params: &Params, jvc: i32) -> ProtocolVersion {
        match params.get("ver").ok().flatten() {
            Some(v) => ProtocolVersion::from_param(Some(&v)).reviewed(jvc),
            None if jvc > 3 => ProtocolVersion::V4_1,
            None => ProtocolVersion::V0,
        }
    }

    fn upload(&self, reply: &ReplyChannel, payload: &str, version: Option<ProtocolVersion>) {
        if let Err(e) = self.uploader.store(&self.config.http, &reply.storage_servlet, &reply.id, payload) {
            let err = intermediate::store_error(&e);
            self.show_error(&err, version);
        }
    }

    fn run_operation(
        &self,
        kind: OperationKind,
        params: &Params,
        channel: Option<ProtocolVersion>,
        jvc: i32,
        by_socket: bool,
        origin: RequestOrigin,
    ) -> String {
        let http = self.config.http.clone();
        let ctx = ParseContext { services_required: !by_socket, http: &http, locale: self.config.locale };
        // Errores previos a la operación: Java los muestra y los devuelve
        // con la versión del canal (o el formato antiguo en invocación
        // directa), pero no los sube.
        let early_failure = |err: &ProtocolError, reply: Option<ReplyChannel>| -> String {
            let text = self.error_response(err, channel);
            if !by_socket && self.config.upload_all_errors {
                if let Some(r) = reply.or_else(|| request::reply_channel_hint(params)) {
                    let hv = Self::hint_version(params, jvc);
                    self.upload(&r, &err.response(Some(hv), self.config.locale), Some(hv));
                }
            }
            text
        };
        let mut req = match request::parse_request(kind, params, &ctx) {
            Ok(r) => r,
            Err(f) => return early_failure(&f.error, f.reply),
        };
        // Petición en el servidor intermedio.
        if let (Some(fid), Some(rt)) = (req.common().file_id.clone(), req.common().retrieve_servlet.clone()) {
            let env = match envelope::fetch_envelope(&http, &rt, &fid, req.common().cipher_config.as_deref(), kind) {
                Ok(p) => p,
                Err(e) => {
                    // Java solo mostraba el error (y en `save` lo subía con el
                    // identificador del fichero, que la página no consulta).
                    let text = self.error_response(&ProtocolError::parameter(e.code, e.message.clone()), channel);
                    if !by_socket && self.config.upload_all_errors {
                        if let Some(r) = request::reply_channel_hint(params) {
                            let hv = Self::hint_version(params, jvc);
                            self.upload(&r, &e.response(Some(hv), self.config.locale), Some(hv));
                        }
                    }
                    return text;
                }
            };
            let env_ctx = ParseContext { services_required: true, ..ctx };
            req = match request::parse_request(kind, &env, &env_ctx) {
                Ok(r) => r,
                Err(f) => return early_failure(&f.error, f.reply.or_else(|| request::reply_channel_hint(&env))),
            };
            if req.common().file_id.is_some() && req.common().data.is_none() {
                // Un sobre que remite a otro sobre no está soportado.
                return early_failure(&ProtocolError::unexpected(kind.generic_error(), "Sobre anidado"), request::reply_channel_hint(&env));
            }
        }
        let version = match channel {
            Some(v) => v,
            None => ProtocolVersion::from_param(Some(&req.common().requested_version)).reviewed(jvc),
        };
        // `load` no puede devolver su resultado por el servidor intermedio
        // (Java fallaba al final con 200600 tras mostrar el diálogo).
        if !by_socket && kind == OperationKind::Load {
            return self.error_response(
                &ProtocolError::unexpected(codes::UNKNOWN_LOADING_DATA_ERROR, "La carga de ficheros no esta disponible por servidor intermedio"),
                None,
            );
        }
        let reply = match (&req.common().id, &req.common().storage_servlet) {
            (Some(id), Some(st)) if !by_socket => Some(ReplyChannel { id: id.clone(), storage_servlet: st.clone() }),
            _ => None,
        };
        let waiting: Option<ActiveWaiting> = match &reply {
            Some(r) if req.common().active_waiting => Some(self.uploader.start_active_waiting(
                http.clone(),
                r.storage_servlet.clone(),
                r.id.clone(),
                self.config.active_waiting_interval,
            )),
            _ => None,
        };
        let mut info = RequestInfo::new(origin, kind);
        let result = match &req {
            Request::Sign(p) => self.process_sign(p, version, false, &mut info),
            Request::SignAndSave(p) => self.process_sign(p, version, true, &mut info),
            Request::SelectCert(p) => self.process_select_cert(p, version, &info),
            Request::Batch(p) => self.process_batch(p, version, &mut info),
            Request::Save(p) => self.process_save(p, version, &mut info),
            Request::Load(p) => self.process_load(p, version, &info),
        };
        self.progress(&ExtraParams::new(), ProgressEvent::Hide, Some(&info));
        if let Some(w) = waiting {
            w.stop();
        }
        let (text, upload) = match &result {
            Ok(s) => (s.clone(), true),
            Err(e) => (self.error_response(e, Some(version)), e.origin == ErrorOrigin::Operation || self.config.upload_all_errors),
        };
        if let (Some(r), true) = (&reply, upload) {
            self.upload(r, &text, Some(version));
        }
        text
    }

    fn check_versions(&self, version: ProtocolVersion, mcv: Option<&str>, kind: OperationKind) -> Result<(), ProtocolError> {
        if !version.is_supported_by_app() {
            return Err(ProtocolError::op_code(codes::UNSUPPORTED_PROTOCOL_VERSION));
        }
        if let Some(m) = mcv {
            match version::minimum_version_not_satisfied(m, &self.config.app_version) {
                Ok(true) => return Err(ProtocolError::op_code(codes::MINIMUM_VERSION_NON_SATISTIED)),
                Ok(false) => {}
                Err(e) => return Err(ProtocolError::unexpected(kind.generic_error(), e.to_string())),
            }
        }
        Ok(())
    }

    /// Selección de certificado con el firmante persistente. Devuelve la
    /// clave y si se mostró el diálogo.
    fn select_key(&self, sel: &KeySelection<'_>, restrict: Option<&[u8]>) -> Result<(Arc<dyn SigningKey>, bool), ProtocolError> {
        if restrict.is_none() && sel.sticky && !sel.reset_sticky {
            if let Some(k) = self.sticky_key() {
                return Ok((k, false));
            }
        }
        self.progress(sel.extra, ProgressEvent::LoadingKeyStore, Some(sel.info));
        let req = CertificateRequest {
            info: sel.info,
            operation: sel.kind,
            extra_params: sel.extra,
            keystore: sel.keystore,
            restrict_to_certificate: restrict,
        };
        self.progress(sel.extra, ProgressEvent::Hide, Some(sel.info));
        match self.handler.select_certificate(&req) {
            Ok(k) => Ok((k, true)),
            Err(e) if e.is_cancelled() => Err(ProtocolError::cancelled()),
            Err(e) => {
                let code = match e.code {
                    Some(c) if c == codes::CERTIFICATE_NEEDED => match sel.kind {
                        OperationKind::SelectCert => codes::NO_CERTS_FOUND_SELECTING_CERT,
                        OperationKind::Batch => codes::NO_CERTS_FOUND_SIGNING_BATCH,
                        _ => codes::NO_CERTS_FOUND_SIGNING,
                    },
                    Some(c) => c,
                    None => codes::LOADING_KEYSTORE_INTERNAL_ERROR,
                };
                let err = ProtocolError::operation(code, e.to_string());
                if sel.kind == OperationKind::Batch {
                    self.show_error(&err, None);
                }
                Err(err)
            }
        }
    }

    /// Bucle de intervención del usuario (`RuntimeConfigNeededException`):
    /// repite `op` tras la confirmación o la contraseña.
    fn with_interventions<T>(
        &self,
        origin: Option<&RequestOrigin>,
        extra: &mut ExtraParams,
        mut op: impl FnMut(&ExtraParams) -> Result<T, AfirmaError>,
    ) -> Result<T, AfirmaError> {
        loop {
            match op(extra) {
                Err(e) => {
                    let ErrorKind::NeedsIntervention { intervention, denied } = &e.kind else { return Err(e) };
                    if *denied || extra.get_bool("headless", false) {
                        return Err(e);
                    }
                    match intervention {
                        UserIntervention::Confirm { requestor_text, param, effect } => {
                            if !self.handler.confirm(&ConfirmRequest {
                                origin: origin.cloned(),
                                requestor_text: requestor_text.clone(),
                                message: e.message.clone(),
                            }) {
                                return Err(AfirmaError::cancelled());
                            }
                            match effect {
                                ConfirmEffect::SetParamTrue => {
                                    extra.set(param.clone(), "true");
                                }
                                ConfirmEffect::RemovePolicyParams => {
                                    for k in ["policyIdentifier", "policyIdentifierHash", "policyIdentifierHashAlgorithm", "policyDescription", "policyQualifier"] {
                                        extra.remove(k);
                                    }
                                }
                            }
                        }
                        UserIntervention::Password { requestor_text, param } => {
                            let Some(pwd) = self.handler.request_password(&PasswordRequest {
                                origin: origin.cloned(),
                                requestor_text: requestor_text.clone(),
                                message: e.message.clone(),
                            }) else {
                                return Err(AfirmaError::cancelled());
                            };
                            if requestor_text == "pdfpasswordprotected" || requestor_text == "pdfbadpassword" {
                                extra.set("ownerPassword", pwd);
                                extra.remove("userPassword");
                            } else {
                                extra.set(param.clone(), pwd);
                            }
                        }
                    }
                }
                ok => return ok,
            }
        }
    }

    /// Firma local o trifásica de una operación (`executeSign`).
    #[allow(clippy::too_many_arguments)]
    fn execute_sign(
        &self,
        op: CryptoOperation,
        format: &str,
        data: Option<&[u8]>,
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &mut ExtraParams,
        tri_http: &HttpClient,
        origin: Option<&RequestOrigin>,
    ) -> Result<Vec<u8>, AfirmaError> {
        let target = if extra.get("target").is_some_and(|t| t.eq_ignore_ascii_case("tree")) { CounterSignTarget::Tree } else { CounterSignTarget::Leafs };
        if let Some(tf) = TriphaseFormat::from_format_name(format) {
            let client = TriphaseClient::new(tri_http.with_ssl_error_handling(afirma_core::http::SslErrorHandling::from_extra_params(extra)));
            return self.with_interventions(origin, extra, |ep| client.sign(tf, op, data, algorithm, key, ep, Some(&target)));
        }
        let data = data.unwrap_or(&[]);
        self.with_interventions(origin, extra, |ep| {
            self.signer.sign(&LocalSignRequest { operation: op, format, data, algorithm, key, extra_params: ep, target: target.clone() })
        })
    }

    fn map_sign_error(e: AfirmaError, generic: ErrorCode) -> ProtocolError {
        if e.is_cancelled() {
            return ProtocolError::cancelled();
        }
        let code = match (&e.kind, e.code) {
            (ErrorKind::InvalidArgument, _) => codes::INVALID_FORMAT_SIGNATURE_PARAM,
            (ErrorKind::Unsupported, _) => codes::UNSUPPORTED_OPERATION,
            (_, Some(c)) => c,
            (_, None) => generic,
        };
        ProtocolError::operation(code, e.to_string())
    }

    fn cipher(&self, config: Option<&[u8]>, code: ErrorCode) -> Result<Option<ServerCipher>, ProtocolError> {
        match config {
            None => Ok(None),
            Some(c) => ServerCipher::from_config(c).map_err(|e| ProtocolError::operation(code, e.to_string())),
        }
    }

    /// Firma, cofirma y contrafirma (`ProtocolInvocationLauncherSign`) y
    /// `signandsave`.
    fn process_sign(&self, p: &SignParams, version: ProtocolVersion, and_save: bool, info: &mut RequestInfo) -> Result<String, ProtocolError> {
        let kind = if and_save { OperationKind::SignAndSave } else { OperationKind::Sign };
        info.app_name = p.app_name.clone();
        info.crypto_operation = p.operation;
        info.format = Some(p.format.clone());
        info.file_name = p.filename.clone().or_else(|| p.extra_params.get("filenameActualName").map(str::to_string));
        self.check_versions(version, p.common.min_client_version.as_deref(), kind)?;
        let mut extra = p.extra_params.clone();
        extra.remove("profile");
        let cipher = self.cipher(p.common.cipher_config.as_deref(), codes::POSTPROCESING_SIGNATURE)?;
        let is_auto = p.format.eq_ignore_ascii_case("AUTO");
        let tri = TriphaseFormat::from_format_name(&p.format);
        if !is_auto && tri.is_none() && !self.signer.supports_format(&p.format) {
            return Err(ProtocolError::op_code(codes::UNSUPPORTED_SIGNATURE_FORMAT));
        }
        let op = p.operation.ok_or_else(|| ProtocolError::operation(codes::UNKNOWN_SIGNING_ERROR, "No se ha indicado la operacion criptografica"))?;
        // Datos (o diálogo de selección de fichero).
        let mut data = p.common.data.clone();
        let mut input_filename = None;
        if data.is_none() {
            let without_data = !is_auto && self.signer.can_sign_without_data(op, &p.format, &extra);
            if !without_data {
                let file = self.choose_file(op, &extra, info)?;
                input_filename = Some(file.name);
                data = Some(file.data);
            }
        }
        // AUTO.
        let format = if is_auto {
            let d = data.as_deref().unwrap_or(&[]);
            self.signer.detect_format(op, d).ok_or_else(|| ProtocolError::op_code(codes::CANT_IDENTIFY_SIGNATURE_FORMAT))?
        } else {
            p.format.clone()
        };
        info.format = Some(format.clone());
        if let Some(name) = &input_filename {
            info.file_name = Some(name.clone());
        }
        info.data_len = data.as_ref().map(Vec::len);
        info.data = data.as_ref().map(|d| Arc::<[u8]>::from(d.as_slice()));
        // XAdES explícita (obsoleta).
        if op == CryptoOperation::Sign
            && format.to_ascii_lowercase().starts_with("xades")
            && extra.get("mode").is_some_and(|m| m.eq_ignore_ascii_case("explicit"))
            && !extra.get_bool("useManifest", false)
            && !format.eq_ignore_ascii_case("XAdEStri")
        {
            if let Some(d) = &data {
                data = Some(afirma_core::DigestAlgorithm::Sha1.digest(d));
                extra.set("mimeType", "hash/sha1");
            }
        }
        // Validación previa de las firmas.
        if let Some(d) = &data {
            if extra.get_bool("checkSignatures", false) {
                self.progress(&extra, ProgressEvent::CheckingSignatures, Some(info));
                if PADES_FORMATS.contains(&format.as_str()) && !extra.get_bool("allowShadowAttack", false) && !extra.contains("pagesToCheckShadowAttack") {
                    extra.set("pagesToCheckShadowAttack", "10");
                }
                let signer = self.signer.clone();
                let fmt = format.clone();
                let r = self.with_interventions(Some(&info.origin), &mut extra, |ep| signer.check_signatures(op, &fmt, d, ep));
                self.progress(&extra, ProgressEvent::Hide, Some(info));
                if let Err(e) = r {
                    if e.is_cancelled() {
                        return Err(ProtocolError::cancelled());
                    }
                    let code = if and_save { codes::INVALID_SIGNATURE } else { e.code.unwrap_or(codes::INVALID_SIGNATURE) };
                    return Err(ProtocolError::operation(code, e.to_string()));
                }
            }
        }
        // Políticas.
        extra = self.signer.expand_extra_params(&extra, data.as_deref(), &format).map_err(|e| {
            ProtocolError::operation(e.code.unwrap_or(codes::SIGNING_WITH_POLICY_INCOMPATIBILITY), e.to_string())
        })?;
        // Firma visible PDF.
        if PADES_FORMATS.contains(&format.as_str()) {
            let vs = extra.get("visibleSignature").map(str::to_ascii_lowercase);
            if matches!(vs.as_deref(), Some("want") | Some("optional")) {
                let mandatory = vs.as_deref() == Some("want");
                let d = data.as_deref().unwrap_or(&[]);
                let req = VisibleSignatureRequest {
                    info,
                    data: d,
                    extra_params: &extra,
                    mandatory,
                    custom_appearance: extra.get("visibleAppearance").is_some_and(|v| v.eq_ignore_ascii_case("custom")),
                };
                match self.handler.visible_signature(&req) {
                    Ok(Some(new)) => extra.extend(&new),
                    Ok(None) => {
                        let has_area = ["signaturePositionOnPageLowerLeftX", "signaturePositionOnPageLowerLeftY", "signaturePositionOnPageUpperRightX", "signaturePositionOnPageUpperRightY"]
                            .iter()
                            .all(|k| extra.contains(k))
                            && (extra.contains("signaturePage") || extra.contains("signaturePages"));
                        if mandatory && !has_area {
                            return Err(ProtocolError::operation(codes::VISIBLE_SIGNATURE_IS_MANDATORY, "Es obligatorio mostrar la firma en el documento PDF"));
                        }
                    }
                    Err(e) if e.is_cancelled() => {
                        return Err(ProtocolError::operation(codes::VISIBLE_SIGNATURE_IS_MANDATORY, "Es obligatorio mostrar la firma en el documento PDF"));
                    }
                    Err(e) => return Err(ProtocolError::from_afirma(&e, codes::UNKNOWN_SIGNING_ERROR)),
                }
            }
        }
        // Certificado y firma (con reintento por PIN erróneo).
        let info_snapshot = info.clone();
        let sel = KeySelection { info: &info_snapshot, kind, extra: &extra, keystore: p.keystore.as_ref(), sticky: p.sticky, reset_sticky: p.reset_sticky };
        let (mut key, _) = self.select_key(&sel, None)?;
        // Java no aplica `servicetimeout` a los firmadores trifásicos en
        // `signandsave`.
        let tri_http = if and_save {
            self.config.http.clone()
        } else {
            self.config.http.with_read_timeout(p.common.service_timeout.map(|ms| Duration::from_millis(u64::from(ms))))
        };
        let signature = loop {
            let algorithm = afirma_core::algorithms::compose_signature_algorithm(&p.algorithm, key.key_algorithm())
                .map_err(|e| ProtocolError::operation(codes::INVALID_SIGNING_KEY, e.to_string()))?
                .java_name();
            if !and_save {
                self.set_sticky_key(if p.sticky { Some(key.clone()) } else { None });
            }
            self.progress(&extra, ProgressEvent::Signing, Some(&info_snapshot));
            let mut ep = extra.clone();
            let r = self.execute_sign(op, &format, data.as_deref(), &algorithm, key.as_ref(), &mut ep, &tri_http, Some(&info_snapshot.origin));
            self.progress(&extra, ProgressEvent::Hide, Some(&info_snapshot));
            match r {
                Ok(s) => break s,
                Err(e) if e.code == Some(codes::INVALID_SMARTCARD_PIN) => {
                    let cert = key.certificate().to_vec();
                    key = self.select_key(&sel, Some(&cert))?.0;
                }
                Err(e) if e.code == Some(codes::KEYSTORE_LOCKED) || e.code == Some(codes::SMARTCARD_LOCKED) => {
                    self.set_sticky_key(None);
                    return Err(ProtocolError::operation(e.code.unwrap_or(codes::KEYSTORE_LOCKED), e.to_string()));
                }
                Err(e) => return Err(Self::map_sign_error(e, codes::UNKNOWN_SIGNING_ERROR)),
            }
        };
        if and_save {
            self.set_sticky_key(if p.sticky { Some(key.clone()) } else { None });
            self.save_signature(p, &extra, &format, input_filename.as_deref(), &signature, &info_snapshot)?;
        }
        response::sign_result(key.certificate(), &signature, input_filename.as_deref(), version.major, cipher.as_ref())
    }

    fn choose_file(&self, op: CryptoOperation, extra: &ExtraParams, info: &RequestInfo) -> Result<FileData, ProtocolError> {
        let locale = self.config.locale;
        let title_key = if op == CryptoOperation::Sign { "ProtocolLauncher.25" } else { "ProtocolLauncher.26" };
        let exts = extra.get("filenameExts").map(str::to_string);
        let desc = format!(
            "{}{}",
            extra.get("filenameDescription").map(str::to_string).unwrap_or_else(|| messages::get(locale, "ProtocolLauncher.32")),
            match &exts {
                None => " (*.*)".to_string(),
                Some(e) => format!(" (*.{})", e.replace(',', ",*.")),
            }
        );
        let req = OpenFileRequest {
            info: info.clone(),
            title_key,
            title: messages::get(locale, title_key),
            extensions: exts.map(|e| e.split(',').map(str::to_string).collect()),
            description: desc,
            current_dir: extra.get("filenameCurrentDir").map(str::to_string),
            file_name: extra.get("filenameActualName").map(str::to_string),
        };
        self.handler.choose_file_to_sign(&req).map_err(|e| {
            if e.is_cancelled() { ProtocolError::cancelled() } else { ProtocolError::operation(codes::LOADING_DATA_ERROR, e.to_string()) }
        })
    }

    fn save_signature(
        &self,
        p: &SignParams,
        extra: &ExtraParams,
        format: &str,
        input: Option<&str>,
        signature: &[u8],
        info: &RequestInfo,
    ) -> Result<(), ProtocolError> {
        let locale = self.config.locale;
        let exts = extra.get("filenameSaveExts").map(str::to_string);
        let desc = format!(
            "{}{}",
            extra.get("filenameSaveDescription").map(str::to_string).unwrap_or_else(|| messages::get(locale, "ProtocolLauncher.30")),
            match &exts {
                None => " (*.*)".to_string(),
                Some(e) => format!(" (*.{})", e.replace(',', ",*.")),
            }
        );
        let proposed = match &p.filename {
            Some(f) => f.clone(),
            None => {
                let name = match input {
                    Some(f) => match f.rfind('.') {
                        Some(dot) if dot > 0 => f[..dot].to_string(),
                        _ => f.to_string(),
                    },
                    None => messages::get(locale, "ProtocolLauncher.30"),
                };
                match TriphaseFormat::from_format_name(format) {
                    Some(t) => t.signed_name(&name),
                    None => self.signer.signed_file_name(format, &name),
                }
            }
        };
        let req = SaveFileRequest {
            info,
            title: messages::get(locale, "ProtocolLauncher.31"),
            data: signature,
            proposed_name: Some(proposed),
            extensions: exts.map(|e| e.split(',').map(str::to_string).collect()),
            description: Some(desc),
            current_dir: extra.get("filenameSaveCurrentDir").map(str::to_string),
        };
        self.handler.save_file(&req).map_err(|e| {
            if e.is_cancelled() { ProtocolError::cancelled() } else { ProtocolError::operation(codes::CANT_SAVE_FILE, e.to_string()) }
        })
    }

    /// Selección de certificado (`ProtocolInvocationLauncherSelectCert`).
    fn process_select_cert(&self, p: &SelectCertParams, version: ProtocolVersion, info: &RequestInfo) -> Result<String, ProtocolError> {
        self.check_versions(version, p.common.min_client_version.as_deref(), OperationKind::SelectCert)?;
        let sel = KeySelection {
            info,
            kind: OperationKind::SelectCert,
            extra: &p.extra_params,
            keystore: p.keystore.as_ref(),
            sticky: p.sticky,
            reset_sticky: p.reset_sticky,
        };
        let (key, dialog) = self.select_key(&sel, None)?;
        if dialog {
            self.set_sticky_key(if p.sticky { Some(key.clone()) } else { None });
        }
        let cipher = self.cipher(p.common.cipher_config.as_deref(), codes::ENCRIPTING_SELECTED_CERT)?;
        response::select_cert_result(key.certificate(), cipher.as_ref())
    }

    /// Firma de lotes (`ProtocolInvocationLauncherBatch`).
    fn process_batch(&self, p: &BatchParams, version: ProtocolVersion, info: &mut RequestInfo) -> Result<String, ProtocolError> {
        self.check_versions(version, p.common.min_client_version.as_deref(), OperationKind::Batch)?;
        info.app_name = p.app_name.clone();
        if let Some(d) = &p.common.data {
            let (format, count) = batch_summary(d, p.json_batch);
            info.format = format;
            info.document_count = count;
            info.data_len = Some(d.len());
        }
        let info = &*info;
        let sel = KeySelection {
            info,
            kind: OperationKind::Batch,
            extra: &p.extra_params,
            keystore: p.keystore.as_ref(),
            sticky: p.sticky,
            reset_sticky: p.reset_sticky,
        };
        let generic = if p.local_batch_process {
            codes::INTERNAL_LOCAL_BATCH_ERROR
        } else if p.json_batch {
            codes::SIMPLE_INTERNAL_JSON_BATCH_ERROR
        } else {
            codes::INTERNAL_XML_BATCH_ERROR
        };
        let (mut key, dialog) = self.select_key(&sel, None)?;
        if dialog {
            self.set_sticky_key(if p.sticky { Some(key.clone()) } else { None });
        }
        let http = self.config.http.with_read_timeout(p.common.service_timeout.map(|ms| Duration::from_millis(u64::from(ms))));
        let result = loop {
            self.progress(&p.extra_params, ProgressEvent::Signing, Some(info));
            let r = self.sign_batch(p, key.as_ref(), &http, info);
            self.progress(&p.extra_params, ProgressEvent::Hide, Some(info));
            match r {
                Ok(s) => break s,
                Err(BatchError::Afirma(e)) if e.code == Some(codes::INVALID_SMARTCARD_PIN) => {
                    self.set_sticky_key(None);
                    let cert = key.certificate().to_vec();
                    key = self.select_key(&sel, Some(&cert))?.0;
                }
                Err(BatchError::Afirma(e)) if e.is_cancelled() => return Err(ProtocolError::cancelled()),
                Err(BatchError::Afirma(e)) if e.code == Some(codes::KEYSTORE_LOCKED) || e.code == Some(codes::SMARTCARD_LOCKED) => {
                    self.set_sticky_key(None);
                    return Err(ProtocolError::operation(e.code.unwrap_or(codes::KEYSTORE_LOCKED), e.to_string()));
                }
                Err(BatchError::Afirma(e)) => {
                    let code = match (&e.kind, e.code) {
                        (ErrorKind::InvalidArgument, _) => codes::INVALID_FORMAT_SIGN_BATCH_PARAM,
                        (_, Some(c)) => c,
                        (_, None) => generic,
                    };
                    let err = ProtocolError::operation(code, e.to_string());
                    if e.code.is_none() {
                        self.show_error(&err, Some(version));
                    }
                    return Err(err);
                }
                Err(BatchError::InvalidArgument(m)) => return Err(ProtocolError::operation(codes::INVALID_FORMAT_SIGN_BATCH_PARAM, m)),
                Err(BatchError::Internal(m)) => {
                    let err = ProtocolError::operation(generic, m);
                    self.show_error(&err, Some(version));
                    return Err(err);
                }
            }
        };
        let cert = if p.need_cert { Some(key.certificate().to_vec()) } else { None };
        let cipher = self.cipher(p.common.cipher_config.as_deref(), codes::ENCRIPTING_BATCH_RESULT)?;
        response::batch_result(&result, cert.as_deref(), cipher.as_ref())
    }

    fn sign_batch(&self, p: &BatchParams, key: &dyn SigningKey, http: &HttpClient, info: &RequestInfo) -> Result<String, BatchError> {
        let data = p.common.data.as_deref();
        if p.json_batch && p.local_batch_process {
            let Some(d) = data else { return Err(BatchError::Internal("No se ha proporcionado el lote".into())) };
            let lb = match batch::parse_local_batch(d) {
                Ok(b) => b,
                Err(LocalBatchParseError::InvalidJson(m)) => return Err(BatchError::Internal(m)),
                Err(LocalBatchParseError::Malformed(m)) => {
                    return Err(BatchError::Afirma(AfirmaError::new(codes::MALFORMED_JSON_BATCH, "La declaracion del lote suministrada no es correcta").with_cause(m)));
                }
            };
            let results = batch::run_local_batch(&lb, |s| self.sign_local_batch_item(s, key, http, info));
            return Ok(batch::local_batch_result_json(&results));
        }
        let (Some(pre), Some(post)) = (p.presigner_url.as_deref(), p.postsigner_url.as_deref()) else {
            return Err(BatchError::InvalidArgument("La URL de preproceso de lotes no puede se nula ni vacia".into()));
        };
        let Some(d) = data else { return Err(BatchError::InvalidArgument("El lote de firma no puede ser nulo ni vacio".into())) };
        if p.json_batch {
            batch::sign_json_batch(http, d, pre, post, key, &p.extra_params)
        } else {
            batch::sign_xml_batch(http, d, pre, post, key, &p.extra_params)
        }
    }

    /// Firma de un elemento del lote local (`LocalBatchSigner.processSign`).
    /// El error es la descripción del resultado (`ERROR_PRE`).
    fn sign_local_batch_item(&self, s: &batch::LocalSingleSign, key: &dyn SigningKey, http: &HttpClient, info: &RequestInfo) -> Result<Vec<u8>, String> {
        let describe = |e: ProtocolError| if e.message.is_empty() { e.code.code_str() } else { e.message };
        let algorithm = afirma_core::algorithms::compose_signature_algorithm(&s.algorithm, key.key_algorithm())
            .map_err(|e| describe(ProtocolError::operation(codes::INVALID_SIGNING_KEY, e.to_string())))?
            .java_name();
        let is_auto = s.format.eq_ignore_ascii_case("AUTO");
        if !is_auto && TriphaseFormat::from_format_name(&s.format).is_none() && !self.signer.supports_format(&s.format) {
            return Err(describe(ProtocolError::op_code(codes::UNSUPPORTED_SIGNATURE_FORMAT)));
        }
        let Some(op) = s.operation else {
            return Err(codes::INTERNAL_LOCAL_BATCH_ERROR.code_str());
        };
        let format = if is_auto {
            self.signer.detect_format(op, &s.data).ok_or_else(|| describe(ProtocolError::op_code(codes::CANT_IDENTIFY_SIGNATURE_FORMAT)))?
        } else {
            s.format.clone()
        };
        let mut extra = s.extra_params.clone();
        extra.set("headless", "true");
        self.execute_sign(op, &format, Some(&s.data), &algorithm, key, &mut extra, http, Some(&info.origin))
            .map_err(|e| describe(Self::map_sign_error(e, codes::INTERNAL_LOCAL_BATCH_ERROR)))
    }

    /// Guardado de datos (`ProtocolInvocationLauncherSave`).
    fn process_save(&self, p: &SaveParams, version: ProtocolVersion, info: &mut RequestInfo) -> Result<String, ProtocolError> {
        self.check_versions(version, p.common.min_client_version.as_deref(), OperationKind::Save)?;
        let data = p.common.data.clone().unwrap_or_default();
        info.file_name = p.filename.clone();
        info.data_len = Some(data.len());
        info.data = Some(Arc::from(data.as_slice()));
        let req = SaveFileRequest {
            info,
            title: p.title.clone(),
            data: &data,
            proposed_name: p.filename.clone(),
            extensions: p.extensions.clone().map(|e| vec![e]),
            description: p.description.clone(),
            current_dir: None,
        };
        self.handler.save_file(&req).map_err(|e| {
            if e.is_cancelled() { ProtocolError::cancelled() } else { ProtocolError::operation(codes::CANT_SAVE_FILE, e.to_string()) }
        })?;
        Ok(response::SAVE_OK.to_string())
    }

    /// Carga de ficheros (`ProtocolInvocationLauncherLoad`).
    fn process_load(&self, p: &LoadParams, version: ProtocolVersion, info: &RequestInfo) -> Result<String, ProtocolError> {
        self.check_versions(version, p.common.min_client_version.as_deref(), OperationKind::Load)?;
        let req = LoadRequest {
            info: info.clone(),
            title: p.title.clone(),
            extensions: p.extensions.clone().map(|e| e.split(',').map(str::to_string).collect()),
            description: p.description.clone(),
            file_path: p.file_path.clone(),
            multiple: p.multiload,
        };
        let files = self.handler.load_files(&req).map_err(|e| {
            if e.is_cancelled() { ProtocolError::cancelled() } else { ProtocolError::operation(codes::CANT_LOAD_FILE, e.to_string()) }
        })?;
        Ok(response::load_result(&files.into_iter().map(|f| (f.name, f.data)).collect::<Vec<_>>()))
    }
}

/// Formato y número de documentos de un lote (para [`RequestInfo`]).
fn batch_summary(data: &[u8], json: bool) -> (Option<String>, Option<usize>) {
    if json {
        match crate::json_lenient::parse_object_bytes(data) {
            Ok(o) => (o.opt_string("format"), o.get_array("singlesigns").ok().map(Vec::len)),
            Err(_) => (None, None),
        }
    } else {
        match afirma_xml::dom::Document::parse_bytes(data) {
            Ok((doc, _)) => {
                let Some(root) = doc.document_element() else { return (None, None) };
                let singles: Vec<_> = doc
                    .child_elements(root)
                    .filter(|c| doc.element(*c).is_some_and(|e| e.local.eq_ignore_ascii_case("singlesign")))
                    .collect();
                let format = singles.first().and_then(|s| {
                    doc.child_elements(*s)
                        .find(|c| doc.element(*c).is_some_and(|e| e.local == "format"))
                        .map(|c| doc.text_content(c).trim().to_string())
                });
                (format, Some(singles.len()))
            }
            Err(_) => (None, None),
        }
    }
}

/// Formatos en los que se ofrece la firma visible PDF (lista exacta de Java).
const PADES_FORMATS: &[&str] = &["Adobe PDF", "Adobe PDF TriPhase", "PAdES", "PAdEStri", "ETSI.CAdES.detached", "adbe.pkcs7.detached"];
