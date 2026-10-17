//! Puente JNI con la capa Java (paquete `io.github.autofirma_rs.android`).
//!
//! - Rust → Java: métodos de instancia de `MainActivity` sobre la referencia global de la
//!   actividad que mantiene `android-activity` ([`JavaPlatform`]). Se llaman sobre el
//!   objeto (no con `FindClass`), así funcionan desde cualquier hilo enganchado a la JVM.
//! - Java → Rust: métodos `static native` de `NativeBridge`, exportados con
//!   [`jni_mangle`]. Solo copian los datos y encolan un evento en [`Bridge::global`].

use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};

use afirma_core::SignatureAlgorithm;
use android_activity::{AndroidApp, OnCreateState};
use jni::errors::{Error as JniError, LogErrorAndDefault};
use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString, JValue};
use jni::sys::{jboolean, jfloat, jint, jlong};
use jni::{Env, EnvUnowned, JavaVM, jni_mangle, jni_sig, jni_str};

use crate::bridge::{
    Bridge, DOCUMENT_TOO_LARGE, DeviceConfig, NfcTagInfo, Platform, PlatformError, PlatformEvent, RequestId,
};
use crate::ime::{ImeRequest, ImeState};

/// Tamaño máximo de un documento abierto con el selector del sistema.
const MAX_DOCUMENT_BYTES: u64 = 256 * 1024 * 1024;

fn jni_error(e: JniError) -> PlatformError {
    match e {
        JniError::CaughtJavaException { name, msg, .. } => PlatformError(format!("{name}: {msg}")),
        other => PlatformError(format!("error de JNI: {other}")),
    }
}

/// Inicia `rustls-platform-verifier` (verificación TLS con el almacén de Android, que usa
/// `ureq` en afirma-core) con el contexto de la aplicación.
pub fn init_tls_verifier(state: &OnCreateState) -> Result<(), PlatformError> {
    // SAFETY: puntero a la JavaVM del proceso que entrega android-activity.
    let vm = unsafe { JavaVM::from_raw(state.vm_as_ptr().cast()) };
    let activity = state.activity_as_ptr() as jni::sys::jobject;
    vm.attach_current_thread(|env| -> Result<(), JniError> {
        // SAFETY: referencia de la actividad válida mientras dura onCreate.
        let activity = unsafe { env.as_cast_raw::<JObject>(&activity)? };
        let context = env
            .call_method(
                &*activity,
                jni_str!("getApplicationContext"),
                jni_sig!("()Landroid/content/Context;"),
                &[],
            )?
            .l()?;
        rustls_platform_verifier::android::init_with_env(env, context)
    })
    .map_err(jni_error)
}

/// Llamadas de Rust a la capa Java (métodos públicos de `MainActivity`).
pub struct JavaPlatform {
    app: AndroidApp,
}

impl JavaPlatform {
    pub fn new(app: AndroidApp) -> Self {
        JavaPlatform { app }
    }

    /// Ejecuta `f` con el hilo actual enganchado a la JVM y la actividad.
    fn with_activity<T>(
        &self,
        f: impl FnOnce(&mut Env<'_>, &JObject<'_>) -> Result<T, JniError>,
    ) -> Result<T, PlatformError> {
        let vm = JavaVM::singleton().map_err(jni_error)?;
        let activity = self.app.activity_as_ptr() as jni::sys::jobject;
        vm.attach_current_thread(|env| -> Result<T, JniError> {
            // SAFETY: referencia global de la actividad, válida mientras viva `self.app`.
            let activity = unsafe { env.as_cast_raw::<JObject>(&activity)? };
            f(env, &activity)
        })
        .map_err(jni_error)
    }
}

impl Platform for JavaPlatform {
    fn open_document(&self, request: RequestId, mime_types: &[&str]) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            let mime_types = JString::new(env, mime_types.join(","))?;
            env.call_method(
                activity,
                jni_str!("openDocument"),
                jni_sig!("(JLjava/lang/String;)V"),
                &[JValue::Long(request), JValue::Object(&mime_types)],
            )?;
            Ok(())
        })
    }

    fn create_document(&self, request: RequestId, mime_type: &str, name: &str) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            let mime_type = JString::new(env, mime_type)?;
            let name = JString::new(env, name)?;
            env.call_method(
                activity,
                jni_str!("createDocument"),
                jni_sig!("(JLjava/lang/String;Ljava/lang/String;)V"),
                &[JValue::Long(request), JValue::Object(&mime_type), JValue::Object(&name)],
            )?;
            Ok(())
        })
    }

    fn install_certificate(&self, request: RequestId, pkcs12: &[u8]) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            let pkcs12 = env.byte_array_from_slice(pkcs12)?;
            env.call_method(
                activity,
                jni_str!("installCertificate"),
                jni_sig!("(J[B)V"),
                &[JValue::Long(request), JValue::Object(&pkcs12)],
            )?;
            Ok(())
        })
    }

    fn choose_certificate(&self, request: RequestId) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            env.call_method(
                activity,
                jni_str!("chooseCertificate"),
                jni_sig!("(J)V"),
                &[JValue::Long(request)],
            )?;
            Ok(())
        })
    }

    fn certificate_chain(&self, alias: &str) -> Result<Vec<Vec<u8>>, PlatformError> {
        self.with_activity(|env, activity| {
            let alias = JString::new(env, alias)?;
            let chain = env
                .call_method(
                    activity,
                    jni_str!("certificateChain"),
                    jni_sig!("(Ljava/lang/String;)[[B"),
                    &[JValue::Object(&alias)],
                )?
                .l()?;
            let chain = env.cast_local::<JObjectArray<JByteArray>>(chain)?;
            let len = chain.len(env)?;
            let mut certificates = Vec::with_capacity(len);
            for i in 0..len {
                let der = chain.get_element(env, i)?;
                certificates.push(env.convert_byte_array(&der)?);
            }
            Ok(certificates)
        })
    }

    fn sign(&self, alias: &str, algorithm: SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>, PlatformError> {
        self.with_activity(|env, activity| {
            let alias = JString::new(env, alias)?;
            let algorithm = JString::new(env, algorithm.java_name())?;
            let data = env.byte_array_from_slice(data)?;
            let signature = env
                .call_method(
                    activity,
                    jni_str!("sign"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/String;[B)[B"),
                    &[
                        JValue::Object(&alias),
                        JValue::Object(&algorithm),
                        JValue::Object(&data),
                    ],
                )?
                .l()?;
            let signature = env.cast_local::<JByteArray>(signature)?;
            env.convert_byte_array(&signature)
        })
    }

    fn start_nfc_reader(&self, request: RequestId) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            env.call_method(
                activity,
                jni_str!("startNfcReader"),
                jni_sig!("(J)V"),
                &[JValue::Long(request)],
            )?;
            Ok(())
        })
    }

    fn nfc_transceive(&self, apdu: &[u8]) -> Result<Vec<u8>, PlatformError> {
        self.with_activity(|env, activity| {
            let apdu = env.byte_array_from_slice(apdu)?;
            let response = env
                .call_method(
                    activity,
                    jni_str!("nfcTransceive"),
                    jni_sig!("([B)[B"),
                    &[JValue::Object(&apdu)],
                )?
                .l()?;
            let response = env.cast_local::<JByteArray>(response)?;
            env.convert_byte_array(&response)
        })
    }

    fn stop_nfc_reader(&self) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            env.call_method(activity, jni_str!("stopNfcReader"), jni_sig!("()V"), &[])?;
            Ok(())
        })
    }

    fn leave_app(&self) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            env.call_method(activity, jni_str!("leaveApp"), jni_sig!("()V"), &[])?;
            Ok(())
        })
    }

    fn set_back_at_root(&self, at_root: bool) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            env.call_method(
                activity,
                jni_str!("setBackAtRoot"),
                jni_sig!("(Z)V"),
                &[JValue::Bool(at_root)],
            )?;
            Ok(())
        })
    }

    fn open_url(&self, request: RequestId, url: &str) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            let url = JString::new(env, url)?;
            env.call_method(
                activity,
                jni_str!("openUrl"),
                jni_sig!("(JLjava/lang/String;)V"),
                &[JValue::Long(request), JValue::Object(&url)],
            )?;
            Ok(())
        })
    }

    fn ime_show(&self, request: &ImeRequest) -> Result<(), PlatformError> {
        let (start, end) = request.state.selection_utf16();
        self.with_activity(|env, activity| {
            let text = JString::new(env, &request.state.text)?;
            env.call_method(
                activity,
                jni_str!("imeShow"),
                jni_sig!("(IIILjava/lang/String;II)V"),
                &[
                    JValue::Int(request.kind.input_type()),
                    JValue::Int(request.kind.action_id()),
                    JValue::Int(request.kind.ime_options()),
                    JValue::Object(&text),
                    JValue::Int(start),
                    JValue::Int(end),
                ],
            )?;
            Ok(())
        })
    }

    fn ime_update(&self, state: &ImeState) -> Result<(), PlatformError> {
        let (start, end) = state.selection_utf16();
        self.with_activity(|env, activity| {
            let text = JString::new(env, &state.text)?;
            env.call_method(
                activity,
                jni_str!("imeUpdate"),
                jni_sig!("(Ljava/lang/String;II)V"),
                &[JValue::Object(&text), JValue::Int(start), JValue::Int(end)],
            )?;
            Ok(())
        })
    }

    fn ime_hide(&self) -> Result<(), PlatformError> {
        self.with_activity(|env, activity| {
            env.call_method(activity, jni_str!("imeHide"), jni_sig!("()V"), &[])?;
            Ok(())
        })
    }
}

// ----------------------------------------------------------------------------------------
// Java → Rust (`NativeBridge`). Todos vuelven enseguida: copian los datos y encolan un evento.

fn optional_bytes(env: &Env<'_>, value: &JByteArray<'_>) -> Result<Option<Vec<u8>>, JniError> {
    if value.is_null() {
        Ok(None)
    } else {
        env.convert_byte_array(value).map(Some)
    }
}

fn optional_string(env: &Env<'_>, value: &JString<'_>) -> Result<Option<String>, JniError> {
    if value.is_null() {
        Ok(None)
    } else {
        value.try_to_string(env).map(Some)
    }
}

/// `NativeBridge.onViewIntent(String uri)`: intent `VIEW` (`afirma://...`).
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_view_intent<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>, uri: JString<'local>) {
    env.with_env(|env| -> Result<(), JniError> {
        if let Some(uri) = optional_string(env, &uri)? {
            Bridge::global().post(PlatformEvent::ViewIntent { uri });
        }
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onDocumentOpened(long request, String uri, String name, int fd)`: documento
/// elegido en el selector. Java cede el descriptor (`ParcelFileDescriptor.detachFd`); se lee
/// aquí, en el hilo de E/S de la capa Java.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_document_opened<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jlong,
    uri: JString<'local>,
    name: JString<'local>,
    fd: jint,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let uri = optional_string(env, &uri)?.unwrap_or_default();
        let name = optional_string(env, &name)?;
        let event = if fd < 0 {
            PlatformEvent::RequestFailed {
                request,
                cancelled: false,
                message: Some("descriptor de fichero no válido".to_string()),
            }
        } else {
            // SAFETY: Java ha cedido la propiedad del descriptor y no lo vuelve a usar.
            let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
            let mut data = Vec::new();
            match file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut data) {
                Ok(n) if n as u64 > MAX_DOCUMENT_BYTES => {
                    tracing::warn!(
                        "El documento supera el tamaño máximo ({} MB)",
                        MAX_DOCUMENT_BYTES / 1024 / 1024
                    );
                    PlatformEvent::RequestFailed {
                        request,
                        cancelled: false,
                        message: Some(DOCUMENT_TOO_LARGE.to_string()),
                    }
                }
                Ok(_) => PlatformEvent::DocumentOpened {
                    request,
                    uri,
                    name,
                    data,
                },
                Err(e) => PlatformEvent::RequestFailed {
                    request,
                    cancelled: false,
                    message: Some(format!("no se pudo leer el documento: {e}")),
                },
            }
        };
        Bridge::global().post(event);
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onDocumentCreated(long request, String uri, String name, int fd)`: documento
/// nuevo del diálogo de guardado. Java cede el descriptor, abierto para escribir; aquí (hilo
/// de E/S de la capa Java) se escriben los datos de la petición y se cierra.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_document_created<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jlong,
    uri: JString<'local>,
    name: JString<'local>,
    fd: jint,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let uri = optional_string(env, &uri)?.unwrap_or_default();
        let name = optional_string(env, &name)?;
        let bridge = Bridge::global();
        if fd < 0 {
            bridge.take_write(request);
            bridge.post(PlatformEvent::RequestFailed {
                request,
                cancelled: false,
                message: Some("descriptor de fichero no válido".to_string()),
            });
        } else {
            // SAFETY: Java ha cedido la propiedad del descriptor y no lo vuelve a usar.
            let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
            bridge.complete_write(request, uri, name, file);
        }
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onCertificateInstalled(long request)`: el instalador del sistema ha añadido
/// el certificado.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_certificate_installed<'local>(_env: EnvUnowned<'local>, _class: JClass<'local>, request: jlong) {
    Bridge::global().post(PlatformEvent::CertificateInstalled { request });
}

/// `NativeBridge.onCertificateChosen(long request, String alias)`: resultado del selector de
/// KeyChain (`alias` nulo si no se eligió ninguno).
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_certificate_chosen<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jlong,
    alias: JString<'local>,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let alias = optional_string(env, &alias)?;
        Bridge::global().post(PlatformEvent::CertificateChosen { request, alias });
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onNfcTag(long request, byte[] tagId, byte[] historicalBytes,
/// byte[] hiLayerResponse, byte[] nfcbApplicationData, byte[] nfcbProtocolInfo)`: tarjeta
/// ISO-DEP conectada (los cuatro últimos pueden ser nulos).
#[allow(clippy::too_many_arguments)] // firma fijada por el método nativo de Java
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_nfc_tag<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jlong,
    tag_id: JByteArray<'local>,
    historical_bytes: JByteArray<'local>,
    hi_layer_response: JByteArray<'local>,
    nfcb_application_data: JByteArray<'local>,
    nfcb_protocol_info: JByteArray<'local>,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let tag = NfcTagInfo {
            id: optional_bytes(env, &tag_id)?.unwrap_or_default(),
            historical_bytes: optional_bytes(env, &historical_bytes)?,
            hi_layer_response: optional_bytes(env, &hi_layer_response)?,
            nfcb_application_data: optional_bytes(env, &nfcb_application_data)?,
            nfcb_protocol_info: optional_bytes(env, &nfcb_protocol_info)?,
        };
        Bridge::global().post(PlatformEvent::NfcTag { request, tag });
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onRequestFailed(long request, boolean cancelled, String message)`.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_request_failed<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request: jlong,
    cancelled: jboolean,
    message: JString<'local>,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let message = optional_string(env, &message)?;
        Bridge::global().post(PlatformEvent::RequestFailed {
            request,
            cancelled,
            message,
        });
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onInsets(int left, int top, int right, int bottom)`: zona segura en píxeles.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_insets<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    left: jint,
    top: jint,
    right: jint,
    bottom: jint,
) {
    Bridge::global().set_safe_area_px([left as f32, top as f32, right as f32, bottom as f32]);
}

/// `NativeBridge.onBackPressed()`: botón o gesto «Atrás».
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_back_pressed<'local>(_env: EnvUnowned<'local>, _class: JClass<'local>) {
    Bridge::global().post(PlatformEvent::Back);
}

/// `NativeBridge.onConfiguration(String locale, boolean night, float fontScale,
/// boolean hasNfc)`: configuración del dispositivo (al crear la actividad y al cambiar).
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_configuration<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    locale: JString<'local>,
    night: jboolean,
    font_scale: jfloat,
    has_nfc: jboolean,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let locale = optional_string(env, &locale)?.unwrap_or_default();
        Bridge::global().post(PlatformEvent::Configuration(DeviceConfig {
            locale,
            night,
            font_scale: if font_scale.is_finite() && font_scale > 0.0 {
                font_scale
            } else {
                1.0
            },
            has_nfc,
        }));
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onTextInput(String text, int selStart, int selEnd, int composingStart,
/// int composingEnd)`: estado del editor del teclado (índices UTF-16 de Java). No se
/// registra nunca el texto (puede ser una contraseña o un PIN).
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_text_input<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    text: JString<'local>,
    sel_start: jint,
    sel_end: jint,
    composing_start: jint,
    composing_end: jint,
) {
    env.with_env(|env| -> Result<(), JniError> {
        let text = optional_string(env, &text)?.unwrap_or_default();
        let state = ImeState::from_java(text, sel_start, sel_end, composing_start, composing_end);
        Bridge::global().post(PlatformEvent::ImeState(state));
        Ok(())
    })
    .resolve::<LogErrorAndDefault>()
}

/// `NativeBridge.onEditorAction(int action)`: tecla de acción del teclado.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_editor_action<'local>(_env: EnvUnowned<'local>, _class: JClass<'local>, action: jint) {
    Bridge::global().post(PlatformEvent::ImeAction(action));
}

/// `NativeBridge.onImeVisibility(boolean visible)`: el teclado se ha mostrado u ocultado.
#[jni_mangle("io.github.autofirma_rs.android.NativeBridge")]
pub fn on_ime_visibility<'local>(_env: EnvUnowned<'local>, _class: JClass<'local>, visible: jboolean) {
    Bridge::global().post(PlatformEvent::ImeVisibility(visible));
}
