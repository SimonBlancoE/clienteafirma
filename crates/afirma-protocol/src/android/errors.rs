//! Catálogo de errores de Autofirma App 1.9 (`errors/*Errors.java`,
//! `ErrorManager`; `docs/spec/09-android.md` §8) y formato de las respuestas de
//! error que se suben al servidor intermedio (§5.12).
//!
//! Formato (`ErrorManager.genError`): `ERR-NN:=AA<código> - <mensaje>`, con el
//! texto de usuario localizado de la categoría o, si no se da (solo `save`), el
//! texto fijo en español del identificador `ERR-NN`. Antes de subirlo se
//! codifica con `URLEncoder.encode(…, "UTF-8")` ([`java_url_encode`]).

use super::texts::{UserText, WebLanguage};

/// Identificador `ERR-NN` con su texto fijo (`ErrorManager.ERRORS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorId {
    /// `ERR-NN`.
    pub id: &'static str,
    /// Texto fijo en español (sin acentos).
    pub text: &'static str,
}

macro_rules! error_ids {
    ($($(#[$m:meta])* $name:ident = $id:literal, $text:literal;)*) => {
        $( $(#[$m])* pub const $name: ErrorId = ErrorId { id: $id, text: $text }; )*
        /// Todos los identificadores del catálogo.
        pub const ALL_ERROR_IDS: &[ErrorId] = &[$($name),*];
    };
}

error_ids! {
    ERR_MISSING_OPERATION_NAME = "ERR-00", "No se ha indicado codigo de operacion";
    ERR_UNSUPPORTED_OPERATION_NAME = "ERR-01", "Codigo de operacion no soportado";
    ERR_MISSING_DATA = "ERR-02", "No se han proporcionado los datos de la operacion";
    ERR_BAD_XML = "ERR-03", "Se ha recibido un XML mal formado";
    ERR_BAD_CERTIFICATE = "ERR-04", "Se ha recibido un certificado corrupto";
    ERR_MISSING_DATA_ID = "ERR-05", "No se ha proporcionado un identificador para los datos";
    ERR_INVALID_DATA_ID = "ERR-06", "El identificador para los datos es invalido";
    ERR_INVALID_DATA = "ERR-07", "Los datos solicitados o enviados son invalidos";
    ERR_MISSING_SERVLET = "ERR-08", "No se ha proporcionado el sevlet para la comunicacion de los datos";
    ERR_INVALID_SERVLET = "ERR-09", "La ruta del servlet es invalida";
    ERR_NOT_SUPPORTED_FORMAT = "ERR-10", "Se ha configurado un formato de firma no soportado";
    ERR_CANCELLED_OPERATION = "ERR-11", "Operacion cancelada";
    ERR_CODING_BASE64 = "ERR-12", "Error en la codificacion del base 64";
    ERR_PKE = "ERR-13", "No se pudo recuperar la clave del certificado";
    ERR_SIGNING = "ERR-14", "Ocurrio un error en la operacion de firma";
    ERR_INVALID_CIPHER_KEY = "ERR-15", "La clave de cifrado proporcionada no es valida";
    ERR_CIPHERING = "ERR-16", "Error durante el proceso de cifrado de los datos";
    ERR_NO_CERT_SELECTED = "ERR-17", "No se selecciono ningun certificado de firma";
    ERR_COMMUNICATING_WITH_WEB = "ERR-18", "Error de comunicacion con el servicio";
    ERR_PKE_ANDROID_4_1 = "ERR-21", "Android 4.1 y 4.1.1 no permiten que los nombres de certificados contengan caracteres especiales (espacios, guiones...). Modifique el alias de sus certificados al importarlos para evitar este error.";
    ERR_BAD_PARAMETERS = "ERR-22", "No se ha realizado correctamente la invocacion de la aplicacion";
    ERR_ESTABLISHING_KEYSTORE = "ERR-23", "No se ha podido establecer un almacen de certificados para su uso";
    ERR_MSC_PIN = "ERR-24", "Error en la firma. Compruebe que el PIN de su dispositivo criptografico es correcto. Varios intentos incorrectos pueden bloquearlo.";
    ERR_SELECTING_CERTIFICATE = "ERR-25", "Ocurrio un error en la seleccion del certificado";
    ERR_SAVING_DATA = "ERR-26", "Error al guardar los datos en el dispositivo";
}

/// Texto que `ErrorManager` usa para un identificador desconocido.
pub const GENERIC_ERROR_TEXT: &str = "Error generico";

/// Categoría de error `AA` (`ErrorCategory`): código, texto de usuario
/// (localizado) y texto de administración (fijo, solo para el registro).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCategory {
    /// Código numérico (sin el prefijo `AA`).
    pub code: u32,
    /// Texto de usuario; `None` = *genérico* (`not_completed_request`).
    pub user_text: Option<UserText>,
    /// Texto de administración.
    pub admin_text: &'static str,
}

impl ErrorCategory {
    /// Texto de usuario en un idioma.
    pub fn user_text(&self, lang: WebLanguage) -> &'static str {
        self.user_text.unwrap_or(UserText::NotCompletedRequest).text(lang)
    }

    /// `getUserMsg`: `AA<código> - <texto de usuario>` (diálogos).
    pub fn user_msg(&self, lang: WebLanguage) -> String {
        format!("AA{} - {}", self.code, self.user_text(lang))
    }

    /// `getAdminMsg`: `AA<código> - <texto de administración>` (registro).
    pub fn admin_msg(&self) -> String {
        format!("AA{} - {}", self.code, self.admin_text)
    }
}

macro_rules! categories {
    ($($name:ident = $code:literal, $user:expr, $admin:literal;)*) => {
        $( pub const $name: ErrorCategory = ErrorCategory { code: $code, user_text: $user, admin_text: $admin }; )*
        /// Categorías del catálogo (§8.1) que intervienen en las operaciones web y
        /// en la firma. Las del DNIe por NFC (3001xx), la importación de
        /// certificados (201100) y los dominios de confianza (200700) solo se
        /// muestran en la interfaz y las gestiona la aplicación.
        pub const CATEGORIES: &[ErrorCategory] = &[$($name),*];
    };
}

categories! {
    AA_RESET_NFC = 102000, None, "Error al resetear la tarjeta NFC";
    AA_SOFTWARE_GENERAL = 200000, None, "Error general de software";
    AA_CANT_SAVE_SIGN_RECORD = 200001, None, "La firma se ha realizado correctamente pero no se ha podido guardar en el histórico de firmas";
    AA_ERROR_SIGNING = 200002, None, "Error durante la firma";
    AA_CYPHERING_SIGN = 200100, None, "Error al cifrar la firma para enviarla al servidor intermedio";
    AA_ENCRYPTING_CERT = 200101, None, "Error al cifrar el certificado para enviarlo al servidor intermedio";
    AA_LOADING_LOCAL_FILE = 200102, None, "Error al cargar el fichero local para realizar la firma";
    AA_OUT_OF_MEMORY = 200105, Some(UserText::FileReadOutOfMemory), "Error de memoria al cargar el fichero";
    AA_USER_SELECT_NOT_PDF = 200106, Some(UserText::NecessaryPdfFile), "El usuario selecciono un documento no PDF sobre el que realizar una firma PAdES";
    AA_PADES_NO_PDF_SIGN = 200107, None, "No es posible hacer firma PAdES sobre datos no PDF";
    AA_CYPHERING_CERT = 200200, None, "Error al cifrar el certificado para enviarlo al servidor intermedio";
    AA_SAVING_DATA_DISK = 200301, None, "No se ha podido guardar el fichero en disco";
    AA_NO_DEVICE_STORE = 200302, None, "No se ha encontrado donde guardar la firma generada";
    AA_CANT_OBTAIN_DATA_FLOW = 200303, Some(UserText::ErrorSavingSignature), "No se pudo obtener el flujo para el guardado de los datos";
    AA_NO_STORAGE_PERMISSIONS = 200304, Some(UserText::ErrorNoStoragePermissions), "No dispone de permisos de escritura";
    AA_SAVING_DATA_OP = 200305, Some(UserText::ErrorSavingData), "Error al guardar datos";
    AA_CYPHERING_SIGN_INFO_TO_SEND = 200400, None, "Error al cifrar la información de las firmas del lote para enviarla al servidor intermedio";
    AA_CYPHERING_CERT_TO_SEND = 200401, None, "Error al cifrar el certificado para enviarlo al sevidor intermedio";
    AA_LOAD_KEYSTORE = 201101, Some(UserText::ErrorLoadingKeystore), "Error al cargar el almacen de certificados";
    AA_ALIAS_NOT_VALID = 201102, Some(UserText::ErrorLoadingCert), "Error al cargar el certificado, posiblemente relacionado por usar un alias de certificado no valido";
    AA_LOAD_KEY = 201103, Some(UserText::ErrorLoadingCert), "Error al cargar la clave del certificado";
    AA_USER_NOT_SELECT_CERT = 201104, Some(UserText::NotSelectedCert), "El usuario no selecciono un certificado";
    AA_UNEXPECTED_RECOVERING_KEY = 201105, Some(UserText::ErrorLoadingCert), "Error inesperado al recuperar la clave del certificado de firma";
    AA_LOAD_CERT = 201106, Some(UserText::ErrorLoadingCert), "Error al cargar certificado";
    AA_HTTP_PRESIGN = 300400, None, "Error HTTP al realizar la operacion de prefirma";
    AA_HTTP_POSTSIGN = 300404, None, "Error HTTP al realizar la operacion de posfirma";
    AA_UNKNOWN_ERROR = 400000, None, "Error desconocido al enviar el error obtenido al servidor";
    AA_COMMUNICATION_WITH_SERVICE = 400001, None, "Error durante la descarga de la configuracion para la seleccion de certificado";
    AA_DOWNLOAD_SIGN = 401100, None, "Error en la descarga de la firma";
    AA_DOWNLOAD_CONFIG_CERT = 401101, None, "Error durante la descarga de la configuracion para la seleccion de certificado";
    AA_UPLOAD_DATA = 401200, None, "Error en el envio de datos";
    AA_CANCELED_BY_USER = 500001, Some(UserText::OperationCancelled), "Operacion cancelada por el usuario";
    AA_NO_CERTIFICATES = 501001, Some(UserText::ErrorDescKeystoreEmpty), "Error en la operacion, no hay certificados";
    AA_NOT_SUPPORTED_OPERATION = 600002, None, "La operacion no esta soportada";
    AA_REQUEST_PARAM_NOT_VALID = 600006, None, "Los parametros de la peticion no eran validos";
    AA_ENCODING_CERT = 600007, None, "Error en la codificacion del certificado";
    AA_INVOCATION_WITHOUT_URL = 600008, None, "Se ha invocado sin URL a la actividad de firma por protocolo";
    AA_NO_DATA_NO_ID = 600100, None, "No se ha recibido los datos en la petición ni el id del fichero a descargar para la operacion de firma";
    AA_FORMAT_NOT_VALID = 600105, None, "El formato de firma no es valido para la operacion de firma";
    AA_CANT_DECODE_DATA = 600108, None, "Los datos de la operacion no se han podido decodificar para la operacion de firma";
    AA_PARAM_NOT_COMPATIBLE_POLICY = 600109, None, "Los parametros configurados son incompatibles con la politica de firma";
    AA_NO_DATA_NO_ID_BATCH = 600400, None, "No se ha recibido los datos en la petición ni el id del fichero a descargar para la operacion de firma de lotes";
    AA_URL_DOWNLOAD_NOT_FOUND_BATCH = 600401, None, "Es necesario descargar la informacion del servidor intermedio, ha llegado el id de fichero pero no ha llegado la url del servidor de descarga para la operacion de firma de lotes";
    AA_BATCHPRESIGNERURL_NOT_FOUND_BATCH = 600405, None, "No se ha recibido el batchpresignerurl en la firma batch";
    AA_BATCHPOSTSIGNERURL_NOT_FOUND_BATCH = 600406, None, "No se ha recibido el batchpostsignerurl en la firma batch";
    AA_JSON_NOT_FORMED_CORRECTLY = 600407, None, "El data de la operacion de firma batch no es un JSON valido";
    AA_ALGORITHM_NOT_FOUND_BATCH = 600408, None, "No se ha recibido el algoritmo de firma en la firma batch";
}

/// `ErrorManager.genError(id, código, mensaje)`: `ERR-NN:=AA<código> - <mensaje>`;
/// sin mensaje, el texto fijo del identificador.
pub fn gen_error(id: ErrorId, code: u32, msg: Option<&str>) -> String {
    format!("{}:=AA{code} - {}", id.id, msg.unwrap_or(id.text))
}

/// `URLEncoder.encode(texto, "UTF-8")`: se conservan `a-z`, `A-Z`, `0-9`, `.`,
/// `-`, `*` y `_`; el espacio pasa a `+`; el resto, a `%HH` (mayúsculas) por
/// cada byte UTF-8.
pub fn java_url_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for &b in text.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Error que se devuelve a la web: identificador `ERR-NN` y categoría `AA`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebError {
    pub id: ErrorId,
    pub category: ErrorCategory,
    /// `true` (todas las operaciones salvo `save`): el mensaje es el texto de
    /// usuario localizado de la categoría. `false` (`save`): el texto fijo de
    /// `ERR-NN`.
    pub localized: bool,
}

impl WebError {
    /// Error con el texto de usuario localizado.
    pub const fn new(id: ErrorId, category: ErrorCategory) -> Self {
        WebError {
            id,
            category,
            localized: true,
        }
    }

    /// Error con el texto fijo del identificador (los de `save`).
    pub const fn fixed(id: ErrorId, category: ErrorCategory) -> Self {
        WebError {
            id,
            category,
            localized: false,
        }
    }

    /// Cancelación (`ERR-11` con AA500001).
    pub const fn cancelled() -> Self {
        WebError::new(ERR_CANCELLED_OPERATION, AA_CANCELED_BY_USER)
    }

    /// Texto del error (`genError`) antes de codificarlo.
    pub fn text(&self, lang: WebLanguage) -> String {
        if self.localized {
            gen_error(self.id, self.category.code, Some(self.category.user_text(lang)))
        } else {
            gen_error(self.id, self.category.code, None)
        }
    }

    /// Texto tal y como se sube al servidor intermedio (`URLEncoder`).
    pub fn upload_text(&self, lang: WebLanguage) -> String {
        java_url_encode(&self.text(lang))
    }

    /// Indica si es una cancelación (`ERR-11`).
    pub fn is_cancellation(&self) -> bool {
        self.id == ERR_CANCELLED_OPERATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_error_format() {
        assert_eq!(
            WebError::cancelled().text(WebLanguage::Es),
            "ERR-11:=AA500001 - Operacion cancelada"
        );
        assert_eq!(
            WebError::fixed(ERR_SAVING_DATA, AA_SAVING_DATA_OP).text(WebLanguage::En),
            "ERR-26:=AA200305 - Error al guardar los datos en el dispositivo"
        );
        assert_eq!(
            WebError::new(ERR_BAD_PARAMETERS, AA_REQUEST_PARAM_NOT_VALID).text(WebLanguage::Es),
            "ERR-22:=AA600006 - Hemos intentado procesar tu solicitud, pero no ha podido ser completada con éxito. \
             Por favor revisa la documentación."
        );
        assert_eq!(
            WebError::new(ERR_CANCELLED_OPERATION, AA_USER_NOT_SELECT_CERT).text(WebLanguage::Ca),
            "ERR-11:=AA201104 - Certificat no seleccionat"
        );
        assert_eq!(
            gen_error(
                ErrorId {
                    id: "ERR-99",
                    text: GENERIC_ERROR_TEXT
                },
                1,
                None
            ),
            "ERR-99:=AA1 - Error generico"
        );
    }

    #[test]
    fn url_encoder() {
        assert_eq!(
            java_url_encode("ERR-11:=AA500001 - Operacion cancelada"),
            "ERR-11%3A%3DAA500001+-+Operacion+cancelada"
        );
        assert_eq!(java_url_encode("éxito ¿?*._~/"), "%C3%A9xito+%C2%BF%3F*._%7E%2F");
        assert_eq!(
            WebError::new(ERR_PKE, AA_LOAD_KEY).upload_text(WebLanguage::Es),
            "ERR-13%3A%3DAA201103+-+Error+al+cargar+el+certificado"
        );
    }

    #[test]
    fn catalogue_is_complete() {
        assert_eq!(CATEGORIES.len(), 47);
        assert_eq!(ALL_ERROR_IDS.len(), 25);
        let mut codes: Vec<u32> = CATEGORIES.iter().map(|c| c.code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), CATEGORIES.len());
        assert_eq!(
            AA_LOAD_KEY.user_msg(WebLanguage::Es),
            "AA201103 - Error al cargar el certificado"
        );
        assert_eq!(AA_UPLOAD_DATA.admin_msg(), "AA401200 - Error en el envio de datos");
    }
}
