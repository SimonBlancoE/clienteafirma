//! Interfaz que implementa la app Android para las operaciones web: elección
//! de almacén y certificado (KeyChain, DNIe por NFC, tarjeta USB), avisos
//! sobre el certificado, selector de ficheros (SAF), vista previa de la firma
//! visible, contraseña de PDF, guardado (SAF) y diálogos.
//!
//! Todos los métodos se llaman desde el hilo de trabajo de la operación (nunca
//! desde el de la interfaz): la implementación debe mostrar el diálogo en el
//! hilo de la interfaz y esperar la respuesta.

use std::sync::Arc;

use afirma_core::{ExtraParams, SigningKey};

use super::errors::ErrorCategory;
use super::request::WebOperation;

/// Para qué se pide el certificado (título de `ChooseCertTypeDialog`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    /// Firma y lotes: «¿Con qué firmarás?».
    Sign,
    /// `selectcert`: «¿Con qué te identificarás?» (modo autenticación).
    Authenticate,
}

/// Petición de certificado (`LoadKeyStoreFragmentActivity.loadKeyStore`).
///
/// La implementación hace todo el recorrido de §4.1: `ChooseCertTypeDialog`
/// si el NFC está habilitado, lector USB, `KeyChain`… Si el usuario cancela el
/// selector de `KeyChain` y el DNIe por NFC es la conexión preferida, debe
/// volver a ofrecer la elección de almacén (también en lotes, a diferencia de
/// Java, §10 n.º 14) y solo devolver [`KeySelectionError::Cancelled`] cuando el
/// usuario cierra la elección.
#[derive(Debug, Clone)]
pub struct KeyRequest<'a> {
    pub operation: WebOperation,
    pub purpose: KeyPurpose,
    /// La firma anterior falló por PIN incorrecto de la tarjeta: con NFC se
    /// vuelve directamente al DNIe indicando «PIN incorrecto» (§4.9.8).
    pub bad_pin_retry: bool,
    /// `appname` declarado por la página (informativo).
    pub app_name: Option<&'a str>,
}

/// Origen de la clave elegida.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySource {
    /// Almacén de Android (`KeyChain`): en firma y lotes se comprueban los
    /// avisos de caducidad y seudónimo.
    SystemKeyStore,
    /// DNIe por NFC: nunca se guarda en la caché de certificado.
    DnieNfc,
    /// Tarjeta por lector USB u otro almacén JCA (sin avisos).
    SmartCard,
}

/// Clave elegida por el usuario.
#[derive(Clone)]
pub struct SelectedKey {
    pub key: Arc<dyn SigningKey>,
    pub source: KeySource,
}

impl std::fmt::Debug for SelectedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedKey")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Error de la elección de almacén o certificado, con la clasificación que
/// usa la app para la respuesta (§5.12 y §6.6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeySelectionError {
    /// El usuario no eligió (selector de tipo cerrado, `KeyChain` sin elegir,
    /// aviso cancelado…). → `ERR-11` (AA500001; AA201104 en `selectcert`).
    #[error("El usuario no selecciono un certificado")]
    Cancelled,
    /// Error al cargar el almacén. Como en Java, la cancelación de
    /// `PinDialog`/`SelectAliasDialog` y un almacén JCA vacío también se
    /// devuelven así (§10 n.º 11). → `ERR-23` AA201101.
    #[error("Error al cargar el almacen de certificados: {0}")]
    KeyStore(String),
    /// Alias de certificado no válido (Android 4.1). → `ERR-21`.
    #[error("Alias de certificado no valido: {0}")]
    InvalidAlias(String),
    /// `KeyChainException` al obtener la clave. → `ERR-13` AA201103.
    #[error("No se pudo extraer la clave privada del certificado: {0}")]
    KeyChain(String),
    /// Otro error al recuperar la clave. → `ERR-13` AA201105 (AA201106 en
    /// `selectcert`).
    #[error("Error al recuperar la clave del certificado: {0}")]
    Other(String),
}

/// Aviso sobre el certificado elegido en `KeyChain` (§4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateWarning {
    /// «Certificado caducado» / «El certificado no es válido, ya que está
    /// caducado.».
    Expired,
    /// Certificado aún no válido. Java lo trataba como error genérico de
    /// selección (§10 n.º 13); aquí es un aviso como el de caducado.
    NotYetValid,
    /// «Certificado próximo a caducar» (menos de 7 días).
    ExpiresSoon,
    /// «Certificado de seudónimo».
    Pseudonym,
}

/// Petición del selector del fichero a firmar (§5.4.3).
#[derive(Debug, Clone)]
pub struct ChooseFileRequest<'a> {
    pub operation: WebOperation,
    /// Formato pedido.
    pub format: &'a str,
    /// Filtro `.pdf` (formato exactamente `PAdES` o `PAdEStri`) del selector
    /// propio de Android < 11.
    pub pdf_only: bool,
}

/// Fichero elegido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenFile {
    /// Nombre (sin ruta); se usa en el histórico.
    pub name: String,
    pub data: Vec<u8>,
}

/// Error del selector de ficheros.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileChoiceError {
    /// Cancelado. → `ERR-11` AA500001.
    #[error("cancelado")]
    Cancelled,
    /// Permiso de almacenamiento denegado (Android < 11). → `ERR-14` AA200002.
    #[error("No se concedieron permisos de acceso a disco")]
    PermissionDenied,
    /// Fichero demasiado grande. Java solo mostraba el diálogo AA200105; aquí
    /// además se responde `ERR-14` AA200105.
    #[error("fichero demasiado grande")]
    TooLarge,
    /// Error de lectura que el usuario no resolvió (Java mostraba un *toast*
    /// y, con `IOException`, reabría el selector: eso lo hace la
    /// implementación). Aquí se responde `ERR-14` AA200102.
    #[error("error al leer el fichero: {0}")]
    Read(String),
}

/// Área de firma visible elegida en la vista previa (coordenadas PDF ya
/// convertidas, §3.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleArea {
    /// Página (base 1).
    pub page: u32,
    pub lower_left_x: i64,
    pub lower_left_y: i64,
    pub upper_right_x: i64,
    pub upper_right_y: i64,
}

/// Petición de la vista previa de firma visible (§5.5).
#[derive(Debug, Clone)]
pub struct VisibleSignatureRequest<'a> {
    /// PDF que se va a firmar. Java solo podía mostrar la vista previa si el
    /// usuario había elegido el fichero en la app (con `dat` se cerraba por
    /// `NullPointerException` y con sobre la ignoraba, §10 n.º 33): aquí
    /// siempre se dan los datos.
    pub data: &'a [u8],
    /// Nombre del fichero si lo eligió el usuario.
    pub file_name: Option<&'a str>,
    /// `visibleSignature=want`: el área es obligatoria.
    pub mandatory: bool,
    pub extra_params: &'a ExtraParams,
}

/// Resultado de la vista previa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisibleSignatureResult {
    /// `RESULT_OK`: contraseña del PDF si se introdujo y área si se eligió
    /// (sin área y `want` → cancelación; sin área y `optional` → firma
    /// invisible).
    Selected {
        owner_password: Option<String>,
        area: Option<VisibleArea>,
    },
    /// `RESULT_CANCELED`. → `ERR-11`.
    Cancelled,
    /// El PDF no se pudo cargar (resultado `106`). → diálogo y `ERR-07`
    /// AA200102.
    LoadError(String),
}

/// Petición de la contraseña de un PDF protegido al firmar (§3.7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfPasswordRequest {
    /// La contraseña anterior era incorrecta («Contraseña incorrecta:»).
    pub bad_password: bool,
}

/// Petición del diálogo de guardado (`save`, SAF `ACTION_CREATE_DOCUMENT`).
#[derive(Debug, Clone)]
pub struct SaveFileRequest<'a> {
    pub data: &'a [u8],
    /// Nombre propuesto: `filename` o `datos.<ext>` (corrección: Java proponía
    /// «datosdatos.<ext>», §10 n.º 49).
    pub proposed_name: String,
    /// `title`, `exts` y `desc` de la petición. Java los ignoraba; se pasan
    /// por si la interfaz los quiere usar (§10 n.º 50).
    pub title: &'a str,
    pub extensions: Option<&'a str>,
    pub description: Option<&'a str>,
}

/// Error del guardado.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SaveFileError {
    /// Cancelado o no guardado. → `ERR-11`.
    #[error("cancelado")]
    Cancelled,
    /// Error al escribir. → diálogo AA200305 y `ERR-26`.
    #[error("error al escribir: {0}")]
    Write(String),
}

/// Diálogo de error («¡Algo salió mal!», `error_ocurred`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDialog {
    pub category: ErrorCategory,
    /// `AA<código> - <texto de usuario>` en el idioma de la app.
    pub message: String,
}

/// Avisos de progreso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgressEvent {
    /// «Cargando almacén de claves» (`selectcert`).
    LoadingKeyStore,
    /// «Firmando» (firma y lotes).
    Signing,
    /// Fin del diálogo de progreso.
    Hide,
}

/// Interfaz de usuario de las operaciones web.
pub trait AndroidWebHandler: Send + Sync {
    /// Elección de almacén y certificado.
    fn select_key(&self, req: &KeyRequest<'_>) -> Result<SelectedKey, KeySelectionError>;

    /// Aviso sobre el certificado elegido en `KeyChain` (botones «Continuar» y
    /// «Cancelar»). `false` vuelve a la elección de almacén. Por defecto,
    /// continuar.
    fn confirm_certificate_warning(&self, _warning: CertificateWarning, _certificate: &[u8]) -> bool {
        true
    }

    /// Elección del fichero a firmar cuando la web no envía datos.
    fn choose_file(&self, req: &ChooseFileRequest<'_>) -> Result<ChosenFile, FileChoiceError>;

    /// Vista previa de la firma visible. Por defecto, cancelada.
    fn visible_signature(&self, _req: &VisibleSignatureRequest<'_>) -> VisibleSignatureResult {
        VisibleSignatureResult::Cancelled
    }

    /// Contraseña de un PDF protegido. `None` = cancelado.
    fn pdf_password(&self, _req: &PdfPasswordRequest) -> Option<String> {
        None
    }

    /// Guardado de los datos de `save`.
    fn save_file(&self, req: &SaveFileRequest<'_>) -> Result<(), SaveFileError>;

    /// Diálogo de error.
    fn show_error(&self, _dialog: &ErrorDialog) {}

    /// Diálogo de progreso.
    fn progress(&self, _event: ProgressEvent) {}
}
