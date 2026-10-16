//! Interfaces que implementa la aplicación.
//!
//! El crate reproduce el flujo completo de cada operación del protocolo
//! (orden de las comprobaciones, códigos de error, firmante persistente,
//! reintentos por PIN erróneo, confirmaciones del usuario, firma trifásica y
//! por lotes, construcción y cifrado de la respuesta) y delega en la
//! aplicación:
//!
//! - [`OperationHandler`]: todo lo que muestra interfaz (selección de
//!   certificado, diálogos de ficheros, confirmaciones, contraseñas, firma
//!   visible PDF, diálogos de error).
//! - [`LocalSigner`]: la firma local con el registro de firmadores
//!   (CAdES, XAdES, PAdES...), la detección de formato `AUTO`, la validación
//!   previa de firmas y la expansión de políticas.

use std::sync::Arc;

use afirma_core::{AfirmaError, CounterSignTarget, ExtraParams, SigningKey};

use crate::errors::ProtocolError;
use crate::request::{KeyStoreParam, OperationKind};
use crate::triphase::CryptoOperation;
use crate::version::ProtocolVersion;

/// Quién hace la petición.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestOrigin {
    /// Página web conectada por WebSocket: cabecera `Origin` del saludo
    /// (`https://sede.ejemplo.gob.es`).
    WebSocket { origin: Option<String> },
    /// Página conectada por el socket de servicio: cabecera `Origin` de la
    /// petición HTTP, si venía.
    ServiceSocket { origin: Option<String> },
    /// Invocación directa por servidor intermedio: host del servicio de
    /// guardado (o de recuperación) usado por la página.
    IntermediateServer { host: Option<String> },
}

impl RequestOrigin {
    /// Texto breve para mostrar al usuario (origen o host; `None` si no se
    /// conoce).
    pub fn display(&self) -> Option<&str> {
        match self {
            RequestOrigin::WebSocket { origin } | RequestOrigin::ServiceSocket { origin } => origin.as_deref(),
            RequestOrigin::IntermediateServer { host } => host.as_deref(),
        }
    }
}

/// Contexto de la petición para que la interfaz pueda mostrar QUÉ se firma
/// y QUIÉN lo pide (ventana "petición desde la web").
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub origin: RequestOrigin,
    /// Operación del protocolo.
    pub operation: OperationKind,
    /// Operación criptográfica (firma, cofirma, contrafirma) si aplica.
    pub crypto_operation: Option<CryptoOperation>,
    /// Formato de firma (ya resuelto si era `AUTO`).
    pub format: Option<String>,
    /// Número de documentos (lotes).
    pub document_count: Option<usize>,
    /// Tamaño de los datos (operaciones de un documento).
    pub data_len: Option<usize>,
    /// Nombre de fichero conocido (elegido por el usuario o indicado en los
    /// parámetros `filenameActualName`/`filename`).
    pub file_name: Option<String>,
    /// Datos a firmar (para mostrar el tipo de documento o una vista previa).
    pub data: Option<Arc<[u8]>>,
    /// `appname` declarado por la página (informativo, no fiable).
    pub app_name: Option<String>,
}

impl RequestInfo {
    pub fn new(origin: RequestOrigin, operation: OperationKind) -> Self {
        RequestInfo {
            origin,
            operation,
            crypto_operation: None,
            format: None,
            document_count: None,
            data_len: None,
            file_name: None,
            data: None,
            app_name: None,
        }
    }
}

/// Petición de selección de certificado (`AOKeyStoreDialog`).
#[derive(Debug, Clone)]
pub struct CertificateRequest<'a> {
    /// Qué se firma y quién lo pide.
    pub info: &'a RequestInfo,
    /// Operación que pide el certificado (determina el código de error si
    /// no hay certificados: 501001, 502001 o 504001).
    pub operation: OperationKind,
    /// Parámetros adicionales: filtros (`filter`, `filters`, `filters.N`,
    /// `disableopeningexternalstores`), `headless` y
    /// `mandatoryCertSelection`.
    pub extra_params: &'a ExtraParams,
    /// Almacén pedido por la web (`keystore`/`ksb64`). La precedencia con
    /// las preferencias (§12.3: último almacén elegido en el proceso,
    /// preferencia "usar el almacén por defecto en las llamadas del
    /// navegador"...) la decide la aplicación.
    pub keystore: Option<&'a KeyStoreParam>,
    /// Tras un PIN erróneo: se debe volver a pedir el certificado
    /// restringiendo la selección a este (DER), de forma obligatoria y con
    /// el almacén recargado.
    pub restrict_to_certificate: Option<&'a [u8]>,
}

/// Petición del diálogo de apertura de un fichero a firmar.
#[derive(Debug, Clone)]
pub struct OpenFileRequest {
    /// Quién lo pide.
    pub info: RequestInfo,
    /// Clave del título: `ProtocolLauncher.25` (firma) o `ProtocolLauncher.26`
    /// (cofirma/contrafirma).
    pub title_key: &'static str,
    /// Título ya localizado.
    pub title: String,
    /// `filenameExts` (lista).
    pub extensions: Option<Vec<String>>,
    /// Descripción del filtro ya compuesta (`filenameDescription` o "Ficheros
    /// de datos", más ` (*.ext,*.ext2)` o ` (*.*)`).
    pub description: String,
    /// `filenameCurrentDir`.
    pub current_dir: Option<String>,
    /// `filenameActualName`.
    pub file_name: Option<String>,
}

/// Fichero elegido o cargado por el usuario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileData {
    /// Nombre del fichero (sin ruta).
    pub name: String,
    pub data: Vec<u8>,
}

/// Petición del diálogo de guardado (`save` y `signandsave`).
#[derive(Debug, Clone)]
pub struct SaveFileRequest<'a> {
    /// Quién lo pide.
    pub info: &'a RequestInfo,
    pub title: String,
    pub data: &'a [u8],
    pub proposed_name: Option<String>,
    /// Extensiones del filtro.
    pub extensions: Option<Vec<String>>,
    pub description: Option<String>,
    pub current_dir: Option<String>,
}

/// Petición del diálogo de carga (`load`).
#[derive(Debug, Clone)]
pub struct LoadRequest {
    /// Quién lo pide.
    pub info: RequestInfo,
    /// Título (`None` = el del sistema).
    pub title: Option<String>,
    pub extensions: Option<Vec<String>>,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub multiple: bool,
}

/// Confirmación pedida por un firmador o por el servidor trifásico
/// (`RuntimeConfigNeededException` de tipo `CONFIRM`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmRequest {
    /// Origen de la petición en curso.
    pub origin: Option<RequestOrigin>,
    /// Clave del mensaje (`signingLts`, `pdfShadowAttackSuspect`...), que la
    /// aplicación busca en sus textos (`SimpleAfirmaMessages`).
    pub requestor_text: String,
    /// Mensaje técnico recibido.
    pub message: String,
}

/// Contraseña pedida (`RuntimeConfigNeededException` de tipo `PASSWORD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRequest {
    /// Origen de la petición en curso.
    pub origin: Option<RequestOrigin>,
    pub requestor_text: String,
    pub message: String,
}

/// Petición del diálogo de posición de la firma visible PDF.
#[derive(Debug, Clone)]
pub struct VisibleSignatureRequest<'a> {
    /// Qué se firma y quién lo pide.
    pub info: &'a RequestInfo,
    pub data: &'a [u8],
    pub extra_params: &'a ExtraParams,
    /// `visibleSignature=want` (obligatoria).
    pub mandatory: bool,
    /// `visibleAppearance=custom`.
    pub custom_appearance: bool,
}

/// Datos de un diálogo de error que Java mostraría.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDialog {
    pub title: String,
    pub message: String,
    pub error: ProtocolError,
    pub version: Option<ProtocolVersion>,
}

/// Interfaz de usuario de las operaciones del protocolo.
///
/// Todos los métodos se llaman desde hilos de trabajo (nunca desde el
/// bucle asíncrono de los servidores). La cancelación del usuario se indica
/// con [`AfirmaError::cancelled`].
pub trait OperationHandler: Send + Sync {
    /// Muestra el diálogo de selección de certificado (o lo resuelve
    /// automáticamente con `headless`/`mandatoryCertSelection=false`) y
    /// devuelve la clave elegida. Si no hay certificados debe devolver un
    /// error con el código 501001 (`CERTIFICATE_NEEDED`); los errores del
    /// almacén con su código o 201101.
    fn select_certificate(&self, req: &CertificateRequest<'_>) -> Result<Arc<dyn SigningKey>, AfirmaError>;

    /// Diálogo para elegir el fichero a firmar cuando la web no envía datos.
    fn choose_file_to_sign(&self, req: &OpenFileRequest) -> Result<FileData, AfirmaError>;

    /// Diálogo para guardar datos (`save` y la firma de `signandsave`).
    fn save_file(&self, req: &SaveFileRequest<'_>) -> Result<(), AfirmaError>;

    /// Diálogo para cargar uno o varios ficheros (`load`).
    fn load_files(&self, req: &LoadRequest) -> Result<Vec<FileData>, AfirmaError>;

    /// Pregunta sí/no al usuario. Por defecto, no.
    fn confirm(&self, _req: &ConfirmRequest) -> bool {
        false
    }

    /// Pide una contraseña. `None` = cancelado.
    fn request_password(&self, _req: &PasswordRequest) -> Option<String> {
        None
    }

    /// Diálogo de área de firma visible PDF. Devuelve los parámetros con la
    /// posición elegida, `Ok(None)` si el usuario lo cancela o si no se
    /// soporta, o un error.
    fn visible_signature(&self, _req: &VisibleSignatureRequest<'_>) -> Result<Option<ExtraParams>, AfirmaError> {
        Ok(None)
    }

    /// Muestra un diálogo de error (Java lo hace para los errores de
    /// parámetros y los inesperados).
    fn show_error(&self, _dialog: &ErrorDialog) {}

    /// Aviso de JavaScript no seguro (`jvc < 1`, `ProtocolLauncher.51/52`).
    fn warn_insecure_javascript(&self) {}

    /// Aviso de progreso (`dlgload`/`headless` deciden si se muestra).
    /// `info` describe la petición en curso.
    fn progress(&self, _event: ProgressEvent, _info: Option<&RequestInfo>) {}
}

/// Eventos de progreso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressEvent {
    /// Comprobando firmas (`ProgressInfoDialog.0`).
    CheckingSignatures,
    /// Cargando el almacén (`ProgressInfoDialog.2`).
    LoadingKeyStore,
    /// Firmando (`ProgressInfoDialog.1`).
    Signing,
    /// Fin de la fase con diálogo.
    Hide,
}

/// Petición de firma local.
#[derive(Clone)]
pub struct LocalSignRequest<'a> {
    pub operation: CryptoOperation,
    /// Formato (ya resuelto si era `AUTO`).
    pub format: &'a str,
    /// Datos o firma (en cofirma y contrafirma).
    pub data: &'a [u8],
    /// Algoritmo compuesto con el tipo de clave (`SHA256withRSA`).
    pub algorithm: &'a str,
    pub key: &'a dyn SigningKey,
    pub extra_params: &'a ExtraParams,
    /// Objetivo de la contrafirma (`tree` o `leafs`).
    pub target: CounterSignTarget,
}

/// Firma local con el registro de firmadores de la aplicación.
pub trait LocalSigner: Send + Sync {
    /// Indica si existe un firmador para el nombre de formato (sin
    /// distinguir mayúsculas). Los formatos trifásicos (`*tri`) los atiende
    /// este crate y no se consultan aquí.
    fn supports_format(&self, format: &str) -> bool;

    /// Firma, cofirma o contrafirma. Errores habituales: confirmación o
    /// contraseña necesarias ([`afirma_core::ErrorKind::NeedsIntervention`]),
    /// PIN erróneo (501003), almacén bloqueado (511003/511004), argumentos
    /// no válidos ([`afirma_core::ErrorKind::InvalidArgument`] → 600121),
    /// operación no soportada ([`afirma_core::ErrorKind::Unsupported`] →
    /// 600002).
    fn sign(&self, req: &LocalSignRequest<'_>) -> Result<Vec<u8>, AfirmaError>;

    /// Formato `AUTO`: en firma PDF→`PAdES`, FacturaE→`FacturaE`,
    /// XML→`XAdES`, otro→`CAdES`; en cofirma/contrafirma el formato de la
    /// firma recibida. `None` si no se identifica (501009).
    fn detect_format(&self, operation: CryptoOperation, data: &[u8]) -> Option<String>;

    /// Validación previa de las firmas existentes (`checkSignatures=true`).
    /// Debe devolver error (con su código o 500002) si no son válidas; en
    /// `sign`, la ausencia de firmas no es un error.
    fn check_signatures(&self, _operation: CryptoOperation, _format: &str, _data: &[u8], _extra: &ExtraParams) -> Result<(), AfirmaError> {
        Ok(())
    }

    /// `ExtraParamsProcessor.expandProperties` (políticas `expPolicy`);
    /// error 501008 si son incompatibles.
    fn expand_extra_params(&self, extra: &ExtraParams, _data: Option<&[u8]>, _format: &str) -> Result<ExtraParams, AfirmaError> {
        Ok(extra.clone())
    }

    /// Nombre propuesto para la firma guardada (`getSignedName`).
    fn signed_file_name(&self, format: &str, original: &str) -> String {
        let _ = format;
        format!("{original}.sig")
    }

    /// Indica si el firmador puede firmar sin datos (`OptionalDataInterface`):
    /// XAdES con `format=XAdES Externally Detached` o `useManifest=true`.
    fn can_sign_without_data(&self, operation: CryptoOperation, format: &str, extra: &ExtraParams) -> bool {
        let f = format.to_ascii_lowercase();
        let xades = f.starts_with("xades") && !f.contains("asic");
        xades
            && operation == CryptoOperation::Sign
            && (extra.get("format") == Some("XAdES Externally Detached") || extra.get_bool("useManifest", false))
    }
}
