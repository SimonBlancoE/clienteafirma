//! Modelo de las peticiones del protocolo y su análisis y validación
//! (`UrlParameters*`), con el mismo orden de comprobación y los mismos
//! códigos de error que AutoFirma.

use std::collections::BTreeMap;

use afirma_core::ExtraParams;
use afirma_core::error::{ErrorCode, codes};

use crate::errors::ProtocolError;
use crate::http::{HttpClient, Method};
use crate::jbase64;
use crate::messages::Locale;
use crate::query::{MalformedEscape, Params, url_decode};
use crate::triphase::CryptoOperation;

/// Longitud máxima de los identificadores de operación.
pub const MAX_ID_LENGTH: usize = 20;

/// Operación pedida en la URL (`afirma://<op>?`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationKind {
    /// `sign`, `cosign` o `countersign` (la operación criptográfica la
    /// decide el parámetro `op`).
    Sign,
    SignAndSave,
    SelectCert,
    Batch,
    Save,
    Load,
}

impl OperationKind {
    /// Código genérico de error de la operación (excepciones no controladas).
    pub fn generic_error(self) -> ErrorCode {
        match self {
            OperationKind::Sign | OperationKind::SignAndSave => codes::UNKNOWN_SIGNING_ERROR,
            OperationKind::SelectCert => codes::UNKNOWN_SELECTING_CERT_ERROR,
            OperationKind::Batch => codes::UNKNOWN_BATCH_ERROR,
            OperationKind::Save => codes::UNKNOWN_SAVING_DATA_ERROR,
            OperationKind::Load => codes::UNKNOWN_LOADING_DATA_ERROR,
        }
    }

    /// Código de error de descarga del sobre del servidor intermedio
    /// (E/S genérica, tiempo de espera).
    pub fn retrieve_errors(self) -> (ErrorCode, ErrorCode) {
        match self {
            OperationKind::Sign => (
                codes::RECIVING_DATA_OF_SIGN_OPERATION,
                codes::RECIVING_DATA_OF_SIGN_TIMEOUT,
            ),
            OperationKind::SelectCert => (
                codes::RECIVING_DATA_OF_CERT_OPERATION,
                codes::RECIVING_DATA_OF_CERT_TIMEOUT,
            ),
            OperationKind::Batch => (
                codes::RECIVING_DATA_OF_BATCH_OPERATION,
                codes::RECIVING_DATA_OF_BATCH_TIMEOUT,
            ),
            OperationKind::Save => (
                codes::RECIVING_DATA_OF_SAVE_OPERATION,
                codes::RECIVING_DATA_OF_SAVE_TIMEOUT,
            ),
            OperationKind::Load => (
                codes::RECIVING_DATA_OF_LOAD_OPERATION,
                codes::RECIVING_DATA_OF_LOAD_TIMEOUT,
            ),
            OperationKind::SignAndSave => (
                codes::RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION,
                codes::RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT,
            ),
        }
    }

    /// Nombre de la operación en el protocolo.
    pub fn name(self) -> &'static str {
        match self {
            OperationKind::Sign => "sign",
            OperationKind::SignAndSave => "signandsave",
            OperationKind::SelectCert => "selectcert",
            OperationKind::Batch => "batch",
            OperationKind::Save => "save",
            OperationKind::Load => "load",
        }
    }
}

/// Resultado del reparto de una URL o mensaje (`ProtocolInvocationLauncher.launch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// `afirma://websocket?`.
    WebSocket,
    /// `afirma://service?`.
    Service,
    Operation(OperationKind),
    /// Esquema no soportado (620009).
    UnsupportedScheme,
    /// Operación desconocida (600002).
    UnsupportedOperation,
}

/// Reparte una URL con las comprobaciones de prefijo exactas de Java (con
/// distinción de mayúsculas y admitiendo `afirma://<op>/?`).
pub fn dispatch(url: &str) -> Dispatch {
    if !url.starts_with("afirma://") && !url.starts_with("getresult?") {
        return Dispatch::UnsupportedScheme;
    }
    let is = |op: &str| url.starts_with(&format!("afirma://{op}?")) || url.starts_with(&format!("afirma://{op}/?"));
    if is("websocket") {
        Dispatch::WebSocket
    } else if is("service") {
        Dispatch::Service
    } else if is("batch") {
        Dispatch::Operation(OperationKind::Batch)
    } else if is("selectcert") {
        Dispatch::Operation(OperationKind::SelectCert)
    } else if is("save") {
        Dispatch::Operation(OperationKind::Save)
    } else if is("signandsave") {
        Dispatch::Operation(OperationKind::SignAndSave)
    } else if is("sign") || is("cosign") || is("countersign") {
        Dispatch::Operation(OperationKind::Sign)
    } else if is("load") {
        Dispatch::Operation(OperationKind::Load)
    } else {
        Dispatch::UnsupportedOperation
    }
}

/// Almacén pedido por la web (`keystore` o `ksb64`): `NOMBRE[:BIBLIOTECA]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStoreParam {
    /// Nombre tal como llega (constante o nombre visible).
    pub name: Option<String>,
    /// Ruta de la biblioteca (PKCS#11...), ya limpiada.
    pub library: Option<String>,
}

impl KeyStoreParam {
    /// Constante del almacén (`WINDOWS`, `MOZ_UNI_WITH_OS`...) según las
    /// reglas de `SimpleKeyStoreManager.getKeyStore(nombre, true)`: primero
    /// el nombre visible (sin distinguir mayúsculas), después la constante
    /// exacta. `MOZ_UNI` se sustituye por `MOZ_UNI_WITH_OS` al invocarse desde
    /// el navegador. Los nombres de tarjetas registradas por el usuario los
    /// resuelve la aplicación.
    pub fn resolved_constant(&self) -> Option<&'static str> {
        let name = self.name.as_deref()?;
        let found = KEYSTORE_NAMES
            .iter()
            .find(|(_, display)| display.eq_ignore_ascii_case(name))
            .or_else(|| KEYSTORE_NAMES.iter().find(|(c, _)| *c == name))
            .map(|(c, _)| *c)?;
        Some(if found == "MOZ_UNI" { "MOZ_UNI_WITH_OS" } else { found })
    }
}

/// Constantes de almacén y sus nombres visibles.
pub const KEYSTORE_NAMES: &[(&str, &str)] = &[
    ("WINDOWS", "Windows"),
    ("APPLE", "Llavero de Mac"),
    ("SHARED_NSS", "NSS"),
    ("PKCS12", "PKCS#12 / PFX"),
    ("JAVA", "Java KeyStore / JKS"),
    ("PKCS11", "PKCS#11"),
    ("SINGLE", "PKCS#7 / X.509"),
    ("MOZ_UNI", "Mozilla / Firefox (unificado)"),
    ("MOZ_UNI_WITH_OS", "Mozilla / Firefox (unificado) junto a almacen de SO"),
    ("JCEKS", "Java Cryptography Extension KeyStore (JCEKS)"),
    ("JAVACE", "Java KeyStore / JKS (Case Exact)"),
    ("TEMD", "TEMD (Tarjeta del Ministerio de Defensa)"),
    (
        "WINADDRESSBOOK",
        "Windows / Internet Explorer (otras personas / libreta de direcciones)",
    ),
    ("WINCA", "Windows / Internet Explorer (CA intermedias)"),
    ("CERES", "Tarjeta FNMT-RCM CERES"),
    ("DNIEJAVA", "DNIe y tarjetas FNMT-TIF"),
    ("KNOWN_SMARTCARDS", "Tarjetas inteligentes conocidas mediante PKCS#11"),
    ("SMARTCAFE", "G&D SmartCafe con Applet PKCS#15"),
    ("CERES_430", "Tarjeta FNMT-RCM CERES 4.30 o superior"),
];

/// Parámetros comunes de todas las operaciones (`setCommonParameters`) y
/// los de identificación/retorno de la operación.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommonParams {
    /// Configuración de cifrado (texto JSON) si se recibió `key`/`cipher`.
    pub cipher_config: Option<Vec<u8>>,
    /// `aw=true`: espera activa (solo en invocación directa).
    pub active_waiting: bool,
    /// `mcv`: versión mínima de AutoFirma exigida.
    pub min_client_version: Option<String>,
    /// `servicetimeout` en milisegundos (si es >= 0).
    pub service_timeout: Option<u32>,
    /// Datos (`dat`) ya obtenidos.
    pub data: Option<Vec<u8>>,
    /// `fileid`: la petición real está en el servidor intermedio.
    pub file_id: Option<String>,
    /// `rtservlet` validado.
    pub retrieve_servlet: Option<String>,
    /// `id` (o `fileid`) validado: nombre del resultado en el servidor intermedio.
    pub id: Option<String>,
    /// `stservlet` validado.
    pub storage_servlet: Option<String>,
    /// `ver` (por defecto `"0"`).
    pub requested_version: String,
}

/// Petición de firma, cofirma o contrafirma (también `signandsave`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignParams {
    pub common: CommonParams,
    /// Operación criptográfica (`op` o, en `signandsave`, `cop`). `None` si
    /// falta o no es válida (Java falla después con 200115).
    pub operation: Option<CryptoOperation>,
    pub format: String,
    pub algorithm: String,
    pub extra_params: ExtraParams,
    pub sticky: bool,
    pub reset_sticky: bool,
    pub keystore: Option<KeyStoreParam>,
    pub app_name: Option<String>,
    /// `signandsave`: nombre de fichero propuesto.
    pub filename: Option<String>,
    /// Parámetros desconocidos (solo `sign`), que Java pasa a los plugins.
    pub other_params: BTreeMap<String, String>,
}

/// Petición de selección de certificado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectCertParams {
    pub common: CommonParams,
    pub extra_params: ExtraParams,
    pub sticky: bool,
    pub reset_sticky: bool,
    pub keystore: Option<KeyStoreParam>,
}

/// Petición de firma por lotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchParams {
    pub common: CommonParams,
    pub app_name: Option<String>,
    pub local_batch_process: bool,
    pub presigner_url: Option<String>,
    pub postsigner_url: Option<String>,
    pub extra_params: ExtraParams,
    pub sticky: bool,
    pub reset_sticky: bool,
    pub need_cert: bool,
    pub json_batch: bool,
    pub keystore: Option<KeyStoreParam>,
}

/// Petición de guardado de datos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveParams {
    pub common: CommonParams,
    pub title: String,
    pub filename: Option<String>,
    pub extensions: Option<String>,
    pub description: Option<String>,
}

/// Petición de carga de ficheros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadParams {
    pub common: CommonParams,
    pub multiload: bool,
    pub title: Option<String>,
    pub extensions: Option<String>,
    pub description: Option<String>,
    pub file_path: Option<String>,
}

/// Petición ya analizada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Sign(SignParams),
    SignAndSave(SignParams),
    SelectCert(SelectCertParams),
    Batch(BatchParams),
    Save(SaveParams),
    Load(LoadParams),
}

impl Request {
    pub fn common(&self) -> &CommonParams {
        match self {
            Request::Sign(p) | Request::SignAndSave(p) => &p.common,
            Request::SelectCert(p) => &p.common,
            Request::Batch(p) => &p.common,
            Request::Save(p) => &p.common,
            Request::Load(p) => &p.common,
        }
    }

    pub fn kind(&self) -> OperationKind {
        match self {
            Request::Sign(_) => OperationKind::Sign,
            Request::SignAndSave(_) => OperationKind::SignAndSave,
            Request::SelectCert(_) => OperationKind::SelectCert,
            Request::Batch(_) => OperationKind::Batch,
            Request::Save(_) => OperationKind::Save,
            Request::Load(_) => OperationKind::Load,
        }
    }
}

/// Canal por el que se puede devolver un error al servidor intermedio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyChannel {
    pub id: String,
    pub storage_servlet: String,
}

/// Fallo del análisis: el error y, si ya se habían validado `id` y
/// `stservlet`, el canal para devolverlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure {
    pub error: ProtocolError,
    pub reply: Option<ReplyChannel>,
}

/// Contexto del análisis.
#[derive(Clone, Copy)]
pub struct ParseContext<'a> {
    /// `true` en invocación directa (servidor intermedio): se valida y
    /// exige `stservlet`.
    pub services_required: bool,
    /// Cliente para descargar `dat` cuando es una URL.
    pub http: &'a HttpClient,
    pub locale: Locale,
}

/// Error de validación de una URL de servicio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    /// La URL apunta al propio equipo.
    Local,
    /// URL mal formada, protocolo no soportado o con parámetros.
    Invalid(String),
}

/// Comprueba si un host es el propio equipo. Java solo bloqueaba
/// `localhost` y `127.0.0.1` exactos; aquí se bloquea cualquier variante de
/// bucle local (desviación de seguridad documentada).
pub fn is_loopback_host(host: &str) -> bool {
    let h = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h == "localhost"
        || h.ends_with(".localhost")
        || h == "0.0.0.0"
        || h == "::"
        || h == "::1"
        || h == "0:0:0:0:0:0:0:1"
    {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
            }
        };
    }
    false
}

/// `UrlParameters.validateURL`: decodifica de nuevo, exige `http`/`https`,
/// rechaza los hosts locales y las URL con `?` o `=`. Devuelve la URL
/// decodificada.
pub fn validate_url(value: &str) -> Result<String, UrlError> {
    let decoded = url_decode(value).map_err(|e| {
        UrlError::Invalid(format!(
            "La URL proporcionada para el servlet no es valida ({value}): {e}"
        ))
    })?;
    let invalid = |m: &str| {
        UrlError::Invalid(format!(
            "La URL proporcionada para el servlet no es valida ({value}): {m}"
        ))
    };
    let colon = decoded.find(':').ok_or_else(|| invalid("no protocol"))?;
    let scheme = &decoded[..colon];
    if !scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return Err(invalid("no protocol"));
    }
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ftp" | "file" | "jar" | "mailto") {
        return Err(invalid(&format!("unknown protocol: {scheme}")));
    }
    if scheme != "http" && scheme != "https" {
        return Err(UrlError::Invalid(format!(
            "El protocolo de la URL proporcionada para el servlet no esta soportado: {scheme}"
        )));
    }
    if !decoded[colon..].starts_with("://") {
        return Err(invalid("falta la autoridad"));
    }
    let host = crate::http::host_of(&decoded).unwrap_or_default();
    if host.is_empty() {
        return Err(invalid("falta el host"));
    }
    if is_loopback_host(&host) {
        return Err(UrlError::Local);
    }
    if decoded.contains('?') || decoded.contains('=') {
        return Err(UrlError::Invalid(
            "Se han encontrado parametros en la URL del servlet".into(),
        ));
    }
    Ok(decoded)
}

/// Comprueba un identificador de operación: como mucho 20 caracteres
/// (UTF-16) y, en minúsculas, solo `a-z0-9`.
pub fn is_valid_operation_id(id: &str) -> bool {
    id.encode_utf16().count() <= MAX_ID_LENGTH
        && id
            .chars()
            .flat_map(char::to_lowercase)
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// Clave DES válida (`verifyDESCipherKey`): `None` si falta o está vacía.
fn verify_des_key(p: &Params) -> Result<Option<String>, ParseFailure> {
    let Some(key) = p
        .get_base64("key")
        .map_err(|e| unexpected_escape(e, OperationKind::Sign))?
    else {
        return Ok(None);
    };
    if key.is_empty() {
        return Ok(None);
    }
    if key.encode_utf16().count() != 8 {
        return Err(param_err(
            codes::UNSUPPORTED_CIPHER_KEY,
            "La longitud de la clave de cifrado no es correcta",
        ));
    }
    Ok(Some(key))
}

fn param_err(code: ErrorCode, msg: impl Into<String>) -> ParseFailure {
    ParseFailure {
        error: ProtocolError::parameter(code, msg),
        reply: None,
    }
}

fn unexpected_escape(e: MalformedEscape, kind: OperationKind) -> ParseFailure {
    ParseFailure {
        error: ProtocolError::unexpected(kind.generic_error(), e.to_string()),
        reply: None,
    }
}

/// Lector de parámetros con el código genérico de la operación para los
/// escapes mal formados.
struct Reader<'a> {
    p: &'a Params,
    kind: OperationKind,
}

impl Reader<'_> {
    fn get(&self, key: &str) -> Result<Option<String>, ParseFailure> {
        self.p.get(key).map_err(|e| unexpected_escape(e, self.kind))
    }

    fn get_b64(&self, key: &str) -> Result<Option<String>, ParseFailure> {
        self.p.get_base64(key).map_err(|e| unexpected_escape(e, self.kind))
    }

    fn contains(&self, key: &str) -> bool {
        self.p.contains(key)
    }

    fn bool(&self, key: &str) -> Result<bool, ParseFailure> {
        Ok(self.get(key)?.is_some_and(|v| v.eq_ignore_ascii_case("true")))
    }
}

/// `DataDownloader.downloadData(dat, gzip)`.
pub fn download_data(dat: &str, gzip: bool, http: &HttpClient) -> Result<Vec<u8>, String> {
    if gzip && jbase64::is_base64(dat) {
        let compressed = jbase64::decode_normalized(dat).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        use std::io::Read;
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .map_err(|e| e.to_string())?;
        return Ok(out);
    }
    let s = crate::triphase::data::java_trim(dat);
    if s.starts_with("http://") || s.starts_with("https://") {
        return http
            .with_ssl_error_handling(afirma_core::http::SslErrorHandling::Interactive { headless: false })
            .read_url(s, Method::Get)
            .map_err(|e| e.to_string());
    }
    if s.starts_with("ftp://") {
        return Err("No se soporta la descarga de datos por FTP".into());
    }
    if jbase64::is_base64(s)
        && let Ok(v) = jbase64::decode_normalized(s)
    {
        return Ok(v);
    }
    Ok(s.as_bytes().to_vec())
}

fn keystore_param(r: &Reader<'_>) -> Result<Option<KeyStoreParam>, ParseFailure> {
    let value = if let Some(v) = r.get("keystore")? {
        Some(v)
    } else if let Some(b) = r.get_b64("ksb64")? {
        // Java usa el decodificador estándar sin normalizar, por lo que un
        // valor URL-safe con '-' o '_' se descartaba; aquí se normaliza.
        jbase64::decode_normalized(&b)
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    } else {
        None
    };
    let Some(v) = value else { return Ok(None) };
    let (name, library) = match v.find(':') {
        None => (Some(v.clone()), None),
        Some(i) => {
            let name = if v.chars().count() > 1 {
                Some(v[..i].trim().to_string())
            } else {
                None
            };
            let lib = if i < v.len() - 1 {
                let cleaned = v[i + 1..].trim().replace(['"', '\''], "");
                std::path::absolute(&cleaned)
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
            } else {
                None
            };
            (name, lib)
        }
    };
    if name.is_none() && library.is_none() {
        return Ok(None);
    }
    Ok(Some(KeyStoreParam { name, library }))
}

fn extra_params(r: &Reader<'_>) -> Result<ExtraParams, ParseFailure> {
    Ok(match r.get_b64("properties")? {
        Some(p) if !p.is_empty() => crate::properties::load_base64(&p).unwrap_or_default(),
        _ => ExtraParams::new(),
    })
}

/// `setCommonParameters`.
fn parse_common(r: &Reader<'_>, ctx: &ParseContext<'_>) -> Result<CommonParams, ParseFailure> {
    let mut c = CommonParams {
        requested_version: "0".into(),
        ..Default::default()
    };
    if let Some(cipher) = r.get_b64("cipher")? {
        let decoded = match jbase64::decode_normalized(&cipher) {
            Ok(v) => v,
            Err(jbase64::Base64Error::TooShort(n)) => {
                return Err(ParseFailure {
                    error: ProtocolError::unexpected(r.kind.generic_error(), format!("Base64 de longitud {n}")),
                    reply: None,
                });
            }
            Err(_) => {
                return Err(param_err(
                    codes::UNSUPPORTED_CIPHER_KEY,
                    "El JSON para la clave de cifrado no esta formado correctamente",
                ));
            }
        };
        let mut config = decoded;
        if r.contains("key")
            && let Some(des) = verify_des_key(r.p)?
        {
            config = crate::cipher::add_legacy_des(&config, &des);
        }
        c.cipher_config = Some(config);
    } else if r.contains("key")
        && let Some(des) = verify_des_key(r.p)?
    {
        c.cipher_config = Some(crate::cipher::des_config(&des));
    }
    c.active_waiting = r.bool("aw")?;
    c.min_client_version = r.get("mcv")?;
    if let Some(t) = r.get("servicetimeout")? {
        match crate::version::java_parse_int(&t) {
            Some(v) if v >= 0 => c.service_timeout = Some(v as u32),
            Some(_) => {}
            None => {
                return Err(param_err(
                    codes::UNSUPPORTED_CIPHER_KEY,
                    "El valor del parametro del tiempo de espera de lectura de los servicios no es valido",
                ));
            }
        }
    }
    if !r.contains("dat") {
        if r.contains("fileid") {
            c.file_id = r.get("fileid")?;
            let Some(rt) = r.get("rtservlet")? else {
                return Err(param_err(
                    codes::RETRIEVE_URL_TO_SIGN_NOT_FOUND,
                    "No se ha recibido la direccion del servlet para la recuperacion de los datos a firmar",
                ));
            };
            c.retrieve_servlet = Some(validate_url(&rt).map_err(|e| match e {
                UrlError::Local => param_err(
                    codes::LOCAL_RETRIEVE_URL,
                    "La URL del servicio de recuperacion de datos no puede ser local",
                ),
                UrlError::Invalid(m) => param_err(
                    codes::INVALID_RETRIEVE_URL_TO_SIGN,
                    format!("Error al validar la URL del servlet de recuperacion: {m}"),
                ),
            })?);
        }
    } else {
        let dat =
            r.p.get_data("dat")
                .map_err(|e| unexpected_escape(e, r.kind))?
                .unwrap_or_default();
        // Java solo comprobaba el prefijo exacto antes de recortar, de modo
        // que " file:/..." acababa leyendo el fichero local. Aquí se rechaza
        // cualquier variante (desviación de seguridad documentada).
        let trimmed = crate::triphase::data::java_trim(&dat);
        if dat.starts_with("file:/") || trimmed.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("file:")) {
            return Err(param_err(
                codes::RETRIEVE_URL_TO_SIGN_CANT_BE_LOCAL,
                format!("No se permite la lectura de ficheros locales: {dat}"),
            ));
        }
        let gzip = r.bool("gzip")?;
        c.data = Some(download_data(&dat, gzip, ctx.http).map_err(|e| {
            param_err(
                codes::LOADING_LOCAL_FILE_ERROR,
                format!("No se han podido obtener los datos: {e}"),
            )
        })?);
    }
    Ok(c)
}

/// Valida `id` (o `fileid`) con el código de la operación.
fn parse_id(r: &Reader<'_>, c: &mut CommonParams, code: ErrorCode) -> Result<(), ParseFailure> {
    let id = if r.contains("id") {
        r.get("id")?
    } else {
        r.get("fileid")?
    };
    if let Some(id) = id {
        if !is_valid_operation_id(&id) {
            return Err(param_err(code, "El identificador de la operacion no es valido"));
        }
        c.id = Some(id);
    }
    Ok(())
}

/// Valida `stservlet` en invocación directa (códigos 6004xx de lotes, como
/// Java para todas las operaciones).
fn parse_storage(r: &Reader<'_>, c: &mut CommonParams, ctx: &ParseContext<'_>) -> Result<(), ParseFailure> {
    if !ctx.services_required {
        return Ok(());
    }
    if let Some(st) = r.get("stservlet")? {
        let url = validate_url(&st).map_err(|e| match e {
            UrlError::Local => param_err(
                codes::LOCAL_STORAGE_URL_TO_SIGN_BATCH,
                "La URL del servicio de guardado no puede ser local",
            ),
            UrlError::Invalid(m) => param_err(
                codes::INVALID_STORAGE_URL_TO_SIGN_BATCH,
                format!("Error al validar la URL del servicio de guardado: {m}"),
            ),
        })?;
        c.storage_servlet = Some(url);
    } else if r.contains("id") {
        return Err(param_err(
            codes::STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND,
            "No se ha recibido la direccion del servlet para el guardado del resultado de la operacion",
        ));
    }
    Ok(())
}

fn reply_of(c: &CommonParams) -> Option<ReplyChannel> {
    Some(ReplyChannel {
        id: c.id.clone()?,
        storage_servlet: c.storage_servlet.clone()?,
    })
}

const SIGN_ALGORITHMS: &[&str] = &[
    "SHA1",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA1withRSA",
    "SHA256withRSA",
    "SHA384withRSA",
    "SHA512withRSA",
    "SHA1withECDSA",
    "SHA256withECDSA",
    "SHA384withECDSA",
    "SHA512withECDSA",
];
const SIGN_AND_SAVE_ALGORITHMS: &[&str] = &[
    "SHA1",
    "SHA256",
    "SHA384",
    "SHA512",
    "SHA1withRSA",
    "SHA256withRSA",
    "SHA384withRSA",
    "SHA512withRSA",
];
const SIGN_KNOWN_PARAMS: &[&str] = &[
    "format",
    "algorithm",
    "id",
    "ver",
    "sticky",
    "resetsticky",
    "properties",
    "dat",
    "gzip",
    "rtservlet",
    "stservlet",
    "key",
    "fileid",
    "keystore",
    "ksb64",
    "aw",
    "mcv",
    "appname",
];
const INVALID_FILENAME_CHARS: &str = "\\/:*?\"<>|";

fn parse_sign(r: &Reader<'_>, ctx: &ParseContext<'_>, and_save: bool) -> Result<SignParams, ParseFailure> {
    let mut common = parse_common(r, ctx)?;
    parse_id(r, &mut common, codes::INVALID_SESSION_ID_TO_SIGN)?;
    common.requested_version = r.get("ver")?.unwrap_or_else(|| "0".into());
    let app_name = if and_save {
        None
    } else {
        match r.get("appname")? {
            Some(a) => Some(url_decode(&a).map_err(|e| unexpected_escape(e, r.kind))?),
            None => None,
        }
    };
    let operation = r
        .get(if and_save { "cop" } else { "op" })?
        .and_then(|o| CryptoOperation::parse(&o));
    let mut sp = SignParams {
        common,
        operation,
        format: String::new(),
        algorithm: String::new(),
        extra_params: ExtraParams::new(),
        sticky: false,
        reset_sticky: false,
        keystore: None,
        app_name,
        filename: None,
        other_params: BTreeMap::new(),
    };
    if sp.common.file_id.is_some() {
        return Ok(sp);
    }
    parse_storage(r, &mut sp.common, ctx)?;
    let reply = reply_of(&sp.common);
    let fail = |code: ErrorCode, msg: &str| ParseFailure {
        error: ProtocolError::parameter(code, msg),
        reply: reply.clone(),
    };
    sp.format = r.get("format")?.ok_or_else(|| {
        fail(
            codes::SIGNATURE_FORMAT_NOT_FOUND,
            "No se ha recibido el formato de firma",
        )
    })?;
    let algo = r.get("algorithm")?.ok_or_else(|| {
        fail(
            codes::SIGNATURE_ALGORITHM_NOT_FOUND,
            "No se ha recibido el algoritmo de firma",
        )
    })?;
    let allowed = if and_save {
        SIGN_AND_SAVE_ALGORITHMS
    } else {
        SIGN_ALGORITHMS
    };
    if !allowed.contains(&algo.as_str()) {
        return Err(fail(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            &format!("Algoritmo de firma no soportado: {algo}"),
        ));
    }
    sp.algorithm = algo;
    sp.extra_params = extra_params(r)?;
    sp.sticky = r.bool("sticky")?;
    sp.reset_sticky = r.bool("resetsticky")?;
    sp.keystore = keystore_param(r)?;
    if and_save {
        if let Some(f) = r.get("filename")? {
            if let Some(c) = f.chars().find(|c| INVALID_FILENAME_CHARS.contains(*c)) {
                return Err(fail(
                    codes::FILENAME_TO_SAVE_NOT_FOUND,
                    &format!("Se ha indicado un nombre de fichero con el caracter invalido: {c}"),
                ));
            }
            sp.filename = Some(f);
        }
    } else {
        for k in r.p.keys() {
            if !SIGN_KNOWN_PARAMS.contains(&k)
                && let Ok(Some(v)) = r.p.get(k)
            {
                sp.other_params.insert(k.to_string(), v);
            }
        }
    }
    Ok(sp)
}

fn parse_select_cert(r: &Reader<'_>, ctx: &ParseContext<'_>) -> Result<SelectCertParams, ParseFailure> {
    let mut common = parse_common(r, ctx)?;
    parse_id(r, &mut common, codes::INVALID_SESSION_ID_TO_SELECT_CERT)?;
    common.requested_version = r.get("ver")?.unwrap_or_else(|| "0".into());
    let mut p = SelectCertParams {
        common,
        extra_params: ExtraParams::new(),
        sticky: false,
        reset_sticky: false,
        keystore: None,
    };
    if p.common.file_id.is_some() {
        return Ok(p);
    }
    parse_storage(r, &mut p.common, ctx)?;
    p.extra_params = extra_params(r)?;
    p.sticky = r.bool("sticky")?;
    p.reset_sticky = r.bool("resetsticky")?;
    p.keystore = keystore_param(r)?;
    Ok(p)
}

fn parse_batch(r: &Reader<'_>, ctx: &ParseContext<'_>) -> Result<BatchParams, ParseFailure> {
    let mut common = parse_common(r, ctx)?;
    parse_id(r, &mut common, codes::INVALID_SESSION_ID_TO_SIGN_BATCH)?;
    common.requested_version = r.get("ver")?.unwrap_or_else(|| "0".into());
    let app_name = match r.get("appname")? {
        Some(a) => Some(url_decode(&a).map_err(|e| unexpected_escape(e, r.kind))?),
        None => None,
    };
    let mut p = BatchParams {
        common,
        app_name,
        local_batch_process: false,
        presigner_url: None,
        postsigner_url: None,
        extra_params: ExtraParams::new(),
        sticky: false,
        reset_sticky: false,
        need_cert: false,
        json_batch: false,
        keystore: None,
    };
    if p.common.file_id.is_some() {
        return Ok(p);
    }
    p.local_batch_process = r.bool("localBatchProcess")?;
    if !p.local_batch_process {
        let post = r.get("batchpostsignerurl")?.ok_or_else(|| {
            param_err(
                codes::POSTSIGN_BATCH_URL_NOT_FOUND,
                "No se ha recibido la URL del postprocesador de lotes",
            )
        })?;
        let pre = r.get("batchpresignerurl")?.ok_or_else(|| {
            param_err(
                codes::PRESIGN_BATCH_URL_NOT_FOUND,
                "No se ha recibido la URL del preprocesador de lotes",
            )
        })?;
        p.postsigner_url = Some(validate_url(&post).map_err(|e| match e {
            UrlError::Local => param_err(
                codes::LOCAL_POSTSIGN_BATCH_URL,
                "La URL del servicio de postfirma de lote no puede ser local",
            ),
            UrlError::Invalid(m) => param_err(
                codes::INVALID_POSTSIGN_BATCH_URL,
                format!("Error al validar la URL de postfirma de lote: {m}"),
            ),
        })?);
        p.presigner_url = Some(validate_url(&pre).map_err(|e| match e {
            UrlError::Local => param_err(
                codes::LOCAL_PRESIGN_BATCH_URL,
                "La URL del servicio de prefirma de lote no puede ser local",
            ),
            UrlError::Invalid(m) => param_err(
                codes::INVALID_PRESIGN_BATCH_URL,
                format!("Error al validar la URL de prefirma de lote: {m}"),
            ),
        })?);
    }
    parse_storage(r, &mut p.common, ctx)?;
    p.extra_params = extra_params(r)?;
    p.sticky = r.bool("sticky")?;
    p.reset_sticky = r.bool("resetsticky")?;
    p.need_cert = r.bool("needcert")?;
    p.json_batch = r.bool("jsonbatch")?;
    p.keystore = keystore_param(r)?;
    Ok(p)
}

/// Título por defecto del diálogo de guardado (`ProtocolInvocationUriParser.1`).
pub fn default_save_title(locale: Locale) -> &'static str {
    match locale {
        Locale::Es | Locale::Gl => "Guardar fichero",
        Locale::En => "Save file",
        Locale::Ca | Locale::Va => "Guardar fitxer",
        Locale::Eu => "Gorde fitxategia",
    }
}

fn parse_save(r: &Reader<'_>, ctx: &ParseContext<'_>) -> Result<SaveParams, ParseFailure> {
    let mut common = parse_common(r, ctx)?;
    if !r.contains("fileid") && !r.contains("dat") {
        return Err(param_err(
            codes::DATA_TO_SAVE_NOT_FOUND,
            "No se ha proporcionado el identificador de fichero ni los datos a guardar",
        ));
    }
    parse_id(r, &mut common, codes::INVALID_SESSION_ID_TO_SAVE)?;
    common.requested_version = r.get("ver")?.unwrap_or_else(|| "0".into());
    parse_storage(r, &mut common, ctx)?;
    let reply = reply_of(&common);
    let fail = |code: ErrorCode, msg: String| ParseFailure {
        error: ProtocolError::parameter(code, msg),
        reply: reply.clone(),
    };
    let title = r
        .get("title")?
        .unwrap_or_else(|| default_save_title(ctx.locale).to_string());
    let filename = r.get("filename")?;
    if let Some(f) = &filename
        && let Some(c) = f.chars().find(|c| INVALID_FILENAME_CHARS.contains(*c))
    {
        return Err(fail(
            codes::FILENAME_TO_SAVE_NOT_FOUND,
            format!("Se ha indicado un nombre de fichero con el caracter invalido: {c}"),
        ));
    }
    let extensions = r.get("exts")?;
    if let Some(e) = &extensions
        && let Some(c) = e.chars().find(|c| "\\/:*?\"<>|; ".contains(*c))
    {
        return Err(fail(
            codes::FILE_EXTENSION_TO_SAVE_NOT_FOUND,
            format!("Se ha indicado una lista de extensiones de nombre de fichero con caracteres invalidos: {c}"),
        ));
    }
    let description = r.get("desc")?.map(|d| match &extensions {
        Some(exts) if !d.ends_with(')') => {
            let mut s = format!("{d} (");
            for ext in exts.split(',') {
                s.push_str("*.");
                s.push_str(ext);
            }
            s.push(')');
            s
        }
        _ => d,
    });
    Ok(SaveParams {
        common,
        title,
        filename,
        extensions,
        description,
    })
}

fn parse_load(r: &Reader<'_>, ctx: &ParseContext<'_>) -> Result<LoadParams, ParseFailure> {
    let mut common = parse_common(r, ctx)?;
    common.requested_version = r.get("ver")?.unwrap_or_else(|| "0".into());
    Ok(LoadParams {
        common,
        multiload: r.bool("multiload")?,
        title: r.get("title")?,
        extensions: r.get("exts")?,
        description: r.get("desc")?,
        file_path: r.get("filePath")?.filter(|p| !p.is_empty()),
    })
}

/// Analiza y valida los parámetros de una operación.
pub fn parse_request(kind: OperationKind, params: &Params, ctx: &ParseContext<'_>) -> Result<Request, ParseFailure> {
    let r = Reader { p: params, kind };
    Ok(match kind {
        OperationKind::Sign => Request::Sign(parse_sign(&r, ctx, false)?),
        OperationKind::SignAndSave => Request::SignAndSave(parse_sign(&r, ctx, true)?),
        OperationKind::SelectCert => Request::SelectCert(parse_select_cert(&r, ctx)?),
        OperationKind::Batch => Request::Batch(parse_batch(&r, ctx)?),
        OperationKind::Save => Request::Save(parse_save(&r, ctx)?),
        OperationKind::Load => Request::Load(parse_load(&r, ctx)?),
    })
}

/// Para las mejoras de notificación de errores: id y servlet de guardado
/// de la URL sin el resto de validaciones de la operación (solo si ambos
/// son válidos). Se usa `rid` cuando no hay `id` (sobres por `fileid`).
pub fn reply_channel_hint(params: &Params) -> Option<ReplyChannel> {
    let id = match params.get("id").ok()? {
        Some(id) => id,
        None => params.get("rid").ok()??,
    };
    if id.is_empty() || !is_valid_operation_id(&id) {
        return None;
    }
    let st = validate_url(&params.get("stservlet").ok()??).ok()?;
    Some(ReplyChannel {
        id,
        storage_servlet: st,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{MockTransport, ok};
    fn http() -> HttpClient {
        HttpClient::new(MockTransport::new(|r| {
            if r.url.contains("doc") {
                ok("REMOTO")
            } else {
                crate::http::testing::status(404)
            }
        }))
    }

    fn parse(url: &str, direct: bool) -> Result<Request, ParseFailure> {
        let h = http();
        let ctx = ParseContext {
            services_required: direct,
            http: &h,
            locale: Locale::Es,
        };
        let kind = match dispatch(url) {
            Dispatch::Operation(k) => k,
            other => panic!("{other:?}"),
        };
        parse_request(kind, &Params::from_query(url), &ctx)
    }

    fn code(url: &str, direct: bool) -> u32 {
        parse(url, direct).unwrap_err().error.code.code
    }

    #[test]
    fn dispatching() {
        assert_eq!(dispatch("afirma://websocket?v=4"), Dispatch::WebSocket);
        assert_eq!(dispatch("afirma://service/?v=4"), Dispatch::Service);
        assert_eq!(
            dispatch("afirma://sign?op=sign"),
            Dispatch::Operation(OperationKind::Sign)
        );
        assert_eq!(
            dispatch("afirma://countersign/?op=x"),
            Dispatch::Operation(OperationKind::Sign)
        );
        assert_eq!(
            dispatch("afirma://signandsave?x"),
            Dispatch::Operation(OperationKind::SignAndSave)
        );
        assert_eq!(dispatch("afirma://SIGN?op=sign"), Dispatch::UnsupportedOperation);
        assert_eq!(dispatch("afirma://sign"), Dispatch::UnsupportedOperation);
        assert_eq!(dispatch("AFIRMA://sign?x"), Dispatch::UnsupportedScheme);
        assert_eq!(dispatch("getresult?idsession=x"), Dispatch::UnsupportedOperation);
        assert_eq!(dispatch("http://x"), Dispatch::UnsupportedScheme);
        assert_eq!(dispatch("afirma://getversion?x"), Dispatch::UnsupportedOperation);
    }

    #[test]
    fn url_validation() {
        assert_eq!(
            validate_url("https://s.gob.es/afirma-signature-storage/StorageService").unwrap(),
            "https://s.gob.es/afirma-signature-storage/StorageService"
        );
        assert_eq!(
            validate_url("https%3A%2F%2Fs.gob.es%2FSt").unwrap(),
            "https://s.gob.es/St"
        );
        assert_eq!(validate_url("http://localhost/x"), Err(UrlError::Local));
        assert_eq!(validate_url("http://127.0.0.1:8080/x"), Err(UrlError::Local));
        assert_eq!(validate_url("http://LOCALHOST/x"), Err(UrlError::Local));
        assert_eq!(validate_url("http://127.0.0.2/x"), Err(UrlError::Local));
        assert_eq!(validate_url("http://[::1]:80/x"), Err(UrlError::Local));
        assert!(matches!(validate_url("ftp://s/x"), Err(UrlError::Invalid(_))));
        assert!(matches!(validate_url("https://s/x?op=1"), Err(UrlError::Invalid(_))));
        assert!(matches!(validate_url("https://s/x=1"), Err(UrlError::Invalid(_))));
        assert!(matches!(validate_url("nada"), Err(UrlError::Invalid(_))));
        assert!(matches!(validate_url("%zz"), Err(UrlError::Invalid(_))));
    }

    #[test]
    fn ids() {
        assert!(is_valid_operation_id(""));
        assert!(is_valid_operation_id("Q3k9aZ0bT1cL2mN4pX7r"));
        assert!(!is_valid_operation_id("Q3k9aZ0bT1cL2mN4pX7rX"));
        assert!(!is_valid_operation_id("a-b"));
        assert!(!is_valid_operation_id("añ"));
    }

    #[test]
    fn sign_param_order_and_codes() {
        let base = "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=SG9sYQ==";
        let Request::Sign(p) = parse(base, false).unwrap() else {
            panic!()
        };
        assert_eq!(p.common.data.as_deref(), Some(&b"Hola"[..]));
        assert_eq!(p.operation, Some(CryptoOperation::Sign));
        assert_eq!(p.common.requested_version, "0");
        // Errores en orden.
        assert_eq!(code("afirma://sign?key=123&op=sign", false), 600009);
        assert_eq!(code("afirma://sign?cipher=%25%25%25%25&op=sign", false), 600009);
        assert_eq!(code("afirma://sign?servicetimeout=x&op=sign", false), 600009);
        assert_eq!(code("afirma://sign?dat=file:/etc/passwd", false), 600117);
        assert_eq!(code("afirma://sign?dat=%20file:/etc/passwd", false), 600117);
        assert_eq!(code("afirma://sign?dat=FILE:///etc/passwd", false), 600117);
        assert_eq!(code("afirma://sign?dat=https://h/notfound", false), 200102);
        assert_eq!(code("afirma://sign?fileid=abc", false), 600101);
        assert_eq!(
            code("afirma://sign?fileid=abc&rtservlet=http://localhost/r", false),
            600010
        );
        assert_eq!(code("afirma://sign?fileid=abc&rtservlet=nourl", false), 600116);
        assert_eq!(code("afirma://sign?id=no-valido&dat=SG9sYQ==", false), 600120);
        assert_eq!(code("afirma://sign?op=sign&dat=SG9sYQ==", false), 600104);
        assert_eq!(code("afirma://sign?op=sign&format=CAdES&dat=SG9sYQ==", false), 600106);
        assert_eq!(
            code(
                "afirma://sign?op=sign&format=CAdES&algorithm=MD5withRSA&dat=SG9sYQ==",
                false
            ),
            600107
        );
        assert_eq!(
            code(
                "afirma://sign?op=sign&format=CAdES&algorithm=sha256withrsa&dat=SG9sYQ==",
                false
            ),
            600107
        );
        // Directa: stservlet.
        assert_eq!(
            code(
                "afirma://sign?id=abc&op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==",
                true
            ),
            600402
        );
        assert_eq!(
            code(
                "afirma://sign?id=abc&stservlet=http://127.0.0.1/s&op=sign&dat=SG9sYQ==",
                true
            ),
            600412
        );
        assert_eq!(
            code(
                "afirma://sign?id=abc&stservlet=https://h/s?x&op=sign&dat=SG9sYQ==",
                true
            ),
            600411
        );
        let f = parse("afirma://sign?id=abc&stservlet=https://h/s&op=sign&dat=SG9sYQ==", true).unwrap_err();
        assert_eq!(f.error.code.code, 600104);
        assert_eq!(
            f.reply,
            Some(ReplyChannel {
                id: "abc".into(),
                storage_servlet: "https://h/s".into()
            })
        );
        // Escape mal formado → error genérico de la operación.
        let f = parse("afirma://sign?op=sign&format=%zz", false).unwrap_err();
        assert_eq!(f.error.code.code, 200115);
        // Con fileid se detiene antes de format.
        let Request::Sign(p) = parse("afirma://sign?fileid=abc&rtservlet=https://h/r&key=12345678", true).unwrap()
        else {
            panic!()
        };
        assert_eq!(p.common.file_id.as_deref(), Some("abc"));
        assert_eq!(p.common.id.as_deref(), Some("abc"));
        assert_eq!(
            p.common.cipher_config.as_deref(),
            Some(&b"{algo:\"DES\", key:\"12345678\"}"[..])
        );
        // URL remota descargada.
        let Request::Sign(p) =
            parse("afirma://sign?op=cosign&format=CAdES&algorithm=SHA256&dat=https://h/doc&properties=bW9kZT1pbXBsaWNpdA==&other=1", false).unwrap()
        else {
            panic!()
        };
        assert_eq!(p.common.data.as_deref(), Some(&b"REMOTO"[..]));
        assert_eq!(p.extra_params.get("mode"), Some("implicit"));
        assert_eq!(p.other_params.get("other").map(String::as_str), Some("1"));
        assert_eq!(p.other_params.get("op").map(String::as_str), Some("cosign"));
        assert_eq!(p.operation, Some(CryptoOperation::CoSign));
    }

    #[test]
    fn signandsave_specifics() {
        assert_eq!(
            code(
                "afirma://signandsave?cop=sign&format=CAdES&algorithm=SHA256withECDSA&dat=SG9sYQ==",
                false
            ),
            600107
        );
        assert_eq!(
            code(
                "afirma://signandsave?cop=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==&filename=a/b",
                false
            ),
            600306
        );
        let Request::SignAndSave(p) = parse(
            "afirma://signandsave?cop=countersign&op=sign&format=CAdES&algorithm=SHA256&dat=SG9sYQ==&filename=x.csig",
            false,
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(p.operation, Some(CryptoOperation::CounterSign));
        assert_eq!(p.filename.as_deref(), Some("x.csig"));
        assert!(p.other_params.is_empty());
    }

    #[test]
    fn selectcert_batch_save_load() {
        assert_eq!(code("afirma://selectcert?id=a_b", false), 600201);
        let Request::SelectCert(p) = parse(
            "afirma://selectcert?op=selectcert&ksb64=TU9aX1VOSQ==&sticky=TRUE",
            false,
        )
        .unwrap() else {
            panic!()
        };
        assert!(p.sticky);
        assert_eq!(
            p.keystore.as_ref().unwrap().resolved_constant(),
            Some("MOZ_UNI_WITH_OS")
        );
        assert_eq!(code("afirma://batch?id=a_b", false), 600410);
        assert_eq!(code("afirma://batch?op=batch&dat=e30=", false), 600406);
        assert_eq!(
            code(
                "afirma://batch?op=batch&dat=e30=&batchpostsignerurl=https://h/post",
                false
            ),
            600405
        );
        assert_eq!(
            code(
                "afirma://batch?op=batch&dat=e30=&batchpostsignerurl=https://localhost/post&batchpresignerurl=x",
                false
            ),
            600416
        );
        assert_eq!(
            code(
                "afirma://batch?op=batch&dat=e30=&batchpostsignerurl=https://h/post&batchpresignerurl=http://127.0.0.1/p",
                false
            ),
            600414
        );
        assert_eq!(
            code(
                "afirma://batch?op=batch&dat=e30=&batchpostsignerurl=x&batchpresignerurl=http://127.0.0.1/p",
                false
            ),
            600415
        );
        assert_eq!(
            code(
                "afirma://batch?op=batch&dat=e30=&batchpostsignerurl=https://h/post&batchpresignerurl=x",
                false
            ),
            600413
        );
        let Request::Batch(p) = parse(
            "afirma://batch?op=batch&dat=e30=&localBatchProcess=true&jsonbatch=true&needcert=true",
            false,
        )
        .unwrap() else {
            panic!()
        };
        assert!(p.local_batch_process && p.json_batch && p.need_cert);
        assert_eq!(code("afirma://save?op=save", false), 600300);
        assert_eq!(code("afirma://save?op=save&dat=SG9sYQ==&id=a_b", false), 600303);
        assert_eq!(code("afirma://save?op=save&dat=SG9sYQ==&filename=a:b", false), 600306);
        assert_eq!(code("afirma://save?op=save&dat=SG9sYQ==&exts=p%20df", false), 600307);
        let Request::Save(p) = parse("afirma://save?op=save&dat=SG9sYQ==&exts=pdf,xml&desc=Docs", false).unwrap()
        else {
            panic!()
        };
        assert_eq!(p.title, "Guardar fichero");
        assert_eq!(p.description.as_deref(), Some("Docs (*.pdf*.xml)"));
        let Request::Load(p) = parse("afirma://load?op=load&multiload=true&exts=pdf&filePath=", false).unwrap() else {
            panic!()
        };
        assert!(p.multiload);
        assert_eq!(p.file_path, None);
    }

    #[test]
    fn keystore_params() {
        let ks = |url: &str| {
            let p = Params::from_query(url);
            keystore_param(&Reader {
                p: &p,
                kind: OperationKind::SelectCert,
            })
            .unwrap()
        };
        let k = ks("x?keystore=PKCS11:%22/usr/lib/a.so%22&ksb64=TU9aX1VOSQ==").unwrap();
        assert_eq!(k.name.as_deref(), Some("PKCS11"));
        assert_eq!(k.library.as_deref(), Some("/usr/lib/a.so"));
        assert_eq!(ks("x?ksb64=bm9iYXNlNjQ").map(|k| k.name), Some(Some("nobase".into())));
        assert_eq!(ks("x?keystore=%3A"), None);
        assert_eq!(ks("x?keystore=windows").unwrap().resolved_constant(), Some("WINDOWS"));
        assert_eq!(
            ks("x?keystore=Llavero%20de%20Mac").unwrap().resolved_constant(),
            Some("APPLE")
        );
        assert_eq!(ks("x?keystore=moz_uni").unwrap().resolved_constant(), None);
    }

    #[test]
    fn gzip_data() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"comprimido").unwrap();
        let b64 = jbase64::encode_url_safe(&enc.finish().unwrap());
        assert_eq!(download_data(&b64, true, &http()).unwrap(), b"comprimido");
        assert_eq!(download_data(" SG9sYQ== ", false, &http()).unwrap(), b"Hola");
        assert_eq!(download_data("texto plano", false, &http()).unwrap(), b"texto plano");
        assert!(download_data("ftp://x/y", false, &http()).is_err());
    }
}
