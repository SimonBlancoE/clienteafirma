//! Análisis de las peticiones `afirma://` con la semántica de `afirma-core`
//! **1.9** (la versión que usa Autofirma App 1.9; `docs/spec/09-android.md`
//! §0.3, §5.2 y §6.2): `ProtocolInvocationUriParser`,
//! `ProtocolInvocationUriParserUtil`, `UrlParameters*`.
//!
//! Diferencias con el análisis del escritorio (`crate::request`, 1.9.1):
//! - La operación sale del *host* de la URL (`afirma://cosign?…` ⇒ `cosign`),
//!   que sobrescribe cualquier `op=`. En los sobres XML, el nombre del raíz,
//!   sobrescrito por `<e k="op">` si existe. En `batch` no se añade `op`.
//! - Solo cifrado DES con `key` (8 caracteres; otra longitud es error). No
//!   existen `cipher` ni `servicetimeout` (se ignoran).
//! - Todos los errores son `ParameterException` (en la app, AA600006).
//! - Todos los valores se decodifican al analizar la URL: un `%` mal formado en
//!   **cualquier** parámetro hace fallar la petición.
//!
//! Se mantienen de `01-protocol.md`: `dat` en Base64 o URL `http(s)` que se
//! descarga y `gzip`, validación de las URL de servicio, identificadores de
//! hasta 20 caracteres alfanuméricos, `format` y `algorithm` obligatorios y la
//! lista de algoritmos admitidos.
//!
//! Desviaciones compartidas con el escritorio (documentadas en
//! `docs/deviations/afirma-protocol.md`): un `+` literal en `properties`, en
//! `key` o en un `dat` Base64 se conserva (Java lo convertía en espacio y
//! corrompía el Base64; pasa con los `properties` de los sobres de AutoScript,
//! que van sin codificar), los sobres XML admiten espacios y comentarios entre
//! elementos, se rechaza cualquier variante de `file:` en `dat` (Java leía el
//! fichero local si el valor empezaba por un espacio) y se rechazan como
//! locales todas las direcciones de bucle local (Java solo `localhost` y
//! `127.0.0.1`).

use std::collections::BTreeMap;

use afirma_core::ExtraParams;
use afirma_core::base64 as jb64;

use crate::http::{HttpClient, Method};
use crate::query::{Params, operation_name, url_decode};
use crate::request::{UrlError, is_valid_operation_id, validate_url};
use crate::triphase::CryptoOperation;
use crate::triphase::data::java_trim;

/// Operación registrada por la app (§5.3): `afirma://sign|cosign|countersign|
/// selectcert|save|batch`. `signandsave`, `load`, `websocket` y `service` no
/// tienen actividad en Android.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebOperation {
    Sign,
    CoSign,
    CounterSign,
    SelectCert,
    Save,
    Batch,
}

impl WebOperation {
    /// Operación de una URL por su *host* (sin distinguir mayúsculas).
    /// `None` si la app no la registra.
    pub fn from_url(url: &str) -> Option<WebOperation> {
        Self::from_name(&operation_name(url))
    }

    /// Operación por nombre (sin distinguir mayúsculas).
    pub fn from_name(name: &str) -> Option<WebOperation> {
        Some(match name.to_ascii_lowercase().as_str() {
            "sign" => WebOperation::Sign,
            "cosign" => WebOperation::CoSign,
            "countersign" => WebOperation::CounterSign,
            "selectcert" => WebOperation::SelectCert,
            "save" => WebOperation::Save,
            "batch" => WebOperation::Batch,
            _ => return None,
        })
    }

    /// Nombre en el protocolo.
    pub fn name(self) -> &'static str {
        match self {
            WebOperation::Sign => "sign",
            WebOperation::CoSign => "cosign",
            WebOperation::CounterSign => "countersign",
            WebOperation::SelectCert => "selectcert",
            WebOperation::Save => "save",
            WebOperation::Batch => "batch",
        }
    }

    /// Indica si es firma, cofirma o contrafirma (`WebSignActivity`).
    pub fn is_sign_family(self) -> bool {
        matches!(
            self,
            WebOperation::Sign | WebOperation::CoSign | WebOperation::CounterSign
        )
    }
}

/// Error de los parámetros (`ParameterException` o excepción durante el
/// análisis). En la app siempre se trata como AA600006.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ParamError(pub String);

impl ParamError {
    fn new(m: impl Into<String>) -> Self {
        ParamError(m.into())
    }
}

/// Parámetros de una petición con la semántica de `parserUri`/`parseXml` (se
/// guardan sin decodificar, pero se comprueba al construirlos que todos los
/// valores se pueden decodificar, como hacía Java).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebParams {
    p: Params,
}

impl WebParams {
    fn checked(p: Params) -> Result<WebParams, ParamError> {
        let keys: Vec<String> = p.keys().map(str::to_string).collect();
        for k in keys {
            p.get(&k)
                .map_err(|e| ParamError::new(format!("Valor no valido en el parametro '{k}': {e}")))?;
        }
        Ok(WebParams { p })
    }

    /// `ProtocolInvocationUriParser.parserUri`: parámetros de la consulta y
    /// `op` = *host* de la URL.
    pub fn from_url(url: &str) -> Result<WebParams, ParamError> {
        let mut p = Params::from_query(url);
        p.insert_raw("op", operation_name(url));
        Self::checked(p)
    }

    /// `WebSignBatchActivity.extractParamsForBatch`: como la anterior pero sin
    /// `op`. (Java no capturaba el error de un `%` mal formado y la app se
    /// cerraba; aquí es un error de parámetros.)
    pub fn from_batch_url(url: &str) -> Result<WebParams, ParamError> {
        Self::checked(Params::from_query(url))
    }

    /// `ProtocolInvocationUriParserUtil.parseXml`: sobre XML descargado con
    /// `fileid`.
    pub fn from_envelope(xml: &[u8]) -> Result<WebParams, ParamError> {
        let p = crate::envelope::parse_xml_envelope(xml)
            .map_err(|e| ParamError::new(format!("Error grave durante el analisis del XML: {e}")))?;
        Self::checked(p)
    }

    /// Indica si el parámetro existe (`containsKey`).
    pub fn contains(&self, key: &str) -> bool {
        self.p.contains(key)
    }

    /// Valor decodificado (`URLDecoder`).
    pub fn get(&self, key: &str) -> Option<String> {
        self.p.get(key).ok().flatten()
    }

    /// Valor sin decodificar.
    pub fn raw(&self, key: &str) -> Option<&str> {
        self.p.raw(key)
    }

    /// `Boolean.parseBoolean(params.get(key))`.
    pub fn get_bool(&self, key: &str) -> bool {
        self.get(key).is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    fn get_base64(&self, key: &str) -> Option<String> {
        self.p.get_base64(key).ok().flatten()
    }

    fn get_data(&self, key: &str) -> Option<String> {
        self.p.get_data(key).ok().flatten()
    }

    /// Nombres de los parámetros.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.p.keys()
    }
}

/// Parámetros comunes (`UrlParameters.setCommonParameters` y los de
/// identificación de la operación).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommonParams {
    /// Clave DES (`key`): los bytes UTF-8 de sus 8 caracteres.
    pub des_key: Option<Vec<u8>>,
    /// `aw=true` (solo tiene efecto en `batch` con sobre descargado).
    pub active_waiting: bool,
    /// `mcv` (se lee pero no se comprueba).
    pub min_client_version: Option<String>,
    /// Datos (`dat`) ya obtenidos.
    pub data: Option<Vec<u8>>,
    /// `fileid` (solo si no hay `dat`).
    pub file_id: Option<String>,
    /// `rtservlet` validado (obligatorio con `fileid`).
    pub retrieve_servlet: Option<String>,
    /// `id` (o `fileid`) validado.
    pub id: Option<String>,
    /// `stservlet` validado.
    pub storage_servlet: Option<String>,
    /// `ver` (por defecto `"0"`; se lee pero no se usa).
    pub min_protocol_version: String,
}

/// Firma, cofirma o contrafirma (`UrlParametersToSign`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub common: CommonParams,
    /// Valor de `op` (el *host* o el del sobre), tal cual.
    pub operation: String,
    /// `format` (`None` solo si la petición está en un sobre por descargar).
    pub format: Option<String>,
    /// `algorithm` (de la lista admitida).
    pub algorithm: Option<String>,
    /// `properties` decodificado (vacío si no se pudo cargar).
    pub extra_params: ExtraParams,
    pub sticky: bool,
    pub reset_sticky: bool,
    /// `appname` (solo se usa en el histórico).
    pub app_name: Option<String>,
    /// Parámetros desconocidos (`getAnotherParams`).
    pub other_params: BTreeMap<String, String>,
}

impl SignRequest {
    /// Operación criptográfica (`None` si `op` no es `sign`, `cosign` ni
    /// `countersign`).
    pub fn crypto_operation(&self) -> Option<CryptoOperation> {
        CryptoOperation::parse(&self.operation)
    }
}

/// Selección de certificado (`UrlParametersToSelectCert`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectCertRequest {
    pub common: CommonParams,
    /// `properties` (no se usa para nada en Android).
    pub extra_params: ExtraParams,
    pub sticky: bool,
    pub reset_sticky: bool,
}

/// Guardado de datos (`UrlParametersToSave`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveRequest {
    pub common: CommonParams,
    /// `title` o «Guardar fichero».
    pub title: String,
    /// `filename` (sin `\/:*?"<>|`).
    pub filename: Option<String>,
    /// `exts` (sin `\/:*?"<>|; `).
    pub extensions: Option<String>,
    /// `desc` (con las extensiones añadidas como en Java).
    pub description: Option<String>,
}

/// Firma de lotes (`UrlParametersForBatch`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRequest {
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
}

/// Petición analizada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebRequest {
    Sign(SignRequest),
    SelectCert(SelectCertRequest),
    Save(SaveRequest),
    Batch(BatchRequest),
}

impl WebRequest {
    pub fn common(&self) -> &CommonParams {
        match self {
            WebRequest::Sign(r) => &r.common,
            WebRequest::SelectCert(r) => &r.common,
            WebRequest::Save(r) => &r.common,
            WebRequest::Batch(r) => &r.common,
        }
    }

    /// Indica si los parámetros reales están en un sobre por descargar.
    pub fn needs_envelope(&self) -> bool {
        let c = self.common();
        c.data.is_none() && c.file_id.is_some()
    }
}

/// Algoritmos admitidos (`UrlParametersToSign.SUPPORTED_SIGNATURE_ALGORITHMS`).
pub const SUPPORTED_SIGNATURE_ALGORITHMS: &[&str] = &[
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

/// `DataDownloader.downloadData(dat, gzip)` sin diálogos TLS (en Android no hay
/// importación de certificados).
pub fn download_data(dat: &str, gzip: bool, http: &HttpClient) -> Result<Vec<u8>, String> {
    if gzip && jb64::is_base64_bytes(dat.as_bytes()) {
        let compressed = jb64::decode_url_safe_as_standard(dat).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        use std::io::Read;
        flate2::read::GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .map_err(|e| e.to_string())?;
        return Ok(out);
    }
    let s = java_trim(dat);
    if s.starts_with("http://") || s.starts_with("https://") {
        return http.read_url(s, Method::Get).map_err(|e| e.to_string());
    }
    if s.starts_with("ftp://") {
        return Err("No se soporta la descarga de datos por FTP".into());
    }
    if jb64::is_base64_bytes(s.as_bytes())
        && let Ok(v) = jb64::decode_url_safe_as_standard(s)
    {
        return Ok(v);
    }
    Ok(s.as_bytes().to_vec())
}

/// `AOUtil.base642Properties` (un error deja los parámetros vacíos).
fn properties(p: &WebParams) -> ExtraParams {
    match p.get_base64("properties") {
        Some(b64) if !b64.is_empty() => match jb64::decode_url_safe_as_standard(&b64) {
            Ok(bytes) => ExtraParams::parse(&String::from_utf8_lossy(&bytes)),
            Err(e) => {
                tracing::warn!(
                    "Las propiedades adicionales indicadas en el parametro 'properties' no se han podido cargar: {e}"
                );
                ExtraParams::new()
            }
        },
        _ => ExtraParams::new(),
    }
}

/// `UrlParameters.validateURL` con el mensaje del contexto.
fn checked_url(value: &str, what: &str) -> Result<String, ParamError> {
    validate_url(value).map_err(|e| match e {
        UrlError::Local => ParamError::new(format!("La URL del {what} no puede ser local")),
        UrlError::Invalid(m) => ParamError::new(format!("Error al validar la URL del {what}: {m}")),
    })
}

/// `setCommonParameters`.
fn common(p: &WebParams, http: &HttpClient) -> Result<CommonParams, ParamError> {
    let mut c = CommonParams {
        min_protocol_version: "0".into(),
        ..Default::default()
    };
    // verifyCipherKey (el `+` se conserva, como en el escritorio: desviación R1).
    if p.contains("key") {
        let key = p.get_base64("key").unwrap_or_default();
        if !key.is_empty() {
            if key.encode_utf16().count() != 8 {
                return Err(ParamError::new("La longitud de la clave de cifrado no es correcta"));
            }
            c.des_key = Some(key.into_bytes());
        }
    }
    c.active_waiting = p.get_bool("aw");
    if p.contains("mcv") {
        c.min_client_version = p.get("mcv");
    }
    if !p.contains("dat") {
        if p.contains("fileid") {
            c.file_id = p.get("fileid");
            let Some(rt) = p.get("rtservlet") else {
                return Err(ParamError::new(
                    "No se ha recibido la direccion del servlet para la recuperacion de los datos a firmar",
                ));
            };
            c.retrieve_servlet = Some(checked_url(&rt, "servicio de recuperacion de datos")?);
        }
    } else {
        let dat = p.get_data("dat").unwrap_or_default();
        let trimmed = java_trim(&dat);
        if dat.starts_with("file:/") || trimmed.get(..5).is_some_and(|x| x.eq_ignore_ascii_case("file:")) {
            return Err(ParamError::new(format!(
                "No se permite la lectura de ficheros locales: {dat}"
            )));
        }
        c.data = Some(
            download_data(&dat, p.get_bool("gzip"), http)
                .map_err(|e| ParamError::new(format!("No se han podido obtener los datos: {e}")))?,
        );
    }
    Ok(c)
}

/// Identificador de sesión: `id` o, si falta, `fileid`.
fn session_id(p: &WebParams, c: &mut CommonParams, msg: &str) -> Result<(), ParamError> {
    let id = if p.contains("id") {
        p.get("id")
    } else if p.contains("fileid") {
        p.get("fileid")
    } else {
        None
    };
    if let Some(id) = id {
        if id.encode_utf16().count() > crate::request::MAX_ID_LENGTH {
            return Err(ParamError::new(format!(
                "La longitud del identificador de la operacion es mayor de {} caracteres.",
                crate::request::MAX_ID_LENGTH
            )));
        }
        if !is_valid_operation_id(&id) {
            return Err(ParamError::new(msg));
        }
        c.id = Some(id);
    }
    Ok(())
}

/// `ver` (por defecto `"0"`).
fn version(p: &WebParams, c: &mut CommonParams) {
    if p.contains("ver") {
        c.min_protocol_version = p.get("ver").unwrap_or_default();
    }
}

/// `stservlet` (siempre `servicesRequired = true` en la app).
fn storage(p: &WebParams, c: &mut CommonParams) -> Result<(), ParamError> {
    if let Some(st) = p.get("stservlet") {
        c.storage_servlet = Some(checked_url(&st, "servicio de guardado")?);
    } else if p.contains("id") {
        return Err(ParamError::new(
            "No se ha recibido la direccion del servlet para el guardado del resultado de la operacion",
        ));
    }
    Ok(())
}

/// `getParametersToSign(params, servicesRequired = true)`.
pub fn parse_sign(p: &WebParams, http: &HttpClient) -> Result<SignRequest, ParamError> {
    let mut common = common(p, http)?;
    session_id(p, &mut common, "El identificador de la firma debe ser alfanumerico.")?;
    version(p, &mut common);
    let app_name = if p.contains("appname") { p.get("appname") } else { None };
    let operation = p.get("op").unwrap_or_default();
    let other_params: BTreeMap<String, String> = p
        .keys()
        .filter(|k| !SIGN_KNOWN_PARAMS.contains(k))
        .map(|k| (k.to_string(), p.get(k).unwrap_or_default()))
        .collect();
    let mut req = SignRequest {
        common,
        operation,
        format: None,
        algorithm: None,
        extra_params: ExtraParams::new(),
        sticky: false,
        reset_sticky: false,
        app_name,
        other_params,
    };
    if req.common.file_id.is_some() {
        return Ok(req);
    }
    storage(p, &mut req.common)?;
    let Some(format) = p.get("format").filter(|_| p.contains("format")) else {
        return Err(ParamError::new("No se ha recibido el formato de firma"));
    };
    req.format = Some(format);
    if !p.contains("algorithm") {
        return Err(ParamError::new("No se ha recibido el algoritmo de firma"));
    }
    let algo = p.get("algorithm").unwrap_or_default();
    if !SUPPORTED_SIGNATURE_ALGORITHMS.contains(&algo.as_str()) {
        return Err(ParamError::new(format!("Algoritmo de firma no soportado: {algo}")));
    }
    req.algorithm = Some(algo);
    req.extra_params = properties(p);
    req.sticky = p.get_bool("sticky");
    req.reset_sticky = p.get_bool("resetsticky");
    Ok(req)
}

/// `getParametersToSelectCert(params, servicesRequired = true)`.
pub fn parse_select_cert(p: &WebParams, http: &HttpClient) -> Result<SelectCertRequest, ParamError> {
    // `dat` se descarga y valida, pero no se usa para nada.
    let mut common = common(p, http)?;
    session_id(p, &mut common, "El identificador de la sesion debe ser alfanumerico.")?;
    version(p, &mut common);
    let mut req = SelectCertRequest {
        common,
        extra_params: ExtraParams::new(),
        sticky: false,
        reset_sticky: false,
    };
    if req.common.file_id.is_some() {
        return Ok(req);
    }
    storage(p, &mut req.common)?;
    req.extra_params = properties(p);
    req.sticky = p.get_bool("sticky");
    req.reset_sticky = p.get_bool("resetsticky");
    Ok(req)
}

const INVALID_FILENAME_CHARS: &str = "\\/:*?\"<>|";
const INVALID_EXTS_CHARS: &str = "\\/:*?\"<>|; ";

/// `getParametersToSave(params, servicesRequired = true)`.
pub fn parse_save(p: &WebParams, http: &HttpClient) -> Result<SaveRequest, ParamError> {
    let mut common = common(p, http)?;
    if !p.contains("fileid") && !p.contains("dat") {
        return Err(ParamError::new(
            "No se ha proporcionado el identificador de fichero ni los datos a guardar",
        ));
    }
    session_id(p, &mut common, "El identificador de la firma debe ser alfanumerico.")?;
    version(p, &mut common);
    storage(p, &mut common)?;
    let title = if p.contains("title") {
        p.get("title").unwrap_or_default()
    } else {
        "Guardar fichero".to_string()
    };
    let filename = if p.contains("filename") {
        let f = p.get("filename").unwrap_or_default();
        if let Some(c) = INVALID_FILENAME_CHARS.chars().find(|c| f.contains(*c)) {
            return Err(ParamError::new(format!(
                "Se ha indicado un nombre de fichero con el caracter invalido: {c}"
            )));
        }
        Some(f)
    } else {
        None
    };
    let extensions = if p.contains("exts") {
        let e = p.get("exts").unwrap_or_default();
        if let Some(c) = INVALID_EXTS_CHARS.chars().find(|c| e.contains(*c)) {
            return Err(ParamError::new(format!(
                "Se ha indicado una lista de extensiones de nombre de fichero con caracteres invalidos: {c}"
            )));
        }
        Some(e)
    } else {
        None
    };
    let description = if p.contains("desc") {
        let mut d = p.get("desc").unwrap_or_default();
        if let Some(e) = &extensions
            && !d.ends_with(')')
        {
            d.push_str(" (");
            // `String.split(",")` descarta las cadenas vacías finales.
            let mut parts: Vec<&str> = e.split(',').collect();
            while parts.last().is_some_and(|x| x.is_empty()) {
                parts.pop();
            }
            for ext in parts {
                d.push_str("*.");
                d.push_str(ext);
            }
            d.push(')');
        }
        Some(d)
    } else {
        None
    };
    Ok(SaveRequest {
        common,
        title,
        filename,
        extensions,
        description,
    })
}

/// `getParametersToBatch(params, servicesRequired = true)`.
pub fn parse_batch(p: &WebParams, http: &HttpClient) -> Result<BatchRequest, ParamError> {
    let mut common = common(p, http)?;
    if p.contains("id") || p.contains("fileid") {
        session_id(p, &mut common, "El identificador de la firma debe ser alfanumerico.")?;
    }
    version(p, &mut common);
    let app_name = if p.contains("appname") { p.get("appname") } else { None };
    let mut req = BatchRequest {
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
    };
    if req.common.file_id.is_some() {
        return Ok(req);
    }
    req.local_batch_process = p.get_bool("localBatchProcess");
    if !req.local_batch_process {
        let Some(post) = p.get("batchpostsignerurl") else {
            return Err(ParamError::new("No se ha recibido la URL del postprocesador de lotes"));
        };
        let Some(pre) = p.get("batchpresignerurl") else {
            return Err(ParamError::new("No se ha recibido la URL del preprocesador de lotes"));
        };
        req.postsigner_url = Some(checked_url(&post, "postprocesador de lotes")?);
        req.presigner_url = Some(checked_url(&pre, "preprocesador de lotes")?);
    }
    storage(p, &mut req.common)?;
    req.extra_params = properties(p);
    req.sticky = p.get_bool("sticky");
    req.reset_sticky = p.get_bool("resetsticky");
    req.need_cert = p.get_bool("needcert");
    req.json_batch = p.get_bool("jsonbatch");
    Ok(req)
}

/// Analiza los parámetros de una operación.
pub fn parse(op: WebOperation, p: &WebParams, http: &HttpClient) -> Result<WebRequest, ParamError> {
    Ok(match op {
        WebOperation::Sign | WebOperation::CoSign | WebOperation::CounterSign => WebRequest::Sign(parse_sign(p, http)?),
        WebOperation::SelectCert => WebRequest::SelectCert(parse_select_cert(p, http)?),
        WebOperation::Save => WebRequest::Save(parse_save(p, http)?),
        WebOperation::Batch => WebRequest::Batch(parse_batch(p, http)?),
    })
}

/// Analiza una URL completa de la operación indicada (`batch` usa
/// `extractParamsForBatch`).
pub fn parse_url(op: WebOperation, url: &str, http: &HttpClient) -> Result<WebRequest, ParamError> {
    let p = if op == WebOperation::Batch {
        WebParams::from_batch_url(url)?
    } else {
        WebParams::from_url(url)?
    };
    parse(op, &p, http)
}

/// Destino de una respuesta en el servidor intermedio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyTarget {
    pub id: String,
    pub storage_servlet: String,
}

/// Destino al que responder cuando la petición no se pudo analizar o el sobre
/// no se pudo obtener (corrección: Java no respondía, §10 n.º 35 y 36).
///
/// Se usa `stservlet` (validado) y el identificador que consulta la página:
/// `id`; si no está, `rid` (AutoScript lo envía con `fileid` y es el
/// identificador que consulta); y si tampoco, `fileid` (el que usaba Java en
/// `save`). Solo identificadores válidos.
pub fn reply_hint(p: &WebParams) -> Option<ReplyTarget> {
    let storage_servlet = validate_url(&p.get("stservlet")?).ok()?;
    let id = ["id", "rid", "fileid"]
        .into_iter()
        .filter_map(|k| p.get(k))
        .find(|v| !v.is_empty() && is_valid_operation_id(v))?;
    Some(ReplyTarget { id, storage_servlet })
}

/// Destino de la respuesta de una URL que no se pudo ni siquiera trocear (un
/// `%` mal formado): se buscan los parámetros sin decodificar los demás.
pub fn reply_hint_lenient(url: &str) -> Option<ReplyTarget> {
    let p = Params::from_query(url);
    let get = |k: &str| p.raw(k).and_then(|v| url_decode(v).ok());
    let storage_servlet = validate_url(&get("stservlet")?).ok()?;
    let id = ["id", "rid", "fileid"]
        .into_iter()
        .filter_map(get)
        .find(|v| !v.is_empty() && is_valid_operation_id(v))?;
    Some(ReplyTarget { id, storage_servlet })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{MockTransport, ok};

    fn http() -> HttpClient {
        HttpClient::new(MockTransport::new(|_| ok("DESCARGADO")))
    }

    fn sign(url: &str) -> Result<SignRequest, ParamError> {
        parse_sign(&WebParams::from_url(url)?, &http())
    }

    const ST: &str = "https%3A%2F%2Fservidor.example%2Fafirma-signature-storage%2FStorageService";
    const RT: &str = "https%3A%2F%2Fservidor.example%2Fafirma-signature-retriever%2FRetrieveService";

    #[test]
    fn operation_from_host() {
        assert_eq!(
            WebOperation::from_url("afirma://cosign?op=sign"),
            Some(WebOperation::CoSign)
        );
        assert_eq!(WebOperation::from_url("afirma://SIGN/?a=b"), Some(WebOperation::Sign));
        assert_eq!(WebOperation::from_url("afirma://batch/x?a"), Some(WebOperation::Batch));
        for op in ["signandsave", "load", "websocket", "service", ""] {
            assert_eq!(WebOperation::from_url(&format!("afirma://{op}?a=b")), None, "{op}");
        }
        // El host sobrescribe `op=`.
        let r = sign(&format!(
            "afirma://countersign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=SG9sYQ==&id=ABC&stservlet={ST}"
        ))
        .unwrap();
        assert_eq!(r.operation, "countersign");
        assert_eq!(r.crypto_operation(), Some(CryptoOperation::CounterSign));
    }

    #[test]
    fn sign_full() {
        let url = format!(
            "afirma://sign?ver=4&id=AbC123&stservlet={ST}&format=CAdES&algorithm=SHA256withRSA&key=12345678\
             &properties=bW9kZT1pbXBsaWNpdA%3D%3D&dat=SG9sYQ%3D%3D&sticky=true&appname=sede.example&otro=x%20y&aw=true"
        );
        let r = sign(&url).unwrap();
        assert_eq!(r.common.id.as_deref(), Some("AbC123"));
        assert_eq!(
            r.common.storage_servlet.as_deref(),
            Some("https://servidor.example/afirma-signature-storage/StorageService")
        );
        assert_eq!(r.common.des_key.as_deref(), Some(&b"12345678"[..]));
        assert_eq!(r.common.data.as_deref(), Some(&b"Hola"[..]));
        assert_eq!(r.common.min_protocol_version, "4");
        assert!(r.common.active_waiting);
        assert_eq!(r.format.as_deref(), Some("CAdES"));
        assert_eq!(r.extra_params.get("mode"), Some("implicit"));
        assert!(r.sticky && !r.reset_sticky);
        assert_eq!(r.app_name.as_deref(), Some("sede.example"));
        assert_eq!(r.other_params.get("otro").map(String::as_str), Some("x y"));
        assert_eq!(r.other_params.get("op").map(String::as_str), Some("sign"));
    }

    #[test]
    fn sign_errors() {
        let base = format!("afirma://sign?id=ABC&stservlet={ST}&dat=SG9sYQ==");
        assert_eq!(sign(&base).unwrap_err().0, "No se ha recibido el formato de firma");
        assert_eq!(
            sign(&format!("{base}&format=CAdES")).unwrap_err().0,
            "No se ha recibido el algoritmo de firma"
        );
        assert!(sign(&format!("{base}&format=CAdES&algorithm=MD5withRSA")).is_err());
        // Clave de otra longitud.
        assert!(sign(&format!("{base}&format=CAdES&algorithm=SHA256&key=1234")).is_err());
        // Clave vacía = sin cifrado.
        assert!(
            sign(&format!("{base}&format=CAdES&algorithm=SHA256&key="))
                .unwrap()
                .common
                .des_key
                .is_none()
        );
        // `cipher` y `servicetimeout` no existen (se ignoran).
        let r = sign(&format!(
            "{base}&format=CAdES&algorithm=SHA256&cipher=xx&servicetimeout=abc"
        ))
        .unwrap();
        assert!(r.other_params.contains_key("cipher"));
        // Id no alfanumérico o largo.
        assert!(
            sign(&format!(
                "afirma://sign?id=AB-C&stservlet={ST}&dat=SG9sYQ==&format=CAdES&algorithm=SHA256"
            ))
            .is_err()
        );
        assert!(
            sign(&format!(
                "afirma://sign?id={}&stservlet={ST}&format=CAdES&algorithm=SHA256",
                "A".repeat(21)
            ))
            .is_err()
        );
        // Con `id` hace falta `stservlet`.
        assert!(sign("afirma://sign?id=ABC&dat=SG9sYQ==&format=CAdES&algorithm=SHA256").is_err());
        // Sin `id` no: la respuesta posterior no tendría a dónde ir.
        assert!(sign("afirma://sign?dat=SG9sYQ==&format=CAdES&algorithm=SHA256").is_ok());
        // Un `%` mal formado en CUALQUIER parámetro hace fallar (Java decodifica todo al trocear).
        assert!(sign(&format!("{base}&format=CAdES&algorithm=SHA256&nada=100%")).is_err());
        // URL de servicio local.
        assert!(
            sign("afirma://sign?id=ABC&stservlet=http%3A%2F%2Flocalhost%2Fs&format=CAdES&algorithm=SHA256").is_err()
        );
        // `file:` en dat.
        assert!(sign("afirma://sign?dat=%20file%3A%2Fetc%2Fpasswd&format=CAdES&algorithm=SHA256").is_err());
    }

    #[test]
    fn data_sources() {
        let h = http();
        assert_eq!(download_data("SG9sYQ==", false, &h).unwrap(), b"Hola");
        // URL-safe también.
        assert_eq!(download_data("-_8=", false, &h).unwrap(), vec![0xfb, 0xff]);
        assert_eq!(download_data(" https://h/datos ", false, &h).unwrap(), b"DESCARGADO");
        assert_eq!(download_data("no es base64", false, &h).unwrap(), b"no es base64");
        // gzip
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"comprimido").unwrap();
        let gz = jb64::encode_url_safe(&enc.finish().unwrap());
        assert_eq!(download_data(&gz, true, &h).unwrap(), b"comprimido");
    }

    #[test]
    fn envelope_reference() {
        let url = format!("afirma://sign?fileid=FID123&rid=RID456&rtservlet={RT}&stservlet={ST}&key=87654321");
        let r = sign(&url).unwrap();
        assert_eq!(r.common.file_id.as_deref(), Some("FID123"));
        assert_eq!(r.common.id.as_deref(), Some("FID123"));
        // El análisis se detiene en `fileid`: `stservlet` no se conoce aún.
        assert_eq!(r.common.storage_servlet, None);
        assert!(r.format.is_none());
        assert!(WebRequest::Sign(r).needs_envelope());
        // Sin rtservlet → error.
        assert!(sign("afirma://sign?fileid=FID123&key=87654321").is_err());
        // Pista de respuesta: `rid`.
        let hint = reply_hint(&WebParams::from_url(&url).unwrap()).unwrap();
        assert_eq!(hint.id, "RID456");
        assert!(hint.storage_servlet.ends_with("/StorageService"));
        // `dat` gana a `fileid`.
        let r = sign("afirma://sign?fileid=F1&dat=SG9sYQ==&format=CAdES&algorithm=SHA1").unwrap();
        assert!(r.common.file_id.is_none());
    }

    #[test]
    fn envelope_xml() {
        let xml = format!(
            "<sign><e k=\"format\" v=\"PAdES\"/><e k=\"algorithm\" v=\"SHA512withRSA\"/>\
             <e k=\"dat\" v=\"SG9sYQ==\"/><e k=\"op\" v=\"cosign\"/><e k=\"id\" v=\"RID1\"/>\
             <e k=\"stservlet\" v=\"{ST}\"/><e k=\"key\" v=\"11112222\"/><e k=\"properties\" v=\"bW9kZT1pbXBsaWNpdA+=\"/></sign>"
        );
        let r = parse_sign(&WebParams::from_envelope(xml.as_bytes()).unwrap(), &http()).unwrap();
        assert_eq!(r.operation, "cosign");
        assert_eq!(r.common.id.as_deref(), Some("RID1"));
        assert_eq!(r.common.des_key.as_deref(), Some(&b"11112222"[..]));
        assert_eq!(r.format.as_deref(), Some("PAdES"));
        // El raíz `op` equivale a SIGN.
        let p = WebParams::from_envelope(b"<op><e k=\"x\" v=\"1\"/></op>").unwrap();
        assert_eq!(p.get("op").as_deref(), Some("SIGN"));
        assert!(WebParams::from_envelope(b"<sign><x/></sign>").is_err());
        assert!(WebParams::from_envelope(b"<sign><e k=\"a\" v=\"%zz\"/></sign>").is_err());
        assert!(WebParams::from_envelope(b"no xml").is_err());
    }

    #[test]
    fn select_cert_save_batch() {
        let h = http();
        let r = parse_select_cert(
            &WebParams::from_url(&format!(
                "afirma://selectcert?id=ID1&stservlet={ST}&dat=SG9sYQ==&sticky=true"
            ))
            .unwrap(),
            &h,
        )
        .unwrap();
        assert_eq!(r.common.data.as_deref(), Some(&b"Hola"[..]));
        assert!(r.sticky);

        let r = parse_save(
            &WebParams::from_url(&format!(
                "afirma://save?id=ID1&stservlet={ST}&dat=SG9sYQ==&filename=a.txt&exts=txt,pdf&desc=Texto"
            ))
            .unwrap(),
            &h,
        )
        .unwrap();
        assert_eq!(r.filename.as_deref(), Some("a.txt"));
        assert_eq!(r.description.as_deref(), Some("Texto (*.txt*.pdf)"));
        assert_eq!(r.title, "Guardar fichero");
        assert!(parse_save(&WebParams::from_url("afirma://save?id=ID1").unwrap(), &h).is_err());
        assert!(
            parse_save(
                &WebParams::from_url(&format!(
                    "afirma://save?id=ID1&stservlet={ST}&dat=SG9sYQ==&filename=a/b"
                ))
                .unwrap(),
                &h
            )
            .is_err()
        );
        // `save` valida `stservlet` también con `fileid`.
        let r = parse_save(
            &WebParams::from_url(&format!("afirma://save?fileid=F1&rtservlet={RT}&stservlet={ST}")).unwrap(),
            &h,
        )
        .unwrap();
        assert_eq!(r.common.id.as_deref(), Some("F1"));
        assert!(r.common.storage_servlet.is_some());

        let url = format!(
            "afirma://batch?id=ID1&stservlet={ST}&dat=e30%3D&batchpresignerurl=https%3A%2F%2Fl.example%2Fpre\
             &batchpostsignerurl=https%3A%2F%2Fl.example%2Fpost&jsonbatch=true&needcert=true"
        );
        let r = parse_batch(&WebParams::from_batch_url(&url).unwrap(), &h).unwrap();
        assert_eq!(r.presigner_url.as_deref(), Some("https://l.example/pre"));
        assert!(r.json_batch && r.need_cert);
        // En lotes no se añade `op`.
        assert!(!WebParams::from_batch_url(&url).unwrap().contains("op"));
        let missing = format!("afirma://batch?id=ID1&stservlet={ST}&dat=e30%3D&jsonbatch=true");
        assert!(parse_batch(&WebParams::from_batch_url(&missing).unwrap(), &h).is_err());
        let local = format!("{missing}&localBatchProcess=true");
        assert!(
            parse_batch(&WebParams::from_batch_url(&local).unwrap(), &h)
                .unwrap()
                .local_batch_process
        );
    }

    #[test]
    fn lenient_hint() {
        let url = format!("afirma://sign?id=ID9&stservlet={ST}&x=%zz");
        assert!(WebParams::from_url(&url).is_err());
        assert_eq!(reply_hint_lenient(&url).unwrap().id, "ID9");
        assert!(reply_hint_lenient("afirma://sign?id=ID9").is_none());
    }
}
