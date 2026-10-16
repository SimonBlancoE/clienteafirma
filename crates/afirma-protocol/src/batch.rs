//! Firma por lotes (cliente): lotes JSON y XML contra el servicio de lotes
//! del servidor trifásico (`BatchSigner`) y lote JSON local
//! (`JSONBatchManager` + `LocalBatchSigner`).

use afirma_core::error::{ErrorCode, codes};
use afirma_core::{AfirmaError, ExtraParams, SigningKey};
use afirma_xml::dom::Document;

use crate::http::{HttpClient, HttpError};
use crate::jbase64;
use crate::json_lenient::{self, JsonObject, JsonValue};
use crate::triphase::CryptoOperation;
use crate::triphase::data::TriphaseData;

/// Estados de resultado de una firma del lote (`BatchDataResult.Result`).
pub const RESULT_NAMES: &[&str] = &[
    "NOT_STARTED",
    "DONE_AND_SAVED",
    "DONE_BUT_NOT_SAVED_YET",
    "DONE_BUT_SAVED_SKIPPED",
    "DONE_BUT_ERROR_SAVING",
    "ERROR_PRE",
    "ERROR_POST",
    "SKIPPED",
    "SAVE_ROLLBACKED",
];

/// Cadena de certificados de los lotes: Base64 URL-safe separados por `;`.
pub fn batch_cert_chain(chain: &[Vec<u8>]) -> String {
    chain.iter().map(|c| jbase64::encode_url_safe(c)).collect::<Vec<_>>().join(";")
}

/// Resultado parcial devuelto por la prefirma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignResult {
    pub id: String,
    pub result: String,
    pub description: Option<String>,
}

/// Respuesta de la prefirma de un lote JSON (`JSONPreSignBatchParser`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignBatch {
    pub td: Option<TriphaseData>,
    pub results: Option<Vec<PresignResult>>,
}

/// Analiza la respuesta de prefirma de un lote JSON.
pub fn parse_presign_response(json: &[u8]) -> Result<PresignBatch, String> {
    let obj = json_lenient::parse_object_bytes(json).map_err(|e| format!("El JSON de prefirma del lote no esta formado correctamente: {e}"))?;
    let td = match obj.get("td") {
        Some(_) => Some(TriphaseData::from_json(obj.get_object("td")?)?),
        None => None,
    };
    let results = match obj.get("results") {
        Some(_) => {
            let arr = obj.get_array("results")?;
            if arr.is_empty() {
                None
            } else {
                let mut out = Vec::new();
                for r in arr {
                    let r = r.as_object().ok_or("JSONArray[i] is not a JSONObject.")?;
                    if !r.has("id") || !r.has("result") {
                        return Err("Se obtuvo un resultado parcial sin identificador o resultado".into());
                    }
                    let result = r.get_string("result")?.to_string();
                    if !RESULT_NAMES.contains(&result.as_str()) {
                        return Err("Estado de firma trifasica desconocido".into());
                    }
                    let id = r.get_string("id")?.to_string();
                    let description = match r.get("description") {
                        Some(_) => Some(r.get_string("description")?.to_string()),
                        None => None,
                    };
                    out.push(PresignResult { id, result, description });
                }
                Some(out)
            }
        }
        None => None,
    };
    Ok(PresignBatch { td, results })
}

fn results_json(results: &[PresignResult]) -> String {
    let signs: Vec<JsonValue> = results
        .iter()
        .map(|r| {
            let mut o = JsonObject::new();
            o.put("id", JsonValue::str(r.id.clone()));
            o.put("result", JsonValue::str(r.result.clone()));
            if let Some(d) = &r.description {
                o.put("description", JsonValue::str(d.clone()));
            }
            JsonValue::Object(o)
        })
        .collect();
    let mut main = JsonObject::new();
    main.put("signs", JsonValue::Array(signs));
    main.to_org_json()
}

/// `JSONBatchInfo.updateResults`: marca en el lote las firmas que ya
/// fallaron en la prefirma.
pub fn update_batch_results(batch: &[u8], results: &[PresignResult]) -> Result<String, String> {
    let mut obj = json_lenient::parse_object_bytes(batch).map_err(|e| format!("El JSON del lote de firmas no esta formado correctamente: {e}"))?;
    let Some(JsonValue::Array(signs)) = obj.0.iter_mut().find(|(k, _)| k == "singlesigns").map(|(_, v)| v) else {
        return Err("JSONObject[\"singlesigns\"] not found.".into());
    };
    for s in signs.iter_mut() {
        let JsonValue::Object(single) = s else { return Err("JSONArray[i] is not a JSONObject.".into()) };
        let id = single.get_string("id")?.to_string();
        if let Some(r) = results.iter().find(|r| r.id == id) {
            for k in ["datareference", "format", "suboperation", "extraparams"] {
                single.remove(k);
            }
            single.put("result", JsonValue::str(r.result.clone()));
            if let Some(d) = &r.description {
                single.put("description", JsonValue::str(d.clone()));
            }
        }
    }
    Ok(obj.to_org_json())
}

/// Algoritmo del lote JSON (`getAlgorithmForJSON`).
pub fn json_batch_algorithm(batch: &[u8]) -> Result<String, String> {
    let obj = json_lenient::parse_object_bytes(batch)?;
    if !obj.has("algorithm") {
        return Err("El nodo 'signbatch' debe contener al manos el atributo de algoritmo".into());
    }
    Ok(obj.get_string("algorithm")?.to_string())
}

/// Algoritmo del lote XML (`getAlgorithmForXML`): atributo `algorithm` del
/// elemento raíz `signbatch`.
pub fn xml_batch_algorithm(batch: &[u8]) -> Result<String, String> {
    let (doc, _) = Document::parse_bytes(batch).map_err(|e| format!("Error al cargar el fichero XML de lote: {e}"))?;
    if doc.doctype.is_some() {
        return Err("Error al cargar el fichero XML de lote: DOCTYPE no permitido".into());
    }
    let root = doc.document_element().ok_or("XML sin raíz")?;
    let el = doc.element(root).ok_or("XML sin raíz")?;
    if !el.qname().eq_ignore_ascii_case("signbatch") {
        return Err("No se encontro el nodo 'signbatch' en el XML proporcionado".into());
    }
    el.attrs
        .iter()
        .find(|a| a.qname() == "algorithm")
        .map(|a| a.value.clone())
        .ok_or_else(|| "El nodo 'signbatch' debe contener al manos el atributo de algoritmo".into())
}

struct PhaseCodes {
    bad_params: ErrorCode,
    comm: ErrorCode,
    server: ErrorCode,
    timeout: ErrorCode,
    conn: ErrorCode,
}

const JSON_PRE: PhaseCodes = PhaseCodes {
    bad_params: codes::INVALID_PARAMS_TO_PRESIGN_JSON_BATCH,
    comm: codes::JSON_BATCH_PRESIGN_COMMUNICATION_ERROR,
    server: codes::JSON_BATCH_PRESIGN_ERROR,
    timeout: codes::JSON_BATCH_PRESIGN_TIMEOUT,
    conn: codes::JSON_BATCH_PRESIGN_CONNECTION_ERROR,
};
const JSON_POST: PhaseCodes = PhaseCodes {
    bad_params: codes::INVALID_PARAMS_TO_POSTSIGN_JSON_BATCH,
    comm: codes::JSON_BATCH_POSTSIGN_COMMUNICATION_ERROR,
    server: codes::JSON_BATCH_POSTSIGN_ERROR,
    timeout: codes::JSON_BATCH_POSTSIGN_TIMEOUT,
    conn: codes::JSON_BATCH_POSTSIGN_CONNECTION_ERROR,
};
const XML_PRE: PhaseCodes = PhaseCodes {
    bad_params: codes::INVALID_PARAMS_TO_PRESIGN_XML_BATCH,
    comm: codes::XML_BATCH_PRESIGN_COMMUNICATION_ERROR,
    server: codes::XML_BATCH_PRESIGN_ERROR,
    timeout: codes::XML_BATCH_PRESIGN_TIMEOUT,
    conn: codes::XML_BATCH_PRESIGN_CONNECTION_ERROR,
};
const XML_POST: PhaseCodes = PhaseCodes {
    bad_params: codes::INVALID_PARAMS_TO_POSTSIGN_XML_BATCH,
    comm: codes::XML_BATCH_POSTSIGN_COMMUNICATION_ERROR,
    server: codes::XML_BATCH_POSTSIGN_ERROR,
    timeout: codes::XML_BATCH_POSTSIGN_TIMEOUT,
    conn: codes::XML_BATCH_POSTSIGN_CONNECTION_ERROR,
};

fn map_http(e: HttpError, c: &PhaseCodes, what: &str) -> AfirmaError {
    let code = match &e {
        HttpError::Status { code: 400, .. } => c.bad_params,
        HttpError::Status { code, .. } if code / 100 == 4 => c.comm,
        HttpError::Status { .. } => c.server,
        HttpError::Timeout(_) => c.timeout,
        _ => c.conn,
    };
    AfirmaError::new(code, format!("Error en la llamada al servicio de {what}")).with_cause(e)
}

/// Error de un lote que no es `AfirmaError` en Java (`JSONException`,
/// `IOException`...): el lanzador lo convierte en el error interno del lote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// Error con código (`AOException`).
    Afirma(AfirmaError),
    /// Excepción no controlada (JSON mal formado de la respuesta...).
    Internal(String),
    /// `IllegalArgumentException` (600420).
    InvalidArgument(String),
}

impl From<AfirmaError> for BatchError {
    fn from(e: AfirmaError) -> Self {
        BatchError::Afirma(e)
    }
}

/// `BatchSigner.signJSON`: prefirma, firma PKCS#1 y postfirma de un lote
/// JSON. Devuelve el cuerpo de la respuesta de la postfirma.
pub fn sign_json_batch(
    http: &HttpClient,
    batch: &[u8],
    presigner_url: &str,
    postsigner_url: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
) -> Result<String, BatchError> {
    if batch.is_empty() {
        return Err(BatchError::InvalidArgument("El lote de firma no puede ser nulo ni vacio".into()));
    }
    let chain = key.certificate_chain();
    if chain.is_empty() {
        return Err(BatchError::InvalidArgument("La cadena de certificados del firmante no puede ser nula ni vacia".into()));
    }
    let algorithm = json_batch_algorithm(batch).map_err(|e| {
        AfirmaError::new(codes::MALFORMED_JSON_BATCH, "El lote proporcionado no es un JSON bien formado o no tiene la estructura correcta").with_cause(e)
    })?;
    let certs = batch_cert_chain(&chain);
    let mut batch_b64 = jbase64::encode_url_safe(batch);
    let pre_http = http.with_ssl_error_handling(afirma_core::http::SslErrorHandling::from_extra_params(extra));
    let ret = pre_http
        .post(presigner_url, &format!("json={batch_b64}&certs={certs}"))
        .map_err(|e| map_http(e, &JSON_PRE, "prefirma de lotes JSON"))?;
    let presign = parse_presign_response(&ret).map_err(BatchError::Internal)?;
    let Some(mut td) = presign.td else {
        return Ok(match presign.results {
            None => "{\"signs\":[]}".to_string(),
            Some(r) => results_json(&r),
        });
    };
    if let Some(results) = &presign.results {
        batch_b64 = jbase64::encode_url_safe(update_batch_results(batch, results).map_err(BatchError::Internal)?.as_bytes());
    }
    td.sign_all(key, &algorithm)?;
    let tridata = jbase64::encode_url_safe(td.to_json().as_bytes());
    let ret = http
        .with_ssl_error_handling(afirma_core::http::SslErrorHandling::None)
        .post(postsigner_url, &format!("json={batch_b64}&certs={certs}&tridata={tridata}"))
        .map_err(|e| map_http(e, &JSON_POST, "postfirma de lotes JSON"))?;
    Ok(String::from_utf8_lossy(&ret).into_owned())
}

/// `BatchSigner.signXML`: lote XML (servidores antiguos `BatchPresigner` /
/// `BatchPostsigner`).
pub fn sign_xml_batch(
    http: &HttpClient,
    batch: &[u8],
    presigner_url: &str,
    postsigner_url: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
) -> Result<String, BatchError> {
    if batch.is_empty() {
        return Err(BatchError::InvalidArgument("El lote de firma no puede ser nulo ni vacio".into()));
    }
    let chain = key.certificate_chain();
    if chain.is_empty() {
        return Err(BatchError::InvalidArgument("La cadena de certificados del firmante no puede ser nula ni vacia".into()));
    }
    let algorithm = xml_batch_algorithm(batch).map_err(|e| {
        AfirmaError::new(codes::MALFORMED_XML_BATCH, "El lote proporcionado no es un XML bien formado o no tiene la estructura correcta").with_cause(e)
    })?;
    let certs = batch_cert_chain(&chain);
    let batch_b64 = jbase64::encode_url_safe(batch);
    let pre_http = http.with_ssl_error_handling(afirma_core::http::SslErrorHandling::from_extra_params(extra));
    let ret = pre_http
        .post(presigner_url, &format!("xml={batch_b64}&certs={certs}"))
        .map_err(|e| map_http(e, &XML_PRE, "prefirma de lotes XML"))?;
    let mut td = TriphaseData::parse_xml(&ret).map_err(|e| {
        if e.0.contains("'firmas'") { BatchError::InvalidArgument(e.0) } else { BatchError::Internal(e.0) }
    })?;
    td.sign_all(key, &algorithm)?;
    let tridata = jbase64::encode_url_safe(td.to_xml().as_bytes());
    let ret = http
        .with_ssl_error_handling(afirma_core::http::SslErrorHandling::None)
        .post(postsigner_url, &format!("xml={batch_b64}&certs={certs}&tridata={tridata}"))
        .map_err(|e| map_http(e, &XML_POST, "postfirma de lotes XML"))?;
    Ok(String::from_utf8_lossy(&ret).into_owned())
}

/// Firma individual de un lote local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSingleSign {
    pub id: String,
    pub data: Vec<u8>,
    /// `None` si la suboperación no es válida (Java falla al firmar con 200412).
    pub operation: Option<CryptoOperation>,
    pub format: String,
    pub algorithm: String,
    pub extra_params: ExtraParams,
}

/// Lote local (`BatchSignOperation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBatch {
    pub stop_on_error: bool,
    pub signs: Vec<LocalSingleSign>,
}

/// Error del análisis del lote local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalBatchParseError {
    /// JSON mal formado (`JSONException` → 200412).
    InvalidJson(String),
    /// Estructura incorrecta (600419).
    Malformed(String),
}

/// `expanExtraParams`: Base64 estándar → UTF-8 → `trim` → `\n` literales a
/// saltos de línea → `.properties`. Java lo cargaba como ISO-8859-1 y
/// corrompía los caracteres no ASCII; aquí se respeta el UTF-8.
fn expand_batch_extra_params(b64: &str) -> Result<Option<ExtraParams>, String> {
    if b64.is_empty() {
        return Ok(None);
    }
    let bytes = jbase64::decode(b64).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes);
    let clean = crate::triphase::data::java_trim(&text).replace("\\n", "\n");
    Ok(Some(ExtraParams::parse(&clean)))
}

/// `JSONBatchManager.parseBatchConfig`.
pub fn parse_local_batch(batch: &[u8]) -> Result<LocalBatch, LocalBatchParseError> {
    let obj = json_lenient::parse_object_bytes(batch).map_err(LocalBatchParseError::InvalidJson)?;
    parse_local_batch_obj(&obj).map_err(LocalBatchParseError::Malformed)
}

fn parse_local_batch_obj(json: &JsonObject) -> Result<LocalBatch, String> {
    let stop_on_error = json.has("stoponerror") && json.get_boolean("stoponerror")?;
    let sub_op = if json.has("suboperation") { CryptoOperation::parse(json.get_string("suboperation")?) } else { Some(CryptoOperation::Sign) };
    if !json.has("format") {
        return Err("El lote no declaraba el formato de firma".into());
    }
    let format = json.get_string("format")?.to_string();
    if !json.has("algorithm") {
        return Err("El lote no declaraba el algoritmo de firma".into());
    }
    let algorithm = json.get_string("algorithm")?.to_string();
    let extra = if json.has("extraparams") { expand_batch_extra_params(json.get_string("extraparams")?)? } else { None };
    let mut signs = Vec::new();
    for item in json.get_array("singlesigns")? {
        let s = item.as_object().ok_or("JSONArray[i] is not a JSONObject.")?;
        if !s.has("id") {
            return Err("No se ha incluido el identificador de un documento del lote".into());
        }
        let id = s.get_string("id")?.to_string();
        if !s.has("datareference") {
            return Err("No se ha incluido la referencia de un documento del lote".into());
        }
        let data = jbase64::decode(s.get_string("datareference")?).map_err(|e| e.to_string())?;
        let operation = if s.has("suboperation") { CryptoOperation::parse(s.get_string("suboperation")?) } else { sub_op };
        let format = if s.has("format") { s.get_string("format")?.to_string() } else { format.clone() };
        let extra_params = if s.has("extraparams") {
            expand_batch_extra_params(s.get_string("extraparams")?)?.unwrap_or_default()
        } else {
            extra.clone().unwrap_or_default()
        };
        signs.push(LocalSingleSign { id, data, operation, format, algorithm: algorithm.clone(), extra_params });
    }
    Ok(LocalBatch { stop_on_error, signs })
}

/// Resultado de una firma del lote local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSingleResult {
    pub id: String,
    pub result: &'static str,
    pub description: Option<String>,
    pub signature: Option<Vec<u8>>,
}

/// `LocalBatchSigner.signLocalBatch`: firma secuencial con la semántica de
/// `stoponerror` (al primer error, los anteriores pasan a `SKIPPED` sin
/// firma, el erróneo es `ERROR_PRE` y los siguientes `SKIPPED`).
pub fn run_local_batch(batch: &LocalBatch, mut sign: impl FnMut(&LocalSingleSign) -> Result<Vec<u8>, String>) -> Vec<LocalSingleResult> {
    let mut results: Vec<LocalSingleResult> = Vec::new();
    let mut error = false;
    for s in &batch.signs {
        if error && batch.stop_on_error {
            results.push(LocalSingleResult { id: s.id.clone(), result: "SKIPPED", description: None, signature: None });
            continue;
        }
        match sign(s) {
            Ok(sig) => results.push(LocalSingleResult { id: s.id.clone(), result: "DONE_AND_SAVED", description: None, signature: Some(sig) }),
            Err(description) => {
                error = true;
                if batch.stop_on_error {
                    for r in &mut results {
                        r.result = "SKIPPED";
                        r.signature = None;
                    }
                }
                results.push(LocalSingleResult { id: s.id.clone(), result: "ERROR_PRE", description: Some(description), signature: None });
            }
        }
    }
    results
}

/// `JSONBatchManager.buildBatchResultJson`.
pub fn local_batch_result_json(results: &[LocalSingleResult]) -> String {
    let signs: Vec<JsonValue> = results
        .iter()
        .map(|r| {
            let mut o = JsonObject::new();
            o.put("id", JsonValue::str(r.id.clone()));
            o.put("result", JsonValue::str(r.result));
            if let Some(d) = &r.description {
                o.put("description", JsonValue::str(d.clone()));
            }
            if let Some(s) = &r.signature {
                o.put("signature", JsonValue::str(jbase64::encode(s)));
            }
            JsonValue::Object(o)
        })
        .collect();
    let mut main = JsonObject::new();
    main.put("signs", JsonValue::Array(signs));
    main.to_org_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presign_parsing() {
        let p = parse_presign_response(br#"{"td":{"format":"XAdES","signs":[{"signinfo":[{"id":"a1","params":{"PRE":"AA=="}}]}]},"results":[{"id":"a2","result":"ERROR_PRE","description":"mal"}]}"#).unwrap();
        assert_eq!(p.td.unwrap().signs[0].id.as_deref(), Some("a1"));
        assert_eq!(p.results.unwrap()[0].description.as_deref(), Some("mal"));
        assert_eq!(parse_presign_response(b"{\"results\":[]}").unwrap(), PresignBatch { td: None, results: None });
        assert!(parse_presign_response(br#"{"results":[{"id":"x","result":"RARO"}]}"#).is_err());
        assert!(parse_presign_response(br#"{"results":[{"id":"x"}]}"#).is_err());
        assert!(parse_presign_response(b"no json").is_err());
        assert_eq!(
            results_json(&[PresignResult { id: "a2".into(), result: "ERROR_PRE".into(), description: None }]),
            r#"{"signs":[{"result":"ERROR_PRE","id":"a2"}]}"#
        );
    }

    #[test]
    fn update_results() {
        let batch = br#"{"algorithm":"SHA256withRSA","format":"XAdES","singlesigns":[{"id":"a1","datareference":"AA==","format":"XAdES"},{"id":"a2","datareference":"AQ=="}]}"#;
        let out = update_batch_results(batch, &[PresignResult { id: "a2".into(), result: "ERROR_PRE".into(), description: Some("d".into()) }]).unwrap();
        let o = json_lenient::parse_object(&out).unwrap();
        let signs = o.get_array("singlesigns").unwrap();
        let a2 = signs[1].as_object().unwrap();
        assert!(!a2.has("datareference"));
        assert_eq!(a2.get_string("result"), Ok("ERROR_PRE"));
        assert_eq!(a2.get_string("description"), Ok("d"));
        assert!(signs[0].as_object().unwrap().has("datareference"));
    }

    #[test]
    fn algorithms() {
        assert_eq!(json_batch_algorithm(br#"{"algorithm":"SHA256"}"#).unwrap(), "SHA256");
        assert!(json_batch_algorithm(br#"{"format":"x"}"#).is_err());
        assert!(json_batch_algorithm(br#"{"algorithm":256}"#).is_err());
        assert_eq!(xml_batch_algorithm(b"<SignBatch algorithm=\"SHA512\"><singlesign/></SignBatch>").unwrap(), "SHA512");
        assert!(xml_batch_algorithm(b"<lote algorithm=\"SHA512\"/>").is_err());
        assert!(xml_batch_algorithm(b"<signbatch/>").is_err());
    }

    #[test]
    fn local_batch() {
        let props = jbase64::encode("mode=implicit\\nlayer2Text=ñ".as_bytes());
        let json = format!(
            r#"{{"algorithm":"SHA256","format":"CAdES","suboperation":"sign","extraparams":"{props}","stoponerror":"true","singlesigns":[{{"id":"1","datareference":"SG9sYQ=="}},{{"id":"2","datareference":"SG9sYQ==","suboperation":"raro","format":"XAdES","extraparams":""}},{{"id":"3","datareference":"SG9sYQ=="}}]}}"#
        );
        let b = parse_local_batch(json.as_bytes()).unwrap();
        assert!(b.stop_on_error);
        assert_eq!(b.signs[0].extra_params.get("layer2Text"), Some("ñ"));
        assert_eq!(b.signs[0].extra_params.get("mode"), Some("implicit"));
        assert_eq!(b.signs[1].operation, None);
        assert_eq!(b.signs[1].format, "XAdES");
        assert!(b.signs[1].extra_params.is_empty());
        let results = run_local_batch(&b, |s| if s.id == "2" { Err("fallo".into()) } else { Ok(vec![1, 2]) });
        let names: Vec<&str> = results.iter().map(|r| r.result).collect();
        assert_eq!(names, ["SKIPPED", "ERROR_PRE", "SKIPPED"]);
        assert!(results[0].signature.is_none());
        let json = local_batch_result_json(&results);
        assert_eq!(json, r#"{"signs":[{"result":"SKIPPED","id":"1"},{"result":"ERROR_PRE","description":"fallo","id":"2"},{"result":"SKIPPED","id":"3"}]}"#);
        // Sin stoponerror.
        let mut b2 = b.clone();
        b2.stop_on_error = false;
        let results = run_local_batch(&b2, |s| if s.id == "2" { Err("fallo".into()) } else { Ok(vec![1, 2]) });
        let names: Vec<&str> = results.iter().map(|r| r.result).collect();
        assert_eq!(names, ["DONE_AND_SAVED", "ERROR_PRE", "DONE_AND_SAVED"]);
        assert!(local_batch_result_json(&results).contains(r#""signature":"AQI=""#));
        // Errores de análisis.
        assert!(matches!(parse_local_batch(b"{"), Err(LocalBatchParseError::InvalidJson(_))));
        assert!(matches!(parse_local_batch(br#"{"algorithm":"SHA256","singlesigns":[]}"#), Err(LocalBatchParseError::Malformed(_))));
        assert!(matches!(
            parse_local_batch(br#"{"algorithm":"SHA256","format":"CAdES","singlesigns":[{"id":"1","datareference":"-_8="}]}"#),
            Err(LocalBatchParseError::Malformed(_))
        ));
    }
}
