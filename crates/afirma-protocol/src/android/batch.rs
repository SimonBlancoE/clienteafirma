//! Firma de lotes JSON contra un servidor de lotes como la hace Autofirma App
//! 1.9 (`BatchSigner.signJSON`, `JSONPreSignBatchParser`, `JSONBatchInfo`,
//! `TriphaseDataParser`; `docs/spec/09-android.md` §6.4).
//!
//! Orden de la app: validaciones → prefirma (`json=<lote B64U>&certs=<cadena>`)
//! → análisis de `td`/`results` → reescritura del lote si hubo resultados
//! parciales → algoritmo del lote → PKCS#1 de cada `PRE` → postfirma
//! (`json=…&certs=…&tridata=<B64U del JSON de la sesión>`) → cuerpo de la
//! respuesta tal cual. Los JSON que genera la app usan `org.json` de Android:
//! claves en orden de inserción y `/` escapado como `\/` ([`android_json`]).
//!
//! Correcciones (documentadas):
//! - Java leía el algoritmo y reescribía el lote decodificando el Base64
//!   **URL-safe** del lote con el decodificador **estándar**, que descarta `-`
//!   y `_` y corrompe el JSON: casi cualquier lote real fallaba después de la
//!   prefirma (error genérico `ERR-14`). Aquí se usan los datos originales.
//! - El `signid` de cada firma se conserva en la postfirma (§10 n.º 51).

use afirma_core::error::codes;
use afirma_core::{AfirmaError, SigningKey};

use crate::batch::{PresignResult, batch_cert_chain, json_batch_algorithm, parse_presign_response};
use crate::http::{HttpClient, HttpError};
use crate::json_lenient::{self, JsonObject, JsonValue};
use crate::triphase::data::TriphaseData;

/// Fallo del lote con la clasificación que usa la app para elegir la
/// respuesta (`SignBatchTask` y `WebSignBatchActivity.onSigningError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchFailure {
    /// `IllegalArgumentException`: datos o URL ausentes, sin certificados,
    /// algoritmo ausente o HTTP 400 del servidor. → `ERR-14` AA200002.
    #[error("Los datos proporcionados al servicio no son validos: {0}")]
    InvalidArgument(String),
    /// `HttpError` 4xx distinto de 400. → `ERR-18` AA400001.
    #[error("No se pudo conectar con el servicio de firma de lotes: {0}")]
    HttpClientError(HttpError),
    /// `AOException` (5xx, errores de la firma PKCS#1…). → `ERR-14` AA200002.
    #[error("El servicio de firma de lotes devolvio un error: {0}")]
    Signing(String),
    /// PIN erróneo de la tarjeta: la app vuelve a pedir el certificado.
    #[error("PIN incorrecto: {0}")]
    BadPin(String),
    /// Cancelación del usuario. → `ERR-11` AA500001.
    #[error("Operacion cancelada por el usuario")]
    Cancelled,
    /// Cualquier otro error (red, JSON mal formado…). → `ERR-14` AA200002.
    #[error("{0}")]
    Other(String),
}

impl BatchFailure {
    fn from_http(e: HttpError) -> Self {
        match e.status() {
            Some(400) => BatchFailure::InvalidArgument(format!("AA600006 - {e}")),
            Some(c) if c / 100 == 4 => BatchFailure::HttpClientError(e),
            Some(_) => BatchFailure::Signing(format!("AA200002 - {e}")),
            None => BatchFailure::Other(e.to_string()),
        }
    }

    /// Error de la firma PKCS#1 o de la clave.
    pub fn from_afirma(e: AfirmaError) -> Self {
        if e.is_cancelled() {
            BatchFailure::Cancelled
        } else if e.code == Some(codes::INVALID_SMARTCARD_PIN) {
            BatchFailure::BadPin(e.to_string())
        } else {
            BatchFailure::Signing(e.to_string())
        }
    }
}

/// `BatchSigner.signJSON`.
pub fn sign_json_batch(
    http: &HttpClient,
    batch: &[u8],
    presigner_url: Option<&str>,
    postsigner_url: Option<&str>,
    key: &dyn SigningKey,
) -> Result<Vec<u8>, BatchFailure> {
    let batch_b64 = afirma_core::base64::encode_url_safe(batch);
    if batch_b64.is_empty() {
        return Err(BatchFailure::InvalidArgument(
            "600400 - No se ha recibido los datos en la petición ni el id del fichero a descargar para la operacion de firma de lotes".into(),
        ));
    }
    let pre = presigner_url.filter(|u| !u.is_empty()).ok_or_else(|| {
        BatchFailure::InvalidArgument("600405 - No se ha recibido el batchpresignerurl en la firma batch".into())
    })?;
    let post = postsigner_url.filter(|u| !u.is_empty()).ok_or_else(|| {
        BatchFailure::InvalidArgument("600406 - No se ha recibido el batchpostsignerurl en la firma batch".into())
    })?;
    let chain = key.certificate_chain();
    if chain.is_empty() {
        return Err(BatchFailure::InvalidArgument(
            "501001 - Error en la operacion, no hay certificados".into(),
        ));
    }
    let certs = batch_cert_chain(&chain);
    let ret = http
        .post(pre, &format!("json={batch_b64}&certs={certs}"))
        .map_err(BatchFailure::from_http)?;
    let presign = parse_presign_response(&ret).map_err(BatchFailure::Other)?;
    let Some(mut td) = presign.td else {
        return Ok(match presign.results {
            None => "{\"signs\":[]}".as_bytes().to_vec(),
            Some(r) => results_json(&r).into_bytes(),
        });
    };
    let mut batch_url_safe = batch_b64;
    if let Some(results) = &presign.results {
        let updated = update_batch_results(batch, results).map_err(BatchFailure::Other)?;
        batch_url_safe = afirma_core::base64::encode_url_safe(updated.as_bytes());
    }
    let algorithm = json_batch_algorithm(batch).map_err(|e| {
        if e.contains("algoritmo") {
            BatchFailure::InvalidArgument(format!("600408 - {e}"))
        } else {
            BatchFailure::Other(format!(
                "600407 - El data de la operacion de firma batch no es un JSON valido: {e}"
            ))
        }
    })?;
    td.sign_all(key, &algorithm).map_err(BatchFailure::from_afirma)?;
    let tridata = afirma_core::base64::encode_url_safe(tridata_json(&td).as_bytes());
    let ret = http
        .post(post, &format!("json={batch_url_safe}&certs={certs}&tridata={tridata}"))
        .map_err(BatchFailure::from_http)?;
    Ok(ret)
}

/// `JSONBatchInfoParser.buildResult`: `{"signs":[{"id":…,"result":…[,"description":…]}]}`.
pub fn results_json(results: &[PresignResult]) -> String {
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
    android_json(&main)
}

/// `JSONBatchInfo.updateResults` + `getInfoString`: cada `singlesigns[i]` con
/// resultado parcial pierde `datareference`, `format`, `suboperation` y
/// `extraparams` y gana `result` (y `description`).
pub fn update_batch_results(batch: &[u8], results: &[PresignResult]) -> Result<String, String> {
    let mut obj = json_lenient::parse_object_bytes(batch)
        .map_err(|e| format!("El JSON del lote de firmas no esta formado correctamente: {e}"))?;
    let Some(JsonValue::Array(signs)) = obj.0.iter_mut().find(|(k, _)| k == "singlesigns").map(|(_, v)| v) else {
        return Err("JSONObject[\"singlesigns\"] not found.".into());
    };
    for s in signs.iter_mut() {
        let JsonValue::Object(single) = s else {
            return Err("JSONArray[i] is not a JSONObject.".into());
        };
        let id = match single.get("id") {
            Some(JsonValue::Str(s)) => s.clone(),
            Some(JsonValue::Num(n)) => n.clone(),
            _ => return Err("JSONObject[\"id\"] not found.".into()),
        };
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
    Ok(android_json(&obj))
}

/// `TriphaseDataParser.triphaseDataToJson` (con `signid`, ver el módulo).
pub fn tridata_json(td: &TriphaseData) -> String {
    let mut infos = Vec::new();
    for s in &td.signs {
        let mut info = JsonObject::new();
        if let Some(id) = &s.id {
            info.put("id", JsonValue::str(id.clone()));
        }
        if let Some(sid) = &s.signid {
            info.put("signid", JsonValue::str(sid.clone()));
        }
        let mut params = JsonObject::new();
        for (k, v) in s.params_java_order() {
            params.put(k, JsonValue::str(v));
        }
        info.put("params", JsonValue::Object(params));
        infos.push(JsonValue::Object(info));
    }
    let mut obj = JsonObject::new();
    // `JSONObject.put(nombre, null)` de Android elimina la clave.
    if let Some(f) = &td.format {
        obj.put("format", JsonValue::str(f.clone()));
    }
    obj.put("signinfo", JsonValue::Array(infos));
    android_json(&obj)
}

/// `JSONObject.toString()` de `org.json` de Android: compacto, claves en orden
/// de inserción, `"`, `\` y `/` escapados con `\`, `\t \b \n \r \f` con su
/// escape y el resto de controles como `\u00XX`. Los números enteros se
/// normalizan como `Long.toString` (los demás se conservan tal cual).
pub fn android_json(obj: &JsonObject) -> String {
    let mut out = String::new();
    write_object(obj, &mut out);
    out
}

fn write_object(o: &JsonObject, out: &mut String) {
    out.push('{');
    for (i, (k, v)) in o.0.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        quote(k, out);
        out.push(':');
        write_value(v, out);
    }
    out.push('}');
}

fn write_value(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Str(s) => quote(s, out),
        JsonValue::Num(n) => out.push_str(&android_number(n)),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Null => out.push_str("null"),
        JsonValue::Object(o) => write_object(o, out),
        JsonValue::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
    }
}

fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' | '/' => {
                out.push('\\');
                out.push(c);
            }
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) <= 0x1f => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Números enteros como los lee `JSONTokener.readLiteral` (decimal, `0x`
/// hexadecimal o `0` octal) y los escribe `numberToString`.
fn android_number(text: &str) -> String {
    if !text.contains(['.', 'e', 'E']) {
        let (neg, body) = match text.strip_prefix('-') {
            Some(b) => (true, b),
            None => (false, text),
        };
        let parsed = if let Some(h) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            i64::from_str_radix(h, 16).ok()
        } else if body.len() > 1 && body.starts_with('0') {
            i64::from_str_radix(&body[1..], 8).ok()
        } else {
            body.parse::<i64>().ok()
        };
        if let Some(v) = parsed {
            return (if neg { -v } else { v }).to_string();
        }
    }
    text.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triphase::data::TriSign;

    #[test]
    fn android_serialization() {
        let obj = json_lenient::parse_object(r#"{"z":"a/b","a":[1,010,-2,1.50,true,null],"m":{"q":"\"\\\n\u0001"}}"#)
            .unwrap();
        assert_eq!(
            android_json(&obj),
            r#"{"z":"a\/b","a":[1,8,-2,1.50,true,null],"m":{"q":"\"\\\n\u0001"}}"#
        );
    }

    #[test]
    fn partial_results_rewrite() {
        let batch = br#"{"algorithm":"SHA256withRSA","format":"CAdES","singlesigns":[{"id":"1","datareference":"QQ==","format":"PAdES","extraparams":"","suboperation":"sign"},{"id":"2","datareference":"https://x/y"}]}"#;
        let r = vec![PresignResult {
            id: "1".into(),
            result: "ERROR_PRE".into(),
            description: Some("falla/1".into()),
        }];
        assert_eq!(
            update_batch_results(batch, &r).unwrap(),
            r#"{"algorithm":"SHA256withRSA","format":"CAdES","singlesigns":[{"id":"1","result":"ERROR_PRE","description":"falla\/1"},{"id":"2","datareference":"https:\/\/x\/y"}]}"#
        );
        assert_eq!(
            results_json(&r),
            r#"{"signs":[{"id":"1","result":"ERROR_PRE","description":"falla\/1"}]}"#
        );
    }

    #[test]
    fn tridata_keeps_signid() {
        let mut s = TriSign::new(Some("1".into()), Some("S1".into()));
        s.set("PK1", "a/b=");
        let td = TriphaseData {
            format: None,
            signs: vec![s],
        };
        assert_eq!(
            tridata_json(&td),
            r#"{"signinfo":[{"id":"1","signid":"S1","params":{"PK1":"a\/b="}}]}"#
        );
    }

    #[test]
    fn http_classification() {
        let st = |code| HttpError::Status {
            code,
            reason: "x".into(),
            body: vec![],
            url: "u".into(),
        };
        assert!(matches!(
            BatchFailure::from_http(st(400)),
            BatchFailure::InvalidArgument(_)
        ));
        assert!(matches!(
            BatchFailure::from_http(st(404)),
            BatchFailure::HttpClientError(_)
        ));
        assert!(matches!(BatchFailure::from_http(st(503)), BatchFailure::Signing(_)));
        assert!(matches!(
            BatchFailure::from_http(HttpError::Io("x".into())),
            BatchFailure::Other(_)
        ));
        assert_eq!(
            BatchFailure::from_afirma(AfirmaError::cancelled()),
            BatchFailure::Cancelled
        );
    }
}
