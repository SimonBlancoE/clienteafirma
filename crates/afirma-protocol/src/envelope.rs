//! Sobres de las peticiones indirectas (`fileid`): descarga del
//! RetrieveService, descifrado y análisis del XML (o JSON) de parámetros.

use afirma_core::error::codes;
use afirma_xml::dom::{Document, NodeKind};

use crate::cipher::ServerCipher;
use crate::errors::ProtocolError;
use crate::http::HttpClient;
use crate::intermediate;
use crate::json_lenient::{self, JsonValue};
use crate::query::Params;
use crate::request::OperationKind;

/// Analiza el sobre XML (`ProtocolInvocationUriParserUtil.parseXml`):
/// `<op><e k=".." v=".."/>...</op>`. El nombre del elemento raíz es el
/// valor inicial de `op` (`SIGN` si el raíz se llama `op`); los valores se
/// guardan sin decodificar (se aplican las reglas de `URLDecoder` al leerlos).
///
/// A diferencia de Java, se ignoran los nodos de texto en blanco y los
/// comentarios entre elementos (Java fallaba).
pub fn parse_xml_envelope(xml: &[u8]) -> Result<Params, String> {
    let (doc, _) = Document::parse_bytes(xml).map_err(|e| e.to_string())?;
    if doc.doctype.is_some() {
        return Err("DOCTYPE no permitido".into());
    }
    let root = doc.document_element().ok_or("sin elemento raíz")?;
    let root_el = doc.element(root).ok_or("sin elemento raíz")?;
    let root_name = root_el.qname();
    let mut pairs = vec![(
        "op".to_string(),
        if root_name.eq_ignore_ascii_case("op") {
            "SIGN".to_string()
        } else {
            root_name
        },
    )];
    for &child in doc.children(root) {
        match doc.kind(child) {
            NodeKind::Element(el) => {
                if el.qname() != "e" {
                    return Err(format!("Elemento no esperado: {}", el.qname()));
                }
                let k = el.attrs.iter().find(|a| a.qname() == "k").map(|a| a.value.clone());
                let v = el.attrs.iter().find(|a| a.qname() == "v").map(|a| a.value.clone());
                match (k, v) {
                    (Some(k), Some(v)) => pairs.push((k, v)),
                    _ => return Err("Elemento 'e' sin atributos 'k' y 'v'".into()),
                }
            }
            NodeKind::Text { text, .. } if text.trim().is_empty() => {}
            NodeKind::Comment(_) => {}
            _ => return Err("Nodo no esperado en el XML de la operacion".into()),
        }
    }
    Ok(Params::from_raw_pairs(pairs))
}

/// Analiza el sobre JSON (`TriphaseDataParser.parseParamsListJson`):
/// `{"params":[{"k":..,"v":..}]}`.
pub fn parse_json_envelope(json: &[u8]) -> Result<Params, String> {
    let obj = json_lenient::parse_object_bytes(json)?;
    let mut pairs = Vec::new();
    for item in obj.get_array("params")? {
        let Some(o) = item.as_object() else {
            return Err("JSONArray[i] is not a JSONObject.".into());
        };
        if o.has("k") && o.has("v") {
            let k = o.get_string("k")?.to_string();
            let v = match o.get("v") {
                Some(JsonValue::Str(s)) => s.clone(),
                _ => return Err("v no es una cadena".into()),
            };
            pairs.push((k, v));
        }
    }
    Ok(Params::from_raw_pairs(pairs))
}

/// Analiza un sobre XML o JSON según su primer carácter significativo.
pub fn parse_envelope(data: &[u8]) -> Result<Params, String> {
    let first = data.iter().find(|b| !b.is_ascii_whitespace()).copied();
    if first == Some(b'{') {
        parse_json_envelope(data)
    } else {
        parse_xml_envelope(data)
    }
}

/// Descarga, descifra y analiza el sobre de una operación
/// (`getDataFromRetrieveServlet` + análisis).
pub fn fetch_envelope(
    http: &HttpClient,
    retrieve_servlet: &str,
    file_id: &str,
    cipher_config: Option<&[u8]>,
    kind: OperationKind,
) -> Result<Params, ProtocolError> {
    let (io_code, timeout_code) = kind.retrieve_errors();
    let body = intermediate::retrieve(http, retrieve_servlet, file_id).map_err(|e| {
        let code = if e.is_timeout() { timeout_code } else { io_code };
        ProtocolError::operation(
            code,
            format!("Error al recuperar los datos enviados por el cliente a traves del servidor intermedio: {e}"),
        )
    })?;
    if intermediate::is_error_response(&body) {
        return Err(ProtocolError::operation(
            codes::ERROR_RECIVED_FROM_CLIENT,
            format!(
                "Se recupera un error desde el servidor intermedio: {}",
                String::from_utf8_lossy(&body).trim()
            ),
        ));
    }
    let plain = match cipher_config {
        None => None,
        Some(cfg) => match ServerCipher::from_config(cfg) {
            Err(e) => {
                return Err(ProtocolError::operation(
                    io_code,
                    format!("Error al instanciar el cifrador de datos: {e}"),
                ));
            }
            Ok(None) => None,
            Ok(Some(c)) => Some(c.decipher(&String::from_utf8_lossy(&body)).map_err(|e| {
                ProtocolError::operation(
                    codes::DECRYPTING_PARAMS_ERROR,
                    format!("Error en el descifrado de los datos: {e}"),
                )
            })?),
        },
    };
    let Some(plain) = plain else {
        return Err(ProtocolError::unexpected(
            kind.generic_error(),
            "No se han podido descifrar los datos del servidor intermedio (sin clave)",
        ));
    };
    parse_envelope(&plain).map_err(|e| {
        ProtocolError::unexpected(
            kind.generic_error(),
            format!("La respuesta del servidor intermedio al descargar la informacion no es un XML valido: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::des_config;
    use crate::http::testing::{MockTransport, ok};

    const ENVELOPE: &str = r#"<sign><e k="format" v="CAdES"/><e k="algorithm" v="SHA256withRSA"/><e k="properties" v="bW9kZT1pbXBsaWNpdA+="/><e k="dat" v="SG9sYQ=="/><e k="ver" v="4"/><e k="op" v="cosign"/><e k="id" v="RID123"/><e k="key" v="04719233"/><e k="stservlet" v="https://h/StorageService"/><e k="aw" v="true"/></sign>"#;

    #[test]
    fn xml_envelope() {
        let p = parse_xml_envelope(ENVELOPE.as_bytes()).unwrap();
        assert_eq!(p.get("op").unwrap().as_deref(), Some("cosign"));
        assert_eq!(p.get("format").unwrap().as_deref(), Some("CAdES"));
        // '+' de Base64 conservado en los parámetros Base64.
        assert_eq!(
            p.get_base64("properties").unwrap().as_deref(),
            Some("bW9kZT1pbXBsaWNpdA+=")
        );
        let p = parse_xml_envelope(b"<OP><e k='x' v='a%20b'/></OP>").unwrap();
        assert_eq!(p.get("op").unwrap().as_deref(), Some("SIGN"));
        assert_eq!(p.get("x").unwrap().as_deref(), Some("a b"));
        assert!(parse_xml_envelope(b"<sign><x k='a' v='b'/></sign>").is_err());
        assert!(parse_xml_envelope(b"<sign><e k='a'/></sign>").is_err());
        assert!(parse_xml_envelope(b"<sign>texto</sign>").is_err());
        assert!(parse_xml_envelope(b"<!DOCTYPE sign><sign/>").is_err());
        // Blancos tolerados.
        assert!(parse_xml_envelope(b"<sign>\n <e k='a' v='b'/>\n</sign>").is_ok());
        let p = parse_envelope(br#" {"params":[{"k":"format","v":"XAdES"},{"k":"x"}]}"#).unwrap();
        assert_eq!(p.get("format").unwrap().as_deref(), Some("XAdES"));
        assert!(!p.contains("x"));
    }

    #[test]
    fn fetch_and_decrypt() {
        let cipher = crate::cipher::ServerCipher::from_config(&des_config("04719233"))
            .unwrap()
            .unwrap();
        let body = format!("{}\n", cipher.cipher(ENVELOPE.as_bytes()).unwrap());
        let t = MockTransport::new(move |_| ok(body.clone()));
        let http = HttpClient::new(t.clone());
        let p = fetch_envelope(
            &http,
            "https://h/RetrieveService",
            "FID",
            Some(&des_config("04719233")),
            OperationKind::Sign,
        )
        .unwrap();
        assert_eq!(p.get("id").unwrap().as_deref(), Some("RID123"));
        assert_eq!(t.bodies(), vec!["op=get&v=1_0&id=FID".to_string()]);
        // Error del servidor intermedio.
        let http = HttpClient::new(MockTransport::new(|_| {
            ok("ERR-06:=El identificador para los datos es inválido\n")
        }));
        let e = fetch_envelope(
            &http,
            "https://h/r",
            "FID",
            Some(&des_config("04719233")),
            OperationKind::Batch,
        )
        .unwrap_err();
        assert_eq!(e.code.code, 220003);
        // Descifrado erróneo.
        let http = HttpClient::new(MockTransport::new(|_| ok("0.AAAAAAAAAAAAAAA=")));
        let e = fetch_envelope(
            &http,
            "https://h/r",
            "FID",
            Some(&des_config("04719233")),
            OperationKind::Save,
        )
        .unwrap_err();
        assert_eq!(e.code.code, 220002);
        // Sin clave → error genérico.
        let http = HttpClient::new(MockTransport::new(|_| ok("PHNpZ24vPg==AAAA")));
        assert_eq!(
            fetch_envelope(&http, "https://h/r", "FID", None, OperationKind::SelectCert)
                .unwrap_err()
                .code
                .code,
            200201
        );
        // E/S y tiempo de espera.
        let http = HttpClient::new(MockTransport::new(|_| crate::http::testing::timeout()));
        assert_eq!(
            fetch_envelope(&http, "https://h/r", "FID", None, OperationKind::Load)
                .unwrap_err()
                .code
                .code,
            401110
        );
        let http = HttpClient::new(MockTransport::new(|_| crate::http::testing::status(500)));
        assert_eq!(
            fetch_envelope(&http, "https://h/r", "FID", None, OperationKind::SignAndSave)
                .unwrap_err()
                .code
                .code,
            401105
        );
    }
}
