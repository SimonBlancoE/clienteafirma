//! Datos de sesión de la firma trifásica (`TriphaseData`): XML de sesión de
//! la firma simple y JSON de la firma por lotes.

use afirma_core::error::codes;
use afirma_core::{AfirmaError, SigningKey};
use afirma_xml::dom::{Document, NodeId, NodeKind};

use crate::javamap::java_hash_order;
use crate::jbase64;
use crate::json_lenient::{JsonObject, JsonValue};

pub const PARAM_PRE: &str = "PRE";
pub const PARAM_PK1: &str = "PK1";
pub const PARAM_NEED_PRE: &str = "NEED_PRE";

/// Una firma dentro de la sesión trifásica (`TriSign`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriSign {
    /// Atributo `Id` (si falta al analizar se genera un UUID, como en Java).
    pub id: Option<String>,
    /// Atributo `signid`.
    pub signid: Option<String>,
    /// Parámetros en orden de inserción (claves únicas).
    params: Vec<(String, String)>,
}

impl TriSign {
    pub fn new(id: Option<String>, signid: Option<String>) -> Self {
        TriSign { id, signid, params: Vec::new() }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// `addProperty`: sustituye o añade.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        match self.params.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => self.params.push((key, value)),
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        let pos = self.params.iter().position(|(k, _)| k == key)?;
        Some(self.params.remove(pos).1)
    }

    /// Parámetros en orden de inserción.
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }

    /// Parámetros en el orden de iteración de `ConcurrentHashMap` de Java.
    pub fn params_java_order(&self) -> Vec<(&str, &str)> {
        let keys: Vec<&str> = self.params.iter().map(|(k, _)| k.as_str()).collect();
        java_hash_order(&keys).into_iter().map(|i| (self.params[i].0.as_str(), self.params[i].1.as_str())).collect()
    }
}

/// Sesión trifásica (`TriphaseData`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TriphaseData {
    pub format: Option<String>,
    pub signs: Vec<TriSign>,
}

/// Error de análisis de los datos trifásicos.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TriphaseParseError(pub String);

fn element_children(doc: &Document, id: NodeId) -> Vec<NodeId> {
    doc.children(id).iter().copied().filter(|c| matches!(doc.kind(*c), NodeKind::Element(_))).collect()
}

/// `String.trim()` de Java (elimina los caracteres <= U+0020 de los extremos).
pub(crate) fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

impl TriphaseData {
    /// Analiza el XML de sesión (`TriphaseData.parser`).
    pub fn parse_xml(xml: &[u8]) -> Result<TriphaseData, TriphaseParseError> {
        let (doc, _) = Document::parse_bytes(xml).map_err(|e| TriphaseParseError(format!("Error al cargar el fichero XML: {e}")))?;
        if doc.doctype.is_some() {
            return Err(TriphaseParseError("Error al cargar el fichero XML: DOCTYPE no permitido".into()));
        }
        let root = doc.document_element().ok_or_else(|| TriphaseParseError("XML sin elemento raíz".into()))?;
        let not_found = || TriphaseParseError("No se encontro el nodo 'firmas' en el XML proporcionado".into());
        let firmas = *element_children(&doc, root).first().ok_or_else(not_found)?;
        let firmas_el = doc.element(firmas).ok_or_else(not_found)?;
        if !firmas_el.qname().eq_ignore_ascii_case("firmas") {
            return Err(not_found());
        }
        let format = qattr(firmas_el, "format");
        let mut signs = Vec::new();
        for s in element_children(&doc, firmas) {
            let el = doc.element(s).ok_or_else(not_found)?;
            let id = qattr(el, "Id").or_else(|| Some(uuid::Uuid::new_v4().to_string()));
            let mut ts = TriSign::new(id, qattr(el, "signid"));
            for p in element_children(&doc, s) {
                let pel = doc.element(p).ok_or_else(not_found)?;
                let key = qattr(pel, "n").ok_or_else(|| TriphaseParseError("Parametro sin atributo 'n'".into()))?;
                ts.set(key, java_trim(&doc.text_content(p)).to_string());
            }
            signs.push(ts);
        }
        Ok(TriphaseData { format, signs })
    }

    /// Serialización exacta de `TriphaseData.toString()` (sin declaración
    /// XML, sin escapar los valores y sin salto de línea final).
    pub fn to_xml(&self) -> String {
        let mut b = String::from("<xml>\n <firmas");
        if let Some(f) = &self.format {
            b.push_str(&format!(" format=\"{f}\""));
        }
        b.push_str(">\n");
        for s in &self.signs {
            b.push_str("  <firma");
            if let Some(id) = &s.id {
                b.push_str(&format!(" Id=\"{id}\""));
            }
            if let Some(sid) = &s.signid {
                b.push_str(&format!(" signid=\"{sid}\""));
            }
            b.push_str(">\n");
            for (k, v) in s.params_java_order() {
                b.push_str(&format!("   <param n=\"{k}\">{v}</param>\n"));
            }
            b.push_str("  </firma>\n");
        }
        b.push_str(" </firmas>\n</xml>");
        b
    }

    /// Analiza la forma JSON (`TriphaseDataParser.parseFromJSON`): con
    /// `signs` (cada uno con su `signinfo`) o plana con `signinfo`.
    pub fn from_json(obj: &JsonObject) -> Result<TriphaseData, String> {
        let format = match obj.get("format") {
            Some(_) => Some(obj.get_string("format")?.to_string()),
            None => None,
        };
        let mut signs = Vec::new();
        let mut parse_infos = |infos: &Vec<JsonValue>| -> Result<(), String> {
            for info in infos {
                let info = info.as_object().ok_or("JSONArray[i] is not a JSONObject.")?;
                let id = info.get_string("id")?.to_string();
                let signid = info.opt_string("signid");
                let params = info.get_object("params")?;
                let mut ts = TriSign::new(Some(id), signid);
                for (k, v) in &params.0 {
                    match v {
                        JsonValue::Str(s) => ts.set(k.clone(), s.clone()),
                        _ => return Err(format!("El parametro {k} no es una cadena")),
                    }
                }
                signs.push(ts);
            }
            Ok(())
        };
        if obj.has("signs") {
            for sign in obj.get_array("signs")? {
                let sign = sign.as_object().ok_or("JSONArray[i] is not a JSONObject.")?;
                parse_infos(sign.get_array("signinfo")?)?;
            }
        } else {
            parse_infos(obj.get_array("signinfo")?)?;
        }
        Ok(TriphaseData { format, signs })
    }

    /// `TriphaseDataParser.triphaseDataToJsonString`.
    pub fn to_json(&self) -> String {
        let mut infos = Vec::new();
        for s in &self.signs {
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
        let mut td = JsonObject::new();
        if let Some(f) = &self.format {
            td.put("format", JsonValue::str(f.clone()));
        }
        td.put("signinfo", JsonValue::Array(infos));
        td.to_org_json()
    }

    /// `TriphaseDataSigner.doSign`: firma cada `PRE` (Base64 estándar),
    /// añade `PK1` y elimina `PRE` salvo que `NEED_PRE` sea `true`.
    pub fn sign_all(&mut self, key: &dyn SigningKey, algorithm: &str) -> Result<(), AfirmaError> {
        if self.signs.is_empty() {
            return Err(AfirmaError::new(codes::PRESIGNS_NOT_FOUND, "No se han recibido prefirmas que firmar"));
        }
        for (i, s) in self.signs.iter_mut().enumerate() {
            let pk1 = sign_pre(s, i, key, algorithm)?;
            s.set(PARAM_PK1, pk1);
            let need_pre = s.get(PARAM_NEED_PRE).is_some_and(|v| v.eq_ignore_ascii_case("true"));
            if !need_pre {
                s.remove(PARAM_PRE);
            }
        }
        Ok(())
    }

    /// Firma de `AOPkcs1TriPhaseSigner` (formato NONE): solo la primera
    /// firma y sin eliminar `PRE`.
    pub fn sign_first(&mut self, key: &dyn SigningKey, algorithm: &str) -> Result<(), AfirmaError> {
        let s = self
            .signs
            .first_mut()
            .ok_or_else(|| AfirmaError::new(codes::PRESIGNS_NOT_FOUND, "No se han recibido prefirmas que firmar"))?;
        let pk1 = sign_pre(s, 0, key, algorithm)?;
        s.set(PARAM_PK1, pk1);
        Ok(())
    }
}

fn sign_pre(s: &TriSign, i: usize, key: &dyn SigningKey, algorithm: &str) -> Result<String, AfirmaError> {
    let pre = s
        .get(PARAM_PRE)
        .ok_or_else(|| AfirmaError::new(codes::MALFORMED_PRESIGN_RESPONSE, format!("El servidor no ha devuelto la prefirma numero {i}")))?;
    let pre = jbase64::decode(pre)
        .map_err(|e| AfirmaError::new(codes::MALFORMED_PRESIGN_RESPONSE, format!("Error decodificando la prefirma: {e}")))?;
    let sig = crate::pkcs1::sign(key, algorithm, &pre)?;
    Ok(jbase64::encode(&sig))
}

/// Atributo por nombre cualificado exacto (`getNamedItem`).
fn qattr(el: &afirma_xml::dom::Element, qname: &str) -> Option<String> {
    el.attrs.iter().find(|a| a.qname() == qname).map(|a| a.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_lenient::parse_object;

    #[test]
    fn xml_roundtrip_exact() {
        let xml = "<xml>\n <firmas>\n  <firma Id=\"a1\">\n   <param n=\"NEED_PRE\">true</param>\n   <param n=\"PRE\">\n  AAEC  \n</param>\n  </firma>\n </firmas>\n</xml>";
        let td = TriphaseData::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(td.format, None);
        assert_eq!(td.signs[0].get("PRE"), Some("AAEC"));
        // Orden de ConcurrentHashMap de Java: PRE antes que NEED_PRE.
        assert_eq!(
            td.to_xml(),
            "<xml>\n <firmas>\n  <firma Id=\"a1\">\n   <param n=\"PRE\">AAEC</param>\n   <param n=\"NEED_PRE\">true</param>\n  </firma>\n </firmas>\n</xml>"
        );
        let td = TriphaseData::parse_xml(b"<r><!--c--><FIRMAS format=\"XAdES\"><x signid=\"s\"><p n=\"k\">v</p></x></FIRMAS></r>").unwrap();
        assert_eq!(td.format.as_deref(), Some("XAdES"));
        assert_eq!(td.signs[0].signid.as_deref(), Some("s"));
        // Sin Id: UUID.
        assert_eq!(td.signs[0].id.as_ref().map(|s| s.len()), Some(36));
        assert!(TriphaseData::parse_xml(b"<xml><otro/></xml>").is_err());
        assert!(TriphaseData::parse_xml(b"<xml></xml>").is_err());
        assert!(TriphaseData::parse_xml(b"<xml><firmas><firma><param>v</param></firma></firmas></xml>").is_err());
        assert!(TriphaseData::parse_xml(b"<!DOCTYPE x [<!ENTITY e \"x\">]><xml><firmas/></xml>").is_err());
        assert!(TriphaseData::parse_xml(b"no xml").is_err());
    }

    #[test]
    fn json_forms() {
        let o = parse_object(r#"{"td":{"format":"XAdES","signs":[{"signinfo":[{"id":"1","params":{"PRE":"AA==","NEED_PRE":"true"}}]},{"signinfo":[{"id":"2","signid":"s2","params":{"PRE":"AQ=="}}]}]}}"#).unwrap();
        let td = TriphaseData::from_json(o.get_object("td").unwrap()).unwrap();
        assert_eq!(td.format.as_deref(), Some("XAdES"));
        assert_eq!(td.signs.len(), 2);
        assert_eq!(td.signs[1].signid.as_deref(), Some("s2"));
        let flat = parse_object(r#"{"signinfo":[{"id":"1","params":{"PRE":"AA=="}}]}"#).unwrap();
        assert_eq!(TriphaseData::from_json(&flat).unwrap().signs.len(), 1);
        let bad = parse_object(r#"{"signinfo":[{"id":"1","params":{"PRE":1}}]}"#).unwrap();
        assert!(TriphaseData::from_json(&bad).is_err());
        assert_eq!(
            td.to_json(),
            // Salida de TriphaseDataParser.triphaseDataToJsonString en una JVM.
            r#"{"signinfo":[{"id":"1","params":{"PRE":"AA==","NEED_PRE":"true"}},{"id":"2","params":{"PRE":"AQ=="},"signid":"s2"}],"format":"XAdES"}"#
        );
    }
}
