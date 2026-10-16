//! Datos de la firma trifásica (`TriphaseData`, `TriphaseDataSigner`,
//! `TriphaseUtil`; §3.4).
//!
//! El XML intercambiado con el servidor trifásico tiene la forma:
//!
//! ```text
//! <xml>
//!  <firmas format="FMT">
//!   <firma Id="ID" signid="SIGNID">
//!    <param n="CLAVE">VALOR</param>
//!   </firma>
//!  </firmas>
//! </xml>
//! ```
//!
//! Igual que en Java, los valores **no** se escapan al serializar.

use crate::error::{AfirmaError, Result, codes};
use crate::extra_params::ExtraParams;
use crate::key::SigningKey;

/// Parámetro con la prefirma.
pub const PROPERTY_NAME_PRESIGN: &str = "PRE";
/// Parámetro con la firma PKCS#1 de la prefirma.
pub const PROPERTY_NAME_PKCS1_SIGN: &str = "PK1";
/// Parámetro que indica que el servidor necesita conservar la prefirma.
pub const PROPERTY_NAME_NEED_PRE: &str = "NEED_PRE";
/// Parámetro adicional para enviar solo el certificado de firma (con la
/// errata del original).
pub const EXTRA_PARAM_INCLUDE_ONLY_SIGNING_CERTIFICATE: &str = "includeOnlySignningCertificate";

/// Firma individual de una operación trifásica (`TriphaseData.TriSign`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriSign {
    /// Identificador (`Id`); si el XML no lo trae se genera un UUID.
    pub id: String,
    /// Identificador de la firma a la que pertenece (`signid`).
    pub signature_id: Option<String>,
    /// Parámetros en orden de inserción.
    params: Vec<(String, String)>,
}

impl TriSign {
    /// Crea una firma (con un UUID aleatorio si no se indica identificador).
    pub fn new(id: Option<String>, signature_id: Option<String>) -> Self {
        TriSign {
            id: id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            signature_id,
            params: Vec::new(),
        }
    }

    /// Valor de un parámetro.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Establece (o sustituye) un parámetro.
    pub fn add_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        match self.params.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => self.params.push((key, value)),
        }
    }

    /// Elimina un parámetro.
    pub fn delete_property(&mut self, key: &str) {
        self.params.retain(|(k, _)| k != key);
    }

    /// Parámetros.
    pub fn properties(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    fn belongs_to(&self, sign_id: &str) -> bool {
        self.signature_id.as_deref() == Some(sign_id) || self.id == sign_id
    }
}

impl std::fmt::Display for TriSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Firma trifasica individual con identificador {}", self.id)
    }
}

/// Datos de una operación trifásica (`TriphaseData`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TriphaseData {
    /// Formato de firma (atributo `format`).
    pub format: Option<String>,
    /// Firmas.
    pub signs: Vec<TriSign>,
}

impl TriphaseData {
    /// Datos vacíos.
    pub fn new() -> Self {
        Self::default()
    }

    /// Primera firma cuyo `signid` o `Id` coincide (`getTriSign`).
    pub fn tri_sign(&self, sign_id: &str) -> Option<&TriSign> {
        self.signs.iter().find(|s| s.belongs_to(sign_id))
    }

    /// Copia de todas las firmas cuyo `signid` o `Id` coincide
    /// (`getTriSigns(id)`; `None` si no hay ninguna).
    pub fn tri_signs(&self, sign_id: &str) -> Option<Vec<TriSign>> {
        let v: Vec<TriSign> = self.signs.iter().filter(|s| s.belongs_to(sign_id)).cloned().collect();
        (!v.is_empty()).then_some(v)
    }

    /// `TriphaseData.parser(byte[])`: análisis seguro (sin DOCTYPE). El
    /// primer elemento hijo de la raíz debe llamarse `firmas` (sin distinguir
    /// mayúsculas); cada elemento hijo suyo es una firma con atributos
    /// opcionales `Id` y `signid`, y cada elemento hijo de una firma es un
    /// parámetro con nombre en el atributo `n` y valor su texto recortado.
    pub fn parse(xml: &[u8]) -> Result<Self> {
        // Java lanza una IOException sin código: el llamante decide el código
        // (300401 en la prefirma, por ejemplo).
        let text = crate::mime::xml::secure_parse_text(xml)
            .ok_or_else(|| AfirmaError::msg("Error al cargar el fichero XML: el XML no es valido"))?;
        let doc = roxmltree::Document::parse_with_options(&text, crate::mime::xml::parsing_options())
            .map_err(|e| AfirmaError::msg(format!("Error al cargar el fichero XML: {e}")))?;
        let root = doc.root_element();
        let signs_node = root
            .children()
            .find(|n| n.is_element())
            .filter(|n| crate::mime::xml::qualified_name(n).eq_ignore_ascii_case("firmas"))
            .ok_or_else(|| AfirmaError::invalid_argument("No se encontro el nodo 'firmas' en el XML proporcionado"))?;
        let mut data = TriphaseData {
            format: signs_node.attribute("format").map(str::to_string),
            signs: Vec::new(),
        };
        for sign_node in signs_node.children().filter(|n| n.is_element()) {
            let mut sign = TriSign::new(
                sign_node.attribute("Id").map(str::to_string),
                sign_node.attribute("signid").map(str::to_string),
            );
            for param in sign_node.children().filter(|n| n.is_element()) {
                let key = param
                    .attribute("n")
                    .ok_or_else(|| AfirmaError::invalid_argument("Parametro de firma trifasica sin atributo 'n'"))?;
                let value: String = param
                    .descendants()
                    .filter(|n| n.is_text())
                    .filter_map(|n| n.text())
                    .collect();
                sign.add_property(key, value.trim_matches(|c: char| c <= ' '));
            }
            data.signs.push(sign);
        }
        Ok(data)
    }

    /// Serialización exacta de `TriphaseData.toString()` (sin escapar los
    /// valores).
    pub fn to_xml_string(&self) -> String {
        let mut b = String::from("<xml>\n <firmas");
        if let Some(f) = &self.format {
            b.push_str(&format!(" format=\"{f}\""));
        }
        b.push_str(">\n");
        for s in &self.signs {
            b.push_str(&format!("  <firma Id=\"{}\"", s.id));
            if let Some(sid) = &s.signature_id {
                b.push_str(&format!(" signid=\"{sid}\""));
            }
            b.push_str(">\n");
            for (k, v) in &s.params {
                b.push_str(&format!("   <param n=\"{k}\">{v}</param>\n"));
            }
            b.push_str("  </firma>\n");
        }
        b.push_str(" </firmas>\n</xml>");
        b
    }
}

impl std::fmt::Display for TriphaseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_xml_string())
    }
}

/// `TriphaseUtil.prepareCertChainParam`: certificado de firma en Base64
/// URL-safe o, salvo `includeOnlySignningCertificate=true`, toda la cadena
/// separada por comas.
pub fn prepare_cert_chain_param(cert_chain: &[Vec<u8>], extra_params: Option<&ExtraParams>) -> Result<String> {
    if cert_chain.is_empty() {
        return Err(AfirmaError::invalid_argument(
            "La cadena de certificados no puede ser nula ni vacia",
        ));
    }
    let only_first = extra_params.is_none_or(|p| p.get_bool(EXTRA_PARAM_INCLUDE_ONLY_SIGNING_CERTIFICATE, false));
    if only_first {
        return Ok(crate::base64::encode_url_safe(&cert_chain[0]));
    }
    Ok(cert_chain
        .iter()
        .map(|c| crate::base64::encode_url_safe(c))
        .collect::<Vec<_>>()
        .join(","))
}

/// `TriphaseDataSigner.doSign`: firma (PKCS#1 con autoverificación) la
/// prefirma `PRE` de cada firma, añade `PK1` y elimina `PRE` salvo que la
/// firma tenga `NEED_PRE=true`.
pub fn do_sign(data: &mut TriphaseData, algorithm: &str, key: &dyn SigningKey, cert_chain: &[Vec<u8>]) -> Result<()> {
    if data.signs.is_empty() {
        return Err(AfirmaError::new(
            codes::PRESIGNS_NOT_FOUND,
            "No se han recibido prefirmas que firmar",
        ));
    }
    for (i, sign) in data.signs.iter_mut().enumerate() {
        let pre = sign.property(PROPERTY_NAME_PRESIGN).ok_or_else(|| {
            AfirmaError::new(
                codes::MALFORMED_PRESIGN_RESPONSE,
                format!("El servidor no ha devuelto la prefirma numero {i}"),
            )
        })?;
        let pre = crate::base64::decode(pre).map_err(|e| {
            AfirmaError::new(
                codes::MALFORMED_PRESIGN_RESPONSE,
                format!("Error decodificando la prefirma: {e}"),
            )
        })?;
        let pk1 = crate::pkcs1::pkcs1_sign(&pre, algorithm, key, cert_chain)?;
        sign.add_property(PROPERTY_NAME_PKCS1_SIGN, crate::base64::encode(&pk1));
        let need_pre = sign
            .property(PROPERTY_NAME_NEED_PRE)
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if !need_pre {
            sign.delete_property(PROPERTY_NAME_PRESIGN);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_roundtrip() {
        let xml = b"<?xml version=\"1.0\"?>\n<xml>\n <firmas format=\"CAdES\">\n  <firma Id=\"1\" signid=\"a\">\n   <param n=\"PRE\">  QUJD \n</param>\n   <param n=\"NEED_PRE\">true</param>\n  </firma>\n  <otra>\n   <param n=\"x\"><b>y</b>z</param>\n  </otra>\n </firmas>\n</xml>";
        let d = TriphaseData::parse(xml).unwrap();
        assert_eq!(d.format.as_deref(), Some("CAdES"));
        assert_eq!(d.signs.len(), 2);
        assert_eq!(d.signs[0].property("PRE"), Some("QUJD"));
        assert_eq!(d.signs[1].property("x"), Some("yz"));
        assert_eq!(d.signs[1].id.len(), 36);
        assert_eq!(d.tri_sign("a").unwrap().id, "1");
        assert_eq!(d.tri_sign("1").unwrap().id, "1");
        assert!(d.tri_signs("nada").is_none());
        let s = d.to_xml_string();
        assert!(s.starts_with(
            "<xml>\n <firmas format=\"CAdES\">\n  <firma Id=\"1\" signid=\"a\">\n   <param n=\"PRE\">QUJD</param>\n"
        ));
        assert!(s.ends_with("  </firma>\n </firmas>\n</xml>"));
        assert_eq!(TriphaseData::parse(s.as_bytes()).unwrap().signs[0], d.signs[0]);
        assert_eq!(
            TriphaseData::parse(b"<xml><otro/></xml>").unwrap_err().message,
            "No se encontro el nodo 'firmas' en el XML proporcionado"
        );
        assert!(TriphaseData::parse(b"<!DOCTYPE x><xml><firmas/></xml>").is_err());
        let empty = TriphaseData::new();
        assert_eq!(empty.to_xml_string(), "<xml>\n <firmas>\n </firmas>\n</xml>");
        assert_eq!(d.signs[0].to_string(), "Firma trifasica individual con identificador 1");
    }

    #[test]
    fn cert_chain_param() {
        let chain = vec![vec![0xfb, 0xff], vec![1, 2, 3]];
        assert_eq!(prepare_cert_chain_param(&chain, None).unwrap(), "-_8=");
        assert_eq!(
            prepare_cert_chain_param(&chain, Some(&ExtraParams::new())).unwrap(),
            "-_8=,AQID"
        );
        let p: ExtraParams = [("includeOnlySignningCertificate", "TRUE")].into_iter().collect();
        assert_eq!(prepare_cert_chain_param(&chain, Some(&p)).unwrap(), "-_8=");
        assert!(prepare_cert_chain_param(&[], None).is_err());
    }
}
