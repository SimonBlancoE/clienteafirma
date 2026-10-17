//! CDF y PrKDF PKCS#15 del DNIe (especificación 10 §7.3 y §7.4).
//!
//! Los ficheros son objetos concatenados (sin SEQUENCE exterior) seguidos de relleno `00`; como
//! JMulticard, el análisis se detiene en el primer elemento que no se puede decodificar.

use crate::error::DnieError;
use crate::tlv::{self, Tlv};

/// Máximo de objetos que se leen (JMulticard: 10).
const MAX_OBJECTS: usize = 16;

/// Certificado del CDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateObject {
    /// Etiqueta (alias): `CertAutenticacion`, `CertFirmaDigital`, `CertCAIntermediaDGP`.
    pub label: String,
    /// Identificador que enlaza con la clave privada.
    pub id: Vec<u8>,
    /// Ruta del fichero con el certificado (comprimido).
    pub path: Vec<u8>,
}

/// Clave privada RSA del PrKDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyObject {
    /// Etiqueta: `KprivAutenticacion`, `KprivFirmaDigital`.
    pub label: String,
    pub id: Vec<u8>,
    /// Ruta de la clave (`3F110102`); su último identificador va en `MSE:SET DST`.
    pub path: Vec<u8>,
    /// Referencia de la clave (último octeto del INTEGER `keyReference`).
    pub key_reference: Option<u8>,
    /// Longitud del módulo en bits, si se indica.
    pub modulus_bits: Option<u32>,
}

impl PrivateKeyObject {
    /// Identificador de fichero de la clave (último elemento de la ruta).
    pub fn key_fid(&self) -> Option<[u8; 2]> {
        let n = self.path.len();
        (n >= 2).then(|| [self.path[n - 2], self.path[n - 1]])
    }
}

/// Objetos de nivel superior, deteniéndose en el relleno o en el primer elemento no válido.
fn records(data: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() && rest[0] == 0x30 && out.len() < MAX_OBJECTS {
        match tlv::parse_one(rest) {
            Ok((t, n)) => {
                out.push(t);
                rest = &rest[n..];
            }
            Err(_) => break,
        }
    }
    out
}

fn utf8(t: &Tlv<'_>) -> String {
    String::from_utf8_lossy(t.value).into_owned()
}

/// Primer `OCTET STRING` de la ruta dentro de `[1] { SEQUENCE { SEQUENCE { 04 ruta … } … } }`.
fn path_and_second<'a>(type_attrs: &Tlv<'a>) -> Result<(Vec<u8>, Vec<Tlv<'a>>), DnieError> {
    let inner = type_attrs
        .children()?
        .into_iter()
        .find(|t| t.tag == 0x30)
        .ok_or_else(|| DnieError::Read("PKCS#15: faltan los atributos de tipo".into()))?;
    let fields = inner.children()?;
    let path_seq = fields
        .iter()
        .find(|t| t.tag == 0x30)
        .ok_or_else(|| DnieError::Read("PKCS#15: falta la ruta".into()))?;
    let path = path_seq
        .child(0x04)?
        .ok_or_else(|| DnieError::Read("PKCS#15: ruta sin OCTET STRING".into()))?;
    Ok((path.value.to_vec(), fields))
}

fn parse_certificate_object(obj: &Tlv<'_>) -> Result<CertificateObject, DnieError> {
    let parts = obj.children()?;
    let common = parts.first().filter(|t| t.tag == 0x30);
    let label = common
        .and_then(|c| c.child(0x0C).ok().flatten())
        .map(|t| utf8(&t))
        .ok_or_else(|| DnieError::Read("CDF: objeto sin etiqueta".into()))?;
    let id = parts
        .get(1)
        .filter(|t| t.tag == 0x30)
        .and_then(|c| c.child(0x04).ok().flatten())
        .map(|t| t.value.to_vec())
        .ok_or_else(|| DnieError::Read("CDF: objeto sin identificador".into()))?;
    let type_attrs = parts
        .iter()
        .find(|t| t.tag == 0xA1)
        .ok_or_else(|| DnieError::Read("CDF: objeto sin atributos X.509".into()))?;
    let (path, _) = path_and_second(type_attrs)?;
    Ok(CertificateObject { label, id, path })
}

fn parse_private_key_object(obj: &Tlv<'_>) -> Result<PrivateKeyObject, DnieError> {
    let parts = obj.children()?;
    let label = parts
        .first()
        .filter(|t| t.tag == 0x30)
        .and_then(|c| c.child(0x0C).ok().flatten())
        .map(|t| utf8(&t))
        .ok_or_else(|| DnieError::Read("PrKDF: objeto sin etiqueta".into()))?;
    let key_attrs = parts
        .get(1)
        .filter(|t| t.tag == 0x30)
        .ok_or_else(|| DnieError::Read("PrKDF: faltan los atributos de clave".into()))?
        .children()?;
    let id = key_attrs
        .iter()
        .find(|t| t.tag == 0x04)
        .map(|t| t.value.to_vec())
        .ok_or_else(|| DnieError::Read("PrKDF: objeto sin identificador".into()))?;
    let key_reference = key_attrs
        .iter()
        .rev()
        .find(|t| t.tag == 0x02)
        .and_then(|t| t.value.last().copied());
    let type_attrs = parts
        .iter()
        .find(|t| t.tag == 0xA1)
        .ok_or_else(|| DnieError::Read("PrKDF: objeto sin atributos RSA".into()))?;
    let (path, fields) = path_and_second(type_attrs)?;
    let modulus_bits = fields
        .iter()
        .find(|t| t.tag == 0x02)
        .filter(|t| !t.value.is_empty() && t.value.len() <= 4)
        .map(|t| t.value.iter().fold(0u32, |a, b| (a << 8) | *b as u32));
    Ok(PrivateKeyObject {
        label,
        id,
        path,
        key_reference,
        modulus_bits,
    })
}

/// Analiza el CDF.
pub fn parse_cdf(data: &[u8]) -> Result<Vec<CertificateObject>, DnieError> {
    let mut out = Vec::new();
    for r in records(data) {
        match parse_certificate_object(&r) {
            Ok(o) => out.push(o),
            Err(e) => {
                tracing::warn!("CDF: se ignora el resto del fichero: {e}");
                break;
            }
        }
    }
    if out.is_empty() {
        return Err(DnieError::Read("El CDF del DNIe no contiene certificados".into()));
    }
    Ok(out)
}

/// Analiza el PrKDF.
pub fn parse_prkdf(data: &[u8]) -> Result<Vec<PrivateKeyObject>, DnieError> {
    let mut out = Vec::new();
    for r in records(data) {
        match parse_private_key_object(&r) {
            Ok(o) => out.push(o),
            Err(e) => {
                tracing::warn!("PrKDF: se ignora el resto del fichero: {e}");
                break;
            }
        }
    }
    if out.is_empty() {
        return Err(DnieError::Read("El PrKDF del DNIe no contiene claves".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tools/oracle/dnie/data/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn specimen_cdf() {
        let cdf = parse_cdf(&data("CDF_ESPECIMEN.ber")).unwrap();
        let rows: Vec<(String, String, String)> = cdf
            .iter()
            .map(|c| {
                (
                    c.label.clone(),
                    String::from_utf8(c.id.clone()).unwrap(),
                    hex::encode_upper(&c.path),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                (
                    "CertAutenticacion".into(),
                    "A02034674163C2020160830144606".into(),
                    "60617001".into()
                ),
                (
                    "CertFirmaDigital".into(),
                    "F02034674163C2020160830144606".into(),
                    "60617002".into()
                ),
                (
                    "CertCAIntermediaDGP".into(),
                    "S02034674163C2020160830144606".into(),
                    "60617003".into()
                ),
            ]
        );
    }

    #[test]
    fn specimen_prkdf() {
        let keys = parse_prkdf(&data("PRKDF_ESPECIMEN.ber")).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].label, "KprivAutenticacion");
        assert_eq!(keys[1].label, "KprivFirmaDigital");
        assert_eq!(keys[1].id, b"F02034674163C2020160830144606");
        assert_eq!(keys[1].path, vec![0x3F, 0x11, 0x01, 0x02]);
        assert_eq!(keys[1].key_fid(), Some([0x01, 0x02]));
        assert_eq!(keys[0].key_reference, Some(1));
        assert_eq!(keys[1].key_reference, Some(2));
        assert_eq!(keys[1].modulus_bits, Some(2048));
    }

    #[test]
    fn padding_and_garbage() {
        let mut d = data("PRKDF_ESPECIMEN.ber");
        d.truncate(99 + 50);
        // El segundo objeto queda truncado: se conserva el primero.
        assert_eq!(parse_prkdf(&d).unwrap().len(), 1);
        assert!(parse_cdf(&[0u8; 64]).is_err());
        assert!(parse_prkdf(&[]).is_err());
    }
}
