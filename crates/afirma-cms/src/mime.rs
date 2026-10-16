//! Tipo de los datos firmados (`MimeHelper`) y tabla OID ↔ MIME
//! (`mimetypes_oids.properties`), sobre el puerto de JMimeMagic de
//! `afirma_core::mime`.
//!
//! El detector se puede sustituir con [`set_data_type_detector`] (p. ej. en
//! pruebas o para usar otro analizador).

use std::sync::OnceLock;

/// OID de `id-data`, usado cuando no hay un OID más concreto.
pub const DEFAULT_CONTENT_OID_DATA: &str = "1.2.840.113549.1.7.1";
/// Descripción por defecto del contenido.
pub const DEFAULT_CONTENT_DESCRIPTION: &str = "binary";
/// Tipo MIME por defecto.
pub const DEFAULT_MIMETYPE: &str = "application/octet-stream";

/// Información de tipo de unos datos (`MimeHelper`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeInfo {
    /// Tipo MIME (`getMimeType()`, nunca vacío).
    pub mime_type: String,
    /// Descripción (`getDescription()`).
    pub description: String,
    /// Extensión sin punto (`getExtension()`), si se conoce.
    pub extension: Option<String>,
}

/// Detector del tipo de los datos.
pub trait DataTypeDetector: Send + Sync {
    fn analyze(&self, data: &[u8]) -> DataTypeInfo;
}

/// Detector por defecto: `afirma_core::mime::MimeHelper` (JMimeMagic).
/// Si el análisis falla (datos de más de 1 GB) se devuelven los valores por
/// defecto, como hace `CAdESParameters` al capturar la excepción.
pub struct CoreDetector;

impl DataTypeDetector for CoreDetector {
    fn analyze(&self, data: &[u8]) -> DataTypeInfo {
        match afirma_core::mime::mime_info(data) {
            Ok(i) => DataTypeInfo {
                mime_type: i.mime,
                description: i.description,
                extension: i.extension,
            },
            Err(e) => {
                tracing::warn!("No se ha podido identificar el tipo de dato firmado: {e}");
                DataTypeInfo {
                    mime_type: DEFAULT_MIMETYPE.to_string(),
                    description: DEFAULT_CONTENT_DESCRIPTION.to_string(),
                    extension: None,
                }
            }
        }
    }
}

static DETECTOR: OnceLock<Box<dyn DataTypeDetector>> = OnceLock::new();

/// Sustituye el detector por defecto (solo surte efecto la primera vez y
/// antes de cualquier detección).
pub fn set_data_type_detector(detector: Box<dyn DataTypeDetector>) -> bool {
    DETECTOR.set(detector).is_ok()
}

/// Analiza los datos con el detector configurado.
pub fn analyze(data: &[u8]) -> DataTypeInfo {
    DETECTOR.get_or_init(|| Box::new(CoreDetector)).analyze(data)
}

/// `MimeHelper.transformMimeTypeToOid`: OID de un tipo MIME (`id-data` si
/// no se conoce).
pub fn mime_to_oid(mime: Option<&str>) -> &'static str {
    afirma_core::mime::transform_mime_type_to_oid(mime)
}

/// `MimeHelper.transformOidToMimeType`: tipo MIME de un OID
/// (`application/octet-stream` si no se conoce; `id-data` da `data`).
pub fn oid_to_mime(oid: Option<&str>) -> &'static str {
    afirma_core::mime::transform_oid_to_mime_type(oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables() {
        assert_eq!(mime_to_oid(Some("application/pdf")), "1.2.840.10003.5.109.1");
        assert_eq!(mime_to_oid(Some("text/plain")), DEFAULT_CONTENT_OID_DATA);
        assert_eq!(mime_to_oid(None), DEFAULT_CONTENT_OID_DATA);
        assert_eq!(oid_to_mime(Some(DEFAULT_CONTENT_OID_DATA)), "data");
        assert_eq!(oid_to_mime(Some("1.2.3")), DEFAULT_MIMETYPE);
    }

    #[test]
    fn detection() {
        let pdf = analyze(b"%PDF-1.4\n...");
        assert_eq!(pdf.mime_type, "application/pdf");
        assert_eq!(pdf.description, "PDF document");
        let xml = analyze(b"<?xml version=\"1.0\"?><a/>");
        assert_eq!(
            (xml.mime_type.as_str(), xml.description.as_str()),
            ("text/xml", "Documento XML")
        );
        let txt = analyze(b"Hola mundo");
        assert_eq!(
            (txt.mime_type.as_str(), txt.description.as_str()),
            ("text/plain", "Texto plano")
        );
    }
}
