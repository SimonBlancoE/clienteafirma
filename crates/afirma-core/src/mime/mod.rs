//! Detección del tipo de los datos (`MimeHelper`, `OfficeAnalizer`,
//! `AOFileUtils.isXML`; §6 de la especificación).
//!
//! JMimeMagic se sustituye por una tabla generada a partir de su propio
//! `magic.xml` (módulo privado `magic`), por lo que el tipo MIME, la extensión y la
//! descripción coinciden con los de AutoFirma Java (verificado contra el
//! oráculo con las muestras de `testdata/core/mime`).
//!
//! Comportamientos de Java reproducidos (no son errores de la adaptación):
//!
//! * Un XML sin declaración `<?xml` se clasifica como `text/plain` (si es
//!   ASCII) o `application/octet-stream`: Java solo confirma `text/xml`
//!   cuando JMimeMagic ya lo había detectado como XML.
//! * Un XML con `DOCTYPE` no es XML (`application/octet-stream`).
//! * `OfficeAnalizer` devuelve `application/octect-stream` (con errata) para
//!   documentos OLE2 o ZIP no reconocidos.
//! * [`MimeHelper::is_zip_data`] solo confía en la detección "mágica"; la
//!   comprobación de cabecera de bytes está en [`is_zip`].

mod magic;
mod magic_table;
pub mod office;
pub mod xml;

use std::cell::OnceCell;

pub use office::{is_odf_document, is_ooxml_document, office_mime_type, ooxml_mime_type};
pub use xml::is_xml;

use crate::constants::{
    DEFAULT_CONTENT_DESCRIPTION, DEFAULT_CONTENT_OID_DATA, DEFAULT_MIMETYPE, UNKNOWN_JMIMEMAGIC_VALUE,
};

/// Tipo MIME de XML.
pub const XML_MIMETYPE: &str = "text/xml";
/// Extensión de XML.
pub const XML_EXTENSION: &str = "xml";
/// Descripción de XML.
pub const XML_DESCRIPTION: &str = "Documento XML";
/// Tipo MIME de Word 97-2003.
pub const DOC_OFFICE_MIMETYPE: &str = "application/msword";
/// Cabecera de los ficheros PDF.
pub const PDF_FILE_HEADER: &[u8] = b"%PDF-";
/// Tamaño mínimo de un PDF para `AOPDFSigner.isValidDataFile`.
pub const PDF_MIN_FILE_SIZE: usize = 70;

/// Error en la detección del tipo de datos.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MimeError {
    /// Los datos superan el tamaño máximo que analiza `OfficeAnalizer`.
    #[error("El archivo tiene un tamano superior al permitido.")]
    TooLarge,
}

/// Resultado de la detección del tipo de datos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeInfo {
    /// Tipo MIME (`MimeHelper.getMimeType()`).
    pub mime: String,
    /// Extensión sin punto (`MimeHelper.getExtension()`); puede no existir o
    /// ser una cadena vacía (p. ej. GIF), como en Java.
    pub extension: Option<String>,
    /// Descripción (`MimeHelper.getDescription()`).
    pub description: String,
}

/// Analizador del tipo de unos datos (`MimeHelper`).
pub struct MimeHelper<'a> {
    data: &'a [u8],
    magic_mime: Option<&'static str>,
    magic_extension: Option<&'static str>,
    magic_description: Option<&'static str>,
    verified_mime: OnceCell<Result<String, MimeError>>,
}

fn known(v: &'static str) -> Option<&'static str> {
    (v != UNKNOWN_JMIMEMAGIC_VALUE).then_some(v)
}

impl<'a> MimeHelper<'a> {
    /// Analiza la cabecera de los datos (constructor de `MimeHelper`).
    pub fn new(data: &'a [u8]) -> Self {
        let rule = magic::magic_match(data);
        MimeHelper {
            data,
            magic_mime: rule.and_then(|r| known(r.mime)),
            magic_extension: rule.and_then(|r| known(r.extension)),
            magic_description: rule.and_then(|r| known(r.description)),
            verified_mime: OnceCell::new(),
        }
    }

    /// Resultado de JMimeMagic (tipo, extensión, descripción), con `???`
    /// convertido en `None`.
    pub fn magic_info(&self) -> (Option<&'static str>, Option<&'static str>, Option<&'static str>) {
        (self.magic_mime, self.magic_extension, self.magic_description)
    }

    /// Tipo MIME de los datos (`MimeHelper.getMimeType()`).
    pub fn mime_type(&self) -> Result<String, MimeError> {
        self.verified_mime.get_or_init(|| self.compute_mime_type()).clone()
    }

    fn compute_mime_type(&self) -> Result<String, MimeError> {
        let mut m_type = self.magic_mime;
        let mut result: Option<String> = m_type.map(str::to_string);
        if m_type.is_none() || m_type == Some(XML_MIMETYPE) {
            if is_xml(self.data) {
                result = Some(XML_MIMETYPE.to_string());
            } else {
                m_type = None;
            }
        }
        if m_type == Some(office::ZIP_MIMETYPE) || m_type == Some(DOC_OFFICE_MIMETYPE) {
            result = Some(office_mime_type(self.data)?);
        }
        // GOTCHA del original: si JMimeMagic no detectó nada, aunque el XML
        // sea válido se acaba devolviendo el tipo por defecto.
        if m_type.is_none() {
            result = Some(DEFAULT_MIMETYPE.to_string());
        }
        Ok(result.unwrap_or_else(|| DEFAULT_MIMETYPE.to_string()))
    }

    /// Extensión sin punto (`MimeHelper.getExtension()`).
    pub fn extension(&self) -> Result<Option<String>, MimeError> {
        let t = self.mime_type()?;
        let verified = if t == DEFAULT_MIMETYPE {
            None
        } else if t == XML_MIMETYPE {
            Some(XML_EXTENSION)
        } else {
            office::office_extension(&t)
        };
        Ok(verified.or(self.magic_extension).map(str::to_string))
    }

    /// Descripción del contenido (`MimeHelper.getDescription()`).
    pub fn description(&self) -> Result<String, MimeError> {
        let t = self.mime_type()?;
        let verified = if t == XML_MIMETYPE {
            Some(XML_DESCRIPTION)
        } else if t != DEFAULT_MIMETYPE {
            office::office_description(&t)
        } else {
            None
        };
        Ok(verified
            .or(self.magic_description)
            .unwrap_or(DEFAULT_CONTENT_DESCRIPTION)
            .to_string())
    }

    /// Tipo, extensión y descripción.
    pub fn info(&self) -> Result<MimeInfo, MimeError> {
        Ok(MimeInfo {
            mime: self.mime_type()?,
            extension: self.extension()?,
            description: self.description()?,
        })
    }

    /// `MimeHelper.isZipData()`: en Java solo devuelve si JMimeMagic detectó
    /// `application/zip` (la comprobación de bytes es código muerto).
    pub fn is_zip_data(&self) -> bool {
        self.magic_mime == Some(office::ZIP_MIMETYPE)
    }
}

/// Tipo, extensión y descripción de unos datos.
pub fn mime_info(data: &[u8]) -> Result<MimeInfo, MimeError> {
    MimeHelper::new(data).info()
}

/// Indica si los datos empiezan por una cabecera ZIP (`PK\3\4`, `PK\5\6` o
/// `PK\7\8`).
pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == 0x50
        && data[1] == 0x4b
        && matches!((data[2], data[3]), (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08))
}

/// Comprobación previa de `AOPDFSigner.isPdfFile`: al menos 70 bytes y
/// cabecera `%PDF-` (el firmador PDF debe además poder abrir el documento).
pub fn is_pdf_header(data: &[u8]) -> bool {
    data.len() >= PDF_MIN_FILE_SIZE && data.starts_with(PDF_FILE_HEADER)
}

/// Tabla `mimetypes_oids.properties` (OID, tipo MIME).
pub const MIMETYPE_OIDS: [(&str, &str); 16] = [
    ("1.2.840.113549.1.7.1", "data"),
    ("1.2.840.10003.5.109.1", "application/pdf"),
    ("1.2.840.10003.5.109.2", "application/postscript"),
    ("1.2.840.10003.5.109.3", "text/html"),
    ("1.2.840.10003.5.109.4", "image/tiff"),
    ("1.2.840.10003.5.109.5", "image/gif"),
    ("1.2.840.10003.5.109.6", "image/jpeg"),
    ("1.2.840.10003.5.109.7", "image/png"),
    ("1.2.840.10003.5.109.8", "video/mpeg"),
    ("1.2.840.10003.5.109.9", "text/sgml"),
    ("1.2.840.10003.5.109.10", "text/xml"),
    ("1.2.840.113556.4.2", "application/msword"),
    ("1.2.840.113556.4.3", "application/vnd.ms-excel"),
    ("1.2.840.113556.4.4", "application/vnd.ms-project"),
    ("1.2.840.113556.4.5", "application/vnd.ms-powerpoint"),
    ("1.2.840.113556.4.6", "application/vnd.ms-works"),
];

/// `MimeHelper.transformMimeTypeToOid`: OID del tipo MIME o
/// `1.2.840.113549.1.7.1` si es nulo o desconocido.
pub fn transform_mime_type_to_oid(mime: Option<&str>) -> &'static str {
    mime.and_then(|m| MIMETYPE_OIDS.iter().rev().find(|(_, t)| *t == m).map(|(o, _)| *o))
        .unwrap_or(DEFAULT_CONTENT_OID_DATA)
}

/// `MimeHelper.transformOidToMimeType`: tipo MIME del OID (`data` para
/// id-data) o `application/octet-stream` si es nulo o desconocido.
pub fn transform_oid_to_mime_type(oid: Option<&str>) -> &'static str {
    oid.and_then(|o| MIMETYPE_OIDS.iter().find(|(x, _)| *x == o).map(|(_, m)| *m))
        .unwrap_or(DEFAULT_MIMETYPE)
}

/// Nombre por defecto de los datos dentro de un contenedor ASiC-S
/// (`dataobject.<ext>`, con `bin` si no se conoce la extensión).
pub fn asic_default_data_filename(data: &[u8]) -> String {
    let ext = MimeHelper::new(data)
        .extension()
        .ok()
        .flatten()
        .filter(|e| !e.is_empty());
    format!(
        "{}.{}",
        crate::constants::ASIC_DEFAULT_DATA_OBJECT_NAME,
        ext.as_deref()
            .unwrap_or(crate::constants::ASIC_DEFAULT_DATA_OBJECT_EXTENSION)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::esc;

    #[test]
    fn matches_java_oracle() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/core");
        let golden = std::fs::read_to_string(format!("{root}/mime.golden")).unwrap();
        let mut n = 0;
        for line in golden.lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            let data = std::fs::read(format!("{root}/mime/{}", cols[0])).unwrap();
            let h = MimeHelper::new(&data);
            let ext = h
                .extension()
                .unwrap()
                .map(|e| esc(&e))
                .unwrap_or_else(|| "<null>".into());
            let got = format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                cols[0],
                esc(&h.mime_type().unwrap()),
                ext,
                esc(&h.description().unwrap()),
                h.is_zip_data(),
                is_ooxml_document(&data),
                is_odf_document(&data),
                is_xml(&data)
            );
            assert_eq!(got, line);
            n += 1;
        }
        assert!(n >= 60);
    }

    #[test]
    fn oid_table_and_helpers() {
        assert_eq!(
            transform_mime_type_to_oid(Some("application/pdf")),
            "1.2.840.10003.5.109.1"
        );
        assert_eq!(transform_mime_type_to_oid(Some("data")), "1.2.840.113549.1.7.1");
        assert_eq!(
            transform_mime_type_to_oid(Some("application/x-foo")),
            "1.2.840.113549.1.7.1"
        );
        assert_eq!(transform_mime_type_to_oid(None), "1.2.840.113549.1.7.1");
        assert_eq!(transform_oid_to_mime_type(Some("1.2.840.113549.1.7.1")), "data");
        assert_eq!(
            transform_oid_to_mime_type(Some("1.2.840.113556.4.3")),
            "application/vnd.ms-excel"
        );
        assert_eq!(transform_oid_to_mime_type(Some("1.2.3")), "application/octet-stream");
        assert_eq!(transform_oid_to_mime_type(None), "application/octet-stream");
        assert!(is_zip(b"PK\x03\x04"));
        assert!(is_zip(b"PK\x05\x06rest"));
        assert!(!is_zip(b"PK\x01\x02"));
        assert!(!is_zip(b"PK"));
        let mut pdf = b"%PDF-1.7\n".to_vec();
        assert!(!is_pdf_header(&pdf));
        pdf.resize(70, b' ');
        assert!(is_pdf_header(&pdf));
        assert_eq!(asic_default_data_filename(b"%PDF-1.4\nxxxxxxxxxx"), "dataobject.pdf");
        assert_eq!(asic_default_data_filename(&[0xff; 10]), "dataobject.bin");
        assert_eq!(asic_default_data_filename(b"GIF89a....."), "dataobject.bin");
        assert_eq!(asic_default_data_filename(b"hola mundo"), "dataobject.txt");
    }

    #[test]
    fn built_office_documents() {
        use std::io::Write;
        let build = |entries: &[(&str, &[u8])]| -> Vec<u8> {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut zw = zip::ZipWriter::new(&mut buf);
                for (name, content) in entries {
                    zw.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                    zw.write_all(content).unwrap();
                }
                zw.finish().unwrap();
            }
            buf.into_inner()
        };
        let ods = build(&[
            ("mimetype", b"application/vnd.oasis.opendocument.spreadsheet"),
            ("content.xml", b"<a/>"),
            ("meta.xml", b"<a/>"),
            ("settings.xml", b"<a/>"),
            ("styles.xml", b"<a/>"),
            ("META-INF/manifest.xml", b"<a/>"),
        ]);
        let info = mime_info(&ods).unwrap();
        assert_eq!(info.mime, "application/vnd.oasis.opendocument.spreadsheet");
        assert_eq!(info.extension.as_deref(), Some("ods"));
        assert_eq!(info.description, "Hoja de cálculo");
        let xlsm = build(&[
            ("[Content_Types].xml", b"<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'><Override PartName='/x' ContentType='application/vnd.ms-excel.sheet.macroEnabled.12'/></Types>"),
            ("_rels/.rels", b"<a/>"),
            ("docProps/app.xml", b"<a/>"),
            ("docProps/core.xml", b"<a/>"),
        ]);
        // ".12" se elimina como "extensión" → no es un tipo conocido → zip.
        assert_eq!(office_mime_type(&xlsm).unwrap(), "application/zip");
        let pptx = build(&[
            ("[Content_Types].xml", b"<Types><override contenttype='application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml'/></Types>"),
            ("_rels/.rels", b""),
            ("docProps/app.xml", b""),
            ("docProps/core.xml", b""),
        ]);
        assert_eq!(
            office_mime_type(&pptx).unwrap(),
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        );
        assert!(is_ooxml_document(&pptx));
        assert!(!is_odf_document(&pptx));
        assert_eq!(
            ooxml_mime_type(b"<!DOCTYPE x><Types><Override ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'/></Types>"),
            None
        );
        assert_eq!(office_mime_type(b"no es un zip").unwrap(), "application/octect-stream");
        assert_eq!(
            office_mime_type(b"xx Microsoft Visio yy").unwrap(),
            "application/vnd.visio"
        );
    }
}
