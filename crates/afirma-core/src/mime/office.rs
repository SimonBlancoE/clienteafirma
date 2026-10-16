//! Detección de documentos ofimáticos (`OfficeAnalizer`, §6.2): ODF, OOXML y
//! Office 97-2003. A diferencia del original no se usan ficheros temporales:
//! el ZIP se lee en memoria.

use std::io::{Cursor, Read};

use zip::ZipArchive;

use super::MimeError;
use crate::constants::{OFFICE_ANALIZER_DEFAULT_MIMETYPE, THRESHOLD_FILE_SIZE};

/// Tipo MIME de ZIP.
pub const ZIP_MIMETYPE: &str = "application/zip";

/// Tipos MIME OOXML reconocidos (`OOXML_MIMETYPES`).
pub const OOXML_MIMETYPES: [&str; 17] = [
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-word.template.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.ms-powerpoint.template.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.presentationml.template",
    "application/vnd.ms-powerpoint.addin.macroEnabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel.addin.macroEnabled.12",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.template.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
];

/// Tipos MIME ODF reconocidos (`ODF_MIMETYPES`).
pub const ODF_MIMETYPES: [&str; 15] = [
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.text-template",
    "application/vnd.oasis.opendocument.text-web",
    "application/vnd.oasis.opendocument.text-master",
    "application/vnd.oasis.opendocument.graphics",
    "application/vnd.oasis.opendocument.graphics-template",
    "application/vnd.oasis.opendocument.presentation",
    "application/vnd.oasis.opendocument.presentation-template",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.spreadsheet-template",
    "application/vnd.oasis.opendocument.chart",
    "application/vnd.oasis.opendocument.formula",
    "application/vnd.oasis.opendocument.database",
    "application/vnd.oasis.opendocument.image",
    "application/vnd.openofficeorg.extension",
];

/// Tabla `FILE_EXTENSIONS` / `FILE_DESCRIPTIONS`: (tipo, extensión, descripción).
pub const FILE_TYPES: [(&str, &str, &str); 17] = [
    ("application/zip", "zip", "Archivo zip"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "Documento de texto"),
    ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx", "Presentación"),
    ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", "Hoja de cálculo"),
    ("application/vnd.oasis.opendocument.text", "odt", "Documento de texto"),
    ("application/vnd.oasis.opendocument.presentation", "odp", "Presentación"),
    ("application/vnd.oasis.opendocument.spreadsheet", "ods", "Hoja de cálculo"),
    ("application/vnd.oasis.opendocument.graphics", "odg", "Gráfico"),
    ("application/vnd.oasis.opendocument.chart", "odc", "Diagrama"),
    ("application/vnd.oasis.opendocument.formula", "odf", "Fórmula"),
    ("application/vnd.oasis.opendocument.database", "odb", "Base de datos"),
    ("application/vnd.oasis.opendocument.image", "odi", "Imagen"),
    ("application/vnd.oasis.opendocument.text-master", "odm", "Plantilla de documento"),
    ("application/msword", "doc", "Documento de texto"),
    ("application/vnd.ms-powerpoint", "ppt", "Presentación"),
    ("application/vnd.ms-excel", "xls", "Hoja de cálculo"),
    ("application/vnd.ms-project", "mpp", "Planificaci&oacute;n de proyecto"),
];

/// Extensión asociada a un tipo MIME (`OfficeAnalizer.getExtension(String)`).
pub fn office_extension(mime: &str) -> Option<&'static str> {
    FILE_TYPES.iter().find(|t| t.0 == mime).map(|t| t.1)
}

/// Descripción asociada a un tipo MIME (`OfficeAnalizer.getDescription(String)`).
pub fn office_description(mime: &str) -> Option<&'static str> {
    FILE_TYPES.iter().find(|t| t.0 == mime).map(|t| t.2)
}

/// ZIP en memoria con la búsqueda de entradas de `java.util.zip.ZipFile`.
struct Zip<'a>(ZipArchive<Cursor<&'a [u8]>>);

impl<'a> Zip<'a> {
    fn open(data: &'a [u8]) -> Option<Self> {
        ZipArchive::new(Cursor::new(data)).ok().map(Zip)
    }

    /// `ZipFile.getEntry(name)`: nombre exacto o, si no existe, `name/`.
    fn index(&self, name: &str) -> Option<usize> {
        self.0.index_for_name(name).or_else(|| self.0.index_for_name(&format!("{name}/")))
    }

    fn has(&self, name: &str) -> bool {
        self.index(name).is_some()
    }

    fn read(&mut self, name: &str) -> Option<Vec<u8>> {
        let idx = self.index(name)?;
        let mut file = self.0.by_index(idx).ok()?;
        let mut out = Vec::new();
        file.read_to_end(&mut out).ok()?;
        Some(out)
    }

    fn is_odf(&self) -> bool {
        ["mimetype", "content.xml", "meta.xml", "settings.xml", "styles.xml", "META-INF/manifest.xml"]
            .iter()
            .all(|n| self.has(n))
    }

    fn is_ooxml(&self) -> bool {
        ["[Content_Types].xml", "_rels/.rels", "docProps/app.xml", "docProps/core.xml"].iter().all(|n| self.has(n))
    }
}

/// `OfficeAnalizer.getMimeType(byte[])`: tipo ODF u OOXML de un ZIP,
/// `application/zip` para otros ZIP y, si no es un ZIP, tipo Office 97-2003
/// por cadenas o `application/octect-stream` (con la errata del original).
pub fn office_mime_type(data: &[u8]) -> Result<String, MimeError> {
    if data.len() >= THRESHOLD_FILE_SIZE {
        return Err(MimeError::TooLarge);
    }
    let mut mimetype: Option<String> = None;
    if let Some(mut zip) = Zip::open(data) {
        if zip.is_odf() {
            mimetype = zip.read("mimetype").and_then(|b| odf_mime_type(&b));
        } else if zip.is_ooxml() {
            mimetype = zip.read("[Content_Types].xml").and_then(|b| ooxml_mime_type(&b));
        } else {
            mimetype = office97_mime_type(data).map(str::to_string);
        }
        if mimetype.is_none() {
            mimetype = Some(ZIP_MIMETYPE.to_string());
        }
    }
    if mimetype.is_none() {
        mimetype = office97_mime_type(data).map(str::to_string);
    }
    Ok(mimetype.unwrap_or_else(|| OFFICE_ANALIZER_DEFAULT_MIMETYPE.to_string()))
}

/// Contenido de la entrada `mimetype` de un ODF si es un tipo soportado (sin
/// recortar espacios, como el original).
fn odf_mime_type(content: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(content);
    ODF_MIMETYPES.contains(&s.as_ref()).then(|| s.into_owned())
}

/// `OfficeAnalizer.getOOXMLMimeType`: analiza `[Content_Types].xml` (de forma
/// segura), toma el atributo `ContentType` de cada `Override`, elimina desde
/// el último `.` y devuelve el primero que sea un tipo OOXML conocido.
pub fn ooxml_mime_type(content_types_xml: &[u8]) -> Option<String> {
    let text = super::xml::secure_parse_text(content_types_xml)?;
    let doc = roxmltree::Document::parse_with_options(&text, super::xml::parsing_options()).ok()?;
    let root = doc.root_element();
    if !super::xml::qualified_name(&root).eq_ignore_ascii_case("Types") {
        return None;
    }
    for node in root.children().filter(|n| n.is_element()) {
        if !super::xml::qualified_name(&node).eq_ignore_ascii_case("Override") {
            continue;
        }
        let attr = node.attributes().find(|a| {
            let name = match a.namespace().and_then(|ns| node.lookup_prefix(ns)) {
                Some(p) if !p.is_empty() => format!("{p}:{}", a.name()),
                _ => a.name().to_string(),
            };
            name.eq_ignore_ascii_case("ContentType")
        });
        if let Some(attr) = attr {
            let mut value = attr.value();
            if let Some(dot) = value.rfind('.') {
                value = &value[..dot];
            }
            if OOXML_MIMETYPES.contains(&value) {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Detección de Office 97-2003 por cadenas (`getMimeTypeOffice97`).
pub fn office97_mime_type(data: &[u8]) -> Option<&'static str> {
    const PATTERNS: [(&[u8], &str); 5] = [
        (b"Microsoft Excel", "application/vnd.ms-excel"),
        (b"Microsoft Office Word", "application/msword"),
        (b"Microsoft Office PowerPoint", "application/vnd.ms-powerpoint"),
        (b"Microsoft Project", "application/vnd.ms-project"),
        (b"Microsoft Visio", "application/vnd.visio"),
    ];
    PATTERNS.iter().find(|(p, _)| contains(data, p)).map(|(_, m)| *m)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `OfficeAnalizer.isOOXMLDocument`: ZIP con `[Content_Types].xml`,
/// `_rels/.rels`, `docProps/app.xml` y `docProps/core.xml`.
pub fn is_ooxml_document(data: &[u8]) -> bool {
    data.len() < THRESHOLD_FILE_SIZE && Zip::open(data).is_some_and(|z| z.is_ooxml())
}

/// `OfficeAnalizer.isODFDocument`: ZIP con `mimetype`, `content.xml`,
/// `meta.xml`, `settings.xml`, `styles.xml` y `META-INF/manifest.xml` (no
/// comprueba el valor de `mimetype`).
pub fn is_odf_document(data: &[u8]) -> bool {
    data.len() < THRESHOLD_FILE_SIZE && Zip::open(data).is_some_and(|z| z.is_odf())
}
