//! Detección de tipo MIME para los firmadores XML (tipo de los datos binarios
//! que se incrustan, `MimeType`/`DataObjectFormat`, y su OID), delegando en
//! `MimeHelper` de `afirma-core`, más utilidades ZIP y la comprobación de
//! datos XML de AutoFirma.

use std::io::Read;

pub const DEFAULT_MIMETYPE: &str = "application/octet-stream";
pub const DEFAULT_OID: &str = "1.2.840.113549.1.7.1";

/// `MimeHelper.transformMimeTypeToOid`.
pub fn mime_to_oid(mime: &str) -> String {
    afirma_core::mime::transform_mime_type_to_oid(Some(mime)).to_string()
}

/// `MimeHelper.isZipData` (comprobación por bytes mágicos).
pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == 0x50
        && data[1] == 0x4b
        && matches!((data[2], data[3]), (3, 4) | (5, 6) | (7, 8))
}

/// Lee una entrada de un ZIP.
pub fn zip_entry(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(data)).ok()?;
    let mut f = z.by_name(name).ok()?;
    let mut out = Vec::new();
    f.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Nombres de las entradas de un ZIP (orden del directorio central).
pub fn zip_names(data: &[u8]) -> Option<Vec<String>> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(data)).ok()?;
    Some(
        (0..z.len())
            .filter_map(|i| {
                z.by_index_raw(i)
                    .ok()
                    .and_then(|f| f.name().ok().map(|n| n.to_string()))
            })
            .collect(),
    )
}

/// Indica si los datos son XML según AutoFirma (`AOFileUtils.isXML`): se
/// analizan correctamente y no tienen DOCTYPE.
pub fn is_xml(data: &[u8]) -> bool {
    match crate::dom::Document::parse_bytes(data) {
        Ok((d, _)) => d.doctype.is_none(),
        Err(_) => false,
    }
}

/// `MimeHelper.getMimeType()`; si falla (p. ej. un ZIP dañado), el tipo por
/// defecto, como hacen los firmadores Java.
pub fn detect(data: &[u8]) -> String {
    afirma_core::mime::MimeHelper::new(data)
        .mime_type()
        .unwrap_or_else(|_| DEFAULT_MIMETYPE.to_string())
}

/// `MimeHelper.getExtension()` (sin punto).
pub fn extension(data: &[u8]) -> Option<String> {
    afirma_core::mime::MimeHelper::new(data)
        .extension()
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_detection() {
        assert_eq!(detect(b"hello world"), "text/plain");
        assert_eq!(detect(&[0u8]), DEFAULT_MIMETYPE);
        assert_eq!(detect(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"), "application/pdf");
        assert_eq!(extension(b"hello world").as_deref(), Some("txt"));
        assert_eq!(mime_to_oid("text/xml"), "1.2.840.10003.5.109.10");
        assert_eq!(mime_to_oid("text/plain"), DEFAULT_OID);
        assert!(is_xml(b"<?xml version=\"1.0\"?><a/>"));
        assert!(!is_xml(b"<!DOCTYPE a><a/>"));
    }
}
