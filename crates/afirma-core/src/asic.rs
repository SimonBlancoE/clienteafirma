//! Contenedores ASiC-S (`es.gob.afirma.core.signers.asic.ASiCUtil`, §14).
//!
//! Se reproduce la estructura que genera AutoFirma: comentario de archivo
//! `mimetype=application/vnd.etsi.asic-s+zip` y entradas, por este orden,
//! `mimetype` (**comprimida**, como hace Java aunque ETSI pide que se
//! almacene sin comprimir), los datos y la firma. La lectura recorre las
//! cabeceras locales en orden, como `ZipInputStream`.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use crate::constants::{
    ASIC_ENTRY_NAME_BINARY_SIGNATURE, ASIC_ENTRY_NAME_MIMETYPE, ASIC_ENTRY_NAME_XML_SIGNATURE, ASIC_S_MIMETYPE,
    THRESHOLD_FILE_SIZE,
};

/// Error de las utilidades ASiC.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AsicError {
    /// `IllegalArgumentException`.
    #[error("{0}")]
    IllegalArgument(String),
    /// `IOException`.
    #[error("{0}")]
    Io(String),
}

fn io(e: impl std::fmt::Display) -> AsicError {
    AsicError::Io(e.to_string())
}

/// Nombre por defecto de los datos (`dataobject.<ext>`).
pub fn default_data_filename(data: &[u8]) -> String {
    crate::mime::asic_default_data_filename(data)
}

/// `ASiCUtil.isDataEntry`: no es `mimetype` ni una de las entradas de firma
/// (los directorios y otras entradas de `META-INF` sí cuentan como datos).
pub fn is_data_entry(name: &str) -> bool {
    name != ASIC_ENTRY_NAME_BINARY_SIGNATURE
        && name != ASIC_ENTRY_NAME_XML_SIGNATURE
        && name != ASIC_ENTRY_NAME_MIMETYPE
}

fn zip_now() -> zip::DateTime {
    use chrono::{Datelike, Timelike};
    let now = chrono::Local::now();
    zip::DateTime::from_date_and_time(
        u16::try_from(now.year()).unwrap_or(1980),
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
    )
    .unwrap_or_default()
}

/// `ASiCUtil.createSContainer`: crea un contenedor ASiC-S. `signature_filename`
/// por defecto es `META-INF/signature.p7s` y `data_filename`, el nombre por
/// defecto de los datos.
pub fn create_s_container(
    signature: &[u8],
    data: &[u8],
    signature_filename: Option<&str>,
    data_filename: Option<&str>,
) -> Result<Vec<u8>, AsicError> {
    if signature.is_empty() {
        return Err(AsicError::IllegalArgument("La firma no puede ser nula ni vacia".into()));
    }
    if data.is_empty() {
        return Err(AsicError::IllegalArgument("Los datos no pueden ser nulos ni vacios".into()));
    }
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip_now());
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zw.set_comment(format!("mimetype={ASIC_S_MIMETYPE}")).map_err(io)?;
    zw.start_file(ASIC_ENTRY_NAME_MIMETYPE, options).map_err(io)?;
    zw.write_all(ASIC_S_MIMETYPE.as_bytes()).map_err(io)?;
    let data_name = data_filename.map(str::to_string).unwrap_or_else(|| default_data_filename(data));
    zw.start_file(data_name, options).map_err(io)?;
    zw.write_all(data).map_err(io)?;
    zw.start_file(signature_filename.unwrap_or(ASIC_ENTRY_NAME_BINARY_SIGNATURE), options).map_err(io)?;
    zw.write_all(signature).map_err(io)?;
    Ok(zw.finish().map_err(io)?.into_inner())
}

fn check_input(asic: &[u8]) -> Result<(), AsicError> {
    if asic.is_empty() {
        return Err(AsicError::IllegalArgument("La firma ASiC proporcionada no puede ser nula ni vacia".into()));
    }
    if asic.len() >= THRESHOLD_FILE_SIZE {
        return Err(AsicError::Io("El archivo tiene un tamano superior al permitido.".into()));
    }
    Ok(())
}

/// Recorre las entradas del contenedor. Se usa el directorio central (orden
/// de las entradas, que coincide con el de las cabeceras locales que lee
/// `ZipInputStream`); si el ZIP no lo tiene, se leen las cabeceras locales.
/// Leer por el directorio central admite los ZIP con descriptores de datos
/// que genera Java (tamaño no disponible en la cabecera local).
fn walk_entries(
    asic: &[u8],
    mut visit: impl FnMut(&str, &mut dyn Read) -> Result<bool, AsicError>,
) -> Result<(), AsicError> {
    if let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(asic)) {
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(io)?;
            let name = file.name().map_err(io)?.to_string();
            if visit(&name, &mut file)? {
                return Ok(());
            }
        }
        return Ok(());
    }
    let mut cursor = Cursor::new(asic);
    loop {
        let entry = zip::read::read_zipfile_from_stream(&mut cursor).map_err(io)?;
        let Some(mut file) = entry else { return Ok(()) };
        let name = file.name().map_err(io)?.to_string();
        if visit(&name, &mut file)? {
            return Ok(());
        }
        // Se consume el resto de la entrada para pasar a la siguiente.
        std::io::copy(&mut file, &mut std::io::sink()).map_err(io)?;
    }
}

fn get_signature(asic: &[u8], entry_name: &str) -> Result<Vec<u8>, AsicError> {
    check_input(asic)?;
    let mut found = None;
    walk_entries(asic, |name, r| {
        if name == entry_name {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(io)?;
            found = Some(v);
            return Ok(true);
        }
        Ok(false)
    })?;
    found.ok_or_else(|| {
        AsicError::Io(format!(
            "Los datos proporcionados no son una firma ASiC-S conteniendo la entrada {}",
            crate::logging::trim_str(entry_name)
        ))
    })
}

/// `ASiCUtil.getASiCSBinarySignature`: contenido de `META-INF/signature.p7s`.
pub fn get_binary_signature(asic: &[u8]) -> Result<Vec<u8>, AsicError> {
    get_signature(asic, ASIC_ENTRY_NAME_BINARY_SIGNATURE)
}

/// `ASiCUtil.getASiCSXMLSignature`: contenido de `META-INF/signatures.xml`.
pub fn get_xml_signature(asic: &[u8]) -> Result<Vec<u8>, AsicError> {
    get_signature(asic, ASIC_ENTRY_NAME_XML_SIGNATURE)
}

/// `ASiCUtil.getASiCSData`: entradas de datos indexadas por su nombre base.
pub fn get_data(asic: &[u8]) -> Result<HashMap<String, Vec<u8>>, AsicError> {
    check_input(asic)?;
    let mut out = HashMap::new();
    walk_entries(asic, |name, r| {
        if is_data_entry(name) {
            let base = name.trim_end_matches('/').rsplit('/').next().unwrap_or(name).to_string();
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(io)?;
            out.insert(base, v);
        }
        Ok(false)
    })?;
    if out.is_empty() {
        return Err(AsicError::Io("Los datos proporcionados no son una firma ASiC-S".into()));
    }
    Ok(out)
}

/// `ASiCUtil.getASiCSDataFilename`: nombre completo de la primera entrada de
/// datos.
pub fn get_data_filename(asic: &[u8]) -> Result<String, AsicError> {
    check_input(asic)?;
    let mut found = None;
    walk_entries(asic, |name, _| {
        if is_data_entry(name) {
            found = Some(name.to_string());
            return Ok(true);
        }
        Ok(false)
    })?;
    found.ok_or_else(|| AsicError::Io("Los datos proporcionados no son una firma ASiC-S".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_roundtrip() {
        let data = b"%PDF-1.4\n contenido de prueba";
        let asic = create_s_container(b"FIRMA", data, None, None).unwrap();
        // Estructura: comentario y orden de entradas.
        let archive = zip::ZipArchive::new(Cursor::new(&asic)).unwrap();
        assert_eq!(archive.comment(), b"mimetype=application/vnd.etsi.asic-s+zip");
        assert_eq!(archive.len(), 3);
        let mut archive = archive;
        assert_eq!(archive.by_index(0).unwrap().name().unwrap(), "mimetype");
        assert_eq!(archive.by_index(0).unwrap().compression(), zip::CompressionMethod::Deflated);
        assert_eq!(archive.by_index(1).unwrap().name().unwrap(), "dataobject.pdf");
        assert_eq!(archive.by_index(2).unwrap().name().unwrap(), "META-INF/signature.p7s");
        assert_eq!(get_binary_signature(&asic).unwrap(), b"FIRMA");
        assert!(get_xml_signature(&asic).unwrap_err().to_string().ends_with("META-INF/signatures.xml"));
        assert_eq!(get_data_filename(&asic).unwrap(), "dataobject.pdf");
        assert_eq!(get_data(&asic).unwrap().get("dataobject.pdf").unwrap(), data);
        let xml =
            create_s_container(b"<x/>", b"datos", Some("META-INF/signatures.xml"), Some("carpeta/datos.txt")).unwrap();
        assert_eq!(get_xml_signature(&xml).unwrap(), b"<x/>");
        assert!(get_data(&xml).unwrap().contains_key("datos.txt"));
        assert_eq!(get_data_filename(&xml).unwrap(), "carpeta/datos.txt");
        assert!(create_s_container(b"", b"x", None, None).is_err());
        assert!(create_s_container(b"x", b"", None, None).is_err());
        assert!(get_binary_signature(b"").is_err());
        assert!(get_data(b"no es un zip").is_err());
        assert!(is_data_entry("META-INF/manifest.xml"));
        assert!(!is_data_entry("mimetype"));
    }
}
