//! Firmas de documentos ofimáticos: OpenDocument (ODF,
//! `META-INF/documentsignatures.xml`) y Office Open XML (OOXML,
//! `_xmlsignatures/`).

pub mod odf;
pub mod ooxml;

use std::io::{Cursor, Read, Write};

use afirma_core::error::{AfirmaError, ErrorCode, codes};

/// Tamaño máximo de los documentos (`>= 1_000_000_000` se rechaza).
pub const MAX_SIZE: usize = 1_000_000_000;

/// Entrada de un paquete ZIP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub is_dir: bool,
}

/// Lee todas las entradas en el orden del directorio central
/// (`ZipFile.entries()`).
pub fn read_zip(data: &[u8], code: ErrorCode) -> afirma_core::Result<Vec<ZipEntry>> {
    let bad = |e: String| AfirmaError::new(code, format!("El documento no es un ZIP valido: {e}"));
    let mut z = zip::ZipArchive::new(Cursor::new(data)).map_err(|e| bad(e.to_string()))?;
    let mut out = Vec::with_capacity(z.len());
    for i in 0..z.len() {
        let mut f = z.by_index(i).map_err(|e| bad(e.to_string()))?;
        let name = f.name().map_err(|e| bad(e.to_string()))?.to_string();
        let is_dir = f.is_dir();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| bad(e.to_string()))?;
        out.push(ZipEntry {
            name,
            data: buf,
            is_dir,
        });
    }
    Ok(out)
}

pub(crate) fn zip_now() -> zip::DateTime {
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

/// Escritor de paquetes: todas las entradas comprimidas salvo las indicadas
/// como almacenadas.
pub struct ZipBuilder {
    zw: zip::ZipWriter<Cursor<Vec<u8>>>,
    code: ErrorCode,
}

impl ZipBuilder {
    pub fn new(code: ErrorCode) -> Self {
        ZipBuilder {
            zw: zip::ZipWriter::new(Cursor::new(Vec::new())),
            code,
        }
    }

    pub fn add(&mut self, name: &str, data: &[u8], stored: bool, is_dir: bool) -> afirma_core::Result<()> {
        let method = if stored {
            zip::CompressionMethod::Stored
        } else {
            zip::CompressionMethod::Deflated
        };
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(method)
            .last_modified_time(zip_now());
        let err = |e: String| AfirmaError::new(self.code, format!("Error al escribir el paquete: {e}"));
        if is_dir {
            self.zw
                .add_directory(name.trim_end_matches('/'), opts)
                .map_err(|e| err(e.to_string()))?;
        } else {
            self.zw.start_file(name, opts).map_err(|e| err(e.to_string()))?;
            self.zw.write_all(data).map_err(|e| err(e.to_string()))?;
        }
        Ok(())
    }

    pub fn finish(self) -> afirma_core::Result<Vec<u8>> {
        let code = self.code;
        self.zw
            .finish()
            .map(|c| c.into_inner())
            .map_err(|e| AfirmaError::new(code, format!("Error al escribir el paquete: {e}")))
    }
}

/// Comprueba el tamaño máximo de los documentos.
pub fn check_size(data: &[u8]) -> afirma_core::Result<()> {
    if data.len() >= MAX_SIZE {
        return Err(AfirmaError::new(
            codes::DOCUMENT_TOO_LARGE,
            "El archivo tiene un tamano superior al permitido.",
        ));
    }
    Ok(())
}
