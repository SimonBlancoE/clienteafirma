//! Contenedores ASiC-S (`ASiCUtil`) y firmador CAdES-ASiC-S
//! (`AOCAdESASiCSSigner`, `AOCAdESASiCSCoSigner`, `AOCAdESASiCSCounterSigner`).
//!
//! Diferencias deliberadas con Java (ver `docs/deviations/afirma-cms.md`):
//! la entrada `mimetype` se guarda sin comprimir (STORED) como exige ETSI,
//! `is_sign` detecta de verdad los contenedores y la cofirma/contrafirma no
//! intercambian los nombres de las entradas.

use std::io::{Cursor, Read, Write};

use afirma_core::error::{AfirmaError, codes};
use afirma_core::{CounterSignTarget, ExtraParams, SignInfo, Signer, SignersTree, SigningKey};
use chrono::{Datelike, Timelike, Utc};

use crate::cades::{self, CadesSigner};
use crate::mime;

/// Tipo MIME de los contenedores ASiC-S.
pub const ASIC_S_MIMETYPE: &str = "application/vnd.etsi.asic-s+zip";
/// Entrada de la firma binaria (CAdES).
pub const ENTRY_NAME_BINARY_SIGNATURE: &str = "META-INF/signature.p7s";
/// Entrada de la firma XML (XAdES).
pub const ENTRY_NAME_XML_SIGNATURE: &str = "META-INF/signatures.xml";
/// Entrada con el tipo MIME del contenedor.
pub const ENTRY_NAME_MIMETYPE: &str = "mimetype";
/// Tamaño máximo admitido de un contenedor (1 GB).
pub const THRESHOLD_FILE_SIZE: usize = 1_000_000_000;
/// Nombre del formato.
pub const FORMAT_CADES_ASIC_S: &str = "CAdES-ASiC-S";

fn io_err(msg: impl Into<String>) -> AfirmaError {
    AfirmaError::msg(msg)
}

/// Nombre por defecto de la entrada de datos: `dataobject.<extensión>`.
pub fn default_data_filename(data: &[u8]) -> String {
    let ext = mime::analyze(data).extension.filter(|e| !e.is_empty()).unwrap_or_else(|| "bin".to_string());
    format!("dataobject.{ext}")
}

/// Indica si una entrada del contenedor es de datos (`ASiCUtil.isDataEntry`).
pub fn is_data_entry(name: &str) -> bool {
    name != ENTRY_NAME_BINARY_SIGNATURE && name != ENTRY_NAME_XML_SIGNATURE && name != ENTRY_NAME_MIMETYPE
}

/// Crea un contenedor ASiC-S (`ASiCUtil.createSContainer`): `mimetype`
/// (sin comprimir), los datos y la firma, con el comentario
/// `mimetype=application/vnd.etsi.asic-s+zip`.
pub fn create_s_container(
    signature: &[u8],
    data: &[u8],
    signature_filename: Option<&str>,
    data_filename: Option<&str>,
) -> afirma_core::Result<Vec<u8>> {
    if signature.is_empty() {
        return Err(AfirmaError::invalid_argument("La firma no puede ser nula ni vacia"));
    }
    if data.is_empty() {
        return Err(AfirmaError::invalid_argument("Los datos no pueden ser nulos ni vacios"));
    }
    let wrap = |e: zip::result::ZipError| {
        AfirmaError::new(codes::BUILDING_ASIC_CONTAINER_ERROR, "No se ha podido construir el contenedor CAdES-ASiC")
            .with_cause(e)
    };
    let io = |e: std::io::Error| {
        AfirmaError::new(codes::BUILDING_ASIC_CONTAINER_ERROR, "No se ha podido construir el contenedor CAdES-ASiC")
            .with_cause(e)
    };
    let now = Utc::now();
    let ts = zip::DateTime::from_date_and_time(
        now.year().clamp(1980, 2107) as u16,
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
    )
    .unwrap_or_default();
    let stored = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(ts);
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(ts);
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zw.set_comment(format!("mimetype={ASIC_S_MIMETYPE}")).map_err(wrap)?;
    zw.start_file(ENTRY_NAME_MIMETYPE, stored).map_err(wrap)?;
    zw.write_all(ASIC_S_MIMETYPE.as_bytes()).map_err(io)?;
    let data_name = data_filename.map(str::to_string).unwrap_or_else(|| default_data_filename(data));
    zw.start_file(data_name, deflated).map_err(wrap)?;
    zw.write_all(data).map_err(io)?;
    zw.start_file(signature_filename.unwrap_or(ENTRY_NAME_BINARY_SIGNATURE), deflated).map_err(wrap)?;
    zw.write_all(signature).map_err(io)?;
    Ok(zw.finish().map_err(wrap)?.into_inner())
}

/// Entrada de un contenedor ASiC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsicEntry {
    /// Nombre completo de la entrada.
    pub name: String,
    pub content: Vec<u8>,
}

impl AsicEntry {
    /// Nombre base (sin directorios), como `new File(name).getName()`.
    pub fn base_name(&self) -> &str {
        self.name.trim_end_matches('/').rsplit('/').next().unwrap_or(&self.name)
    }
}

/// Lee todas las entradas de un contenedor en el orden del ZIP.
pub fn read_entries(asic: &[u8]) -> afirma_core::Result<Vec<AsicEntry>> {
    if asic.is_empty() {
        return Err(AfirmaError::invalid_argument("La firma ASiC proporcionada no puede ser nula ni vacia"));
    }
    if asic.len() >= THRESHOLD_FILE_SIZE {
        return Err(io_err("El archivo tiene un tamano superior al permitido."));
    }
    let mut zip =
        zip::ZipArchive::new(Cursor::new(asic)).map_err(|e| io_err(format!("Los datos no son un ZIP: {e}")))?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| io_err(e.to_string()))?;
        if f.size() as usize >= THRESHOLD_FILE_SIZE {
            return Err(io_err("El archivo tiene un tamano superior al permitido."));
        }
        let name = f.name().map_err(|e| io_err(e.to_string()))?.to_string();
        let mut content = Vec::new();
        f.read_to_end(&mut content).map_err(|e| io_err(e.to_string()))?;
        out.push(AsicEntry { name, content });
    }
    Ok(out)
}

fn signature_entry(asic: &[u8], name: &str) -> afirma_core::Result<Vec<u8>> {
    read_entries(asic)?.into_iter().find(|e| e.name == name).map(|e| e.content).ok_or_else(|| {
        io_err(format!("Los datos proporcionados no son una firma ASiC-S conteniendo la entrada {name}"))
    })
}

/// Firma binaria (`META-INF/signature.p7s`) de un contenedor.
pub fn get_binary_signature(asic: &[u8]) -> afirma_core::Result<Vec<u8>> {
    signature_entry(asic, ENTRY_NAME_BINARY_SIGNATURE)
}

/// Firma XML (`META-INF/signatures.xml`) de un contenedor.
pub fn get_xml_signature(asic: &[u8]) -> afirma_core::Result<Vec<u8>> {
    signature_entry(asic, ENTRY_NAME_XML_SIGNATURE)
}

/// Entradas de datos del contenedor, en el orden del ZIP (Java usa el orden
/// de un `HashMap` por nombre base; con una sola entrada es equivalente).
pub fn get_data_entries(asic: &[u8]) -> afirma_core::Result<Vec<AsicEntry>> {
    let data: Vec<AsicEntry> = read_entries(asic)?.into_iter().filter(|e| is_data_entry(&e.name)).collect();
    if data.is_empty() {
        return Err(io_err("Los datos proporcionados no son una firma ASiC-S"));
    }
    Ok(data)
}

/// Primera entrada de datos: `(nombre base, contenido)`.
pub fn get_data(asic: &[u8]) -> afirma_core::Result<(String, Vec<u8>)> {
    let e = get_data_entries(asic)?
        .into_iter()
        .next()
        .ok_or_else(|| io_err("Los datos proporcionados no son una firma ASiC-S"))?;
    Ok((e.base_name().to_string(), e.content))
}

/// Firmador CAdES-ASiC-S.
#[derive(Debug, Clone, Copy, Default)]
pub struct CadesAsicsSigner;

fn explicit_params(extra: &ExtraParams) -> ExtraParams {
    let mut p = extra.clone();
    p.set("mode", "explicit");
    p
}

fn inner_parts(sign: &[u8]) -> afirma_core::Result<(Vec<u8>, String, Vec<u8>)> {
    let sig = get_binary_signature(sign).map_err(|e| {
        AfirmaError::invalid_signature_format("No se encontro la firma CAdES dentro del contenedor ASiC").with_cause(e)
    })?;
    let (name, data) = get_data(sign).map_err(|e| {
        AfirmaError::invalid_signature_format("No se encontraron los datos firmados dentro del contenedor CAdES-ASiC")
            .with_cause(e)
    })?;
    Ok((sig, name, data))
}

impl Signer for CadesAsicsSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_CADES_ASIC_S
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let params = explicit_params(extra);
        let signature = cades::sign_at(data, algorithm, key, &params, cades::now())?;
        create_s_container(&signature, data, Some(ENTRY_NAME_BINARY_SIGNATURE), params.get("asicsFilename"))
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let (sig, name, data) = inner_parts(sign)?;
        let new_sig = cades::cosign_at(Some(&data), &sig, algorithm, key, &explicit_params(extra), cades::now())?;
        create_s_container(&new_sig, &data, Some(ENTRY_NAME_BINARY_SIGNATURE), Some(&name))
    }

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let (sig, name, data) = inner_parts(sign)?;
        let new_sig = cades::countersign_at(&sig, algorithm, target, key, extra, cades::now())?;
        create_s_container(&new_sig, &data, Some(ENTRY_NAME_BINARY_SIGNATURE), Some(&name))
    }

    fn signers_structure(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        let sig = get_binary_signature(sign).map_err(|e| AfirmaError::invalid_signature_format(e.message))?;
        CadesSigner.signers_structure(&sig, params)
    }

    fn is_sign(&self, data: &[u8], params: &ExtraParams) -> bool {
        get_binary_signature(data).is_ok_and(|sig| CadesSigner.is_sign(&sig, params))
    }

    fn is_valid_data_file(&self, _data: &[u8]) -> bool {
        true
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        cades::signed_name_with(original, in_text, ".asics")
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        let (_, data) = get_data(sign).map_err(|e| AfirmaError::invalid_signature_format(e.message))?;
        Ok(Some(data))
    }

    fn sign_info(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        let sig = get_binary_signature(sign).map_err(|e| AfirmaError::invalid_signature_format(e.message))?;
        // Como Java, se informa el formato de la firma interna ("CAdES").
        CadesSigner.sign_info(&sig, params)
    }
}
