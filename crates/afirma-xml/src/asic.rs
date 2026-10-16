//! Firmador XAdES-ASiC-S (`AOXAdESASiCSSigner`): firma XAdES Externally
//! Detached de los datos dentro de un contenedor ASiC-S
//! (`META-INF/signatures.xml`).
//!
//! Desviación: Java comprime la entrada `mimetype` (ETSI EN 319 162 exige que
//! se almacene sin comprimir y sea la primera); aquí se almacena sin comprimir.

use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::sync::Arc;

use afirma_core::constants::{ASIC_ENTRY_NAME_MIMETYPE, ASIC_ENTRY_NAME_XML_SIGNATURE, ASIC_S_MIMETYPE};
use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::{CounterSignTarget, SignInfo, Signer, SignersTree};

use crate::dsig::{External, Resolver};
use crate::xades::{self, FORMAT_EXTERNALLY_DETACHED, XadesSigner};

pub const FORMAT_XADES_ASIC_S: &str = "XAdES-ASiC-S";

/// `setASiCProperties`.
pub fn set_asic_properties(p: &mut ExtraParams, data: &[u8]) {
    let name = p
        .get("asicsFilename")
        .map(str::to_string)
        .unwrap_or_else(|| afirma_core::asic::default_data_filename(data));
    p.set("addKeyInfoKeyName", "true");
    p.set("uri", name);
    p.set("RootXmlNodeName", "asic:XAdESSignatures");
    p.set("RootXmlNodeNamespace", "http://uri.etsi.org/02918/v1.2.1#");
    p.set("RootXmlNodeNamespacePrefix", "xmlns:asic");
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

/// `ASiCUtil.createSContainer` con `mimetype` sin comprimir.
pub fn create_container(signature: &[u8], data: &[u8], data_name: &str) -> afirma_core::Result<Vec<u8>> {
    let io = |e: zip::result::ZipError| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            format!("Error al crear el contenedor ASiC-S: {e}"),
        )
    };
    let io2 = |e: std::io::Error| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            format!("Error al crear el contenedor ASiC-S: {e}"),
        )
    };
    let deflated = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip_now());
    let stored = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(zip_now());
    let mut zw = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zw.set_comment(format!("mimetype={ASIC_S_MIMETYPE}")).map_err(io)?;
    zw.start_file(ASIC_ENTRY_NAME_MIMETYPE, stored).map_err(io)?;
    zw.write_all(ASIC_S_MIMETYPE.as_bytes()).map_err(io2)?;
    zw.start_file(data_name, deflated).map_err(io)?;
    zw.write_all(data).map_err(io2)?;
    zw.start_file(ASIC_ENTRY_NAME_XML_SIGNATURE, deflated).map_err(io)?;
    zw.write_all(signature).map_err(io2)?;
    Ok(zw.finish().map_err(io)?.into_inner())
}

/// Entradas de un contenedor ZIP en orden (nombre, contenido).
///
/// Se lee el directorio central (los ZIP de Java usan descriptores de datos
/// que impiden leerlos solo con las cabeceras locales).
fn zip_entries(zip_bytes: &[u8]) -> afirma_core::Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    if zip_bytes.len() >= afirma_core::constants::THRESHOLD_FILE_SIZE {
        return Err(AfirmaError::new(
            codes::DOCUMENT_TOO_LARGE,
            "El archivo tiene un tamano superior al permitido.",
        ));
    }
    let bad = |e: zip::result::ZipError| {
        AfirmaError::invalid_signature_format(format!("El contenedor ASiC no es valido: {e}"))
    };
    let mut z = zip::ZipArchive::new(Cursor::new(zip_bytes)).map_err(bad)?;
    let mut out = Vec::new();
    for i in 0..z.len() {
        let mut f = z.by_index(i).map_err(bad)?;
        let name = f.name().map_err(bad)?.to_string();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
        out.push((name, buf));
    }
    Ok(out)
}

/// Firma XML de un contenedor (`ASiCUtil.getASiCSXMLSignature`).
pub fn xml_signature(sign: &[u8]) -> afirma_core::Result<Vec<u8>> {
    zip_entries(sign)?
        .into_iter()
        .find(|(n, _)| n == ASIC_ENTRY_NAME_XML_SIGNATURE)
        .map(|(_, d)| d)
        .ok_or_else(|| {
            AfirmaError::invalid_signature_format("No se ha encontrado la firma XML en el contenedor ASiC-S")
        })
}

/// Firma XML y datos (nombre, contenido) de un contenedor.
fn unpack(sign: &[u8]) -> afirma_core::Result<(Vec<u8>, String, Vec<u8>)> {
    let entries = zip_entries(sign)?;
    let xml = entries
        .iter()
        .find(|(n, _)| n == ASIC_ENTRY_NAME_XML_SIGNATURE)
        .map(|(_, d)| d.clone())
        .ok_or_else(|| {
            AfirmaError::invalid_signature_format("No se ha encontrado la firma XML en el contenedor ASiC-S")
        })?;
    let (name, data) = entries
        .into_iter()
        .find(|(n, _)| afirma_core::asic::is_data_entry(n))
        .ok_or_else(|| {
            AfirmaError::invalid_signature_format("No se han encontrado los datos en el contenedor ASiC-S")
        })?;
    let name = name.rsplit('/').next().unwrap_or(&name).to_string();
    Ok((xml, name, data))
}

/// Resolutor de la URI relativa de los datos (`UriAndDataDereferencer`).
struct DataResolver(HashMap<String, Vec<u8>>);

impl Resolver for DataResolver {
    fn resolve(&self, uri: &str) -> Option<External> {
        self.0.get(uri).cloned().map(External::Octets)
    }
}

/// Valida las firmas XAdES de un contenedor ASiC-S resolviendo la referencia
/// relativa a los datos del propio contenedor (extensión sin equivalente en
/// Java, cuyo `SignValiderFactory` no tiene validador ASiC). Mismos
/// veredictos que [`crate::validation::validate`].
pub fn validate_container(
    sign: &[u8],
    check_certificates: bool,
) -> afirma_core::Result<Vec<afirma_core::validity::SignValidity>> {
    let (xml, name, data) = unpack(sign)?;
    let resolver = DataResolver(HashMap::from([(name, data)]));
    Ok(crate::validation::validate(&xml, check_certificates, &resolver))
}

/// Firmador XAdES-ASiC-S.
#[derive(Default)]
pub struct XadesAsicSigner;

impl XadesAsicSigner {
    pub fn new() -> Self {
        XadesAsicSigner
    }
}

impl Signer for XadesAsicSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_XADES_ASIC_S
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let mut p = extra.clone();
        set_asic_properties(&mut p, data);
        p.set("keepKeyInfoUnsigned", "true");
        p.set("format", FORMAT_EXTERNALLY_DETACHED);
        let digest_method = p
            .get_or("referencesDigestMethod", xades::DEFAULT_DIGEST_METHOD)
            .to_string();
        let ext = p
            .get("precalculatedHashAlgorithm")
            .unwrap_or(&digest_method)
            .to_string();
        let alg: afirma_core::DigestAlgorithm = afirma_core::algorithms::java_digest_algorithm_name(&ext)
            .replace('-', "")
            .parse()
            .map_err(|_| {
                AfirmaError::new(
                    codes::INVALID_REFERENCES_HASH_ALGORITHM_URI,
                    "No se reconoce el algoritmo de huella digital",
                )
            })?;
        let digest = alg.digest(data);
        let signature = XadesSigner::new().sign_optional(Some(&digest), algorithm, key, &p)?;
        create_container(&signature, data, p.get("uri").unwrap_or("dataobject.bin"))
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let (xml, name, data) = unpack(sign)?;
        let mut p = extra.clone();
        set_asic_properties(&mut p, &data);
        p.set("keepKeyInfoUnsigned", "true");
        let mut map = HashMap::new();
        map.insert(name.clone(), data.clone());
        let signer = XadesSigner::with_resolver(Arc::new(DataResolver(map)));
        let cosigned = signer.cosign(Some(&data), &xml, algorithm, key, &p)?;
        create_container(&cosigned, &data, &name)
    }

    fn countersign(
        &self,
        sign: &[u8],
        algorithm: &str,
        target: &CounterSignTarget,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        let (xml, name, data) = unpack(sign)?;
        let mut p = extra.clone();
        set_asic_properties(&mut p, &data);
        p.set("keepKeyInfoUnsigned", "true");
        let cs = XadesSigner::new().countersign(&xml, algorithm, target, key, &p)?;
        create_container(&cs, &data, &name)
    }

    fn signers_structure(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        xades::info::signers_structure(&xml_signature(sign)?)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        xml_signature(data).is_ok_and(|x| xades::info::is_sign(&x))
    }

    fn is_valid_data_file(&self, _data: &[u8]) -> bool {
        true
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        format!("{}{}.asics", original.unwrap_or("null"), in_text.unwrap_or(""))
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        let (_, _, data) = unpack(sign)?;
        Ok(Some(data))
    }

    fn sign_info(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        xades::info::sign_info(&xml_signature(sign)?)
    }
}
