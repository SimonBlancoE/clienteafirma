//! Selección automática del formato de firma.
//!
//! - Escritorio (`SignPanel.configureDataSigner`, spec 07 §4.4.A): PDF →
//!   FacturaE → OOXML → ODF → firma existente → XML → binario, con el formato
//!   por defecto de cada tipo tomado de las preferencias.
//! - Protocolo web con `format=auto` (§4.4.B).

use afirma_core::constants::*;
use afirma_core::formats::{DataFileType, SignerKind};
use afirma_core::{ExtraParams, Signer};

use crate::registry;

/// Operación que se propone para un fichero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposedOperation {
    Sign,
    /// El fichero ya está firmado: cofirmar (o contrafirmar según las
    /// preferencias `cadesMultisign`/`xadesMultisign`).
    Multisign,
}

/// Resultado del análisis de un fichero para la pantalla de firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAnalysis {
    pub file_type: DataFileType,
    /// Formato elegido (nombre de `AOSignConstants`).
    pub format: String,
    /// Formatos que el usuario puede elegir para este tipo de fichero.
    pub alternatives: Vec<String>,
    pub operation: ProposedOperation,
    /// Familia de la firma existente, si el fichero ya es una firma.
    pub existing_signature: Option<SignerKind>,
}

/// Formatos permitidos para cada tipo de fichero (orden del combo de
/// "Formatos de firma", spec 06 §4.6).
pub fn alternatives_for(file_type: DataFileType) -> &'static [&'static str] {
    match file_type {
        DataFileType::Pdf => &[SIGN_FORMAT_PADES, SIGN_FORMAT_CADES, SIGN_FORMAT_XADES],
        DataFileType::FacturaE => &[SIGN_FORMAT_FACTURAE, SIGN_FORMAT_XADES, SIGN_FORMAT_CADES],
        DataFileType::Ooxml => &[SIGN_FORMAT_OOXML, SIGN_FORMAT_CADES, SIGN_FORMAT_XADES],
        DataFileType::Odf => &[SIGN_FORMAT_ODF, SIGN_FORMAT_CADES, SIGN_FORMAT_XADES],
        DataFileType::Xml => &[SIGN_FORMAT_XADES, SIGN_FORMAT_CADES],
        DataFileType::Binary => &[SIGN_FORMAT_CADES, SIGN_FORMAT_XADES],
        DataFileType::SignXades | DataFileType::SignCades => &[],
    }
}

/// Analiza un fichero como la aplicación de escritorio. `pref` devuelve el
/// valor de una preferencia (los formatos por defecto de cada tipo).
pub fn analyze_for_desktop(data: &[u8], pref: &dyn Fn(&str) -> Option<String>) -> FileAnalysis {
    let params = ExtraParams::new();
    let pdf = registry::signer(SignerKind::Pdf);
    let facturae = registry::signer(SignerKind::FacturaE);

    let file_type = if pdf.as_ref().is_some_and(|s| s.is_valid_data_file(data)) {
        DataFileType::Pdf
    } else if facturae.as_ref().is_some_and(|s| s.is_valid_data_file(data)) {
        DataFileType::FacturaE
    } else if afirma_core::mime::office::is_ooxml_document(data) {
        DataFileType::Ooxml
    } else if afirma_core::mime::office::is_odf_document(data) {
        DataFileType::Odf
    } else if let Some((kind, _)) = registry::detect(data, &params) {
        let ft = if kind == SignerKind::Xades { DataFileType::SignXades } else { DataFileType::SignCades };
        return FileAnalysis {
            file_type: ft,
            format: afirma_core::formats::get_sign_format(kind).to_string(),
            alternatives: vec![afirma_core::formats::get_sign_format(kind).to_string()],
            operation: ProposedOperation::Multisign,
            existing_signature: Some(kind),
        };
    } else if afirma_core::mime::is_xml(data) {
        DataFileType::Xml
    } else {
        DataFileType::Binary
    };

    let (key, default) = file_type.default_format_preference().unwrap_or(("", SIGN_FORMAT_CADES));
    let alternatives: Vec<String> = alternatives_for(file_type).iter().map(|s| s.to_string()).collect();
    let mut format = pref(key).filter(|f| !f.trim().is_empty()).unwrap_or_else(|| default.to_string());
    if !alternatives.iter().any(|a| a.eq_ignore_ascii_case(&format)) {
        format = default.to_string();
    }
    // Un PDF ya firmado se cofirma (sigue siendo de tipo PDF).
    let mut operation = ProposedOperation::Sign;
    let mut existing = None;
    if file_type == DataFileType::Pdf {
        if let Some(s) = &pdf {
            if format.eq_ignore_ascii_case(SIGN_FORMAT_PADES) && s.is_sign(data, &params) {
                operation = ProposedOperation::Multisign;
                existing = Some(SignerKind::Pdf);
            }
        }
    }
    FileAnalysis { file_type, format, alternatives, operation, existing_signature: existing }
}

/// Operación criptográfica para la selección automática del protocolo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOp {
    Sign,
    Cosign,
    Countersign,
}

/// Formato para `format=auto` en el protocolo web
/// (`ProtocolInvocationLauncherUtil.identifyFormatFromData`). `None` si no
/// se reconoce la firma en cofirma/contrafirma (error 501009).
pub fn protocol_auto_format(op: CryptoOp, data: &[u8]) -> Option<String> {
    match op {
        CryptoOp::Sign => {
            let is_pdf = registry::signer(SignerKind::Pdf).is_some_and(|s| s.is_valid_data_file(data));
            let is_facturae = !is_pdf && registry::signer(SignerKind::FacturaE).is_some_and(|s| s.is_valid_data_file(data));
            let is_xml = !is_pdf && !is_facturae && afirma_core::mime::is_xml(data);
            Some(afirma_core::formats::protocol_auto_sign_format(is_pdf, is_facturae, is_xml).to_string())
        }
        CryptoOp::Cosign | CryptoOp::Countersign => registry::detect_format_name(data, &ExtraParams::new()).map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_prefs(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn classifies_common_inputs() {
        let a = analyze_for_desktop(b"hola mundo", &no_prefs);
        assert_eq!(a.file_type, DataFileType::Binary);
        assert_eq!(a.format, "CAdES");
        let x = analyze_for_desktop(b"<?xml version=\"1.0\"?><r><a/></r>", &no_prefs);
        assert_eq!(x.file_type, DataFileType::Xml);
        assert_eq!(x.format, "XAdES");
        // Con DOCTYPE AutoFirma no lo considera XML.
        let d = analyze_for_desktop(b"<!DOCTYPE r><r/>", &no_prefs);
        assert_eq!(d.file_type, DataFileType::Binary);
        let pref = |k: &str| (k == PREFERENCE_DEFAULT_SIGNATURE_FORMAT_XML).then(|| "CAdES".to_string());
        assert_eq!(analyze_for_desktop(b"<r/>", &pref).format, "CAdES");
        assert_eq!(protocol_auto_format(CryptoOp::Sign, b"<r/>").as_deref(), Some("XAdES"));
        assert_eq!(protocol_auto_format(CryptoOp::Sign, b"datos").as_deref(), Some("CAdES"));
        assert_eq!(protocol_auto_format(CryptoOp::Cosign, b"datos"), None);
    }
}
