//! Validación de firmas (`SignValiderFactory`, spec 07 §11.3).

use afirma_core::validity::{SignValidity, ValidityError, ko_priority, long_standing_priority};
use afirma_core::{ExtraParams, formats::SignerKind};

use crate::registry;

/// Tipo de validador elegido para unos datos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorKind {
    Pdf,
    Xml,
    Ooxml,
    Odf,
    Binary,
}

/// Elige el validador por el contenido, en el orden de AutoFirma: PDF →
/// FacturaE/XML → OOXML → ODF → binario.
pub fn validator_for(data: &[u8]) -> ValidatorKind {
    if registry::signer(SignerKind::Pdf).is_some_and(|s| s.is_valid_data_file(data)) {
        ValidatorKind::Pdf
    } else if registry::signer(SignerKind::FacturaE).is_some_and(|s| s.is_valid_data_file(data))
        || afirma_core::mime::is_xml(data)
    {
        ValidatorKind::Xml
    } else if afirma_core::mime::office::is_ooxml_document(data) {
        ValidatorKind::Ooxml
    } else if afirma_core::mime::office::is_odf_document(data) {
        ValidatorKind::Odf
    } else {
        ValidatorKind::Binary
    }
}

/// Valida una firma (o un documento firmado). El primer elemento es el
/// veredicto global; el resto, detalles. `params` admite las opciones de
/// validación de PDF (`allowShadowAttack`, `pagesToCheckShadowAttack`,
/// `allowModifiedForm`, contraseñas).
pub fn validate(data: &[u8], params: &ExtraParams) -> Vec<SignValidity> {
    if data.is_empty() {
        return vec![SignValidity::ko(ValidityError::UnknownSignatureFormat)];
    }
    if let Some(list) = validate_asic(data) {
        return list;
    }
    let list = match validator_for(data) {
        ValidatorKind::Pdf => match afirma_pdf::validate::validate_pdf(data, params, false) {
            Ok(l) => l,
            Err(e) => vec![SignValidity::ko(ValidityError::UnknownError).with_detail(e.to_string())],
        },
        ValidatorKind::Xml => afirma_xml::validation::validate(data, true, &afirma_xml::dsig::NoResolver),
        ValidatorKind::Ooxml => vec![SignValidity::unknown(ValidityError::OoxmlUnknownValidity)],
        ValidatorKind::Odf => vec![SignValidity::unknown(ValidityError::OdfUnknownValidity)],
        ValidatorKind::Binary => afirma_cms::validation::validate(data, None, true),
    };
    if list.is_empty() {
        return vec![SignValidity::ko(ValidityError::UnknownSignatureFormat)];
    }
    long_standing_priority(ko_priority(list))
}

/// Valida un contenedor ASiC-S (CAdES o XAdES) comprobando la firma contra
/// los datos que contiene. AutoFirma (Java) no valida estos contenedores
/// (los trata como binarios y devuelve "no es una firma"); es una mejora
/// documentada en `docs/deviations/afirma-signers.md`.
fn validate_asic(data: &[u8]) -> Option<Vec<SignValidity>> {
    if !afirma_core::mime::is_zip(data) {
        return None;
    }
    let mut files = afirma_core::asic::get_data(data).ok()?;
    let name = afirma_core::asic::get_data_filename(data).ok()?;
    let content = files.remove(&name).unwrap_or_default();
    if let Ok(p7s) = afirma_core::asic::get_binary_signature(data) {
        return Some(validate_detached(&p7s, &content));
    }
    if let Ok(xml) = afirma_core::asic::get_xml_signature(data) {
        let resolver = move |uri: &str| {
            let uri = uri.trim_start_matches("./");
            (uri == name).then(|| afirma_xml::dsig::External::Octets(content.clone()))
        };
        let list = afirma_xml::validation::validate(&xml, true, &resolver);
        if list.is_empty() {
            return Some(vec![SignValidity::ko(ValidityError::UnknownSignatureFormat)]);
        }
        return Some(long_standing_priority(ko_priority(list)));
    }
    None
}

/// Valida una firma explícita (separada) con sus datos originales.
pub fn validate_detached(sign: &[u8], data: &[u8]) -> Vec<SignValidity> {
    let list = afirma_cms::validation::validate(sign, Some(data), true);
    if list.is_empty() {
        return vec![SignValidity::ko(ValidityError::UnknownSignatureFormat)];
    }
    long_standing_priority(ko_priority(list))
}
