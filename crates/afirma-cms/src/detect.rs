//! Detección de firmas CMS/CAdES y extracción de datos
//! (`CAdESValidator`, `ValidateCMSSignedData`, `ObtainContentSignedData`).

use afirma_core::algorithms::DigestAlgorithm;
use afirma_core::error::AfirmaError;

use crate::asn1::tags;
use crate::cms::{SignedData, parse_content_info};
use crate::oids;

/// `CAdESValidator.isCAdESSignedData`: es un `SignedData` y, si se exige
/// CAdES, todos sus firmantes tienen `signingCertificate` o
/// `signingCertificateV2` (un firmante sin atributos firmados hace que no lo sea).
pub fn is_cades_signed_data(data: &[u8], enforce_cades: bool) -> bool {
    let Ok(sd) = SignedData::parse(data) else { return false };
    if !enforce_cades {
        return true;
    }
    sd.signer_infos.iter().all(|si| {
        si.signed_attrs.is_some()
            && si.signed_attributes().is_ok_and(|attrs| {
                attrs.iter().any(|a| a.is(oids::SIGNING_CERTIFICATE) || a.is(oids::SIGNING_CERTIFICATE_V2))
            })
    })
}

/// `ValidateCMSSignedData.isCMSSignedData`: es un `SignedData` y ningún
/// firmante tiene política de firma (`sigPolicyId`). Los firmantes sin
/// atributos firmados hacen que no lo sea.
pub fn is_cms_signed_data(data: &[u8]) -> bool {
    let Ok(sd) = SignedData::parse(data) else { return false };
    sd.signer_infos.iter().all(|si| {
        si.signed_attrs.is_some()
            && si.signed_attributes().is_ok_and(|attrs| !attrs.iter().any(|a| a.is(oids::SIG_POLICY_ID)))
    })
}

/// `CAdESValidator.isCAdESValid(data, enforce)`: `ContentInfo` de tipo Data,
/// SignedData, DigestedData, EncryptedData, EnvelopedData o
/// SignedAndEnvelopedData.
pub fn is_cades_valid(data: &[u8], enforce_cades: bool) -> bool {
    let Ok((oid, content, _)) = parse_content_info(data) else { return false };
    let Some(content) = content else { return false };
    match oid.to_dotted().as_str() {
        oids::DATA => true,
        oids::SIGNED_DATA => is_cades_signed_data(data, enforce_cades),
        oids::DIGESTED_DATA | oids::ENVELOPED_DATA | oids::ENCRYPTED_DATA | oids::SIGNED_AND_ENVELOPED_DATA => {
            content.tag == tags::SEQUENCE && content.children().is_ok_and(|c| c.len() >= 2)
        }
        _ => false,
    }
}

/// `ObtainContentSignedData.obtainData`: contenido firmado de un
/// `SignedData` implícito, `None` si es explícito o no es `SignedData`.
pub fn obtain_data(sign: &[u8]) -> afirma_core::Result<Option<Vec<u8>>> {
    let (oid, content, ci) = parse_content_info(sign)
        .map_err(|e| AfirmaError::invalid_signature_format(format!("Error al parsear la firma ASN.1: {e}")))?;
    if !oid.is(oids::SIGNED_DATA) {
        tracing::warn!("La firma proporcionada no es de tipo SignedData");
        return Ok(None);
    }
    let content = content.ok_or_else(|| AfirmaError::invalid_signature_format("Error al parsear la firma ASN.1"))?;
    let sd = SignedData::parse_signed_data(ci, content)
        .map_err(|e| AfirmaError::invalid_signature_format(format!("Error al parsear la firma ASN.1: {e}")))?;
    Ok(sd.content())
}

/// `ObtainContentSignedData.obtainMessageDigest`: `messageDigest` del
/// primer firmante con el algoritmo de huella indicado.
pub fn obtain_message_digest(sign: &[u8], digest: DigestAlgorithm) -> Option<Vec<u8>> {
    let sd = SignedData::parse(sign).ok()?;
    sd.signer_infos.iter().filter(|si| si.digest_oid.is(digest.oid())).find_map(|si| si.message_digest())
}
