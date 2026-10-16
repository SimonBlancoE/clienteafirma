//! Validación de firmas CMS/CAdES (`ValidateBinarySignature`) y detección
//! del perfil ASN.1 (`SignatureFormatDetectorPadesCades.resolveASN1Format`).
//!
//! Como en AutoFirma solo se comprueban la integridad criptográfica (huella
//! de los datos y firma de los atributos) y el periodo de validez de los
//! certificados; no se construyen cadenas ni se consulta la revocación.

use afirma_core::algorithms::DigestAlgorithm;
use afirma_core::error::ErrorKind;
use afirma_core::validity::{SignValidity, Validity, ValidityError, ko_priority, long_standing_priority};
use afirma_core::{ExtraParams, Signer};
use chrono::{DateTime, Utc};

use crate::alg;
use crate::asn1::der;
use crate::cades::CadesSigner;
use crate::cert::CertView;
use crate::cms::{SignedData, SignerInfo};
use crate::cms_signer::CmsSigner;
use crate::{oids, verify};

/// Perfiles de `ISignatureFormatDetector` usados para CMS/CAdES.
pub mod formats {
    pub const UNRECOGNIZED: &str = "No reconocido";
    pub const CMS: &str = "CMS";
    pub const CMS_T: &str = "CMS-T";
    pub const CADES_BES: &str = "CAdES-BES";
    pub const CADES_EPES: &str = "CAdES-EPES";
    pub const CADES_T: &str = "CAdES-T";
    pub const CADES_B_LEVEL: &str = "CAdES B-Level";
    pub const CADES_B_B_LEVEL: &str = "CAdES B-B-Level";
    pub const CADES_T_LEVEL: &str = "CAdES T-Level";
    pub const CADES_LT_LEVEL: &str = "CAdES LT-Level";
    pub const CADES_LTA_LEVEL: &str = "CAdES LTA-Level";
}

/// Perfiles que AutoFirma valida por completo (el resto da
/// `SIGN_PROFILE_NOT_CHECKED`).
pub const CHECKED_PROFILES: [&str; 6] = [
    formats::CADES_BES,
    formats::UNRECOGNIZED,
    formats::CADES_B_LEVEL,
    formats::CADES_B_B_LEVEL,
    formats::CMS,
    formats::CADES_EPES,
];

const LT_EXCLUDED: [&str; 11] = [
    oids::CERTIFICATE_REFS,
    oids::REVOCATION_REFS,
    oids::ATTR_CERTIFICATE_REFS,
    oids::ATTR_REVOCATION_REFS,
    oids::ESC_TIMESTAMP,
    oids::CERT_CRL_TIMESTAMP,
    oids::CERT_VALUES,
    oids::REVOCATION_VALUES,
    oids::ARCHIVE_TIMESTAMP,
    oids::ARCHIVE_TIMESTAMP_V2,
    oids::LONG_TERM_VALIDATION,
];

/// Perfil de un firmante (`resolveASN1Format`).
pub fn resolve_asn1_format(sd: &SignedData<'_>, si: &SignerInfo<'_>) -> &'static str {
    if si.signed_attrs.is_none() || si.signed_attributes().is_err() {
        return formats::UNRECOGNIZED;
    }
    let has = |o: &str| si.has_signed_attr(o);
    let is_t = si.has_unsigned_attr(oids::SIGNATURE_TIMESTAMP_TOKEN);
    let is_cms = !has(oids::SIGNING_CERTIFICATE) && !has(oids::SIGNING_CERTIFICATE_V2) && !has(oids::OTHER_SIG_CERT);
    let is_b_level = has(oids::SIGNING_TIME);
    let is_lt = || LT_EXCLUDED.iter().all(|o| !si.has_unsigned_attr(o)) && sd.has_crls();
    let is_lta = || si.has_unsigned_attr(oids::ARCHIVE_TIMESTAMP_V3);
    let baseline = || {
        let mut f = formats::CADES_B_LEVEL;
        if is_t {
            f = formats::CADES_T_LEVEL;
            if is_lt() {
                f = formats::CADES_LT_LEVEL;
                if is_lta() {
                    f = formats::CADES_LTA_LEVEL;
                }
            }
        }
        f
    };
    if is_cms {
        return if is_t { formats::CMS_T } else { formats::CMS };
    }
    if has(oids::SIG_POLICY_ID) {
        return if is_b_level {
            baseline()
        } else if is_t {
            formats::CADES_T
        } else {
            formats::CADES_EPES
        };
    }
    // BES (incluye signingCertificateV2, por lo que B-B-Level es inalcanzable).
    if is_b_level { baseline() } else { formats::CADES_BES }
}

enum VerifyFailure {
    DigestMismatch,
    Other(String),
}

/// Valor único de un atributo firmado (`getSingleValuedSignedAttribute`).
fn single_valued<'a>(si: &SignerInfo<'a>, oid: &str) -> Result<Option<crate::asn1::Tlv<'a>>, VerifyFailure> {
    let attrs = si.signed_attributes().map_err(|e| VerifyFailure::Other(e.to_string()))?;
    let found: Vec<_> = attrs.into_iter().filter(|a| a.is(oid)).collect();
    match found.as_slice() {
        [] => Ok(None),
        [a] if a.values.len() == 1 => Ok(Some(a.values[0])),
        _ => Err(VerifyFailure::Other(format!("El atributo {oid} debe tener un unico valor"))),
    }
}

/// Verificación de un firmante con las comprobaciones de
/// `SignerInformation.verify` de Bouncy Castle.
fn bc_verify(
    sd: &SignedData<'_>,
    si: &SignerInfo<'_>,
    cert: &[u8],
    content: Option<&[u8]>,
    is_countersignature: bool,
) -> Result<bool, VerifyFailure> {
    let view = CertView::parse(cert).map_err(|e| VerifyFailure::Other(e.to_string()))?;
    // Validez del certificado en la fecha de firma.
    if si.signed_attrs.is_some() {
        if let Some(t) = single_valued(si, oids::SIGNING_TIME)? {
            let when = t.as_time().map_err(|e| VerifyFailure::Other(e.to_string()))?;
            if !view.is_valid_at(when) {
                return Err(VerifyFailure::Other("verifier not valid at signingTime".into()));
            }
        }
    }
    let digest = DigestAlgorithm::from_oid(&si.digest_oid.to_dotted())
        .ok_or_else(|| VerifyFailure::Other(format!("Algoritmo de huella no soportado: {}", si.digest_oid)))?;
    let sig_alg = alg::signer_signature_algorithm(&si.digest_oid.to_dotted(), &si.signature_oid.to_dotted())
        .ok_or_else(|| VerifyFailure::Other(format!("Algoritmo de firma no soportado: {}", si.signature_oid)))?;
    let Some(_) = si.signed_attrs else {
        let content = content.ok_or_else(|| {
            VerifyFailure::Other("data not encapsulated in signature - use detached constructor.".into())
        })?;
        return verify::verify_with_certificate(cert, sig_alg, content, &si.signature_value())
            .map_err(|e| VerifyFailure::Other(e.to_string()));
    };
    let result_digest = digest.digest(content.unwrap_or_default());
    // contentType.
    match single_valued(si, oids::CONTENT_TYPE)? {
        None if !is_countersignature => {
            return Err(VerifyFailure::Other(
                "The content-type attribute type MUST be present whenever signed attributes are present in signed-data"
                    .into(),
            ));
        }
        None => {}
        Some(ct) => {
            if is_countersignature {
                return Err(VerifyFailure::Other(
                    "[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute"
                        .into(),
                ));
            }
            let oid = ct.as_oid().map_err(|_| {
                VerifyFailure::Other("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'".into())
            })?;
            if oid != sd.econtent_type {
                return Err(VerifyFailure::Other("content-type attribute value does not match eContentType".into()));
            }
        }
    }
    // messageDigest.
    let md = single_valued(si, oids::MESSAGE_DIGEST)?
        .ok_or_else(|| {
            VerifyFailure::Other(
                "the message-digest signed attribute type MUST be present when there are any signed attributes present"
                    .into(),
            )
        })?
        .octet_string_content()
        .map_err(|e| VerifyFailure::Other(e.to_string()))?;
    if md != result_digest {
        return Err(VerifyFailure::DigestMismatch);
    }
    if si.has_signed_attr(oids::COUNTER_SIGNATURE) {
        return Err(VerifyFailure::Other("A countersignature attribute MUST NOT be a signed attribute".into()));
    }
    for ua in si.unsigned_attributes().map_err(|e| VerifyFailure::Other(e.to_string()))? {
        if ua.is(oids::COUNTER_SIGNATURE) && ua.values.is_empty() {
            return Err(VerifyFailure::Other(
                "A countersignature attribute MUST contain at least one AttributeValue".into(),
            ));
        }
    }
    let tbs =
        si.signed_attrs_to_be_signed().ok_or_else(|| VerifyFailure::Other("atributos firmados no validos".into()))?;
    let sig = si.signature_value();
    let ok =
        verify::verify_with_certificate(cert, sig_alg, &tbs, &sig).map_err(|e| VerifyFailure::Other(e.to_string()))?;
    if ok {
        return Ok(true);
    }
    // Bouncy Castle verifica sobre la codificación DER (ordenada) de los atributos.
    let sorted = crate::asn1::Tlv::parse_single(&tbs)
        .ok()
        .and_then(|t| t.children().ok())
        .map(|c| der::set_of(c.iter().map(|x| x.raw.to_vec())));
    match sorted {
        Some(s) if s != tbs => {
            verify::verify_with_certificate(cert, sig_alg, &s, &sig).map_err(|e| VerifyFailure::Other(e.to_string()))
        }
        _ => Ok(false),
    }
}

/// `ValidateBinarySignature.verifySign` para un firmante de primer nivel.
pub fn verify_signer(
    sd: &SignedData<'_>,
    si: &SignerInfo<'_>,
    content: Option<&[u8]>,
    check_certificates: bool,
    now: DateTime<Utc>,
) -> Vec<SignValidity> {
    let mut result = Vec::new();
    let profile = resolve_asn1_format(sd, si);
    // Certificado por número de serie (sin mirar el emisor).
    let cert = si.issuer_and_serial().and_then(|(_, serial)| sd.find_certificate_by_serial(serial));
    match cert {
        None => result.push(
            SignValidity::ko(ValidityError::CantValidateCert)
                .with_detail("No se encuentra el certificado del firmante"),
        ),
        Some(cert) => {
            let view = CertView::parse(cert);
            let validity = view.as_ref().map(|v| (v.not_before_time(), v.not_after_time()));
            match validity {
                Ok((Ok(_), Ok(na))) if check_certificates && now > na => {
                    result.push(SignValidity::ko(ValidityError::CertificateExpired));
                }
                Ok((Ok(nb), Ok(_))) if check_certificates && now < nb => {
                    result.push(SignValidity::ko(ValidityError::CertificateNotValidYet));
                }
                Ok(_) => match bc_verify(sd, si, cert, content, false) {
                    Ok(true) => {}
                    Ok(false) => {
                        result.push(SignValidity::ko(ValidityError::CantValidateCert).with_detail("Firma no valida"))
                    }
                    Err(VerifyFailure::DigestMismatch) => {
                        if content.is_some() {
                            result.push(
                                SignValidity::ko(ValidityError::NoMatchData)
                                    .with_detail("message-digest attribute value does not match calculated value"),
                            );
                        }
                    }
                    Err(VerifyFailure::Other(m)) => {
                        result.push(SignValidity::ko(ValidityError::CantValidateCert).with_detail(m))
                    }
                },
                Err(e) => result.push(SignValidity::ko(ValidityError::CantValidateCert).with_detail(e.to_string())),
            }
        }
    }
    if !CHECKED_PROFILES.contains(&profile) {
        result.push(SignValidity::unknown(ValidityError::SignProfileNotChecked));
    }
    if result.is_empty() {
        result.push(SignValidity::ok());
    }
    result
}

/// Valida una firma CMS/CAdES (`ValidateBinarySignature.validate(sign, data,
/// checkCertificates)`) en el instante indicado.
pub fn validate_at(
    sign: &[u8],
    data: Option<&[u8]>,
    check_certificates: bool,
    now: DateTime<Utc>,
) -> Vec<SignValidity> {
    let params = ExtraParams::new();
    let signer: &dyn Signer = if CadesSigner.is_sign(sign, &params) {
        &CadesSigner
    } else if CmsSigner.is_sign(sign, &params) {
        &CmsSigner
    } else {
        return vec![SignValidity::ko(ValidityError::NoSign)];
    };
    let mut list = Vec::new();
    let signed_data: Option<Vec<u8>> = match data {
        Some(d) => Some(d.to_vec()),
        None => match signer.get_data(sign, &params) {
            Ok(Some(d)) => Some(d),
            Ok(None) => {
                list.push(SignValidity::unknown(ValidityError::NoData));
                None
            }
            Err(e) if e.kind == ErrorKind::InvalidSignatureFormat => {
                list.push(SignValidity::ko(ValidityError::NoSign).with_detail(e.to_string()));
                None
            }
            Err(_) => {
                list.push(SignValidity::ko(ValidityError::UnknownError));
                None
            }
        },
    };
    match SignedData::parse(sign) {
        Ok(sd) => {
            for si in &sd.signer_infos {
                for v in verify_signer(&sd, si, signed_data.as_deref(), check_certificates, now) {
                    if v.validity == Validity::Unknown {
                        list.insert(0, v);
                    } else {
                        list.push(v);
                    }
                }
            }
        }
        Err(e) => list.push(SignValidity::new(Validity::Ko, None).with_detail(e.to_string())),
    }
    long_standing_priority(ko_priority(list))
}

/// Valida una firma CMS/CAdES en el instante actual.
pub fn validate(sign: &[u8], data: Option<&[u8]>, check_certificates: bool) -> Vec<SignValidity> {
    validate_at(sign, data, check_certificates, Utc::now())
}

/// Comprueba la firma de un sello de tiempo de forma aislada (para la
/// interfaz de validación): devuelve `true` si es criptográficamente válido.
pub fn verify_timestamp_token(token: &[u8]) -> bool {
    let Ok(info) = crate::tsp::parse_timestamp_token(token) else { return false };
    let Some(cert) = &info.tsa_certificate else { return false };
    let Ok(sd) = SignedData::parse(token) else { return false };
    let Some(si) = sd.signer_infos.first() else { return false };
    sd.content().is_some_and(|c| crate::tsp::verify_signer_info(si, cert, Some(&c)).unwrap_or(false))
}
