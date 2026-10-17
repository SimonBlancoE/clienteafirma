//! Validación de firmas XML (`ValidateXMLSignature`) y detección del nivel
//! XAdES (`SignatureFormatDetectorXades`).
//!
//! Igual que AutoFirma Java, solo se comprueba la integridad criptográfica de
//! cada `ds:Signature` (valor de firma y referencias), el periodo de validez de
//! los certificados incluidos en `KeyInfo` y el perfil de la firma: no se
//! construyen cadenas de confianza ni se consulta la revocación.

use afirma_core::validity::{SignValidity, Validity, ValidityError};

use crate::dom::{Document, NodeId};
use crate::dsig::{self, DSIG_NS, DsigError, Resolver};

/// Constantes de formato (`ISignatureFormatDetector`).
pub mod level {
    pub const UNRECOGNIZED: &str = "No reconocido";
    pub const XADES_BES: &str = "XAdES-BES";
    pub const XADES_EPES: &str = "XAdES-EPES";
    pub const XADES_T: &str = "XAdES-T";
    pub const XADES_C: &str = "XAdES-C";
    pub const XADES_X1: &str = "XAdES-X1";
    pub const XADES_X2: &str = "XAdES-X2";
    pub const XADES_XL1: &str = "XAdES-XL1";
    pub const XADES_XL2: &str = "XAdES-XL2";
    pub const XADES_A: &str = "XAdES-A";
    pub const XADES_B_LEVEL: &str = "XAdES B-Level";
    pub const XADES_B_B_LEVEL: &str = "XAdES B-B-Level";
    pub const XADES_T_LEVEL: &str = "XAdES T-Level";
    pub const XADES_LT_LEVEL: &str = "XAdES LT-Level";
    pub const XADES_LTA_LEVEL: &str = "XAdES LTA-Level";
}

const NS132: &str = "http://uri.etsi.org/01903/v1.3.2#";
const NS141: &str = "http://uri.etsi.org/01903/v1.4.1#";

/// `getXMLElement`: primer descendiente con el espacio de nombres y nombre
/// dados o, si no hay, el primero cuyo nombre cualificado sea `name`.
fn xml_element(doc: &Document, parent: NodeId, ns: &str, name: &str) -> Option<NodeId> {
    doc.find_descendants(parent, ns, name).into_iter().next().or_else(|| {
        doc.descendants(parent)
            .into_iter()
            .skip(1)
            .find(|&n| doc.element(n).is_some_and(|e| e.qname() == name))
    })
}

fn has_desc(doc: &Document, parent: NodeId, ns: &str, name: &str) -> bool {
    !doc.find_descendants(parent, ns, name).is_empty()
}

fn usp(doc: &Document, sig: NodeId) -> Option<NodeId> {
    let up = xml_element(doc, sig, NS132, "UnsignedProperties")?;
    xml_element(doc, up, NS132, "UnsignedSignatureProperties")
}

fn usp_has(doc: &Document, sig: NodeId, ns: &str, name: &str) -> bool {
    usp(doc, sig).is_some_and(|u| xml_element(doc, u, ns, name).is_some())
}

/// `hasSignaturePolicyIdentifier`.
pub fn has_signature_policy_identifier(doc: &Document, sig: NodeId) -> bool {
    xml_element(doc, sig, NS132, "SignedProperties")
        .and_then(|sp| xml_element(doc, sp, NS132, "SignedSignatureProperties"))
        .is_some_and(|ssp| xml_element(doc, ssp, NS132, "SignaturePolicyIdentifier").is_some())
}

fn is_bes(doc: &Document, sig: NodeId) -> bool {
    xml_element(doc, sig, NS132, "QualifyingProperties").is_some()
}

fn is_b_level_with(doc: &Document, sig: NodeId, cert_tag: &str) -> bool {
    if has_desc(doc, sig, NS132, "QualifyingPropertiesReference") {
        return false;
    }
    let Some(sp) = doc.find_descendants(sig, NS132, "SignedProperties").into_iter().next() else {
        return false;
    };
    let mut has_cert = false;
    let mut has_time = false;
    if has_desc(doc, sp, NS132, "SignedSignatureProperties") {
        // Java toma la primera SignedSignatureProperties bajo la firma.
        if let Some(ssp) = doc
            .find_descendants(sig, NS132, "SignedSignatureProperties")
            .into_iter()
            .next()
        {
            has_cert = has_desc(doc, ssp, NS132, cert_tag);
            has_time = has_desc(doc, ssp, NS132, "SigningTime");
        }
    }
    let mut has_dof = false;
    let mut has_mime = false;
    if let Some(sdop) = doc
        .find_descendants(sp, NS132, "SignedDataObjectProperties")
        .into_iter()
        .next()
        && let Some(dof) = xml_element(doc, sdop, NS132, "DataObjectFormat")
    {
        has_dof = true;
        has_mime = has_desc(doc, dof, NS132, "MimeType");
    }
    has_time && has_cert && has_dof && has_mime
}

fn is_t(doc: &Document, sig: NodeId) -> bool {
    usp_has(doc, sig, NS132, "SignatureTimeStamp")
}

fn is_c(doc: &Document, sig: NodeId) -> bool {
    usp_has(doc, sig, NS132, "CompleteCertificateRefs") && usp_has(doc, sig, NS132, "CompleteRevocationRefs")
}

fn is_x1(doc: &Document, sig: NodeId) -> bool {
    usp_has(doc, sig, NS132, "SigAndRefsTimeStamp")
}

fn is_x2(doc: &Document, sig: NodeId) -> bool {
    usp_has(doc, sig, NS132, "RefsOnlyTimeStamp")
}

fn is_xl1(doc: &Document, sig: NodeId) -> bool {
    is_x1(doc, sig) && usp_has(doc, sig, NS132, "CertificateValues") && usp_has(doc, sig, NS132, "RevocationValues")
}

fn is_xl2(doc: &Document, sig: NodeId) -> bool {
    is_x2(doc, sig) && usp_has(doc, sig, NS132, "CertificateValues") && usp_has(doc, sig, NS132, "RevocationValues")
}

fn is_a(doc: &Document, sig: NodeId) -> bool {
    usp(doc, sig).is_some_and(|u| {
        doc.child_elements(u)
            .any(|c| doc.element(c).is_some_and(|e| e.local == "ArchiveTimeStamp"))
    })
}

/// `isXAdESLTLevel`, con el fallo de Java (el valor de `RevocationValues` se
/// asigna a `hasCertificateValues` y `hasRevocationValues` es siempre falso).
fn is_lt(doc: &Document, sig: NodeId) -> bool {
    let Some(_) = usp(doc, sig) else { return false };
    let has_ts_validation_data = usp_has(doc, sig, NS141, "TimeStampValidationData");
    let refs = [
        "CompleteCertificateRefs",
        "CompleteRevocationRefs",
        "AttributeCertificateRefs",
        "AttributeRevocationRefs",
        "SigAndRefsTimeStamp",
        "RefsOnlyTimeStamp",
    ];
    has_ts_validation_data && !refs.iter().any(|r| usp_has(doc, sig, NS132, r))
}

fn baseline_format(tmp: &'static str, doc: &Document, sig: NodeId) -> &'static str {
    if is_b_level_with(doc, sig, "SigningCertificate") {
        let mut f = level::XADES_B_LEVEL;
        if is_t(doc, sig) {
            f = level::XADES_T_LEVEL;
            if is_lt(doc, sig) {
                f = level::XADES_LT_LEVEL;
                if is_a(doc, sig) {
                    f = level::XADES_LTA_LEVEL;
                }
            }
        }
        f
    } else if is_b_level_with(doc, sig, "SigningCertificateV2") {
        level::XADES_B_B_LEVEL
    } else {
        tmp
    }
}

fn no_baseline_format(tmp: &'static str, doc: &Document, sig: NodeId) -> &'static str {
    if is_a(doc, sig) {
        level::XADES_A
    } else if is_xl1(doc, sig) {
        level::XADES_XL1
    } else if is_xl2(doc, sig) {
        level::XADES_XL2
    } else if is_x1(doc, sig) {
        level::XADES_X1
    } else if is_x2(doc, sig) {
        level::XADES_X2
    } else if is_c(doc, sig) {
        level::XADES_C
    } else if is_t(doc, sig) && tmp != level::XADES_T_LEVEL {
        level::XADES_T
    } else {
        tmp
    }
}

/// `SignatureFormatDetectorXades.resolveSignerXAdESFormat`.
pub fn resolve_signer_format(doc: &Document, sig: NodeId) -> &'static str {
    let base = if has_signature_policy_identifier(doc, sig) {
        level::XADES_EPES
    } else if is_bes(doc, sig) {
        level::XADES_BES
    } else {
        return level::UNRECOGNIZED;
    };
    let f = baseline_format(base, doc, sig);
    if f == base {
        no_baseline_format(base, doc, sig)
    } else {
        f
    }
}

/// `getListSignatures`: firmas que no pertenecen a un sello de tiempo XML.
pub fn list_signatures(doc: &Document) -> Vec<NodeId> {
    doc.find_descendants(doc.root(), DSIG_NS, "Signature")
        .into_iter()
        .filter(|&s| {
            doc.parent(s)
                .and_then(|p| doc.element(p))
                .is_none_or(|e| e.local != "XMLTimeStamp")
        })
        .collect()
}

/// `SignatureFormatDetectorXades.getSignatureFormat` (documento completo).
pub fn signature_format(data: &[u8]) -> &'static str {
    let Some(doc) = crate::xades::sign::load_xml(data).map(|x| x.doc) else {
        return level::UNRECOGNIZED;
    };
    let sigs = list_signatures(&doc);
    let any = |f: &dyn Fn(NodeId) -> bool| sigs.iter().any(|&s| f(s));
    let base = if any(&|s| has_signature_policy_identifier(&doc, s)) {
        level::XADES_EPES
    } else if any(&|s| is_bes(&doc, s)) {
        level::XADES_BES
    } else {
        return level::UNRECOGNIZED;
    };
    let mut f = base;
    if sigs
        .first()
        .is_some_and(|&s| is_b_level_with(&doc, s, "SigningCertificate"))
    {
        f = level::XADES_B_LEVEL;
        if any(&|s| is_t(&doc, s)) {
            f = level::XADES_T_LEVEL;
            if any(&|s| is_lt(&doc, s)) {
                f = level::XADES_LT_LEVEL;
                if any(&|s| is_a(&doc, s)) {
                    f = level::XADES_LTA_LEVEL;
                }
            }
        }
    }
    if f != base {
        return f;
    }
    if any(&|s| is_a(&doc, s)) {
        level::XADES_A
    } else if any(&|s| is_xl1(&doc, s)) {
        level::XADES_XL1
    } else if any(&|s| is_xl2(&doc, s)) {
        level::XADES_XL2
    } else if any(&|s| is_x1(&doc, s)) {
        level::XADES_X1
    } else if any(&|s| is_x2(&doc, s)) {
        level::XADES_X2
    } else if any(&|s| is_c(&doc, s)) {
        level::XADES_C
    } else if any(&|s| is_t(&doc, s)) {
        level::XADES_T
    } else {
        base
    }
}

/// `isXAdESBaseline`.
pub fn is_xades_baseline(format: &str) -> bool {
    matches!(
        format,
        level::XADES_B_LEVEL | level::XADES_T_LEVEL | level::XADES_LT_LEVEL | level::XADES_LTA_LEVEL
    )
}

/// Perfiles que AutoFirma puede validar completamente.
fn profile_checked(f: &str) -> bool {
    matches!(
        f,
        level::XADES_B_LEVEL | level::UNRECOGNIZED | level::XADES_B_B_LEVEL | level::XADES_BES | level::XADES_EPES
    )
}

/// `SignValider.checkLongStandingValiditySign`.
pub fn check_long_standing(mut list: Vec<SignValidity>) -> Vec<SignValidity> {
    let expired = list
        .iter()
        .any(|v| v.validity == Validity::Ko && v.error == Some(ValidityError::CertificateExpired));
    let other_ko = list
        .iter()
        .any(|v| v.validity == Validity::Ko && v.error != Some(ValidityError::CertificateExpired));
    if expired
        && !other_ko
        && let Some(pos) = list
            .iter()
            .rposition(|v| v.validity == Validity::Unknown && v.error == Some(ValidityError::SignProfileNotChecked))
    {
        list.swap(0, pos);
    }
    list
}

enum Abort {
    BadBuild(String),
    Unknown(String),
}

fn classify(e: DsigError) -> Abort {
    match e {
        DsigError::Dereference(_) | DsigError::Processing(_) | DsigError::KeyNotFound => Abort::BadBuild(e.to_string()),
        DsigError::Malformed(_) | DsigError::Unsupported(_) => Abort::Unknown(e.to_string()),
    }
}

fn push_abort(result: &mut Vec<SignValidity>, e: DsigError) {
    match classify(e) {
        Abort::BadBuild(m) => result.push(SignValidity::ko(ValidityError::BadBuildSign).with_detail(m)),
        Abort::Unknown(m) => result.push(SignValidity::unknown(ValidityError::UnknownError).with_detail(m)),
    }
}

/// Certificado del firmante (primer `X509Certificate` de `KeyInfo`) de
/// cada `ds:Signature` del documento, en orden.
pub fn signature_certificates(sign: &[u8]) -> Vec<Vec<u8>> {
    let Some(x) = crate::xades::sign::load_xml(sign) else {
        return Vec::new();
    };
    let doc = x.doc;
    doc.find_descendants(doc.root(), DSIG_NS, "Signature")
        .into_iter()
        .filter_map(|s| keyinfo_certificates(&doc, s).and_then(|v| v.into_iter().next()))
        .collect()
}

/// Certificados de los `X509Data` de `KeyInfo` (DER).
fn keyinfo_certificates(doc: &Document, sig: NodeId) -> Option<Vec<Vec<u8>>> {
    let ki = dsig::ds_child(doc, sig, "KeyInfo")?;
    let mut out = Vec::new();
    for xd in dsig::ds_children(doc, ki, "X509Data") {
        for c in dsig::ds_children(doc, xd, "X509Certificate") {
            if let Some(der) = crate::util::b64_decode(&doc.text_content(c)) {
                out.push(der);
            }
        }
    }
    Some(out)
}

/// Resultado de validar un documento XML firmado (`ValidateXMLSignature.validate`),
/// con la validación segura de AutoFirma 1.9.
pub fn validate(sign: &[u8], check_certificates: bool, resolver: &dyn Resolver) -> Vec<SignValidity> {
    validate_with(sign, check_certificates, resolver, dsig::RefOptions::default())
}

/// [`validate`] con opciones de proceso de las referencias (por ejemplo, sin
/// validación segura para aplicar la transformada XSLT, que AutoFirma 1.9
/// rechaza).
pub fn validate_with(
    sign: &[u8],
    check_certificates: bool,
    resolver: &dyn Resolver,
    options: dsig::RefOptions,
) -> Vec<SignValidity> {
    let doc = match crate::xades::sign::load_xml(sign) {
        Some(x) => x.doc,
        None => return vec![SignValidity::ko(ValidityError::NoSign)],
    };
    let sigs = doc.find_descendants(doc.root(), DSIG_NS, "Signature");
    if sigs.is_empty() {
        return vec![SignValidity::ko(ValidityError::NoSign)];
    }
    let mut result = Vec::new();
    let mut no_match = false;
    let mut expired_reported = false;
    let now = chrono::Utc::now();
    'firmas: for sig in sigs {
        // 1. `unmarshalXMLSignature`: algoritmos no reconocidos -> MarshalException.
        if let Err(e) = dsig::unmarshal_check(&doc, sig) {
            push_abort(&mut result, e);
            break;
        }
        // 2. `signature.validate()`: primero el valor de firma; si es correcto,
        //    las referencias (una excepción en cualquiera aborta).
        let sv_ok = match dsig::verify_signature_value(&doc, sig, None) {
            Ok(v) => v,
            Err(e) => {
                push_abort(&mut result, e);
                break;
            }
        };
        let Some(si) = dsig::ds_child(&doc, sig, "SignedInfo") else {
            break;
        };
        let ctx = dsig::RefContext {
            doc: &doc,
            signature: sig,
            resolver,
            options,
        };
        let refs = dsig::ds_children(&doc, si, "Reference");
        let uri_of = |r: NodeId| doc.element(r).and_then(|e| e.attr("URI")).unwrap_or("").to_string();
        let mut failing: Vec<String> = Vec::new();
        if sv_ok {
            for &r in &refs {
                match ctx.check_reference(r) {
                    Ok(true) => {}
                    Ok(false) => failing.push(uri_of(r)),
                    Err(e) => {
                        push_abort(&mut result, e);
                        break 'firmas;
                    }
                }
            }
            if !failing.is_empty() && !no_match {
                result.push(SignValidity::ko(ValidityError::NoMatchData));
                no_match = true;
            }
            for uri in failing {
                result.push(
                    SignValidity::ko(ValidityError::NoMatchData).with_detail(format!("Referencia no valida: {uri}")),
                );
            }
        } else {
            if !no_match {
                result.push(SignValidity::ko(ValidityError::NoMatchData));
                no_match = true;
            }
            // 3. `Reference.validate()` de cada referencia.
            for &r in &refs {
                match ctx.check_reference(r) {
                    Ok(true) => {}
                    Ok(false) => result.push(
                        SignValidity::ko(ValidityError::NoMatchData)
                            .with_detail(format!("Referencia no valida: {}", uri_of(r))),
                    ),
                    Err(e) => {
                        push_abort(&mut result, e);
                        break 'firmas;
                    }
                }
            }
        }
        if check_certificates {
            let Some(certs) = keyinfo_certificates(&doc, sig) else {
                result.push(SignValidity::unknown(ValidityError::UnknownError).with_detail("Objeto KeyInfo nulo"));
                break;
            };
            for der in certs {
                if let Some(info) = afirma_core::cert::CertInfo::parse(&der) {
                    if now > info.not_after {
                        if !expired_reported {
                            result.push(SignValidity::ko(ValidityError::CertificateExpired));
                            expired_reported = true;
                        }
                    } else if now < info.not_before {
                        result.push(SignValidity::ko(ValidityError::CertificateNotValidYet));
                    }
                }
            }
        }
        if !profile_checked(resolve_signer_format(&doc, sig)) {
            result.push(SignValidity::unknown(ValidityError::SignProfileNotChecked));
        }
    }
    let mut result = check_long_standing(result);
    if result.is_empty() {
        result.push(SignValidity::ok());
    }
    result
}

/// Validación de una firma concreta (`ValidateXMLSignature.validateSign`),
/// usada por el panel de detalles.
pub fn validate_signature(
    doc: &Document,
    sig: NodeId,
    profile: &str,
    externally_detached: bool,
    resolver: &dyn Resolver,
) -> Vec<SignValidity> {
    if externally_detached {
        return vec![SignValidity::unknown(ValidityError::CantValidateExternallyDetached)];
    }
    let mut out = Vec::new();
    match dsig::validate_core(doc, sig, resolver, None) {
        Ok(core) => {
            if !core.is_valid() {
                out.push(SignValidity::ko(ValidityError::NoMatchData));
            }
        }
        Err(e) => match classify(e) {
            Abort::BadBuild(m) => out.push(SignValidity::ko(ValidityError::BadBuildSign).with_detail(m)),
            Abort::Unknown(m) => out.push(SignValidity::unknown(ValidityError::UnknownError).with_detail(m)),
        },
    }
    if !profile_checked(profile) {
        out.push(SignValidity::unknown(ValidityError::SignProfileNotChecked));
    }
    if out.is_empty() {
        out.push(SignValidity::ok());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_standing_swap() {
        let list = vec![
            SignValidity::ko(ValidityError::CertificateExpired),
            SignValidity::unknown(ValidityError::SignProfileNotChecked),
        ];
        let out = check_long_standing(list);
        assert_eq!(out[0].error, Some(ValidityError::SignProfileNotChecked));
        assert_eq!(out[1].error, Some(ValidityError::CertificateExpired));
    }

    #[test]
    fn not_xml_or_no_signature() {
        assert_eq!(
            validate(b"hola", true, &dsig::NoResolver)[0].error,
            Some(ValidityError::NoSign)
        );
        assert_eq!(
            validate(b"<a/>", true, &dsig::NoResolver)[0].error,
            Some(ValidityError::NoSign)
        );
    }
}
