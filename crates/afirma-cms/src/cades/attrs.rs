//! Atributos firmados CAdES (`CAdESUtils.generateSignedAttributes`).

use afirma_core::algorithms::DigestAlgorithm;
use afirma_core::error::{AfirmaError, codes};

use crate::alg;
use crate::asn1::{Oid, der};
use crate::cades::params::{CadesParameters, CommitmentTypeIndication, Profile, SignerLocation};
use crate::cades::policy::AdesPolicy;
use crate::cert::CertView;
use crate::cms::encode_attribute;
use crate::oids;

fn internal(msg: impl Into<String>) -> AfirmaError {
    AfirmaError::new(codes::INTERNAL_BINARY_SIGNING_ERROR, msg)
}

fn parse_oid(s: &str, what: &str) -> afirma_core::Result<Oid> {
    s.parse::<Oid>().map_err(|_| AfirmaError::invalid_argument(format!("{what} debe ser un OID valido: {s}")))
}

/// `SigningCertificateV2` (RFC 5035). El algoritmo se omite cuando es
/// SHA-256 (valor por defecto en DER).
pub fn signing_certificate_v2(
    cert: &CertView<'_>,
    digest: DigestAlgorithm,
    include_policies: bool,
    include_issuer_serial: bool,
) -> Vec<u8> {
    let mut ess = Vec::new();
    if digest != DigestAlgorithm::Sha256 {
        ess.push(alg::digest_alg_id(digest));
    }
    ess.push(der::octet_string(&digest.digest(cert.raw)));
    if include_issuer_serial {
        ess.push(cert.ess_issuer_serial());
    }
    let mut parts = vec![der::sequence([der::sequence(ess)])];
    if include_policies
        && let Some(p) = cert.policy_informations() {
            parts.push(der::sequence(p));
        }
    encode_attribute(oids::SIGNING_CERTIFICATE_V2, &[der::sequence(parts)])
}

/// `SigningCertificate` (RFC 2634).
pub fn signing_certificate_v1(
    cert: &CertView<'_>,
    digest: DigestAlgorithm,
    include_policies: bool,
    include_issuer_serial: bool,
) -> Vec<u8> {
    let mut ess = vec![der::octet_string(&digest.digest(cert.raw))];
    if include_issuer_serial {
        ess.push(cert.ess_issuer_serial());
    }
    let mut parts = vec![der::sequence([der::sequence(ess)])];
    if include_policies
        && let Some(p) = cert.policy_informations() {
            parts.push(der::sequence(p));
        }
    encode_attribute(oids::SIGNING_CERTIFICATE, &[der::sequence(parts)])
}

/// `SignaturePolicyId` (RFC 5126 §5.8.1).
pub fn sig_policy_id(policy: &AdesPolicy) -> afirma_core::Result<Vec<u8>> {
    let id = policy.identifier.to_lowercase().replace("urn:oid:", "");
    let oid = parse_oid(&id, "El identificador de la politica")?;
    let hash_alg = alg::digest_from_java_name(&policy.hash_algorithm).ok_or_else(|| {
        AfirmaError::invalid_argument(format!("Se desconoce el algoritmo '{}'", policy.hash_algorithm))
    })?;
    let hash = afirma_core::base64_decode_lenient(&policy.hash_b64)
        .map_err(|e| AfirmaError::invalid_argument(format!("La huella de la politica no es Base64 valido: {e}")))?;
    let mut parts = vec![der::oid(&oid), der::sequence([alg::digest_alg_id(hash_alg), der::octet_string(&hash)])];
    if let Some(q) = &policy.qualifier {
        parts.push(der::sequence([der::sequence([der::oid_str(oids::SPQ_ETS_URI), der::ia5_string(q)])]));
    }
    Ok(encode_attribute(oids::SIG_POLICY_ID, &[der::sequence(parts)]))
}

/// `contentHints` (RFC 2634 §2.9): la descripción va primero.
pub fn content_hints(content_type: &str, description: Option<&str>) -> afirma_core::Result<Vec<u8>> {
    let oid = parse_oid(content_type, "El tipo de contenido")?;
    let mut parts = Vec::new();
    if let Some(d) = description {
        parts.push(der::utf8_string(d));
    }
    parts.push(der::oid(&oid));
    Ok(encode_attribute(oids::CONTENT_HINT, &[der::sequence(parts)]))
}

/// `commitmentTypeIndication` (calificadores como OID sueltos, como AutoFirma).
pub fn commitment_type(cti: &CommitmentTypeIndication) -> afirma_core::Result<Vec<u8>> {
    let id = parse_oid(&cti.identifier, "El identificador del CommitmentTypeIndication")?;
    let mut parts = vec![der::oid(&id)];
    if let Some(q) = cti.qualifiers.as_ref().filter(|q| !q.is_empty()) {
        let mut quals = Vec::new();
        for s in q {
            quals.push(der::oid(&s.parse::<Oid>().map_err(|_| {
                AfirmaError::invalid_argument(format!("El calificador proporcionado no es un OID ({s})"))
            })?));
        }
        parts.push(der::sequence(quals));
    }
    Ok(encode_attribute(oids::COMMITMENT_TYPE, &[der::sequence(parts)]))
}

/// `SignerLocation` (RFC 5126 §5.11.2).
pub fn signer_location(loc: &SignerLocation) -> Option<Vec<u8>> {
    if loc.country.is_none() && loc.locality.is_none() && loc.postal_address.is_none() {
        return None;
    }
    let mut parts = Vec::new();
    if let Some(c) = &loc.country {
        parts.push(der::explicit(0, &der::utf8_string(c)));
    }
    if let Some(l) = &loc.locality {
        parts.push(der::explicit(1, &der::utf8_string(l)));
    }
    if let Some(p) = &loc.postal_address {
        parts.push(der::explicit(2, &der::sequence(p.iter().map(|l| der::utf8_string(l)))));
    }
    Some(encode_attribute(oids::SIGNER_LOCATION, &[der::sequence(parts)]))
}

/// `signerAttr`/`signerAttrV2` con los roles declarados.
pub fn signer_attr(roles: &[String], profile: Profile) -> Option<Vec<u8>> {
    let attrs: Vec<Vec<u8>> =
        roles.iter().filter(|r| !r.is_empty()).map(|r| encode_attribute(oids::ROLE, &[der::utf8_string(r)])).collect();
    if attrs.is_empty() {
        return None;
    }
    let oid = match profile {
        Profile::Advanced => oids::SIGNER_ATTR,
        Profile::Baseline => oids::SIGNER_ATTR_V2,
    };
    Some(encode_attribute(oid, &[der::sequence([der::explicit(0, &der::sequence(attrs))])]))
}

/// Genera los atributos firmados (cada uno codificado como `Attribute`).
pub fn generate_signed_attributes(
    cert_der: &[u8],
    cfg: &CadesParameters,
    is_countersign: bool,
) -> afirma_core::Result<Vec<Vec<u8>>> {
    let cert = CertView::parse(cert_der).map_err(|e| internal(format!("Certificado de firma no valido: {e}")))?;
    let mut out = Vec::new();
    if !is_countersign {
        out.push(encode_attribute(oids::CONTENT_TYPE, &[der::oid_str(oids::DATA)]));
    }
    let md = match (&cfg.data_digest, &cfg.content_data) {
        (Some(d), _) => d.clone(),
        (None, Some(c)) => cfg.digest_algorithm.digest(c),
        (None, None) => {
            return Err(AfirmaError::invalid_argument(
                "Ni los datos a firmar ni la huella de los mismos se han configurado o encontrado ",
            ));
        }
    };
    out.push(encode_attribute(oids::MESSAGE_DIGEST, &[der::octet_string(&md)]));
    if cfg.signing_certificate_v2 {
        out.push(signing_certificate_v2(
            &cert,
            cfg.digest_algorithm,
            cfg.included_policy_on_signing_certificate,
            cfg.included_issuer_serial,
        ));
    } else {
        out.push(signing_certificate_v1(
            &cert,
            cfg.digest_algorithm,
            cfg.included_policy_on_signing_certificate,
            cfg.included_issuer_serial,
        ));
    }
    if let Some(p) = &cfg.external_policy {
        out.push(sig_policy_id(p)?);
    }
    if (!is_countersign || cfg.profile != Profile::Baseline)
        && let Some(ct) = &cfg.content_type_oid {
            out.push(content_hints(ct, cfg.content_description.as_deref())?);
        }
    for cti in &cfg.commitment_type_indications {
        out.push(commitment_type(cti)?);
    }
    if let Some(loc) = cfg.signer_location.as_ref().and_then(signer_location) {
        out.push(loc);
    }
    if let Some(roles) = cfg.claimed_roles.as_ref().filter(|r| !r.is_empty())
        && let Some(a) = signer_attr(roles, cfg.profile) {
            out.push(a);
        }
    if let Some(t) = &cfg.signing_time {
        out.push(encode_attribute(oids::SIGNING_TIME, &[der::utc_time(t)]));
    }
    if !is_countersign
        && let Some(m) = &cfg.mime_type {
            out.push(encode_attribute(oids::MIME_TYPE, &[der::utf8_string(m)]));
        }
    Ok(out)
}

/// Codifica los atributos como `SET OF` DER ordenado (datos a firmar).
pub fn attributes_set(attrs: &[Vec<u8>]) -> Vec<u8> {
    der::set_of(attrs)
}
