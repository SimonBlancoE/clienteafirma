//! Lectura de los datos de una firma CMS/CAdES para la interfaz de
//! validación y para otros formatos (PAdES, XAdES): certificados, atributos,
//! huellas, fecha de firma, sellos de tiempo y contrafirmas.

use afirma_core::algorithms::DigestAlgorithm;
use afirma_core::error::AfirmaError;
use chrono::{DateTime, Utc};

use crate::cms::{SignedData, SignerInfo};
use crate::tsp::{TimeStampTokenInfo, parse_timestamp_token};
use crate::{alg, oids, validation};

/// Datos de un firmante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerDetails {
    /// Certificado del firmante (si está en la firma).
    pub certificate: Option<Vec<u8>>,
    pub signing_time: Option<DateTime<Utc>>,
    pub message_digest: Option<Vec<u8>>,
    pub digest_algorithm: Option<DigestAlgorithm>,
    pub digest_algorithm_oid: String,
    pub signature_algorithm_oid: String,
    /// Nombre al estilo AutoFirma (`SHA256withRSA`).
    pub signature_algorithm_name: String,
    pub signature_value: Vec<u8>,
    /// OID de los atributos firmados, en el orden codificado.
    pub signed_attribute_oids: Vec<String>,
    /// OID de los atributos no firmados, en el orden codificado.
    pub unsigned_attribute_oids: Vec<String>,
    /// Identificador de la política de firma (`sigPolicyId`).
    pub policy_oid: Option<String>,
    /// Sellos de tiempo de firma (`signatureTimeStampToken`).
    pub timestamps: Vec<TimeStampTokenInfo>,
    /// Perfil (`CAdES B-Level`, `CMS`...).
    pub profile: &'static str,
    pub countersigners: Vec<SignerDetails>,
}

fn details(sd: &SignedData<'_>, si: &SignerInfo<'_>) -> SignerDetails {
    let signed = si.signed_attributes().unwrap_or_default();
    let unsigned = si.unsigned_attributes().unwrap_or_default();
    let policy_oid = si
        .signed_attr(oids::SIG_POLICY_ID)
        .and_then(|a| a.first_value())
        .and_then(|v| v.children().ok())
        .and_then(|c| c.first().and_then(|o| o.as_oid().ok()))
        .map(|o| o.to_dotted());
    SignerDetails {
        certificate: sd.signer_certificate(si).map(<[u8]>::to_vec),
        signing_time: si.signing_time(),
        message_digest: si.message_digest(),
        digest_algorithm: DigestAlgorithm::from_oid(&si.digest_oid.to_dotted()),
        digest_algorithm_oid: si.digest_oid.to_dotted(),
        signature_algorithm_oid: si.signature_oid.to_dotted(),
        signature_algorithm_name: alg::tree_signature_algorithm_name(
            &si.digest_oid.to_dotted(),
            &si.signature_oid.to_dotted(),
        ),
        signature_value: si.signature_value(),
        signed_attribute_oids: signed.iter().map(|a| a.oid.to_dotted()).collect(),
        unsigned_attribute_oids: unsigned.iter().map(|a| a.oid.to_dotted()).collect(),
        policy_oid,
        timestamps: si
            .timestamp_tokens()
            .iter()
            .filter_map(|t| parse_timestamp_token(t).ok())
            .collect(),
        profile: validation::resolve_asn1_format(sd, si),
        countersigners: si.counter_signatures().iter().map(|c| details(sd, c)).collect(),
    }
}

/// Datos de los firmantes de primer nivel (con sus contrafirmas anidadas).
pub fn signers(sign: &[u8]) -> afirma_core::Result<Vec<SignerDetails>> {
    let sd = SignedData::parse(sign).map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
    Ok(sd.signer_infos.iter().map(|si| details(&sd, si)).collect())
}

/// Certificados incluidos en la firma (DER, en el orden codificado).
pub fn certificates(sign: &[u8]) -> afirma_core::Result<Vec<Vec<u8>>> {
    let sd = SignedData::parse(sign).map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
    Ok(sd.certificates_der().into_iter().map(<[u8]>::to_vec).collect())
}

/// Resumen estructural de una firma con los valores variables enmascarados
/// (fechas de firma, valores de firma y huellas de las contrafirmas). Dos
/// firmas generadas con los mismos datos, parámetros y clave RSA tienen el
/// mismo resumen; se usa para comparar con la versión Java.
pub fn structure_summary(sign: &[u8]) -> afirma_core::Result<String> {
    let sd = SignedData::parse(sign).map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
    let mut out = String::new();
    out.push_str(&format!("SignedData v{}\n", sd.version));
    let algs: Vec<String> = sd
        .digest_algorithms
        .children()
        .unwrap_or_default()
        .iter()
        .map(|a| hex::encode(a.raw))
        .collect();
    out.push_str(&format!(" digestAlgorithms: {}\n", algs.join(" ")));
    let content = sd.content();
    out.push_str(&format!(
        " encap: {} content={}\n",
        sd.econtent_type,
        content
            .as_ref()
            .map(|c| format!("{}B sha256={}", c.len(), hex::encode(DigestAlgorithm::Sha256.digest(c))))
            .unwrap_or_else(|| "none".into())
    ));
    match &sd.certificates {
        Some(_) => {
            let names: Vec<String> = sd
                .certificates_der()
                .iter()
                .map(|c| {
                    crate::cert::CertView::parse(c)
                        .map(|v| format!("{}#{}", v.common_name(), hex::encode(v.serial)))
                        .unwrap_or_else(|_| "?".into())
                })
                .collect();
            out.push_str(&format!(" certificates: [{}]\n", names.join(", ")));
        }
        None => out.push_str(" certificates: none\n"),
    }
    out.push_str(&format!(
        " crls: {}\n",
        sd.crls
            .as_ref()
            .and_then(|c| c.children().ok())
            .map(|c| c.len().to_string())
            .unwrap_or_else(|| "none".into())
    ));
    for si in &sd.signer_infos {
        summary_signer(si, 1, &mut out);
    }
    Ok(out)
}

fn summary_signer(si: &SignerInfo<'_>, depth: usize, out: &mut String) {
    let pad = " ".repeat(depth * 2);
    out.push_str(&format!(
        "{pad}SignerInfo v{} sid={} digest={} sigalg={} sig={}\n",
        si.version,
        hex::encode(si.sid.raw),
        hex::encode(si.digest_algorithm.raw),
        hex::encode(si.signature_algorithm.raw),
        // La longitud de las firmas ECDSA varía de una firma a otra.
        if si.signature_oid.to_dotted().starts_with("1.2.840.10045") {
            "ecdsa".to_string()
        } else {
            format!("{}B", si.signature_value().len())
        }
    ));
    if let Ok(attrs) = si.signed_attributes() {
        out.push_str(&format!("{pad} signed:\n"));
        for a in attrs {
            let v = if a.is(oids::SIGNING_TIME) {
                "<signingTime>".to_string()
            } else if a.is(oids::MESSAGE_DIGEST) && depth > 1 {
                "<messageDigest>".to_string()
            } else {
                a.values
                    .iter()
                    .map(|v| hex::encode(v.raw))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            out.push_str(&format!("{pad}  {} = {}\n", a.oid, v));
        }
    }
    if let Some(ua) = &si.unsigned_attrs {
        out.push_str(&format!("{pad} unsigned:\n"));
        for a in crate::cms::parse_attributes(ua).unwrap_or_default() {
            if a.is(oids::COUNTER_SIGNATURE) {
                out.push_str(&format!("{pad}  {} ({} valores)\n", a.oid, a.values.len()));
                for v in &a.values {
                    if let Ok(c) = SignerInfo::parse(*v) {
                        summary_signer(&c, depth + 1, out);
                    }
                }
            } else if a.is(oids::SIGNATURE_TIMESTAMP_TOKEN) {
                out.push_str(&format!("{pad}  {} = <timestamp>\n", a.oid));
            } else {
                out.push_str(&format!("{pad}  {} = {}B\n", a.oid, a.raw.raw.len()));
            }
        }
    }
}
