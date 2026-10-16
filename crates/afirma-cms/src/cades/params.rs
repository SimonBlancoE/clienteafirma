//! Configuración de una firma CAdES a partir de los `extraParams`
//! (equivalente exacto de `CAdESParameters.load`).

use afirma_core::ExtraParams;
use afirma_core::algorithms::{DigestAlgorithm, java_digest_algorithm_name};
use afirma_core::error::AfirmaError;
use chrono::{DateTime, Utc};

use crate::alg;
use crate::cades::policy::{AdesPolicy, build_ades_policy};
use crate::cms::SignedData;
use crate::mime;
use crate::oids;

/// Perfil de firma (`profile`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Advanced,
    Baseline,
}

/// Indicación de compromiso (`commitmentTypeIndication<n>...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentTypeIndication {
    /// OID del tipo de compromiso (`1.2.840.113549.1.9.16.6.n`).
    pub identifier: String,
    /// Calificadores (OID) tal y como se recibieron.
    pub qualifiers: Option<Vec<String>>,
}

/// Lugar de firma (`SignerLocation`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignerLocation {
    pub country: Option<String>,
    pub locality: Option<String>,
    /// Líneas de la dirección postal (máximo 6).
    pub postal_address: Option<Vec<String>>,
}

/// Configuración de una firma, cofirma o contrafirma CAdES.
#[derive(Debug, Clone)]
pub struct CadesParameters {
    pub external_policy: Option<AdesPolicy>,
    pub signing_certificate_v2: bool,
    pub included_only_signing_certificate: bool,
    /// Algoritmo de huella de los atributos (`messageDigest`,
    /// `signingCertificate`): el de la firma o el de la huella precalculada.
    pub digest_algorithm: DigestAlgorithm,
    pub data_digest: Option<Vec<u8>>,
    pub content_needed: bool,
    /// Datos a incrustar (firma implícita) o a resumir.
    pub content_data: Option<Vec<u8>>,
    pub signing_time: Option<DateTime<Utc>>,
    pub content_type_oid: Option<String>,
    pub content_description: Option<String>,
    pub mime_type: Option<String>,
    pub commitment_type_indications: Vec<CommitmentTypeIndication>,
    pub claimed_roles: Option<Vec<String>>,
    pub signer_location: Option<SignerLocation>,
    pub included_policy_on_signing_certificate: bool,
    pub included_issuer_serial: bool,
    pub profile: Profile,
    pub extra_params: ExtraParams,
}

/// `String.split` de Java con un separador literal (se eliminan las cadenas
/// vacías finales; sin coincidencias devuelve la cadena original).
pub fn java_split(s: &str, sep: &str) -> Vec<String> {
    if !s.contains(sep) {
        return vec![s.to_string()];
    }
    let mut v: Vec<String> = s.split(sep).map(String::from).collect();
    while v.last().is_some_and(String::is_empty) {
        v.pop();
    }
    v
}

/// Lee las indicaciones de compromiso (`CommitmentTypeIndicationsHelper`).
pub fn commitment_type_indications(params: &ExtraParams) -> Vec<CommitmentTypeIndication> {
    let mut out = Vec::new();
    let Some(n) = params.get("commitmentTypeIndications") else { return out };
    let n: i64 = match n.parse() {
        Ok(v) if v >= 1 => v,
        _ => {
            tracing::error!(
                "El parametro adicional 'CommitmentTypeIndications' debe contener un valor numerico entero (el valor actual es {n}), no se anadira el CommitmentTypeIndication"
            );
            return out;
        }
    };
    // AutoFirma recorre los índices 0..=N.
    for i in 0..=n {
        let Some(id) = params.get(&format!("commitmentTypeIndication{i}Identifier")) else { continue };
        let identifier = match id {
            "1" | "2" | "3" | "4" | "5" | "6" => format!("{}.{id}", oids::COMMITMENT_TYPE_PREFIX),
            other => {
                tracing::error!(
                    "El identificador del CommitmentTypeIndication {i} no es un tipo soportado ({other}), se omitira y se continuara con el siguiente"
                );
                continue;
            }
        };
        let qualifiers =
            params.get(&format!("commitmentTypeIndication{i}CommitmentTypeQualifiers")).map(|q| java_split(q, "|"));
        out.push(CommitmentTypeIndication { identifier, qualifiers });
    }
    out
}

/// Lee el lugar de firma (`CAdESSignerMetadataHelper.getCAdESSignerMetadata`).
pub fn signer_location(params: &ExtraParams) -> afirma_core::Result<Option<SignerLocation>> {
    let postal = params.get("signatureProductionPostalCode").map(|p| java_split(p, "\n"));
    let country = params.get("signatureProductionCountry").map(str::to_string);
    let locality = params.get("signatureProductionCity").map(str::to_string);
    if postal.is_none() && country.is_none() && locality.is_none() {
        return Ok(None);
    }
    if let Some(p) = &postal {
        if p.len() > 6 {
            return Err(AfirmaError::invalid_argument(format!(
                "La direccion postal debe tener un maximo de seis lineas, y se han proporcionado {}",
                p.len()
            )));
        }
    }
    Ok(Some(SignerLocation { country, locality, postal_address: postal }))
}

impl CadesParameters {
    /// Carga la configuración (`CAdESParameters.load`).
    ///
    /// * `data`: datos (o su huella si hay `precalculatedHashAlgorithm`).
    /// * `signed_data`: firma previa en las cofirmas (para heredar
    ///   `contentHints`/`mimeType`).
    /// * `algorithm`: nombre del algoritmo de firma (`SHA256withRSA`...).
    /// * `now`: instante de la firma.
    pub fn load(
        data: Option<&[u8]>,
        signed_data: Option<&SignedData<'_>>,
        algorithm: &str,
        config: &ExtraParams,
        now: DateTime<Utc>,
    ) -> afirma_core::Result<Self> {
        // 1. signingCertificateV2.
        let signing_certificate_v2 = if alg::is_sha2_signature_algorithm(algorithm) {
            true
        } else if config.contains("signingCertificateV2") {
            config.get_bool("signingCertificateV2", false)
        } else {
            java_digest_algorithm_name(algorithm) != "SHA1"
        };

        // 2-3. Modo, huella y contenido.
        let precalculated = config.get("precalculatedHashAlgorithm");
        let mode = config.get_or("mode", "explicit");
        let omit_content = precalculated.is_some() || mode.eq_ignore_ascii_case("explicit");
        let (digest_algorithm, data_digest, content_data) = match precalculated {
            Some(pre) => (alg::require_digest(pre)?, data.map(<[u8]>::to_vec), None),
            None => {
                let d = alg::require_digest(algorithm)?;
                let content = if omit_content { None } else { data.map(<[u8]>::to_vec) };
                (d, data.map(|x| d.digest(x)), content)
            }
        };

        // 4-8.
        let claimed_roles = config.get("signerClaimedRoles").filter(|r| !r.is_empty()).map(|r| java_split(r, "|"));
        let included_policy_on_signing_certificate = !config.get_bool("doNotIncludePolicyOnSigningCertificate", false);
        let external_policy = build_ades_policy(config)?;
        let included_only_signing_certificate = config.get_bool("includeOnlySignningCertificate", false);
        let commitment_type_indications = commitment_type_indications(config);

        // 9. signingTime.
        let include_signing_time =
            !config.contains("includeSigningTimeAttribute") || config.get_bool("includeSigningTimeAttribute", false);
        let signing_time = include_signing_time.then_some(now);

        // 10. contentHints y mimeType.
        let content_hint_needed = !config.contains("includeContentHintAttribute")
            || !config.get("includeContentHintAttribute").is_some_and(|v| v.eq_ignore_ascii_case("false"));
        let mimetype_needed = config.get_bool("includeMimeTypeAttribute", false);
        let mut content_type_oid = None;
        let mut content_description = None;
        let mut mime_type = None;
        if content_hint_needed || mimetype_needed {
            let mut oid: Option<String> = config.get("contentTypeOid").map(str::to_string);
            let mut desc: Option<String> = config.get("contentDescription").map(str::to_string);
            let mut mime: Option<String> = config.get("mimeType").map(str::to_string);

            if mimetype_needed && mime.is_none() && oid.is_some() {
                let m = mime::oid_to_mime(oid.as_deref());
                mime = (m != mime::DEFAULT_MIMETYPE).then(|| m.to_string());
            }

            if ((content_hint_needed && oid.is_none()) || (mimetype_needed && mime.is_none())) && signed_data.is_some()
            {
                let mut found = false;
                for si in signed_data.map(|s| s.signer_infos.as_slice()).unwrap_or_default() {
                    if found {
                        break;
                    }
                    if mimetype_needed && mime.is_none() {
                        if let Some(v) = si.signed_attr(oids::MIME_TYPE).and_then(|a| a.first_value()) {
                            mime = v.as_string().ok();
                            found = true;
                        }
                    }
                    if content_hint_needed && oid.is_none() {
                        if let Some(v) = si.signed_attr(oids::CONTENT_HINT).and_then(|a| a.first_value()) {
                            if let Some((d, o)) = parse_content_hints(&v) {
                                oid = Some(o);
                                if desc.is_none() {
                                    desc = d;
                                }
                                found = true;
                            }
                        }
                    }
                    if mime.is_some() && oid.is_none() {
                        let o = mime::mime_to_oid(mime.as_deref());
                        oid = (o != mime::DEFAULT_CONTENT_OID_DATA).then(|| o.to_string());
                    } else if mimetype_needed
                        && mime.is_none()
                        && oid.as_deref().is_some_and(|o| o != mime::DEFAULT_CONTENT_OID_DATA)
                    {
                        let m = mime::oid_to_mime(oid.as_deref());
                        mime = (m != mime::DEFAULT_MIMETYPE).then(|| m.to_string());
                    }
                }
            }

            if ((content_hint_needed && oid.is_none()) || (mimetype_needed && mime.is_none())) && data.is_some() {
                let info = mime::analyze(data.unwrap_or_default());
                if content_hint_needed && oid.is_none() {
                    let o = mime::mime_to_oid(Some(&info.mime_type));
                    oid = (o != mime::DEFAULT_CONTENT_OID_DATA).then(|| o.to_string());
                }
                if content_hint_needed && desc.is_none() {
                    desc = Some(info.description.clone());
                }
                if mimetype_needed && mime.is_none() {
                    mime = Some(info.mime_type.clone());
                }
            }

            if content_hint_needed {
                content_type_oid = Some(oid.unwrap_or_else(|| mime::DEFAULT_CONTENT_OID_DATA.to_string()));
                content_description = Some(desc.unwrap_or_else(|| mime::DEFAULT_CONTENT_DESCRIPTION.to_string()));
            }
            if mimetype_needed {
                mime_type = Some(mime.unwrap_or_else(|| mime::DEFAULT_MIMETYPE.to_string()));
            }
        }

        // 11-13.
        let signer_location = signer_location(config)?;
        let profile = if config.get("profile") == Some("baseline") { Profile::Baseline } else { Profile::Advanced };

        Ok(CadesParameters {
            external_policy,
            signing_certificate_v2,
            included_only_signing_certificate,
            digest_algorithm,
            data_digest,
            content_needed: !omit_content,
            content_data,
            signing_time,
            content_type_oid,
            content_description,
            mime_type,
            commitment_type_indications,
            claimed_roles,
            signer_location,
            included_policy_on_signing_certificate,
            included_issuer_serial: true,
            profile,
            extra_params: config.clone(),
        })
    }
}

/// Lee un `ContentHints` (`SEQUENCE { contentDescription UTF8String OPTIONAL, contentType OID }`).
pub fn parse_content_hints(v: &crate::asn1::Tlv<'_>) -> Option<(Option<String>, String)> {
    let parts = v.children().ok()?;
    match parts.as_slice() {
        [o] => Some((None, o.as_oid().ok()?.to_dotted())),
        [d, o, ..] => Some((d.as_string().ok(), o.as_oid().ok()?.to_dotted())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split() {
        assert_eq!(java_split("", "\n"), vec![""]);
        assert_eq!(java_split("\n", "\n"), Vec::<String>::new());
        assert_eq!(java_split("a\n\nb\n\n", "\n"), vec!["a", "", "b"]);
        assert_eq!(java_split("\na", "\n"), vec!["", "a"]);
        assert_eq!(java_split("a|b", "|"), vec!["a", "b"]);
    }

    #[test]
    fn commitments_loop_is_inclusive() {
        let mut p = ExtraParams::new();
        p.set("commitmentTypeIndications", "1");
        p.set("commitmentTypeIndication0Identifier", "1");
        p.set("commitmentTypeIndication1Identifier", "5");
        p.set("commitmentTypeIndication1CommitmentTypeQualifiers", "1.2.3|1.2.4");
        p.set("commitmentTypeIndication2Identifier", "2");
        let c = commitment_type_indications(&p);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].identifier, "1.2.840.113549.1.9.16.6.1");
        assert_eq!(c[1].qualifiers.as_ref().unwrap(), &vec!["1.2.3".to_string(), "1.2.4".to_string()]);
    }

    #[test]
    fn defaults() {
        let now = Utc::now();
        let p = ExtraParams::new();
        let c = CadesParameters::load(Some(b"hola"), None, "SHA1withRSA", &p, now).unwrap();
        assert!(!c.signing_certificate_v2);
        assert!(c.content_data.is_none());
        assert_eq!(c.content_type_oid.as_deref(), Some(mime::DEFAULT_CONTENT_OID_DATA));
        let c = CadesParameters::load(Some(b"hola"), None, "SHA512withRSA", &p, now).unwrap();
        assert!(c.signing_certificate_v2);
        assert_eq!(c.digest_algorithm, DigestAlgorithm::Sha512);
        let mut p = ExtraParams::new();
        p.set("mode", "IMPLICIT");
        p.set("profile", "Baseline");
        let c = CadesParameters::load(Some(b"hola"), None, "SHA256withRSA", &p, now).unwrap();
        assert_eq!(c.content_data.as_deref(), Some(&b"hola"[..]));
        assert_eq!(c.profile, Profile::Advanced);
    }
}
