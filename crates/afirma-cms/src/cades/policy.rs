//! Política de firma (`AdESPolicy`) para CAdES-EPES.
//!
//! Adaptación de `afirma_core::policy::AdESPolicy` a los datos que usa el
//! atributo `sigPolicyId`.

use afirma_core::ExtraParams;
use afirma_core::error::AfirmaError;

/// Política de firma configurada en los `extraParams`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdesPolicy {
    /// Identificador tal y como se recibió (`policyIdentifier`).
    pub identifier: String,
    /// Huella en Base64 (`policyIdentifierHash`).
    pub hash_b64: String,
    /// Algoritmo de huella normalizado (`getDigestAlgorithmName`).
    pub hash_algorithm: String,
    /// Calificador (URL) normalizado como `java.net.URL.toString()`.
    pub qualifier: Option<String>,
}

/// Protocolos que acepta `java.net.URL` por defecto.
const URL_PROTOCOLS: [&str; 8] = ["http", "https", "ftp", "file", "jar", "mailto", "jrt", "jmod"];

/// Normaliza una URL como `new URL(s).toString()` (protocolo en minúsculas).
/// Devuelve `None` si Java la rechazaría por protocolo desconocido.
pub fn java_url(s: &str) -> Option<String> {
    let idx = s.find(':')?;
    let proto = s[..idx].to_ascii_lowercase();
    if !URL_PROTOCOLS.contains(&proto.as_str()) {
        return None;
    }
    Some(format!("{proto}{}", &s[idx..]))
}

/// `AdESPolicy.buildAdESPolicy(extraParams)` (sobre `afirma_core::policy`,
/// que descarga el documento de la política si no se indica su huella).
pub fn build_ades_policy(params: &ExtraParams) -> afirma_core::Result<Option<AdesPolicy>> {
    let Some(p) = afirma_core::policy::AdESPolicy::from_extra_params(params)? else { return Ok(None) };
    let qualifier =
        match p.qualifier() {
            Some(q) => Some(java_url(q).ok_or_else(|| {
                AfirmaError::invalid_argument("El calificador de la politica debe ser una URL valida")
            })?),
            None => None,
        };
    Ok(Some(AdesPolicy {
        identifier: p.identifier().to_string(),
        hash_b64: p.hash().to_string(),
        hash_algorithm: p.hash_algorithm().to_string(),
        qualifier,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_policy() {
        let mut p = ExtraParams::new();
        assert_eq!(build_ades_policy(&p).unwrap(), None);
        p.set("policyIdentifier", "urn:oid:2.16.724.1.3.1.1.2.1.9");
        p.set("policyIdentifierHash", "G7roucf600+f03r/o0bAOQ6WAs0=");
        p.set("policyIdentifierHashAlgorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
        p.set("policyQualifier", "HTTPS://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf");
        let pol = build_ades_policy(&p).unwrap().unwrap();
        assert_eq!(pol.hash_algorithm, "SHA1");
        assert_eq!(pol.qualifier.as_deref(), Some("https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf"));
        p.set("policyIdentifierHash", "0");
        assert!(build_ades_policy(&p).is_err());
        p.set("policyIdentifierHash", "no*base64");
        assert!(build_ades_policy(&p).is_err());
    }
}
