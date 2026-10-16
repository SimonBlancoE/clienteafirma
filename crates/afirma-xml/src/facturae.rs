//! Firmador FacturaE (`AOFacturaESigner`): XAdES Enveloped sobre facturas
//! electrónicas con la política FacturaE 3.1 (o 3.0) y rol de firmante.

use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::{CounterSignTarget, SignInfo, Signer, SignersTree};

use crate::dom::Document;
use crate::xades::{self, FORMAT_ENVELOPED};

pub const FORMAT_FACTURAE: &str = "FacturaE";

/// Política FacturaE 3.1 (identificador, huella Base64).
pub const POLICY_FACTURAE_31: (&str, &str) = (
    "http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf",
    "Ohixl6upD6av8N7pEvDABhEL6hM=",
);
/// Política FacturaE 3.0.
pub const POLICY_FACTURAE_30: (&str, &str) = (
    "http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf",
    "xmfh8D/Ec/hHeE1IB4zPd61zHIY=",
);

const ALLOWED_PARAMS: &[&str] = &[
    "signatureProductionCity",
    "signatureProductionProvince",
    "signatureProductionPostalCode",
    "signatureProductionCountry",
    "xadesNamespace",
    "signedPropertiesTypeUrl",
    "policyIdentifier",
    "policyIdentifierHash",
    "policyIdentifierHashAlgorithm",
    "policyDescription",
    "policyQualifier",
    "signerClaimedRoles",
    "SignatureId",
];

const ROLES: &[&str] = &["emisor", "receptor", "tercero", "supplier", "customer", "third party"];

/// `AOFacturaESigner.getFacturaEExtraParams`: parámetros XAdES de una firma
/// FacturaE (lista blanca, rol por defecto `emisor`, política FacturaE 3.1).
pub fn facturae_extra_params(original: &ExtraParams) -> afirma_core::Result<ExtraParams> {
    let mut x = ExtraParams::new();
    x.set("format", FORMAT_ENVELOPED);
    x.set("facturaeSign", "true");
    let mut o = original.clone();
    let role = o.get("signerClaimedRoles").unwrap_or("emisor").to_lowercase();
    if !ROLES.contains(&role.as_str()) {
        return Err(AfirmaError::invalid_argument(format!(
            "El papel '{role}' no es valido para una factura electronica"
        )));
    }
    o.set("signerClaimedRoles", role);
    match o.get("policyIdentifier") {
        Some(id) => {
            let hash = o.get("policyIdentifierHash").unwrap_or("");
            let alg = o
                .get("policyIdentifierHashAlgorithm")
                .map(afirma_core::algorithms::java_digest_algorithm_name);
            let matches = |(pid, phash): (&str, &str)| id == pid && hash == phash && alg.as_deref() == Some("SHA1");
            if !matches(POLICY_FACTURAE_31) && !matches(POLICY_FACTURAE_30) {
                return Err(AfirmaError::invalid_argument(format!(
                    "La politica no esta soportada (solo se soporta FacturaE 3.0 y 3.1): {id}"
                )));
            }
        }
        None => {
            o.remove("policyQualifier");
            o.set("policyIdentifier", POLICY_FACTURAE_31.0);
            o.set("policyIdentifierHash", POLICY_FACTURAE_31.1);
            o.set("policyIdentifierHashAlgorithm", "SHA1");
        }
    }
    for (k, v) in o.iter() {
        if ALLOWED_PARAMS.contains(&k) {
            x.set(k, v);
        }
    }
    Ok(x)
}

/// `AOFacturaESigner.isValidDataFile(Document)`.
pub fn is_facturae_doc(doc: &Document) -> bool {
    let Some(root) = doc.document_element() else {
        return false;
    };
    if doc.element(root).map(|e| e.local.as_str()) != Some("Facturae") {
        return false;
    }
    let names: Vec<&str> = doc
        .child_elements(root)
        .filter_map(|c| doc.element(c).map(|e| e.local.as_str()))
        .collect();
    ["FileHeader", "Parties", "Invoices"].iter().all(|n| names.contains(n))
}

/// Firmador FacturaE.
#[derive(Default)]
pub struct FacturaeSigner;

impl FacturaeSigner {
    pub fn new() -> Self {
        FacturaeSigner
    }
}

fn parse(data: &[u8]) -> Option<Document> {
    if data.is_empty() {
        return None;
    }
    Document::parse_bytes(data).ok().map(|(d, _)| d)
}

impl Signer for FacturaeSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_FACTURAE
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        if !self.is_valid_data_file(data) {
            return Err(AfirmaError::from_code(codes::FACTURAE_NEEDED));
        }
        if self.is_sign(data, extra) {
            return Err(AfirmaError::from_code(codes::FACTURAE_ALREADY_SIGNED));
        }
        let params = facturae_extra_params(extra)?;
        xades::sign::sign(Some(data), algorithm, key, &params, &crate::dsig::NoResolver)
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        _sign: &[u8],
        _algorithm: &str,
        _key: &dyn SigningKey,
        _extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        Err(AfirmaError::unsupported("No se soporta la cofirma de facturas"))
    }

    fn countersign(
        &self,
        _sign: &[u8],
        _algorithm: &str,
        _target: &CounterSignTarget,
        _key: &dyn SigningKey,
        _extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        Err(AfirmaError::unsupported("No se soporta la contrafirma de facturas"))
    }

    fn signers_structure(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        xades::info::signers_structure(sign)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        parse(data).is_some_and(|d| is_facturae_doc(&d) && xades::info::is_sign_doc(&d))
    }

    fn is_valid_data_file(&self, data: &[u8]) -> bool {
        parse(data).is_some_and(|d| is_facturae_doc(&d))
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        format!("{}{}.xsig", original.unwrap_or("null"), in_text.unwrap_or(""))
    }

    fn get_data(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        xades::info::get_data(sign)
    }

    fn sign_info(&self, _sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        Ok(SignInfo {
            format: FORMAT_FACTURAE.into(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_whitelist_and_policy() {
        let p = ExtraParams::parse(
            "referencesDigestMethod=http://www.w3.org/2000/09/xmldsig#sha1\nsignatureProductionCity=Madrid\nsignerClaimedRoles=Receptor\npolicyQualifier=http://x\n",
        );
        let x = facturae_extra_params(&p).unwrap();
        assert_eq!(x.get("format"), Some("XAdES Enveloped"));
        assert_eq!(x.get("facturaeSign"), Some("true"));
        assert_eq!(x.get("signerClaimedRoles"), Some("receptor"));
        assert_eq!(x.get("policyIdentifier"), Some(POLICY_FACTURAE_31.0));
        assert_eq!(x.get("policyIdentifierHashAlgorithm"), Some("SHA1"));
        assert!(x.get("policyQualifier").is_none());
        assert!(x.get("referencesDigestMethod").is_none());
        assert_eq!(x.get("signatureProductionCity"), Some("Madrid"));
        assert!(facturae_extra_params(&ExtraParams::parse("signerClaimedRoles=jefe")).is_err());
        assert!(
            facturae_extra_params(&ExtraParams::parse(
                "policyIdentifier=urn:oid:1.2.3\npolicyIdentifierHash=AA==\npolicyIdentifierHashAlgorithm=SHA1"
            ))
            .is_err()
        );
        let p30 = ExtraParams::parse(&format!(
            "policyIdentifier={}\npolicyIdentifierHash={}\npolicyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1",
            POLICY_FACTURAE_30.0.replace(' ', "\\ "),
            POLICY_FACTURAE_30.1
        ));
        assert!(facturae_extra_params(&p30).is_ok());
    }
}
