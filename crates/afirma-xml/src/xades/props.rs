//! Construcción de `QualifyingProperties` (jxades 0.2.2), `KeyInfo` y de los
//! metadatos comunes (política, lugar de firma, roles, compromisos).

use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;

use crate::dn::CertNames;
use crate::dsig::{self, DsNames};
use crate::util::{b64, esc_attr, esc_text};

/// Identificadores de los tipos de compromiso (`commitmentTypeIndication<n>Identifier`).
pub const COMMITMENT_TYPES: &[(&str, &str)] = &[
    ("1", "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin"),
    ("2", "http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt"),
    ("3", "http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery"),
    ("4", "http://uri.etsi.org/01903/v1.2.2#ProofOfSender"),
    ("5", "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval"),
    ("6", "http://uri.etsi.org/01903/v1.2.2#ProofOfCreation"),
];

/// Política de firma explícita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub identifier: String,
    pub hash_algorithm_uri: String,
    pub hash: String,
    pub description: String,
    pub qualifier: Option<String>,
}

/// Lugar de producción de la firma (los campos `None` no se emiten).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Place {
    pub city: Option<String>,
    pub street: Option<String>,
    pub province: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

impl Place {
    fn is_empty(&self, v2: bool) -> bool {
        self.city.is_none()
            && (!v2 || self.street.is_none())
            && self.province.is_none()
            && self.postal_code.is_none()
            && self.country.is_none()
    }
}

/// `ObjectIdentifier` de un `DataObjectFormat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier {
    pub identifier: String,
    pub qualifier: Option<String>,
    pub description: Option<String>,
    pub documentation_references: Vec<String>,
}

impl ObjectIdentifier {
    /// Identificador `OIDAsURN` (añade `urn:oid:` si falta).
    pub fn oid_as_urn(oid: &str) -> Self {
        let identifier = if oid.starts_with("urn:oid:") {
            oid.to_string()
        } else {
            format!("urn:oid:{oid}")
        };
        ObjectIdentifier {
            identifier,
            qualifier: Some("OIDAsURN".into()),
            description: None,
            documentation_references: vec![],
        }
    }
}

/// `DataObjectFormat`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataObjectFormat {
    pub object_reference: String,
    pub description: Option<String>,
    pub object_identifier: Option<ObjectIdentifier>,
    pub mime_type: Option<String>,
    pub encoding: Option<String>,
}

/// `CommitmentTypeIndication`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub identifier: String,
    pub description: Option<String>,
    pub documentation_references: Vec<String>,
    /// `Some("#Reference-...")` o `None` para `AllSignedDataObjects`.
    pub object_reference: Option<String>,
    pub qualifiers: Vec<String>,
}

/// Política implícita (OOXML) o explícita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySpec {
    None,
    Implied,
    Explicit(Policy),
}

/// Contenido de `SignedProperties`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedProps {
    /// Perfil B-Level (`SigningCertificateV2`, `...V2`).
    pub baseline: bool,
    pub signing_time: String,
    pub cert_der: Vec<u8>,
    /// URI de `CertDigest/DigestMethod` (`referencesDigestMethod`).
    pub cert_digest_uri: String,
    pub policy: PolicySpec,
    pub place: Option<Place>,
    pub roles: Vec<String>,
    pub data_object_formats: Vec<DataObjectFormat>,
    pub commitments: Vec<Commitment>,
}

/// Huella del certificado de firma con las peculiaridades de jxades.
pub fn cert_digest(cert: &[u8], uri: &str, v2: bool) -> Vec<u8> {
    use afirma_core::DigestAlgorithm as D;
    let alg = if v2 {
        if uri == "http://www.w3.org/2001/04/xmlenc#sha512" {
            D::Sha512
        } else {
            D::Sha256
        }
    } else {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#sha256" => D::Sha256,
            "http://www.w3.org/2001/04/xmlenc#sha512" => D::Sha512,
            _ => D::Sha1,
        }
    };
    alg.digest(cert)
}

struct W<'a> {
    x: &'a str,
    ds: &'a DsNames,
    out: String,
}

impl W<'_> {
    fn xq(&self, local: &str) -> String {
        format!("{}:{local}", self.x)
    }
    fn open(&mut self, local: &str) {
        let q = self.xq(local);
        self.out.push_str(&format!("<{q}>"));
    }
    fn close(&mut self, local: &str) {
        let q = self.xq(local);
        self.out.push_str(&format!("</{q}>"));
    }
    fn leaf(&mut self, local: &str, text: &str) {
        let q = self.xq(local);
        if text.is_empty() {
            self.out.push_str(&format!("<{q}/>"));
        } else {
            self.out.push_str(&format!("<{q}>{}</{q}>", esc_text(text)));
        }
    }
    fn ds_digest(&mut self, alg: &str, value: &str) {
        self.out.push_str(&format!(
            "<{dm} Algorithm=\"{}\"/><{dv}>{}</{dv}>",
            esc_attr(alg),
            esc_text(value),
            dm = self.ds.q("DigestMethod"),
            dv = self.ds.q("DigestValue")
        ));
    }
}

/// Texto completo del `ds:Object` con `QualifyingProperties`.
///
/// `in_scope_xades`: el prefijo XAdES ya está declarado en el ámbito de
/// inserción (contrafirmas), lo que solo cambia el orden de los atributos.
#[allow(clippy::too_many_arguments)]
pub fn render_qualifying_object(
    ds: &DsNames,
    xades_prefix: &str,
    xades_ns: &str,
    sig_prefix: &str,
    props: &SignedProps,
    in_scope_xades: bool,
) -> String {
    let mut w = W {
        x: xades_prefix,
        ds,
        out: String::new(),
    };
    let ds_decl = ds.xmlns();
    let xades_decl = format!(" xmlns:{xades_prefix}=\"{}\"", esc_attr(xades_ns));
    let id_target = format!(" Id=\"{sig_prefix}-QualifyingProperties\" Target=\"#{sig_prefix}-Signature\"");
    w.out.push_str(&format!("<{}>", ds.q("Object")));
    if in_scope_xades {
        let mut attrs = vec![id_target.trim().to_string()];
        attrs.extend([ds_decl.trim().to_string(), xades_decl.trim().to_string()]);
        // Orden por nombre cualificado (Id, Target, xmlns:...).
        w.out
            .push_str(&format!("<{}:QualifyingProperties {}>", xades_prefix, attrs.join(" ")));
    } else {
        w.out.push_str(&format!(
            "<{}:QualifyingProperties{xades_decl}{id_target}{ds_decl}>",
            xades_prefix
        ));
    }
    w.out.push_str(&format!(
        "<{}:SignedProperties Id=\"{sig_prefix}-SignedProperties\">",
        xades_prefix
    ));
    w.open("SignedSignatureProperties");
    w.leaf("SigningTime", &props.signing_time);
    let names = CertNames::from_der(&props.cert_der);
    let render_cert = |w: &mut W<'_>| {
        let v2 = props.baseline;
        let digest = cert_digest(&props.cert_der, &props.cert_digest_uri, v2);
        w.open(if v2 {
            "SigningCertificateV2"
        } else {
            "SigningCertificate"
        });
        w.open("Cert");
        w.open("CertDigest");
        w.ds_digest(&props.cert_digest_uri, &b64(&digest));
        w.close("CertDigest");
        if v2 {
            w.leaf("IssuerSerialV2", "");
        } else {
            w.open("IssuerSerial");
            let (issuer, serial) = names
                .as_ref()
                .map(|n| (n.issuer_java.clone(), n.serial_decimal.clone()))
                .unwrap_or_default();
            w.out.push_str(&format!(
                "<{a}>{}</{a}><{b}>{}</{b}>",
                esc_text(&issuer),
                esc_text(&serial),
                a = ds.q("X509IssuerName"),
                b = ds.q("X509SerialNumber")
            ));
            w.close("IssuerSerial");
        }
        w.close("Cert");
        w.close(if v2 {
            "SigningCertificateV2"
        } else {
            "SigningCertificate"
        });
    };
    let render_policy = |w: &mut W<'_>| match &props.policy {
        PolicySpec::None => {}
        PolicySpec::Implied => {
            w.open("SignaturePolicyIdentifier");
            w.leaf("SignaturePolicyImplied", "");
            w.close("SignaturePolicyIdentifier");
        }
        PolicySpec::Explicit(p) => {
            w.open("SignaturePolicyIdentifier");
            w.open("SignaturePolicyId");
            w.open("SigPolicyId");
            w.leaf("Identifier", &p.identifier);
            w.leaf("Description", &p.description);
            w.close("SigPolicyId");
            w.open("SigPolicyHash");
            w.ds_digest(&p.hash_algorithm_uri, &p.hash);
            w.close("SigPolicyHash");
            if let Some(q) = &p.qualifier {
                w.open("SigPolicyQualifiers");
                w.open("SigPolicyQualifier");
                w.leaf("SPURI", q);
                w.close("SigPolicyQualifier");
                w.close("SigPolicyQualifiers");
            }
            w.close("SignaturePolicyId");
            w.close("SignaturePolicyIdentifier");
        }
    };
    if props.baseline {
        render_policy(&mut w);
        render_cert(&mut w);
    } else {
        render_cert(&mut w);
        render_policy(&mut w);
    }
    if let Some(place) = &props.place
        && !place.is_empty(props.baseline)
    {
        let name = if props.baseline {
            "SignatureProductionPlaceV2"
        } else {
            "SignatureProductionPlace"
        };
        w.open(name);
        if let Some(v) = &place.city {
            w.leaf("City", v);
        }
        if props.baseline
            && let Some(v) = &place.street
        {
            w.leaf("StreetAddress", v);
        }
        if let Some(v) = &place.province {
            w.leaf("StateOrProvince", v);
        }
        if let Some(v) = &place.postal_code {
            w.leaf("PostalCode", v);
        }
        if let Some(v) = &place.country {
            w.leaf("CountryName", v);
        }
        w.close(name);
    }
    if !props.roles.is_empty() {
        let name = if props.baseline { "SignerRoleV2" } else { "SignerRole" };
        w.open(name);
        w.open("ClaimedRoles");
        for r in &props.roles {
            w.leaf("ClaimedRole", r);
        }
        w.close("ClaimedRoles");
        w.close(name);
    }
    w.close("SignedSignatureProperties");
    if !props.data_object_formats.is_empty() || !props.commitments.is_empty() {
        w.open("SignedDataObjectProperties");
        for d in &props.data_object_formats {
            w.out.push_str(&format!(
                "<{}:DataObjectFormat ObjectReference=\"{}\">",
                xades_prefix,
                esc_attr(&d.object_reference)
            ));
            w.leaf("Description", d.description.as_deref().unwrap_or(""));
            if let Some(oi) = &d.object_identifier {
                w.open("ObjectIdentifier");
                let q = oi
                    .qualifier
                    .as_ref()
                    .map(|q| format!(" Qualifier=\"{}\"", esc_attr(q)))
                    .unwrap_or_default();
                w.out.push_str(&format!(
                    "<{xades_prefix}:Identifier{q}>{}</{xades_prefix}:Identifier>",
                    esc_text(&oi.identifier)
                ));
                w.leaf("Description", oi.description.as_deref().unwrap_or(""));
                if !oi.documentation_references.is_empty() {
                    w.open("DocumentationReferences");
                    for r in &oi.documentation_references {
                        w.leaf("DocumentationReference", r);
                    }
                    w.close("DocumentationReferences");
                }
                w.close("ObjectIdentifier");
            }
            w.leaf("MimeType", d.mime_type.as_deref().unwrap_or(""));
            w.leaf("Encoding", d.encoding.as_deref().unwrap_or(""));
            w.close("DataObjectFormat");
        }
        for c in &props.commitments {
            w.open("CommitmentTypeIndication");
            w.open("CommitmentTypeId");
            if c.identifier.starts_with("urn:oid:") {
                w.out.push_str(&format!(
                    "<{}:Identifier Qualifier=\"OIDAsURN\">{}</{}:Identifier>",
                    xades_prefix,
                    esc_text(&c.identifier),
                    xades_prefix
                ));
            } else {
                w.leaf("Identifier", &c.identifier);
            }
            w.leaf("Description", c.description.as_deref().unwrap_or(""));
            if !c.documentation_references.is_empty() {
                w.open("DocumentationReferences");
                for d in &c.documentation_references {
                    w.leaf("DocumentationReference", d);
                }
                w.close("DocumentationReferences");
            }
            w.close("CommitmentTypeId");
            match &c.object_reference {
                Some(r) => w.leaf("ObjectReference", r),
                None => w.leaf("AllSignedDataObjects", ""),
            }
            w.open("CommitmentTypeQualifiers");
            for q in &c.qualifiers {
                w.leaf("CommitmentTypeQualifier", q);
            }
            w.close("CommitmentTypeQualifiers");
            w.close("CommitmentTypeIndication");
        }
        w.close("SignedDataObjectProperties");
    }
    w.out.push_str(&format!("</{}:SignedProperties>", xades_prefix));
    w.out.push_str(&format!("</{}:QualifyingProperties>", xades_prefix));
    w.out.push_str(&format!("</{}>", ds.q("Object")));
    w.out
}

/// Opciones del `KeyInfo` de AutoFirma (`AOXMLAdvancedSignature.newKeyInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfoOptions {
    pub certs: Vec<Vec<u8>>,
    pub key_value: bool,
    pub key_name: bool,
    pub issuer_serial: bool,
}

/// `KeyInfo` de AutoFirma.
pub fn render_key_info(ds: &DsNames, id: &str, o: &KeyInfoOptions) -> String {
    let mut s = format!("<{} Id=\"{}\">", ds.q("KeyInfo"), esc_attr(id));
    s.push_str(&dsig::render_x509_data(ds, &o.certs));
    let first = o.certs.first().cloned().unwrap_or_default();
    let is_ec = crate::crypto::cert_key_algorithm(&first) == Some(afirma_core::KeyAlgorithm::Ec);
    if o.key_value
        && !is_ec
        && let Some(kv) = dsig::render_key_value(ds, &first)
    {
        s.push_str(&kv);
    }
    let names = CertNames::from_der(&first);
    if o.key_name
        && let Some(n) = &names
    {
        s.push_str(&format!(
            "<{k}>{}</{k}>",
            esc_text(&n.subject_ldap),
            k = ds.q("KeyName")
        ));
    }
    if o.issuer_serial
        && let Some(n) = &names
    {
        s.push_str(&format!(
            "<{is}><{a}>{}</{a}><{b}>{}</{b}></{is}>",
            esc_text(&n.issuer_ldap),
            esc_text(&n.serial_decimal),
            is = ds.q("X509IssuerSerial"),
            a = ds.q("X509IssuerName"),
            b = ds.q("X509SerialNumber")
        ));
    }
    s.push_str(&format!("</{}>", ds.q("KeyInfo")));
    s
}

/// `KeyInfo` de jxades (`XMLAdvancedSignature.newKeyInfo`), usado en
/// cofirma/contrafirma con `includeOnlySignningCertificate=true`.
pub fn render_jxades_key_info(ds: &DsNames, id: &str, cert: &[u8]) -> String {
    let mut s = format!("<{} Id=\"{}\">", ds.q("KeyInfo"), esc_attr(id));
    if let Some(kv) = dsig::render_key_value(ds, cert) {
        s.push_str(&kv);
    }
    let names = CertNames::from_der(cert);
    s.push_str(&format!("<{}>", ds.q("X509Data")));
    s.push_str(&format!("<{x}>{}</{x}>", b64(cert), x = ds.q("X509Certificate")));
    if let Some(n) = &names {
        s.push_str(&format!(
            "<{x}>{}</{x}>",
            esc_text(&n.subject_rfc1779),
            x = ds.q("X509SubjectName")
        ));
        s.push_str(&format!(
            "<{is}><{a}>{}</{a}><{b}>{}</{b}></{is}>",
            esc_text(&n.issuer_java),
            esc_text(&n.serial_decimal),
            is = ds.q("X509IssuerSerial"),
            a = ds.q("X509IssuerName"),
            b = ds.q("X509SerialNumber")
        ));
    }
    s.push_str(&format!("</{}>", ds.q("X509Data")));
    s.push_str(&format!("</{}>", ds.q("KeyInfo")));
    s
}

// ---------------------------------------------------------------------------
// Lectura de metadatos de los parámetros
// ---------------------------------------------------------------------------

/// `XAdESUtil.getDigestMethodByCommonName`: solo SHA1, SHA-256 y SHA-512.
pub fn digest_method_by_common_name(name: &str) -> Option<&'static str> {
    match afirma_core::algorithms::java_digest_algorithm_name(name).as_str() {
        "SHA1" => Some("http://www.w3.org/2000/09/xmldsig#sha1"),
        "SHA-256" => Some("http://www.w3.org/2001/04/xmlenc#sha256"),
        "SHA-512" => Some("http://www.w3.org/2001/04/xmlenc#sha512"),
        _ => None,
    }
}

fn is_dotted_oid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Política de firma de los parámetros (`XAdESCommonMetadataUtil.getPolicy`).
///
/// Sin huella o sin algoritmo de huella jxades descargaría el documento de la
/// política; aquí la política se omite en ese caso (con aviso), igual que hace
/// Java cuando la descarga falla.
pub fn policy_from_params(p: &ExtraParams) -> afirma_core::Result<Option<Policy>> {
    let Some(id) = p.get("policyIdentifier") else {
        return Ok(None);
    };
    let identifier = if is_dotted_oid(id) {
        format!("urn:oid:{id}")
    } else {
        id.to_string()
    };
    let hash_alg = match p.get("policyIdentifierHashAlgorithm") {
        Some(a) => Some(digest_method_by_common_name(a).ok_or_else(|| {
            AfirmaError::new(
                codes::UNSUPPORTED_POLICY_HASH_ALGORITHM,
                format!("El algoritmo indicado para la politica no esta soportado: {a}"),
            )
        })?),
        None => None,
    };
    let (Some(hash_alg), Some(hash)) = (hash_alg, p.get("policyIdentifierHash")) else {
        tracing::warn!(
            "No se ha indicado la huella de la politica '{identifier}' o su algoritmo; no se descarga el documento de politica y se omite la politica"
        );
        return Ok(None);
    };
    Ok(Some(Policy {
        identifier,
        hash_algorithm_uri: hash_alg.to_string(),
        hash: hash.to_string(),
        description: p.get("policyDescription").unwrap_or("").to_string(),
        qualifier: p.get("policyQualifier").map(str::to_string),
    }))
}

/// Lugar de firma de los parámetros.
pub fn place_from_params(p: &ExtraParams) -> Option<Place> {
    let place = Place {
        city: p.get("signatureProductionCity").map(str::to_string),
        street: p.get("signatureProductionStreetAddress").map(str::to_string),
        province: p.get("signatureProductionProvince").map(str::to_string),
        postal_code: p.get("signatureProductionPostalCode").map(str::to_string),
        country: p.get("signatureProductionCountry").map(str::to_string),
    };
    if place.city.is_none()
        && place.street.is_none()
        && place.province.is_none()
        && place.postal_code.is_none()
        && place.country.is_none()
    {
        None
    } else {
        Some(place)
    }
}

/// Roles declarados (`signerClaimedRoles`, separados por `|`).
pub fn roles_from_params(p: &ExtraParams) -> Vec<String> {
    match p.get("signerClaimedRoles") {
        Some(v) => v
            .split('|')
            .filter(|r| !r.trim().is_empty())
            .map(str::to_string)
            .collect(),
        None => vec![],
    }
}

fn is_java_url(s: &str) -> bool {
    match s.split_once(':') {
        Some((scheme, rest)) => {
            matches!(
                scheme.to_ascii_lowercase().as_str(),
                "http" | "https" | "ftp" | "file" | "jar" | "mailto"
            ) && !rest.is_empty()
        }
        None => false,
    }
}

/// `XAdESUtil.parseCommitmentTypeIndications` (índices `0..=N`, como Java).
pub fn commitments_from_params(p: &ExtraParams, signed_data_id: Option<&str>) -> Vec<Commitment> {
    let Some(n) = p.get("commitmentTypeIndications") else {
        return vec![];
    };
    let n: i64 = match n.trim().parse() {
        Ok(v) if v >= 1 => v,
        _ => {
            tracing::warn!("El parametro 'commitmentTypeIndications' debe contener un entero positivo: {n}");
            return vec![];
        }
    };
    let mut out = Vec::new();
    for i in 0..=n {
        let Some(id) = p.get(&format!("commitmentTypeIndication{i}Identifier")) else {
            continue;
        };
        let Some((_, uri)) = COMMITMENT_TYPES.iter().find(|(k, _)| *k == id) else {
            tracing::warn!("Tipo de compromiso no soportado: {id}");
            continue;
        };
        let docs = p
            .get(&format!("commitmentTypeIndication{i}DocumentationReferences"))
            .map(|v| v.split('|').filter(|d| is_java_url(d)).map(str::to_string).collect())
            .unwrap_or_default();
        let quals = p
            .get(&format!("commitmentTypeIndication{i}CommitmentTypeQualifiers"))
            .map(|v| v.split('|').map(str::to_string).collect())
            .unwrap_or_default();
        out.push(Commitment {
            identifier: uri.to_string(),
            description: p
                .get(&format!("commitmentTypeIndication{i}Description"))
                .map(str::to_string),
            documentation_references: docs,
            object_reference: signed_data_id.map(|s| format!("#{s}")),
            qualifiers: quals,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctis_zero_to_n_inclusive() {
        let p = ExtraParams::parse(
            "commitmentTypeIndications=1\ncommitmentTypeIndication0Identifier=1\ncommitmentTypeIndication1Identifier=5\ncommitmentTypeIndication1DocumentationReferences=http://a.es/x|nourl\n",
        );
        let c = commitments_from_params(&p, Some("Reference-1"));
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].identifier, "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval");
        assert_eq!(c[1].documentation_references, vec!["http://a.es/x".to_string()]);
        assert_eq!(c[0].object_reference.as_deref(), Some("#Reference-1"));
    }

    #[test]
    fn policy_parsing() {
        let p = ExtraParams::parse(
            "policyIdentifier=2.16.724.1.3.1.1.2.1.9\npolicyIdentifierHash=G7roucf600+f03r/o0bAOQ6WAs0=\npolicyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1\n",
        );
        let pol = policy_from_params(&p).unwrap().unwrap();
        assert_eq!(pol.identifier, "urn:oid:2.16.724.1.3.1.1.2.1.9");
        assert_eq!(pol.hash_algorithm_uri, "http://www.w3.org/2000/09/xmldsig#sha1");
        let bad = ExtraParams::parse(
            "policyIdentifier=x\npolicyIdentifierHash=AA==\npolicyIdentifierHashAlgorithm=SHA-384\n",
        );
        assert_eq!(
            policy_from_params(&bad).unwrap_err().code,
            Some(codes::UNSUPPORTED_POLICY_HASH_ALGORITHM)
        );
    }
}
