//! Certificado X.509 con los campos que necesita la validación, extraídos
//! con el lector ASN.1 de `afirma-cms` (conservando las codificaciones
//! originales del nombre, la clave y el `tbsCertificate`).

use afirma_cms::asn1::{Class, Tag, Tlv, tags};
use afirma_cms::cert::{CertView, minimal_twos_complement};
use chrono::{DateTime, Duration, Utc};

/// `id-pe-authorityInfoAccess`.
pub(crate) const OID_AIA: &str = "1.3.6.1.5.5.7.1.1";
/// `id-ad-ocsp`.
pub(crate) const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
/// `id-ad-caIssuers`.
pub(crate) const OID_AD_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
/// `id-ce-cRLDistributionPoints`.
pub(crate) const OID_CRL_DP: &str = "2.5.29.31";
/// `id-ce-extKeyUsage`.
pub(crate) const OID_EKU: &str = "2.5.29.37";
/// `id-kp-OCSPSigning`.
pub(crate) const OID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// Etiqueta `[6] IMPLICIT IA5String` (`uniformResourceIdentifier`).
const TAG_URI: Tag = Tag {
    class: Class::Context,
    constructed: false,
    number: 6,
};

/// Certificado analizado.
#[derive(Debug, Clone)]
pub(crate) struct Cert {
    /// Codificación DER completa.
    pub der: Vec<u8>,
    /// `tbsCertificate` (codificación original, lo firmado).
    pub tbs: Vec<u8>,
    /// `signatureAlgorithm` (AlgorithmIdentifier completo).
    pub sig_alg: Vec<u8>,
    /// Firma (contenido del BIT STRING).
    pub signature: Vec<u8>,
    /// Número de serie (complemento a dos mínimo).
    pub serial: Vec<u8>,
    /// Nombre del emisor (Name completo, codificación original).
    pub issuer: Vec<u8>,
    /// Nombre del titular (Name completo, codificación original).
    pub subject: Vec<u8>,
    /// SubjectPublicKeyInfo completa.
    pub spki: Vec<u8>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Entradas URI de la extensión AIA, en orden: (OID del método, URI).
    pub aia: Vec<(String, String)>,
    /// URI de los `fullName` de la extensión de puntos de distribución de CRL.
    pub crl_urls: Vec<String>,
    /// El certificado tiene el uso extendido `id-kp-OCSPSigning`.
    pub ocsp_signing: bool,
}

impl Cert {
    /// Analiza un certificado DER.
    pub fn parse(der: &[u8]) -> Result<Cert, String> {
        let view = CertView::parse(der).map_err(|e| format!("Certificado no valido: {e}"))?;
        let top = Tlv::parse_single(der)
            .and_then(|t| t.children())
            .map_err(|e| e.to_string())?;
        let [tbs, sig_alg, sig] = top.as_slice() else {
            return Err("Certificado no valido: estructura incorrecta".into());
        };
        let signature = sig.bit_string_content().map_err(|e| e.to_string())?.to_vec();
        let not_before = view.not_before_time().map_err(|e| e.to_string())?;
        let not_after = view.not_after_time().map_err(|e| e.to_string())?;
        // Las extensiones mal formadas se ignoran (como si no existieran).
        let aia = view
            .extension(OID_AIA)
            .map(|v| parse_aia(&v).unwrap_or_default())
            .unwrap_or_default();
        let crl_urls = view
            .extension(OID_CRL_DP)
            .map(|v| parse_crl_dp(&v).unwrap_or_default())
            .unwrap_or_default();
        let ocsp_signing = view
            .extension(OID_EKU)
            .is_some_and(|v| eku_contains(&v, OID_KP_OCSP_SIGNING));
        Ok(Cert {
            der: der.to_vec(),
            tbs: tbs.raw.to_vec(),
            sig_alg: sig_alg.raw.to_vec(),
            signature,
            serial: minimal_twos_complement(view.serial).to_vec(),
            issuer: view.issuer.to_vec(),
            subject: view.subject.to_vec(),
            spki: view.spki.raw.to_vec(),
            not_before,
            not_after,
            aia,
            crl_urls,
            ocsp_signing,
        })
    }

    /// Clave pública (contenido del BIT STRING de la SubjectPublicKeyInfo).
    pub fn public_key_bits(&self) -> Option<Vec<u8>> {
        let spki = Tlv::parse_single(&self.spki).ok()?;
        Some(spki.children().ok()?.get(1)?.bit_string_content().ok()?.to_vec())
    }

    /// URL de servicios OCSP (`id-ad-ocsp`) declaradas, recortadas.
    pub fn ocsp_urls(&self) -> Vec<String> {
        self.aia_urls(OID_AD_OCSP)
    }

    /// URL de certificados del emisor (`id-ad-caIssuers`).
    pub fn ca_issuers_urls(&self) -> Vec<String> {
        self.aia_urls(OID_AD_CA_ISSUERS)
    }

    fn aia_urls(&self, method: &str) -> Vec<String> {
        self.aia
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, u)| u.trim().to_string())
            .collect()
    }

    /// Todas las URI de la extensión AIA, sea cual sea el método
    /// (`OcspHelper.getAIALocations`).
    pub fn all_aia_uris(&self) -> Vec<String> {
        self.aia.iter().map(|(_, u)| u.clone()).collect()
    }

    /// Indica si emisor y titular coinciden.
    pub fn is_self_issued(&self) -> bool {
        names_match(&self.issuer, &self.subject)
    }

    /// Indica si el certificado está en vigor en `t` con un margen `skew`.
    pub fn is_valid_at(&self, t: DateTime<Utc>, skew: Duration) -> bool {
        self.not_before - skew <= t && t <= self.not_after + skew
    }

    /// Verifica la firma del certificado con la clave pública indicada
    /// (SubjectPublicKeyInfo DER).
    pub fn verify_signed_by(&self, issuer_spki: &[u8]) -> Result<(), String> {
        crate::sig::verify(&self.sig_alg, issuer_spki, &self.tbs, &self.signature)
    }

    /// Indica si `issuer` es el emisor de este certificado: su titular
    /// coincide con nuestro emisor y su clave verifica nuestra firma.
    pub fn is_issued_by(&self, issuer: &Cert) -> bool {
        names_match(&self.issuer, &issuer.subject) && self.verify_signed_by(&issuer.spki).is_ok()
    }
}

/// Analiza el valor de la extensión AIA y devuelve las entradas URI.
fn parse_aia(value: &[u8]) -> Result<Vec<(String, String)>, String> {
    let seq = Tlv::parse_single(value).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for ad in seq.children().map_err(|e| e.to_string())? {
        let parts = ad.children().map_err(|e| e.to_string())?;
        let (Some(method), Some(location)) = (parts.first(), parts.get(1)) else {
            continue;
        };
        let Ok(method) = method.as_oid() else { continue };
        if location.tag == TAG_URI {
            out.push((method.to_dotted(), String::from_utf8_lossy(location.value).into_owned()));
        }
    }
    Ok(out)
}

/// URI de los `fullName` de todos los puntos de distribución, en orden.
fn parse_crl_dp(value: &[u8]) -> Result<Vec<String>, String> {
    let seq = Tlv::parse_single(value).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for dp in seq.children().map_err(|e| e.to_string())? {
        for field in dp.children().map_err(|e| e.to_string())? {
            // distributionPoint [0] DistributionPointName (CHOICE: explícito).
            if field.tag != Tag::context(0, true) {
                continue;
            }
            for name in field.children().map_err(|e| e.to_string())? {
                // fullName [0] IMPLICIT GeneralNames.
                if name.tag != Tag::context(0, true) {
                    continue;
                }
                for gn in name.children().map_err(|e| e.to_string())? {
                    if gn.tag == TAG_URI {
                        out.push(String::from_utf8_lossy(gn.value).into_owned());
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Indica si la extensión ExtendedKeyUsage contiene el OID.
fn eku_contains(value: &[u8], oid: &str) -> bool {
    Tlv::parse_single(value)
        .and_then(|s| s.children())
        .map(|items| items.iter().any(|i| i.as_oid().is_ok_and(|o| o.is(oid))))
        .unwrap_or(false)
}

/// Compara dos nombres X.500: iguales byte a byte o, si no, con los mismos
/// atributos en el mismo orden y valores iguales sin distinguir mayúsculas ni
/// espacios repetidos (aproximación a RFC 5280 §7.1). Java compara
/// `X500Principal.toString()`, que tampoco depende del tipo de cadena.
pub(crate) fn names_match(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    match (normalized_name(a), normalized_name(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn normalized_name(der: &[u8]) -> Option<Vec<Vec<(String, String)>>> {
    let name = Tlv::parse_single(der).ok()?.expect(tags::SEQUENCE).ok()?;
    let mut rdns = Vec::new();
    for rdn in name.children().ok()? {
        let mut avas = Vec::new();
        for ava in rdn.children().ok()? {
            let parts = ava.children().ok()?;
            let oid = parts.first()?.as_oid().ok()?.to_dotted();
            let value = parts.get(1)?;
            let text = match value.as_string() {
                Ok(s) => s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase(),
                Err(_) => format!("#{}", hex::encode(value.raw)),
            };
            avas.push((oid, text));
        }
        avas.sort();
        rdns.push(avas);
    }
    Some(rdns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_comparison() {
        use afirma_cms::asn1::der;
        let name = |cn: Vec<u8>| {
            der::sequence([
                der::set_of([der::sequence([der::oid_str("2.5.4.6"), der::printable_string("ES")])]),
                der::set_of([der::sequence([der::oid_str("2.5.4.3"), cn])]),
            ])
        };
        let a = name(der::printable_string("Mi  CA"));
        let b = name(der::utf8_string("mi ca"));
        let c = name(der::utf8_string("Otra CA"));
        assert!(names_match(&a, &a));
        assert!(names_match(&a, &b));
        assert!(!names_match(&a, &c));
        assert!(!names_match(&a, b"basura"));
    }
}
