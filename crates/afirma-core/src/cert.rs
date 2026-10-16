//! Utilidades de certificados X.509 (lectura de campos para la interfaz,
//! los filtros y los nombres de firmante).

use chrono::{DateTime, TimeZone, Utc};
use x509_parser::prelude::*;

/// Common Name del titular (como `AOUtil.getCN`): el CN si existe; si no, el
/// DN completo.
pub fn common_name(der: &[u8]) -> String {
    match X509Certificate::from_der(der) {
        Ok((_, cert)) => name_cn(cert.subject()),
        Err(_) => String::new(),
    }
}

/// CN de un nombre X.500 (o el nombre completo si no tiene CN).
pub fn name_cn(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|cn| attr_string(cn.attr_value()))
        .unwrap_or_else(|| name.to_string())
}

/// Valor de un atributo de nombre como texto (UTF8, Printable, BMP, T61...).
pub fn attr_string(v: &x509_parser::der_parser::asn1_rs::Any<'_>) -> Option<String> {
    use x509_parser::der_parser::asn1_rs::Tag;
    let data = v.data;
    match v.tag() {
        Tag::BmpString => {
            let units: Vec<u16> = data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
            Some(String::from_utf16_lossy(&units))
        }
        Tag::T61String => Some(data.iter().map(|&b| b as char).collect()),
        Tag::UniversalString => Some(
            data.chunks(4)
                .filter_map(|c| (c.len() == 4).then(|| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))).flatten())
                .collect(),
        ),
        _ => std::str::from_utf8(data).ok().map(str::to_string),
    }
}

/// Uso de clave (`keyUsage`), en el orden de la extensión X.509.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsageFlags {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

/// Datos de un certificado para mostrar y filtrar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub subject_cn: String,
    pub subject_dn: String,
    pub issuer_cn: String,
    pub issuer_dn: String,
    /// Número de serie en hexadecimal (minúsculas, sin ceros a la izquierda).
    pub serial_hex: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// `None` si el certificado no tiene la extensión keyUsage.
    pub key_usage: Option<KeyUsageFlags>,
    pub extended_key_usage: Vec<String>,
    pub policies: Vec<String>,
    /// Huella SHA-1 en hexadecimal (minúsculas).
    pub sha1_hex: String,
    /// Huella SHA-256 en hexadecimal (minúsculas).
    pub sha256_hex: String,
    /// Atributo serialNumber del titular (en certificados españoles, el NIF,
    /// a veces con prefijo `IDCES-`).
    pub subject_serial_number: Option<String>,
    pub is_ca: bool,
    pub self_signed: bool,
}

impl CertInfo {
    pub fn parse(der: &[u8]) -> Option<CertInfo> {
        let (_, cert) = X509Certificate::from_der(der).ok()?;
        let ts = |t: ASN1Time| Utc.timestamp_opt(t.timestamp(), 0).single().unwrap_or_default();
        let mut key_usage = None;
        let mut eku = Vec::new();
        let mut policies = Vec::new();
        let mut is_ca = false;
        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => {
                    key_usage = Some(KeyUsageFlags {
                        digital_signature: ku.digital_signature(),
                        non_repudiation: ku.non_repudiation(),
                        key_encipherment: ku.key_encipherment(),
                        data_encipherment: ku.data_encipherment(),
                        key_agreement: ku.key_agreement(),
                        key_cert_sign: ku.key_cert_sign(),
                        crl_sign: ku.crl_sign(),
                        encipher_only: ku.encipher_only(),
                        decipher_only: ku.decipher_only(),
                    })
                }
                ParsedExtension::ExtendedKeyUsage(e) => {
                    if e.server_auth {
                        eku.push("1.3.6.1.5.5.7.3.1".into());
                    }
                    if e.client_auth {
                        eku.push("1.3.6.1.5.5.7.3.2".into());
                    }
                    if e.code_signing {
                        eku.push("1.3.6.1.5.5.7.3.3".into());
                    }
                    if e.email_protection {
                        eku.push("1.3.6.1.5.5.7.3.4".into());
                    }
                    if e.time_stamping {
                        eku.push("1.3.6.1.5.5.7.3.8".into());
                    }
                    if e.ocsp_signing {
                        eku.push("1.3.6.1.5.5.7.3.9".into());
                    }
                    for o in &e.other {
                        eku.push(o.to_id_string());
                    }
                }
                ParsedExtension::CertificatePolicies(p) => {
                    for pi in p.iter() {
                        policies.push(pi.policy_id.to_id_string());
                    }
                }
                ParsedExtension::BasicConstraints(bc) => is_ca = bc.ca,
                _ => {}
            }
        }
        let subject_serial_number = cert
            .subject()
            .iter_by_oid(&x509_parser::oid_registry::OID_X509_SERIALNUMBER)
            .next()
            .and_then(|a| attr_string(a.attr_value()));
        Some(CertInfo {
            subject_cn: name_cn(cert.subject()),
            subject_dn: cert.subject().to_string(),
            issuer_cn: name_cn(cert.issuer()),
            issuer_dn: cert.issuer().to_string(),
            serial_hex: cert.tbs_certificate.serial.to_str_radix(16),
            not_before: ts(cert.validity().not_before),
            not_after: ts(cert.validity().not_after),
            key_usage,
            extended_key_usage: eku,
            policies,
            sha1_hex: hex::encode(crate::DigestAlgorithm::Sha1.digest(der)),
            sha256_hex: hex::encode(crate::DigestAlgorithm::Sha256.digest(der)),
            subject_serial_number,
            is_ca,
            self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
        })
    }

    /// Indica si el certificado está en vigor en el instante dado.
    pub fn is_valid_at(&self, t: DateTime<Utc>) -> bool {
        self.not_before <= t && t <= self.not_after
    }
}

/// Decodifica un certificado en DER o PEM (o Base64 sin cabeceras).
pub fn decode_certificate(data: &[u8]) -> Option<Vec<u8>> {
    if X509Certificate::from_der(data).is_ok() {
        return Some(data.to_vec());
    }
    let text = std::str::from_utf8(data).ok()?;
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect::<String>();
    let der = crate::base64_decode_lenient(&b64).ok()?;
    let valid = X509Certificate::from_der(&der).is_ok();
    valid.then_some(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_test_certificate() {
        let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/pki/firmante-rsa.crt")).unwrap();
        let der = decode_certificate(&pem).unwrap();
        let info = CertInfo::parse(&der).unwrap();
        assert_eq!(info.subject_cn, "ESPAÑOL ESPAÑOL JUAN - 00000000T");
        assert_eq!(info.issuer_cn, "AC Raiz de Pruebas AutoFirma-rs");
        assert_eq!(info.subject_serial_number.as_deref(), Some("IDCES-00000000T"));
        let ku = info.key_usage.unwrap();
        assert!(ku.digital_signature && ku.non_repudiation && !ku.key_cert_sign);
        assert!(info.policies.contains(&"2.16.724.1.3.5.7.1".to_string()));
        assert!(!info.is_ca);
        assert_eq!(common_name(&der), info.subject_cn);
    }
}
