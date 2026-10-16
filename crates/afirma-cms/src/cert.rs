//! Acceso mínimo a los campos de un certificado X.509 conservando su
//! codificación original (necesario para IssuerAndSerialNumber, ESSCertID...).

use chrono::{DateTime, Utc};

use crate::asn1::{Oid, Result, Tag, Tlv, der, tags};

/// Vista de un certificado X.509 sobre sus bytes DER.
#[derive(Debug, Clone, Copy)]
pub struct CertView<'a> {
    pub raw: &'a [u8],
    pub tbs: Tlv<'a>,
    /// Bytes de complemento a dos del número de serie.
    pub serial: &'a [u8],
    /// Nombre del emisor (SEQUENCE completa, codificación original).
    pub issuer: &'a [u8],
    /// Nombre del titular (SEQUENCE completa, codificación original).
    pub subject: &'a [u8],
    /// SubjectPublicKeyInfo completa.
    pub spki: Tlv<'a>,
    pub not_before: Tlv<'a>,
    pub not_after: Tlv<'a>,
    pub extensions: Option<Tlv<'a>>,
}

impl<'a> CertView<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let cert = Tlv::parse_single(raw)?.expect(tags::SEQUENCE)?;
        let parts = cert.children()?;
        let tbs = parts.first().copied().ok_or(crate::asn1::Asn1Error::Truncated)?.expect(tags::SEQUENCE)?;
        let mut f = tbs.children()?.into_iter().peekable();
        if f.peek().is_some_and(|t| t.tag == Tag::context(0, true)) {
            f.next();
        }
        let serial = f.next().ok_or(crate::asn1::Asn1Error::Truncated)?.as_integer_bytes()?;
        let _sig_alg = f.next();
        let issuer = f.next().ok_or(crate::asn1::Asn1Error::Truncated)?.raw;
        let validity = f.next().ok_or(crate::asn1::Asn1Error::Truncated)?.children()?;
        let subject = f.next().ok_or(crate::asn1::Asn1Error::Truncated)?.raw;
        let spki = f.next().ok_or(crate::asn1::Asn1Error::Truncated)?;
        let extensions = f
            .find(|t| t.tag == Tag::context(3, true))
            .and_then(|t| t.children().ok()?.into_iter().next());
        Ok(CertView {
            raw,
            tbs,
            serial,
            issuer,
            subject,
            spki,
            not_before: *validity.first().ok_or(crate::asn1::Asn1Error::Truncated)?,
            not_after: *validity.get(1).ok_or(crate::asn1::Asn1Error::Truncated)?,
            extensions,
        })
    }

    /// `IssuerAndSerialNumber` (RFC 5652). El número de serie se codifica en
    /// su forma mínima (como `new ASN1Integer(BigInteger)` en Java).
    pub fn issuer_and_serial(&self) -> Vec<u8> {
        der::sequence([self.issuer.to_vec(), self.serial_der()])
    }

    /// `IssuerSerial` de ESSCertID/ESSCertIDv2 (RFC 5035): GeneralNames con el
    /// emisor como directoryName y el número de serie.
    pub fn ess_issuer_serial(&self) -> Vec<u8> {
        let general_name = der::explicit(4, self.issuer);
        der::sequence([der::sequence([general_name]), self.serial_der()])
    }

    /// Número de serie como INTEGER DER mínimo.
    pub fn serial_der(&self) -> Vec<u8> {
        der::integer_raw(minimal_twos_complement(self.serial))
    }

    /// Número de serie en decimal (como `BigInteger.toString()`).
    pub fn serial_decimal(&self) -> String {
        twos_complement_to_decimal(self.serial)
    }

    /// Compara el número de serie con otro (como valores enteros).
    pub fn serial_equals(&self, other: &[u8]) -> bool {
        minimal_twos_complement(self.serial) == minimal_twos_complement(other)
    }

    /// Inicio del periodo de validez.
    pub fn not_before_time(&self) -> Result<DateTime<Utc>> {
        self.not_before.as_time()
    }

    /// Fin del periodo de validez.
    pub fn not_after_time(&self) -> Result<DateTime<Utc>> {
        self.not_after.as_time()
    }

    /// Indica si el certificado es válido en el instante dado (límites incluidos).
    pub fn is_valid_at(&self, t: DateTime<Utc>) -> bool {
        match (self.not_before_time(), self.not_after_time()) {
            (Ok(nb), Ok(na)) => nb <= t && t <= na,
            _ => false,
        }
    }

    /// `PolicyInformation` de la extensión `certificatePolicies` (codificación
    /// original de cada una, en orden), si la extensión existe.
    pub fn policy_informations(&self) -> Option<Vec<Vec<u8>>> {
        let ext = self.extension(crate::oids::CERTIFICATE_POLICIES)?;
        let seq = Tlv::parse_single(&ext).ok()?;
        let items = seq.children().ok()?;
        Some(items.iter().map(Tlv::to_definite).collect())
    }

    /// Tipo de la clave pública del certificado.
    pub fn key_algorithm(&self) -> Option<afirma_core::KeyAlgorithm> {
        crate::alg::key_algorithm_from_spki_oid(&self.public_key_algorithm()?)
    }

    /// OID de la curva elíptica (parámetros de la clave pública EC).
    pub fn ec_curve(&self) -> Option<Oid> {
        let alg = self.spki.children().ok()?.into_iter().next()?;
        alg.children().ok()?.get(1)?.as_oid().ok()
    }

    /// Common Name del titular (como `AOUtil.getCN`).
    pub fn common_name(&self) -> String {
        afirma_core::cert::common_name(self.raw)
    }

    /// Valor de una extensión (contenido del OCTET STRING).
    pub fn extension(&self, oid: &str) -> Option<Vec<u8>> {
        let target = Oid::new(oid);
        for ext in self.extensions?.children().ok()? {
            let fields = ext.children().ok()?;
            if fields.first()?.as_oid().ok()? == target {
                return fields.last()?.octet_string_content().ok();
            }
        }
        None
    }

    /// Identificador de clave del titular (extensión SubjectKeyIdentifier).
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        let ext = self.extension("2.5.29.14")?;
        Tlv::parse_single(&ext).ok()?.octet_string_content().ok()
    }

    /// OID del algoritmo de la clave pública.
    pub fn public_key_algorithm(&self) -> Option<Oid> {
        let alg = self.spki.children().ok()?.into_iter().next()?;
        alg.children().ok()?.into_iter().next()?.as_oid().ok()
    }

    /// Clave pública (contenido del BIT STRING).
    pub fn public_key_bits(&self) -> Option<&'a [u8]> {
        self.spki.children().ok()?.get(1)?.bit_string_content().ok()
    }

    /// Indica si el certificado está autofirmado (emisor == titular).
    pub fn is_self_issued(&self) -> bool {
        self.issuer == self.subject
    }
}

/// Elimina los bytes de signo redundantes de un entero en complemento a dos.
pub fn minimal_twos_complement(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start + 1 < bytes.len() {
        let b = bytes[start];
        let next = bytes[start + 1];
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    &bytes[start..]
}

/// Representación decimal de un entero en complemento a dos (big endian).
pub fn twos_complement_to_decimal(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "0".into();
    }
    let negative = bytes[0] & 0x80 != 0;
    let mut mag: Vec<u8> = if negative {
        // Magnitud = complemento a dos del valor.
        let mut v: Vec<u8> = bytes.iter().map(|b| !b).collect();
        for b in v.iter_mut().rev() {
            let (r, carry) = b.overflowing_add(1);
            *b = r;
            if !carry {
                break;
            }
        }
        v
    } else {
        bytes.to_vec()
    };
    let mut digits = Vec::new();
    while mag.iter().any(|&b| b != 0) {
        let mut rem: u32 = 0;
        for b in mag.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        digits.push(b'0');
    }
    if negative {
        digits.push(b'-');
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_test_certificate() {
        let pem = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/pki/firmante-rsa.crt")).unwrap();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = afirma_test_b64(&b64);
        let c = CertView::parse(&der).unwrap();
        assert!(!c.serial.is_empty());
        assert!(c.subject_key_identifier().is_some());
        assert_eq!(c.public_key_algorithm().unwrap().to_dotted(), "1.2.840.113549.1.1.1");
        assert!(!c.is_self_issued());
        let ias = c.issuer_and_serial();
        assert!(Tlv::parse_single(&ias).is_ok());
        assert!(c.policy_informations().unwrap().len() == 2);
        assert_eq!(c.key_algorithm(), Some(afirma_core::KeyAlgorithm::Rsa));
        assert!(c.is_valid_at(chrono::Utc::now()));
        assert_eq!(c.common_name(), "ESPAÑOL ESPAÑOL JUAN - 00000000T");
    }

    #[test]
    fn integers() {
        assert_eq!(twos_complement_to_decimal(&[0x01, 0x00]), "256");
        assert_eq!(twos_complement_to_decimal(&[0xff]), "-1");
        assert_eq!(twos_complement_to_decimal(&[0x00, 0x9f, 0x98]), "40856");
        assert_eq!(twos_complement_to_decimal(&[0x00]), "0");
        assert_eq!(twos_complement_to_decimal(&[0x80]), "-128");
        assert_eq!(minimal_twos_complement(&[0x00, 0x00, 0x7f]), &[0x7f]);
        assert_eq!(minimal_twos_complement(&[0x00, 0x80]), &[0x00, 0x80]);
        assert_eq!(minimal_twos_complement(&[0xff, 0xff, 0x80]), &[0x80]);
    }

    fn afirma_test_b64(s: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for c in s.bytes().filter(|c| *c != b'=') {
            let v = T.iter().position(|&x| x == c).unwrap() as u32;
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        out
    }
}
