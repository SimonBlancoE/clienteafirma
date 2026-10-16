//! Lectura de certificados descargados (AIA `caIssuers`): DER, PEM (uno o
//! varios bloques), Base64 o PKCS#7 `certs-only` (`.p7c`, DER o PEM).

use afirma_cms::asn1::{Tag, Tlv, tags};

use crate::x509::Cert;

/// `id-signedData`.
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// Certificados (DER) contenidos en `data`. Los que no se pueden analizar
/// se omiten.
pub fn parse_certificates(data: &[u8]) -> Vec<Vec<u8>> {
    if data.first() == Some(&0x30) {
        return parse_der(data);
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut in_block = false;
    let mut b64 = String::new();
    let mut found_block = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with("-----BEGIN") {
            in_block = true;
            found_block = true;
            b64.clear();
        } else if line.starts_with("-----END") {
            in_block = false;
            if let Ok(der) = afirma_core::base64_decode_lenient(&b64) {
                out.extend(parse_der(&der));
            }
            b64.clear();
        } else if in_block && !line.contains(':') {
            b64.push_str(line);
        }
    }
    if !found_block {
        let all: String = text.split_whitespace().collect();
        if let Ok(der) = afirma_core::base64_decode_lenient(&all) {
            out.extend(parse_der(&der));
        }
    }
    out
}

/// Certificado DER o PKCS#7 `SignedData` con certificados.
fn parse_der(der: &[u8]) -> Vec<Vec<u8>> {
    let Ok(top) = Tlv::parse_single(der) else {
        return Vec::new();
    };
    if Cert::parse(top.raw).is_ok() {
        return vec![top.raw.to_vec()];
    }
    pkcs7_certificates(&top).unwrap_or_default()
}

fn pkcs7_certificates(top: &Tlv<'_>) -> Option<Vec<Vec<u8>>> {
    let ci = top.children().ok()?;
    if !ci.first()?.as_oid().ok()?.is(OID_SIGNED_DATA) {
        return None;
    }
    let content = ci.get(1)?.children().ok()?;
    let signed_data = content.first()?.expect(tags::SEQUENCE).ok()?;
    let mut out = Vec::new();
    for field in signed_data.children().ok()? {
        if field.tag != Tag::context(0, true) {
            continue;
        }
        for c in field.children().ok()? {
            if c.tag == tags::SEQUENCE && Cert::parse(c.raw).is_ok() {
                out.push(c.raw.to_vec());
            }
        }
    }
    Some(out)
}
