//! Representaciones textuales de nombres X.500 tal y como las produce Java,
//! necesarias para la paridad de las firmas XML:
//!
//! - [`java_name`]: `X500Name.toString()` (estilo por defecto de Java, usado en
//!   `X509IssuerName` de `SigningCertificate`).
//! - [`rfc1779_name`]: `X500Principal.getName("RFC1779")` (KeyInfo de jxades).
//! - [`rfc2253_name`]: `X500Principal.getName()` (KeyInfo ODF).
//! - [`ldap_escaped_name`]: nombre tratado por `EscapeHelper.escapeLdapName`
//!   (KeyName y X509IssuerSerial de XAdES).

use x509_parser::der_parser::asn1_rs::{Any, Tag};
use x509_parser::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Default,
    Rfc1779,
    Rfc2253,
}

/// Palabra clave Java para un OID (`AVAKeyword`), según el estilo.
fn keyword(oid: &str, style: Style) -> String {
    // (oid, palabra clave, compatible RFC 1779, compatible RFC 2253)
    const TABLE: &[(&str, &str, bool, bool)] = &[
        ("2.5.4.3", "CN", true, true),
        ("2.5.4.6", "C", true, true),
        ("2.5.4.7", "L", true, true),
        ("2.5.4.8", "ST", true, true),
        ("2.5.4.10", "O", true, true),
        ("2.5.4.11", "OU", true, true),
        ("2.5.4.12", "T", false, false),
        ("1.3.6.1.4.1.42.2.11.2.1", "IP", false, false),
        ("2.5.4.9", "STREET", true, true),
        ("0.9.2342.19200300.100.1.25", "DC", false, true),
        ("2.5.4.46", "DNQUALIFIER", false, false),
        ("2.5.4.4", "SURNAME", false, false),
        ("2.5.4.42", "GIVENNAME", false, false),
        ("2.5.4.43", "INITIALS", false, false),
        ("2.5.4.44", "GENERATION", false, false),
        ("1.2.840.113549.1.9.1", "EMAILADDRESS", false, false),
        ("0.9.2342.19200300.100.1.1", "UID", false, true),
        ("2.5.4.5", "SERIALNUMBER", false, false),
    ];
    if let Some((_, kw, r1779, r2253)) = TABLE.iter().find(|(o, ..)| *o == oid) {
        let ok = match style {
            Style::Default => true,
            Style::Rfc1779 => *r1779,
            Style::Rfc2253 => *r2253,
        };
        if ok {
            return kw.to_string();
        }
    }
    match style {
        Style::Rfc2253 => oid.to_string(),
        _ => format!("OID.{oid}"),
    }
}

/// Valor de un atributo como cadena (`DerValue.getAsString()`); `None` si no
/// es un tipo de cadena.
fn value_string(v: &Any<'_>) -> Option<String> {
    let data = v.data;
    match v.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::GeneralString => {
            Some(String::from_utf8_lossy(data).into_owned())
        }
        Tag::T61String => Some(data.iter().map(|&b| b as char).collect()),
        Tag::BmpString => {
            let units: Vec<u16> = data
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
        Tag::UniversalString => Some(
            data.chunks(4)
                .filter_map(|c| {
                    (c.len() == 4)
                        .then(|| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])))
                        .flatten()
                })
                .collect(),
        ),
        _ => None,
    }
}

/// Codificación DER (TLV) de un valor.
fn value_der(v: &Any<'_>) -> Vec<u8> {
    let tag = v.tag().0;
    let class = v.class() as u8;
    let constructed = v.header.is_constructed();
    let mut out = Vec::new();
    let first = (class << 6) | if constructed { 0x20 } else { 0 };
    if tag < 31 {
        out.push(first | tag as u8);
    } else {
        out.push(first | 0x1f);
        let mut bytes = Vec::new();
        let mut t = tag;
        bytes.push((t & 0x7f) as u8);
        t >>= 7;
        while t > 0 {
            bytes.push(0x80 | (t & 0x7f) as u8);
            t >>= 7;
        }
        bytes.reverse();
        out.extend(bytes);
    }
    let len = v.data.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let lb: Vec<u8> = len.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        out.push(0x80 | lb.len() as u8);
        out.extend(lb);
    }
    out.extend_from_slice(v.data);
    out
}

fn hex_upper(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect()
}

/// `DerValue.isPrintableStringChar`.
fn is_printable_string_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
        )
}

/// `AVA.toKeywordValueString` (estilos por defecto y RFC 1779).
fn keyword_value(kw: &str, v: &Any<'_>) -> String {
    let mut out = String::new();
    out.push_str(kw);
    out.push('=');
    match value_string(v) {
        None => {
            out.push('#');
            out.push_str(&hex_upper(&value_der(v)));
        }
        Some(val) => {
            const ESCAPEES: &str = ",+=\n<>#;\\\"";
            let chars: Vec<char> = val.chars().collect();
            let len = chars.len();
            let already_quoted = len > 1 && chars[0] == '"' && chars[len - 1] == '"';
            let mut quote_needed = false;
            let mut previous_white = false;
            let mut sb = String::new();
            for (i, &c) in chars.iter().enumerate() {
                if already_quoted && (i == 0 || i == len - 1) {
                    sb.push(c);
                    continue;
                }
                if is_printable_string_char(c) || ESCAPEES.contains(c) {
                    if !quote_needed && ((i == 0 && (c == ' ' || c == '\n')) || ESCAPEES.contains(c)) {
                        quote_needed = true;
                    }
                    if !(c == ' ' || c == '\n') {
                        if c == '"' || c == '\\' {
                            sb.push('\\');
                        }
                        previous_white = false;
                    } else {
                        if !quote_needed && previous_white {
                            quote_needed = true;
                        }
                        previous_white = true;
                    }
                    sb.push(c);
                } else {
                    previous_white = false;
                    sb.push(c);
                }
            }
            if sb.ends_with(' ') || sb.ends_with('\n') {
                quote_needed = true;
            }
            if !already_quoted && quote_needed {
                out.push('"');
                out.push_str(&sb);
                out.push('"');
            } else {
                out.push_str(&sb);
            }
        }
    }
    out
}

/// `AVA.toRFC2253String`.
fn rfc2253_value(kw: &str, v: &Any<'_>) -> String {
    let mut out = String::new();
    out.push_str(kw);
    out.push('=');
    let is_der_string = matches!(
        v.tag(),
        Tag::PrintableString | Tag::T61String | Tag::Ia5String | Tag::GeneralString | Tag::BmpString | Tag::Utf8String
    );
    if kw.starts_with(|c: char| c.is_ascii_digit()) || !is_der_string {
        out.push('#');
        out.push_str(&hex::encode(value_der(v)));
        return out;
    }
    let val = String::from_utf8_lossy(v.data).into_owned();
    const ESCAPEES: &str = ",=+<>#;\"\\";
    let mut sb: Vec<char> = Vec::new();
    for c in val.chars() {
        if is_printable_string_char(c) || ESCAPEES.contains(c) {
            if ESCAPEES.contains(c) {
                sb.push('\\');
            }
            sb.push(c);
        } else if c == '\0' {
            sb.extend("\\00".chars());
        } else {
            sb.push(c);
        }
    }
    let lead = sb.iter().position(|&c| c != ' ' && c != '\r').unwrap_or(sb.len());
    let trail = sb
        .iter()
        .rposition(|&c| c != ' ' && c != '\r')
        .map(|t| t as isize)
        .unwrap_or(-1);
    for (i, c) in sb.iter().enumerate() {
        if i < lead || (i as isize) > trail {
            out.push('\\');
        }
        out.push(*c);
    }
    out
}

fn format_name(name: &X509Name<'_>, style: Style) -> String {
    let rdns: Vec<_> = name.iter_rdn().collect();
    let mut parts = Vec::new();
    for rdn in rdns.iter().rev() {
        let mut avas: Vec<String> = rdn
            .iter()
            .map(|ava| {
                let oid = ava.attr_type().to_id_string();
                let kw = keyword(&oid, style);
                match style {
                    Style::Rfc2253 => rfc2253_value(&kw, ava.attr_value()),
                    _ => keyword_value(&kw, ava.attr_value()),
                }
            })
            .collect();
        if style == Style::Rfc2253 {
            avas.sort();
            parts.push(avas.join("+"));
        } else {
            parts.push(avas.join(" + "));
        }
    }
    match style {
        Style::Rfc2253 => parts.join(","),
        _ => parts.join(", "),
    }
}

/// `X500Name.toString()` de Java (p. ej. `CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES`).
pub fn java_name(name: &X509Name<'_>) -> String {
    format_name(name, Style::Default)
}

/// `X500Principal.getName("RFC1779")`.
pub fn rfc1779_name(name: &X509Name<'_>) -> String {
    format_name(name, Style::Rfc1779)
}

/// `X500Principal.getName()` (RFC 2253).
pub fn rfc2253_name(name: &X509Name<'_>) -> String {
    format_name(name, Style::Rfc2253)
}

/// `javax.naming.ldap.Rdn.escapeValue` para cadenas.
fn rdn_escape_value(val: &str) -> String {
    const ESCAPEES: &str = ",=+<>#;\"\\";
    let chars: Vec<char> = val.chars().collect();
    let is_ws = |c: char| c == ' ' || c == '\r';
    let lead = chars.iter().position(|&c| !is_ws(c)).unwrap_or(chars.len());
    let trail = chars.iter().rposition(|&c| !is_ws(c)).map(|t| t as isize).unwrap_or(-1);
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if i < lead || (i as isize) > trail || ESCAPEES.contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Sustitución de caracteres acentuados de `EscapeHelper.escapeCharacters`.
fn escape_characters(s: &str) -> String {
    const MAP: &[(char, &str)] = &[
        ('\u{e1}', "\\C3\\A1"),
        ('\u{e9}', "\\C3\\A9"),
        ('\u{ed}', "\\C3\\AD"),
        ('\u{f3}', "\\C3\\B3"),
        ('\u{fa}', "\\C3\\BA"),
        ('\u{c1}', "\\C3\\81"),
        ('\u{c9}', "\\C3\\89"),
        ('\u{cd}', "\\C3\\8D"),
        ('\u{d3}', "\\C3\\93"),
        ('\u{da}', "\\C3\\9A"),
        ('\u{f1}', "\\C3\\B1"),
        ('\u{d1}', "\\C3\\91"),
        ('\u{e7}', "\\C3\\A7"),
        ('\u{c7}', "\\C3\\87"),
        ('\u{e0}', "\\C3\\A0"),
        ('\u{e8}', "\\C3\\A8"),
        ('\u{ec}', "\\C3\\AC"),
        ('\u{f2}', "\\C3\\B2"),
        ('\u{f9}', "\\C3\\B9"),
        ('\u{c0}', "\\C3\\80"),
        ('\u{c8}', "\\C3\\88"),
        ('\u{cc}', "\\C3\\8C"),
        ('\u{d2}', "\\C3\\92"),
        ('\u{d9}', "\\C3\\99"),
        ('\u{fc}', "\\C3\\BC"),
        ('\u{dc}', "\\C3\\9C"),
        ('\u{bf}', "\\C2\\BF"),
        ('\u{a1}', "\\C2\\A1"),
        ('\u{b5}', "\\C2\\B5"),
        ('\u{ba}', "\\C2\\BA"),
        ('\u{aa}', "\\C2\\AA"),
    ];
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match MAP.iter().find(|(k, _)| *k == c) {
            Some((_, rep)) => out.push_str(rep),
            None => out.push(c),
        }
    }
    out
}

/// Nombre tal y como lo deja `EscapeHelper.escapeLdapName` aplicado dos veces
/// (efecto neto): RDN en orden de presentación separados por `,`, palabra
/// clave Java, valor escapado con `Rdn.escapeValue` y acentos como `\C3\A1`.
/// De los RDN multivaluados solo se conserva el primer valor.
pub fn ldap_escaped_name(name: &X509Name<'_>) -> String {
    let rdns: Vec<_> = name.iter_rdn().collect();
    let mut parts = Vec::new();
    for rdn in rdns.iter().rev() {
        let Some(ava) = rdn.iter().next() else {
            continue;
        };
        let oid = ava.attr_type().to_id_string();
        let kw = keyword(&oid, Style::Default);
        let value = match value_string(ava.attr_value()) {
            Some(v) => rdn_escape_value(&v),
            None => format!("#{}", hex_upper(&value_der(ava.attr_value()))),
        };
        parts.push(format!("{kw}={}", escape_characters(&value)));
    }
    parts.join(",")
}

/// Datos de un certificado usados en las firmas XML.
pub struct CertNames {
    pub issuer_java: String,
    pub issuer_ldap: String,
    pub subject_ldap: String,
    pub subject_rfc1779: String,
    pub subject_rfc2253: String,
    /// Número de serie en decimal.
    pub serial_decimal: String,
}

impl CertNames {
    pub fn from_der(der: &[u8]) -> Option<CertNames> {
        let (_, cert) = X509Certificate::from_der(der).ok()?;
        Some(CertNames {
            issuer_java: java_name(cert.issuer()),
            issuer_ldap: ldap_escaped_name(cert.issuer()),
            subject_ldap: ldap_escaped_name(cert.subject()),
            subject_rfc1779: rfc1779_name(cert.subject()),
            subject_rfc2253: rfc2253_name(cert.subject()),
            serial_decimal: cert.tbs_certificate.serial.to_str_radix(10),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdn_escape() {
        assert_eq!(rdn_escape_value(" a,b#c "), "\\ a\\,b\\#c\\ ");
        assert_eq!(escape_characters("Logroño Á"), "Logro\\C3\\B1o \\C3\\81");
    }

    #[test]
    fn test_certificate_names() {
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/pki/firmante-rsa.crt"
        ))
        .unwrap();
        let der = afirma_core::cert::decode_certificate(&pem).unwrap();
        let n = CertNames::from_der(&der).unwrap();
        assert!(
            n.issuer_java.starts_with("CN=AC Raiz de Pruebas AutoFirma-rs"),
            "{}",
            n.issuer_java
        );
        assert!(n.subject_ldap.contains("ESPA\\C3\\91OL"), "{}", n.subject_ldap);
        assert!(!n.serial_decimal.is_empty());
    }
}
