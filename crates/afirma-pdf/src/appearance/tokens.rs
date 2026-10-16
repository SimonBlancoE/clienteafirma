//! Texto de la firma visible: nombres X.500 con el formato de Java,
//! sustitución de las etiquetas `$$…$$` y ofuscación de identificadores.

use x509_parser::der_parser::asn1_rs::{Any, Tag};
use x509_parser::prelude::*;

use crate::pdf::date::{SignTime, java_format_or_default};

// ---------------------------------------------------------------------------
// Nombres X.500
// ---------------------------------------------------------------------------

/// Palabras clave de `X500Principal.toString()` (estilo por defecto de
/// `sun.security.x509.AVA`).
const DEFAULT_KEYWORDS: &[(&str, &str)] = &[
    ("2.5.4.3", "CN"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.12", "T"),
    ("1.3.6.1.4.1.42.2.11.2.1", "IP"),
    ("2.5.4.9", "STREET"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("2.5.4.46", "DNQUALIFIER"),
    ("2.5.4.4", "SURNAME"),
    ("2.5.4.42", "GIVENNAME"),
    ("2.5.4.43", "INITIALS"),
    ("2.5.4.44", "GENERATION"),
    ("1.2.840.113549.1.9.1", "EMAILADDRESS"),
    ("0.9.2342.19200300.100.1.1", "UID"),
    ("2.5.4.5", "SERIALNUMBER"),
];

/// Palabras clave de `X500Principal.getName()` (RFC 2253).
const RFC2253_KEYWORDS: &[(&str, &str)] = &[
    ("2.5.4.3", "CN"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.9", "STREET"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("0.9.2342.19200300.100.1.1", "UID"),
];

/// Valor de un atributo como texto (`DerValue.getAsString()`), o `None` si
/// no es de un tipo cadena.
fn any_string(v: &Any<'_>) -> Option<String> {
    let data = v.data;
    match v.tag() {
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
        Tag::T61String | Tag::GeneralString => Some(data.iter().map(|&b| char::from(b)).collect()),
        Tag::Utf8String
        | Tag::PrintableString
        | Tag::Ia5String
        | Tag::VisibleString
        | Tag::NumericString => Some(String::from_utf8_lossy(data).into_owned()),
        _ => None,
    }
}

/// Codificación DER completa de un valor (para la forma `#hex`).
fn any_der(v: &Any<'_>) -> Vec<u8> {
    let tag = v.tag().0;
    let class = v.class() as u8;
    let constructed = v.header.is_constructed();
    let mut out = Vec::new();
    let first = (class << 6) | if constructed { 0x20 } else { 0 };
    if tag < 31 {
        out.push(first | tag as u8);
    } else {
        out.push(first | 0x1f);
        let mut stack = Vec::new();
        let mut t = tag;
        stack.push((t & 0x7f) as u8);
        t >>= 7;
        while t > 0 {
            stack.push(0x80 | (t & 0x7f) as u8);
            t >>= 7;
        }
        stack.reverse();
        out.extend(stack);
    }
    let len = v.data.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(v.data);
    out
}

fn is_printable_string_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
        )
}

/// Valor de un AVA como en `AVA.toKeywordValueString` (formato por defecto).
fn ava_value_default(value: &Any<'_>) -> String {
    let Some(val) = any_string(value) else {
        let mut s = String::from("#");
        for b in any_der(value) {
            s.push_str(&format!("{b:02X}"));
        }
        return s;
    };
    let escapees = ",+=\n<>#;\\\"";
    let chars: Vec<char> = val.chars().collect();
    let len = chars.len();
    let already_quoted = len > 1 && chars[0] == '"' && chars[len - 1] == '"';
    let mut quote = false;
    let mut prev_white = false;
    let mut buf = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if already_quoted && (i == 0 || i == len - 1) {
            buf.push(c);
            continue;
        }
        if is_printable_string_char(c) || escapees.contains(c) {
            if !quote && ((i == 0 && (c == ' ' || c == '\n')) || escapees.contains(c)) {
                quote = true;
            }
            if c != ' ' && c != '\n' {
                if c == '"' || c == '\\' {
                    buf.push('\\');
                }
                prev_white = false;
            } else {
                if !quote && prev_white {
                    quote = true;
                }
                prev_white = true;
            }
            buf.push(c);
        } else {
            prev_white = false;
            buf.push(c);
        }
    }
    if buf.ends_with(' ') || buf.ends_with('\n') {
        quote = true;
    }
    if !already_quoted && quote {
        format!("\"{buf}\"")
    } else {
        buf
    }
}

/// Valor de un AVA en formato RFC 2253.
fn ava_value_rfc2253(value: &Any<'_>, known: bool) -> String {
    let val = match any_string(value) {
        Some(v) if known => v,
        _ => {
            let mut s = String::from("#");
            for b in any_der(value) {
                s.push_str(&format!("{b:02x}"));
            }
            return s;
        }
    };
    let chars: Vec<char> = val.chars().collect();
    // Java escapa todos los espacios finales (no solo el último).
    let trailing_start = chars.len() - chars.iter().rev().take_while(|c| **c == ' ').count();
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let special = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (i == 0 && (c == '#' || c == ' '))
            || (i >= trailing_start && c == ' ');
        if special {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `X500Principal.toString()` de un nombre DER.
pub fn x500_to_string(name: &X509Name<'_>) -> String {
    let rdns: Vec<String> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|ava| {
                    let oid = ava.attr_type().to_id_string();
                    let kw = DEFAULT_KEYWORDS
                        .iter()
                        .find(|(o, _)| *o == oid)
                        .map(|(_, k)| (*k).to_string())
                        .unwrap_or_else(|| format!("OID.{oid}"));
                    format!("{kw}={}", ava_value_default(ava.attr_value()))
                })
                .collect::<Vec<_>>()
                .join(" + ")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(", ")
}

/// `X500Principal.getName()` (RFC 2253) de un nombre DER.
pub fn x500_rfc2253(name: &X509Name<'_>) -> String {
    let rdns: Vec<String> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|ava| {
                    let oid = ava.attr_type().to_id_string();
                    match RFC2253_KEYWORDS.iter().find(|(o, _)| *o == oid) {
                        Some((_, k)) => {
                            format!("{k}={}", ava_value_rfc2253(ava.attr_value(), true))
                        }
                        None => format!("{oid}={}", ava_value_rfc2253(ava.attr_value(), false)),
                    }
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(",")
}

/// `AOUtil.getRDNvalueFromLdapName`.
pub fn rdn_value(rdn: &str, principal: &str) -> Option<String> {
    let lower = principal.to_lowercase();
    let rdn_l = rdn.to_lowercase();
    let pc: Vec<char> = principal.chars().collect();
    // Trabajamos por índices de carácter (las cadenas en minúsculas pueden
    // diferir en bytes).
    let lc: Vec<char> = lower.chars().collect();
    let rc: Vec<char> = rdn_l.chars().collect();
    if lc.len() != pc.len() {
        return None;
    }
    let find_from = |from: usize| -> Option<usize> {
        if rc.is_empty() {
            return Some(from);
        }
        (from..lc.len().saturating_sub(rc.len() - 1)).find(|&i| lc[i..i + rc.len()] == rc[..])
    };
    let mut offset = 0;
    while let Some(o) = find_from(offset) {
        let mut o1 = o;
        if o1 > 0 && pc[o1 - 1] != ',' && pc[o1 - 1] != ' ' {
            offset = o1 + 1;
            continue;
        }
        o1 += rc.len();
        while o1 < pc.len() && pc[o1] == ' ' {
            o1 += 1;
        }
        if o1 >= pc.len() {
            return None;
        }
        if pc[o1] != '=' {
            offset = o1;
            continue;
        }
        o1 += 1;
        while o1 < pc.len() && pc[o1] == ' ' {
            o1 += 1;
        }
        if o1 >= pc.len() {
            return Some(String::new());
        }
        if pc[o1] == ',' {
            return Some(String::new());
        }
        if pc[o1] == '"' {
            o1 += 1;
            if o1 >= pc.len() {
                return Some(String::new());
            }
            return match pc[o1..].iter().position(|&c| c == '"') {
                Some(0) => Some(String::new()),
                Some(p) => Some(pc[o1..o1 + p].iter().collect()),
                None => Some(pc[o1..].iter().collect()),
            };
        }
        let end = pc[o1..]
            .iter()
            .position(|&c| c == ',')
            .map_or(pc.len(), |p| o1 + p);
        return Some(pc[o1..end].iter().collect::<String>().trim().to_string());
    }
    None
}

/// `AOUtil.getCN(String)`.
pub fn cn_of_principal(principal: &str) -> String {
    if let Some(v) = rdn_value("cn", principal).or_else(|| rdn_value("ou", principal)) {
        return v;
    }
    if let Some(i) = principal.find('=') {
        return rdn_value(&principal[..i], principal).unwrap_or_default();
    }
    principal.to_string()
}

/// `AOUtil.getOUS`.
pub fn ous_of_principal(principal: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut aux = principal.to_string();
    while let Some(ou) = rdn_value("ou", &aux) {
        if out.len() > 64 {
            break;
        }
        out.push(ou.clone());
        let before = aux.clone();
        aux = aux
            .replace(&format!("OU={ou}"), "")
            .replace(&format!("OU=\"{ou}"), "\"")
            .replace(&format!("ou={ou}"), "")
            .replace(&format!("ou=\"{ou}"), "\"");
        if aux == before {
            break;
        }
    }
    out
}

/// Datos de un certificado necesarios para el texto de la firma visible.
#[derive(Debug, Clone, Default)]
pub struct CertText {
    /// `X500Principal.toString()` del titular.
    pub subject: String,
    /// `getName()` (RFC 2253) del emisor.
    pub issuer_rfc2253: String,
    /// Número de serie en decimal.
    pub serial_decimal: String,
    /// El certificado es de seudónimo (contiene el atributo 2.5.4.65).
    pub pseudonym_cert: bool,
}

impl CertText {
    pub fn from_der(der: &[u8]) -> Option<CertText> {
        let (_, cert) = X509Certificate::from_der(der).ok()?;
        let pseudonym_cert = cert
            .subject()
            .iter_attributes()
            .any(|a| a.attr_type().to_id_string() == "2.5.4.65");
        Some(CertText {
            subject: x500_to_string(cert.subject()),
            issuer_rfc2253: x500_rfc2253(cert.issuer()),
            serial_decimal: cert.tbs_certificate.serial.to_str_radix(10),
            pseudonym_cert,
        })
    }

    /// `AOUtil.getCN(cert)`.
    pub fn subject_cn(&self) -> String {
        cn_of_principal(&self.subject)
    }
}

// ---------------------------------------------------------------------------
// Ofuscación
// ---------------------------------------------------------------------------

/// Máscara de ofuscación (`PdfTextMask`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMask {
    pub ch: char,
    pub min_length: usize,
    pub positions: Vec<bool>,
    pub shift: bool,
}

impl Default for TextMask {
    fn default() -> Self {
        TextMask {
            ch: '*',
            min_length: 3,
            positions: vec![false, false, false, true, true, true, true],
            shift: true,
        }
    }
}

fn java_split(s: &str, sep: char) -> Vec<&str> {
    let mut v: Vec<&str> = s.split(sep).collect();
    while v.len() > 1 && v.last() == Some(&"") {
        v.pop();
    }
    if v == [""] && !s.is_empty() {
        v.clear();
    }
    v
}

impl TextMask {
    /// `PdfTextMask.parseParam`.
    pub fn parse(param: &str) -> Result<TextMask, String> {
        let el = java_split(param, ';');
        if el.len() != 4 {
            return Err("El numero de elementos de la mascara no es valido".into());
        }
        let mut chars = el[0].chars();
        let (Some(ch), None) = (chars.next(), chars.next()) else {
            return Err("No se indico un caracter de ofuscacion unico".into());
        };
        if !el[1].chars().all(char::is_numeric) {
            return Err("No se indico un numero valido de digitos minimos".into());
        }
        let length: usize = el[1]
            .parse()
            .map_err(|_| "No se indico un numero valido de digitos minimos".to_string())?;
        let list = java_split(el[2], ',');
        if list.len() <= 1 {
            return Err("No se indico un listado de posiciones valido".into());
        }
        let pb = |s: &str| s.eq_ignore_ascii_case("true");
        let mut pos = list.len() as isize - 1;
        while pos >= 0 && !pb(list[pos as usize]) {
            pos -= 1;
        }
        let shift = pb(el[3]);
        if pos > 0 && ch != '\0' {
            let positions = list[..=pos as usize].iter().map(|s| pb(s)).collect();
            Ok(TextMask {
                ch,
                min_length: length,
                positions,
                shift,
            })
        } else {
            Ok(TextMask::default())
        }
    }
}

fn is_letter_or_digit(c: char) -> bool {
    c.is_alphanumeric()
}

fn is_digit(c: char) -> bool {
    c.is_ascii_digit() || c.general_category_digit()
}

trait DigitCategory {
    fn general_category_digit(self) -> bool;
}

impl DigitCategory for char {
    /// Aproximación de `Character.isDigit` (categoría Nd) para los rangos de
    /// dígitos decimales Unicode más habituales.
    fn general_category_digit(self) -> bool {
        let u = self as u32;
        const RANGES: &[(u32, u32)] = &[
            (0x0660, 0x0669),
            (0x06F0, 0x06F9),
            (0x07C0, 0x07C9),
            (0x0966, 0x096F),
            (0x09E6, 0x09EF),
            (0x0A66, 0x0A6F),
            (0x0AE6, 0x0AEF),
            (0x0B66, 0x0B6F),
            (0x0BE6, 0x0BEF),
            (0x0C66, 0x0C6F),
            (0x0CE6, 0x0CEF),
            (0x0D66, 0x0D6F),
            (0x0E50, 0x0E59),
            (0x0ED0, 0x0ED9),
            (0x0F20, 0x0F29),
            (0x1040, 0x1049),
            (0xFF10, 0xFF19),
        ];
        RANGES.iter().any(|&(a, b)| (a..=b).contains(&u))
    }
}

fn obfuscate_segment(text: &mut [char], pos: usize, length: usize, mask: &TextMask) {
    let num_digits = text.iter().filter(|c| is_digit(**c)).count();
    let plain = mask.positions.iter().filter(|b| **b).count();
    if num_digits >= plain {
        let mut pm = mask.positions.clone();
        if mask.shift && num_digits < pm.len() {
            let mut new_pm = vec![false; num_digits];
            let omit = mask.positions.len() - num_digits;
            let mut cnt = 0;
            for (i, &v) in mask.positions.iter().enumerate() {
                if v || cnt >= omit {
                    if let Some(slot) = new_pm.get_mut(i - cnt) {
                        *slot = v;
                    }
                } else {
                    cnt += 1;
                }
            }
            pm = new_pm;
        }
        let mut j = 0;
        for k in 0..length {
            let c = text[pos + k];
            if is_digit(c) {
                if j >= pm.len() || !pm[j] {
                    text[pos + k] = mask.ch;
                }
                j += 1;
            } else {
                text[pos + k] = mask.ch;
            }
        }
    } else {
        let mut p = mask.positions.len() as isize - 1;
        let mut k = (pos + length) as isize - 1;
        while k >= pos as isize {
            if p < 0 || !mask.positions[p as usize] {
                text[k as usize] = mask.ch;
            }
            p -= 1;
            k -= 1;
        }
    }
}

/// `PdfVisibleAreasUtils.obfuscateIds`.
pub fn obfuscate_ids(text: &str, mask: &TextMask) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    let mut digit_count = 0;
    let mut pos = 0;
    let mut found = false;
    for i in 0..chars.len() {
        let c = chars[i];
        if is_letter_or_digit(c) {
            if is_digit(c) {
                digit_count += 1;
                if digit_count == mask.min_length {
                    found = true;
                }
            } else {
                digit_count = 0;
            }
        } else {
            if found {
                obfuscate_segment(&mut chars, pos, i - pos, mask);
                found = false;
            }
            pos = i + 1;
        }
    }
    if found {
        let len = chars.len();
        obfuscate_segment(&mut chars, pos, len - pos, mask);
    }
    chars.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Etiquetas del texto
// ---------------------------------------------------------------------------

/// Datos para resolver las etiquetas del texto de la firma visible.
#[derive(Debug, Clone, Default)]
pub struct LayerTextData<'a> {
    pub cert: Option<&'a CertText>,
    pub sign_time: Option<SignTime>,
    pub reason: Option<&'a str>,
    pub location: Option<&'a str>,
    pub contact: Option<&'a str>,
    /// Máscara de ofuscación (`None` = no ofuscar).
    pub mask: Option<TextMask>,
}

/// Error al resolver las etiquetas (`$$SIGNDATE` sin cierre, que en Java
/// lanza `StringIndexOutOfBoundsException`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclosedDateTag;

/// `PdfVisibleAreasUtils.getLayerText`.
pub fn layer_text(txt: &str, d: &LayerTextData<'_>) -> Result<String, UnclosedDateTag> {
    let mut ret = txt.to_string();
    if let Some(cert) = d.cert {
        let mut cn = cert.subject_cn();
        if let Some(m) = &d.mask {
            cn = obfuscate_ids(&cn, m);
        }
        ret = ret
            .replace("$$SUBJECTCN$$", &cn)
            .replace("$$ISSUERCN$$", &cn_of_principal(&cert.issuer_rfc2253))
            .replace("$$CERTSERIAL$$", &cert.serial_decimal);
        let mut principal = cert.subject.clone();
        if let Some(p) = rdn_value("OID.2.5.4.65", &principal) {
            ret = ret.replace("$$PSEUDONYM$$", &p);
        }
        let ous = ous_of_principal(&principal);
        if let Some(first) = ous.first() {
            ret = ret.replace("$$OU$$", first);
            ret = ret.replace("$$OUS$$", &ous.join(", "));
        } else {
            ret = ret.replace("$$OU$$", "").replace("$$OUS$$", "");
        }
        let title = rdn_value("t", &principal).unwrap_or_default();
        ret = ret.replace("$$TITLE$$", &title);
        if let Some(m) = &d.mask {
            principal = obfuscate_ids(&principal, m);
        }
        ret = ret.replace("$$SUBJECTDN$$", &principal);
        ret = ret.replace(
            "$$GIVENNAME$$",
            &rdn_value("GIVENNAME", &principal).unwrap_or_default(),
        );
        ret = ret.replace(
            "$$SURNAME$$",
            &rdn_value("SURNAME", &principal).unwrap_or_default(),
        );
        ret = ret.replace(
            "$$ORGANIZATION$$",
            &rdn_value("o", &principal).unwrap_or_default(),
        );
    }
    ret = ret.replace("$$REASON$$", d.reason.unwrap_or(""));
    ret = ret.replace("$$LOCATION$$", d.location.unwrap_or(""));
    ret = ret.replace("$$CONTACT$$", d.contact.unwrap_or(""));

    const PREFIX: &str = "$$SIGNDATE";
    let mut guard = 0;
    while let Some(idx) = ret.find(PREFIX) {
        guard += 1;
        if guard > 1000 {
            break;
        }
        let end = ret[idx + PREFIX.len()..]
            .find("$$")
            .ok_or(UnclosedDateTag)?
            + idx
            + PREFIX.len()
            + 2;
        let tag = ret[idx..end].to_string();
        let t = d.sign_time.unwrap_or_else(crate::pdf::date::now);
        let date = if tag.contains('=') {
            let inner = tag.replace("$$", "");
            let fmt = inner.split('=').nth(1).unwrap_or("");
            java_format_or_default(&t, fmt)
        } else {
            java_format_or_default(&t, crate::pdf::date::DEFAULT_PATTERN)
        };
        ret = ret.replace(&tag, &date);
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x500_strings_match_java() {
        let pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/pades/x500_tricky.crt"
        ))
        .unwrap();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = afirma_core::base64_decode_lenient(&b64).unwrap();
        let c = CertText::from_der(&der).unwrap();
        // Valores obtenidos con Java 21 (X500Principal.toString/getName).
        assert_eq!(
            c.subject,
            "CN=\"GARCÍA LÓPEZ MARÍA - 12345678Z  \", SURNAME=\"GARCÍA  LÓPEZ\", GIVENNAME=MARÍA, SERIALNUMBER=IDCES-12345678Z, EMAILADDRESS=a@b.es, OID.2.5.4.65=SEUDONIMO 1, T=Director, OID.2.5.4.97=VATES-B12345678, OU=Unidad B, OU=Unidad A, O=\"Empresa, S.A.\", C=ES"
        );
        assert_eq!(
            c.issuer_rfc2253,
            "CN=GARCÍA LÓPEZ MARÍA - 12345678Z\\ \\ ,2.5.4.4=#0c0f47415243c38d4120204cc39350455a,2.5.4.42=#0c064d4152c38d41,2.5.4.5=#130f49444345532d31323334353637385a,1.2.840.113549.1.9.1=#16066140622e6573,2.5.4.65=#0c0b534555444f4e494d4f2031,2.5.4.12=#0c084469726563746f72,2.5.4.97=#0c0f56415445532d423132333435363738,OU=Unidad B,OU=Unidad A,O=Empresa\\, S.A.,C=ES"
        );
        assert_eq!(
            c.serial_decimal,
            "184161141018536017143214356788755272174554114566"
        );
        assert!(c.pseudonym_cert);
        assert_eq!(c.subject_cn(), "GARCÍA LÓPEZ MARÍA - 12345678Z  ");
        assert_eq!(
            rdn_value("OID.2.5.4.65", &c.subject).unwrap(),
            "SEUDONIMO 1"
        );
        assert_eq!(ous_of_principal(&c.subject), vec!["Unidad B", "Unidad A"]);
    }

    #[test]
    fn obfuscation_examples() {
        let m = TextMask::default();
        assert_eq!(
            obfuscate_ids("PEREZ GARCIA JUAN - 12345678Z", &m),
            "PEREZ GARCIA JUAN - ***4567**"
        );
        assert_eq!(
            obfuscate_ids("SERIALNUMBER=IDCES-12345678Z", &m),
            "SERIALNUMBER=IDCES-***4567**"
        );
        assert_eq!(
            obfuscate_ids("ESPAÑOL ESPAÑOL JUAN - 00000000T", &m),
            "ESPAÑOL ESPAÑOL JUAN - ***0000**"
        );
        assert_eq!(obfuscate_ids("SIN NUMEROS", &m), "SIN NUMEROS");
    }

    #[test]
    fn mask_parsing() {
        assert_eq!(
            TextMask::parse("*;3;false,false,false,true,true,true,true;true").unwrap(),
            TextMask::default()
        );
        let m = TextMask::parse("#;2;true,true,false;false").unwrap();
        assert_eq!(
            m,
            TextMask {
                ch: '#',
                min_length: 2,
                positions: vec![true, true],
                shift: false
            }
        );
        // La última posición visible es la 0: máscara por defecto.
        assert_eq!(
            TextMask::parse("#;2;true,false;false").unwrap(),
            TextMask::default()
        );
        assert!(TextMask::parse("#;2;true").is_err());
        assert!(TextMask::parse("##;2;true,true;false").is_err());
    }

    #[test]
    fn rdn_lookup() {
        let p = "CN=ESPAÑOL ESPAÑOL JUAN - 00000000T, SURNAME=ESPAÑOL ESPAÑOL, GIVENNAME=JUAN, SERIALNUMBER=IDCES-00000000T, C=ES";
        assert_eq!(
            rdn_value("cn", p).unwrap(),
            "ESPAÑOL ESPAÑOL JUAN - 00000000T"
        );
        assert_eq!(rdn_value("GIVENNAME", p).unwrap(), "JUAN");
        assert_eq!(rdn_value("surname", p).unwrap(), "ESPAÑOL ESPAÑOL");
        assert!(rdn_value("o", p).is_none());
        let q = "CN=X, OU=Unidad A, OU=Unidad B, O=\"Org, S.A.\", C=ES";
        assert_eq!(ous_of_principal(q), vec!["Unidad A", "Unidad B"]);
        assert_eq!(rdn_value("o", q).unwrap(), "Org, S.A.");
        assert_eq!(cn_of_principal("OU=Solo"), "Solo");
        assert_eq!(cn_of_principal("C=ES, O=Org"), "ES");
    }

    #[test]
    fn layer_text_tokens() {
        let cert = CertText {
            subject: "CN=PEREZ GARCIA JUAN - 12345678Z, SURNAME=PEREZ GARCIA, GIVENNAME=JUAN, SERIALNUMBER=IDCES-12345678Z, OU=Unidad A, OU=Unidad B, O=Org Prueba, C=ES".into(),
            issuer_rfc2253: "CN=AC PRUEBA,O=Prueba,C=ES".into(),
            serial_decimal: "123456789".into(),
            pseudonym_cert: false,
        };
        let d = LayerTextData {
            cert: Some(&cert),
            sign_time: Some(crate::pdf::date::fixed(2026, 10, 16, 13, 36, 29, 7200)),
            reason: Some("Prueba"),
            mask: Some(TextMask::default()),
            ..Default::default()
        };
        let t = layer_text("$$SUBJECTCN$$|$$ISSUERCN$$|$$CERTSERIAL$$|$$OU$$|$$OUS$$|$$GIVENNAME$$|$$SURNAME$$|$$ORGANIZATION$$|$$REASON$$|$$LOCATION$$|$$PSEUDONYM$$|$$SIGNDATE=dd/MM/yyyy$$", &d).unwrap();
        assert_eq!(
            t,
            "PEREZ GARCIA JUAN - ***4567**|AC PRUEBA|123456789|Unidad A|Unidad A, Unidad B|JUAN|PEREZ GARCIA|Org Prueba|Prueba||$$PSEUDONYM$$|16/10/2026"
        );
        assert!(layer_text("$$SIGNDATE=dd", &d).is_err());
    }
}
