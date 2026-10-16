//! Representación de nombres X.500 como cadenas, exactamente como Java
//! (apéndice A de la especificación):
//!
//! - `X500Principal.toString()` (y `getSubjectDN().toString()`), en
//!   [`DistinguishedName::java_string`], que usan `AOUtil.getCN`, los filtros
//!   `subject.contains`/`issuer.contains`, los filtros RFC 2254 y los iconos.
//! - `X500Principal.getName()` (RFC 2253), en
//!   [`DistinguishedName::rfc2253_string`], que usan el filtro de seudónimo,
//!   la comparación del `serialNumber` del titular y las vistas del diálogo.
//! - `AOUtil.getCN(String)` y `AOUtil.getRDNvalueFromLdapName`, en
//!   [`get_cn`] y [`get_rdn_value`], con sus particularidades (sin
//!   desescapado, valores hasta la siguiente coma...).
//!
//! El comportamiento reproducido es el de Java 17/21 (comprobado con
//! `tools/oracle/FiltersDnOracle.java`; ficheros de referencia en
//! `testdata/keystores/filters/dn-java.txt`). Java 8 usaba mayúsculas en la
//! forma hexadecimal `#...` de `toString()`; Java 17+ usa minúsculas.

use x509_parser::prelude::*;

/// Atributo (tipo y valor) de un RDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ava {
    /// OID del tipo en notación decimal con puntos.
    pub oid: String,
    /// Etiqueta ASN.1 del valor (`0x0c` UTF8String, `0x13` PrintableString...).
    pub tag: u8,
    /// Codificación DER completa del valor (etiqueta, longitud y contenido).
    pub value_der: Vec<u8>,
    /// Contenido del valor (sin etiqueta ni longitud).
    pub content: Vec<u8>,
}

impl Ava {
    /// Valor como texto si es de un tipo de cadena reconocido por
    /// `DerValue.getAsString()` de Java (UTF8String, PrintableString,
    /// T61String, IA5String, BMPString, GeneralString y UniversalString).
    pub fn java_string_value(&self) -> Option<String> {
        decode_java_string(self.tag, &self.content, true)
    }

    /// Palabra clave de Java para `toString()` (`CN`, `SERIALNUMBER`...) o
    /// `OID.<oid>`.
    pub fn java_keyword(&self) -> String {
        match keyword_default(&self.oid) {
            Some(k) => k.to_string(),
            None => format!("OID.{}", self.oid),
        }
    }

    /// Palabra clave RFC 2253 (`CN`, `C`, `L`, `ST`, `O`, `OU`, `STREET`,
    /// `DC`, `UID`) o el OID en decimal.
    pub fn rfc2253_keyword(&self) -> String {
        match keyword_rfc2253(&self.oid) {
            Some(k) => k.to_string(),
            None => self.oid.clone(),
        }
    }

    /// `AVA.toString()` de Java.
    pub fn java_string(&self) -> String {
        let mut out = self.java_keyword();
        out.push('=');
        match self.java_string_value() {
            None => {
                out.push('#');
                out.push_str(&hex::encode(&self.value_der));
            }
            Some(v) => out.push_str(&java_quote_value(&v)),
        }
        out
    }

    /// `AVA.toRFC2253String()` de Java.
    pub fn rfc2253_string(&self) -> String {
        let kw = self.rfc2253_keyword();
        let mut out = kw.clone();
        out.push('=');
        let string_value = if kw.starts_with(|c: char| c.is_ascii_digit()) {
            None
        } else {
            decode_java_string(self.tag, &self.content, false)
        };
        match string_value {
            None => {
                out.push('#');
                out.push_str(&hex::encode(&self.value_der));
            }
            Some(v) => out.push_str(&rfc2253_escape_value(&v)),
        }
        out
    }
}

/// Nombre X.500 (secuencia de RDN en el orden de la codificación DER).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DistinguishedName {
    /// RDN en orden DER (el primero suele ser `C`). Cada RDN tiene uno o más
    /// atributos, en el orden de la codificación.
    pub rdns: Vec<Vec<Ava>>,
}

impl DistinguishedName {
    /// Interpreta un `Name` codificado en DER.
    pub fn from_der(der: &[u8]) -> Option<DistinguishedName> {
        let (tag, content, _, _) = read_tlv(der)?;
        if tag != 0x30 {
            return None;
        }
        let mut rdns = Vec::new();
        let mut rest = content;
        while !rest.is_empty() {
            let (tag, set, _, r) = read_tlv(rest)?;
            rest = r;
            if tag != 0x31 {
                return None;
            }
            let mut avas = Vec::new();
            let mut srest = set;
            while !srest.is_empty() {
                let (tag, seq, _, r) = read_tlv(srest)?;
                srest = r;
                if tag != 0x30 {
                    return None;
                }
                let (otag, oid, _, vrest) = read_tlv(seq)?;
                if otag != 0x06 {
                    return None;
                }
                let (vtag, vcontent, vfull, _) = read_tlv(vrest)?;
                avas.push(Ava { oid: oid_to_string(oid)?, tag: vtag, value_der: vfull.to_vec(), content: vcontent.to_vec() });
            }
            rdns.push(avas);
        }
        Some(DistinguishedName { rdns })
    }

    /// `X500Principal.toString()`: RDN en orden inverso separados por `", "`,
    /// atributos de un RDN multivaluado unidos con `" + "`.
    pub fn java_string(&self) -> String {
        self.rdns
            .iter()
            .rev()
            .map(|rdn| rdn.iter().map(Ava::java_string).collect::<Vec<_>>().join(" + "))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `X500Principal.getName()` (RFC 2253): orden inverso, separador `","`,
    /// atributos multivaluados unidos con `"+"`.
    pub fn rfc2253_string(&self) -> String {
        self.rdns
            .iter()
            .rev()
            .map(|rdn| rdn.iter().map(Ava::rfc2253_string).collect::<Vec<_>>().join("+"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Atributos tal y como los ve el filtro RFC 2254 de Java (que analiza
    /// `toString()` con `javax.naming.ldap.LdapName` y guarda un valor por
    /// tipo): tipos con la palabra clave de Java, sin distinguir mayúsculas;
    /// si un tipo se repite, gana el situado más a la izquierda en la cadena
    /// (el último en DER); en un RDN multivaluado solo cuenta el atributo cuyo
    /// tipo es menor alfabéticamente (`Rdn.getType()`). Los valores que no son
    /// cadenas se devuelven como [`LdapValue::Binary`].
    pub fn ldap_attributes(&self) -> Vec<(String, LdapValue)> {
        let mut out: Vec<(String, LdapValue)> = Vec::new();
        for rdn in &self.rdns {
            let mut entries: Vec<(String, LdapValue)> = rdn.iter().map(|a| (a.java_keyword(), ldap_value(a))).collect();
            entries.sort_by(|(t1, v1), (t2, v2)| {
                java_compare_ignore_case(t1, t2).then_with(|| v1.sort_key().cmp(&v2.sort_key()))
            });
            let Some((ty, val)) = entries.into_iter().next() else { continue };
            if let Some(pos) = out.iter().position(|(t, _)| t.eq_ignore_ascii_case(&ty)) {
                out[pos].1 = val;
            } else {
                out.push((ty, val));
            }
        }
        out
    }

    /// Indica si el nombre no tiene ningún RDN.
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// Primer valor (en orden DER) de un atributo dado por OID.
    pub fn first_value(&self, oid: &str) -> Option<String> {
        self.rdns.iter().flatten().find(|a| a.oid == oid).and_then(Ava::java_string_value)
    }
}

/// Valor de un atributo visto por el filtro RFC 2254.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapValue {
    Text(String),
    /// Valor no textual (`#hex` en `toString()`): en Java es un `byte[]`.
    Binary(Vec<u8>),
}

impl LdapValue {
    fn sort_key(&self) -> String {
        match self {
            LdapValue::Text(s) => s.to_uppercase(),
            LdapValue::Binary(b) => format!("#{}", hex::encode(b)),
        }
    }
}

fn ldap_value(a: &Ava) -> LdapValue {
    match a.java_string_value() {
        None => LdapValue::Binary(a.value_der.clone()),
        Some(v) => {
            let chars: Vec<char> = v.chars().collect();
            let already_quoted = chars.len() > 1 && chars[0] == '"' && chars[chars.len() - 1] == '"';
            // `LdapName` sobre la cadena de `toString()` recupera el valor
            // original salvo en tres casos (comprobados con Java):
            // - si ya venía entre comillas, Java no lo vuelve a entrecomillar y
            //   `LdapName` las quita;
            // - los valores sin comillas pierden los `\r` de los extremos;
            // - los valores entre comillas que acaban en espacio o `\r`
            //   pierden el último (`Rdn.unescapeValue`).
            let is_ws = |c: char| c == ' ' || c == '\r';
            let quoted = already_quoted || java_quote_value(&v).starts_with('"');
            let mut inner: Vec<char> = if already_quoted { chars[1..chars.len() - 1].to_vec() } else { chars };
            if quoted {
                if inner.last().is_some_and(|&c| is_ws(c)) {
                    inner.pop();
                }
            } else {
                while inner.last().is_some_and(|&c| is_ws(c)) {
                    inner.pop();
                }
                let lead = inner.iter().take_while(|&&c| is_ws(c)).count();
                inner.drain(..lead);
            }
            LdapValue::Text(inner.into_iter().collect())
        }
    }
}

/// TLV DER leído: (etiqueta, contenido, TLV completo, resto).
pub(crate) type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// Lee un TLV DER.
pub(crate) fn read_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let tag = *input.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *input.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*input.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    if input.len() < end {
        return None;
    }
    Some((tag, &input[hdr..end], &input[..end], &input[end..]))
}

fn oid_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut cur: u128 = 0;
    for (i, b) in bytes.iter().enumerate() {
        cur = cur.checked_mul(128)? | u128::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (a, b2) = if cur < 40 {
                    (0, cur)
                } else if cur < 80 {
                    (1, cur - 40)
                } else {
                    (2, cur - 80)
                };
                arcs.push(a);
                arcs.push(b2);
            } else {
                arcs.push(cur);
            }
            cur = 0;
        } else if i == bytes.len() - 1 {
            return None;
        }
    }
    Some(arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("."))
}

/// Palabras clave de `toString()` (`AVAKeyword`, norma `DEFAULT`).
fn keyword_default(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "1.3.6.1.4.1.42.2.11.2.1" => "IP",
        "2.5.4.9" => "STREET",
        "0.9.2342.19200300.100.1.25" => "DC",
        "2.5.4.46" => "DNQ",
        "2.5.4.4" => "SURNAME",
        "2.5.4.42" => "GIVENNAME",
        "2.5.4.43" => "INITIALS",
        "2.5.4.44" => "GENERATION",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        "0.9.2342.19200300.100.1.1" => "UID",
        "2.5.4.5" => "SERIALNUMBER",
        _ => return None,
    })
}

/// Palabras clave de RFC 2253.
fn keyword_rfc2253(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.9" => "STREET",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

/// Decodifica un valor de cadena como `DerValue.getAsString()` (si
/// `universal` es `true`) o como `toRFC2253String` (que no trata
/// UniversalString como cadena).
fn decode_java_string(tag: u8, data: &[u8], universal: bool) -> Option<String> {
    let ascii = |d: &[u8]| d.iter().map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' }).collect::<String>();
    match tag {
        0x0c => Some(String::from_utf8_lossy(data).into_owned()),
        0x13 | 0x16 | 0x1b => Some(ascii(data)),
        0x14 => Some(data.iter().map(|&b| b as char).collect()),
        0x1e => {
            let units: Vec<u16> = data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
            Some(String::from_utf16_lossy(&units))
        }
        0x1c if universal => Some(
            data.chunks(4)
                .map(|c| {
                    if c.len() == 4 {
                        char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).unwrap_or('\u{FFFD}')
                    } else {
                        '\u{FFFD}'
                    }
                })
                .collect(),
        ),
        _ => None,
    }
}

/// `DerValue.isPrintableStringChar`.
fn is_printable_string_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?')
}

/// Entrecomillado y escapado de `AVA.toKeywordValueString`.
fn java_quote_value(val: &str) -> String {
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
    if let Some(last) = sb.chars().last()
        && (last == ' ' || last == '\n') {
            quote_needed = true;
        }
    if !already_quoted && quote_needed { format!("\"{sb}\"") } else { sb }
}

/// Escapado de `AVA.toRFC2253String`.
fn rfc2253_escape_value(val: &str) -> String {
    const ESCAPEES: &str = ",=+<>#;\"\\";
    let mut chars: Vec<char> = Vec::new();
    for c in val.chars() {
        if is_printable_string_char(c) || ESCAPEES.contains(c) {
            if ESCAPEES.contains(c) {
                chars.push('\\');
            }
            chars.push(c);
        } else if c == '\0' {
            chars.extend(['\\', '0', '0']);
        } else {
            chars.push(c);
        }
    }
    let is_ws = |c: char| c == ' ' || c == '\r';
    let lead = chars.iter().position(|&c| !is_ws(c)).unwrap_or(chars.len());
    let trail = chars.iter().rposition(|&c| !is_ws(c)).map(|p| p as isize).unwrap_or(-1);
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if i < lead || (i as isize) > trail {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Comparación `String.compareToIgnoreCase` de Java (por caracteres,
/// mayúsculas y después minúsculas).
pub fn java_compare_ignore_case(a: &str, b: &str) -> std::cmp::Ordering {
    let fold = |c: char| -> char {
        let u = single_upper(c);
        single_lower(u)
    };
    let mut ia = a.chars();
    let mut ib = b.chars();
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                if x != y {
                    let (fx, fy) = (fold(x), fold(y));
                    if fx != fy {
                        return fx.cmp(&fy);
                    }
                }
            }
        }
    }
}

/// `Character.toUpperCase(char)`: solo correspondencias de un carácter.
fn single_upper(c: char) -> char {
    let mut it = c.to_uppercase();
    match (it.next(), it.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

/// `Character.toLowerCase(char)`.
fn single_lower(c: char) -> char {
    let mut it = c.to_lowercase();
    match (it.next(), it.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

/// Minúsculas de Java (`String.toLowerCase`), carácter a carácter.
pub(crate) fn java_lower(s: &str) -> String {
    s.to_lowercase()
}

/// `AOUtil.getRDNvalueFromLdapName(rdn, principal)`: busca `rdn` (sin
/// distinguir mayúsculas) al inicio de la cadena o tras `,` o espacio,
/// seguido de espacios opcionales y `=`; el valor es el contenido entre
/// comillas hasta la siguiente comilla o, si no va entre comillas, hasta la
/// siguiente coma (recortado). No desescapa nada.
pub fn get_rdn_value(rdn: &str, principal: &str) -> Option<String> {
    let p: Vec<char> = principal.chars().collect();
    let lower: Vec<char> = p.iter().map(|&c| single_lower(c)).collect();
    let r: Vec<char> = rdn.chars().map(single_lower).collect();
    let find = |from: usize| -> Option<usize> {
        if r.is_empty() {
            return (from <= lower.len()).then_some(from);
        }
        (from..lower.len()).find(|&i| lower[i..].starts_with(&r))
    };
    let mut offset = 0usize;
    while let Some(found) = find(offset) {
        offset = found;
        if offset > 0 && p[offset - 1] != ',' && p[offset - 1] != ' ' {
            offset += 1;
            continue;
        }
        offset += r.len();
        while offset < p.len() && p[offset] == ' ' {
            offset += 1;
        }
        if offset >= p.len() {
            return None;
        }
        if p[offset] != '=' {
            continue;
        }
        offset += 1;
        while offset < p.len() && p[offset] == ' ' {
            offset += 1;
        }
        if offset >= p.len() {
            return Some(String::new());
        }
        if p[offset] == ',' {
            return Some(String::new());
        } else if p[offset] == '"' {
            offset += 1;
            if offset >= p.len() {
                return Some(String::new());
            }
            return match p[offset..].iter().position(|&c| c == '"') {
                Some(0) => Some(String::new()),
                Some(n) => Some(p[offset..offset + n].iter().collect()),
                None => Some(p[offset..].iter().collect()),
            };
        } else {
            let s: String = match p[offset..].iter().position(|&c| c == ',') {
                Some(n) => p[offset..offset + n].iter().collect(),
                None => p[offset..].iter().collect(),
            };
            return Some(java_trim(&s));
        }
    }
    None
}

/// `String.trim()` de Java (quita caracteres `<= ' '`).
pub(crate) fn java_trim(s: &str) -> String {
    s.trim_matches(|c: char| c <= ' ').to_string()
}

/// `AOUtil.getCN(String principal)`: valor de `CN`; si no hay, de `OU`; si
/// no, el del primer atributo de la cadena; si la cadena no tiene `=`, la
/// propia cadena.
pub fn get_cn(principal: &str) -> String {
    if let Some(v) = get_rdn_value("cn", principal) {
        return v;
    }
    if let Some(v) = get_rdn_value("ou", principal) {
        return v;
    }
    if let Some(i) = principal.find('=') {
        return get_rdn_value(&principal[..i], principal).unwrap_or_default();
    }
    principal.to_string()
}

/// Nombre del titular de un certificado.
pub fn subject_of(cert_der: &[u8]) -> Option<DistinguishedName> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    DistinguishedName::from_der(cert.subject().as_raw())
}

/// Nombre del emisor de un certificado.
pub fn issuer_of(cert_der: &[u8]) -> Option<DistinguishedName> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    DistinguishedName::from_der(cert.issuer().as_raw())
}

/// `getSubjectX500Principal().toString()`.
pub fn java_subject_string(cert_der: &[u8]) -> Option<String> {
    subject_of(cert_der).map(|n| n.java_string())
}

/// `getIssuerX500Principal().toString()`.
pub fn java_issuer_string(cert_der: &[u8]) -> Option<String> {
    issuer_of(cert_der).map(|n| n.java_string())
}

/// `getSubjectX500Principal().getName()` (RFC 2253).
pub fn rfc2253_subject_string(cert_der: &[u8]) -> Option<String> {
    subject_of(cert_der).map(|n| n.rfc2253_string())
}

/// `getIssuerX500Principal().getName()` (RFC 2253).
pub fn rfc2253_issuer_string(cert_der: &[u8]) -> Option<String> {
    issuer_of(cert_der).map(|n| n.rfc2253_string())
}

/// `AOUtil.getCN(X509Certificate)`: CN del titular según [`get_cn`] sobre
/// `toString()`.
pub fn certificate_cn(cert_der: &[u8]) -> Option<String> {
    java_subject_string(cert_der).map(|s| get_cn(&s))
}

/// Atributo `serialNumber` del titular tal y como lo obtiene
/// `FilterUtils.getSubjectSN` (forma `#hex` de RFC 2253 sin la almohadilla,
/// p. ej. `130931323334353637385a`), o `None` si no tiene.
pub fn subject_serial_number_hex(cert_der: &[u8]) -> Option<String> {
    let principal = rfc2253_subject_string(cert_der)?;
    get_rdn_value("serialnumber", &principal)
        .or_else(|| get_rdn_value("2.5.4.5", &principal))
        .map(|v| v.replace('#', ""))
}

/// Indica si es un certificado de seudónimo (`AOUtil.isPseudonymCert`: el
/// titular RFC 2253 contiene el atributo `2.5.4.65`).
pub fn is_pseudonym_certificate(cert_der: &[u8]) -> bool {
    rfc2253_subject_string(cert_der).is_some_and(|p| get_rdn_value("2.5.4.65", &p).is_some())
}

/// Nombre a mostrar de un certificado (§4.1 paso 5): `AOUtil.getCN` del
/// titular; si el certificado no se puede analizar o el resultado es vacío
/// (titular vacío), el alias recortado (los alias de CERES acaban en `\r`).
pub fn friendly_name(cert_der: &[u8], alias: &str) -> String {
    match certificate_cn(cert_der) {
        Some(cn) if !cn.is_empty() => cn,
        _ => java_trim(alias),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn testdata() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
    }

    /// Lee un certificado DER o PEM.
    pub(crate) fn load_cert(path: &Path) -> Vec<u8> {
        let data = std::fs::read(path).unwrap();
        afirma_core::cert::decode_certificate(&data).unwrap()
    }

    fn unesc(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('\\') => out.push('\\'),
                    Some(o) => {
                        out.push('\\');
                        out.push(o);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn golden() -> Vec<(String, String, String)> {
        let text = std::fs::read_to_string(testdata().join("keystores/filters/dn-java.txt")).unwrap();
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let mut p = l.splitn(3, '\t');
                (p.next().unwrap().to_string(), p.next().unwrap().to_string(), unesc(p.next().unwrap_or("")))
            })
            .collect()
    }

    fn cert_files() -> HashMap<String, Vec<u8>> {
        let mut m = HashMap::new();
        for dir in ["pki", "keystores/filters"] {
            for e in std::fs::read_dir(testdata().join(dir)).unwrap() {
                let p = e.unwrap().path();
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "crt" || ext == "der" {
                    m.insert(p.file_name().unwrap().to_str().unwrap().to_string(), load_cert(&p));
                }
            }
        }
        m
    }

    /// Escapado de `FiltersDnOracle.esc` (los valores LDAP del oráculo van
    /// escapados dos veces).
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t")
    }

    fn ldap_line(attrs: &[(String, LdapValue)]) -> String {
        attrs
            .iter()
            .map(|(t, v)| match v {
                LdapValue::Text(s) => format!("{t}=str:{}", esc(s)),
                LdapValue::Binary(b) => format!("{t}=bin:{}", hex::encode(b)),
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Compara con las salidas de Java (`tools/oracle/FiltersDnOracle.java`).
    #[test]
    fn matches_java_golden() {
        let certs = cert_files();
        let mut checked = 0;
        for (file, key, expected) in golden() {
            let der = certs.get(&file).unwrap_or_else(|| panic!("falta {file}"));
            let got: Option<String> = match key.as_str() {
                "subject.toString" | "subjectDN" => java_subject_string(der),
                "subject.rfc2253" => rfc2253_subject_string(der),
                "issuer.toString" => java_issuer_string(der),
                "issuer.rfc2253" => rfc2253_issuer_string(der),
                "getCN" => certificate_cn(der),
                "getCN.issuer.rfc2253" => rfc2253_issuer_string(der).map(|s| get_cn(&s)),
                "getCN.issuer.toString" => java_issuer_string(der).map(|s| get_cn(&s)),
                "subjectSN" => Some(rfc2253_subject_string(der).and_then(|p| get_rdn_value("2.5.4.5", &p)).unwrap_or("<null>".into())),
                "pseudonym" => Some(is_pseudonym_certificate(der).to_string()),
                "ldap.subject" => {
                    // En Java los RDN salen de derecha a izquierda (orden DER) y
                    // el filtro se queda con el último valor de cada tipo; aquí
                    // se compara el resultado final por tipo.
                    let mine = subject_of(der).unwrap().ldap_attributes();
                    let mut java_map: Vec<(String, String)> = Vec::new();
                    for part in expected.split(" | ").filter(|p| !p.is_empty()) {
                        let (t, v) = part.split_once('=').unwrap();
                        if let Some(pos) = java_map.iter().position(|(x, _)| x.eq_ignore_ascii_case(t)) {
                            java_map[pos].1 = v.to_string();
                        } else {
                            java_map.push((t.to_string(), v.to_string()));
                        }
                    }
                    let expected_line =
                        java_map.iter().map(|(t, v)| format!("{t}={v}")).collect::<Vec<_>>().join(" | ");
                    assert_eq!(ldap_line(&mine), expected_line, "{file} {key}");
                    checked += 1;
                    continue;
                }
                "keyusage.text" => Some(crate::display::key_usage_text(der).to_string()),
                _ => continue,
            };
            assert_eq!(got.as_deref(), Some(expected.as_str()), "{file} {key}");
            checked += 1;
        }
        assert!(checked > 300, "solo {checked} comprobaciones");
    }

    #[test]
    fn get_cn_quirks() {
        assert_eq!(get_cn("CN=Juan, O=X"), "Juan");
        assert_eq!(get_cn("OU=Unidad, O=X"), "Unidad");
        assert_eq!(get_cn("O=Org, C=ES"), "Org");
        assert_eq!(get_cn("sin igual"), "sin igual");
        assert_eq!(get_cn(""), "");
        assert_eq!(get_cn("CN=\"a, b\", O=X"), "a, b");
        assert_eq!(get_cn("CN=a + OU=b, C=ES"), "a + OU=b");
        // "cn" dentro de otra palabra no cuenta.
        assert_eq!(get_cn("XCN=no, CN=si"), "si");
        assert_eq!(get_rdn_value("cn", "CN="), Some(String::new()));
        assert_eq!(get_rdn_value("cn", "CN=,O=x"), Some(String::new()));
        assert_eq!(get_rdn_value("cn", "CN"), None);
        assert_eq!(get_rdn_value("cn", "CN=\"\""), Some(String::new()));
        assert_eq!(get_rdn_value("cn", "CN=\"abc"), Some("abc".into()));
        assert_eq!(friendly_name(b"no es un certificado", "  alias\r"), "alias");
    }

    #[test]
    fn compare_ignore_case() {
        use std::cmp::Ordering::*;
        assert_eq!(java_compare_ignore_case("abc", "ABC"), Equal);
        assert_eq!(java_compare_ignore_case("abc", "abd"), Less);
        assert_eq!(java_compare_ignore_case("ab", "abc"), Less);
        assert_eq!(java_compare_ignore_case("Ñ", "ñ"), Equal);
        assert_eq!(java_compare_ignore_case("Z", "a"), Greater);
    }
}
