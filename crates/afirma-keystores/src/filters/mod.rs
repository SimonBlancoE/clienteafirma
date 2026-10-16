//! Filtros de certificados (`CertFilterManager` y los filtros de
//! `afirma-keystores-filters`), sección 7 de la especificación.
//!
//! # Configuración
//!
//! Los filtros llegan en los `extraParams` de la operación (o del valor de
//! `-filter` en la línea de comandos):
//!
//! - Se usa exactamente una de las claves, por este orden de precedencia:
//!   `filter`; si no, `filters`; si no, `filters.1`, `filters.2`... (hasta el
//!   primer hueco).
//! - Cada valor es una **expresión**: elementos separados por `;` que se
//!   combinan con **Y** (se ordenan alfabéticamente y se aplican en
//!   secuencia). Las expresiones de `filters.N` se combinan con **O**: cada
//!   una se aplica sobre los certificados que aún no ha aceptado una
//!   anterior.
//! - Si no hay ninguna clave, se aplica el filtro por defecto que oculta los
//!   certificados caducados. Si hay alguna, no.
//! - Los elementos desconocidos se ignoran (una expresión vacía acepta todo).
//! - `disableopeningexternalstores` no filtra: impide cambiar de almacén.
//! - `headless=true` o `mandatoryCertSelection=false` seleccionan
//!   automáticamente el certificado si solo hay uno.
//!
//! # Uso
//!
//! ```no_run
//! # use afirma_keystores::filters::CertFilterManager;
//! # fn f(params: &afirma_core::ExtraParams, entries: &[afirma_keystores::CertEntry]) -> Result<(), Box<dyn std::error::Error>> {
//! let manager = CertFilterManager::from_extra_params(params)?;
//! let visibles = manager.apply(entries, chrono::Utc::now());
//! # Ok(()) }
//! ```

pub mod rfc2254;

use afirma_core::ExtraParams;
use chrono::{DateTime, Utc};

use crate::dn::{self, DistinguishedName, java_lower};
use crate::store::CertEntry;
use rfc2254::SearchFilter;

/// Filtro RFC 2254 del emisor de los certificados del DNIe.
pub const DNIE_ISSUER_FILTER: &str = "(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))";

/// Emisor de la Generalitat Valenciana cuyos certificados de firma solo
/// tienen `digitalSignature` (`KeyUsagesPattern`).
pub const ACCV_SIGN_ISSUER: &str = "C=ES, O=Generalitat Valenciana, OU=PKIGVA, CN=ACCV-CA2";

/// Error al construir los filtros (en Java, excepción en el constructor de
/// `CertFilterManager`, que hace fallar la operación).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    /// `subject.rfc2254:` o `issuer.rfc2254[.recurse]:` sin valor.
    #[error("Al menos uno de los criterios de filtrado debe no ser nulo")]
    EmptyCriteria,
    /// `policyid:` con una lista vacía (p. ej. `policyid:,`).
    #[error("La lista de OID permitidos no puede ser nula ni vacia")]
    EmptyPolicyList,
}

/// Patrón de 9 posiciones de uso de clave (`digitalSignature`,
/// `nonRepudiation`, `keyEncipherment`, `dataEncipherment`, `keyAgreement`,
/// `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`); `None` = sin
/// importancia.
pub type KeyUsagePattern = [Option<bool>; 9];

/// Patrón de certificado de firma (`KeyUsageFilter.SIGN_CERT_USAGE`).
pub const SIGN_CERT_USAGE: KeyUsagePattern = [None, Some(true), None, None, None, None, None, None, None];
/// Patrón de certificado de autenticación.
pub const AUTH_CERT_USAGE: KeyUsagePattern = [Some(true), None, None, None, None, None, None, None, None];

/// Nombres de los elementos `keyusage.*`, en el orden del patrón.
pub const KEYUSAGE_NAMES: [&str; 9] = [
    "digitalsignature",
    "nonrepudiation",
    "keyencipherment",
    "dataencipherment",
    "keyagreement",
    "keycertsign",
    "crlsign",
    "encipheronly",
    "decipheronly",
];

/// Filtro de certificados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertFilter {
    /// `dnie:` (`SignatureDNIeFilter`): certificados de firma del DNIe.
    SignatureDnie,
    /// `signingcert:` (`SigningCertificateFilter`) y preferencia
    /// `skipAuthCertDnie` (`SkipAuthDNIeFilter`): todo salvo el certificado
    /// de autenticación del DNIe.
    SkipAuthDnie,
    /// `authcert:` (`AuthCertificateFilter`): todo salvo el certificado de
    /// firma del DNIe.
    SkipSignatureDnie,
    /// `nonexpired:` (`ExpiredCertificateFilter`). Con `show_expired` acepta
    /// todo.
    Expired { show_expired: bool },
    /// `sscd:` (`SscdFilter`): extensión QCStatements con QcSSCD.
    Sscd,
    /// `keyusage.*` (`KeyUsageFilter`). Los certificados sin la extensión no
    /// cumplen nunca.
    KeyUsage(KeyUsagePattern),
    /// `subject.rfc2254:`, `issuer.rfc2254:`, `issuer.rfc2254.recurse:`.
    Rfc2254 {
        subject: Option<String>,
        issuer: Option<String>,
        recurse: bool,
    },
    /// `subject.contains:`, `issuer.contains:` (`TextContainedCertificateFilter`).
    TextContained {
        subject: Option<String>,
        issuer: Option<String>,
    },
    /// `thumbprint:<alg>:<hex>`.
    Thumbprint { algorithm: String, thumbprint: String },
    /// `policyid:<oid>[,<oid>...]`: todas las políticas del certificado deben
    /// estar en la lista.
    PolicyId(Vec<String>),
    /// `encodedcert:<base64>`.
    EncodedCert(String),
    /// `ssl:<serie>` (`SSLFilter`).
    Ssl(String),
    /// `qualified:<serie>` (`QualifiedCertificatesFilter`).
    Qualified(String),
    /// `pseudonym:[only|andothers]` (`PseudonymFilter`).
    Pseudonym { only: bool },
    /// Conjunción (`MultipleCertificateFilter`): se aplican en secuencia.
    Multiple(Vec<CertFilter>),
}

/// Datos de un certificado preparados para filtrar.
struct Prepared<'a> {
    entry: &'a CertEntry,
    subject: Option<DistinguishedName>,
    issuer: Option<DistinguishedName>,
    subject_java: String,
    issuer_java: String,
    /// `hexify(serial.toByteArray())` en mayúsculas.
    serial_hex: String,
    /// Serie en complemento a dos (para comparar `BigInteger.equals`).
    serial_raw: Vec<u8>,
    ku: Option<[bool; 9]>,
    policies: Option<Vec<String>>,
    sscd: bool,
    subject_sn: Option<String>,
    pseudonym: bool,
    issuer_canonical: Option<String>,
}

impl<'a> Prepared<'a> {
    fn new(entry: &'a CertEntry) -> Prepared<'a> {
        use x509_parser::prelude::*;
        let der = &entry.certificate;
        let parsed = X509Certificate::from_der(der).ok().map(|(_, c)| c);
        let subject = parsed
            .as_ref()
            .and_then(|c| DistinguishedName::from_der(c.subject().as_raw()));
        let issuer = parsed
            .as_ref()
            .and_then(|c| DistinguishedName::from_der(c.issuer().as_raw()));
        let serial_raw = parsed.as_ref().map(|c| c.raw_serial().to_vec()).unwrap_or_default();
        let ku = entry.info.as_ref().and_then(|i| i.key_usage).map(|k| {
            [
                k.digital_signature,
                k.non_repudiation,
                k.key_encipherment,
                k.data_encipherment,
                k.key_agreement,
                k.key_cert_sign,
                k.crl_sign,
                k.encipher_only,
                k.decipher_only,
            ]
        });
        let mut has_policies_ext = false;
        let mut sscd = false;
        if let Some(c) = &parsed {
            for ext in c.extensions() {
                match ext.oid.to_id_string().as_str() {
                    "2.5.29.32" => has_policies_ext = true,
                    "1.3.6.1.5.5.7.1.3" => sscd = sscd || qc_has_sscd(ext.value),
                    _ => {}
                }
            }
        }
        let policies = entry
            .info
            .as_ref()
            .filter(|_| has_policies_ext)
            .map(|i| i.policies.clone());
        let subject_rfc = subject.as_ref().map(|s| s.rfc2253_string()).unwrap_or_default();
        let subject_sn = dn::get_rdn_value("serialnumber", &subject_rfc)
            .or_else(|| dn::get_rdn_value("2.5.4.5", &subject_rfc))
            .map(|v| v.replace('#', ""));
        let pseudonym = dn::get_rdn_value("2.5.4.65", &subject_rfc).is_some();
        Prepared {
            entry,
            subject_java: subject.as_ref().map(|s| s.java_string()).unwrap_or_default(),
            issuer_java: issuer.as_ref().map(|s| s.java_string()).unwrap_or_default(),
            issuer_canonical: issuer.as_ref().map(canonical_name),
            subject,
            issuer,
            serial_hex: hex::encode_upper(&serial_raw),
            serial_raw,
            ku,
            policies,
            sscd,
            subject_sn,
            pseudonym,
        }
    }

    fn valid(&self) -> bool {
        self.entry.info.is_some()
    }

    /// `yyyy-MM-dd` de `notAfter` en la zona horaria local.
    fn expiry_date(&self) -> Option<String> {
        self.entry
            .info
            .as_ref()
            .map(|i| i.not_after.with_timezone(&chrono::Local).format("%Y-%m-%d").to_string())
    }
}

/// Forma canónica de un nombre para comparar emisores como
/// `X500Principal.equals` (RFC 2253 canónica: tipos en mayúsculas, valores
/// de cadena en minúsculas con espacios normalizados, el resto en
/// hexadecimal, atributos de cada RDN ordenados).
fn canonical_name(name: &DistinguishedName) -> String {
    name.rdns
        .iter()
        .rev()
        .map(|rdn| {
            let mut avas: Vec<String> = rdn
                .iter()
                .map(|a| {
                    let kw = a.rfc2253_keyword().to_uppercase();
                    let string_type = matches!(a.tag, 0x13 | 0x0c) && !kw.starts_with(|c: char| c.is_ascii_digit());
                    let value = match a.java_string_value() {
                        Some(v) if string_type => v
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_uppercase()
                            .to_lowercase(),
                        _ => format!("#{}", hex::encode(&a.value_der)),
                    };
                    format!("{kw}={value}")
                })
                .collect();
            avas.sort();
            avas.join("+")
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Comprueba si una extensión QCStatements contiene QcSSCD (0.4.0.1862.1.4).
fn qc_has_sscd(value: &[u8]) -> bool {
    let Some((0x30, content, _, _)) = dn::read_tlv(value) else {
        return false;
    };
    let mut rest = content;
    while !rest.is_empty() {
        let Some((tag, stmt, _, r)) = dn::read_tlv(rest) else {
            return false;
        };
        rest = r;
        if tag != 0x30 {
            return false;
        }
        let Some((0x06, oid, _, _)) = dn::read_tlv(stmt) else {
            return false;
        };
        // 0.4.0.1862.1.4 = 04 00 8E 46 01 04
        if oid == [0x04, 0x00, 0x8e, 0x46, 0x01, 0x04] {
            return true;
        }
    }
    false
}

/// `prepareSerialNumber` de `SSLFilter`/`QualifiedCertificatesFilter`:
/// recorta, quita espacios y `#` y los ceros a la izquierda.
fn prepare_serial(sn: &str) -> String {
    let s = dn::java_trim(sn).replace([' ', '#'], "");
    s.trim_start_matches('0').to_string()
}

fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars().count() == b.chars().count() && dn::java_compare_ignore_case(a, b) == std::cmp::Ordering::Equal
}

fn key_usage_matches(pattern: &KeyUsagePattern, ku: Option<&[bool; 9]>) -> bool {
    let Some(ku) = ku else { return false };
    pattern.iter().zip(ku.iter()).all(|(p, b)| p.is_none_or(|p| p == *b))
}

fn rfc2254_name(filter: &str, name: Option<&DistinguishedName>) -> bool {
    let Some(name) = name else { return true };
    rfc2254::filter_name(&SearchFilter::parse(filter), name)
}

/// Emisor del DNIe según el filtro RFC 2254 de Java (analizado una vez).
fn dnie_issuer(p: &Prepared) -> bool {
    static FILTER: std::sync::OnceLock<Result<SearchFilter, rfc2254::SearchFilterError>> = std::sync::OnceLock::new();
    let Some(name) = p.issuer.as_ref() else { return true };
    rfc2254::filter_name(FILTER.get_or_init(|| SearchFilter::parse(DNIE_ISSUER_FILTER)), name)
}

fn is_signature_dnie(p: &Prepared) -> bool {
    key_usage_matches(&SIGN_CERT_USAGE, p.ku.as_ref()) && dnie_issuer(p)
}

fn is_authentication_dnie(p: &Prepared) -> bool {
    key_usage_matches(&AUTH_CERT_USAGE, p.ku.as_ref()) && dnie_issuer(p)
}

/// `QualifiedCertificatesFilter.isSignatureCert`: patrón de 8 posiciones
/// según el emisor (por defecto `nonRepudiation`; ACCV-CA2 solo
/// `digitalSignature`).
fn is_signature_cert(p: &Prepared) -> bool {
    let Some(ku) = p.ku else { return false };
    let pattern: [Option<bool>; 8] = if p.issuer_java == ACCV_SIGN_ISSUER {
        [
            Some(true),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        ]
    } else {
        [None, Some(true), None, None, None, None, None, None]
    };
    pattern.iter().zip(ku.iter()).all(|(p, b)| p.is_none_or(|p| p == *b))
}

fn digest_by_java_name(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    use afirma_core::DigestAlgorithm as D;
    let n = name.to_ascii_uppercase();
    let n = n.strip_prefix("OID.").unwrap_or(&n);
    let alg = match n {
        "SHA" | "SHA1" | "SHA-1" | "1.3.14.3.2.26" => D::Sha1,
        "SHA224" | "SHA-224" | "2.16.840.1.101.3.4.2.4" => D::Sha224,
        "SHA256" | "SHA-256" | "2.16.840.1.101.3.4.2.1" => D::Sha256,
        "SHA384" | "SHA-384" | "2.16.840.1.101.3.4.2.2" => D::Sha384,
        "SHA512" | "SHA-512" | "2.16.840.1.101.3.4.2.3" => D::Sha512,
        "MD5" | "1.2.840.113549.2.5" => {
            use md5::Digest;
            return Some(md5::Md5::digest(data).to_vec());
        }
        _ => return None,
    };
    Some(alg.digest(data))
}

impl CertFilter {
    /// Comprueba un certificado de forma aislada (`CertificateFilter.matches(cert)`).
    /// Los filtros que dependen del conjunto de candidatos (`ssl:`,
    /// `qualified:`, `pseudonym:`) se evalúan solo por su condición básica
    /// (número de serie / atributo de seudónimo).
    pub fn matches(&self, entry: &CertEntry, now: DateTime<Utc>) -> bool {
        let p = Prepared::new(entry);
        self.matches_prepared(&p, now)
    }

    fn matches_prepared(&self, p: &Prepared, now: DateTime<Utc>) -> bool {
        if !p.valid() {
            return false;
        }
        match self {
            CertFilter::SignatureDnie => is_signature_dnie(p),
            CertFilter::SkipAuthDnie => !is_authentication_dnie(p),
            CertFilter::SkipSignatureDnie => !is_signature_dnie(p),
            CertFilter::Expired { show_expired } => *show_expired || p.entry.is_valid_at(now),
            CertFilter::Sscd => p.sscd,
            CertFilter::KeyUsage(pattern) => key_usage_matches(pattern, p.ku.as_ref()),
            CertFilter::Rfc2254 { subject, issuer, .. } => {
                subject.as_deref().is_none_or(|f| rfc2254_name(f, p.subject.as_ref()))
                    && issuer.as_deref().is_none_or(|f| rfc2254_name(f, p.issuer.as_ref()))
            }
            CertFilter::TextContained { subject, issuer } => {
                subject
                    .as_deref()
                    .is_none_or(|t| java_lower(&p.subject_java).contains(&java_lower(t)))
                    && issuer
                        .as_deref()
                        .is_none_or(|t| java_lower(&p.issuer_java).contains(&java_lower(t)))
            }
            CertFilter::Thumbprint { algorithm, thumbprint } => digest_by_java_name(algorithm, &p.entry.certificate)
                .is_some_and(|d| eq_ignore_case(thumbprint, &hex::encode_upper(d))),
            CertFilter::PolicyId(allowed) => p
                .policies
                .as_ref()
                .is_some_and(|pols| !pols.is_empty() && pols.iter().all(|o| allowed.contains(o))),
            CertFilter::EncodedCert(b64) => *b64 == afirma_core::base64_encode(&p.entry.certificate),
            CertFilter::Ssl(serial) | CertFilter::Qualified(serial) => {
                eq_ignore_case(&prepare_serial(&p.serial_hex), serial)
            }
            CertFilter::Pseudonym { .. } => p.pseudonym,
            CertFilter::Multiple(fs) => fs.iter().all(|f| f.matches_prepared(p, now)),
        }
    }

    /// Filtra un conjunto de candidatos (`CertificateFilter.matches(aliases, ksm)`):
    /// `idx` son índices en `prepared`; devuelve los índices aceptados.
    fn filter_indices(&self, prepared: &[Prepared], idx: &[usize], now: DateTime<Utc>) -> Vec<usize> {
        match self {
            CertFilter::Multiple(fs) => {
                let mut cur = idx.to_vec();
                for f in fs {
                    cur = f.filter_indices(prepared, &cur, now);
                }
                cur
            }
            CertFilter::Rfc2254 {
                subject,
                issuer,
                recurse: true,
            } => idx
                .iter()
                .copied()
                .filter(|&i| {
                    let p = &prepared[i];
                    p.valid()
                        && subject.as_deref().is_none_or(|f| rfc2254_name(f, p.subject.as_ref()))
                        && p.entry.chain.iter().any(|c| {
                            issuer
                                .as_deref()
                                .is_none_or(|f| rfc2254_name(f, dn::subject_of(c).as_ref()))
                        })
                })
                .collect(),
            CertFilter::Ssl(serial) => {
                let mut out = Vec::new();
                for (pos, &i) in idx.iter().enumerate() {
                    let p = &prepared[i];
                    if !p.valid() || !eq_ignore_case(&prepare_serial(&p.serial_hex), serial) {
                        continue;
                    }
                    if is_authentication_dnie(p) {
                        let sn = p.subject_sn.as_deref();
                        let date = p.expiry_date();
                        let twin = idx.iter().enumerate().find(|&(j, &k)| {
                            let q = &prepared[k];
                            j != pos
                                && q.valid()
                                && is_signature_dnie(q)
                                && q.subject_sn
                                    .as_deref()
                                    .is_some_and(|qs| sn.is_some_and(|s| eq_ignore_case(qs, s)))
                                && q.expiry_date() == date
                        });
                        if let Some((_, &k)) = twin {
                            out.push(k);
                        }
                    } else {
                        out.push(i);
                    }
                }
                dedup(out)
            }
            CertFilter::Qualified(serial) => {
                let mut out = Vec::new();
                for &i in idx {
                    let p = &prepared[i];
                    if !p.valid() || !eq_ignore_case(&prepare_serial(&p.serial_hex), serial) {
                        continue;
                    }
                    if is_signature_cert(p) {
                        out.push(i);
                        continue;
                    }
                    let twin = idx.iter().copied().find(|&k| {
                        let q = &prepared[k];
                        q.valid()
                            && q.serial_raw != p.serial_raw
                            && is_signature_cert(q)
                            && q.issuer_canonical == p.issuer_canonical
                            && q.subject_sn == p.subject_sn
                            && q.expiry_date() == p.expiry_date()
                    });
                    match twin {
                        Some(k) => out.push(k),
                        None if !is_authentication_dnie(p) => out.push(i),
                        None => {}
                    }
                }
                dedup(out)
            }
            CertFilter::Pseudonym { only: true } => idx
                .iter()
                .copied()
                .filter(|&i| prepared[i].valid() && prepared[i].pseudonym)
                .collect(),
            CertFilter::Pseudonym { only: false } => {
                let (pseudo, others): (Vec<usize>, Vec<usize>) =
                    idx.iter().copied().partition(|&i| prepared[i].pseudonym);
                if pseudo.is_empty() {
                    return idx.to_vec();
                }
                let hidden: Vec<usize> = others
                    .iter()
                    .copied()
                    .filter(|&o| pseudo.iter().any(|&ps| is_pseudonym_for(&prepared[ps], &prepared[o])))
                    .collect();
                idx.iter().copied().filter(|i| !hidden.contains(i)).collect()
            }
            _ => idx
                .iter()
                .copied()
                .filter(|&i| self.matches_prepared(&prepared[i], now))
                .collect(),
        }
    }
}

fn dedup(v: Vec<usize>) -> Vec<usize> {
    let mut out = Vec::with_capacity(v.len());
    for i in v {
        if !out.contains(&i) {
            out.push(i);
        }
    }
    out
}

/// `PseudonymFilter.isPseudonymFor`: mismo emisor, mismos usos de clave y
/// menos de 60 s de diferencia en `notAfter`.
fn is_pseudonym_for(pseudo: &Prepared, other: &Prepared) -> bool {
    let (Some(a), Some(b)) = (pseudo.entry.info.as_ref(), other.entry.info.as_ref()) else {
        return false;
    };
    pseudo.issuer_canonical == other.issuer_canonical
        && pseudo.ku == other.ku
        && (a.not_after - b.not_after).num_milliseconds().abs() < 60_000
}

/// `String.split` de Java con un separador de un carácter (elimina las
/// cadenas vacías del final).
fn java_split(s: &str, sep: char) -> Vec<String> {
    if !s.contains(sep) {
        return vec![s.to_string()];
    }
    let mut parts: Vec<String> = s.split(sep).map(str::to_string).collect();
    while parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    parts
}

/// `Boolean.parseBoolean`.
fn parse_bool(s: &str) -> bool {
    s.eq_ignore_ascii_case("true")
}

/// Quita un prefijo ASCII contando caracteres (como `substring(prefix.length())`).
fn after_prefix(s: &str, prefix: &str) -> String {
    s.chars().skip(prefix.chars().count()).collect()
}

/// Resultado de analizar una expresión.
struct ParsedExpression {
    filter: CertFilter,
    disable_external_stores: bool,
}

/// Analiza una expresión de filtro (`CertFilterManager.parseFilter`).
fn parse_expression(expression: &str) -> Result<ParsedExpression, FilterError> {
    let mut items = java_split(expression, ';');
    // Orden de `Arrays.sort` sobre String (unidades UTF-16).
    items.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let mut filters = Vec::new();
    let mut disable = false;
    for (i, item) in items.iter().enumerate() {
        let lower = java_lower(item);
        let sub = |prefix: &str| after_prefix(item, prefix);
        if lower.starts_with("dnie:") {
            filters.push(CertFilter::SignatureDnie);
        } else if lower == "disableopeningexternalstores" {
            disable = true;
        } else if lower.starts_with("ssl:") {
            filters.push(CertFilter::Ssl(prepare_serial(&sub("ssl:"))));
        } else if lower.starts_with("qualified:") {
            filters.push(CertFilter::Qualified(prepare_serial(&sub("qualified:"))));
        } else if lower.starts_with("signingcert:") {
            filters.push(CertFilter::SkipAuthDnie);
        } else if lower.starts_with("authcert:") {
            filters.push(CertFilter::SkipSignatureDnie);
        } else if lower.starts_with("keyusage.") {
            filters.push(CertFilter::KeyUsage(keyusage_pattern(&items, i)));
        } else if lower.starts_with("nonexpired:") {
            let show_expired = if item.eq_ignore_ascii_case("nonexpired:") {
                false
            } else {
                !parse_bool(&sub("nonexpired:"))
            };
            filters.push(CertFilter::Expired { show_expired });
        } else if lower.starts_with("sscd:") {
            filters.push(CertFilter::Sscd);
        } else if lower.starts_with("subject.rfc2254:") {
            filters.push(rfc2254_filter(Some(sub("subject.rfc2254:")), None, false)?);
        } else if lower.starts_with("subject.contains:") {
            filters.push(CertFilter::TextContained {
                subject: Some(sub("subject.contains:")),
                issuer: None,
            });
        } else if lower.starts_with("issuer.rfc2254:") {
            filters.push(rfc2254_filter(None, Some(sub("issuer.rfc2254:")), false)?);
        } else if lower.starts_with("issuer.rfc2254.recurse:") {
            filters.push(rfc2254_filter(None, Some(sub("issuer.rfc2254.recurse:")), true)?);
        } else if lower.starts_with("issuer.contains:") {
            filters.push(CertFilter::TextContained {
                subject: None,
                issuer: Some(sub("issuer.contains:")),
            });
        } else if lower.starts_with("thumbprint:") {
            let params = java_split(&sub("thumbprint:"), ':');
            if params.len() == 2 {
                filters.push(CertFilter::Thumbprint {
                    algorithm: params[0].clone(),
                    thumbprint: params[1].replace(' ', ""),
                });
            }
        } else if lower.starts_with("policyid:") {
            let oids = sub("policyid:");
            if !oids.is_empty() {
                let list = java_split(&oids, ',');
                if list.is_empty() {
                    return Err(FilterError::EmptyPolicyList);
                }
                filters.push(CertFilter::PolicyId(list));
            }
        } else if lower.starts_with("pseudonym:") {
            let only = lower != "pseudonym:" && sub("pseudonym:").eq_ignore_ascii_case("only");
            filters.push(CertFilter::Pseudonym { only });
        } else if lower.starts_with("encodedcert:") {
            filters.push(CertFilter::EncodedCert(sub("encodedcert:")));
        } else {
            tracing::warn!("Se omitira el filtro '{item}' por no estar reconocido");
        }
    }
    let filter = if filters.len() == 1 {
        filters.remove(0)
    } else {
        CertFilter::Multiple(filters)
    };
    Ok(ParsedExpression {
        filter,
        disable_external_stores: disable,
    })
}

fn rfc2254_filter(subject: Option<String>, issuer: Option<String>, recurse: bool) -> Result<CertFilter, FilterError> {
    let subject = subject.filter(|s| !s.is_empty());
    let issuer = issuer.filter(|s| !s.is_empty());
    if subject.is_none() && issuer.is_none() {
        return Err(FilterError::EmptyCriteria);
    }
    Ok(CertFilter::Rfc2254 {
        subject,
        issuer,
        recurse,
    })
}

/// `generateKeyUsageFiltersPattern`: patrón formado por el elemento `pos` y
/// los siguientes que empiecen (sensible a mayúsculas) por `keyusage.`.
fn keyusage_pattern(items: &[String], pos: usize) -> KeyUsagePattern {
    let mut pattern: KeyUsagePattern = [None; 9];
    let mut i = pos;
    loop {
        let item = &items[i];
        let lower = java_lower(item);
        if let Some(k) = KEYUSAGE_NAMES
            .iter()
            .position(|n| lower.starts_with(&format!("keyusage.{n}:")))
        {
            let value = item.split_once(':').map(|(_, v)| v).unwrap_or("");
            pattern[k] = if value.eq_ignore_ascii_case("null") {
                None
            } else {
                Some(parse_bool(value))
            };
        }
        if items.len() > i + 1 && items[i + 1].starts_with("keyusage.") {
            i += 1;
        } else {
            break;
        }
    }
    pattern
}

/// Preferencias de filtrado de la aplicación local (sección 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalFilterPrefs {
    /// `useOnlySignatureCertificates` (por defecto `false`): solo
    /// certificados con `nonRepudiation`.
    pub use_only_signature_certificates: bool,
    /// `skipAuthCertDnie` (por defecto `true`): ocultar el certificado de
    /// autenticación del DNIe.
    pub skip_auth_cert_dnie: bool,
    /// `useOnlyAliasCertificates` (por defecto `false`): solo certificados de
    /// seudónimo.
    pub use_only_alias_certificates: bool,
    /// `showExpiredCerts` (por defecto `false`): mostrar caducados (no es un
    /// filtro: se aplica al construir la lista de candidatos).
    pub show_expired_certs: bool,
}

impl Default for LocalFilterPrefs {
    fn default() -> Self {
        LocalFilterPrefs {
            use_only_signature_certificates: false,
            skip_auth_cert_dnie: true,
            use_only_alias_certificates: false,
            show_expired_certs: false,
        }
    }
}

impl LocalFilterPrefs {
    /// Filtros de `SignPanel.getCertFilters`: ninguno, uno, o una conjunción.
    pub fn filters(&self) -> Vec<CertFilter> {
        let mut fs = Vec::new();
        if self.use_only_signature_certificates {
            fs.push(CertFilter::KeyUsage(SIGN_CERT_USAGE));
        }
        if self.skip_auth_cert_dnie {
            fs.push(CertFilter::SkipAuthDnie);
        }
        if self.use_only_alias_certificates {
            fs.push(CertFilter::Pseudonym { only: true });
        }
        match fs.len() {
            0 => Vec::new(),
            1 => fs,
            _ => vec![CertFilter::Multiple(fs)],
        }
    }
}

/// Gestor de filtros (`CertFilterManager`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFilterManager {
    filters: Vec<CertFilter>,
    mandatory: bool,
    allow_external_stores: bool,
}

impl CertFilterManager {
    /// Gestor con filtros explícitos.
    pub fn new(filters: Vec<CertFilter>, mandatory_certificate: bool, allow_external_stores: bool) -> Self {
        CertFilterManager {
            filters,
            mandatory: mandatory_certificate,
            allow_external_stores,
        }
    }

    /// Gestor a partir de los `extraParams` de una operación (claves
    /// `filter`, `filters`, `filters.N`, `headless`, `mandatoryCertSelection`).
    pub fn from_extra_params(params: &ExtraParams) -> Result<Self, FilterError> {
        Self::from_lookup(|k| params.get(k).map(str::to_string))
    }

    /// Igual que [`Self::from_extra_params`] con una función de consulta de
    /// propiedades (`None` = clave ausente).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, FilterError> {
        let headless = get("headless").is_some_and(|v| parse_bool(&v));
        let omit_selection = get("mandatoryCertSelection").is_some_and(|v| v.eq_ignore_ascii_case("false"));
        let mut values = Vec::new();
        if let Some(v) = get("filter") {
            values.push(v);
        } else if let Some(v) = get("filters") {
            values.push(v);
        } else {
            let mut i = 1;
            while let Some(v) = get(&format!("filters.{i}")) {
                values.push(v);
                i += 1;
            }
        }
        let mut manager = CertFilterManager {
            filters: Vec::new(),
            mandatory: headless || omit_selection,
            allow_external_stores: true,
        };
        for v in values {
            let parsed = parse_expression(&v)?;
            if parsed.disable_external_stores {
                manager.allow_external_stores = false;
            }
            manager.filters.push(parsed.filter);
        }
        // ETSI TS 119 102-1: si no se indicó ningún filtro, se ocultan los
        // caducados.
        if manager.filters.is_empty() {
            manager.filters.push(CertFilter::Expired { show_expired: false });
        }
        Ok(manager)
    }

    /// Gestor para el valor de `-filter` de la línea de comandos (se trata
    /// como la clave `filters`, sin filtro por defecto).
    pub fn from_cli_filter(expression: &str) -> Result<Self, FilterError> {
        Self::from_lookup(|k| (k == "filters").then(|| expression.to_string()))
    }

    /// Gestor con los filtros de las preferencias de la aplicación local.
    pub fn from_local_prefs(prefs: &LocalFilterPrefs) -> Self {
        CertFilterManager {
            filters: prefs.filters(),
            mandatory: false,
            allow_external_stores: true,
        }
    }

    /// Filtros (uno por expresión; se combinan con O).
    pub fn filters(&self) -> &[CertFilter] {
        &self.filters
    }

    /// Selección automática si solo hay un certificado (`headless=true` o
    /// `mandatoryCertSelection=false`).
    pub fn is_mandatory_certificate(&self) -> bool {
        self.mandatory
    }

    /// Se permite cambiar de almacén desde el diálogo (falso si algún
    /// elemento es `disableopeningexternalstores`).
    pub fn allow_external_stores(&self) -> bool {
        self.allow_external_stores
    }

    /// Aplica los filtros a las entradas (en el orden recibido) y devuelve
    /// las aceptadas.
    pub fn apply(&self, entries: &[CertEntry], now: DateTime<Utc>) -> Vec<CertEntry> {
        apply_filters(&self.filters, entries, now)
    }

    /// Igual que [`Self::apply`] pero devuelve los índices aceptados.
    pub fn apply_indices(&self, entries: &[CertEntry], now: DateTime<Utc>) -> Vec<usize> {
        apply_filter_indices(&self.filters, entries, now)
    }
}

/// Aplica una lista de filtros combinados con O como
/// `KeyStoreUtilities.getAliasesByFriendlyName`: cada filtro recibe los
/// candidatos que aún no ha aceptado otro anterior. Una lista vacía acepta
/// todo. Devuelve índices en orden ascendente.
pub fn apply_filter_indices(filters: &[CertFilter], entries: &[CertEntry], now: DateTime<Utc>) -> Vec<usize> {
    if filters.is_empty() {
        return (0..entries.len()).collect();
    }
    let prepared: Vec<Prepared> = entries.iter().map(Prepared::new).collect();
    let mut remaining: Vec<usize> = (0..entries.len()).collect();
    let mut accepted = Vec::new();
    for f in filters {
        let ok = f.filter_indices(&prepared, &remaining, now);
        remaining.retain(|i| !ok.contains(i));
        accepted.extend(ok);
    }
    accepted.sort_unstable();
    accepted.dedup();
    accepted
}

/// [`apply_filter_indices`] devolviendo las entradas.
pub fn apply_filters(filters: &[CertFilter], entries: &[CertEntry], now: DateTime<Utc>) -> Vec<CertEntry> {
    apply_filter_indices(filters, entries, now)
        .into_iter()
        .map(|i| entries[i].clone())
        .collect()
}

#[cfg(test)]
mod tests;
