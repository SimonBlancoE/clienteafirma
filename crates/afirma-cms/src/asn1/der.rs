//! Construcción de estructuras DER.
//!
//! Todas las funciones devuelven la codificación completa del elemento
//! (etiqueta + longitud + contenido) como `Vec<u8>`.

use chrono::{DateTime, Datelike, Timelike, Utc};

use super::{Oid, Tag, tags};

/// Codifica una longitud DER.
pub fn length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    let mut out = vec![0x80 | (bytes.len() - first) as u8];
    out.extend_from_slice(&bytes[first..]);
    out
}

/// Elemento con la etiqueta y el contenido dados.
pub fn tlv(tag: Tag, content: &[u8]) -> Vec<u8> {
    let mut out = tag.encode();
    out.extend(length(content.len()));
    out.extend_from_slice(content);
    out
}

fn concat<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut out = Vec::new();
    for i in items {
        out.extend_from_slice(i.as_ref());
    }
    out
}

/// SEQUENCE con los elementos (ya codificados) en el orden dado.
pub fn sequence<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    tlv(tags::SEQUENCE, &concat(items))
}

/// SET OF ordenado según DER (orden lexicográfico de las codificaciones).
pub fn set_of<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    tlv(tags::SET, &sorted_concat(items))
}

/// Concatenación ordenada de elementos para contenido de SET OF en DER.
pub fn sorted_concat<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut v: Vec<Vec<u8>> = items.into_iter().map(|b| b.as_ref().to_vec()).collect();
    v.sort();
    concat(v)
}

/// SET con los elementos en el orden dado (sin ordenar).
pub fn set_unsorted<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    tlv(tags::SET, &concat(items))
}

/// Etiqueta de contexto explícita `[n] EXPLICIT`.
pub fn explicit(n: u32, inner: &[u8]) -> Vec<u8> {
    tlv(Tag::context(n, true), inner)
}

/// Etiqueta de contexto implícita: sustituye la etiqueta de `inner`.
pub fn implicit(n: u32, inner: &[u8]) -> Vec<u8> {
    let (tlv_, _) = super::Tlv::parse(inner).expect("implicit() requiere un elemento DER válido");
    tlv(Tag::context(n, tlv_.tag.constructed), tlv_.value)
}

/// Etiqueta de contexto implícita a partir del contenido.
pub fn implicit_content(n: u32, constructed: bool, content: &[u8]) -> Vec<u8> {
    tlv(Tag::context(n, constructed), content)
}

pub fn oid(o: &Oid) -> Vec<u8> {
    tlv(tags::OID, o.as_bytes())
}

pub fn oid_str(dotted: &str) -> Vec<u8> {
    oid(&Oid::new(dotted))
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn boolean(v: bool) -> Vec<u8> {
    vec![0x01, 0x01, if v { 0xff } else { 0x00 }]
}

/// INTEGER a partir de un entero con signo.
pub fn integer_i64(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let b = bytes[start];
        let next = bytes[start + 1];
        if (b == 0x00 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(tags::INTEGER, &bytes[start..])
}

/// INTEGER no negativo a partir de sus bytes big endian (se normalizan los
/// ceros iniciales y se añade un 0 si el bit alto está activo).
pub fn integer_unsigned(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[first..];
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.is_empty() || trimmed[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    tlv(tags::INTEGER, &content)
}

/// INTEGER con los bytes de complemento a dos tal cual (p. ej. un número de
/// serie leído de un certificado).
pub fn integer_raw(twos_complement: &[u8]) -> Vec<u8> {
    tlv(tags::INTEGER, twos_complement)
}

pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(tags::OCTET_STRING, content)
}

/// BIT STRING sin bits sobrantes.
pub fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(content.len() + 1);
    c.push(0);
    c.extend_from_slice(content);
    tlv(tags::BIT_STRING, &c)
}

pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(tags::UTF8_STRING, s.as_bytes())
}

pub fn printable_string(s: &str) -> Vec<u8> {
    tlv(tags::PRINTABLE_STRING, s.as_bytes())
}

pub fn ia5_string(s: &str) -> Vec<u8> {
    tlv(tags::IA5_STRING, s.as_bytes())
}

/// UTCTime `YYMMDDhhmmssZ`.
pub fn utc_time(t: &DateTime<Utc>) -> Vec<u8> {
    let s = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        t.year() % 100,
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    tlv(tags::UTC_TIME, s.as_bytes())
}

/// GeneralizedTime `YYYYMMDDhhmmss[.fff]Z` (fracciones sin ceros finales).
pub fn generalized_time(t: &DateTime<Utc>, with_millis: bool) -> Vec<u8> {
    let mut s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    if with_millis {
        let ms = t.timestamp_subsec_millis();
        if ms != 0 {
            let frac = format!("{ms:03}");
            s.push('.');
            s.push_str(frac.trim_end_matches('0'));
        }
    }
    s.push('Z');
    tlv(tags::GENERALIZED_TIME, s.as_bytes())
}

/// Codificación de `Time` según RFC 5280: UTCTime hasta 2049, GeneralizedTime después.
pub fn time(t: &DateTime<Utc>) -> Vec<u8> {
    if (1950..2050).contains(&t.year()) { utc_time(t) } else { generalized_time(t, false) }
}

/// AlgorithmIdentifier con parámetros opcionales (ya codificados).
pub fn algorithm_identifier(alg: &Oid, params: Option<&[u8]>) -> Vec<u8> {
    match params {
        Some(p) => sequence([oid(alg), p.to_vec()]),
        None => sequence([oid(alg)]),
    }
}
