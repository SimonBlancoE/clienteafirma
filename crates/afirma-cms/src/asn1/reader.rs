use std::fmt;

use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

use super::{Asn1Error, Oid, Result, tags};

/// Clase de una etiqueta ASN.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Universal,
    Application,
    Context,
    Private,
}

/// Etiqueta ASN.1 (clase, construida/primitiva y número).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    pub class: Class,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const fn universal(number: u32, constructed: bool) -> Self {
        Tag {
            class: Class::Universal,
            constructed,
            number,
        }
    }

    pub const fn context(number: u32, constructed: bool) -> Self {
        Tag {
            class: Class::Context,
            constructed,
            number,
        }
    }

    /// Codificación de la etiqueta.
    pub fn encode(&self) -> Vec<u8> {
        let class_bits = match self.class {
            Class::Universal => 0x00,
            Class::Application => 0x40,
            Class::Context => 0x80,
            Class::Private => 0xc0,
        };
        let cons = if self.constructed { 0x20 } else { 0 };
        if self.number < 31 {
            vec![class_bits | cons | self.number as u8]
        } else {
            let mut out = vec![class_bits | cons | 0x1f];
            let mut tmp = Vec::new();
            let mut n = self.number;
            loop {
                tmp.push((n & 0x7f) as u8);
                n >>= 7;
                if n == 0 {
                    break;
                }
            }
            tmp.reverse();
            let last = tmp.len() - 1;
            for (i, b) in tmp.into_iter().enumerate() {
                out.push(if i == last { b } else { b | 0x80 });
            }
            out
        }
    }

    /// Misma etiqueta con otro indicador de construcción.
    pub const fn with_constructed(self, constructed: bool) -> Self {
        Tag {
            class: self.class,
            constructed,
            number: self.number,
        }
    }

    /// Compara ignorando el indicador primitivo/construido.
    pub fn same_number(&self, other: Tag) -> bool {
        self.class == other.class && self.number == other.number
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.class {
            Class::Universal => "U",
            Class::Application => "A",
            Class::Context => "C",
            Class::Private => "P",
        };
        write!(
            f,
            "[{}{}{}]",
            class,
            self.number,
            if self.constructed { "c" } else { "" }
        )
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Elemento ASN.1 (etiqueta-longitud-valor) leído de un búfer BER o DER.
///
/// Conserva una referencia a los bytes originales completos (`raw`) para poder
/// reutilizarlos sin recodificar.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: Tag,
    /// Contenido (sin cabecera ni marcador de fin de contenido).
    pub value: &'a [u8],
    /// Codificación completa original (cabecera + contenido + EOC si lo hay).
    pub raw: &'a [u8],
    /// Indica si la longitud era indefinida (BER).
    pub indefinite: bool,
}

impl fmt::Debug for Tlv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tlv({:?}, {} bytes)", self.tag, self.value.len())
    }
}

fn read_tag(input: &[u8]) -> Result<(Tag, usize)> {
    let first = *input.first().ok_or(Asn1Error::Truncated)?;
    let class = match first >> 6 {
        0 => Class::Universal,
        1 => Class::Application,
        2 => Class::Context,
        _ => Class::Private,
    };
    let constructed = first & 0x20 != 0;
    let mut number = u32::from(first & 0x1f);
    let mut pos = 1;
    if number == 0x1f {
        number = 0;
        loop {
            let b = *input.get(pos).ok_or(Asn1Error::Truncated)?;
            pos += 1;
            if number > (u32::MAX >> 7) {
                return Err(Asn1Error::Invalid("número de etiqueta demasiado grande".into()));
            }
            number = (number << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((
        Tag {
            class,
            constructed,
            number,
        },
        pos,
    ))
}

/// Devuelve `(longitud, bytes de cabecera de longitud)`; `None` = indefinida.
fn read_length(input: &[u8]) -> Result<(Option<usize>, usize)> {
    let first = *input.first().ok_or(Asn1Error::Truncated)?;
    if first < 0x80 {
        return Ok((Some(usize::from(first)), 1));
    }
    if first == 0x80 {
        return Ok((None, 1));
    }
    let n = usize::from(first & 0x7f);
    if n > 8 || input.len() < 1 + n {
        return Err(if n > 8 {
            Asn1Error::BadLength
        } else {
            Asn1Error::Truncated
        });
    }
    let mut len: usize = 0;
    for &b in &input[1..=n] {
        len = len.checked_mul(256).ok_or(Asn1Error::BadLength)? + usize::from(b);
    }
    Ok((Some(len), 1 + n))
}

impl<'a> Tlv<'a> {
    /// Lee un elemento del principio de `input` y devuelve el resto.
    pub fn parse(input: &'a [u8]) -> Result<(Tlv<'a>, &'a [u8])> {
        Self::parse_depth(input, 0)
    }

    fn parse_depth(input: &'a [u8], depth: usize) -> Result<(Tlv<'a>, &'a [u8])> {
        if depth > 64 {
            return Err(Asn1Error::Invalid("anidamiento ASN.1 excesivo".into()));
        }
        let (tag, tag_len) = read_tag(input)?;
        let (len, len_len) = read_length(&input[tag_len..])?;
        let header = tag_len + len_len;
        match len {
            Some(len) => {
                let end = header.checked_add(len).ok_or(Asn1Error::BadLength)?;
                if input.len() < end {
                    return Err(Asn1Error::Truncated);
                }
                Ok((
                    Tlv {
                        tag,
                        value: &input[header..end],
                        raw: &input[..end],
                        indefinite: false,
                    },
                    &input[end..],
                ))
            }
            None => {
                if !tag.constructed {
                    return Err(Asn1Error::Invalid("longitud indefinida en tipo primitivo".into()));
                }
                let mut rest = &input[header..];
                loop {
                    if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                        let content_len = input.len() - header - rest.len();
                        let end = header + content_len + 2;
                        return Ok((
                            Tlv {
                                tag,
                                value: &input[header..header + content_len],
                                raw: &input[..end],
                                indefinite: true,
                            },
                            &input[end..],
                        ));
                    }
                    if rest.is_empty() {
                        return Err(Asn1Error::Truncated);
                    }
                    let (_, r) = Self::parse_depth(rest, depth + 1)?;
                    rest = r;
                }
            }
        }
    }

    /// Lee un único elemento que debe ocupar todo el búfer (se toleran ceros
    /// de relleno al final, frecuentes en firmas PDF).
    pub fn parse_single(input: &'a [u8]) -> Result<Tlv<'a>> {
        let (tlv, rest) = Self::parse(input)?;
        if rest.iter().any(|&b| b != 0) {
            return Err(Asn1Error::Invalid("datos sobrantes tras el elemento ASN.1".into()));
        }
        Ok(tlv)
    }

    /// Hijos de un elemento construido.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        if !self.tag.constructed {
            return Err(Asn1Error::Invalid(format!("{} no es construido", self.tag)));
        }
        let mut out = Vec::new();
        let mut rest = self.value;
        while !rest.is_empty() {
            let (child, r) = Self::parse_depth(rest, 1)?;
            out.push(child);
            rest = r;
        }
        Ok(out)
    }

    /// Comprueba la etiqueta y devuelve el propio elemento.
    pub fn expect(self, tag: Tag) -> Result<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(Asn1Error::UnexpectedTag {
                expected: tag.to_string(),
                found: self.tag.to_string(),
            })
        }
    }

    pub fn is(&self, tag: Tag) -> bool {
        self.tag == tag
    }

    /// Bytes con etiqueta [`tags::SET`] en lugar de la original manteniendo el
    /// contenido. Útil para atributos firmados (`[0] IMPLICIT` -> `SET`).
    pub fn retagged_raw(&self, tag: Tag) -> Vec<u8> {
        super::der::tlv(tag, self.value)
    }

    /// Codificación DER de este elemento: si ya estaba en forma definida se
    /// devuelven los bytes originales.
    pub fn to_definite(&self) -> Vec<u8> {
        if !self.indefinite {
            return self.raw.to_vec();
        }
        let mut content = Vec::new();
        if let Ok(children) = self.children() {
            for c in children {
                content.extend(c.to_definite());
            }
        }
        super::der::tlv(self.tag, &content)
    }

    pub fn as_oid(&self) -> Result<Oid> {
        self.expect(tags::OID)?;
        Oid::from_der_content(self.value)
    }

    pub fn as_bool(&self) -> Result<bool> {
        self.expect(tags::BOOLEAN)?;
        Ok(self.value.first().copied().unwrap_or(0) != 0)
    }

    /// Bytes del entero tal cual (complemento a dos, big endian).
    pub fn as_integer_bytes(&self) -> Result<&'a [u8]> {
        if self.tag.number != 2 && self.tag.number != 10 && self.tag.class == Class::Universal {
            return Err(Asn1Error::UnexpectedTag {
                expected: tags::INTEGER.to_string(),
                found: self.tag.to_string(),
            });
        }
        Ok(self.value)
    }

    /// Entero pequeño (hasta 64 bits con signo).
    pub fn as_i64(&self) -> Result<i64> {
        let bytes = self.as_integer_bytes()?;
        if bytes.is_empty() || bytes.len() > 8 {
            return Err(Asn1Error::Invalid("entero fuera de rango".into()));
        }
        let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in bytes {
            v = (v << 8) | i64::from(b);
        }
        Ok(v)
    }

    /// Contenido de un OCTET STRING, concatenando segmentos si era construido (BER).
    pub fn octet_string_content(&self) -> Result<Vec<u8>> {
        if !self.tag.same_number(tags::OCTET_STRING) && self.tag.class == Class::Universal {
            return Err(Asn1Error::UnexpectedTag {
                expected: tags::OCTET_STRING.to_string(),
                found: self.tag.to_string(),
            });
        }
        self.flatten_content()
    }

    /// Contenido de un elemento primitivo o la concatenación de los
    /// contenidos de sus segmentos si es construido (cadenas BER).
    pub fn flatten_content(&self) -> Result<Vec<u8>> {
        if !self.tag.constructed {
            return Ok(self.value.to_vec());
        }
        let mut out = Vec::new();
        for c in self.children()? {
            out.extend(c.flatten_content()?);
        }
        Ok(out)
    }

    /// Contenido de un BIT STRING (sin el byte de bits no usados).
    pub fn bit_string_content(&self) -> Result<&'a [u8]> {
        self.expect(tags::BIT_STRING)?;
        self.value
            .split_first()
            .map(|(_, rest)| rest)
            .ok_or(Asn1Error::Truncated)
    }

    /// Interpreta una cadena de caracteres ASN.1 de cualquier tipo habitual.
    pub fn as_string(&self) -> Result<String> {
        match (self.tag.class, self.tag.number) {
            (Class::Universal, 12 | 18 | 19 | 22 | 26) => {
                Ok(String::from_utf8_lossy(&self.flatten_content()?).into_owned())
            }
            (Class::Universal, 20) => {
                // T61/TeletexString: se trata como Latin-1.
                Ok(self.flatten_content()?.iter().map(|&b| b as char).collect())
            }
            (Class::Universal, 30) => {
                let bytes = self.flatten_content()?;
                let units: Vec<u16> = bytes
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                    .collect();
                Ok(String::from_utf16_lossy(&units))
            }
            (Class::Universal, 28) => {
                let bytes = self.flatten_content()?;
                Ok(bytes
                    .chunks(4)
                    .filter_map(|c| {
                        if c.len() == 4 {
                            char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                        } else {
                            None
                        }
                    })
                    .collect())
            }
            _ => Err(Asn1Error::Invalid(format!("{} no es una cadena", self.tag))),
        }
    }

    /// Interpreta un UTCTime o GeneralizedTime.
    pub fn as_time(&self) -> Result<DateTime<Utc>> {
        let s = std::str::from_utf8(self.value).map_err(|_| Asn1Error::Invalid("fecha no ASCII".into()))?;
        if self.tag == tags::UTC_TIME {
            parse_utc_time(s)
        } else if self.tag == tags::GENERALIZED_TIME {
            parse_generalized_time(s)
        } else {
            Err(Asn1Error::UnexpectedTag {
                expected: "Time".into(),
                found: self.tag.to_string(),
            })
        }
    }
}

fn bad_time(s: &str) -> Asn1Error {
    Asn1Error::Invalid(format!("fecha ASN.1 no válida: {s}"))
}

fn digits(s: &str, from: usize, len: usize) -> Option<u32> {
    s.get(from..from + len)
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// Aplica un desplazamiento horario `+hhmm`/`-hhmm` o `Z` del final de la cadena.
fn apply_zone(naive: NaiveDateTime, zone: &str, s: &str) -> Result<DateTime<Utc>> {
    if zone.is_empty() || zone == "Z" {
        return Ok(Utc.from_utc_datetime(&naive));
    }
    let sign = match zone.as_bytes()[0] {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return Err(bad_time(s)),
    };
    let hh = digits(zone, 1, 2).ok_or_else(|| bad_time(s))?;
    let mm = digits(zone, 3, 2).unwrap_or(0);
    let offset = sign * (i64::from(hh) * 3600 + i64::from(mm) * 60);
    Ok(Utc.from_utc_datetime(&(naive - chrono::Duration::seconds(offset))))
}

fn parse_utc_time(s: &str) -> Result<DateTime<Utc>> {
    let yy = digits(s, 0, 2).ok_or_else(|| bad_time(s))?;
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy } as i32;
    let month = digits(s, 2, 2).ok_or_else(|| bad_time(s))?;
    let day = digits(s, 4, 2).ok_or_else(|| bad_time(s))?;
    let hour = digits(s, 6, 2).ok_or_else(|| bad_time(s))?;
    let min = digits(s, 8, 2).ok_or_else(|| bad_time(s))?;
    let (sec, zone_start) = match digits(s, 10, 2) {
        Some(sec) => (sec, 12),
        None => (0, 10),
    };
    let date = NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| bad_time(s))?;
    let time = NaiveTime::from_hms_opt(hour, min, sec).ok_or_else(|| bad_time(s))?;
    apply_zone(NaiveDateTime::new(date, time), &s[zone_start..], s)
}

fn parse_generalized_time(s: &str) -> Result<DateTime<Utc>> {
    let year = digits(s, 0, 4).ok_or_else(|| bad_time(s))? as i32;
    let month = digits(s, 4, 2).ok_or_else(|| bad_time(s))?;
    let day = digits(s, 6, 2).ok_or_else(|| bad_time(s))?;
    let hour = digits(s, 8, 2).unwrap_or(0);
    let min = digits(s, 10, 2).unwrap_or(0);
    let sec = digits(s, 12, 2).unwrap_or(0);
    let mut pos = 14.min(s.len());
    let mut nanos = 0u32;
    if s.as_bytes().get(pos) == Some(&b'.') || s.as_bytes().get(pos) == Some(&b',') {
        let frac: String = s[pos + 1..].chars().take_while(char::is_ascii_digit).collect();
        pos += 1 + frac.len();
        let padded = format!("{:0<9}", &frac[..frac.len().min(9)]);
        nanos = padded.parse().unwrap_or(0);
    }
    let date = NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| bad_time(s))?;
    let time = NaiveTime::from_hms_nano_opt(hour, min, sec, nanos).ok_or_else(|| bad_time(s))?;
    apply_zone(NaiveDateTime::new(date, time), &s[pos..], s)
}
