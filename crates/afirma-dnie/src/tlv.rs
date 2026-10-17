//! Lectura y escritura de TLV BER (objetos de mensajería segura, datos de GENERAL
//! AUTHENTICATE, FCI, PKCS#15 y X.509).
//!
//! Solo formas de longitud definidas (corta, `81`, `82`, `83`): la longitud indefinida se
//! rechaza (corrige el defecto C4 de JMulticard, que trataba una longitud de 128 como
//! indefinida).

use crate::error::DnieError;

/// Elemento TLV analizado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Etiqueta con todos sus octetos (p. ej. `0x87`, `0x7F49`).
    pub tag: u32,
    /// Valor.
    pub value: &'a [u8],
    /// Codificación completa (etiqueta, longitud y valor).
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Indica si la etiqueta es construida (bit 6 del primer octeto).
    pub fn is_constructed(&self) -> bool {
        let first = if self.tag > 0xFFFFFF {
            self.tag >> 24
        } else if self.tag > 0xFFFF {
            self.tag >> 16
        } else if self.tag > 0xFF {
            self.tag >> 8
        } else {
            self.tag
        };
        first & 0x20 != 0
    }

    /// Hijos de un elemento construido.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>, DnieError> {
        parse_all(self.value)
    }

    /// Primer hijo con la etiqueta indicada.
    pub fn child(&self, tag: u32) -> Result<Option<Tlv<'a>>, DnieError> {
        Ok(self.children()?.into_iter().find(|t| t.tag == tag))
    }
}

fn err(msg: &str, data: &[u8]) -> DnieError {
    let shown = &data[..data.len().min(32)];
    DnieError::Read(format!("TLV no válido ({msg}): {}", hex::encode_upper(shown)))
}

/// Analiza el primer elemento de `data` y devuelve también los octetos consumidos.
pub fn parse_one(data: &[u8]) -> Result<(Tlv<'_>, usize), DnieError> {
    if data.is_empty() {
        return Err(err("vacío", data));
    }
    let mut i = 0;
    let mut tag = data[0] as u32;
    i += 1;
    if data[0] & 0x1F == 0x1F {
        // Etiqueta de varios octetos.
        loop {
            let b = *data.get(i).ok_or_else(|| err("etiqueta truncada", data))?;
            tag = (tag << 8) | b as u32;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
            if i > 4 {
                return Err(err("etiqueta demasiado larga", data));
            }
        }
    }
    let l0 = *data.get(i).ok_or_else(|| err("sin longitud", data))?;
    i += 1;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7F) as usize;
        if n == 0 || n > 3 {
            return Err(err("longitud indefinida o demasiado grande", data));
        }
        let bytes = data.get(i..i + n).ok_or_else(|| err("longitud truncada", data))?;
        i += n;
        bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize)
    };
    let end = i.checked_add(len).ok_or_else(|| err("longitud desbordada", data))?;
    let value = data.get(i..end).ok_or_else(|| err("valor truncado", data))?;
    Ok((
        Tlv {
            tag,
            value,
            raw: &data[..end],
        },
        end,
    ))
}

/// Analiza una secuencia de elementos que ocupa exactamente `data`.
pub fn parse_all(data: &[u8]) -> Result<Vec<Tlv<'_>>, DnieError> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (t, n) = parse_one(rest)?;
        out.push(t);
        rest = &rest[n..];
    }
    Ok(out)
}

/// Codifica la longitud (corta, `81 L`, `82 LL LL`).
pub fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x10000 {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        out.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
}

/// Codifica un TLV con etiqueta de uno o dos octetos.
pub fn encode(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    if tag > 0xFF {
        out.extend_from_slice(&tag.to_be_bytes());
    } else {
        out.push(tag as u8);
    }
    encode_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_tags() {
        for n in [0usize, 1, 127, 128, 255, 256, 265, 70000] {
            let v = vec![0xAB; n];
            let e = encode(0x87, &v);
            let (t, used) = parse_one(&e).unwrap();
            assert_eq!((t.tag, t.value.len(), used), (0x87, n, e.len()));
        }
        // DO87 de 265 octetos (respuesta de PSO:CDS bajo CWA): 87 82 01 09.
        assert_eq!(&encode(0x87, &[0; 265])[..4], &[0x87, 0x82, 0x01, 0x09]);
        let e = encode(0x7F49, &[1, 2]);
        let (t, _) = parse_one(&e).unwrap();
        assert_eq!(t.tag, 0x7F49);
        assert!(t.is_constructed());
        assert!(parse_one(&[0x30, 0x80, 0, 0]).is_err());
        assert!(parse_one(&[0x04, 0x05, 1, 2]).is_err());
        let all = parse_all(&[0x99, 0x02, 0x90, 0x00, 0x8E, 0x01, 0x55]).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].raw, &[0x8E, 0x01, 0x55]);
    }
}
