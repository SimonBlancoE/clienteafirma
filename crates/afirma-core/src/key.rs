//! Abstracción de clave privada de firma.
//!
//! Cada almacén (PKCS#12, PKCS#11, Windows, llavero de macOS, NSS...) ofrece
//! sus claves a través de [`SigningKey`]. Los firmadores (CAdES, XAdES,
//! PAdES...) solo conocen esta interfaz.

use std::sync::Arc;

use crate::algorithms::{KeyAlgorithm, SignatureAlgorithm};

/// Error al usar una clave privada.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("operación cancelada por el usuario")]
    Cancelled,
    #[error("el PIN o la contraseña no son correctos")]
    WrongPin,
    #[error("el PIN está bloqueado")]
    PinLocked,
    #[error("la tarjeta o el dispositivo no está disponible")]
    DeviceUnavailable,
    #[error("algoritmo no soportado por la clave: {0}")]
    Unsupported(String),
    #[error("error en la operación de firma: {0}")]
    Other(String),
}

/// Clave privada con su certificado, capaz de firmar.
pub trait SigningKey: Send + Sync {
    /// Certificado de firma codificado en DER.
    fn certificate(&self) -> &[u8];

    /// Cadena de certificación en DER, empezando por el certificado de firma.
    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        vec![self.certificate().to_vec()]
    }

    /// Tipo de la clave.
    fn key_algorithm(&self) -> KeyAlgorithm;

    /// Firma `data` (se calcula la huella internamente). Para RSA devuelve la
    /// firma PKCS#1 v1.5; para ECDSA, la estructura DER `ECDSA-Sig-Value`.
    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError>;

    /// Alias de la clave en su almacén, si lo tiene.
    fn alias(&self) -> Option<&str> {
        None
    }
}

impl<T: SigningKey + ?Sized> SigningKey for Arc<T> {
    fn certificate(&self) -> &[u8] {
        (**self).certificate()
    }
    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        (**self).certificate_chain()
    }
    fn key_algorithm(&self) -> KeyAlgorithm {
        (**self).key_algorithm()
    }
    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        (**self).sign(data, algorithm)
    }
    fn alias(&self) -> Option<&str> {
        (**self).alias()
    }
}

impl<T: SigningKey + ?Sized> SigningKey for Box<T> {
    fn certificate(&self) -> &[u8] {
        (**self).certificate()
    }
    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        (**self).certificate_chain()
    }
    fn key_algorithm(&self) -> KeyAlgorithm {
        (**self).key_algorithm()
    }
    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        (**self).sign(data, algorithm)
    }
    fn alias(&self) -> Option<&str> {
        (**self).alias()
    }
}

/// Conversiones del formato de firma ECDSA.
pub mod ecdsa_format {
    /// Convierte `r || s` (formato PKCS#11/CNG/XMLDSig) a DER `ECDSA-Sig-Value`.
    pub fn raw_to_der(raw: &[u8]) -> Vec<u8> {
        let half = raw.len() / 2;
        let int = |b: &[u8]| {
            let first = b.iter().position(|&x| x != 0).unwrap_or(b.len().saturating_sub(1));
            let mut v = b[first..].to_vec();
            if v.is_empty() || v[0] & 0x80 != 0 {
                v.insert(0, 0);
            }
            let mut out = vec![0x02];
            push_len(&mut out, v.len());
            out.extend(v);
            out
        };
        let mut content = int(&raw[..half]);
        content.extend(int(&raw[half..]));
        let mut out = vec![0x30];
        push_len(&mut out, content.len());
        out.extend(content);
        out
    }

    /// Convierte DER `ECDSA-Sig-Value` a `r || s` con cada mitad de
    /// `field_len` bytes (32 para P-256, 48 para P-384, 66 para P-521).
    pub fn der_to_raw(der: &[u8], field_len: usize) -> Option<Vec<u8>> {
        let (content, _) = read_tlv(der, 0x30)?;
        let (r, rest) = read_tlv(content, 0x02)?;
        let (s, _) = read_tlv(rest, 0x02)?;
        let mut out = vec![0u8; field_len * 2];
        let r = strip(r);
        let s = strip(s);
        if r.len() > field_len || s.len() > field_len {
            return None;
        }
        out[field_len - r.len()..field_len].copy_from_slice(r);
        out[2 * field_len - s.len()..].copy_from_slice(s);
        Some(out)
    }

    /// Longitud de campo deducida de una firma DER (mayor de r y s, redondeada
    /// al tamaño de curva estándar).
    pub fn guess_field_len(der: &[u8]) -> usize {
        let len = (|| {
            let (content, _) = read_tlv(der, 0x30)?;
            let (r, rest) = read_tlv(content, 0x02)?;
            let (s, _) = read_tlv(rest, 0x02)?;
            Some(strip(r).len().max(strip(s).len()))
        })()
        .unwrap_or(32);
        match len {
            0..=32 => 32,
            33..=48 => 48,
            _ => 66,
        }
    }

    fn strip(b: &[u8]) -> &[u8] {
        let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
        &b[first..]
    }

    fn push_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.extend([0x81, len as u8]);
        } else {
            out.extend([0x82, (len >> 8) as u8, len as u8]);
        }
    }

    fn read_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        if input.first()? != &tag {
            return None;
        }
        let (len, hdr) = match *input.get(1)? {
            l if l < 0x80 => (usize::from(l), 2),
            0x81 => (usize::from(*input.get(2)?), 3),
            0x82 => ((usize::from(*input.get(2)?) << 8) | usize::from(*input.get(3)?), 4),
            _ => return None,
        };
        let end = hdr + len;
        if input.len() < end {
            return None;
        }
        Some((&input[hdr..end], &input[end..]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip() {
            let mut raw = vec![0u8; 64];
            raw[0] = 0x80;
            raw[31] = 1;
            raw[40] = 0x7f;
            let der = raw_to_der(&raw);
            assert_eq!(guess_field_len(&der), 32);
            assert_eq!(der_to_raw(&der, 32).unwrap(), raw);
        }
    }
}
