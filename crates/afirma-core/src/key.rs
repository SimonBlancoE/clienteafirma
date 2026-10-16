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

    /// Error de `Pkcs1Utils` (Java lanza `SignatureException` con estos
    /// mensajes).
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum Pkcs1UtilsError {
        #[error("Could not encode signature")]
        Encode,
        #[error("Invalid encoding for signature")]
        Decode,
    }

    /// `Pkcs1Utils.encodeSignature`: convierte `r || s` (dos mitades de
    /// `len/2` bytes; si la longitud es impar se ignora el último byte) en DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` con enteros mínimos.
    pub fn encode_signature(raw: &[u8]) -> Result<Vec<u8>, Pkcs1UtilsError> {
        let n = raw.len() >> 1;
        let mut tmp = raw[..n].to_vec();
        tmp.extend_from_slice(&raw[n..2 * n]);
        Ok(raw_to_der(&tmp))
    }

    /// `Pkcs1Utils.decodeSignature`: análisis DER estricto de una
    /// `SEQUENCE` con exactamente dos `INTEGER` y sin bytes sobrantes; cada
    /// entero se toma sin signo y sin ceros a la izquierda y el resultado
    /// tiene `2k` bytes con `k = max(len(r), len(s))` (**no** el tamaño de la
    /// curva; para eso está [`der_to_raw`]).
    pub fn decode_signature(der: &[u8]) -> Result<Vec<u8>, Pkcs1UtilsError> {
        let (content, rest) = read_tlv_strict(der, 0x30).ok_or(Pkcs1UtilsError::Decode)?;
        if !rest.is_empty() {
            return Err(Pkcs1UtilsError::Decode);
        }
        let (r, after_r) = read_tlv_strict(content, 0x02).ok_or(Pkcs1UtilsError::Decode)?;
        let (s, after_s) = read_tlv_strict(after_r, 0x02).ok_or(Pkcs1UtilsError::Decode)?;
        if !after_s.is_empty() {
            return Err(Pkcs1UtilsError::Decode);
        }
        for int in [r, s] {
            // Java: entero vacío o con ceros redundantes → error.
            if int.is_empty() || (int.len() >= 2 && int[0] == 0 && int[1] < 0x80) {
                return Err(Pkcs1UtilsError::Decode);
            }
        }
        // `trimZeroes` conserva al menos un byte.
        let trim = |b: &[u8]| -> Vec<u8> {
            let first = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1);
            b[first..].to_vec()
        };
        let r = trim(r);
        let s = trim(s);
        let k = r.len().max(s.len());
        let mut out = vec![0u8; 2 * k];
        out[k - r.len()..k].copy_from_slice(&r);
        out[2 * k - s.len()..].copy_from_slice(&s);
        Ok(out)
    }

    /// Lee un TLV DER con longitud definida y mínima.
    fn read_tlv_strict(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        if *input.first()? != tag {
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
            let bytes = input.get(2..2 + n)?;
            if bytes[0] == 0 {
                return None;
            }
            let len = bytes.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            if len < 0x80 {
                return None;
            }
            (len, 2 + n)
        };
        let end = hdr.checked_add(len)?;
        if input.len() < end {
            return None;
        }
        Some((&input[hdr..end], &input[end..]))
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

        #[test]
        fn java_pkcs1_utils() {
            // r = 0x0100 (2 bytes), s = 0x05 (1 byte) → k = 2.
            let der = [0x30, 0x07, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x05];
            assert_eq!(decode_signature(&der).unwrap(), vec![0x01, 0x00, 0x00, 0x05]);
            // Entero con 0x00 de signo: se recorta.
            let der = [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x7f];
            assert_eq!(decode_signature(&der).unwrap(), vec![0x80, 0x7f]);
            // Entero cero → un byte 0.
            let der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
            assert_eq!(decode_signature(&der).unwrap(), vec![0, 0]);
            // Errores: bytes sobrantes, ceros redundantes, entero vacío, tres enteros.
            assert!(decode_signature(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]).is_err());
            assert!(decode_signature(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]).is_err());
            assert!(decode_signature(&[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01]).is_err());
            assert!(decode_signature(&[0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_err());
            assert!(decode_signature(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_err());
            assert_eq!(
                decode_signature(&[]).unwrap_err().to_string(),
                "Invalid encoding for signature"
            );
            // Codificación e ida y vuelta.
            let raw = [0x00, 0x80, 0x00, 0x01];
            let der = encode_signature(&raw).unwrap();
            assert_eq!(der, vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]);
            assert_eq!(decode_signature(&der).unwrap(), vec![0x80, 0x01]);
            let mut big = vec![0x11u8; 132];
            big[0] = 0xff;
            assert_eq!(decode_signature(&encode_signature(&big).unwrap()).unwrap(), big);
        }
    }
}
