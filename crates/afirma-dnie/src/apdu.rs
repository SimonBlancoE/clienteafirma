//! APDU de ISO/IEC 7816-4: codificación de comandos (cortos y extendidos) y análisis de
//! respuestas (especificación 10 §2.4).
//!
//! Igual que JMulticard, muchos comandos del DNIe se envían **sin Le** aunque esperan datos
//! (SELECT, INTERNAL AUTHENTICATE, GENERAL AUTHENTICATE, PSO:CDS…); la tarjeta responde
//! igualmente. Los constructores de [`crate::session`] reproducen exactamente esa codificación.

use std::fmt;

use zeroize::Zeroize;

use crate::error::DnieError;

/// Palabras de estado usadas por el controlador.
pub mod sw {
    pub const OK: u16 = 0x9000;
    /// Fin de fichero alcanzado antes de leer Le octetos (aviso con datos).
    pub const END_OF_FILE: u16 = 0x6282;
    /// Desplazamiento fuera del fichero.
    pub const WRONG_OFFSET: u16 = 0x6B00;
    /// Estado de seguridad no satisfecho.
    pub const SECURITY_STATUS: u16 = 0x6982;
    /// Método de autenticación bloqueado (PIN bloqueado).
    pub const AUTH_BLOCKED: u16 = 0x6983;
    /// Objetos de mensajería segura ausentes.
    pub const SM_MISSING: u16 = 0x6987;
    /// Objetos de mensajería segura incorrectos.
    pub const SM_INCORRECT: u16 = 0x6988;
    /// Fichero no encontrado.
    pub const FILE_NOT_FOUND: u16 = 0x6A82;
    /// Suma de control criptográfica incorrecta (propietaria, `InvalidCryptographicChecksumException`).
    pub const BAD_CHECKSUM: u16 = 0x6688;
}

/// Comando APDU. Los datos se borran de memoria al liberarse (pueden contener el PIN).
#[derive(Clone, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    data: Vec<u8>,
    le: Option<usize>,
}

impl Drop for CommandApdu {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl CommandApdu {
    /// Comando sin datos ni Le (caso 1).
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        CommandApdu {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// Añade el campo de datos.
    pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
        self
    }

    /// Añade Le (1..=65536; 256 se codifica `00` en forma corta).
    pub fn with_le(mut self, le: usize) -> Self {
        self.le = Some(le);
        self
    }

    /// Sustituye Le.
    pub fn set_le(&mut self, le: Option<usize>) {
        self.le = le;
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn le(&self) -> Option<usize> {
        self.le
    }

    /// Cabecera `CLA INS P1 P2`.
    pub fn header(&self) -> [u8; 4] {
        [self.cla, self.ins, self.p1, self.p2]
    }

    /// Indica si hace falta la codificación extendida.
    pub fn is_extended(&self) -> bool {
        self.data.len() > 255 || self.le.is_some_and(|l| l > 256)
    }

    /// Codificación ISO 7816-4 (corta si cabe, extendida si no).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.data.len());
        out.extend_from_slice(&self.header());
        if !self.is_extended() {
            if !self.data.is_empty() {
                out.push(self.data.len() as u8);
                out.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                out.push(if le >= 256 { 0 } else { le as u8 });
            }
        } else {
            out.push(0);
            if !self.data.is_empty() {
                out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
                out.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                let v = if le >= 65536 { 0 } else { le as u16 };
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        out
    }

    /// Analiza una APDU codificada (cortas y extendidas).
    pub fn parse(bytes: &[u8]) -> Result<Self, DnieError> {
        let bad = || DnieError::Read(format!("APDU mal formada: {}", hex::encode_upper(bytes)));
        if bytes.len() < 4 {
            return Err(bad());
        }
        let mut c = CommandApdu::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let body = &bytes[4..];
        match body.len() {
            0 => {}
            1 => c.le = Some(if body[0] == 0 { 256 } else { body[0] as usize }),
            _ if body[0] != 0 => {
                let lc = body[0] as usize;
                if body.len() == 1 + lc {
                    c.data = body[1..].to_vec();
                } else if body.len() == 2 + lc {
                    c.data = body[1..1 + lc].to_vec();
                    let le = body[1 + lc];
                    c.le = Some(if le == 0 { 256 } else { le as usize });
                } else {
                    return Err(bad());
                }
            }
            3 => {
                let le = u16::from_be_bytes([body[1], body[2]]) as usize;
                c.le = Some(if le == 0 { 65536 } else { le });
            }
            _ => {
                let lc = u16::from_be_bytes([body[1], body[2]]) as usize;
                if lc == 0 {
                    return Err(bad());
                }
                if body.len() == 3 + lc {
                    c.data = body[3..].to_vec();
                } else if body.len() == 5 + lc {
                    c.data = body[3..3 + lc].to_vec();
                    let le = u16::from_be_bytes([body[3 + lc], body[4 + lc]]) as usize;
                    c.le = Some(if le == 0 { 65536 } else { le });
                } else {
                    return Err(bad());
                }
            }
        }
        Ok(c)
    }

    /// Indica si es un VERIFY con datos (lleva el PIN).
    pub fn is_pin_verify(&self) -> bool {
        self.ins == 0x20 && !self.data.is_empty()
    }
}

impl fmt::Debug for CommandApdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_pin_verify() {
            // Nunca se registra el PIN (como `AndroidNfcConnection`).
            return write!(
                f,
                "{:02X}{:02X}{:02X}{:02X} (verificación de PIN)",
                self.cla, self.ins, self.p1, self.p2
            );
        }
        f.write_str(&hex::encode_upper(self.encode()))
    }
}

/// Respuesta APDU: datos y palabra de estado.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl ResponseApdu {
    pub fn new(data: Vec<u8>, sw: u16) -> Self {
        ResponseApdu { data, sw }
    }

    /// Respuesta solo con palabra de estado.
    pub fn status(sw: u16) -> Self {
        ResponseApdu { data: Vec::new(), sw }
    }

    /// Separa `datos ‖ SW1 SW2`.
    pub fn parse(bytes: &[u8]) -> Result<Self, DnieError> {
        if bytes.len() < 2 {
            return Err(DnieError::Read(format!(
                "Respuesta APDU demasiado corta: {}",
                hex::encode_upper(bytes)
            )));
        }
        let n = bytes.len() - 2;
        Ok(ResponseApdu {
            data: bytes[..n].to_vec(),
            sw: u16::from_be_bytes([bytes[n], bytes[n + 1]]),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.data.clone();
        v.extend_from_slice(&self.sw.to_be_bytes());
        v
    }

    pub fn sw1(&self) -> u8 {
        (self.sw >> 8) as u8
    }

    pub fn sw2(&self) -> u8 {
        self.sw as u8
    }

    pub fn is_ok(&self) -> bool {
        self.sw == sw::OK
    }
}

impl fmt::Debug for ResponseApdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:04X}", hex::encode_upper(&self.data), self.sw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn short_cases() {
        assert_eq!(CommandApdu::new(0, 0x44, 0, 0).encode(), hx("00440000"));
        assert_eq!(CommandApdu::new(0, 0xB0, 0, 0).with_le(0xDE).encode(), hx("00B00000DE"));
        assert_eq!(CommandApdu::new(0, 0xB0, 0, 0).with_le(256).encode(), hx("00B0000000"));
        assert_eq!(
            CommandApdu::new(0, 0xA4, 4, 0)
                .with_data(b"Master.File".to_vec())
                .encode(),
            hx("00A404000B4D61737465722E46696C65")
        );
        assert_eq!(
            CommandApdu::new(0, 0xA4, 4, 0)
                .with_data(vec![1, 2])
                .with_le(256)
                .encode(),
            hx("00A4040002010200")
        );
    }

    #[test]
    fn extended_cases() {
        let data = vec![0xAB; 300];
        let e = CommandApdu::new(0, 0x2A, 0x9E, 0x9A).with_data(data.clone()).encode();
        assert_eq!(&e[..7], &hx("002A9E9A00012C")[..]);
        assert_eq!(e.len(), 7 + 300);
        let e = CommandApdu::new(0, 0x2A, 0x9E, 0x9A)
            .with_data(data)
            .with_le(65536)
            .encode();
        assert_eq!(&e[e.len() - 2..], &[0, 0]);
        assert_eq!(
            CommandApdu::new(0, 0xB0, 0, 0).with_le(1000).encode(),
            hx("00B000000003E8")
        );
    }

    #[test]
    fn parse_roundtrip() {
        for c in [
            CommandApdu::new(0, 0x44, 0, 0),
            CommandApdu::new(0x90, 0xB8, 0, 0).with_le(7),
            CommandApdu::new(0, 0xB0, 0, 0).with_le(256),
            CommandApdu::new(0, 0xA4, 0, 0).with_data(vec![0x60, 0x1F]),
            CommandApdu::new(0, 0x88, 0, 0).with_data(vec![1; 16]).with_le(128),
            CommandApdu::new(0, 0x2A, 0, 0xAE).with_data(vec![2; 400]),
            CommandApdu::new(0, 0x2A, 0, 0xAE).with_data(vec![2; 400]).with_le(2048),
            CommandApdu::new(0, 0xB0, 0, 0).with_le(4000),
        ] {
            assert_eq!(CommandApdu::parse(&c.encode()).unwrap(), c);
        }
        assert!(CommandApdu::parse(&hx("0020000005313233")).is_err());
    }

    #[test]
    fn response_and_debug() {
        let r = ResponseApdu::parse(&hx("01026282")).unwrap();
        assert_eq!(r.data, vec![1, 2]);
        assert_eq!(r.sw, 0x6282);
        assert_eq!((r.sw1(), r.sw2()), (0x62, 0x82));
        assert!(ResponseApdu::parse(&[0x90]).is_err());
        let v = CommandApdu::new(0, 0x20, 0, 0).with_data(b"secreto".to_vec());
        assert!(!format!("{v:?}").contains("736563"));
    }
}
