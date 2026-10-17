//! Transporte de APDU hacia la tarjeta y lógica común de transmisión (especificación 10 §2).
//!
//! La interfaz [`CardTransport`] es lo único que tiene que implementar cada plataforma:
//! Android (`IsoDep` por JNI), escritorio (PC/SC con un lector sin contacto) o el simulador
//! ([`crate::sim`]). Sobre ella, [`Link`] aplica la lógica común de JMulticard
//! (`AbstractApduConnectionIso7816.transmit`): troceado `90 C2` de comandos largos,
//! `GET RESPONSE` ante `61xx` y reenvío con el Le correcto ante `6Cxx` (solo en claro).

use crate::apdu::{CommandApdu, ResponseApdu};
use crate::error::{DnieError, TransportError};

/// Enlace con una tarjeta.
pub trait CardTransport: Send {
    /// Envía una APDU completa y devuelve `datos ‖ SW1 ‖ SW2`, sin reintentos ni GET RESPONSE
    /// (los hace [`Link`]).
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// Datos de identificación de la tarjeta **sin efectos secundarios** (nunca reinicia la
    /// tarjeta, a diferencia de `reset()` de JMulticard en PC/SC, §2.2).
    fn identification(&mut self) -> Result<CardIdentification, TransportError> {
        Ok(CardIdentification::default())
    }

    /// Longitud máxima de una APDU de comando que admite el enlace
    /// (`IsoDep.getMaxTransceiveLength()`). El controlador nunca envía más de 255 octetos por
    /// APDU (`getMaxApduSize() = 0xFF` en JMulticard).
    fn max_command_len(&self) -> usize {
        255
    }
}

impl<T: CardTransport + ?Sized> CardTransport for Box<T> {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        (**self).transceive(apdu)
    }
    fn identification(&mut self) -> Result<CardIdentification, TransportError> {
        (**self).identification()
    }
    fn max_command_len(&self) -> usize {
        (**self).max_command_len()
    }
}

impl<T: CardTransport + ?Sized> CardTransport for &mut T {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        (**self).transceive(apdu)
    }
    fn identification(&mut self) -> Result<CardIdentification, TransportError> {
        (**self).identification()
    }
    fn max_command_len(&self) -> usize {
        (**self).max_command_len()
    }
}

/// Datos con los que se identifica la tarjeta (§3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardIdentification {
    /// ATR o pseudo-ATR PC/SC (lector de escritorio).
    pub atr: Option<Vec<u8>>,
    /// Bytes históricos (Android, NfcA: `IsoDep.getHistoricalBytes()`).
    pub historical_bytes: Option<Vec<u8>>,
    /// Respuesta de capa superior del ATTRIB (Android, NfcB: `IsoDep.getHiLayerResponse()`).
    pub hi_layer_response: Option<Vec<u8>>,
    /// Datos de aplicación del ATQB (Android: `NfcB.getApplicationData()`, 4 octetos).
    pub nfcb_application_data: Option<Vec<u8>>,
    /// Información de protocolo del ATQB (Android: `NfcB.getProtocolInfo()`, 3 octetos).
    pub nfcb_protocol_info: Option<Vec<u8>>,
}

impl CardIdentification {
    /// Identificación de un lector PC/SC (o del simulador) a partir de su (pseudo-)ATR.
    pub fn from_atr(atr: impl Into<Vec<u8>>) -> Self {
        CardIdentification {
            atr: Some(atr.into()),
            ..Default::default()
        }
    }

    /// Valor que JMulticard obtiene con `reset()`: el ATR (PC/SC) o, en Android, los bytes
    /// históricos o, si no hay, la respuesta de capa superior.
    pub fn jmulticard_reset_bytes(&self) -> Vec<u8> {
        self.atr
            .clone()
            .or_else(|| self.historical_bytes.clone())
            .or_else(|| self.hi_layer_response.clone())
            .unwrap_or_default()
    }
}

/// Máximo de reintentos encadenados (`61xx`/`6Cxx`) antes de desistir.
const MAX_CHAINED: usize = 32;

/// Enlace con la lógica común de transmisión de JMulticard.
pub struct Link<T: CardTransport> {
    transport: T,
    apdus: usize,
}

impl<T: CardTransport> Link<T> {
    pub fn new(transport: T) -> Self {
        Link { transport, apdus: 0 }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Número de APDU enviadas por el enlace (incluidas las de GET RESPONSE y troceado).
    pub fn apdu_count(&self) -> usize {
        self.apdus
    }

    fn raw(&mut self, apdu: &[u8]) -> Result<ResponseApdu, DnieError> {
        self.apdus += 1;
        let out = self.transport.transceive(apdu)?;
        let r = ResponseApdu::parse(&out)?;
        tracing::trace!(target: "afirma_dnie::apdu", "< {:?}", r);
        Ok(r)
    }

    /// Envía un comando en claro.
    pub fn transmit(&mut self, cmd: &CommandApdu) -> Result<ResponseApdu, DnieError> {
        tracing::trace!(target: "afirma_dnie::apdu", "> {:?}", cmd);
        self.transmit_encoded(&cmd.encode(), Some(cmd))
    }

    /// Envía una APDU ya codificada (p. ej. protegida con mensajería segura).
    pub fn transmit_bytes(&mut self, apdu: &[u8]) -> Result<ResponseApdu, DnieError> {
        tracing::trace!(target: "afirma_dnie::apdu", "> {}", hex::encode_upper(apdu));
        self.transmit_encoded(apdu, None)
    }

    fn transmit_encoded(&mut self, apdu: &[u8], cmd: Option<&CommandApdu>) -> Result<ResponseApdu, DnieError> {
        let max = self.transport.max_command_len().clamp(16, 255);
        let mut resp = if apdu.len() > max {
            self.envelope(apdu, max)?
        } else {
            self.raw(apdu)?
        };
        let mut rounds = 0;
        let mut acc: Vec<u8> = Vec::new();
        loop {
            rounds += 1;
            if rounds > MAX_CHAINED {
                return Err(DnieError::Read(
                    "Demasiadas respuestas encadenadas de la tarjeta".into(),
                ));
            }
            match resp.sw1() {
                0x61 => {
                    // GET RESPONSE en claro; se acumulan los datos parciales.
                    acc.extend_from_slice(&resp.data);
                    let n = resp.sw2();
                    let get = CommandApdu::new(0x00, 0xC0, 0x00, 0x00).with_le(if n == 0 { 256 } else { n as usize });
                    resp = self.raw(&get.encode())?;
                }
                0x6C if apdu.first() == Some(&0x00) => {
                    // Le incorrecto: se reenvía el mismo comando con Le = SW2 (solo en claro).
                    let mut c = match cmd {
                        Some(c) => c.clone(),
                        None => CommandApdu::parse(apdu)?,
                    };
                    let n = resp.sw2();
                    c.set_le(Some(if n == 0 { 256 } else { n as usize }));
                    resp = self.raw(&c.encode())?;
                }
                _ => break,
            }
        }
        if !acc.is_empty() {
            acc.extend_from_slice(&resp.data);
            resp.data = acc;
        }
        Ok(resp)
    }

    /// Comando propietario «ENVELOPE» del DNIe (`90 C2 00 00 Lc bloque`) para APDU de más de
    /// `max` octetos (§2.3; no se usa en el flujo de firma).
    fn envelope(&mut self, apdu: &[u8], max: usize) -> Result<ResponseApdu, DnieError> {
        let chunk = max - 5;
        let mut last = None;
        let parts: Vec<&[u8]> = apdu.chunks(chunk).collect();
        for (i, part) in parts.iter().enumerate() {
            let env = CommandApdu::new(0x90, 0xC2, 0x00, 0x00)
                .with_data(part.to_vec())
                .encode();
            let r = self.raw(&env)?;
            if i + 1 < parts.len() && !r.is_ok() {
                return Ok(r);
            }
            last = Some(r);
        }
        last.ok_or_else(|| DnieError::Read("APDU vacía".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Transporte de pruebas con respuestas programadas.
    struct Script {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
        max: usize,
    }

    impl CardTransport for Script {
        fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.sent.push(apdu.to_vec());
            self.replies
                .pop_front()
                .ok_or_else(|| TransportError::TagLost("sin respuesta".into()))
        }
        fn max_command_len(&self) -> usize {
            self.max
        }
    }

    fn script(replies: &[&str], max: usize) -> Link<Script> {
        Link::new(Script {
            sent: Vec::new(),
            replies: replies.iter().map(|r| hex::decode(r).unwrap()).collect(),
            max,
        })
    }

    #[test]
    fn get_response_chain() {
        let mut l = script(&["01026103", "0304056102", "07089000"], 255);
        let r = l.transmit(&CommandApdu::new(0, 0xB0, 0, 0)).unwrap();
        assert_eq!(r.data, vec![1, 2, 3, 4, 5, 7, 8]);
        assert!(r.is_ok());
        assert_eq!(l.transport.sent[1], hex::decode("00C0000003").unwrap());
        assert_eq!(l.transport.sent[2], hex::decode("00C0000002").unwrap());
        assert_eq!(l.apdu_count(), 3);
    }

    #[test]
    fn wrong_le_resend_only_in_clear() {
        let mut l = script(&["6C10", "AA9000"], 255);
        let r = l.transmit(&CommandApdu::new(0, 0xB0, 0, 0).with_le(0xDE)).unwrap();
        assert_eq!(r.data, vec![0xAA]);
        assert_eq!(l.transport.sent[1], hex::decode("00B0000010").unwrap());
        // Con CLA distinta de 00 (p. ej. protegida) no se reintenta.
        let mut l = script(&["6C10"], 255);
        let r = l.transmit_bytes(&hex::decode("0CB0000000").unwrap()).unwrap();
        assert_eq!(r.sw, 0x6C10);
    }

    #[test]
    fn envelope_splits_long_commands() {
        let cmd = CommandApdu::new(0, 0x2A, 0, 0xAE).with_data(vec![0x55; 300]);
        let mut l = script(&["9000", "9000"], 255);
        let r = l.transmit(&cmd).unwrap();
        assert!(r.is_ok());
        let enc = cmd.encode();
        assert_eq!(l.transport.sent.len(), 2);
        assert_eq!(&l.transport.sent[0][..5], &[0x90, 0xC2, 0, 0, 250]);
        assert_eq!(&l.transport.sent[0][5..], &enc[..250]);
        assert_eq!(&l.transport.sent[1][5..], &enc[250..]);
        // Un bloque intermedio rechazado devuelve esa respuesta.
        let mut l = script(&["6A80"], 255);
        assert_eq!(l.transmit(&cmd).unwrap().sw, 0x6A80);
    }

    #[test]
    fn transport_error_propagates() {
        let mut l = script(&[], 255);
        assert!(matches!(
            l.transmit(&CommandApdu::new(0, 0xA4, 0, 0)),
            Err(DnieError::Transport(TransportError::TagLost(_)))
        ));
    }
}
