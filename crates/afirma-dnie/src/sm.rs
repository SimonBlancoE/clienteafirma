//! Mensajería segura: la de PACE (AES-128, CMAC de 8 octetos, SSC de 16 octetos; §5) y la de
//! los canales CWA-14890 del DNIe (3DES de dos claves, MAC «retail» de 8 octetos, SSC de 8
//! octetos; §6.4).
//!
//! Cada contexto protege comandos en claro y desprotege respuestas; la elección de qué contexto
//! está activo (uno solo a la vez, §0.2) la hace [`crate::session`].

use zeroize::{Zeroize, Zeroizing};

use crate::apdu::{CommandApdu, ResponseApdu, sw};
use crate::crypto::{self, Key16};
use crate::error::DnieError;
use crate::tlv;

fn increment(ssc: &mut [u8]) {
    for b in ssc.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// DO97 con el Le esperado (1 octeto; 256 se codifica `00`; extendido con 2 octetos).
fn do97(le: usize) -> Vec<u8> {
    if le <= 256 {
        vec![0x97, 0x01, if le == 256 { 0 } else { le as u8 }]
    } else {
        let v = if le >= 65536 { 0 } else { le as u16 };
        let b = v.to_be_bytes();
        vec![0x97, 0x02, b[0], b[1]]
    }
}

/// Objetos de una respuesta protegida.
struct RespObjects<'a> {
    /// Objetos cubiertos por el MAC (`85`, `87`, `99`), en el orden recibido.
    maced: Vec<u8>,
    do87: Option<&'a [u8]>,
    do99: Option<&'a [u8]>,
    do8e: Option<&'a [u8]>,
}

fn split_response(data: &[u8]) -> Result<RespObjects<'_>, DnieError> {
    let mut r = RespObjects {
        maced: Vec::new(),
        do87: None,
        do99: None,
        do8e: None,
    };
    for t in tlv::parse_all(data).map_err(|e| DnieError::SecureMessaging(format!("Respuesta protegida: {e}")))? {
        match t.tag {
            0x87 => {
                r.maced.extend_from_slice(t.raw);
                r.do87 = Some(t.value);
            }
            0x85 => r.maced.extend_from_slice(t.raw),
            0x99 => {
                r.maced.extend_from_slice(t.raw);
                r.do99 = Some(t.value);
            }
            0x8E => r.do8e = Some(t.value),
            other => tracing::warn!("Objeto de mensajería segura desconocido en la respuesta: {other:02X}"),
        }
    }
    Ok(r)
}

fn inner_sw(do99: &[u8]) -> Result<u16, DnieError> {
    if do99.len() != 2 {
        return Err(DnieError::SecureMessaging("DO99 con longitud distinta de 2".into()));
    }
    Ok(u16::from_be_bytes([do99[0], do99[1]]))
}

/// Contexto de mensajería segura de PACE (ICAO 9303-11 §9.8).
pub struct PaceSm {
    kenc: Key16,
    kmac: Key16,
    ssc: [u8; 16],
}

impl Drop for PaceSm {
    fn drop(&mut self) {
        self.ssc.zeroize();
    }
}

impl PaceSm {
    /// Contexto recién negociado (SSC a cero).
    pub fn new(kenc: Key16, kmac: Key16) -> Self {
        PaceSm {
            kenc,
            kmac,
            ssc: [0; 16],
        }
    }

    /// Contexto con un SSC inicial dado (antes del primer incremento).
    pub fn with_ssc(kenc: Key16, kmac: Key16, ssc: [u8; 16]) -> Self {
        PaceSm { kenc, kmac, ssc }
    }

    pub fn ssc(&self) -> [u8; 16] {
        self.ssc
    }

    fn iv(&self) -> [u8; 16] {
        crypto::aes_ecb_encrypt(&self.kenc, &self.ssc)
    }

    fn mac(&self, input: &[u8]) -> [u8; 8] {
        let mut n = Vec::with_capacity(16 + input.len());
        n.extend_from_slice(&self.ssc);
        n.extend_from_slice(input);
        crypto::aes_cmac8(&self.kmac, &crypto::pad(&n, 16))
    }

    /// Protege un comando: `CLA|0C INS P1 P2 Lc DO87 DO97 DO8E 00` (§5.2). El MAC de los
    /// comandos sin datos ni Le es el de ICAO (`pad(SSC ‖ pad(cabecera))`), no la variante de
    /// JMulticard (defecto P6).
    pub fn wrap(&mut self, cmd: &CommandApdu) -> Result<Vec<u8>, DnieError> {
        increment(&mut self.ssc);
        let hdr = [cmd.cla | 0x0C, cmd.ins, cmd.p1, cmd.p2];
        let mut body = Vec::new();
        if !cmd.data().is_empty() {
            let padded = Zeroizing::new(crypto::pad(cmd.data(), 16));
            let ct = crypto::aes_cbc_encrypt(&self.kenc, &self.iv(), &padded)?;
            let mut v = Vec::with_capacity(ct.len() + 1);
            v.push(0x01);
            v.extend_from_slice(&ct);
            body.extend_from_slice(&tlv::encode(0x87, &v));
        }
        if let Some(le) = cmd.le() {
            body.extend_from_slice(&do97(le));
        }
        let mut m = crypto::pad(&hdr, 16);
        m.extend_from_slice(&body);
        let mac = self.mac(&m);
        body.extend_from_slice(&[0x8E, 0x08]);
        body.extend_from_slice(&mac);
        let le = if body.len() > 255 { 65536 } else { 256 };
        Ok(CommandApdu::new(hdr[0], hdr[1], hdr[2], hdr[3])
            .with_data(body)
            .with_le(le)
            .encode())
    }

    /// Desprotege una respuesta (§5.3). Si la SW externa no es `9000` ni `6282` la tarjeta no
    /// ha protegido la respuesta (p. ej. `6987`/`6988`: ha descartado el contexto) y se
    /// devuelve un error.
    pub fn unwrap(&mut self, resp: &ResponseApdu) -> Result<ResponseApdu, DnieError> {
        if resp.sw != sw::OK && resp.sw != sw::END_OF_FILE {
            return Err(DnieError::SecureMessaging(format!(
                "La tarjeta ha respondido {:04X} sin mensajería segura",
                resp.sw
            )));
        }
        increment(&mut self.ssc);
        let objs = split_response(&resp.data)?;
        let (Some(do99), Some(do8e)) = (objs.do99, objs.do8e) else {
            return Err(DnieError::SecureMessaging(
                "Faltan los objetos DO99 o DO8E en la respuesta protegida".into(),
            ));
        };
        if !crypto::ct_eq(&self.mac(&objs.maced), do8e) {
            return Err(DnieError::SecureMessaging(
                "Suma de control (MAC) incorrecta en la respuesta PACE".into(),
            ));
        }
        let status = inner_sw(do99)?;
        let data = match objs.do87 {
            Some(v) => {
                if v.first() != Some(&0x01) {
                    return Err(DnieError::SecureMessaging("DO87 sin indicador de relleno 01".into()));
                }
                let pt = crypto::aes_cbc_decrypt(&self.kenc, &self.iv(), &v[1..])?;
                crypto::unpad(&pt)?.to_vec()
            }
            None => Vec::new(),
        };
        Ok(ResponseApdu::new(data, status))
    }
}

/// Contexto de mensajería segura de un canal CWA-14890 v2 (MAC de 8 octetos).
pub struct CwaSm {
    kenc: Key16,
    kmac: Key16,
    ssc: [u8; 8],
}

impl Drop for CwaSm {
    fn drop(&mut self) {
        self.ssc.zeroize();
    }
}

impl CwaSm {
    /// Contexto con el SSC inicial `RND.ICC[4..8] ‖ RND.IFD[4..8]` (antes del primer incremento).
    pub fn new(kenc: Key16, kmac: Key16, ssc: [u8; 8]) -> Self {
        CwaSm { kenc, kmac, ssc }
    }

    pub fn ssc(&self) -> [u8; 8] {
        self.ssc
    }

    /// Protege un comando: `CLA|0C INS P1 P2 Lc DO87 DO97 DO8E`, **sin Le** (§6.4).
    pub fn wrap(&mut self, cmd: &CommandApdu) -> Result<Vec<u8>, DnieError> {
        increment(&mut self.ssc);
        let hdr = [cmd.cla | 0x0C, cmd.ins, cmd.p1, cmd.p2];
        let mut body = Vec::new();
        if !cmd.data().is_empty() {
            let padded = Zeroizing::new(crypto::pad(cmd.data(), 8));
            let ct = crypto::tdes_cbc_encrypt(&self.kenc, &padded)?;
            let mut v = Vec::with_capacity(ct.len() + 1);
            v.push(0x01);
            v.extend_from_slice(&ct);
            body.extend_from_slice(&tlv::encode(0x87, &v));
        }
        if let Some(le) = cmd.le() {
            body.extend_from_slice(&do97(le));
        }
        let mut m = crypto::pad(&hdr, 8);
        m.extend_from_slice(&body);
        let mac = crypto::retail_mac(&self.kmac, &self.ssc, &crypto::pad(&m, 8))?;
        body.extend_from_slice(&[0x8E, 0x08]);
        body.extend_from_slice(&mac);
        Ok(CommandApdu::new(hdr[0], hdr[1], hdr[2], hdr[3])
            .with_data(body)
            .encode())
    }

    /// Desprotege una respuesta (§6.4). El SSC se incrementa siempre. Si la SW externa no es
    /// `9000` y la respuesta no trae objetos de mensajería segura se devuelve esa SW tal cual
    /// (paridad con JMulticard); si los trae, se verifican y se devuelve la SW interna.
    pub fn unwrap(&mut self, resp: &ResponseApdu) -> Result<ResponseApdu, DnieError> {
        increment(&mut self.ssc);
        if resp.sw == sw::BAD_CHECKSUM {
            return Err(DnieError::SecureMessaging(
                "La tarjeta indica suma de control criptográfica incorrecta (6688)".into(),
            ));
        }
        if resp.sw != sw::OK && resp.data.is_empty() {
            return Ok(ResponseApdu::status(resp.sw));
        }
        let objs = split_response(&resp.data)?;
        let (Some(do99), Some(do8e)) = (objs.do99, objs.do8e) else {
            return Err(DnieError::SecureMessaging(
                "Faltan los objetos DO99 o DO8E en la respuesta protegida".into(),
            ));
        };
        let mac = crypto::retail_mac(&self.kmac, &self.ssc, &crypto::pad(&objs.maced, 8))?;
        if !crypto::ct_eq(&mac, do8e) {
            return Err(DnieError::SecureMessaging(
                "Suma de control (MAC) incorrecta en la respuesta del canal seguro".into(),
            ));
        }
        let status = inner_sw(do99)?;
        let data = match objs.do87 {
            Some(v) => {
                if v.first() != Some(&0x01) {
                    return Err(DnieError::SecureMessaging("DO87 sin indicador de relleno 01".into()));
                }
                let pt = crypto::tdes_cbc_decrypt(&self.kenc, &v[1..])?;
                crypto::unpad(&pt)?.to_vec()
            }
            None => Vec::new(),
        };
        Ok(ResponseApdu::new(data, status))
    }
}

/// Lado tarjeta de la mensajería segura (simulador): desprotege comandos y protege
/// respuestas con el mismo formato.
#[cfg(any(test, feature = "sim"))]
pub(crate) mod card_side {
    use super::*;

    /// Comando desprotegido.
    pub struct Unwrapped {
        pub cmd: CommandApdu,
    }

    /// Objetos de un comando protegido: los cubiertos por el MAC, DO87, Le de DO97 y DO8E.
    struct CmdObjects<'a> {
        maced: Vec<u8>,
        do87: Option<&'a [u8]>,
        le: Option<usize>,
        mac: &'a [u8],
    }

    fn parse_cmd_objects(apdu: &CommandApdu) -> Result<CmdObjects<'_>, String> {
        let mut maced = Vec::new();
        let mut do87 = None;
        let mut le = None;
        let mut mac = None;
        for t in tlv::parse_all(apdu.data()).map_err(|e| e.to_string())? {
            match t.tag {
                0x87 => {
                    maced.extend_from_slice(t.raw);
                    do87 = Some(t.value);
                }
                0x97 => {
                    maced.extend_from_slice(t.raw);
                    le = Some(match t.value {
                        [0] => 256,
                        [b] => *b as usize,
                        [0, 0] => 65536,
                        [h, l] => u16::from_be_bytes([*h, *l]) as usize,
                        _ => return Err("DO97 no válido".into()),
                    });
                }
                0x8E => mac = Some(t.value),
                other => return Err(format!("objeto {other:02X} inesperado")),
            }
        }
        let mac = mac.ok_or("Falta DO8E")?;
        Ok(CmdObjects { maced, do87, le, mac })
    }

    impl PaceSm {
        /// Desprotege un comando recibido (verificador ICAO estricto).
        pub fn card_unwrap_command(&mut self, apdu: &CommandApdu) -> Result<Unwrapped, String> {
            increment(&mut self.ssc);
            let CmdObjects { maced, do87, le, mac } = parse_cmd_objects(apdu)?;
            let mut m = crypto::pad(&apdu.header(), 16);
            m.extend_from_slice(&maced);
            if !crypto::ct_eq(&self.mac(&m), mac) {
                return Err("MAC PACE incorrecto".into());
            }
            let mut cmd = CommandApdu::new(apdu.cla & 0xF3, apdu.ins, apdu.p1, apdu.p2);
            if let Some(v) = do87 {
                if v.first() != Some(&1) {
                    return Err("DO87 sin indicador 01".into());
                }
                let pt = crypto::aes_cbc_decrypt(&self.kenc, &self.iv(), &v[1..]).map_err(|e| e.to_string())?;
                cmd = cmd.with_data(crypto::unpad(&pt).map_err(|e| e.to_string())?.to_vec());
            }
            if let Some(le) = le {
                cmd = cmd.with_le(le);
            }
            Ok(Unwrapped { cmd })
        }

        /// Protege una respuesta (SW externa `9000`).
        pub fn card_wrap_response(&mut self, data: &[u8], status: u16) -> Vec<u8> {
            increment(&mut self.ssc);
            let mut objs = Vec::new();
            if !data.is_empty() {
                let ct = crypto::aes_cbc_encrypt(&self.kenc, &self.iv(), &crypto::pad(data, 16)).expect("alineado");
                let mut v = vec![1u8];
                v.extend_from_slice(&ct);
                objs.extend_from_slice(&tlv::encode(0x87, &v));
            }
            objs.extend_from_slice(&tlv::encode(0x99, &status.to_be_bytes()));
            let mac = self.mac(&objs);
            objs.extend_from_slice(&tlv::encode(0x8E, &mac));
            objs.extend_from_slice(&sw::OK.to_be_bytes());
            objs
        }
    }

    impl CwaSm {
        /// Desprotege un comando recibido.
        pub fn card_unwrap_command(&mut self, apdu: &CommandApdu) -> Result<Unwrapped, String> {
            increment(&mut self.ssc);
            let CmdObjects { maced, do87, le, mac } = parse_cmd_objects(apdu)?;
            let mut m = crypto::pad(&apdu.header(), 8);
            m.extend_from_slice(&maced);
            let expected = crypto::retail_mac(&self.kmac, &self.ssc, &crypto::pad(&m, 8)).map_err(|e| e.to_string())?;
            if !crypto::ct_eq(&expected, mac) {
                return Err("MAC CWA incorrecto".into());
            }
            let mut cmd = CommandApdu::new(apdu.cla & 0xF3, apdu.ins, apdu.p1, apdu.p2);
            if let Some(v) = do87 {
                if v.first() != Some(&1) {
                    return Err("DO87 sin indicador 01".into());
                }
                let pt = crypto::tdes_cbc_decrypt(&self.kenc, &v[1..]).map_err(|e| e.to_string())?;
                cmd = cmd.with_data(crypto::unpad(&pt).map_err(|e| e.to_string())?.to_vec());
            }
            if let Some(le) = le {
                cmd = cmd.with_le(le);
            }
            Ok(Unwrapped { cmd })
        }

        /// Protege una respuesta; `outer` es la SW externa (`9000` o, en el modo «SW externa =
        /// interna» del simulador, la propia SW interna).
        pub fn card_wrap_response(&mut self, data: &[u8], status: u16, outer: u16) -> Vec<u8> {
            increment(&mut self.ssc);
            let mut objs = Vec::new();
            if !data.is_empty() {
                let ct = crypto::tdes_cbc_encrypt(&self.kenc, &crypto::pad(data, 8)).expect("alineado");
                let mut v = vec![1u8];
                v.extend_from_slice(&ct);
                objs.extend_from_slice(&tlv::encode(0x87, &v));
            }
            objs.extend_from_slice(&tlv::encode(0x99, &status.to_be_bytes()));
            let mac = crypto::retail_mac(&self.kmac, &self.ssc, &crypto::pad(&objs, 8)).expect("alineado");
            objs.extend_from_slice(&tlv::encode(0x8E, &mac));
            objs.extend_from_slice(&outer.to_be_bytes());
            objs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    fn key(s: &str) -> Key16 {
        Zeroizing::new(hx(s).try_into().unwrap())
    }

    fn minus_one<const N: usize>(s: &str) -> [u8; N] {
        let mut v: [u8; N] = hx(s).try_into().unwrap();
        for b in v.iter_mut().rev() {
            let (r, borrow) = b.overflowing_sub(1);
            *b = r;
            if !borrow {
                break;
            }
        }
        v
    }

    fn resp(s: &str) -> ResponseApdu {
        ResponseApdu::parse(&hx(s)).unwrap()
    }

    fn select_mf() -> CommandApdu {
        CommandApdu::new(0, 0xA4, 4, 0).with_data(b"Master.File".to_vec())
    }

    #[test]
    fn pace_vector_jmulticard_test() {
        // §5.4 a (TestApduEncrypter): SSC ya incrementado = 3DE0…2F60.
        let mut sm = PaceSm::with_ssc(
            key("F1B0D6449CEC48864C1EFABB4957D64B"),
            key("1665A3ADCB579053CC5D908720CE4DC1"),
            minus_one("3DE0C9658F836888BD352DBF46462F60"),
        );
        assert_eq!(
            sm.wrap(&select_mf()).unwrap(),
            hx("0CA404001D 871101F5124EE2F53962E86E66A6D234827F0F 8E0870E6DE5F679AEE64 00")
        );
    }

    fn pace_46() -> PaceSm {
        PaceSm::new(
            key("F5F0E35C0D7161EE6724EE513A0D9A7F"),
            key("FE251C7858B356B24514B3BD5F4297D1"),
        )
    }

    #[test]
    fn pace_session_vector() {
        // §5.4 b: continuación del vector PACE con CAN de §4.6.
        let mut sm = pace_46();
        assert_eq!(
            sm.wrap(&select_mf()).unwrap(),
            hx("0CA404001D8711011D75C8363A14ACA516C1DE24B08357668E0847E2D5CE090F139600")
        );
        let r = sm.unwrap(&resp("990290008E08BEA7B381C494A079 9000")).unwrap();
        assert_eq!((r.data.len(), r.sw), (0, 0x9000));
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0xA4, 0, 0).with_data(vec![0x00, 0x06]))
                .unwrap(),
            hx("0CA400001D871101EDF0D12A625FDCC8BAAFFF47F06BFFB58E085423DE9AFCFE57A400")
        );
        let r = sm
            .unwrap(&resp(
                "871101DC00E0BE4FD2B2585F464E60FE835AB1 99029000 8E08457F9F7BD3C1BA11 9000",
            ))
            .unwrap();
        assert_eq!(r.data, hx("6F048102000A"));
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0xB0, 0, 0).with_le(0x0A)).unwrap(),
            hx("0CB000000D97010A8E082BBCA7B0F1532FDB00")
        );
        let r = sm
            .unwrap(&resp(
                "871101D76C448EFA497EEAE097326CB7DF137E 99029000 8E084D849DFCF0B2CCB5 9000",
            ))
            .unwrap();
        assert_eq!(r.data, b"BMP100002\0");
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0xB0, 0, 0).with_le(0xDE)).unwrap(),
            hx("0CB000000D9701DE8E08764D4C914F41831000")
        );
        assert_eq!(sm.ssc()[15], 7);
    }

    #[test]
    fn pace_case1_icao_vs_jmulticard() {
        // §5.2, defecto P6: con las claves de §4.6 y SSC = 8, `00 44 00 00`. JMulticard calcula
        // el MAC sin rellenar la cabecera (AAAD79CE7FBB6E52); aquí se usa la variante ICAO.
        let mut sm = PaceSm::with_ssc(
            key("F5F0E35C0D7161EE6724EE513A0D9A7F"),
            key("FE251C7858B356B24514B3BD5F4297D1"),
            minus_one("00000000000000000000000000000008"),
        );
        let w = sm.wrap(&CommandApdu::new(0, 0x44, 0, 0)).unwrap();
        assert_eq!(w, hx("0C4400000A8E087BC479A4BC34946800"));
        assert_ne!(&w[7..15], &hx("AAAD79CE7FBB6E52")[..]);
    }

    #[test]
    fn pace_errors() {
        let mut sm = pace_46();
        sm.wrap(&select_mf()).unwrap();
        // SW externa de error: no se desprotege y queda señalado.
        assert!(matches!(sm.unwrap(&resp("6987")), Err(DnieError::SecureMessaging(_))));
        // MAC alterado.
        let mut sm = pace_46();
        sm.wrap(&select_mf()).unwrap();
        assert!(sm.unwrap(&resp("990290008E08BEA7B381C494A078 9000")).is_err());
        // Sin DO8E.
        let mut sm = pace_46();
        sm.wrap(&select_mf()).unwrap();
        assert!(sm.unwrap(&resp("99029000 9000")).is_err());
        // Relleno incorrecto: se cifra un bloque sin 80 y se protege con el lado tarjeta.
        let mut card = pace_46();
        let mut host = pace_46();
        let w = host.wrap(&select_mf()).unwrap();
        card.card_unwrap_command(&CommandApdu::parse(&w).unwrap()).unwrap();
        increment(&mut card.ssc);
        let ct = crypto::aes_cbc_encrypt(&card.kenc, &card.iv(), &[0x11; 16]).unwrap();
        let mut objs = tlv::encode(0x87, &[&[1u8][..], &ct].concat());
        objs.extend_from_slice(&tlv::encode(0x99, &[0x90, 0]));
        let mac = card.mac(&objs);
        objs.extend_from_slice(&tlv::encode(0x8E, &mac));
        objs.extend_from_slice(&[0x90, 0]);
        let e = host.unwrap(&ResponseApdu::parse(&objs).unwrap()).unwrap_err();
        assert!(e.to_string().contains("Relleno"), "{e}");
    }

    #[test]
    fn ssc_overflow_wraps() {
        let mut s = [0xFF; 16];
        increment(&mut s);
        assert_eq!(s, [0; 16]);
        let mut s = [0, 0xFF];
        increment(&mut s);
        assert_eq!(s, [1, 0]);
    }

    fn cwa() -> (Key16, Key16) {
        (
            key("598F26E36E11A8EC14B81E19BDA223CA"),
            key("5DE2939A1EA03A930B88206D8F73E8A7"),
        )
    }

    #[test]
    fn cwa_vectors() {
        // §6.4 (TestApduEncrypter con MAC de 8 octetos).
        let (e, m) = cwa();
        let mut sm = CwaSm::new(e, m, minus_one("D31AC8EC7BA0FE6F"));
        let verify = CommandApdu::new(0, 0x20, 0, 0).with_data(b"CRYPTOKI".to_vec());
        assert_eq!(
            sm.wrap(&verify).unwrap(),
            hx("0C2000001D 871101CE1AB937C332F3FAEE43336D4311EF33 8E086908DF4E6EB3CEAE")
        );
        let (e, m) = cwa();
        let mut sm = CwaSm::new(e, m, minus_one("D31AC8EC7BA0FE70"));
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0x20, 0, 0).with_le(256)).unwrap(),
            hx("0C2000000D 970100 8E08BE9DF8CB9EC57B9D")
        );
        let (e, m) = cwa();
        let mut sm = CwaSm::new(e, m, minus_one("D31AC8EC7BA0FE72"));
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0x22, 0x41, 0xB6).with_data(hx("84020102")))
                .unwrap(),
            hx("0C2241B615 870901E09FC9BCFA520CF8 8E08FF5D2104F58149D1")
        );
    }

    #[test]
    fn cwa_icao_bac_example() {
        // ICAO 9303-11, BAC: SELECT EF.COM y su respuesta (§6.4).
        let mut sm = CwaSm::new(
            key("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            key("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            hx("887022120C06C226").try_into().unwrap(),
        );
        assert_eq!(
            sm.wrap(&CommandApdu::new(0, 0xA4, 0x02, 0x0C).with_data(hx("011E")))
                .unwrap(),
            hx("0CA4020C15 8709016375432908C044F6 8E08BF8B92D635FF24F8")
        );
        let r = sm.unwrap(&resp("99029000 8E08FA855A5D4C50A8ED 9000")).unwrap();
        assert_eq!(r.sw, 0x9000);
    }

    #[test]
    fn cwa_response_paths() {
        let (e, m) = cwa();
        let mut host = CwaSm::new(e, m, [1; 8]);
        let (e, m) = cwa();
        let mut card = CwaSm::new(e, m, [1; 8]);
        let cmd = CommandApdu::new(0, 0x2A, 0x9E, 0x9A).with_data(vec![0x30; 51]);
        let w = host.wrap(&cmd).unwrap();
        // Sin Le final: Lc ‖ cuerpo.
        assert_eq!(w.len(), 5 + w[4] as usize);
        let u = card.card_unwrap_command(&CommandApdu::parse(&w).unwrap()).unwrap();
        assert_eq!(u.cmd.data(), cmd.data());
        // Respuesta de 256 octetos: DO87 de 265 octetos (87 82 01 09) y 285 octetos en total.
        let sig = vec![0x5A; 256];
        let r = card.card_wrap_response(&sig, 0x9000, 0x9000);
        assert_eq!(r.len(), 285);
        assert_eq!(&r[..5], &[0x87, 0x82, 0x01, 0x09, 0x01]);
        let out = host.unwrap(&ResponseApdu::parse(&r).unwrap()).unwrap();
        assert_eq!((out.data, out.sw), (sig, 0x9000));
        // SW externa = interna (63C2 con objetos): se verifica y se devuelve la interna.
        host.wrap(&CommandApdu::new(0, 0x20, 0, 0).with_le(256)).unwrap();
        increment(&mut card.ssc);
        let r = card.card_wrap_response(&[], 0x63C2, 0x63C2);
        assert_eq!(host.unwrap(&ResponseApdu::parse(&r).unwrap()).unwrap().sw, 0x63C2);
        // SW externa sin objetos: se devuelve tal cual.
        host.wrap(&CommandApdu::new(0, 0x20, 0, 0).with_le(256)).unwrap();
        assert_eq!(host.unwrap(&resp("6983")).unwrap().sw, 0x6983);
        // Respuesta sin DO99 o con MAC erróneo.
        host.wrap(&CommandApdu::new(0, 0x20, 0, 0).with_le(256)).unwrap();
        assert!(host.unwrap(&resp("8E080102030405060708 9000")).is_err());
        assert!(matches!(host.unwrap(&resp("6688")), Err(DnieError::SecureMessaging(_))));
    }
}
