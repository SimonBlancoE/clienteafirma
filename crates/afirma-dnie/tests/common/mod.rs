//! Utilidades comunes de las pruebas de integración.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Mutex;

use afirma_dnie::interaction::{CanRequest, DnieInteraction, PinRequest, SignatureRequest};
use afirma_dnie::sim::SimCard;
use afirma_dnie::{Cancelled, DnieError};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use zeroize::Zeroizing;

pub const CAN: &str = "123456";
pub const PIN: &str = "1234abcd";

/// Directorio de datos del simulador (el mismo que usa el oráculo Java).
pub fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/oracle/dnie/data")
}

pub fn sim(seed: u64) -> SimCard {
    let mut s = SimCard::from_dir(data_dir(), seed).expect("datos del simulador");
    s.record_transcript();
    s
}

/// Interacción que registra las peticiones y responde con valores fijos (o cancela).
pub struct Recorder {
    pub can: Option<String>,
    pub pins: Mutex<Vec<String>>,
    pub pin_prompts: Mutex<Vec<String>>,
    pub can_requests: Mutex<usize>,
    pub confirm: bool,
}

impl Recorder {
    pub fn new(can: &str, pins: &[&str]) -> Self {
        Recorder {
            can: Some(can.to_string()),
            pins: Mutex::new(pins.iter().rev().map(|s| s.to_string()).collect()),
            pin_prompts: Mutex::new(Vec::new()),
            can_requests: Mutex::new(0),
            confirm: true,
        }
    }

    pub fn prompts(&self) -> Vec<String> {
        self.pin_prompts.lock().unwrap().clone()
    }
}

impl DnieInteraction for Recorder {
    fn request_can(&self, _request: &CanRequest) -> Result<Zeroizing<String>, Cancelled> {
        *self.can_requests.lock().unwrap() += 1;
        self.can.clone().map(Zeroizing::new).ok_or(Cancelled)
    }

    fn request_pin(&self, request: &PinRequest) -> Result<Zeroizing<String>, Cancelled> {
        self.pin_prompts.lock().unwrap().push(request.prompt());
        let mut pins = self.pins.lock().unwrap();
        let pin = if pins.len() > 1 {
            pins.pop()
        } else {
            pins.last().cloned()
        };
        pin.map(Zeroizing::new).ok_or(Cancelled)
    }

    fn confirm_signature(&self, _request: &SignatureRequest) -> Result<bool, Cancelled> {
        Ok(self.confirm)
    }
}

/// Verificación RSA PKCS#1 v1.5 «a mano» (independiente de la del controlador): `s^e mod n`
/// debe ser `00 01 FF… 00 ‖ DigestInfo`.
pub fn verify_pkcs1(key: &RsaPublicKey, digest_info: &[u8], sig: &[u8]) -> bool {
    let k = key.n().bits().div_ceil(8);
    if sig.len() != k {
        return false;
    }
    let m = BigUint::from_bytes_be(sig).modpow(key.e(), key.n()).to_bytes_be();
    let mut em = vec![0u8; k - m.len()];
    em.extend_from_slice(&m);
    let ps_end = k - digest_info.len() - 1;
    em[0] == 0
        && em[1] == 1
        && em[2..ps_end].iter().all(|b| *b == 0xFF)
        && em[ps_end] == 0
        && &em[ps_end + 1..] == digest_info
}

pub fn assert_category(e: &DnieError, cat: afirma_dnie::ErrorCategory) {
    assert_eq!(e.category(), cat, "{e:?}");
}

/// Paso de una transcripción normalizado para comparar el Rust con JMulticard: contexto de SM,
/// comando interno (con los aleatorios enmascarados), longitudes en el aire y SW interna.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub context: String,
    pub inner: String,
    pub cmd_len: usize,
    pub rsp_len: usize,
    pub inner_sw: Option<u16>,
}

/// Enmascara lo que depende de los aleatorios: claves efímeras y tokens de PACE (GA2–GA4),
/// `RND.IFD` de INTERNAL AUTHENTICATE y el criptograma de EXTERNAL AUTHENTICATE.
pub fn mask_inner(inner: &[u8]) -> String {
    let h = hex::encode_upper(inner);
    match inner.get(1) {
        Some(0x86) if inner.len() > 9 => format!("{}…[{}]", &h[..18], inner.len()),
        Some(0x88) if inner.len() >= 13 => format!("{}XXXXXXXXXXXXXXXX{}", &h[..10], &h[26..]),
        Some(0x82) if inner.len() > 5 => format!("{}…[{}]", &h[..10], inner.len()),
        _ => h,
    }
}

/// Analiza una transcripción del oráculo Java (`testdata/dnie/transcript_*.txt` o la del modo
/// `serve`): devuelve `(número de APDU, paso)`.
pub fn parse_java_transcript(text: &str) -> Vec<(usize, Step)> {
    let mut out: Vec<(usize, Step)> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("> C-APDU #") {
            let n: usize = rest.split(' ').next().unwrap().parse().unwrap();
            let len: usize = rest
                .split('[')
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let ctx = rest
                .split("activo: ")
                .nth(1)
                .unwrap()
                .split(')')
                .next()
                .unwrap()
                .to_string();
            let cmd = hex::decode(rest.rsplit(' ').next().unwrap()).unwrap();
            out.push((
                n,
                Step {
                    context: ctx,
                    inner: mask_inner(&cmd),
                    cmd_len: len,
                    rsp_len: 0,
                    inner_sw: None,
                },
            ));
        } else if l.contains("comando interno:") {
            let h = l.rsplit('[').next().unwrap().trim_end_matches(']');
            out.last_mut().unwrap().1.inner = mask_inner(&hex::decode(h).unwrap());
        } else if let Some(r) = l.strip_prefix("respuesta interna:") {
            let sw = r.rsplit("SW=").next().unwrap();
            out.last_mut().unwrap().1.inner_sw = Some(u16::from_str_radix(sw.trim(), 16).unwrap());
        } else if let Some(r) = l.strip_prefix("< R-APDU [") {
            let len: usize = r.split(' ').next().unwrap().parse().unwrap();
            let hexr = r.rsplit(' ').next().unwrap();
            let step = &mut out.last_mut().unwrap().1;
            step.rsp_len = len;
            if step.inner_sw.is_none() {
                step.inner_sw = Some(u16::from_str_radix(&hexr[hexr.len() - 4..], 16).unwrap());
            }
        }
    }
    out
}

/// Pasos de la transcripción del simulador Rust.
pub fn steps_from_sim(t: &[afirma_dnie::sim::TranscriptEntry]) -> Vec<Step> {
    t.iter()
        .map(|e| Step {
            context: e.context.to_string(),
            inner: mask_inner(e.inner.as_deref().unwrap_or(&e.command)),
            cmd_len: e.command.len(),
            rsp_len: e.response.len(),
            inner_sw: e.inner_sw,
        })
        .collect()
}

/// Transcripción de referencia de JMulticard (`testdata/dnie/<nombre>`) sin las APDU indicadas.
pub fn reference(name: &str, skip: std::ops::RangeInclusive<usize>) -> Vec<Step> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/dnie")
        .join(name);
    parse_java_transcript(&std::fs::read_to_string(path).unwrap())
        .into_iter()
        .filter(|(n, _)| !skip.contains(n))
        .map(|(_, s)| s)
        .collect()
}

/// `transcript_full.txt` (carga, firma 1 y firma 2) sin las APDU 57–59, que son una segunda
/// lectura del IDESP hecha por el propio arnés Java (`card.getIdesp()` al registrar la tarjeta),
/// no por JMulticard.
pub fn reference_full() -> Vec<Step> {
    reference("transcript_full.txt", 57..=59)
}

/// Compara dos secuencias de pasos e informa de la primera diferencia.
pub fn assert_same_steps(ours: &[Step], reference: &[Step]) {
    for (i, (a, b)) in ours.iter().zip(reference).enumerate() {
        assert_eq!(a, b, "APDU {} distinta (Rust / JMulticard)", i + 1);
    }
    assert_eq!(ours.len(), reference.len(), "número de APDU");
}
