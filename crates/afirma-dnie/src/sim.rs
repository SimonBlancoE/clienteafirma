//! Simulador software de un DNIe 3.0/4.0 sin contacto (lado tarjeta).
//!
//! Puerto del simulador Java del oráculo (`tools/oracle/dnie/src/sim/SimCard.java`, que valida la
//! especificación contra JMulticard real) con los mismos datos (`tools/oracle/dnie/data`): CDF y
//! PrKDF del espécimen, certificados comprimidos y claves RSA de prueba generados, y las claves de
//! terminal reales de JMulticard para el canal CWA-14890. Modela (especificación 10 §14.3):
//!
//! - un único contexto de mensajería segura (`sin SM`, `PACE`, `CWA-PIN`, `CWA-USR`); cada canal
//!   nuevo se negocia dentro del actual y lo sustituye tras la respuesta;
//! - PACE ECDH-GM brainpoolP256r1 con el CAN (con CAN erróneo, `6300` en GA4);
//! - verificador ICAO estricto de la mensajería segura (MAC erróneo → `6988` y se descarta el
//!   contexto; APDU en claro con SM activo → `6987` y se descarta, que es lo que provoca el
//!   «reset» de JMulticard tras cada firma);
//! - sistema de ficheros, `GET CHIP INFO`, autenticación interna/externa CWA, intentos de PIN,
//!   `VERIFY` (3 intentos, bloqueo con `6983`) y firma PKCS#1 v1.5 con RSA-2048;
//! - inyección de fallos: retirada de la tarjeta, pérdida del contexto SM (`6987`), MAC alterado y
//!   respuestas troceadas con `61xx`.
//!
//! Es más estricto que el simulador Java en dos puntos (para comprobar las capas): `VERIFY` con
//! PIN solo se acepta en el canal de PIN y `PSO:CDS` solo en el canal de usuario.

use std::collections::BTreeMap;
use std::path::Path;

use rsa::BigUint;
use sha1::{Digest, Sha1};

use crate::apdu::{CommandApdu, ResponseApdu, sw};
use crate::crypto;
use crate::cwa::{self, CwaChannel, Terminal};
use crate::ec::{Point, Scalar};
use crate::error::{DnieError, TransportError};
use crate::pace;
use crate::rng::RandomSource;
use crate::sm::{CwaSm, PaceSm};
use crate::tlv;
use crate::transport::{CardIdentification, CardTransport};

/// Generador determinista del simulador (SplitMix64; no criptográfico, solo para pruebas).
#[derive(Debug, Clone)]
pub struct SimRng(u64);

impl SimRng {
    pub fn new(seed: u64) -> Self {
        SimRng(seed)
    }
}

impl RandomSource for SimRng {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), DnieError> {
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_be_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// Fallos inyectados (las APDU se numeran desde 1, como en las transcripciones).
#[derive(Debug, Clone, Default)]
pub struct Faults {
    /// A partir de esta APDU el enlace falla (tarjeta retirada).
    pub remove_at_apdu: Option<usize>,
    /// A esta APDU se responde `6987` en claro y se descarta el contexto de SM.
    pub drop_sm_at_apdu: Option<usize>,
    /// Se altera el MAC de la respuesta a esta APDU.
    pub corrupt_mac_at_apdu: Option<usize>,
}

/// Estadísticas.
#[derive(Debug, Clone, Default)]
pub struct SimStats {
    pub apdus: usize,
    pub max_command: usize,
    pub max_response: usize,
    pub envelope_used: bool,
    /// Sesiones PACE completadas.
    pub pace_sessions: usize,
    /// GA4 rechazados (`T_IFD` incorrecto).
    pub pace_failures: usize,
    /// Sesiones PACE en las que la X del secreto compartido empieza por `00`.
    pub kx_leading_zero: usize,
    /// La última sesión PACE tuvo X con `00` inicial.
    pub last_kx_leading_zero: bool,
    /// Comandos internos que volvían a llevar SM (doble envoltura; debe ser 0).
    pub nested_sm: usize,
    /// Comandos en claro recibidos con SM activo (cada «reset» tras una firma cuenta uno).
    pub plain_with_sm: usize,
    /// Firmas realizadas.
    pub signatures: usize,
}

/// Entrada de la transcripción.
#[derive(Debug, Clone)]
pub struct TranscriptEntry {
    /// APDU recibida (en el aire).
    pub command: Vec<u8>,
    /// Respuesta enviada (en el aire).
    pub response: Vec<u8>,
    /// Contexto de SM activo al recibirla.
    pub context: &'static str,
    /// Comando interno (desprotegido) si iba protegido.
    pub inner: Option<Vec<u8>>,
    /// SW del comando interno (la de la respuesta en claro si no iba protegido).
    pub inner_sw: Option<u16>,
}

#[derive(Debug, Clone)]
enum Entry {
    Df,
    Ef(Vec<u8>),
    Idesp,
}

enum CardCtx {
    Pace(PaceSm),
    Cwa(CwaChannel, CwaSm),
}

impl CardCtx {
    fn name(&self) -> &'static str {
        match self {
            CardCtx::Pace(_) => "PACE",
            CardCtx::Cwa(CwaChannel::Pin, _) => "CWA-PIN",
            CardCtx::Cwa(CwaChannel::User, _) => "CWA-USR",
        }
    }
}

#[derive(Default)]
struct PaceState {
    mse_done: bool,
    s: Option<Vec<u8>>,
    g_mapped: Option<Point>,
    pk_ifd: Option<Point>,
    pk_icc: Option<Point>,
    kenc: Option<crypto::Key16>,
    kmac: Option<crypto::Key16>,
}

#[derive(Default)]
struct CwaState {
    terminal: Option<(Terminal, CwaChannel)>,
    rnd_ifd: Option<[u8; 8]>,
    kicc: Option<Vec<u8>>,
    rnd_icc: Option<[u8; 8]>,
}

struct RsaKey {
    n: BigUint,
    d: BigUint,
}

const MF: [u8; 2] = [0x3F, 0x00];

/// Tarjeta simulada.
pub struct SimCard {
    /// Identificación que devuelve el transporte (por defecto, pseudo-ATR PC/SC del DNIe).
    pub identification: CardIdentification,
    pub can: String,
    pub pin: String,
    /// Contenido del IDESP (`3F00/0006`).
    pub idesp: Vec<u8>,
    /// SW externa de las respuestas CWA igual a la interna (en vez de `9000`).
    pub cwa_outer_sw_equals_inner: bool,
    /// Intentos de PIN restantes.
    pub retries: u8,
    pub serial: [u8; 7],
    /// Las respuestas con más datos que esto se trocean con `61xx` + GET RESPONSE.
    pub max_response_data: Option<usize>,
    pub faults: Faults,
    pub stats: SimStats,
    transcript: Option<Vec<TranscriptEntry>>,
    rng: SimRng,
    ctx: Option<CardCtx>,
    pending: Option<CardCtx>,
    pace: PaceState,
    cwa: CwaState,
    pin_verified: bool,
    dst_key: Option<[u8; 2]>,
    files: BTreeMap<([u8; 2], [u8; 2]), Entry>,
    cur_df: [u8; 2],
    cur_ef: Option<[u8; 2]>,
    icc: RsaKey,
    user_keys: BTreeMap<[u8; 2], RsaKey>,
    get_response: Vec<u8>,
    envelope: Vec<u8>,
    removed: bool,
}

fn read_properties(path: &Path) -> std::io::Result<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect())
}

fn rsa_key(path: &Path) -> std::io::Result<RsaKey> {
    let p = read_properties(path)?;
    let get = |k: &str| {
        p.get(k)
            .and_then(|v| BigUint::parse_bytes(v.as_bytes(), 16))
            .ok_or_else(|| std::io::Error::other(format!("{}: falta {k}", path.display())))
    };
    Ok(RsaKey {
        n: get("n")?,
        d: get("d")?,
    })
}

fn fixed(v: &BigUint, len: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(b.len())];
    out.extend_from_slice(&b[b.len().saturating_sub(len)..]);
    out
}

impl SimCard {
    /// Carga los datos del simulador (directorio `tools/oracle/dnie/data`). `seed` fija los
    /// aleatorios de la tarjeta.
    pub fn from_dir(dir: impl AsRef<Path>, seed: u64) -> std::io::Result<SimCard> {
        let dir = dir.as_ref();
        let file = |n: &str| std::fs::read(dir.join(n));
        let mut files = BTreeMap::new();
        files.insert((MF, [0x00, 0x06]), Entry::Idesp);
        files.insert((MF, [0x60, 0x1F]), Entry::Ef(file("icc_cert.der")?));
        files.insert((MF, [0x50, 0x15]), Entry::Df);
        files.insert(([0x50, 0x15], [0x60, 0x04]), Entry::Ef(file("CDF_ESPECIMEN.ber")?));
        files.insert(([0x50, 0x15], [0x60, 0x01]), Entry::Ef(file("PRKDF_ESPECIMEN.ber")?));
        files.insert((MF, [0x60, 0x61]), Entry::Df);
        for (f, name) in [([0x70, 0x01], "7001"), ([0x70, 0x02], "7002"), ([0x70, 0x03], "7003")] {
            files.insert(([0x60, 0x61], f), Entry::Ef(file(&format!("cert_{name}.bin"))?));
        }
        files.insert((MF, [0x3F, 0x11]), Entry::Df);
        let mut user_keys = BTreeMap::new();
        user_keys.insert([0x01, 0x01], rsa_key(&dir.join("key_0101.properties"))?);
        user_keys.insert([0x01, 0x02], rsa_key(&dir.join("key_0102.properties"))?);
        Ok(SimCard {
            identification: CardIdentification::from_atr(crate::atr::ATR_NFC.pattern.to_vec()),
            can: "123456".into(),
            pin: "1234abcd".into(),
            idesp: b"BMP100002".to_vec(),
            cwa_outer_sw_equals_inner: false,
            retries: 3,
            serial: [1, 2, 3, 4, 5, 6, 7],
            max_response_data: None,
            faults: Faults::default(),
            stats: SimStats::default(),
            transcript: None,
            rng: SimRng::new(seed),
            ctx: None,
            pending: None,
            pace: PaceState::default(),
            cwa: CwaState::default(),
            pin_verified: false,
            dst_key: None,
            files,
            cur_df: MF,
            cur_ef: None,
            icc: rsa_key(&dir.join("icc_key.properties"))?,
            user_keys,
            get_response: Vec::new(),
            envelope: Vec::new(),
            removed: false,
        })
    }

    /// Empieza a registrar la transcripción.
    pub fn record_transcript(&mut self) {
        self.transcript = Some(Vec::new());
    }

    pub fn transcript(&self) -> &[TranscriptEntry] {
        self.transcript.as_deref().unwrap_or(&[])
    }

    /// Contexto de SM activo en la tarjeta.
    pub fn context_name(&self) -> &'static str {
        self.ctx.as_ref().map_or("sin SM", CardCtx::name)
    }

    pub fn pin_verified(&self) -> bool {
        self.pin_verified
    }

    /// Elimina un fichero (para simular tarjetas sin la estructura del DNIe, como la TIE).
    pub fn remove_file(&mut self, df: [u8; 2], fid: [u8; 2]) -> bool {
        self.files.remove(&(df, fid)).is_some()
    }

    /// Vuelve a insertar la tarjeta tras una retirada (estado de SM perdido).
    pub fn reinsert(&mut self) {
        self.removed = false;
        self.faults.remove_at_apdu = None;
        self.drop_sm();
    }

    fn drop_sm(&mut self) {
        self.ctx = None;
        self.pending = None;
        self.pin_verified = false;
        self.dst_key = None;
    }

    fn rand(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.rng.fill(&mut v).expect("SplitMix no falla");
        v
    }

    /// Procesa una APDU recibida y devuelve la respuesta completa (`datos ‖ SW`).
    fn process(&mut self, apdu: &[u8]) -> (Vec<u8>, Option<(Vec<u8>, u16)>) {
        if apdu.len() < 4 {
            return (sw::SM_INCORRECT.to_be_bytes().to_vec(), None);
        }
        if apdu[0] == 0x90 && apdu[1] == 0xC2 {
            self.stats.envelope_used = true;
            if apdu.len() > 5 {
                self.envelope.extend_from_slice(&apdu[5..]);
            }
            let e = &self.envelope;
            if e.len() >= 5 && e.len() >= 5 + e[4] as usize {
                let full = std::mem::take(&mut self.envelope);
                return self.process(&full);
            }
            return (sw::OK.to_be_bytes().to_vec(), None);
        }
        let protected = apdu[0] & 0x0C == 0x0C;
        if self.ctx.is_none() {
            if protected {
                return (sw::SM_INCORRECT.to_be_bytes().to_vec(), None);
            }
            let r = match CommandApdu::parse(apdu) {
                Ok(c) => self.exec(&c),
                Err(_) => ResponseApdu::status(0x6700),
            };
            if let Some(p) = self.pending.take() {
                self.ctx = Some(p);
            }
            return (r.encode(), None);
        }
        if !protected {
            self.stats.plain_with_sm += 1;
            self.drop_sm();
            return (sw::SM_MISSING.to_be_bytes().to_vec(), None);
        }
        let parsed = CommandApdu::parse(apdu).map_err(|e| e.to_string());
        let ctx = self.ctx.as_mut().expect("contexto activo");
        let unwrapped = parsed.and_then(|c| match ctx {
            CardCtx::Pace(sm) => sm.card_unwrap_command(&c),
            CardCtx::Cwa(_, sm) => sm.card_unwrap_command(&c),
        });
        let inner = match unwrapped {
            Ok(u) => u.cmd,
            Err(e) => {
                tracing::debug!("Simulador: error de SM ({e}); se descarta el contexto");
                self.drop_sm();
                return (sw::SM_INCORRECT.to_be_bytes().to_vec(), None);
            }
        };
        if inner.cla & 0x0C == 0x0C {
            self.stats.nested_sm += 1;
        }
        let r = self.exec(&inner);
        let outer_equals_inner = self.cwa_outer_sw_equals_inner;
        let wrapped = match self.ctx.as_mut().expect("contexto activo") {
            CardCtx::Pace(sm) => sm.card_wrap_response(&r.data, r.sw),
            CardCtx::Cwa(_, sm) => {
                let outer = if outer_equals_inner { r.sw } else { sw::OK };
                sm.card_wrap_response(&r.data, r.sw, outer)
            }
        };
        if let Some(p) = self.pending.take() {
            self.ctx = Some(p);
        }
        (wrapped, Some((inner.encode(), r.sw)))
    }

    fn exec(&mut self, c: &CommandApdu) -> ResponseApdu {
        let r = match c.ins {
            0x22 => self.mse(c),
            0x86 => self.general_authenticate(c),
            0xA4 => self.select(c),
            0xB0 => self.read(c),
            0xB8 => Ok(ResponseApdu::new(self.serial.to_vec(), sw::OK)),
            0x2A if c.p2 == 0xAE => Ok(ResponseApdu::status(sw::OK)),
            0x2A if c.p1 == 0x9E && c.p2 == 0x9A => self.pso_cds(c),
            0x2A => Ok(ResponseApdu::status(0x6A86)),
            0x88 => self.internal_authenticate(c),
            0x84 => {
                let r = self.rand(8);
                self.cwa.rnd_icc = Some(r.clone().try_into().expect("8 octetos"));
                Ok(ResponseApdu::new(r, sw::OK))
            }
            0x82 => self.external_authenticate(c),
            0x20 => Ok(self.verify(c)),
            _ => Ok(ResponseApdu::status(0x6D00)),
        };
        r.unwrap_or_else(|e| {
            tracing::debug!("Simulador: {e}");
            ResponseApdu::status(0x6F00)
        })
    }

    fn mse(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        let objs = tlv::parse_all(c.data()).map_err(|e| e.to_string())?;
        let get = |tag: u32| objs.iter().find(|t| t.tag == tag).map(|t| t.value);
        match (c.p1, c.p2) {
            (0xC1, 0xA4) if get(0x80).is_some() => {
                let ok = get(0x80) == Some(&pace::PACE_OID[..])
                    && get(0x83) == Some(&[0x02][..])
                    && get(0x84) == Some(&[pace::DOMAIN_PARAMETER_ID][..]);
                self.pace = PaceState {
                    mse_done: ok,
                    ..Default::default()
                };
                Ok(ResponseApdu::status(if ok { sw::OK } else { 0x6A80 }))
            }
            (0xC1, 0xA4) => {
                let reference = get(0x83).ok_or("MSE:SET AT sin 83")?;
                if reference.len() < 8 || get(0x84) != Some(&crate::consts::REF_ICC_PRIVATE_KEY[..]) {
                    return Ok(ResponseApdu::status(0x6A80));
                }
                let chr = &reference[reference.len() - 8..];
                let found = cwa::all_terminals()
                    .into_iter()
                    .find(|t| t.chr_c_cv_ifd == chr)
                    .map(|t| {
                        let ch = if t.name.contains("Pin") {
                            CwaChannel::Pin
                        } else {
                            CwaChannel::User
                        };
                        (t, ch)
                    });
                if found.is_none() {
                    return Ok(ResponseApdu::status(0x6A88));
                }
                self.cwa = CwaState {
                    terminal: found,
                    ..Default::default()
                };
                Ok(ResponseApdu::status(sw::OK))
            }
            (0x41, 0xB6) => {
                let k = get(0x84).filter(|v| v.len() == 2).ok_or("DST sin 84")?;
                self.dst_key = Some([k[0], k[1]]);
                Ok(ResponseApdu::status(sw::OK))
            }
            _ => Ok(ResponseApdu::status(sw::OK)),
        }
    }

    fn general_authenticate(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        if !self.pace.mse_done {
            return Ok(ResponseApdu::status(0x6985));
        }
        let (outer, _) = tlv::parse_one(c.data()).map_err(|e| e.to_string())?;
        if outer.tag != 0x7C {
            return Ok(ResponseApdu::status(0x6A80));
        }
        let ok = |tag: u16, v: &[u8]| ResponseApdu::new(tlv::encode(0x7C, &tlv::encode(tag, v)), sw::OK);
        if outer.value.is_empty() {
            let s = self.rand(16);
            let kpi = pace::PacePassword::can(&self.can).map_err(|e| e.to_string())?.key();
            let z = crypto::aes_ecb_encrypt(&kpi, &s.clone().try_into().expect("16"));
            self.pace.s = Some(s);
            return Ok(ok(0x80, &z));
        }
        let (inner, _) = tlv::parse_one(outer.value).map_err(|e| e.to_string())?;
        match inner.tag {
            0x81 => {
                let Ok(pk_ifd_map) = Point::from_uncompressed(inner.value) else {
                    return Ok(ResponseApdu::status(0x6A80));
                };
                let sk = Scalar::random(&mut self.rng).map_err(|e| e.to_string())?;
                let pk = Point::generator().mul(&sk).ok_or("identidad")?;
                let h = pk_ifd_map.mul(&sk).ok_or("H nulo")?;
                let s = self.pace.s.clone().ok_or("sin nonce")?;
                self.pace.g_mapped = Some(pace::map_generator(&s, &h).map_err(|e| e.to_string())?);
                Ok(ok(0x82, &pk.to_uncompressed()))
            }
            0x83 => {
                let Ok(pk_ifd) = Point::from_uncompressed(inner.value) else {
                    return Ok(ResponseApdu::status(0x6A80));
                };
                let g = self.pace.g_mapped.ok_or("sin mapeo")?;
                let sk = Scalar::random(&mut self.rng).map_err(|e| e.to_string())?;
                let pk_icc = g.mul(&sk).ok_or("identidad")?;
                let kx = pk_ifd.mul(&sk).ok_or("K nulo")?.x_bytes();
                self.stats.last_kx_leading_zero = kx[0] == 0;
                if kx[0] == 0 {
                    self.stats.kx_leading_zero += 1;
                }
                let (kenc, kmac) = pace::session_keys(&kx);
                self.pace.pk_ifd = Some(pk_ifd);
                self.pace.pk_icc = Some(pk_icc);
                self.pace.kenc = Some(kenc);
                self.pace.kmac = Some(kmac);
                Ok(ok(0x84, &pk_icc.to_uncompressed()))
            }
            0x85 => {
                let (Some(kmac), Some(pk_icc), Some(pk_ifd)) = (&self.pace.kmac, self.pace.pk_icc, self.pace.pk_ifd)
                else {
                    return Ok(ResponseApdu::status(0x6985));
                };
                if !crypto::ct_eq(&pace::auth_token(kmac, &pk_icc), inner.value) {
                    self.stats.pace_failures += 1;
                    self.pace = PaceState::default();
                    return Ok(ResponseApdu::status(0x6300));
                }
                let t_icc = pace::auth_token(kmac, &pk_ifd);
                let kenc = self.pace.kenc.take().ok_or("sin claves")?;
                let kmac = self.pace.kmac.take().ok_or("sin claves")?;
                self.pending = Some(CardCtx::Pace(PaceSm::new(kenc, kmac)));
                self.stats.pace_sessions += 1;
                self.pace = PaceState::default();
                Ok(ok(0x86, &t_icc))
            }
            _ => Ok(ResponseApdu::status(0x6A80)),
        }
    }

    fn fci(fid: [u8; 2], df: bool, size: usize) -> Vec<u8> {
        let mut v = vec![
            0x81,
            0x02,
            (size >> 8) as u8,
            size as u8,
            0x82,
            0x01,
            if df { 0x38 } else { 0x01 },
        ];
        v.extend_from_slice(&[0x83, 0x02, fid[0], fid[1]]);
        tlv::encode(0x6F, &v)
    }

    fn content(&self, e: &Entry) -> Vec<u8> {
        match e {
            Entry::Ef(c) => c.clone(),
            Entry::Idesp => self.idesp.clone(),
            Entry::Df => Vec::new(),
        }
    }

    fn select(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        if c.p1 == 0x04 {
            if c.data() == crate::fs::MASTER_FILE_NAME {
                self.cur_df = MF;
                self.cur_ef = None;
                return Ok(ResponseApdu::status(sw::OK));
            }
            return Ok(ResponseApdu::status(sw::FILE_NOT_FOUND));
        }
        let fid: [u8; 2] = c.data().try_into().map_err(|_| "FID de longitud distinta de 2")?;
        let key = if self.files.contains_key(&(self.cur_df, fid)) {
            (self.cur_df, fid)
        } else {
            (MF, fid)
        };
        let Some(entry) = self.files.get(&key).cloned() else {
            return Ok(ResponseApdu::status(sw::FILE_NOT_FOUND));
        };
        if let Entry::Df = entry {
            self.cur_df = fid;
            self.cur_ef = None;
            return Ok(ResponseApdu::new(Self::fci(fid, true, 0), sw::OK));
        }
        self.cur_df = key.0;
        self.cur_ef = Some(fid);
        let size = self.content(&entry).len();
        Ok(ResponseApdu::new(Self::fci(fid, false, size), sw::OK))
    }

    fn read(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        let Some(ef) = self.cur_ef else {
            return Ok(ResponseApdu::status(0x6986));
        };
        let entry = self
            .files
            .get(&(self.cur_df, ef))
            .cloned()
            .ok_or("EF actual inexistente")?;
        let content = self.content(&entry);
        let off = ((c.p1 as usize) << 8) | c.p2 as usize;
        if off > content.len() {
            return Ok(ResponseApdu::status(sw::WRONG_OFFSET));
        }
        let le = c.le().filter(|l| *l != 0).unwrap_or(256);
        let n = le.min(content.len() - off);
        Ok(ResponseApdu::new(
            content[off..off + n].to_vec(),
            if n < le { sw::END_OF_FILE } else { sw::OK },
        ))
    }

    fn internal_authenticate(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        let Some((term, _)) = self.cwa.terminal else {
            return Ok(ResponseApdu::status(0x6985));
        };
        if c.data().len() != 16 {
            return Ok(ResponseApdu::status(0x6700));
        }
        let rnd_ifd: [u8; 8] = c.data()[..8].try_into().expect("8");
        let sn_ifd = c.data()[8..].to_vec();
        let prnd1 = self.rand(74);
        let kicc = self.rand(32);
        let h: [u8; 20] = Sha1::new()
            .chain_update(&prnd1)
            .chain_update(&kicc)
            .chain_update(rnd_ifd)
            .chain_update(&sn_ifd)
            .finalize()
            .into();
        let m = cwa::message(&prnd1, &kicc, &h);
        let sig = BigUint::from_bytes_be(&m[..]).modpow(&self.icc.d, &self.icc.n);
        let alt = &self.icc.n - &sig;
        let sigmin = if alt < sig { alt } else { sig };
        let n_ifd = BigUint::from_bytes_be(term.modulus);
        let resp = cwa::modpow128(&sigmin, &BigUint::from(cwa::IFD_PUBLIC_EXPONENT), &n_ifd);
        self.cwa.rnd_ifd = Some(rnd_ifd);
        self.cwa.kicc = Some(kicc);
        Ok(ResponseApdu::new(resp.to_vec(), sw::OK))
    }

    fn external_authenticate(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        let (Some((term, channel)), Some(rnd_ifd), Some(kicc), Some(rnd_icc)) = (
            self.cwa.terminal,
            self.cwa.rnd_ifd,
            self.cwa.kicc.clone(),
            self.cwa.rnd_icc,
        ) else {
            return Ok(ResponseApdu::status(0x6985));
        };
        let n_ifd = BigUint::from_bytes_be(term.modulus);
        let e_ifd = BigUint::from(cwa::IFD_PUBLIC_EXPONENT);
        let sigmin = BigUint::from_bytes_be(c.data()).modpow(&self.icc.d, &self.icc.n);
        let mut m = cwa::modpow128(&sigmin, &e_ifd, &n_ifd);
        if (m[0] != 0x6A || m[127] != 0xBC) && sigmin < n_ifd {
            m = cwa::modpow128(&(&n_ifd - &sigmin), &e_ifd, &n_ifd);
        }
        if m[0] != 0x6A || m[127] != 0xBC {
            return Ok(ResponseApdu::status(0x6300));
        }
        let mut sn = [0u8; 8];
        sn[1..].copy_from_slice(&self.serial);
        let h: [u8; 20] = Sha1::new()
            .chain_update(&m[1..75])
            .chain_update(&m[75..107])
            .chain_update(rnd_icc)
            .chain_update(sn)
            .finalize()
            .into();
        if h[..] != m[107..127] {
            return Ok(ResponseApdu::status(0x6300));
        }
        let sm = cwa::session_keys(&kicc, &m[75..107], &rnd_icc, &rnd_ifd);
        self.pending = Some(CardCtx::Cwa(channel, sm));
        self.cwa = CwaState::default();
        Ok(ResponseApdu::status(sw::OK))
    }

    fn verify(&mut self, c: &CommandApdu) -> ResponseApdu {
        let blocked_or_retries = |r: u8| {
            if r == 0 { sw::AUTH_BLOCKED } else { 0x63C0 | r as u16 }
        };
        if c.data().is_empty() {
            if self.pin_verified {
                return ResponseApdu::status(sw::OK);
            }
            return ResponseApdu::status(blocked_or_retries(self.retries));
        }
        if !matches!(self.ctx, Some(CardCtx::Cwa(CwaChannel::Pin, _))) {
            return ResponseApdu::status(sw::SECURITY_STATUS);
        }
        if self.retries == 0 {
            return ResponseApdu::status(sw::AUTH_BLOCKED);
        }
        if c.data() == self.pin.as_bytes() {
            self.pin_verified = true;
            self.retries = 3;
            return ResponseApdu::status(sw::OK);
        }
        self.retries -= 1;
        ResponseApdu::status(blocked_or_retries(self.retries))
    }

    fn pso_cds(&mut self, c: &CommandApdu) -> Result<ResponseApdu, String> {
        if !self.pin_verified || !matches!(self.ctx, Some(CardCtx::Cwa(CwaChannel::User, _))) {
            return Ok(ResponseApdu::status(sw::SECURITY_STATUS));
        }
        let Some(key) = self.dst_key.and_then(|k| self.user_keys.get(&k)) else {
            return Ok(ResponseApdu::status(0x6A88));
        };
        let len = key.n.bits().div_ceil(8);
        if c.data().len() + 11 > len {
            return Ok(ResponseApdu::status(0x6700));
        }
        let mut em = vec![0xFFu8; len];
        em[0] = 0;
        em[1] = 1;
        em[len - c.data().len() - 1] = 0;
        em[len - c.data().len()..].copy_from_slice(c.data());
        let sig = BigUint::from_bytes_be(&em).modpow(&key.d, &key.n);
        self.stats.signatures += 1;
        Ok(ResponseApdu::new(fixed(&sig, len), sw::OK))
    }
}

impl CardTransport for SimCard {
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        let n = self.stats.apdus + 1;
        if self.removed || self.faults.remove_at_apdu.is_some_and(|r| n >= r) {
            self.removed = true;
            return Err(TransportError::TagLost(
                "Tag was lost (tarjeta simulada retirada)".into(),
            ));
        }
        self.stats.apdus = n;
        self.stats.max_command = self.stats.max_command.max(apdu.len());
        let context = self.context_name();
        let (mut response, inner) = if apdu.len() >= 4 && apdu[0] == 0x00 && apdu[1] == 0xC0 {
            // GET RESPONSE en claro (no afecta a la mensajería segura).
            let le = apdu.get(4).map_or(256, |b| if *b == 0 { 256 } else { *b as usize });
            if self.get_response.len() <= 2 {
                (0x6985u16.to_be_bytes().to_vec(), None)
            } else {
                let data_left = self.get_response.len() - 2;
                let take = le.min(data_left);
                let mut out: Vec<u8> = self.get_response.drain(..take).collect();
                if self.get_response.len() > 2 {
                    let left = self.get_response.len() - 2;
                    out.extend_from_slice(&[0x61, left.min(255) as u8]);
                } else {
                    out.extend_from_slice(&std::mem::take(&mut self.get_response));
                }
                (out, None)
            }
        } else if self.faults.drop_sm_at_apdu == Some(n) {
            self.drop_sm();
            (sw::SM_MISSING.to_be_bytes().to_vec(), None)
        } else {
            self.process(apdu)
        };
        if self.faults.corrupt_mac_at_apdu == Some(n) && response.len() > 4 {
            let i = response.len() - 3;
            response[i] ^= 0x01;
        }
        if let Some(max) = self.max_response_data
            && response.len() > max + 2
        {
            let rest = response.split_off(max);
            let left = rest.len() - 2;
            self.get_response = rest;
            response.extend_from_slice(&[0x61, left.min(255) as u8]);
        }
        self.stats.max_response = self.stats.max_response.max(response.len());
        if let Some(t) = self.transcript.as_mut() {
            let n = response.len();
            let plain_sw = (n >= 2).then(|| u16::from_be_bytes([response[n - 2], response[n - 1]]));
            t.push(TranscriptEntry {
                command: apdu.to_vec(),
                response: response.clone(),
                context,
                inner_sw: inner.as_ref().map(|i| i.1).or(plain_sw),
                inner: inner.map(|i| i.0),
            });
        }
        Ok(response)
    }

    fn identification(&mut self) -> Result<CardIdentification, TransportError> {
        if self.removed {
            return Err(TransportError::TagLost("tarjeta simulada retirada".into()));
        }
        Ok(self.identification.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic() {
        let mut a = SimRng::new(7);
        let mut b = SimRng::new(7);
        let (mut x, mut y) = ([0u8; 13], [0u8; 13]);
        a.fill(&mut x).unwrap();
        b.fill(&mut y).unwrap();
        assert_eq!(x, y);
        assert_ne!(x, [0u8; 13]);
    }
}
