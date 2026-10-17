//! Sesión con un DNIe sin contacto: máquina de estados con un único contexto de mensajería
//! segura (especificación 10 §0.2, §7.6, §9 y §13).
//!
//! ```text
//!  fase                          contexto en el que viajan las APDU
//!  PACE (MSE:SET AT, GA×4)       Plain
//!  lectura de CDF/PrKDF/certs    Pace
//!  handshake del canal de PIN    Pace        → CwaPin
//!  intentos + VERIFY             CwaPin
//!  handshake del canal usuario   CwaPin      → CwaUser
//!  MSE:SET DST + PSO:CDS         CwaUser
//!  «reset» tras la firma         SELECT MF en claro (la tarjeta descarta el contexto) → Plain
//! ```
//!
//! Establecer un canal es ejecutar su handshake con `Channel::send` (envuelto en el contexto
//! actual) y, si termina bien, **sustituir** el contexto: nunca se envuelve dos veces.

use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::apdu::{CommandApdu, ResponseApdu, sw};
use crate::atr::{self, DetectionEvidence, DetectionPolicy};
use crate::certs;
use crate::cwa::{self, CwaChannel};
use crate::error::{DnieError, TransportError};
use crate::fs;
use crate::interaction::{CanRequest, DnieInteraction, PinRequest, SignatureRequest};
use crate::pace::{self, PacePassword};
use crate::pkcs15;
use crate::rng::{OsRandom, RandomSource};
use crate::sm::{CwaSm, PaceSm};
use crate::transport::{CardTransport, Link};

pub use crate::cwa::CwaSet;

/// Alias del certificado de firma (el que usa siempre la app Android).
pub const CERT_FIRMA_DIGITAL: &str = "CertFirmaDigital";
/// Alias del certificado de autenticación.
pub const CERT_AUTENTICACION: &str = "CertAutenticacion";
/// Alias de la CA intermedia (sin clave; se oculta y se añade a la cadena).
pub const CERT_CA_INTERMEDIA: &str = "CertCAIntermediaDGP";

/// Nombre de la tarjeta (`DnieNfc.getCardName()`).
pub const CARD_NAME: &str = "DNIe 3.0/4.0 accedido de forma inalambrica";

/// Huella para el `DigestInfo` que firma la tarjeta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    /// Normaliza un nombre de algoritmo como `DigestInfo.encode` de JMulticard (`SHA1`,
    /// `SHA-256`, `SHA256withRSA`, `SHA512withRSAEncryption`…).
    pub fn from_name(name: &str) -> Option<DigestAlgorithm> {
        let n = name.trim().to_ascii_uppercase().replace('-', "");
        let base = n.split("WITH").next().unwrap_or("");
        match base {
            "SHA" | "SHA1" => Some(DigestAlgorithm::Sha1),
            "SHA256" => Some(DigestAlgorithm::Sha256),
            "SHA384" => Some(DigestAlgorithm::Sha384),
            "SHA512" => Some(DigestAlgorithm::Sha512),
            _ => None,
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            DigestAlgorithm::Sha1 => 20,
            DigestAlgorithm::Sha256 => 32,
            DigestAlgorithm::Sha384 => 48,
            DigestAlgorithm::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// Cabecera DER fija del `DigestInfo` (§9.3).
    pub fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            DigestAlgorithm::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
            ],
            DigestAlgorithm::Sha256 => &[
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
                0x04, 0x20,
            ],
            DigestAlgorithm::Sha384 => &[
                0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
                0x04, 0x30,
            ],
            DigestAlgorithm::Sha512 => &[
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
                0x04, 0x40,
            ],
        }
    }

    /// `DigestInfo` DER de una huella ya calculada.
    pub fn digest_info(self, digest: &[u8]) -> Result<Vec<u8>, DnieError> {
        if digest.len() != self.output_len() {
            return Err(DnieError::UnsupportedAlgorithm(format!(
                "huella de {} octetos para {self:?}",
                digest.len()
            )));
        }
        let mut v = self.digest_info_prefix().to_vec();
        v.extend_from_slice(digest);
        Ok(v)
    }
}

/// Opciones de la sesión.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Política de detección de la tarjeta.
    pub detection: DetectionPolicy,
    /// Verificar cada firma con la clave pública del certificado antes de devolverla.
    pub verify_signatures: bool,
    /// Ante un error de comunicación o de mensajería segura durante una firma, reabrir la
    /// sesión desde PACE una sola vez (§5.5; nunca se repite un `VERIFY` de resultado
    /// desconocido).
    pub reopen_on_link_error: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        SessionOptions {
            detection: DetectionPolicy::Strict,
            verify_signatures: true,
            reopen_on_link_error: true,
        }
    }
}

/// Datos de la tarjeta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardInfo {
    /// Con qué se ha reconocido.
    pub evidence: DetectionEvidence,
    /// Número de soporte (contenido de `3F00/0006`, sin recortar), si se ha podido leer.
    pub idesp: Option<String>,
    /// Juego de constantes CWA elegido por el IDESP.
    pub cwa_set: CwaSet,
}

impl CardInfo {
    pub fn card_name(&self) -> &'static str {
        CARD_NAME
    }
}

/// Clave privada del DNIe con su certificado.
#[derive(Debug, Clone)]
pub struct DnieKey {
    /// Alias (etiqueta del CDF): `CertFirmaDigital`, `CertAutenticacion`.
    pub alias: String,
    /// Certificado X.509 DER.
    pub certificate: Vec<u8>,
    /// Cadena: certificado, CA intermedia y raíz del DNIe si la verifica (§7.7).
    pub chain: Vec<Vec<u8>>,
    /// Identificador PKCS#15 que enlaza certificado y clave.
    pub id: Vec<u8>,
    /// Etiqueta de la clave en el PrKDF.
    pub key_label: String,
    /// Ruta de la clave en el PrKDF (`3F110102`).
    pub key_path: Vec<u8>,
    /// Referencia de la clave (PrKDF).
    pub key_reference: Option<u8>,
    /// Longitud de la clave en bits (del certificado).
    pub key_bits: usize,
    public_key: RsaPublicKey,
}

impl DnieKey {
    /// Identificador de fichero de la clave para `MSE:SET DST`.
    pub fn key_fid(&self) -> [u8; 2] {
        let n = self.key_path.len();
        [self.key_path[n - 2], self.key_path[n - 1]]
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

/// Contexto de mensajería segura activo (uno solo a la vez).
enum SmContext {
    Plain,
    Pace(PaceSm),
    CwaPin(CwaSm),
    CwaUser(CwaSm),
    /// La tarjeta o el enlace han perdido la sincronía: hay que volver a PACE.
    Broken,
}

impl SmContext {
    fn name(&self) -> &'static str {
        match self {
            SmContext::Plain => "sin SM",
            SmContext::Pace(_) => "PACE",
            SmContext::CwaPin(_) => "CWA-PIN",
            SmContext::CwaUser(_) => "CWA-USR",
            SmContext::Broken => "roto",
        }
    }
}

/// Enlace con el contexto de mensajería segura activo.
pub(crate) struct Channel<T: CardTransport> {
    link: Link<T>,
    ctx: SmContext,
}

/// Reintentos encadenados por `6Cxx`/`62xx` dentro de un canal seguro.
const MAX_SM_RETRIES: usize = 4;

impl<T: CardTransport> Channel<T> {
    fn new(transport: T) -> Self {
        Channel {
            link: Link::new(transport),
            ctx: SmContext::Plain,
        }
    }

    /// Nombre del contexto activo.
    pub fn context_name(&self) -> &'static str {
        self.ctx.name()
    }

    /// Envía un comando en claro envolviéndolo con el contexto activo, con los reintentos
    /// `6Cxx` (y `62xx` con Le en CWA) de JMulticard.
    pub fn send(&mut self, cmd: &CommandApdu) -> Result<ResponseApdu, DnieError> {
        tracing::trace!(target: "afirma_dnie::apdu", "[{}] > {:?}", self.ctx.name(), cmd);
        let mut cmd = cmd.clone();
        let mut retries = 0;
        loop {
            let r = self.send_once(&cmd)?;
            tracing::trace!(target: "afirma_dnie::apdu", "[{}] < {:?}", self.ctx.name(), r);
            let protected = !matches!(self.ctx, SmContext::Plain);
            if protected && retries < MAX_SM_RETRIES {
                if r.sw1() == 0x6C {
                    let n = r.sw2() as usize;
                    cmd.set_le(Some(if n == 0 { 256 } else { n }));
                    retries += 1;
                    continue;
                }
                // C5: solo con Le (JMulticard fallaba con NullPointerException sin él).
                if matches!(self.ctx, SmContext::CwaPin(_) | SmContext::CwaUser(_))
                    && r.sw1() == 0x62
                    && r.sw != sw::END_OF_FILE
                    && let Some(le) = cmd.le()
                    && le > 1
                {
                    cmd.set_le(Some(le - 1));
                    retries += 1;
                    continue;
                }
            }
            return Ok(r);
        }
    }

    fn send_once(&mut self, cmd: &CommandApdu) -> Result<ResponseApdu, DnieError> {
        let result = match &mut self.ctx {
            SmContext::Plain => return self.link.transmit(cmd),
            SmContext::Broken => {
                return Err(DnieError::SecureMessaging(
                    "Se ha perdido la sincronía del canal seguro con la tarjeta".into(),
                ));
            }
            SmContext::Pace(sm) => sm
                .wrap(cmd)
                .and_then(|w| self.link.transmit_bytes(&w))
                .and_then(|r| sm.unwrap(&r)),
            SmContext::CwaPin(sm) | SmContext::CwaUser(sm) => sm.wrap(cmd).and_then(|w| {
                let r = self.link.transmit_bytes(&w)?;
                if r.data.is_empty() && (r.sw == sw::SM_MISSING || r.sw == sw::SM_INCORRECT) {
                    return Err(DnieError::SecureMessaging(format!(
                        "La tarjeta ha descartado el canal seguro (respuesta {:04X})",
                        r.sw
                    )));
                }
                sm.unwrap(&r)
            }),
        };
        if result.is_err() {
            self.ctx = SmContext::Broken;
        }
        result
    }

    /// Descarta la mensajería segura: `SELECT MF` en claro, al que la tarjeta responde con un
    /// error de SM (`6987`) y abandona su contexto (§9.4). Los errores se ignoran.
    fn reset_card(&mut self) {
        match self.link.transmit(&fs::select_mf_command()) {
            Ok(r) => tracing::debug!("Paso de canal seguro a no seguro al reiniciar: {:04X}", r.sw),
            Err(e) => tracing::debug!("Paso de canal seguro a no seguro al reiniciar: {e}"),
        }
        self.ctx = SmContext::Plain;
    }
}

/// Estado del PIN dentro de una firma (para decidir si se puede reintentar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinState {
    NotRequested,
    Obtained,
    /// Se ha enviado `VERIFY` y no se sabe el resultado: no se puede reintentar.
    Sent,
    /// La tarjeta ha respondido al `VERIFY` (correcto o no).
    Answered,
}

/// Sesión con un DNIe.
pub struct DnieSession<T: CardTransport> {
    chan: Channel<T>,
    can: PacePassword,
    info: CardInfo,
    keys: Vec<DnieKey>,
    intermediate: Option<Vec<u8>>,
    rng: Box<dyn RandomSource>,
    options: SessionOptions,
}

impl<T: CardTransport> DnieSession<T> {
    /// Detecta la tarjeta, pide el CAN, abre PACE y lee certificados (`DnieNfc.<init>`).
    pub fn open(transport: T, ui: &dyn DnieInteraction) -> Result<Self, DnieError> {
        Self::open_with(transport, ui, Box::new(OsRandom), SessionOptions::default())
    }

    /// [`Self::open`] con fuente de aleatorios y opciones explícitas.
    pub fn open_with(
        mut transport: T,
        ui: &dyn DnieInteraction,
        rng: Box<dyn RandomSource>,
        options: SessionOptions,
    ) -> Result<Self, DnieError> {
        let id = transport
            .identification()
            .map_err(|e| DnieError::ConnectionFailed(e.to_string()))?;
        let evidence = atr::detect(&id, options.detection)?;
        tracing::info!("Tarjeta detectada como DNIe sin contacto: {evidence:?}");
        let can = ui.request_can(&CanRequest::default())?;
        let can = PacePassword::can(can.trim())?;
        let mut session = DnieSession {
            chan: Channel::new(transport),
            can,
            info: CardInfo {
                evidence,
                idesp: None,
                cwa_set: CwaSet::R2,
            },
            keys: Vec::new(),
            intermediate: None,
            rng,
            options,
        };
        session.establish_pace()?;
        session.load().map_err(not_supported_unless_link)?;
        Ok(session)
    }

    /// Datos de la tarjeta.
    pub fn info(&self) -> &CardInfo {
        &self.info
    }

    /// Claves con certificado (sin la CA intermedia), en el orden del CDF.
    pub fn keys(&self) -> &[DnieKey] {
        &self.keys
    }

    /// Clave por alias.
    pub fn key(&self, alias: &str) -> Result<&DnieKey, DnieError> {
        self.keys
            .iter()
            .find(|k| k.alias == alias)
            .ok_or_else(|| DnieError::AliasNotFound(alias.to_string()))
    }

    /// Certificado de la CA intermedia (`CertCAIntermediaDGP`), si lo hay.
    pub fn intermediate_certificate(&self) -> Option<&[u8]> {
        self.intermediate.as_deref()
    }

    /// Nombre del contexto de mensajería segura activo (diagnóstico).
    pub fn context_name(&self) -> &'static str {
        self.chan.context_name()
    }

    /// APDU enviadas por el enlace desde la apertura.
    pub fn apdu_count(&self) -> usize {
        self.chan.link.apdu_count()
    }

    pub fn transport(&self) -> &T {
        self.chan.link.transport()
    }

    pub fn transport_mut(&mut self) -> &mut T {
        self.chan.link.transport_mut()
    }

    /// Cierra la sesión: descarta la mensajería segura y devuelve el transporte.
    pub fn close(mut self) -> T {
        if !matches!(self.chan.ctx, SmContext::Plain) {
            self.chan.reset_card();
        }
        let DnieSession { chan, .. } = self;
        chan.link.into_transport()
    }

    /// Vuelve a abrir PACE con el CAN guardado y a leer los certificados (botón «Recargar»).
    pub fn reload(&mut self) -> Result<(), DnieError> {
        if !matches!(self.chan.ctx, SmContext::Plain) {
            self.chan.reset_card();
        }
        self.establish_pace()?;
        self.load().map_err(not_supported_unless_link)
    }

    fn establish_pace(&mut self) -> Result<(), DnieError> {
        if !matches!(self.chan.ctx, SmContext::Plain) {
            self.chan.reset_card();
        }
        let DnieSession { chan, can, rng, .. } = self;
        let link = &mut chan.link;
        let mut tx = |c: &CommandApdu| link.transmit(c);
        let out = pace::establish(&mut tx, can, rng.as_mut())?;
        chan.ctx = SmContext::Pace(out.sm);
        tracing::debug!("Canal PACE establecido");
        Ok(())
    }

    /// Carga de certificados y claves bajo PACE (`Dnie.loadCertificates` + IDESP).
    fn load(&mut self) -> Result<(), DnieError> {
        let chan = &mut self.chan;
        let mut send = |c: &CommandApdu| chan.send(c);
        fs::select_mf(&mut send)?;
        let cdf = pkcs15::parse_cdf(&fs::read_path(&mut send, &fs::CDF_PATH)?)?;
        let mut certs: Vec<(pkcs15::CertificateObject, Vec<u8>)> = Vec::new();
        for c in cdf {
            let raw = fs::read_path(&mut send, &c.path)?;
            let der = certs::decompress_certificate(&raw)?;
            certs.push((c, der));
        }
        let prkdf = pkcs15::parse_prkdf(&fs::read_path(&mut send, &fs::PRKDF_PATH)?)?;
        let idesp = match fs::read_path(&mut send, &fs::IDESP_PATH) {
            Ok(b) => Some(String::from_utf8_lossy(&b).into_owned()),
            Err(e) if e.is_link_error() => return Err(e),
            Err(e) => {
                tracing::warn!("No se ha podido leer el IDESP del DNIe: {e}");
                None
            }
        };
        let intermediate = certs
            .iter()
            .find(|(c, _)| c.label == CERT_CA_INTERMEDIA)
            .map(|(_, d)| d.clone());
        let mut keys = Vec::new();
        for (c, der) in &certs {
            let Some(k) = prkdf.iter().find(|k| k.id == c.id) else {
                continue;
            };
            if k.key_fid().is_none() {
                continue;
            }
            let public_key = certs::rsa_public_key(der)?;
            keys.push(DnieKey {
                alias: c.label.clone(),
                certificate: der.clone(),
                chain: certs::build_chain(der, intermediate.as_deref()),
                id: c.id.clone(),
                key_label: k.label.clone(),
                key_path: k.path.clone(),
                key_reference: k.key_reference,
                key_bits: certs::modulus_bits(&public_key),
                public_key,
            });
        }
        let cwa_set = cwa::cwa_set_for_idesp(idesp.as_deref());
        if idesp.as_deref().is_none_or(str::is_empty) {
            tracing::warn!("IDESP desconocido: se usan las constantes CWA r2");
        }
        tracing::info!(
            "DNIe cargado: IDESP={:?}, constantes {:?}, claves {:?}",
            idesp,
            cwa_set,
            keys.iter().map(|k| k.alias.as_str()).collect::<Vec<_>>()
        );
        self.keys = keys;
        self.intermediate = intermediate;
        self.info.idesp = idesp;
        self.info.cwa_set = cwa_set;
        Ok(())
    }

    /// Firma `data` con la clave `alias`: calcula la huella, abre los canales CWA, pide y
    /// verifica el PIN y envía `MSE:SET DST` + `PSO:CDS`. Devuelve la firma PKCS#1 v1.5.
    pub fn sign(
        &mut self,
        alias: &str,
        alg: DigestAlgorithm,
        data: &[u8],
        ui: &dyn DnieInteraction,
    ) -> Result<Vec<u8>, DnieError> {
        let digest = alg.digest(data);
        self.sign_digest(alias, alg, &digest, ui)
    }

    /// Como [`Self::sign`] con la huella ya calculada.
    pub fn sign_digest(
        &mut self,
        alias: &str,
        alg: DigestAlgorithm,
        digest: &[u8],
        ui: &dyn DnieInteraction,
    ) -> Result<Vec<u8>, DnieError> {
        let key = self.key(alias)?.clone();
        let digest_info = alg.digest_info(digest)?;
        if !ui.confirm_signature(&SignatureRequest {
            alias: alias.to_string(),
        })? {
            return Err(DnieError::Cancelled);
        }
        let mut pin: Option<Zeroizing<String>> = None;
        let mut state = PinState::NotRequested;
        let mut attempt = 0;
        let signature = loop {
            attempt += 1;
            match self.sign_attempt(&key, &digest_info, ui, &mut pin, &mut state) {
                Ok(sig) => break sig,
                Err(e) => {
                    // Cualquier fallo deja la tarjeta en un estado desconocido: se descarta la
                    // mensajería segura y la siguiente operación empieza desde PACE.
                    self.chan.reset_card();
                    let retry = self.options.reopen_on_link_error
                        && attempt == 1
                        && e.is_link_error()
                        && state != PinState::Sent;
                    if !retry {
                        return Err(e);
                    }
                    tracing::warn!("Error de comunicación durante la firma ({e}); se reabre la sesión desde PACE");
                }
            }
        };
        if self.options.verify_signatures
            && key
                .public_key
                .verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, &signature)
                .is_err()
        {
            return Err(DnieError::BadSignature);
        }
        Ok(signature)
    }

    fn sign_attempt(
        &mut self,
        key: &DnieKey,
        digest_info: &[u8],
        ui: &dyn DnieInteraction,
        pin: &mut Option<Zeroizing<String>>,
        state: &mut PinState,
    ) -> Result<Vec<u8>, DnieError> {
        // PACE (en la primera firma ya está abierto; en las siguientes se reabre con el CAN).
        if !matches!(self.chan.ctx, SmContext::Pace(_)) {
            self.establish_pace()?;
        }
        // Canal de PIN, intentos y VERIFY.
        self.open_cwa(CwaChannel::Pin)?;
        let retries = self.pin_retries()?;
        if pin.is_none() {
            let p = ui.request_pin(&PinRequest {
                retries_left: retries,
                alias: key.alias.clone(),
            })?;
            validate_pin(&p)?;
            *pin = Some(p);
            *state = PinState::Obtained;
        }
        let pin_bytes = Zeroizing::new(pin.as_ref().map(|p| p.as_bytes().to_vec()).unwrap_or_default());
        *state = PinState::Sent;
        let r = self
            .chan
            .send(&CommandApdu::new(0x00, 0x20, 0x00, 0x00).with_data(pin_bytes.to_vec()))?;
        match r.sw {
            sw::OK => *state = PinState::Answered,
            s if s & 0xFFF0 == 0x63C0 => {
                *state = PinState::Answered;
                let left = (s & 0x0F) as u8;
                return Err(if left == 0 {
                    DnieError::PinBlocked
                } else {
                    DnieError::WrongPin {
                        retries_left: Some(left),
                    }
                });
            }
            sw::AUTH_BLOCKED => {
                *state = PinState::Answered;
                return Err(DnieError::PinBlocked);
            }
            0x0000 => {
                return Err(DnieError::Transport(TransportError::TagLost(
                    "Se ha perdido el canal NFC".into(),
                )));
            }
            other => return Err(DnieError::card("verificación de PIN", other)),
        }
        // Canal de usuario y firma.
        self.open_cwa(CwaChannel::User)?;
        let fid = key.key_fid();
        let r = self
            .chan
            .send(&CommandApdu::new(0x00, 0x22, 0x41, 0xB6).with_data(vec![0x84, 0x02, fid[0], fid[1]]))?;
        if !r.is_ok() {
            return Err(DnieError::card("establecimiento de la clave de firma", r.sw));
        }
        let r = self
            .chan
            .send(&CommandApdu::new(0x00, 0x2A, 0x9E, 0x9A).with_data(digest_info.to_vec()))?;
        if !r.is_ok() {
            return Err(DnieError::card("operación de firma", r.sw));
        }
        let signature = r.data;
        // «Reset»: SELECT en claro para que la tarjeta descarte el canal de usuario (§9.4).
        self.chan.reset_card();
        if signature.len() * 8 < key.key_bits.saturating_sub(7) || signature.is_empty() {
            return Err(DnieError::Read(format!("Firma de {} octetos", signature.len())));
        }
        Ok(signature)
    }

    /// `SELECT MF` y handshake CWA por el contexto actual; el nuevo canal sustituye al actual.
    fn open_cwa(&mut self, channel: CwaChannel) -> Result<(), DnieError> {
        let term = cwa::terminal(self.info.cwa_set, channel);
        let DnieSession { chan, rng, .. } = self;
        match fs::select_mf(&mut |c: &CommandApdu| chan.send(c)) {
            Ok(()) => {}
            Err(e) if channel == CwaChannel::User || e.is_link_error() => return Err(e),
            Err(e) => tracing::warn!("SELECT MF antes del canal de PIN: {e}"),
        }
        let sm = cwa::handshake(&mut |c: &CommandApdu| chan.send(c), &term, rng.as_mut())?;
        chan.ctx = match channel {
            CwaChannel::Pin => SmContext::CwaPin(sm),
            CwaChannel::User => SmContext::CwaUser(sm),
        };
        tracing::debug!("Canal CWA-14890 establecido: {:?}", term);
        Ok(())
    }

    /// Intentos restantes de PIN (`00 20 00 00`, Le = 00) por el canal de PIN (§8.1).
    fn pin_retries(&mut self) -> Result<Option<u8>, DnieError> {
        let r = self.chan.send(&CommandApdu::new(0x00, 0x20, 0x00, 0x00).with_le(256))?;
        match r.sw {
            s if s & 0xFFF0 == 0x63C0 => {
                let n = (s & 0x0F) as u8;
                if n == 0 {
                    Err(DnieError::PinBlocked)
                } else {
                    Ok(Some(n))
                }
            }
            sw::AUTH_BLOCKED => Err(DnieError::PinBlocked),
            // Ya verificado o la tarjeta no informa: intentos desconocidos.
            sw::OK => Ok(None),
            other => Err(DnieError::card("consulta de intentos de PIN", other)),
        }
    }
}

/// Validación local del PIN: no vacío, ASCII imprimible y como mucho 16 caracteres (no se envía a
/// la tarjeta un PIN que no puede ser válido; no gasta intentos).
fn validate_pin(pin: &str) -> Result<(), DnieError> {
    if pin.is_empty() {
        return Err(DnieError::InvalidPinFormat("El PIN no puede ser nulo ni vacío".into()));
    }
    if !pin.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return Err(DnieError::InvalidPinFormat(
            "El PIN solo puede contener caracteres ASCII imprimibles".into(),
        ));
    }
    if pin.len() > 16 {
        return Err(DnieError::InvalidPinFormat(
            "El PIN del DNIe no puede tener más de 16 caracteres".into(),
        ));
    }
    Ok(())
}

/// Tras PACE, cualquier respuesta inesperada de la tarjeta al leer sus estructuras indica que no
/// es un DNIe soportado (p. ej. una TIE, §1); los errores de enlace se conservan.
fn not_supported_unless_link(e: DnieError) -> DnieError {
    match e {
        DnieError::Card { .. } | DnieError::Read(_) => {
            DnieError::CardNotSupported(format!("no se han podido leer las estructuras del DNIe ({e})"))
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_names_and_info() {
        assert_eq!(
            DigestAlgorithm::from_name("SHA256withRSA"),
            Some(DigestAlgorithm::Sha256)
        );
        assert_eq!(DigestAlgorithm::from_name("SHA-1"), Some(DigestAlgorithm::Sha1));
        assert_eq!(DigestAlgorithm::from_name("SHAwithRSA"), Some(DigestAlgorithm::Sha1));
        assert_eq!(
            DigestAlgorithm::from_name("SHA512withRSAEncryption"),
            Some(DigestAlgorithm::Sha512)
        );
        assert_eq!(DigestAlgorithm::from_name("MD5withRSA"), None);
        for (a, total) in [
            (DigestAlgorithm::Sha1, 35),
            (DigestAlgorithm::Sha256, 51),
            (DigestAlgorithm::Sha384, 67),
            (DigestAlgorithm::Sha512, 83),
        ] {
            assert_eq!(a.digest_info(&a.digest(b"x")).unwrap().len(), total);
        }
        assert!(DigestAlgorithm::Sha256.digest_info(&[0; 20]).is_err());
    }

    #[test]
    fn pin_validation() {
        assert!(validate_pin("1234abcd").is_ok());
        assert!(validate_pin("").is_err());
        assert!(validate_pin("pin con ñ").is_err());
        assert!(validate_pin("12345678901234567").is_err());
    }
}
