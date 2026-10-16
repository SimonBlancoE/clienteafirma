//! Firma trifásica PAdES (`PAdESTriPhaseSigner`, `PAdESTriPhasePreProcessor`).
//!
//! En AutoFirma casi todo el trabajo de la firma trifásica PAdES lo hace el
//! servidor: la prefirma construye la revisión del PDF y los atributos
//! firmados; el cliente solo firma (PKCS#1) el valor `PRE` y la postfirma
//! regenera la misma revisión e inserta el CMS. Este módulo ofrece esas
//! piezas para un servidor trifásico en Rust o para emular el flujo
//! localmente:
//!
//! - [`presign`]: prefirma determinista (mismos datos ⇒ mismos bytes) y los
//!   parámetros de sesión `PRE`, `NEED_PRE`, `TIME` y `PID`.
//! - [`sign_pre`]: lo que hace el cliente (PKCS#1 sobre `PRE`).
//! - [`postsign`]: regenera la revisión a partir de la sesión, comprueba que
//!   coincide con la prefirma (`PID`) e inserta el PKCS#1.

use afirma_core::algorithms::compose_signature_algorithm;
use afirma_core::{AfirmaError, ExtraParams, KeyAlgorithm, SigningKey};

use crate::pades::{PadesPreSign, PadesSigner};
use crate::pdf::date::{SignTime, from_millis, millis};

/// Parámetro con los atributos firmados (Base64).
pub const PRE: &str = "PRE";
/// Indica que `PRE` debe devolverse en la postfirma.
pub const NEED_PRE: &str = "NEED_PRE";
/// Instante de firma en milisegundos.
pub const TIME: &str = "TIME";
/// Identificador del fichero (`/ID`) generado en la prefirma (Base64).
pub const PID: &str = "PID";
/// Firma PKCS#1 (Base64) devuelta por el cliente.
pub const PK1: &str = "PK1";

/// Datos de sesión de una firma PAdES trifásica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PadesSession {
    /// Atributos firmados (DER).
    pub pre: Vec<u8>,
    /// Instante de firma (ms).
    pub time: i64,
    /// Cadena del `/ID` del trailer (`[<hex><hex>]`).
    pub file_id: String,
    /// Firma PKCS#1 (tras la firma del cliente).
    pub pk1: Option<Vec<u8>>,
}

/// Representación del `/ID` como la cadena que usa Java (`PdfArray.toString`
/// del identificador).
pub fn file_id_string(id: &(Vec<u8>, Vec<u8>)) -> String {
    format!("[<{}><{}>]", hex::encode(&id.0), hex::encode(&id.1))
}

impl PadesSession {
    /// Parámetros del `TriSign` (`PRE`, `NEED_PRE`, `TIME`, `PID` y `PK1` si
    /// existe).
    pub fn to_params(&self) -> Vec<(String, String)> {
        let mut v = vec![
            (PRE.to_string(), afirma_core::base64_encode(&self.pre)),
            (NEED_PRE.to_string(), "true".to_string()),
            (TIME.to_string(), self.time.to_string()),
            (PID.to_string(), afirma_core::base64_encode(self.file_id.as_bytes())),
        ];
        if let Some(p) = &self.pk1 {
            v.push((PK1.to_string(), afirma_core::base64_encode(p)));
        }
        v
    }

    /// Lee los parámetros de un `TriSign`.
    pub fn from_params<'a>(params: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<PadesSession, AfirmaError> {
        let mut pre = None;
        let mut time = None;
        let mut pid = None;
        let mut pk1 = None;
        for (k, v) in params {
            match k {
                PRE => pre = afirma_core::base64_decode_lenient(v).ok(),
                TIME => time = v.trim().parse::<i64>().ok(),
                PID => {
                    pid = afirma_core::base64_decode_lenient(v)
                        .ok()
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                }
                PK1 => pk1 = afirma_core::base64_decode_lenient(v).ok(),
                _ => {}
            }
        }
        let bad = |m: &str| AfirmaError::invalid_argument(format!("Sesion trifasica PAdES no valida: falta {m}"));
        Ok(PadesSession {
            pre: pre.ok_or_else(|| bad(PRE))?,
            time: time.ok_or_else(|| bad(TIME))?,
            file_id: pid.ok_or_else(|| bad(PID))?,
            pk1,
        })
    }
}

/// Prefirma trifásica (lado servidor). `algorithm` es el nombre recibido
/// (`SHA256withRSA`...), `key_algorithm` el tipo de la clave del certificado.
pub fn presign(
    pdf: &[u8],
    algorithm: &str,
    key_algorithm: KeyAlgorithm,
    chain: &[Vec<u8>],
    sign_time: SignTime,
    xp: &ExtraParams,
) -> Result<(PadesPreSign, PadesSession), AfirmaError> {
    let mut xp = xp.clone();
    crate::pades::params::check_params(algorithm, &mut xp)?;
    let alg = compose_signature_algorithm(algorithm, key_algorithm)?;
    let chain = if crate::pades::params::is_true(&xp, crate::pades::params::INCLUDE_ONLY_SIGNING_CERTIFICATE) {
        chain.iter().take(1).cloned().collect::<Vec<_>>()
    } else {
        chain.to_vec()
    };
    // Sin milisegundos: la sesión solo transporta la fecha en ms, pero la
    // fecha PDF y el texto visible tienen precisión de segundos.
    let pre = PadesSigner::new().presign(pdf, alg, &chain, sign_time, &xp)?;
    let session = PadesSession {
        pre: pre.signed_attributes.clone(),
        time: millis(&sign_time),
        file_id: file_id_string(&pre.prepared.file_id),
        pk1: None,
    };
    Ok((pre, session))
}

/// Firma del cliente: PKCS#1 sobre `PRE` (`TriphaseDataSigner.doSign`).
pub fn sign_pre(pre: &[u8], algorithm: &str, key: &dyn SigningKey) -> Result<Vec<u8>, AfirmaError> {
    let alg = compose_signature_algorithm(algorithm, key.key_algorithm())?;
    Ok(key.sign(pre, alg)?)
}

/// Postfirma trifásica (lado servidor, sin estado): regenera la revisión con
/// los mismos datos de la prefirma, comprueba el `PID` y los atributos, e
/// inserta el PKCS#1 del cliente.
pub fn postsign(
    pdf: &[u8],
    algorithm: &str,
    key_algorithm: KeyAlgorithm,
    chain: &[Vec<u8>],
    session: &PadesSession,
    xp: &ExtraParams,
) -> Result<Vec<u8>, AfirmaError> {
    let pk1 = session
        .pk1
        .as_ref()
        .ok_or_else(|| AfirmaError::invalid_argument("La sesion trifasica no contiene el PKCS#1 (PK1)"))?;
    let sign_time =
        from_millis(session.time).ok_or_else(|| AfirmaError::invalid_argument("Fecha de firma trifasica no valida"))?;
    let (pre, regenerated) = presign(pdf, algorithm, key_algorithm, chain, sign_time, xp)?;
    if regenerated.file_id != session.file_id || regenerated.pre != session.pre {
        return Err(crate::pades::errors::internal(
            "La postfirma PAdES no reproduce la prefirma (el documento o los parametros han cambiado)",
        ));
    }
    let mut xp = xp.clone();
    crate::pades::params::check_params(algorithm, &mut xp)?;
    let tsa = crate::tsp::TsaParams::from_extra_params(&xp)?
        .filter(|_| xp.get(crate::pades::params::TS_TYPE).unwrap_or("").trim() != "2");
    PadesSigner::new().postsign(&pre, pk1, tsa.as_ref(), &xp)
}
