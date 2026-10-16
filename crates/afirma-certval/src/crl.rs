//! Listas de revocación (CRL, RFC 5280 §5): análisis, verificación de la
//! firma y búsqueda del número de serie.

use std::borrow::Cow;

use afirma_cms::asn1::{Tag, Tlv, tags};
use afirma_cms::cert::minimal_twos_complement;
use chrono::{DateTime, Utc};

use crate::result::{RevocationInfo, RevocationReason};

/// `id-ce-cRLReasons`.
const OID_CRL_REASON: &str = "2.5.29.21";
/// `id-ce-deltaCRLIndicator`.
const OID_DELTA_CRL: &str = "2.5.29.27";

/// Vista de una CRL sobre sus bytes DER.
#[derive(Debug, Clone)]
pub(crate) struct CrlView<'a> {
    pub tbs: &'a [u8],
    pub sig_alg: &'a [u8],
    pub signature: &'a [u8],
    pub issuer: &'a [u8],
    pub this_update: DateTime<Utc>,
    pub next_update: Option<DateTime<Utc>>,
    revoked: Option<Tlv<'a>>,
    /// Es una CRL delta (incompleta por sí sola).
    pub is_delta: bool,
}

fn e<E: std::fmt::Display>(err: E) -> String {
    format!("CRL mal formada: {err}")
}

fn is_time(t: &Tlv<'_>) -> bool {
    t.tag == tags::UTC_TIME || t.tag == tags::GENERALIZED_TIME
}

/// Bytes DER de una CRL descargada: DER tal cual, o PEM (`X509 CRL`) o
/// Base64.
pub(crate) fn decode(data: &[u8]) -> Option<Cow<'_, [u8]>> {
    if data.first() == Some(&0x30) {
        return Some(Cow::Borrowed(data));
    }
    let text = std::str::from_utf8(data).ok()?;
    let b64: String = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = afirma_core::base64_decode_lenient(&b64).ok()?;
    (der.first() == Some(&0x30)).then_some(Cow::Owned(der))
}

impl<'a> CrlView<'a> {
    /// Analiza una CRL DER.
    pub fn parse(der: &'a [u8]) -> Result<Self, String> {
        let top = Tlv::parse_single(der).and_then(|t| t.children()).map_err(e)?;
        let [tbs, sig_alg, sig] = top.as_slice() else {
            return Err(e("estructura incorrecta"));
        };
        let fields = tbs.children().map_err(e)?;
        let mut i = 0;
        if fields.first().is_some_and(|f| f.tag == tags::INTEGER) {
            i += 1;
        }
        let _alg = fields.get(i).ok_or_else(|| e("sin algoritmo"))?;
        let issuer = fields
            .get(i + 1)
            .ok_or_else(|| e("sin emisor"))?
            .expect(tags::SEQUENCE)
            .map_err(e)?;
        let this_update = fields
            .get(i + 2)
            .ok_or_else(|| e("sin thisUpdate"))?
            .as_time()
            .map_err(e)?;
        i += 3;
        let mut next_update = None;
        if let Some(t) = fields.get(i).filter(|t| is_time(t)) {
            next_update = Some(t.as_time().map_err(e)?);
            i += 1;
        }
        let mut revoked = None;
        if let Some(t) = fields.get(i).filter(|t| t.tag == tags::SEQUENCE) {
            revoked = Some(*t);
            i += 1;
        }
        let mut is_delta = false;
        if let Some(t) = fields.get(i).filter(|t| t.tag == Tag::context(0, true)) {
            for ext in t
                .children()
                .map_err(e)?
                .first()
                .map(|s| s.children())
                .transpose()
                .map_err(e)?
                .unwrap_or_default()
            {
                let parts = ext.children().map_err(e)?;
                if parts
                    .first()
                    .and_then(|o| o.as_oid().ok())
                    .is_some_and(|o| o.is(OID_DELTA_CRL))
                {
                    is_delta = true;
                }
            }
        }
        Ok(CrlView {
            tbs: tbs.raw,
            sig_alg: sig_alg.raw,
            signature: sig.bit_string_content().map_err(e)?,
            issuer: issuer.raw,
            this_update,
            next_update,
            revoked,
            is_delta,
        })
    }

    /// Busca un número de serie (complemento a dos) entre los revocados.
    pub fn find(&self, serial: &[u8]) -> Result<Option<RevocationInfo>, String> {
        let Some(list) = self.revoked else { return Ok(None) };
        let target = minimal_twos_complement(serial);
        for entry in list.children().map_err(e)? {
            let f = entry.children().map_err(e)?;
            let Some(s) = f.first() else { continue };
            if minimal_twos_complement(s.as_integer_bytes().map_err(e)?) != target {
                continue;
            }
            let time = f.get(1).and_then(|t| t.as_time().ok());
            let reason = f.get(2).and_then(|exts| entry_reason(exts));
            return Ok(Some(RevocationInfo { time, reason }));
        }
        Ok(None)
    }
}

/// Motivo de revocación de las extensiones de una entrada.
fn entry_reason(exts: &Tlv<'_>) -> Option<RevocationReason> {
    for ext in exts.children().ok()? {
        let parts = ext.children().ok()?;
        if !parts.first()?.as_oid().ok()?.is(OID_CRL_REASON) {
            continue;
        }
        let value = parts.last()?.octet_string_content().ok()?;
        let reason = Tlv::parse_single(&value).ok()?.as_i64().ok()?;
        return u8::try_from(reason).ok().map(RevocationReason);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoding() {
        assert!(decode(b"\x30\x00").is_some());
        assert!(decode(b"-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n").is_some());
        assert!(decode(b"no es una CRL").is_none());
        assert!(CrlView::parse(b"\x30\x00").is_err());
    }
}
