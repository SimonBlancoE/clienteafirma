//! Detección del DNIe 3.0/4.0 sin contacto (especificación 10 §3).
//!
//! JMulticard compara lo que devuelve `reset()` con dos patrones de pseudo-ATR **por sufijo**
//! (`Atr.equals`), lo que en Android (DNIe tipo B, bytes históricos nulos y respuesta de capa
//! superior previsiblemente vacía) acepta cualquier tarjeta tipo B. Aquí se reproduce esa
//! comparación para la ruta de paridad y, cuando el transporte aporta los datos del ATQB
//! (`NfcB.getApplicationData()`/`getProtocolInfo()`), se construye el pseudo-ATR PC/SC completo y
//! se compara entero con `ATR_NFC`, que rechaza limpiamente las tarjetas que no son DNIe.

use crate::error::DnieError;
use crate::transport::CardIdentification;

/// Patrón de ATR con su máscara (`FF` = octeto significativo).
#[derive(Debug, Clone, Copy)]
pub struct AtrPattern {
    pub name: &'static str,
    pub pattern: &'static [u8],
    pub mask: &'static [u8],
}

/// Pseudo-ATR PC/SC del DNIe tipo B: `3B 88 80 01` + datos de aplicación del ATQB
/// (`E1 F3 5E 11`) + información de protocolo (`77 81 xx`) + MBLI + TCK.
pub const ATR_NFC: AtrPattern = AtrPattern {
    name: "ATR_NFC",
    pattern: &[
        0x3B, 0x88, 0x80, 0x01, 0xE1, 0xF3, 0x5E, 0x11, 0x77, 0x81, 0xA1, 0x00, 0x03,
    ],
    mask: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00,
    ],
};

/// Formato de otros lectores: `3B 8C 80 01 50` + PUPI + datos de aplicación + información de
/// protocolo + TCK.
pub const ATR_NFC2: AtrPattern = AtrPattern {
    name: "ATR_NFC2",
    pattern: &[
        0x3B, 0x8C, 0x80, 0x01, 0x50, 0x42, 0x8E, 0x93, 0x2A, 0xE1, 0xF3, 0x5E, 0x11, 0x77, 0x81, 0x81, 0x02,
    ],
    mask: &[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    ],
};

/// ATR de contacto del DNIe (`3B 7F … 6A 44 4E 49 65 … 90 00`; no soportado por este controlador).
pub const ATR_CONTACT: AtrPattern = AtrPattern {
    name: "ATR (contacto)",
    pattern: &[
        0x3B, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x44, 0x4E, 0x49, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x90, 0x00,
    ],
    mask: &[
        0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF,
    ],
};

impl AtrPattern {
    /// Semántica exacta de `Atr.equals` de JMulticard (§3.2): compara `actual` con el **sufijo**
    /// del patrón usando la máscara del patrón. Una entrada vacía siempre coincide.
    pub fn matches_suffix(&self, actual: &[u8]) -> bool {
        if self.pattern.len() < actual.len() {
            return false;
        }
        let off = self.pattern.len() - actual.len();
        (0..actual.len())
            .rev()
            .all(|i| self.pattern[i + off] & self.mask[i + off] == actual[i] & self.mask[i + off])
    }

    /// Comparación completa (misma longitud) con la máscara.
    pub fn matches_exactly(&self, actual: &[u8]) -> bool {
        actual.len() == self.pattern.len() && self.matches_suffix(actual)
    }
}

/// Construye el pseudo-ATR PC/SC (PC/SC parte 3, tarjetas tipo B) a partir de los datos de
/// aplicación (4 octetos) y la información de protocolo (3 octetos) del ATQB:
/// `3B 88 80 01 ‖ appData ‖ protInfo ‖ 00 ‖ TCK`.
pub fn pseudo_atr_type_b(app_data: &[u8], protocol_info: &[u8]) -> Option<Vec<u8>> {
    if app_data.len() != 4 || protocol_info.len() != 3 {
        return None;
    }
    let mut atr = vec![0x3B, 0x88, 0x80, 0x01];
    atr.extend_from_slice(app_data);
    atr.extend_from_slice(protocol_info);
    atr.push(0x00);
    let tck = atr[1..].iter().fold(0u8, |a, b| a ^ b);
    atr.push(tck);
    Some(atr)
}

/// Con qué datos se ha reconocido la tarjeta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectionEvidence {
    /// Pseudo-ATR construido con los datos del ATQB y comparado entero con `ATR_NFC`.
    NfcBPseudoAtr(Vec<u8>),
    /// (Pseudo-)ATR del lector, comparado como JMulticard.
    Atr(Vec<u8>),
    /// Bytes históricos o respuesta de capa superior (Android sin datos del ATQB), comparados
    /// como JMulticard; incluye el caso de respuesta vacía, que JMulticard acepta siempre.
    ResetBytes(Vec<u8>),
    /// El llamante ha pedido omitir la detección.
    Skipped,
}

/// Política de detección.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetectionPolicy {
    /// Pseudo-ATR completo si hay datos del ATQB; si no, comparación de JMulticard.
    #[default]
    Strict,
    /// Solo la comparación de JMulticard (paridad exacta).
    JMulticard,
    /// No comprobar (transportes sin datos de identificación).
    Skip,
}

/// Reconoce un DNIe 3.0/4.0 sin contacto.
pub fn detect(id: &CardIdentification, policy: DetectionPolicy) -> Result<DetectionEvidence, DnieError> {
    if policy == DetectionPolicy::Skip {
        return Ok(DetectionEvidence::Skipped);
    }
    if policy == DetectionPolicy::Strict
        && let (Some(app), Some(prot)) = (&id.nfcb_application_data, &id.nfcb_protocol_info)
    {
        let atr = pseudo_atr_type_b(app, prot).ok_or_else(|| {
            DnieError::CardNotSupported("datos de aplicación o de protocolo del ATQB con longitud no válida".into())
        })?;
        tracing::info!(
            "Pseudo-ATR construido con los datos del ATQB: {}",
            hex::encode_upper(&atr)
        );
        return if ATR_NFC.matches_exactly(&atr) {
            Ok(DetectionEvidence::NfcBPseudoAtr(atr))
        } else {
            Err(DnieError::CardNotSupported(format!(
                "la tarjeta tipo B no es un DNIe (pseudo-ATR {})",
                hex::encode_upper(&atr)
            )))
        };
    }
    let bytes = id.jmulticard_reset_bytes();
    tracing::info!("Identificación de la tarjeta: {}", hex::encode_upper(&bytes));
    if ATR_NFC.matches_suffix(&bytes) || ATR_NFC2.matches_suffix(&bytes) {
        return Ok(if id.atr.is_some() {
            DetectionEvidence::Atr(bytes)
        } else {
            DetectionEvidence::ResetBytes(bytes)
        });
    }
    if bytes.len() >= 2 && bytes[bytes.len() - 2..] == [0x65, 0x81] {
        return Err(DnieError::CardNotSupported(
            "DNIe con la memoria volátil borrada («quemado»)".into(),
        ));
    }
    if ATR_CONTACT.matches_exactly(&bytes) {
        return Err(DnieError::CardNotSupported(
            "DNIe por contacto: este controlador solo admite el acceso sin contacto".into(),
        ));
    }
    Err(DnieError::CardNotSupported(format!(
        "identificación no reconocida ({})",
        hex::encode_upper(&bytes)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn jmc(bytes: &str) -> bool {
        let b = hx(bytes);
        ATR_NFC.matches_suffix(&b) || ATR_NFC2.matches_suffix(&b)
    }

    #[test]
    fn jmulticard_table() {
        // §3.2 y testdata/dnie/transcript_detect.txt.
        assert!(jmc(""));
        assert!(jmc("3B888001E1F35E117781A10003"));
        assert!(jmc("3B8C800150428E932AE1F35E1177818102"));
        assert!(jmc("E1F35E117781A100"));
        assert!(jmc("3B8C800150D71A03F3E1F35E117781A16A"));
        assert!(jmc("0102"));
        assert!(!jmc("AABBCC"));
        assert!(!jmc("3B8F8001804F0CA000000306030001000000006A"));
        assert!(!jmc("3B8180018080"));
    }

    #[test]
    fn pseudo_atr_from_atqb() {
        let atr = pseudo_atr_type_b(&hx("E1F35E11"), &hx("7781A1")).unwrap();
        assert_eq!(atr, hx("3B888001E1F35E117781A10003"));
        assert!(ATR_NFC.matches_exactly(&atr));
        // Otro FWI/ADC/FO (enmascarado) también vale; otros datos de aplicación no.
        assert!(ATR_NFC.matches_exactly(&pseudo_atr_type_b(&hx("E1F35E11"), &hx("778185")).unwrap()));
        assert!(!ATR_NFC.matches_exactly(&pseudo_atr_type_b(&hx("00000000"), &hx("7781A1")).unwrap()));
        assert!(pseudo_atr_type_b(&hx("E1F35E"), &hx("7781A1")).is_none());
    }

    #[test]
    fn detection_policies() {
        let android_dnie = CardIdentification {
            hi_layer_response: Some(vec![]),
            nfcb_application_data: Some(hx("E1F35E11")),
            nfcb_protocol_info: Some(hx("7781A1")),
            ..Default::default()
        };
        assert!(matches!(
            detect(&android_dnie, DetectionPolicy::Strict),
            Ok(DetectionEvidence::NfcBPseudoAtr(_))
        ));
        let other_b = CardIdentification {
            hi_layer_response: Some(vec![]),
            nfcb_application_data: Some(hx("00112233")),
            nfcb_protocol_info: Some(hx("718100")),
            ..Default::default()
        };
        // JMulticard acepta cualquier tipo B con HLR vacío; la política estricta la rechaza.
        assert!(matches!(
            detect(&other_b, DetectionPolicy::Strict),
            Err(DnieError::CardNotSupported(_))
        ));
        assert!(matches!(
            detect(&other_b, DetectionPolicy::JMulticard),
            Ok(DetectionEvidence::ResetBytes(_))
        ));
        let pcsc = CardIdentification::from_atr(hx("3B888001E1F35E117781A10003"));
        assert!(matches!(
            detect(&pcsc, DetectionPolicy::Strict),
            Ok(DetectionEvidence::Atr(_))
        ));
        let ceres = CardIdentification::from_atr(hx("3B8F8001804F0CA000000306030001000000006A"));
        assert!(detect(&ceres, DetectionPolicy::Strict).is_err());
        let contact = CardIdentification::from_atr(hx("3B7F960000006A444E4965100101550421039000"));
        assert!(detect(&contact, DetectionPolicy::Strict).is_err());
        let burned = CardIdentification::from_atr(hx("3B7F960000006A444E4965100101550421036581"));
        assert!(
            detect(&burned, DetectionPolicy::Strict)
                .unwrap_err()
                .to_string()
                .contains("quemado")
        );
        assert_eq!(
            detect(&CardIdentification::default(), DetectionPolicy::Skip).unwrap(),
            DetectionEvidence::Skipped
        );
    }
}
