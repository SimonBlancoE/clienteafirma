//! Firmador según el formato pedido en Autofirma App 1.9
//! (`SignTask.getSupportedCompatibleSigner` y `AOSignerFactory` con las
//! bibliotecas que lleva la app; `docs/spec/09-android.md` §3.7.1 y §5.14).
//!
//! | Formato (sin distinguir mayúsculas) | Firmador |
//! |---|---|
//! | empieza por `xades` | `XAdEStri` (la app no lleva XAdES monofásico) |
//! | empieza por `facturae` | `FacturaEtri` |
//! | `AUTO` en cofirma o contrafirma | el de la firma recibida entre CAdES, CAdES-ASiC-S y PAdES |
//! | `CAdES`, `CAdES-ASiC-S`, `PAdES`, `Adobe PDF`, `NONE` | monofásico local |
//! | `CAdEStri`, `CAdES-ASiC-S-tri`, `PAdEStri`, `Adobe PDF TriPhase`, `NONEtri` | trifásico |
//! | cualquier otro (`CMS/PKCS#7`, `XMLDSig*`, `ODF*`, `OOXML*`, `Factura-e`, `AUTO` en firma…) | ninguno: «formato no soportado» |
//!
//! Los trifásicos (y por tanto XAdES y FacturaE) necesitan el extraParam
//! `serverUrl` (§10 n.º 31).
//!
//! Corrección (§10 n.º 30): Java firmaba `XAdES-ASiC-S` y `XAdES-ASiC-S-tri`
//! como XAdES trifásica **sin** contenedor ASiC; aquí se usan como
//! `XAdES-ASiC-S-tri`, que es lo que pide la página.

use crate::triphase::{CryptoOperation, TriphaseFormat};

/// Firmador elegido.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AndroidSigner {
    /// Firmador monofásico local, con el nombre de formato que se le pasa
    /// (`CAdES`, `CAdES-ASiC-S`, `PAdES`, `Adobe PDF` o `NONE`).
    Local(&'static str),
    /// Firmador trifásico cliente.
    Triphase(TriphaseFormat),
}

impl AndroidSigner {
    /// Nombre del formato del firmador.
    pub fn format_name(self) -> &'static str {
        match self {
            AndroidSigner::Local(f) => f,
            AndroidSigner::Triphase(t) => match t {
                TriphaseFormat::Cades => "CAdEStri",
                TriphaseFormat::CadesAsics => "CAdES-ASiC-S-tri",
                TriphaseFormat::Xades => "XAdEStri",
                TriphaseFormat::XadesAsics => "XAdES-ASiC-S-tri",
                TriphaseFormat::FacturaE => "FacturaEtri",
                TriphaseFormat::Pades => "PAdEStri",
                TriphaseFormat::None => "NONEtri",
            },
        }
    }
}

/// Formatos monofásicos que lleva la app (`AOSignerFactory.getSigner(String)`
/// sin distinguir mayúsculas).
const LOCAL_FORMATS: &[&str] = &["CAdES", "CAdES-ASiC-S", "PAdES", "Adobe PDF", "NONE"];

/// Formatos con identificación de firmas disponibles en la app, en el orden de
/// `AOSignerFactory.getSigner(byte[])`.
pub const AUTO_DETECTION_FORMATS: &[&str] = &["CAdES", "CAdES-ASiC-S", "PAdES"];

/// Firmador para un formato, sin considerar `AUTO` (que necesita los datos).
pub fn signer_for_format(format: &str) -> Option<AndroidSigner> {
    let lower = format.to_lowercase();
    if lower.starts_with("xades") {
        return Some(AndroidSigner::Triphase(if lower.starts_with("xades-asic-s") {
            TriphaseFormat::XadesAsics
        } else {
            TriphaseFormat::Xades
        }));
    }
    if lower.starts_with("facturae") {
        return Some(AndroidSigner::Triphase(TriphaseFormat::FacturaE));
    }
    if let Some(f) = LOCAL_FORMATS.iter().find(|f| f.eq_ignore_ascii_case(format)) {
        return Some(AndroidSigner::Local(f));
    }
    TriphaseFormat::from_format_name(format).map(AndroidSigner::Triphase)
}

/// Indica si el formato es `AUTO` y la operación permite detectarlo (cofirma
/// o contrafirma).
pub fn is_auto_detection(format: &str, op: CryptoOperation) -> bool {
    format.eq_ignore_ascii_case("AUTO") && op != CryptoOperation::Sign
}

/// Resultado de la detección de `AUTO` restringido a los formatos de la app:
/// `detected` es el formato que identificó el firmador local (`PAdES` y
/// `Adobe PDF` son el mismo firmador).
pub fn auto_signer(detected: Option<&str>) -> Option<AndroidSigner> {
    let d = detected?;
    if d.eq_ignore_ascii_case("Adobe PDF") || d.eq_ignore_ascii_case("PAdES") {
        return Some(AndroidSigner::Local("PAdES"));
    }
    AUTO_DETECTION_FORMATS
        .iter()
        .find(|f| f.eq_ignore_ascii_case(d))
        .map(|f| AndroidSigner::Local(f))
}

/// Formatos con comprobación de PDF y firma visible (comparación exacta,
/// §5.4.4 y §5.5).
pub const PDF_FORMATS: &[&str] = &["PAdES", "PAdEStri", "Adobe PDF", "Adobe PDF TriPhase"];

/// Formatos cuya política se expande en la app (`CAdES` y `PAdES` exactos,
/// §10 n.º 58).
pub const POLICY_EXPANSION_FORMATS: &[&str] = &["CAdES", "PAdES"];

/// Formatos para los que el selector de ficheros filtra `.pdf` (Android < 11).
pub const PDF_FILTER_FORMATS: &[&str] = &["PAdES", "PAdEStri"];

/// `FileUtil.isPdfFile`: al menos 70 bytes y cabecera `%PDF-`.
pub fn is_pdf_file(data: &[u8]) -> bool {
    data.len() >= 70 && data.starts_with(b"%PDF-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        let tri = |t| Some(AndroidSigner::Triphase(t));
        assert_eq!(signer_for_format("XAdES"), tri(TriphaseFormat::Xades));
        assert_eq!(signer_for_format("xades enveloping"), tri(TriphaseFormat::Xades));
        assert_eq!(signer_for_format("XAdEStri"), tri(TriphaseFormat::Xades));
        assert_eq!(signer_for_format("XAdES Detached"), tri(TriphaseFormat::Xades));
        // Corrección: ASiC conservado.
        assert_eq!(signer_for_format("XAdES-ASiC-S"), tri(TriphaseFormat::XadesAsics));
        assert_eq!(signer_for_format("XAdES-ASiC-S-tri"), tri(TriphaseFormat::XadesAsics));
        assert_eq!(signer_for_format("FacturaE"), tri(TriphaseFormat::FacturaE));
        assert_eq!(signer_for_format("facturaetri"), tri(TriphaseFormat::FacturaE));
        assert_eq!(signer_for_format("cades"), Some(AndroidSigner::Local("CAdES")));
        assert_eq!(
            signer_for_format("CAdES-ASiC-S"),
            Some(AndroidSigner::Local("CAdES-ASiC-S"))
        );
        assert_eq!(signer_for_format("Adobe PDF"), Some(AndroidSigner::Local("Adobe PDF")));
        assert_eq!(signer_for_format("NONE"), Some(AndroidSigner::Local("NONE")));
        assert_eq!(signer_for_format("PAdEStri"), tri(TriphaseFormat::Pades));
        assert_eq!(signer_for_format("Adobe PDF TriPhase"), tri(TriphaseFormat::Pades));
        assert_eq!(signer_for_format("CAdES-ASiC-S-tri"), tri(TriphaseFormat::CadesAsics));
        assert_eq!(signer_for_format("NONEtri"), tri(TriphaseFormat::None));
        for f in [
            "CMS/PKCS#7",
            "XMLDSig",
            "XMLDSig Enveloped",
            "ODF",
            "OOXML",
            "Factura-e",
            "AUTO",
            "",
        ] {
            assert_eq!(signer_for_format(f), None, "{f}");
        }
        assert_eq!(AndroidSigner::Triphase(TriphaseFormat::Pades).format_name(), "PAdEStri");
    }

    #[test]
    fn auto() {
        assert!(is_auto_detection("auto", CryptoOperation::CoSign));
        assert!(!is_auto_detection("AUTO", CryptoOperation::Sign));
        assert_eq!(auto_signer(Some("Adobe PDF")), Some(AndroidSigner::Local("PAdES")));
        assert_eq!(auto_signer(Some("CAdES")), Some(AndroidSigner::Local("CAdES")));
        // Formatos que la app no lleva: no se identifican.
        assert_eq!(auto_signer(Some("XAdES")), None);
        assert_eq!(auto_signer(Some("CMS/PKCS#7")), None);
        assert_eq!(auto_signer(None), None);
    }

    #[test]
    fn pdf_check() {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        assert!(!is_pdf_file(&pdf));
        pdf.resize(70, b' ');
        assert!(is_pdf_file(&pdf));
        assert!(!is_pdf_file(&[b' '; 80]));
    }
}
