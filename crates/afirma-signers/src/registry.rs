//! Registro de firmadores (`AOSignerFactory`).
//!
//! La tabla de formatos (nombres, familias y orden de detección) está en
//! [`afirma_core::formats`]; aquí se asocia cada familia con su
//! implementación. Los formatos trifásicos (`*tri`) los resuelve el crate del
//! protocolo, que habla con el servidor de firma.

use afirma_core::formats::{self, SignerKind};
use afirma_core::{ExtraParams, Signer};

/// Firmador de una familia (`None` si no hay implementación local, como en
/// los formatos trifásicos).
pub fn signer(kind: SignerKind) -> Option<Box<dyn Signer>> {
    Some(match kind {
        SignerKind::Cades => Box::new(afirma_cms::CadesSigner),
        SignerKind::Cms => Box::new(afirma_cms::CmsSigner),
        SignerKind::CadesAsicS => Box::new(afirma_cms::CadesAsicsSigner),
        SignerKind::Xades => Box::new(afirma_xml::xades::XadesSigner::new()),
        SignerKind::FacturaE => Box::new(afirma_xml::facturae::FacturaeSigner::new()),
        SignerKind::XadesAsicS => Box::new(afirma_xml::asic::XadesAsicSigner::new()),
        SignerKind::Pdf => Box::new(afirma_pdf::PadesSigner::new()),
        SignerKind::Pkcs1 => Box::new(crate::pkcs1::Pkcs1Signer),
        SignerKind::XmlDSig | SignerKind::Odf | SignerKind::Ooxml => return extra_signer(kind),
        SignerKind::CadesTri
        | SignerKind::CadesAsicSTri
        | SignerKind::FacturaETri
        | SignerKind::XadesTri
        | SignerKind::XadesAsicSTri
        | SignerKind::PdfTri
        | SignerKind::Pkcs1Tri => return None,
    })
}

/// Firmadores que aún pueden no estar disponibles en todas las
/// compilaciones (XMLDSig, ODF y OOXML).
fn extra_signer(kind: SignerKind) -> Option<Box<dyn Signer>> {
    tracing::debug!("firmador no disponible en esta compilación: {kind:?}");
    None
}

/// Firmador para un nombre de formato (sin distinguir mayúsculas), como
/// `AOSignerFactory.getSigner(String)`.
pub fn signer_for_format(format: &str) -> Option<Box<dyn Signer>> {
    formats::signer_kind_for_format(format).and_then(signer)
}

/// Detecta el formato de una firma probando los firmadores en el orden de
/// AutoFirma (`AOSignerFactory.getSigner(byte[])`).
pub fn detect(data: &[u8], params: &ExtraParams) -> Option<(SignerKind, Box<dyn Signer>)> {
    for kind in formats::detection_order() {
        if let Some(s) = signer(kind) {
            if s.is_sign(data, params) {
                return Some((kind, s));
            }
        }
    }
    None
}

/// Nombre de formato de una firma detectada (`getSignFormat`), p. ej.
/// `Adobe PDF` para un PDF firmado, como en Java.
pub fn detect_format_name(data: &[u8], params: &ExtraParams) -> Option<&'static str> {
    detect(data, params).map(|(k, _)| formats::get_sign_format(k))
}
