//! Tabla de formatos de `AOSignerFactory` (`docs/spec/07-core.md` §4).
//!
//! Los firmadores concretos viven en otros crates; aquí se modela la tabla de
//! registro como datos: nombre del formato, familia del firmador
//! ([`SignerKind`], equivalente a la clase Java que lo implementa) e
//! indicador de si se usa para detectar el formato de una firma
//! (`AOSignerFactory.getSigner(byte[])`). El orden de la tabla es el de Java
//! y es también el orden de detección.

use crate::constants::*;

/// Firmador que implementa un formato (una variante por clase Java).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerKind {
    /// `AOCAdESSigner`.
    Cades,
    /// `AOCAdESTriPhaseSigner`.
    CadesTri,
    /// `AOCAdESASiCSSigner`.
    CadesAsicS,
    /// `AOCAdESASiCSTriPhaseSigner`.
    CadesAsicSTri,
    /// `AOCMSSigner`.
    Cms,
    /// `AOFacturaESigner`.
    FacturaE,
    /// `AOFacturaETriPhaseSigner`.
    FacturaETri,
    /// `AOXAdESSigner`.
    Xades,
    /// `AOXAdESTriPhaseSigner`.
    XadesTri,
    /// `AOXAdESASiCSSigner`.
    XadesAsicS,
    /// `AOXAdESASiCSTriPhaseSigner`.
    XadesAsicSTri,
    /// `AOXMLDSigSigner`.
    XmlDSig,
    /// `AOPDFSigner` (PAdES).
    Pdf,
    /// `AOPDFTriPhaseSigner`.
    PdfTri,
    /// `AOODFSigner`.
    Odf,
    /// `AOOOXMLSigner`.
    Ooxml,
    /// `AOPkcs1Signer` (`NONE`).
    Pkcs1,
    /// `AOPkcs1TriPhaseSigner` (`NONEtri`).
    Pkcs1Tri,
}

impl SignerKind {
    /// Todas las familias, en el orden de su primera aparición en la tabla.
    pub const ALL: [SignerKind; 18] = [
        Self::Cades,
        Self::CadesTri,
        Self::CadesAsicS,
        Self::CadesAsicSTri,
        Self::Cms,
        Self::FacturaE,
        Self::FacturaETri,
        Self::Xades,
        Self::XadesTri,
        Self::XadesAsicS,
        Self::XadesAsicSTri,
        Self::XmlDSig,
        Self::Pdf,
        Self::PdfTri,
        Self::Odf,
        Self::Ooxml,
        Self::Pkcs1,
        Self::Pkcs1Tri,
    ];

    /// Nombre de formato con el que `AOSignerFactory.getSignFormat` identifica
    /// a este firmador: el de la primera fila de la tabla con la misma clase.
    /// Así `Pdf` → `Adobe PDF` (no `PAdES`), `Xades` → `XAdES`, `Odf` →
    /// `ODF (Open Document Format)`.
    pub fn sign_format(self) -> &'static str {
        SIGNER_FORMATS.iter().find(|f| f.kind == self).map(|f| f.name).unwrap_or(SIGN_FORMAT_CADES)
    }

    /// Nombre de la clase Java equivalente.
    pub fn java_class(self) -> &'static str {
        match self {
            Self::Cades => "es.gob.afirma.signers.cades.AOCAdESSigner",
            Self::CadesTri => "es.gob.afirma.signers.cadestri.client.AOCAdESTriPhaseSigner",
            Self::CadesAsicS => "es.gob.afirma.signers.cades.asic.AOCAdESASiCSSigner",
            Self::CadesAsicSTri => "es.gob.afirma.signers.cadestri.client.asic.AOCAdESASiCSTriPhaseSigner",
            Self::Cms => "es.gob.afirma.signers.cms.AOCMSSigner",
            Self::FacturaE => "es.gob.afirma.signers.xades.AOFacturaESigner",
            Self::FacturaETri => "es.gob.afirma.signers.xadestri.client.AOFacturaETriPhaseSigner",
            Self::Xades => "es.gob.afirma.signers.xades.AOXAdESSigner",
            Self::XadesTri => "es.gob.afirma.signers.xadestri.client.AOXAdESTriPhaseSigner",
            Self::XadesAsicS => "es.gob.afirma.signers.xades.asic.AOXAdESASiCSSigner",
            Self::XadesAsicSTri => "es.gob.afirma.signers.xadestri.client.asic.AOXAdESASiCSTriPhaseSigner",
            Self::XmlDSig => "es.gob.afirma.signers.xmldsig.AOXMLDSigSigner",
            Self::Pdf => "es.gob.afirma.signers.pades.AOPDFSigner",
            Self::PdfTri => "es.gob.afirma.signers.padestri.client.AOPDFTriPhaseSigner",
            Self::Odf => "es.gob.afirma.signers.odf.AOODFSigner",
            Self::Ooxml => "es.gob.afirma.signers.ooxml.AOOOXMLSigner",
            Self::Pkcs1 => "es.gob.afirma.core.signers.AOPkcs1Signer",
            Self::Pkcs1Tri => "es.gob.afirma.core.signers.AOPkcs1TriPhaseSigner",
        }
    }

    /// Indica si es un firmador trifásico.
    pub fn is_triphase(self) -> bool {
        matches!(
            self,
            Self::CadesTri
                | Self::CadesAsicSTri
                | Self::FacturaETri
                | Self::XadesTri
                | Self::XadesAsicSTri
                | Self::PdfTri
                | Self::Pkcs1Tri
        )
    }

    /// Indica si `AOSignerFactory.getSigner(byte[])` prueba este firmador
    /// para detectar el formato de una firma.
    pub fn used_for_detection(self) -> bool {
        SIGNER_FORMATS.iter().any(|f| f.kind == self && f.used_for_detection)
    }
}

/// Fila de la tabla de registro de `AOSignerFactory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerFormat {
    /// Nombre del formato (clave de la tabla).
    pub name: &'static str,
    /// Firmador que lo implementa.
    pub kind: SignerKind,
    /// Si se usa para detectar el formato de una firma (`isSign`).
    pub used_for_detection: bool,
}

const fn row(name: &'static str, kind: SignerKind, used_for_detection: bool) -> SignerFormat {
    SignerFormat { name, kind, used_for_detection }
}

/// Tabla de registro de `AOSignerFactory`, en su orden exacto (que también
/// es el de detección).
pub static SIGNER_FORMATS: [SignerFormat; 29] = [
    row(SIGN_FORMAT_CADES, SignerKind::Cades, true),
    row(SIGN_FORMAT_CADES_TRI, SignerKind::CadesTri, false),
    row(SIGN_FORMAT_CADES_ASIC_S, SignerKind::CadesAsicS, true),
    row(SIGN_FORMAT_CADES_ASIC_S_TRI, SignerKind::CadesAsicSTri, false),
    row(SIGN_FORMAT_CMS, SignerKind::Cms, true),
    row(SIGN_FORMAT_FACTURAE, SignerKind::FacturaE, true),
    row(SIGN_FORMAT_FACTURAE_ALT1, SignerKind::FacturaE, false),
    row(SIGN_FORMAT_FACTURAE_TRI, SignerKind::FacturaETri, false),
    row(SIGN_FORMAT_XADES, SignerKind::Xades, true),
    row(SIGN_FORMAT_XADES_DETACHED, SignerKind::Xades, false),
    row(SIGN_FORMAT_XADES_ENVELOPED, SignerKind::Xades, false),
    row(SIGN_FORMAT_XADES_ENVELOPING, SignerKind::Xades, false),
    row(SIGN_FORMAT_XADES_TRI, SignerKind::XadesTri, false),
    row(SIGN_FORMAT_XADES_ASIC_S, SignerKind::XadesAsicS, true),
    row(SIGN_FORMAT_XADES_ASIC_S_TRI, SignerKind::XadesAsicSTri, false),
    row(SIGN_FORMAT_XMLDSIG, SignerKind::XmlDSig, true),
    row(SIGN_FORMAT_XMLDSIG_DETACHED, SignerKind::XmlDSig, false),
    row(SIGN_FORMAT_XMLDSIG_ENVELOPED, SignerKind::XmlDSig, false),
    row(SIGN_FORMAT_XMLDSIG_ENVELOPING, SignerKind::XmlDSig, false),
    row(SIGN_FORMAT_PDF, SignerKind::Pdf, false),
    row(SIGN_FORMAT_PDF_TRI, SignerKind::PdfTri, false),
    row(SIGN_FORMAT_PADES, SignerKind::Pdf, true),
    row(SIGN_FORMAT_PADES_TRI, SignerKind::PdfTri, false),
    row(SIGN_FORMAT_ODF, SignerKind::Odf, true),
    row(SIGN_FORMAT_ODF_ALT1, SignerKind::Odf, false),
    row(SIGN_FORMAT_OOXML, SignerKind::Ooxml, true),
    row(SIGN_FORMAT_OOXML_ALT1, SignerKind::Ooxml, false),
    row(SIGN_FORMAT_PKCS1, SignerKind::Pkcs1, false),
    row(SIGN_FORMAT_PKCS1_TRI, SignerKind::Pkcs1Tri, false),
];

/// Busca la fila de un formato sin distinguir mayúsculas (primera
/// coincidencia, como `AOSignerFactory.getSigner(String)`). `auto`, `PKCS1`,
/// `PKCS#1`, los formatos *Externally Detached* y `SOAP` no están
/// registrados y devuelven `None`.
pub fn find_format(sign_format: &str) -> Option<&'static SignerFormat> {
    SIGNER_FORMATS.iter().find(|f| equals_ignore_case(f.name, sign_format))
}

/// Firmador que implementa un formato (`None` si no está registrado).
pub fn signer_kind_for_format(sign_format: &str) -> Option<SignerKind> {
    find_format(sign_format).map(|f| f.kind)
}

/// Nombre canónico (tal y como aparece en la tabla) de un formato escrito
/// con cualquier combinación de mayúsculas.
pub fn canonical_format_name(sign_format: &str) -> Option<&'static str> {
    find_format(sign_format).map(|f| f.name)
}

/// Formatos soportados (`AOSignerFactory.getSupportedFormats()`), en orden.
pub fn supported_formats() -> impl Iterator<Item = &'static str> {
    SIGNER_FORMATS.iter().map(|f| f.name)
}

/// Firmadores que se prueban, en orden, al detectar el formato de una firma
/// (`AOSignerFactory.getSigner(byte[])`): CAdES, CAdES-ASiC-S, CMS, FacturaE,
/// XAdES, XAdES-ASiC-S, XMLDSig, PAdES, ODF y OOXML.
pub fn detection_order() -> impl Iterator<Item = SignerKind> {
    SIGNER_FORMATS.iter().filter(|f| f.used_for_detection).map(|f| f.kind)
}

/// Nombre de formato de un firmador (`AOSignerFactory.getSignFormat`).
pub fn get_sign_format(kind: SignerKind) -> &'static str {
    kind.sign_format()
}

/// Indica si el formato es la selección automática (`auto` sin distinguir
/// mayúsculas).
pub fn is_auto_format(sign_format: &str) -> bool {
    equals_ignore_case(sign_format, SIGN_FORMAT_AUTO)
}

/// Formato que elige el protocolo web con `format=auto` para una operación
/// de firma (`ProtocolInvocationLauncherUtil.identifyFormatFromData`):
/// PDF → `PAdES`; FacturaE → `FacturaE`; XML bien formado → `XAdES`; en
/// cualquier otro caso (incluidos OOXML y ODF) → `CAdES`. Las comprobaciones
/// las hace el llamante con los firmadores reales.
pub fn protocol_auto_sign_format(is_pdf: bool, is_facturae: bool, is_xml: bool) -> &'static str {
    if is_pdf {
        SIGN_FORMAT_PADES
    } else if is_facturae {
        SIGN_FORMAT_FACTURAE
    } else if is_xml {
        SIGN_FORMAT_XADES
    } else {
        SIGN_FORMAT_CADES
    }
}

/// Tipo de fichero detectado por la aplicación de escritorio
/// (`SignPanel.configureDataSigner`, §4.4.A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataFileType {
    Pdf,
    FacturaE,
    Ooxml,
    Odf,
    /// Firma XAdES existente.
    SignXades,
    /// Firma binaria (o de otro formato no XAdES) existente.
    SignCades,
    Xml,
    Binary,
}

impl DataFileType {
    /// Preferencia que fija el formato por defecto de este tipo de fichero y
    /// su valor por defecto (`None` para firmas existentes, que se cofirman
    /// con su propio formato).
    pub fn default_format_preference(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Pdf => Some((PREFERENCE_DEFAULT_SIGNATURE_FORMAT_PDF, DEFAULT_SIGNATURE_FORMAT_PDF)),
            Self::FacturaE => Some((PREFERENCE_DEFAULT_SIGNATURE_FORMAT_FACTURAE, DEFAULT_SIGNATURE_FORMAT_FACTURAE)),
            Self::Ooxml => Some((PREFERENCE_DEFAULT_SIGNATURE_FORMAT_OOXML, DEFAULT_SIGNATURE_FORMAT_OOXML)),
            Self::Odf => Some((PREFERENCE_DEFAULT_SIGNATURE_FORMAT_ODF, DEFAULT_SIGNATURE_FORMAT_ODF)),
            Self::Xml => Some((PREFERENCE_DEFAULT_SIGNATURE_FORMAT_XML, DEFAULT_SIGNATURE_FORMAT_XML)),
            Self::Binary => Some((PREFERENCE_DEFAULT_SIGNATURE_FORMAT_BIN, DEFAULT_SIGNATURE_FORMAT_BIN)),
            Self::SignXades | Self::SignCades => None,
        }
    }
}

/// `String.equalsIgnoreCase` de Java (plegado simple de mayúsculas carácter a
/// carácter).
pub(crate) fn equals_ignore_case(a: &str, b: &str) -> bool {
    let mut ia = a.chars();
    let mut ib = b.chars();
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) => {
                if x != y {
                    let ux = x.to_uppercase().next().unwrap_or(x);
                    let uy = y.to_uppercase().next().unwrap_or(y);
                    if ux != uy && ux.to_lowercase().next() != uy.to_lowercase().next() {
                        return false;
                    }
                }
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_table() {
        assert_eq!(SIGNER_FORMATS.len(), 29);
        assert_eq!(supported_formats().collect::<Vec<_>>()[19], "Adobe PDF");
        assert_eq!(signer_kind_for_format("cades"), Some(SignerKind::Cades));
        assert_eq!(signer_kind_for_format("XADES DETACHED"), Some(SignerKind::Xades));
        assert_eq!(canonical_format_name("pades"), Some("PAdES"));
        assert_eq!(canonical_format_name("padestri"), Some("PAdEStri"));
        assert_eq!(canonical_format_name("factura-e"), Some("Factura-e"));
        for unregistered in
            ["auto", "PKCS1", "PKCS#1", "XAdES Externally Detached", "XMLDSig Externally Detached", "SOAP", ""]
        {
            assert!(find_format(unregistered).is_none(), "{unregistered}");
        }
        assert!(is_auto_format("AUTO"));
        assert!(!is_auto_format("automatic"));
    }

    #[test]
    fn sign_format_naming() {
        assert_eq!(get_sign_format(SignerKind::Pdf), "Adobe PDF");
        assert_eq!(get_sign_format(SignerKind::PdfTri), "Adobe PDF TriPhase");
        assert_eq!(get_sign_format(SignerKind::Xades), "XAdES");
        assert_eq!(get_sign_format(SignerKind::FacturaE), "FacturaE");
        assert_eq!(get_sign_format(SignerKind::Odf), "ODF (Open Document Format)");
        assert_eq!(get_sign_format(SignerKind::Ooxml), "OOXML (Office Open XML)");
        assert_eq!(get_sign_format(SignerKind::Pkcs1Tri), "NONEtri");
        for k in SignerKind::ALL {
            assert_eq!(signer_kind_for_format(k.sign_format()), Some(k));
        }
    }

    #[test]
    fn detection() {
        let order: Vec<SignerKind> = detection_order().collect();
        assert_eq!(
            order,
            vec![
                SignerKind::Cades,
                SignerKind::CadesAsicS,
                SignerKind::Cms,
                SignerKind::FacturaE,
                SignerKind::Xades,
                SignerKind::XadesAsicS,
                SignerKind::XmlDSig,
                SignerKind::Pdf,
                SignerKind::Odf,
                SignerKind::Ooxml
            ]
        );
        assert!(SignerKind::Pdf.used_for_detection());
        assert!(!SignerKind::Pkcs1.used_for_detection());
        assert!(SignerKind::CadesTri.is_triphase());
    }

    #[test]
    fn auto_format() {
        assert_eq!(protocol_auto_sign_format(true, true, true), "PAdES");
        assert_eq!(protocol_auto_sign_format(false, true, true), "FacturaE");
        assert_eq!(protocol_auto_sign_format(false, false, true), "XAdES");
        assert_eq!(protocol_auto_sign_format(false, false, false), "CAdES");
        assert_eq!(DataFileType::Ooxml.default_format_preference(), Some(("defaultSignatureFormatOoxml", "CAdES")));
        assert_eq!(DataFileType::SignCades.default_format_preference(), None);
        assert!(!equals_ignore_case("Straße", "STRASSE"));
        assert!(equals_ignore_case("ñandú", "ÑANDÚ"));
    }
}
