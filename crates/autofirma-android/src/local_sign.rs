//! Firma local de un fichero (`docs/spec/09-android.md` §3.4 a §3.8), sin interfaz: formato
//! según el nombre, parámetros, firma con los firmadores de `afirma-signers`, nombre y tipo
//! MIME del fichero firmado. La orquestación (selector, almacén, avisos, guardado) está en
//! [`crate::flow`].
//!
//! Como el original (§10 n.º 20, «replicar»), el formato sale del nombre del fichero y no del
//! contenido, siempre es una firma (nunca cofirma ni contrafirma), con SHA-256 y
//! `mode=implicit`:
//!
//! | Nombre | Formato | Fichero firmado |
//! |---|---|---|
//! | `*.pdf` | PAdES | `<nombre>_signed.pdf` |
//! | `*.xml` | XAdES (*Enveloping*, el valor por defecto del firmador) | `<nombre>.xsig` |
//! | otro | CAdES implícita | `<nombre>.csig` |
//!
//! La fila XAdES es un añadido: el original solo tenía XAdES trifásica (con servidor) y
//! firmaba los XML en CAdES. AutoFirma-rs tiene el firmador XAdES monofásico del escritorio y
//! lo usa para los `.xml` (`docs/ANDROID.md` §9.8).

use afirma_core::error::codes;
use afirma_core::{AfirmaError, ExtraParams, Signer, SigningKey};

use crate::i18n::tr;

/// Algoritmo de huella de la firma local (`DEFAULT_SIGNATURE_ALGORITHM`); el firmador lo
/// compone con el tipo de clave (`SHA256withRSA`, `SHA256withECDSA`).
pub const ALGORITHM: &str = "SHA256";

/// Texto que se inserta en el nombre de un PDF firmado.
const PDF_SIGNED_SUFFIX: &str = "_signed";

/// Formato de la firma local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalFormat {
    Pades,
    Cades,
    Xades,
}

impl LocalFormat {
    /// Formato para un fichero por su nombre (sin mirar el contenido, como el original).
    pub fn for_file(name: &str) -> LocalFormat {
        let lower = name.to_lowercase();
        if lower.ends_with(".pdf") {
            LocalFormat::Pades
        } else if lower.ends_with(".xml") {
            LocalFormat::Xades
        } else {
            LocalFormat::Cades
        }
    }

    /// Nombre del formato (`AOSignConstants`).
    pub fn name(self) -> &'static str {
        match self {
            LocalFormat::Pades => afirma_core::constants::SIGN_FORMAT_PADES,
            LocalFormat::Cades => afirma_core::constants::SIGN_FORMAT_CADES,
            LocalFormat::Xades => afirma_core::constants::SIGN_FORMAT_XADES,
        }
    }

    /// Firmador del formato.
    pub fn signer(self) -> Box<dyn Signer> {
        afirma_signers::signer_for_format(self.name()).expect("los tres formatos tienen firmador")
    }

    /// Nombre propuesto para el fichero firmado (`AOSigner.getSignedName`, con `_signed` solo
    /// en PAdES).
    pub fn signed_name(self, original: &str) -> String {
        let in_text = (self == LocalFormat::Pades).then_some(PDF_SIGNED_SUFFIX);
        self.signer().signed_name(Some(original), in_text)
    }
}

/// Tipo MIME del fichero firmado: `application/` y la extensión (`application/pdf`,
/// `application/csig`, `application/xsig`), como el original.
pub fn mime_type(signed_name: &str) -> String {
    let ext = signed_name.rsplit_once('.').map_or("", |(_, ext)| ext);
    format!("application/{}", ext.to_lowercase())
}

/// Parámetros de toda firma local (`mode=implicit`, también en PAdES, donde no tiene efecto).
pub fn base_params() -> ExtraParams {
    let mut params = ExtraParams::new();
    params.set("mode", "implicit");
    params
}

/// Área de la firma visible en puntos PDF (origen abajo a la izquierda) y página (desde 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleArea {
    pub page: usize,
    pub llx: i64,
    pub lly: i64,
    pub urx: i64,
    pub ury: i64,
}

/// Añade los parámetros de la firma visible (§3.5.5): ofuscación, página, texto de la
/// plantilla del idioma activo y posición.
pub fn add_visible_params(params: &mut ExtraParams, area: &VisibleArea, obfuscate: bool) {
    params.set("obfuscateCertText", obfuscate.to_string());
    params.set("signaturePages", area.page.to_string());
    params.set("layer2Text", tr("pdf_visible_sign_template"));
    params.set("signaturePositionOnPageLowerLeftX", area.llx.to_string());
    params.set("signaturePositionOnPageLowerLeftY", area.lly.to_string());
    params.set("signaturePositionOnPageUpperRightX", area.urx.to_string());
    params.set("signaturePositionOnPageUpperRightY", area.ury.to_string());
}

/// Con un certificado de seudónimo, la firma visible local usa la plantilla de seudónimo
/// (`doSign`): solo si ya hay texto de firma visible.
pub fn use_pseudonym_template(params: &mut ExtraParams) {
    if params.get("layer2Text").is_some() {
        params.set("layer2Text", tr("pdf_visible_sign_pseudonym_template"));
    }
}

/// Contraseña del PDF para reintentar la firma (`PDFPasswordDialog`): `ownerPassword` y sin
/// `userPassword`.
pub fn set_pdf_password(params: &mut ExtraParams, password: &str) {
    params.set("ownerPassword", password);
    params.remove("userPassword");
}

/// Por qué no se ha podido firmar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignFailure {
    /// El PDF está protegido y hace falta su contraseña (`PdfIsPasswordProtectedException`).
    PasswordNeeded,
    /// La contraseña del PDF no es correcta (`BadPdfPasswordException`).
    BadPassword,
    /// Cualquier otro error (texto para el registro).
    Failed(String),
}

impl From<AfirmaError> for SignFailure {
    fn from(e: AfirmaError) -> SignFailure {
        match e.code {
            Some(c) if c == codes::SIGNING_PDF_WITHOUT_PASSWORD => SignFailure::PasswordNeeded,
            Some(c) if c == codes::SIGNING_PDF_WITH_BAD_PASSWORD => SignFailure::BadPassword,
            _ => SignFailure::Failed(e.to_string()),
        }
    }
}

/// Firma `data` en el formato con la clave y los parámetros. Bloquea (con KeyChain, llama a
/// Java): se usa desde un hilo de trabajo.
pub fn sign(
    format: LocalFormat,
    data: &[u8],
    key: &dyn SigningKey,
    params: &ExtraParams,
) -> Result<Vec<u8>, SignFailure> {
    format
        .signer()
        .sign(data, ALGORITHM, key, params)
        .map_err(SignFailure::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Language, set_language, test_lock};

    #[test]
    fn formato_por_el_nombre_del_fichero() {
        assert_eq!(LocalFormat::for_file("informe.pdf"), LocalFormat::Pades);
        assert_eq!(LocalFormat::for_file("INFORME.PDF"), LocalFormat::Pades);
        assert_eq!(LocalFormat::for_file("factura.xml"), LocalFormat::Xades);
        assert_eq!(LocalFormat::for_file("Factura.XML"), LocalFormat::Xades);
        assert_eq!(LocalFormat::for_file("informe.docx"), LocalFormat::Cades);
        assert_eq!(LocalFormat::for_file("sin_extension"), LocalFormat::Cades);
        // Por el nombre, no por el contenido (§10 n.º 20): un PDF renombrado va en CAdES.
        assert_eq!(LocalFormat::for_file("documento.pdf.bin"), LocalFormat::Cades);
        assert_eq!(LocalFormat::for_file("pdf"), LocalFormat::Cades);
        assert_eq!(LocalFormat::Pades.name(), "PAdES");
        assert_eq!(LocalFormat::Cades.name(), "CAdES");
        assert_eq!(LocalFormat::Xades.name(), "XAdES");
    }

    #[test]
    fn nombres_y_tipos_de_los_ficheros_firmados() {
        assert_eq!(LocalFormat::Pades.signed_name("informe.pdf"), "informe_signed.pdf");
        assert_eq!(LocalFormat::Pades.signed_name("INFORME.PDF"), "INFORME_signed.pdf");
        assert_eq!(LocalFormat::Cades.signed_name("informe.docx"), "informe.docx.csig");
        assert_eq!(LocalFormat::Cades.signed_name("datos"), "datos.csig");
        assert_eq!(LocalFormat::Xades.signed_name("factura.xml"), "factura.xml.xsig");
        assert_eq!(mime_type("informe_signed.pdf"), "application/pdf");
        assert_eq!(mime_type("informe.docx.csig"), "application/csig");
        assert_eq!(mime_type("factura.xml.xsig"), "application/xsig");
        assert_eq!(mime_type("sin_extension"), "application/");
    }

    #[test]
    fn parametros_de_la_firma_visible() {
        let _lock = test_lock();
        set_language(Language::Es);
        let mut p = base_params();
        assert_eq!(p.get("mode"), Some("implicit"));
        use_pseudonym_template(&mut p);
        assert_eq!(p.get("layer2Text"), None, "sin firma visible no hay plantilla");
        let area = VisibleArea {
            page: 2,
            llx: 10,
            lly: 20,
            urx: 210,
            ury: 120,
        };
        add_visible_params(&mut p, &area, true);
        assert_eq!(p.get("signaturePages"), Some("2"));
        assert_eq!(p.get("obfuscateCertText"), Some("true"));
        assert_eq!(p.get("signaturePositionOnPageUpperRightY"), Some("120"));
        assert!(p.get("layer2Text").unwrap().starts_with("Firmado por $$SUBJECTCN$$"));
        use_pseudonym_template(&mut p);
        assert!(
            p.get("layer2Text")
                .unwrap()
                .starts_with("Firmado por $$PSEUDONYM$$ - $$OUS$$")
        );
        p.set("userPassword", "u");
        set_pdf_password(&mut p, "propietario");
        assert_eq!(p.get("ownerPassword"), Some("propietario"));
        assert_eq!(p.get("userPassword"), None);
    }

    #[test]
    fn errores_de_contrasena_del_pdf() {
        let pdf = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/pades/encrypted_aes128_user.pdf"
        ))
        .unwrap();
        let key = crate::testing::software_key();
        assert_eq!(
            sign(LocalFormat::Pades, &pdf, &key, &base_params()),
            Err(SignFailure::PasswordNeeded)
        );
        let mut p = base_params();
        set_pdf_password(&mut p, "mala");
        assert_eq!(sign(LocalFormat::Pades, &pdf, &key, &p), Err(SignFailure::BadPassword));
        set_pdf_password(&mut p, "owner");
        assert!(sign(LocalFormat::Pades, &pdf, &key, &p).is_ok());
        assert!(matches!(
            sign(LocalFormat::Pades, b"no es un pdf", &key, &base_params()),
            Err(SignFailure::Failed(_))
        ));
    }
}
