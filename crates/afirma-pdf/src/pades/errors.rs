//! Errores de PAdES con los códigos y las peticiones de intervención del
//! usuario de AutoFirma (`PdfErrorCode`, `RuntimeConfigNeededException`).

use afirma_core::AfirmaError;
use afirma_core::error::{ConfirmEffect, ErrorKind, codes};

/// Clave del mensaje: el PDF está certificado.
pub const REQ_CERTIFIED: &str = "signingCertifiedPdf";
/// Clave del mensaje: el PDF tiene firmas no registradas.
pub const REQ_UNREGISTERED: &str = "signingPdfWithUnregisteredSigns";
/// Clave del mensaje: formulario modificado tras la firma.
pub const REQ_MODIFIED_FORM: &str = "signingModifiedPdfForm";
/// Clave del mensaje: sospecha de PDF Shadow Attack.
pub const REQ_PSA: &str = "pdfShadowAttackSuspect";
/// Clave del mensaje: el PDF necesita contraseña.
pub const REQ_PASSWORD_PROTECTED: &str = "pdfpasswordprotected";
/// Clave del mensaje: contraseña incorrecta.
pub const REQ_BAD_PASSWORD: &str = "pdfbadpassword";

/// Texto en español de cada petición (`messages_es_ES` de afirma-simple).
pub fn requestor_message(key: &str) -> Option<&'static str> {
    Some(match key {
        REQ_CERTIFIED => {
            "El PDF que desea firmar está certificado y no admite nuevas firmas. Agregar nuevas firmas invalidará la firma anterior.\n¿Desea continuar?"
        }
        REQ_UNREGISTERED => {
            "El PDF que desea firmar contiene firmas previas en un formato antiguo. Agregar nuevas firmas podría invalidar las ya existentes.\n¿Desea continuar?"
        }
        REQ_MODIFIED_FORM => {
            "Se han detectado cambios en un formulario posteriores a la primera firma.\n¿Desea continuar?"
        }
        REQ_PSA => "El PDF es sospechoso de haber sido modificado tras la última firma. ¿Desea continuar?",
        REQ_PASSWORD_PROTECTED => "El PDF está protegido por contraseña. Introduzca de la contraseña del PDF.",
        REQ_BAD_PASSWORD => "La contraseña introducida es incorrecta. Introduzca de la contraseña del PDF.",
        _ => return None,
    })
}

fn deny(mut e: AfirmaError, denied: bool) -> AfirmaError {
    if let ErrorKind::NeedsIntervention { denied: d, .. } = &mut e.kind {
        *d = denied;
    }
    e
}

/// `InvalidPdfException` (510005).
pub fn pdf_needed() -> AfirmaError {
    AfirmaError::new(
        codes::PDF_DOCUMENT_NEEDED,
        "La firma requiere que los datos sean un documento PDF",
    )
}

/// `PdfIsPasswordProtectedException` (212005).
pub fn password_protected(message: &str) -> AfirmaError {
    AfirmaError::needs_password(
        codes::SIGNING_PDF_WITHOUT_PASSWORD,
        message,
        REQ_PASSWORD_PROTECTED,
        "ownerPassword",
    )
}

/// `BadPdfPasswordException` (212004).
pub fn bad_password(message: &str) -> AfirmaError {
    AfirmaError::needs_password(
        codes::SIGNING_PDF_WITH_BAD_PASSWORD,
        message,
        REQ_BAD_PASSWORD,
        "ownerPassword",
    )
}

/// `PdfIsCertifiedException` (212007).
pub fn certified(denied: bool) -> AfirmaError {
    deny(
        AfirmaError::needs_confirmation(
            codes::SIGNING_PDF_WITH_CERTIFIED_SIGN,
            "El PDF esta certificado y no admite nuevas firmas",
            REQ_CERTIFIED,
            "allowSigningCertifiedPdfs",
            ConfirmEffect::SetParamTrue,
        ),
        denied,
    )
}

/// `PdfHasUnregisteredSignaturesException` (212003).
pub fn unregistered(denied: bool) -> AfirmaError {
    deny(
        AfirmaError::needs_confirmation(
            codes::SIGNING_PDF_WITH_UNREGISTER_SIGNATURES,
            "El PDF contiene firmas sin registrar",
            REQ_UNREGISTERED,
            "allowCosigningUnregisteredSignatures",
            ConfirmEffect::SetParamTrue,
        ),
        denied,
    )
}

/// `PdfFormModifiedException` (212006).
pub fn modified_form(denied: bool) -> AfirmaError {
    deny(
        AfirmaError::needs_confirmation(
            codes::SIGNING_PDF_WITH_MODIFIED_FORM,
            "Se han detectado cambios en un formulario posteriores a la primera firma",
            REQ_MODIFIED_FORM,
            "allowModifiedForm",
            ConfirmEffect::SetParamTrue,
        ),
        denied,
    )
}

/// `SuspectedPSAException` (212008).
pub fn shadow_attack(message: &str, denied: bool) -> AfirmaError {
    deny(
        AfirmaError::needs_confirmation(
            codes::SIGNING_PDF_WITH_SUSPICION_OF_PSA,
            message,
            REQ_PSA,
            "allowShadowAttack",
            ConfirmEffect::SetParamTrue,
        ),
        denied,
    )
}

/// Error interno de PAdES (212002).
pub fn internal(message: impl Into<String>) -> AfirmaError {
    AfirmaError::new(codes::INTERNAL_PADES_SIGNING_ERROR, message)
}

/// `InvalidSignaturePositionException` (610301).
pub fn invalid_position() -> AfirmaError {
    AfirmaError::new(
        codes::INVALID_SIGNATURE_POSITION,
        "La posicion proporcionada no se encuentra en el rango de ninguna de las paginas a estampar del documento",
    )
}
