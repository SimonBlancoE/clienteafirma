//! Resultado de la validación de firmas (`SignValidity`).

use crate::error::ErrorCode;

/// Veredicto de validez (`SIGN_DETAIL_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Validity {
    Ok,
    Ko,
    Unknown,
    PendingConfirmByUser,
    Generated,
}

impl Validity {
    /// Texto del veredicto (`SignValidationMessage.0..3`).
    pub fn message(self) -> &'static str {
        match self {
            Self::Ok | Self::Generated => "Firma válida",
            Self::Unknown => "Validación incompleta",
            Self::PendingConfirmByUser => "Validez a confirmar por el usuario",
            Self::Ko => "Firma no válida",
        }
    }
}

/// Causa de un resultado de validación (`VALIDITY_ERROR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityError {
    NoData,
    CorruptedSign,
    NoMatchData,
    NoSign,
    CertificateProblem,
    CertificateExpired,
    CertificateNotValidYet,
    CantValidateCert,
    AlgorithmNotSupported,
    CaNotSupported,
    CrlProblem,
    PdfUnknownValidity,
    OoxmlUnknownValidity,
    OdfUnknownValidity,
    UnknownError,
    UnknownSignatureFormat,
    ModifiedForm,
    ModifiedDocument,
    OverlappingSignature,
    SuspectedSignature,
    SignProfileNotChecked,
    CantValidateExternallyDetached,
    BadBuildSign,
    CertifiedSignRevision,
}

impl ValidityError {
    /// Texto de la causa (`SignValidationMessage.4..27`, con las entidades
    /// HTML del original ya resueltas).
    pub fn message(self) -> &'static str {
        match self {
            Self::NoData => "no se puede comprobar la validez por no tener los datos firmados",
            Self::CorruptedSign => "la información contenida en la firma no es consistente (certificados corruptos, etc.)",
            Self::NoMatchData => "la firma no se corresponde con los datos firmados",
            Self::NoSign => "no se encuentra la firma dentro del documento",
            Self::CertificateProblem => "no se puede extraer un certificado o este no es válido",
            Self::CertificateExpired => "existe un certificado de firma caducado",
            Self::CertificateNotValidYet => "existe un certificado de firma que aun no es válido",
            Self::CantValidateCert => "no se ha podido validar el certificado correctamente",
            Self::AlgorithmNotSupported => "la firma contiene un algoritmo no reconocido o no soportado",
            Self::CaNotSupported => "no se soporta la CA de expedición",
            Self::CrlProblem => "existe algun problema con las CRLs incrustadas en la firma",
            Self::PdfUnknownValidity => "no se puede comprobar la validez de la firma PDF",
            Self::OoxmlUnknownValidity => "no se puede comprobar la validez de la firma OOXML",
            Self::OdfUnknownValidity => "no se puede comprobar la validez de la firma ODF",
            Self::UnknownError => "no se puede comprobar la validez de la firma",
            Self::UnknownSignatureFormat => "los datos proporcionados no se corresponden con ningún formato de firma reconocido",
            Self::ModifiedDocument => "el documento PDF es sospechoso de haberse modificado tras la firma",
            Self::OverlappingSignature => "las firmas del documento se solapan pudiendo ocultar información",
            Self::ModifiedForm => "un formulario del documento fue modificado tras la firma",
            Self::SuspectedSignature => "el documento es sospechoso y el usuario debe revisar la firma",
            Self::SignProfileNotChecked => {
                "la firma contiene atributos longevos que Autofirma no puede validar. Para una validación completa recurra a VALIDe."
            }
            Self::CantValidateExternallyDetached => "no se permite la validación de firmas con referencias externas",
            Self::BadBuildSign => "la firma no está correctamente formada",
            Self::CertifiedSignRevision => "El documento certificado no permitía nuevas firmas",
        }
    }
}

/// Resultado de validación de una firma o de un aspecto de ella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignValidity {
    pub validity: Validity,
    pub error: Option<ValidityError>,
    pub error_code: Option<ErrorCode>,
    /// Detalle técnico adicional (mensaje de la excepción original).
    pub detail: Option<String>,
}

impl SignValidity {
    pub fn new(validity: Validity, error: Option<ValidityError>) -> Self {
        SignValidity { validity, error, error_code: None, detail: None }
    }

    pub fn ok() -> Self {
        Self::new(Validity::Ok, None)
    }

    pub fn ko(error: ValidityError) -> Self {
        Self::new(Validity::Ko, Some(error))
    }

    pub fn unknown(error: ValidityError) -> Self {
        Self::new(Validity::Unknown, Some(error))
    }

    pub fn with_code(mut self, code: ErrorCode) -> Self {
        self.error_code = Some(code);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

impl std::fmt::Display for SignValidity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.validity.message())?;
        if let Some(e) = self.error {
            write!(f, ": {}", e.message())?;
        }
        Ok(())
    }
}

/// Reordena poniendo primero los resultados KO (`checkValidityKOPriority`).
pub fn ko_priority(list: Vec<SignValidity>) -> Vec<SignValidity> {
    let mut kos: Vec<SignValidity> = Vec::new();
    let mut others = Vec::new();
    for v in list {
        if v.validity == Validity::Ko {
            kos.insert(0, v);
        } else {
            others.push(v);
        }
    }
    kos.extend(others);
    kos
}

/// Si una firma longeva solo falla por certificado caducado, el veredicto
/// pasa a "validación incompleta" (`checkLongStandingValiditySign`).
pub fn long_standing_priority(mut list: Vec<SignValidity>) -> Vec<SignValidity> {
    let expired = list.iter().any(|v| v.validity == Validity::Ko && v.error == Some(ValidityError::CertificateExpired));
    let other_ko = list.iter().any(|v| v.validity == Validity::Ko && v.error != Some(ValidityError::CertificateExpired));
    if expired && !other_ko {
        // Como Java: se intercambia la posición 0 con la última entrada
        // "validación incompleta" por atributos longevos.
        if let Some(pos) = list
            .iter()
            .rposition(|v| v.validity == Validity::Unknown && v.error == Some(ValidityError::SignProfileNotChecked))
        {
            list.swap(0, pos);
        }
    }
    list
}
