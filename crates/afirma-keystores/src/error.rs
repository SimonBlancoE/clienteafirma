//! Errores de los almacenes de claves y su correspondencia con los códigos de
//! error de AutoFirma (`KeyStoreErrorCode`, `ErrorCode`).

use std::path::PathBuf;

use afirma_core::error::{AfirmaError, ErrorCode, codes};
use afirma_core::key::KeyError;

use crate::kind::KeyStoreKind;

/// Error al abrir o usar un almacén de claves.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyStoreError {
    /// El usuario canceló un diálogo (contraseña, PIN, selección de fichero).
    #[error("Operacion cancelada por el usuario")]
    Cancelled,
    /// Contraseña de almacén incorrecta (PKCS#12, contraseña maestra de NSS...).
    #[error("{message}")]
    WrongPassword { message: String },
    /// PIN de tarjeta (PKCS#11, DNIe) incorrecto.
    #[error("La contraseña introducida no es correcta.")]
    WrongPin { retries_left: Option<u32> },
    /// Longitud de PIN no válida (`CKR_PIN_LEN_RANGE`).
    #[error("La longitud de la contraseña introducida no es válida.")]
    PinLengthInvalid,
    /// PIN bloqueado o almacén bloqueado.
    #[error("Su almacén de claves esta bloqueado.")]
    Locked { smartcard: bool },
    /// El almacén no contiene ningún certificado utilizable.
    #[error("No se han encontrado certificados para realizar la seleccion")]
    NoCertificates,
    /// Combinación de almacén y sistema operativo no soportada (600011).
    #[error("La plataforma de navegador '{store}' mas sistema operativo '{os}' no esta soportada")]
    Unsupported {
        store: String,
        os: String,
        alternative: Option<KeyStoreKind>,
    },
    /// No hay almacén por defecto para este sistema operativo (201116).
    #[error("No hay definido un almacen de claves por defecto para este sistema operativo")]
    UndefinedDefault,
    /// La biblioteca PKCS#11 indicada no existe.
    #[error("La biblioteca '{}' no existe", .0.display())]
    LibraryNotFound(PathBuf),
    /// El fichero de almacén indicado no existe o no se puede leer.
    #[error("No se encuentra o no se puede leer el fichero '{}'", .0.display())]
    FileNotFound(PathBuf),
    /// No se ha encontrado Firefox, su perfil o las bibliotecas de NSS.
    #[error("{0}")]
    Firefox(String),
    /// Error genérico al cargar un almacén de un tipo dado.
    #[error("{message}")]
    Load { kind: KeyStoreKind, message: String },
    /// No hay ninguna tarjeta en los lectores.
    #[error("No se ha detectado ninguna tarjeta inteligente en el lector")]
    CardNotPresent,
    /// La tarjeta del lector no es del tipo esperado.
    #[error("La tarjeta detectada en el lector no es del tipo esperado")]
    InvalidCard,
    /// No existe ninguna entrada con el alias indicado.
    #[error("No se hay ninguna entrada en el almacen con el alias indicado: {0}")]
    AliasNotFound(String),
    /// La entrada existe pero no tiene clave privada.
    #[error("La entrada no tiene clave privada: {0}")]
    NoPrivateKey(String),
    /// Error de PKCS#11 no traducible a otra variante.
    #[error("Error PKCS#11 en {function}: {rv}")]
    Pkcs11 { function: String, rv: String },
    /// Error del sistema operativo (CryptoAPI/CNG, Security.framework).
    #[error("Error del sistema ({code:#x}): {message}")]
    Os { code: i64, message: String },
    /// Error de la clave al firmar.
    #[error(transparent)]
    Key(#[from] KeyError),
}

impl KeyStoreError {
    /// Error de carga de un almacén del tipo indicado.
    pub fn load(kind: KeyStoreKind, message: impl Into<String>) -> Self {
        KeyStoreError::Load {
            kind,
            message: message.into(),
        }
    }

    /// Indica si es una cancelación del usuario.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, KeyStoreError::Cancelled | KeyStoreError::Key(KeyError::Cancelled))
    }

    /// Código de error de AutoFirma correspondiente.
    pub fn code(&self) -> ErrorCode {
        match self {
            KeyStoreError::Cancelled => codes::CANCELLED_OPERATION,
            KeyStoreError::WrongPassword { .. } => codes::LOADING_KEYSTORE_INTERNAL_ERROR,
            KeyStoreError::WrongPin { .. } | KeyStoreError::PinLengthInvalid => codes::INVALID_SMARTCARD_PIN,
            KeyStoreError::Locked { smartcard: true } => codes::SMARTCARD_LOCKED,
            KeyStoreError::Locked { smartcard: false } => codes::KEYSTORE_LOCKED,
            KeyStoreError::NoCertificates => codes::NO_CERTS_FOUND_SIGNING,
            KeyStoreError::Unsupported { .. } => codes::UNSUPPORTED_KEYSTORE,
            KeyStoreError::UndefinedDefault => codes::UNDEFINED_DEFAULT_KEYSTORE,
            KeyStoreError::LibraryNotFound(_) => codes::LOADING_PKCS11_KEYSTORE_ERROR,
            KeyStoreError::FileNotFound(_) => codes::LOADING_KEYSTORE_INTERNAL_ERROR,
            KeyStoreError::Firefox(_) => codes::LOADING_MOZILLA_KEYSTORE_ERROR,
            KeyStoreError::Load { kind, .. } => load_code(*kind),
            KeyStoreError::CardNotPresent | KeyStoreError::InvalidCard => codes::LOADING_JMULTICARD_KEYSTORE_ERROR,
            KeyStoreError::AliasNotFound(_) | KeyStoreError::NoPrivateKey(_) => codes::LOADING_PRIVATE_KEY_ERROR,
            KeyStoreError::Pkcs11 { .. } => codes::LOADING_PKCS11_KEYSTORE_ERROR,
            KeyStoreError::Os { .. } => codes::LOADING_KEYSTORE_INTERNAL_ERROR,
            KeyStoreError::Key(k) => AfirmaError::from(k.clone()).effective_code(),
        }
    }
}

/// Código de carga por tipo de almacén (`KeyStoreErrorCode.Internal.LOADING_*`).
pub fn load_code(kind: KeyStoreKind) -> ErrorCode {
    use KeyStoreKind::*;
    match kind {
        Windows | KnownSmartcards => codes::LOADING_WINDOWS_KEYSTORE_ERROR,
        WinAddressBook | WinCa => codes::LOADING_PUBLIC_WINDOWS_KEYSTORE_ERROR,
        Apple => codes::LOADING_APPLE_KEYSTORE_ERROR,
        MozUni | MozUniWithOs | SharedNss => codes::LOADING_MOZILLA_KEYSTORE_ERROR,
        Pkcs12 => codes::LOADING_PKCS12_KEYSTORE_ERROR,
        Java | Jceks | JavaCe => codes::LOADING_JAVA_KEYSTORE_ERROR,
        Pkcs11 | Temd => codes::LOADING_PKCS11_KEYSTORE_ERROR,
        DnieJava | Ceres | Ceres430 | SmartCafe => codes::LOADING_JMULTICARD_KEYSTORE_ERROR,
        Single => codes::LOADING_FILE_CERTSTORE_ERROR,
        Other => codes::LOADING_KEYSTORE_INTERNAL_ERROR,
    }
}

impl From<KeyStoreError> for AfirmaError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Cancelled => AfirmaError::cancelled(),
            KeyStoreError::Key(k) => AfirmaError::from(k),
            other => AfirmaError::new(other.code(), other.to_string()),
        }
    }
}

/// Convierte un error de almacén en error de clave (para las operaciones de
/// firma, cuya interfaz devuelve [`KeyError`]).
impl From<KeyStoreError> for KeyError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Cancelled => KeyError::Cancelled,
            KeyStoreError::WrongPin { .. } | KeyStoreError::PinLengthInvalid | KeyStoreError::WrongPassword { .. } => {
                KeyError::WrongPin
            }
            KeyStoreError::Locked { .. } => KeyError::PinLocked,
            KeyStoreError::CardNotPresent => KeyError::DeviceUnavailable,
            KeyStoreError::Key(k) => k,
            other => KeyError::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(KeyStoreError::Cancelled.code().code, 500001);
        assert_eq!(KeyStoreError::WrongPin { retries_left: Some(2) }.code().code, 501003);
        assert_eq!(KeyStoreError::Locked { smartcard: true }.code().code, 511004);
        assert_eq!(KeyStoreError::Locked { smartcard: false }.code().code, 511003);
        assert_eq!(KeyStoreError::UndefinedDefault.code().code, 201116);
        assert_eq!(
            KeyStoreError::Unsupported {
                store: "Windows".into(),
                os: "Linux".into(),
                alternative: None
            }
            .code()
            .code,
            600011
        );
        assert_eq!(KeyStoreError::load(KeyStoreKind::Pkcs12, "x").code().code, 201110);
        assert_eq!(KeyStoreError::load(KeyStoreKind::MozUni, "x").code().code, 201108);
        let a: AfirmaError = KeyStoreError::Cancelled.into();
        assert!(a.is_cancelled());
        assert_eq!(
            KeyStoreError::Unsupported {
                store: "Windows".into(),
                os: "Linux".into(),
                alternative: None
            }
            .to_string(),
            "La plataforma de navegador 'Windows' mas sistema operativo 'Linux' no esta soportada"
        );
    }
}
