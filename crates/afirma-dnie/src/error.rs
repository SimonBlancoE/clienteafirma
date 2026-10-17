//! Errores del controlador del DNIe y su correspondencia con las categorías de error que
//! muestra la aplicación (especificación 09 §4.9.8 y 10 §1.1).

use std::fmt;

/// Error del transporte (enlace NFC `IsoDep`, lector PC/SC…).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// La tarjeta se ha retirado o se ha perdido el enlace (`TagLostException` en Android,
    /// `SCARD_W_REMOVED_CARD` en PC/SC).
    #[error("Se ha perdido la conexión con la tarjeta: {0}")]
    TagLost(String),
    /// La tarjeta no ha respondido a tiempo.
    #[error("La tarjeta no ha respondido a tiempo: {0}")]
    Timeout(String),
    /// La APDU es demasiado larga para el enlace.
    #[error("La APDU de {0} octetos es demasiado larga para el enlace")]
    TooLong(usize),
    /// Cualquier otro error de entrada/salida.
    #[error("Error de comunicación con la tarjeta: {0}")]
    Io(String),
}

/// Categoría de un error desde el punto de vista del usuario: decide qué diálogo muestra la
/// aplicación y qué hace después (09 §4.9.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// La tarjeta no es un DNIe 3.0/4.0 (300100): vuelve a la introducción.
    CardNotSupported,
    /// No se ha podido conectar con la tarjeta (300102): paso 3 con «Reintentar».
    ConnectionFailed,
    /// CAN incorrecto (300108): se borran CAN y PIN y se vuelve a la introducción.
    WrongCan,
    /// Error de lectura o conexión perdida (300103): paso 3 con «Reintentar».
    ReadError,
    /// PIN incorrecto (300105): se reinicia el flujo NFC.
    WrongPin,
    /// PIN bloqueado (300106).
    PinBlocked,
    /// El DNIe no tiene certificado de firma (300110).
    NoSigningCertificate,
    /// El usuario canceló.
    Cancelled,
    /// Otro error (algoritmo no soportado, error interno…): error genérico de firma.
    Other,
}

impl ErrorCategory {
    /// Código de error de la app Android (`ThirdPartyErrors`), si lo tiene.
    pub fn code(self) -> Option<u32> {
        match self {
            ErrorCategory::CardNotSupported => Some(300100),
            ErrorCategory::ConnectionFailed => Some(300102),
            ErrorCategory::ReadError => Some(300103),
            ErrorCategory::WrongPin => Some(300105),
            ErrorCategory::PinBlocked => Some(300106),
            ErrorCategory::WrongCan => Some(300108),
            ErrorCategory::NoSigningCertificate => Some(300110),
            ErrorCategory::Cancelled | ErrorCategory::Other => None,
        }
    }

    /// Título del diálogo (textos `es` de firma-android).
    pub fn title(self) -> &'static str {
        match self {
            ErrorCategory::CardNotSupported => "¡Algo salió mal!",
            ErrorCategory::WrongCan => "CAN incorrecto",
            ErrorCategory::ConnectionFailed | ErrorCategory::ReadError => "Error en la lectura de tu DNIe",
            ErrorCategory::WrongPin => "PIN incorrecto",
            ErrorCategory::PinBlocked => "DNI bloqueado",
            ErrorCategory::NoSigningCertificate => "Error en la lectura de tu DNIe",
            ErrorCategory::Cancelled => "Operación cancelada",
            ErrorCategory::Other => "Error durante la operación de firma",
        }
    }

    /// Texto del diálogo (sin el prefijo `AAnnnnnn - `; ver [`Self::dialog_text`]).
    pub fn message(self) -> &'static str {
        match self {
            ErrorCategory::CardNotSupported => {
                "La tarjeta que has proporcionado no parece ser un DNIe. Por favor inténtalo de nuevo"
            }
            ErrorCategory::WrongCan => {
                "Error al iniciar la conexión con la tarjeta. Es posible que el CAN sea incorrecto. Inténtelo de nuevo."
            }
            ErrorCategory::ConnectionFailed | ErrorCategory::ReadError => {
                "Se ha producido un error al intentar leer tu DNIe. Por favor, vuelve a intentarlo. Recuerda \
                 mantenerlo en una superficie lisa y mantener tu teléfono móvil unos segundos fijo sobre la tarjeta \
                 para su correcta lectura."
            }
            ErrorCategory::WrongPin => {
                "El PIN del dispositivo criptográfico es incorrecto. Tenga en cuenta que varios intentos fallidos \
                 consecutivos podrían bloquearlo."
            }
            ErrorCategory::PinBlocked => {
                "El DNIe tiene el PIN bloqueado. Puedes acudir a una comisaría de Policía Nacional a un Punto de \
                 Actualización del DNIe (PAD) para desbloquearlo."
            }
            ErrorCategory::NoSigningCertificate => {
                "El DNIe que has aproximado no tiene certificado de firma o el certificado está caducado. Puedes \
                 acudir a una comisaría de Policía Nacional a un Punto de Actualización del DNIe (PAD), para \
                 solucionarlo."
            }
            ErrorCategory::Cancelled => "Operación cancelada por el usuario",
            ErrorCategory::Other => "Error durante la operación de firma",
        }
    }

    /// Texto completo del diálogo de la app (`AA300100 - …`). El error de conexión (300102)
    /// muestra el texto del error de lectura, como firma-android.
    pub fn dialog_text(self) -> String {
        let shown = if self == ErrorCategory::ConnectionFailed {
            ErrorCategory::ReadError
        } else {
            self
        };
        match shown.code() {
            Some(code) => format!("AA{code} - {}", shown.message()),
            None => shown.message().to_string(),
        }
    }
}

/// Error del controlador del DNIe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnieError {
    /// La tarjeta detectada no es un DNIe 3.0/4.0 (o es una TIE u otra tarjeta que no admite el
    /// flujo del DNIe).
    #[error("La tarjeta no es un DNIe 3.0/4.0 soportado: {0}")]
    CardNotSupported(String),
    /// No se ha podido establecer la comunicación inicial con la tarjeta.
    #[error("No se ha podido conectar con la tarjeta: {0}")]
    ConnectionFailed(String),
    /// Error del enlace con la tarjeta (retirada, tiempo agotado…).
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// El CAN no tiene el formato esperado (de 1 a 6 dígitos).
    #[error("El CAN debe estar formado por entre 1 y 6 dígitos")]
    InvalidCanFormat,
    /// La tarjeta ha rechazado la autenticación PACE: el CAN no es correcto.
    #[error("El CAN indicado del DNIe no es correcto{}", sw_suffix(*.sw))]
    WrongCan { sw: Option<u16> },
    /// Error de mensajería segura (MAC incorrecto, objetos ausentes, contexto perdido en la
    /// tarjeta…).
    #[error("Error de mensajería segura: {0}")]
    SecureMessaging(String),
    /// Error en el establecimiento del canal seguro CWA-14890.
    #[error("Error estableciendo el canal seguro con el DNIe: {0}")]
    SecureChannel(String),
    /// Respuesta inesperada de la tarjeta a una operación.
    #[error("Error en la operación «{operation}» con el DNIe (respuesta {sw:04X})")]
    Card { operation: &'static str, sw: u16 },
    /// Contenido de la tarjeta con formato no válido (CDF, PrKDF, certificados…).
    #[error("Error leyendo el DNIe: {0}")]
    Read(String),
    /// PIN con un formato que no se puede enviar a la tarjeta (no se gasta ningún intento).
    #[error("El PIN no tiene un formato válido: {0}")]
    InvalidPinFormat(String),
    /// PIN incorrecto.
    #[error("PIN incorrecto{}", retries_suffix(*.retries_left))]
    WrongPin { retries_left: Option<u8> },
    /// PIN bloqueado (sin intentos restantes).
    #[error("El PIN del DNIe está bloqueado")]
    PinBlocked,
    /// El usuario canceló la petición de CAN, PIN o la confirmación.
    #[error("Operación cancelada por el usuario")]
    Cancelled,
    /// No hay ninguna clave con el alias indicado.
    #[error("El DNIe no contiene ninguna clave con el alias «{0}»")]
    AliasNotFound(String),
    /// Algoritmo de firma no soportado por el DNIe.
    #[error("Algoritmo de firma no soportado por el DNIe: {0}")]
    UnsupportedAlgorithm(String),
    /// La firma devuelta por la tarjeta no se verifica con la clave pública del certificado.
    #[error("La firma generada por el DNIe no se corresponde con su certificado")]
    BadSignature,
    /// No se han podido obtener números aleatorios del sistema.
    #[error("No se han podido generar números aleatorios: {0}")]
    Random(String),
}

fn sw_suffix(sw: Option<u16>) -> String {
    sw.map(|s| format!(" (respuesta {s:04X})")).unwrap_or_default()
}

fn retries_suffix(r: Option<u8>) -> String {
    r.map(|n| format!(", intentos restantes: {n}")).unwrap_or_default()
}

impl DnieError {
    /// Categoría del error para la interfaz.
    pub fn category(&self) -> ErrorCategory {
        match self {
            DnieError::CardNotSupported(_) => ErrorCategory::CardNotSupported,
            DnieError::ConnectionFailed(_) => ErrorCategory::ConnectionFailed,
            DnieError::Transport(_)
            | DnieError::SecureMessaging(_)
            | DnieError::SecureChannel(_)
            | DnieError::Card { .. }
            | DnieError::Read(_) => ErrorCategory::ReadError,
            DnieError::InvalidCanFormat | DnieError::WrongCan { .. } => ErrorCategory::WrongCan,
            DnieError::InvalidPinFormat(_) | DnieError::WrongPin { .. } => ErrorCategory::WrongPin,
            DnieError::PinBlocked => ErrorCategory::PinBlocked,
            DnieError::Cancelled => ErrorCategory::Cancelled,
            DnieError::AliasNotFound(_) => ErrorCategory::NoSigningCertificate,
            DnieError::UnsupportedAlgorithm(_) | DnieError::BadSignature | DnieError::Random(_) => ErrorCategory::Other,
        }
    }

    /// Error de comunicación o de mensajería segura tras el cual tiene sentido reabrir la sesión
    /// desde PACE (una sola vez, §5.5).
    pub fn is_link_error(&self) -> bool {
        matches!(self, DnieError::Transport(_) | DnieError::SecureMessaging(_))
    }

    /// Error de la tarjeta a una operación.
    pub(crate) fn card(operation: &'static str, sw: u16) -> Self {
        DnieError::Card { operation, sw }
    }
}

/// Marcador de cancelación devuelto por las peticiones de CAN, PIN y confirmación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Operación cancelada por el usuario")
    }
}

impl std::error::Error for Cancelled {}

impl From<Cancelled> for DnieError {
    fn from(_: Cancelled) -> Self {
        DnieError::Cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_and_texts() {
        assert_eq!(
            DnieError::WrongCan { sw: Some(0x6300) }.category(),
            ErrorCategory::WrongCan
        );
        assert_eq!(
            DnieError::WrongCan { sw: Some(0x6300) }.to_string(),
            "El CAN indicado del DNIe no es correcto (respuesta 6300)"
        );
        assert_eq!(
            DnieError::WrongPin { retries_left: Some(2) }.to_string(),
            "PIN incorrecto, intentos restantes: 2"
        );
        assert_eq!(DnieError::PinBlocked.category().code(), Some(300106));
        assert_eq!(
            ErrorCategory::CardNotSupported.dialog_text(),
            "AA300100 - La tarjeta que has proporcionado no parece ser un DNIe. Por favor inténtalo de nuevo"
        );
        assert!(
            ErrorCategory::ConnectionFailed
                .dialog_text()
                .starts_with("AA300103 - Se ha producido")
        );
        assert!(
            DnieError::Transport(TransportError::TagLost("x".into())).is_link_error()
                && DnieError::Transport(TransportError::TagLost("x".into())).category() == ErrorCategory::ReadError
        );
        assert!(!DnieError::WrongPin { retries_left: None }.is_link_error());
    }
}
