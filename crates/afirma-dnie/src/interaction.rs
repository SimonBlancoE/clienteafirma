//! Interacción con el usuario: peticiones de CAN y PIN y confirmación de firma (especificación
//! 10 §10; equivalente al `CallbackHandler` de JMulticard).
//!
//! El controlador nunca muestra diálogos: llama a [`DnieInteraction`], que implementa la
//! interfaz (Android: CAN y PIN pedidos antes de acercar la tarjeta, [`FixedInteraction`];
//! escritorio: diálogos «DNI Electrónico: Introducción de CAN/PIN»). El PIN no se guarda en el
//! controlador: se pide en cada firma.

use zeroize::Zeroizing;

use crate::error::Cancelled;

/// Texto de petición del CAN de JMulticard (`CardMessages "DnieNFC.0"`).
pub const PROMPT_CAN_JMULTICARD: &str = "Por favor, introduzca el CAN o la MRZ del documento de identidad";
/// Texto de petición del CAN del diálogo de escritorio de AutoFirma.
pub const PROMPT_CAN: &str = "Por favor, introduzca el CAN del DNIe";
/// Título del diálogo de CAN de escritorio.
pub const TITLE_CAN: &str = "DNI Electrónico: Introducción de CAN";
/// Texto de petición del PIN (`CardMessages "Dnie.0"`, sin la línea de intentos).
pub const PROMPT_PIN: &str = "Por favor, introduzca el PIN del DNIe.";
/// Título del diálogo de PIN.
pub const TITLE_PIN: &str = "DNI Electrónico: Introducción de PIN";

/// Petición del CAN (una vez por sesión de tarjeta).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanRequest {
    pub title: &'static str,
    pub prompt: &'static str,
}

impl Default for CanRequest {
    fn default() -> Self {
        CanRequest {
            title: TITLE_CAN,
            prompt: PROMPT_CAN,
        }
    }
}

/// Petición del PIN (antes de cada `VERIFY`, es decir, en cada firma).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRequest {
    /// Intentos restantes leídos de la tarjeta (`None` si la tarjeta no los indica).
    pub retries_left: Option<u8>,
    /// Alias de la clave con la que se va a firmar.
    pub alias: String,
}

impl PinRequest {
    pub fn title(&self) -> &'static str {
        TITLE_PIN
    }

    /// Texto de JMulticard: «Por favor, introduzca el PIN del DNIe.\nIntentos restantes: n».
    pub fn prompt(&self) -> String {
        match self.retries_left {
            Some(n) => format!("{PROMPT_PIN}\nIntentos restantes: {n}"),
            None => PROMPT_PIN.to_string(),
        }
    }
}

/// Petición de confirmación de firma (JMulticard 2.1 nunca la emite; AutoFirma de escritorio la
/// muestra para el DNIe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRequest {
    pub alias: String,
}

impl SignatureRequest {
    pub fn title(&self) -> &'static str {
        "DNI Electrónico: Firma electrónica"
    }

    pub fn message(&self) -> &'static str {
        "¿Desea realizar una firma electrónica con su clave privada?"
    }
}

/// Interfaz de usuario del controlador.
pub trait DnieInteraction: Send + Sync {
    /// Devuelve el CAN (solo dígitos). `Err(Cancelled)` si el usuario cancela.
    fn request_can(&self, request: &CanRequest) -> Result<Zeroizing<String>, Cancelled>;

    /// Devuelve el PIN. `Err(Cancelled)` si el usuario cancela.
    fn request_pin(&self, request: &PinRequest) -> Result<Zeroizing<String>, Cancelled>;

    /// Confirma el uso de la clave de firma. Por defecto se acepta.
    fn confirm_signature(&self, _request: &SignatureRequest) -> Result<bool, Cancelled> {
        Ok(true)
    }
}

impl<T: DnieInteraction + ?Sized> DnieInteraction for std::sync::Arc<T> {
    fn request_can(&self, request: &CanRequest) -> Result<Zeroizing<String>, Cancelled> {
        (**self).request_can(request)
    }
    fn request_pin(&self, request: &PinRequest) -> Result<Zeroizing<String>, Cancelled> {
        (**self).request_pin(request)
    }
    fn confirm_signature(&self, request: &SignatureRequest) -> Result<bool, Cancelled> {
        (**self).confirm_signature(request)
    }
}

impl<T: DnieInteraction + ?Sized> DnieInteraction for &T {
    fn request_can(&self, request: &CanRequest) -> Result<Zeroizing<String>, Cancelled> {
        (**self).request_can(request)
    }
    fn request_pin(&self, request: &PinRequest) -> Result<Zeroizing<String>, Cancelled> {
        (**self).request_pin(request)
    }
    fn confirm_signature(&self, request: &SignatureRequest) -> Result<bool, Cancelled> {
        (**self).confirm_signature(request)
    }
}

/// CAN y PIN introducidos de antemano (lo que hace la app Android con
/// `AndroidDnieNFCCallbackHandler`: ignora el número de intentos). Un valor `None` equivale a
/// cancelar la petición.
pub struct FixedInteraction {
    can: Option<Zeroizing<String>>,
    pin: Option<Zeroizing<String>>,
}

impl FixedInteraction {
    pub fn new(can: Option<&str>, pin: Option<&str>) -> Self {
        FixedInteraction {
            can: can.map(|s| Zeroizing::new(s.to_string())),
            pin: pin.map(|s| Zeroizing::new(s.to_string())),
        }
    }
}

impl DnieInteraction for FixedInteraction {
    fn request_can(&self, _request: &CanRequest) -> Result<Zeroizing<String>, Cancelled> {
        self.can.clone().ok_or(Cancelled)
    }

    fn request_pin(&self, _request: &PinRequest) -> Result<Zeroizing<String>, Cancelled> {
        self.pin.clone().ok_or(Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts() {
        let r = PinRequest {
            retries_left: Some(3),
            alias: "CertFirmaDigital".into(),
        };
        assert_eq!(
            r.prompt(),
            "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: 3"
        );
        let f = FixedInteraction::new(Some("123456"), None);
        assert_eq!(f.request_can(&CanRequest::default()).unwrap().as_str(), "123456");
        assert_eq!(f.request_pin(&r), Err(Cancelled));
        assert_eq!(f.confirm_signature(&SignatureRequest { alias: "x".into() }), Ok(true));
    }
}
