//! Tipos de almacén de claves (`AOKeyStore`) y sistema operativo.
//!
//! Los identificadores (`WINDOWS`, `MOZ_UNI`...) y los nombres visibles
//! (`Windows`, `Mozilla / Firefox (unificado)`...) son los que usan el
//! protocolo `afirma://` (parámetros `keystore`/`ksb64` y la preferencia
//! `defaultKeystore`) y deben coincidir exactamente con los de Java.

use std::fmt;

use crate::error::KeyStoreError;

/// Sistema operativo, a efectos de selección de almacén.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
    Solaris,
    Other,
}

impl Os {
    /// Sistema operativo en el que se ejecuta el proceso.
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else if cfg!(target_os = "linux") || cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") || cfg!(target_os = "netbsd") {
            // Java (`Platform.getOS()`) trata los UNIX libres como Linux.
            Os::Linux
        } else if cfg!(target_os = "solaris") || cfg!(target_os = "illumos") {
            Os::Solaris
        } else {
            Os::Other
        }
    }

    /// Nombre del sistema operativo tal y como aparece en los mensajes de
    /// error de Java (`Platform.OS`).
    pub fn name(self) -> &'static str {
        match self {
            Os::Windows => "WINDOWS",
            Os::MacOs => "MACOSX",
            Os::Linux => "LINUX",
            Os::Solaris => "SOLARIS",
            Os::Other => "OTHER",
        }
    }
}

/// Tipo de almacén de claves (equivalente al enumerado `AOKeyStore` de Java).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyStoreKind {
    /// Almacén de usuario de Windows (`MY`).
    Windows,
    /// Llavero de macOS.
    Apple,
    /// Base de datos NSS compartida (`~/.pki/nssdb`), solo Linux.
    SharedNss,
    /// Fichero PKCS#12 / PFX.
    Pkcs12,
    /// Java KeyStore (JKS).
    Java,
    /// Biblioteca PKCS#11 (genérica o tarjeta registrada).
    Pkcs11,
    /// Certificados sueltos PKCS#7 / X.509 (sin claves).
    Single,
    /// Firefox (NSS + módulos PKCS#11 externos).
    MozUni,
    /// Firefox junto al almacén del sistema operativo.
    MozUniWithOs,
    /// JCEKS.
    Jceks,
    /// JKS sensible a mayúsculas.
    JavaCe,
    /// Tarjeta del Ministerio de Defensa (no soportada).
    Temd,
    /// Windows "otras personas" (libreta de direcciones).
    WinAddressBook,
    /// Windows CA intermedias.
    WinCa,
    /// Tarjeta FNMT-RCM CERES.
    Ceres,
    /// DNIe y tarjetas FNMT-TIF.
    DnieJava,
    /// Tarjetas conocidas mediante PKCS#11 (perfil temporal de Windows).
    KnownSmartcards,
    /// G&D SmartCafe.
    SmartCafe,
    /// Tarjeta FNMT-RCM CERES 4.30 o superior.
    Ceres430,
    /// Tipo desconocido.
    Other,
}

/// Mensajes de petición de contraseña (`keystoremessages_es_ES.properties`).
pub mod prompts {
    /// `AOKeyStore.0`
    pub const PKCS12_ENTRY: &str = "Introduzca la contraseña del certificado dentro del fichero PKCS#12.";
    /// `AOKeyStore.1`
    pub const PKCS12_STORE: &str = "Introduzca la contraseña del almacén PKCS#12.";
    /// `AOKeyStore.2`, `.6`, `.8`
    pub const JAVA_ENTRY: &str = "Introduzca la contraseña del certificado dentro del almacén Java.";
    /// `AOKeyStore.3`, `.7`, `.9`
    pub const JAVA_STORE: &str = "Introduzca la contraseña del almacén Java.";
    /// `AOKeyStore.4`
    pub const PKCS11_STORE: &str = "Introduzca la contraseña del almacén PKCS#11.";
    /// `AOKeyStore.5`
    pub const MOZILLA_STORE: &str = "Introduzca la contraseña del almacén de claves de Mozilla Firefox.";
    /// `AOKeyStore.13`
    pub const SHARED_NSS_STORE: &str = "Introduzca la contraseña del almacén de claves del sistema.";
    /// `AOKeyStore.14`
    pub const TEMD_STORE: &str = "Introduzca el PIN de su Tarjeta del Ministerio de Defensa.";
    /// `MozillaUnifiedKeyStoreManager.0`
    pub const MOZILLA_NO_CALLBACK: &str = "Contraseña del almacén de Firefox";
    /// `CAPIKeyStoreManager.0`
    pub const CAPI_DEVICE: &str = "Por favor, introduzca la contraseña de su dispositivo criptográfico";
    /// `KeyStoreUtilities.5`
    pub const WRONG_PIN: &str = "La contraseña introducida no es correcta.";
    /// `KeyStoreUtilities.6`
    pub const LOAD_ERROR_TITLE: &str = "Error al cargar el almacén de claves";
    /// `KeyStoreUtilities.7`
    pub const LOCKED: &str = "Su almacén de claves esta bloqueado.";
    /// `KeyStoreUtilities.8`
    pub const PIN_LENGTH: &str = "La longitud de la contraseña introducida no es válida.";
    /// `CommonPasswordCallback.4`
    pub const DNIE_PIN: &str = "Por favor, introduzca el PIN del DNIe.";
    /// `CommonPasswordCallback.3`
    pub const DNIE_PIN_RETRIES: &str = "Por favor, introduzca el PIN del DNIe.\nIntentos restantes: %0";
    /// `CommonPasswordCallback.6`
    pub const CARD_PIN: &str = "Por favor, introduzca el PIN de la tarjeta.";
    /// `CommonPasswordCallback.5`
    pub const CARD_PIN_RETRIES: &str = "Por favor, introduzca el PIN de la tarjeta.\nIntentos restantes: %0";
    /// `CommonPasswordCallback.1`
    pub const DNIE_PIN_TITLE: &str = "DNI Electrónico: Introducción de PIN";
    /// `CommonPasswordCallback.2`
    pub const CARD_PIN_TITLE: &str = "Tarjeta inteligente: Introducción de PIN";

    /// `AOKeyStore.15`: "Introduzca la contraseña del almacén %0."
    pub fn store_with_name(name: &str) -> String {
        format!("Introduzca la contraseña del almacén {name}.")
    }

    /// Módulo PKCS#11 externo de Firefox.
    pub fn firefox_module(description: &str) -> String {
        format!("Introduzca la contraseña de {description}")
    }

    /// Tarjetas conocidas del perfil temporal de Windows
    /// (`SmartCardUnifiedKeyStoreManager.0`).
    pub fn known_card(name: &str) -> String {
        format!("Por favor, introduzca la contraseña de la tarjeta {name}")
    }
}

impl KeyStoreKind {
    /// Todos los tipos, en el orden de declaración de Java.
    pub const ALL: [KeyStoreKind; 20] = [
        KeyStoreKind::Windows,
        KeyStoreKind::Apple,
        KeyStoreKind::SharedNss,
        KeyStoreKind::Pkcs12,
        KeyStoreKind::Java,
        KeyStoreKind::Pkcs11,
        KeyStoreKind::Single,
        KeyStoreKind::MozUni,
        KeyStoreKind::MozUniWithOs,
        KeyStoreKind::Jceks,
        KeyStoreKind::JavaCe,
        KeyStoreKind::Temd,
        KeyStoreKind::WinAddressBook,
        KeyStoreKind::WinCa,
        KeyStoreKind::Ceres,
        KeyStoreKind::DnieJava,
        KeyStoreKind::KnownSmartcards,
        KeyStoreKind::SmartCafe,
        KeyStoreKind::Ceres430,
        KeyStoreKind::Other,
    ];

    /// Identificador (nombre de la constante Java, `AOKeyStore.name()`).
    pub fn id(self) -> &'static str {
        use KeyStoreKind::*;
        match self {
            Windows => "WINDOWS",
            Apple => "APPLE",
            SharedNss => "SHARED_NSS",
            Pkcs12 => "PKCS12",
            Java => "JAVA",
            Pkcs11 => "PKCS11",
            Single => "SINGLE",
            MozUni => "MOZ_UNI",
            MozUniWithOs => "MOZ_UNI_WITH_OS",
            Jceks => "JCEKS",
            JavaCe => "JAVACE",
            Temd => "TEMD",
            WinAddressBook => "WINADDRESSBOOK",
            WinCa => "WINCA",
            Ceres => "CERES",
            DnieJava => "DNIEJAVA",
            KnownSmartcards => "KNOWN_SMARTCARDS",
            SmartCafe => "SMARTCAFE",
            Ceres430 => "CERES_430",
            Other => "OTHER",
        }
    }

    /// Nombre visible (`AOKeyStore.getName()`), que también se usa como valor
    /// de la preferencia `defaultKeystore` y en el título del diálogo.
    pub fn display_name(self) -> &'static str {
        use KeyStoreKind::*;
        match self {
            Windows => "Windows",
            Apple => "Llavero de Mac",
            SharedNss => "NSS",
            Pkcs12 => "PKCS#12 / PFX",
            Java => "Java KeyStore / JKS",
            Pkcs11 => "PKCS#11",
            Single => "PKCS#7 / X.509",
            MozUni => "Mozilla / Firefox (unificado)",
            MozUniWithOs => "Mozilla / Firefox (unificado) junto a almacen de SO",
            Jceks => "Java Cryptography Extension KeyStore (JCEKS)",
            JavaCe => "Java KeyStore / JKS (Case Exact)",
            Temd => "TEMD (Tarjeta del Ministerio de Defensa)",
            WinAddressBook => "Windows / Internet Explorer (otras personas / libreta de direcciones)",
            WinCa => "Windows / Internet Explorer (CA intermedias)",
            Ceres => "Tarjeta FNMT-RCM CERES",
            DnieJava => "DNIe y tarjetas FNMT-TIF",
            KnownSmartcards => "Tarjetas inteligentes conocidas mediante PKCS#11",
            SmartCafe => "G&D SmartCafe con Applet PKCS#15",
            Ceres430 => "Tarjeta FNMT-RCM CERES 4.30 o superior",
            Other => "Tipo desconocido",
        }
    }

    /// Tipo JCA de Java (`getProviderName()`), solo informativo.
    pub fn jca_type(self) -> Option<&'static str> {
        use KeyStoreKind::*;
        Some(match self {
            Windows => "Windows-MY",
            Apple => "KeychainStore",
            SharedNss | Pkcs11 | MozUni | MozUniWithOs | Temd => "PKCS11",
            Pkcs12 => "PKCS12",
            Java => "JKS",
            Single => "PKCS7",
            Jceks => "JCEKS",
            JavaCe => "CaseExactJKS",
            WinAddressBook => "Windows-ADDRESSBOOK",
            WinCa => "Windows-ROOT",
            Ceres => "CERES",
            DnieJava => "DNI",
            KnownSmartcards => "SMARTCARDS",
            SmartCafe => "GDSCPKCS15",
            Ceres430 => "CERES430",
            Other => return None,
        })
    }

    /// Busca por nombre visible (sin distinguir mayúsculas, recortando
    /// espacios), como el primer paso de `SimpleKeyStoreManager.getKeyStore`.
    pub fn from_display_name(name: &str) -> Option<KeyStoreKind> {
        let n = name.trim();
        Self::ALL.into_iter().find(|k| k.display_name().eq_ignore_ascii_case(n) || unicode_eq_ignore_case(k.display_name(), n))
    }

    /// Busca por identificador exacto (`AOKeyStore.valueOf`: sensible a
    /// mayúsculas y sin recortar).
    pub fn from_id(id: &str) -> Option<KeyStoreKind> {
        Self::ALL.into_iter().find(|k| k.id() == id)
    }

    /// Almacén por defecto del sistema operativo
    /// (`AOKeyStore.getDefaultKeyStoreTypeByOs`).
    pub fn default_for(os: Os) -> Option<KeyStoreKind> {
        match os {
            Os::Windows => Some(KeyStoreKind::Windows),
            Os::MacOs => Some(KeyStoreKind::Apple),
            Os::Linux => Some(KeyStoreKind::SharedNss),
            Os::Solaris => Some(KeyStoreKind::MozUni),
            Os::Other => None,
        }
    }

    /// Almacén por defecto del sistema actual o error 201116.
    pub fn default_for_current_os() -> Result<KeyStoreKind, KeyStoreError> {
        Self::default_for(Os::current()).ok_or(KeyStoreError::UndefinedDefault)
    }

    /// Almacén "del sistema" del selector del diálogo (`openSystemKeyStore`):
    /// Windows → `WINDOWS`, Linux/Solaris → `SHARED_NSS`, macOS → `APPLE`.
    pub fn system_store_for(os: Os) -> Result<KeyStoreKind, KeyStoreError> {
        match os {
            Os::Windows => Ok(KeyStoreKind::Windows),
            Os::MacOs => Ok(KeyStoreKind::Apple),
            Os::Linux | Os::Solaris => Ok(KeyStoreKind::SharedNss),
            Os::Other => Err(KeyStoreError::UndefinedDefault),
        }
    }

    /// Indica si la factoría puede abrir este tipo en el sistema indicado
    /// (sección 1.3 de la especificación). Los almacenes Java (JKS, JCEKS)
    /// no están implementados en AutoFirma-rs (prioridad baja).
    pub fn is_supported_on(self, os: Os) -> bool {
        use KeyStoreKind::*;
        match self {
            Pkcs12 | Pkcs11 | Single | MozUni | MozUniWithOs => true,
            DnieJava | Ceres | Ceres430 | SmartCafe => true,
            Windows | WinAddressBook | WinCa => os == Os::Windows,
            Apple => os == Os::MacOs,
            SharedNss => os == Os::Linux,
            Java | Jceks | JavaCe => false,
            Temd | Other | KnownSmartcards => false,
        }
    }

    /// Almacén alternativo sugerido cuando este no está disponible
    /// (`KeystoreAlternativeException.getAlternateKeyStoreType`).
    pub fn alternative(self, os: Os) -> Option<KeyStoreKind> {
        if self == KeyStoreKind::Pkcs12 {
            return None;
        }
        match os {
            Os::Windows if self != KeyStoreKind::Windows => Some(KeyStoreKind::Windows),
            Os::MacOs if self != KeyStoreKind::Apple => Some(KeyStoreKind::Apple),
            Os::Windows | Os::MacOs => None,
            _ => Some(KeyStoreKind::Pkcs12),
        }
    }

    /// Error "no soportado" de la factoría para este tipo.
    pub fn unsupported_error(self, os: Os) -> KeyStoreError {
        KeyStoreError::Unsupported { store: self.display_name().to_string(), os: os.name().to_string(), alternative: self.alternative(os) }
    }

    /// Indica si necesita un fichero o biblioteca (`lib`).
    pub fn needs_lib(self) -> bool {
        matches!(self, KeyStoreKind::Pkcs12 | KeyStoreKind::Pkcs11 | KeyStoreKind::Java | KeyStoreKind::Jceks | KeyStoreKind::JavaCe | KeyStoreKind::Single)
    }

    /// Tipos implementados en Java con el controlador jmulticard (DNIe y
    /// CERES), que en AutoFirma-rs se implementan sobre PKCS#11. Son
    /// almacenes "preferentes": ocultan los duplicados de los demás.
    pub fn is_card_driver(self) -> bool {
        matches!(self, KeyStoreKind::DnieJava | KeyStoreKind::Ceres | KeyStoreKind::Ceres430 | KeyStoreKind::SmartCafe)
    }

    /// Tipos basados en NSS/Firefox.
    pub fn is_mozilla(self) -> bool {
        matches!(self, KeyStoreKind::MozUni | KeyStoreKind::MozUniWithOs | KeyStoreKind::SharedNss)
    }

    /// Texto para pedir la contraseña del almacén (`null` si el tipo no la pide).
    /// `file_name` es el nombre del fichero o biblioteca, si se conoce
    /// (PKCS#12 → `AOKeyStore.15`).
    pub fn store_password_prompt(self, file_name: Option<&str>) -> Option<String> {
        use KeyStoreKind::*;
        match self {
            Pkcs12 => Some(match file_name {
                Some(f) => prompts::store_with_name(f),
                None => prompts::PKCS12_STORE.to_string(),
            }),
            Pkcs11 => Some(prompts::store_with_name(self.display_name())),
            Java | Jceks | JavaCe => Some(prompts::JAVA_STORE.to_string()),
            MozUni | MozUniWithOs => Some(prompts::MOZILLA_STORE.to_string()),
            SharedNss => Some(prompts::SHARED_NSS_STORE.to_string()),
            Temd => Some(prompts::TEMD_STORE.to_string()),
            _ => None,
        }
    }

    /// Texto para pedir la contraseña de una entrada (solo los almacenes en
    /// fichero la piden).
    pub fn entry_password_prompt(self) -> Option<&'static str> {
        match self {
            KeyStoreKind::Pkcs12 => Some(prompts::PKCS12_ENTRY),
            KeyStoreKind::Java | KeyStoreKind::Jceks | KeyStoreKind::JavaCe => Some(prompts::JAVA_ENTRY),
            _ => None,
        }
    }
}

/// Comparación sin mayúsculas para nombres con caracteres no ASCII
/// (`String.equalsIgnoreCase`).
fn unicode_eq_ignore_case(a: &str, b: &str) -> bool {
    a.chars().count() == b.chars().count()
        && a.chars().zip(b.chars()).all(|(x, y)| x == y || x.to_uppercase().eq(y.to_uppercase()) || x.to_lowercase().eq(y.to_lowercase()))
}

impl fmt::Display for KeyStoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ids() {
        assert_eq!(KeyStoreKind::from_display_name("  windows "), Some(KeyStoreKind::Windows));
        assert_eq!(KeyStoreKind::from_display_name("nss"), Some(KeyStoreKind::SharedNss));
        assert_eq!(KeyStoreKind::from_display_name("PKCS#12 / PFX"), Some(KeyStoreKind::Pkcs12));
        assert_eq!(KeyStoreKind::from_display_name("LLAVERO DE MAC"), Some(KeyStoreKind::Apple));
        assert_eq!(KeyStoreKind::from_id("MOZ_UNI"), Some(KeyStoreKind::MozUni));
        assert_eq!(KeyStoreKind::from_id("moz_uni"), None);
        assert_eq!(KeyStoreKind::from_id(" MOZ_UNI"), None);
        for k in KeyStoreKind::ALL {
            assert_eq!(KeyStoreKind::from_id(k.id()), Some(k));
        }
        // CERES_430 y OTHER comparten ordinal en Java pero son distintos.
        assert_eq!(KeyStoreKind::from_id("CERES_430"), Some(KeyStoreKind::Ceres430));
    }

    #[test]
    fn defaults() {
        assert_eq!(KeyStoreKind::default_for(Os::Linux), Some(KeyStoreKind::SharedNss));
        assert_eq!(KeyStoreKind::default_for(Os::Solaris), Some(KeyStoreKind::MozUni));
        assert_eq!(KeyStoreKind::default_for(Os::Other), None);
        assert_eq!(KeyStoreKind::Windows.alternative(Os::Linux), Some(KeyStoreKind::Pkcs12));
        assert_eq!(KeyStoreKind::MozUni.alternative(Os::Windows), Some(KeyStoreKind::Windows));
        assert_eq!(KeyStoreKind::Pkcs12.alternative(Os::Windows), None);
        assert!(!KeyStoreKind::Windows.is_supported_on(Os::Linux));
        assert!(KeyStoreKind::SharedNss.is_supported_on(Os::Linux));
        assert!(!KeyStoreKind::SharedNss.is_supported_on(Os::MacOs));
    }

    #[test]
    fn prompts_text() {
        assert_eq!(
            KeyStoreKind::Pkcs12.store_password_prompt(Some("a.p12")).unwrap(),
            "Introduzca la contraseña del almacén a.p12."
        );
        assert_eq!(KeyStoreKind::Pkcs11.store_password_prompt(None).unwrap(), "Introduzca la contraseña del almacén PKCS#11.");
    }
}
