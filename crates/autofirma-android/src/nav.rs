//! Navegación entre pantallas (`docs/spec/09-android.md` §2.3, §2.4 y §2.13).
//!
//! Cada actividad del original es una [`Screen`] con su estado (lo que en Java eran los
//! campos de la actividad), en una pila: entrar en una pantalla la apila y «Atrás» vuelve a
//! la anterior con el estado que tenía. Diferencias con el original, corregidas
//! (§10 n.º 4): «Atrás» en Ajustes y en Idioma vuelve a la pantalla anterior en lugar de
//! abrir otra instancia de Inicio o de Ajustes (en el original la pila crecía sin fin); y en
//! las pantallas raíz (Bienvenida, Condiciones, Inicio), donde el original no hacía nada,
//! deja la aplicación en segundo plano, que es lo que espera Android (la actividad no se
//! cierra; véase `docs/ANDROID.md` §3.1).
//!
//! La lógica no depende de egui ni de Android y se prueba en el anfitrión.

use crate::history::SignRecord;
use crate::prefs::{CacheMinutes, Preferences};

/// Valores de «Configuración de firma» mientras se editan: no se guardan hasta pulsar
/// «Guardar» (§2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignConfigDraft {
    pub use_nfc: bool,
    pub visible_signature: bool,
    pub obfuscate_cert_info: bool,
    pub cache_minutes: CacheMinutes,
}

impl SignConfigDraft {
    pub fn from_prefs(p: &Preferences) -> SignConfigDraft {
        SignConfigDraft {
            use_nfc: p.use_nfc,
            visible_signature: p.pades_visible_signature,
            obfuscate_cert_info: p.pades_obfuscate_cert_info,
            cache_minutes: p.sticky_signature_timeout,
        }
    }

    /// Copia los valores a las preferencias («Guardar»).
    pub fn apply(&self, p: &mut Preferences) {
        p.use_nfc = self.use_nfc;
        p.pades_visible_signature = self.visible_signature;
        p.pades_obfuscate_cert_info = self.obfuscate_cert_info;
        p.sticky_signature_timeout = self.cache_minutes;
    }
}

/// Funciones de fases posteriores que de momento son una pantalla que lo explica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Importar un `.p12`/`.pfx` en KeyChain (§4.8).
    ImportCertificate,
}

/// Pantallas de la aplicación, con su estado.
#[derive(Debug, Clone, PartialEq)]
pub enum Screen {
    /// Arranque (§2.4): logotipo y enrutado a bienvenida, condiciones o inicio.
    Splash,
    /// Bienvenida de la primera ejecución (`IntroScreenActivity`).
    Intro,
    /// Aceptación de los textos legales (`ConditionsActivity`).
    Conditions {
        privacy: bool,
        legal: bool,
    },
    /// Inicio (`HomeActivity` + `MainFragment`).
    Home,
    Settings,
    Language,
    SignConfiguration(SignConfigDraft),
    /// Dominios de confianza; el texto del campo, sin guardar.
    TrustedDomains {
        text: String,
    },
    SignsRecord {
        records: Vec<SignRecord>,
    },
    Faq {
        open: [bool; 3],
    },
    HelpDnieNfc,
    HelpVisibleSign,
    HelpTrustedDomains,
    HelpImportCerts,
    AccessibilityStatement,
    LegalNotice,
    PrivacyPolicy,
    Version,
    /// Instrucciones para importar un certificado (dos páginas, §4.8).
    ImportInstructions {
        page: usize,
    },
    /// Certificados del almacén de Android.
    Certificates,
    /// Información sobre la firma desde las páginas web.
    WebSigningInfo,
    /// Documento elegido con «Firmar fichero».
    SignFile,
    /// Petición `afirma://` recibida.
    WebRequest,
    /// Función aún no disponible.
    Unavailable(Feature),
}

impl Screen {
    /// Identificador estable (registros y pruebas en el emulador).
    pub fn id(&self) -> &'static str {
        match self {
            Screen::Splash => "splash",
            Screen::Intro => "intro",
            Screen::Conditions { .. } => "conditions",
            Screen::Home => "home",
            Screen::Settings => "settings",
            Screen::Language => "language",
            Screen::SignConfiguration(_) => "sign_configuration",
            Screen::TrustedDomains { .. } => "trusted_domains",
            Screen::SignsRecord { .. } => "signs_record",
            Screen::Faq { .. } => "faq",
            Screen::HelpDnieNfc => "help_dnie_nfc",
            Screen::HelpVisibleSign => "help_visible_sign",
            Screen::HelpTrustedDomains => "help_trusted_domains",
            Screen::HelpImportCerts => "help_import_certs",
            Screen::AccessibilityStatement => "accessibility",
            Screen::LegalNotice => "legal",
            Screen::PrivacyPolicy => "privacy",
            Screen::Version => "version",
            Screen::ImportInstructions { page: 0 } => "import_instructions_1",
            Screen::ImportInstructions { .. } => "import_instructions_2",
            Screen::Certificates => "certificates",
            Screen::WebSigningInfo => "web_signing",
            Screen::SignFile => "sign_file",
            Screen::WebRequest => "web_request",
            Screen::Unavailable(_) => "unavailable",
        }
    }
}

/// Destino tras el arranque (§2.4): bienvenida si no se ha visto, condiciones si no se han
/// aceptado, y si no, inicio.
pub fn route_after_splash(p: &Preferences) -> Screen {
    if !p.skip_intro_screen {
        Screen::Intro
    } else if !p.skip_conditions_screen {
        Screen::Conditions {
            privacy: false,
            legal: false,
        }
    } else {
        Screen::Home
    }
}

/// Resultado de «Atrás».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackOutcome {
    /// Se ha vuelto a la pantalla (o página) anterior.
    Handled,
    /// Es la pantalla raíz: la aplicación pasa a segundo plano.
    LeaveApp,
}

/// Pila de pantallas.
#[derive(Debug, Clone)]
pub struct Navigator {
    stack: Vec<Screen>,
}

impl Navigator {
    pub fn new(root: Screen) -> Navigator {
        Navigator { stack: vec![root] }
    }

    pub fn current(&self) -> &Screen {
        self.stack.last().expect("la pila nunca está vacía")
    }

    pub fn current_mut(&mut self) -> &mut Screen {
        self.stack.last_mut().expect("la pila nunca está vacía")
    }

    /// Número de pantallas apiladas.
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Identificadores de la pila, de la raíz a la actual.
    pub fn ids(&self) -> Vec<&'static str> {
        self.stack.iter().map(Screen::id).collect()
    }

    /// Entra en una pantalla.
    pub fn push(&mut self, screen: Screen) {
        self.stack.push(screen);
    }

    /// Sustituye toda la pila por una pantalla raíz.
    pub fn reset(&mut self, root: Screen) {
        self.stack = vec![root];
    }

    /// Sustituye la pantalla raíz conservando las que tiene encima.
    pub fn replace_root(&mut self, root: Screen) {
        self.stack[0] = root;
    }

    /// Botón «Atrás» (§2.13).
    pub fn back(&mut self) -> BackOutcome {
        if let Screen::ImportInstructions { page } = self.current_mut()
            && *page > 0
        {
            *page -= 1;
            return BackOutcome::Handled;
        }
        if self.stack.len() > 1 {
            self.stack.pop();
            BackOutcome::Handled
        } else {
            BackOutcome::LeaveApp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrutado_del_arranque() {
        let mut p = Preferences::default();
        assert_eq!(route_after_splash(&p), Screen::Intro);
        p.skip_intro_screen = true;
        assert_eq!(route_after_splash(&p).id(), "conditions");
        p.skip_conditions_screen = true;
        assert_eq!(route_after_splash(&p), Screen::Home);
        // Condiciones aceptadas pero bienvenida no vista: bienvenida.
        p.skip_intro_screen = false;
        assert_eq!(route_after_splash(&p), Screen::Intro);
    }

    #[test]
    fn pila_y_atras() {
        let mut nav = Navigator::new(Screen::Home);
        assert_eq!(nav.back(), BackOutcome::LeaveApp, "desde Inicio se sale");
        nav.push(Screen::Settings);
        nav.push(Screen::Language);
        assert_eq!(nav.ids(), ["home", "settings", "language"]);
        // Idioma → Ajustes → Inicio (el original abría instancias nuevas).
        assert_eq!(nav.back(), BackOutcome::Handled);
        assert_eq!(nav.current(), &Screen::Settings);
        assert_eq!(nav.back(), BackOutcome::Handled);
        assert_eq!(nav.current(), &Screen::Home);
        assert_eq!(nav.depth(), 1);

        // Las instrucciones de importación retroceden de página antes de salir.
        nav.push(Screen::ImportInstructions { page: 1 });
        assert_eq!(nav.current().id(), "import_instructions_2");
        assert_eq!(nav.back(), BackOutcome::Handled);
        assert_eq!(nav.current(), &Screen::ImportInstructions { page: 0 });
        assert_eq!(nav.back(), BackOutcome::Handled);
        assert_eq!(nav.current(), &Screen::Home);

        // El estado de una pantalla se conserva al volver a ella.
        nav.push(Screen::Faq {
            open: [false, true, false],
        });
        nav.push(Screen::Version);
        nav.back();
        assert_eq!(
            nav.current(),
            &Screen::Faq {
                open: [false, true, false]
            }
        );

        nav.reset(Screen::Intro);
        assert_eq!(nav.ids(), ["intro"]);
        nav.push(Screen::WebRequest);
        nav.replace_root(Screen::Home);
        assert_eq!(nav.ids(), ["home", "web_request"]);
    }

    #[test]
    fn borrador_de_configuracion() {
        let mut p = Preferences::default();
        let mut draft = SignConfigDraft::from_prefs(&p);
        draft.use_nfc = true;
        draft.cache_minutes = CacheMinutes::Thirty;
        assert!(!p.use_nfc, "nada se guarda sin «Guardar»");
        draft.apply(&mut p);
        assert!(p.use_nfc);
        assert_eq!(p.sticky_signature_timeout, CacheMinutes::Thirty);
    }
}
