//! Textos de ayuda (`buildGeneralSyntax` y `CommandLineParameters.build*SyntaxError`).
//!
//! Los textos de los comandos de Java se construyen exactamente igual (mismas
//! tabulaciones y claves). La ayuda general añade, como comandos integrados,
//! `createdigest` y `checkdigest` (en Java llegaban del plugin de huellas) y
//! una sección nueva con los comandos de integración con el sistema.

use afirma_hash::HashCommand;

use crate::messages::{Language, Messages};
use crate::params::Command;

/// Textos nuevos (sin equivalente en Java) en español y en inglés; el resto
/// de idiomas usa el español.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Text {
    SystemTitle,
    InstallDesc,
    UninstallDesc,
    DoctorDesc,
    RestoreDesc,
    OptSystem,
    OptUser,
    OptBrowserPolicies,
    OptOrigins,
    OptDryRun,
    OptJson,
    NoSystemOps,
    ScopeRequired,
    ScopeExclusive,
    MissingOrigins,
}

pub(crate) fn text(m: &Messages, t: Text) -> &'static str {
    let en = m.language() == Language::EnUs;
    match t {
        Text::SystemTitle => {
            if en {
                "System integration commands"
            } else {
                "Comandos de integracion con el sistema"
            }
        }
        Text::InstallDesc => {
            if en {
                "installs the integration of Autofirma with the system and the browsers"
            } else {
                "instala la integracion de Autofirma con el sistema y los navegadores"
            }
        }
        Text::UninstallDesc => {
            if en {
                "removes the integration of Autofirma with the system and the browsers"
            } else {
                "elimina la integracion de Autofirma con el sistema y los navegadores"
            }
        }
        Text::DoctorDesc => {
            if en {
                "diagnoses the installation and configuration of Autofirma"
            } else {
                "diagnostica la instalacion y la configuracion de Autofirma"
            }
        }
        Text::RestoreDesc => {
            if en {
                "restores the local certificates and the afirma:// protocol handler"
            } else {
                "restaura los certificados locales y el manejador del protocolo afirma://"
            }
        }
        Text::OptSystem => {
            if en {
                "For all the users of the computer (requires administrator privileges)"
            } else {
                "Para todos los usuarios del equipo (requiere permisos de administrador)"
            }
        }
        Text::OptUser => {
            if en {
                "Only for the current user"
            } else {
                "Solo para el usuario actual"
            }
        }
        Text::OptBrowserPolicies => {
            if en {
                "Configures the browser policies to open afirma:// links without prompts"
            } else {
                "Configura las directivas de los navegadores para abrir afirma:// sin avisos"
            }
        }
        Text::OptOrigins => {
            if en {
                "Comma separated web origins allowed to open afirma:// (implies --browser-policies)"
            } else {
                "Origenes web, separados por comas, que pueden abrir afirma:// (implica --browser-policies)"
            }
        }
        Text::OptDryRun => {
            if en {
                "Shows the actions without performing them"
            } else {
                "Muestra las acciones sin realizarlas"
            }
        }
        Text::OptJson => {
            if en {
                "Formats the answer as JSON"
            } else {
                "Formatea la respuesta como JSON"
            }
        }
        Text::NoSystemOps => {
            if en {
                "The system integration is not available in this build"
            } else {
                "La integracion con el sistema no esta disponible en esta version"
            }
        }
        Text::ScopeRequired => {
            if en {
                "One of the options '--system' or '--user' must be indicated"
            } else {
                "Se tiene que indicar una de las opciones '--system' o '--user'"
            }
        }
        Text::ScopeExclusive => {
            if en {
                "Options '--system' and '--user' are exclusive"
            } else {
                "Las opciones '--system' y '--user' son excluyentes"
            }
        }
        Text::MissingOrigins => {
            if en {
                "No origins indicated"
            } else {
                "No se ha indicado la lista de origenes"
            }
        }
    }
}

/// Comandos de integración con el sistema (nuevos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemCommand {
    /// `install --system|--user [--browser-policies] [--origins LISTA] [--dry-run]`.
    Install,
    /// `uninstall --system|--user [--dry-run]`.
    Uninstall,
    /// `doctor [--json]`.
    Doctor,
    /// `restore-config`.
    RestoreConfig,
}

impl SystemCommand {
    /// Todos, en el orden de la ayuda.
    pub const ALL: [SystemCommand; 4] = [
        Self::Install,
        Self::Uninstall,
        Self::Doctor,
        Self::RestoreConfig,
    ];

    /// Nombre del comando.
    pub fn op(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::Doctor => "doctor",
            Self::RestoreConfig => "restore-config",
        }
    }

    /// Comando de un nombre en minúsculas.
    pub fn parse(op: &str) -> Option<SystemCommand> {
        Self::ALL.into_iter().find(|c| c.op() == op)
    }

    fn description(self, m: &Messages) -> &'static str {
        text(
            m,
            match self {
                Self::Install => Text::InstallDesc,
                Self::Uninstall => Text::UninstallDesc,
                Self::Doctor => Text::DoctorDesc,
                Self::RestoreConfig => Text::RestoreDesc,
            },
        )
    }
}

/// Ayuda general (`buildGeneralSyntax`). Con `error`, el mensaje sustituye a
/// la línea de título.
pub fn general_help(m: &Messages, app: &str, error: Option<&str>) -> String {
    let mut sb = String::new();
    match error {
        Some(e) => {
            sb.push_str(e);
            sb.push('\n');
        }
        None => {
            sb.push_str(&m.get(34));
            sb.push_str("\n\n");
        }
    }
    sb.push_str(&format!("{}: {app} cmd [{}...]\n\n", m.get(7), m.get(140)));
    sb.push_str(&format!("{} cmd:\n\n", m.get(33)));
    sb.push_str(&format!("  {}\t\t ({})\n", Command::Sign.op(), m.get(8)));
    sb.push_str(&format!("  {}\t ({})\n", Command::Cosign.op(), m.get(9)));
    sb.push_str(&format!(
        "  {}\t ({})\n",
        Command::Countersign.op(),
        m.get(10)
    ));
    sb.push_str(&format!("  {}\t ({})\n", Command::List.op(), m.get(11)));
    sb.push_str(&format!("  {}\t ({})\n", Command::Verify.op(), m.get(29)));
    sb.push_str(&format!(
        "  {}\t ({})\n",
        Command::BatchSign.op(),
        m.get(69)
    ));
    for h in HashCommand::ALL {
        sb.push_str(&format!("  {}\t ({})\n", h.op(), h.description()));
    }
    sb.push('\n');
    sb.push_str(&format!("{}:\n\n", text(m, Text::SystemTitle)));
    for c in SystemCommand::ALL {
        sb.push_str(&format!("  {}\t ({})\n", c.op(), c.description(m)));
    }
    sb.push('\n');
    sb.push_str(&m.fmt(30, &[app]));
    sb
}

fn header(m: &Messages, app: &str, op: &str, error: Option<&str>) -> String {
    let mut sb = String::new();
    if let Some(e) = error {
        sb.push_str(e);
        sb.push('\n');
    }
    sb.push_str(&format!("{}: {app} {op} [{}...]\n\n", m.get(7), m.get(140)));
    sb.push_str(&format!("{}:\n", m.get(115)));
    sb
}

/// Líneas de `-store` (con o sin `pkcs11`).
fn store_lines(m: &Messages, pkcs11: bool) -> String {
    let mut sb = String::new();
    sb.push_str(&format!("  -store\t\t ({})\n", m.get(31)));
    sb.push_str(&format!("  \t auto\t\t ({})\n", m.get(36)));
    sb.push_str(&format!("  \t windows\t ({})\n", m.get(37)));
    sb.push_str(&format!("  \t mac\t\t ({})\n", m.get(38)));
    sb.push_str(&format!("  \t mozilla\t ({})\n", m.get(39)));
    sb.push_str(&format!("  \t dni\t\t ({})\n", m.get(40)));
    sb.push_str(&format!("  \t pkcs12:p12file\t ({})\n", m.get(41)));
    if pkcs11 {
        sb.push_str(&format!("  \t pkcs11:p11file\t ({})\n", m.get(47)));
    }
    sb
}

/// Texto de la opción `-gui` de los comandos de firma: `.23 + " " + .146(-certgui)`.
/// Los catálogos sin `.146` (todos salvo el español) incluyen el `%0` en
/// `.23`, así que se sustituye ahí en lugar de imprimir
/// `... %0 !CommandLineLauncher.146!` como Java.
fn gui_option_text(m: &Messages) -> String {
    if m.has_own(146) {
        format!("{} {}", m.get(23), m.fmt(146, &["-certgui"]))
    } else {
        m.fmt(23, &["-certgui"])
    }
}

/// Ayuda de `sign`, `cosign` y `countersign`.
fn sign_help(m: &Messages, app: &str, op: &str, error: Option<&str>) -> String {
    let mut sb = header(m, app, op, error);
    sb.push_str(&format!("  -gui\t\t\t ({})\n", gui_option_text(m)));
    sb.push_str(&format!("  -certgui\t\t ({})\n", m.get(76)));
    sb.push_str(&format!("  -i inputfile\t\t ({})\n", m.get(13)));
    sb.push_str(&format!("  -o outputfile\t\t ({})\n", m.get(14)));
    sb.push_str(&format!("  -algorithm algo\t ({})\n", m.get(20)));
    for (algo, key) in [
        ("sha1", 142),
        ("sha256", 143),
        ("sha384", 144),
        ("sha512", 145),
    ] {
        sb.push_str(&format!("  \t {algo}\t\t ({})\n", m.get(key)));
    }
    sb.push_str(&format!("  -format\t\t ({})\n", m.get(32)));
    for (fmt, tabs, key) in [
        ("auto", "\t\t", 42),
        ("cades", "\t\t", 43),
        ("pades", "\t\t", 44),
        ("xades", "\t\t", 45),
        ("facturae", "\t", 46),
        ("ooxml", "\t\t", 72),
        ("odf", "\t\t", 73),
    ] {
        sb.push_str(&format!("  \t {fmt}{tabs} ({})\n", m.get(key)));
    }
    sb.push_str(&format!("  -config extraParams\t ({})\n", m.get(27)));
    sb.push_str(&store_lines(m, true));
    sb.push_str(&format!("  -password password\t ({})\n", m.get(12)));
    sb.push_str(&format!("  -alias alias\t\t ({})\n", m.get(16)));
    sb.push_str(&format!("  -filter filter\t ({})\n", m.get(66)));
    sb.push_str(&format!("  -xml\t\t\t ({})", m.get(18)));
    sb
}

/// Ayuda de `batchsign` (sin `-config`, como en Java).
fn batch_help(m: &Messages, app: &str, op: &str, error: Option<&str>) -> String {
    let mut sb = header(m, app, op, error);
    sb.push_str(&format!("  -i inputfile\t\t ({})\n", m.get(62)));
    sb.push_str(&format!("  -o outputfile\t\t ({})\n", m.get(63)));
    sb.push_str(&store_lines(m, true));
    sb.push_str(&format!("  -password password\t ({})\n", m.get(12)));
    sb.push_str(&format!("  -alias alias\t\t ({})\n", m.get(16)));
    sb.push_str(&format!("  -filter filter\t ({})\n", m.get(66)));
    sb.push_str(&format!("  -preurl url\t\t ({})\n", m.get(64)));
    sb.push_str(&format!("  -posturl url\t\t ({})\n", m.get(65)));
    sb.push_str(&format!("  -xml\t\t\t ({})", m.get(18)));
    sb
}

/// Ayuda de `verify`.
fn verify_help(m: &Messages, app: &str, op: &str, error: Option<&str>) -> String {
    let mut sb = header(m, app, op, error);
    sb.push_str(&format!("  -gui \t\t ({})\n", m.get(23)));
    sb.push_str(&format!("  -i inputfile\t ({})", m.get(13)));
    sb
}

/// Ayuda de `listaliases` (sin `pkcs11`, aunque se admite).
fn list_help(m: &Messages, app: &str, op: &str, error: Option<&str>) -> String {
    let mut sb = header(m, app, op, error);
    sb.push_str(&store_lines(m, false));
    sb.push_str(&format!("  -password password\t ({})\n", m.get(12)));
    sb.push_str(&format!("  -xml\t\t\t ({})", m.get(18)));
    sb
}

/// Ayuda de un comando integrado (`buildSyntaxError(op, error)`).
pub fn command_help(command: Command, m: &Messages, app: &str, error: Option<&str>) -> String {
    let op = command.op();
    match command {
        Command::Sign | Command::Cosign | Command::Countersign => sign_help(m, app, op, error),
        Command::List => list_help(m, app, op, error),
        Command::Verify => verify_help(m, app, op, error),
        Command::BatchSign => batch_help(m, app, op, error),
    }
}

/// Ayuda de un comando de integración con el sistema.
pub fn system_help(command: SystemCommand, m: &Messages, app: &str, error: Option<&str>) -> String {
    let op = command.op();
    let mut sb = String::new();
    if let Some(e) = error {
        sb.push_str(e);
        sb.push('\n');
    }
    let syntax = match command {
        SystemCommand::Install => {
            "(--system|--user) [--browser-policies] [--origins origins] [--dry-run]"
        }
        SystemCommand::Uninstall => "(--system|--user) [--dry-run]",
        SystemCommand::Doctor => "[--json]",
        SystemCommand::RestoreConfig => "",
    };
    let sep = if syntax.is_empty() { "" } else { " " };
    sb.push_str(&format!("{}: {app} {op}{sep}{syntax}\n\n", m.get(7)));
    sb.push_str(&format!("  ({})", command.description(m)));
    let mut opts: Vec<(&str, Text)> = Vec::new();
    match command {
        SystemCommand::Install => {
            opts.extend([
                ("--system\t\t", Text::OptSystem),
                ("--user\t\t\t", Text::OptUser),
                ("--browser-policies\t", Text::OptBrowserPolicies),
                ("--origins origins\t", Text::OptOrigins),
                ("--dry-run\t\t", Text::OptDryRun),
            ]);
        }
        SystemCommand::Uninstall => {
            opts.extend([
                ("--system\t\t", Text::OptSystem),
                ("--user\t\t\t", Text::OptUser),
                ("--dry-run\t\t", Text::OptDryRun),
            ]);
        }
        SystemCommand::Doctor => opts.push(("--json\t\t\t", Text::OptJson)),
        SystemCommand::RestoreConfig => {}
    }
    if !opts.is_empty() {
        sb.push_str(&format!("\n\n{}:", m.get(115)));
        for (opt, t) in opts {
            sb.push_str(&format!("\n  {opt} ({})", text(m, t)));
        }
    }
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ayuda_general_espanol() {
        let m = Messages::new(Language::EsEs);
        let h = general_help(&m, "autofirma", None);
        assert!(h.starts_with("Herramienta de firma de documentos.\n\nSintaxis: autofirma cmd [opciones...]\n\nComandos cmd:\n\n  sign\t\t (firma de fichero)\n"));
        assert!(h.contains("  batchsign\t (firma/multifirma de lotes de ficheros)\n  createdigest\t (Creación de huellas digitales con interfaz gráfica)\n"));
        assert!(h.contains("Comandos de integracion con el sistema:\n\n  install\t ("));
        assert!(h.contains("  restore-config\t ("));
        assert!(h.ends_with(
            "\n\nUtilice \"autofirma cmd -help\" para ver la sintaxis del comando \"cmd\""
        ));
        let e = general_help(&m, "x", Some("Comando no reconocido: foo"));
        assert!(e.starts_with("Comando no reconocido: foo\nSintaxis: x cmd"));
    }

    #[test]
    fn opcion_gui_sin_clave_146() {
        let en = Messages::new(Language::EnUs);
        let h = command_help(Command::Sign, &en, "a", None);
        assert!(h.contains("  -gui\t\t\t (Perform the operation with graphic environment. Priority over -certgui)\n"));
        let es = Messages::new(Language::EsEs);
        let h = command_help(Command::Cosign, &es, "a", None);
        assert!(h.contains("  -gui\t\t\t (Realiza la operacion con entorno grafico. Tiene prioridad sobre -certgui)\n"));
    }

    #[test]
    fn ayuda_de_sistema() {
        let m = Messages::new(Language::EsEs);
        let h = system_help(SystemCommand::Install, &m, "autofirma", None);
        assert!(h.starts_with("Sintaxis: autofirma install (--system|--user)"));
        assert!(h.contains("--origins origins"));
        let h = system_help(SystemCommand::RestoreConfig, &m, "autofirma", None);
        assert_eq!(
            h,
            "Sintaxis: autofirma restore-config\n\n  (restaura los certificados locales y el manejador del protocolo afirma://)"
        );
    }
}
