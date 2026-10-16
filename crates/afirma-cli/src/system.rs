//! Comandos de integración con el sistema que usan los instaladores (nuevos
//! respecto a Java, donde había un configurador aparte):
//!
//! ```text
//! <app> install   (--system|--user) [--browser-policies] [--origins <lista>] [--dry-run]
//! <app> uninstall (--system|--user) [--dry-run]
//! <app> doctor    [--json]
//! <app> restore-config
//! ```
//!
//! Este crate solo analiza los argumentos y delega en [`SystemOps`], que
//! implementa la aplicación (con la característica `afirma-system`,
//! [`crate::system_adapter::AfirmaSystemOps`] lo hace con el crate
//! `afirma-system`). Las opciones admiten también la forma `--opcion=valor`.
//! Los errores de sintaxis imprimen el mensaje y la ayuda del comando con
//! estado -1.

use crate::help::{SystemCommand, Text, system_help, text};
use crate::messages::Messages;

/// Ámbito de instalación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Todo el equipo (`--system`; requiere privilegios).
    System,
    /// Solo el usuario actual (`--user`).
    User,
}

/// `install`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    /// Ámbito.
    pub scope: Scope,
    /// Configurar las directivas de los navegadores (`--browser-policies` o
    /// `--origins`).
    pub browser_policies: bool,
    /// Orígenes permitidos (`--origins a,b`), sin espacios ni vacíos.
    pub origins: Vec<String>,
    /// Solo mostrar las acciones (`--dry-run`).
    pub dry_run: bool,
    /// Opciones avanzadas de los instaladores (`--firefox-roots`,
    /// `--config-path=...`, `--default-language=...`, `--keystore-path=...`
    /// y `--certificate-path=...`, `--update-config`...), normalizadas como
    /// `--nombre` o `--nombre=valor`.
    pub advanced: Vec<String>,
}

/// `uninstall`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallRequest {
    /// Ámbito.
    pub scope: Scope,
    /// Solo mostrar las acciones (`--dry-run`).
    pub dry_run: bool,
    /// `--keep-certs`, `--keep-system-prefs`, `--revert-firefox-roots`.
    pub advanced: Vec<String>,
}

/// `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DoctorRequest {
    /// Respuesta en JSON (`--json`).
    pub json: bool,
}

/// `restore-config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestoreRequest;

/// Resultado de una operación de sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemOutcome {
    /// Estado de salida (0 correcto, -1 error; `doctor` puede devolver 1 si
    /// encuentra problemas).
    pub status: i32,
    /// Texto a imprimir (se añade un salto de línea final si no lo tiene).
    pub output: String,
}

/// Operaciones de integración con el sistema que conecta la aplicación.
pub trait SystemOps: Send + Sync {
    /// `install`.
    fn install(&self, request: &InstallRequest) -> SystemOutcome;
    /// `uninstall`.
    fn uninstall(&self, request: &UninstallRequest) -> SystemOutcome;
    /// `doctor`.
    fn doctor(&self, request: &DoctorRequest) -> SystemOutcome;
    /// `restore-config`.
    fn restore_config(&self, request: &RestoreRequest) -> SystemOutcome;
}

/// Petición analizada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemRequest {
    /// `install`.
    Install(InstallRequest),
    /// `uninstall`.
    Uninstall(UninstallRequest),
    /// `doctor`.
    Doctor(DoctorRequest),
    /// `restore-config`.
    RestoreConfig(RestoreRequest),
    /// `<comando> -help` / `--help`.
    Help,
}

/// Analiza los argumentos que siguen al comando. El error es el mensaje que
/// se imprime antes de la ayuda.
/// Opciones avanzadas sin valor de `install`.
const INSTALL_FLAGS: &[&str] = &[
    "--firefox-roots",
    "--no-firefox-roots",
    "--update-config",
    "--regenerate",
    "--no-menus",
    "--no-path",
    "--no-certs",
    "--no-nss",
    "--no-os-trust",
    "--no-protocol",
];
/// Opciones avanzadas con valor de `install`.
const INSTALL_VALUES: &[&str] = &[
    "--config-path",
    "--default-language",
    "--keystore-path",
    "--certificate-path",
    "--menus",
];
/// Opciones avanzadas de `uninstall`.
const UNINSTALL_FLAGS: &[&str] = &["--keep-certs", "--keep-system-prefs", "--revert-firefox-roots"];

pub fn parse(command: SystemCommand, args: &[String], m: &Messages) -> Result<SystemRequest, String> {
    if args
        .first()
        .is_some_and(|a| a.eq_ignore_ascii_case("-help") || a.eq_ignore_ascii_case("--help"))
    {
        return Ok(SystemRequest::Help);
    }
    let mut scope: Option<Scope> = None;
    let mut browser_policies = false;
    let mut origins: Option<Vec<String>> = None;
    let mut dry_run = false;
    let mut json = false;
    let mut advanced = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (arg, None),
        };
        let (flags, values): (&[&str], &[&str]) = match command {
            SystemCommand::Install => (INSTALL_FLAGS, INSTALL_VALUES),
            SystemCommand::Uninstall => (UNINSTALL_FLAGS, &[]),
            _ => (&[], &[]),
        };
        if flags.contains(&name) && inline.is_none() {
            advanced.push(name.to_string());
            i += 1;
            continue;
        }
        if values.contains(&name) {
            let value = match inline {
                Some(v) => v,
                None => {
                    i += 1;
                    args.get(i).cloned().ok_or_else(|| m.fmt(25, &[arg]))?
                }
            };
            advanced.push(format!("{name}={value}"));
            i += 1;
            continue;
        }
        let allowed: &[&str] = match command {
            SystemCommand::Install => &["--system", "--user", "--browser-policies", "--origins", "--dry-run"],
            SystemCommand::Uninstall => &["--system", "--user", "--dry-run"],
            SystemCommand::Doctor => &["--json"],
            SystemCommand::RestoreConfig => &[],
        };
        if !allowed.contains(&name) || (inline.is_some() && name != "--origins") {
            return Err(m.fmt(25, &[arg]));
        }
        match name {
            "--system" | "--user" => {
                let s = if name == "--system" { Scope::System } else { Scope::User };
                match scope {
                    Some(prev) if prev == s => return Err(m.fmt(26, &[name])),
                    Some(_) => return Err(text(m, Text::ScopeExclusive).to_string()),
                    None => scope = Some(s),
                }
            }
            "--browser-policies" => browser_policies = true,
            "--dry-run" => dry_run = true,
            "--json" => json = true,
            "--origins" => {
                if origins.is_some() {
                    return Err(m.fmt(26, &[name]));
                }
                let value = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| text(m, Text::MissingOrigins).to_string())?
                    }
                };
                origins = Some(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                );
            }
            _ => return Err(m.fmt(25, &[arg])),
        }
        i += 1;
    }
    let need_scope = || scope.ok_or_else(|| text(m, Text::ScopeRequired).to_string());
    Ok(match command {
        SystemCommand::Install => SystemRequest::Install(InstallRequest {
            scope: need_scope()?,
            browser_policies: browser_policies || origins.is_some(),
            origins: origins.unwrap_or_default(),
            dry_run,
            advanced,
        }),
        SystemCommand::Uninstall => SystemRequest::Uninstall(UninstallRequest {
            scope: need_scope()?,
            dry_run,
            advanced,
        }),
        SystemCommand::Doctor => SystemRequest::Doctor(DoctorRequest { json }),
        SystemCommand::RestoreConfig => SystemRequest::RestoreConfig(RestoreRequest),
    })
}

/// Ejecuta un comando de sistema y devuelve `(estado, salida)`.
pub fn run(
    command: SystemCommand,
    args: &[String],
    ops: Option<&dyn SystemOps>,
    m: &Messages,
    app: &str,
) -> (i32, String) {
    let request = match parse(command, args, m) {
        Ok(r) => r,
        Err(e) => return (crate::STATUS_ERROR, system_help(command, m, app, Some(&e))),
    };
    if request == SystemRequest::Help {
        return (crate::STATUS_SUCCESS, system_help(command, m, app, None));
    }
    let Some(ops) = ops else {
        return (crate::STATUS_ERROR, text(m, Text::NoSystemOps).to_string());
    };
    let outcome = match &request {
        SystemRequest::Install(r) => ops.install(r),
        SystemRequest::Uninstall(r) => ops.uninstall(r),
        SystemRequest::Doctor(r) => ops.doctor(r),
        SystemRequest::RestoreConfig(r) => ops.restore_config(r),
        SystemRequest::Help => return (crate::STATUS_SUCCESS, system_help(command, m, app, None)),
    };
    (
        outcome.status,
        outcome.output.strip_suffix('\n').unwrap_or(&outcome.output).to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Language;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn p(c: SystemCommand, v: &[&str]) -> Result<SystemRequest, String> {
        parse(c, &s(v), &Messages::new(Language::EsEs))
    }

    #[test]
    fn install() {
        assert_eq!(
            p(
                SystemCommand::Install,
                &["--system", "--origins", "https://a.es, https://*.b.es,", "--dry-run"]
            ),
            Ok(SystemRequest::Install(InstallRequest {
                scope: Scope::System,
                browser_policies: true,
                origins: vec!["https://a.es".into(), "https://*.b.es".into()],
                dry_run: true,
                advanced: vec![]
            }))
        );
        assert_eq!(
            p(
                SystemCommand::Install,
                &["--user", "--browser-policies", "--origins=https://x.es"]
            ),
            Ok(SystemRequest::Install(InstallRequest {
                scope: Scope::User,
                browser_policies: true,
                origins: vec!["https://x.es".into()],
                dry_run: false,
                advanced: vec![]
            }))
        );
        assert_eq!(
            p(SystemCommand::Install, &[]),
            Err("Se tiene que indicar una de las opciones '--system' o '--user'".into())
        );
        assert_eq!(
            p(SystemCommand::Install, &["--system", "--user"]),
            Err("Las opciones '--system' y '--user' son excluyentes".into())
        );
        assert_eq!(
            p(SystemCommand::Install, &["--user", "--user"]),
            Err("Parametro duplicado: --user".into())
        );
        assert_eq!(
            p(SystemCommand::Install, &["--user", "--sytem"]),
            Err("No se reconoce el parametro --sytem".into())
        );
        assert_eq!(
            p(SystemCommand::Install, &["--user", "--origins"]),
            Err("No se ha indicado la lista de origenes".into())
        );
        assert_eq!(
            p(SystemCommand::Install, &["--user", "--dry-run=1"]),
            Err("No se reconoce el parametro --dry-run=1".into())
        );
        assert_eq!(p(SystemCommand::Install, &["-help"]), Ok(SystemRequest::Help));
    }

    #[test]
    fn opciones_de_los_instaladores() {
        assert_eq!(
            p(
                SystemCommand::Install,
                &[
                    "--system",
                    "--firefox-roots",
                    "--config-path",
                    r"https:\\intra\c.afconfig",
                    "--default-language=ca_ES"
                ]
            ),
            Ok(SystemRequest::Install(InstallRequest {
                scope: Scope::System,
                browser_policies: false,
                origins: vec![],
                dry_run: false,
                advanced: vec![
                    "--firefox-roots".into(),
                    r"--config-path=https:\\intra\c.afconfig".into(),
                    "--default-language=ca_ES".into()
                ]
            }))
        );
        assert!(p(SystemCommand::Install, &["--user", "--firefox-roots=1"]).is_err());
        assert!(p(SystemCommand::Uninstall, &["--user", "--firefox-roots"]).is_err());
    }

    #[test]
    fn otros() {
        assert_eq!(
            p(SystemCommand::Uninstall, &["--user", "--dry-run"]),
            Ok(SystemRequest::Uninstall(UninstallRequest {
                scope: Scope::User,
                dry_run: true,
                advanced: vec![]
            }))
        );
        assert_eq!(
            p(SystemCommand::Uninstall, &["--user", "--origins", "x"]),
            Err("No se reconoce el parametro --origins".into())
        );
        assert_eq!(
            p(SystemCommand::Doctor, &["--json"]),
            Ok(SystemRequest::Doctor(DoctorRequest { json: true }))
        );
        assert_eq!(
            p(SystemCommand::Doctor, &[]),
            Ok(SystemRequest::Doctor(DoctorRequest { json: false }))
        );
        assert_eq!(
            p(SystemCommand::RestoreConfig, &[]),
            Ok(SystemRequest::RestoreConfig(RestoreRequest))
        );
        assert_eq!(
            p(SystemCommand::RestoreConfig, &["--user"]),
            Err("No se reconoce el parametro --user".into())
        );
    }
}
