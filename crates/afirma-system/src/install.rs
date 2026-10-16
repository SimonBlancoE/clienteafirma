//! Orquestación de la instalación y desinstalación (equivalente al configurador
//! `AutofirmaConfigurator` y a los pasos de los instaladores), con planificación previa y
//! modo simulación: [`plan_install`] / [`plan_uninstall`] devuelven la lista de acciones
//! (para mostrarlas en la interfaz o en `--dry-run`) y [`execute`] las ejecuta.
//!
//! Con privilegios se configura todo el equipo (almacén `LocalMachine\ROOT`, llavero del
//! sistema, anclas de Linux, perfiles de todos los usuarios, registro en HKLM, directivas de
//! navegadores) sin ningún aviso. Sin privilegios, solo el usuario actual.

use std::path::PathBuf;

use crate::browser_policy::{self, BrowserPolicyOptions};
use crate::certs::{self, AdminCerts, CertProfile, LocalCerts, Regenerate};
use crate::ctx::{Context, Os};
use crate::error::{Result, SystemError};
use crate::firefox;
use crate::prefs;
use crate::protocol::{self, ContextMenus, ProtocolOptions};
use crate::trust::nss::{self, NssDb};
use crate::trust::{self, Change, TrustScope};

/// Ámbito de la instalación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    /// Equipo si hay privilegios; usuario si no.
    #[default]
    Auto,
    /// Todo el equipo (requiere privilegios).
    Machine,
    /// Solo el usuario actual.
    User,
}

/// Valor de tres estados para `security.enterprise_roots.enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Tristate {
    /// No tocar (por defecto; Java escribía `false` en la restauración).
    #[default]
    Leave,
    Enable,
    Disable,
}

/// Opciones de instalación (las del configurador Java y las nuevas).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstallOptions {
    pub scope: Scope,
    /// Generar/reutilizar los certificados locales.
    pub certificates: bool,
    /// Política de regeneración.
    pub regenerate: Regenerate,
    /// Certificados del administrador (`-keystore_path`, `-certificate_path`).
    pub admin_certs: Option<AdminCerts>,
    /// Directorio de los certificados (por defecto [`certs::target_dir`]).
    pub cert_dir: Option<PathBuf>,
    /// Instalar la CA en el almacén del sistema.
    pub os_trust: bool,
    /// Instalar la CA en las bases NSS (Firefox y Chrome/Chromium en Linux).
    pub nss: bool,
    /// Perfiles de todos los usuarios (solo con privilegios).
    pub all_users: bool,
    /// `-firefox_roots`.
    pub firefox_enterprise_roots: Tristate,
    /// Registro del protocolo y menús.
    pub protocol: bool,
    /// Menús contextuales.
    pub menus: ContextMenus,
    /// Linux: preferencias `autofirma.js` de Firefox para el protocolo (paquete `.deb`).
    pub firefox_protocol_prefs: bool,
    /// Directivas de navegadores (nuevo; desactivado por defecto).
    pub browser_policies: Option<BrowserPolicyOptions>,
    /// `-config_path`.
    pub config_path: Option<String>,
    /// `-update_config`.
    pub update_config: bool,
    /// `-default_language`.
    pub default_language: Option<String>,
    /// Windows: añadir el directorio de la aplicación al `PATH` (como el configurador Java).
    pub add_to_path: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            scope: Scope::Auto,
            certificates: true,
            regenerate: Regenerate::IfInvalid,
            admin_certs: None,
            cert_dir: None,
            os_trust: true,
            nss: true,
            all_users: true,
            firefox_enterprise_roots: Tristate::Leave,
            protocol: true,
            menus: ContextMenus::default(),
            firefox_protocol_prefs: true,
            browser_policies: None,
            config_path: None,
            update_config: false,
            default_language: None,
            add_to_path: true,
        }
    }
}

/// Opciones de desinstalación.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UninstallOptions {
    pub scope: Scope,
    pub all_users: bool,
    /// Borrar también los ficheros de certificados.
    pub remove_certificates: bool,
    /// Borrar las preferencias de sistema (`removeSystemPrefs`).
    pub remove_system_prefs: bool,
    /// Quitar `security.enterprise_roots.enabled` de los `user.js` (Java no lo hacía).
    pub revert_firefox_enterprise_roots: bool,
}

impl Default for UninstallOptions {
    fn default() -> Self {
        Self {
            scope: Scope::Auto,
            all_users: true,
            remove_certificates: true,
            remove_system_prefs: true,
            revert_firefox_enterprise_roots: false,
        }
    }
}

/// Acción planificada.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ActionKind {
    SetDefaultLanguage {
        locale: String,
    },
    EnsureCertificates {
        dir: PathBuf,
        regenerate: Regenerate,
        admin: Option<AdminCerts>,
    },
    TrustWindowsRoot {
        scope: TrustScope,
    },
    TrustMacKeychain {
        scope: TrustScope,
    },
    TrustLinuxAnchors,
    TrustNss {
        db: NssDb,
    },
    FirefoxEnterpriseRoots {
        profile: PathBuf,
        enable: bool,
    },
    FirefoxEnterpriseRootsPolicy,
    RegisterProtocol {
        opts: ProtocolOptions,
    },
    FirefoxProtocolPrefs,
    BrowserPolicies {
        opts: BrowserPolicyOptions,
    },
    ImportSystemConfig {
        path: String,
        allow_updates: bool,
    },
    RemoveBrowserPolicies,
    UnregisterProtocol {
        opts: ProtocolOptions,
    },
    RemoveFirefoxProtocolPrefs,
    UntrustNss {
        db: NssDb,
    },
    RemoveFirefoxEnterpriseRoots {
        profile: PathBuf,
    },
    UntrustWindowsRoot {
        scope: TrustScope,
    },
    UntrustMacKeychain {
        scope: TrustScope,
    },
    UntrustLinuxAnchors,
    RemoveCertificates {
        dir: PathBuf,
    },
    RemoveSystemPrefs,
    AddToPath {
        scope: TrustScope,
        dir: PathBuf,
    },
    RemoveFromPath {
        scope: TrustScope,
        dir: PathBuf,
    },
}

/// Acción con su descripción.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Action {
    pub kind: ActionKind,
    /// Descripción en castellano para la interfaz.
    pub description: String,
    /// Requiere privilegios de administrador.
    pub requires_elevation: bool,
}

/// Plan de acciones.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Plan {
    pub actions: Vec<Action>,
    /// Avisos de la planificación (p. ej. sin mecanismo NSS).
    pub notes: Vec<String>,
}

/// Resultado de una acción.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Status {
    /// Realizada (con o sin cambios).
    Done(Change),
    /// Simulación: se haría.
    Planned,
    /// Omitida (motivo).
    Skipped(String),
    /// Fallida (error).
    Failed(String),
}

/// Resultado de una acción.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Outcome {
    pub description: String,
    pub status: Status,
}

/// Informe de ejecución.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Report {
    pub dry_run: bool,
    pub outcomes: Vec<Outcome>,
    pub notes: Vec<String>,
}

impl Report {
    /// `true` si ninguna acción falló.
    pub fn ok(&self) -> bool {
        !self
            .outcomes
            .iter()
            .any(|o| matches!(o.status, Status::Failed(_)))
    }

    /// Código de salida del configurador (0 / −1 como Java).
    pub fn exit_code(&self) -> i32 {
        if self.ok() { 0 } else { -1 }
    }

    /// Texto legible.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for o in &self.outcomes {
            let st = match &o.status {
                Status::Done(Change::Changed) => "HECHO".to_string(),
                Status::Done(Change::Unchanged) => "SIN CAMBIOS".to_string(),
                Status::Planned => "SE HARÍA".to_string(),
                Status::Skipped(r) => format!("OMITIDO: {r}"),
                Status::Failed(e) => format!("ERROR: {e}"),
            };
            s.push_str(&format!("[{st}] {}\n", o.description));
        }
        for n in &self.notes {
            s.push_str(&format!("NOTA: {n}\n"));
        }
        s
    }
}

fn effective_scope(ctx: &Context, s: Scope) -> TrustScope {
    match s {
        Scope::Machine => TrustScope::Machine,
        Scope::User => TrustScope::User,
        Scope::Auto => {
            if ctx.elevated {
                TrustScope::Machine
            } else {
                TrustScope::User
            }
        }
    }
}

fn action(kind: ActionKind, description: impl Into<String>, requires_elevation: bool) -> Action {
    Action {
        kind,
        description: description.into(),
        requires_elevation,
    }
}

/// Planifica la instalación.
pub fn plan_install(ctx: &Context, opts: &InstallOptions) -> Plan {
    let scope = effective_scope(ctx, opts.scope);
    let machine = scope == TrustScope::Machine;
    let mut plan = Plan::default();
    let a = &mut plan.actions;
    if let Some(l) = &opts.default_language {
        a.push(action(
            ActionKind::SetDefaultLanguage { locale: l.clone() },
            format!("Establecer el idioma por defecto del sistema: {l}"),
            false,
        ));
    }
    let dir = opts
        .cert_dir
        .clone()
        .unwrap_or_else(|| certs::target_dir(ctx));
    if opts.certificates {
        let what = if opts.admin_certs.is_some() {
            "Copiar los certificados SSL del administrador"
        } else {
            "Generar o reutilizar los certificados SSL de la comunicación con el navegador"
        };
        a.push(action(
            ActionKind::EnsureCertificates {
                dir: dir.clone(),
                regenerate: opts.regenerate,
                admin: opts.admin_certs.clone(),
            },
            format!("{what} en {}", dir.display()),
            false,
        ));
    }
    if opts.os_trust {
        match ctx.os {
            Os::Windows => a.push(action(
                ActionKind::TrustWindowsRoot { scope },
                if machine {
                    "Instalar la CA «Autofirma ROOT» en el almacén de confianza del equipo (LocalMachine\\ROOT)".to_string()
                } else {
                    "Instalar la CA «Autofirma ROOT» en el almacén de confianza del usuario (CurrentUser\\ROOT; Windows pedirá confirmación)".to_string()
                },
                machine,
            )),
            Os::MacOs => a.push(action(
                ActionKind::TrustMacKeychain { scope },
                if machine { "Instalar la CA y el certificado SSL como de confianza en el llavero del sistema" } else { "Instalar la CA como de confianza en el llavero de sesión (macOS pedirá la contraseña)" },
                machine,
            )),
            Os::Linux => {
                if machine {
                    a.push(action(ActionKind::TrustLinuxAnchors, "Instalar la CA en las anclas de confianza del sistema", true));
                }
            }
        }
    }
    let users = ctx.user_homes(opts.all_users && machine);
    if opts.nss {
        let dbs = nss::discover(ctx, &users, true, true);
        if !dbs.is_empty() && nss::backend(ctx).is_none() {
            plan.notes.push("No se encontró certutil ni el módulo softokn3 de NSS: no se podrá instalar la CA en Firefox/Chrome (NSS).".into());
        }
        for db in dbs {
            let d = format!("Instalar la CA en el almacén NSS: {}", db.description);
            a.push(action(ActionKind::TrustNss { db }, d, false));
        }
    }
    if opts.firefox_enterprise_roots == Tristate::Enable && machine && ctx.os != Os::Linux {
        a.push(action(
            ActionKind::FirefoxEnterpriseRootsPolicy,
            "Activar la directiva de Firefox Certificates.ImportEnterpriseRoots (confiar en las raíces del sistema)",
            true,
        ));
    }
    if opts.firefox_enterprise_roots != Tristate::Leave {
        let enable = opts.firefox_enterprise_roots == Tristate::Enable;
        for p in firefox::discover_profiles(ctx, &users) {
            let d = format!(
                "Escribir security.enterprise_roots.enabled={enable} en user.js del perfil {}",
                p.dir.display()
            );
            a.push(action(
                ActionKind::FirefoxEnterpriseRoots {
                    profile: p.dir,
                    enable,
                },
                d,
                false,
            ));
        }
    }
    if opts.protocol {
        let popts = ProtocolOptions {
            scope,
            menus: opts.menus,
            locale: opts
                .default_language
                .clone()
                .unwrap_or_else(|| "es_ES".into()),
            ..Default::default()
        };
        let d = match ctx.os {
            Os::Windows => format!(
                "Registrar el protocolo afirma:// y los menús contextuales en {}\\Software\\Classes",
                if machine { "HKLM" } else { "HKCU" }
            ),
            Os::Linux => {
                "Registrar el protocolo afirma:// (fichero .desktop y mimeapps.list)".to_string()
            }
            Os::MacOs => "Registrar la aplicación en LaunchServices para afirma://".to_string(),
        };
        a.push(action(
            ActionKind::RegisterProtocol { opts: popts },
            d,
            machine && ctx.os != Os::MacOs,
        ));
        if ctx.os == Os::Linux && machine && opts.firefox_protocol_prefs {
            a.push(action(
                ActionKind::FirefoxProtocolPrefs,
                "Escribir las preferencias de Firefox del protocolo (autofirma.js)",
                true,
            ));
        }
    }
    if ctx.os == Os::Windows && opts.add_to_path {
        a.push(action(
            ActionKind::AddToPath {
                scope,
                dir: ctx.app.app_dir.clone(),
            },
            format!(
                "Añadir {} al PATH {}",
                ctx.app.app_dir.display(),
                if machine {
                    "del sistema"
                } else {
                    "del usuario"
                }
            ),
            machine,
        ));
    }
    if let Some(bp) = &opts.browser_policies {
        a.push(action(
            ActionKind::BrowserPolicies { opts: bp.clone() },
            "Configurar las directivas de los navegadores para abrir afirma:// sin avisos",
            true,
        ));
    }
    if let Some(p) = &opts.config_path {
        a.push(action(
            ActionKind::ImportSystemConfig {
                path: p.clone(),
                allow_updates: opts.update_config,
            },
            format!(
                "Importar la configuración del sistema desde {p}{}",
                if opts.update_config {
                    " (con actualización diaria)"
                } else {
                    ""
                }
            ),
            false,
        ));
    }
    plan
}

/// Planifica la desinstalación.
pub fn plan_uninstall(ctx: &Context, opts: &UninstallOptions) -> Plan {
    let scope = effective_scope(ctx, opts.scope);
    let machine = scope == TrustScope::Machine;
    let mut plan = Plan::default();
    let a = &mut plan.actions;
    if machine {
        a.push(action(
            ActionKind::RemoveBrowserPolicies,
            "Retirar las directivas de navegadores de AutoFirma",
            true,
        ));
    }
    let mut scopes = vec![TrustScope::User];
    if machine {
        scopes.insert(0, TrustScope::Machine);
    }
    for s in &scopes {
        let popts = ProtocolOptions {
            scope: *s,
            menus: ContextMenus {
                sign: true,
                verify: true,
                hash: true,
            },
            ..Default::default()
        };
        if ctx.os != Os::MacOs {
            a.push(action(
                ActionKind::UnregisterProtocol { opts: popts },
                format!("Eliminar el registro del protocolo afirma:// y los menús ({s:?})"),
                *s == TrustScope::Machine,
            ));
        }
    }
    if ctx.os == Os::Linux && machine {
        a.push(action(
            ActionKind::RemoveFirefoxProtocolPrefs,
            "Eliminar autofirma.js de las preferencias de Firefox",
            true,
        ));
    }
    let users = ctx.user_homes(opts.all_users && machine);
    for db in nss::discover(ctx, &users, true, true) {
        let d = format!("Retirar la CA del almacén NSS: {}", db.description);
        a.push(action(ActionKind::UntrustNss { db }, d, false));
    }
    if opts.revert_firefox_enterprise_roots {
        for p in firefox::discover_profiles(ctx, &users) {
            let d = format!(
                "Quitar security.enterprise_roots.enabled de {}",
                p.dir.display()
            );
            a.push(action(
                ActionKind::RemoveFirefoxEnterpriseRoots { profile: p.dir },
                d,
                false,
            ));
        }
    }
    match ctx.os {
        Os::Windows => {
            for s in &scopes {
                a.push(action(
                    ActionKind::UntrustWindowsRoot { scope: *s },
                    format!("Retirar la CA de AutoFirma del almacén ROOT ({s:?})"),
                    *s == TrustScope::Machine,
                ));
            }
        }
        Os::MacOs => {
            for s in &scopes {
                a.push(action(
                    ActionKind::UntrustMacKeychain { scope: *s },
                    format!("Retirar los certificados de AutoFirma del llavero ({s:?})"),
                    *s == TrustScope::Machine,
                ));
            }
        }
        Os::Linux => {
            if machine {
                a.push(action(
                    ActionKind::UntrustLinuxAnchors,
                    "Retirar la CA de las anclas de confianza del sistema",
                    true,
                ));
            }
        }
    }
    if ctx.os == Os::Windows {
        for s in &scopes {
            a.push(action(
                ActionKind::RemoveFromPath {
                    scope: *s,
                    dir: ctx.app.app_dir.clone(),
                },
                format!("Quitar {} del PATH ({s:?})", ctx.app.app_dir.display()),
                *s == TrustScope::Machine,
            ));
        }
    }
    if opts.remove_certificates {
        let mut dirs = certs::search_dirs(ctx);
        if !machine {
            dirs.retain(|d| crate::fsutil::dir_is_writable(d));
        }
        for d in dirs {
            if d.join(certs::KS_FILENAME).exists() || d.join(certs::CA_CERT_FILENAME).exists() {
                let desc = format!("Borrar los certificados SSL de {}", d.display());
                a.push(action(
                    ActionKind::RemoveCertificates { dir: d },
                    desc,
                    false,
                ));
            }
        }
    }
    if opts.remove_system_prefs && machine {
        a.push(action(
            ActionKind::RemoveSystemPrefs,
            "Borrar las preferencias de sistema de AutoFirma",
            true,
        ));
    }
    plan
}

/// Estado compartido durante la ejecución.
#[derive(Default)]
struct ExecState {
    certs: Option<LocalCerts>,
}

fn need_certs(ctx: &Context, st: &mut ExecState) -> Result<LocalCerts> {
    if let Some(c) = &st.certs {
        return Ok(c.clone());
    }
    let c = certs::locate(ctx).ok_or_else(|| {
        SystemError::Certificate(
            "no hay certificados locales (genere primero los certificados)".into(),
        )
    })?;
    st.certs = Some(c.clone());
    Ok(c)
}

fn run_action(ctx: &Context, a: &Action, st: &mut ExecState) -> Result<Change> {
    match &a.kind {
        ActionKind::SetDefaultLanguage { locale } => {
            let mut w = prefs::system::SystemPrefsWriter::open(ctx)?;
            w.put(prefs::keys::LOCALE.name(), locale);
            w.flush()?;
            Ok(Change::Changed)
        }
        ActionKind::EnsureCertificates {
            dir,
            regenerate,
            admin,
        } => {
            let out = certs::ensure(
                ctx,
                dir,
                *regenerate,
                admin.as_ref(),
                &CertProfile::default(),
            )?;
            let ch = if out.generated || out.copied_admin {
                Change::Changed
            } else {
                Change::Unchanged
            };
            st.certs = Some(out.certs);
            Ok(ch)
        }
        ActionKind::TrustWindowsRoot { scope } => {
            let c = need_certs(ctx, st)?;
            // Sin privilegios: si la CA ya está en el almacén del equipo no se toca el del
            // usuario (evita el diálogo de Windows).
            if *scope == TrustScope::User
                && trust::windows::check(ctx.win_certs.as_ref(), TrustScope::Machine, &c.ca_der)
                    .ok()
            {
                return Ok(Change::Unchanged);
            }
            trust::windows::install(ctx.win_certs.as_ref(), *scope, &c.ca_der)
        }
        ActionKind::TrustMacKeychain { scope } => {
            let c = need_certs(ctx, st)?;
            trust::macos::install(ctx, *scope, &c)
        }
        ActionKind::TrustLinuxAnchors => {
            let c = need_certs(ctx, st)?;
            trust::linux::install(ctx, &c.ca_der)
        }
        ActionKind::TrustNss { db } => {
            let c = need_certs(ctx, st)?;
            let b = nss::backend(ctx).ok_or_else(|| {
                SystemError::Unsupported("no hay certutil ni softokn3 de NSS".into())
            })?;
            nss::install(ctx, db, &b, &c.ca_der, &c.ca_path())
        }
        ActionKind::FirefoxEnterpriseRoots { profile, enable } => {
            Ok(if firefox::set_enterprise_roots(profile, *enable)? {
                Change::Changed
            } else {
                Change::Unchanged
            })
        }
        ActionKind::FirefoxEnterpriseRootsPolicy => {
            browser_policy::install_firefox_enterprise_roots(ctx)
        }
        ActionKind::RegisterProtocol { opts } => protocol::register(ctx, opts),
        ActionKind::FirefoxProtocolPrefs => protocol::install_firefox_protocol_prefs(ctx),
        ActionKind::BrowserPolicies { opts } => browser_policy::install(ctx, opts),
        ActionKind::ImportSystemConfig {
            path,
            allow_updates,
        } => {
            prefs::remote::install_system_config(
                ctx,
                path,
                *allow_updates,
                &prefs::remote::HttpsFetcher::default(),
                None,
            )?;
            Ok(Change::Changed)
        }
        ActionKind::RemoveBrowserPolicies => browser_policy::remove(ctx),
        ActionKind::UnregisterProtocol { opts } => protocol::unregister(ctx, opts),
        ActionKind::RemoveFirefoxProtocolPrefs => protocol::remove_firefox_protocol_prefs(ctx),
        ActionKind::UntrustNss { db } => {
            let b = nss::backend(ctx).ok_or_else(|| {
                SystemError::Unsupported("no hay certutil ni softokn3 de NSS".into())
            })?;
            nss::remove(ctx, db, &b)
        }
        ActionKind::RemoveFirefoxEnterpriseRoots { profile } => {
            Ok(if firefox::remove_enterprise_roots(profile)? {
                Change::Changed
            } else {
                Change::Unchanged
            })
        }
        ActionKind::UntrustWindowsRoot { scope } => {
            trust::windows::remove(ctx.win_certs.as_ref(), *scope)
        }
        ActionKind::UntrustMacKeychain { scope } => trust::macos::remove(ctx, *scope),
        ActionKind::UntrustLinuxAnchors => trust::linux::remove(ctx),
        ActionKind::RemoveCertificates { dir } => {
            let mut ch = false;
            for f in [
                certs::KS_FILENAME,
                certs::CA_CERT_FILENAME,
                certs::SSL_CERT_FILENAME,
            ] {
                ch |= crate::fsutil::remove_file_if_exists(&dir.join(f))?;
            }
            Ok(if ch {
                Change::Changed
            } else {
                Change::Unchanged
            })
        }
        ActionKind::AddToPath { scope, dir } => crate::winpath::add(ctx, *scope, dir),
        ActionKind::RemoveFromPath { scope, dir } => crate::winpath::remove(ctx, *scope, dir),
        ActionKind::RemoveSystemPrefs => {
            let mut ch = prefs::system::SystemPrefsWriter::remove_all(ctx)?;
            ch |= crate::fsutil::remove_file_if_exists(&crate::state::state_path(ctx))?;
            Ok(if ch {
                Change::Changed
            } else {
                Change::Unchanged
            })
        }
    }
}

/// Ejecuta (o simula) un plan. Las acciones son independientes: un fallo no detiene las
/// siguientes (salvo las que dependen de los certificados).
pub fn execute(ctx: &Context, plan: &Plan, dry_run: bool) -> Report {
    let mut rep = Report {
        dry_run,
        notes: plan.notes.clone(),
        ..Default::default()
    };
    let mut st = ExecState::default();
    for a in &plan.actions {
        let status = if a.requires_elevation && !ctx.elevated {
            Status::Skipped("requiere privilegios de administrador".into())
        } else if dry_run {
            Status::Planned
        } else {
            match run_action(ctx, a, &mut st) {
                Ok(c) => Status::Done(c),
                Err(SystemError::NotElevated(e)) => {
                    Status::Skipped(format!("requiere privilegios de administrador ({e})"))
                }
                Err(e) => Status::Failed(e.to_string()),
            }
        };
        tracing::info!("{}: {:?}", a.description, status);
        rep.outcomes.push(Outcome {
            description: a.description.clone(),
            status,
        });
    }
    rep
}

/// Instala (o simula la instalación).
pub fn install(ctx: &Context, opts: &InstallOptions, dry_run: bool) -> Report {
    execute(ctx, &plan_install(ctx, opts), dry_run)
}

/// Desinstala (o simula la desinstalación).
pub fn uninstall(ctx: &Context, opts: &UninstallOptions, dry_run: bool) -> Report {
    execute(ctx, &plan_uninstall(ctx, opts), dry_run)
}

/// Interpreta los argumentos del configurador Java (§9.1.1, sin distinguir mayúsculas; las
/// opciones desconocidas como `/passive` se ignoran). Devuelve `(desinstalar, opciones)`.
pub fn parse_configurator_args<I: IntoIterator<Item = String>>(
    args: I,
) -> (bool, InstallOptions, UninstallOptions) {
    let mut io = InstallOptions::default();
    let uo = UninstallOptions::default();
    let mut uninstall = false;
    let mut ks: Option<PathBuf> = None;
    let mut cert: Option<PathBuf> = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.to_ascii_lowercase().as_str() {
            "-install" => uninstall = false,
            "-uninstall" => uninstall = true,
            "-firefox_roots" => io.firefox_enterprise_roots = Tristate::Enable,
            "-certificate_path" => cert = it.next().map(PathBuf::from),
            "-keystore_path" => ks = it.next().map(PathBuf::from),
            "-config_path" => io.config_path = it.next(),
            "-update_config" => io.update_config = true,
            "-default_language" => io.default_language = it.next(),
            "-language_path" => {
                let _ = it.next();
            }
            _ => {}
        }
    }
    // Java solo usa los certificados del administrador si se dan los dos.
    if let (Some(pfx), Some(ca_cert)) = (ks, cert) {
        io.admin_certs = Some(AdminCerts { pfx, ca_cert });
    }
    (uninstall, io, uo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::FakeRunner;
    use std::sync::Arc;

    #[test]
    fn instalacion_windows_completa_y_simulada() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Windows, t.path());
        ctx.elevated = true;
        std::fs::create_dir_all(&ctx.app.app_dir).unwrap();
        let opts = InstallOptions {
            browser_policies: Some(Default::default()),
            default_language: Some("ca_ES".into()),
            ..Default::default()
        };
        let dry = install(&ctx, &opts, true);
        assert!(
            dry.outcomes.iter().all(|o| o.status == Status::Planned),
            "{}",
            dry.to_text()
        );
        assert!(
            !ctx.app.app_dir.join(certs::KS_FILENAME).exists(),
            "la simulación no escribe"
        );
        let rep = install(&ctx, &opts, false);
        assert!(rep.ok(), "{}", rep.to_text());
        assert!(ctx.app.app_dir.join(certs::KS_FILENAME).exists());
        let c = certs::locate(&ctx).unwrap();
        assert!(trust::windows::check(ctx.win_certs.as_ref(), TrustScope::Machine, &c.ca_der).ok());
        assert!(protocol::status(&ctx).points_to_current);
        assert_eq!(
            prefs::Preferences::load(&ctx, prefs::ResolutionMode::Strict)
                .unwrap()
                .get("default.locale")
                .as_deref(),
            Some("ca_ES")
        );
        let again = install(&ctx, &opts, false);
        assert!(
            again
                .outcomes
                .iter()
                .filter(|o| !o.description.contains("idioma"))
                .all(|o| o.status == Status::Done(Change::Unchanged)),
            "{}",
            again.to_text()
        );
        let un = uninstall(&ctx, &UninstallOptions::default(), false);
        assert!(un.ok(), "{}", un.to_text());
        assert!(!protocol::status(&ctx).registered);
        assert_eq!(
            trust::windows::check(ctx.win_certs.as_ref(), TrustScope::Machine, &c.ca_der),
            trust::TrustCheck::Missing
        );
        assert!(!ctx.app.app_dir.join(certs::KS_FILENAME).exists());
    }

    #[test]
    fn sin_privilegios_omite_lo_del_equipo() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Linux, t.path());
        ctx.runner = Arc::new(FakeRunner::default());
        let opts = InstallOptions {
            scope: Scope::Machine,
            browser_policies: Some(Default::default()),
            ..Default::default()
        };
        let rep = install(&ctx, &opts, false);
        assert!(
            rep.outcomes
                .iter()
                .any(|o| matches!(&o.status, Status::Skipped(r) if r.contains("privilegios"))),
            "{}",
            rep.to_text()
        );
        let rep = install(&ctx, &InstallOptions::default(), false);
        assert!(rep.ok(), "{}", rep.to_text());
        assert!(
            ctx.paths
                .home
                .join(".local/share/applications/autofirma.desktop")
                .is_file()
        );
    }

    #[test]
    fn argumentos_del_configurador() {
        let (u, io, _) = parse_configurator_args(
            [
                "-INSTALL",
                "-firefox_roots",
                "-config_path",
                r"https:\\intra\c.afconfig",
                "-update_config",
                "-default_language",
                "en_US",
                "/passive",
                "-keystore_path",
                "a.pfx",
            ]
            .map(String::from),
        );
        assert!(!u);
        assert_eq!(io.firefox_enterprise_roots, Tristate::Enable);
        assert_eq!(io.config_path.as_deref(), Some(r"https:\\intra\c.afconfig"));
        assert!(io.update_config && io.admin_certs.is_none());
        assert_eq!(io.default_language.as_deref(), Some("en_US"));
        assert!(parse_configurator_args(["-uninstall".to_string()]).0);
    }
}
