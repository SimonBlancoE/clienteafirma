//! «Restaurar instalación» (`RestoreConfigManager`, §10): repara la integración con los
//! navegadores para el usuario actual (o para todos con privilegios), con los mensajes de
//! consola de Java (`INFO:`/`ADVERTENCIA:`/`ERROR:`) y corrigiendo sus fallos documentados:
//!
//! * El certificado regenerado incluye `DNS:localhost` (Java solo `IP:127.0.0.1`) y se
//!   regenera si está caducado, a punto de caducar o la cadena no cuadra.
//! * `security.enterprise_roots.enabled` no se toca por defecto ([`Tristate::Leave`]); Java
//!   escribía `false` si la casilla estaba desmarcada.
//! * Linux: el paso del protocolo funciona (Java fallaba siempre por un recurso ausente),
//!   registra el `.desktop`/`mimeapps.list` del usuario y, con privilegios, las anclas del
//!   sistema y las preferencias de Firefox; la detección de root funciona.
//! * Windows: el protocolo se registra en `HKCU` sin elevación (o `HKLM` con privilegios), con
//!   rutas entrecomilladas; si la CA ya está en `LocalMachine\ROOT` no se toca el almacén del
//!   usuario (evita el diálogo de Windows).
//! * Se instala en **todos** los perfiles de Firefox (no uno por usuario), incluidos snap,
//!   flatpak, XDG y perfiles con ruta absoluta, sin necesidad de cerrar Firefox (bases SQL).
//! * macOS: no se pide la contraseña en el proceso ni se usa `sudo -S`.

use crate::certs::{self, CertProfile, Regenerate};
use crate::ctx::{Context, Os};
use crate::firefox;
use crate::install::Tristate;
use crate::protocol::{self, ProtocolOptions};
use crate::trust::nss::{self, NssPurpose};
use crate::trust::{self, Change, TrustCheck, TrustScope};

/// Nivel de un mensaje.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Level {
    Info,
    Warning,
    Error,
}

/// Línea de la consola de restauración.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LogLine {
    pub level: Level,
    pub message: String,
}

impl LogLine {
    /// Texto con el prefijo de Java.
    pub fn text(&self) -> String {
        let p = match self.level {
            Level::Info => "INFO",
            Level::Warning => "ADVERTENCIA",
            Level::Error => "ERROR",
        };
        format!("{p}: {}", self.message)
    }
}

/// Opciones de la restauración.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreOptions {
    /// Casilla «Configurar Firefox para que confíe en los certificados raíz del sistema»
    /// (Windows y macOS). Por defecto no se modifica.
    pub firefox_enterprise_roots: Tristate,
    /// Con privilegios, todos los usuarios.
    pub all_users: bool,
    /// Política de regeneración de certificados.
    pub regenerate: Regenerate,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            firefox_enterprise_roots: Tristate::Leave,
            all_users: true,
            regenerate: Regenerate::IfInvalid,
        }
    }
}

/// Resultado de la restauración.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RestoreReport {
    pub lines: Vec<LogLine>,
}

impl RestoreReport {
    /// `true` si no hubo errores.
    pub fn ok(&self) -> bool {
        !self.lines.iter().any(|l| l.level == Level::Error)
    }

    /// Texto de la consola.
    pub fn to_text(&self) -> String {
        self.lines.iter().map(|l| l.text() + "\n").collect()
    }
}

struct Console<'a> {
    rep: RestoreReport,
    sink: &'a mut dyn FnMut(&LogLine),
}

impl Console<'_> {
    fn log(&mut self, level: Level, msg: impl Into<String>) {
        let l = LogLine {
            level,
            message: msg.into(),
        };
        (self.sink)(&l);
        self.rep.lines.push(l);
    }
    fn info(&mut self, m: impl Into<String>) {
        self.log(Level::Info, m)
    }
    fn warn(&mut self, m: impl Into<String>) {
        self.log(Level::Warning, m)
    }
    fn error(&mut self, m: impl Into<String>) {
        self.log(Level::Error, m)
    }
}

/// Ejecuta la restauración; `sink` recibe cada línea en cuanto se produce (para la interfaz).
pub fn restore(
    ctx: &Context,
    opts: &RestoreOptions,
    sink: &mut dyn FnMut(&LogLine),
) -> RestoreReport {
    let mut c = Console {
        rep: RestoreReport::default(),
        sink,
    };
    c.info("Inicio de la restauración");
    c.info(format!(
        "Directorio de aplicación: {}",
        ctx.app.app_dir.display()
    ));
    let users = ctx.user_homes(opts.all_users);

    // 1. Certificados.
    let app_status = certs::inspect(&ctx.app.app_dir);
    let reuse_app =
        app_status.usable() && !app_status.needs_renewal() && opts.regenerate != Regenerate::Always;
    let dir = if reuse_app {
        ctx.app.app_dir.clone()
    } else {
        certs::target_dir(ctx)
    };
    if reuse_app {
        c.info("Se reutilizarán los certificados del directorio de instalación.");
    } else if app_status.pfx_present {
        c.info("Se crearán nuevos certificados SSL.");
    }
    let local = match certs::ensure(ctx, &dir, opts.regenerate, None, &CertProfile::default()) {
        Ok(o) => {
            if o.generated {
                c.info("Generando certificados para la comunicación con el navegador web...");
                c.info("Guardando en disco los certificados SSL...");
            } else {
                c.info("El certificado para la configuración del canal seguro ya se encuentra generado.");
            }
            Some(o.certs)
        }
        Err(e) => {
            c.error(format!(
                "No se han podido generar y copiar a disco los certificados SSL para la conexión con los navegadores. Se omite su configuración. ({e})"
            ));
            None
        }
    };

    if let Some(local) = &local {
        // 2. Almacén del sistema.
        match ctx.os {
            Os::Windows => {
                c.info("Instalando certificados SSL en el almacén de Windows...");
                let store = ctx.win_certs.as_ref();
                let scope = if ctx.elevated {
                    TrustScope::Machine
                } else {
                    TrustScope::User
                };
                if scope == TrustScope::User
                    && trust::windows::check(store, TrustScope::Machine, &local.ca_der).ok()
                {
                    c.info(
                        "El certificado raíz ya se encontraba instalado en el almacén de Windows.",
                    );
                } else {
                    match trust::windows::install(store, scope, &local.ca_der) {
                        Ok(Change::Unchanged) => c.info("El certificado raíz ya se encontraba instalado en el almacén de Windows."),
                        Ok(Change::Changed) => {}
                        Err(e) => c.error(format!(
                            "No se ha importado el certificado raíz CA \"Autofirma ROOT\" en almacén de Windows. El proceso de restauración continuará pero no estará completo hasta importar el certificado en el almacén de Windows. ({e})"
                        )),
                    }
                }
            }
            Os::MacOs => {
                c.info("Importando certificado en el almacén de confianza del sistema...");
                let scope = if ctx.elevated {
                    TrustScope::Machine
                } else {
                    TrustScope::User
                };
                match trust::macos::install(ctx, scope, local) {
                    Ok(_) => {
                        c.info("Certificado de CA importado.");
                        c.info("Certificado SSL importado.");
                    }
                    Err(e) => c.error(format!("No se ha podido instalar el certificado de confianza SSL en el llavero del sistema. ({e})")),
                }
            }
            Os::Linux => {
                if ctx.elevated {
                    c.info("Instalando el certificado en el almacén del sistema...");
                    if let Err(e) = trust::linux::install(ctx, &local.ca_der) {
                        c.error(format!("No se ha podido instalar el certificado de confianza SSL en el almacén del sistema. ({e})"));
                    }
                }
            }
        }

        // 3. NSS (Chrome/Chromium en Linux y Firefox).
        let dbs = nss::discover(ctx, &users, true, true);
        let backend = nss::backend(ctx);
        let shared: Vec<_> = dbs
            .iter()
            .filter(|d| d.purpose == NssPurpose::Shared)
            .collect();
        let fx: Vec<_> = dbs
            .iter()
            .filter(|d| d.purpose == NssPurpose::Firefox)
            .collect();
        if !shared.is_empty() {
            c.info("Instalando el certificado en el almacén del sistema...");
        }
        if ctx.os == Os::Windows {
            c.info("Instalando el certificado SSL en el almacén de Mozilla Firefox");
        } else {
            c.info(
                "Instalando el certificado de confianza SSL en el almacén de Mozilla Firefox...",
            );
        }
        if fx.is_empty() {
            c.warn("No se ha detectado un perfil de Mozilla Firefox en el que instalar el certificado.");
        }
        match &backend {
            None if !dbs.is_empty() => c.warn("No se pudo configurar \"certutil\" por lo que no se podran instalar los certificados en el almacen de Firefox."),
            None => {}
            Some(b) => {
                let mut fx_fail = false;
                for db in &dbs {
                    if db.purpose == NssPurpose::Firefox {
                        c.info(format!("Restauramos los certificados en el perfil de Firefox: {}", db.dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
                    }
                    if let Err(e) = nss::install(ctx, db, b, &local.ca_der, &local.ca_path()) {
                        if db.purpose == NssPurpose::Firefox {
                            fx_fail = true;
                            c.warn(format!(
                                "No se ha pudieron restaurar los certificados en el perfil '{}'. Es posible que el usuario no posea permisos sobre el mismo. ({e})",
                                db.dir.display()
                            ));
                        } else {
                            c.error(format!("No se ha podido instalar el certificado de confianza SSL en el almacén del sistema. ({}: {e})", db.description));
                        }
                    } else if nss::check(ctx, db, b, &local.ca_der) != TrustCheck::Trusted {
                        c.warn(format!("{}: el certificado no figura como de confianza tras instalarlo", db.description));
                    }
                }
                if fx_fail {
                    c.warn("No se ha podido instalar el certificado de confianza SSL en todos los perfiles de Mozilla Firefox.");
                }
            }
        }
    }

    // 4. Protocolo afirma://
    match ctx.os {
        Os::Windows => {
            c.info("Restaurando la configuración del protocolo afirma en el registro de Windows...")
        }
        _ => c.info("Restaurando la configuración del protocolo \"afirma\" en Mozilla Firefox..."),
    }
    let popts = ProtocolOptions {
        scope: if ctx.elevated {
            TrustScope::Machine
        } else {
            TrustScope::User
        },
        ..Default::default()
    };
    match protocol::register(ctx, &popts) {
        Ok(_) => {}
        Err(e) => {
            if ctx.os == Os::Windows {
                c.error(format!("No se ha podido restaurar el protocolo \"afirma\". Ejecute Autofirma con privilegios de administrador para realizar esta tarea. ({e})"));
            } else {
                c.error(format!(
                    "No se ha podido restaurar la configuración del protocolo \"afirma\". ({e})"
                ));
            }
        }
    }
    if ctx.os == Os::Linux
        && ctx.elevated
        && let Err(e) = protocol::install_firefox_protocol_prefs(ctx)
    {
        c.warn(format!(
            "No se han podido escribir las preferencias del protocolo en Firefox. ({e})"
        ));
    }

    // 5. Confianza de Firefox en las raíces del sistema (Windows y macOS).
    if ctx.os != Os::Linux {
        match opts.firefox_enterprise_roots {
            Tristate::Leave => c.info(
                "Se mantiene la configuración de Firefox sobre los certificados raíz del sistema.",
            ),
            t => {
                let enable = t == Tristate::Enable;
                if enable {
                    c.info("Configuramos Firefox para que confíe en los certificados raíz del almacén de confianza del sistema.");
                } else {
                    c.info("Se restaura la configuración de Firefox para que sólo confíe en los certificados de su almacén.");
                }
                let profiles = firefox::discover_profiles(ctx, &users);
                if profiles.is_empty() {
                    c.info("No se han detectado perfiles de Mozilla Firefox en los que configurar la confianza en el almacén del sistema.");
                }
                for p in profiles {
                    if ctx.os == Os::MacOs {
                        c.info(format!("Editamos la confianza de Firefox en el almacén del sistema para el perfil: {}", p.dir.display()));
                    }
                    if let Err(e) = firefox::set_enterprise_roots(&p.dir, enable) {
                        c.warn(format!(
                            "No se pudo editar la confianza de Firefox en el almacén del sistema para el perfil '{}'. Es posible que el usuario no posea permisos sobre el mismo. ({e})",
                            p.dir.display()
                        ));
                    }
                }
            }
        }
    }
    c.info("Fin de la restauración");
    c.rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restauracion_windows_sin_privilegios() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Windows, t.path());
        // El directorio de instalación no existe/no es escribible: se usa el alternativo.
        let mut lines = Vec::new();
        let rep = restore(&ctx, &RestoreOptions::default(), &mut |l| {
            lines.push(l.text())
        });
        assert!(rep.ok(), "{}", rep.to_text());
        assert_eq!(
            lines.first().map(String::as_str),
            Some("INFO: Inicio de la restauración")
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("INFO: Fin de la restauración")
        );
        assert!(ctx.paths.alternative_dir.join(certs::KS_FILENAME).is_file());
        let c = certs::locate(&ctx).unwrap();
        assert!(trust::windows::check(ctx.win_certs.as_ref(), TrustScope::User, &c.ca_der).ok());
        assert!(protocol::status(&ctx).registered);
        assert!(
            rep.to_text()
                .contains("Se mantiene la configuración de Firefox")
        );
        // Segunda ejecución: reutiliza y no cambia nada.
        let rep2 = restore(&ctx, &RestoreOptions::default(), &mut |_| {});
        assert!(rep2.to_text().contains("ya se encuentra generado"));
    }

    #[test]
    fn restauracion_linux_registra_el_protocolo() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let rep = restore(&ctx, &RestoreOptions::default(), &mut |_| {});
        assert!(rep.ok(), "{}", rep.to_text());
        assert!(
            ctx.paths
                .home
                .join(".local/share/applications/autofirma.desktop")
                .is_file()
        );
        assert!(ctx.paths.alternative_dir.join(certs::KS_FILENAME).is_file());
    }
}
