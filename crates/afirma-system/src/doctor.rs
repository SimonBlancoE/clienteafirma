//! Diagnóstico (`autofirma doctor`): comprueba certificados locales, su confianza en cada
//! almacén y perfil, el registro del protocolo, el puerto local, las bibliotecas NSS, las
//! directivas de navegadores y las preferencias/directivas de AutoFirma. Devuelve resultados
//! estructurados (serializables a JSON) y un texto legible.

use crate::browser_policy;
use crate::certs;
use crate::ctx::{Context, Os};
use crate::firefox;
use crate::prefs::{self, ResolutionMode};
use crate::protocol;
use crate::trust::nss::{self, Backend};
use crate::trust::{self, TrustCheck, TrustScope};

/// Estado de una comprobación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum CheckStatus {
    Ok,
    Info,
    Warning,
    Error,
    Skipped,
}

/// Comprobación.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    /// Identificador estable (`certs.files`, `trust.nss`...).
    pub id: String,
    pub status: CheckStatus,
    pub title: String,
    pub detail: String,
    /// Cómo corregirlo.
    pub fix: Option<String>,
}

/// Opciones del diagnóstico.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DoctorOptions {
    /// Revisar los perfiles de todos los usuarios (con privilegios).
    pub all_users: bool,
    /// Puertos del servidor local a comprobar (por defecto 63117).
    pub ports: Vec<u16>,
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self {
            all_users: true,
            ports: vec![63117],
        }
    }
}

/// Informe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorReport {
    pub os: Os,
    pub elevated: bool,
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// Peor estado.
    pub fn worst(&self) -> CheckStatus {
        self.checks
            .iter()
            .map(|c| c.status)
            .filter(|s| *s != CheckStatus::Skipped)
            .max()
            .unwrap_or(CheckStatus::Ok)
    }

    /// Código de salida sugerido (0 bien o avisos, 1 errores).
    pub fn exit_code(&self) -> i32 {
        if self.worst() == CheckStatus::Error {
            1
        } else {
            0
        }
    }

    /// Texto legible.
    pub fn to_text(&self) -> String {
        let mut s = format!(
            "Diagnóstico de AutoFirma ({:?}{})\n",
            self.os,
            if self.elevated { ", administrador" } else { "" }
        );
        for c in &self.checks {
            let tag = match c.status {
                CheckStatus::Ok => "OK",
                CheckStatus::Info => "INFO",
                CheckStatus::Warning => "AVISO",
                CheckStatus::Error => "ERROR",
                CheckStatus::Skipped => "OMITIDO",
            };
            s.push_str(&format!("[{tag:7}] {}", c.title));
            if !c.detail.is_empty() {
                s.push_str(&format!(" — {}", c.detail));
            }
            s.push('\n');
            if let Some(f) = &c.fix {
                s.push_str(&format!("          → {f}\n"));
            }
        }
        s
    }
}

fn check(
    id: &str,
    status: CheckStatus,
    title: impl Into<String>,
    detail: impl Into<String>,
    fix: Option<&str>,
) -> Check {
    Check {
        id: id.into(),
        status,
        title: title.into(),
        detail: detail.into(),
        fix: fix.map(str::to_string),
    }
}

fn trust_to_status(t: &TrustCheck) -> (CheckStatus, String) {
    match t {
        TrustCheck::Trusted => (CheckStatus::Ok, "CA instalada y de confianza".into()),
        TrustCheck::Missing => (CheckStatus::Error, "la CA no está instalada".into()),
        TrustCheck::Mismatch(m) => (CheckStatus::Warning, m.clone()),
        TrustCheck::Unknown(e) => (CheckStatus::Warning, format!("no se pudo comprobar: {e}")),
    }
}

const FIX_RESTORE: &str =
    "Ejecute «autofirma restore-config» (o «Herramientas > Restaurar instalación»)";

/// Ejecuta el diagnóstico.
pub fn run(ctx: &Context, opts: &DoctorOptions) -> DoctorReport {
    let mut checks = Vec::new();

    // Certificados locales.
    let located = certs::locate(ctx);
    match &located {
        None => {
            let dirs: Vec<String> = certs::search_dirs(ctx)
                .iter()
                .map(|d| d.display().to_string())
                .collect();
            checks.push(check(
                "certs.files",
                CheckStatus::Error,
                "Certificados del servidor local",
                format!("no hay autofirma.pfx utilizable en {}", dirs.join(", ")),
                Some(FIX_RESTORE),
            ));
        }
        Some(c) => {
            let st = certs::inspect(&c.dir);
            let (status, detail) = if !st.usable() {
                (
                    CheckStatus::Error,
                    format!(
                        "{}: certificados no utilizables ({})",
                        c.dir.display(),
                        st.pfx_error
                            .clone()
                            .unwrap_or_else(|| "cadena incorrecta o caducados".into())
                    ),
                )
            } else if st.needs_renewal() {
                (
                    CheckStatus::Warning,
                    format!(
                        "{}: caducan en {} días",
                        c.dir.display(),
                        st.days_left.unwrap_or(0)
                    ),
                )
            } else {
                (
                    CheckStatus::Ok,
                    format!(
                        "{} (alias {}, caducan en {} días)",
                        c.dir.display(),
                        st.alias.clone().unwrap_or_default(),
                        st.days_left.unwrap_or(0)
                    ),
                )
            };
            checks.push(check(
                "certs.files",
                status,
                "Certificados del servidor local",
                detail,
                (status != CheckStatus::Ok).then_some(FIX_RESTORE),
            ));
            if let Some(ssl) = &st.ssl {
                let localhost = ssl.san_dns.iter().any(|d| d == "localhost");
                checks.push(check(
                    "certs.san",
                    if localhost { CheckStatus::Ok } else { CheckStatus::Info },
                    "Nombres del certificado SSL",
                    format!("IP: {} · DNS: {}", ssl.san_ip.join(", "), if ssl.san_dns.is_empty() { "-".into() } else { ssl.san_dns.join(", ") }),
                    (!localhost).then_some("Sin DNS:localhost (certificado de «Restaurar instalación» de Java); válido para 127.0.0.1"),
                ));
            }
        }
    }

    // Confianza en el almacén del sistema.
    if let Some(c) = &located {
        match ctx.os {
            Os::Windows => {
                let m =
                    trust::windows::check(ctx.win_certs.as_ref(), TrustScope::Machine, &c.ca_der);
                let u = trust::windows::check(ctx.win_certs.as_ref(), TrustScope::User, &c.ca_der);
                let ok = m.ok() || u.ok();
                let (st, _) = trust_to_status(if ok { &TrustCheck::Trusted } else { &m });
                checks.push(check(
                    "trust.os",
                    st,
                    "Almacén de confianza de Windows (ROOT)",
                    format!("equipo: {m:?}; usuario: {u:?}"),
                    (!ok).then_some(FIX_RESTORE),
                ));
            }
            Os::MacOs => {
                let s = trust::macos::check(ctx, TrustScope::Machine, c);
                let u = if s.ok() {
                    TrustCheck::Trusted
                } else {
                    trust::macos::check(ctx, TrustScope::User, c)
                };
                let best = if s.ok() { &s } else { &u };
                let (st, d) = trust_to_status(best);
                checks.push(check(
                    "trust.os",
                    st,
                    "Llavero de macOS",
                    format!("sistema: {s:?}; sesión: {u:?} — {d}"),
                    (!best.ok()).then_some(FIX_RESTORE),
                ));
            }
            Os::Linux => {
                let t = trust::linux::check(ctx, &c.ca_der);
                let (st, d) = trust_to_status(&t);
                // Las anclas del sistema solo las usan algunas aplicaciones: no es un error.
                let st = if st == CheckStatus::Error {
                    CheckStatus::Info
                } else {
                    st
                };
                checks.push(check(
                    "trust.os",
                    st,
                    "Anclas de confianza del sistema (Linux)",
                    d,
                    (!t.ok())
                        .then_some("sudo autofirma install (opcional: Chrome/Firefox usan NSS)"),
                ));
            }
        }
    }

    // NSS.
    let users = ctx.user_homes(opts.all_users);
    let dbs = nss::discover(ctx, &users, true, true);
    let backend = nss::backend(ctx);
    match &backend {
        Some(Backend::Certutil(p)) => checks.push(check(
            "nss.backend",
            CheckStatus::Ok,
            "Herramientas NSS",
            format!("certutil: {}", p.display()),
            None,
        )),
        Some(Backend::Softokn(p)) => checks.push(check(
            "nss.backend",
            CheckStatus::Ok,
            "Herramientas NSS",
            format!("softokn3 (PKCS#11): {}", p.display()),
            None,
        )),
        None if dbs.is_empty() => checks.push(check(
            "nss.backend",
            CheckStatus::Info,
            "Herramientas NSS",
            "no se encontró certutil ni softokn3 (no hay bases NSS)",
            None,
        )),
        None => checks.push(check(
            "nss.backend",
            CheckStatus::Warning,
            "Herramientas NSS",
            "no se encontró certutil ni softokn3",
            Some("Instale el paquete libnss3-tools / nss-tools / mozilla-nss-tools"),
        )),
    }
    if dbs.is_empty() {
        checks.push(check(
            "trust.nss",
            CheckStatus::Info,
            "Almacenes NSS (Firefox, Chrome/Chromium)",
            "no se encontraron perfiles con base de datos NSS",
            None,
        ));
    }
    if let (Some(c), Some(b)) = (&located, &backend) {
        for db in &dbs {
            let t = nss::check(ctx, db, b, &c.ca_der);
            let (mut st, d) = trust_to_status(&t);
            // En Windows/macOS Firefox puede confiar en el almacén del sistema.
            if st == CheckStatus::Error
                && ctx.os != Os::Linux
                && firefox::enterprise_roots_state(&db.dir) == Some(true)
            {
                st = CheckStatus::Info;
            }
            checks.push(check(
                "trust.nss",
                st,
                format!("NSS: {}", db.description),
                d,
                (!t.ok()).then_some(FIX_RESTORE),
            ));
        }
    }

    // Raíces de empresa en Firefox (Windows/macOS).
    if ctx.os != Os::Linux {
        for p in firefox::discover_profiles(ctx, &users) {
            let s = firefox::enterprise_roots_state(&p.dir);
            checks.push(check(
                "firefox.enterprise_roots",
                if s == Some(false) {
                    CheckStatus::Warning
                } else {
                    CheckStatus::Info
                },
                format!("Firefox «{}»: confianza en las raíces del sistema", p.name),
                match s {
                    Some(true) => "activada en user.js".to_string(),
                    Some(false) => {
                        "desactivada en user.js (Java la desactivaba en «Restaurar instalación»)"
                            .to_string()
                    }
                    None => "valor por defecto de Firefox".to_string(),
                },
                (s == Some(false)).then_some("autofirma restore-config --firefox-roots"),
            ));
        }
    }

    // Protocolo.
    let ps = protocol::status(ctx);
    let (st, fix) = if !ps.registered {
        (CheckStatus::Error, Some(FIX_RESTORE))
    } else if !ps.points_to_current {
        (
            CheckStatus::Warning,
            Some(
                "El protocolo apunta a otra instalación (¿AutoFirma Java?): ejecute «autofirma restore-config»",
            ),
        )
    } else {
        (CheckStatus::Ok, None)
    };
    checks.push(check(
        "protocol",
        st,
        "Manejador del protocolo afirma://",
        format!("{} {}", ps.handler.clone().unwrap_or_default(), ps.detail)
            .trim()
            .to_string(),
        fix,
    ));

    // Puertos.
    for port in &opts.ports {
        let free = std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok();
        checks.push(check(
            "ports",
            if free {
                CheckStatus::Ok
            } else {
                CheckStatus::Warning
            },
            format!("Puerto local {port}"),
            if free {
                "libre".to_string()
            } else {
                "en uso (¿AutoFirma ya en ejecución u otra aplicación?)".to_string()
            },
            None,
        ));
    }

    // Directivas de navegadores.
    for p in browser_policy::status(ctx) {
        let detail = if p.auto_launch {
            if p.origins.is_empty() {
                format!("{} (manejador de Firefox)", p.location)
            } else {
                format!("{} — orígenes: {}", p.location, p.origins.join(", "))
            }
        } else {
            format!(
                "{}: sin directiva (el navegador preguntará antes de abrir AutoFirma)",
                p.location
            )
        };
        checks.push(check(
            "browser_policy",
            CheckStatus::Info,
            format!("Directivas de {:?}", p.browser),
            detail,
            None,
        ));
    }

    // Preferencias y directivas de AutoFirma.
    match prefs::Preferences::load(ctx, ResolutionMode::Strict) {
        Ok(p) => {
            let pol = p.policies();
            let locked = p.effective().iter().filter(|e| e.lock.is_some()).count();
            checks.push(check(
                "prefs.policy",
                if pol.warnings.is_empty() { CheckStatus::Info } else { CheckStatus::Warning },
                "Directivas de AutoFirma",
                format!(
                    "orígenes: {}; obligatorias: {}; recomendadas: {}; bloqueo: {}; claves bloqueadas: {locked}{}",
                    if pol.sources.is_empty() { "ninguno".into() } else { pol.sources.join(", ") },
                    pol.mandatory.len(),
                    pol.recommended.len(),
                    if p.is_blocked() { "sí" } else { "no" },
                    if pol.warnings.is_empty() { String::new() } else { format!("; avisos: {}", pol.warnings.join(" | ")) }
                ),
                None,
            ));
            if let Some(url) = p.get("configFileUrl") {
                checks.push(check(
                    "prefs.remote",
                    CheckStatus::Info,
                    "Configuración del sistema",
                    format!(
                        "origen {url}; actualización diaria: {}; última comprobación: {}",
                        p.get_bool("allowUpdateConfig"),
                        p.get("configDate").unwrap_or_else(|| "-".into())
                    ),
                    None,
                ));
            }
        }
        Err(e) => checks.push(check(
            "prefs.policy",
            CheckStatus::Warning,
            "Preferencias",
            e.to_string(),
            None,
        )),
    }

    DoctorReport {
        os: ctx.os,
        elevated: ctx.elevated,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostico_antes_y_despues_de_restaurar() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Windows, t.path());
        let r = run(
            &ctx,
            &DoctorOptions {
                ports: vec![],
                ..Default::default()
            },
        );
        assert_eq!(r.worst(), CheckStatus::Error);
        assert!(
            r.checks
                .iter()
                .any(|c| c.id == "certs.files" && c.status == CheckStatus::Error)
        );
        crate::restore::restore(&ctx, &Default::default(), &mut |_| {});
        let r = run(
            &ctx,
            &DoctorOptions {
                ports: vec![],
                ..Default::default()
            },
        );
        assert_eq!(r.worst(), CheckStatus::Info, "{}", r.to_text());
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"certs.files\""));
    }
}
