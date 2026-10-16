//! Implementación de [`SystemOps`] con el crate `afirma-system`
//! (característica `afirma-system`).
//!
//! Se traduce cada petición a la línea de órdenes de
//! `afirma_system::cli::run` (`--system` → `--machine`; `--user` →
//! `--user --current-user-only`), que es la interfaz más estable del crate.

use afirma_system::{AppIdentity, Context};

use crate::system::{
    DoctorRequest, InstallRequest, RestoreRequest, Scope, SystemOps, SystemOutcome,
    UninstallRequest,
};

/// [`SystemOps`] sobre `afirma-system`.
#[derive(Debug, Clone)]
pub struct AfirmaSystemOps {
    ctx: Context,
}

impl AfirmaSystemOps {
    /// Con el contexto real del proceso (ejecutable en curso).
    pub fn detect() -> Self {
        Self::new(Context::detect(AppIdentity::current()))
    }

    /// Con un contexto dado (pruebas, otra identidad de aplicación).
    pub fn new(ctx: Context) -> Self {
        AfirmaSystemOps { ctx }
    }

    fn call(&self, args: Vec<String>) -> SystemOutcome {
        let mut out = Vec::new();
        let status = afirma_system::cli::run(&self.ctx, &args, &mut out);
        SystemOutcome {
            status,
            output: String::from_utf8_lossy(&out).into_owned(),
        }
    }
}

fn scope_args(scope: Scope) -> Vec<String> {
    match scope {
        Scope::System => vec!["--machine".into()],
        Scope::User => vec!["--user".into(), "--current-user-only".into()],
    }
}

impl SystemOps for AfirmaSystemOps {
    fn install(&self, request: &InstallRequest) -> SystemOutcome {
        let mut args = vec!["install".to_string()];
        args.extend(scope_args(request.scope));
        if request.browser_policies {
            args.push("--browser-policies".into());
        }
        if !request.origins.is_empty() {
            args.push(format!("--origins={}", request.origins.join(",")));
        }
        if request.dry_run {
            args.push("--dry-run".into());
        }
        args.extend(request.advanced.iter().cloned());
        self.call(args)
    }

    fn uninstall(&self, request: &UninstallRequest) -> SystemOutcome {
        let mut args = vec!["uninstall".to_string()];
        args.extend(scope_args(request.scope));
        if request.dry_run {
            args.push("--dry-run".into());
        }
        args.extend(request.advanced.iter().cloned());
        self.call(args)
    }

    fn doctor(&self, request: &DoctorRequest) -> SystemOutcome {
        let mut args = vec!["doctor".to_string()];
        if request.json {
            args.push("--json".into());
        }
        self.call(args)
    }

    fn restore_config(&self, _request: &RestoreRequest) -> SystemOutcome {
        self.call(vec!["restore-config".to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulacion_en_contexto_de_pruebas() {
        let t = tempfile::tempdir().unwrap();
        let ops = AfirmaSystemOps::new(Context::for_tests(afirma_system::Os::Linux, t.path()));
        let r = ops.install(&InstallRequest {
            scope: Scope::User,
            browser_policies: true,
            origins: vec!["https://a.es".into()],
            dry_run: true,
            advanced: vec!["--firefox-roots".into(), "--default-language=ca_ES".into()],
        });
        assert_eq!(r.status, 0, "{}", r.output);
        assert!(!r.output.is_empty());
        let r = ops.doctor(&DoctorRequest { json: true });
        assert!(r.output.trim_start().starts_with('{'), "{}", r.output);
    }
}
