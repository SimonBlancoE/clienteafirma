//! Anclas de confianza del sistema en Linux (requiere privilegios).
//!
//! | Familia | Directorio | Fichero | Actualización |
//! |---|---|---|---|
//! | openSUSE/SLES | `/etc/pki/trust/anchors` | `Autofirma_ROOT.pem` | `update-ca-certificates` |
//! | Fedora/RHEL | `/etc/pki/ca-trust/source/anchors` | `Autofirma_ROOT.pem` | `update-ca-trust extract` |
//! | Arch | `/etc/ca-certificates/trust-source/anchors` | `Autofirma_ROOT.crt` | `update-ca-trust` o `trust extract-compat` |
//! | Debian/Ubuntu | `/usr/local/share/ca-certificates` | `Autofirma_ROOT.crt` | `update-ca-certificates` |
//!
//! Java solo lo hacía en el paquete `.deb` (y además en `/usr/share/ca-certificates/Autofirma/`,
//! que se limpia al desinstalar).

use std::path::PathBuf;

use super::{Change, TrustCheck};
use crate::certs::der_to_pem;
use crate::ctx::Context;
use crate::error::{Result, SystemError};
use crate::exec::Cmd;
use crate::fsutil;

/// Familia de distribución (según el sistema de anclas disponible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum AnchorFlavor {
    Suse,
    Fedora,
    Arch,
    Debian,
}

impl AnchorFlavor {
    /// Directorio de anclas.
    pub fn dir(self) -> &'static str {
        match self {
            AnchorFlavor::Suse => "/etc/pki/trust/anchors",
            AnchorFlavor::Fedora => "/etc/pki/ca-trust/source/anchors",
            AnchorFlavor::Arch => "/etc/ca-certificates/trust-source/anchors",
            AnchorFlavor::Debian => "/usr/local/share/ca-certificates",
        }
    }

    /// Nombre del fichero.
    pub fn file_name(self) -> &'static str {
        match self {
            AnchorFlavor::Suse | AnchorFlavor::Fedora => "Autofirma_ROOT.pem",
            AnchorFlavor::Arch | AnchorFlavor::Debian => "Autofirma_ROOT.crt",
        }
    }

    /// Mandatos de actualización (se usa el primero disponible).
    pub fn update_commands(self) -> &'static [&'static [&'static str]] {
        match self {
            AnchorFlavor::Suse | AnchorFlavor::Debian => &[&["update-ca-certificates"]],
            AnchorFlavor::Fedora => &[
                &["update-ca-trust", "extract"],
                &["trust", "extract-compat"],
            ],
            AnchorFlavor::Arch => &[&["update-ca-trust"], &["trust", "extract-compat"]],
        }
    }

    /// Paquetes de certificados resultantes donde comprobar la presencia de la CA.
    pub fn bundles(self) -> &'static [&'static str] {
        match self {
            AnchorFlavor::Suse => &[
                "/var/lib/ca-certificates/ca-bundle.pem",
                "/etc/ssl/ca-bundle.pem",
            ],
            AnchorFlavor::Fedora => &[
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "/etc/pki/tls/certs/ca-bundle.crt",
            ],
            AnchorFlavor::Arch => &[
                "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
                "/etc/ssl/certs/ca-certificates.crt",
            ],
            AnchorFlavor::Debian => &["/etc/ssl/certs/ca-certificates.crt"],
        }
    }
}

/// Detecta la familia por los directorios existentes.
pub fn detect(ctx: &Context) -> Option<AnchorFlavor> {
    if ctx.sys("/etc/pki/trust").is_dir() {
        Some(AnchorFlavor::Suse)
    } else if ctx.sys("/etc/pki/ca-trust/source").is_dir() {
        Some(AnchorFlavor::Fedora)
    } else if ctx.sys("/etc/ca-certificates/trust-source").is_dir() {
        Some(AnchorFlavor::Arch)
    } else if ctx.sys("/usr/local/share/ca-certificates").is_dir()
        || ctx.sys("/etc/ssl/certs").is_dir()
    {
        Some(AnchorFlavor::Debian)
    } else {
        None
    }
}

/// Ruta del fichero de ancla.
pub fn anchor_path(ctx: &Context, f: AnchorFlavor) -> PathBuf {
    ctx.sys(f.dir()).join(f.file_name())
}

fn run_update(ctx: &Context, f: AnchorFlavor) -> Result<()> {
    let mut last = String::from("no se encontró ningún mandato de actualización");
    for cmd in f.update_commands() {
        if ctx.runner.which(cmd[0]).is_none() {
            continue;
        }
        let o = ctx
            .runner
            .run(
                &Cmd::new(cmd[0])
                    .args(cmd[1..].iter().copied())
                    .timeout(std::time::Duration::from_secs(180)),
            )
            .map_err(|e| SystemError::Command {
                program: cmd[0].into(),
                detail: e.to_string(),
            })?;
        if o.success() {
            return Ok(());
        }
        last = format!("{}: {}", cmd.join(" "), o.message());
    }
    Err(SystemError::TrustStore {
        store: "anclas del sistema".into(),
        detail: last,
    })
}

/// Comprueba el ancla y el paquete generado.
pub fn check(ctx: &Context, ca_der: &[u8]) -> TrustCheck {
    let Some(f) = detect(ctx) else {
        return TrustCheck::Unknown("sistema de anclas no reconocido".into());
    };
    let pem = der_to_pem(ca_der);
    let p = anchor_path(ctx, f);
    match std::fs::read_to_string(&p) {
        Ok(t) if crate::fsutil::normalize_newlines(&t).trim() == pem.trim() => {}
        Ok(_) => return TrustCheck::Mismatch(format!("{} contiene otra CA", p.display())),
        Err(_) => return TrustCheck::Missing,
    }
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    for b in f.bundles() {
        if let Ok(t) = std::fs::read_to_string(ctx.sys(b)) {
            let flat: String = t.lines().filter(|l| !l.starts_with("-----")).collect();
            return if flat.contains(&body) {
                TrustCheck::Trusted
            } else {
                TrustCheck::Mismatch(format!("la CA no está en {b} (falta actualizar)"))
            };
        }
    }
    TrustCheck::Trusted
}

/// Instala la CA como ancla del sistema y regenera los paquetes. Idempotente.
pub fn install(ctx: &Context, ca_der: &[u8]) -> Result<Change> {
    if !ctx.elevated {
        return Err(SystemError::NotElevated(
            "anclas de confianza del sistema".into(),
        ));
    }
    let f = detect(ctx).ok_or_else(|| {
        SystemError::Unsupported("sistema de anclas de confianza no reconocido".into())
    })?;
    if check(ctx, ca_der) == TrustCheck::Trusted {
        return Ok(Change::Unchanged);
    }
    let pem = der_to_pem(ca_der);
    fsutil::write_atomic(&anchor_path(ctx, f), pem.as_bytes(), Some(0o644))?;
    run_update(ctx, f)?;
    Ok(Change::Changed)
}

/// Ficheros de anclas de AutoFirma conocidos (incluidos los del paquete `.deb` de Java).
pub fn known_anchor_files(ctx: &Context) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        AnchorFlavor::Suse,
        AnchorFlavor::Fedora,
        AnchorFlavor::Arch,
        AnchorFlavor::Debian,
    ]
    .iter()
    .map(|f| anchor_path(ctx, *f))
    .collect();
    v.push(ctx.sys("/usr/share/ca-certificates/Autofirma/Autofirma_ROOT.crt"));
    v
}

/// Retira los ficheros de anclas de AutoFirma y regenera los paquetes.
pub fn remove(ctx: &Context) -> Result<Change> {
    if !ctx.elevated {
        return Err(SystemError::NotElevated(
            "anclas de confianza del sistema".into(),
        ));
    }
    let mut changed = false;
    for p in known_anchor_files(ctx) {
        changed |= fsutil::remove_file_if_exists(&p)?;
    }
    let java_dir = ctx.sys("/usr/share/ca-certificates/Autofirma");
    if java_dir.is_dir()
        && std::fs::read_dir(&java_dir)
            .map(|mut r| r.next().is_none())
            .unwrap_or(false)
    {
        let _ = std::fs::remove_dir(&java_dir);
    }
    if changed && let Some(f) = detect(ctx) {
        run_update(ctx, f)?;
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;
    use crate::exec::FakeRunner;
    use std::sync::Arc;

    #[test]
    fn anclas_suse() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Linux, t.path());
        std::fs::create_dir_all(t.path().join("etc/pki/trust/anchors")).unwrap();
        let runner = Arc::new(FakeRunner::default().with_programs(&["update-ca-certificates"]));
        ctx.runner = runner.clone();
        let p = crate::certs::generate(&Default::default()).unwrap();
        assert!(install(&ctx, &p.ca_der).is_err(), "sin privilegios");
        ctx.elevated = true;
        assert_eq!(detect(&ctx), Some(AnchorFlavor::Suse));
        assert_eq!(install(&ctx, &p.ca_der).unwrap(), Change::Changed);
        assert_eq!(
            runner.call_lines(),
            vec!["update-ca-certificates".to_string()]
        );
        assert_eq!(check(&ctx, &p.ca_der), TrustCheck::Trusted);
        assert_eq!(install(&ctx, &p.ca_der).unwrap(), Change::Unchanged);
        assert_eq!(remove(&ctx).unwrap(), Change::Changed);
        assert_eq!(check(&ctx, &p.ca_der), TrustCheck::Missing);
    }
}
