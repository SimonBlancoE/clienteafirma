//! Llaveros de macOS con la herramienta `security`.
//!
//! * Con privilegios (instalador `.pkg`, `postinstall` como root): llavero del sistema
//!   `/Library/Keychains/System.keychain`, CA como `trustRoot` y certificado SSL como
//!   `trustAsRoot` (como Java, porque la validez de 10 años supera el límite de 825 días que
//!   macOS impone a los certificados de servidor que solo confían a través de la CA).
//! * Sin privilegios: llavero de sesión (macOS pide la contraseña del usuario para cambiar
//!   la configuración de confianza; no se puede evitar).
//!
//! A diferencia de Java no se pide ni se maneja la contraseña del usuario en el proceso
//! (`sudo -S`); para la instalación silenciosa en equipos gestionados se recomienda además
//! desplegar la CA con un perfil de configuración (ver [`crate::browser_policy::macos_mobileconfig`]).
//! Nota: desde macOS 11 `add-trusted-cert` puede requerir interacción incluso como root
//! fuera de un instalador; en ese caso el error se informa y se recomienda el perfil MDM.

use std::path::{Path, PathBuf};

use super::{Change, TrustCheck, TrustScope, is_autofirma_cert};
use crate::certs::{CA_CN, LocalCerts, SSL_CN, parse_cert_file, sha1_hex};
use crate::ctx::Context;
use crate::error::{Result, SystemError};
use crate::exec::Cmd;

/// Llavero del sistema.
pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";

/// Llavero según el ámbito.
pub fn keychain(ctx: &Context, scope: TrustScope) -> PathBuf {
    match scope {
        TrustScope::Machine => ctx.sys(SYSTEM_KEYCHAIN),
        TrustScope::User => ctx.paths.home.join("Library/Keychains/login.keychain-db"),
    }
}

fn security(ctx: &Context, args: &[&str]) -> Result<crate::exec::Output> {
    ctx.runner
        .run(
            &Cmd::new("/usr/bin/security")
                .args(args.iter().copied())
                .timeout(std::time::Duration::from_secs(120)),
        )
        .map_err(|e| SystemError::Command {
            program: "security".into(),
            detail: e.to_string(),
        })
}

/// Certificados con un CN dado en un llavero: (SHA-1, DER). `find-certificate -c` busca por
/// subcadena, por eso se filtran los resultados (Java podía borrar certificados ajenos).
fn find(ctx: &Context, kc: &Path, cn: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let kcs = kc.to_string_lossy();
    let o = security(ctx, &["find-certificate", "-a", "-c", cn, "-Z", "-p", &kcs])?;
    if !o.success() {
        // «The specified item could not be found in the keychain»: ninguno.
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut rest = o.stdout.as_str();
    while let Some(s) = rest.find("-----BEGIN CERTIFICATE-----") {
        let Some(e) = rest[s..].find("-----END CERTIFICATE-----") else {
            break;
        };
        if let Ok(der) = parse_cert_file(&rest.as_bytes()[s..s + e + 25]) {
            out.push((sha1_hex(&der), der));
        }
        rest = &rest[s + e + 25..];
    }
    Ok(out)
}

/// Comprueba la CA (y, en el llavero del sistema, el certificado SSL de confianza).
pub fn check(ctx: &Context, scope: TrustScope, certs: &LocalCerts) -> TrustCheck {
    let kc = keychain(ctx, scope);
    let found = match find(ctx, &kc, CA_CN) {
        Ok(f) => f,
        Err(e) => return TrustCheck::Unknown(e.to_string()),
    };
    if !found.iter().any(|(_, d)| d == &certs.ca_der) {
        return if found.iter().any(|(_, d)| is_autofirma_cert(d)) {
            TrustCheck::Mismatch("hay una CA de AutoFirma distinta (antigua)".into())
        } else {
            TrustCheck::Missing
        };
    }
    // Validación real de la cadena SSL sin red.
    let ssl = certs.ssl_path();
    if ssl.is_file() {
        let s = ssl.to_string_lossy();
        match security(ctx, &["verify-cert", "-c", &s, "-p", "ssl", "-s", SSL_CN, "-L"]) {
            Ok(o) if o.success() => TrustCheck::Trusted,
            Ok(o) => TrustCheck::Mismatch(format!(
                "la CA está en el llavero pero no es de confianza: {}",
                o.message()
            )),
            Err(e) => TrustCheck::Unknown(e.to_string()),
        }
    } else {
        TrustCheck::Trusted
    }
}

fn delete_old(ctx: &Context, kc: &Path, keep: &[&[u8]]) -> Result<bool> {
    let kcs = kc.to_string_lossy();
    let mut changed = false;
    for cn in [CA_CN, SSL_CN] {
        for (hash, der) in find(ctx, kc, cn)? {
            if keep.contains(&der.as_slice()) || !is_autofirma_cert(&der) {
                continue;
            }
            let o = security(ctx, &["delete-certificate", "-Z", &hash, "-t", &kcs])?;
            if !o.success() {
                return Err(SystemError::TrustStore {
                    store: kcs.to_string(),
                    detail: o.message(),
                });
            }
            changed = true;
        }
    }
    Ok(changed)
}

/// Instala la CA (`trustRoot`) y el certificado SSL (`trustAsRoot`). Idempotente.
pub fn install(ctx: &Context, scope: TrustScope, certs: &LocalCerts) -> Result<Change> {
    if scope == TrustScope::Machine && !ctx.elevated {
        return Err(SystemError::NotElevated("llavero del sistema".into()));
    }
    let kc = keychain(ctx, scope);
    let kcs = kc.to_string_lossy().into_owned();
    if check(ctx, scope, certs).ok() {
        let removed = delete_old(ctx, &kc, &[&certs.ca_der, &certs.ssl_der])?;
        return Ok(if removed { Change::Changed } else { Change::Unchanged });
    }
    delete_old(ctx, &kc, &[])?;
    let ca = certs.ca_path().to_string_lossy().into_owned();
    let mut args = vec!["add-trusted-cert"];
    if scope == TrustScope::Machine {
        args.push("-d");
    }
    args.extend(["-r", "trustRoot", "-k", &kcs, &ca]);
    let o = security(ctx, &args)?;
    if !o.success() {
        return Err(SystemError::TrustStore {
            store: kcs.clone(),
            detail: o.message(),
        });
    }
    let ssl = certs.ssl_path();
    if ssl.is_file() {
        let ssl = ssl.to_string_lossy().into_owned();
        let mut args = vec!["add-trusted-cert"];
        if scope == TrustScope::Machine {
            args.push("-d");
        }
        args.extend(["-r", "trustAsRoot", "-p", "ssl", "-k", &kcs, &ssl]);
        let o = security(ctx, &args)?;
        if !o.success() {
            return Err(SystemError::TrustStore {
                store: kcs,
                detail: o.message(),
            });
        }
    }
    Ok(Change::Changed)
}

/// Retira la CA y los certificados SSL de AutoFirma (y su configuración de confianza).
pub fn remove(ctx: &Context, scope: TrustScope) -> Result<Change> {
    let kc = keychain(ctx, scope);
    Ok(if delete_old(ctx, &kc, &[])? {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;
    use crate::exec::{FakeRunner, Output};
    use std::sync::Arc;

    #[test]
    fn instala_con_security() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::MacOs, t.path());
        ctx.elevated = true;
        let dir = t.path().join("certs");
        let out = crate::certs::ensure(
            &ctx,
            &dir,
            crate::certs::Regenerate::IfInvalid,
            None,
            &Default::default(),
        )
        .unwrap();
        let old = crate::certs::generate(&Default::default()).unwrap();
        let old_pem = crate::certs::der_to_pem(&old.ca_der);
        let runner = Arc::new(FakeRunner::new(move |c| {
            if c.args.first().map(String::as_str) == Some("find-certificate")
                && c.args.get(3).map(String::as_str) == Some(CA_CN)
            {
                Ok(Output::ok(format!("SHA-256 hash: X\nSHA-1 hash: Y\n{old_pem}")))
            } else if c.args.first().map(String::as_str) == Some("find-certificate") {
                Ok(Output::fail(
                    44,
                    "The specified item could not be found in the keychain.",
                ))
            } else {
                Ok(Output::ok(""))
            }
        }));
        ctx.runner = runner.clone();
        assert_eq!(install(&ctx, TrustScope::Machine, &out.certs).unwrap(), Change::Changed);
        let lines = runner.call_lines();
        assert!(
            lines
                .iter()
                .any(|l| l.contains("delete-certificate -Z") && l.contains(&crate::certs::sha1_hex(&old.ca_der)))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("add-trusted-cert -d -r trustRoot -k") && l.contains("Autofirma_ROOT.cer"))
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("add-trusted-cert -d -r trustAsRoot -p ssl") && l.contains("autofirma.cer"))
        );
    }
}
