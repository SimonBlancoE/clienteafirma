//! Subórdenes de línea de comandos listas para que la aplicación las exponga
//! (`autofirma install|uninstall|restore-config|doctor|policy-templates|configurator`).
//!
//! ```text
//! autofirma install [--dry-run] [--json] [--user|--machine] [--firefox-roots|--no-firefox-roots]
//!                   [--no-certs] [--regenerate] [--no-os-trust] [--no-nss] [--current-user-only]
//!                   [--no-protocol] [--menus=sign,verify,hash|--no-menus] [--no-path]
//!                   [--browser-policies] [--origins=https://sede.example.es,...]
//!                   [--config-path=RUTA|URL] [--update-config] [--default-language=es_ES]
//!                   [--keystore-path=PFX --certificate-path=CER]
//! autofirma uninstall [--dry-run] [--json] [--user|--machine] [--keep-certs] [--keep-system-prefs]
//!                     [--revert-firefox-roots]
//! autofirma restore-config [--json] [--firefox-roots|--no-firefox-roots] [--current-user-only] [--regenerate]
//! autofirma doctor [--json] [--port=N]... [--current-user-only]
//! autofirma policy-templates --out=DIR [--origins=...] [--prefs-policy=policy.json] [--ca=Autofirma_ROOT.cer]
//! autofirma configurator [-install|-uninstall] [-firefox_roots] [-config_path P] [-update_config]
//!                        [-default_language L] [-keystore_path P -certificate_path P]   (opciones de Java)
//! ```
//!
//! Los códigos de salida son 0 (correcto) y −1/255 (error), como el configurador Java; `doctor`
//! devuelve 1 si hay errores.

use std::io::Write;
use std::path::PathBuf;

use crate::browser_policy::{self, BrowserPolicyOptions};
use crate::certs::{AdminCerts, Regenerate};
use crate::ctx::Context;
use crate::doctor::{self, DoctorOptions};
use crate::install::{self, InstallOptions, Scope, Tristate, UninstallOptions};
use crate::prefs::policy::{self, PolicySet};
use crate::protocol::ContextMenus;
use crate::restore::{self, RestoreOptions};

struct Args {
    flags: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(args: &[String]) -> Self {
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some((k, v)) = a.split_once('=') {
                flags.push((
                    k.trim_start_matches('-')
                        .to_ascii_lowercase()
                        .replace('_', "-"),
                    Some(v.to_string()),
                ));
            } else {
                let k = a
                    .trim_start_matches('-')
                    .to_ascii_lowercase()
                    .replace('_', "-");
                // Opciones con valor (formas de Java y largas).
                let takes = matches!(
                    k.as_str(),
                    "config-path"
                        | "default-language"
                        | "keystore-path"
                        | "certificate-path"
                        | "language-path"
                        | "out"
                        | "origins"
                        | "prefs-policy"
                        | "ca"
                        | "port"
                        | "menus"
                );
                if takes && i + 1 < args.len() {
                    flags.push((k, Some(args[i + 1].clone())));
                    i += 1;
                } else {
                    flags.push((k, None));
                }
            }
            i += 1;
        }
        Self { flags }
    }

    fn has(&self, k: &str) -> bool {
        self.flags.iter().any(|(f, _)| f == k)
    }

    fn val(&self, k: &str) -> Option<String> {
        self.flags
            .iter()
            .rev()
            .find(|(f, _)| f == k)
            .and_then(|(_, v)| v.clone())
    }

    fn vals(&self, k: &str) -> Vec<String> {
        self.flags
            .iter()
            .filter(|(f, _)| f == k)
            .filter_map(|(_, v)| v.clone())
            .collect()
    }

    fn list(&self, k: &str) -> Vec<String> {
        self.vals(k)
            .iter()
            .flat_map(|v| v.split(',').map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect()
    }
}

fn scope(a: &Args) -> Scope {
    if a.has("user") {
        Scope::User
    } else if a.has("machine") {
        Scope::Machine
    } else {
        Scope::Auto
    }
}

fn firefox_roots(a: &Args) -> Tristate {
    if a.has("firefox-roots") {
        Tristate::Enable
    } else if a.has("no-firefox-roots") {
        Tristate::Disable
    } else {
        Tristate::Leave
    }
}

/// Opciones de instalación a partir de los argumentos.
pub fn install_options(args: &[String]) -> InstallOptions {
    let a = Args::parse(args);
    let mut o = InstallOptions {
        scope: scope(&a),
        firefox_enterprise_roots: firefox_roots(&a),
        ..Default::default()
    };
    o.certificates = !a.has("no-certs");
    if a.has("regenerate") {
        o.regenerate = Regenerate::Always;
    }
    o.os_trust = !a.has("no-os-trust");
    o.nss = !a.has("no-nss");
    o.all_users = !a.has("current-user-only");
    o.protocol = !a.has("no-protocol");
    o.add_to_path = !a.has("no-path");
    if a.has("no-menus") {
        o.menus = ContextMenus {
            sign: false,
            verify: false,
            hash: false,
        };
    } else if a.has("menus") {
        let m = a.list("menus");
        o.menus = ContextMenus {
            sign: m.iter().any(|x| x == "sign"),
            verify: m.iter().any(|x| x == "verify"),
            hash: m.iter().any(|x| x == "hash"),
        };
    }
    if a.has("browser-policies") || a.has("origins") {
        o.browser_policies = Some(BrowserPolicyOptions {
            allowed_origins: a.list("origins"),
            ..Default::default()
        });
    }
    o.config_path = a.val("config-path");
    o.update_config = a.has("update-config");
    o.default_language = a.val("default-language");
    if let (Some(pfx), Some(cer)) = (a.val("keystore-path"), a.val("certificate-path")) {
        o.admin_certs = Some(AdminCerts {
            pfx: PathBuf::from(pfx),
            ca_cert: PathBuf::from(cer),
        });
    }
    o
}

fn print<T: serde::Serialize>(out: &mut dyn Write, json: bool, v: &T, text: String) {
    if json {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(v).unwrap_or_default()
        );
    } else {
        let _ = write!(out, "{text}");
    }
}

/// Ejecuta una subórden. `args[0]` es el nombre de la subórden.
pub fn run(ctx: &Context, args: &[String], out: &mut dyn Write) -> i32 {
    let Some(cmd) = args.first() else {
        let _ = writeln!(
            out,
            "Uso: autofirma install|uninstall|restore-config|doctor|policy-templates|configurator [opciones]"
        );
        return -1;
    };
    let rest = &args[1..];
    let a = Args::parse(rest);
    let json = a.has("json");
    match cmd.as_str() {
        "install" => {
            let rep = install::install(ctx, &install_options(rest), a.has("dry-run"));
            print(out, json, &rep, rep.to_text());
            rep.exit_code()
        }
        "uninstall" => {
            let o = UninstallOptions {
                scope: scope(&a),
                all_users: !a.has("current-user-only"),
                remove_certificates: !a.has("keep-certs"),
                remove_system_prefs: !a.has("keep-system-prefs"),
                revert_firefox_enterprise_roots: a.has("revert-firefox-roots"),
            };
            let rep = install::uninstall(ctx, &o, a.has("dry-run"));
            print(out, json, &rep, rep.to_text());
            rep.exit_code()
        }
        "configurator" => {
            let (uninstall, io, uo) = install::parse_configurator_args(rest.iter().cloned());
            let rep = if uninstall {
                install::uninstall(ctx, &uo, false)
            } else {
                install::install(ctx, &io, false)
            };
            print(out, json, &rep, rep.to_text());
            rep.exit_code()
        }
        "restore-config" => {
            let o = RestoreOptions {
                firefox_enterprise_roots: firefox_roots(&a),
                all_users: !a.has("current-user-only"),
                regenerate: if a.has("regenerate") {
                    Regenerate::Always
                } else {
                    Regenerate::IfInvalid
                },
            };
            let mut lines = Vec::new();
            let rep = restore::restore(ctx, &o, &mut |l| lines.push(l.text()));
            print(out, json, &rep, rep.to_text());
            if rep.ok() { 0 } else { -1 }
        }
        "doctor" => {
            let mut o = DoctorOptions {
                all_users: !a.has("current-user-only"),
                ..Default::default()
            };
            let ports: Vec<u16> = a
                .vals("port")
                .iter()
                .filter_map(|p| p.parse().ok())
                .collect();
            if !ports.is_empty() {
                o.ports = ports;
            }
            let rep = doctor::run(ctx, &o);
            print(out, json, &rep, rep.to_text());
            rep.exit_code()
        }
        "policy-templates" => match write_templates(ctx, &a) {
            Ok(files) => {
                for f in files {
                    let _ = writeln!(out, "{}", f.display());
                }
                0
            }
            Err(e) => {
                let _ = writeln!(out, "Error: {e}");
                -1
            }
        },
        other => {
            let _ = writeln!(out, "Orden desconocida: {other}");
            -1
        }
    }
}

fn write_templates(ctx: &Context, a: &Args) -> crate::error::Result<Vec<PathBuf>> {
    let dir = PathBuf::from(
        a.val("out")
            .ok_or_else(|| crate::error::SystemError::Other("falta --out=DIR".into()))?,
    );
    let opts = BrowserPolicyOptions {
        allowed_origins: a.list("origins"),
        ..Default::default()
    };
    let prefs: Option<PolicySet> = match a.val("prefs-policy") {
        Some(p) => {
            let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&p)?)
                .map_err(|e| crate::error::SystemError::Other(e.to_string()))?;
            let mut ps = PolicySet::default();
            policy::apply_json(&mut ps, &p, &doc);
            Some(ps)
        }
        None => None,
    };
    let ca = match a.val("ca") {
        Some(p) => Some(crate::certs::parse_cert_file(&std::fs::read(&p)?)?),
        None => None,
    };
    let mut written = Vec::new();
    let reg = dir.join("autofirma-policies.reg");
    crate::fsutil::write_atomic(
        &reg,
        &browser_policy::reg_file_bytes(&browser_policy::windows_reg_template(
            &opts,
            prefs.as_ref(),
        )),
        Some(0o644),
    )?;
    written.push(reg);
    let mc = dir.join("autofirma.mobileconfig");
    crate::fsutil::write_atomic(
        &mc,
        &browser_policy::macos_mobileconfig(
            &opts,
            prefs.as_ref(),
            &ctx.app.macos_bundle_id,
            ca.as_deref(),
        ),
        Some(0o644),
    )?;
    written.push(mc);
    for (path, content) in browser_policy::linux_policy_files(&opts) {
        let p = dir.join("linux").join(path.trim_start_matches('/'));
        crate::fsutil::write_atomic(&p, content.as_bytes(), Some(0o644))?;
        written.push(p);
    }
    let pj = dir.join("linux/etc/autofirma/policy.json");
    crate::fsutil::write_atomic(&pj, policy::linux_policy_template().as_bytes(), Some(0o644))?;
    written.push(pj);
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn opciones_largas_y_de_java() {
        let o = install_options(&s(&[
            "--user",
            "-firefox_roots",
            "--origins=https://a.es,https://*.b.es",
            "-config_path",
            "https:\\\\x\\y",
            "--menus",
            "sign,hash",
            "--no-path",
        ]));
        assert_eq!(o.scope, Scope::User);
        assert_eq!(o.firefox_enterprise_roots, Tristate::Enable);
        assert_eq!(
            o.browser_policies.unwrap().allowed_origins,
            vec!["https://a.es", "https://*.b.es"]
        );
        assert_eq!(o.config_path.as_deref(), Some("https:\\\\x\\y"));
        assert!(o.menus.sign && o.menus.hash && !o.menus.verify && !o.add_to_path);
    }

    #[test]
    fn ordenes_de_extremo_a_extremo() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let mut out = Vec::new();
        assert_eq!(run(&ctx, &s(&["install", "--dry-run"]), &mut out), 0);
        assert!(String::from_utf8_lossy(&out).contains("SE HARÍA"));
        let mut out = Vec::new();
        assert_eq!(run(&ctx, &s(&["restore-config", "--json"]), &mut out), 0);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v["lines"].as_array().unwrap().len() > 3);
        let mut out = Vec::new();
        let code = run(&ctx, &s(&["doctor", "--port=1"]), &mut out);
        assert!(
            String::from_utf8_lossy(&out).contains("Diagnóstico de AutoFirma"),
            "{code}"
        );
        let mut out = Vec::new();
        let dir = t.path().join("plantillas");
        assert_eq!(
            run(
                &ctx,
                &s(&[
                    "policy-templates",
                    &format!("--out={}", dir.display()),
                    "--origins=https://sede.example.es"
                ]),
                &mut out
            ),
            0
        );
        assert!(
            dir.join("autofirma-policies.reg").is_file()
                && dir.join("autofirma.mobileconfig").is_file()
        );
        assert!(
            dir.join("linux/etc/opt/chrome/policies/managed/autofirma.json")
                .is_file()
        );
        assert_eq!(run(&ctx, &s(&["nada"]), &mut Vec::new()), -1);
    }
}
