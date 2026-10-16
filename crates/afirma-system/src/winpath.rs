//! Directorio de la aplicación en el `PATH` de Windows (`autofirma-addpath.cmd` /
//! `autofirma-removepath.cmd` del configurador Java), para poder invocar `Autofirma` desde una
//! consola. A diferencia de Java se notifica el cambio (`WM_SETTINGCHANGE`) y se admite el
//! `PATH` del usuario cuando no hay privilegios.

use std::path::Path;

use crate::ctx::Context;
use crate::error::{Result, SystemError};
use crate::registry::{Hive, RegValue};
use crate::trust::{Change, TrustScope};

/// Clave del entorno del sistema.
pub const MACHINE_ENV_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
/// Clave del entorno del usuario.
pub const USER_ENV_KEY: &str = "Environment";

fn loc(scope: TrustScope) -> (Hive, &'static str) {
    match scope {
        TrustScope::Machine => (Hive::LocalMachine, MACHINE_ENV_KEY),
        TrustScope::User => (Hive::CurrentUser, USER_ENV_KEY),
    }
}

fn norm(e: &str) -> String {
    e.trim().trim_end_matches('\\').to_ascii_lowercase()
}

fn read(ctx: &Context, scope: TrustScope) -> Result<(Option<RegValue>, String)> {
    let (h, k) = loc(scope);
    let v = ctx.registry.read(h, k, "Path").map_err(|e| SystemError::Registry {
        key: k.into(),
        detail: e.to_string(),
    })?;
    let s = v.as_ref().and_then(RegValue::as_string).unwrap_or_default();
    Ok((v, s))
}

fn write(ctx: &Context, scope: TrustScope, prev: Option<&RegValue>, value: String) -> Result<()> {
    let (h, k) = loc(scope);
    let v = match prev {
        Some(RegValue::Sz(_)) => RegValue::Sz(value),
        _ => RegValue::ExpandSz(value),
    };
    ctx.registry
        .write(h, k, "Path", &v)
        .map_err(|e| SystemError::Registry {
            key: k.into(),
            detail: e.to_string(),
        })?;
    broadcast();
    Ok(())
}

/// Añade el directorio al `PATH` si no está (sin distinguir mayúsculas ni `\` final).
pub fn add(ctx: &Context, scope: TrustScope, dir: &Path) -> Result<Change> {
    let (prev, cur) = read(ctx, scope)?;
    let target = dir.display().to_string().trim_end_matches('\\').to_string();
    if cur.split(';').any(|e| norm(e) == norm(&target)) {
        return Ok(Change::Unchanged);
    }
    let new = if cur.trim().is_empty() {
        target
    } else {
        format!("{};{target}", cur.trim_end_matches(';'))
    };
    write(ctx, scope, prev.as_ref(), new)?;
    Ok(Change::Changed)
}

/// Quita el directorio del `PATH`.
pub fn remove(ctx: &Context, scope: TrustScope, dir: &Path) -> Result<Change> {
    let (prev, cur) = read(ctx, scope)?;
    let target = norm(&dir.display().to_string());
    let kept: Vec<&str> = cur.split(';').filter(|e| norm(e) != target).collect();
    let new = kept.join(";");
    if new == cur {
        return Ok(Change::Unchanged);
    }
    write(ctx, scope, prev.as_ref(), new)?;
    Ok(Change::Changed)
}

/// Notifica a las aplicaciones el cambio de entorno.
fn broadcast() {
    #[cfg(windows)]
    // SAFETY: FFI con user32; la cadena UTF-16 vive durante la llamada.
    unsafe {
        use windows::Win32::Foundation::{LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
        };
        let env: Vec<u16> = "Environment\0".encode_utf16().collect();
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(env.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            5000,
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;

    #[test]
    fn anade_y_quita_del_path() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Windows, t.path());
        ctx.registry
            .write(
                Hive::LocalMachine,
                MACHINE_ENV_KEY,
                "Path",
                &RegValue::ExpandSz(r"%SystemRoot%\system32;C:\Otro".into()),
            )
            .unwrap();
        let d = Path::new(r"C:\Program Files\Autofirma\");
        assert_eq!(add(&ctx, TrustScope::Machine, d).unwrap(), Change::Changed);
        assert_eq!(
            add(&ctx, TrustScope::Machine, Path::new(r"c:\program files\autofirma")).unwrap(),
            Change::Unchanged
        );
        assert_eq!(
            ctx.registry.read(Hive::LocalMachine, MACHINE_ENV_KEY, "Path").unwrap(),
            Some(RegValue::ExpandSz(
                r"%SystemRoot%\system32;C:\Otro;C:\Program Files\Autofirma".into()
            ))
        );
        assert_eq!(remove(&ctx, TrustScope::Machine, d).unwrap(), Change::Changed);
        assert_eq!(
            ctx.registry
                .read_string(Hive::LocalMachine, MACHINE_ENV_KEY, "Path")
                .unwrap()
                .unwrap(),
            r"%SystemRoot%\system32;C:\Otro"
        );
    }
}
