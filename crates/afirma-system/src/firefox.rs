//! Firefox: localización de perfiles (`profiles.ini`, con las reglas de la especificación de
//! almacenes §3.6 y las ubicaciones que Java no cubría: XDG, snap **y** clásico a la vez,
//! flatpak), edición de `user.js` (`security.enterprise_roots.enabled`) y detección de
//! procesos en ejecución.
//!
//! Se duplica aquí un analizador pequeño de `profiles.ini` para no depender de
//! `afirma-keystores`.

use std::path::{Path, PathBuf};

use crate::ctx::{Context, Os, UserHome};
use crate::error::{Result, io_at};
use crate::exec::Cmd;
use crate::fsutil;

/// Variante de instalación de Firefox de la que procede un perfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum FirefoxFlavor {
    /// `~/.mozilla/firefox` (Linux) o la ubicación estándar de Windows/macOS.
    Classic,
    /// `~/.config/mozilla/firefox` (Firefox 147+ en Linux).
    Xdg,
    /// `~/snap/firefox/common/.mozilla/firefox` (Ubuntu).
    Snap,
    /// `~/.var/app/org.mozilla.firefox/...` (Flatpak).
    Flatpak,
}

/// Perfil de Firefox.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FirefoxProfile {
    /// Directorio del perfil.
    pub dir: PathBuf,
    /// Nombre (`Name=`).
    pub name: String,
    /// `profiles.ini` del que procede.
    pub ini: PathBuf,
    /// Variante.
    pub flavor: FirefoxFlavor,
    /// Usuario propietario.
    pub user: String,
    /// `Default=1`.
    pub is_default: bool,
}

impl FirefoxProfile {
    /// Tipo de base de datos NSS del perfil (si existe).
    pub fn nss_db(&self) -> Option<NssDbKind> {
        nss_db_kind(&self.dir)
    }
}

/// Tipo de base de datos NSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum NssDbKind {
    /// `cert9.db`/`key4.db`/`pkcs11.txt` (prefijo `sql:`).
    Sql,
    /// `cert8.db`/`key3.db`/`secmod.db` (heredado, prefijo `dbm:`).
    Dbm,
}

/// Detecta si un directorio contiene ya una base de datos NSS (no se crean bases nuevas).
pub fn nss_db_kind(dir: &Path) -> Option<NssDbKind> {
    if dir.join("cert9.db").is_file() || dir.join("pkcs11.txt").is_file() {
        Some(NssDbKind::Sql)
    } else if dir.join("cert8.db").is_file() {
        Some(NssDbKind::Dbm)
    } else {
        None
    }
}

/// Entrada de perfil de `profiles.ini`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IniProfile {
    pub name: String,
    pub path: String,
    pub is_relative: bool,
    pub default: bool,
}

/// Contenido de `profiles.ini`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfilesIni {
    /// `[General] Version=` (por defecto 1).
    pub version: u32,
    pub profiles: Vec<IniProfile>,
    /// `Default=` de la sección `[Install...]` elegida.
    pub install_default: Option<String>,
}

/// Analiza `profiles.ini` con las reglas de `ProfilesIni` (§3.6.2 de la especificación de almacenes).
pub fn parse_profiles_ini(text: &str) -> ProfilesIni {
    #[derive(PartialEq)]
    enum Sec {
        None,
        General,
        Profile,
        Install,
    }
    let mut ini = ProfilesIni {
        version: 1,
        ..Default::default()
    };
    let mut sec = Sec::None;
    let mut cur = IniProfile {
        is_relative: true,
        ..Default::default()
    };
    let mut install: Option<(String, bool)> = None;
    let mut cur_install: (Option<String>, bool) = (None, false);
    let flush_profile = |cur: &mut IniProfile, ini: &mut ProfilesIni| {
        if !cur.name.is_empty() && !cur.path.is_empty() {
            ini.profiles.push(cur.clone());
        }
        *cur = IniProfile {
            is_relative: true,
            ..Default::default()
        };
    };
    let flush_install = |ci: &mut (Option<String>, bool), install: &mut Option<(String, bool)>| {
        if let Some(d) = ci.0.take() {
            // Una sección posterior sustituye a la anterior salvo que esta declarase Locked=.
            if !install.as_ref().is_some_and(|(_, locked)| *locked) {
                *install = Some((d, ci.1));
            }
        }
        ci.1 = false;
    };
    for raw in text.lines().take(4096) {
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        if line.is_empty() || line.starts_with('[') {
            match sec {
                Sec::Profile => flush_profile(&mut cur, &mut ini),
                Sec::Install => flush_install(&mut cur_install, &mut install),
                _ => {}
            }
            sec = Sec::None;
            if lower.starts_with("[profile") {
                sec = Sec::Profile;
            } else if lower == "[general]" {
                sec = Sec::General;
            } else if lower.starts_with("[install") {
                sec = Sec::Install;
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match sec {
            Sec::General if k == "version" => ini.version = v.parse().unwrap_or(1),
            Sec::Profile => match k.as_str() {
                "name" => cur.name = v.to_string(),
                "path" => cur.path = v.to_string(),
                "isrelative" => cur.is_relative = v == "1",
                "default" => cur.default = v == "1",
                _ => {}
            },
            Sec::Install => match k.as_str() {
                "default" => cur_install.0 = Some(v.to_string()),
                "locked" => cur_install.1 = true,
                _ => {}
            },
            _ => {}
        }
    }
    match sec {
        Sec::Profile => flush_profile(&mut cur, &mut ini),
        Sec::Install => flush_install(&mut cur_install, &mut install),
        _ => {}
    }
    ini.install_default = install.map(|(d, _)| d);
    ini
}

/// Ruta absoluta de un perfil (honra `IsRelative`, que Java ignoraba).
pub fn profile_path(ini_dir: &Path, p: &IniProfile) -> PathBuf {
    if p.is_relative {
        ini_dir.join(&p.path)
    } else {
        PathBuf::from(&p.path)
    }
}

/// `true` si el perfil es «ficticio» (menos de 10 entradas o sin `key4.db`/`key3.db`).
pub fn is_dummy_profile(dir: &Path) -> bool {
    let n = std::fs::read_dir(dir).map(|r| r.count()).unwrap_or(0);
    n < 10 || !(dir.join("key4.db").is_file() || dir.join("key3.db").is_file())
}

/// Perfil «actual» con el algoritmo de `NSPreferences.getFireFoxUserProfileDirectory`.
pub fn select_current_profile(ini_dir: &Path, ini: &ProfilesIni) -> Option<PathBuf> {
    let paths: Vec<(PathBuf, &IniProfile)> = ini
        .profiles
        .iter()
        .map(|p| (profile_path(ini_dir, p), p))
        .collect();
    let valid = |p: &Path| !is_dummy_profile(p);
    if ini.version == 1 {
        for (p, _) in &paths {
            if valid(p)
                && (p.join("lock").exists()
                    || p.join("lock").is_symlink()
                    || p.join("parent.lock").exists())
            {
                return Some(p.clone());
            }
        }
    } else if let Some(d) = &ini.install_default
        && let Some((p, _)) = paths.iter().find(|(_, ip)| &ip.path == d)
        && valid(p)
    {
        return Some(p.clone());
    }
    if let Some((p, _)) = paths.iter().find(|(p, ip)| ip.default && valid(p)) {
        return Some(p.clone());
    }
    paths
        .iter()
        .filter(|(p, _)| valid(p))
        .max_by_key(|(p, _)| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .map(|(p, _)| p.clone())
        .or_else(|| paths.first().map(|(p, _)| p.clone()))
}

/// Directorios que pueden contener `profiles.ini` para un usuario.
pub fn profile_roots(os: Os, home: &Path) -> Vec<(PathBuf, FirefoxFlavor)> {
    match os {
        Os::Windows => vec![(
            home.join(r"AppData\Roaming\Mozilla\Firefox"),
            FirefoxFlavor::Classic,
        )],
        Os::MacOs => vec![
            (
                home.join("Library/Application Support/Firefox"),
                FirefoxFlavor::Classic,
            ),
            // Volúmenes sensibles a mayúsculas (Java usaba la minúscula).
            (
                home.join("Library/Application Support/firefox"),
                FirefoxFlavor::Classic,
            ),
        ],
        Os::Linux => vec![
            (home.join(".mozilla/firefox"), FirefoxFlavor::Classic),
            (home.join(".config/mozilla/firefox"), FirefoxFlavor::Xdg),
            (
                home.join("snap/firefox/common/.mozilla/firefox"),
                FirefoxFlavor::Snap,
            ),
            (
                home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
                FirefoxFlavor::Flatpak,
            ),
            (
                home.join(".var/app/org.mozilla.firefox/config/mozilla/firefox"),
                FirefoxFlavor::Flatpak,
            ),
        ],
    }
}

/// Todos los perfiles de todos los `profiles.ini` de los usuarios indicados (sin duplicados).
pub fn discover_profiles(ctx: &Context, users: &[UserHome]) -> Vec<FirefoxProfile> {
    let mut out: Vec<FirefoxProfile> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for u in users {
        for (root, flavor) in profile_roots(ctx.os, &u.home) {
            let ini_path = root.join("profiles.ini");
            let Ok(text) = std::fs::read_to_string(&ini_path) else {
                continue;
            };
            let ini = parse_profiles_ini(&text);
            for p in &ini.profiles {
                let dir = profile_path(&root, p);
                if !dir.is_dir() {
                    continue;
                }
                let canon = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
                if seen.contains(&canon) {
                    continue;
                }
                seen.push(canon);
                out.push(FirefoxProfile {
                    dir,
                    name: p.name.clone(),
                    ini: ini_path.clone(),
                    flavor,
                    user: u.name.clone(),
                    is_default: p.default,
                });
            }
        }
    }
    out
}

/// Preferencia de confianza en las raíces del sistema.
pub const ENTERPRISE_ROOTS_PREF: &str = "security.enterprise_roots.enabled";
const USERJS_HEADER: &str = "// === PROPIEDADES PERSONALIZADAS DE CONFIGURACION ===\r\n";
const USERJS_COMMENT: &str =
    "\r\n// Confianza en los certificados raices del almacen del sistema\r\n";

fn pref_line(enable: bool) -> String {
    format!("user_pref(\"{ENTERPRISE_ROOTS_PREF}\", {enable});")
}

/// Valor de `security.enterprise_roots.enabled` en el `user.js` del perfil.
pub fn enterprise_roots_state(profile_dir: &Path) -> Option<bool> {
    let text = std::fs::read_to_string(profile_dir.join("user.js")).ok()?;
    text.lines()
        .rfind(|l| l.contains(ENTERPRISE_ROOTS_PREF) && !l.trim_start().starts_with("//"))
        .map(|l| l.contains("true"))
}

/// Escribe `security.enterprise_roots.enabled` en `user.js` con el algoritmo de Java
/// (sustituye las líneas existentes o añade comentario + preferencia; CRLF; UTF-8). No
/// reescribe el fichero si ya tiene el valor pedido. Devuelve `true` si lo modificó.
pub fn set_enterprise_roots(profile_dir: &Path, enable: bool) -> Result<bool> {
    let path = profile_dir.join("user.js");
    let line = pref_line(enable);
    let new_text = match fsutil::read_text_opt(&path)? {
        Some(text) => {
            if enterprise_roots_state(profile_dir) == Some(enable)
                && text
                    .lines()
                    .filter(|l| l.contains(ENTERPRISE_ROOTS_PREF))
                    .all(|l| l.trim() == line || l.trim_start().starts_with("//"))
            {
                return Ok(false);
            }
            let mut found = false;
            let mut out = String::new();
            for l in text.lines() {
                if l.contains(ENTERPRISE_ROOTS_PREF) {
                    found = true;
                    out.push_str(&line);
                } else {
                    out.push_str(l.trim_end_matches('\r'));
                }
                out.push_str("\r\n");
            }
            if !found {
                out.push_str(USERJS_COMMENT);
                out.push_str(&line);
                out.push_str("\r\n");
            }
            out
        }
        None => format!("{USERJS_HEADER}{USERJS_COMMENT}{line}\r\n"),
    };
    fsutil::write_atomic(&path, new_text.as_bytes(), None)?;
    Ok(true)
}

/// Elimina la preferencia de `user.js` (desinstalación). Devuelve `true` si cambió algo.
pub fn remove_enterprise_roots(profile_dir: &Path) -> Result<bool> {
    let path = profile_dir.join("user.js");
    let Some(text) = fsutil::read_text_opt(&path)? else {
        return Ok(false);
    };
    if !text.contains(ENTERPRISE_ROOTS_PREF) {
        return Ok(false);
    }
    let mut out = String::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        let lt = l.trim_end_matches('\r');
        // Comentario que Java añadía justo antes de la preferencia.
        if lt.contains("// Confianza en los certificados raices del almacen del sistema")
            && lines
                .get(i + 1)
                .is_some_and(|n| n.contains(ENTERPRISE_ROOTS_PREF))
        {
            continue;
        }
        if lt.contains(ENTERPRISE_ROOTS_PREF) {
            continue;
        }
        out.push_str(lt);
        out.push_str("\r\n");
    }
    if out.trim().is_empty() || out.trim() == USERJS_HEADER.trim() {
        std::fs::remove_file(&path).map_err(io_at(&path))?;
    } else {
        fsutil::write_atomic(&path, out.as_bytes(), None)?;
    }
    Ok(true)
}

/// `true` si hay algún Firefox en ejecución (cualquier variante).
pub fn is_running(ctx: &Context) -> bool {
    match ctx.os {
        Os::Windows => ctx
            .runner
            .run(&Cmd::new("tasklist").args(["/FI", "IMAGENAME eq firefox.exe", "/NH"]))
            .map(|o| o.stdout.to_ascii_lowercase().contains("firefox.exe"))
            .unwrap_or(false),
        Os::MacOs | Os::Linux => ctx
            .runner
            .run(&Cmd::new("pgrep").args(["-x", "-i", "firefox|firefox-bin|firefox-esr|GeckoMain"]))
            .map(|o| o.success())
            .unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INI: &str = "[Install4F96D1932A9F858E]\nDefault=Profiles/abcd.default-release\nLocked=1\n\n[Profile1]\nName=default\nIsRelative=1\nPath=Profiles/xyz.default\nDefault=1\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abcd.default-release\n\n[Profile2]\nName=externo\nIsRelative=0\nPath=/srv/perfiles/ext\n\n[General]\nStartWithLastProfile=1\nVersion=2\n";

    #[test]
    fn analiza_profiles_ini() {
        let ini = parse_profiles_ini(INI);
        assert_eq!(ini.version, 2);
        assert_eq!(ini.profiles.len(), 3);
        assert_eq!(
            ini.install_default.as_deref(),
            Some("Profiles/abcd.default-release")
        );
        assert!(!ini.profiles[2].is_relative);
        assert_eq!(
            profile_path(Path::new("/h/.mozilla/firefox"), &ini.profiles[2]),
            PathBuf::from("/srv/perfiles/ext")
        );
    }

    #[test]
    fn descubre_perfiles_de_todas_las_variantes() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let home = ctx.paths.home.clone();
        for (root, prof) in [
            (".mozilla/firefox", "a.default"),
            ("snap/firefox/common/.mozilla/firefox", "b.default"),
            (".var/app/org.mozilla.firefox/.mozilla/firefox", "c.default"),
        ] {
            let r = home.join(root);
            std::fs::create_dir_all(r.join(prof)).unwrap();
            std::fs::write(
                r.join("profiles.ini"),
                format!("[Profile0]\nName=x\nIsRelative=1\nPath={prof}\nDefault=1\n"),
            )
            .unwrap();
        }
        let users = ctx.user_homes(false);
        let profs = discover_profiles(&ctx, &users);
        assert_eq!(
            profs.len(),
            3,
            "Java ignoraba el clásico si había snap y nunca veía flatpak"
        );
        assert!(profs.iter().any(|p| p.flavor == FirefoxFlavor::Flatpak));
    }

    #[test]
    fn user_js_como_java_e_idempotente() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        assert!(set_enterprise_roots(d, true).unwrap());
        let text = std::fs::read_to_string(d.join("user.js")).unwrap();
        assert_eq!(
            text,
            "// === PROPIEDADES PERSONALIZADAS DE CONFIGURACION ===\r\n\r\n// Confianza en los certificados raices del almacen del sistema\r\nuser_pref(\"security.enterprise_roots.enabled\", true);\r\n"
        );
        assert!(!set_enterprise_roots(d, true).unwrap(), "sin cambios");
        assert_eq!(enterprise_roots_state(d), Some(true));
        std::fs::write(
            d.join("user.js"),
            "user_pref(\"a\", 1);\nuser_pref(\"security.enterprise_roots.enabled\", false);\n",
        )
        .unwrap();
        assert!(set_enterprise_roots(d, true).unwrap());
        assert_eq!(
            std::fs::read_to_string(d.join("user.js")).unwrap(),
            "user_pref(\"a\", 1);\r\nuser_pref(\"security.enterprise_roots.enabled\", true);\r\n"
        );
        assert!(remove_enterprise_roots(d).unwrap());
        assert_eq!(
            std::fs::read_to_string(d.join("user.js")).unwrap(),
            "user_pref(\"a\", 1);\r\n"
        );
        assert_eq!(enterprise_roots_state(d), None);
    }
}
