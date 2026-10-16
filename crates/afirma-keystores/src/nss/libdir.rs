//! Localización de las bibliotecas NSS (`softokn3`) en cada sistema y
//! comprobación de arquitectura del binario (ELF, PE, Mach-O).
//!
//! Correcciones respecto a Java (ver `docs/deviations/afirma-keystores.md`):
//! - Linux: el triplete multiarquitectura se deriva del destino de
//!   compilación (`aarch64-linux-gnu`...) y la comprobación ELF compara
//!   `e_machine` con la arquitectura del proceso (Java solo aceptaba
//!   x86/x86-64, por lo que en aarch64 nunca encontraba NSS).
//! - `AFIRMA_NSS_HOME_ENV` se respeta (en Java se sobrescribía).
//! - macOS: también se buscan las ediciones Developer/Nightly/ESR de Firefox.
//! - Windows: si `compatibility.ini` no indica el directorio, se prueban las
//!   instalaciones habituales de Firefox.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::KeyStoreError;
use crate::kind::Os;
use crate::nss::profiles::{AFIRMA_NSS_HOME_ENV, MozEnv};
use crate::pkcs11::known::multiarch_triple;

/// Nombre del fichero de `softokn3` en cada sistema.
pub fn softokn_file_name(os: Os) -> &'static str {
    match os {
        Os::Windows => "softokn3.dll",
        Os::MacOs => "libsoftokn3.dylib",
        _ => "libsoftokn3.so",
    }
}

/// Dependencias que se precargan (por ruta absoluta) si la primera carga de
/// `softokn3` falla, en el orden de Java.
pub fn softokn_dependencies(os: Os) -> &'static [&'static str] {
    match os {
        Os::Windows => &[
            "msvcr100.dll",
            "msvcp100.dll",
            "msvcr120.dll",
            "msvcp120.dll",
            "vcruntime140.dll",
            "msvcp140.dll",
            "mozglue.dll",
            "nss3.dll",
            "mozutils.dll",
            "mozcrt19.dll",
            "nspr4.dll",
            "plds4.dll",
            "plc4.dll",
            "nssutil3.dll",
            "mozsqlite3.dll",
            "sqlite3.dll",
            "nssdbm3.dll",
            "freebl3.dll",
        ],
        Os::MacOs => &[
            "libmozglue.dylib",
            "libmozutils.dylib",
            "libnspr4.dylib",
            "libplds4.dylib",
            "libplc4.dylib",
            "libnssutil3.dylib",
            "libmozsqlite3.dylib",
            "libnss3.dylib",
        ],
        _ => &["libnspr4.so", "libplds4.so", "libplc4.so", "libnssutil3.so", "libsqlite3.so", "libmozsqlite3.so", "libsqlite3.so.0"],
    }
}

/// Directorio de bibliotecas del sistema de Java (`Platform.getSystemLibDir`
/// en UNIX): `/usr/lib64` si existe, si no `/usr/lib`.
fn unix_system_lib_dir() -> &'static str {
    if Path::new("/usr/lib64").is_dir() { "/usr/lib64" } else { "/usr/lib" }
}

/// Mayor versión numérica `firefox-<x.y.z>` en un directorio.
fn last_firefox_version(dir: &Path) -> Option<String> {
    let mut best: Option<(Vec<u64>, String)> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(v) = name.strip_prefix("firefox-") else { continue };
        let Ok(parts) = v.split('.').map(str::parse::<u64>).collect::<Result<Vec<_>, _>>() else { continue };
        let newer = match &best {
            None => true,
            Some((b, _)) => {
                let n = parts.len().max(b.len());
                let pad = |x: &Vec<u64>| (0..n).map(|i| *x.get(i).unwrap_or(&0)).collect::<Vec<_>>();
                pad(&parts) > pad(b)
            }
        };
        if newer {
            best = Some((parts, v.to_string()));
        }
    }
    best.map(|(_, s)| s)
}

/// Directorios candidatos de NSS en Linux/UNIX, en el orden de Java
/// (corregido para cualquier arquitectura) y solo los existentes.
pub fn unix_candidates() -> Vec<PathBuf> {
    let triple = multiarch_triple();
    let sys = unix_system_lib_dir();
    let bits64 = cfg!(target_pointer_width = "64");
    let mut v: Vec<String> = vec![format!("/usr/lib/{triple}/nss"), format!("/usr/lib/{triple}")];
    v.push(format!("{sys}/nss"));
    v.push(sys.to_string());
    v.push(format!("{sys}/firefox"));
    if let Some(ver) = last_firefox_version(Path::new(sys)) {
        v.push(format!("{sys}/firefox-{ver}"));
    }
    v.push(format!("{sys}/thunderbird"));
    v.push(if bits64 && Path::new("/lib64").is_dir() { "/lib64".into() } else { "/lib".into() });
    v.push("/opt/firefox".into());
    v.push(if bits64 && Path::new("/usr/lib64").is_dir() { "/usr/lib64".into() } else { "/usr/lib".into() });
    if let Some(ver) = last_firefox_version(Path::new("/opt")) {
        v.push(format!("/opt/firefox-{ver}"));
    }
    v.push("/opt/fedora-ds/clients/lib".into());
    v.push("/opt/google/chrome".into());
    let mut out: Vec<PathBuf> = Vec::new();
    for p in v {
        let Ok(real) = std::fs::canonicalize(&p) else { continue };
        if real.is_dir() && !out.contains(&PathBuf::from(&p)) {
            out.push(PathBuf::from(p));
        }
    }
    out
}

/// Directorios candidatos de NSS en macOS.
pub fn macos_candidates() -> Vec<PathBuf> {
    [
        "/Applications/Firefox.app/Contents/MacOS",
        "/Applications/Firefox ESR.app/Contents/MacOS",
        "/Applications/Firefox Developer Edition.app/Contents/MacOS",
        "/Applications/Firefox Nightly.app/Contents/MacOS",
        "/lib",
        "/usr/lib",
        "/usr/lib/nss",
        "/Applications/Minefield.app/Contents/MacOS",
        "/opt/homebrew/lib",
        "/usr/local/lib",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

/// `LastPlatformDir=` de `compatibility.ini` del perfil (Windows).
pub fn compatibility_ini_platform_dir(profile_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read(profile_dir.join("compatibility.ini")).ok()?;
    let text = String::from_utf8_lossy(&text);
    text.lines().take(512).find_map(|l| l.strip_prefix("LastPlatformDir=").map(|v| PathBuf::from(v.trim())))
}

/// Directorio de las bibliotecas NSS (`getSystemNSSLibDir`).
pub fn nss_lib_dir(env: &MozEnv, firefox_profile: Option<&Path>) -> Result<PathBuf, KeyStoreError> {
    let softokn = softokn_file_name(env.os);
    let usable = |dir: &Path| {
        let f = dir.join(softokn);
        f.is_file() && binary_arch_matches(&f)
    };
    if env.use_env_vars()
        && let Some(d) = env.var(AFIRMA_NSS_HOME_ENV) {
            let d = PathBuf::from(d);
            if d.is_dir() && usable(&d) {
                return Ok(d);
            }
            tracing::warn!("La variable de entorno '{AFIRMA_NSS_HOME_ENV}' apunta a un directorio que no existe o sobre el que no se tienen permisos de lectura, se ignorara");
        }
    let candidates: Vec<PathBuf> = match env.os {
        Os::Windows => {
            let mut v = Vec::new();
            if let Some(d) = firefox_profile.and_then(compatibility_ini_platform_dir) {
                v.push(d);
            }
            for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
                if let Some(pf) = env.var(var) {
                    v.push(Path::new(pf).join("Mozilla Firefox"));
                }
            }
            v
        }
        Os::MacOs => macos_candidates(),
        _ => unix_candidates(),
    };
    candidates
        .into_iter()
        .find(|d| usable(d))
        .ok_or_else(|| KeyStoreError::Firefox("No se han encontrado bibliotecas NSS instaladas en su sistema operativo".into()))
}

/// Indica si el binario (ELF, PE o Mach-O, incluido universal) es de la
/// arquitectura del proceso. Si no se reconoce el formato, `false`.
pub fn binary_arch_matches(path: &Path) -> bool {
    let mut head = vec![0u8; 4096];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) {
        Ok(n) => n,
        Err(_) => return false,
    };
    head.truncate(n);
    if head.starts_with(b"\x7fELF") {
        return elf_matches(&head);
    }
    if head.starts_with(b"MZ") {
        return pe_matches(path, &head);
    }
    macho_matches(&head)
}

/// `e_machine` esperado para la arquitectura de compilación.
fn expected_elf_machine() -> Option<u16> {
    Some(if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "x86") {
        3
    } else if cfg!(target_arch = "aarch64") {
        183
    } else if cfg!(target_arch = "arm") {
        40
    } else if cfg!(target_arch = "powerpc64") {
        21
    } else if cfg!(target_arch = "riscv64") {
        243
    } else if cfg!(target_arch = "s390x") {
        22
    } else if cfg!(target_arch = "loongarch64") {
        258
    } else {
        return None;
    })
}

fn elf_matches(h: &[u8]) -> bool {
    if h.len() < 20 {
        return false;
    }
    let class64 = h[4] == 2;
    if class64 != cfg!(target_pointer_width = "64") {
        return false;
    }
    let machine = if h[5] == 2 { u16::from_be_bytes([h[18], h[19]]) } else { u16::from_le_bytes([h[18], h[19]]) };
    expected_elf_machine().is_none_or(|m| m == machine)
}

fn pe_matches(path: &Path, head: &[u8]) -> bool {
    if head.len() < 0x40 {
        return false;
    }
    let off = u32::from_le_bytes([head[0x3c], head[0x3d], head[0x3e], head[0x3f]]) as usize;
    let mut buf = head.to_vec();
    if buf.len() < off + 6 {
        let Ok(data) = std::fs::read(path) else { return false };
        buf = data;
    }
    if buf.len() < off + 6 || &buf[off..off + 4] != b"PE\0\0" {
        return false;
    }
    let machine = u16::from_le_bytes([buf[off + 4], buf[off + 5]]);
    let expected: u16 = if cfg!(target_arch = "x86_64") {
        0x8664
    } else if cfg!(target_arch = "x86") {
        0x014c
    } else if cfg!(target_arch = "aarch64") {
        0xaa64
    } else {
        return true;
    };
    machine == expected
}

fn macho_matches(h: &[u8]) -> bool {
    const CPU_X86_64: u32 = 0x0100_0007;
    const CPU_ARM64: u32 = 0x0100_000c;
    let expected = if cfg!(target_arch = "x86_64") {
        CPU_X86_64
    } else if cfg!(target_arch = "aarch64") {
        CPU_ARM64
    } else {
        return false;
    };
    if h.len() < 8 {
        return false;
    }
    let magic_le = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    match magic_le {
        // MH_MAGIC_64 / MH_MAGIC (little-endian).
        0xfeed_facf | 0xfeed_face => u32::from_le_bytes([h[4], h[5], h[6], h[7]]) == expected,
        _ => {
            let magic_be = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
            // FAT_MAGIC / FAT_MAGIC_64: binario universal.
            if magic_be != 0xcafe_babe && magic_be != 0xcafe_babf {
                return false;
            }
            let entry = if magic_be == 0xcafe_babe { 20 } else { 32 };
            let n = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
            (0..n.min(16)).any(|i| {
                let o = 8 + i * entry;
                h.len() >= o + 4 && u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) == expected
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_detection() {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = if cfg!(target_pointer_width = "64") { 2 } else { 1 };
        h[5] = 1;
        let m = expected_elf_machine().unwrap();
        h[18..20].copy_from_slice(&m.to_le_bytes());
        assert!(elf_matches(&h));
        h[18..20].copy_from_slice(&999u16.to_le_bytes());
        assert!(!elf_matches(&h));
        // El propio ejecutable de pruebas es de la arquitectura actual.
        #[cfg(target_os = "linux")]
        assert!(binary_arch_matches(&std::env::current_exe().unwrap()));
    }

    #[test]
    fn macho_fat() {
        let cpu: u32 = if cfg!(target_arch = "aarch64") { 0x0100_000c } else { 0x0100_0007 };
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        h[4..8].copy_from_slice(&2u32.to_be_bytes());
        h[8..12].copy_from_slice(&0x0100_0012u32.to_be_bytes());
        h[28..32].copy_from_slice(&cpu.to_be_bytes());
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            assert!(macho_matches(&h));
        }
        h[28..32].copy_from_slice(&0x0100_0012u32.to_be_bytes());
        assert!(!macho_matches(&h));
    }

    #[test]
    fn firefox_versions_and_compat_ini() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["firefox-9.0", "firefox-10.0.1", "firefox-10.0", "firefox-esr", "otro"] {
            std::fs::create_dir(tmp.path().join(d)).unwrap();
        }
        assert_eq!(last_firefox_version(tmp.path()).as_deref(), Some("10.0.1"));
        std::fs::write(tmp.path().join("compatibility.ini"), "[Compatibility]\nLastVersion=1\nLastPlatformDir=C:\\Program Files\\Mozilla Firefox \nLastAppDir=x\n").unwrap();
        assert_eq!(compatibility_ini_platform_dir(tmp.path()).unwrap(), PathBuf::from("C:\\Program Files\\Mozilla Firefox"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn finds_system_nss_on_this_host_if_installed() {
        let env = MozEnv::current();
        match nss_lib_dir(&env, None) {
            Ok(d) => assert!(d.join("libsoftokn3.so").is_file()),
            Err(e) => eprintln!("NSS no instalado en este sistema: {e}"),
        }
    }
}
