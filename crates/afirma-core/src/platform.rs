//! Información de la plataforma (`es.gob.afirma.core.misc.Platform`, §8.1):
//! sistema operativo, arquitectura, navegador, directorios del usuario y del
//! sistema.

use std::path::PathBuf;

/// Separador de línea de la plataforma (`System.lineSeparator()`).
#[cfg(windows)]
pub const LINE_SEPARATOR: &str = "\r\n";
/// Separador de línea de la plataforma (`System.lineSeparator()`).
#[cfg(not(windows))]
pub const LINE_SEPARATOR: &str = "\n";

/// Sistema operativo (`Platform.OS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    Linux,
    Solaris,
    MacOsX,
    Android,
    Other,
}

impl Os {
    /// Nombre de la constante Java (`WINDOWS`, `LINUX`, `MACOSX`...).
    pub fn java_name(self) -> &'static str {
        match self {
            Self::Windows => "WINDOWS",
            Self::Linux => "LINUX",
            Self::Solaris => "SOLARIS",
            Self::MacOsX => "MACOSX",
            Self::Android => "ANDROID",
            Self::Other => "OTHER",
        }
    }

    /// Clasifica un valor de `os.name` de Java con las mismas reglas que
    /// `Platform.recoverOsName` (`indows`, `inux`, `SunOS`/`olaris`,
    /// `Mac OS X`).
    pub fn from_java_os_name(os_name: &str, java_vm_name: Option<&str>) -> Os {
        if os_name.contains("indows") {
            Os::Windows
        } else if os_name.contains("inux") {
            if java_vm_name == Some("Dalvik") {
                Os::Android
            } else {
                Os::Linux
            }
        } else if os_name.contains("SunOS") || os_name.contains("olaris") {
            Os::Solaris
        } else if os_name.starts_with("Mac OS X") {
            Os::MacOsX
        } else {
            Os::Other
        }
    }
}

/// Sistema operativo en el que se ejecuta el programa (`Platform.getOS()`).
pub fn os() -> Os {
    match std::env::consts::OS {
        "windows" => Os::Windows,
        "linux" => Os::Linux,
        "android" => Os::Android,
        "macos" => Os::MacOsX,
        "solaris" | "illumos" => Os::Solaris,
        _ => Os::Other,
    }
}

/// Indica si el sistema es de tipo Unix (`Platform.isUnixSystem`: Linux,
/// macOS o Solaris).
pub fn is_unix_system(os: Os) -> bool {
    matches!(os, Os::Linux | Os::MacOsX | Os::Solaris)
}

/// Arquitectura de la máquina (`Platform.MACHINE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    Arm64,
    Mips64,
    Mips32,
    Amd64,
    X86,
    Other,
}

impl Machine {
    /// Clasifica un valor de `os.arch` de Java (`Platform.getMachineType`).
    /// Ojo: Java devuelve `OTHER` para `i386`/`i686` y nunca devuelve ARM de
    /// 32 bits.
    pub fn from_java_os_arch(arch: &str) -> Machine {
        if arch == "aarch64" || arch.starts_with("arm64") {
            Machine::Arm64
        } else if arch == "mips64" {
            Machine::Mips64
        } else if arch == "mips" {
            Machine::Mips32
        } else if arch == "x86_64" || arch.starts_with("amd64") {
            Machine::Amd64
        } else if arch == "x86" {
            Machine::X86
        } else {
            Machine::Other
        }
    }
}

/// Arquitectura en la que se ejecuta el programa.
pub fn machine() -> Machine {
    Machine::from_java_os_arch(std::env::consts::ARCH)
}

/// Ancho de palabra del proceso, como `Platform.getJavaArch()` (`"32"` o
/// `"64"`).
pub fn java_arch() -> &'static str {
    if cfg!(target_pointer_width = "64") { "64" } else { "32" }
}

/// Navegador web (`Platform.BROWSER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    InternetExplorer,
    Firefox,
    Chrome,
    Safari,
    Opera,
    Other,
}

/// Identifica el navegador a partir del `User-Agent`
/// (`Platform.getBrowser`): busca en minúsculas, por orden, `msie`,
/// `firefox`, `chrome`, `safari` y `opera`.
pub fn browser(user_agent: Option<&str>) -> Browser {
    let Some(ua) = user_agent else { return Browser::Other };
    let ua = ua.to_lowercase();
    if ua.contains("msie") {
        Browser::InternetExplorer
    } else if ua.contains("firefox") {
        Browser::Firefox
    } else if ua.contains("chrome") {
        Browser::Chrome
    } else if ua.contains("safari") {
        Browser::Safari
    } else if ua.contains("opera") {
        Browser::Opera
    } else {
        Browser::Other
    }
}

/// Directorio del usuario (`user.home`), sin separador final.
pub fn user_home() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let home = std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .or_else(|| if cfg!(windows) { std::env::var_os("HOME") } else { None })
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    strip_trailing_separator(home)
}

fn strip_trailing_separator(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    let trimmed = s.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() || trimmed.len() == s.len() || trimmed.ends_with(':') {
        p
    } else {
        PathBuf::from(trimmed)
    }
}

/// Directorio temporal (`java.io.tmpdir`).
pub fn temp_dir() -> PathBuf {
    std::env::temp_dir()
}

/// Directorio de AutoFirma en el directorio del usuario (`~/.afirma`).
pub fn afirma_dir() -> PathBuf {
    user_home().join(crate::constants::AFIRMA_SUBDIR)
}

/// Ruta del almacén de confianza propio de AutoFirma
/// (`~/.afirma/TrustedCertsKeystore.jks`).
pub fn trusted_certs_keystore_path() -> PathBuf {
    afirma_dir().join(crate::constants::TRUSTSTORE_FILENAME)
}

/// Directorio raíz del sistema (`Platform.getSystemRoot`): `/` fuera de
/// Windows; en Windows, la variable de entorno `SystemRoot` o `C:\WINDOWS` si
/// existe `C:\WINDOWS\system32` (Java consulta por error una propiedad del
/// sistema con ese nombre, que normalmente no existe).
pub fn system_root() -> PathBuf {
    if os() != Os::Windows {
        return PathBuf::from(std::path::MAIN_SEPARATOR_STR);
    }
    if let Some(root) = std::env::var_os("SystemRoot").filter(|v| !v.is_empty()) {
        return PathBuf::from(root);
    }
    let default = PathBuf::from("C:\\WINDOWS");
    if default.join("system32").is_dir() {
        return default;
    }
    PathBuf::from(std::path::MAIN_SEPARATOR_STR)
}

/// Directorio de bibliotecas del sistema (`Platform.getSystemLibDir`): en
/// Windows `<raíz>\System32` (o `SysWOW64` en procesos de 32 bits si existe);
/// en Unix `/usr/lib<32|64>` si existe y si no `/usr/lib`.
pub fn system_lib_dir() -> PathBuf {
    if os() == Os::Windows {
        let root = system_root();
        if java_arch() == "32" {
            let wow = root.join("SysWOW64");
            if wow.is_dir() {
                return wow;
            }
        }
        return root.join("System32");
    }
    let canonical = PathBuf::from(format!("/usr/lib{}", java_arch()));
    if canonical.exists() {
        canonical
    } else {
        PathBuf::from("/usr/lib")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_classification() {
        assert_eq!(Os::from_java_os_name("Windows 11", None), Os::Windows);
        assert_eq!(Os::from_java_os_name("Linux", Some("Dalvik")), Os::Android);
        assert_eq!(Os::from_java_os_name("Linux", None), Os::Linux);
        assert_eq!(Os::from_java_os_name("Mac OS X", None), Os::MacOsX);
        assert_eq!(Os::from_java_os_name("SunOS", None), Os::Solaris);
        assert_eq!(Os::from_java_os_name("FreeBSD", None), Os::Other);
        assert_eq!(Machine::from_java_os_arch("amd64"), Machine::Amd64);
        assert_eq!(Machine::from_java_os_arch("arm64e"), Machine::Arm64);
        assert_eq!(Machine::from_java_os_arch("i386"), Machine::Other);
        assert_eq!(Machine::from_java_os_arch("x86"), Machine::X86);
        assert_eq!(
            browser(Some("Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537")),
            Browser::Chrome
        );
        assert_eq!(browser(Some("Mozilla/5.0 Firefox/120")), Browser::Firefox);
        assert_eq!(
            browser(Some("Mozilla/4.0 (compatible; MSIE 8.0)")),
            Browser::InternetExplorer
        );
        assert_eq!(browser(None), Browser::Other);
        assert!(is_unix_system(Os::MacOsX));
        assert!(!is_unix_system(Os::Windows));
    }

    #[test]
    fn directories() {
        let home = user_home();
        assert!(!home.as_os_str().is_empty());
        assert!(!home.to_string_lossy().ends_with('/') || home.to_string_lossy() == "/");
        assert!(afirma_dir().ends_with(".afirma"));
        assert!(trusted_certs_keystore_path().ends_with("TrustedCertsKeystore.jks"));
        if os() != Os::Windows {
            assert_eq!(system_root(), PathBuf::from("/"));
            assert!(system_lib_dir().to_string_lossy().starts_with("/usr/lib"));
        }
        assert_eq!(
            strip_trailing_separator(PathBuf::from("/home/u/")),
            PathBuf::from("/home/u")
        );
        assert_eq!(strip_trailing_separator(PathBuf::from("/")), PathBuf::from("/"));
        assert!(java_arch() == "64" || java_arch() == "32");
        let _ = machine();
        let _ = temp_dir();
    }
}
