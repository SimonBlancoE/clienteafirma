//! Contexto de ejecución: sistema operativo, privilegios, rutas base, identidad de la
//! aplicación, ejecutor de mandatos y registro. Todas las funciones del crate reciben un
//! [`Context`], lo que permite probarlas contra directorios temporales, un registro en
//! memoria y un ejecutor simulado.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::exec::{CommandRunner, FakeRunner, SystemRunner};
use crate::registry::{MemoryRegistry, Registry, system_registry};
use crate::trust::windows::{MemoryCertStore, WinCertStore, system_cert_store};

/// Sistema operativo de destino.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Os {
    Windows,
    MacOs,
    Linux,
}

impl Os {
    /// Sistema operativo para el que se ha compilado.
    pub fn current() -> Os {
        if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::MacOs
        } else {
            Os::Linux
        }
    }
}

/// Identidad de la aplicación instalada (rutas del ejecutable, nombres, identificadores).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppIdentity {
    /// Ejecutable de la aplicación (manejador de `afirma://` y menús contextuales).
    pub exe: PathBuf,
    /// Directorio de instalación (en Java, el directorio de `autofirma.jar`); aquí se buscan
    /// primero `autofirma.pfx` y `Autofirma_ROOT.cer`.
    pub app_dir: PathBuf,
    /// Icono (`.ico` en Windows, `.png`/`.svg` en Linux). Por defecto, el propio ejecutable en Windows.
    pub icon: Option<PathBuf>,
    /// Paquete `.app` en macOS.
    pub macos_bundle: Option<PathBuf>,
    /// Identificador del paquete de macOS (debe coincidir con `CFBundleIdentifier`).
    pub macos_bundle_id: String,
    /// Identificador del fichero `.desktop` en Linux (sin extensión).
    pub desktop_id: String,
    /// Nombre visible.
    pub display_name: String,
    /// Versión (para el registro de Windows y los ficheros `.desktop`).
    pub version: String,
}

/// Identificador del paquete de macOS de AutoFirma-rs (`CFBundleIdentifier` de
/// `packaging/macos/Info.plist`). Es propio para no confundirse con la versión Java en
/// Launch Services; las directivas MDM ya desplegadas para Java se siguen leyendo de
/// [`LEGACY_MACOS_PREFS_DOMAIN`].
pub const MACOS_BUNDLE_ID: &str = "io.github.autofirma-rs.AutoFirma";

/// Dominio de preferencias gestionadas de la versión Java (compatibilidad con perfiles
/// MDM existentes; menor prioridad que el dominio propio).
pub const LEGACY_MACOS_PREFS_DOMAIN: &str = "es.gob.afirma.simpleafirma.osx";

/// Identificador del fichero `.desktop` (paquetes RPM de Java: `autofirma.desktop`).
pub const DESKTOP_ID: &str = "autofirma";

/// Nombre visible de la aplicación.
pub const DISPLAY_NAME: &str = "AutoFirma";

impl AppIdentity {
    /// Identidad a partir del ejecutable en curso.
    pub fn current() -> Self {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("autofirma"));
        let mut id = Self::for_exe(exe);
        // Dentro de una AppImage el ejecutable está en un montaje temporal
        // (/tmp/.mount_*); al registrar el protocolo hay que usar la propia AppImage.
        if let Some(appimage) = std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_file()) {
            id.exe = appimage;
        }
        id
    }

    /// Identidad para un ejecutable dado.
    pub fn for_exe(exe: PathBuf) -> Self {
        let app_dir = exe
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        // Dentro de un paquete .app: <bundle>/Contents/MacOS/<exe>
        let macos_bundle = app_dir
            .parent()
            .and_then(|contents| contents.parent())
            .filter(|b| b.extension().is_some_and(|e| e == "app"))
            .map(Path::to_path_buf);
        Self {
            exe,
            app_dir,
            icon: None,
            macos_bundle,
            macos_bundle_id: MACOS_BUNDLE_ID.into(),
            desktop_id: DESKTOP_ID.into(),
            display_name: DISPLAY_NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// Rutas base del sistema y del usuario.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Paths {
    /// Raíz del sistema de ficheros para las rutas absolutas de Unix (`/` en ejecución real;
    /// un directorio temporal en pruebas). Ver [`Context::sys`].
    pub root: PathBuf,
    /// Directorio personal del usuario actual.
    pub home: PathBuf,
    /// Nombre del usuario actual.
    pub user_name: Option<String>,
    /// Directorio de configuración del usuario para AutoFirma-rs (preferencias nativas).
    pub user_config_dir: PathBuf,
    /// Directorio de configuración del sistema para AutoFirma-rs (preferencias de sistema,
    /// directivas en Linux y estado de la instalación).
    pub system_config_dir: PathBuf,
    /// Directorio «alternativo» de Java: Windows `%ALLUSERSPROFILE%\Autofirma`, Linux
    /// `~/.afirma/Autofirma`, macOS `~/Library/Application Support/Autofirma`.
    pub alternative_dir: PathBuf,
    /// Windows: `%ProgramData%`.
    pub program_data: Option<PathBuf>,
    /// Directorio que contiene los perfiles de usuario (Windows `C:\Users`, macOS `/Users`).
    pub users_dir: Option<PathBuf>,
    /// Windows: `%ProgramFiles%` y `%ProgramFiles(x86)%`.
    pub program_files: Vec<PathBuf>,
    /// Directorio temporal.
    pub temp_dir: PathBuf,
}

/// Contexto de ejecución.
#[derive(Clone)]
pub struct Context {
    /// Sistema operativo.
    pub os: Os,
    /// `true` si el proceso tiene privilegios de administrador (root / elevado).
    pub elevated: bool,
    /// Rutas.
    pub paths: Paths,
    /// Identidad de la aplicación.
    pub app: AppIdentity,
    /// Ejecutor de mandatos.
    pub runner: Arc<dyn CommandRunner>,
    /// Registro de Windows (vacío fuera de Windows).
    pub registry: Arc<dyn Registry>,
    /// Almacén de certificados `ROOT` de Windows (no disponible fuera de Windows).
    pub win_certs: Arc<dyn WinCertStore>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("os", &self.os)
            .field("elevated", &self.elevated)
            .field("paths", &self.paths)
            .finish()
    }
}

/// Usuario del sistema con su directorio personal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UserHome {
    pub name: String,
    pub home: PathBuf,
    /// UID (Unix).
    pub uid: Option<u32>,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

impl Context {
    /// Contexto real del proceso en curso.
    pub fn detect(app: AppIdentity) -> Self {
        let os = Os::current();
        let base = directories::BaseDirs::new();
        let home = base
            .as_ref()
            .map(|b| b.home_dir().to_path_buf())
            .or_else(|| env_path("HOME"))
            .unwrap_or_else(|| PathBuf::from("."));
        let user_name = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).ok();
        let config_base = base
            .as_ref()
            .map(|b| b.config_dir().to_path_buf())
            .unwrap_or_else(|| home.join(".config"));
        let program_data = if os == Os::Windows {
            env_path("ProgramData")
                .or_else(|| env_path("ALLUSERSPROFILE"))
                .or_else(|| Some(PathBuf::from(r"C:\ProgramData")))
        } else {
            None
        };
        let (user_config_dir, system_config_dir, alternative_dir, users_dir) = match os {
            Os::Windows => {
                let pd = program_data.clone().unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
                let alt = env_path("ALLUSERSPROFILE")
                    .unwrap_or_else(|| pd.clone())
                    .join("Autofirma");
                let users = env_path("PUBLIC")
                    .and_then(|p| p.parent().map(Path::to_path_buf))
                    .or_else(|| home.parent().map(Path::to_path_buf))
                    .or_else(|| env_path("SystemDrive").map(|d| d.join("Users")));
                (config_base.join("AutoFirma"), pd.join("AutoFirma"), alt, users)
            }
            Os::MacOs => (
                config_base.join("AutoFirma"),
                PathBuf::from("/Library/Application Support/AutoFirma"),
                home.join("Library/Application Support/Autofirma"),
                Some(PathBuf::from("/Users")),
            ),
            Os::Linux => (
                config_base.join("autofirma"),
                PathBuf::from("/etc/autofirma"),
                home.join(".afirma/Autofirma"),
                None,
            ),
        };
        let mut program_files = Vec::new();
        if os == Os::Windows {
            for v in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"] {
                if let Some(p) = env_path(v)
                    && !program_files.contains(&p)
                {
                    program_files.push(p);
                }
            }
        }
        Self {
            os,
            elevated: detect_elevated(),
            paths: Paths {
                root: PathBuf::from("/"),
                home,
                user_name,
                user_config_dir,
                system_config_dir,
                alternative_dir,
                program_data,
                users_dir,
                program_files,
                temp_dir: std::env::temp_dir(),
            },
            app,
            runner: Arc::new(SystemRunner),
            registry: system_registry(),
            win_certs: system_cert_store(),
        }
    }

    /// Contexto de pruebas: todo bajo `root` (que debe existir), registro en memoria y
    /// ejecutor simulado que responde con éxito y sin salida.
    pub fn for_tests(os: Os, root: &Path) -> Self {
        let home = root.join("home/usuario");
        let (user_config_dir, system_config_dir, alternative_dir, program_data, users_dir) = match os {
            Os::Windows => (
                root.join("Users/usuario/AppData/Roaming/AutoFirma"),
                root.join("ProgramData/AutoFirma"),
                root.join("ProgramData/Autofirma"),
                Some(root.join("ProgramData")),
                Some(root.join("Users")),
            ),
            Os::MacOs => (
                home.join("Library/Application Support/AutoFirma"),
                root.join("Library/Application Support/AutoFirma"),
                home.join("Library/Application Support/Autofirma"),
                None,
                Some(root.join("Users")),
            ),
            Os::Linux => (
                home.join(".config/autofirma"),
                root.join("etc/autofirma"),
                home.join(".afirma/Autofirma"),
                None,
                None,
            ),
        };
        let home = if os == Os::Windows {
            root.join("Users/usuario")
        } else {
            home
        };
        let app_dir = root.join("opt/autofirma");
        let mut app = AppIdentity::for_exe(app_dir.join(if os == Os::Windows {
            "Autofirma.exe"
        } else {
            "autofirma"
        }));
        app.version = "1.0.0".into();
        let _ = std::fs::create_dir_all(&home);
        Self {
            os,
            elevated: false,
            paths: Paths {
                root: root.to_path_buf(),
                home,
                user_name: Some("usuario".into()),
                user_config_dir,
                system_config_dir,
                alternative_dir,
                program_data,
                users_dir,
                program_files: if os == Os::Windows {
                    vec![root.join("Program Files")]
                } else {
                    Vec::new()
                },
                temp_dir: root.join("tmp"),
            },
            app,
            runner: Arc::new(FakeRunner::default()),
            registry: Arc::new(MemoryRegistry::new()),
            win_certs: Arc::new(MemoryCertStore::default()),
        }
    }

    /// Resuelve una ruta absoluta de estilo Unix (`/etc/...`) respecto a la raíz del contexto.
    pub fn sys(&self, abs: &str) -> PathBuf {
        if self.paths.root == Path::new("/") {
            PathBuf::from(abs)
        } else {
            self.paths.root.join(abs.trim_start_matches('/'))
        }
    }

    /// Usuarios cuyos perfiles se deben configurar: todos (si `all_users` y el proceso tiene
    /// privilegios) o solo el actual.
    pub fn user_homes(&self, all_users: bool) -> Vec<UserHome> {
        let current = UserHome {
            name: self.paths.user_name.clone().unwrap_or_default(),
            home: self.paths.home.clone(),
            uid: current_uid(),
        };
        if !(all_users && self.elevated) {
            return vec![current];
        }
        let mut out = match self.os {
            Os::Linux => self.linux_users(),
            Os::MacOs | Os::Windows => self.dir_users(),
        };
        if !out.iter().any(|u| u.home == current.home) && current.home.is_dir() && current.uid != Some(0) {
            out.push(current);
        }
        out
    }

    /// Usuarios de `/etc/passwd` con UID de usuario normal (≥ 1000) o con el directorio
    /// personal bajo un `home/` (criterio de Java), cuyo directorio exista.
    fn linux_users(&self) -> Vec<UserHome> {
        let Ok(passwd) = std::fs::read_to_string(self.sys("/etc/passwd")) else {
            return Vec::new();
        };
        let mut out: Vec<UserHome> = Vec::new();
        for line in passwd.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                continue;
            }
            let uid: Option<u32> = f[2].parse().ok();
            let home = f[5];
            let normal = uid.is_some_and(|u| (1000..60000).contains(&u));
            if !(normal || home.to_ascii_lowercase().contains("home/")) || home.is_empty() || home == "/" {
                continue;
            }
            let h = self.sys(home);
            if h.is_dir() && !out.iter().any(|u| u.home == h) {
                out.push(UserHome {
                    name: f[0].to_string(),
                    home: h,
                    uid,
                });
            }
        }
        out
    }

    /// Usuarios como subdirectorios de `C:\Users` o `/Users` (excluidos los perfiles especiales).
    fn dir_users(&self) -> Vec<UserHome> {
        const SKIP: &[&str] = &[
            "default",
            "default user",
            "public",
            "all users",
            "defaultuser0",
            "wdagutilityaccount",
            "shared",
            "guest",
        ];
        let Some(dir) = &self.paths.users_dir else {
            return Vec::new();
        };
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || SKIP.contains(&name.to_ascii_lowercase().as_str()) {
                continue;
            }
            let p = e.path();
            if p.is_dir() {
                out.push(UserHome {
                    uid: unix_uid_of(&p),
                    name,
                    home: p,
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

#[cfg(unix)]
fn unix_uid_of(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.uid())
}

#[cfg(not(unix))]
fn unix_uid_of(_p: &Path) -> Option<u32> {
    None
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    // SAFETY: getuid no tiene precondiciones.
    Some(unsafe { libc::getuid() })
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// Detecta si el proceso tiene privilegios de administrador.
pub fn detect_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid no tiene precondiciones.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // SAFETY: FFI con shell32; sin parámetros.
        unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usuarios_linux_desde_passwd() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Linux, t.path());
        std::fs::create_dir_all(t.path().join("etc")).unwrap();
        std::fs::create_dir_all(t.path().join("home/ana")).unwrap();
        std::fs::create_dir_all(t.path().join("srv/luis")).unwrap();
        std::fs::write(
            t.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/bash\nluis:x:1001:1001::/srv/luis:/bin/zsh\nnobody:x:65534:65534::/var/lib/nobody:/bin/false\nfalta:x:1002:1002::/home/falta:/bin/bash\n",
        )
        .unwrap();
        assert_eq!(ctx.user_homes(true).len(), 1, "sin privilegios solo el usuario actual");
        ctx.elevated = true;
        let names: Vec<String> = ctx.user_homes(true).into_iter().map(|u| u.name).collect();
        assert!(names.contains(&"ana".to_string()));
        assert!(
            names.contains(&"luis".to_string()),
            "Java omitía los homes fuera de /home"
        );
        assert!(!names.contains(&"falta".to_string()));
        assert!(!names.contains(&"nobody".to_string()));
    }
}
