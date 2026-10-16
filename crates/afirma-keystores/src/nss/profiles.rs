//! Localización de `profiles.ini` de Firefox, su interpretación
//! (`ProfilesIni`) y la elección del perfil activo
//! (`NSPreferences.getFireFoxUserProfileDirectory`), y localización de la
//! base de datos NSS compartida (`SharedNssUtil`).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::error::KeyStoreError;
use crate::kind::Os;

/// Entorno en el que se buscan los perfiles y bibliotecas: sistema
/// operativo, directorio personal y variables de entorno. Se puede
/// construir a mano en las pruebas.
#[derive(Debug, Clone)]
pub struct MozEnv {
    pub os: Os,
    pub home: PathBuf,
    pub user_name: Option<String>,
    pub vars: BTreeMap<String, String>,
}

/// Variable (o propiedad Java) que habilita `AFIRMA_NSS_PROFILES_INI` y
/// `AFIRMA_NSS_HOME_ENV`.
pub const USE_ENV_VARS: &str = "es.gob.afirma.keystores.mozilla.UseEnvironmentVariables";
/// Alias con un nombre de variable de entorno convencional (mejora).
pub const USE_ENV_VARS_ALT: &str = "AFIRMA_NSS_USE_ENVIRONMENT_VARIABLES";
/// Ruta explícita de `profiles.ini`.
pub const AFIRMA_NSS_PROFILES_INI: &str = "AFIRMA_NSS_PROFILES_INI";
/// Directorio explícito de las bibliotecas NSS.
pub const AFIRMA_NSS_HOME_ENV: &str = "AFIRMA_NSS_HOME_ENV";

impl MozEnv {
    /// Entorno del proceso actual.
    pub fn current() -> MozEnv {
        let home = directories::BaseDirs::new()
            .map(|d| d.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let user_name = std::env::var("USER").ok().or_else(|| std::env::var("USERNAME").ok());
        MozEnv {
            os: Os::current(),
            home,
            user_name,
            vars: std::env::vars().collect(),
        }
    }

    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str).or_else(|| {
            // Windows no distingue mayúsculas en los nombres de variables.
            if self.os == Os::Windows {
                self.vars
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            } else {
                None
            }
        })
    }

    /// `Boolean.parseBoolean(getenv(name))`.
    pub fn flag(&self, name: &str) -> bool {
        self.var(name).is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    /// Variables de entorno de NSS habilitadas
    /// (`es.gob.afirma.keystores.mozilla.UseEnvironmentVariables`).
    pub fn use_env_vars(&self) -> bool {
        self.flag(USE_ENV_VARS) || self.flag(USE_ENV_VARS_ALT)
    }

    /// Directorio `AppData\Roaming` de Windows: variable `AppData` o
    /// `C:\Users\<usuario>\AppData\Roaming` si existe.
    pub fn windows_app_data(&self) -> Option<PathBuf> {
        if let Some(v) = self.var("AppData") {
            return Some(PathBuf::from(v));
        }
        let user = self.user_name.as_deref()?;
        let p = PathBuf::from(format!("C:\\Users\\{user}\\AppData\\Roaming"));
        p.is_dir().then_some(p)
    }

    /// Directorio de configuración XDG (`$XDG_CONFIG_HOME` o `~/.config`).
    fn xdg_config(&self) -> PathBuf {
        match self.var("XDG_CONFIG_HOME") {
            Some(v) if Path::new(v).is_absolute() => PathBuf::from(v),
            _ => self.home.join(".config"),
        }
    }
}

/// Rutas candidatas de `profiles.ini` en orden (sin la variable
/// `AFIRMA_NSS_PROFILES_INI`). En Linux, tras la de snap se añaden las de
/// Flatpak (no soportadas por Java) y la de XDG (Firefox 147+); la última
/// (`~/.mozilla/firefox`) se devuelve aunque no exista.
pub fn profiles_ini_candidates(env: &MozEnv) -> Vec<PathBuf> {
    match env.os {
        Os::Windows => env
            .windows_app_data()
            .map(|a| a.join("Mozilla").join("Firefox").join("profiles.ini"))
            .into_iter()
            .collect(),
        Os::MacOs => vec![env.home.join("Library/Application Support/Firefox/profiles.ini")],
        _ => {
            let h = &env.home;
            let mut v = vec![
                h.join("snap/firefox/common/.mozilla/firefox/profiles.ini"),
                h.join(".var/app/org.mozilla.firefox/.mozilla/firefox/profiles.ini"),
                h.join(".var/app/org.mozilla.firefox/config/mozilla/firefox/profiles.ini"),
                h.join(".config/mozilla/firefox/profiles.ini"),
            ];
            let xdg = env.xdg_config().join("mozilla/firefox/profiles.ini");
            if !v.contains(&xdg) {
                v.push(xdg);
            }
            v.push(h.join(".mozilla/firefox/profiles.ini"));
            v
        }
    }
}

/// Ruta de `profiles.ini` (`MozillaKeyStoreUtilities.getProfilesIniPath`).
pub fn profiles_ini_path(env: &MozEnv) -> Option<PathBuf> {
    if env.use_env_vars()
        && let Some(p) = env.var(AFIRMA_NSS_PROFILES_INI)
    {
        let mut p = p.to_string();
        if let Some(idx) = p.to_uppercase().find("%APPDATA%")
            && let Some(app) = env.windows_app_data()
        {
            p.replace_range(idx..idx + "%APPDATA%".len(), &app.to_string_lossy());
        }
        let path = PathBuf::from(&p);
        if path.is_file() && std::fs::File::open(&path).is_ok() {
            return Some(path);
        }
        tracing::warn!(
            "La variable de entorno '{AFIRMA_NSS_PROFILES_INI}' apunta a un fichero que no existe o sobre el que no se tienen permisos de lectura, se ignorara"
        );
    }
    let candidates = profiles_ini_candidates(env);
    match env.os {
        Os::Windows | Os::MacOs => candidates.into_iter().next(),
        _ => {
            let last = candidates.last().cloned();
            candidates.into_iter().find(|p| p.is_file()).or(last)
        }
    }
}

/// Perfil declarado en `profiles.ini`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirefoxProfile {
    pub name: String,
    /// `IsRelative=1` (por defecto, verdadero).
    pub relative: bool,
    /// Valor literal de `Path=`.
    pub path: String,
    pub absolute_path: PathBuf,
    pub default: bool,
    pub locked: bool,
}

/// Sección `[General]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralInfo {
    /// `Version=` (1 por defecto).
    pub version: i32,
    pub start_with_last_profile: bool,
}

impl Default for GeneralInfo {
    fn default() -> Self {
        GeneralInfo {
            version: 1,
            start_with_last_profile: false,
        }
    }
}

/// Sección `[Install…]` (Firefox 69+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateInfo {
    pub default_profile_path: String,
    pub locked: bool,
    /// Se declaró `Locked=` (aunque fuera 0).
    pub locked_declared: bool,
}

/// Contenido de `profiles.ini`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfilesIni {
    pub profiles: Vec<FirefoxProfile>,
    pub general: GeneralInfo,
    pub state: Option<StateInfo>,
}

fn starts_with_ci(line: &str, prefix: &str) -> bool {
    line.len() >= prefix.len()
        && line.is_char_boundary(prefix.len())
        && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

impl ProfilesIni {
    /// Lee e interpreta un `profiles.ini`.
    pub fn load(path: &Path) -> Result<ProfilesIni, KeyStoreError> {
        let bytes = std::fs::read(path)
            .map_err(|e| KeyStoreError::Firefox(format!("No se pudo cargar el fichero de perfiles de Firefox: {e}")))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Ok(Self::parse(&String::from_utf8_lossy(&bytes), base))
    }

    /// Interpreta el texto de un `profiles.ini` (rutas relativas respecto a
    /// `base_dir`).
    pub fn parse(text: &str, base_dir: &Path) -> ProfilesIni {
        // Mejora: se descarta una posible marca BOM (Java no lo hace y
        // perdería la primera sección).
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let lines: Vec<&str> = text.lines().collect();
        let mut out = ProfilesIni::default();
        let mut i = 0;
        // Cuerpo de una sección: hasta una línea vacía (que se consume) o
        // la siguiente cabecera (que no).
        let section_body = |start: usize| -> (Vec<String>, usize) {
            let mut body = Vec::new();
            let mut j = start;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() {
                    j += 1;
                    break;
                }
                if t.starts_with('[') {
                    break;
                }
                body.push(t.to_string());
                j += 1;
            }
            (body, j)
        };
        while i < lines.len() {
            let line = lines[i].trim();
            i += 1;
            if !line.starts_with('[') {
                continue;
            }
            let (body, next) = section_body(i);
            i = next;
            if starts_with_ci(line, "[profile") {
                match parse_profile(&body, base_dir) {
                    Some(p) => out.profiles.push(p),
                    None => tracing::warn!("No se ha podido leer la informacion de uno de los perfiles de Firefox"),
                }
            } else if line.eq_ignore_ascii_case("[General]") {
                match parse_general(&body) {
                    Some(g) => out.general = g,
                    None => {
                        tracing::warn!("No se ha podido leer la seccion general del fichero de perfiles de Firefox")
                    }
                }
            } else if starts_with_ci(line, "[install")
                && let Some(s) = parse_state(&body)
            {
                // Con varias secciones prevalece la que declara Locked=.
                if out.state.as_ref().is_none_or(|st| !st.locked_declared) {
                    out.state = Some(s);
                }
            }
        }
        out
    }
}

fn parse_profile(body: &[String], base_dir: &Path) -> Option<FirefoxProfile> {
    let mut name = None;
    let mut relative = true;
    let mut path = None;
    let mut default = false;
    for l in body {
        if starts_with_ci(l, "name=") {
            name = Some(l[5..].to_string());
        } else if starts_with_ci(l, "isrelative=") {
            relative = &l[11..] == "1";
        } else if starts_with_ci(l, "path=") {
            path = Some(l[5..].to_string());
        } else if starts_with_ci(l, "default=") {
            default = &l[8..] == "1";
        }
    }
    let (name, path) = (name?, path?);
    let absolute_path = if relative {
        base_dir.join(&path)
    } else {
        PathBuf::from(&path)
    };
    let lock = absolute_path.join("lock");
    let locked =
        lock.exists() || std::fs::symlink_metadata(&lock).is_ok() || absolute_path.join("parent.lock").exists();
    Some(FirefoxProfile {
        name,
        relative,
        path,
        absolute_path,
        default,
        locked,
    })
}

fn parse_general(body: &[String]) -> Option<GeneralInfo> {
    let mut g = GeneralInfo::default();
    for l in body {
        if starts_with_ci(l, "version=") {
            // Java: Integer.parseInt; un valor no numérico invalida la sección.
            g.version = l[8..].parse().ok()?;
        } else if starts_with_ci(l, "startwithlastprofile=") {
            g.start_with_last_profile = &l[21..] == "1";
        }
    }
    Some(g)
}

fn parse_state(body: &[String]) -> Option<StateInfo> {
    let mut path = None;
    let mut locked = false;
    let mut locked_declared = false;
    for l in body {
        if starts_with_ci(l, "default=") {
            path = Some(l[8..].to_string());
        } else if starts_with_ci(l, "locked=") {
            locked = &l[7..] == "1";
            locked_declared = true;
        }
    }
    Some(StateInfo {
        default_profile_path: path?,
        locked,
        locked_declared,
    })
}

/// Número mínimo de ficheros de un perfil válido.
pub const MIN_FIREFOX_FILES_ON_PROFILE: usize = 10;

/// Perfil "ficticio" (no válido): menos de 10 entradas o sin `key4.db` ni
/// `key3.db` legibles. Un directorio inexistente también lo es (Java
/// fallaría con una excepción).
pub fn is_dummy_profile(dir: &Path) -> bool {
    let count = std::fs::read_dir(dir).map(|r| r.count()).unwrap_or(0);
    if count < MIN_FIREFOX_FILES_ON_PROFILE {
        return true;
    }
    let readable = |f: &str| std::fs::File::open(dir.join(f)).is_ok();
    !readable("key4.db") && !readable("key3.db")
}

/// Elige el directorio del perfil activo:
/// 1. activo: versión 1 → primer perfil válido bloqueado; versión ≥ 2 →
///    perfil cuyo `Path` coincide con `Default=` de `[Install…]`, si es
///    válido;
/// 2. primer perfil válido con `Default=1`;
/// 3. perfil válido modificado más recientemente;
/// 4. primer perfil (aunque no sea válido).
pub fn select_profile(ini: &ProfilesIni) -> Option<PathBuf> {
    let active = if ini.general.version == 1 {
        ini.profiles
            .iter()
            .find(|p| !is_dummy_profile(&p.absolute_path) && p.locked)
    } else {
        ini.state
            .as_ref()
            .and_then(|s| ini.profiles.iter().find(|p| p.path == s.default_profile_path))
    };
    if let Some(p) = active
        && !is_dummy_profile(&p.absolute_path)
    {
        return Some(p.absolute_path.clone());
    }
    if let Some(p) = ini
        .profiles
        .iter()
        .find(|p| !is_dummy_profile(&p.absolute_path) && p.default)
    {
        return Some(p.absolute_path.clone());
    }
    let mut best: Option<(std::time::SystemTime, &FirefoxProfile)> = None;
    for p in ini.profiles.iter().filter(|p| !is_dummy_profile(&p.absolute_path)) {
        let Ok(m) = std::fs::metadata(&p.absolute_path).and_then(|m| m.modified()) else {
            continue;
        };
        if best.is_none_or(|(b, _)| m > b) {
            best = Some((m, p));
        }
    }
    if let Some((_, p)) = best {
        return Some(p.absolute_path.clone());
    }
    ini.profiles.first().map(|p| p.absolute_path.clone())
}

/// Perfil elegido para un `profiles.ini`, con caché por ruta canónica
/// durante la vida del proceso (como Java).
pub fn profile_dir_for_ini(ini_path: &Path) -> Result<Option<PathBuf>, KeyStoreError> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Option<PathBuf>>>> = OnceLock::new();
    let key = std::fs::canonicalize(ini_path).unwrap_or_else(|_| ini_path.to_path_buf());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().ok().and_then(|c| c.get(&key).cloned()) {
        return Ok(v);
    }
    if !ini_path.is_file() {
        return Err(KeyStoreError::Firefox(format!(
            "No se ha encontrado el fichero con los perfiles de Firefox en: {}",
            ini_path.display()
        )));
    }
    let ini = ProfilesIni::load(ini_path)?;
    let dir = select_profile(&ini);
    if let Ok(mut c) = cache.lock() {
        c.insert(key, dir.clone());
    }
    Ok(dir)
}

/// Directorio del perfil de Firefox del usuario
/// (`getMozillaUserProfileDirectory`): en Windows cualquier fallo es un
/// error; en el resto, si no se puede leer `profiles.ini` se usa la base de
/// datos NSS compartida.
pub fn firefox_profile_dir(env: &MozEnv) -> Result<PathBuf, KeyStoreError> {
    let not_found = || KeyStoreError::Firefox("No se ha encontrado el directorio de perfil de Mozilla".into());
    let ini = profiles_ini_path(env);
    let result = match &ini {
        Some(p) => profile_dir_for_ini(p),
        None => Err(not_found()),
    };
    match (env.os, result) {
        (_, Ok(Some(dir))) => Ok(dir),
        (Os::Windows, Ok(None)) | (Os::Windows, Err(_)) => Err(not_found()),
        (_, Ok(None)) => Err(not_found()),
        (_, Err(e)) => {
            tracing::warn!(
                "No ha podido determinarse el perfil de usuario de Mozilla, se intentara usar el global: {e}"
            );
            shared_nss_dir(env)
        }
    }
}

/// Directorios candidatos de la base de datos NSS compartida.
pub fn shared_nss_candidates(env: &MozEnv) -> Vec<PathBuf> {
    vec![
        env.home.join(".pki/nssdb"),
        env.home.join("snap/chromium/current/.pki/nssdb"),
        PathBuf::from("/etc/pki/nssdb"),
    ]
}

/// Indica si el directorio contiene al menos un fichero `key*.db`.
pub fn is_nss_profile_dir(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|rd| {
        rd.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("key") && n.ends_with(".db")
        })
    })
}

/// Base de datos NSS compartida (`SharedNssUtil.getSharedUserProfileDirectory`).
pub fn shared_nss_dir(env: &MozEnv) -> Result<PathBuf, KeyStoreError> {
    shared_nss_candidates(env)
        .into_iter()
        .find(|p| is_nss_profile_dir(p))
        .ok_or_else(|| KeyStoreError::Firefox("No se ha encontrado un directorio de perfil de NSS compartido".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(dir: &Path, files: usize, key4: bool) {
        std::fs::create_dir_all(dir).unwrap();
        for i in 0..files {
            std::fs::write(dir.join(format!("f{i}")), b"x").unwrap();
        }
        if key4 {
            std::fs::write(dir.join("key4.db"), b"x").unwrap();
        }
    }

    fn env(home: &Path, os: Os) -> MozEnv {
        MozEnv {
            os,
            home: home.to_path_buf(),
            user_name: Some("u".into()),
            vars: BTreeMap::new(),
        }
    }

    #[test]
    fn parses_ini_quirks() {
        let text = "\u{feff}[Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\nLocked=1\n\n[Install111]\nDefault=Profiles/otro\n[Profile1]\nName=default\nIsRelative=1\nPath=Profiles/xyz.default\nDefault=1\n\n[Profile0]\nName=default-release\nisrelative=1\nPATH=Profiles/abc.default-release\n[Profile2]\nName=sin-ruta\n\n[General]\nStartWithLastProfile=1\nVersion=2\n\n[Profile3]\nName=abs\nIsRelative=0\nPath=/opt/perfil\n";
        let ini = ProfilesIni::parse(text, Path::new("/base"));
        assert_eq!(ini.profiles.len(), 3, "el perfil sin Path se descarta");
        assert_eq!(ini.profiles[0].absolute_path, Path::new("/base/Profiles/xyz.default"));
        assert!(ini.profiles[0].default);
        assert_eq!(ini.profiles[1].path, "Profiles/abc.default-release");
        assert!(ini.profiles[1].relative);
        assert_eq!(ini.profiles[2].absolute_path, Path::new("/opt/perfil"));
        assert_eq!(ini.general.version, 2);
        assert!(ini.general.start_with_last_profile);
        // La primera sección Install declara Locked= y prevalece.
        assert_eq!(
            ini.state.as_ref().unwrap().default_profile_path,
            "Profiles/abc.default-release"
        );
        assert!(ini.state.as_ref().unwrap().locked);
        // Sin [General] la versión es 1.
        assert_eq!(
            ProfilesIni::parse("[Profile0]\nName=a\nPath=b\n", Path::new("/"))
                .general
                .version,
            1
        );
        // Versión no numérica: se ignora la sección general.
        assert_eq!(
            ProfilesIni::parse("[General]\nVersion=x\n", Path::new("/")).general,
            GeneralInfo::default()
        );
    }

    #[test]
    fn selects_profile_like_java() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        make_profile(&base.join("Profiles/a"), 12, true);
        make_profile(&base.join("Profiles/b"), 12, true);
        make_profile(&base.join("Profiles/dummy"), 3, true);
        make_profile(&base.join("Profiles/nokey"), 12, false);
        // Versión 2: el de [Install] si es válido.
        let ini = ProfilesIni::parse(
            "[Install1]\nDefault=Profiles/b\n\n[Profile0]\nName=a\nPath=Profiles/a\nDefault=1\n\n[Profile1]\nName=b\nPath=Profiles/b\n\n[General]\nVersion=2\n",
            base,
        );
        assert_eq!(select_profile(&ini).unwrap(), base.join("Profiles/b"));
        // [Install] apunta a un perfil ficticio → el Default=1 válido.
        let ini = ProfilesIni::parse(
            "[Install1]\nDefault=Profiles/dummy\n\n[Profile0]\nName=d\nPath=Profiles/dummy\nDefault=1\n\n[Profile1]\nName=a\nPath=Profiles/a\nDefault=1\n\n[General]\nVersion=2\n",
            base,
        );
        assert_eq!(select_profile(&ini).unwrap(), base.join("Profiles/a"));
        // Versión 1: el bloqueado (fichero lock o enlace simbólico colgante).
        #[cfg(unix)]
        std::os::unix::fs::symlink("127.0.0.1:+1234", base.join("Profiles/b/lock")).unwrap();
        #[cfg(not(unix))]
        std::fs::write(base.join("Profiles/b/parent.lock"), b"").unwrap();
        let ini = ProfilesIni::parse(
            "[Profile0]\nName=a\nPath=Profiles/a\nDefault=1\n\n[Profile1]\nName=b\nPath=Profiles/b\n",
            base,
        );
        assert!(ini.profiles[1].locked);
        assert_eq!(select_profile(&ini).unwrap(), base.join("Profiles/b"));
        // Ninguno activo ni por defecto válido → el más reciente válido.
        let ini = ProfilesIni::parse(
            "[Profile0]\nName=n\nPath=Profiles/nokey\n\n[Profile1]\nName=a\nPath=Profiles/a\n\n[General]\nVersion=2\n",
            base,
        );
        assert_eq!(select_profile(&ini).unwrap(), base.join("Profiles/a"));
        // Todos ficticios → el primero.
        let ini = ProfilesIni::parse(
            "[Profile0]\nName=n\nPath=Profiles/nokey\n\n[Profile1]\nName=d\nPath=Profiles/dummy\n",
            base,
        );
        assert_eq!(select_profile(&ini).unwrap(), base.join("Profiles/nokey"));
        assert!(select_profile(&ProfilesIni::default()).is_none());
    }

    #[test]
    fn ini_locations() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let e = env(home, Os::Linux);
        // Ninguno existe → el clásico.
        assert_eq!(
            profiles_ini_path(&e).unwrap(),
            home.join(".mozilla/firefox/profiles.ini")
        );
        // Flatpak (mejora sobre Java).
        let flat = home.join(".var/app/org.mozilla.firefox/.mozilla/firefox");
        std::fs::create_dir_all(&flat).unwrap();
        std::fs::write(flat.join("profiles.ini"), b"").unwrap();
        assert_eq!(profiles_ini_path(&e).unwrap(), flat.join("profiles.ini"));
        // Snap tiene prioridad.
        let snap = home.join("snap/firefox/common/.mozilla/firefox");
        std::fs::create_dir_all(&snap).unwrap();
        std::fs::write(snap.join("profiles.ini"), b"").unwrap();
        assert_eq!(profiles_ini_path(&e).unwrap(), snap.join("profiles.ini"));
        // Variable de entorno, solo si está habilitada.
        let explicit = home.join("mi.ini");
        std::fs::write(&explicit, b"").unwrap();
        let mut e2 = e.clone();
        e2.vars
            .insert(AFIRMA_NSS_PROFILES_INI.into(), explicit.to_string_lossy().into());
        assert_eq!(profiles_ini_path(&e2).unwrap(), snap.join("profiles.ini"));
        e2.vars.insert(USE_ENV_VARS.into(), "TRUE".into());
        assert_eq!(profiles_ini_path(&e2).unwrap(), explicit);
        // macOS y Windows.
        assert_eq!(
            profiles_ini_path(&env(home, Os::MacOs)).unwrap(),
            home.join("Library/Application Support/Firefox/profiles.ini")
        );
        let mut w = env(home, Os::Windows);
        w.vars.insert("APPDATA".into(), "C:\\Users\\u\\AppData\\Roaming".into());
        assert_eq!(
            profiles_ini_path(&w).unwrap(),
            PathBuf::from("C:\\Users\\u\\AppData\\Roaming")
                .join("Mozilla")
                .join("Firefox")
                .join("profiles.ini")
        );
    }

    #[test]
    fn shared_db_and_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let e = env(home, Os::Linux);
        let nssdb = home.join(".pki/nssdb");
        std::fs::create_dir_all(&nssdb).unwrap();
        // Sin key*.db no es un perfil NSS (salvo que exista /etc/pki/nssdb).
        if !is_nss_profile_dir(Path::new("/etc/pki/nssdb")) {
            assert!(shared_nss_dir(&e).is_err());
        }
        std::fs::write(nssdb.join("key4.db"), b"").unwrap();
        assert_eq!(shared_nss_dir(&e).unwrap(), nssdb);
        // Sin profiles.ini (Linux): se usa la base de datos compartida.
        assert_eq!(firefox_profile_dir(&e).unwrap(), nssdb);
        // En Windows es un error.
        assert!(firefox_profile_dir(&env(home, Os::Windows)).is_err());
    }
}
