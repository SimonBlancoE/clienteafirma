//! Módulos PKCS#11 externos registrados en un perfil NSS (`pkcs11.txt` en
//! bases de datos SQLite y `secmod.db` en las antiguas Berkeley DB), con
//! las reglas de Java para excluir los módulos nativos del DNIe, añadir los
//! módulos conocidos de Windows y depurar duplicados y `nssckbi`.

use std::path::{Path, PathBuf};

use crate::kind::Os;
use crate::pkcs11::known::{WINDOWS_FIREFOX_KNOWN_MODULES, is_native_dnie_lib, is_nss_root_module};

/// Módulo PKCS#11 externo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalModule {
    /// Descripción (`name=` de `pkcs11.txt`).
    pub description: String,
    /// Ruta de la biblioteca.
    pub lib: String,
}

const MAX_LINES: usize = 512;
const MAX_LINE_LEN: usize = 4096;

/// Interpreta `pkcs11.txt` como `Pkcs11Txt.getModules`. Devuelve error si
/// el fichero supera los límites de Java (512 líneas de 4 KB).
pub fn parse_pkcs11_txt(text: &str) -> Result<Vec<ExternalModule>, String> {
    const LIB: &str = "library=";
    const NAME: &str = " name=\"";
    let mut out = Vec::new();
    let mut lib: Option<String> = None;
    let mut name: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        if i >= MAX_LINES {
            return Err("pkcs11.txt supera el número máximo de líneas".into());
        }
        if line.len() > MAX_LINE_LEN {
            return Err("pkcs11.txt contiene una línea demasiado larga".into());
        }
        if line.trim().is_empty() {
            // Una línea en blanco empieza una nueva sección.
            lib = None;
            name = None;
            continue;
        }
        let lib_pos = if line.starts_with(LIB) {
            Some(LIB.len())
        } else {
            line.find(" library=").map(|p| p + " library=".len())
        };
        if let Some(lp) = lib_pos {
            match line[lp..].find(NAME).map(|p| p + lp) {
                Some(np) => {
                    lib = Some(line[lp..np].trim().to_string());
                    let start = np + NAME.len();
                    // Java: substring hasta la siguiente comilla (si no hay,
                    // la excepción descarta la línea).
                    if let Some(end) = line[start..].find('"') {
                        name = Some(line[start..start + end].to_string());
                    }
                }
                None => lib = Some(line[lp..].trim().to_string()),
            }
        } else if let Some(n) = line.strip_prefix("name=") {
            name = Some(n.trim().to_string());
        }
        if let (Some(l), Some(n)) = (&lib, &name)
            && !l.is_empty()
            && !n.is_empty()
        {
            out.push(ExternalModule {
                description: n.clone(),
                lib: l.clone(),
            });
            lib = None;
            name = None;
        }
    }
    Ok(out)
}

/// Interpreta `secmod.db` con la heurística de `AOSecMod`: en cada posición
/// se lee un nombre y una biblioteca con prefijo de longitud de 16 bits; se
/// acepta si la biblioteca parece una biblioteca del sistema y existe
/// (`resolve`). La primera aparición de cada biblioteca gana.
pub fn parse_secmod_db(data: &[u8], os: Os, resolve: &dyn Fn(&str) -> Option<String>) -> Vec<ExternalModule> {
    let mut out: Vec<ExternalModule> = Vec::new();
    let be16 = |i: usize| -> Option<usize> { Some((usize::from(*data.get(i)?) << 8) | usize::from(*data.get(i + 1)?)) };
    for i in 0..data.len() {
        let Some(len1) = be16(i) else { continue };
        let Some(name_bytes) = data.get(i + 2..i + 2 + len1) else {
            continue;
        };
        let next = i + 2 + len1;
        let Some(len2) = be16(next) else { continue };
        let Some(lib_bytes) = data.get(next + 2..next + 2 + len2) else {
            continue;
        };
        let lib = String::from_utf8_lossy(lib_bytes).to_string();
        let is_lib = match os {
            Os::Windows => lib.ends_with(".dll") || lib.ends_with(".DLL"),
            _ => lib.ends_with(".so") || lib.contains(".so.") || lib.ends_with(".dylib"),
        };
        if !is_lib {
            continue;
        }
        let Some(true_lib) = resolve(&lib) else { continue };
        let name = String::from_utf8_lossy(name_bytes).to_string();
        // Se descarta hasta el último carácter no imprimible.
        let offset = name
            .char_indices()
            .rev()
            .find(|(_, c)| (*c as u32) < 32 || (*c as u32) > 126)
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        let description = name[offset..].to_string();
        if !out.iter().any(|m| m.lib == true_lib) {
            out.push(ExternalModule {
                description,
                lib: true_lib,
            });
        }
    }
    out
}

/// Resolución de bibliotecas de `secmod.db`: la ruta tal cual si existe; si
/// no, en los directorios de bibliotecas habituales (equivalente a buscar en
/// `java.library.path`).
pub fn resolve_library(lib: &str) -> Option<String> {
    if Path::new(lib).is_file() {
        return Some(lib.to_string());
    }
    let name = Path::new(lib).file_name()?;
    let mut dirs: Vec<PathBuf> = std::env::var_os("LD_LIBRARY_PATH")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    dirs.extend(["/usr/lib64", "/usr/lib", "/lib64", "/lib", "/usr/local/lib"].map(PathBuf::from));
    dirs.push(PathBuf::from(format!(
        "/usr/lib/{}",
        crate::pkcs11::known::multiarch_triple()
    )));
    dirs.into_iter()
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// Módulos registrados en un directorio de perfil NSS: `pkcs11.txt` si
/// `NSS_DEFAULT_DB_TYPE=sql` o si el fichero existe (si falla, se usa
/// `secmod.db`); si no, `secmod.db`.
pub fn read_profile_modules(profile_dir: &Path, os: Os, nss_default_db_sql: bool) -> Vec<ExternalModule> {
    let txt = profile_dir.join("pkcs11.txt");
    if nss_default_db_sql || txt.exists() {
        match std::fs::read(&txt)
            .map_err(|e| e.to_string())
            .and_then(|b| parse_pkcs11_txt(&String::from_utf8_lossy(&b)))
        {
            Ok(m) => return m,
            Err(e) => {
                tracing::error!("No se han podido obtener los modulos externos de Mozilla desde 'pkcs11.txt': {e}")
            }
        }
    }
    match std::fs::read(profile_dir.join("secmod.db")) {
        Ok(data) => parse_secmod_db(&data, os, &resolve_library),
        Err(e) => {
            tracing::debug!("No se han podido obtener los modulos externos de Mozilla desde 'secmod.db': {e}");
            Vec::new()
        }
    }
}

/// Opciones de depuración de la lista de módulos.
#[derive(Debug, Clone, Default)]
pub struct ModuleFilter {
    /// Excluir los módulos nativos del DNIe (cuando el DNIe se usa como
    /// almacén preferente).
    pub exclude_native_dnie: bool,
    /// `es.gob.afirma.keystores.mozilla.disableDnieNativeDriver`: si está
    /// activo, los módulos nativos del DNIe no se consideran "DNIe".
    pub disable_dnie_native_driver: bool,
    /// Añadir los módulos conocidos de Windows.
    pub include_known_modules: bool,
    /// Directorio de bibliotecas del sistema de Windows (`System32`, o
    /// `SysWOW64` en un proceso de 32 bits).
    pub windows_system_dir: Option<PathBuf>,
}

/// Aplica exclusiones, módulos conocidos y depuración
/// (`getPkcs11ModulesFromModuleNames` + `purgeStoresTable`), conservando el
/// orden del fichero (en Java es el de un `HashMap`).
pub fn filter_modules(modules: Vec<ExternalModule>, opts: &ModuleFilter, os: Os) -> Vec<ExternalModule> {
    let is_dnie = |lib: &str| !opts.disable_dnie_native_driver && is_native_dnie_lib(lib);
    // Mapa por descripción: una descripción repetida sustituye la biblioteca.
    let mut by_desc: Vec<ExternalModule> = Vec::new();
    for m in modules {
        if opts.exclude_native_dnie && is_dnie(&m.lib) {
            continue;
        }
        match by_desc.iter_mut().find(|x| x.description == m.description) {
            Some(x) => x.lib = m.lib,
            None => by_desc.push(m),
        }
    }
    if opts.include_known_modules && os == Os::Windows {
        let snapshot = by_desc.clone();
        for k in WINDOWS_FIREFOX_KNOWN_MODULES {
            if opts.exclude_native_dnie && is_dnie(k.lib) {
                continue;
            }
            let included = snapshot
                .iter()
                .any(|m| m.lib.to_lowercase().ends_with(&k.lib.to_lowercase()));
            if included {
                continue;
            }
            let path = match &opts.windows_system_dir {
                Some(d) => d.join(k.lib).to_string_lossy().into_owned(),
                None => k.lib.to_string(),
            };
            if k.always || Path::new(&path).exists() {
                match by_desc.iter_mut().find(|x| x.description == k.description) {
                    Some(x) => x.lib = path,
                    None => by_desc.push(ExternalModule {
                        description: k.description.to_string(),
                        lib: path,
                    }),
                }
            }
        }
    }
    // Depuración: misma biblioteca (sin mayúsculas si es .dll) y nssckbi.
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for m in by_desc {
        let key = if m.lib.to_lowercase().ends_with(".dll") {
            m.lib.to_lowercase()
        } else {
            m.lib.clone()
        };
        if seen.contains(&key) || is_nss_root_module(&m.lib) {
            tracing::warn!(
                "Se eliminara el modulo '{}' porque ya existe uno con la misma biblioteca o es un modulo de certificados raiz: {}",
                m.description,
                m.lib
            );
            continue;
        }
        seen.push(key);
        out.push(m);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKCS11_TXT: &str = "library=\nname=NSS Internal PKCS #11 Module\nparameters=configdir='sql:/home/u/.mozilla/firefox/x' certPrefix='' keyPrefix='' secmod='secmod.db' flags= updatedir='' \nNSS=Flags=internal,critical trustOrder=75 cipherOrder=100 slotParams=(1={slotFlags=[ECC,RSA] askpw=any timeout=30})\n\nlibrary=/usr/lib64/opensc-pkcs11.so\nname=OpenSC\n\nlibrary=/usr/lib64/libnssckbi.so\nname=Builtin Roots\n\nlibrary=/opt/fnmt/libpkcs11-fnmtdnie.so name=\"FNMT DNIe\" NSS=\"slotParams=x\"\n\nname=\"Con comillas\"\nlibrary=/usr/lib/libpkcs11-dnie.so\n\nlibrary=/usr/lib64/opensc-pkcs11.so\nname=OpenSC otra vez\n";

    #[test]
    fn pkcs11_txt() {
        let m = parse_pkcs11_txt(PKCS11_TXT).unwrap();
        let pairs: Vec<(&str, &str)> = m.iter().map(|x| (x.description.as_str(), x.lib.as_str())).collect();
        assert_eq!(
            pairs,
            vec![
                ("OpenSC", "/usr/lib64/opensc-pkcs11.so"),
                ("Builtin Roots", "/usr/lib64/libnssckbi.so"),
                ("FNMT DNIe", "/opt/fnmt/libpkcs11-fnmtdnie.so"),
                ("\"Con comillas\"", "/usr/lib/libpkcs11-dnie.so"),
                ("OpenSC otra vez", "/usr/lib64/opensc-pkcs11.so"),
            ]
        );
        let f = filter_modules(m.clone(), &ModuleFilter::default(), Os::Linux);
        let libs: Vec<&str> = f.iter().map(|x| x.lib.as_str()).collect();
        assert_eq!(
            libs,
            vec![
                "/usr/lib64/opensc-pkcs11.so",
                "/opt/fnmt/libpkcs11-fnmtdnie.so",
                "/usr/lib/libpkcs11-dnie.so"
            ]
        );
        let f = filter_modules(
            m,
            &ModuleFilter {
                exclude_native_dnie: true,
                ..Default::default()
            },
            Os::Linux,
        );
        assert!(!f.iter().any(|x| x.lib.ends_with("libpkcs11-dnie.so")));
        let too_long = format!("library={}\nname=x\n", "a".repeat(5000));
        assert!(parse_pkcs11_txt(&too_long).is_err());
    }

    #[test]
    fn windows_known_modules() {
        let m = vec![ExternalModule {
            description: "FNMT".into(),
            lib: "C:\\Windows\\System32\\FNMT_P11_x64.DLL".into(),
        }];
        let opts = ModuleFilter {
            include_known_modules: true,
            windows_system_dir: Some(PathBuf::from("C:\\Windows\\System32")),
            ..Default::default()
        };
        let f = filter_modules(m, &opts, Os::Windows);
        let descs: Vec<&str> = f.iter().map(|x| x.description.as_str()).collect();
        // FNMT 64 ya incluido (por nombre de biblioteca); FNMT 32 se añade
        // siempre; CardOS solo si existe.
        assert_eq!(descs, vec!["FNMT", "FNMT-RCM Modulo PKCS#11 32bits"]);
        // DNIe nativo excluido incluso entre los conocidos (TIF no está).
        let f = filter_modules(
            vec![ExternalModule {
                description: "DNIe".into(),
                lib: "C:\\x\\DNIe_P11_priv.dll".into(),
            }],
            &ModuleFilter {
                exclude_native_dnie: true,
                ..opts
            },
            Os::Windows,
        );
        assert!(!f.iter().any(|x| x.description == "DNIe"));
    }

    #[test]
    fn secmod_heuristic() {
        let mut data = vec![0u8, 1, 2, 0xff];
        let push = |d: &mut Vec<u8>, s: &[u8]| {
            d.extend((s.len() as u16).to_be_bytes());
            d.extend_from_slice(s);
        };
        push(&mut data, b"\x01\x02Mi modulo");
        push(&mut data, b"/opt/x/libmimodulo.so");
        data.extend([9, 9, 9]);
        push(&mut data, b"Otro");
        push(&mut data, b"/opt/x/libmimodulo.so");
        let m = parse_secmod_db(&data, Os::Linux, &|l| Some(l.to_string()));
        assert_eq!(
            m,
            vec![ExternalModule {
                description: "Mi modulo".into(),
                lib: "/opt/x/libmimodulo.so".into()
            }]
        );
        assert!(parse_secmod_db(&data, Os::Linux, &|_| None).is_empty());
        assert!(parse_secmod_db(&data, Os::Windows, &|l| Some(l.to_string())).is_empty());
    }
}
