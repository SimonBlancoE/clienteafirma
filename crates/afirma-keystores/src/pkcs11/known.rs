//! Bibliotecas PKCS#11 conocidas (tabla 1.4 de la especificación) y
//! detección de controladores de tarjeta instalados.
//!
//! **Decisión de diseño (DNIe/CERES):** Java accede al DNIe y a las tarjetas
//! CERES con jmulticard, un controlador 100 % Java sobre PC/SC (canal seguro
//! CWA-14890, PACE/CAN). AutoFirma-rs no reimplementa ese controlador: usa los
//! módulos PKCS#11 ya existentes y mantenidos —OpenSC (`opensc-pkcs11`, con
//! los controladores `dnie` y `fnmt`), el módulo de la FNMT
//! (`libpkcs11-fnmtdnie`) y los módulos oficiales del DNIe/FNMT en Windows
//! (`DNIe_P11_priv.dll`, `FNMT_P11_x64.dll`, `TIF_P11.dll`...)—, detectados
//! automáticamente en las rutas habituales de cada sistema. El
//! comportamiento visible se conserva: los almacenes `DNIEJAVA`, `CERES` y
//! `CERES_430` son "preferentes" (ocultan sus duplicados en otros almacenes),
//! el PIN se pide al firmar con los textos de jmulticard, con la caché
//! opcional de 1 h y la confirmación de firma del DNIe.

use std::path::{Path, PathBuf};

use crate::kind::Os;

/// Bibliotecas con las que no debe usarse `CKM_SHA1_RSA_PKCS` (fallo del
/// controlador FNMT v10). Se comparan sin distinguir mayúsculas con el
/// nombre del fichero.
pub const SHA1_RSA_PKCS_DISABLED_LIBS: &[&str] = &[
    "DNIe_P11_priv.dll",
    "DNIe_P11_pub.dll",
    "FNMT_P11.dll",
    "FNMT_P11_x64.dll",
    "UsrPkcs11.dll",
    "UsrPubPkcs11.dll",
    "TIF_P11.dll",
];

/// Módulos PKCS#11 "nativos" del DNIe (comparación sin mayúsculas con
/// `endsWith`): se excluyen de los módulos externos de Firefox cuando el
/// DNIe se usa como almacén preferente.
pub const NATIVE_DNIE_LIBS: &[&str] = &[
    "libopensc-dnie.dylib",
    "libpkcs11-dnie.so",
    "usrpkcs11.dll",
    "dnie_p11_priv.dll",
    "dnie_p11_pub.dll",
    "opensc-pkcs11.dll",
    "DNIE_P11.dll",
    "TIF_P11.dll",
];

/// Módulo conocido de Windows que se añade a la lista de módulos de Firefox
/// aunque no esté registrado en el perfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownWindowsModule {
    pub description: &'static str,
    /// Nombre del fichero en el directorio de bibliotecas del sistema
    /// (`System32` o `SysWOW64` en un proceso de 32 bits).
    pub lib: &'static str,
    /// Se añade siempre, exista o no el fichero (comportamiento de Java).
    pub always: bool,
}

/// Módulos conocidos de Windows (tabla 1.4).
pub const WINDOWS_FIREFOX_KNOWN_MODULES: &[KnownWindowsModule] = &[
    KnownWindowsModule {
        description: "Atos CardOS (preinstalado)",
        lib: "siecap11.dll",
        always: false,
    },
    KnownWindowsModule {
        description: "FNMT-RCM Modulo PKCS#11 64bits",
        lib: "FNMT_P11_x64.dll",
        always: true,
    },
    KnownWindowsModule {
        description: "FNMT-RCM Modulo PKCS#11 32bits",
        lib: "FNMT_P11.dll",
        always: true,
    },
];

/// Tarjetas conocidas para el perfil temporal de Windows
/// (`KNOWN_SMARTCARDS`), en orden; las variables de entorno se expanden.
pub const WINDOWS_KNOWN_SMARTCARDS: &[(&str, &[&str])] = &[
    (
        "FNMT-CERES",
        &[
            "%SYSTEMROOT%/System32/FNMT_P11_x64.dll",
            "%SYSTEMROOT%/System32/FNMT_P11.dll",
            "%SYSTEMROOT%/SysWOW64/FNMT_P11.dll",
        ],
    ),
    (
        "CardOS",
        &[
            "%SYSTEMROOT%/SysWOW64/siecap11.dll",
            "%SYSTEMROOT%/System32/siecap11.dll",
        ],
    ),
    (
        "TUI",
        &[
            "%PROGRAMFILES%/umu/Third-Party/Gemalto/Classic Client/BIN/gclib.dll",
            "%PROGRAMFILES(x86)%/umu/Third-Party/Gemalto/Classic Client/BIN/gclib.dll",
            "%PROGRAMFILES%/umu/UMU-Crypto/lib/libumupkcs11.dll",
            "%PROGRAMFILES(x86)%/umu/UMU-Crypto/lib/libumupkcs11.dll",
            "%PROGRAMFILES%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS1164.dll",
            "%PROGRAMFILES%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS11.dll",
            "%PROGRAMFILES(x86)%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS1164.dll",
            "%PROGRAMFILES(x86)%/Gemalto/IDGo 800 PKCS#11/IDPrimePKCS11.dll",
        ],
    ),
    (
        "SafeSign",
        &[
            "%SYSTEMROOT%/SysWOW64/aetpkss1.dll",
            "%SYSTEMROOT%/System32/aetpkss1.dll",
        ],
    ),
];

/// Indica si para esta biblioteca hay que desactivar `CKM_SHA1_RSA_PKCS`.
pub fn sha1_rsa_pkcs_disabled(lib: &Path) -> bool {
    // Nombre del fichero con separadores de cualquier sistema.
    let full = lib.to_string_lossy();
    let name = full.rsplit(['/', '\\']).next().unwrap_or(&full);
    SHA1_RSA_PKCS_DISABLED_LIBS.iter().any(|l| l.eq_ignore_ascii_case(name))
}

/// Indica si la biblioteca es un módulo nativo del DNIe (tabla 1.4).
pub fn is_native_dnie_lib(lib: &str) -> bool {
    let lower = lib.to_lowercase();
    NATIVE_DNIE_LIBS.iter().any(|l| lower.ends_with(&l.to_lowercase()))
}

/// Indica si la biblioteca es el módulo de certificados raíz de NSS
/// (`nssckbi`), que siempre se descarta.
pub fn is_nss_root_module(lib: &str) -> bool {
    lib.to_lowercase().contains("nssckbi")
}

/// Expande `%VAR%` (sin distinguir mayúsculas en el nombre, como Windows)
/// con la función de consulta dada. Las variables inexistentes se dejan tal
/// cual.
pub fn expand_windows_env(s: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match lookup(name).or_else(|| lookup(&name.to_uppercase())) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// Tipo de tarjeta según la información del token PKCS#11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardFamily {
    /// DNIe (DNI electrónico, Dirección General de la Policía).
    Dnie,
    /// Tarjetas FNMT-RCM (CERES, TIF).
    Fnmt,
    /// Cualquier otra.
    Other,
}

/// Clasifica un token por su etiqueta, fabricante y modelo. Heurística
/// (no hay forma estándar): OpenSC publica el DNIe con fabricante
/// `DGP-FNMT` y etiqueta "DNI electrónico"; el módulo FNMT usa "DNIe";
/// las tarjetas CERES/TIF aparecen con "FNMT"/"CERES".
pub fn classify_token(label: &str, manufacturer: &str, model: &str) -> CardFamily {
    let all = format!("{label} {manufacturer} {model}").to_uppercase();
    if all.contains("DNI") || all.contains("DGP") || all.contains("POLICIA") {
        CardFamily::Dnie
    } else if all.contains("FNMT") || all.contains("CERES") || all.contains("TIF") {
        CardFamily::Fnmt
    } else {
        CardFamily::Other
    }
}

/// Controlador PKCS#11 de tarjetas detectado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartCardModule {
    /// Nombre descriptivo.
    pub name: &'static str,
    pub path: PathBuf,
}

/// Rutas conocidas de controladores PKCS#11 de tarjetas para cada sistema,
/// en orden de preferencia (mejora sobre Java, que no tiene rutas fijas en
/// Linux/macOS). `multiarch` es el triplete de Debian (`x86_64-linux-gnu`,
/// `aarch64-linux-gnu`...).
pub fn candidate_smartcard_modules(os: Os, env: &dyn Fn(&str) -> Option<String>) -> Vec<(&'static str, PathBuf)> {
    let mut v: Vec<(&'static str, PathBuf)> = Vec::new();
    match os {
        Os::Windows => {
            let sys = env("SYSTEMROOT")
                .or_else(|| env("SystemRoot"))
                .unwrap_or_else(|| "C:\\Windows".into());
            let pf = env("PROGRAMFILES")
                .or_else(|| env("ProgramFiles"))
                .unwrap_or_else(|| "C:\\Program Files".into());
            let pf86 = env("PROGRAMFILES(X86)")
                .or_else(|| env("ProgramFiles(x86)"))
                .unwrap_or_else(|| "C:\\Program Files (x86)".into());
            let sys32 = Path::new(&sys).join("System32");
            v.push(("DNIe (módulo oficial)", sys32.join("DNIe_P11_priv.dll")));
            v.push(("FNMT-RCM", sys32.join("FNMT_P11_x64.dll")));
            v.push(("FNMT-RCM TIF", sys32.join("TIF_P11.dll")));
            v.push((
                "OpenSC",
                Path::new(&pf)
                    .join("OpenSC Project")
                    .join("OpenSC")
                    .join("pkcs11")
                    .join("opensc-pkcs11.dll"),
            ));
            v.push(("OpenSC", sys32.join("opensc-pkcs11.dll")));
            v.push((
                "OpenSC (32 bits)",
                Path::new(&pf86)
                    .join("OpenSC Project")
                    .join("OpenSC")
                    .join("pkcs11")
                    .join("opensc-pkcs11.dll"),
            ));
        }
        Os::MacOs => {
            v.push((
                "FNMT-RCM",
                PathBuf::from("/Library/Libpkcs11-fnmtdnie/lib/libpkcs11-fnmtdnie.so"),
            ));
            v.push(("FNMT-RCM", PathBuf::from("/usr/local/lib/libpkcs11-fnmtdnie.so")));
            v.push(("FNMT-RCM", PathBuf::from("/usr/local/lib/libpkcs11-fnmtdnie.dylib")));
            v.push(("OpenSC", PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so")));
            v.push(("OpenSC", PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so")));
            v.push(("OpenSC", PathBuf::from("/usr/local/lib/opensc-pkcs11.so")));
            v.push((
                "DNIe (OpenSC-DNIe)",
                PathBuf::from("/usr/local/lib/libopensc-dnie.dylib"),
            ));
        }
        Os::Linux | Os::Solaris | Os::Other => {
            let triple = multiarch_triple();
            for dir in [
                format!("/usr/lib/{triple}"),
                format!("/usr/lib/{triple}/pkcs11"),
                "/usr/lib64".to_string(),
                "/usr/lib64/pkcs11".to_string(),
                "/usr/lib".to_string(),
                "/usr/lib/pkcs11".to_string(),
                "/usr/local/lib".to_string(),
                "/usr/local/lib/pkcs11".to_string(),
            ] {
                v.push(("FNMT-RCM", Path::new(&dir).join("libpkcs11-fnmtdnie.so")));
                v.push(("DNIe (OpenSC-DNIe)", Path::new(&dir).join("libpkcs11-dnie.so")));
                v.push(("OpenSC", Path::new(&dir).join("opensc-pkcs11.so")));
            }
        }
    }
    v
}

/// Controladores de tarjetas instalados (los candidatos que existen),
/// eliminando duplicados por ruta canónica.
pub fn detect_smartcard_modules(os: Os) -> Vec<SmartCardModule> {
    let env = |k: &str| std::env::var(k).ok();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut out = Vec::new();
    for (name, path) in candidate_smartcard_modules(os, &env) {
        if !path.is_file() {
            continue;
        }
        let canon = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.contains(&canon) {
            continue;
        }
        seen.push(canon);
        out.push(SmartCardModule { name, path });
    }
    out
}

/// Triplete multiarquitectura de Debian/Ubuntu para el destino de
/// compilación (corrige el fallo de Java, que solo contemplaba x86/x86-64).
pub fn multiarch_triple() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64-linux-gnu"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-linux-gnu"
    } else if cfg!(target_arch = "x86") {
        "i386-linux-gnu"
    } else if cfg!(target_arch = "arm") {
        "arm-linux-gnueabihf"
    } else if cfg!(target_arch = "powerpc64") {
        "powerpc64le-linux-gnu"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64-linux-gnu"
    } else if cfg!(target_arch = "s390x") {
        "s390x-linux-gnu"
    } else if cfg!(target_arch = "loongarch64") {
        "loongarch64-linux-gnu"
    } else {
        "unknown-linux-gnu"
    }
}

/// Bibliotecas de las tarjetas conocidas del perfil temporal de Windows,
/// expandidas, en orden (incluye las que no existen; el llamante las
/// prueba).
pub fn windows_known_smartcard_paths(env: &dyn Fn(&str) -> Option<String>) -> Vec<(&'static str, PathBuf)> {
    WINDOWS_KNOWN_SMARTCARDS
        .iter()
        .flat_map(|(name, paths)| {
            paths
                .iter()
                .map(move |p| (*name, PathBuf::from(expand_windows_env(p, env))))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables() {
        assert!(sha1_rsa_pkcs_disabled(Path::new(
            "C:\\Windows\\System32\\fnmt_p11_x64.DLL"
        )));
        assert!(!sha1_rsa_pkcs_disabled(Path::new("/usr/lib/opensc-pkcs11.so")));
        assert!(is_native_dnie_lib("C:\\x\\DNIe_P11_priv.dll"));
        assert!(is_native_dnie_lib("/usr/lib/libpkcs11-dnie.so"));
        assert!(!is_native_dnie_lib("/usr/lib/opensc-pkcs11.so"));
        assert!(is_nss_root_module("/usr/lib64/libNSSCKBI.so"));
    }

    #[test]
    fn env_expansion() {
        let env = |k: &str| match k {
            "SYSTEMROOT" => Some("C:\\Windows".to_string()),
            "PROGRAMFILES(X86)" => Some("C:\\PF86".to_string()),
            _ => None,
        };
        assert_eq!(
            expand_windows_env("%SYSTEMROOT%/System32/x.dll", &env),
            "C:\\Windows/System32/x.dll"
        );
        assert_eq!(expand_windows_env("%SystemRoot%/a", &env), "C:\\Windows/a");
        assert_eq!(expand_windows_env("%NOPE%/a", &env), "%NOPE%/a");
        assert_eq!(expand_windows_env("100%", &env), "100%");
        let paths = windows_known_smartcard_paths(&env);
        assert_eq!(
            paths[0],
            ("FNMT-CERES", PathBuf::from("C:\\Windows/System32/FNMT_P11_x64.dll"))
        );
        assert_eq!(paths.len(), 3 + 2 + 8 + 2);
        assert!(
            paths
                .iter()
                .any(|(_, p)| p == Path::new("C:\\PF86/umu/UMU-Crypto/lib/libumupkcs11.dll"))
        );
    }

    #[test]
    fn token_classification() {
        assert_eq!(
            classify_token("DNI electrónico (PIN1)", "DGP-FNMT", "PKCS#15 emulated"),
            CardFamily::Dnie
        );
        assert_eq!(classify_token("CERES", "FNMT-RCM", "CERES 4.30"), CardFamily::Fnmt);
        assert_eq!(
            classify_token("SoftHSM", "SoftHSM project", "SoftHSM v2"),
            CardFamily::Other
        );
    }

    #[test]
    fn linux_candidates_use_target_multiarch() {
        let c = candidate_smartcard_modules(Os::Linux, &|_| None);
        assert!(c.iter().any(|(_, p)| p.to_string_lossy().contains(multiarch_triple())));
        assert!(c.iter().any(|(_, p)| p == Path::new("/usr/lib64/opensc-pkcs11.so")));
    }
}
