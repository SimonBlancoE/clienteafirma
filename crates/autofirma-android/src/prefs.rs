//! Preferencias de la aplicación (`docs/spec/09-android.md` §7).
//!
//! Son las mismas claves, tipos y valores por defecto que las `SharedPreferences`
//! `afirma.client` del original, guardadas como JSON en el directorio privado de la
//! aplicación (`Context.getFilesDir()`, que GameActivity pasa a android-activity:
//! `AndroidApp::internal_data_path`). No se copian en las copias de seguridad
//! (`allowBackup="false"`). Cada cambio se escribe enseguida y de forma atómica (fichero
//! temporal y `rename`), así que no se pierde nada si Android mata el proceso.
//!
//! [`Prefs`] es un manejador que se puede clonar y compartir entre hilos (las fases de
//! firma lo leerán desde los hilos de trabajo: validación TLS, caché de certificado...).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::{info, warn};

use crate::i18n::Language;

/// Nombre del fichero de preferencias (el del original es `afirma.client.xml`).
pub const PREFS_FILE: &str = "afirma.client.json";

/// Minutos de vida de la caché de certificado (`stickySignatureTimeout`, §2.8, §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMinutes {
    #[default]
    Five,
    Fifteen,
    Thirty,
    Sixty,
    OneHundredTwenty,
}

impl CacheMinutes {
    /// Valores del diálogo «Selecciona un valor en minutos», en su orden.
    pub const ALL: [CacheMinutes; 5] = [
        CacheMinutes::Five,
        CacheMinutes::Fifteen,
        CacheMinutes::Thirty,
        CacheMinutes::Sixty,
        CacheMinutes::OneHundredTwenty,
    ];

    pub fn minutes(self) -> u32 {
        match self {
            CacheMinutes::Five => 5,
            CacheMinutes::Fifteen => 15,
            CacheMinutes::Thirty => 30,
            CacheMinutes::Sixty => 60,
            CacheMinutes::OneHundredTwenty => 120,
        }
    }

    /// Valor de unos minutos; los que no ofrece el diálogo vuelven al de por defecto.
    pub fn from_minutes(minutes: u32) -> CacheMinutes {
        CacheMinutes::ALL
            .into_iter()
            .find(|c| c.minutes() == minutes)
            .unwrap_or_default()
    }

    /// Duración de la caché.
    pub fn duration(self) -> std::time::Duration {
        std::time::Duration::from_secs(u64::from(self.minutes()) * 60)
    }
}

impl Serialize for CacheMinutes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.minutes())
    }
}

impl<'de> Deserialize<'de> for CacheMinutes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // El original lo guarda como texto («5»); se aceptan número y texto.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u32),
            Text(String),
        }
        Ok(match Raw::deserialize(d)? {
            Raw::Number(n) => CacheMinutes::from_minutes(n),
            Raw::Text(t) => CacheMinutes::from_minutes(t.trim().parse().unwrap_or(5)),
        })
    }
}

/// Valores de las preferencias. Los nombres en el fichero son las claves del original.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Preferences {
    /// Mostrar una vez la pregunta de habilitar el DNIe por NFC (§2.5).
    pub first_execution: bool,
    /// Firmar también con el DNIe por NFC (elección de almacén, §4.1).
    pub use_nfc: bool,
    /// La bienvenida ya se ha mostrado.
    pub skip_intro_screen: bool,
    /// Los textos legales ya se han aceptado.
    pub skip_conditions_screen: bool,
    /// Validar los certificados TLS de las conexiones (§5.10).
    pub validate_ssl_checks: bool,
    /// Dominios en los que no se valida TLS (§2.9, §5.10), uno por elemento.
    pub secure_domains_list: Vec<String>,
    /// Firma visible en la firma local de PDF (§3.4).
    pub pades_visible_signature: bool,
    /// Ofuscar los identificadores del titular en las firmas visibles (§3.5.5).
    pub pades_obfuscate_cert_info: bool,
    /// Vida de la caché de certificado (§4.7).
    pub sticky_signature_timeout: CacheMinutes,
    /// Idioma elegido; `None` sigue el idioma del sistema.
    #[serde(with = "language_tag")]
    pub locale_config: Option<Language>,
}

impl Default for Preferences {
    fn default() -> Self {
        Preferences {
            first_execution: true,
            use_nfc: false,
            skip_intro_screen: false,
            skip_conditions_screen: false,
            validate_ssl_checks: true,
            secure_domains_list: Vec::new(),
            pades_visible_signature: false,
            pades_obfuscate_cert_info: true,
            sticky_signature_timeout: CacheMinutes::Five,
            locale_config: None,
        }
    }
}

mod language_tag {
    use super::*;

    pub fn serialize<S: Serializer>(value: &Option<Language>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(l) => s.serialize_some(l.tag()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Language>, D::Error> {
        Ok(Option::<String>::deserialize(d)?.and_then(|t| Language::from_tag(&t)))
    }
}

/// Error al guardar las preferencias.
#[derive(Debug, thiserror::Error)]
#[error("no se pudieron guardar las preferencias en {path}: {source}")]
pub struct PrefsError {
    path: String,
    #[source]
    source: std::io::Error,
}

struct Inner {
    path: Option<PathBuf>,
    values: Preferences,
}

/// Preferencias de la aplicación: lectura y escritura con persistencia inmediata.
#[derive(Clone)]
pub struct Prefs {
    inner: Arc<Mutex<Inner>>,
}

impl Prefs {
    /// Abre (o crea) las preferencias del directorio privado de la aplicación. Si el fichero
    /// no existe o está dañado se empieza con los valores por defecto (y se registra).
    pub fn open(dir: &Path) -> Prefs {
        let path = dir.join(PREFS_FILE);
        let values = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(values) => values,
                Err(e) => {
                    warn!("Preferencias dañadas ({e}); se usan las de por defecto");
                    Preferences::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("Primera ejecución: preferencias por defecto");
                Preferences::default()
            }
            Err(e) => {
                warn!("No se pudieron leer las preferencias ({e}); se usan las de por defecto");
                Preferences::default()
            }
        };
        Prefs {
            inner: Arc::new(Mutex::new(Inner {
                path: Some(path),
                values,
            })),
        }
    }

    /// Preferencias solo en memoria (pruebas, o si no hay directorio de datos).
    pub fn in_memory(values: Preferences) -> Prefs {
        Prefs {
            inner: Arc::new(Mutex::new(Inner { path: None, values })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Copia de los valores actuales.
    pub fn get(&self) -> Preferences {
        self.lock().values.clone()
    }

    /// Fichero donde se guardan (`None` si son solo de memoria).
    pub fn path(&self) -> Option<PathBuf> {
        self.lock().path.clone()
    }

    /// Cambia los valores y los guarda. Aunque falle la escritura, el cambio queda en
    /// memoria para el resto de la sesión.
    pub fn update(&self, change: impl FnOnce(&mut Preferences)) -> Result<(), PrefsError> {
        let mut inner = self.lock();
        let before = inner.values.clone();
        change(&mut inner.values);
        if inner.values == before {
            return Ok(());
        }
        let Some(path) = inner.path.clone() else {
            return Ok(());
        };
        write_atomically(&path, &inner.values).map_err(|source| PrefsError {
            path: path.display().to_string(),
            source,
        })
    }
}

fn write_atomically(path: &Path, values: &Preferences) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(values).map_err(std::io::Error::other)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Comprueba la lista de dominios de confianza tal como se escribe en su pantalla (§2.9):
/// cada dominio, recortado, debe cumplir `^[a-z0-9*][a-z0-9-.:]{1,61}[a-z0-9*]$` sin
/// distinguir mayúsculas. Se separan por saltos de línea, como en el original, y también
/// por comas, que es lo que dice su ayuda (§10 n.º 47). Devuelve los dominios o el primero
/// que no es válido.
pub fn parse_trusted_domains(text: &str) -> Result<Vec<String>, String> {
    let mut domains = Vec::new();
    for domain in text.split(['\n', ',']).map(str::trim).filter(|d| !d.is_empty()) {
        if !is_valid_domain(domain) {
            return Err(domain.to_string());
        }
        domains.push(domain.to_string());
    }
    Ok(domains)
}

fn is_valid_domain(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    let edge = |b: u8| b.is_ascii_alphanumeric() || b == b'*';
    let inner = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':');
    (3..=63).contains(&bytes.len())
        && edge(bytes[0])
        && edge(bytes[bytes.len() - 1])
        && bytes[1..bytes.len() - 1].iter().all(|&b| inner(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valores_por_defecto_del_original() {
        let p = Preferences::default();
        assert!(p.first_execution && !p.use_nfc && !p.skip_intro_screen && !p.skip_conditions_screen);
        assert!(p.validate_ssl_checks && p.secure_domains_list.is_empty());
        assert!(!p.pades_visible_signature && p.pades_obfuscate_cert_info);
        assert_eq!(p.sticky_signature_timeout.minutes(), 5);
        assert_eq!(p.locale_config, None);
    }

    #[test]
    fn se_guardan_con_las_claves_del_original_y_se_vuelven_a_leer() {
        let dir = tempfile::tempdir().unwrap();
        let prefs = Prefs::open(dir.path());
        assert_eq!(prefs.get(), Preferences::default());
        prefs
            .update(|p| {
                p.use_nfc = true;
                p.locale_config = Some(Language::CaValencia);
                p.sticky_signature_timeout = CacheMinutes::Sixty;
                p.secure_domains_list = vec!["*.ejemplo.es".into()];
            })
            .unwrap();
        let json = std::fs::read_to_string(dir.path().join(PREFS_FILE)).unwrap();
        for key in [
            "\"firstExecution\": true",
            "\"useNfc\": true",
            "\"localeConfig\": \"ca-ES-valencia\"",
            "\"stickySignatureTimeout\": 60",
            "\"validateSslChecks\": true",
            "\"padesObfuscateCertInfo\": true",
            "\"secureDomainsList\"",
        ] {
            assert!(json.contains(key), "falta {key} en {json}");
        }
        let again = Prefs::open(dir.path()).get();
        assert!(again.use_nfc);
        assert_eq!(again.locale_config, Some(Language::CaValencia));
        assert_eq!(again.sticky_signature_timeout, CacheMinutes::Sixty);
        assert_eq!(again.secure_domains_list, ["*.ejemplo.es"]);
    }

    #[test]
    fn fichero_danado_o_valores_raros() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(PREFS_FILE), "{no es json").unwrap();
        assert_eq!(Prefs::open(dir.path()).get(), Preferences::default());
        std::fs::write(
            dir.path().join(PREFS_FILE),
            r#"{"stickySignatureTimeout": "15", "localeConfig": "fr", "otra": 1}"#,
        )
        .unwrap();
        let p = Prefs::open(dir.path()).get();
        assert_eq!(p.sticky_signature_timeout, CacheMinutes::Fifteen);
        assert_eq!(p.locale_config, None);
        assert!(p.first_execution, "las claves que faltan toman su valor por defecto");
        assert_eq!(CacheMinutes::from_minutes(7), CacheMinutes::Five);
    }

    #[test]
    fn dominios_de_confianza() {
        assert_eq!(
            parse_trusted_domains("  sede.ejemplo.es \n\n*.gob.es\nlocalhost:8443").unwrap(),
            ["sede.ejemplo.es", "*.gob.es", "localhost:8443"]
        );
        // También separados por comas, como dice la ayuda.
        assert_eq!(parse_trusted_domains("a.es, b.es").unwrap(), ["a.es", "b.es"]);
        assert_eq!(parse_trusted_domains("   ").unwrap(), Vec::<String>::new());
        assert_eq!(parse_trusted_domains("ok.es\nmal dominio").unwrap_err(), "mal dominio");
        assert_eq!(parse_trusted_domains("ab").unwrap_err(), "ab");
        assert_eq!(parse_trusted_domains("-ab.es").unwrap_err(), "-ab.es");
        assert_eq!(parse_trusted_domains("a*b.es").unwrap_err(), "a*b.es");
        assert!(parse_trusted_domains("SEDE.Ejemplo.ES").is_ok());
        assert!(parse_trusted_domains(&format!("a{}b", "c".repeat(61))).is_ok());
        assert!(parse_trusted_domains(&format!("a{}b", "c".repeat(62))).is_err());
        assert!(parse_trusted_domains("ñandú.es").is_err());
    }
}
