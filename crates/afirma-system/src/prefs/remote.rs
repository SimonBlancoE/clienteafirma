//! Configuración del sistema desde fichero o URL (`-config_path`, `-update_config`) y
//! actualización remota diaria (§4.11, §9.6).
//!
//! Desviaciones documentadas respecto a Java:
//! * Las descargas `https://` validan TLS con el almacén del sistema (Java las hacía sin
//!   validar el certificado del servidor).
//! * Se aplica `requireSignedPrerefences` / `certHashToSignedPrerefences` también a la
//!   configuración de sistema y remota (Java no comprobaba la firma).
//! * `configDate` usa el año natural (`yyyyMMdd`); un valor heredado «del futuro» (patrón
//!   `YYYY` de semana de Java) se trata como caducado.
//! * Se rechazan URL `http://` (solo `https://` o rutas locales).

use std::io::Read as _;
use std::time::Duration;

use sha2::Digest as _;

use super::Preferences;
use super::afconfig::{self, ConfigError, ConfigSignatureVerifier, SignatureStatus, codes};
use super::keys;
use super::system::{SystemPrefsWriter, SystemTarget};
use crate::ctx::Context;
use crate::error::{Result, SystemError};

/// Descarga de ficheros de configuración.
pub trait Fetcher: Send + Sync {
    /// Descarga el contenido de una URL `https://`.
    fn fetch(&self, url: &str) -> std::result::Result<Vec<u8>, String>;
}

/// Descargador HTTPS con validación TLS del sistema (rustls + verificador de la plataforma).
#[derive(Debug, Clone)]
pub struct HttpsFetcher {
    /// Tiempo máximo total.
    pub timeout: Duration,
    /// Tamaño máximo.
    pub max_size: u64,
}

impl Default for HttpsFetcher {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_size: afconfig::MAX_AFCONFIG_SIZE as u64,
        }
    }
}

impl Fetcher for HttpsFetcher {
    fn fetch(&self, url: &str) -> std::result::Result<Vec<u8>, String> {
        if !url.to_ascii_lowercase().starts_with("https://") {
            return Err("solo se admiten URL https://".into());
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build()
            .into();
        let resp = agent.get(url).call().map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        resp.into_body()
            .into_reader()
            .take(self.max_size + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() as u64 > self.max_size {
            return Err("el fichero de configuración es demasiado grande".into());
        }
        Ok(data)
    }
}

/// Normaliza la ruta de configuración: `https:\\host\f` (MSI) → `https://host/f`.
pub fn normalize_config_path(path: &str) -> String {
    let p = path.trim();
    if p.len() >= 6 && p[..6].eq_ignore_ascii_case("https:") {
        p.replace('\\', "/")
    } else {
        p.to_string()
    }
}

fn is_https(p: &str) -> bool {
    p.len() >= 8 && p[..8].eq_ignore_ascii_case("https://")
}

/// Lee el fichero de configuración de una ruta local o URL `https://`.
pub fn read_config_source(
    path: &str,
    fetcher: &dyn Fetcher,
) -> std::result::Result<Vec<u8>, ConfigError> {
    let p = normalize_config_path(path);
    if is_https(&p) {
        return fetcher
            .fetch(&p)
            .map_err(|e| ConfigError::new(codes::CANT_READ_PREFERENCES_FILE).with_detail(e));
    }
    if p.len() >= 7 && p[..7].eq_ignore_ascii_case("http://") {
        return Err(ConfigError::new(codes::CANT_READ_PREFERENCES_FILE)
            .with_detail("las URL http:// no están permitidas; use https://"));
    }
    let meta = std::fs::metadata(&p).map_err(|e| {
        ConfigError::new(codes::CANT_READ_PREFERENCES_FILE).with_detail(e.to_string())
    })?;
    if meta.len() > afconfig::MAX_AFCONFIG_SIZE as u64 {
        return Err(ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE)
            .with_detail("fichero demasiado grande"));
    }
    std::fs::read(&p)
        .map_err(|e| ConfigError::new(codes::CANT_READ_PREFERENCES_FILE).with_detail(e.to_string()))
}

/// Huella SHA-256 en hexadecimal en mayúsculas (`ConfigDataInfo`).
pub fn config_hash(data: &[u8]) -> String {
    hex::encode_upper(sha2::Sha256::digest(data))
}

/// Fecha en el formato de `configDate` (año natural).
pub fn config_date(d: chrono::NaiveDate) -> String {
    d.format("%Y%m%d").to_string()
}

/// Resultado de la instalación de una configuración de sistema.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemConfigReport {
    /// Destino de la escritura.
    pub written_to_user_copy: bool,
    /// Claves aplicadas.
    pub keys: usize,
    /// Tarjetas aplicadas (si el fichero las declaraba).
    pub smartcards: Option<usize>,
    /// Huella del fichero.
    pub sha256: String,
    /// Si quedó activada la actualización diaria.
    pub updates_enabled: bool,
    /// Firmante (CN) si el fichero estaba firmado y se verificó.
    pub signer: Option<String>,
}

fn check_system_signature(
    data: &[u8],
    content: &afconfig::AfconfigContent,
    prefs: Option<&Preferences>,
    verifier: Option<&dyn ConfigSignatureVerifier>,
) -> std::result::Result<Option<String>, ConfigError> {
    let policy = prefs.map(Preferences::signature_policy).unwrap_or_default();
    if content.has_signature && verifier.is_none() && !policy.require_signed {
        tracing::warn!(
            "La configuración está firmada pero no hay verificador XMLDSig disponible: se importa sin verificar la firma"
        );
        return Ok(None);
    }
    match afconfig::check_signature(data, content, verifier, &policy, chrono::Utc::now())? {
        SignatureStatus::Signed(s) => Ok(Some(s.common_name())),
        SignatureStatus::Unsigned => Ok(None),
    }
}

/// Importa una configuración en la capa de sistema (`ConfigUpdaterManager.savePrefsConfigFile`):
/// borra las preferencias de sistema, aplica las del fichero (y sus tarjetas, que sustituyen a
/// las de sistema) y registra el origen, la huella y la fecha en el nodo interno.
pub fn install_system_config(
    ctx: &Context,
    path: &str,
    allow_updates: bool,
    fetcher: &dyn Fetcher,
    verifier: Option<&dyn ConfigSignatureVerifier>,
) -> Result<SystemConfigReport> {
    let path = normalize_config_path(path);
    let data = read_config_source(&path, fetcher)?;
    let prefs = Preferences::load(ctx, super::ResolutionMode::Strict).ok();
    apply_system_config(
        ctx,
        &path,
        &data,
        allow_updates,
        prefs.as_ref(),
        verifier,
        chrono::Local::now().date_naive(),
    )
}

/// Aplica unos datos de configuración ya leídos a la capa de sistema.
pub fn apply_system_config(
    ctx: &Context,
    path: &str,
    data: &[u8],
    allow_updates: bool,
    prefs: Option<&Preferences>,
    verifier: Option<&dyn ConfigSignatureVerifier>,
    today: chrono::NaiveDate,
) -> Result<SystemConfigReport> {
    let content = afconfig::parse(data)?;
    let signer = check_system_signature(data, &content, prefs, verifier)?;
    let hash = config_hash(data);
    let mut w = SystemPrefsWriter::open(ctx)?;
    w.clear_main();
    for (k, v) in &content.prefs {
        w.put(k, v);
    }
    if let Some(cards) = &content.smartcards {
        w.replace_smartcards(cards);
    }
    let updates = allow_updates && is_https(path);
    w.put_internal(keys::CONFIG_FILE_URL.name(), path);
    if updates {
        w.put_internal(keys::ALLOW_UPDATE_CONFIG.name(), "true");
    } else {
        w.remove_internal(keys::ALLOW_UPDATE_CONFIG.name());
    }
    w.put_internal(keys::CONFIG_FILE_SHA256.name(), &hash);
    w.put_internal(keys::CONFIG_DATE.name(), &config_date(today));
    w.flush()?;
    Ok(SystemConfigReport {
        written_to_user_copy: *w.target() == SystemTarget::UserFallback,
        keys: content.prefs.len(),
        smartcards: content.smartcards.as_ref().map(|c| c.len()),
        sha256: hash,
        updates_enabled: updates,
        signer,
    })
}

/// `needCheckConfigUpdates`: actualización activada, URL `https://` y sin comprobar hoy.
pub fn needs_update_check(prefs: &Preferences, today: chrono::NaiveDate) -> bool {
    if !prefs.get_bool(keys::ALLOW_UPDATE_CONFIG.name()) {
        return false;
    }
    let Some(url) = prefs.get(keys::CONFIG_FILE_URL.name()) else {
        return false;
    };
    if !is_https(&url) {
        return false;
    }
    let t = config_date(today);
    match prefs.get(keys::CONFIG_DATE.name()) {
        None => true,
        // Comparación de cadenas como Java; una fecha futura (año de semana) se considera caducada.
        Some(d) => d != t,
    }
}

/// Resultado de la comprobación diaria.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum UpdateOutcome {
    /// No tocaba comprobar.
    NotNeeded,
    /// El fichero no ha cambiado (se actualiza la fecha).
    Unchanged,
    /// Se aplicó la nueva configuración (efectiva en el próximo arranque).
    Updated,
}

/// Comprobación diaria de la configuración remota (`updatePrefsConfigFile`).
pub fn run_update_check(
    ctx: &Context,
    prefs: &Preferences,
    fetcher: &dyn Fetcher,
    verifier: Option<&dyn ConfigSignatureVerifier>,
    today: chrono::NaiveDate,
) -> Result<UpdateOutcome> {
    if !needs_update_check(prefs, today) {
        return Ok(UpdateOutcome::NotNeeded);
    }
    let url = prefs.get(keys::CONFIG_FILE_URL.name()).unwrap_or_default();
    // Error de descarga: se registra y no se actualiza la fecha (como Java).
    let data = fetcher.fetch(&url).map_err(|e| {
        SystemError::Config(ConfigError::new(codes::CANT_READ_PREFERENCES_FILE).with_detail(e))
    })?;
    let hash = config_hash(&data);
    if prefs.get(keys::CONFIG_FILE_SHA256.name()).as_deref() == Some(hash.as_str()) {
        let mut w = SystemPrefsWriter::open(ctx)?;
        w.put_internal(keys::CONFIG_DATE.name(), &config_date(today));
        w.flush()?;
        return Ok(UpdateOutcome::Unchanged);
    }
    apply_system_config(ctx, &url, &data, true, Some(prefs), verifier, today)?;
    Ok(UpdateOutcome::Updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;
    use crate::prefs::ResolutionMode;
    use crate::prefs::tree::NODE_MAIN;

    struct MapFetcher(std::collections::BTreeMap<String, Vec<u8>>);
    impl Fetcher for MapFetcher {
        fn fetch(&self, url: &str) -> std::result::Result<Vec<u8>, String> {
            self.0.get(url).cloned().ok_or_else(|| "404".into())
        }
    }

    const CFG1: &str = "<plist><dict><key>signatureHashAlgorithm</key><string>SHA512</string><key>preferencesBlocked</key><true/></dict></plist>";
    const CFG2: &str =
        "<plist><dict><key>signatureHashAlgorithm</key><string>SHA384</string></dict></plist>";

    #[test]
    fn normaliza_rutas_msi() {
        assert_eq!(
            normalize_config_path(r"https:\\intranet.example\autofirma.afconfig"),
            "https://intranet.example/autofirma.afconfig"
        );
        assert_eq!(
            normalize_config_path(r"C:\cfg\a.afconfig"),
            r"C:\cfg\a.afconfig"
        );
        let f = MapFetcher(Default::default());
        assert!(read_config_source("http://x/y", &f).is_err());
    }

    #[test]
    fn instalacion_y_actualizacion_diaria() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let url = "https://intra.example/af.afconfig";
        let mut m = std::collections::BTreeMap::new();
        m.insert(url.to_string(), CFG1.as_bytes().to_vec());
        let f = MapFetcher(m);
        let rep = install_system_config(&ctx, r"https:\\intra.example\af.afconfig", true, &f, None)
            .unwrap();
        assert!(rep.updates_enabled);
        assert_eq!(rep.sha256, config_hash(CFG1.as_bytes()));
        let p = Preferences::load(&ctx, ResolutionMode::Strict).unwrap();
        assert_eq!(p.get("signatureHashAlgorithm").as_deref(), Some("SHA512"));
        assert!(p.is_blocked());
        assert_eq!(p.get("configFileUrl").as_deref(), Some(url));
        let today = chrono::Local::now().date_naive();
        assert!(!needs_update_check(&p, today), "ya comprobado hoy");
        let tomorrow = today + chrono::Duration::days(1);
        assert!(needs_update_check(&p, tomorrow));
        assert_eq!(
            run_update_check(&ctx, &p, &f, None, tomorrow).unwrap(),
            UpdateOutcome::Unchanged
        );
        let mut m2 = std::collections::BTreeMap::new();
        m2.insert(url.to_string(), CFG2.as_bytes().to_vec());
        let f2 = MapFetcher(m2);
        let p = Preferences::load(&ctx, ResolutionMode::Strict).unwrap();
        let later = tomorrow + chrono::Duration::days(1);
        assert_eq!(
            run_update_check(&ctx, &p, &f2, None, later).unwrap(),
            UpdateOutcome::Updated
        );
        let p = Preferences::load(&ctx, ResolutionMode::Strict).unwrap();
        assert_eq!(
            p.system_layer()
                .main
                .get("signatureHashAlgorithm")
                .map(String::as_str),
            Some("SHA384")
        );
        assert!(!p.is_blocked());
        assert!(p.user_tree().node(NODE_MAIN).is_none());
    }

    #[test]
    fn fecha_heredada_del_futuro_se_considera_caducada() {
        let mut layer = crate::prefs::SystemLayer::default();
        layer
            .internal
            .insert("allowUpdateConfig".into(), "true".into());
        layer
            .internal
            .insert("configFileUrl".into(), "https://x/y".into());
        layer
            .internal
            .insert("configDate".into(), "20271231".into());
        let p = Preferences::from_layers(
            ResolutionMode::Strict,
            Default::default(),
            layer,
            Default::default(),
        );
        let d = chrono::NaiveDate::from_ymd_opt(2026, 12, 30).unwrap();
        assert!(needs_update_check(&p, d));
    }
}
