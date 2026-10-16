//! Aviso de nueva versión (el `Updater` de AutoFirma): solo informa y ofrece
//! abrir la página de descarga; nunca descarga ni instala nada.
//!
//! La fuente es la API de versiones publicadas del repositorio del proyecto,
//! fijada al compilar con `AUTOFIRMA_RELEASES_API` (p. ej.
//! `https://api.github.com/repos/<org>/<repo>/releases/latest`). Sin ella la
//! comprobación queda desactivada, como deben hacer las compilaciones de las
//! distribuciones y de las tiendas. Se respetan las mismas exclusiones que en
//! Java: `AUTOFIRMA_AVOID_UPDATE_CHECK=true`, la preferencia `checkForUpdates`
//! (bloqueable por el administrador) y como mucho una comprobación al día.

use afirma_core::http::{HttpMethod, HttpRequest};
use afirma_system::prefs::{Preferences, ResolutionMode, keys};
use afirma_system::{AppIdentity, Context};

/// API de la última versión publicada (configurada al compilar).
pub const RELEASES_API: Option<&str> = option_env!("AUTOFIRMA_RELEASES_API");

/// Versión disponible más reciente que la instalada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateInfo {
    pub version: String,
    /// Página de la versión (se abre en el navegador).
    pub url: String,
}

/// Si la comprobación está permitida (sin mirar la fecha de la última).
pub fn enabled(get: &dyn Fn(&str) -> Option<String>) -> bool {
    let avoid = std::env::var("AUTOFIRMA_AVOID_UPDATE_CHECK").is_ok_and(|v| v.eq_ignore_ascii_case("true"));
    RELEASES_API.is_some() && !avoid && get("checkForUpdates").as_deref() != Some("false")
}

/// Comprueba si hay una versión nueva (como mucho una vez al día). Se ejecuta
/// en segundo plano; cualquier error se registra y se ignora.
pub fn check_daily() -> Option<UpdateInfo> {
    let api = RELEASES_API?;
    let ctx = Context::detect(AppIdentity::current());
    let mut prefs = Preferences::load(&ctx, ResolutionMode::Strict).ok()?;
    let today = chrono::Local::now().format("%Y%m%d").to_string();
    if prefs.get_aux(keys::AUX_UPDATER_LAST_CHECK).is_some_and(|d| d >= today) {
        return None;
    }
    let body = match afirma_core::http::installed_http_client().read_url(&HttpRequest::new(api, HttpMethod::Get)) {
        Ok(b) => b,
        Err(e) => {
            tracing::info!("No se ha podido comprobar si hay una versión nueva: {e}");
            return None;
        }
    };
    // Solo se anota la fecha si la comprobación ha funcionado (como Java).
    let _ = prefs.put_aux(keys::AUX_UPDATER_LAST_CHECK, &today);
    let info = parse_release(&body)?;
    if is_newer(&info.version, env!("CARGO_PKG_VERSION")) {
        tracing::info!("Versión nueva disponible: {}", info.version);
        Some(info)
    } else {
        tracing::info!("Se usa la última versión");
        None
    }
}

/// `tag_name` y `html_url` de la respuesta de la API de versiones.
fn parse_release(body: &[u8]) -> Option<UpdateInfo> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    if v.get("draft").and_then(|d| d.as_bool()) == Some(true) || v.get("prerelease").and_then(|d| d.as_bool()) == Some(true) {
        return None;
    }
    let tag = v.get("tag_name")?.as_str()?;
    let url = v.get("html_url")?.as_str()?;
    if !url.starts_with("https://") {
        return None;
    }
    Some(UpdateInfo { version: tag.trim_start_matches(['v', 'V']).to_string(), url: url.to_string() })
}

/// Compara versiones semánticas (`2.1.0` > `2.0.0` > `2.0.0-alpha.1`).
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<((u64, u64, u64), Option<String>)> {
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p.to_string())),
            None => (v, None),
        };
        let mut n = core.split('.').map(|x| x.parse::<u64>().ok());
        Some(((n.next()??, n.next().flatten().unwrap_or(0), n.next().flatten().unwrap_or(0)), pre))
    }
    let (Some((a, pa)), Some((b, pb))) = (parse(candidate), parse(current)) else { return false };
    match a.cmp(&b) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Misma versión: una definitiva es posterior a sus versiones previas.
        std::cmp::Ordering::Equal => matches!((pa, pb), (None, Some(_))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparacion_de_versiones() {
        assert!(is_newer("2.0.1", "2.0.0"));
        assert!(is_newer("2.0.0", "2.0.0-alpha.1"));
        assert!(is_newer("3", "2.9.9"));
        assert!(!is_newer("2.0.0-beta.1", "2.0.0"));
        assert!(!is_newer("2.0.0", "2.0.0"));
        assert!(!is_newer("1.9", "2.0.0-alpha.1"));
        assert!(!is_newer("x", "2.0.0"));
    }

    #[test]
    fn respuesta_de_la_api() {
        let r = parse_release(br#"{"tag_name":"v2.1.0","html_url":"https://example.org/r/2.1.0","draft":false,"prerelease":false}"#).unwrap();
        assert_eq!(r.version, "2.1.0");
        assert!(parse_release(br#"{"tag_name":"v2.1.0","html_url":"https://x","prerelease":true}"#).is_none());
        assert!(parse_release(br#"{"tag_name":"v2.1.0","html_url":"http://x"}"#).is_none());
    }
}
