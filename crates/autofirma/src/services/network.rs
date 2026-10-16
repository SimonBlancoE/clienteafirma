//! Conexiones de red de la aplicación (sedes, sellos de tiempo, lotes,
//! servidores intermedios) con el proxy y la política TLS de las preferencias,
//! como `ProxyUtil.setProxySettings` de AutoFirma.

use std::sync::Arc;

use afirma_core::http::{HttpClient, HttpMethod, HttpRequest, HttpSettings, ProxyMode, UreqHttpClient};

/// URL con la que se comprueba la conexión desde Preferencias.
const TEST_URL: &str = "https://www.google.com";

/// Configuración HTTP a partir de las preferencias (`proxyType`, `proxyHost`,
/// `secureConnections`, `secureDomainsList`...).
pub fn settings_from(get: &dyn Fn(&str) -> Option<String>) -> HttpSettings {
    let proxy = ProxyMode::from_preferences(
        get("proxyType").as_deref(),
        get("proxySelected").as_deref() == Some("true"),
        get("proxyHost").as_deref(),
        get("proxyPort").as_deref(),
        get("proxyUsername").as_deref(),
        get("proxyPassword").as_deref(),
        get("proxyExcludedUrls").as_deref(),
    );
    HttpSettings {
        proxy,
        disable_ssl_checks: get("secureConnections").as_deref() == Some("false"),
        secure_domains: get("secureDomainsList")
            .map(|l| HttpSettings::parse_secure_domains(&l))
            .unwrap_or_default(),
        block_auto_import_trusted_certs: get("blockAutoImportTrustedCerts").as_deref() == Some("true"),
        ..Default::default()
    }
}

/// Instala el cliente HTTP del proceso con la configuración de las preferencias.
pub fn install(get: &dyn Fn(&str) -> Option<String>) {
    let settings = settings_from(get);
    tracing::info!(
        "Red: proxy {:?}",
        match &settings.proxy {
            ProxyMode::None => "ninguno".to_string(),
            ProxyMode::System => "del sistema".to_string(),
            ProxyMode::Custom(p) => format!("{}:{}", p.host, p.port),
        }
    );
    afirma_core::http::install_http_client(Arc::new(UreqHttpClient::new(settings)));
}

/// Comprueba la conexión a Internet con una configuración (botón «Comprobar»).
pub fn test(get: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    let client = UreqHttpClient::new(settings_from(get));
    client
        .read_url(&HttpRequest::new(TEST_URL, HttpMethod::Get))
        .map(|_| ())
        .map_err(|e| e.to_string())
}
