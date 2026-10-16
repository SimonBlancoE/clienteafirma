//! Conexiones de red de la aplicación (sedes, sellos de tiempo, lotes,
//! servidores intermedios) con el proxy y la política TLS de las preferencias,
//! como `ProxyUtil.setProxySettings` de AutoFirma.

use std::sync::{Arc, OnceLock};

use afirma_core::http::{
    HttpClient, HttpMethod, HttpRequest, HttpSettings, ProxyMode, TrustPrompt, UntrustedServer, UreqHttpClient,
};

use crate::i18n::{tr, trf};
use crate::services::bridge::UiBridge;

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
        block_auto_import_trusted_certs: get("blockAutoImportTrustedCerts").as_deref() == Some("true")
            || get("allowAutoImportTrustedCerts").as_deref() == Some("false"),
        extra_trusted_certs: if personal_truststore_allowed(get) {
            afirma_keystores::jks::load_trusted_certs()
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

/// Los certificados de confianza personales solo se usan con conexiones
/// seguras y si el administrador no los ha desactivado (`allowPersonalTruststore`).
pub fn personal_truststore_allowed(get: &dyn Fn(&str) -> Option<String>) -> bool {
    get("secureConnections").as_deref() != Some("false") && get("allowPersonalTruststore").as_deref() != Some("false")
}

static PROMPT: OnceLock<Arc<dyn TrustPrompt>> = OnceLock::new();

/// Pregunta al usuario, desde la interfaz, si confía en un servidor con un
/// certificado TLS no reconocido (`SSLErrorProcessor` de AutoFirma) y guarda
/// los aceptados en el almacén de confianza personal.
struct AppTrustPrompt(UiBridge);

impl TrustPrompt for AppTrustPrompt {
    fn confirm_trust(&self, server: &UntrustedServer) -> bool {
        self.0.confirm(
            tr("Verificación de dominio"),
            trf(
                "Se ha intentado conectar con {0}, que presenta un certificado SSL que no es de confianza. ¿Quieres importar este certificado a tu almacén de confianza?",
                &[&server.host],
            ),
        )
    }

    fn store_trusted(&self, certs: &[Vec<u8>]) {
        match afirma_keystores::jks::TrustStore::open_default().and_then(|mut ts| ts.import(certs)) {
            Ok(n) => tracing::info!("{n} certificados añadidos al almacén de confianza personal"),
            Err(e) => tracing::warn!("No se han podido guardar los certificados de confianza: {e}"),
        }
    }
}

/// Activa la pregunta de confianza para las conexiones del proceso (una vez
/// creada la interfaz).
pub fn set_trust_prompt(bridge: UiBridge) {
    let _ = PROMPT.set(Arc::new(AppTrustPrompt(bridge)));
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
    let client = UreqHttpClient::new(settings);
    client.set_trust_prompt(PROMPT.get().cloned());
    afirma_core::http::install_http_client(Arc::new(client));
}

/// Comprueba la conexión a Internet con una configuración (botón «Comprobar»).
pub fn test(get: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    let client = UreqHttpClient::new(settings_from(get));
    client
        .read_url(&HttpRequest::new(TEST_URL, HttpMethod::Get))
        .map(|_| ())
        .map_err(|e| e.to_string())
}
