//! Almacenes de certificados para la interfaz.

use std::sync::Arc;

use afirma_keystores::{
    CandidateOptions, CertEntry, CertFilterManager, KeyStore, KeyStoreKind, LocalFilterPrefs, OpenOptions, Os,
    PasswordCallback, StoreSpec, select_candidates,
};

use crate::ui::cert_picker::StoreOption;
use crate::ui::icons;
use crate::ui::model::CertItem;

/// Almacén abierto con sus certificados candidatos.
pub struct LoadedStore {
    pub spec: StoreSpec,
    pub store: Arc<dyn KeyStore>,
    pub label: String,
    /// Entradas candidatas (filtradas y ordenadas), en el orden de `items`.
    pub entries: Vec<CertEntry>,
    pub items: Vec<CertItem>,
    /// Certificados ocultos por caducados (para informar al usuario).
    pub hidden_expired: usize,
}

/// Almacenes que se ofrecen al usuario en este sistema.
pub fn store_options() -> Vec<StoreOption> {
    let mut out = Vec::new();
    match Os::current() {
        Os::Windows => out.push(StoreOption { id: "WINDOWS".into(), label: "Almacén de Windows".into(), icon: icons::VAULT }),
        Os::MacOs => out.push(StoreOption { id: "APPLE".into(), label: "Llavero de macOS".into(), icon: icons::VAULT }),
        _ => out.push(StoreOption { id: "SHARED_NSS".into(), label: "Almacén del sistema (NSS)".into(), icon: icons::VAULT }),
    }
    out.push(StoreOption { id: "MOZ_UNI".into(), label: "Firefox".into(), icon: icons::BROWSER });
    out.push(StoreOption { id: "DNIEJAVA".into(), label: "DNIe y tarjetas".into(), icon: icons::IDENTIFICATION_BADGE });
    out.push(StoreOption { id: "PKCS12".into(), label: "Fichero .p12 / .pfx…".into(), icon: icons::FILE_LOCK });
    out
}

/// Almacén por defecto de este sistema.
pub fn default_spec() -> StoreSpec {
    StoreSpec::new(KeyStoreKind::default_for_current_os().unwrap_or(KeyStoreKind::Pkcs12))
}

/// Almacén por defecto según las preferencias `defaultKeystore` y
/// `defaultLocalKeystorePath` (como `SimpleKeyStoreManager`).
pub fn spec_from_prefs(pref: &dyn Fn(&str) -> Option<String>) -> StoreSpec {
    let prefs = afirma_keystores::selection::StorePreferences {
        default_keystore: pref("defaultKeystore").unwrap_or_else(|| "default".into()),
        default_local_keystore_path: pref("defaultLocalKeystorePath").unwrap_or_default(),
        use_default_store_in_browser_calls: pref("useDefaultStoreInBrowserCalls").is_some_and(|v| v == "true"),
    };
    let firefox = afirma_keystores::nss::is_firefox_available(&afirma_keystores::nss::profiles::MozEnv::current());
    afirma_keystores::selection::local_default_store(&prefs, &afirma_keystores::RegisteredCards::new(), Os::current(), firefox)
        .unwrap_or_else(default_spec)
}

/// Especificación a partir del identificador del selector (y, para
/// PKCS#12/PKCS#11, de la ruta).
pub fn spec_for(id: &str, lib: Option<String>) -> Option<StoreSpec> {
    let kind = KeyStoreKind::from_id(id)?;
    Some(StoreSpec { kind, lib, card_name: None })
}

/// Abre un almacén y obtiene sus certificados candidatos para firmar.
pub fn load(spec: &StoreSpec, callback: Arc<dyn PasswordCallback>, filters: &LocalFilterPrefs, force_reset: bool) -> Result<LoadedStore, String> {
    let opts = OpenOptions { force_reset, load_all_external_modules: true, dedup_all: true, ..OpenOptions::new(callback) };
    let store = afirma_keystores::open_store(spec, &opts).map_err(|e| e.to_string())?;
    if force_reset {
        let _ = store.refresh();
    }
    let all = store.entries().map_err(|e| e.to_string())?;
    let manager = CertFilterManager::from_local_prefs(filters);
    let options = CandidateOptions { check_private_keys: true, show_expired: filters.show_expired_certs, now: chrono::Utc::now() };
    let list = select_candidates(&all, manager.filters(), &options);
    let mut items = Vec::new();
    let mut entries = Vec::new();
    for e in list.candidates {
        if let Some(item) = CertItem::from_der(e.id.clone(), e.certificate.clone()) {
            items.push(item);
            entries.push(e);
        }
    }
    Ok(LoadedStore { label: spec.display_name(), spec: spec.clone(), store, entries, items, hidden_expired: list.hidden_expired })
}

/// Preferencias de filtrado de la aplicación de escritorio.
pub fn local_filters(pref: &dyn Fn(&str) -> Option<String>) -> LocalFilterPrefs {
    let b = |k: &str, d: bool| pref(k).map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(d);
    LocalFilterPrefs {
        use_only_signature_certificates: b("useOnlySignatureCertificates", false),
        skip_auth_cert_dnie: b("skipAuthCertDnie", true),
        use_only_alias_certificates: b("useOnlyAliasCertificates", false),
        show_expired_certs: b("showExpiredCerts", false),
    }
}
