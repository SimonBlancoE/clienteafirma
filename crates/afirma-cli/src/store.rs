//! Almacén de claves y certificado de firma (`getKsm`, `filterCertificates`,
//! `-certgui`), §5.5 y §5.6.

use std::sync::Arc;

use afirma_core::ExtraParams;
use afirma_keystores::selection::{CliStoreError, parse_cli_store};
use afirma_keystores::{
    CandidateOptions, CertEntry, CertFilterManager, FixedPassword, KeyStore, KeyStoreError,
    KeyStoreKind, OpenOptions, Os, PasswordCallback, candidates_with_manager, open_store,
};

use crate::CliEnv;
use crate::error::CliError;
use crate::messages::Messages;

/// Petición de selección gráfica de certificado (`-certgui`,
/// `AOKeyStoreDialog`): solo certificados con clave privada, mostrando los
/// caducados (los oculta el filtro por defecto si no se indica ninguno), sin
/// aviso de caducidad y sin selección obligatoria.
pub struct CertificateRequest {
    /// Almacén abierto con `-store`.
    pub store: Arc<dyn KeyStore>,
    /// Filtros (`filter`/`filters`/`filters.N`/`headless`/`mandatoryCertSelection`
    /// de `-config`; `-filter` sustituye a `filters`).
    pub filters: CertFilterManager,
    /// Candidatos de `store` ya filtrados y ordenados como el diálogo.
    pub candidates: Vec<CertEntry>,
    /// Si el diálogo puede abrir otros almacenes (falso con
    /// `disableopeningexternalstores`).
    pub allow_external_stores: bool,
}

impl std::fmt::Debug for CertificateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateRequest")
            .field("store", &self.store.kind())
            .field("filters", &self.filters)
            .field("candidates", &self.candidates.len())
            .field("allow_external_stores", &self.allow_external_stores)
            .finish()
    }
}

/// Certificado elegido en el diálogo. El almacén puede ser distinto del de
/// `-store` si el usuario cambió de almacén en el diálogo.
pub struct CertificateChoice {
    /// Almacén del certificado elegido.
    pub store: Arc<dyn KeyStore>,
    /// Alias (o identificador) de la entrada.
    pub alias: String,
}

/// Selector gráfico de certificados que proporciona la aplicación para
/// `-certgui`.
pub trait CertificateChooser: Send + Sync {
    /// Muestra el diálogo. `Ok(None)` si el usuario cancela; `Err` con un
    /// mensaje si no se puede mostrar.
    fn choose(&self, request: &CertificateRequest) -> Result<Option<CertificateChoice>, String>;
}

/// Mensaje de Java cuando no se elige certificado (`AOKeyStoreDialog`).
pub const NO_CERTIFICATE_SELECTED: &str = "No se ha seleccionado certificado";
/// Mensaje cuando no hay selector gráfico (nuevo).
pub const NO_CHOOSER: &str =
    "No se puede mostrar el dialogo de seleccion de certificado (-certgui) en este entorno";

/// Abre el almacén de `-store` (`getKsm`): con `-password`, contraseña fija;
/// si no, el proveedor de contraseñas de la aplicación.
pub fn open(
    store: Option<&str>,
    password: Option<&str>,
    env: &CliEnv,
    m: &Messages,
) -> Result<Arc<dyn KeyStore>, CliError> {
    let spec = parse_cli_store(store, Os::current()).map_err(|e| match e {
        CliStoreError::Unknown(v) => CliError::syntax_plain(m.fmt(48, &[&v])),
        other => CliError::plain(other.to_string()),
    })?;
    let callback: Arc<dyn PasswordCallback> = match password {
        Some(p) => Arc::new(FixedPassword::new(p)),
        None => env.password_callback.clone(),
    };
    let mut opts = OpenOptions::new(callback);
    opts.description = Some("CommandLine".into());
    open_store(&spec, &opts).map_err(|e| keystore_error(&e, m))
}

/// Error de apertura del almacén como lo imprime Java: los errores de
/// disponibilidad (`KeystoreAlternativeException`) con `CommandLineLauncher.49`,
/// el resto con su mensaje; la cancelación como error no reconocido.
pub fn keystore_error(e: &KeyStoreError, m: &Messages) -> CliError {
    match e {
        KeyStoreError::Cancelled => CliError::Unexpected(e.to_string()),
        KeyStoreError::Unsupported { .. }
        | KeyStoreError::UndefinedDefault
        | KeyStoreError::Firefox(_) => CliError::plain(m.fmt(49, &[&e.to_string()])),
        KeyStoreError::Load { kind, .. } if *kind != KeyStoreKind::Pkcs12 => {
            CliError::plain(m.fmt(49, &[&e.to_string()]))
        }
        KeyStoreError::Pkcs11 { .. } | KeyStoreError::LibraryNotFound(_) => {
            CliError::plain(m.fmt(49, &[&e.to_string()]))
        }
        _ => CliError::plain(e.to_string()),
    }
}

/// `filterCertificates`: el filtro de `-filter` debe aceptar exactamente un
/// certificado de todos los del almacén.
pub fn filter_alias(store: &dyn KeyStore, filter: &str, m: &Messages) -> Result<String, CliError> {
    let manager = CertFilterManager::from_cli_filter(filter)
        .map_err(|e| CliError::Unexpected(e.to_string()))?;
    let entries = store
        .entries()
        .map_err(|e| CliError::plain(e.to_string()))?;
    let matches = manager.apply(&entries, chrono::Utc::now());
    match matches.as_slice() {
        [] => Err(CliError::plain(m.get(52))),
        [one] => Ok(one.alias.clone()),
        _ => Err(CliError::plain(m.get(53))),
    }
}

/// `-certgui`: diálogo de selección de la aplicación.
pub fn choose_with_gui(
    store: Arc<dyn KeyStore>,
    config: &ExtraParams,
    filter: Option<&str>,
    env: &CliEnv,
) -> Result<(Arc<dyn KeyStore>, String), CliError> {
    let mut props = config.clone();
    if let Some(f) = filter.filter(|f| !f.is_empty()) {
        props.set("filters", f);
    }
    let filters = CertFilterManager::from_extra_params(&props)
        .map_err(|e| CliError::Unexpected(e.to_string()))?;
    let Some(chooser) = env.certificate_chooser.as_ref() else {
        return Err(CliError::plain(NO_CHOOSER));
    };
    let entries = store
        .entries()
        .map_err(|e| CliError::plain(e.to_string()))?;
    let candidates = candidates_with_manager(
        &entries,
        &filters,
        &CandidateOptions::protocol(chrono::Utc::now()),
    )
    .candidates;
    let request = CertificateRequest {
        allow_external_stores: filters.allow_external_stores(),
        store,
        filters,
        candidates,
    };
    match chooser.choose(&request) {
        Ok(Some(choice)) => Ok((choice.store, choice.alias)),
        Ok(None) => Err(CliError::Unexpected(NO_CERTIFICATE_SELECTED.into())),
        Err(e) => Err(CliError::plain(e)),
    }
}
