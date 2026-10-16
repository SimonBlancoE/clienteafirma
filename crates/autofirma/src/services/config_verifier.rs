//! Verificación de la firma XMLDSig de los ficheros de configuración
//! `.afconfig` (importación desde Preferencias, instalación corporativa y
//! actualización diaria).

use afirma_core::validity::{Validity, ValidityError};
use afirma_system::prefs::afconfig::{ConfigError, ConfigSignatureVerifier, ConfigSigner, codes};

pub struct XmlConfigVerifier;

impl ConfigSignatureVerifier for XmlConfigVerifier {
    fn verify(&self, xml: &[u8]) -> Result<ConfigSigner, ConfigError> {
        let results = afirma_xml::validation::validate(xml, false, &afirma_xml::dsig::NoResolver);
        let valid = !results.is_empty()
            && results.iter().all(|v| {
                v.validity == Validity::Ok
                    || (v.validity == Validity::Unknown && v.error == Some(ValidityError::SignProfileNotChecked))
            });
        if !valid {
            let detail = results.first().map(|v| v.to_string()).unwrap_or_default();
            return Err(ConfigError::new(codes::INVALID_PREFERENCES_FILE_SIGNATURE).with_detail(detail));
        }
        let certificate_der = afirma_xml::validation::signature_certificates(xml)
            .into_iter()
            .next()
            .ok_or_else(|| ConfigError::new(codes::INVALID_PREFERENCES_FILE_SIGNATURE).with_detail(crate::i18n::tr("firma sin certificado")))?;
        Ok(ConfigSigner { certificate_der })
    }
}

/// Registra el verificador para todo el proceso.
pub fn register() {
    afirma_system::prefs::afconfig::set_default_verifier(Box::new(XmlConfigVerifier));
}

/// Comprobación diaria de la configuración corporativa remota
/// (`allowUpdateConfig`), en segundo plano.
pub fn spawn_daily_update() {
    let _ = std::thread::Builder::new().name("config-remota".into()).spawn(|| {
        use afirma_system::prefs::{Preferences, ResolutionMode, remote};
        use afirma_system::{AppIdentity, Context};
        let ctx = Context::detect(AppIdentity::current());
        let Ok(prefs) = Preferences::load(&ctx, ResolutionMode::Strict) else { return };
        let today = chrono::Local::now().date_naive();
        match remote::run_update_check(
            &ctx,
            &prefs,
            &remote::HttpsFetcher::default(),
            afirma_system::prefs::afconfig::default_verifier(),
            today,
        ) {
            Ok(outcome) => tracing::info!("Configuración remota: {outcome:?}"),
            Err(e) => tracing::warn!("No se ha podido actualizar la configuración remota: {e}"),
        }
    });
}
