//! Validación del estado de un certificado (OCSP o CRL), como el complemento
//! «Validación de certificados» de AutoFirma.

use std::path::Path;

use afirma_certval::{ValidationOptions, ValidationReport, ValidationResult};

use crate::i18n::{tr, trf};

/// Resultado para la interfaz.
#[derive(Debug, Clone)]
pub struct CertCheck {
    pub ok: bool,
    pub title: String,
    /// Detalle técnico (mecanismo, respondedor, motivo de revocación...).
    pub detail: Option<String>,
}

/// Valida un certificado con su cadena (si se conoce). Bloquea: se llama en
/// segundo plano.
pub fn check(der: &[u8], chain: &[Vec<u8>]) -> CertCheck {
    let report = afirma_certval::validate_certificate_report(der, &ValidationOptions::with_chain(chain));
    tracing::info!("Validación de certificado: {:?} ({:?})", report.result, report.method);
    from_report(&report)
}

/// Valida el primer certificado de un fichero (DER o PEM).
pub fn check_file(path: &Path) -> CertCheck {
    let parsed = std::fs::read(path)
        .map_err(|e| e.to_string())
        .and_then(|d| afirma_keystores::jks::parse_certificate_file(&d).map_err(|e| e.to_string()));
    match parsed {
        Ok(certs) if !certs.is_empty() => check(&certs[0], &certs[1..]),
        Ok(_) => CertCheck {
            ok: false,
            title: tr("El fichero no contiene ningún certificado").into(),
            detail: None,
        },
        Err(e) => CertCheck {
            ok: false,
            title: tr("No se ha podido leer el certificado").into(),
            detail: Some(e),
        },
    }
}

fn from_report(report: &ValidationReport) -> CertCheck {
    let title = if report.no_mechanism {
        tr("No se dispone de ningún mecanismo de validación para el tipo de certificado utilizado").to_string()
    } else {
        message(report.result).to_string()
    };
    let mut detail = report.detail.clone();
    if let Some(t) = report.revocation.as_ref().and_then(|r| r.time) {
        let when = trf("Revocado el {0}", &[&t.format("%d/%m/%Y %H:%M")]);
        detail = Some(match detail {
            Some(d) => format!("{when}\n{d}"),
            None => when,
        });
    }
    CertCheck {
        ok: !report.dialog_is_error(),
        title,
        detail,
    }
}

/// Textos del diálogo de resultado de AutoFirma (traducidos).
fn message(result: ValidationResult) -> &'static str {
    match result {
        ValidationResult::Valid => tr("El certificado es válido"),
        ValidationResult::Expired => tr("El certificado está caducado"),
        ValidationResult::Revoked => tr("El certificado está revocado"),
        ValidationResult::NotYetValid => tr("El certificado aún no es válido"),
        ValidationResult::CaNotSupported => tr("Autoridad de certificación no soportada"),
        ValidationResult::Corrupt => tr("El certificado está corrupto"),
        ValidationResult::ServerError => tr("El servicio de validación devolvió un error"),
        ValidationResult::Unknown => tr("Se desconoce el estado del certificado."),
        _ => tr("No se ha podido comprobar la validez del certificado"),
    }
}
