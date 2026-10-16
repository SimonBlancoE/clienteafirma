//! Validación del estado de certificados X.509 por OCSP y CRL: plugin
//! «Validación de certificados» de AutoFirma
//! (`afirma-simple-plugin-validatecerts`, especificación
//! `docs/spec/06-app-ui-cli-installer.md` §7.6).
//!
//! Uso habitual desde la interfaz (botón "Validar certificado de firma" de
//! las pantallas de resultado), en un hilo de trabajo:
//!
//! ```no_run
//! use afirma_certval::{ValidationOptions, validate_certificate_report};
//! # let cert_der: Vec<u8> = Vec::new();
//! # let chain: Vec<Vec<u8>> = Vec::new();
//! let report = validate_certificate_report(&cert_der, &ValidationOptions::with_chain(&chain));
//! println!("{}: {}", report.dialog_title(), report.dialog_message());
//! ```
//!
//! Comportamiento (ver [`ValidationOptions`] y `docs/deviations/afirma-certval.md`):
//!
//! 1. Certificado no analizable → `CORRUPT`; fuera del periodo de validez →
//!    `EXPIRED` / `NOT_YET_VALID`.
//! 2. Emisor: el indicado (que debe haber emitido el certificado, si no
//!    `CA_NOT_SUPPORTED`) o el que se encuentre en la cadena, entre las CA
//!    incluidas o descargándolo de la AIA (`caIssuers`).
//! 3. Revocación: OCSP (servicio `id-ad-ocsp` de la AIA) y, si no da una
//!    respuesta definitiva, CRL (puntos de distribución HTTP, HTTPS, LDAP o
//!    fichero). Con [`SelectionMode::JavaFactory`] se elige como Java.
//! 4. A diferencia de Java, se verifican la firma de las respuestas OCSP (por
//!    el emisor o un respondedor delegado autorizado), el `CertID` y las
//!    fechas `thisUpdate`/`nextUpdate`, y la firma y vigencia de las CRL.
//!
//! La red se usa a través de [`HttpFetcher`]; por defecto,
//! [`AfirmaHttpFetcher`] con el cliente HTTP del proceso
//! ([`afirma_core::http::installed_http_client`]), que aplica el proxy y la
//! configuración TLS del usuario.

mod certs;
mod crl;
mod factory;
pub mod fetch;
pub mod ldap;
pub mod messages;
mod ocsp;
mod options;
mod result;
mod sig;
mod validate;
mod x509;

pub use certs::parse_certificates;
pub use factory::{bundled_ca_certificates, java_issuer_identifier};
pub use fetch::{AfirmaHttpFetcher, FetchError, HttpFetcher, Timeouts};
pub use options::{OcspHttpMethod, SelectionMode, ValidationOptions};
pub use result::{
    IssuerSource, RevocationInfo, RevocationReason, ValidationMethod, ValidationReport, ValidationResult,
};
pub use validate::{validate_certificate, validate_certificate_report};

/// Funciones internas expuestas solo para las pruebas diferenciales con el
/// oráculo Java (`tests/`). No forman parte de la API estable.
#[doc(hidden)]
pub mod testing {
    /// Petición OCSP (DER) para `cert` con el emisor `issuer` (o el propio
    /// certificado si no se indica, como Java).
    pub fn ocsp_request(cert_der: &[u8], issuer_der: Option<&[u8]>) -> Option<Vec<u8>> {
        let cert = crate::x509::Cert::parse(cert_der).ok()?;
        let issuer = match issuer_der {
            Some(d) => crate::x509::Cert::parse(d).ok()?,
            None => cert.clone(),
        };
        let id = crate::ocsp::CertId::new(
            afirma_core::algorithms::DigestAlgorithm::Sha1,
            &cert.serial,
            &issuer.subject,
            &issuer.public_key_bits()?,
        );
        Some(crate::ocsp::build_request(&id))
    }

    /// `OcspHelper.analyzeOcspResponse` (sin comprobaciones de seguridad).
    pub fn java_analyze_ocsp(response: &[u8]) -> crate::ValidationResult {
        crate::ocsp::java_analyze(response).unwrap_or(crate::ValidationResult::ServerError)
    }

    /// Nombre JCA del algoritmo de firma de un certificado.
    pub fn jca_signature_name(cert_der: &[u8]) -> Option<String> {
        crate::x509::Cert::parse(cert_der)
            .ok()
            .map(|c| crate::sig::jca_signature_name(&c.sig_alg))
    }
}
