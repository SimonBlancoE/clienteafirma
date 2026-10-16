//! Opciones de la validación.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::fetch::{HttpFetcher, Timeouts};

/// Cómo se elige el mecanismo de validación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionMode {
    /// OCSP si el certificado declara un servicio OCSP (`id-ad-ocsp` en la
    /// extensión AIA) y se conoce su emisor; si no, o si OCSP no da una
    /// respuesta concluyente y `crl_fallback` está activo, CRL.
    #[default]
    Auto,
    /// Selección de `CertificateVerifierFactory` de Java: OCSP solo para los
    /// emisores de su tabla marcados como OCSP (con el servicio elegido como
    /// `getBestResponder` entre **todas** las URI de la AIA), CRL para el
    /// resto, sin alternativa si falla. El certificado de CA de la tabla, si
    /// se conserva, actúa como emisor configurado (un certificado que no
    /// verifique con él es `CA_NOT_SUPPORTED`). Las comprobaciones de
    /// seguridad añadidas (firma, `CertID`, fechas) se siguen aplicando.
    JavaFactory,
}

/// Método HTTP de las consultas OCSP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcspHttpMethod {
    /// POST (como Java) si el [`HttpFetcher`] lo admite y, si no, GET
    /// (RFC 6960, apéndice A.1).
    #[default]
    Auto,
    /// Siempre GET.
    Get,
    /// Siempre POST (error si el [`HttpFetcher`] no lo admite).
    Post,
}

/// Opciones de [`crate::validate_certificate`].
#[derive(Clone)]
pub struct ValidationOptions {
    /// Certificado del emisor (DER). Si se indica, se comprueba como en Java
    /// que emitió el certificado (nombre y firma): si no,
    /// `CA_NOT_SUPPORTED`.
    pub issuer: Option<Vec<u8>>,
    /// Otros certificados disponibles (DER), normalmente la cadena del
    /// almacén de claves; puede incluir el propio certificado. Se busca en
    /// ellos el emisor y, si la respuesta OCSP no lo incluye, el certificado
    /// del respondedor.
    pub chain: Vec<Vec<u8>>,
    /// Elección del mecanismo de validación.
    pub selection: SelectionMode,
    /// Acceso a la red; `None` = [`crate::AfirmaHttpFetcher`] (cliente HTTP
    /// instalado en el proceso).
    pub fetcher: Option<Arc<dyn HttpFetcher>>,
    /// Tiempo máximo de conexión de cada descarga.
    pub connect_timeout: Duration,
    /// Tiempo máximo de espera de datos de cada descarga.
    pub read_timeout: Duration,
    /// Descargar el certificado del emisor de la extensión AIA
    /// (`caIssuers`) si no se ha indicado ni está en `chain`.
    pub download_issuer: bool,
    /// En [`SelectionMode::Auto`], consultar las CRL si OCSP no da una
    /// respuesta concluyente (válido o revocado).
    pub crl_fallback: bool,
    /// Exigir que las respuestas OCSP y las CRL estén firmadas por el
    /// emisor del certificado (o por un respondedor que haya autorizado). Si
    /// no se conoce el emisor el resultado es `UNKNOWN`. Con `false` se
    /// aceptan sin verificar cuando no hay emisor, como hace Java.
    pub require_verified_revocation: bool,
    /// Método HTTP de las consultas OCSP.
    pub ocsp_method: OcspHttpMethod,
    /// Margen de reloj para las fechas de respuestas OCSP, CRL y del
    /// certificado del respondedor (no para el periodo de validez del
    /// certificado, que se comprueba exactamente como en Java).
    pub clock_skew: Duration,
    /// Antigüedad máxima de una respuesta OCSP sin `nextUpdate`.
    pub ocsp_max_age_without_next_update: Duration,
    /// Instante de referencia (por defecto, el actual).
    pub now: Option<DateTime<Utc>>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        ValidationOptions {
            issuer: None,
            chain: Vec::new(),
            selection: SelectionMode::Auto,
            fetcher: None,
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(60),
            download_issuer: true,
            crl_fallback: true,
            require_verified_revocation: true,
            ocsp_method: OcspHttpMethod::Auto,
            clock_skew: Duration::from_secs(5 * 60),
            ocsp_max_age_without_next_update: Duration::from_secs(24 * 60 * 60),
            now: None,
        }
    }
}

impl std::fmt::Debug for ValidationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationOptions")
            .field("issuer", &self.issuer.as_ref().map(|i| i.len()))
            .field("chain", &self.chain.len())
            .field("selection", &self.selection)
            .field("fetcher", &self.fetcher.as_ref().map(|_| "personalizado"))
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("download_issuer", &self.download_issuer)
            .field("crl_fallback", &self.crl_fallback)
            .field("require_verified_revocation", &self.require_verified_revocation)
            .field("ocsp_method", &self.ocsp_method)
            .field("clock_skew", &self.clock_skew)
            .field(
                "ocsp_max_age_without_next_update",
                &self.ocsp_max_age_without_next_update,
            )
            .field("now", &self.now)
            .finish()
    }
}

impl ValidationOptions {
    /// Opciones por defecto con la cadena de certificados del almacén
    /// (el certificado y sus emisores, en cualquier orden).
    pub fn with_chain(chain: &[Vec<u8>]) -> Self {
        ValidationOptions {
            chain: chain.to_vec(),
            ..Default::default()
        }
    }

    pub(crate) fn timeouts(&self) -> Timeouts {
        Timeouts {
            connect: self.connect_timeout,
            read: self.read_timeout,
        }
    }
}
