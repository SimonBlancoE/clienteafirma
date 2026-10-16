//! Algoritmo de validación (`CertificateVerifier.validateCertificate` y sus
//! subclases OCSP y CRL), con las comprobaciones de seguridad que Java no
//! hace.

use std::sync::Arc;

use afirma_core::algorithms::DigestAlgorithm;
use chrono::{DateTime, Utc};

use crate::crl::{self, CrlView};
use crate::factory::{self, FactoryEntry, VerifierKind};
use crate::fetch::{AfirmaHttpFetcher, FetchError, HttpFetcher, ocsp_get_url, read_file_url};
use crate::ocsp::{self, CertId};
use crate::options::{OcspHttpMethod, SelectionMode, ValidationOptions};
use crate::result::{IssuerSource, RevocationInfo, ValidationMethod, ValidationReport, ValidationResult};
use crate::x509::{Cert, names_match};

/// Valida un certificado (DER) y devuelve solo el resultado.
pub fn validate_certificate(cert_der: &[u8], options: &ValidationOptions) -> ValidationResult {
    validate_certificate_report(cert_der, options).result
}

/// Valida un certificado (DER) y devuelve el informe completo. Hace
/// operaciones de red bloqueantes: llámese desde un hilo de trabajo.
pub fn validate_certificate_report(cert_der: &[u8], options: &ValidationOptions) -> ValidationReport {
    let now = options.now.unwrap_or_else(Utc::now);
    let mut v = Validator {
        opts: options,
        fetcher: options
            .fetcher
            .clone()
            .unwrap_or_else(|| Arc::new(AfirmaHttpFetcher::new())),
        now,
        skew: chrono::Duration::from_std(options.clock_skew).unwrap_or(chrono::Duration::zero()),
        notes: Vec::new(),
    };
    let report = v.run(cert_der);
    tracing::info!(
        "Resultado de la validacion del certificado: {} ({:?})",
        report.result.name(),
        report.method
    );
    report
}

/// Intento de comprobación de la revocación.
struct Attempt {
    result: ValidationResult,
    method: ValidationMethod,
    revocation: Option<RevocationInfo>,
}

impl Attempt {
    /// Válido o revocado: el servicio ha dado una respuesta definitiva.
    fn conclusive(&self) -> bool {
        matches!(self.result, ValidationResult::Valid | ValidationResult::Revoked)
    }
}

/// Emisor resuelto.
struct Issuer {
    cert: Cert,
    source: IssuerSource,
}

struct Validator<'a> {
    opts: &'a ValidationOptions,
    fetcher: Arc<dyn HttpFetcher>,
    now: DateTime<Utc>,
    skew: chrono::Duration,
    /// Detalles acumulados para el informe.
    notes: Vec<String>,
}

fn is_http(url: &str) -> bool {
    let l = url.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

impl Validator<'_> {
    fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        tracing::info!("{s}");
        self.notes.push(s);
    }

    fn report(
        &mut self,
        result: ValidationResult,
        method: ValidationMethod,
        revocation: Option<RevocationInfo>,
        issuer: Option<&Issuer>,
    ) -> ValidationReport {
        ValidationReport {
            result,
            method,
            detail: (!self.notes.is_empty()).then(|| self.notes.join("\n")),
            checked_at: self.now,
            revocation: if result == ValidationResult::Revoked {
                revocation
            } else {
                None
            },
            issuer_source: issuer.map(|i| i.source.clone()),
            no_mechanism: false,
        }
    }

    fn run(&mut self, der: &[u8]) -> ValidationReport {
        let cert = match Cert::parse(der) {
            Ok(c) => c,
            Err(e) => {
                self.note(e);
                return self.report(ValidationResult::Corrupt, ValidationMethod::None, None, None);
            }
        };

        // Java crea el verificador (y puede fallar) antes de validar nada.
        let entry = (self.opts.selection == SelectionMode::JavaFactory)
            .then(|| factory::lookup(&cert))
            .flatten();
        let mut java_ocsp_url = None;
        if self.opts.selection == SelectionMode::JavaFactory {
            if let Some(e) = entry {
                self.note(format!(
                    "Emisor reconocido por la tabla de AutoFirma: {} ({})",
                    e.name, e.id
                ));
            }
            if entry.is_some_and(|e| e.kind == VerifierKind::Ocsp) {
                match factory::java_best_responder(&cert.all_aia_uris()) {
                    Some(u) => java_ocsp_url = Some(u),
                    None => {
                        self.note("El certificado no declara servicios en la extension AIA");
                        let mut r = self.report(ValidationResult::Unknown, ValidationMethod::None, None, None);
                        r.no_mechanism = true;
                        return r;
                    }
                }
            }
        }

        // Periodo de validez (exacto, como `new Date().after(notAfter)`).
        if self.now > cert.not_after {
            self.note(format!("El certificado caduco el {}", cert.not_after));
            return self.report(ValidationResult::Expired, ValidationMethod::None, None, None);
        }
        if self.now < cert.not_before {
            self.note(format!("El certificado no es valido hasta el {}", cert.not_before));
            return self.report(ValidationResult::NotYetValid, ValidationMethod::None, None, None);
        }

        let issuer = match self.resolve_issuer(&cert, entry) {
            Ok(i) => i,
            Err(result) => return self.report(result, ValidationMethod::None, None, None),
        };
        let attempt = match self.opts.selection {
            SelectionMode::JavaFactory => match java_ocsp_url {
                Some(url) => self.ocsp(&cert, issuer.as_ref(), &[url]),
                None => self.crl(&cert, issuer.as_ref()),
            },
            SelectionMode::Auto => self.auto(&cert, issuer.as_ref()),
        };
        self.report(attempt.result, attempt.method, attempt.revocation, issuer.as_ref())
    }

    /// OCSP si se puede y, si no da una respuesta definitiva, CRL.
    fn auto(&mut self, cert: &Cert, issuer: Option<&Issuer>) -> Attempt {
        let urls: Vec<String> = cert.ocsp_urls().into_iter().filter(|u| is_http(u)).collect();
        let mut primary = None;
        if !urls.is_empty() {
            let a = self.ocsp(cert, issuer, &urls);
            if a.conclusive() {
                return a;
            }
            primary = Some(a);
        }
        if (primary.is_none() || self.opts.crl_fallback) && !cert.crl_urls.is_empty() {
            let c = self.crl(cert, issuer);
            if c.conclusive() || primary.is_none() {
                return c;
            }
        }
        primary.unwrap_or_else(|| {
            if cert.crl_urls.is_empty() && urls.is_empty() {
                self.note("El certificado no declara servicios OCSP ni puntos de distribucion de CRL");
            }
            Attempt {
                result: ValidationResult::Unknown,
                method: ValidationMethod::None,
                revocation: None,
            }
        })
    }

    /// Emisor del certificado: el indicado (o el de la tabla de Java), que
    /// debe haberlo emitido, o el que se encuentre en la cadena, entre los
    /// certificados incluidos o en la AIA.
    fn resolve_issuer(
        &mut self,
        cert: &Cert,
        entry: Option<&FactoryEntry>,
    ) -> Result<Option<Issuer>, ValidationResult> {
        let configured = match (entry.and_then(|e| e.issuer), &self.opts.issuer) {
            (Some(bundled), _) => Some((bundled.to_vec(), IssuerSource::Bundled)),
            (None, Some(given)) => Some((given.clone(), IssuerSource::Provided)),
            (None, None) => None,
        };
        if let Some((der, source)) = configured {
            let issuer = Cert::parse(&der).map_err(|e| {
                self.note(format!("El certificado del emisor no es valido: {e}"));
                ValidationResult::ServerError
            })?;
            // `CertificateVerifier.verifyIssuer`.
            if !names_match(&cert.issuer, &issuer.subject) {
                self.note("El certificado proporcionado no esta emitido por la CA configurada");
                return Err(ValidationResult::CaNotSupported);
            }
            if let Err(e) = cert.verify_signed_by(&issuer.spki) {
                self.note(format!(
                    "La firma del certificado no se corresponde con la CA configurada: {e}"
                ));
                return Err(ValidationResult::CaNotSupported);
            }
            return Ok(Some(Issuer { cert: issuer, source }));
        }
        if cert.is_self_issued() && cert.verify_signed_by(&cert.spki).is_ok() {
            return Ok(Some(Issuer {
                cert: cert.clone(),
                source: IssuerSource::SelfSigned,
            }));
        }
        for der in &self.opts.chain {
            if let Ok(c) = Cert::parse(der)
                && c.der != cert.der
                && cert.is_issued_by(&c)
            {
                return Ok(Some(Issuer {
                    cert: c,
                    source: IssuerSource::Chain,
                }));
            }
        }
        for der in factory::bundled_ca_certificates() {
            if let Ok(c) = Cert::parse(der)
                && cert.is_issued_by(&c)
            {
                return Ok(Some(Issuer {
                    cert: c,
                    source: IssuerSource::Bundled,
                }));
            }
        }
        if self.opts.download_issuer {
            for url in cert.ca_issuers_urls().into_iter().filter(|u| is_http(u)) {
                match self.fetcher.get(
                    &url,
                    "application/pkix-cert, application/pkcs7-mime, */*",
                    self.opts.timeouts(),
                ) {
                    Ok(data) => {
                        let found = crate::certs::parse_certificates(&data)
                            .into_iter()
                            .filter_map(|d| Cert::parse(&d).ok())
                            .find(|c| cert.is_issued_by(c));
                        match found {
                            Some(c) => {
                                self.note(format!("Certificado del emisor descargado de {url}"));
                                return Ok(Some(Issuer {
                                    cert: c,
                                    source: IssuerSource::Downloaded { url },
                                }));
                            }
                            None => self.note(format!("{url} no contiene el certificado del emisor")),
                        }
                    }
                    Err(e) => self.note(format!(
                        "No se ha podido descargar el certificado del emisor de {url}: {e}"
                    )),
                }
            }
        }
        self.note("No se ha encontrado el certificado del emisor");
        Ok(None)
    }

    /// Envía la petición OCSP con el método configurado.
    fn send_ocsp(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, FetchError> {
        const REQ: &str = "application/ocsp-request";
        const RESP: &str = "application/ocsp-response";
        let t = self.opts.timeouts();
        match self.opts.ocsp_method {
            OcspHttpMethod::Get => self.fetcher.get(&ocsp_get_url(url, request), RESP, t),
            OcspHttpMethod::Post => self.fetcher.post(url, REQ, RESP, request, t),
            OcspHttpMethod::Auto => match self.fetcher.post(url, REQ, RESP, request, t) {
                Err(FetchError::Unsupported(_)) => self.fetcher.get(&ocsp_get_url(url, request), RESP, t),
                r => r,
            },
        }
    }

    /// Consulta OCSP a los servicios indicados, por orden, hasta obtener una
    /// respuesta definitiva.
    fn ocsp(&mut self, cert: &Cert, issuer: Option<&Issuer>, urls: &[String]) -> Attempt {
        if issuer.is_none() && self.opts.require_verified_revocation {
            self.note("No se puede consultar el servicio OCSP sin el certificado del emisor");
            let method = urls
                .first()
                .map_or(ValidationMethod::None, |u| ValidationMethod::Ocsp { url: u.clone() });
            return Attempt {
                result: ValidationResult::Unknown,
                method,
                revocation: None,
            };
        }
        // Sin emisor, Java calcula el CertID con el propio certificado.
        let (name, key) = match issuer {
            Some(i) => (i.cert.subject.clone(), i.cert.public_key_bits()),
            None => (cert.subject.clone(), cert.public_key_bits()),
        };
        let cert_id = CertId::new(DigestAlgorithm::Sha1, &cert.serial, &name, &key.unwrap_or_default());
        let request = ocsp::build_request(&cert_id);
        let extra: Vec<Cert> = self.opts.chain.iter().filter_map(|d| Cert::parse(d).ok()).collect();
        let mut last = None;
        for url in urls {
            let method = ValidationMethod::Ocsp { url: url.clone() };
            self.note(format!("Consulta OCSP a {url}"));
            if !is_http(url) {
                self.note(format!("Servicio OCSP no soportado: {url}"));
                last = Some(Attempt {
                    result: ValidationResult::ServerError,
                    method,
                    revocation: None,
                });
                continue;
            }
            let data = match self.send_ocsp(url, &request) {
                Ok(d) => d,
                Err(e) => {
                    self.note(format!("Error enviando la peticion OCSP al servidor ({url}): {e}"));
                    last = Some(Attempt {
                        result: ValidationResult::ServerError,
                        method,
                        revocation: None,
                    });
                    continue;
                }
            };
            if issuer.is_none() {
                self.note("La respuesta OCSP no se puede verificar: no se conoce el emisor");
            }
            let check = ocsp::Check {
                cert_id: &cert_id,
                issuer: issuer.map(|i| &i.cert),
                extra_certs: &extra,
                now: self.now,
                skew: self.skew,
                max_age_without_next_update: chrono::Duration::from_std(self.opts.ocsp_max_age_without_next_update)
                    .unwrap_or(chrono::Duration::zero()),
            };
            let outcome = ocsp::evaluate(&data, &check);
            if let Some(d) = outcome.detail {
                self.note(d);
            }
            let attempt = Attempt {
                result: outcome.result,
                method,
                revocation: outcome.revocation,
            };
            if attempt.conclusive() || attempt.result == ValidationResult::Unknown {
                // "unknown" firmado también es una respuesta del servicio:
                // no se pregunta a otros servicios OCSP.
                return attempt;
            }
            last = Some(attempt);
        }
        last.unwrap_or(Attempt {
            result: ValidationResult::ServerError,
            method: ValidationMethod::None,
            revocation: None,
        })
    }

    /// Descarga una CRL según el protocolo de la URL.
    fn download_crl(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let lower = url.to_ascii_lowercase();
        if is_http(url) {
            self.fetcher.get(url, "application/pkix-crl, */*", self.opts.timeouts())
        } else if lower.starts_with("ldap://") {
            self.fetcher.ldap(url, self.opts.timeouts())
        } else if lower.starts_with("file:/") {
            read_file_url(url)
        } else {
            Err(FetchError::Unsupported(format!(
                "No se soporta el protocolo del punto de distribucion de CRL: {url}"
            )))
        }
    }

    /// Comprobación con las CRL de los puntos de distribución
    /// (`CrlHelper.verifyCertificateCRLs`).
    fn crl(&mut self, cert: &Cert, issuer: Option<&Issuer>) -> Attempt {
        let mut urls: Vec<String> = cert.crl_urls.iter().map(|u| u.trim().to_string()).collect();
        if urls.is_empty() {
            self.note("El certificado no tiene CRL asociadas");
            return Attempt {
                result: ValidationResult::Unknown,
                method: ValidationMethod::None,
                revocation: None,
            };
        }
        if issuer.is_none() && self.opts.require_verified_revocation {
            self.note("No se puede verificar la CRL sin el certificado del emisor");
            return Attempt {
                result: ValidationResult::Unknown,
                method: ValidationMethod::Crl { urls },
                revocation: None,
            };
        }
        // Primero HTTP(S) y ficheros; LDAP (lento o bloqueado) al final.
        urls.sort_by_key(|u| u.to_ascii_lowercase().starts_with("ldap:"));
        let mut tried = Vec::new();
        let mut download_failed = false;
        let mut invalid = false;
        for url in urls {
            tried.push(url.clone());
            let data = match self.download_crl(&url) {
                Ok(d) => d,
                Err(e) => {
                    self.note(format!("No se ha podido descargar la CRL ({url}): {e}"));
                    download_failed = true;
                    continue;
                }
            };
            match self.check_crl(&data, cert, issuer) {
                Ok(revocation) => {
                    self.note(format!("Comprobada la CRL de {url}"));
                    let result = if revocation.is_some() {
                        ValidationResult::Revoked
                    } else {
                        ValidationResult::Valid
                    };
                    return Attempt {
                        result,
                        method: ValidationMethod::Crl { urls: tried },
                        revocation,
                    };
                }
                Err(e) => {
                    self.note(format!("CRL de {url} no valida: {e}"));
                    invalid = true;
                }
            }
        }
        let result = if invalid {
            ValidationResult::ServerError
        } else if download_failed {
            ValidationResult::CannotDownloadCrl
        } else {
            ValidationResult::Unknown
        };
        Attempt {
            result,
            method: ValidationMethod::Crl { urls: tried },
            revocation: None,
        }
    }

    /// Analiza y verifica una CRL y busca el certificado en ella.
    fn check_crl(&self, data: &[u8], cert: &Cert, issuer: Option<&Issuer>) -> Result<Option<RevocationInfo>, String> {
        let der = crl::decode(data).ok_or("no es una CRL")?;
        let view = CrlView::parse(&der)?;
        if !names_match(view.issuer, &cert.issuer) {
            return Err("la CRL no la ha emitido el emisor del certificado".into());
        }
        if view.is_delta {
            return Err("las CRL delta no se admiten".into());
        }
        if let Some(i) = issuer {
            crate::sig::verify(view.sig_alg, &i.cert.spki, view.tbs, view.signature)
                .map_err(|e| format!("la firma de la CRL no es valida: {e}"))?;
        }
        if view.this_update > self.now + self.skew {
            return Err(format!("la CRL tiene fecha futura (thisUpdate {})", view.this_update));
        }
        if let Some(next) = view.next_update
            && next + self.skew < self.now
        {
            return Err(format!("la CRL esta caducada (nextUpdate {next})"));
        }
        view.find(&cert.serial)
    }
}
