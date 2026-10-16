//! Pruebas de extremo a extremo con la PKI de `testdata/certval`: servidor
//! HTTP local (127.0.0.1), OpenSSL como respondedor OCSP y CRL reales.
//! Sin acceso a la red exterior.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use afirma_certval::{
    IssuerSource, OcspHttpMethod, RevocationReason, SelectionMode, ValidationMethod, ValidationOptions,
    ValidationResult, validate_certificate, validate_certificate_report,
};
use common::*;

const OCSP_URL: &str = "http://ocsp.certval.test/";
const CRL_URL: &str = "http://crl.certval.test/ca.crl";

macro_rules! require_openssl {
    () => {
        if !openssl_available() {
            eprintln!("openssl no disponible: prueba omitida");
            return;
        }
    };
}

fn with_chain(mut o: ValidationOptions, chain: &[&str]) -> ValidationOptions {
    o.chain = chain.iter().map(|c| cert(c)).collect();
    o
}

#[test]
fn ocsp_live_good_revoked_unknown_by_get() {
    require_openssl!();
    let s = full_server();
    let o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);

    let r = validate_certificate_report(&cert("good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(r.method, ValidationMethod::Ocsp { url: OCSP_URL.into() });
    assert_eq!(r.issuer_source, Some(IssuerSource::Chain));
    assert!(r.is_ok() && !r.dialog_is_error());
    assert_eq!(r.dialog_message(), "El certificado es válido");
    // El cliente por defecto usa GET (RFC 6960 A.1) con la petición de Java.
    let reqs = s.requests_to("/ocsp.certval.test/");
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].header("Accept"), Some("application/ocsp-response"));
    let java_req = hex::decode(raw("java-ocspreq-good.txt").trim_ascii()).unwrap();
    assert_eq!(ocsp_request_of(&reqs[0]), java_req);

    let r = validate_certificate_report(&cert("revoked"), &o);
    assert_eq!(r.result, ValidationResult::Revoked, "{r:?}");
    let rev = r.revocation.clone().expect("datos de revocacion");
    assert_eq!(rev.reason, Some(RevocationReason(1)));
    assert!(rev.time.is_some());
    assert_eq!(r.dialog_message(), "El certificado está revocado");

    // "unknown" no es concluyente: sin alternativa queda UNKNOWN...
    let mut strict = o.clone();
    strict.crl_fallback = false;
    let r = validate_certificate_report(&cert("unknown"), &strict);
    assert_eq!(r.result, ValidationResult::Unknown, "{r:?}");
    assert_eq!(r.method, ValidationMethod::Ocsp { url: OCSP_URL.into() });
    // ...y con alternativa decide la CRL firmada por la CA.
    let r = validate_certificate_report(&cert("unknown"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Crl {
            urls: vec![CRL_URL.into()]
        }
    );
}

#[test]
fn ocsp_live_post_like_java() {
    require_openssl!();
    let s = full_server();
    let mut f = MappingFetcher::new(&s);
    f.post = true;
    let o = with_chain(options(f), &["ca"]);
    assert_eq!(validate_certificate(&cert("good"), &o), ValidationResult::Valid);
    assert_eq!(validate_certificate(&cert("revoked"), &o), ValidationResult::Revoked);
    let reqs = s.requests_to("/ocsp.certval.test/");
    assert_eq!(reqs.len(), 2);
    assert!(reqs.iter().all(|r| r.method == "POST"));
    assert_eq!(reqs[0].header("Content-Type"), Some("application/ocsp-request"));
    assert_eq!(reqs[0].header("Accept"), Some("application/ocsp-response"));
    let java_req = hex::decode(raw("java-ocspreq-good.txt").trim_ascii()).unwrap();
    assert_eq!(reqs[0].body, java_req);

    // Forzar GET con un cliente que admite POST.
    let mut o2 = o.clone();
    o2.ocsp_method = OcspHttpMethod::Get;
    assert_eq!(validate_certificate(&cert("good"), &o2), ValidationResult::Valid);
    assert_eq!(s.requests_to("/ocsp.certval.test/").last().unwrap().method, "GET");
}

#[test]
fn ocsp_live_ecdsa_issuer_signs_directly() {
    require_openssl!();
    let s = full_server();
    let o = with_chain(options(MappingFetcher::new(&s)), &["ec_ca"]);
    let r = validate_certificate_report(&cert("ec_good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Ocsp {
            url: "http://ecocsp.certval.test/".into()
        }
    );
}

#[test]
fn validity_period_is_checked_first_without_network() {
    let s = full_server();
    let o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);
    let r = validate_certificate_report(&cert("expired"), &o);
    assert_eq!(r.result, ValidationResult::Expired);
    assert_eq!(r.method, ValidationMethod::None);
    assert_eq!(r.dialog_message(), "El certificado está caducado");
    assert_eq!(validate_certificate(&cert("notyet"), &o), ValidationResult::NotYetValid);
    assert_eq!(
        validate_certificate(b"no es un certificado", &o),
        ValidationResult::Corrupt
    );
    assert!(s.requests().is_empty());
}

#[test]
fn issuer_discovery() {
    require_openssl!();
    let s = full_server();
    // Sin cadena: se descarga de la AIA (DER y PKCS#7).
    let o = options(MappingFetcher::new(&s));
    let r = validate_certificate_report(&cert("good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.issuer_source,
        Some(IssuerSource::Downloaded {
            url: "http://aia.certval.test/ca.cer".into()
        })
    );
    let r = validate_certificate_report(&cert("aia_p7c"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.issuer_source,
        Some(IssuerSource::Downloaded {
            url: "http://aia.certval.test/ca.p7c".into()
        })
    );

    // Sin emisor no se puede verificar nada: UNKNOWN.
    let mut no_dl = options(MappingFetcher::new(&s));
    no_dl.download_issuer = false;
    let r = validate_certificate_report(&cert("good"), &no_dl);
    assert_eq!(r.result, ValidationResult::Unknown, "{r:?}");
    assert_eq!(r.issuer_source, None);
    // La cadena puede traer certificados ajenos y el propio certificado.
    let o = with_chain(no_dl.clone(), &["good", "other_ca", "root", "ca"]);
    assert_eq!(validate_certificate(&cert("good"), &o), ValidationResult::Valid);

    // Emisor indicado que no lo emitió: CA_NOT_SUPPORTED (como Java).
    let mut wrong = options(MappingFetcher::new(&s));
    wrong.issuer = Some(cert("other_ca"));
    let r = validate_certificate_report(&cert("good"), &wrong);
    assert_eq!(r.result, ValidationResult::CaNotSupported);
    assert_eq!(r.dialog_message(), "Autoridad de certificación no soportada");
    // Mismo nombre, otra clave.
    wrong.issuer = Some(cert("fake_ca"));
    assert_eq!(
        validate_certificate(&cert("good"), &wrong),
        ValidationResult::CaNotSupported
    );
    wrong.issuer = Some(cert("ca"));
    let r = validate_certificate_report(&cert("good"), &wrong);
    assert_eq!(r.result, ValidationResult::Valid);
    assert_eq!(r.issuer_source, Some(IssuerSource::Provided));
}

/// Opciones para probar respuestas OCSP precalculadas sin alternativa CRL.
fn stored(s: &Server, resp: Vec<u8>) -> ValidationOptions {
    s.file("/ocsp.certval.test/", resp);
    let mut o = with_chain(options(MappingFetcher::new(s)), &["ca"]);
    o.crl_fallback = false;
    o
}

#[test]
fn ocsp_response_security_checks() {
    let s = Server::start();
    let good = cert("good");
    let check = |resp: Vec<u8>| validate_certificate_report(&good, &stored(&s, resp));

    for ok in ["resp_good.der", "resp_good_keyid.der", "resp_good_by_ca.der"] {
        let r = check(raw(ok));
        assert_eq!(r.result, ValidationResult::Valid, "{ok}: {r:?}");
    }
    // Respondedor delegado no incluido en la respuesta: se busca en la cadena.
    let r = check(raw("resp_good_nocerts.der"));
    assert_eq!(r.result, ValidationResult::ServerError, "{r:?}");
    let mut o = stored(&s, raw("resp_good_nocerts.der"));
    o.chain.push(cert("ocsp"));
    assert_eq!(validate_certificate(&good, &o), ValidationResult::Valid);

    // Respondedor sin id-kp-OCSPSigning y respondedor de otra CA: Java los acepta.
    for (bad, why) in [("resp_rogue.der", "OCSPSigning"), ("resp_other.der", "emitido la CA")] {
        assert_eq!(
            afirma_certval::testing::java_analyze_ocsp(&raw(bad)),
            ValidationResult::Valid
        );
        let r = check(raw(bad));
        assert_eq!(r.result, ValidationResult::ServerError, "{bad}: {r:?}");
        assert!(r.detail.as_deref().unwrap_or("").contains(why), "{bad}: {:?}", r.detail);
    }

    // Firma alterada.
    let mut tampered = raw("resp_good.der");
    let n = tampered.len();
    tampered[n - 300] ^= 0x01; // dentro de la firma o del certificado incluido
    assert_eq!(check(tampered).result, ValidationResult::ServerError);
    let mut tampered = raw("resp_good.der");
    // Cambiar un byte de producedAt (primer GeneralizedTime) invalida la firma.
    let pos = tampered.windows(2).position(|w| w == [0x18, 0x0f]).unwrap() + 5;
    tampered[pos] ^= 0x01;
    assert_eq!(check(tampered).result, ValidationResult::ServerError);

    // Respuesta de otro certificado (CertID distinto): Java diría VALID.
    let r = validate_certificate_report(&cert("revoked"), &stored(&s, raw("resp_good.der")));
    assert_eq!(r.result, ValidationResult::ServerError, "{r:?}");
    assert!(r.detail.unwrap().contains("no corresponde"));

    // Estados de error del servicio (OCSPResponse sin responseBytes).
    for (status, expected) in [
        (1u8, ValidationResult::MalformedRequest),
        (2, ValidationResult::ServerError),
        (3, ValidationResult::ServerError),
        (4, ValidationResult::ServerError),
        (5, ValidationResult::SigRequired),
        (6, ValidationResult::Unauthorized),
    ] {
        let r = check(vec![0x30, 0x03, 0x0a, 0x01, status]);
        assert_eq!(r.result, expected, "estado {status}");
    }
    assert_eq!(check(b"basura".to_vec()).result, ValidationResult::ServerError);
    s.status("/ocsp.certval.test/", 500);
    let mut o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);
    o.crl_fallback = false;
    assert_eq!(validate_certificate(&good, &o), ValidationResult::ServerError);
}

#[test]
fn ocsp_freshness() {
    let s = Server::start();
    let good = cert("good");
    let later = chrono::Utc::now() + chrono::Duration::days(2);

    // nextUpdate = thisUpdate + 1 día.
    let mut o = stored(&s, raw("resp_stale.der"));
    o.now = Some(later);
    let r = validate_certificate_report(&good, &o);
    assert_eq!(r.result, ValidationResult::ServerError, "{r:?}");
    assert!(r.detail.unwrap().contains("caducada"));

    // Sin nextUpdate: 24 horas por defecto.
    let mut o = stored(&s, raw("resp_nonext.der"));
    o.now = Some(later);
    assert_eq!(validate_certificate(&good, &o), ValidationResult::ServerError);
    o.ocsp_max_age_without_next_update = Duration::from_secs(3650 * 86400);
    assert_eq!(validate_certificate(&good, &o), ValidationResult::Valid);
    // thisUpdate en el futuro: prueba unitaria de `ocsp::evaluate` (el
    // certificado se emitió a la vez que la respuesta).
}

#[test]
fn ocsp_failure_falls_back_to_crl() {
    let s = Server::start();
    s.file("/crl.certval.test/ca.crl", raw("ca.crl"));
    s.file("/ocsp.certval.test/", raw("resp_rogue.der"));
    let o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);
    let r = validate_certificate_report(&cert("good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Crl {
            urls: vec![CRL_URL.into()]
        }
    );
    assert_eq!(validate_certificate(&cert("revoked"), &o), ValidationResult::Revoked);
    // Si la CRL tampoco sirve, el resultado es el de OCSP.
    s.status("/crl.certval.test/ca.crl", 404);
    let r = validate_certificate_report(&cert("good"), &o);
    assert_eq!(r.result, ValidationResult::ServerError, "{r:?}");
    assert_eq!(r.method, ValidationMethod::Ocsp { url: OCSP_URL.into() });
    // Servicio OCSP inaccesible.
    let mut f = MappingFetcher::new(&s);
    f.down.push("ocsp.certval.test".into());
    s.file("/crl.certval.test/ca.crl", raw("ca.crl"));
    let o = with_chain(options(f), &["ca"]);
    let r = validate_certificate_report(&cert("good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert!(matches!(r.method, ValidationMethod::Crl { .. }));
}

#[test]
fn crl_checks() {
    let s = Server::start();
    let o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);
    let serve = |name: &str| s.file("/crl.certval.test/ca.crl", raw(name));

    serve("ca.crl");
    let r = validate_certificate_report(&cert("crlonly"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Crl {
            urls: vec![CRL_URL.into()]
        }
    );
    let r = validate_certificate_report(&cert("crlonly_revoked"), &o);
    assert_eq!(r.result, ValidationResult::Revoked);
    assert_eq!(r.revocation.unwrap().reason, Some(RevocationReason(4)));

    serve("ca.crl.pem");
    assert_eq!(validate_certificate(&cert("crlonly"), &o), ValidationResult::Valid);
    // Firma RSASSA-PSS.
    serve("ca_pss.crl");
    assert_eq!(validate_certificate(&cert("crlonly"), &o), ValidationResult::Valid);
    assert_eq!(
        validate_certificate(&cert("crlonly_revoked"), &o),
        ValidationResult::Revoked
    );
    // PSS con un byte alterado en la firma.
    let mut bad = raw("ca_pss.crl");
    let n = bad.len();
    bad[n - 1] ^= 0x01;
    s.file("/crl.certval.test/ca.crl", bad);
    assert_eq!(
        validate_certificate(&cert("crlonly"), &o),
        ValidationResult::ServerError
    );

    // CRL caducada y CRL falsificada (mismo nombre, otra clave).
    serve("ca_stale.crl");
    let r = validate_certificate_report(&cert("crlonly_revoked"), &o);
    assert_eq!(r.result, ValidationResult::ServerError, "{r:?}");
    assert!(r.detail.unwrap().contains("caducada"));
    serve("ca_fake.crl");
    let r = validate_certificate_report(&cert("crlonly_revoked"), &o);
    assert_eq!(r.result, ValidationResult::ServerError, "{r:?}");
    assert!(r.detail.unwrap().contains("firma"));
    // CRL de otra CA.
    serve("ec_ca.crl");
    assert_eq!(
        validate_certificate(&cert("crlonly"), &o),
        ValidationResult::ServerError
    );
    serve("ca.crl");

    // Sin emisor: UNKNOWN; sin exigir verificación, como Java.
    let mut lax = options(MappingFetcher::new(&s));
    lax.download_issuer = false;
    assert_eq!(
        validate_certificate(&cert("crlonly_revoked"), &lax),
        ValidationResult::Unknown
    );
    lax.require_verified_revocation = false;
    assert_eq!(
        validate_certificate(&cert("crlonly_revoked"), &lax),
        ValidationResult::Revoked
    );
    serve("ca_fake.crl");
    assert_eq!(
        validate_certificate(&cert("crlonly_revoked"), &lax),
        ValidationResult::Valid
    );
    serve("ca.crl");

    // Descargas.
    s.status("/crl.certval.test/ca.crl", 404);
    let r = validate_certificate_report(&cert("crlonly"), &o);
    assert_eq!(r.result, ValidationResult::CannotDownloadCrl);
    assert_eq!(
        r.dialog_message(),
        "No se ha podido comprobar la validez del certificado"
    );
    serve("ca.crl");
    // Primer punto de distribución inaccesible, el segundo funciona.
    let r = validate_certificate_report(&cert("multidp"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Crl {
            urls: vec!["http://down.certval.test/ca.crl".into(), CRL_URL.into()]
        }
    );
    s.status("/crl.certval.test/ca.crl", 503);
    assert_eq!(
        validate_certificate(&cert("multidp"), &o),
        ValidationResult::CannotDownloadCrl
    );

    // Sin OCSP ni CRL.
    let r = validate_certificate_report(&cert("nothing"), &o);
    assert_eq!(r.result, ValidationResult::Unknown);
    assert_eq!(r.method, ValidationMethod::None);
}

#[test]
fn crl_ecdsa() {
    let s = Server::start();
    s.file("/crl.certval.test/ec_ca.crl", raw("ec_ca.crl"));
    // OCSP de la CA EC sin servicio: se usa su CRL (firma ECDSA P-384).
    let o = with_chain(options(MappingFetcher::new(&s)), &["ec_ca"]);
    let r = validate_certificate_report(&cert("ec_good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Crl {
            urls: vec!["http://crl.certval.test/ec_ca.crl".into()]
        }
    );
}

#[test]
fn crl_over_ldap() {
    let s = Server::start();
    const DN: &str = "cn=CA CertVal Pruebas,o=AutoFirma-rs Pruebas,c=ES";
    let (port, log) = ldap_server(
        DN,
        HashMap::from([("certificateRevocationList;binary".to_string(), raw("ca.crl"))]),
    );
    let mut f = MappingFetcher::new(&s);
    f.ldap_port = Some(port);
    let o = with_chain(options(f), &["ca"]);
    let r = validate_certificate_report(&cert("ldap"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    let searches = log.lock().unwrap().clone();
    assert_eq!(
        searches,
        vec![(DN.to_string(), vec!["certificateRevocationList;binary".to_string()])]
    );
    // Servidor LDAP inaccesible.
    let o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);
    assert_eq!(
        validate_certificate(&cert("ldap"), &o),
        ValidationResult::CannotDownloadCrl
    );
}

/// El servidor LDAP de las pruebas responde a un cliente real
/// (`ldapsearch` de OpenLDAP, si está instalado) igual que a nuestro
/// cliente: así la prueba anterior no se limita a comprobarse a sí misma.
#[test]
fn fake_ldap_server_speaks_ldap() {
    if std::process::Command::new("ldapsearch").arg("-VV").output().is_err() {
        eprintln!("ldapsearch no disponible: prueba omitida");
        return;
    }
    const DN: &str = "cn=CA CertVal Pruebas,o=AutoFirma-rs Pruebas,c=ES";
    let crl = raw("ca.crl");
    let (port, _) = ldap_server(
        DN,
        HashMap::from([("certificateRevocationList;binary".to_string(), crl.clone())]),
    );
    let out = std::process::Command::new("ldapsearch")
        .args([
            "-x",
            "-LLL",
            "-o",
            "ldif-wrap=no",
            "-H",
            &format!("ldap://127.0.0.1:{port}"),
            "-s",
            "base",
            "-b",
            DN,
        ])
        .args(["(objectClass=*)", "certificateRevocationList;binary"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let b64 = text
        .lines()
        .find_map(|l| l.strip_prefix("certificateRevocationList;binary:: "))
        .unwrap_or_else(|| panic!("salida de ldapsearch: {text} {}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(afirma_core::base64::decode(b64).unwrap(), crl);
}

#[test]
fn java_factory_selection() {
    let s = Server::start();
    s.file("/crl.certval.test/ca.crl", raw("ca.crl"));
    let mut o = with_chain(options(MappingFetcher::new(&s)), &["ca"]);
    o.selection = SelectionMode::JavaFactory;
    // CA fuera de la tabla de Java: CRL aunque haya OCSP.
    let r = validate_certificate_report(&cert("good"), &o);
    assert_eq!(r.result, ValidationResult::Valid, "{r:?}");
    assert_eq!(
        r.method,
        ValidationMethod::Crl {
            urls: vec![CRL_URL.into()]
        }
    );
    assert_eq!(validate_certificate(&cert("revoked"), &o), ValidationResult::Revoked);
    assert!(s.requests_to("/ocsp.certval.test/").is_empty());

    // Emisor de la tabla (OCSP) sin AIA: no hay mecanismo de validación.
    let r = validate_certificate_report(&cert("fnmt_noaia"), &o);
    assert!(r.no_mechanism);
    assert_eq!(r.dialog_title(), "Error");
    assert_eq!(
        r.dialog_message(),
        "No se dispone de ningún mecanismo de validación para el tipo de certificado utilizado"
    );
    // Emisor de la tabla con AIA pero que no verifica con la CA incluida.
    let r = validate_certificate_report(&cert("fnmt_aia"), &o);
    assert_eq!(r.result, ValidationResult::CaNotSupported, "{r:?}");
    assert!(!r.no_mechanism);
    assert!(s.requests_to("/ocsp.certval.test/").is_empty());
}
