//! Transporte HTTPS del cliente de sellado de tiempo: almacén de confianza
//! (`tsaSslTrustStore`), certificado cliente (`tsaSslKeyStore`) y
//! `verifyHostname`, contra un servidor TLS local (rustls) que responde con
//! la TSA de pruebas.

#![allow(clippy::result_large_err)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use afirma_cms::tsp::mock::MockTsa;
use afirma_cms::tsp::{Timestamper, TsaParams};
use afirma_core::ExtraParams;
use afirma_core::algorithms::DigestAlgorithm;
use afirma_core::error::codes;
use common::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct Pki {
    ca_der: Vec<u8>,
    server_der: Vec<u8>,
    server_key: Vec<u8>,
}

fn pki(host: &str) -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "CA TLS de pruebas");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, host);
    let cert = params.signed_by(&key, &ca).unwrap();
    Pki {
        ca_der: ca.der().to_vec(),
        server_der: cert.der().to_vec(),
        server_key: key.serialize_der(),
    }
}

/// Almacén PKCS#12 solo con certificados (almacén de confianza).
fn truststore(cert: &[u8]) -> String {
    let mut ks = p12_keystore::KeyStore::new();
    ks.add_entry(
        "ca",
        p12_keystore::KeyStoreEntry::Certificate(p12_keystore::Certificate::from_der(cert).unwrap()),
    );
    afirma_core::base64_encode(&ks.writer("clave").write().unwrap())
}

/// Servidor HTTPS con la TSA de pruebas. Si `client_ca` es `Some`, exige
/// certificado cliente emitido por esa CA.
fn serve(p: &Pki, client_ca: Option<Vec<u8>>, requests: usize) -> (u16, std::thread::JoinHandle<()>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = match client_ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(ca)).unwrap();
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };
    let config = Arc::new(
        builder
            .with_single_cert(
                vec![CertificateDer::from(p.server_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p.server_key.clone())),
            )
            .unwrap(),
    );
    let tsa = MockTsa::new(Box::new(key("tsa")));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let Ok(stream) = stream else { continue };
            let Ok(conn) = rustls::ServerConnection::new(config.clone()) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut reader = BufReader::new(&mut tls);
            let mut len = 0usize;
            let mut line = String::new();
            let mut ok = true;
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => {
                        ok = false;
                        break;
                    }
                    _ => {}
                }
                let l = line.trim_end();
                if l.is_empty() {
                    break;
                }
                if let Some((k, v)) = l.split_once(':')
                    && k.eq_ignore_ascii_case("content-length")
                {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            if !ok {
                continue;
            }
            let mut body = vec![0u8; len];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let resp = tsa.respond(&body);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp.len()
            );
            let _ = tls.write_all(head.as_bytes());
            let _ = tls.write_all(&resp);
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    (port, h)
}

fn request(extra: &ExtraParams) -> afirma_core::Result<Vec<u8>> {
    Timestamper::new(TsaParams::from_extra_params(extra).unwrap().unwrap())
        .get_timestamp_token(&DigestAlgorithm::Sha256.digest(b"x"), DigestAlgorithm::Sha256)
}

#[test]
fn https_with_truststore_and_hostname_checks() {
    let p = pki("localhost");
    let (port, h) = serve(&p, None, 4);
    let mut extra = ExtraParams::new();
    extra.set("tsaURL", format!("https://localhost:{port}/tsa"));
    // Sin almacén de confianza: CA desconocida para el sistema (Java confiaría en todo).
    assert_eq!(request(&extra).unwrap_err().code, Some(codes::TSA_CONNECTION_ERROR));
    // Con el almacén de confianza.
    extra.set("tsaSslTrustStore", truststore(&p.ca_der));
    extra.set("tsaSslTrustStorePassword", "clave");
    assert!(request(&extra).is_ok());
    // Nombre distinto del del certificado: falla salvo con verifyHostname=false.
    extra.set("tsaURL", format!("https://127.0.0.1:{port}/tsa"));
    assert_eq!(request(&extra).unwrap_err().code, Some(codes::TSA_CONNECTION_ERROR));
    extra.set("verifyHostname", "false");
    assert!(request(&extra).is_ok());
    h.join().unwrap();
}

#[test]
fn https_client_certificate() {
    let p = pki("localhost");
    // El servidor exige certificado de la CA de pruebas de AutoFirma-rs.
    let ca = afirma_core::cert::decode_certificate(&read("pki/ca.crt")).unwrap();
    let (port, h) = serve(&p, Some(ca), 2);
    let mut extra = ExtraParams::new();
    extra.set("tsaURL", format!("https://localhost:{port}/tsa"));
    extra.set("tsaSslTrustStore", truststore(&p.ca_der));
    extra.set("tsaSslTrustStorePassword", "clave");
    assert_eq!(request(&extra).unwrap_err().code, Some(codes::TSA_CONNECTION_ERROR));
    extra.set(
        "tsaSslKeyStore",
        afirma_core::base64_encode(&read("pki/autenticacion.p12")),
    );
    extra.set("tsaSslKeyStorePassword", "12341234");
    assert!(request(&extra).is_ok(), "{:?}", request(&extra).err());
    h.join().unwrap();
}
