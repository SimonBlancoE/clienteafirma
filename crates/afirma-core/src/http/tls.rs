//! Utilidades TLS de `SSLErrorProcessor`: descarga de la cadena de
//! certificados de un servidor (sin verificarla) y comprobación de que el
//! certificado corresponde al dominio.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use x509_parser::prelude::*;

use super::proxy::ProxyEndpoint;

/// Verificador que acepta cualquier certificado y guarda la cadena recibida.
#[derive(Debug)]
struct RecordingVerifier {
    chain: Mutex<Vec<Vec<u8>>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut c) = self.chain.lock() {
            *c = std::iter::once(end_entity).chain(intermediates.iter()).map(|d| d.as_ref().to_vec()).collect();
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Descarga la cadena de certificados que presenta el servidor de una URL
/// `https` sin validarla (`downloadFromRemoteServer`), atravesando el proxy
/// del modo indicado con `CONNECT` si corresponde.
pub fn fetch_server_certificates(
    url: &str,
    proxy: &super::ProxyMode,
    timeout: Option<Duration>,
) -> Result<Vec<Vec<u8>>, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("URL no valida: {e}"))?;
    let host = parsed.host_str().ok_or("La URL no tiene servidor")?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let endpoint =
        if super::is_loopback_host(&host) { None } else { super::proxy::resolve_proxy(proxy, "https", &host) };
    fetch_chain(&host, port, endpoint.as_ref(), timeout)
}

fn connect(host: &str, port: u16, timeout: Option<Duration>) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host.trim_start_matches('[').trim_end_matches(']'), port)
        .to_socket_addrs()
        .map_err(|e| format!("No se pudo resolver {host}: {e}"))?
        .collect();
    let mut last = String::from("sin direcciones");
    for a in addrs {
        let r = match timeout {
            Some(t) => TcpStream::connect_timeout(&a, t),
            None => TcpStream::connect(a),
        };
        match r {
            Ok(s) => {
                let _ = s.set_read_timeout(timeout);
                let _ = s.set_write_timeout(timeout);
                return Ok(s);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("No se pudo conectar con {host}:{port}: {last}"))
}

pub(crate) fn fetch_chain(
    host: &str,
    port: u16,
    proxy: Option<&ProxyEndpoint>,
    timeout: Option<Duration>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut sock = match proxy {
        None => connect(host, port, timeout)?,
        Some(p) => {
            let mut s = connect(&p.host, p.port, timeout)?;
            let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
            if let (Some(u), Some(pw)) = (&p.username, &p.password) {
                req.push_str(&format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    crate::base64::encode(format!("{u}:{pw}").as_bytes())
                ));
            }
            req.push_str("\r\n");
            s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
            let mut resp = Vec::new();
            let mut byte = [0u8; 1];
            while !resp.ends_with(b"\r\n\r\n") {
                if s.read(&mut byte).map_err(|e| e.to_string())? == 0 || resp.len() > 16 * 1024 {
                    return Err("Respuesta no valida del proxy".into());
                }
                resp.push(byte[0]);
            }
            let status_line = String::from_utf8_lossy(&resp);
            let code = status_line.split_whitespace().nth(1).unwrap_or("");
            if code != "200" {
                return Err(format!("El proxy rechazo la conexion: {}", status_line.lines().next().unwrap_or("")));
            }
            s
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(RecordingVerifier { chain: Mutex::new(Vec::new()), provider: provider.clone() });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string())
        .map_err(|e| format!("Nombre de servidor no valido: {e}"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| format!("Error en la negociacion TLS: {e}"))?;
    }
    let chain = verifier.chain.lock().map(|c| c.clone()).unwrap_or_default();
    if chain.is_empty() {
        return Err("El servidor no ha enviado certificados".into());
    }
    Ok(chain)
}

/// Certificados a importar (`getCertsToImport`): los emisores si la cadena
/// tiene más de un certificado y, si no, el único certificado.
pub fn certs_to_import(chain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if chain.len() > 1 { chain[1..].to_vec() } else { chain.to_vec() }
}

/// `isIP`: IPv4 en notación decimal con cuatro partes 0-255 sin ceros a la
/// izquierda, o cualquier texto con `:` (IPv6).
pub fn is_ip_literal(host: &str) -> bool {
    if host.contains(':') {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && !(p.len() > 1 && p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|v| v <= 255)
        })
}

/// `matchesHost`: igualdad o comodín de un solo nivel (`*.dominio`) para
/// nombres DNS cuando el servidor no es una IP.
fn matches_host(host: &str, name: &str, host_is_ip: bool) -> bool {
    if name == host {
        return true;
    }
    if host_is_ip || !name.starts_with("*.") || name.ends_with('.') {
        return false;
    }
    let san_domain = &name[1..];
    if !host.ends_with(san_domain) {
        return false;
    }
    let prefix = &host[..host.len() - san_domain.len()];
    !prefix.is_empty() && !prefix.contains('.')
}

/// `checkCorrectIssuer`: el certificado del servidor corresponde al dominio.
/// Con nombres alternativos se comparan los `dNSName` y `iPAddress` (en
/// minúsculas); sin ellos, el CN del titular.
pub fn certificate_matches_host(cert_der: &[u8], host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_lowercase();
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else { return false };
    let san = cert.subject_alternative_name().ok().flatten();
    if let Some(san) = san {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(d) => {
                    if matches_host(&host, &d.to_lowercase(), is_ip_literal(&host)) {
                        return true;
                    }
                }
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_to_java_string(bytes) {
                        if matches_host(&host, &ip, true) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    } else {
        let cn = crate::cert::name_cn(cert.subject());
        !cn.is_empty() && matches_host(&host, &cn.to_lowercase(), is_ip_literal(&host))
    }
}

/// Representación de Java de una IP de `getSubjectAlternativeNames`
/// (IPv6 completa en hexadecimal sin ceros a la izquierda).
fn ip_to_java_string(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])),
        16 => Some(
            bytes.chunks(2).map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]]))).collect::<Vec<_>>().join(":"),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matching_rules() {
        assert!(is_ip_literal("192.168.1.10"));
        assert!(!is_ip_literal("192.168.01.10"));
        assert!(!is_ip_literal("256.1.1.1"));
        assert!(!is_ip_literal("a.b.c.d"));
        assert!(is_ip_literal("::1"));
        assert!(matches_host("www.gob.es", "*.gob.es", false));
        assert!(!matches_host("a.www.gob.es", "*.gob.es", false));
        assert!(!matches_host("gob.es", "*.gob.es", false));
        assert!(!matches_host("1.2.3.4", "*.3.4", true));
        assert!(!matches_host("www.gob.es", "*.gob.es.", false));
        assert_eq!(ip_to_java_string(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap(), "0:0:0:0:0:0:0:1");
        assert_eq!(certs_to_import(&[vec![1], vec![2], vec![3]]), vec![vec![2], vec![3]]);
        assert_eq!(certs_to_import(&[vec![1]]), vec![vec![1]]);
    }

    #[test]
    fn certificate_host() {
        let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/pki/firmante-rsa.crt")).unwrap();
        let der = crate::cert::decode_certificate(&pem).unwrap();
        // Certificado de persona: no corresponde a ningún servidor.
        assert!(!certificate_matches_host(&der, "www.gob.es"));
        assert!(!certificate_matches_host(b"basura", "x"));
    }
}
