//! Transporte de las peticiones de sello de tiempo: HTTP/HTTPS (RFC 3161
//! §3.4) y el protocolo `socket://` de AutoFirma (TCP con prefijo de longitud).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::TsaParams;

/// Tiempo de espera del transporte por socket (`CMSTimestamper.SOCKET_TIMEOUT`).
pub const SOCKET_TIMEOUT: Duration = Duration::from_millis(500_000);

/// Envío de una petición `TimeStampReq` (DER) y recepción de la respuesta.
pub trait TsaTransport: Send + Sync {
    fn send(&self, params: &TsaParams, request: &[u8]) -> Result<Vec<u8>, String>;
}

/// Transporte por defecto según el esquema de la URL.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultTransport;

impl TsaTransport for DefaultTransport {
    fn send(&self, params: &TsaParams, request: &[u8]) -> Result<Vec<u8>, String> {
        let scheme = params.url.split(':').next().unwrap_or_default();
        match scheme {
            "socket" => send_socket(&params.url, request),
            "http" | "https" => send_http(params, request),
            other => Err(format!("Protocolo de conexion con TSA no soportado: {other}")),
        }
    }
}

/// `socket://host:puerto`: se envía `int32 BE (len + 1)`, un byte `0` y la
/// petición; se recibe `int32 BE tamaño`, un byte de indicador (5 o 6) y
/// `tamaño - 1` bytes de respuesta.
pub fn send_socket(url: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("socket://").ok_or_else(|| format!("URL de socket no valida: {url}"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    let mut stream = TcpStream::connect(authority).map_err(|e| format!("No se pudo conectar con {authority}: {e}"))?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).map_err(|e| e.to_string())?;
    let len = u32::try_from(request.len() + 1).map_err(|_| "peticion demasiado grande".to_string())?;
    let mut out = Vec::with_capacity(request.len() + 5);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(0);
    out.extend_from_slice(request);
    stream.write_all(&out).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).map_err(|e| e.to_string())?;
    let size = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let flag = hdr[4];
    if size == 0 || size > 64 * 1024 * 1024 {
        return Err(format!("Tamano de respuesta de la TSA no valido: {size}"));
    }
    let mut resp = vec![0u8; size - 1];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;
    if flag != 5 && flag != 6 {
        return Err(format!("Obtenida resuesta incorrecta del servidor TSA: {}", String::from_utf8_lossy(&resp)));
    }
    Ok(resp)
}

/// Lee los certificados de un almacén PKCS#12 (para la confianza HTTPS).
#[cfg(feature = "http")]
fn pkcs12_certs(data: &[u8], password: &str) -> Result<Vec<Vec<u8>>, String> {
    let archive = p12_keystore::Pkcs12Archive::from_pkcs12(data, password)
        .map_err(|e| format!("No se ha podido abrir el almacen PKCS#12: {e}"))?;
    Ok(archive.certs.iter().map(|c| c.cert.as_der().to_vec()).collect())
}

/// Lee la clave (PKCS#8) y la cadena de un almacén PKCS#12 (certificado
/// cliente para HTTPS).
#[cfg(feature = "http")]
fn pkcs12_client(data: &[u8], password: &str) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let archive = p12_keystore::Pkcs12Archive::from_pkcs12(data, password)
        .map_err(|e| format!("Error obteniendo el almacen de certificados cliente para el SSL: {e}"))?;
    let key = archive.keys.first().ok_or_else(|| "El almacen de certificado cliente no contiene claves".to_string())?;
    let id = key.local_key_id.as_ref().map(|k| k.0.clone());
    let mut chain: Vec<Vec<u8>> = Vec::new();
    if let Some(id) = &id
        && let Some(c) = archive.certs.iter().find(|c| c.local_key_id.as_deref() == Some(id.as_slice())) {
            chain.push(c.cert.as_der().to_vec());
        }
    for c in &archive.certs {
        let der = c.cert.as_der().to_vec();
        if !chain.contains(&der) {
            chain.push(der);
        }
    }
    Ok((key.key.as_der().to_vec(), chain))
}

/// Envío por HTTP(S) con `ureq` (rustls). La confianza HTTPS es la del
/// sistema salvo que se indique `tsaSslTrustStore`; `verifyHostname=false`
/// desactiva la verificación del servidor.
#[cfg(feature = "http")]
pub fn send_http(params: &TsaParams, request: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine;
    use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};

    let mut tls = TlsConfig::builder();
    if let Some(ts) = &params.ssl_truststore {
        if !params.ssl_truststore_type.eq_ignore_ascii_case("PKCS12") {
            return Err(format!("Tipo de almacen de confianza no soportado: {}", params.ssl_truststore_type));
        }
        let roots: Vec<Certificate<'static>> = pkcs12_certs(ts, &params.ssl_truststore_password)?
            .into_iter()
            .map(|c| Certificate::from_der(&c).to_owned())
            .collect();
        tls = tls.root_certs(RootCerts::new_with_certs(&roots));
    } else {
        tls = tls.root_certs(RootCerts::PlatformVerifier);
    }
    if let Some(ks) = &params.ssl_keystore {
        if !params.ssl_keystore_type.eq_ignore_ascii_case("PKCS12") {
            return Err(format!("Tipo de almacen de claves no soportado: {}", params.ssl_keystore_type));
        }
        let (key, chain) = pkcs12_client(ks, &params.ssl_keystore_password)?;
        let certs: Vec<Certificate<'static>> = chain.iter().map(|c| Certificate::from_der(c).to_owned()).collect();
        // `KeyKind` no es público en ureq: se pasa la clave PKCS#8 como PEM.
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&key)
        );
        let pk = PrivateKey::from_pem(pem.as_bytes())
            .map_err(|e| format!("Clave del certificado cliente no valida: {e}"))?;
        tls = tls.client_cert(Some(ClientCert::new_with_certs(&certs, pk)));
    }
    if !params.verify_hostname {
        tls = tls.disable_verification(true);
    }
    let config = ureq::Agent::config_builder()
        .tls_config(tls.build())
        .http_status_as_error(true)
        .timeout_global(Some(Duration::from_secs(120)))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let mut req = agent
        .post(&params.url)
        .header("Content-Type", "application/timestamp-query")
        .header("Content-Transfer-Encoding", "binary");
    if let Some(user) = params.user.as_deref().filter(|u| !u.is_empty()) {
        // Como Java: si no hay contraseña se concatena el texto "null".
        let pwd = params.password.as_deref().unwrap_or("null");
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pwd}"));
        req = req.header("Authorization", format!("Basic {token}"));
    }
    let mut resp = req.send(request).map_err(|e| e.to_string())?;
    let encoding = resp.headers().get("Content-Encoding").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_vec().map_err(|e| e.to_string())?;
    if encoding.is_some_and(|e| e.eq_ignore_ascii_case("base64")) {
        let text = String::from_utf8_lossy(&body).to_string();
        return afirma_core::base64_decode_lenient(&text).map_err(|e| format!("Respuesta Base64 no valida: {e}"));
    }
    Ok(body)
}

/// Sin la característica `http` solo se admite el transporte por socket.
#[cfg(not(feature = "http"))]
pub fn send_http(_params: &TsaParams, _request: &[u8]) -> Result<Vec<u8>, String> {
    Err("Transporte HTTP no disponible (compilado sin la caracteristica 'http')".into())
}
