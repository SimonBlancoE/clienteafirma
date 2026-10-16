//! Cliente LDAP v3 mínimo para descargar CRL de puntos de distribución
//! `ldap://` (lo que Java hace con JNDI en `CrlHelper.downloadCrlFromLdap`):
//! enlace anónimo, búsqueda `baseObject` con filtro `(objectClass=*)` del
//! atributo de la URL (por defecto `certificateRevocationList;binary`) y
//! desenlace. Sin TLS (`ldaps://` no se admite), sin referencias ni
//! paginación.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use afirma_cms::asn1::{Class, Tag, Tlv, der, tags};

use crate::fetch::{FetchError, Timeouts};

/// Puerto LDAP por defecto.
const DEFAULT_PORT: u16 = 389;
/// Atributo pedido si la URL no indica ninguno.
const DEFAULT_ATTRIBUTE: &str = "certificateRevocationList;binary";
/// Tamaño máximo de un mensaje LDAP aceptado.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Componentes de una URL LDAP (RFC 4516) que se usan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUrl {
    pub host: String,
    pub port: u16,
    /// DN base (decodificado).
    pub dn: String,
    /// Atributos pedidos (decodificados).
    pub attributes: Vec<String>,
}

/// Decodifica las secuencias `%XX` (las inválidas se dejan tal cual).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Interpreta una URL `ldap://servidor[:puerto]/dn[?atributos[?ámbito[?filtro]]]`.
pub fn parse_ldap_url(url: &str) -> Result<LdapUrl, FetchError> {
    let rest = url
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("ldap://"))
        .map(|_| &url[7..])
        .ok_or_else(|| FetchError::Unsupported(format!("URL LDAP no soportada: {url}")))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        let host = &authority[1..=end];
        let port = authority[end + 2..].strip_prefix(':');
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(FetchError::Io(format!("La URL LDAP no indica servidor: {url}")));
    }
    let port = match port {
        Some(p) if !p.is_empty() => p
            .parse::<u16>()
            .map_err(|_| FetchError::Io(format!("Puerto LDAP no valido: {url}")))?,
        _ => DEFAULT_PORT,
    };
    let mut parts = path.splitn(3, '?');
    let dn = percent_decode(parts.next().unwrap_or(""));
    let attributes: Vec<String> = parts
        .next()
        .unwrap_or("")
        .split(',')
        .map(percent_decode)
        .filter(|a| !a.is_empty())
        .collect();
    let attributes = if attributes.is_empty() {
        vec![DEFAULT_ATTRIBUTE.to_string()]
    } else {
        attributes
    };
    Ok(LdapUrl {
        host: host.to_string(),
        port,
        dn,
        attributes,
    })
}

fn app(number: u32, constructed: bool) -> Tag {
    Tag {
        class: Class::Application,
        constructed,
        number,
    }
}

fn enumerated(v: u8) -> Vec<u8> {
    der::tlv(tags::ENUMERATED, &[v])
}

/// `BindRequest` anónimo (versión 3, nombre y contraseña vacíos).
pub fn bind_request(message_id: i64) -> Vec<u8> {
    let bind = der::tlv(
        app(0, true),
        &[
            der::integer_i64(3),
            der::octet_string(b""),
            der::implicit_content(0, false, b""),
        ]
        .concat(),
    );
    der::sequence([der::integer_i64(message_id), bind])
}

/// `SearchRequest` de un único objeto con filtro `(objectClass=*)`.
pub fn search_request(message_id: i64, dn: &str, attributes: &[String]) -> Vec<u8> {
    let attrs = der::sequence(attributes.iter().map(|a| der::octet_string(a.as_bytes())));
    let search = der::tlv(
        app(3, true),
        &[
            der::octet_string(dn.as_bytes()),
            enumerated(0), // baseObject
            enumerated(3), // derefAlways (valor por defecto de JNDI)
            der::integer_i64(0),
            der::integer_i64(0),
            der::boolean(false),
            der::implicit_content(7, false, b"objectClass"), // present
            attrs,
        ]
        .concat(),
    );
    der::sequence([der::integer_i64(message_id), search])
}

/// `UnbindRequest`.
pub fn unbind_request(message_id: i64) -> Vec<u8> {
    der::sequence([der::integer_i64(message_id), der::tlv(app(2, false), b"")])
}

/// Lee un mensaje BER completo (longitud definida) del flujo.
fn read_message(stream: &mut impl Read) -> Result<Vec<u8>, FetchError> {
    let io = |e: std::io::Error| FetchError::Io(format!("Error leyendo la respuesta LDAP: {e}"));
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).map_err(io)?;
    let mut msg = head.to_vec();
    let len = if head[1] < 0x80 {
        usize::from(head[1])
    } else {
        let n = usize::from(head[1] & 0x7f);
        if n == 0 || n > 4 {
            return Err(FetchError::Io("Longitud de mensaje LDAP no soportada".into()));
        }
        let mut lb = vec![0u8; n];
        stream.read_exact(&mut lb).map_err(io)?;
        msg.extend_from_slice(&lb);
        lb.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
    };
    if len > MAX_MESSAGE {
        return Err(FetchError::Io(format!("Mensaje LDAP demasiado grande ({len} bytes)")));
    }
    let start = msg.len();
    msg.resize(start + len, 0);
    stream.read_exact(&mut msg[start..]).map_err(io)?;
    Ok(msg)
}

/// Operación y su contenido de un `LDAPMessage`.
fn split_message(msg: &[u8]) -> Result<(i64, Tlv<'_>), FetchError> {
    let bad = |e: afirma_cms::asn1::Asn1Error| FetchError::Io(format!("Mensaje LDAP no valido: {e}"));
    let parts = Tlv::parse_single(msg).and_then(|t| t.children()).map_err(bad)?;
    let id = parts
        .first()
        .ok_or_else(|| FetchError::Io("Mensaje LDAP vacio".into()))?
        .as_i64()
        .map_err(bad)?;
    let op = *parts
        .get(1)
        .ok_or_else(|| FetchError::Io("Mensaje LDAP sin operacion".into()))?;
    Ok((id, op))
}

/// `resultCode` y mensaje de diagnóstico de un `LDAPResult`.
fn ldap_result(op: &Tlv<'_>) -> Result<(i64, String), FetchError> {
    let bad = |e: afirma_cms::asn1::Asn1Error| FetchError::Io(format!("Resultado LDAP no valido: {e}"));
    let fields = op.children().map_err(bad)?;
    let code = fields
        .first()
        .ok_or_else(|| FetchError::Io("Resultado LDAP vacio".into()))?
        .as_i64()
        .map_err(bad)?;
    let diag = fields
        .get(2)
        .map(|d| String::from_utf8_lossy(d.value).into_owned())
        .unwrap_or_default();
    Ok((code, diag))
}

/// Nombre de atributo sin opciones (`;binary`) y en minúsculas.
fn attribute_base(name: &str) -> String {
    name.split(';').next().unwrap_or("").to_ascii_lowercase()
}

/// Busca el primer valor de alguno de los atributos pedidos en un
/// `SearchResultEntry`.
fn entry_value(op: &Tlv<'_>, wanted: &[String]) -> Option<Vec<u8>> {
    let fields = op.children().ok()?;
    let wanted: Vec<String> = wanted.iter().map(|w| attribute_base(w)).collect();
    for attr in fields.get(1)?.children().ok()? {
        let parts = attr.children().ok()?;
        let name = String::from_utf8_lossy(parts.first()?.value).into_owned();
        if !wanted.contains(&attribute_base(&name)) {
            continue;
        }
        if let Some(v) = parts.get(1)?.children().ok()?.into_iter().next() {
            let v = v.octet_string_content().ok()?;
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn connect(host: &str, port: u16, timeouts: Timeouts) -> Result<TcpStream, FetchError> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| FetchError::Io(format!("No se pudo resolver {host}: {e}")))?
        .collect();
    let mut last = String::from("sin direcciones");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeouts.connect) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(timeouts.read));
                let _ = s.set_write_timeout(Some(timeouts.read));
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => last = format!("tiempo agotado ({e})"),
            Err(e) => last = e.to_string(),
        }
    }
    Err(FetchError::Io(format!("No se pudo conectar con {host}:{port}: {last}")))
}

/// Descarga el primer valor del atributo de la URL (la CRL) de un servidor
/// LDAP, con enlace anónimo.
pub fn fetch_crl(url: &str, timeouts: Timeouts) -> Result<Vec<u8>, FetchError> {
    let target = parse_ldap_url(url)?;
    let mut stream = connect(&target.host, target.port, timeouts)?;
    let io = |e: std::io::Error| FetchError::Io(format!("Error de comunicacion LDAP con {url}: {e}"));

    stream.write_all(&bind_request(1)).map_err(io)?;
    let msg = read_message(&mut stream)?;
    let (_, op) = split_message(&msg)?;
    if op.tag != app(1, true) {
        return Err(FetchError::Io(format!(
            "Respuesta LDAP inesperada al enlace: {}",
            op.tag
        )));
    }
    let (code, diag) = ldap_result(&op)?;
    if code != 0 {
        return Err(FetchError::Io(format!(
            "El servidor LDAP rechazo el enlace anonimo ({code}): {diag}"
        )));
    }

    stream
        .write_all(&search_request(2, &target.dn, &target.attributes))
        .map_err(io)?;
    let mut value = None;
    loop {
        let msg = read_message(&mut stream)?;
        let (_, op) = split_message(&msg)?;
        match op.tag.number {
            4 if op.tag.class == Class::Application => {
                if value.is_none() {
                    value = entry_value(&op, &target.attributes);
                }
            }
            5 if op.tag.class == Class::Application => {
                let (code, diag) = ldap_result(&op)?;
                if code != 0 {
                    return Err(FetchError::Io(format!("Busqueda LDAP fallida ({code}): {diag}")));
                }
                break;
            }
            // Referencias de búsqueda y otros mensajes: se ignoran.
            _ => {}
        }
    }
    let _ = stream.write_all(&unbind_request(3));
    value.ok_or_else(|| FetchError::Io(format!("No se ha podido descargar la CRL desde {url}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_ldap_url(
            "ldap://ldapusu.cert.fnmt.es/cn=CRL1,cn=AC%20FNMT%20Usuarios,ou=CERES,o=FNMT-RCM,c=ES?certificateRevocationList;binary?base?objectclass=cRLDistributionPoint",
        )
        .unwrap();
        assert_eq!(u.host, "ldapusu.cert.fnmt.es");
        assert_eq!(u.port, 389);
        assert_eq!(u.dn, "cn=CRL1,cn=AC FNMT Usuarios,ou=CERES,o=FNMT-RCM,c=ES");
        assert_eq!(u.attributes, vec!["certificateRevocationList;binary".to_string()]);
        let u = parse_ldap_url("LDAP://[::1]:1389/cn=x%2Cc=ES").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.dn.as_str()), ("::1", 1389, "cn=x,c=ES"));
        assert_eq!(u.attributes, vec![DEFAULT_ATTRIBUTE.to_string()]);
        let u = parse_ldap_url("ldap://h:10389/o=x?authorityRevocationList;binary").unwrap();
        assert_eq!(u.port, 10389);
        assert_eq!(u.attributes, vec!["authorityRevocationList;binary".to_string()]);
        assert!(parse_ldap_url("ldaps://h/o=x").is_err());
        assert!(parse_ldap_url("ldap:///o=x").is_err());
        assert!(parse_ldap_url("ldap://h:x/o=x").is_err());
    }

    #[test]
    fn encodings() {
        // Enlace anónimo LDAPv3: 30 0c 02 01 01 60 07 02 01 03 04 00 80 00.
        assert_eq!(hex::encode(bind_request(1)), "300c020101600702010304008000");
        assert_eq!(hex::encode(unbind_request(3)), "30050201034200");
        let s = search_request(2, "o=x", &["a;binary".into()]);
        assert_eq!(
            hex::encode(&s),
            "3032020102632d04036f3d780a01000a0103020100020100010100870b6f626a656374436c617373300a0408613b62696e617279"
        );
    }
}
