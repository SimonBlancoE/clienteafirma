//! CA local y certificado SSL de `127.0.0.1` para el servidor WebSocket/socket del
//! navegador (§9.2, §10.4).
//!
//! Igual que Java: CA `CN=Autofirma ROOT` y certificado `CN=127.0.0.1`, RSA-2048,
//! SHA256withRSA, 3650 días, ficheros `autofirma.pfx` (contraseña `654321`, alias
//! `SocketAutoFirma`, cadena `[SSL, CA]`), `Autofirma_ROOT.cer` y (macOS) `autofirma.cer`,
//! todos en DER. La clave privada de la CA se descarta.
//!
//! Mejoras documentadas: números de serie positivos de 128 bits, `notBefore` adelantado un día
//! (desfase de reloj), certificado SSL con `KeyUsage` (digitalSignature, keyEncipherment),
//! `ExtendedKeyUsage` serverAuth y SAN `IP:127.0.0.1`, `IP:::1`, `DNS:localhost` (sin el
//! `DNS:127.0.0.1` erróneo de Java).

use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha1::Digest as _;
use x509_parser::prelude::*;

use crate::ctx::{Context, Os};
use crate::error::{Result, SystemError, io_at};
use crate::fsutil;

/// Almacén PKCS#12 del servidor local.
pub const KS_FILENAME: &str = "autofirma.pfx";
/// Certificado de la CA (DER).
pub const CA_CERT_FILENAME: &str = "Autofirma_ROOT.cer";
/// Certificado SSL (DER), solo macOS en Java.
pub const SSL_CERT_FILENAME: &str = "autofirma.cer";
/// Contraseña del almacén y de la clave.
pub const KS_PASSWORD: &str = "654321";
/// Alias del PKCS#12 y apodo en NSS.
pub const CERT_ALIAS: &str = "SocketAutoFirma";
/// CN de la CA (y nombre descriptivo en el almacén de Windows).
pub const CA_CN: &str = "Autofirma ROOT";
/// CN del certificado SSL.
pub const SSL_CN: &str = "127.0.0.1";
/// Nombres (sin distinguir mayúsculas) de CA de versiones anteriores que se limpian.
pub const LEGACY_CA_NAMES: &[&str] = &["Autofirma ROOT", "AutoFirma ROOT"];
/// Validez de los certificados (10 × 365 días, como Java).
pub const VALIDITY_DAYS: i64 = 3650;
/// Margen por debajo del cual se regeneran los certificados.
pub const RENEW_BEFORE_DAYS: i64 = 30;

/// Parámetros de generación.
#[derive(Debug, Clone)]
pub struct CertProfile {
    /// Validez en días.
    pub validity_days: i64,
    /// Adelanto de `notBefore`.
    pub backdate: chrono::Duration,
    /// Incluir `IP:::1` en el SAN.
    pub include_ipv6: bool,
}

impl Default for CertProfile {
    fn default() -> Self {
        Self {
            validity_days: VALIDITY_DAYS,
            backdate: chrono::Duration::days(1),
            include_ipv6: true,
        }
    }
}

/// Material generado.
#[derive(Clone)]
pub struct CertPack {
    /// Certificado de la CA (DER).
    pub ca_der: Vec<u8>,
    /// Certificado SSL (DER).
    pub ssl_der: Vec<u8>,
    /// Clave privada SSL (PKCS#8 DER).
    pub ssl_key_pkcs8: Vec<u8>,
    /// PKCS#12 con la clave SSL y la cadena `[SSL, CA]`.
    pub pfx: Vec<u8>,
}

impl std::fmt::Debug for CertPack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertPack")
            .field("ca", &sha1_hex(&self.ca_der))
            .field("ssl", &sha1_hex(&self.ssl_der))
            .finish()
    }
}

fn cert_err(e: impl std::fmt::Display) -> SystemError {
    SystemError::Certificate(e.to_string())
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    use ring::rand::SecureRandom;
    let mut v = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut v)
        .map_err(|_| cert_err("sin fuente de aleatoriedad"))?;
    Ok(v)
}

/// Número de serie positivo de 128 bits (sin ceros iniciales).
fn positive_serial() -> Result<rcgen::SerialNumber> {
    let mut s = random_bytes(16)?;
    s[0] = (s[0] & 0x7f) | 0x40;
    Ok(rcgen::SerialNumber::from_slice(&s))
}

fn rsa_2048() -> Result<(Vec<u8>, Vec<u8>)> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(cert_err)?;
    let pkcs8 = key.to_pkcs8_der().map_err(cert_err)?.as_bytes().to_vec();
    let spk = key
        .to_public_key()
        .to_pkcs1_der()
        .map_err(cert_err)?
        .as_bytes()
        .to_vec();
    Ok((pkcs8, spk))
}

fn to_offset(dt: chrono::DateTime<chrono::Utc>) -> Result<::time::OffsetDateTime> {
    ::time::OffsetDateTime::from_unix_timestamp(dt.timestamp()).map_err(cert_err)
}

/// Genera una CA y un certificado SSL nuevos.
pub fn generate(profile: &CertProfile) -> Result<CertPack> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose as Eku, IsCa, KeyIdMethod, KeyPair,
        KeyUsagePurpose as Ku, SanType,
    };

    let now = chrono::Utc::now();
    let not_before = to_offset(now - profile.backdate)?;
    let not_after = to_offset(now + chrono::Duration::days(profile.validity_days))?;

    // CA
    let (ca_pkcs8, ca_spk) = rsa_2048()?;
    let ca_key = KeyPair::try_from(ca_pkcs8.as_slice()).map_err(cert_err)?;
    let mut ca = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_CN);
    ca.distinguished_name = dn;
    ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        Ku::KeyCertSign,
        Ku::DigitalSignature,
        Ku::KeyEncipherment,
        Ku::DataEncipherment,
        Ku::CrlSign,
    ];
    ca.extended_key_usages = vec![Eku::ServerAuth, Eku::ClientAuth, Eku::Any];
    ca.not_before = not_before;
    ca.not_after = not_after;
    ca.serial_number = Some(positive_serial()?);
    // RFC 5280, método 1: SHA-1 de la clave pública (como Java).
    ca.key_identifier_method = KeyIdMethod::PreSpecified(sha1::Sha1::digest(&ca_spk).to_vec());
    let ca_cert = ca.self_signed(&ca_key).map_err(cert_err)?;
    let issuer = rcgen::Issuer::new(ca, ca_key);

    // SSL
    let (ssl_pkcs8, ssl_spk) = rsa_2048()?;
    let ssl_key = KeyPair::try_from(ssl_pkcs8.as_slice()).map_err(cert_err)?;
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, SSL_CN);
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![Ku::DigitalSignature, Ku::KeyEncipherment];
    p.extended_key_usages = vec![Eku::ServerAuth];
    let mut sans = vec![SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))];
    if profile.include_ipv6 {
        sans.push(SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    }
    sans.push(SanType::DnsName("localhost".try_into().map_err(cert_err)?));
    p.subject_alt_names = sans;
    p.not_before = not_before;
    p.not_after = not_after;
    p.serial_number = Some(positive_serial()?);
    p.use_authority_key_identifier_extension = true;
    p.key_identifier_method = KeyIdMethod::PreSpecified(sha1::Sha1::digest(&ssl_spk).to_vec());
    let ssl_cert = p.signed_by(&ssl_key, &issuer).map_err(cert_err)?;

    let ca_der = ca_cert.der().to_vec();
    let ssl_der = ssl_cert.der().to_vec();
    let pfx = build_pfx(&ssl_pkcs8, &ssl_der, &ca_der)?;
    Ok(CertPack {
        ca_der,
        ssl_der,
        ssl_key_pkcs8: ssl_pkcs8,
        pfx,
    })
}

/// Construye el PKCS#12 (`SocketAutoFirma`, contraseña `654321`, cadena `[SSL, CA]`) con los
/// algoritmos por defecto del JDK moderno (PBES2/AES-256, HMAC-SHA256, 10000 iteraciones).
pub fn build_pfx(key_pkcs8: &[u8], ssl_der: &[u8], ca_der: &[u8]) -> Result<Vec<u8>> {
    use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
    let key = PrivateKey::from_der(key_pkcs8).map_err(cert_err)?;
    let chain = vec![
        Certificate::from_der(ssl_der).map_err(cert_err)?,
        Certificate::from_der(ca_der).map_err(cert_err)?,
    ];
    let local_key_id = sha1::Sha1::digest(ssl_der).to_vec();
    let mut ks = KeyStore::new();
    ks.add_entry(
        CERT_ALIAS,
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(local_key_id, key, chain)),
    );
    ks.writer(KS_PASSWORD).write().map_err(cert_err)
}

/// Contenido de un PKCS#12 del servidor local.
#[derive(Debug, Clone)]
pub struct PfxContent {
    /// Alias de la entrada con clave.
    pub alias: String,
    /// Certificado SSL (DER).
    pub ssl_der: Vec<u8>,
    /// Cadena completa (el primero es el SSL; el último, normalmente la CA).
    pub chain: Vec<Vec<u8>>,
}

/// Abre un PKCS#12 con la contraseña indicada y devuelve la primera entrada con clave.
pub fn read_pfx(data: &[u8], password: &str) -> Result<PfxContent> {
    let ks = p12_keystore::KeyStore::from_pkcs12(data, password, p12_keystore::Pkcs12ImportPolicy::Relaxed)
        .map_err(cert_err)?;
    let (alias, chain) = ks
        .private_key_chain()
        .ok_or_else(|| cert_err("el almacén no contiene ninguna clave privada"))?;
    let chain: Vec<Vec<u8>> = chain.certs().iter().map(|c| c.as_der().to_vec()).collect();
    let ssl_der = chain
        .first()
        .cloned()
        .ok_or_else(|| cert_err("la clave del almacén no tiene certificado"))?;
    Ok(PfxContent {
        alias: alias.to_string(),
        ssl_der,
        chain,
    })
}

/// DER → PEM.
pub fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(&String::from_utf8_lossy(chunk));
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

/// Lee un certificado en DER o PEM.
pub fn parse_cert_file(data: &[u8]) -> Result<Vec<u8>> {
    if let Ok(text) = std::str::from_utf8(data)
        && let Some(start) = text.find("-----BEGIN CERTIFICATE-----")
    {
        let rest = &text[start + 27..];
        let end = rest
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| cert_err("PEM incompleto"))?;
        let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
        return base64::engine::general_purpose::STANDARD.decode(b64).map_err(cert_err);
    }
    X509Certificate::from_der(data).map_err(cert_err)?;
    Ok(data.to_vec())
}

/// SHA-1 en hexadecimal en mayúsculas.
pub fn sha1_hex(der: &[u8]) -> String {
    hex::encode_upper(sha1::Sha1::digest(der))
}

/// SHA-256 en hexadecimal en mayúsculas.
pub fn sha256_hex(der: &[u8]) -> String {
    hex::encode_upper(sha2::Sha256::digest(der))
}

/// Datos básicos de un certificado.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub common_name: Option<String>,
    pub serial_hex: String,
    pub not_before: i64,
    pub not_after: i64,
    pub sha1: String,
    pub sha256: String,
    pub is_ca: bool,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub server_auth: bool,
}

/// Analiza un certificado DER.
pub fn cert_info(der: &[u8]) -> Result<CertInfo> {
    let (_, c) = X509Certificate::from_der(der).map_err(cert_err)?;
    let mut san_dns = Vec::new();
    let mut san_ip = Vec::new();
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => san_dns.push(d.to_string()),
                GeneralName::IPAddress(b) => san_ip.push(match b.len() {
                    4 => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
                    16 => {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(b);
                        std::net::Ipv6Addr::from(a).to_string()
                    }
                    _ => hex::encode(b),
                }),
                _ => {}
            }
        }
    }
    let server_auth = c
        .extended_key_usage()
        .ok()
        .flatten()
        .map(|e| e.value.server_auth || e.value.any)
        .unwrap_or(true);
    Ok(CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        common_name: c
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok().map(str::to_string)),
        serial_hex: c.raw_serial_as_string(),
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        sha1: sha1_hex(der),
        sha256: sha256_hex(der),
        is_ca: c.basic_constraints().ok().flatten().is_some_and(|b| b.value.ca),
        san_dns,
        san_ip,
        server_auth,
    })
}

/// `true` si `ca_der` firma `leaf_der`.
pub fn verifies(leaf_der: &[u8], ca_der: &[u8]) -> bool {
    let (Ok((_, leaf)), Ok((_, ca))) = (X509Certificate::from_der(leaf_der), X509Certificate::from_der(ca_der)) else {
        return false;
    };
    leaf.verify_signature(Some(ca.public_key())).is_ok()
}

/// Directorios donde la aplicación busca `autofirma.pfx` (orden de `SecureSocketUtils`:
/// directorio de instalación y después el alternativo; en macOS, además, el de sistema).
pub fn search_dirs(ctx: &Context) -> Vec<PathBuf> {
    let mut v = vec![ctx.app.app_dir.clone(), ctx.paths.alternative_dir.clone()];
    if ctx.os == Os::MacOs {
        v.push(ctx.paths.system_config_dir.clone());
    }
    v.dedup();
    v
}

/// Directorio donde se generan los certificados al instalar o restaurar.
pub fn target_dir(ctx: &Context) -> PathBuf {
    match ctx.os {
        // El paquete .app no se modifica (firma de código): sistema si hay privilegios,
        // directorio de usuario si no (como Java).
        Os::MacOs => {
            if ctx.elevated {
                ctx.paths.system_config_dir.clone()
            } else {
                ctx.paths.alternative_dir.clone()
            }
        }
        _ => {
            if fsutil::dir_is_writable(&ctx.app.app_dir) {
                ctx.app.app_dir.clone()
            } else {
                ctx.paths.alternative_dir.clone()
            }
        }
    }
}

/// Estado de los certificados de un directorio.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertStatus {
    pub dir: PathBuf,
    pub pfx_present: bool,
    pub ca_present: bool,
    /// Error al abrir el PKCS#12 (contraseña, formato...).
    pub pfx_error: Option<String>,
    pub alias: Option<String>,
    pub ssl: Option<CertInfo>,
    pub ca: Option<CertInfo>,
    /// La CA de `Autofirma_ROOT.cer` firma el certificado SSL.
    pub chain_ok: bool,
    /// Días hasta la caducidad más próxima.
    pub days_left: Option<i64>,
}

impl CertStatus {
    /// `true` si se puede usar tal cual.
    pub fn usable(&self) -> bool {
        self.pfx_error.is_none()
            && self.ssl.is_some()
            && self.ca.is_some()
            && self.chain_ok
            && self.days_left.is_some_and(|d| d > 0)
    }

    /// `true` si hay que regenerar (inutilizable o a punto de caducar).
    pub fn needs_renewal(&self) -> bool {
        !self.usable() || self.days_left.is_some_and(|d| d < RENEW_BEFORE_DAYS)
    }
}

/// Inspecciona los certificados de un directorio.
pub fn inspect(dir: &Path) -> CertStatus {
    let pfx_path = dir.join(KS_FILENAME);
    let ca_path = dir.join(CA_CERT_FILENAME);
    let mut st = CertStatus {
        dir: dir.to_path_buf(),
        pfx_present: pfx_path.is_file(),
        ca_present: ca_path.is_file(),
        pfx_error: None,
        alias: None,
        ssl: None,
        ca: None,
        chain_ok: false,
        days_left: None,
    };
    if st.pfx_present {
        match std::fs::read(&pfx_path)
            .map_err(cert_err)
            .and_then(|d| read_pfx(&d, KS_PASSWORD))
        {
            Ok(c) => {
                st.alias = Some(c.alias);
                st.ssl = cert_info(&c.ssl_der).ok();
                let chain_ca = c.chain.last().filter(|_| c.chain.len() > 1).cloned();
                if let Some(ca_der) = std::fs::read(&ca_path).ok().and_then(|d| parse_cert_file(&d).ok()) {
                    st.chain_ok = verifies(&c.ssl_der, &ca_der);
                    st.ca = cert_info(&ca_der).ok();
                } else if let Some(ca) = &chain_ca {
                    st.chain_ok = verifies(&c.ssl_der, ca);
                }
            }
            Err(e) => st.pfx_error = Some(e.to_string()),
        }
    } else if st.ca_present {
        st.ca = std::fs::read(&ca_path)
            .ok()
            .and_then(|d| parse_cert_file(&d).ok())
            .and_then(|d| cert_info(&d).ok());
    }
    let now = chrono::Utc::now().timestamp();
    let min_after = [
        st.ssl.as_ref().map(|c| c.not_after),
        st.ca.as_ref().map(|c| c.not_after),
    ]
    .into_iter()
    .flatten()
    .min();
    st.days_left = min_after.map(|a| (a - now).div_euclid(86_400));
    st
}

/// Certificados locales listos para usar.
#[derive(Debug, Clone)]
pub struct LocalCerts {
    /// Directorio.
    pub dir: PathBuf,
    /// CA (DER).
    pub ca_der: Vec<u8>,
    /// Certificado SSL (DER).
    pub ssl_der: Vec<u8>,
}

impl LocalCerts {
    /// Ruta de `Autofirma_ROOT.cer`.
    pub fn ca_path(&self) -> PathBuf {
        self.dir.join(CA_CERT_FILENAME)
    }
    /// Ruta de `autofirma.cer`.
    pub fn ssl_path(&self) -> PathBuf {
        self.dir.join(SSL_CERT_FILENAME)
    }
    /// Ruta de `autofirma.pfx`.
    pub fn pfx_path(&self) -> PathBuf {
        self.dir.join(KS_FILENAME)
    }
}

/// Política de regeneración.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Regenerate {
    /// Solo si falta el PKCS#12 (Java).
    IfMissing,
    /// Si falta, no se puede abrir, la cadena no cuadra o caduca en menos de 30 días.
    #[default]
    IfInvalid,
    /// Siempre.
    Always,
}

/// Resultado de [`ensure`].
#[derive(Debug, Clone)]
pub struct EnsureOutcome {
    pub certs: LocalCerts,
    /// `true` si se generaron certificados nuevos.
    pub generated: bool,
    /// `true` si se copiaron certificados aportados por el administrador.
    pub copied_admin: bool,
}

/// Certificados aportados por el administrador (`-keystore_path` / `-certificate_path`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminCerts {
    pub pfx: PathBuf,
    pub ca_cert: PathBuf,
}

fn write_files(dir: &Path, ca_der: &[u8], ssl_der: &[u8], pfx: &[u8], os: Os) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(io_at(dir))?;
    // El PKCS#12 debe ser legible por todos los usuarios cuando está en un directorio común
    // (como en Java); la clave solo sirve para 127.0.0.1 y la clave de la CA no se guarda.
    fsutil::write_atomic(&dir.join(KS_FILENAME), pfx, Some(0o644))?;
    fsutil::write_atomic(&dir.join(CA_CERT_FILENAME), ca_der, Some(0o644))?;
    if os == Os::MacOs {
        fsutil::write_atomic(&dir.join(SSL_CERT_FILENAME), ssl_der, Some(0o644))?;
    }
    Ok(())
}

/// Garantiza que existen certificados válidos en `dir` (generándolos o copiando los del
/// administrador). Reproduce la recuperación de Java de `Autofirma_ROOT.cer` desde la
/// cadena del PKCS#12 cuando solo falta el certificado de la CA.
pub fn ensure(
    ctx: &Context,
    dir: &Path,
    policy: Regenerate,
    admin: Option<&AdminCerts>,
    profile: &CertProfile,
) -> Result<EnsureOutcome> {
    if let Some(a) = admin {
        let pfx = std::fs::read(&a.pfx).map_err(io_at(&a.pfx))?;
        let content = read_pfx(&pfx, KS_PASSWORD).map_err(|e| {
            cert_err(format!(
                "el almacén del administrador no se abre con la contraseña {KS_PASSWORD}: {e}"
            ))
        })?;
        let ca_der = parse_cert_file(&std::fs::read(&a.ca_cert).map_err(io_at(&a.ca_cert))?)?;
        write_files(dir, &ca_der, &content.ssl_der, &pfx, ctx.os)?;
        return Ok(EnsureOutcome {
            certs: LocalCerts {
                dir: dir.to_path_buf(),
                ca_der,
                ssl_der: content.ssl_der,
            },
            generated: false,
            copied_admin: true,
        });
    }
    let st = inspect(dir);
    let regenerate = match policy {
        Regenerate::Always => true,
        Regenerate::IfMissing => !st.pfx_present,
        Regenerate::IfInvalid => {
            // Caso B de Java: PKCS#12 válido sin Autofirma_ROOT.cer → se recupera de la cadena.
            if st.pfx_present && st.pfx_error.is_none() && !st.ca_present {
                false
            } else {
                st.needs_renewal()
            }
        }
    };
    if !regenerate {
        let pfx = std::fs::read(dir.join(KS_FILENAME)).map_err(io_at(&dir.join(KS_FILENAME)))?;
        let content = read_pfx(&pfx, KS_PASSWORD)?;
        let ca_path = dir.join(CA_CERT_FILENAME);
        let ca_der = match std::fs::read(&ca_path).ok().and_then(|d| parse_cert_file(&d).ok()) {
            Some(d) => d,
            None => {
                let ca = content
                    .chain
                    .last()
                    .filter(|_| content.chain.len() > 1)
                    .cloned()
                    .ok_or_else(|| cert_err("el PKCS#12 no contiene la CA"))?;
                fsutil::write_atomic(&ca_path, &ca, Some(0o644))?;
                ca
            }
        };
        if ctx.os == Os::MacOs && !dir.join(SSL_CERT_FILENAME).is_file() {
            fsutil::write_atomic(&dir.join(SSL_CERT_FILENAME), &content.ssl_der, Some(0o644))?;
        }
        return Ok(EnsureOutcome {
            certs: LocalCerts {
                dir: dir.to_path_buf(),
                ca_der,
                ssl_der: content.ssl_der,
            },
            generated: false,
            copied_admin: false,
        });
    }
    let pack = generate(profile)?;
    write_files(dir, &pack.ca_der, &pack.ssl_der, &pack.pfx, ctx.os)?;
    Ok(EnsureOutcome {
        certs: LocalCerts {
            dir: dir.to_path_buf(),
            ca_der: pack.ca_der,
            ssl_der: pack.ssl_der,
        },
        generated: true,
        copied_admin: false,
    })
}

/// Busca los certificados del servidor local en los directorios de búsqueda: el primero
/// utilizable (no caducado y con la cadena correcta) y, si no hay ninguno, el primero que se
/// pueda abrir. Recomendado también para el servidor WebSocket (Java usaba el primero que
/// existiera aunque estuviera caducado).
pub fn locate(ctx: &Context) -> Option<LocalCerts> {
    let load = |d: &Path| -> Option<LocalCerts> {
        let pfx = std::fs::read(d.join(KS_FILENAME)).ok()?;
        let content = read_pfx(&pfx, KS_PASSWORD).ok()?;
        let ca_der = std::fs::read(d.join(CA_CERT_FILENAME))
            .ok()
            .and_then(|x| parse_cert_file(&x).ok())
            .or_else(|| content.chain.last().filter(|_| content.chain.len() > 1).cloned())?;
        Some(LocalCerts {
            dir: d.to_path_buf(),
            ca_der,
            ssl_der: content.ssl_der,
        })
    };
    let dirs = search_dirs(ctx);
    dirs.iter()
        .filter(|d| inspect(d).usable())
        .find_map(|d| load(d))
        .or_else(|| dirs.iter().find_map(|d| load(d)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genera_como_java_con_mejoras() {
        let pack = generate(&CertProfile::default()).unwrap();
        let ca = cert_info(&pack.ca_der).unwrap();
        let ssl = cert_info(&pack.ssl_der).unwrap();
        assert_eq!(ca.subject, "CN=Autofirma ROOT");
        assert_eq!(ca.issuer, "CN=Autofirma ROOT");
        assert!(ca.is_ca);
        assert_eq!(ssl.subject, "CN=127.0.0.1");
        assert_eq!(ssl.issuer, "CN=Autofirma ROOT");
        assert!(!ssl.is_ca);
        assert!(ssl.server_auth);
        assert_eq!(ssl.san_dns, vec!["localhost".to_string()]);
        assert_eq!(ssl.san_ip, vec!["127.0.0.1".to_string(), "::1".to_string()]);
        assert!(verifies(&pack.ssl_der, &pack.ca_der));
        let days = (ssl.not_after - ssl.not_before) / 86_400;
        assert_eq!(days, VALIDITY_DAYS + 1);
        // Serie positiva.
        let (_, c) = X509Certificate::from_der(&pack.ssl_der).unwrap();
        assert!(c.raw_serial()[0] & 0x80 == 0 && c.raw_serial().len() >= 16);
        // PKCS#12: alias, contraseña y cadena.
        let p = read_pfx(&pack.pfx, KS_PASSWORD).unwrap();
        assert_eq!(p.alias, CERT_ALIAS);
        assert_eq!(p.chain, vec![pack.ssl_der.clone(), pack.ca_der.clone()]);
        assert!(read_pfx(&pack.pfx, "otra").is_err());
    }

    #[test]
    fn ensure_reutiliza_recupera_y_regenera() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        let dir = t.path().join("certs");
        let a = ensure(&ctx, &dir, Regenerate::IfInvalid, None, &CertProfile::default()).unwrap();
        assert!(a.generated);
        assert!(inspect(&dir).usable());
        let b = ensure(&ctx, &dir, Regenerate::IfInvalid, None, &CertProfile::default()).unwrap();
        assert!(!b.generated);
        assert_eq!(a.certs.ca_der, b.certs.ca_der);
        std::fs::remove_file(dir.join(CA_CERT_FILENAME)).unwrap();
        let c = ensure(&ctx, &dir, Regenerate::IfInvalid, None, &CertProfile::default()).unwrap();
        assert!(!c.generated, "se recupera la CA de la cadena");
        assert_eq!(std::fs::read(dir.join(CA_CERT_FILENAME)).unwrap(), a.certs.ca_der);
        // Caducado → se regenera.
        let short = generate(&CertProfile {
            validity_days: 10,
            ..Default::default()
        })
        .unwrap();
        std::fs::write(dir.join(KS_FILENAME), &short.pfx).unwrap();
        std::fs::write(dir.join(CA_CERT_FILENAME), &short.ca_der).unwrap();
        assert!(inspect(&dir).needs_renewal());
        let d = ensure(&ctx, &dir, Regenerate::IfInvalid, None, &CertProfile::default()).unwrap();
        assert!(d.generated);
        assert!(
            !ensure(&ctx, &dir, Regenerate::IfMissing, None, &CertProfile::default())
                .unwrap()
                .generated
        );
    }

    #[test]
    fn pem_ida_y_vuelta() {
        let pack = generate(&CertProfile::default()).unwrap();
        let pem = der_to_pem(&pack.ca_der);
        assert_eq!(parse_cert_file(pem.as_bytes()).unwrap(), pack.ca_der);
    }
}
