//! Almacén de confianza personal de AutoFirma
//! (`~/.afirma/TrustedCertsKeystore.jks`, `TrustStoreManager`, especificación
//! `docs/spec/06-app-ui-cli-installer.md` §4.14).
//!
//! - [`JksKeyStore`]: lectura y escritura del formato JKS de Sun
//!   (`sun.security.provider.JavaKeyStore`): número mágico `0xFEEDFEED`,
//!   versiones 1 y 2, entradas `trustedCertEntry` y `PrivateKeyEntry` (estas
//!   se conservan tal cual pero no se usan), alias en minúsculas, fechas en
//!   milisegundos y huella SHA-1 de integridad con la contraseña en UTF-16BE
//!   y la sal `"Mighty Aphrodite"`. Lo que se escribe es idéntico a lo que
//!   escribe Java (versión 2) y lo lee `keytool`.
//! - [`TrustStore`]: gestión del almacén con las reglas de
//!   `TrustStoreManager` (alias = `X500Principal.toString()` del titular, con
//!   `" (1)"`, `" (2)"`... si ya existe; se omiten los certificados repetidos).
//! - [`load_trusted_certs`]: certificados para
//!   `afirma_core::http::HttpSettings::extra_trusted_certs`.
//! - [`parse_certificate_file`] y [`fetch_server_chain`]: importación desde
//!   ficheros `.cer/.cert/.crt` y desde la cadena de un servidor HTTPS.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha1::{Digest, Sha1};

/// Número mágico de JKS.
pub const JKS_MAGIC: u32 = 0xFEED_FEED;
/// Versión de JKS que escribe Java (con el tipo de certificado).
pub const JKS_VERSION_2: u32 = 2;
/// Versión antigua de JKS (sin el tipo de certificado).
pub const JKS_VERSION_1: u32 = 1;
const TAG_PRIVATE_KEY: u32 = 1;
const TAG_TRUSTED_CERT: u32 = 2;
/// Sal de la huella de integridad (`"Mighty Aphrodite".getBytes("UTF8")`).
const INTEGRITY_SALT: &[u8] = b"Mighty Aphrodite";
/// Tipo de certificado que escribe Java.
const X509: &str = "X.509";

/// Contraseña del almacén de confianza de AutoFirma.
pub const TRUSTSTORE_PASSWORD: &str = afirma_core::constants::TRUSTSTORE_PASSWORD;

/// `AutofirmaTrustStore.0`: el almacén existe pero no se puede cargar (se
/// pregunta si se quiere borrar y crear de nuevo).
pub const LOAD_ERROR_MESSAGE: &str =
    "No se ha podido cargar el almacén de claves de Autofirma. Es posible que esté corrupto. ¿Desea crearlo de nuevo?";
/// `AutofirmaTrustStore.1`: título de ese diálogo.
pub const LOAD_ERROR_TITLE: &str = "Carga del almacén de confianza";

/// Error del almacén JKS.
#[derive(Debug, thiserror::Error)]
pub enum JksError {
    /// El fichero no es un JKS válido.
    #[error("El almacén de confianza no tiene un formato válido: {0}")]
    Format(String),
    /// La huella de integridad no coincide
    /// (`Keystore was tampered with, or password was incorrect`).
    #[error("El almacén de confianza ha sido manipulado o la contraseña es incorrecta")]
    Integrity,
    /// Error de lectura o escritura del fichero.
    #[error("Error de acceso al almacén de confianza {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Certificado que no se puede analizar.
    #[error("El certificado no es válido: {0}")]
    InvalidCertificate(String),
    /// Dato que no se puede representar en JKS (alias demasiado largo...).
    #[error("{0}")]
    Unsupported(String),
}

/// Contenido de una entrada JKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JksEntryKind {
    /// `trustedCertEntry`: un certificado de confianza.
    TrustedCert {
        /// Tipo de certificado (`X.509`; vacío en la versión 1).
        cert_type: String,
        /// Certificado (DER).
        der: Vec<u8>,
    },
    /// `PrivateKeyEntry`: clave privada protegida (formato propietario de
    /// Sun, que no se descifra) y su cadena (tipo, DER).
    PrivateKey {
        protected_key: Vec<u8>,
        chain: Vec<(String, Vec<u8>)>,
    },
}

/// Entrada de un almacén JKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JksEntry {
    /// Alias (en minúsculas, como lo guarda Java).
    pub alias: String,
    /// Fecha de creación en milisegundos desde 1970 (`Date.getTime()`).
    pub timestamp_millis: i64,
    pub kind: JksEntryKind,
}

/// Almacén JKS en memoria (entradas en el orden del fichero).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JksKeyStore {
    pub entries: Vec<JksEntry>,
}

/// `String.toLowerCase(Locale.ENGLISH)` (`JavaKeyStore.convertAlias`).
pub fn java_alias(alias: &str) -> String {
    alias.to_lowercase()
}

/// Bytes de la contraseña para la huella: cada `char` de Java como dos bytes
/// (UTF-16BE).
fn password_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(|c| c.to_be_bytes()).collect()
}

/// `DataOutput.writeUTF`: UTF-8 modificado (U+0000 en dos bytes, caracteres
/// suplementarios como pares sustitutos de tres bytes cada uno) con la
/// longitud en 16 bits delante.
fn write_utf(out: &mut Vec<u8>, s: &str) -> Result<(), JksError> {
    let mut bytes = Vec::with_capacity(s.len());
    for c in s.encode_utf16() {
        match c {
            0x0001..=0x007f => bytes.push(c as u8),
            0x0080..=0x07ff | 0 => {
                bytes.push(0xc0 | ((c >> 6) & 0x1f) as u8);
                bytes.push(0x80 | (c & 0x3f) as u8);
            }
            _ => {
                bytes.push(0xe0 | ((c >> 12) & 0x0f) as u8);
                bytes.push(0x80 | ((c >> 6) & 0x3f) as u8);
                bytes.push(0x80 | (c & 0x3f) as u8);
            }
        }
    }
    let len = u16::try_from(bytes.len())
        .map_err(|_| JksError::Unsupported(format!("Texto demasiado largo para JKS ({} bytes)", bytes.len())))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes);
    Ok(())
}

/// Lector secuencial con los errores de JKS.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], JksError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| {
                JksError::Format(format!(
                    "datos truncados (se esperaban {n} bytes en la posición {})",
                    self.pos
                ))
            })?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32, JksError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i64(&mut self) -> Result<i64, JksError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }

    /// Bloque con longitud `int` delante (certificados y clave protegida).
    fn block(&mut self) -> Result<Vec<u8>, JksError> {
        let len = self.u32()?;
        let len = usize::try_from(i32::try_from(len).map_err(|_| JksError::Format("longitud negativa".into()))?)
            .map_err(|_| JksError::Format("longitud no válida".into()))?;
        Ok(self.take(len)?.to_vec())
    }

    /// `DataInput.readUTF`.
    fn utf(&mut self) -> Result<String, JksError> {
        let b = self.take(2)?;
        let len = usize::from(u16::from_be_bytes([b[0], b[1]]));
        let bytes = self.take(len)?;
        let bad = || JksError::Format("texto UTF-8 modificado no válido".into());
        let mut units: Vec<u16> = Vec::with_capacity(len);
        let mut i = 0;
        while i < bytes.len() {
            let b0 = bytes[i];
            if b0 & 0x80 == 0 {
                units.push(u16::from(b0));
                i += 1;
            } else if b0 & 0xe0 == 0xc0 {
                let b1 = *bytes.get(i + 1).ok_or_else(bad)?;
                if b1 & 0xc0 != 0x80 {
                    return Err(bad());
                }
                units.push((u16::from(b0 & 0x1f) << 6) | u16::from(b1 & 0x3f));
                i += 2;
            } else if b0 & 0xf0 == 0xe0 {
                let (b1, b2) = (*bytes.get(i + 1).ok_or_else(bad)?, *bytes.get(i + 2).ok_or_else(bad)?);
                if b1 & 0xc0 != 0x80 || b2 & 0xc0 != 0x80 {
                    return Err(bad());
                }
                units.push((u16::from(b0 & 0x0f) << 12) | (u16::from(b1 & 0x3f) << 6) | u16::from(b2 & 0x3f));
                i += 3;
            } else {
                return Err(bad());
            }
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

impl JksKeyStore {
    /// Almacén vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lee un almacén JKS. Con `password` se comprueba la huella de
    /// integridad (como `KeyStore.load(is, password)`); con `None` no (como
    /// `KeyStore.load(is, null)`). Como Java, los alias se pasan a
    /// minúsculas y un alias repetido sustituye al anterior.
    pub fn parse(data: &[u8], password: Option<&str>) -> Result<Self, JksError> {
        let mut r = Reader { data, pos: 0 };
        let magic = r.u32()?;
        if magic != JKS_MAGIC {
            return Err(JksError::Format(format!("número mágico incorrecto ({magic:#010x})")));
        }
        let version = r.u32()?;
        if version != JKS_VERSION_1 && version != JKS_VERSION_2 {
            return Err(JksError::Format(format!("versión no soportada ({version})")));
        }
        let count = r.u32()?;
        let mut store = JksKeyStore::new();
        for _ in 0..count {
            let tag = r.u32()?;
            let alias = java_alias(&r.utf()?);
            let timestamp_millis = r.i64()?;
            let kind = match tag {
                TAG_PRIVATE_KEY => {
                    let protected_key = r.block()?;
                    let n = r.u32()?;
                    let mut chain = Vec::new();
                    for _ in 0..n {
                        let cert_type = if version == JKS_VERSION_2 {
                            r.utf()?
                        } else {
                            String::new()
                        };
                        chain.push((cert_type, r.block()?));
                    }
                    JksEntryKind::PrivateKey { protected_key, chain }
                }
                TAG_TRUSTED_CERT => {
                    let cert_type = if version == JKS_VERSION_2 {
                        r.utf()?
                    } else {
                        String::new()
                    };
                    JksEntryKind::TrustedCert {
                        cert_type,
                        der: r.block()?,
                    }
                }
                other => return Err(JksError::Format(format!("tipo de entrada desconocido ({other})"))),
            };
            store.entries.retain(|e| e.alias != alias);
            store.entries.push(JksEntry {
                alias,
                timestamp_millis,
                kind,
            });
        }
        if let Some(pw) = password {
            let end = r.pos;
            let stored = r.take(20)?;
            if integrity_digest(pw, &data[..end]).as_slice() != stored {
                return Err(JksError::Integrity);
            }
        }
        Ok(store)
    }

    /// Codificación JKS versión 2 (la que escribe Java).
    pub fn to_bytes(&self, password: &str) -> Result<Vec<u8>, JksError> {
        self.to_bytes_with_version(password, JKS_VERSION_2)
    }

    /// Codificación JKS en la versión indicada (1 o 2). En la versión 2 se
    /// escribe `X.509` como tipo de los certificados que no lo tengan.
    pub fn to_bytes_with_version(&self, password: &str, version: u32) -> Result<Vec<u8>, JksError> {
        if version != JKS_VERSION_1 && version != JKS_VERSION_2 {
            return Err(JksError::Unsupported(format!("Versión de JKS no soportada: {version}")));
        }
        let len32 = |n: usize| {
            i32::try_from(n)
                .map(|v| (v as u32).to_be_bytes())
                .map_err(|_| JksError::Unsupported("Entrada demasiado grande para JKS".into()))
        };
        let cert_type = |t: &str| if t.is_empty() { X509.to_string() } else { t.to_string() };
        let mut out = Vec::new();
        out.extend_from_slice(&JKS_MAGIC.to_be_bytes());
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&len32(self.entries.len())?);
        for e in &self.entries {
            match &e.kind {
                JksEntryKind::PrivateKey { protected_key, chain } => {
                    out.extend_from_slice(&TAG_PRIVATE_KEY.to_be_bytes());
                    write_utf(&mut out, &e.alias)?;
                    out.extend_from_slice(&e.timestamp_millis.to_be_bytes());
                    out.extend_from_slice(&len32(protected_key.len())?);
                    out.extend_from_slice(protected_key);
                    out.extend_from_slice(&len32(chain.len())?);
                    for (t, der) in chain {
                        if version == JKS_VERSION_2 {
                            write_utf(&mut out, &cert_type(t))?;
                        }
                        out.extend_from_slice(&len32(der.len())?);
                        out.extend_from_slice(der);
                    }
                }
                JksEntryKind::TrustedCert { cert_type: t, der } => {
                    out.extend_from_slice(&TAG_TRUSTED_CERT.to_be_bytes());
                    write_utf(&mut out, &e.alias)?;
                    out.extend_from_slice(&e.timestamp_millis.to_be_bytes());
                    if version == JKS_VERSION_2 {
                        write_utf(&mut out, &cert_type(t))?;
                    }
                    out.extend_from_slice(&len32(der.len())?);
                    out.extend_from_slice(der);
                }
            }
        }
        let digest = integrity_digest(password, &out);
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// Indica si existe el alias (sin distinguir mayúsculas, como JKS).
    pub fn contains_alias(&self, alias: &str) -> bool {
        let a = java_alias(alias);
        self.entries.iter().any(|e| e.alias == a)
    }

    /// `setCertificateEntry`: añade o sustituye una entrada de certificado
    /// de confianza (Java no permite sustituir una entrada de clave).
    pub fn set_certificate_entry(&mut self, alias: &str, der: &[u8], timestamp_millis: i64) -> Result<(), JksError> {
        let alias = java_alias(alias);
        if self
            .entries
            .iter()
            .any(|e| e.alias == alias && matches!(e.kind, JksEntryKind::PrivateKey { .. }))
        {
            return Err(JksError::Unsupported(format!(
                "No se puede sustituir la entrada de clave '{alias}'"
            )));
        }
        let entry = JksEntry {
            alias: alias.clone(),
            timestamp_millis,
            kind: JksEntryKind::TrustedCert {
                cert_type: X509.into(),
                der: der.to_vec(),
            },
        };
        match self.entries.iter_mut().find(|e| e.alias == alias) {
            Some(e) => *e = entry,
            None => self.entries.push(entry),
        }
        Ok(())
    }

    /// `deleteEntry`.
    pub fn delete_entry(&mut self, alias: &str) -> bool {
        let a = java_alias(alias);
        let before = self.entries.len();
        self.entries.retain(|e| e.alias != a);
        self.entries.len() != before
    }
}

/// SHA-1 de contraseña (UTF-16BE) + `"Mighty Aphrodite"` + datos.
fn integrity_digest(password: &str, data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(password_bytes(password));
    h.update(INTEGRITY_SALT);
    h.update(data);
    h.finalize().into()
}

/// Certificado de confianza del almacén.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCert {
    /// Alias (en minúsculas).
    pub alias: String,
    /// Certificado (DER).
    pub der: Vec<u8>,
}

/// Ruta del almacén de confianza (`~/.afirma/TrustedCertsKeystore.jks`).
pub fn default_path() -> PathBuf {
    afirma_core::platform::afirma_dir().join(afirma_core::constants::TRUSTSTORE_FILENAME)
}

/// Milisegundos actuales desde 1970 (`new Date().getTime()`).
fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// `X500Principal.toString()` del titular de un certificado.
fn subject_principal(der: &[u8]) -> Result<String, JksError> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| JksError::InvalidCertificate(e.to_string()))?;
    let dn = crate::dn::DistinguishedName::from_der(cert.subject().as_raw())
        .ok_or_else(|| JksError::InvalidCertificate("nombre del titular no válido".into()))?;
    Ok(dn.java_string())
}

/// Almacén de confianza personal (`TrustStoreManager`). Los cambios se
/// guardan con [`TrustStore::save`].
#[derive(Debug, Clone)]
pub struct TrustStore {
    path: PathBuf,
    password: String,
    store: JksKeyStore,
}

impl TrustStore {
    /// Abre el almacén o, si el fichero no existe, crea uno vacío en memoria
    /// (no se escribe hasta [`TrustStore::save`]). Si existe pero no se puede
    /// cargar devuelve el error: AutoFirma pregunta entonces
    /// [`LOAD_ERROR_MESSAGE`] y, si el usuario acepta, se recrea con
    /// [`TrustStore::recreate`].
    pub fn open_or_create(path: impl Into<PathBuf>, password: &str) -> Result<TrustStore, JksError> {
        let path = path.into();
        let store = match std::fs::read(&path) {
            Ok(data) => parse_store(&data, password)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => JksKeyStore::new(),
            Err(source) => return Err(JksError::Io { path, source }),
        };
        Ok(TrustStore {
            path,
            password: password.to_string(),
            store,
        })
    }

    /// Abre el almacén de AutoFirma ([`default_path`], contraseña
    /// `changeit`).
    pub fn open_default() -> Result<TrustStore, JksError> {
        Self::open_or_create(default_path(), TRUSTSTORE_PASSWORD)
    }

    /// Borra el fichero (si existe) y devuelve un almacén vacío: la opción
    /// "crearlo de nuevo" del diálogo [`LOAD_ERROR_MESSAGE`].
    pub fn recreate(path: impl Into<PathBuf>, password: &str) -> Result<TrustStore, JksError> {
        let path = path.into();
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(JksError::Io { path, source }),
        }
        Ok(TrustStore {
            path,
            password: password.to_string(),
            store: JksKeyStore::new(),
        })
    }

    /// Ruta del fichero.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Almacén JKS subyacente.
    pub fn keystore(&self) -> &JksKeyStore {
        &self.store
    }

    /// Certificados de confianza, en el orden del almacén. Las entradas de
    /// clave privada se ignoran (se conservan al guardar).
    pub fn certificates(&self) -> Vec<TrustedCert> {
        self.store
            .entries
            .iter()
            .filter_map(|e| match &e.kind {
                JksEntryKind::TrustedCert { der, .. } => Some(TrustedCert {
                    alias: e.alias.clone(),
                    der: der.clone(),
                }),
                JksEntryKind::PrivateKey { .. } => None,
            })
            .collect()
    }

    /// Alias del certificado si ya está en el almacén (`searchCert`:
    /// mismo DER).
    pub fn find(&self, der: &[u8]) -> Option<String> {
        self.certificates().into_iter().find(|c| c.der == der).map(|c| c.alias)
    }

    /// Indica si el certificado ya está en el almacén (`containsCert`).
    pub fn contains(&self, der: &[u8]) -> bool {
        self.find(der).is_some()
    }

    /// Alias que asignaría Java (`generateAlias`): el titular como
    /// `X500Principal.toString()` y, si ya existe, `"<titular> (1)"`,
    /// `"<titular> (2)"`... (comparando sin distinguir mayúsculas). Se
    /// devuelve en minúsculas, como lo guarda JKS.
    pub fn generate_alias(&self, der: &[u8]) -> Result<String, JksError> {
        let principal = subject_principal(der)?;
        let mut alias = principal.clone();
        let mut i = 1u32;
        while self.store.contains_alias(&alias) {
            alias = format!("{principal} ({i})");
            i += 1;
        }
        Ok(java_alias(&alias))
    }

    /// Añade un certificado (DER) con la regla de alias de Java. Devuelve
    /// `false` si ya estaba (mismo DER).
    pub fn add(&mut self, der: &[u8]) -> Result<bool, JksError> {
        if self.contains(der) {
            return Ok(false);
        }
        let alias = self.generate_alias(der)?;
        self.store.set_certificate_entry(&alias, der, now_millis())?;
        Ok(true)
    }

    /// `importCerts`: añade los certificados y guarda el almacén. Devuelve
    /// cuántos se han añadido.
    pub fn import(&mut self, certs: &[Vec<u8>]) -> Result<usize, JksError> {
        let mut added = 0;
        for c in certs {
            if self.add(c)? {
                added += 1;
            }
        }
        self.save()?;
        Ok(added)
    }

    /// Elimina la entrada con ese alias (sin distinguir mayúsculas).
    pub fn remove(&mut self, alias: &str) -> bool {
        self.store.delete_entry(alias)
    }

    /// Elimina el certificado (`deleteCert`, por DER).
    pub fn remove_certificate(&mut self, der: &[u8]) -> bool {
        match self.find(der) {
            Some(alias) => self.store.delete_entry(&alias),
            None => false,
        }
    }

    /// Guarda el almacén (JKS versión 2) de forma atómica: se escribe un
    /// fichero temporal en el mismo directorio y se renombra. Crea el
    /// directorio si no existe.
    pub fn save(&self) -> Result<(), JksError> {
        let io = |path: &Path, source| JksError::Io {
            path: path.to_path_buf(),
            source,
        };
        let data = self.store.to_bytes(&self.password)?;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        let file_name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
            Ok(())
        };
        if let Err(e) = write() {
            let _ = std::fs::remove_file(&tmp);
            return Err(io(&tmp, e));
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io(&self.path, e)
        })
    }
}

/// Lee el almacén: JKS o, como el tipo `JKS` de Java 9+ (formato dual),
/// PKCS#12 (solo los certificados; se guardará como JKS).
fn parse_store(data: &[u8], password: &str) -> Result<JksKeyStore, JksError> {
    if data.first() == Some(&0x30) {
        let archive = p12_keystore::Pkcs12Archive::from_pkcs12(data, password)
            .map_err(|e| JksError::Format(format!("PKCS#12 no válido: {e}")))?;
        let mut store = JksKeyStore::new();
        for (i, bag) in archive.certs.iter().enumerate() {
            let alias = bag.friendly_name.clone().unwrap_or_else(|| format!("cert{i}"));
            if !store.contains_alias(&alias) {
                store.set_certificate_entry(&alias, bag.cert.as_der(), now_millis())?;
            }
        }
        return Ok(store);
    }
    JksKeyStore::parse(data, Some(password))
}

/// Certificados de confianza del almacén de AutoFirma para
/// `afirma_core::http::HttpSettings::extra_trusted_certs`. Vacío si el
/// almacén no existe o no se puede leer.
pub fn load_trusted_certs() -> Vec<Vec<u8>> {
    load_trusted_certs_from(&default_path(), TRUSTSTORE_PASSWORD)
}

/// Como [`load_trusted_certs`] con otra ruta y contraseña.
pub fn load_trusted_certs_from(path: &Path, password: &str) -> Vec<Vec<u8>> {
    match std::fs::read(path) {
        Ok(data) => match parse_store(&data, password) {
            Ok(store) => store
                .entries
                .into_iter()
                .filter_map(|e| match e.kind {
                    JksEntryKind::TrustedCert { der, .. } => Some(der),
                    JksEntryKind::PrivateKey { .. } => None,
                })
                .collect(),
            Err(e) => {
                tracing::warn!("No se ha podido cargar el almacen de confianza {}: {e}", path.display());
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Certificados de un fichero `.cer/.cert/.crt`: DER o PEM (uno o varios
/// bloques `CERTIFICATE`, o Base64 sin cabeceras). Error si no contiene
/// ninguno.
pub fn parse_certificate_file(data: &[u8]) -> Result<Vec<Vec<u8>>, JksError> {
    use x509_parser::prelude::*;
    let valid = |d: &[u8]| X509Certificate::from_der(d).is_ok_and(|(rest, _)| rest.is_empty());
    if valid(data) {
        return Ok(vec![data.to_vec()]);
    }
    let text = std::str::from_utf8(data)
        .map_err(|_| JksError::InvalidCertificate("el fichero no es un certificado DER ni PEM".into()))?;
    let mut certs = Vec::new();
    let mut block: Option<String> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with("-----BEGIN") {
            block = line.contains("CERTIFICATE").then(String::new);
        } else if line.starts_with("-----END") {
            if let Some(b64) = block.take() {
                let der = afirma_core::base64_decode_lenient(&b64)
                    .map_err(|e| JksError::InvalidCertificate(format!("Base64 no válido: {e}")))?;
                if !valid(&der) {
                    return Err(JksError::InvalidCertificate(
                        "bloque PEM que no es un certificado".into(),
                    ));
                }
                certs.push(der);
            }
        } else if let Some(b) = block.as_mut()
            && !line.contains(':')
        {
            b.push_str(line);
        }
    }
    if certs.is_empty()
        && let Some(der) = afirma_core::cert::decode_certificate(data)
    {
        certs.push(der);
    }
    if certs.is_empty() {
        return Err(JksError::InvalidCertificate(
            "el fichero no contiene certificados".into(),
        ));
    }
    Ok(certs)
}

/// URL `https://` del texto del campo "URL" (`buildUrl`): se fuerza
/// `https://` sustituyendo cualquier otro esquema.
pub fn import_url(domain: &str) -> String {
    const SEP: &str = "://";
    let domain = domain.trim();
    if domain.to_ascii_lowercase().starts_with("https://") {
        domain.to_string()
    } else if let Some(i) = domain.find(SEP) {
        format!("https://{}", &domain[i + SEP.len()..])
    } else {
        format!("https://{domain}")
    }
}

/// Certificados que se propondrán para importar desde un servidor
/// (`downloadServerCerts`): se descarga la cadena que presenta (sin
/// validarla, a través del proxy indicado) y se devuelven los emisores si
/// hay más de un certificado o el único certificado si no.
pub fn fetch_server_chain(
    url: &str,
    proxy: &afirma_core::http::ProxyMode,
    timeout: Option<Duration>,
) -> Result<Vec<Vec<u8>>, String> {
    let chain = afirma_core::http::fetch_server_certificates(&import_url(url), proxy, timeout)?;
    Ok(afirma_core::http::certs_to_import(&chain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(cn: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CountryName, "ES");
        dn.push(rcgen::DnType::OrganizationName, "AutoFirma Pruebas");
        dn.push(rcgen::DnType::CommonName, cn);
        params.distinguished_name = dn;
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn modified_utf8() {
        for s in ["", "abc", "Ñandú (1)", "a\u{0}b", "😀 emoji", "日本"] {
            let mut out = Vec::new();
            write_utf(&mut out, s).unwrap();
            let mut r = Reader { data: &out, pos: 0 };
            assert_eq!(r.utf().unwrap(), s);
            assert_eq!(r.pos, out.len());
        }
        let mut out = Vec::new();
        write_utf(&mut out, "a\u{0}😀").unwrap();
        // U+0000 en dos bytes y el emoji como dos sustitutos de tres bytes.
        assert_eq!(out, [0, 9, b'a', 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
        assert!(write_utf(&mut Vec::new(), &"x".repeat(70_000)).is_err());
    }

    #[test]
    fn round_trip_and_integrity() {
        let mut ks = JksKeyStore::new();
        ks.set_certificate_entry("Mi CA", &cert("Mi CA"), 1_700_000_000_123)
            .unwrap();
        ks.entries.push(JksEntry {
            alias: "clave".into(),
            timestamp_millis: 42,
            kind: JksEntryKind::PrivateKey {
                protected_key: vec![1, 2, 3],
                chain: vec![("X.509".into(), cert("hoja"))],
            },
        });
        for v in [JKS_VERSION_1, JKS_VERSION_2] {
            let data = ks.to_bytes_with_version("changeit", v).unwrap();
            assert_eq!(&data[..8], [0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, v as u8]);
            let back = JksKeyStore::parse(&data, Some("changeit")).unwrap();
            assert_eq!(back.entries.len(), 2);
            assert_eq!(back.entries[0].alias, "mi ca");
            assert_eq!(back.entries[0].timestamp_millis, 1_700_000_000_123);
            if v == JKS_VERSION_2 {
                assert_eq!(back, ks);
            }
            assert!(matches!(
                JksKeyStore::parse(&data, Some("otra")),
                Err(JksError::Integrity)
            ));
            assert!(JksKeyStore::parse(&data, None).is_ok());
            let mut tampered = data.clone();
            tampered[30] ^= 1;
            assert!(JksKeyStore::parse(&tampered, Some("changeit")).is_err());
            assert!(JksKeyStore::parse(&data[..data.len() - 5], Some("changeit")).is_err());
        }
        assert!(JksKeyStore::parse(b"\xca\xfe\xba\xbe", None).is_err());
        assert!(ks.set_certificate_entry("CLAVE", &cert("x"), 0).is_err());
    }

    #[test]
    fn trust_store_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("TrustedCertsKeystore.jks");
        let mut ts = TrustStore::open_or_create(&path, "changeit").unwrap();
        assert!(ts.certificates().is_empty());
        let a = cert("Raíz Ñ");
        let a2 = cert("Raíz Ñ"); // mismo titular, otro certificado
        let a3 = cert("RAÍZ Ñ"); // alias igual sin distinguir mayúsculas
        let b = cert("Otra");
        assert!(ts.add(&a).unwrap());
        assert!(!ts.add(&a).unwrap());
        assert!(ts.add(&a2).unwrap());
        assert!(ts.add(&a3).unwrap());
        assert!(ts.add(&b).unwrap());
        let aliases: Vec<String> = ts.certificates().into_iter().map(|c| c.alias).collect();
        assert_eq!(
            aliases,
            [
                "cn=raíz ñ, o=autofirma pruebas, c=es",
                "cn=raíz ñ, o=autofirma pruebas, c=es (1)",
                "cn=raíz ñ, o=autofirma pruebas, c=es (2)",
                "cn=otra, o=autofirma pruebas, c=es"
            ]
        );
        ts.save().unwrap();
        let ts2 = TrustStore::open_or_create(&path, "changeit").unwrap();
        assert_eq!(ts2.certificates(), ts.certificates());
        assert_eq!(
            load_trusted_certs_from(&path, "changeit"),
            vec![a.clone(), a2.clone(), a3, b.clone()]
        );
        assert!(load_trusted_certs_from(&path, "mala").is_empty());
        assert!(load_trusted_certs_from(&dir.path().join("no"), "changeit").is_empty());

        let mut ts = ts2;
        assert!(ts.remove("CN=Raíz Ñ, O=AutoFirma Pruebas, C=ES (1)"));
        assert!(!ts.remove("no existe"));
        assert!(ts.remove_certificate(&b));
        assert!(!ts.remove_certificate(&b));
        // El alias libre se reutiliza.
        assert!(ts.add(&a2).unwrap());
        assert_eq!(ts.find(&a2).unwrap(), "cn=raíz ñ, o=autofirma pruebas, c=es (1)");
        assert_eq!(ts.import(&[b.clone(), a.clone()]).unwrap(), 1);
        assert_eq!(
            TrustStore::open_or_create(&path, "changeit")
                .unwrap()
                .certificates()
                .len(),
            4
        );
        // Sin restos del fichero temporal.
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);

        // Almacén dañado: error al abrir y se puede recrear.
        std::fs::write(&path, b"basura").unwrap();
        assert!(TrustStore::open_or_create(&path, "changeit").is_err());
        let ts = TrustStore::recreate(&path, "changeit").unwrap();
        assert!(ts.certificates().is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn certificate_files() {
        let (a, b) = (cert("A"), cert("B"));
        assert_eq!(parse_certificate_file(&a).unwrap(), vec![a.clone()]);
        let pem = |d: &[u8]| {
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                afirma_core::base64::encode(d)
            )
        };
        let both = format!("Emisor: x\n{}texto\n{}", pem(&a), pem(&b));
        assert_eq!(parse_certificate_file(both.as_bytes()).unwrap(), vec![a.clone(), b]);
        assert_eq!(
            parse_certificate_file(afirma_core::base64::encode(&a).as_bytes()).unwrap(),
            vec![a]
        );
        assert!(parse_certificate_file(b"nada").is_err());
        assert!(parse_certificate_file(b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----").is_err());
    }

    #[test]
    fn import_urls() {
        assert_eq!(import_url("sede.example.es"), "https://sede.example.es");
        assert_eq!(import_url("http://sede.example.es/x"), "https://sede.example.es/x");
        assert_eq!(import_url("HTTPS://Sede.example.es"), "HTTPS://Sede.example.es");
        assert_eq!(import_url("ftp://h:21"), "https://h:21");
    }

    #[test]
    fn default_location() {
        assert_eq!(default_path(), afirma_core::platform::trusted_certs_keystore_path());
    }
}
