//! Almacén de certificados de Windows (CryptoAPI / CNG).
//!
//! Equivale a `CAPIKeyStoreManager` de Java (proveedor SunMSCAPI,
//! `Windows-MY`) y a los obsoletos `WINADDRESSBOOK`/`WINCA`:
//!
//! - Se abre el almacén de sistema del usuario actual en modo lectura
//!   (`CertOpenStore(CERT_STORE_PROV_SYSTEM_W, …, CERT_SYSTEM_STORE_CURRENT_USER
//!   | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, "MY")`).
//! - Alias: nombre descriptivo (`CertGetNameStringW(CERT_NAME_FRIENDLY_DISPLAY_TYPE)`,
//!   que devuelve la propiedad `CERT_FRIENDLY_NAME_PROP_ID` si existe y, si
//!   no, el nombre del titular), con sufijos ` (1)`, ` (2)`… para los
//!   repetidos (regla de SunMSCAPI en Java 11+).
//! - Una entrada tiene clave si `CryptAcquireCertificatePrivateKey` en modo
//!   silencioso tiene éxito o devuelve `NTE_SILENT_CONTEXT` (la clave existe
//!   pero necesita interfaz, p. ej. una tarjeta).
//! - Al firmar se adquiere la clave **sin** modo silencioso (el KSP/CSP
//!   muestra su diálogo de PIN), preferentemente como clave CNG:
//!   `NCryptSignHash` con relleno PKCS#1 (RSA) o en bruto `r‖s` (ECDSA, que
//!   se convierte a DER). Las claves de CSP antiguos (tarjetas con CSP
//!   propio) se firman con `CryptCreateHash`, `CryptSetHashParam(HP_HASHVAL)`
//!   y `CryptSignHash`, invirtiendo el resultado (CryptoAPI es
//!   little-endian); si el CSP no soporta SHA-2 se reabre el mismo
//!   contenedor con el proveedor `PROV_RSA_AES`, como hace SunMSCAPI.
//!
//! Todo el código `unsafe` se limita a las llamadas a la API de Windows, con
//! envoltorios RAII para cada manejador.

use std::ffi::c_void;
use std::sync::Mutex;

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::key::{KeyError, SigningKey};
use windows::Win32::Foundation::{
    ERROR_CANCELLED, ERROR_FILE_NOT_FOUND, NTE_BUFFER_TOO_SMALL, NTE_NO_KEY, NTE_SILENT_CONTEXT, NTE_USER_CANCELLED,
    SCARD_E_NO_SMARTCARD, SCARD_W_CANCELLED_BY_USER, SCARD_W_CHV_BLOCKED, SCARD_W_REMOVED_CARD, SCARD_W_WRONG_CHV,
};
use windows::Win32::Security::Cryptography::{
    ALG_ID, AT_KEYEXCHANGE, AT_SIGNATURE, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
    BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA512_ALGORITHM, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, CALG_SHA1,
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_PARA,
    CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_SPEC, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NCRYPT_KEY_SPEC,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W,
    CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_FLAGS,
    CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_SILENT_FLAG, CRYPT_IMPL_HARDWARE, CRYPT_IMPL_REMOVABLE,
    CRYPT_KEY_PROV_INFO, CertCloseStore, CertDuplicateCertificateContext, CertEnumCertificatesInStore,
    CertFreeCertificateChain, CertFreeCertificateContext, CertGetCertificateChain, CertGetCertificateContextProperty,
    CertGetNameStringW, CertOpenStore, CryptAcquireCertificatePrivateKey, CryptAcquireContextA, CryptCreateHash,
    CryptDestroyHash, CryptGetProvParam, CryptReleaseContext, CryptSetHashParam, CryptSignHashW, HCERTSTORE,
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, HP_HASHVAL, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG,
    NCRYPT_IMPL_REMOVABLE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_PAD_PKCS1_FLAG, NCryptFreeObject,
    NCryptGetProperty, NCryptSignHash, PP_CONTAINER, PP_IMPTYPE, PROV_RSA_AES,
};
use windows::core::{BOOL, HRESULT, PCSTR, PCWSTR, w};

use crate::error::KeyStoreError;
use crate::kind::KeyStoreKind;
use crate::store::{AliasSet, CertEntry, EntryCapabilities, KeyStore, find_entry};
use crate::verify::{
    EcCurve, certificate_curve, certificate_key_algorithm, certificate_key_bits, ecdsa_raw_to_der, ecdsa_truncate_hash,
};

/// Almacén de sistema de Windows del usuario actual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemStore {
    /// Certificados personales (`MY`), con claves privadas.
    My,
    /// "Otras personas" (`ADDRESSBOOK`): solo certificados públicos.
    AddressBook,
    /// Entidades de certificación intermedias (`CA`).
    Ca,
    /// Entidades de certificación raíz de confianza (`ROOT`).
    Root,
}

impl SystemStore {
    /// Nombre del almacén de sistema de Windows.
    pub fn name(self) -> &'static str {
        match self {
            SystemStore::My => "MY",
            SystemStore::AddressBook => "ADDRESSBOOK",
            SystemStore::Ca => "CA",
            SystemStore::Root => "ROOT",
        }
    }

    /// Tipo de almacén de AutoFirma al que corresponde.
    pub fn kind(self) -> KeyStoreKind {
        match self {
            SystemStore::My => KeyStoreKind::Windows,
            SystemStore::AddressBook => KeyStoreKind::WinAddressBook,
            SystemStore::Ca | SystemStore::Root => KeyStoreKind::WinCa,
        }
    }

    fn wide_name(self) -> PCWSTR {
        match self {
            SystemStore::My => w!("MY"),
            SystemStore::AddressBook => w!("ADDRESSBOOK"),
            SystemStore::Ca => w!("CA"),
            SystemStore::Root => w!("ROOT"),
        }
    }

    fn source(self) -> String {
        match self {
            SystemStore::My => "Windows".to_string(),
            other => format!("Windows ({})", other.name()),
        }
    }
}

/// Preferencia al adquirir la clave privada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyPreference {
    /// Preferir CNG (`CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG`): las claves de
    /// CSP antiguos que no se pueden abrir con CNG se devuelven como
    /// contexto CryptoAPI. Es la opción por defecto.
    #[default]
    PreferCng,
    /// Preferir CryptoAPI (como hace SunMSCAPI en Java 8): se intenta sin
    /// permitir CNG y, si la clave solo existe en un KSP, se usa CNG.
    PreferLegacy,
}

// ---------------------------------------------------------------------------
// Envoltorios RAII
// ---------------------------------------------------------------------------

/// Almacén de certificados abierto (`HCERTSTORE`).
struct CertStore(HCERTSTORE);

// SAFETY: las funciones de almacenes de CryptoAPI son seguras entre hilos
// (el manejador es un objeto con contador de referencias del sistema) y aquí
// solo se usa para enumerar y cerrar.
unsafe impl Send for CertStore {}
// SAFETY: véase `Send`; no hay estado mutable en el lado de Rust.
unsafe impl Sync for CertStore {}

impl CertStore {
    /// Abre un almacén de sistema del usuario actual en modo lectura.
    fn open_system(store: SystemStore) -> windows::core::Result<CertStore> {
        let flags = CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER)
            | CERT_STORE_OPEN_EXISTING_FLAG
            | CERT_STORE_READONLY_FLAG;
        // SAFETY: `wide_name` es una cadena UTF-16 estática terminada en nulo,
        // que es el `pvPara` que espera `CERT_STORE_PROV_SYSTEM_W`; no se pasa
        // proveedor (`hCryptProv` = 0).
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                flags,
                Some(store.wide_name().as_ptr() as *const c_void),
            )
        }?;
        Ok(CertStore(handle))
    }

    /// Certificados del almacén, en el orden de enumeración (cada uno con su
    /// propia referencia).
    fn certificates(&self) -> Vec<CertContext> {
        let mut out = Vec::new();
        let mut prev: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // SAFETY: `self.0` es un almacén abierto; `prev` es nulo o el
            // contexto devuelto por la llamada anterior, que
            // `CertEnumCertificatesInStore` libera. Al llegar al final (nulo)
            // la función ya ha liberado el último contexto.
            let cur = unsafe {
                CertEnumCertificatesInStore(self.0, (!prev.is_null()).then_some(prev as *const CERT_CONTEXT))
            };
            if cur.is_null() {
                break;
            }
            // SAFETY: `cur` es un contexto válido devuelto por la enumeración.
            out.push(unsafe { CertContext::duplicate(cur) });
            prev = cur;
        }
        out
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: el manejador se abrió con `CertOpenStore` y se cierra una
        // sola vez; los contextos duplicados mantienen el almacén vivo.
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}

/// Contexto de certificado con referencia propia (`PCCERT_CONTEXT`).
struct CertContext(*const CERT_CONTEXT);

// SAFETY: un `CERT_CONTEXT` es inmutable una vez creado y su contador de
// referencias se gestiona con funciones seguras entre hilos
// (`CertDuplicateCertificateContext`/`CertFreeCertificateContext`).
unsafe impl Send for CertContext {}
// SAFETY: véase `Send`.
unsafe impl Sync for CertContext {}

impl CertContext {
    /// Toma una referencia nueva de un contexto.
    ///
    /// # Safety
    /// `ctx` debe ser un contexto de certificado válido.
    unsafe fn duplicate(ctx: *const CERT_CONTEXT) -> CertContext {
        // SAFETY: garantizado por el llamante.
        CertContext(unsafe { CertDuplicateCertificateContext(Some(ctx)) })
    }

    /// Certificado en DER.
    fn der(&self) -> Vec<u8> {
        // SAFETY: `self.0` es un contexto válido mientras exista `self`;
        // `pbCertEncoded` apunta a `cbCertEncoded` bytes.
        unsafe {
            let c = &*self.0;
            if c.pbCertEncoded.is_null() {
                return Vec::new();
            }
            std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec()
        }
    }

    /// Valor de una propiedad del certificado en un búfer alineado a 8
    /// bytes (las estructuras devueltas contienen punteros a su interior).
    fn property(&self, id: u32) -> Option<(Vec<u64>, usize)> {
        let mut len = 0u32;
        // SAFETY: consulta de tamaño con búfer nulo.
        unsafe { CertGetCertificateContextProperty(self.0, id, None, &mut len) }.ok()?;
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: `buf` tiene al menos `len` bytes.
        unsafe { CertGetCertificateContextProperty(self.0, id, Some(buf.as_mut_ptr() as *mut c_void), &mut len) }
            .ok()?;
        Some((buf, len as usize))
    }

    /// Proveedor y contenedor de la clave (`CERT_KEY_PROV_INFO_PROP_ID`).
    fn key_provider(&self) -> Option<String> {
        let (buf, len) = self.property(CERT_KEY_PROV_INFO_PROP_ID)?;
        if len < std::mem::size_of::<CRYPT_KEY_PROV_INFO>() {
            return None;
        }
        // SAFETY: el sistema ha escrito una `CRYPT_KEY_PROV_INFO` al inicio de
        // `buf` (alineado a 8) y sus punteros apuntan dentro de `buf`, que
        // sigue vivo durante esta función.
        unsafe {
            let info = &*(buf.as_ptr() as *const CRYPT_KEY_PROV_INFO);
            if info.pwszProvName.is_null() {
                return None;
            }
            info.pwszProvName.to_string().ok()
        }
    }

    /// Nombre descriptivo (`CERT_NAME_FRIENDLY_DISPLAY_TYPE`): propiedad de
    /// nombre descriptivo o, si no existe, nombre del titular.
    fn friendly_display_name(&self) -> String {
        // SAFETY: consulta de longitud (incluye el nulo final).
        let len = unsafe { CertGetNameStringW(self.0, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, None, None) };
        if len <= 1 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize];
        // SAFETY: `buf` tiene la longitud indicada por la llamada anterior.
        let written =
            unsafe { CertGetNameStringW(self.0, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, None, Some(&mut buf)) } as usize;
        let end = buf[..written.min(buf.len())]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(written.min(buf.len()));
        String::from_utf16_lossy(&buf[..end])
    }

    /// Cadena de certificación construida por Windows (primera cadena
    /// simple, empezando por el certificado final). Solo se usan las URL en
    /// caché para no bloquear sin red. Si falla, `[certificado]`.
    fn chain(&self) -> Vec<Vec<u8>> {
        let own = self.der();
        let para = CERT_CHAIN_PARA {
            cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
            ..Default::default()
        };
        let mut chain: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        // SAFETY: parámetros documentados de `CertGetCertificateChain` con el
        // motor por defecto del usuario (`HCCE_CURRENT_USER` = nulo).
        let ok = unsafe {
            CertGetCertificateChain(
                None,
                self.0,
                None,
                None,
                &para,
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE,
                None,
                &mut chain,
            )
        };
        if ok.is_err() || chain.is_null() {
            return vec![own];
        }
        let mut out = Vec::new();
        // SAFETY: `chain` es un contexto de cadena válido hasta
        // `CertFreeCertificateChain`; se recorren `cChain`/`cElement` elementos
        // de los arrays que contiene.
        unsafe {
            let ctx = &*chain;
            if ctx.cChain > 0 && !ctx.rgpChain.is_null() {
                let simple = *ctx.rgpChain;
                if !simple.is_null() {
                    let simple = &*simple;
                    for i in 0..simple.cElement as usize {
                        let el = *simple.rgpElement.add(i);
                        if el.is_null() || (*el).pCertContext.is_null() {
                            continue;
                        }
                        let c = &*(*el).pCertContext;
                        if !c.pbCertEncoded.is_null() {
                            out.push(std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec());
                        }
                    }
                }
            }
            CertFreeCertificateChain(chain);
        }
        if out.first() != Some(&own) {
            return vec![own];
        }
        out
    }

    /// Adquiere la clave privada del certificado.
    fn acquire(&self, flags: CRYPT_ACQUIRE_FLAGS) -> windows::core::Result<AcquiredKey> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0);
        let mut spec = CERT_KEY_SPEC(0);
        let mut free = BOOL(0);
        // SAFETY: parámetros de salida válidos; el contexto es válido.
        unsafe {
            CryptAcquireCertificatePrivateKey(self.0, flags, None, &mut handle, Some(&mut spec), Some(&mut free))
        }?;
        Ok(if spec == CERT_NCRYPT_KEY_SPEC {
            AcquiredKey::Cng {
                handle: NCRYPT_KEY_HANDLE(handle.0),
                free: free.as_bool(),
            }
        } else {
            AcquiredKey::Capi {
                prov: handle.0,
                key_spec: spec.0,
                free: free.as_bool(),
            }
        })
    }

    /// Comprueba si el certificado tiene clave privada utilizable, sin
    /// mostrar interfaz (como SunMSCAPI al cargar el almacén). Devuelve
    /// `(tiene_clave, es_hardware)`.
    fn probe_private_key(&self) -> (bool, bool) {
        let provider_hw = self.key_provider().is_some_and(|p| is_hardware_provider(&p));
        match self.acquire(CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG) {
            Ok(key) => (true, provider_hw || key.is_hardware()),
            // La clave existe pero necesita interfaz (normalmente una tarjeta).
            Err(e) if e.code() == NTE_SILENT_CONTEXT => (true, true),
            Err(e) => {
                tracing::debug!(
                    "Certificado sin clave privada utilizable: {} ({:#010x})",
                    e.message(),
                    e.code().0 as u32
                );
                (false, provider_hw)
            }
        }
    }
}

impl Clone for CertContext {
    fn clone(&self) -> Self {
        // SAFETY: `self.0` es un contexto válido.
        unsafe { CertContext::duplicate(self.0) }
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        // SAFETY: se libera la referencia tomada en `duplicate`.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
    }
}

/// Proveedores que guardan las claves en hardware (tarjeta, TPM).
fn is_hardware_provider(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("smart card")
        || n.contains("smartcard")
        || n.contains("platform crypto")
        || n.contains("dnie")
        || n.contains("fnmt")
}

/// Clave privada adquirida: CNG (`NCRYPT_KEY_HANDLE`) o CryptoAPI
/// (`HCRYPTPROV` + `dwKeySpec`).
enum AcquiredKey {
    Cng { handle: NCRYPT_KEY_HANDLE, free: bool },
    Capi { prov: usize, key_spec: u32, free: bool },
}

// SAFETY: los manejadores de CNG y CryptoAPI no están ligados al hilo que los
// creó; `CapiKey` los protege con un `Mutex`, así que nunca se usan desde
// dos hilos a la vez.
unsafe impl Send for AcquiredKey {}

impl AcquiredKey {
    fn kind_name(&self) -> &'static str {
        match self {
            AcquiredKey::Cng { .. } => "CNG",
            AcquiredKey::Capi { .. } => "CryptoAPI",
        }
    }

    /// Indica si el proveedor declara implementación hardware o extraíble.
    fn is_hardware(&self) -> bool {
        match self {
            AcquiredKey::Cng { handle, .. } => {
                let mut value = [0u8; 4];
                let mut len = 0u32;
                // SAFETY: búfer de 4 bytes para la propiedad DWORD
                // `NCRYPT_IMPL_TYPE_PROPERTY` de una clave válida.
                let r = unsafe {
                    NCryptGetProperty(
                        NCRYPT_HANDLE(handle.0),
                        NCRYPT_IMPL_TYPE_PROPERTY,
                        Some(&mut value),
                        &mut len,
                        Default::default(),
                    )
                };
                r.is_ok() && u32::from_le_bytes(value) & (NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG) != 0
            }
            AcquiredKey::Capi { prov, .. } => {
                let mut value = [0u8; 4];
                let mut len = 4u32;
                // SAFETY: búfer de 4 bytes para `PP_IMPTYPE` (DWORD).
                let r = unsafe { CryptGetProvParam(*prov, PP_IMPTYPE, Some(value.as_mut_ptr()), &mut len, 0) };
                r.is_ok() && u32::from_le_bytes(value) & (CRYPT_IMPL_HARDWARE | CRYPT_IMPL_REMOVABLE) != 0
            }
        }
    }
}

impl Drop for AcquiredKey {
    fn drop(&mut self) {
        match self {
            AcquiredKey::Cng { handle, free: true } => {
                // SAFETY: el sistema indicó que el llamante debe liberar el
                // manejador; se libera una sola vez.
                let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) };
            }
            AcquiredKey::Capi { prov, free: true, .. } => {
                // SAFETY: ídem para el contexto de CryptoAPI.
                let _ = unsafe { CryptReleaseContext(*prov, 0) };
            }
            _ => {}
        }
    }
}

/// Contexto de CryptoAPI propio (abierto con `CryptAcquireContext`).
struct CryptProv(usize);

impl Drop for CryptProv {
    fn drop(&mut self) {
        // SAFETY: contexto abierto por nosotros con `CryptAcquireContextA`.
        let _ = unsafe { CryptReleaseContext(self.0, 0) };
    }
}

/// Objeto de huella de CryptoAPI.
struct CryptHash(usize);

impl CryptHash {
    fn create(prov: usize, alg: ALG_ID) -> windows::core::Result<CryptHash> {
        let mut h = 0usize;
        // SAFETY: `prov` es un contexto válido; `h` es un parámetro de salida.
        unsafe { CryptCreateHash(prov, alg, 0, 0, &mut h) }?;
        Ok(CryptHash(h))
    }
}

impl Drop for CryptHash {
    fn drop(&mut self) {
        // SAFETY: objeto creado con `CryptCreateHash`, destruido una vez.
        let _ = unsafe { CryptDestroyHash(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Firma
// ---------------------------------------------------------------------------

/// Traduce un error de Windows a [`KeyError`] (tabla 5.3 de la
/// especificación).
fn key_error(context: &str, e: &windows::core::Error) -> KeyError {
    map_hresult(context, e.code(), &e.message())
}

fn map_hresult(context: &str, code: HRESULT, message: &str) -> KeyError {
    if code == SCARD_W_WRONG_CHV {
        KeyError::WrongPin
    } else if code == SCARD_W_CHV_BLOCKED {
        KeyError::PinLocked
    } else if code == SCARD_W_CANCELLED_BY_USER
        || code == NTE_USER_CANCELLED
        || code == HRESULT::from_win32(ERROR_CANCELLED.0)
    {
        KeyError::Cancelled
    } else if code == SCARD_W_REMOVED_CARD || code == SCARD_E_NO_SMARTCARD {
        KeyError::DeviceUnavailable
    } else {
        KeyError::Other(format!("{context}: {message} ({:#010x})", code.0 as u32))
    }
}

/// Firma con CNG.
fn sign_cng(
    handle: NCRYPT_KEY_HANDLE,
    key: &CapiKeyInfo,
    alg: SignatureAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let hash = alg.digest.digest(data);
    match key.key_alg {
        KeyAlgorithm::Rsa => {
            // SHA-224 no tiene identificador en CNG: se firma el DigestInfo
            // completo con relleno PKCS#1 sin OID (`pszAlgId` nulo).
            let (alg_id, input) = match alg.digest {
                DigestAlgorithm::Sha1 => (BCRYPT_SHA1_ALGORITHM, hash),
                DigestAlgorithm::Sha224 => (PCWSTR::null(), alg.digest.digest_info(&hash)),
                DigestAlgorithm::Sha256 => (BCRYPT_SHA256_ALGORITHM, hash),
                DigestAlgorithm::Sha384 => (BCRYPT_SHA384_ALGORITHM, hash),
                DigestAlgorithm::Sha512 => (BCRYPT_SHA512_ALGORITHM, hash),
            };
            let info = BCRYPT_PKCS1_PADDING_INFO { pszAlgId: alg_id };
            ncrypt_sign(
                handle,
                Some(&info as *const BCRYPT_PKCS1_PADDING_INFO as *const c_void),
                &input,
                NCRYPT_PAD_PKCS1_FLAG,
                key.sig_len,
            )
        }
        KeyAlgorithm::Ec => {
            let h = ecdsa_truncate_hash(&hash, key.curve);
            let raw = ncrypt_sign(handle, None, &h, NCRYPT_FLAGS(0), key.sig_len)?;
            ecdsa_raw_to_der(&raw)
        }
        KeyAlgorithm::Dsa => Err(KeyError::Unsupported("claves DSA".into())),
    }
}

/// `NCryptSignHash` con una sola llamada si se conoce el tamaño de la firma
/// (para no interrogar dos veces a la tarjeta), o consultando antes el
/// tamaño.
fn ncrypt_sign(
    handle: NCRYPT_KEY_HANDLE,
    padding: Option<*const c_void>,
    input: &[u8],
    flags: NCRYPT_FLAGS,
    expected: Option<usize>,
) -> Result<Vec<u8>, KeyError> {
    let mut len = 0u32;
    if let Some(n) = expected {
        let mut buf = vec![0u8; n];
        // SAFETY: `padding` apunta a una estructura viva durante la llamada (o
        // es nulo); `buf` y `input` son búferes válidos.
        match unsafe { NCryptSignHash(handle, padding, input, Some(&mut buf), &mut len, flags) } {
            Ok(()) => {
                buf.truncate(len as usize);
                return Ok(buf);
            }
            Err(e) if e.code() == NTE_BUFFER_TOO_SMALL => {}
            Err(e) => return Err(key_error("Error al firmar con CNG (NCryptSignHash)", &e)),
        }
    }
    // SAFETY: consulta de tamaño con búfer nulo.
    unsafe { NCryptSignHash(handle, padding, input, None, &mut len, flags) }
        .map_err(|e| key_error("Error al firmar con CNG (NCryptSignHash)", &e))?;
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` tiene el tamaño indicado por el sistema.
    unsafe { NCryptSignHash(handle, padding, input, Some(&mut buf), &mut len, flags) }
        .map_err(|e| key_error("Error al firmar con CNG (NCryptSignHash)", &e))?;
    buf.truncate(len as usize);
    Ok(buf)
}

fn capi_alg(digest: DigestAlgorithm) -> Option<ALG_ID> {
    match digest {
        DigestAlgorithm::Sha1 => Some(CALG_SHA1),
        DigestAlgorithm::Sha256 => Some(CALG_SHA_256),
        DigestAlgorithm::Sha384 => Some(CALG_SHA_384),
        DigestAlgorithm::Sha512 => Some(CALG_SHA_512),
        DigestAlgorithm::Sha224 => None,
    }
}

/// Firma con un contexto de CryptoAPI (`CryptSignHash`).
fn sign_capi(
    prov: usize,
    key_spec: u32,
    key: &CapiKeyInfo,
    alg: SignatureAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, KeyError> {
    if key.key_alg != KeyAlgorithm::Rsa {
        return Err(KeyError::Unsupported(format!(
            "{} con un proveedor CryptoAPI",
            alg.java_name()
        )));
    }
    let calg = capi_alg(alg.digest)
        .ok_or_else(|| KeyError::Unsupported(format!("{} con un proveedor CryptoAPI", alg.java_name())))?;
    let hash = alg.digest.digest(data);
    // `dwKeySpec` debería ser AT_KEYEXCHANGE o AT_SIGNATURE; si el
    // proveedor informa otro valor (p. ej. la importación PFX de Wine) se
    // prueban ambos (la verificación posterior detecta cualquier error).
    let specs: &[u32] = if key_spec == AT_KEYEXCHANGE.0 || key_spec == AT_SIGNATURE.0 {
        &[key_spec]
    } else {
        &[AT_KEYEXCHANGE.0, AT_SIGNATURE.0]
    };
    let mut last = None;
    for &spec in specs {
        match capi_sign_with(prov, calg, spec, &hash) {
            Err(CapiSignError::NoKey(e)) => last = Some(e),
            Err(CapiSignError::Key(e)) => return Err(e),
            Ok(sig) => return Ok(sig),
        }
    }
    Err(last.unwrap_or_else(|| KeyError::Other("Error al firmar con CryptoAPI".into())))
}

enum CapiSignError {
    /// No existe una clave con ese `dwKeySpec` en el contenedor.
    NoKey(KeyError),
    Key(KeyError),
}

/// Crea el objeto de huella (con el proveedor `PROV_RSA_AES` si el CSP no
/// admite el algoritmo) y firma con la clave `key_spec`.
fn capi_sign_with(prov: usize, calg: ALG_ID, key_spec: u32, hash: &[u8]) -> Result<Vec<u8>, CapiSignError> {
    let mut alt_prov = None;
    let h = match CryptHash::create(prov, calg) {
        Ok(h) => h,
        Err(first) => {
            // El CSP (p. ej. PROV_RSA_FULL) no admite SHA-2: se reabre el
            // mismo contenedor con el proveedor PROV_RSA_AES por defecto,
            // como hace SunMSCAPI.
            let alt = reacquire_aes(prov)
                .map_err(|_| CapiSignError::Key(key_error("Error al crear la huella con CryptoAPI", &first)))?;
            let h = CryptHash::create(alt.0, calg)
                .map_err(|e| CapiSignError::Key(key_error("Error al crear la huella con CryptoAPI", &e)))?;
            alt_prov = Some(alt);
            h
        }
    };
    let r = capi_sign_hash(&h, key_spec, hash);
    // El objeto de huella debe destruirse antes que su proveedor.
    drop(h);
    drop(alt_prov);
    r
}

fn capi_sign_hash(h: &CryptHash, key_spec: u32, hash: &[u8]) -> Result<Vec<u8>, CapiSignError> {
    let sign_err = |e: windows::core::Error| {
        let k = key_error("Error al firmar con CryptoAPI (CryptSignHash)", &e);
        if e.code() == NTE_NO_KEY {
            CapiSignError::NoKey(k)
        } else {
            CapiSignError::Key(k)
        }
    };
    // SAFETY: `hash` tiene la longitud del algoritmo del objeto de huella.
    unsafe { CryptSetHashParam(h.0, HP_HASHVAL, hash.as_ptr(), 0) }
        .map_err(|e| CapiSignError::Key(key_error("Error al establecer la huella con CryptoAPI", &e)))?;
    let mut len = 0u32;
    // SAFETY: consulta de tamaño con búfer nulo.
    unsafe { CryptSignHashW(h.0, key_spec, PCWSTR::null(), 0, None, &mut len) }.map_err(sign_err)?;
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` tiene el tamaño indicado por el sistema.
    unsafe { CryptSignHashW(h.0, key_spec, PCWSTR::null(), 0, Some(buf.as_mut_ptr()), &mut len) }.map_err(sign_err)?;
    buf.truncate(len as usize);
    // CryptoAPI devuelve la firma en little-endian.
    buf.reverse();
    Ok(buf)
}

/// Abre el contenedor de `prov` con el proveedor `PROV_RSA_AES` por defecto.
fn reacquire_aes(prov: usize) -> windows::core::Result<CryptProv> {
    let mut len = 0u32;
    // SAFETY: consulta de tamaño con búfer nulo.
    unsafe { CryptGetProvParam(prov, PP_CONTAINER, None, &mut len, 0) }?;
    let mut name = vec![0u8; len as usize + 1];
    // SAFETY: `name` tiene al menos `len` bytes.
    unsafe { CryptGetProvParam(prov, PP_CONTAINER, Some(name.as_mut_ptr()), &mut len, 0) }?;
    if !name.contains(&0) {
        name.push(0);
    }
    let mut alt = 0usize;
    // SAFETY: `name` es una cadena ANSI terminada en nulo (la devuelta por
    // `PP_CONTAINER`); proveedor nulo = proveedor por defecto del tipo.
    unsafe { CryptAcquireContextA(&mut alt, PCSTR(name.as_ptr()), PCSTR::null(), PROV_RSA_AES, 0) }?;
    Ok(CryptProv(alt))
}

/// Datos de la clave necesarios para firmar.
struct CapiKeyInfo {
    key_alg: KeyAlgorithm,
    curve: Option<EcCurve>,
    /// Tamaño esperado de la firma en bruto (módulo RSA o `2·campo` en EC).
    sig_len: Option<usize>,
}

/// Clave privada de un certificado del almacén de Windows.
///
/// La clave se adquiere al firmar por primera vez (el proveedor puede pedir
/// el PIN entonces o al firmar) y se conserva para firmas posteriores
/// (firmante "sticky", lotes).
pub struct CapiKey {
    // Se declara antes que `cert` para liberarse antes que el contexto del
    // certificado (los manejadores en caché pertenecen al contexto).
    handle: Mutex<Option<AcquiredKey>>,
    cert: CertContext,
    der: Vec<u8>,
    chain: Vec<Vec<u8>>,
    alias: String,
    info: CapiKeyInfo,
    preference: KeyPreference,
}

impl CapiKey {
    fn new(
        cert: CertContext,
        chain: Vec<Vec<u8>>,
        alias: String,
        preference: KeyPreference,
    ) -> Result<CapiKey, KeyStoreError> {
        let der = cert.der();
        let key_alg = certificate_key_algorithm(&der).ok_or_else(|| {
            KeyStoreError::Key(KeyError::Unsupported(
                "tipo de clave del certificado no soportado".into(),
            ))
        })?;
        let curve = certificate_curve(&der);
        let sig_len = match key_alg {
            KeyAlgorithm::Rsa => certificate_key_bits(&der).map(|b| b.div_ceil(8)),
            KeyAlgorithm::Ec => curve.map(|c| c.field_len() * 2),
            KeyAlgorithm::Dsa => None,
        };
        Ok(CapiKey {
            handle: Mutex::new(None),
            cert,
            der,
            chain,
            alias,
            info: CapiKeyInfo {
                key_alg,
                curve,
                sig_len,
            },
            preference,
        })
    }

    fn acquire(&self) -> Result<AcquiredKey, KeyError> {
        let r = match self.preference {
            KeyPreference::PreferCng => self.cert.acquire(CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG),
            KeyPreference::PreferLegacy => self.cert.acquire(CRYPT_ACQUIRE_FLAGS(0)).or_else(|e| {
                // Si la clave solo existe en un KSP se usa CNG; los errores de
                // PIN o cancelación se respetan.
                match map_hresult("", e.code(), "") {
                    KeyError::Other(_) => self.cert.acquire(CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG),
                    _ => Err(e),
                }
            }),
        };
        r.map_err(|e| key_error("No se ha podido acceder a la clave privada del certificado", &e))
    }

    /// Tipo de manejador adquirido (`"CNG"`/`"CryptoAPI"`), si ya se adquirió.
    pub fn provider_kind(&self) -> Option<&'static str> {
        self.handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(AcquiredKey::kind_name))
    }
}

impl SigningKey for CapiKey {
    fn certificate(&self) -> &[u8] {
        &self.der
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.info.key_alg
    }

    fn alias(&self) -> Option<&str> {
        Some(&self.alias)
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        if algorithm.key != self.info.key_alg {
            return Err(KeyError::Unsupported(format!(
                "{} con una clave {}",
                algorithm.java_name(),
                self.info.key_alg.java_suffix()
            )));
        }
        let mut guard = self
            .handle
            .lock()
            .map_err(|_| KeyError::Other("estado de la clave inconsistente".into()))?;
        if guard.is_none() {
            *guard = Some(self.acquire()?);
        }
        let result = match guard.as_ref() {
            Some(AcquiredKey::Cng { handle, .. }) => sign_cng(*handle, &self.info, algorithm, data),
            Some(AcquiredKey::Capi { prov, key_spec, .. }) => sign_capi(*prov, *key_spec, &self.info, algorithm, data),
            None => Err(KeyError::Other("clave no adquirida".into())),
        };
        // Tras un error que no sea de PIN se libera el manejador para volver
        // a adquirir la clave en el siguiente intento (p. ej. tarjeta
        // reinsertada).
        if matches!(result, Err(KeyError::DeviceUnavailable | KeyError::Other(_))) {
            *guard = None;
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Almacén
// ---------------------------------------------------------------------------

struct Item {
    entry: CertEntry,
    ctx: CertContext,
}

struct Loaded {
    _store: Option<CertStore>,
    items: Vec<Item>,
}

/// Almacén de sistema de Windows del usuario actual (`WINDOWS`,
/// `WINADDRESSBOOK`, `WINCA`).
pub struct CapiStore {
    system: SystemStore,
    preference: KeyPreference,
    state: Mutex<Option<Loaded>>,
}

impl CapiStore {
    /// Abre el almacén de sistema indicado del usuario actual.
    pub fn open(store: SystemStore) -> Result<CapiStore, KeyStoreError> {
        let s = CapiStore {
            system: store,
            preference: KeyPreference::default(),
            state: Mutex::new(None),
        };
        s.load()?;
        Ok(s)
    }

    /// Cambia la preferencia de adquisición de claves (CNG por defecto).
    pub fn with_key_preference(mut self, preference: KeyPreference) -> Self {
        self.preference = preference;
        self
    }

    /// Almacén de sistema abierto.
    pub fn system_store(&self) -> SystemStore {
        self.system
    }

    fn load(&self) -> Result<(), KeyStoreError> {
        let kind = self.system.kind();
        let mut not_found = false;
        let store = CertStore::open_system(self.system).map_err(|e| {
            not_found = e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0);
            KeyStoreError::load(
                kind,
                format!(
                    "No se ha podido abrir el almacén {} de Windows: {} ({:#010x})",
                    self.system.name(),
                    e.message(),
                    e.code().0 as u32
                ),
            )
        });
        let store = match store {
            Ok(s) => Some(s),
            // El almacén de sistema todavía no existe (perfil nuevo, libreta
            // de direcciones sin usar): está vacío. Java (CertOpenSystemStore)
            // lo crearía; aquí se abre en modo lectura.
            Err(_) if not_found => None,
            Err(e) => {
                // Como en Java, si no se puede recargar el almacén sus
                // entradas desaparecen.
                if let Ok(mut st) = self.state.lock() {
                    *st = None;
                }
                return Err(e);
            }
        };
        let source = self.system.source();
        let mut aliases = AliasSet::new();
        let mut items = Vec::new();
        for ctx in store.as_ref().map(CertStore::certificates).unwrap_or_default() {
            let der = ctx.der();
            if der.is_empty() {
                continue;
            }
            let mut name = ctx.friendly_display_name();
            if name.is_empty() {
                name = hex::encode_upper(DigestAlgorithm::Sha1.digest(&der));
            }
            let alias = aliases.unique(&name);
            let (has_key, hardware) = if self.system == SystemStore::My {
                ctx.probe_private_key()
            } else {
                (false, false)
            };
            let chain = if has_key { ctx.chain() } else { vec![der.clone()] };
            let caps = EntryCapabilities {
                has_private_key: has_key,
                key_algorithm: None,
                hardware,
                pin_at_sign: false,
            };
            let entry = CertEntry::new(alias, der, chain, caps, source.clone());
            items.push(Item { entry, ctx });
        }
        let mut st = self
            .state
            .lock()
            .map_err(|_| KeyStoreError::load(kind, "estado del almacén inconsistente"))?;
        *st = Some(Loaded { _store: store, items });
        Ok(())
    }
}

impl KeyStore for CapiStore {
    fn kind(&self) -> KeyStoreKind {
        self.system.kind()
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        let st = self
            .state
            .lock()
            .map_err(|_| KeyStoreError::load(self.kind(), "estado del almacén inconsistente"))?;
        Ok(st
            .as_ref()
            .map(|l| l.items.iter().map(|i| i.entry.clone()).collect())
            .unwrap_or_default())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let st = self
            .state
            .lock()
            .map_err(|_| KeyStoreError::load(self.kind(), "estado del almacén inconsistente"))?;
        let items = st.as_ref().map(|l| l.items.as_slice()).unwrap_or_default();
        let entries: Vec<CertEntry> = items.iter().map(|i| i.entry.clone()).collect();
        let found = find_entry(&entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let item = items
            .iter()
            .find(|i| i.entry.id == found.id)
            .ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        if !item.entry.capabilities.has_private_key {
            return Err(KeyStoreError::NoPrivateKey(item.entry.alias.clone()));
        }
        let key = CapiKey::new(
            item.ctx.clone(),
            item.entry.chain.clone(),
            item.entry.alias.clone(),
            self.preference,
        )?;
        Ok(Box::new(key))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        self.load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_kinds() {
        assert_eq!(SystemStore::My.name(), "MY");
        assert_eq!(SystemStore::My.kind(), KeyStoreKind::Windows);
        assert_eq!(SystemStore::AddressBook.kind(), KeyStoreKind::WinAddressBook);
        assert_eq!(SystemStore::Ca.kind(), KeyStoreKind::WinCa);
        assert_eq!(SystemStore::Root.kind(), KeyStoreKind::WinCa);
    }

    #[test]
    fn error_mapping() {
        assert_eq!(map_hresult("x", SCARD_W_WRONG_CHV, ""), KeyError::WrongPin);
        assert_eq!(map_hresult("x", SCARD_W_CHV_BLOCKED, ""), KeyError::PinLocked);
        assert_eq!(map_hresult("x", SCARD_W_CANCELLED_BY_USER, ""), KeyError::Cancelled);
        assert_eq!(map_hresult("x", NTE_USER_CANCELLED, ""), KeyError::Cancelled);
        assert_eq!(
            map_hresult("x", HRESULT::from_win32(ERROR_CANCELLED.0), ""),
            KeyError::Cancelled
        );
        assert_eq!(map_hresult("x", SCARD_W_REMOVED_CARD, ""), KeyError::DeviceUnavailable);
        assert_eq!(map_hresult("x", SCARD_E_NO_SMARTCARD, ""), KeyError::DeviceUnavailable);
        assert!(matches!(map_hresult("x", NTE_BUFFER_TOO_SMALL, "m"), KeyError::Other(m) if m.contains("0x80090028")));
        assert!(is_hardware_provider("Microsoft Smart Card Key Storage Provider"));
        assert!(!is_hardware_provider("Microsoft Software Key Storage Provider"));
    }

    #[test]
    fn opens_my_store() {
        // El almacén MY existe siempre para el usuario (también en Wine).
        let s = CapiStore::open(SystemStore::My).expect("abrir MY");
        let _ = s.entries().unwrap();
        s.refresh().unwrap();
    }

    /// Importa `testdata/pki/<fichero>` en `CurrentUser\MY` con las opciones
    /// de `PFXImportCertStore` indicadas. Devuelve la huella SHA-1 del
    /// certificado con clave.
    fn import_pfx(file: &str, flags: windows::Win32::Security::Cryptography::CRYPT_KEY_FLAGS) -> String {
        use windows::Win32::Security::Cryptography::{
            CERT_STORE_ADD_REPLACE_EXISTING, CRYPT_INTEGER_BLOB, CertAddCertificateContextToStore, PFXImportCertStore,
        };
        let data = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/pki")
                .join(file),
        )
        .unwrap();
        let blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        // SAFETY: `blob` apunta a `data`, vivo durante la llamada.
        let pfx = unsafe { PFXImportCertStore(&blob, w!("12341234"), flags) }
            .or_else(|_| {
                // Wine solo admite CRYPT_USER_KEYSET/CRYPT_EXPORTABLE.
                // SAFETY: ídem.
                unsafe {
                    PFXImportCertStore(
                        &blob,
                        w!("12341234"),
                        windows::Win32::Security::Cryptography::CRYPT_USER_KEYSET,
                    )
                }
            })
            .expect("PFXImportCertStore");
        let pfx = CertStore(pfx);
        let flags = CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER);
        // SAFETY: igual que en `CertStore::open_system`, en modo escritura.
        let my = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                flags,
                Some(w!("MY").as_ptr() as *const c_void),
            )
        }
        .expect("abrir MY para escritura");
        let my = CertStore(my);
        // SAFETY: ídem para el almacén CA (intermedias) del usuario.
        let ca = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(0),
                None,
                flags,
                Some(w!("CA").as_ptr() as *const c_void),
            )
        }
        .expect("abrir CA para escritura");
        let ca = CertStore(ca);
        // La CA de pruebas también se añade explícitamente (la importación PFX
        // de Wine solo devuelve el certificado con clave).
        let ca_der = afirma_core::cert::decode_certificate(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki/ca.crt")).unwrap(),
        )
        .unwrap();
        // SAFETY: `ca_der` es un certificado DER válido durante la llamada.
        unsafe {
            windows::Win32::Security::Cryptography::CertAddEncodedCertificateToStore(
                Some(ca.0),
                windows::Win32::Security::Cryptography::X509_ASN_ENCODING,
                &ca_der,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
        }
        .expect("añadir la CA");
        let mut thumb = String::new();
        let certs = pfx.certificates();
        eprintln!("PFX {file}: {} certificados", certs.len());
        for c in certs {
            if c.key_provider().is_none() {
                // Certificados de la cadena: al almacén CA para que Windows
                // pueda construir la cadena.
                // SAFETY: contexto y almacén válidos.
                unsafe { CertAddCertificateContextToStore(Some(ca.0), c.0, CERT_STORE_ADD_REPLACE_EXISTING, None) }
                    .expect("añadir a CA");
                continue;
            }
            // SAFETY: contexto y almacén válidos.
            unsafe { CertAddCertificateContextToStore(Some(my.0), c.0, CERT_STORE_ADD_REPLACE_EXISTING, None) }
                .expect("añadir a MY");
            thumb = hex::encode_upper(DigestAlgorithm::Sha1.digest(&c.der()));
        }
        assert!(!thumb.is_empty(), "el PFX no tenía certificado con clave");
        thumb
    }

    /// Firma directamente con CNG (`sign_cng`) usando claves efímeras
    /// importadas en el KSP de software, sin tocar los almacenes del
    /// usuario. Si el entorno no ofrece CNG (algunas versiones de Wine) se
    /// informa y se omite.
    #[test]
    fn cng_sign_with_ephemeral_keys() {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        use windows::Win32::Security::Cryptography::{
            BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAPRIVATE_MAGIC,
            MS_KEY_STORAGE_PROVIDER, NCRYPT_PROV_HANDLE, NCryptImportKey, NCryptOpenStorageProvider,
        };
        let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki");
        let pem = |f: &str| std::fs::read_to_string(pki.join(f)).unwrap();
        let cert = |f: &str| afirma_core::cert::decode_certificate(pem(f).as_bytes()).unwrap();

        let mut prov = NCRYPT_PROV_HANDLE(0);
        // SAFETY: parámetro de salida válido; nombre de proveedor estático.
        if let Err(e) = unsafe { NCryptOpenStorageProvider(&mut prov, MS_KEY_STORAGE_PROVIDER, 0) } {
            eprintln!("CNG no disponible ({e}); se omite la prueba");
            return;
        }
        let _prov_guard = AcquiredKey::Cng {
            handle: NCRYPT_KEY_HANDLE(prov.0),
            free: true,
        };

        // RSA: BCRYPT_RSAKEY_BLOB + e + n + p + q (big-endian).
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem("firmante-rsa.key")).unwrap();
        let (e, n) = (rsa_key.e().to_bytes_be(), rsa_key.n().to_bytes_be());
        let (p, q) = (rsa_key.primes()[0].to_bytes_be(), rsa_key.primes()[1].to_bytes_be());
        let mut rsa_blob = Vec::new();
        for v in [
            BCRYPT_RSAPRIVATE_MAGIC.0,
            (n.len() * 8) as u32,
            e.len() as u32,
            n.len() as u32,
            p.len() as u32,
            q.len() as u32,
        ] {
            rsa_blob.extend_from_slice(&v.to_le_bytes());
        }
        for part in [&e, &n, &p, &q] {
            rsa_blob.extend_from_slice(part);
        }
        // EC P-256: BCRYPT_ECCKEY_BLOB + X + Y + d.
        let ec_key = p256::SecretKey::from_pkcs8_pem(&pem("firmante-ec.key")).unwrap();
        let point = ec_key.public_key().to_sec1_bytes();
        let mut ec_blob = Vec::new();
        ec_blob.extend_from_slice(&BCRYPT_ECDSA_PRIVATE_P256_MAGIC.to_le_bytes());
        ec_blob.extend_from_slice(&32u32.to_le_bytes());
        ec_blob.extend_from_slice(&point[1..]);
        ec_blob.extend_from_slice(&ec_key.to_bytes());

        for (blob_type, blob, cert_der) in [
            (BCRYPT_RSAPRIVATE_BLOB, rsa_blob, cert("firmante-rsa.crt")),
            (BCRYPT_ECCPRIVATE_BLOB, ec_blob, cert("firmante-ec.crt")),
        ] {
            let mut handle = NCRYPT_KEY_HANDLE(0);
            // SAFETY: `blob` es un búfer válido con el formato indicado.
            if let Err(e) = unsafe { NCryptImportKey(prov, None, blob_type, None, &mut handle, &blob, NCRYPT_FLAGS(0)) }
            {
                eprintln!("NCryptImportKey no disponible ({e}); se omite");
                continue;
            }
            let _guard = AcquiredKey::Cng { handle, free: true };
            let key_alg = certificate_key_algorithm(&cert_der).unwrap();
            let curve = certificate_curve(&cert_der);
            let sig_len = match key_alg {
                KeyAlgorithm::Rsa => certificate_key_bits(&cert_der).map(|b| b.div_ceil(8)),
                _ => curve.map(|c| c.field_len() * 2),
            };
            let info = CapiKeyInfo {
                key_alg,
                curve,
                sig_len,
            };
            for d in DigestAlgorithm::ALL {
                let alg = SignatureAlgorithm::new(d, key_alg);
                match sign_cng(handle, &info, alg, b"datos de prueba") {
                    Ok(sig) => {
                        let v = crate::verify::verify_signature(&cert_der, alg, b"datos de prueba", &sig);
                        eprintln!("[CNG efímera] {alg}: {} bytes, verificación {v:?}", sig.len());
                        assert!(v.is_ok(), "{alg}");
                    }
                    Err(e) => eprintln!("[CNG efímera] {alg}: error {e}"),
                }
            }
        }
    }

    /// Prueba de humo que **modifica el almacén MY del usuario**: solo se
    /// ejecuta explícitamente (`--ignored`), pensada para Wine o una máquina
    /// virtual de pruebas.
    #[test]
    #[ignore]
    fn smoke_import_sign_verify() {
        use windows::Win32::Security::Cryptography::{
            CRYPT_KEY_FLAGS, CRYPT_USER_KEYSET, PKCS12_ALLOW_OVERWRITE_KEY, PKCS12_PREFER_CNG_KSP,
        };
        let cases: [(&str, CRYPT_KEY_FLAGS, &str); 3] = [
            (
                "firmante-rsa.p12",
                CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY,
                "RSA en CSP",
            ),
            (
                "autenticacion.p12",
                CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_PREFER_CNG_KSP,
                "RSA en KSP",
            ),
            (
                "firmante-ec.p12",
                CRYPT_USER_KEYSET | PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_PREFER_CNG_KSP,
                "EC en KSP",
            ),
        ];
        for (file, flags, label) in cases {
            let thumb = std::panic::catch_unwind(|| import_pfx(file, flags));
            let Ok(thumb) = thumb else {
                eprintln!("[{label}] no se pudo importar {file}");
                continue;
            };
            let ca = CapiStore::open(SystemStore::Ca).unwrap();
            let ca_entries = ca.entries().unwrap();
            for e in &ca_entries {
                eprintln!(
                    "[{label}] CA: alias={:?} nombre={:?} clave={}",
                    e.alias, e.friendly_name, e.capabilities.has_private_key
                );
            }
            assert!(
                ca_entries
                    .iter()
                    .any(|e| e.friendly_name == "AC Raiz de Pruebas AutoFirma-rs" && !e.capabilities.has_private_key)
            );
            assert!(matches!(
                ca.signing_key(&ca_entries[0].alias),
                Err(KeyStoreError::NoPrivateKey(_))
            ));
            for pref in [KeyPreference::PreferCng, KeyPreference::PreferLegacy] {
                let store = CapiStore::open(SystemStore::My).unwrap().with_key_preference(pref);
                let entry = store.entry(&format!("sha1:{thumb}")).expect("entrada importada");
                eprintln!(
                    "[{label}/{pref:?}] alias={:?} clave={} hardware={} cadena={}",
                    entry.alias,
                    entry.capabilities.has_private_key,
                    entry.capabilities.hardware,
                    entry.chain.len()
                );
                assert_eq!(entry.chain.len(), 2, "la cadena debe incluir la CA de pruebas");
                if !entry.capabilities.has_private_key {
                    eprintln!("[{label}/{pref:?}] sin clave privada detectada");
                    continue;
                }
                let key = store.signing_key(&entry.alias).unwrap();
                for d in DigestAlgorithm::ALL {
                    let alg = SignatureAlgorithm::new(d, key.key_algorithm());
                    match key.sign(b"datos de prueba", alg) {
                        Ok(sig) => {
                            let v = crate::verify::verify_signature(key.certificate(), alg, b"datos de prueba", &sig);
                            eprintln!(
                                "[{label}/{pref:?}] {alg}: firma {} bytes, verificación {v:?}",
                                sig.len()
                            );
                            assert!(v.is_ok(), "{label} {alg}");
                        }
                        Err(e) => eprintln!("[{label}/{pref:?}] {alg}: error {e}"),
                    }
                }
            }
        }
    }
}
