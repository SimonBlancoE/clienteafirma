//! Acceso directo al módulo PKCS#11 `softokn3` de NSS (sin `certutil`) para añadir,
//! comprobar y retirar la CA de AutoFirma y su objeto de confianza NSS
//! (`CKO_NSS_TRUST`) en una base de datos NSS existente.
//!
//! **FFI**: este módulo usa `unsafe` para cargar la biblioteca con `libloading` y llamar a
//! la tabla de funciones PKCS#11 (`C_GetFunctionList`). Las estructuras son las de
//! `cryptoki-sys` (con el empaquetado correcto por plataforma). Se respetan estas reglas:
//! cada puntero pasado vive durante la llamada, los búferes tienen la longitud declarada y
//! la biblioteca se mantiene cargada durante toda la vida del proceso (NSS no admite bien
//! descargarse). NSS es un singleton de proceso: si ya está inicializado por otro componente
//! (`CKR_CRYPTOKI_ALREADY_INITIALIZED`), la operación falla y se debe usar `certutil`.

use std::ffi::{CString, c_void};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cryptoki_sys::*;
use sha1::Digest as _;
use x509_parser::prelude::*;

use super::nss::TrustFlags;
use crate::ctx::{Context, Os};
use crate::error::{Result, SystemError};
use crate::firefox::NssDbKind;

/// Valor de confianza NSS (`CK_TRUST`).
pub type TrustValue = CK_ULONG;

const NSSCK_VENDOR_NSS: CK_ULONG = 0x4E53_4350;
const CKO_NSS: CK_ULONG = 0x8000_0000 | NSSCK_VENDOR_NSS;
const CKO_NSS_TRUST: CK_ULONG = CKO_NSS + 3;
const CKA_NSS: CK_ULONG = 0x8000_0000 | NSSCK_VENDOR_NSS;
const CKA_TRUST: CK_ULONG = CKA_NSS + 0x2000;
const CKA_TRUST_SERVER_AUTH: CK_ULONG = CKA_TRUST + 8;
const CKA_TRUST_CLIENT_AUTH: CK_ULONG = CKA_TRUST + 9;
const CKA_TRUST_CODE_SIGNING: CK_ULONG = CKA_TRUST + 10;
const CKA_TRUST_EMAIL_PROTECTION: CK_ULONG = CKA_TRUST + 11;
const CKA_TRUST_STEP_UP_APPROVED: CK_ULONG = CKA_TRUST + 16;
const CKA_CERT_SHA1_HASH: CK_ULONG = CKA_TRUST + 100;
const CKA_CERT_MD5_HASH: CK_ULONG = CKA_TRUST + 101;
const CKT_NSS: CK_ULONG = 0x8000_0000 | NSSCK_VENDOR_NSS;
/// Confianza como par (P).
pub const CKT_NSS_TRUSTED: CK_ULONG = CKT_NSS + 1;
/// Confianza como CA (C/T).
pub const CKT_NSS_TRUSTED_DELEGATOR: CK_ULONG = CKT_NSS + 2;
/// Sin confianza explícita.
pub const CKT_NSS_MUST_VERIFY_TRUST: CK_ULONG = CKT_NSS + 3;

/// Argumentos de `C_Initialize` de NSS (`CK_NSS_C_INITIALIZE_ARGS`, con `LibraryParameters`).
#[cfg_attr(windows, repr(C, packed))]
#[cfg_attr(not(windows), repr(C))]
struct NssInitArgs {
    create_mutex: *mut c_void,
    destroy_mutex: *mut c_void,
    lock_mutex: *mut c_void,
    unlock_mutex: *mut c_void,
    flags: CK_FLAGS,
    library_parameters: *mut std::os::raw::c_char,
    reserved: *mut c_void,
}

/// Bibliotecas cargadas (se mantienen durante toda la vida del proceso) y exclusión mutua.
static LOADED: Mutex<Vec<(PathBuf, &'static libloading::Library)>> = Mutex::new(Vec::new());

fn load(path: &Path) -> Result<&'static libloading::Library> {
    let mut l = LOADED
        .lock()
        .map_err(|_| SystemError::Other("bloqueo envenenado".into()))?;
    if let Some((_, lib)) = l.iter().find(|(p, _)| p == path) {
        return Ok(lib);
    }
    // SAFETY: carga de una biblioteca del sistema (NSS); sus constructores no tienen requisitos.
    #[cfg(windows)]
    let lib = unsafe {
        // LOAD_WITH_ALTERED_SEARCH_PATH: dependencias (nss3.dll, mozglue.dll...) junto a softokn3.dll.
        libloading::os::windows::Library::load_with_flags(path, 0x0000_0008).map(libloading::Library::from)
    };
    #[cfg(not(windows))]
    let lib = unsafe { libloading::Library::new(path) };
    let lib = lib.map_err(|e| SystemError::Other(format!("no se pudo cargar {}: {e}", path.display())))?;
    let lib: &'static libloading::Library = Box::leak(Box::new(lib));
    l.push((path.to_path_buf(), lib));
    Ok(lib)
}

/// Busca `softokn3` (sistema o Firefox).
pub fn find_softokn(ctx: &Context) -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    match ctx.os {
        Os::Linux => {
            let triple = if cfg!(target_arch = "aarch64") {
                "aarch64-linux-gnu"
            } else if cfg!(target_arch = "x86") {
                "i386-linux-gnu"
            } else {
                "x86_64-linux-gnu"
            };
            for d in [
                format!("/usr/lib/{triple}/nss"),
                format!("/usr/lib/{triple}"),
                "/usr/lib64/nss".into(),
                "/usr/lib64".into(),
                "/usr/lib/nss".into(),
                "/usr/lib".into(),
                "/usr/lib64/firefox".into(),
                "/usr/lib/firefox".into(),
                "/opt/firefox".into(),
                "/lib64".into(),
                "/lib".into(),
            ] {
                cands.push(ctx.sys(&d).join("libsoftokn3.so"));
            }
        }
        Os::MacOs => {
            for d in [
                "/Applications/Firefox.app/Contents/MacOS",
                "/opt/homebrew/opt/nss/lib",
                "/usr/local/opt/nss/lib",
            ] {
                cands.push(ctx.sys(d).join("libsoftokn3.dylib"));
            }
        }
        Os::Windows => {
            for d in super::windows::firefox_install_dirs(ctx) {
                cands.push(d.join("softokn3.dll"));
            }
        }
    }
    cands.into_iter().find(|p| p.is_file())
}

fn ck(rv: CK_RV, what: &str) -> Result<()> {
    if rv == CKR_OK as CK_RV {
        Ok(())
    } else if rv == CKR_USER_NOT_LOGGED_IN as CK_RV || rv == CKR_PIN_INCORRECT as CK_RV {
        Err(SystemError::TrustStore {
            store: "NSS".into(),
            detail: format!("{what}: la base de datos está protegida con contraseña maestra (0x{rv:X})"),
        })
    } else {
        Err(SystemError::TrustStore {
            store: "NSS".into(),
            detail: format!("{what}: error PKCS#11 0x{rv:X}"),
        })
    }
}

/// DER de un INTEGER a partir de su contenido.
fn der_integer(content: &[u8]) -> Vec<u8> {
    let mut v = vec![0x02];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else if n < 0x100 {
        v.extend_from_slice(&[0x81, n as u8]);
    } else {
        v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(content);
    v
}

/// Datos del certificado necesarios para las plantillas PKCS#11.
struct CertIds {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}

fn cert_ids(der: &[u8]) -> Result<CertIds> {
    let (_, c) = X509Certificate::from_der(der).map_err(|e| SystemError::Certificate(e.to_string()))?;
    Ok(CertIds {
        subject: c.subject().as_raw().to_vec(),
        issuer: c.issuer().as_raw().to_vec(),
        serial: der_integer(c.tbs_certificate.raw_serial()),
    })
}

/// Valor de atributo con su almacenamiento.
enum AttrVal {
    Bytes(Vec<u8>),
    Ulong(CK_ULONG),
    Bool(CK_BBOOL),
}

struct Template {
    vals: Vec<(CK_ATTRIBUTE_TYPE, AttrVal)>,
    raw: Vec<CK_ATTRIBUTE>,
}

impl Template {
    fn new(vals: Vec<(CK_ATTRIBUTE_TYPE, AttrVal)>) -> Self {
        let mut t = Self { vals, raw: Vec::new() };
        t.raw = t
            .vals
            .iter_mut()
            .map(|(ty, v)| {
                let (ptr, len) = match v {
                    AttrVal::Bytes(b) => (b.as_mut_ptr() as *mut c_void, b.len()),
                    AttrVal::Ulong(u) => (u as *mut CK_ULONG as *mut c_void, std::mem::size_of::<CK_ULONG>()),
                    AttrVal::Bool(b) => (b as *mut CK_BBOOL as *mut c_void, 1),
                };
                CK_ATTRIBUTE {
                    type_: *ty,
                    pValue: ptr,
                    ulValueLen: len as CK_ULONG,
                }
            })
            .collect();
        t
    }
}

/// Sesión abierta sobre una base de datos NSS.
pub struct SoftoknSession {
    fl: *const CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    _guard: std::sync::MutexGuard<'static, ()>,
}

static SESSION_LOCK: Mutex<()> = Mutex::new(());

macro_rules! f {
    ($s:expr, $name:ident) => {{
        // SAFETY: `fl` apunta a la tabla estática devuelta por C_GetFunctionList, válida
        // mientras la biblioteca esté cargada (siempre).
        let fl = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*$s.fl).$name)) };
        fl.ok_or_else(|| SystemError::Other(concat!("función PKCS#11 ausente: ", stringify!($name)).into()))?
    }};
}

impl SoftoknSession {
    /// Inicializa `softokn` sobre la base de datos de `dir` y abre una sesión de escritura en
    /// el token «NSS Certificate DB».
    pub fn open(lib_path: &Path, dir: &Path, kind: NssDbKind) -> Result<Self> {
        let guard = SESSION_LOCK
            .lock()
            .map_err(|_| SystemError::Other("bloqueo envenenado".into()))?;
        let lib = load(lib_path)?;
        let dir_s = dir.to_string_lossy();
        if dir_s.contains('\'') {
            return Err(SystemError::Other("ruta de base NSS no admitida".into()));
        }
        let prefix = match kind {
            NssDbKind::Sql => "sql:",
            NssDbKind::Dbm => "dbm:",
        };
        let params = CString::new(format!(
            "configdir='{prefix}{dir_s}' certPrefix='' keyPrefix='' secmod='secmod.db' flags= "
        ))
        .map_err(|_| SystemError::Other("ruta no válida".into()))?;
        // SAFETY: símbolo estándar PKCS#11 con la firma de cryptoki-sys.
        let get_fl: libloading::Symbol<'_, unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV> =
            unsafe { lib.get(b"C_GetFunctionList\0") }
                .map_err(|e| SystemError::Other(format!("C_GetFunctionList: {e}")))?;
        let mut fl: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        // SAFETY: puntero de salida válido.
        ck(unsafe { get_fl(&mut fl) }, "C_GetFunctionList")?;
        if fl.is_null() {
            return Err(SystemError::Other("C_GetFunctionList devolvió NULL".into()));
        }
        let mut s = Self {
            fl,
            session: 0,
            _guard: guard,
        };
        let mut args = NssInitArgs {
            create_mutex: std::ptr::null_mut(),
            destroy_mutex: std::ptr::null_mut(),
            lock_mutex: std::ptr::null_mut(),
            unlock_mutex: std::ptr::null_mut(),
            flags: CKF_OS_LOCKING_OK as CK_FLAGS,
            library_parameters: params.as_ptr() as *mut _,
            reserved: std::ptr::null_mut(),
        };
        let init = f!(s, C_Initialize);
        // SAFETY: `args` y `params` viven durante la llamada.
        let rv = unsafe { init(&mut args as *mut NssInitArgs as *mut c_void) };
        if rv == CKR_CRYPTOKI_ALREADY_INITIALIZED as CK_RV {
            s.fl = std::ptr::null();
            return Err(SystemError::Other(
                "NSS ya está inicializado en este proceso; use certutil".into(),
            ));
        }
        if let Err(e) = ck(rv, "C_Initialize") {
            s.fl = std::ptr::null();
            return Err(e);
        }
        let slot = s.cert_db_slot()?;
        let open = f!(s, C_OpenSession);
        let mut h: CK_SESSION_HANDLE = 0;
        // SAFETY: salida válida; sin notificaciones.
        ck(
            unsafe {
                open(
                    slot,
                    (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS,
                    std::ptr::null_mut(),
                    None,
                    &mut h,
                )
            },
            "C_OpenSession",
        )?;
        s.session = h;
        Ok(s)
    }

    fn cert_db_slot(&self) -> Result<CK_SLOT_ID> {
        let list = f!(self, C_GetSlotList);
        let info = f!(self, C_GetTokenInfo);
        let mut n: CK_ULONG = 0;
        // SAFETY: consulta del número de ranuras.
        ck(unsafe { list(CK_TRUE, std::ptr::null_mut(), &mut n) }, "C_GetSlotList")?;
        let mut slots = vec![0 as CK_SLOT_ID; n as usize];
        // SAFETY: búfer de `n` elementos.
        ck(unsafe { list(CK_TRUE, slots.as_mut_ptr(), &mut n) }, "C_GetSlotList")?;
        slots.truncate(n as usize);
        for &sl in &slots {
            // SAFETY: estructura POD de salida.
            let mut ti: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
            if unsafe { info(sl, &mut ti) } == CKR_OK as CK_RV {
                let label = String::from_utf8_lossy(&ti.label).trim().to_string();
                if label.starts_with("NSS Certificate DB") || label.starts_with("NSS FIPS 140-2 Certificate DB") {
                    return Ok(sl);
                }
            }
        }
        slots
            .into_iter()
            .find(|&s| s == 2)
            .ok_or_else(|| SystemError::Other("no se encontró el token «NSS Certificate DB»".into()))
    }

    fn find(&self, tpl: &mut Template) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let init = f!(self, C_FindObjectsInit);
        let find = f!(self, C_FindObjects);
        let fin = f!(self, C_FindObjectsFinal);
        // SAFETY: plantilla válida durante la llamada.
        ck(
            unsafe { init(self.session, tpl.raw.as_mut_ptr(), tpl.raw.len() as CK_ULONG) },
            "C_FindObjectsInit",
        )?;
        let mut out = Vec::new();
        loop {
            let mut buf = [0 as CK_OBJECT_HANDLE; 32];
            let mut n: CK_ULONG = 0;
            // SAFETY: búfer de 32 elementos.
            let rv = unsafe { find(self.session, buf.as_mut_ptr(), 32, &mut n) };
            if rv != CKR_OK as CK_RV || n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        // SAFETY: cierra la búsqueda de esta sesión.
        unsafe { fin(self.session) };
        Ok(out)
    }

    fn attr(&self, obj: CK_OBJECT_HANDLE, ty: CK_ATTRIBUTE_TYPE) -> Result<Option<Vec<u8>>> {
        let get = f!(self, C_GetAttributeValue);
        let mut a = CK_ATTRIBUTE {
            type_: ty,
            pValue: std::ptr::null_mut(),
            ulValueLen: 0,
        };
        // SAFETY: consulta de longitud.
        if unsafe { get(self.session, obj, &mut a, 1) } != CKR_OK as CK_RV || a.ulValueLen == CK_UNAVAILABLE_INFORMATION
        {
            return Ok(None);
        }
        let mut buf = vec![0u8; a.ulValueLen as usize];
        a.pValue = buf.as_mut_ptr() as *mut c_void;
        // SAFETY: búfer de la longitud indicada.
        ck(unsafe { get(self.session, obj, &mut a, 1) }, "C_GetAttributeValue")?;
        buf.truncate(a.ulValueLen as usize);
        Ok(Some(buf))
    }

    fn destroy(&self, obj: CK_OBJECT_HANDLE) -> Result<()> {
        let d = f!(self, C_DestroyObject);
        // SAFETY: objeto de esta sesión.
        ck(unsafe { d(self.session, obj) }, "C_DestroyObject")
    }

    fn create(&self, tpl: &mut Template) -> Result<()> {
        let c = f!(self, C_CreateObject);
        let mut h: CK_OBJECT_HANDLE = 0;
        // SAFETY: plantilla válida durante la llamada.
        ck(
            unsafe { c(self.session, tpl.raw.as_mut_ptr(), tpl.raw.len() as CK_ULONG, &mut h) },
            "C_CreateObject",
        )
    }

    /// Certificados del token: (manejador, etiqueta, DER).
    pub fn certificates(&self) -> Result<Vec<(CK_OBJECT_HANDLE, String, Vec<u8>)>> {
        let mut tpl = Template::new(vec![(CKA_CLASS, AttrVal::Ulong(CKO_CERTIFICATE as CK_ULONG))]);
        let mut out = Vec::new();
        for h in self.find(&mut tpl)? {
            let label = self
                .attr(h, CKA_LABEL)?
                .map(|l| String::from_utf8_lossy(&l).into_owned())
                .unwrap_or_default();
            if let Some(der) = self.attr(h, CKA_VALUE)? {
                out.push((h, label, der));
            }
        }
        Ok(out)
    }

    fn trust_objects(&self, ids: &CertIds) -> Result<Vec<CK_OBJECT_HANDLE>> {
        let mut tpl = Template::new(vec![
            (CKA_CLASS, AttrVal::Ulong(CKO_NSS_TRUST)),
            (CKA_ISSUER, AttrVal::Bytes(ids.issuer.clone())),
            (CKA_SERIAL_NUMBER, AttrVal::Bytes(ids.serial.clone())),
        ]);
        self.find(&mut tpl)
    }

    /// Confianza SSL del certificado (`CKA_TRUST_SERVER_AUTH`), si tiene objeto de confianza.
    pub fn server_trust(&self, der: &[u8]) -> Result<Option<CK_ULONG>> {
        let ids = cert_ids(der)?;
        for h in self.trust_objects(&ids)? {
            if let Some(v) = self.attr(h, CKA_TRUST_SERVER_AUTH)?
                && v.len() == std::mem::size_of::<CK_ULONG>()
            {
                let mut a = [0u8; std::mem::size_of::<CK_ULONG>()];
                a.copy_from_slice(&v);
                return Ok(Some(CK_ULONG::from_ne_bytes(a)));
            }
        }
        Ok(None)
    }

    /// Elimina un certificado (y su objeto de confianza).
    pub fn remove(&self, handle: CK_OBJECT_HANDLE, der: &[u8]) -> Result<()> {
        if let Ok(ids) = cert_ids(der) {
            for t in self.trust_objects(&ids)? {
                self.destroy(t)?;
            }
        }
        self.destroy(handle)
    }

    /// Añade la CA con la etiqueta y la confianza indicadas.
    pub fn add(&self, der: &[u8], label: &str, flags: &TrustFlags) -> Result<()> {
        let ids = cert_ids(der)?;
        let mut cert = Template::new(vec![
            (CKA_CLASS, AttrVal::Ulong(CKO_CERTIFICATE as CK_ULONG)),
            (CKA_CERTIFICATE_TYPE, AttrVal::Ulong(CKC_X_509 as CK_ULONG)),
            (CKA_TOKEN, AttrVal::Bool(CK_TRUE)),
            (CKA_LABEL, AttrVal::Bytes(label.as_bytes().to_vec())),
            (CKA_SUBJECT, AttrVal::Bytes(ids.subject.clone())),
            (CKA_ISSUER, AttrVal::Bytes(ids.issuer.clone())),
            (CKA_SERIAL_NUMBER, AttrVal::Bytes(ids.serial.clone())),
            (CKA_VALUE, AttrVal::Bytes(der.to_vec())),
        ]);
        self.create(&mut cert)?;
        let (ssl, email, code, client) = flags.pkcs11_trust();
        let mut trust = Template::new(vec![
            (CKA_CLASS, AttrVal::Ulong(CKO_NSS_TRUST)),
            (CKA_TOKEN, AttrVal::Bool(CK_TRUE)),
            (CKA_LABEL, AttrVal::Bytes(label.as_bytes().to_vec())),
            (CKA_ISSUER, AttrVal::Bytes(ids.issuer)),
            (CKA_SERIAL_NUMBER, AttrVal::Bytes(ids.serial)),
            (CKA_CERT_SHA1_HASH, AttrVal::Bytes(sha1::Sha1::digest(der).to_vec())),
            (CKA_CERT_MD5_HASH, AttrVal::Bytes(md5::Md5::digest(der).to_vec())),
            (CKA_TRUST_SERVER_AUTH, AttrVal::Ulong(ssl)),
            (CKA_TRUST_CLIENT_AUTH, AttrVal::Ulong(client)),
            (CKA_TRUST_EMAIL_PROTECTION, AttrVal::Ulong(email)),
            (CKA_TRUST_CODE_SIGNING, AttrVal::Ulong(code)),
            (CKA_TRUST_STEP_UP_APPROVED, AttrVal::Bool(0)),
        ]);
        self.create(&mut trust)
    }
}

impl Drop for SoftoknSession {
    fn drop(&mut self) {
        if self.fl.is_null() {
            return;
        }
        // SAFETY: tabla válida; se cierra la sesión y se finaliza el módulo que inicializamos.
        unsafe {
            let fl = std::ptr::read_unaligned(std::ptr::addr_of!((*self.fl).C_CloseSession));
            if let Some(close) = fl
                && self.session != 0
            {
                close(self.session);
            }
            let fin = std::ptr::read_unaligned(std::ptr::addr_of!((*self.fl).C_Finalize));
            if let Some(fin) = fin {
                fin(std::ptr::null_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_der() {
        assert_eq!(der_integer(&[0x01]), vec![0x02, 0x01, 0x01]);
        assert_eq!(der_integer(&[0u8; 130])[..3], [0x02, 0x81, 130]);
    }
}
