//! Acceso directo (FFI mínimo) a la tabla de funciones PKCS#11 para las dos
//! operaciones que el crate `cryptoki` no expone:
//!
//! 1. `C_Initialize` con `pReserved` = cadena de inicialización de NSS
//!    (`configdir='…' certPrefix='' keyPrefix='' flags='readOnly'`), necesaria
//!    para usar `softokn3` como módulo PKCS#11 (equivalente a `nssArgs` de
//!    SunPKCS11).
//! 2. Firma con claves `CKA_ALWAYS_AUTHENTICATE`: `C_SignInit` +
//!    `C_Login(CKU_CONTEXT_SPECIFIC)` + `C_Sign` en la misma sesión.
//!
//! La biblioteca se carga también aquí (antes que `cryptoki`), de modo que en
//! Windows se resuelven sus DLL dependientes junto al módulo
//! (`LOAD_WITH_ALTERED_SEARCH_PATH`); `cryptoki` vuelve a cargar la misma
//! ruta y obtiene el mismo módulo ya cargado.

use std::ffi::{CStr, c_void};
use std::path::Path;
use std::ptr;

use cryptoki_sys::{
    CK_C_INITIALIZE_ARGS, CK_FUNCTION_LIST, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CKF_OS_LOCKING_OK, CKR_OK,
    CKU_CONTEXT_SPECIFIC,
};

/// Módulo PKCS#11 cargado con su tabla de funciones.
pub(crate) struct RawModule {
    list: *const CK_FUNCTION_LIST,
    // Debe declararse después de `list` y mantenerse vivo mientras se use la
    // tabla (pertenece a la imagen cargada).
    _lib: libloading::Library,
}

// SAFETY: `list` apunta a la tabla de funciones estática del módulo cargado,
// que no se modifica y vive tanto como `_lib`. Las funciones PKCS#11 se
// llaman tras `C_Initialize` con `CKF_OS_LOCKING_OK` (el módulo se encarga
// de la concurrencia) y las sesiones se protegen con `Mutex` en el nivel
// superior.
unsafe impl Send for RawModule {}
unsafe impl Sync for RawModule {}

/// Resultado de una llamada PKCS#11 en bruto.
pub(crate) type RawResult<T> = Result<T, CK_RV>;

fn check(rv: CK_RV) -> RawResult<()> {
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

impl RawModule {
    /// Carga la biblioteca y obtiene su tabla de funciones
    /// (`C_GetFunctionList`).
    pub(crate) fn load(path: &Path) -> Result<RawModule, String> {
        let lib = load_library(path)?;
        // SAFETY: el símbolo `C_GetFunctionList` tiene la firma estándar de
        // PKCS#11 (`CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR)`).
        let list = unsafe {
            let get: libloading::Symbol<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV> =
                lib.get(b"C_GetFunctionList\0").map_err(|e| format!("la biblioteca no es un módulo PKCS#11: {e}"))?;
            let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
            let rv = get(&mut list);
            if rv != CKR_OK || list.is_null() {
                return Err(format!("C_GetFunctionList devolvió {rv:#x}"));
            }
            list as *const CK_FUNCTION_LIST
        };
        Ok(RawModule { list, _lib: lib })
    }

    fn functions(&self) -> &CK_FUNCTION_LIST {
        // SAFETY: comprobado no nulo en `load`; la tabla vive tanto como `_lib`.
        unsafe { &*self.list }
    }

    /// `C_Initialize` con `CKF_OS_LOCKING_OK` y, opcionalmente, `pReserved`
    /// (cadena de inicialización de NSS).
    pub(crate) fn initialize(&self, reserved: Option<&CStr>) -> RawResult<()> {
        let f = self.functions().C_Initialize.ok_or(cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED)?;
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: reserved.map(|r| r.as_ptr() as *mut c_void).unwrap_or(ptr::null_mut()),
        };
        // SAFETY: `args` es una estructura válida que vive durante la llamada;
        // `reserved` (si existe) es una cadena C terminada en NUL que NSS solo
        // lee durante `C_Initialize`.
        check(unsafe { f(&mut args as *mut CK_C_INITIALIZE_ARGS as *mut c_void) })
    }

    /// Firma con una clave que exige autenticación por operación
    /// (`CKA_ALWAYS_AUTHENTICATE`).
    pub(crate) fn sign_with_context_login(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &cryptoki::mechanism::Mechanism,
        key: CK_OBJECT_HANDLE,
        pin: Option<&[u8]>,
        data: &[u8],
    ) -> RawResult<Vec<u8>> {
        let fl = self.functions();
        let sign_init = fl.C_SignInit.ok_or(cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED)?;
        let login = fl.C_Login.ok_or(cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED)?;
        let sign = fl.C_Sign.ok_or(cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED)?;
        let mut mech: CK_MECHANISM = mechanism.into();
        let data_len = CK_ULONG::try_from(data.len()).map_err(|_| cryptoki_sys::CKR_DATA_LEN_RANGE)?;
        // SAFETY: todos los punteros apuntan a búferes válidos durante cada
        // llamada; las longitudes coinciden con los búferes; la sesión y la
        // clave son identificadores obtenidos del mismo módulo.
        unsafe {
            check(sign_init(session, &mut mech, key))?;
            let (pin_ptr, pin_len) = match pin {
                Some(p) => (p.as_ptr() as *mut u8, CK_ULONG::try_from(p.len()).map_err(|_| cryptoki_sys::CKR_PIN_LEN_RANGE)?),
                None => (ptr::null_mut(), 0),
            };
            check(login(session, CKU_CONTEXT_SPECIFIC, pin_ptr, pin_len))?;
            let mut sig_len: CK_ULONG = 0;
            check(sign(session, data.as_ptr() as *mut u8, data_len, ptr::null_mut(), &mut sig_len))?;
            let mut sig = vec![0u8; usize::try_from(sig_len).map_err(|_| cryptoki_sys::CKR_GENERAL_ERROR)?];
            check(sign(session, data.as_ptr() as *mut u8, data_len, sig.as_mut_ptr(), &mut sig_len))?;
            sig.truncate(usize::try_from(sig_len).map_err(|_| cryptoki_sys::CKR_GENERAL_ERROR)?);
            Ok(sig)
        }
    }
}

#[cfg(test)]
impl RawModule {
    /// `C_CloseAllSessions` (solo pruebas: simula la extracción de la
    /// tarjeta, que invalida las sesiones y el inicio de sesión).
    pub(crate) fn close_all_sessions(&self, slot: cryptoki_sys::CK_SLOT_ID) -> RawResult<()> {
        let f = self.functions().C_CloseAllSessions.ok_or(cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED)?;
        // SAFETY: llamada PKCS#11 estándar con un identificador de ranura.
        check(unsafe { f(slot) })
    }
}

#[cfg(windows)]
fn load_library(path: &Path) -> Result<libloading::Library, String> {
    // LOAD_WITH_ALTERED_SEARCH_PATH: las DLL dependientes se buscan en el
    // directorio del módulo (p. ej. NSS de Firefox, controladores FNMT).
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    // SAFETY: cargar una biblioteca ejecuta sus constructores; es inherente a
    // usar un módulo PKCS#11 elegido por el usuario o por el sistema.
    unsafe { libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH) }
        .map(Into::into)
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn load_library(path: &Path) -> Result<libloading::Library, String> {
    // SAFETY: cargar una biblioteca ejecuta sus constructores; es inherente a
    // usar un módulo PKCS#11 elegido por el usuario o por el sistema.
    unsafe { libloading::Library::new(path) }.map_err(|e| e.to_string())
}

/// Carga (y deja cargada durante todo el proceso) una biblioteca auxiliar,
/// con sus símbolos globales en UNIX: dependencias de NSS que no se
/// resolverían solas si el directorio no está en la ruta de búsqueda.
pub(crate) fn preload_global(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_NOW};
        // SAFETY: ver `load_library`.
        match unsafe { Library::open(Some(path), RTLD_NOW | RTLD_GLOBAL) } {
            Ok(lib) => {
                std::mem::forget(lib);
                true
            }
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        match load_library(path) {
            Ok(lib) => {
                std::mem::forget(lib);
                true
            }
            Err(_) => false,
        }
    }
}

/// Identificador numérico de una sesión de `cryptoki` (su `Display` imprime
/// el `CK_SESSION_HANDLE`; el crate no expone el valor de otra forma).
pub(crate) fn session_handle(session: &cryptoki::session::Session) -> Option<CK_SESSION_HANDLE> {
    session.to_string().parse().ok()
}

/// Identificador numérico de un objeto de `cryptoki` (ver [`session_handle`]).
pub(crate) fn object_handle(object: &cryptoki::object::ObjectHandle) -> Option<CK_OBJECT_HANDLE> {
    object.to_string().parse().ok()
}
