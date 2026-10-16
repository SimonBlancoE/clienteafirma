//! Acceso al registro de Windows tras el trait [`Registry`], con una implementación en
//! memoria ([`MemoryRegistry`]) para pruebas y para sistemas que no son Windows.
//!
//! Las rutas se escriben con `\` y sin la colmena (p. ej. `Software\Classes\afirma`). El
//! nombre de valor vacío (`""`) es el valor predeterminado de la clave. En Windows se usa
//! siempre la vista de 64 bits (`KEY_WOW64_64KEY`); la vista de 32 bits es accesible
//! mediante `Software\WOW6432Node\...`.

use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

/// Colmena del registro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Hive {
    /// `HKEY_CURRENT_USER`.
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`.
    LocalMachine,
}

impl Hive {
    /// Abreviatura (`HKCU`/`HKLM`).
    pub fn short(self) -> &'static str {
        match self {
            Hive::CurrentUser => "HKCU",
            Hive::LocalMachine => "HKLM",
        }
    }

    /// Nombre completo (`HKEY_CURRENT_USER`...), para ficheros `.reg`.
    pub fn long(self) -> &'static str {
        match self {
            Hive::CurrentUser => "HKEY_CURRENT_USER",
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
        }
    }
}

/// Valor del registro.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum RegValue {
    /// `REG_SZ`.
    Sz(String),
    /// `REG_EXPAND_SZ`.
    ExpandSz(String),
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_QWORD`.
    Qword(u64),
    /// `REG_MULTI_SZ`.
    MultiSz(Vec<String>),
    /// Otros tipos (binario...).
    Other(Vec<u8>),
}

impl RegValue {
    /// Valor como cadena (para `REG_SZ`/`REG_EXPAND_SZ`; números en decimal).
    pub fn as_string(&self) -> Option<String> {
        match self {
            RegValue::Sz(s) | RegValue::ExpandSz(s) => Some(s.clone()),
            RegValue::Dword(d) => Some(d.to_string()),
            RegValue::Qword(d) => Some(d.to_string()),
            RegValue::MultiSz(v) => Some(v.join("\n")),
            RegValue::Other(_) => None,
        }
    }
}

/// Operaciones sobre el registro.
pub trait Registry: Send + Sync {
    /// Lee un valor (`Ok(None)` si la clave o el valor no existen).
    fn read(&self, hive: Hive, key: &str, name: &str) -> io::Result<Option<RegValue>>;
    /// Enumera los valores de una clave (`Ok(None)` si no existe).
    fn values(&self, hive: Hive, key: &str) -> io::Result<Option<Vec<(String, RegValue)>>>;
    /// Enumera las subclaves de una clave (`Ok(None)` si no existe).
    fn subkeys(&self, hive: Hive, key: &str) -> io::Result<Option<Vec<String>>>;
    /// Escribe un valor creando la clave si hace falta.
    fn write(&self, hive: Hive, key: &str, name: &str, value: &RegValue) -> io::Result<()>;
    /// Crea una clave vacía (si no existe).
    fn create_key(&self, hive: Hive, key: &str) -> io::Result<()>;
    /// Borra un valor; `true` si existía.
    fn delete_value(&self, hive: Hive, key: &str, name: &str) -> io::Result<bool>;
    /// Borra una clave y todo su contenido; `true` si existía.
    fn delete_tree(&self, hive: Hive, key: &str) -> io::Result<bool>;

    /// `true` si la clave existe.
    fn key_exists(&self, hive: Hive, key: &str) -> io::Result<bool> {
        Ok(self.values(hive, key)?.is_some())
    }

    /// Lee un valor como cadena.
    fn read_string(&self, hive: Hive, key: &str, name: &str) -> io::Result<Option<String>> {
        Ok(self.read(hive, key, name)?.and_then(|v| v.as_string()))
    }
}

fn norm(path: &str) -> String {
    path.trim_matches('\\')
        .split('\\')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\\")
        .to_ascii_lowercase()
}

#[derive(Debug, Default, Clone)]
struct MemKey {
    /// Nombre original (con mayúsculas) del último componente.
    name: String,
    /// Valores: nombre en minúsculas → (nombre original, valor).
    values: BTreeMap<String, (String, RegValue)>,
}

/// Registro en memoria, insensible a mayúsculas como el de Windows.
#[derive(Debug, Default)]
pub struct MemoryRegistry {
    keys: Mutex<BTreeMap<(Hive, String), MemKey>>,
    read_only: bool,
}

impl MemoryRegistry {
    /// Registro vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registro vacío que rechaza escrituras (simula falta de permisos o un sistema sin registro).
    pub fn read_only() -> Self {
        Self {
            keys: Mutex::new(BTreeMap::new()),
            read_only: true,
        }
    }

    /// Volcado ordenado `HIVE\ruta\clave => [valores]` (para pruebas y depuración).
    pub fn dump(&self) -> Vec<String> {
        let keys = self.keys.lock().map(|k| k.clone()).unwrap_or_default();
        let mut out = Vec::new();
        for ((h, path), k) in keys {
            if k.values.is_empty() {
                out.push(format!("{}\\{}", h.short(), path));
            }
            for (_, (n, v)) in k.values {
                out.push(format!("{}\\{} [{}] = {:?}", h.short(), path, n, v));
            }
        }
        out
    }

    fn ensure_path(map: &mut BTreeMap<(Hive, String), MemKey>, hive: Hive, key: &str) -> String {
        let comps: Vec<&str> = key.trim_matches('\\').split('\\').filter(|s| !s.is_empty()).collect();
        let mut acc = String::new();
        for c in comps {
            if !acc.is_empty() {
                acc.push('\\');
            }
            acc.push_str(&c.to_ascii_lowercase());
            map.entry((hive, acc.clone())).or_insert_with(|| MemKey {
                name: c.to_string(),
                values: BTreeMap::new(),
            });
        }
        acc
    }

    fn denied() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "registro de solo lectura")
    }
}

impl Registry for MemoryRegistry {
    fn read(&self, hive: Hive, key: &str, name: &str) -> io::Result<Option<RegValue>> {
        let keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        Ok(keys
            .get(&(hive, norm(key)))
            .and_then(|k| k.values.get(&name.to_ascii_lowercase()))
            .map(|(_, v)| v.clone()))
    }

    fn values(&self, hive: Hive, key: &str) -> io::Result<Option<Vec<(String, RegValue)>>> {
        let keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        Ok(keys
            .get(&(hive, norm(key)))
            .map(|k| k.values.values().map(|(n, v)| (n.clone(), v.clone())).collect()))
    }

    fn subkeys(&self, hive: Hive, key: &str) -> io::Result<Option<Vec<String>>> {
        let keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        let k = norm(key);
        if !k.is_empty() && !keys.contains_key(&(hive, k.clone())) {
            return Ok(None);
        }
        let prefix = if k.is_empty() { String::new() } else { format!("{k}\\") };
        let mut out = Vec::new();
        for ((h, p), mk) in keys.iter() {
            if *h == hive && p.starts_with(&prefix) && !p[prefix.len()..].contains('\\') && p.len() > prefix.len() {
                out.push(mk.name.clone());
            }
        }
        Ok(Some(out))
    }

    fn write(&self, hive: Hive, key: &str, name: &str, value: &RegValue) -> io::Result<()> {
        if self.read_only {
            return Err(Self::denied());
        }
        let mut keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        let k = Self::ensure_path(&mut keys, hive, key);
        if let Some(mk) = keys.get_mut(&(hive, k)) {
            mk.values
                .insert(name.to_ascii_lowercase(), (name.to_string(), value.clone()));
        }
        Ok(())
    }

    fn create_key(&self, hive: Hive, key: &str) -> io::Result<()> {
        if self.read_only {
            return Err(Self::denied());
        }
        let mut keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        Self::ensure_path(&mut keys, hive, key);
        Ok(())
    }

    fn delete_value(&self, hive: Hive, key: &str, name: &str) -> io::Result<bool> {
        if self.read_only {
            return Err(Self::denied());
        }
        let mut keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        Ok(keys
            .get_mut(&(hive, norm(key)))
            .map(|k| k.values.remove(&name.to_ascii_lowercase()).is_some())
            .unwrap_or(false))
    }

    fn delete_tree(&self, hive: Hive, key: &str) -> io::Result<bool> {
        if self.read_only {
            return Err(Self::denied());
        }
        let mut keys = self.keys.lock().map_err(|_| io::Error::other("bloqueo envenenado"))?;
        let k = norm(key);
        let prefix = format!("{k}\\");
        let before = keys.len();
        keys.retain(|(h, p), _| !(*h == hive && (*p == k || p.starts_with(&prefix))));
        Ok(keys.len() != before)
    }
}

/// Registro real de Windows (vista de 64 bits).
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsRegistry;

#[cfg(windows)]
mod win {
    use super::*;
    use windows_registry::{CURRENT_USER, Key, LOCAL_MACHINE, Type};

    /// `KEY_WOW64_64KEY`.
    const KEY_WOW64_64KEY: u32 = 0x0100;

    fn root(h: Hive) -> &'static Key {
        match h {
            Hive::CurrentUser => CURRENT_USER,
            Hive::LocalMachine => LOCAL_MACHINE,
        }
    }

    fn not_found(e: &windows_result::Error) -> bool {
        // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND)
        let c = e.code().0 as u32;
        c == 0x8007_0002 || c == 0x8007_0003
    }

    fn to_io(e: windows_result::Error) -> io::Error {
        let c = e.code().0 as u32;
        if c == 0x8007_0005 {
            io::Error::new(io::ErrorKind::PermissionDenied, e.message())
        } else if not_found(&e) {
            io::Error::new(io::ErrorKind::NotFound, e.message())
        } else {
            io::Error::other(format!("{} (0x{c:08X})", e.message()))
        }
    }

    fn open_read(h: Hive, key: &str) -> io::Result<Option<Key>> {
        match root(h).options().read().access(KEY_WOW64_64KEY).open(key) {
            Ok(k) => Ok(Some(k)),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => Err(to_io(e)),
        }
    }

    fn open_write(h: Hive, key: &str) -> io::Result<Key> {
        root(h)
            .options()
            .read()
            .write()
            .create()
            .access(KEY_WOW64_64KEY)
            .open(key)
            .map_err(to_io)
    }

    fn convert(v: windows_registry::Value) -> RegValue {
        match v.ty() {
            Type::String => RegValue::Sz(String::try_from(v).unwrap_or_default()),
            Type::ExpandString => RegValue::ExpandSz(String::try_from(v).unwrap_or_default()),
            Type::U32 => RegValue::Dword(u32::try_from(v).unwrap_or_default()),
            Type::U64 => RegValue::Qword(u64::try_from(v).unwrap_or_default()),
            Type::MultiString => {
                // Se descartan las cadenas vacías del terminador doble NUL.
                let mut l = Vec::<String>::try_from(v).unwrap_or_default();
                while l.last().is_some_and(String::is_empty) {
                    l.pop();
                }
                RegValue::MultiSz(l)
            }
            _ => RegValue::Other(v.to_vec()),
        }
    }

    impl Registry for WindowsRegistry {
        fn read(&self, hive: Hive, key: &str, name: &str) -> io::Result<Option<RegValue>> {
            let Some(k) = open_read(hive, key)? else {
                return Ok(None);
            };
            match k.get_value(name) {
                Ok(v) => Ok(Some(convert(v))),
                Err(e) if not_found(&e) => Ok(None),
                Err(e) => Err(to_io(e)),
            }
        }

        fn values(&self, hive: Hive, key: &str) -> io::Result<Option<Vec<(String, RegValue)>>> {
            let Some(k) = open_read(hive, key)? else {
                return Ok(None);
            };
            let it = k.values().map_err(to_io)?;
            Ok(Some(it.map(|(n, v)| (n, convert(v))).collect()))
        }

        fn subkeys(&self, hive: Hive, key: &str) -> io::Result<Option<Vec<String>>> {
            let Some(k) = open_read(hive, key)? else {
                return Ok(None);
            };
            let it = k.keys().map_err(to_io)?;
            Ok(Some(it.collect()))
        }

        fn write(&self, hive: Hive, key: &str, name: &str, value: &RegValue) -> io::Result<()> {
            let k = open_write(hive, key)?;
            let r = match value {
                RegValue::Sz(s) => k.set_string(name, s),
                RegValue::ExpandSz(s) => k.set_expand_string(name, s),
                RegValue::Dword(d) => k.set_u32(name, *d),
                RegValue::Qword(d) => k.set_u64(name, *d),
                RegValue::MultiSz(v) => {
                    let refs: Vec<&str> = v.iter().map(String::as_str).collect();
                    k.set_multi_string(name, &refs)
                }
                RegValue::Other(b) => k.set_bytes(name, Type::Bytes, b),
            };
            r.map_err(to_io)
        }

        fn create_key(&self, hive: Hive, key: &str) -> io::Result<()> {
            open_write(hive, key).map(|_| ())
        }

        fn delete_value(&self, hive: Hive, key: &str, name: &str) -> io::Result<bool> {
            let k = match root(hive).options().read().write().access(KEY_WOW64_64KEY).open(key) {
                Ok(k) => k,
                Err(e) if not_found(&e) => return Ok(false),
                Err(e) => return Err(to_io(e)),
            };
            match k.remove_value(name) {
                Ok(()) => Ok(true),
                Err(e) if not_found(&e) => Ok(false),
                Err(e) => Err(to_io(e)),
            }
        }

        fn delete_tree(&self, hive: Hive, key: &str) -> io::Result<bool> {
            let (parent, leaf) = match key.trim_matches('\\').rsplit_once('\\') {
                Some((p, l)) => (p.to_string(), l.to_string()),
                None => (String::new(), key.trim_matches('\\').to_string()),
            };
            let p = match root(hive)
                .options()
                .read()
                .write()
                .access(KEY_WOW64_64KEY)
                .open(&parent)
            {
                Ok(k) => k,
                Err(e) if not_found(&e) => return Ok(false),
                Err(e) => return Err(to_io(e)),
            };
            match p.remove_tree(&leaf) {
                Ok(()) => Ok(true),
                Err(e) if not_found(&e) => Ok(false),
                Err(e) => Err(to_io(e)),
            }
        }
    }
}

/// Registro del sistema actual: el real en Windows, uno vacío y de solo lectura en el resto.
pub fn system_registry() -> std::sync::Arc<dyn Registry> {
    #[cfg(windows)]
    {
        std::sync::Arc::new(WindowsRegistry)
    }
    #[cfg(not(windows))]
    {
        std::sync::Arc::new(MemoryRegistry::read_only())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memoria_insensible_a_mayusculas() {
        let r = MemoryRegistry::new();
        r.write(
            Hive::CurrentUser,
            r"Software\Classes\afirma",
            "URL Protocol",
            &RegValue::Sz(String::new()),
        )
        .unwrap();
        r.write(
            Hive::CurrentUser,
            r"Software\Classes\afirma\shell\open\command",
            "",
            &RegValue::Sz("x".into()),
        )
        .unwrap();
        assert_eq!(
            r.read_string(Hive::CurrentUser, r"SOFTWARE\classes\AFIRMA", "url protocol")
                .unwrap(),
            Some(String::new())
        );
        assert_eq!(
            r.subkeys(Hive::CurrentUser, r"Software\Classes").unwrap(),
            Some(vec!["afirma".to_string()])
        );
        assert!(r.delete_tree(Hive::CurrentUser, r"Software\Classes\afirma").unwrap());
        assert!(
            !r.key_exists(Hive::CurrentUser, r"Software\Classes\afirma\shell")
                .unwrap()
        );
        assert!(r.key_exists(Hive::CurrentUser, r"Software\Classes").unwrap());
    }
}
