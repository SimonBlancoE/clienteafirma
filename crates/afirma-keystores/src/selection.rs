//! Selección del almacén de claves (especificación §9): resolución de
//! nombres (`SimpleKeyStoreManager.getKeyStore`), parámetros del protocolo
//! (`keystore`/`ksb64`), precedencia en las operaciones del protocolo,
//! almacén por defecto de la aplicación, opción `-store` de la línea de
//! comandos, detección del perfil temporal de Windows y menú de cambio de
//! almacén del diálogo.

use std::path::{Component, Path, PathBuf};

use crate::kind::{KeyStoreKind, Os};
use crate::registered::RegisteredCards;

/// Almacén pedido: tipo, fichero/biblioteca y, para tarjetas registradas,
/// su nombre (Java muta el nombre visible de `PKCS11`; aquí se lleva aparte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSpec {
    pub kind: KeyStoreKind,
    /// Fichero PKCS#12 o biblioteca PKCS#11.
    pub lib: Option<String>,
    /// Nombre de la tarjeta registrada (solo con `PKCS11`).
    pub card_name: Option<String>,
}

impl StoreSpec {
    pub fn new(kind: KeyStoreKind) -> Self {
        StoreSpec {
            kind,
            lib: None,
            card_name: None,
        }
    }

    pub fn with_lib(kind: KeyStoreKind, lib: impl Into<String>) -> Self {
        StoreSpec {
            kind,
            lib: Some(lib.into()),
            card_name: None,
        }
    }

    /// Nombre visible del almacén (el de la tarjeta si es una registrada).
    pub fn display_name(&self) -> String {
        self.card_name
            .clone()
            .unwrap_or_else(|| self.kind.display_name().to_string())
    }
}

/// Resuelve el nombre de un almacén (§9.1):
/// 1. nombre visible sin mayúsculas y recortado (`MOZ_UNI` → `MOZ_UNI_WITH_OS`
///    si se invoca desde el navegador);
/// 2. tarjeta registrada (nombre exacto) → `PKCS11` con su biblioteca;
/// 3. identificador exacto (`AOKeyStore.valueOf`, sin recortar);
/// 4. si no, `None` ("Almacen de claves no reconocido").
pub fn resolve_store_name(
    name: Option<&str>,
    invoked_from_browser: bool,
    cards: &RegisteredCards,
) -> Option<StoreSpec> {
    let name = name?;
    let browser = |k: KeyStoreKind| {
        if k == KeyStoreKind::MozUni && invoked_from_browser {
            KeyStoreKind::MozUniWithOs
        } else {
            k
        }
    };
    if let Some(k) = KeyStoreKind::from_display_name(name) {
        return Some(StoreSpec::new(browser(k)));
    }
    if let Some(card) = cards.find(name) {
        return Some(StoreSpec {
            kind: KeyStoreKind::Pkcs11,
            lib: Some(card.library.to_string_lossy().into_owned()),
            card_name: Some(card.name.clone()),
        });
    }
    if let Some(k) = KeyStoreKind::from_id(name) {
        return Some(StoreSpec::new(browser(k)));
    }
    tracing::warn!("Almacen de claves no reconocido ({name})");
    None
}

/// Texto del parámetro de almacén del protocolo: `keystore` (texto plano)
/// tiene prioridad sobre `ksb64` (Base64, aquí en alfabeto estándar o
/// URL-safe; Java solo acepta el estándar). Un `ksb64` no decodificable se
/// ignora.
pub fn protocol_keystore_text(keystore: Option<&str>, ksb64: Option<&str>) -> Option<String> {
    if let Some(k) = keystore {
        return Some(k.to_string());
    }
    let b = afirma_core::base64_decode_lenient(ksb64?).ok()?;
    Some(String::from_utf8_lossy(&b).into_owned())
}

/// Divide el texto `"<ALMACÉN>"` o `"<ALMACÉN>:<fichero>"` del protocolo
/// (`UrlParameters.getKeyStoreName` / `getDefaultKeyStoreLib`): el nombre
/// es lo anterior al primer `:` (recortado) o todo el texto; el fichero es
/// lo posterior sin comillas, recortado y canónico. `":"` no es un almacén.
pub fn split_keystore_text(text: &str) -> (Option<String>, Option<String>) {
    let name = match text.find(':') {
        None => Some(text.to_string()),
        Some(pos) if text.len() > 1 => Some(text[..pos].trim().to_string()),
        Some(_) => None,
    };
    let lib = match text.find(':') {
        Some(pos) if pos < text.len() - 1 => cleanup_path(&text[pos + 1..]),
        _ => None,
    };
    (name, lib)
}

/// Limpia una ruta como Java (`cleanupPath`): sin comillas dobles ni
/// simples, recortada y canónica (`File.getCanonicalPath`, que no exige que
/// exista).
pub fn cleanup_path(path: &str) -> Option<String> {
    let cleaned = path.trim().replace(['"', '\''], "");
    if cleaned.is_empty() {
        return None;
    }
    Some(canonical_path(Path::new(&cleaned)).to_string_lossy().into_owned())
}

/// Ruta canónica: la real si existe; si no, absoluta y normalizada.
pub fn canonical_path(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        // En Windows `canonicalize` devuelve rutas `\\?\C:\...`.
        let s = c.to_string_lossy();
        if let Some(rest) = s.strip_prefix(r"\\?\")
            && !rest.starts_with("UNC\\")
        {
            return PathBuf::from(rest);
        }
        return c;
    }
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Almacén pedido en una URL del protocolo (resuelto como invocado desde el
/// navegador). Devuelve `None` si no se pidió ninguno o no se reconoce.
pub fn protocol_store(keystore: Option<&str>, ksb64: Option<&str>, cards: &RegisteredCards) -> Option<StoreSpec> {
    let text = protocol_keystore_text(keystore, ksb64)?;
    let (name, lib) = split_keystore_text(&text);
    let mut spec = resolve_store_name(name.as_deref(), true, cards)?;
    if lib.is_some() {
        spec.lib = lib;
    }
    Some(spec)
}

/// Preferencias que intervienen en la elección del almacén.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePreferences {
    /// `defaultKeystore` (`"default"` = el del sistema).
    pub default_keystore: String,
    /// `defaultLocalKeystorePath`.
    pub default_local_keystore_path: String,
    /// `useDefaultStoreInBrowserCalls`.
    pub use_default_store_in_browser_calls: bool,
}

impl Default for StorePreferences {
    fn default() -> Self {
        StorePreferences {
            default_keystore: "default".into(),
            default_local_keystore_path: String::new(),
            use_default_store_in_browser_calls: false,
        }
    }
}

/// Valida un almacén de preferencias (`getValidKeyStoreType`): `MOZ_UNI`
/// solo si Firefox está disponible, `WINDOWS` solo en Windows, `APPLE` solo
/// en macOS; en otro caso, el del sistema.
pub fn validate_preference_store(kind: KeyStoreKind, os: Os, firefox_available: bool) -> Option<KeyStoreKind> {
    let ok = match kind {
        KeyStoreKind::MozUni | KeyStoreKind::MozUniWithOs => firefox_available,
        KeyStoreKind::Windows => os == Os::Windows,
        KeyStoreKind::Apple => os == Os::MacOs,
        _ => true,
    };
    if ok { Some(kind) } else { KeyStoreKind::default_for(os) }
}

fn with_pref_lib(mut spec: StoreSpec, prefs: &StorePreferences) -> StoreSpec {
    if matches!(spec.kind, KeyStoreKind::Pkcs12 | KeyStoreKind::Pkcs11)
        && spec.lib.is_none()
        && !prefs.default_local_keystore_path.is_empty()
    {
        spec.lib = Some(prefs.default_local_keystore_path.clone());
    }
    spec
}

/// Almacén de una operación del protocolo (`sign`, `signandsave`, `batch`,
/// `selectcert`), §9.2; el primero que aplique:
/// 1. (la clave "sticky" la gestiona el llamante antes de llamar aquí);
/// 2. el último almacén elegido en el diálogo en este proceso (validado);
/// 3. si `useDefaultStoreInBrowserCalls`, la preferencia `defaultKeystore`
///    (salvo `"default"`) con `defaultLocalKeystorePath` para PKCS#12/#11;
/// 4. el almacén de la URL;
/// 5. el del sistema.
///
/// En los pasos 2 y 4 el fichero/biblioteca es el de la URL (o el de la
/// preferencia en el paso 3), no el recordado (como Java).
pub fn protocol_store_choice(
    last_selected: Option<&StoreSpec>,
    prefs: &StorePreferences,
    url_store: Option<&StoreSpec>,
    cards: &RegisteredCards,
    os: Os,
    firefox_available: bool,
) -> Option<StoreSpec> {
    let url_lib = url_store.and_then(|s| s.lib.clone());
    if let Some(last) = last_selected {
        let kind = validate_preference_store(last.kind, os, firefox_available)?;
        let kind = if kind == KeyStoreKind::MozUni {
            KeyStoreKind::MozUniWithOs
        } else {
            kind
        };
        let mut spec = StoreSpec {
            kind,
            lib: url_lib,
            card_name: last.card_name.clone(),
        };
        if prefs.use_default_store_in_browser_calls {
            spec = with_pref_lib(spec, prefs);
        }
        return Some(spec);
    }
    if prefs.use_default_store_in_browser_calls
        && !prefs.default_keystore.eq_ignore_ascii_case("default")
        && let Some(spec) = resolve_store_name(Some(&prefs.default_keystore), true, cards)
    {
        let kind = validate_preference_store(spec.kind, os, firefox_available)?;
        let kind = if kind == KeyStoreKind::MozUni {
            KeyStoreKind::MozUniWithOs
        } else {
            kind
        };
        return Some(with_pref_lib(StoreSpec { kind, ..spec }, prefs));
    }
    if let Some(u) = url_store {
        return Some(u.clone());
    }
    KeyStoreKind::default_for(os).map(StoreSpec::new)
}

/// Almacén que se precarga en segundo plano al empezar una invocación del
/// protocolo: pasos 2–3 de [`protocol_store_choice`] sin PKCS#12/PKCS#11, y
/// el del sistema salvo que sea `WINDOWS`, `APPLE`, `SHARED_NSS` o
/// `MOZ_UNI` (así, `MOZ_UNI_WITH_OS` se sustituye por el del sistema, como
/// en Java).
pub fn preload_store_choice(
    last_selected: Option<&StoreSpec>,
    prefs: &StorePreferences,
    cards: &RegisteredCards,
    os: Os,
    firefox_available: bool,
) -> Option<StoreSpec> {
    let chosen = if let Some(last) = last_selected {
        validate_preference_store(last.kind, os, firefox_available)
    } else if prefs.use_default_store_in_browser_calls && !prefs.default_keystore.eq_ignore_ascii_case("default") {
        resolve_store_name(Some(&prefs.default_keystore), true, cards)
            .and_then(|s| validate_preference_store(s.kind, os, firefox_available))
    } else {
        None
    };
    let kind = match chosen {
        Some(k @ (KeyStoreKind::Windows | KeyStoreKind::Apple | KeyStoreKind::SharedNss | KeyStoreKind::MozUni)) => k,
        _ => KeyStoreKind::default_for(os)?,
    };
    Some(StoreSpec::new(kind))
}

/// Almacén por defecto de la aplicación local (§9.3): preferencia
/// `defaultKeystore` (`"default"` → el del sistema), validada, con
/// `defaultLocalKeystorePath` para PKCS#12/PKCS#11.
pub fn local_default_store(
    prefs: &StorePreferences,
    cards: &RegisteredCards,
    os: Os,
    firefox_available: bool,
) -> Option<StoreSpec> {
    if prefs.default_keystore.is_empty() || prefs.default_keystore.eq_ignore_ascii_case("default") {
        return KeyStoreKind::default_for(os).map(StoreSpec::new);
    }
    match resolve_store_name(Some(&prefs.default_keystore), false, cards) {
        Some(spec) => {
            let kind = validate_preference_store(spec.kind, os, firefox_available)?;
            Some(with_pref_lib(StoreSpec { kind, ..spec }, prefs))
        }
        None => KeyStoreKind::default_for(os).map(StoreSpec::new),
    }
}

/// Error de la opción `-store` de la línea de comandos.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliStoreError {
    /// `CommandLineLauncher.48`.
    #[error("Tipo de almacen desconocido: {0}")]
    Unknown(String),
    #[error("El fichero PKCS#12 indicado no existe: {0}")]
    Pkcs12NotFound(String),
    #[error("No se tienen permisos de lectura para el fichero PKCS#12 indicado: {0}")]
    Pkcs12NotReadable(String),
    #[error("La biblioteca PKCS#11 indicada no existe: {0}")]
    Pkcs11NotFound(String),
    #[error("No se tienen permisos de lectura para la biblioteca PKCS#11 indicada: {0}")]
    Pkcs11NotReadable(String),
}

/// Interpreta `-store` (§9.4; valores exactos, sensibles a mayúsculas):
/// `auto` (o ausente), `windows`, `mac`, `mozilla`, `dni`/`dnie`,
/// `pkcs12:<fichero>`, `pkcs11:<biblioteca>`.
///
/// Diferencia con Java: para PKCS#12 se usa la ruta limpia (sin comillas,
/// canónica) y no el texto original.
pub fn parse_cli_store(value: Option<&str>, os: Os) -> Result<StoreSpec, CliStoreError> {
    let v = match value {
        None | Some("auto") => {
            return Ok(StoreSpec::new(match os {
                Os::MacOs => KeyStoreKind::Apple,
                Os::Windows => KeyStoreKind::Windows,
                _ => KeyStoreKind::SharedNss,
            }));
        }
        Some(v) => v,
    };
    match v {
        "mac" => return Ok(StoreSpec::new(KeyStoreKind::Apple)),
        "windows" => return Ok(StoreSpec::new(KeyStoreKind::Windows)),
        "mozilla" => return Ok(StoreSpec::new(KeyStoreKind::MozUni)),
        "dni" | "dnie" => return Ok(StoreSpec::new(KeyStoreKind::DnieJava)),
        _ => {}
    }
    let check = |prefix: &str, kind: KeyStoreKind| -> Option<Result<StoreSpec, CliStoreError>> {
        if !v.starts_with(prefix) {
            return None;
        }
        // Java: `replace("pkcs12:", "")` quita todas las apariciones.
        let raw = v.replace(prefix, "");
        let cleaned = cleanup_path(&raw)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(&raw));
        type ErrorCtor = fn(String) -> CliStoreError;
        let (nf, nr): (ErrorCtor, ErrorCtor) = if kind == KeyStoreKind::Pkcs12 {
            (CliStoreError::Pkcs12NotFound, CliStoreError::Pkcs12NotReadable)
        } else {
            (CliStoreError::Pkcs11NotFound, CliStoreError::Pkcs11NotReadable)
        };
        if !cleaned.exists() {
            return Some(Err(nf(raw)));
        }
        if std::fs::File::open(&cleaned).is_err() {
            return Some(Err(nr(raw)));
        }
        Some(Ok(StoreSpec::with_lib(kind, cleaned.to_string_lossy())))
    };
    check("pkcs12:", KeyStoreKind::Pkcs12)
        .or_else(|| check("pkcs11:", KeyStoreKind::Pkcs11))
        .unwrap_or_else(|| Err(CliStoreError::Unknown(v.to_string())))
}

/// Perfil temporal de Windows (§3.1.2): `user.name` y `USERPROFILE`
/// existen, el nombre del perfil (último componente de `USERPROFILE`)
/// difiere del usuario y es `TEMP` o empieza por `TEMP.`.
pub fn is_temporary_profile(user_name: Option<&str>, user_profile: Option<&str>) -> bool {
    let (Some(user), Some(profile)) = (user_name, user_profile) else {
        return false;
    };
    let name = profile
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(profile);
    user != name && (name == "TEMP" || name.starts_with("TEMP."))
}

/// Perfil temporal del proceso actual (Windows).
pub fn is_current_temporary_profile() -> bool {
    let user = std::env::var("USERNAME").ok();
    let profile = std::env::var("USERPROFILE").ok();
    is_temporary_profile(user.as_deref(), profile.as_deref())
}

/// Entrada del menú "Cambiar almacén de claves" del diálogo (§8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitcherItem {
    /// "Almacén de claves del sistema" (id 1).
    System,
    /// "Almacén de claves de Mozilla Firefox" (id 2).
    Firefox,
    /// "Almacén de claves en fichero (PFX/PKCS#12)" (id 3).
    Pkcs12File,
    /// "DNI electrónico" (id 4).
    Dnie,
    /// Tarjeta registrada (id 5): nombre y biblioteca.
    Card { name: String, library: PathBuf },
}

impl SwitcherItem {
    /// Texto del menú (`CertificateSelectionPanel.35`–`.38` o el nombre de
    /// la tarjeta).
    pub fn label(&self) -> String {
        match self {
            SwitcherItem::System => "Almacén de claves del sistema".into(),
            SwitcherItem::Firefox => "Almacén de claves de Mozilla Firefox".into(),
            SwitcherItem::Pkcs12File => "Almacén de claves en fichero (PFX/PKCS#12)".into(),
            SwitcherItem::Dnie => "DNI electrónico".into(),
            SwitcherItem::Card { name, .. } => name.clone(),
        }
    }

    /// Identificador numérico de Java.
    pub fn id(&self) -> u32 {
        match self {
            SwitcherItem::System => 1,
            SwitcherItem::Firefox => 2,
            SwitcherItem::Pkcs12File => 3,
            SwitcherItem::Dnie => 4,
            SwitcherItem::Card { .. } => 5,
        }
    }

    /// Almacén que abre la entrada (`changeKeyStoreManager`). El fichero
    /// PKCS#12 lo elige el usuario (selector de ficheros de la interfaz).
    pub fn store(&self, os: Os, invoked_from_browser: bool) -> Option<StoreSpec> {
        Some(match self {
            SwitcherItem::System => StoreSpec::new(KeyStoreKind::default_for(os)?),
            SwitcherItem::Firefox => StoreSpec::new(if invoked_from_browser {
                KeyStoreKind::MozUniWithOs
            } else {
                KeyStoreKind::MozUni
            }),
            SwitcherItem::Pkcs12File => StoreSpec::new(KeyStoreKind::Pkcs12),
            SwitcherItem::Dnie => StoreSpec::new(KeyStoreKind::DnieJava),
            SwitcherItem::Card { name, library } => StoreSpec {
                kind: KeyStoreKind::Pkcs11,
                lib: Some(library.to_string_lossy().into_owned()),
                card_name: Some(name.clone()),
            },
        })
    }
}

/// Entradas del menú de cambio de almacén (§8.4): Windows/macOS: sistema,
/// Firefox, PKCS#12, DNIe; Linux: sistema, PKCS#12, DNIe si el almacén
/// actual es `SHARED_NSS` y Firefox, PKCS#12, DNIe en otro caso (NSS no se
/// puede reinicializar con otra base de datos en el mismo proceso); después
/// las tarjetas de usuario y las de sistema.
///
/// Nota: Java informaba `SHARED_NSS` también para un almacén de Firefox
/// recién abierto (fallo 3.6.10); aquí se usa el tipo real.
pub fn switcher_items(os: Os, current: KeyStoreKind, cards: &RegisteredCards) -> Vec<SwitcherItem> {
    let mut v = match os {
        Os::Windows | Os::MacOs => vec![
            SwitcherItem::System,
            SwitcherItem::Firefox,
            SwitcherItem::Pkcs12File,
            SwitcherItem::Dnie,
        ],
        _ if current == KeyStoreKind::SharedNss => {
            vec![SwitcherItem::System, SwitcherItem::Pkcs12File, SwitcherItem::Dnie]
        }
        _ => vec![SwitcherItem::Firefox, SwitcherItem::Pkcs12File, SwitcherItem::Dnie],
    };
    v.extend(cards.all().map(|c| SwitcherItem::Card {
        name: c.name.clone(),
        library: c.library.clone(),
    }));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registered::{CardScope, RegisteredCard};

    fn cards() -> RegisteredCards {
        RegisteredCards {
            user: vec![RegisteredCard {
                name: "Mi tarjeta".into(),
                library: "/usr/lib/libmi.so".into(),
                node: "1".into(),
                scope: CardScope::User,
            }],
            system: vec![],
        }
    }

    #[test]
    fn name_resolution() {
        let c = cards();
        assert_eq!(
            resolve_store_name(Some(" windows "), false, &c).unwrap().kind,
            KeyStoreKind::Windows
        );
        assert_eq!(
            resolve_store_name(Some("Mozilla / Firefox (unificado)"), true, &c)
                .unwrap()
                .kind,
            KeyStoreKind::MozUniWithOs
        );
        assert_eq!(
            resolve_store_name(Some("MOZ_UNI"), true, &c).unwrap().kind,
            KeyStoreKind::MozUniWithOs
        );
        assert_eq!(
            resolve_store_name(Some("MOZ_UNI"), false, &c).unwrap().kind,
            KeyStoreKind::MozUni
        );
        assert_eq!(
            resolve_store_name(Some("PKCS12"), true, &c).unwrap().kind,
            KeyStoreKind::Pkcs12
        );
        assert_eq!(
            resolve_store_name(Some("DNIEJAVA"), true, &c).unwrap().kind,
            KeyStoreKind::DnieJava
        );
        assert!(
            resolve_store_name(Some("pkcs12"), true, &c).is_none(),
            "valueOf es sensible a mayúsculas"
        );
        assert!(
            resolve_store_name(Some(" PKCS12"), true, &c).is_none(),
            "valueOf no recorta"
        );
        let card = resolve_store_name(Some("Mi tarjeta"), true, &c).unwrap();
        assert_eq!(card.kind, KeyStoreKind::Pkcs11);
        assert_eq!(card.lib.as_deref(), Some("/usr/lib/libmi.so"));
        assert_eq!(card.display_name(), "Mi tarjeta");
        assert!(resolve_store_name(None, true, &c).is_none());
    }

    #[test]
    fn protocol_params() {
        let c = cards();
        assert_eq!(split_keystore_text("PKCS12"), (Some("PKCS12".into()), None));
        assert_eq!(split_keystore_text(":"), (None, None));
        assert_eq!(split_keystore_text("PKCS12:"), (Some("PKCS12".into()), None));
        let (n, l) = split_keystore_text(" PKCS12 : \"/tmp/a'b.p12\" ");
        assert_eq!(n.as_deref(), Some("PKCS12"));
        assert!(l.as_deref().unwrap().ends_with("ab.p12"));
        #[cfg(unix)]
        {
            assert_eq!(l.as_deref(), Some("/tmp/ab.p12"));
            let (_, l) = split_keystore_text("PKCS11:/opt/../usr/lib/x.so");
            assert_eq!(l.as_deref(), Some("/usr/lib/x.so"));
        }
        // keystore tiene prioridad; ksb64 en Base64 estándar y URL-safe.
        let std_b64 = afirma_core::base64_encode("PKCS12:/tmp/~~~.p12".as_bytes());
        let url_b64 = afirma_core::base64_encode_url_safe("PKCS12:/tmp/~~~.p12".as_bytes());
        assert!(std_b64.contains('+') && url_b64.contains('-'));
        for b in [&std_b64, &url_b64] {
            let s = protocol_store(None, Some(b), &c).unwrap();
            assert_eq!(s.kind, KeyStoreKind::Pkcs12);
            assert_eq!(s.lib.as_deref(), cleanup_path("/tmp/~~~.p12").as_deref());
        }
        assert_eq!(
            protocol_store(Some("WINDOWS"), Some(&std_b64), &c).unwrap().kind,
            KeyStoreKind::Windows
        );
        assert!(protocol_store(None, Some("%%%"), &c).is_none());
        assert_eq!(
            protocol_store(Some("MOZ_UNI"), None, &c).unwrap().kind,
            KeyStoreKind::MozUniWithOs
        );
    }

    #[test]
    fn protocol_precedence() {
        let c = cards();
        let url = StoreSpec::with_lib(KeyStoreKind::Pkcs12, "/tmp/u.p12");
        let prefs = StorePreferences::default();
        // URL.
        assert_eq!(
            protocol_store_choice(None, &prefs, Some(&url), &c, Os::Linux, false).unwrap(),
            url
        );
        // Sin URL: el del sistema.
        assert_eq!(
            protocol_store_choice(None, &prefs, None, &c, Os::Linux, false)
                .unwrap()
                .kind,
            KeyStoreKind::SharedNss
        );
        // Preferencia en llamadas del navegador.
        let p2 = StorePreferences {
            default_keystore: "Mi tarjeta".into(),
            use_default_store_in_browser_calls: true,
            ..Default::default()
        };
        let s = protocol_store_choice(None, &p2, Some(&url), &c, Os::Linux, false).unwrap();
        assert_eq!(
            (s.kind, s.lib.as_deref()),
            (KeyStoreKind::Pkcs11, Some("/usr/lib/libmi.so"))
        );
        // Último elegido en el diálogo, con la biblioteca de la URL.
        let last = StoreSpec::new(KeyStoreKind::MozUni);
        let s = protocol_store_choice(Some(&last), &p2, Some(&url), &c, Os::Windows, true).unwrap();
        assert_eq!(
            (s.kind, s.lib.as_deref()),
            (KeyStoreKind::MozUniWithOs, Some("/tmp/u.p12"))
        );
        // Firefox no disponible → el del sistema.
        let s = protocol_store_choice(Some(&last), &prefs, None, &c, Os::Windows, false).unwrap();
        assert_eq!(s.kind, KeyStoreKind::Windows);
        // Precarga: MOZ_UNI_WITH_OS no está en la lista → sistema.
        assert_eq!(
            preload_store_choice(Some(&last), &prefs, &c, Os::Linux, true)
                .unwrap()
                .kind,
            KeyStoreKind::MozUni
        );
        let p3 = StorePreferences {
            default_keystore: "PKCS#12 / PFX".into(),
            use_default_store_in_browser_calls: true,
            ..Default::default()
        };
        assert_eq!(
            preload_store_choice(None, &p3, &c, Os::MacOs, false).unwrap().kind,
            KeyStoreKind::Apple
        );
    }

    #[test]
    fn local_default() {
        let c = cards();
        assert_eq!(
            local_default_store(&StorePreferences::default(), &c, Os::MacOs, false)
                .unwrap()
                .kind,
            KeyStoreKind::Apple
        );
        let p = StorePreferences {
            default_keystore: "PKCS#12 / PFX".into(),
            default_local_keystore_path: "/tmp/x.p12".into(),
            ..Default::default()
        };
        let s = local_default_store(&p, &c, Os::Linux, false).unwrap();
        assert_eq!((s.kind, s.lib.as_deref()), (KeyStoreKind::Pkcs12, Some("/tmp/x.p12")));
        let p = StorePreferences {
            default_keystore: "Windows".into(),
            ..Default::default()
        };
        assert_eq!(
            local_default_store(&p, &c, Os::Linux, false).unwrap().kind,
            KeyStoreKind::SharedNss
        );
    }

    #[test]
    fn cli_store() {
        assert_eq!(parse_cli_store(None, Os::Linux).unwrap().kind, KeyStoreKind::SharedNss);
        assert_eq!(
            parse_cli_store(Some("auto"), Os::Solaris).unwrap().kind,
            KeyStoreKind::SharedNss
        );
        assert_eq!(
            parse_cli_store(Some("auto"), Os::MacOs).unwrap().kind,
            KeyStoreKind::Apple
        );
        assert_eq!(
            parse_cli_store(Some("windows"), Os::Linux).unwrap().kind,
            KeyStoreKind::Windows
        );
        assert_eq!(
            parse_cli_store(Some("mozilla"), Os::Linux).unwrap().kind,
            KeyStoreKind::MozUni
        );
        assert_eq!(
            parse_cli_store(Some("dnie"), Os::Linux).unwrap().kind,
            KeyStoreKind::DnieJava
        );
        assert_eq!(
            parse_cli_store(Some("Windows"), Os::Linux).unwrap_err().to_string(),
            "Tipo de almacen desconocido: Windows"
        );
        let p12 = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki/firmante-rsa.p12");
        let s = parse_cli_store(Some(&format!("pkcs12:\"{}\"", p12.display())), Os::Linux).unwrap();
        assert_eq!(s.kind, KeyStoreKind::Pkcs12);
        assert_eq!(PathBuf::from(s.lib.unwrap()), canonical_path(&p12));
        assert_eq!(
            parse_cli_store(Some("pkcs12:/no/existe.p12"), Os::Linux)
                .unwrap_err()
                .to_string(),
            "El fichero PKCS#12 indicado no existe: /no/existe.p12"
        );
        assert_eq!(
            parse_cli_store(Some("pkcs11:/no/existe.so"), Os::Linux)
                .unwrap_err()
                .to_string(),
            "La biblioteca PKCS#11 indicada no existe: /no/existe.so"
        );
    }

    #[test]
    fn temporary_profile() {
        assert!(is_temporary_profile(Some("juan"), Some("C:\\Users\\TEMP")));
        assert!(is_temporary_profile(Some("juan"), Some("C:\\Users\\TEMP.DOMINIO.001")));
        assert!(!is_temporary_profile(Some("TEMP"), Some("C:\\Users\\TEMP")));
        assert!(!is_temporary_profile(Some("juan"), Some("C:\\Users\\juan")));
        assert!(!is_temporary_profile(None, Some("C:\\Users\\TEMP")));
    }

    #[test]
    fn switcher() {
        let c = cards();
        let ids = |v: Vec<SwitcherItem>| v.iter().map(SwitcherItem::id).collect::<Vec<_>>();
        assert_eq!(
            ids(switcher_items(Os::Windows, KeyStoreKind::Windows, &c)),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            ids(switcher_items(Os::Linux, KeyStoreKind::SharedNss, &c)),
            vec![1, 3, 4, 5]
        );
        assert_eq!(
            ids(switcher_items(Os::Linux, KeyStoreKind::MozUni, &c)),
            vec![2, 3, 4, 5]
        );
        assert_eq!(
            SwitcherItem::Firefox.store(Os::Linux, true).unwrap().kind,
            KeyStoreKind::MozUniWithOs
        );
        assert_eq!(
            SwitcherItem::System.store(Os::Linux, true).unwrap().kind,
            KeyStoreKind::SharedNss
        );
        assert_eq!(
            switcher_items(Os::Linux, KeyStoreKind::MozUni, &c)[3].label(),
            "Mi tarjeta"
        );
    }
}
