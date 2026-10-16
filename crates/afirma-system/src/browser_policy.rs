//! Directivas de navegadores para despliegues corporativos sin avisos (**nuevo**: la versión
//! Java no configuraba ninguna).
//!
//! * Chrome/Edge/Chromium/Brave: `AutoLaunchProtocolsFromOrigins` (esquema `afirma`, orígenes
//!   configurables o `*`), `ExternalProtocolDialogShowAlwaysOpenCheckbox` y, con orígenes
//!   explícitos, `LocalNetworkAccessAllowedForUrls` / `InsecurePrivateNetworkRequestsAllowedForUrls`
//!   (acceso de la sede web al servidor local `wss://127.0.0.1`).
//! * Firefox: `Handlers.schemes.afirma` (`useSystemDefault`, `ask: false`) y
//!   `Certificates.ImportEnterpriseRoots`.
//!
//! Ubicaciones: Windows `HKLM\SOFTWARE\Policies\...`; Linux ficheros JSON en
//! `/etc/opt/chrome/policies/managed/`, `/etc/chromium*/policies/managed/`,
//! `/etc/opt/edge/policies/managed/`, `/etc/brave/policies/managed/` y
//! `/etc/firefox/policies/policies.json`; macOS `/Library/Managed Preferences/<dominio>.plist`
//! y `Firefox.app/Contents/Resources/distribution/policies.json` (en macOS lo recomendable es
//! un perfil MDM: [`macos_mobileconfig`]). También se generan plantillas `.reg` y
//! `.mobileconfig`.
//!
//! Las directivas compartidas se fusionan sin borrar las del administrador; al retirar solo
//! se quitan las entradas de `afirma` y las que AutoFirma creó ([`crate::state`]).

use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::ctx::{Context, Os};
use crate::error::{Result, SystemError};
use crate::fsutil;
use crate::prefs::policy::PolicySet;
use crate::protocol::SCHEME;
use crate::registry::{Hive, RegValue};
use crate::state::OwnedEntries;
use crate::trust::Change;

/// Navegador.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Browser {
    Chrome,
    Edge,
    Chromium,
    Brave,
    Firefox,
}

impl Browser {
    /// Todos.
    pub const ALL: [Browser; 5] = [
        Browser::Chrome,
        Browser::Edge,
        Browser::Chromium,
        Browser::Brave,
        Browser::Firefox,
    ];

    /// Clave de directivas en el registro (HKLM).
    pub fn win_key(self) -> &'static str {
        match self {
            Browser::Chrome => r"SOFTWARE\Policies\Google\Chrome",
            Browser::Edge => r"SOFTWARE\Policies\Microsoft\Edge",
            Browser::Chromium => r"SOFTWARE\Policies\Chromium",
            Browser::Brave => r"SOFTWARE\Policies\BraveSoftware\Brave",
            Browser::Firefox => r"SOFTWARE\Policies\Mozilla\Firefox",
        }
    }

    /// Dominio de preferencias de macOS.
    pub fn mac_domain(self) -> &'static str {
        match self {
            Browser::Chrome => "com.google.Chrome",
            Browser::Edge => "com.microsoft.Edge",
            Browser::Chromium => "org.chromium.Chromium",
            Browser::Brave => "com.brave.Browser",
            Browser::Firefox => "org.mozilla.firefox",
        }
    }

    /// Directorios de directivas obligatorias en Linux.
    pub fn linux_dirs(self) -> &'static [&'static str] {
        match self {
            Browser::Chrome => &["/etc/opt/chrome/policies/managed"],
            Browser::Edge => &["/etc/opt/edge/policies/managed"],
            Browser::Chromium => &[
                "/etc/chromium/policies/managed",
                "/etc/chromium-browser/policies/managed",
            ],
            Browser::Brave => &["/etc/brave/policies/managed"],
            Browser::Firefox => &["/etc/firefox/policies", "/etc/firefox-esr/policies"],
        }
    }

    /// Rutas que indican que el navegador está instalado en Linux.
    fn linux_markers(self) -> &'static [&'static str] {
        match self {
            Browser::Chrome => &["/opt/google/chrome", "/etc/opt/chrome"],
            Browser::Edge => &["/opt/microsoft/msedge", "/etc/opt/edge"],
            Browser::Chromium => &[
                "/usr/lib/chromium",
                "/usr/lib64/chromium",
                "/usr/lib/chromium-browser",
                "/etc/chromium",
                "/etc/chromium-browser",
                "/snap/chromium",
            ],
            Browser::Brave => &["/opt/brave.com", "/etc/brave"],
            Browser::Firefox => &[
                "/usr/lib/firefox",
                "/usr/lib64/firefox",
                "/usr/lib/firefox-esr",
                "/opt/firefox",
                "/etc/firefox",
                "/snap/firefox",
            ],
        }
    }

    /// `true` si es de la familia Chromium.
    pub fn is_chromium(self) -> bool {
        self != Browser::Firefox
    }
}

/// Opciones de las directivas.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserPolicyOptions {
    /// Orígenes autorizados a abrir `afirma://` sin preguntar (`https://sede.example.es`,
    /// `https://*.example.es` o `*`). Vacío equivale a `*`.
    pub allowed_origins: Vec<String>,
    /// Navegadores.
    pub browsers: Vec<Browser>,
    /// Mostrar la casilla «Permitir siempre» del diálogo de protocolo externo.
    pub always_open_checkbox: bool,
    /// Permitir a esos orígenes el acceso a la red local (servidor `127.0.0.1`). Solo se aplica
    /// con orígenes explícitos (no con `*`).
    pub local_network_access: bool,
    /// Firefox: confiar en las raíces del almacén del sistema.
    pub firefox_enterprise_roots: bool,
    /// Linux: escribir también para navegadores no detectados.
    pub include_undetected: bool,
}

impl Default for BrowserPolicyOptions {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            browsers: Browser::ALL.to_vec(),
            always_open_checkbox: true,
            local_network_access: true,
            firefox_enterprise_roots: true,
            include_undetected: false,
        }
    }
}

impl BrowserPolicyOptions {
    fn origins(&self) -> Vec<String> {
        let v: Vec<String> = self
            .allowed_origins
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if v.is_empty() { vec!["*".into()] } else { v }
    }

    fn explicit_origins(&self) -> bool {
        !self.origins().iter().any(|o| o == "*")
    }
}

/// Origen en formato de `URLBlocklist` (`AutoLaunchProtocolsFromOrigins`): el host incluye
/// sus subdominios, así que `https://*.x.es` → `https://x.es`.
pub fn to_urlblocklist_origin(o: &str) -> String {
    if o == "*" {
        return "*".into();
    }
    o.replacen("://*.", "://", 1)
        .trim_end_matches('/')
        .to_string()
}

/// Origen en formato de patrón de configuración de contenido (`[*.]` para subdominios).
pub fn to_content_pattern(o: &str) -> String {
    if o == "*" {
        return "*".into();
    }
    o.replacen("://*.", "://[*.]", 1)
        .trim_end_matches('/')
        .to_string()
}

/// Valor de `AutoLaunchProtocolsFromOrigins` para `afirma`.
pub fn auto_launch_entry(opts: &BrowserPolicyOptions) -> Value {
    json!({ "protocol": SCHEME, "allowed_origins": opts.origins().iter().map(|o| to_urlblocklist_origin(o)).collect::<Vec<_>>() })
}

/// Directivas de la familia Chromium (como objeto JSON).
pub fn chromium_policies(opts: &BrowserPolicyOptions) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "AutoLaunchProtocolsFromOrigins".into(),
        json!([auto_launch_entry(opts)]),
    );
    if opts.always_open_checkbox {
        m.insert(
            "ExternalProtocolDialogShowAlwaysOpenCheckbox".into(),
            json!(true),
        );
    }
    if opts.local_network_access && opts.explicit_origins() {
        let pats: Vec<String> = opts
            .origins()
            .iter()
            .map(|o| to_content_pattern(o))
            .collect();
        m.insert("LocalNetworkAccessAllowedForUrls".into(), json!(pats));
        m.insert(
            "InsecurePrivateNetworkRequestsAllowedForUrls".into(),
            json!(pats),
        );
    }
    m
}

/// Manejador de Firefox.
pub fn firefox_handler() -> Value {
    json!({ "action": "useSystemDefault", "ask": false })
}

/// Directivas de Firefox (contenido de `policies`).
pub fn firefox_policies(opts: &BrowserPolicyOptions) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "Handlers".into(),
        json!({ "schemes": { SCHEME: firefox_handler() } }),
    );
    if opts.firefox_enterprise_roots {
        m.insert(
            "Certificates".into(),
            json!({ "ImportEnterpriseRoots": true }),
        );
    }
    m
}

const LIST_POLICIES: &[&str] = &[
    "LocalNetworkAccessAllowedForUrls",
    "InsecurePrivateNetworkRequestsAllowedForUrls",
];

// ------------------------------------------------------------------ fusión JSON (Firefox)

/// Fusiona las directivas de Firefox en un `policies.json` existente.
fn merge_firefox_json(
    doc: &mut Value,
    handlers: bool,
    roots: bool,
    owned: &mut OwnedEntries,
    id: &str,
) -> Result<bool> {
    let before = doc.clone();
    let root = doc
        .as_object_mut()
        .ok_or_else(|| SystemError::Other("policies.json no es un objeto".into()))?;
    let pol = root.entry("policies").or_insert_with(|| json!({}));
    let pol = pol
        .as_object_mut()
        .ok_or_else(|| SystemError::Other("«policies» no es un objeto".into()))?;
    if handlers {
        let h = pol.entry("Handlers").or_insert_with(|| json!({}));
        let schemes = h
            .as_object_mut()
            .ok_or_else(|| SystemError::Other("«Handlers» no es un objeto".into()))?
            .entry("schemes")
            .or_insert_with(|| json!({}));
        schemes
            .as_object_mut()
            .ok_or_else(|| SystemError::Other("«schemes» no es un objeto".into()))?
            .insert(SCHEME.into(), firefox_handler());
    }
    if roots {
        let certs = pol.entry("Certificates").or_insert_with(|| json!({}));
        let certs = certs
            .as_object_mut()
            .ok_or_else(|| SystemError::Other("«Certificates» no es un objeto".into()))?;
        if !certs.contains_key("ImportEnterpriseRoots") {
            owned.add(format!("{id}:Certificates.ImportEnterpriseRoots"));
        }
        certs.insert("ImportEnterpriseRoots".into(), json!(true));
    }
    Ok(*doc != before)
}

fn unmerge_firefox_json(doc: &mut Value, owned: &mut OwnedEntries, id: &str) -> bool {
    let before = doc.clone();
    if let Some(pol) = doc.get_mut("policies").and_then(Value::as_object_mut) {
        if let Some(h) = pol.get_mut("Handlers").and_then(Value::as_object_mut) {
            if let Some(s) = h.get_mut("schemes").and_then(Value::as_object_mut) {
                s.remove(SCHEME);
                if s.is_empty() {
                    h.remove("schemes");
                }
            }
            if h.is_empty() {
                pol.remove("Handlers");
            }
        }
        let k = format!("{id}:Certificates.ImportEnterpriseRoots");
        if owned.owns(&k) {
            if let Some(c) = pol.get_mut("Certificates").and_then(Value::as_object_mut) {
                c.remove("ImportEnterpriseRoots");
                if c.is_empty() {
                    pol.remove("Certificates");
                }
            }
            owned.forget(&k);
        }
    }
    *doc != before
}

fn firefox_policy_files(ctx: &Context) -> Vec<PathBuf> {
    match ctx.os {
        Os::Linux => {
            let mut v = vec![ctx.sys("/etc/firefox/policies/policies.json")];
            if ctx.sys("/etc/firefox-esr").is_dir() {
                v.push(ctx.sys("/etc/firefox-esr/policies/policies.json"));
            }
            v
        }
        Os::MacOs => ["/Applications/Firefox.app", "/Applications/Firefox ESR.app"]
            .iter()
            .map(|a| ctx.sys(a))
            .filter(|a| a.is_dir())
            .map(|a| a.join("Contents/Resources/distribution/policies.json"))
            .collect(),
        // `distribution\policies.json` del directorio de instalación (Firefox lo ignora si hay
        // directivas en el registro, por eso también se escribe el registro).
        Os::Windows => crate::trust::windows::firefox_install_dirs(ctx)
            .into_iter()
            .map(|d| d.join("distribution").join("policies.json"))
            .collect(),
    }
}

fn install_firefox_file(
    path: &std::path::Path,
    handlers: bool,
    roots: bool,
    owned: &mut OwnedEntries,
) -> Result<bool> {
    let id = format!("json:{}", path.display());
    let existed = path.is_file();
    let mut doc: Value = match fsutil::read_opt(path)? {
        Some(d) => serde_json::from_slice(&d).map_err(|e| SystemError::Format {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?,
        None => json!({ "policies": {} }),
    };
    if !merge_firefox_json(&mut doc, handlers, roots, owned, &id)? {
        return Ok(false);
    }
    if !existed {
        owned.add(format!("file:{}", path.display()));
    }
    let text = serde_json::to_string_pretty(&doc).map_err(|e| SystemError::Other(e.to_string()))?;
    fsutil::write_atomic(path, text.as_bytes(), Some(0o644))?;
    Ok(true)
}

fn remove_firefox_file(path: &std::path::Path, owned: &mut OwnedEntries) -> Result<bool> {
    let id = format!("json:{}", path.display());
    let Some(d) = fsutil::read_opt(path)? else {
        return Ok(false);
    };
    let Ok(mut doc) = serde_json::from_slice::<Value>(&d) else {
        return Ok(false);
    };
    if !unmerge_firefox_json(&mut doc, owned, &id) {
        return Ok(false);
    }
    let file_id = format!("file:{}", path.display());
    let empty = doc
        .get("policies")
        .and_then(Value::as_object)
        .is_none_or(|m| m.is_empty())
        && doc.as_object().is_some_and(|o| o.len() <= 1);
    if empty && owned.owns(&file_id) {
        fsutil::remove_file_if_exists(path)?;
        owned.forget(&file_id);
    } else {
        let text =
            serde_json::to_string_pretty(&doc).map_err(|e| SystemError::Other(e.to_string()))?;
        fsutil::write_atomic(path, text.as_bytes(), None)?;
    }
    Ok(true)
}

// ------------------------------------------------------------------ Linux

/// Fichero propio de directivas Chromium.
pub const CHROMIUM_POLICY_FILE: &str = "autofirma.json";

fn linux_detected(ctx: &Context, b: Browser) -> bool {
    b.linux_markers().iter().any(|m| ctx.sys(m).exists())
}

/// Ficheros de directivas para Linux (ruta, contenido) — también para desplegarlos con
/// herramientas de gestión de configuración.
pub fn linux_policy_files(opts: &BrowserPolicyOptions) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for b in &opts.browsers {
        if b.is_chromium() {
            let text = serde_json::to_string_pretty(&Value::Object(chromium_policies(opts)))
                .unwrap_or_default();
            for d in b.linux_dirs() {
                v.push((format!("{d}/{CHROMIUM_POLICY_FILE}"), text.clone()));
            }
        } else {
            let text = serde_json::to_string_pretty(
                &json!({ "policies": Value::Object(firefox_policies(opts)) }),
            )
            .unwrap_or_default();
            v.push(("/etc/firefox/policies/policies.json".into(), text));
        }
    }
    v
}

fn install_linux(
    ctx: &Context,
    opts: &BrowserPolicyOptions,
    owned: &mut OwnedEntries,
) -> Result<Change> {
    let mut changed = false;
    for b in &opts.browsers {
        if !opts.include_undetected && !linux_detected(ctx, *b) {
            continue;
        }
        if b.is_chromium() {
            let text = serde_json::to_string_pretty(&Value::Object(chromium_policies(opts)))
                .map_err(|e| SystemError::Other(e.to_string()))?;
            for d in b.linux_dirs() {
                // Chromium de Debian usa /etc/chromium; el de Ubuntu, /etc/chromium-browser.
                let dir = ctx.sys(d);
                if *b == Browser::Chromium
                    && !opts.include_undetected
                    && !dir
                        .parent()
                        .and_then(|p| p.parent())
                        .is_some_and(|p| p.is_dir())
                {
                    continue;
                }
                let p = dir.join(CHROMIUM_POLICY_FILE);
                if fsutil::read_text_opt(&p)?.as_deref() != Some(text.as_str()) {
                    fsutil::write_atomic(&p, text.as_bytes(), Some(0o644))?;
                    changed = true;
                }
            }
        } else {
            for p in firefox_policy_files(ctx) {
                changed |= install_firefox_file(&p, true, opts.firefox_enterprise_roots, owned)?;
            }
        }
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

fn remove_linux(ctx: &Context, owned: &mut OwnedEntries) -> Result<Change> {
    let mut changed = false;
    for b in Browser::ALL {
        if b.is_chromium() {
            for d in b.linux_dirs() {
                let p = ctx.sys(d).join(CHROMIUM_POLICY_FILE);
                if fsutil::read_text_opt(&p)?.is_some_and(|t| t.contains(SCHEME)) {
                    changed |= fsutil::remove_file_if_exists(&p)?;
                }
            }
        }
    }
    for p in firefox_policy_files(ctx) {
        changed |= remove_firefox_file(&p, owned)?;
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

// ------------------------------------------------------------------ Windows

fn reg_err(key: &str, e: std::io::Error) -> SystemError {
    SystemError::Registry {
        key: key.into(),
        detail: e.to_string(),
    }
}

/// Fusiona la entrada `afirma` en el JSON de `AutoLaunchProtocolsFromOrigins`.
pub fn merge_auto_launch(existing: Option<&str>, entry: Option<&Value>) -> Result<Option<String>> {
    let mut list: Vec<Value> = match existing.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => serde_json::from_str(s).map_err(|e| {
            SystemError::Other(format!(
                "AutoLaunchProtocolsFromOrigins no es JSON válido: {e}"
            ))
        })?,
        None => Vec::new(),
    };
    list.retain(|v| v.get("protocol").and_then(Value::as_str) != Some(SCHEME));
    if let Some(e) = entry {
        list.push(e.clone());
    }
    Ok(if list.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&list).map_err(|e| SystemError::Other(e.to_string()))?)
    })
}

fn install_windows(
    ctx: &Context,
    opts: &BrowserPolicyOptions,
    owned: &mut OwnedEntries,
) -> Result<Change> {
    let reg = &ctx.registry;
    let h = Hive::LocalMachine;
    let mut changed = false;
    for b in &opts.browsers {
        let key = b.win_key();
        if b.is_chromium() {
            let cur = reg
                .read_string(h, key, "AutoLaunchProtocolsFromOrigins")
                .map_err(|e| reg_err(key, e))?;
            if let Some(new) = merge_auto_launch(cur.as_deref(), Some(&auto_launch_entry(opts)))?
                && cur.as_deref() != Some(new.as_str())
            {
                reg.write(h, key, "AutoLaunchProtocolsFromOrigins", &RegValue::Sz(new))
                    .map_err(|e| reg_err(key, e))?;
                changed = true;
            }
            if opts.always_open_checkbox
                && reg
                    .read(h, key, "ExternalProtocolDialogShowAlwaysOpenCheckbox")
                    .map_err(|e| reg_err(key, e))?
                    .is_none()
            {
                reg.write(
                    h,
                    key,
                    "ExternalProtocolDialogShowAlwaysOpenCheckbox",
                    &RegValue::Dword(1),
                )
                .map_err(|e| reg_err(key, e))?;
                owned.add(format!(
                    r"reg:HKLM\{key}:ExternalProtocolDialogShowAlwaysOpenCheckbox"
                ));
                changed = true;
            }
            let pols = chromium_policies(opts);
            for lp in LIST_POLICIES {
                let Some(pats) = pols.get(*lp).and_then(Value::as_array) else {
                    continue;
                };
                let lk = format!(r"{key}\{lp}");
                let existing = reg
                    .values(h, &lk)
                    .map_err(|e| reg_err(&lk, e))?
                    .unwrap_or_default();
                let mut next = existing
                    .iter()
                    .filter_map(|(n, _)| n.parse::<u32>().ok())
                    .max()
                    .unwrap_or(0)
                    + 1;
                for p in pats.iter().filter_map(Value::as_str) {
                    if existing
                        .iter()
                        .any(|(_, v)| v.as_string().as_deref() == Some(p))
                    {
                        continue;
                    }
                    reg.write(h, &lk, &next.to_string(), &RegValue::Sz(p.into()))
                        .map_err(|e| reg_err(&lk, e))?;
                    owned.add(format!(r"reglist:HKLM\{lk}:{p}"));
                    next += 1;
                    changed = true;
                }
            }
        } else {
            // Handlers (JSON en REG_MULTI_SZ, como la plantilla ADMX de Mozilla).
            let cur = reg.read(h, key, "Handlers").map_err(|e| reg_err(key, e))?;
            let cur_text = cur
                .as_ref()
                .and_then(RegValue::as_string)
                .unwrap_or_default();
            let mut doc: Value = if cur_text.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&cur_text)
                    .map_err(|e| SystemError::Other(format!("Handlers no es JSON válido: {e}")))?
            };
            let schemes = doc
                .as_object_mut()
                .ok_or_else(|| SystemError::Other("Handlers no es un objeto".into()))?
                .entry("schemes")
                .or_insert_with(|| json!({}));
            if let Some(s) = schemes.as_object_mut() {
                s.insert(SCHEME.into(), firefox_handler());
            }
            let new = serde_json::to_string(&doc).map_err(|e| SystemError::Other(e.to_string()))?;
            if new != cur_text {
                reg.write(h, key, "Handlers", &RegValue::MultiSz(vec![new]))
                    .map_err(|e| reg_err(key, e))?;
                changed = true;
            }
            if opts.firefox_enterprise_roots {
                changed |= set_win_enterprise_roots(ctx, owned)?;
            }
            for p in firefox_policy_files(ctx) {
                changed |= install_firefox_file(&p, true, opts.firefox_enterprise_roots, owned)?;
            }
        }
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

fn set_win_enterprise_roots(ctx: &Context, owned: &mut OwnedEntries) -> Result<bool> {
    let ck = format!(r"{}\Certificates", Browser::Firefox.win_key());
    let reg = &ctx.registry;
    match reg
        .read(Hive::LocalMachine, &ck, "ImportEnterpriseRoots")
        .map_err(|e| reg_err(&ck, e))?
    {
        Some(RegValue::Dword(1)) => Ok(false),
        prev => {
            if prev.is_none() {
                owned.add(format!(r"reg:HKLM\{ck}:ImportEnterpriseRoots"));
            }
            reg.write(
                Hive::LocalMachine,
                &ck,
                "ImportEnterpriseRoots",
                &RegValue::Dword(1),
            )
            .map_err(|e| reg_err(&ck, e))?;
            Ok(true)
        }
    }
}

/// Activa la directiva `Certificates.ImportEnterpriseRoots` de Firefox (equivalente
/// corporativo de `security.enterprise_roots.enabled`): en Windows en el registro y en
/// `distribution\policies.json` de cada instalación; en macOS en el `policies.json` de
/// `Firefox.app`. Requiere privilegios. En Linux Firefox no la admite (se omite).
pub fn install_firefox_enterprise_roots(ctx: &Context) -> Result<Change> {
    if !ctx.elevated {
        return Err(SystemError::NotElevated("directivas de Firefox".into()));
    }
    let mut owned = OwnedEntries::load(ctx);
    let mut changed = false;
    if ctx.os == Os::Windows {
        changed |= set_win_enterprise_roots(ctx, &mut owned)?;
    }
    if ctx.os != Os::Linux {
        for p in firefox_policy_files(ctx) {
            changed |= install_firefox_file(&p, false, true, &mut owned)?;
        }
    }
    owned.save(ctx)?;
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

fn remove_windows(ctx: &Context, owned: &mut OwnedEntries) -> Result<Change> {
    let reg = &ctx.registry;
    let h = Hive::LocalMachine;
    let mut changed = false;
    for b in Browser::ALL {
        let key = b.win_key();
        if b.is_chromium() {
            let cur = reg
                .read_string(h, key, "AutoLaunchProtocolsFromOrigins")
                .map_err(|e| reg_err(key, e))?;
            if let Some(c) = &cur {
                match merge_auto_launch(Some(c), None)? {
                    Some(n) if &n != c => {
                        reg.write(h, key, "AutoLaunchProtocolsFromOrigins", &RegValue::Sz(n))
                            .map_err(|e| reg_err(key, e))?;
                        changed = true;
                    }
                    Some(_) => {}
                    None => {
                        changed |= reg
                            .delete_value(h, key, "AutoLaunchProtocolsFromOrigins")
                            .map_err(|e| reg_err(key, e))?
                    }
                }
            }
            let id = format!(r"reg:HKLM\{key}:ExternalProtocolDialogShowAlwaysOpenCheckbox");
            if owned.owns(&id) {
                changed |= reg
                    .delete_value(h, key, "ExternalProtocolDialogShowAlwaysOpenCheckbox")
                    .map_err(|e| reg_err(key, e))?;
                owned.forget(&id);
            }
            for lp in LIST_POLICIES {
                let lk = format!(r"{key}\{lp}");
                for (n, v) in reg
                    .values(h, &lk)
                    .map_err(|e| reg_err(&lk, e))?
                    .unwrap_or_default()
                {
                    let id = format!(r"reglist:HKLM\{lk}:{}", v.as_string().unwrap_or_default());
                    if owned.owns(&id) {
                        changed |= reg.delete_value(h, &lk, &n).map_err(|e| reg_err(&lk, e))?;
                        owned.forget(&id);
                    }
                }
                if reg
                    .values(h, &lk)
                    .ok()
                    .flatten()
                    .is_some_and(|v| v.is_empty())
                {
                    let _ = reg.delete_tree(h, &lk);
                }
            }
        } else {
            if let Some(cur) = reg
                .read(h, key, "Handlers")
                .map_err(|e| reg_err(key, e))?
                .and_then(|v| v.as_string())
                && let Ok(mut doc) = serde_json::from_str::<Value>(&cur)
                && let Some(s) = doc.get_mut("schemes").and_then(Value::as_object_mut)
                && s.remove(SCHEME).is_some()
            {
                if s.is_empty() {
                    doc.as_object_mut().map(|o| o.remove("schemes"));
                }
                if doc.as_object().is_some_and(|o| o.is_empty()) {
                    reg.delete_value(h, key, "Handlers")
                        .map_err(|e| reg_err(key, e))?;
                } else {
                    reg.write(
                        h,
                        key,
                        "Handlers",
                        &RegValue::MultiSz(vec![doc.to_string()]),
                    )
                    .map_err(|e| reg_err(key, e))?;
                }
                changed = true;
            }
            let ck = format!(r"{key}\Certificates");
            let id = format!(r"reg:HKLM\{ck}:ImportEnterpriseRoots");
            if owned.owns(&id) {
                changed |= reg
                    .delete_value(h, &ck, "ImportEnterpriseRoots")
                    .map_err(|e| reg_err(&ck, e))?;
                owned.forget(&id);
            }
            for p in firefox_policy_files(ctx) {
                changed |= remove_firefox_file(&p, owned)?;
            }
        }
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

// ------------------------------------------------------------------ macOS

fn json_to_plist(v: &Value) -> plist::Value {
    match v {
        Value::Bool(b) => plist::Value::Boolean(*b),
        Value::Number(n) => n
            .as_i64()
            .map(|i| plist::Value::Integer(i.into()))
            .unwrap_or_else(|| plist::Value::Real(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => plist::Value::String(s.clone()),
        Value::Array(a) => plist::Value::Array(a.iter().map(json_to_plist).collect()),
        Value::Object(o) => plist::Value::Dictionary(
            o.iter()
                .map(|(k, v)| (k.clone(), json_to_plist(v)))
                .collect(),
        ),
        Value::Null => plist::Value::String(String::new()),
    }
}

fn mac_managed_plist(ctx: &Context, b: Browser) -> PathBuf {
    ctx.sys(&format!(
        "/Library/Managed Preferences/{}.plist",
        b.mac_domain()
    ))
}

fn install_macos(
    ctx: &Context,
    opts: &BrowserPolicyOptions,
    owned: &mut OwnedEntries,
) -> Result<Change> {
    let mut changed = false;
    for b in &opts.browsers {
        if b.is_chromium() {
            let p = mac_managed_plist(ctx, *b);
            let mut dict = match plist::Value::from_file(&p) {
                Ok(plist::Value::Dictionary(d)) => d,
                _ => plist::Dictionary::new(),
            };
            let before = dict.clone();
            let cur = dict.get("AutoLaunchProtocolsFromOrigins").cloned();
            let mut list: Vec<plist::Value> = cur.and_then(|v| v.into_array()).unwrap_or_default();
            list.retain(|v| {
                v.as_dictionary()
                    .and_then(|d| d.get("protocol"))
                    .and_then(|p| p.as_string())
                    != Some(SCHEME)
            });
            list.push(json_to_plist(&auto_launch_entry(opts)));
            dict.insert(
                "AutoLaunchProtocolsFromOrigins".into(),
                plist::Value::Array(list),
            );
            if opts.always_open_checkbox
                && !dict.contains_key("ExternalProtocolDialogShowAlwaysOpenCheckbox")
            {
                dict.insert(
                    "ExternalProtocolDialogShowAlwaysOpenCheckbox".into(),
                    plist::Value::Boolean(true),
                );
                owned.add(format!(
                    "plist:{}:ExternalProtocolDialogShowAlwaysOpenCheckbox",
                    p.display()
                ));
            }
            let pols = chromium_policies(opts);
            for lp in LIST_POLICIES {
                if let Some(pats) = pols.get(*lp).and_then(Value::as_array) {
                    let mut l: Vec<plist::Value> = dict
                        .get(lp)
                        .cloned()
                        .and_then(|v| v.into_array())
                        .unwrap_or_default();
                    for pat in pats.iter().filter_map(Value::as_str) {
                        if !l.iter().any(|x| x.as_string() == Some(pat)) {
                            l.push(plist::Value::String(pat.into()));
                            owned.add(format!("plistlist:{}:{lp}:{pat}", p.display()));
                        }
                    }
                    dict.insert((*lp).into(), plist::Value::Array(l));
                }
            }
            if dict != before {
                let mut buf = Vec::new();
                plist::Value::Dictionary(dict)
                    .to_writer_xml(&mut buf)
                    .map_err(|e| SystemError::Other(e.to_string()))?;
                fsutil::write_atomic(&p, &buf, Some(0o644))?;
                changed = true;
            }
        } else {
            for p in firefox_policy_files(ctx) {
                changed |= install_firefox_file(&p, true, opts.firefox_enterprise_roots, owned)?;
            }
        }
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

fn remove_macos(ctx: &Context, owned: &mut OwnedEntries) -> Result<Change> {
    let mut changed = false;
    for b in Browser::ALL {
        if b.is_chromium() {
            let p = mac_managed_plist(ctx, b);
            let Ok(plist::Value::Dictionary(mut dict)) = plist::Value::from_file(&p) else {
                continue;
            };
            let before = dict.clone();
            if let Some(mut l) = dict
                .get("AutoLaunchProtocolsFromOrigins")
                .cloned()
                .and_then(|v| v.into_array())
            {
                l.retain(|v| {
                    v.as_dictionary()
                        .and_then(|d| d.get("protocol"))
                        .and_then(|p| p.as_string())
                        != Some(SCHEME)
                });
                if l.is_empty() {
                    dict.remove("AutoLaunchProtocolsFromOrigins");
                } else {
                    dict.insert(
                        "AutoLaunchProtocolsFromOrigins".into(),
                        plist::Value::Array(l),
                    );
                }
            }
            let id = format!(
                "plist:{}:ExternalProtocolDialogShowAlwaysOpenCheckbox",
                p.display()
            );
            if owned.owns(&id) {
                dict.remove("ExternalProtocolDialogShowAlwaysOpenCheckbox");
                owned.forget(&id);
            }
            for lp in LIST_POLICIES {
                if let Some(mut l) = dict.get(lp).cloned().and_then(|v| v.into_array()) {
                    l.retain(|x| {
                        let id = format!(
                            "plistlist:{}:{lp}:{}",
                            p.display(),
                            x.as_string().unwrap_or_default()
                        );
                        !owned.owns(&id)
                    });
                    if l.is_empty() {
                        dict.remove(lp);
                    } else {
                        dict.insert((*lp).into(), plist::Value::Array(l));
                    }
                }
            }
            owned
                .entries
                .retain(|e| !e.starts_with(&format!("plistlist:{}:", p.display())));
            if dict != before {
                if dict.is_empty() {
                    fsutil::remove_file_if_exists(&p)?;
                } else {
                    let mut buf = Vec::new();
                    plist::Value::Dictionary(dict)
                        .to_writer_xml(&mut buf)
                        .map_err(|e| SystemError::Other(e.to_string()))?;
                    fsutil::write_atomic(&p, &buf, None)?;
                }
                changed = true;
            }
        }
    }
    for p in firefox_policy_files(ctx) {
        changed |= remove_firefox_file(&p, owned)?;
    }
    Ok(if changed {
        Change::Changed
    } else {
        Change::Unchanged
    })
}

// ------------------------------------------------------------------ API

/// Instala (fusiona) las directivas. Requiere privilegios.
pub fn install(ctx: &Context, opts: &BrowserPolicyOptions) -> Result<Change> {
    if !ctx.elevated {
        return Err(SystemError::NotElevated(
            "directivas de los navegadores".into(),
        ));
    }
    let mut owned = OwnedEntries::load(ctx);
    let r = match ctx.os {
        Os::Windows => install_windows(ctx, opts, &mut owned),
        Os::Linux => install_linux(ctx, opts, &mut owned),
        Os::MacOs => install_macos(ctx, opts, &mut owned),
    };
    owned.save(ctx)?;
    r
}

/// Retira las directivas de `afirma` y las entradas creadas por AutoFirma.
pub fn remove(ctx: &Context) -> Result<Change> {
    if !ctx.elevated {
        return Err(SystemError::NotElevated(
            "directivas de los navegadores".into(),
        ));
    }
    let mut owned = OwnedEntries::load(ctx);
    let r = match ctx.os {
        Os::Windows => remove_windows(ctx, &mut owned),
        Os::Linux => remove_linux(ctx, &mut owned),
        Os::MacOs => remove_macos(ctx, &mut owned),
    };
    owned.save(ctx)?;
    r
}

/// Estado de las directivas de un navegador.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyStatus {
    pub browser: Browser,
    /// Dónde se buscó.
    pub location: String,
    /// Hay una directiva para abrir `afirma://` sin preguntar (o el manejador de Firefox).
    pub auto_launch: bool,
    /// Orígenes autorizados.
    pub origins: Vec<String>,
    /// Firefox: `ImportEnterpriseRoots`.
    pub enterprise_roots: Option<bool>,
}

fn origins_from(v: &Value) -> Option<Vec<String>> {
    v.as_array()?
        .iter()
        .find(|e| e.get("protocol").and_then(Value::as_str) == Some(SCHEME))
        .map(|e| {
            e.get("allowed_origins")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        })
}

/// Comprueba las directivas presentes.
pub fn status(ctx: &Context) -> Vec<PolicyStatus> {
    let mut out = Vec::new();
    for b in Browser::ALL {
        match ctx.os {
            Os::Windows => {
                let key = b.win_key();
                if b.is_chromium() {
                    let v = ctx
                        .registry
                        .read_string(Hive::LocalMachine, key, "AutoLaunchProtocolsFromOrigins")
                        .ok()
                        .flatten();
                    let origins = v
                        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                        .and_then(|j| origins_from(&j));
                    out.push(PolicyStatus {
                        browser: b,
                        location: format!(r"HKLM\{key}"),
                        auto_launch: origins.is_some(),
                        origins: origins.unwrap_or_default(),
                        enterprise_roots: None,
                    });
                } else {
                    let h = ctx
                        .registry
                        .read(Hive::LocalMachine, key, "Handlers")
                        .ok()
                        .flatten()
                        .and_then(|v| v.as_string())
                        .unwrap_or_default();
                    let er = ctx
                        .registry
                        .read(
                            Hive::LocalMachine,
                            &format!(r"{key}\Certificates"),
                            "ImportEnterpriseRoots",
                        )
                        .ok()
                        .flatten()
                        .map(|v| v == RegValue::Dword(1));
                    out.push(PolicyStatus {
                        browser: b,
                        location: format!(r"HKLM\{key}"),
                        auto_launch: h.contains("\"afirma\""),
                        origins: Vec::new(),
                        enterprise_roots: er,
                    });
                }
            }
            Os::Linux | Os::MacOs => {
                if b.is_chromium() {
                    let (loc, val) = if ctx.os == Os::Linux {
                        let p = b
                            .linux_dirs()
                            .iter()
                            .map(|d| ctx.sys(d).join(CHROMIUM_POLICY_FILE))
                            .find(|p| p.is_file());
                        let v = p
                            .as_ref()
                            .and_then(|p| std::fs::read(p).ok())
                            .and_then(|d| serde_json::from_slice::<Value>(&d).ok());
                        (
                            p.map(|p| p.display().to_string())
                                .unwrap_or_else(|| b.linux_dirs()[0].to_string()),
                            v,
                        )
                    } else {
                        let p = mac_managed_plist(ctx, b);
                        let v = plist::Value::from_file(&p)
                            .ok()
                            .and_then(|pv| serde_json::to_value(pv).ok());
                        (p.display().to_string(), v)
                    };
                    let origins = val
                        .as_ref()
                        .and_then(|v| v.get("AutoLaunchProtocolsFromOrigins"))
                        .and_then(origins_from);
                    out.push(PolicyStatus {
                        browser: b,
                        location: loc,
                        auto_launch: origins.is_some(),
                        origins: origins.unwrap_or_default(),
                        enterprise_roots: None,
                    });
                } else {
                    for p in firefox_policy_files(ctx) {
                        let v = std::fs::read(&p)
                            .ok()
                            .and_then(|d| serde_json::from_slice::<Value>(&d).ok());
                        let pol = v.as_ref().and_then(|v| v.get("policies"));
                        out.push(PolicyStatus {
                            browser: b,
                            location: p.display().to_string(),
                            auto_launch: pol
                                .and_then(|p| p.pointer("/Handlers/schemes/afirma"))
                                .is_some(),
                            origins: Vec::new(),
                            enterprise_roots: pol
                                .and_then(|p| p.pointer("/Certificates/ImportEnterpriseRoots"))
                                .and_then(Value::as_bool),
                        });
                    }
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ plantillas

fn reg_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn reg_multi_sz_hex(lines: &[String]) -> String {
    let mut bytes = Vec::new();
    for l in lines {
        for u in l.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes.extend_from_slice(&[0, 0]);
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    // Líneas partidas como regedit.
    let mut out = String::from("hex(7):");
    for (i, chunk) in hex.chunks(25).enumerate() {
        if i > 0 {
            out.push_str(",\\\r\n  ");
        }
        out.push_str(&chunk.join(","));
    }
    out
}

fn reg_value_line(name: &str, v: &RegValue) -> String {
    let n = if name.is_empty() {
        "@".to_string()
    } else {
        format!("\"{}\"", reg_escape(name))
    };
    match v {
        RegValue::Sz(s) | RegValue::ExpandSz(s) => format!("{n}=\"{}\"", reg_escape(s)),
        RegValue::Dword(d) => format!("{n}=dword:{d:08x}"),
        RegValue::MultiSz(l) => format!("{n}={}", reg_multi_sz_hex(l)),
        RegValue::Qword(q) => format!(
            "{n}=hex(b):{}",
            q.to_le_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
        RegValue::Other(b) => format!(
            "{n}=hex:{}",
            b.iter()
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// Valor de directiva de AutoFirma en el registro: booleanos como `REG_DWORD`.
fn autofirma_policy_value(k: &str, v: &str) -> RegValue {
    if matches!(
        crate::prefs::keys::info(k).map(|i| i.kind),
        Some(crate::prefs::keys::Kind::Bool)
    ) {
        RegValue::Dword(u32::from(v == "true"))
    } else {
        RegValue::Sz(v.to_string())
    }
}

/// Plantilla `.reg` (texto; ver [`reg_file_bytes`]) con las directivas de los navegadores y,
/// opcionalmente, las de AutoFirma (`HKLM\SOFTWARE\Policies\AutoFirma`).
pub fn windows_reg_template(opts: &BrowserPolicyOptions, prefs: Option<&PolicySet>) -> String {
    let mut sections: Vec<(String, Vec<(String, RegValue)>)> = Vec::new();
    for b in &opts.browsers {
        let key = b.win_key();
        if b.is_chromium() {
            let pols = chromium_policies(opts);
            let mut vals = vec![(
                "AutoLaunchProtocolsFromOrigins".to_string(),
                RegValue::Sz(json!([auto_launch_entry(opts)]).to_string()),
            )];
            if opts.always_open_checkbox {
                vals.push((
                    "ExternalProtocolDialogShowAlwaysOpenCheckbox".into(),
                    RegValue::Dword(1),
                ));
            }
            sections.push((key.to_string(), vals));
            for lp in LIST_POLICIES {
                if let Some(pats) = pols.get(*lp).and_then(Value::as_array) {
                    let vals = pats
                        .iter()
                        .filter_map(Value::as_str)
                        .enumerate()
                        .map(|(i, p)| ((i + 1).to_string(), RegValue::Sz(p.into())))
                        .collect();
                    sections.push((format!(r"{key}\{lp}"), vals));
                }
            }
        } else {
            sections.push((
                key.to_string(),
                vec![(
                    "Handlers".into(),
                    RegValue::MultiSz(vec![
                        json!({ "schemes": { SCHEME: firefox_handler() } }).to_string(),
                    ]),
                )],
            ));
            if opts.firefox_enterprise_roots {
                sections.push((
                    format!(r"{key}\Certificates"),
                    vec![("ImportEnterpriseRoots".into(), RegValue::Dword(1))],
                ));
            }
        }
    }
    if let Some(ps) = prefs {
        let key = crate::prefs::policy::WIN_POLICY_KEY;
        if !ps.mandatory.is_empty() {
            sections.push((
                key.into(),
                ps.mandatory
                    .iter()
                    .map(|(k, v)| (k.clone(), autofirma_policy_value(k, v)))
                    .collect(),
            ));
        }
        if !ps.recommended.is_empty() {
            sections.push((
                format!(r"{key}\Recommended"),
                ps.recommended
                    .iter()
                    .map(|(k, v)| (k.clone(), autofirma_policy_value(k, v)))
                    .collect(),
            ));
        }
        if !ps.smartcards.is_empty() {
            sections.push((
                format!(r"{key}\SmartCards"),
                ps.smartcards
                    .iter()
                    .map(|(k, v)| (k.clone(), RegValue::Sz(v.clone())))
                    .collect(),
            ));
        }
    }
    let mut s = String::from("Windows Registry Editor Version 5.00\r\n");
    for (key, vals) in sections {
        s.push_str(&format!("\r\n[{}\\{}]\r\n", Hive::LocalMachine.long(), key));
        for (n, v) in vals {
            s.push_str(&reg_value_line(&n, &v));
            s.push_str("\r\n");
        }
    }
    s
}

/// Bytes de un fichero `.reg` (UTF-16LE con BOM, como exige la versión 5.00).
pub fn reg_file_bytes(text: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn uuid() -> String {
    uuid_v4()
}

fn uuid_v4() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode_upper(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn payload(ptype: &str, ident: &str, name: &str, content: plist::Dictionary) -> plist::Value {
    let mut d = content;
    d.insert("PayloadType".into(), ptype.into());
    d.insert("PayloadIdentifier".into(), ident.into());
    d.insert("PayloadUUID".into(), uuid().into());
    d.insert("PayloadVersion".into(), plist::Value::Integer(1.into()));
    d.insert("PayloadDisplayName".into(), name.into());
    plist::Value::Dictionary(d)
}

/// Perfil de configuración `.mobileconfig` para MDM con las directivas de los navegadores, las
/// directivas de AutoFirma (dominio `bundle_id`, que macOS deposita en
/// `/Library/Managed Preferences`) y, si se indica, la CA local como raíz de confianza
/// (`com.apple.security.root`; útil cuando el administrador aporta su propio certificado con
/// `-certificate_path`/`-keystore_path`, idéntico en todos los equipos).
pub fn macos_mobileconfig(
    opts: &BrowserPolicyOptions,
    prefs: Option<&PolicySet>,
    bundle_id: &str,
    ca_der: Option<&[u8]>,
) -> Vec<u8> {
    let mut content = Vec::new();
    for b in &opts.browsers {
        let m = if b.is_chromium() {
            chromium_policies(opts)
        } else {
            let mut m = firefox_policies(opts);
            m.insert("EnterprisePoliciesEnabled".into(), json!(true));
            m
        };
        let d: plist::Dictionary = m
            .iter()
            .map(|(k, v)| (k.clone(), json_to_plist(v)))
            .collect();
        content.push(payload(
            b.mac_domain(),
            &format!("es.gob.afirma.policies.{}", b.mac_domain()),
            &format!("Autofirma: {b:?}"),
            d,
        ));
    }
    if let Some(ps) = prefs {
        let mut d = plist::Dictionary::new();
        for (k, v) in &ps.mandatory {
            let val = if matches!(
                crate::prefs::keys::info(k).map(|i| i.kind),
                Some(crate::prefs::keys::Kind::Bool)
            ) {
                plist::Value::Boolean(v == "true")
            } else {
                plist::Value::String(v.clone())
            };
            d.insert(k.clone(), val);
        }
        if !ps.recommended.is_empty() {
            d.insert(
                "Recommended".into(),
                plist::Value::Dictionary(
                    ps.recommended
                        .iter()
                        .map(|(k, v)| (k.clone(), plist::Value::String(v.clone())))
                        .collect(),
                ),
            );
        }
        if !ps.smartcards.is_empty() {
            d.insert(
                "SmartCards".into(),
                plist::Value::Dictionary(
                    ps.smartcards
                        .iter()
                        .map(|(k, v)| (k.clone(), plist::Value::String(v.clone())))
                        .collect(),
                ),
            );
        }
        content.push(payload(
            bundle_id,
            &format!("es.gob.afirma.policies.{bundle_id}"),
            "Autofirma: preferencias",
            d,
        ));
    }
    if let Some(der) = ca_der {
        let mut d = plist::Dictionary::new();
        d.insert("PayloadContent".into(), plist::Value::Data(der.to_vec()));
        d.insert(
            "PayloadCertificateFileName".into(),
            crate::certs::CA_CERT_FILENAME.into(),
        );
        content.push(payload(
            "com.apple.security.root",
            "es.gob.afirma.policies.ca",
            "Autofirma ROOT",
            d,
        ));
    }
    let mut top = plist::Dictionary::new();
    top.insert("PayloadContent".into(), plist::Value::Array(content));
    top.insert("PayloadScope".into(), "System".into());
    top.insert(
        "PayloadRemovalDisallowed".into(),
        plist::Value::Boolean(false),
    );
    let top = payload("Configuration", "es.gob.afirma.policies", "Autofirma", top);
    let mut buf = Vec::new();
    let _ = top.to_writer_xml(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Os;

    fn opts() -> BrowserPolicyOptions {
        BrowserPolicyOptions {
            allowed_origins: vec![
                "https://*.gob.es".into(),
                "https://sede.example.org/".into(),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn formatos_de_origen() {
        assert_eq!(to_urlblocklist_origin("https://*.gob.es"), "https://gob.es");
        assert_eq!(to_content_pattern("https://*.gob.es"), "https://[*.]gob.es");
        assert_eq!(to_content_pattern("*"), "*");
        let p = chromium_policies(&BrowserPolicyOptions::default());
        assert_eq!(
            p["AutoLaunchProtocolsFromOrigins"],
            json!([{"protocol":"afirma","allowed_origins":["*"]}])
        );
        assert!(
            !p.contains_key("LocalNetworkAccessAllowedForUrls"),
            "no se abre la red local a todos los orígenes"
        );
        let p = chromium_policies(&opts());
        assert_eq!(
            p["LocalNetworkAccessAllowedForUrls"],
            json!(["https://[*.]gob.es", "https://sede.example.org"])
        );
    }

    #[test]
    fn windows_fusiona_y_retira_solo_lo_propio() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Windows, t.path());
        assert!(install(&ctx, &opts()).is_err(), "requiere privilegios");
        ctx.elevated = true;
        let r = ctx.registry.clone();
        let chrome = Browser::Chrome.win_key();
        r.write(
            Hive::LocalMachine,
            chrome,
            "AutoLaunchProtocolsFromOrigins",
            &RegValue::Sz(
                r#"[{"protocol":"zoommtg","allowed_origins":["https://zoom.us"]}]"#.into(),
            ),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            Browser::Edge.win_key(),
            "ExternalProtocolDialogShowAlwaysOpenCheckbox",
            &RegValue::Dword(1),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            &format!(r"{chrome}\LocalNetworkAccessAllowedForUrls"),
            "1",
            &RegValue::Sz("https://intranet".into()),
        )
        .unwrap();
        assert_eq!(install(&ctx, &opts()).unwrap(), Change::Changed);
        assert_eq!(install(&ctx, &opts()).unwrap(), Change::Unchanged);
        let v = r
            .read_string(Hive::LocalMachine, chrome, "AutoLaunchProtocolsFromOrigins")
            .unwrap()
            .unwrap();
        assert!(v.contains("zoommtg") && v.contains("afirma"));
        assert_eq!(
            r.read_string(
                Hive::LocalMachine,
                &format!(r"{chrome}\LocalNetworkAccessAllowedForUrls"),
                "2"
            )
            .unwrap()
            .as_deref(),
            Some("https://[*.]gob.es")
        );
        assert_eq!(
            r.read(
                Hive::LocalMachine,
                r"SOFTWARE\Policies\Mozilla\Firefox\Certificates",
                "ImportEnterpriseRoots"
            )
            .unwrap(),
            Some(RegValue::Dword(1))
        );
        let st = status(&ctx);
        assert!(st.iter().all(|s| s.auto_launch), "{st:#?}");
        assert_eq!(remove(&ctx).unwrap(), Change::Changed);
        let v = r
            .read_string(Hive::LocalMachine, chrome, "AutoLaunchProtocolsFromOrigins")
            .unwrap()
            .unwrap();
        assert!(v.contains("zoommtg") && !v.contains("afirma"));
        assert_eq!(
            r.read(
                Hive::LocalMachine,
                Browser::Edge.win_key(),
                "ExternalProtocolDialogShowAlwaysOpenCheckbox"
            )
            .unwrap(),
            Some(RegValue::Dword(1)),
            "del administrador"
        );
        assert!(
            r.read(
                Hive::LocalMachine,
                chrome,
                "ExternalProtocolDialogShowAlwaysOpenCheckbox"
            )
            .unwrap()
            .is_none(),
            "propia"
        );
        assert_eq!(
            r.values(
                Hive::LocalMachine,
                &format!(r"{chrome}\LocalNetworkAccessAllowedForUrls")
            )
            .unwrap()
            .unwrap()
            .len(),
            1
        );
        assert!(
            r.read(Hive::LocalMachine, Browser::Firefox.win_key(), "Handlers")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn linux_ficheros_y_policies_json() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Linux, t.path());
        ctx.elevated = true;
        std::fs::create_dir_all(t.path().join("opt/google/chrome")).unwrap();
        std::fs::create_dir_all(t.path().join("etc/firefox/policies")).unwrap();
        std::fs::write(t.path().join("etc/firefox/policies/policies.json"), r#"{"policies":{"DisableTelemetry":true,"Certificates":{"ImportEnterpriseRoots":false}}}"#).unwrap();
        assert_eq!(install(&ctx, &opts()).unwrap(), Change::Changed);
        assert!(
            t.path()
                .join("etc/opt/chrome/policies/managed/autofirma.json")
                .is_file()
        );
        assert!(
            !t.path().join("etc/opt/edge").exists(),
            "Edge no está instalado"
        );
        let pj: Value = serde_json::from_slice(
            &std::fs::read(t.path().join("etc/firefox/policies/policies.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            pj.pointer("/policies/Handlers/schemes/afirma/ask"),
            Some(&json!(false))
        );
        assert_eq!(pj.pointer("/policies/DisableTelemetry"), Some(&json!(true)));
        assert_eq!(install(&ctx, &opts()).unwrap(), Change::Unchanged);
        assert_eq!(remove(&ctx).unwrap(), Change::Changed);
        let pj: Value = serde_json::from_slice(
            &std::fs::read(t.path().join("etc/firefox/policies/policies.json")).unwrap(),
        )
        .unwrap();
        assert!(pj.pointer("/policies/Handlers").is_none());
        assert_eq!(
            pj.pointer("/policies/Certificates/ImportEnterpriseRoots"),
            Some(&json!(true)),
            "existía antes: no se retira"
        );
        assert!(
            !t.path()
                .join("etc/opt/chrome/policies/managed/autofirma.json")
                .exists()
        );
    }

    #[test]
    fn raices_de_empresa_de_firefox_en_windows() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Windows, t.path());
        ctx.elevated = true;
        let fx = t.path().join("Program Files/Mozilla Firefox");
        std::fs::create_dir_all(&fx).unwrap();
        assert_eq!(
            install_firefox_enterprise_roots(&ctx).unwrap(),
            Change::Changed
        );
        assert_eq!(
            install_firefox_enterprise_roots(&ctx).unwrap(),
            Change::Unchanged
        );
        let pj: Value =
            serde_json::from_slice(&std::fs::read(fx.join("distribution/policies.json")).unwrap())
                .unwrap();
        assert_eq!(
            pj.pointer("/policies/Certificates/ImportEnterpriseRoots"),
            Some(&json!(true))
        );
        assert!(pj.pointer("/policies/Handlers").is_none());
        assert_eq!(
            ctx.registry
                .read(
                    Hive::LocalMachine,
                    r"SOFTWARE\Policies\Mozilla\Firefox\Certificates",
                    "ImportEnterpriseRoots"
                )
                .unwrap(),
            Some(RegValue::Dword(1))
        );
        assert_eq!(remove(&ctx).unwrap(), Change::Changed);
        assert!(
            !fx.join("distribution/policies.json").exists(),
            "fichero propio vacío: se borra"
        );
        assert!(
            ctx.registry
                .read(
                    Hive::LocalMachine,
                    r"SOFTWARE\Policies\Mozilla\Firefox\Certificates",
                    "ImportEnterpriseRoots"
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn plantillas() {
        let mut ps = PolicySet::default();
        ps.mandatory
            .insert("preferencesBlocked".into(), "true".into());
        ps.mandatory
            .insert("signatureHashAlgorithm".into(), "SHA512".into());
        let reg = windows_reg_template(&opts(), Some(&ps));
        assert!(reg.starts_with("Windows Registry Editor Version 5.00\r\n"));
        assert!(reg.contains("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome]\r\n\"AutoLaunchProtocolsFromOrigins\"=\"[{\\\"allowed_origins\\\""));
        assert!(reg.contains("\"preferencesBlocked\"=dword:00000001"));
        assert!(reg.contains("\"signatureHashAlgorithm\"=\"SHA512\""));
        assert_eq!(&reg_file_bytes("A")[..], &[0xFF, 0xFE, 0x41, 0x00]);
        let ca = crate::certs::generate(&Default::default()).unwrap().ca_der;
        let mc = macos_mobileconfig(
            &opts(),
            Some(&ps),
            "es.gob.afirma.simpleafirma.osx",
            Some(&ca),
        );
        let v = plist::Value::from_reader_xml(&mc[..]).unwrap();
        let d = v.as_dictionary().unwrap();
        assert_eq!(d["PayloadType"].as_string(), Some("Configuration"));
        let content = d["PayloadContent"].as_array().unwrap();
        assert_eq!(content.len(), 7);
        assert!(
            content
                .iter()
                .any(|p| p.as_dictionary().unwrap()["PayloadType"].as_string()
                    == Some("com.apple.security.root"))
        );
        let files = linux_policy_files(&opts());
        assert!(files.iter().any(
            |(p, c)| p == "/etc/opt/chrome/policies/managed/autofirma.json"
                && c.contains("AutoLaunchProtocolsFromOrigins")
        ));
    }
}
