//! Registro del manejador del protocolo `afirma://`, menús contextuales y asociaciones de
//! ficheros.
//!
//! * **Windows**: `HKCU` (por usuario, sin privilegios) o `HKLM` (`Software\Classes`), con
//!   las rutas **entre comillas** (Java no las entrecomillaba). Menú «Firmar con Autofirma»
//!   para todos los ficheros (`sign -gui -i "%1"`), «Verificar con Autofirma» para
//!   `.csig`/`.xsig` (`verify -gui -i "%1"`, mediante `SystemFileAssociations`, que funciona
//!   aunque otra aplicación sea la propietaria de la extensión) y, opcionalmente, los menús de
//!   huellas digitales del antiguo complemento.
//! * **Linux**: fichero `.desktop` con `MimeType=x-scheme-handler/afirma;`, valor por defecto
//!   en `mimeapps.list` (usuario: `~/.config`; sistema: `/etc/xdg`), `update-desktop-database`,
//!   y opcionalmente entradas «Abrir con → Firmar con Autofirma», tipos MIME para
//!   `.csig`/`.xsig` y scripts de Nautilus.
//! * **macOS**: el esquema se declara en `Info.plist` (`CFBundleURLTypes`, ver
//!   [`macos_info_plist_fragment`]); aquí se refresca LaunchServices (`lsregister`) y se fija
//!   la aplicación por defecto (`LSSetDefaultHandlerForURLScheme`, por usuario).

use std::path::{Path, PathBuf};

use crate::ctx::{Context, Os};
use crate::error::{Result, SystemError};
use crate::exec::Cmd;
use crate::fsutil;
use crate::registry::{Hive, RegValue};
use crate::trust::{Change, TrustScope};

/// Esquema de invocación.
pub const SCHEME: &str = "afirma";

/// Menús contextuales y asociaciones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContextMenus {
    /// «Firmar con Autofirma» para cualquier fichero.
    pub sign: bool,
    /// «Verificar con Autofirma» para `.csig`/`.xsig` (y su tipo de fichero).
    pub verify: bool,
    /// Menús de huellas digitales (`createdigest`/`checkdigest`).
    pub hash: bool,
}

impl Default for ContextMenus {
    fn default() -> Self {
        Self {
            sign: true,
            verify: true,
            hash: false,
        }
    }
}

/// Opciones de registro.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtocolOptions {
    /// Equipo o usuario.
    pub scope: TrustScope,
    /// Menús contextuales.
    pub menus: ContextMenus,
    /// Idioma de los textos (`es_ES`, `ca_ES`, `va_ES`, `gl_ES`, `eu_ES`, `en_US`).
    pub locale: String,
    /// Linux: escribir el fichero `.desktop` (los paquetes que ya lo instalan pueden desactivarlo).
    pub write_desktop_file: bool,
    /// Linux: directorio de aplicaciones alternativo.
    pub desktop_dir: Option<PathBuf>,
}

impl Default for ProtocolOptions {
    fn default() -> Self {
        Self {
            scope: TrustScope::User,
            menus: ContextMenus::default(),
            locale: "es_ES".into(),
            write_desktop_file: true,
            desktop_dir: None,
        }
    }
}

/// Textos localizados de los menús (tabla del instalador MSI de Java).
pub struct Labels {
    pub sign: &'static str,
    pub verify: &'static str,
    pub csig: &'static str,
    pub xsig: &'static str,
    pub hash_create: &'static str,
    pub hash_check: &'static str,
}

/// Textos para un idioma.
pub fn labels(locale: &str) -> Labels {
    let (sign, csig, xsig) = match locale {
        "ca_ES" | "va_ES" => (
            "Signar amb Autofirma",
            "Signatura binària CMS/CAdES",
            "Signatura XMLDSig/XAdES",
        ),
        "gl_ES" => ("Asinar con Autofirma", "Firma binaria CMS/CAdES", "Firma XMLDSig/XAdES"),
        "eu_ES" => (
            "Autofirmarekin sinatu",
            "CMS/CAdES sinadura bitarra",
            "Sinadura: XMLDSig/XAdES",
        ),
        "en_US" => (
            "Sign with Autofirma",
            "Binary signature CMS/CAdES",
            "Signature XMLDSig/XAdES",
        ),
        _ => ("Firmar con Autofirma", "Firma binaria CMS/CAdES", "Firma XMLDSig/XAdES"),
    };
    // El verbo «Verificar» de Java estaba siempre en castellano.
    Labels {
        sign,
        verify: "Verificar con Autofirma",
        csig,
        xsig,
        hash_create: "Generar huella digital",
        hash_check: "Comprobar huella digital",
    }
}

// ---------------------------------------------------------------- Windows

/// Valor del registro a escribir.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RegEntry {
    pub hive: Hive,
    pub key: String,
    pub name: String,
    pub value: RegValue,
}

fn hive_for(scope: TrustScope) -> Hive {
    match scope {
        TrustScope::Machine => Hive::LocalMachine,
        TrustScope::User => Hive::CurrentUser,
    }
}

/// Ruta entre comillas para el registro.
pub fn win_quote(p: &Path) -> String {
    format!("\"{}\"", p.display())
}

/// Entradas de registro del protocolo y los menús.
pub fn windows_entries(ctx: &Context, opts: &ProtocolOptions) -> Vec<RegEntry> {
    let hive = hive_for(opts.scope);
    let exe = win_quote(&ctx.app.exe);
    let icon = ctx
        .app
        .icon
        .as_ref()
        .map(|i| win_quote(i))
        .unwrap_or_else(|| format!("{exe},0"));
    let l = labels(&opts.locale);
    let mut v = Vec::new();
    let mut put = |key: &str, name: &str, value: &str| {
        v.push(RegEntry {
            hive,
            key: format!(r"Software\Classes\{key}"),
            name: name.into(),
            value: RegValue::Sz(value.into()),
        });
    };
    put(SCHEME, "", "URL:Afirma Protocol");
    put(SCHEME, "URL Protocol", "");
    put(&format!(r"{SCHEME}\DefaultIcon"), "", &icon);
    put(&format!(r"{SCHEME}\shell\open\command"), "", &format!("{exe} \"%1\""));
    if opts.menus.sign {
        put(r"*\shell\afirma.sign", "", l.sign);
        put(r"*\shell\afirma.sign", "Icon", &exe);
        put(
            r"*\shell\afirma.sign\command",
            "",
            &format!("{exe} sign -gui -i \"%1\""),
        );
    }
    if opts.menus.verify {
        for (ext, desc) in [("csig", l.csig), ("xsig", l.xsig)] {
            let progid = format!("Autofirma.{ext}");
            put(&progid, "", desc);
            put(&progid, "FriendlyTypeName", desc);
            put(&format!(r"{progid}\DefaultIcon"), "", &icon);
            put(&format!(r"{progid}\shell\open"), "", l.verify);
            put(
                &format!(r"{progid}\shell\open\command"),
                "",
                &format!("{exe} verify -gui -i \"%1\""),
            );
            put(&format!(r".{ext}\OpenWithProgids"), &progid, "");
            put(
                &format!(r"SystemFileAssociations\.{ext}\shell\afirma.verify"),
                "",
                l.verify,
            );
            put(
                &format!(r"SystemFileAssociations\.{ext}\shell\afirma.verify"),
                "Icon",
                &exe,
            );
            put(
                &format!(r"SystemFileAssociations\.{ext}\shell\afirma.verify\command"),
                "",
                &format!("{exe} verify -gui -i \"%1\""),
            );
        }
    }
    if opts.menus.hash {
        put(r"*\shell\afirma.hashFile", "", l.hash_create);
        put(r"*\shell\afirma.hashFile", "Icon", &exe);
        put(
            r"*\shell\afirma.hashFile\command",
            "",
            &format!("{exe} createdigest \"%1\" -gui"),
        );
        put(r"Directory\shell\afirma.hashDirectory", "", l.hash_create);
        put(r"Directory\shell\afirma.hashDirectory", "Icon", &exe);
        put(
            r"Directory\shell\afirma.hashDirectory\command",
            "",
            &format!("{exe} createdigest \"%1\" -gui"),
        );
        for ext in ["hash", "hashb64", "hexhash", "hashfiles"] {
            let k = format!(r"SystemFileAssociations\.{ext}\shell\afirma.{ext}");
            let extra = if ext == "hashfiles" { " -d" } else { "" };
            put(&k, "", l.hash_check);
            put(&k, "Icon", &exe);
            put(
                &format!(r"{k}\command"),
                "",
                &format!("{exe} checkdigest -i \"%1\"{extra} -gui"),
            );
        }
    }
    v
}

/// Claves propias que se eliminan al desinstalar (relativas a `Software\Classes`), incluidas
/// las que creaba la versión Java.
pub const WINDOWS_OWNED_KEYS: &[&str] = &[
    "afirma",
    r"*\shell\afirma.sign",
    r"*\shell\afirma.verify",
    r"*\shell\afirma.hashFile",
    r"Directory\shell\afirma.hashDirectory",
    r".csig\shell\Verify",
    r".xsig\shell\Verify",
    "Autofirma.csig",
    "Autofirma.xsig",
    r"SystemFileAssociations\.csig\shell\afirma.verify",
    r"SystemFileAssociations\.xsig\shell\afirma.verify",
    r"SystemFileAssociations\.hash\shell\afirma.hash",
    r"SystemFileAssociations\.hashb64\shell\afirma.hashb64",
    r"SystemFileAssociations\.hexhash\shell\afirma.hexhash",
    r"SystemFileAssociations\.hashfiles\shell\afirma.hashfiles",
    r".hash\shell\afirma.hash",
    r".hashb64\shell\afirma.hashb64",
    r".hexhash\shell\afirma.hexhash",
    r".hashfiles\shell\afirma.hashfiles",
];

fn reg_err(key: &str, e: std::io::Error) -> SystemError {
    SystemError::Registry {
        key: key.into(),
        detail: e.to_string(),
    }
}

/// `true` si la orden registrada pertenece a AutoFirma (Java o Rust).
fn is_autofirma_command(cmd: &str) -> bool {
    cmd.to_ascii_lowercase().contains("autofirma")
}

fn register_windows(ctx: &Context, opts: &ProtocolOptions) -> Result<Change> {
    let mut changed = false;
    // Limpieza de verbos de Java bajo la propia extensión (duplicarían el menú).
    let hive = hive_for(opts.scope);
    for k in [
        r"Software\Classes\.csig\shell\Verify",
        r"Software\Classes\.xsig\shell\Verify",
    ] {
        if let Ok(Some(cmd)) = ctx.registry.read_string(hive, &format!(r"{k}\command"), "")
            && is_autofirma_command(&cmd)
        {
            changed |= ctx.registry.delete_tree(hive, k).map_err(|e| reg_err(k, e))?;
        }
    }
    for e in windows_entries(ctx, opts) {
        let cur = ctx
            .registry
            .read(e.hive, &e.key, &e.name)
            .map_err(|x| reg_err(&e.key, x))?;
        if cur.as_ref() != Some(&e.value) {
            ctx.registry
                .write(e.hive, &e.key, &e.name, &e.value)
                .map_err(|x| reg_err(&e.key, x))?;
            changed = true;
        }
    }
    // Tipo de fichero: solo si ninguna otra aplicación es la propietaria de la extensión.
    if opts.menus.verify {
        for ext in ["csig", "xsig"] {
            let k = format!(r"Software\Classes\.{ext}");
            let cur = ctx
                .registry
                .read_string(hive, &k, "")
                .ok()
                .flatten()
                .unwrap_or_default();
            let progid = format!("Autofirma.{ext}");
            // Java dejaba aquí un texto descriptivo en lugar de un ProgID: se sustituye.
            let java_text = cur.contains("CMS/CAdES")
                || cur.contains("XMLDSig/XAdES")
                || cur.contains("CAdES") && cur.contains("CMS");
            if cur.is_empty() || java_text {
                ctx.registry
                    .write(hive, &k, "", &RegValue::Sz(progid))
                    .map_err(|e| reg_err(&k, e))?;
                changed = true;
            }
        }
    }
    if changed {
        notify_assoc_changed();
    }
    Ok(if changed { Change::Changed } else { Change::Unchanged })
}

fn unregister_windows(ctx: &Context, scope: TrustScope) -> Result<Change> {
    let hive = hive_for(scope);
    let mut changed = false;
    for k in WINDOWS_OWNED_KEYS {
        let full = format!(r"Software\Classes\{k}");
        // El esquema afirma:// solo se borra si apunta a AutoFirma.
        if *k == "afirma"
            && let Ok(Some(cmd)) = ctx
                .registry
                .read_string(hive, &format!(r"{full}\shell\open\command"), "")
            && !is_autofirma_command(&cmd)
        {
            continue;
        }
        changed |= ctx.registry.delete_tree(hive, &full).map_err(|e| reg_err(&full, e))?;
    }
    for ext in ["csig", "xsig"] {
        let k = format!(r"Software\Classes\.{ext}");
        let progid = format!("Autofirma.{ext}");
        changed |= ctx
            .registry
            .delete_value(hive, &format!(r"{k}\OpenWithProgids"), &progid)
            .map_err(|e| reg_err(&k, e))?;
        if ctx.registry.read_string(hive, &k, "").ok().flatten().as_deref() == Some(progid.as_str()) {
            changed |= ctx.registry.delete_value(hive, &k, "").map_err(|e| reg_err(&k, e))?;
        }
        // Clave de extensión vacía que dejaba Java o la nuestra.
        if ctx
            .registry
            .values(hive, &k)
            .ok()
            .flatten()
            .is_some_and(|v| v.is_empty())
            && ctx.registry.subkeys(hive, &k).ok().flatten().is_some_and(|s| {
                s.iter()
                    .all(|x| x.eq_ignore_ascii_case("OpenWithProgids") || x.eq_ignore_ascii_case("DefaultIcon"))
            })
        {
            let _ = ctx.registry.delete_tree(hive, &k);
        }
    }
    if changed {
        notify_assoc_changed();
    }
    Ok(if changed { Change::Changed } else { Change::Unchanged })
}

/// Notifica al Explorador el cambio de asociaciones (`SHChangeNotify`).
fn notify_assoc_changed() {
    #[cfg(windows)]
    // SAFETY: FFI con shell32; sin punteros.
    unsafe {
        use windows::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
}

/// Estado del registro del protocolo.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProtocolStatus {
    /// Registrado.
    pub registered: bool,
    /// Orden u origen efectivo (orden de Windows, `.desktop` de Linux, aplicación de macOS).
    pub handler: Option<String>,
    /// Apunta al ejecutable actual.
    pub points_to_current: bool,
    /// Ámbito de la entrada efectiva.
    pub scope: Option<TrustScope>,
    /// Detalle.
    pub detail: String,
}

fn status_windows(ctx: &Context) -> ProtocolStatus {
    // En HKCR, HKCU tiene prioridad sobre HKLM.
    for (hive, scope) in [
        (Hive::CurrentUser, TrustScope::User),
        (Hive::LocalMachine, TrustScope::Machine),
    ] {
        if let Ok(Some(cmd)) =
            ctx.registry
                .read_string(hive, &format!(r"Software\Classes\{SCHEME}\shell\open\command"), "")
        {
            let expected = format!("{} \"%1\"", win_quote(&ctx.app.exe));
            let url_protocol = ctx
                .registry
                .read(hive, &format!(r"Software\Classes\{SCHEME}"), "URL Protocol")
                .ok()
                .flatten()
                .is_some();
            return ProtocolStatus {
                registered: url_protocol,
                points_to_current: cmd.eq_ignore_ascii_case(&expected),
                handler: Some(cmd),
                scope: Some(scope),
                detail: if url_protocol {
                    String::new()
                } else {
                    "falta el valor «URL Protocol»".into()
                },
            };
        }
    }
    ProtocolStatus {
        registered: false,
        handler: None,
        points_to_current: false,
        scope: None,
        detail: "no hay ninguna clave afirma en el registro".into(),
    }
}

// ---------------------------------------------------------------- Linux

/// Entrecomilla un argumento de `Exec=` según la especificación de entradas de escritorio.
pub fn desktop_exec_quote(arg: &str) -> String {
    let needs = arg.chars().any(|c| " \t\n\"'\\><~|&;$*?#()`".contains(c));
    if !needs {
        return arg.to_string();
    }
    let mut s = String::from("\"");
    for c in arg.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('"');
    // Escapado de cadena del propio fichero .desktop.
    s.replace('\\', "\\\\")
}

fn linux_apps_dir(ctx: &Context, opts: &ProtocolOptions) -> PathBuf {
    if let Some(d) = &opts.desktop_dir {
        return d.clone();
    }
    match opts.scope {
        TrustScope::Machine => ctx.sys("/usr/local/share/applications"),
        TrustScope::User => ctx.paths.home.join(".local/share/applications"),
    }
}

fn linux_mimeapps(ctx: &Context, scope: TrustScope) -> PathBuf {
    match scope {
        TrustScope::Machine => ctx.sys("/etc/xdg/mimeapps.list"),
        TrustScope::User => ctx.paths.home.join(".config/mimeapps.list"),
    }
}

/// Contenido del fichero `.desktop` principal.
pub fn desktop_entry(ctx: &Context) -> String {
    let exe = desktop_exec_quote(&ctx.app.exe.to_string_lossy());
    let icon = ctx
        .app
        .icon
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ctx.app.desktop_id.clone());
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.5\nName={name}\nName[es_ES]={name}\nGenericName=Herramienta de firma\nComment=Herramienta de firma\nExec={exe} %u\nIcon={icon}\nTerminal=false\nCategories=Office;Utility;\nMimeType=x-scheme-handler/{SCHEME};\nStartupNotify=true\nStartupWMClass=autofirma\n",
        name = ctx.app.display_name
    )
}

/// Tipos MIME de los ficheros que se ofrecen en «Abrir con → Firmar con Autofirma».
pub const SIGNABLE_MIME_TYPES: &[&str] = &[
    "application/pdf",
    "application/xml",
    "text/xml",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "application/octet-stream",
    "text/plain",
];

/// Tipos MIME propios de las firmas.
pub const CSIG_MIME: &str = "application/x-autofirma-csig";
/// Tipo MIME de `.xsig`.
pub const XSIG_MIME: &str = "application/x-autofirma-xsig";

/// Definición `shared-mime-info` de `.csig`/`.xsig`.
pub fn mime_package_xml(l: &Labels) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n  <mime-type type=\"{CSIG_MIME}\">\n    <comment>{}</comment>\n    <glob pattern=\"*.csig\"/>\n  </mime-type>\n  <mime-type type=\"{XSIG_MIME}\">\n    <comment>{}</comment>\n    <sub-class-of type=\"application/xml\"/>\n    <glob pattern=\"*.xsig\"/>\n  </mime-type>\n</mime-info>\n",
        l.csig, l.xsig
    )
}

/// Ficheros que se escriben en Linux: (ruta, contenido, modo).
pub fn linux_files(ctx: &Context, opts: &ProtocolOptions) -> Vec<(PathBuf, String, u32)> {
    let apps = linux_apps_dir(ctx, opts);
    let id = &ctx.app.desktop_id;
    let exe = desktop_exec_quote(&ctx.app.exe.to_string_lossy());
    let l = labels(&opts.locale);
    let mut v = Vec::new();
    // Los paquetes .deb/.rpm ya instalan /usr/share/applications/<id>.desktop; uno en
    // /usr/local lo taparía, así que en ese caso no se escribe.
    let packaged = opts.scope == TrustScope::Machine
        && opts.desktop_dir.is_none()
        && ctx.sys(&format!("/usr/share/applications/{id}.desktop")).is_file();
    if opts.write_desktop_file && !packaged {
        v.push((apps.join(format!("{id}.desktop")), desktop_entry(ctx), 0o644));
    }
    if opts.menus.sign {
        v.push((
            apps.join(format!("{id}-sign.desktop")),
            format!(
                "[Desktop Entry]\nType=Application\nName={}\nExec={exe} sign -gui -i %f\nIcon={}\nTerminal=false\nNoDisplay=true\nMimeType={};\n",
                l.sign,
                ctx.app.icon.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| id.clone()),
                SIGNABLE_MIME_TYPES.join(";")
            ),
            0o644,
        ));
    }
    if opts.menus.verify {
        v.push((
            apps.join(format!("{id}-verify.desktop")),
            format!("[Desktop Entry]\nType=Application\nName={}\nExec={exe} verify -gui -i %f\nIcon={}\nTerminal=false\nNoDisplay=true\nMimeType={CSIG_MIME};{XSIG_MIME};\n", l.verify, ctx.app.icon.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| id.clone())),
            0o644,
        ));
        let mime_dir = match opts.scope {
            TrustScope::Machine => ctx.sys("/usr/local/share/mime/packages"),
            TrustScope::User => ctx.paths.home.join(".local/share/mime/packages"),
        };
        v.push((mime_dir.join("autofirma.xml"), mime_package_xml(&l), 0o644));
    }
    if opts.menus.sign && opts.scope == TrustScope::User && ctx.paths.home.join(".local/share/nautilus").is_dir() {
        let script = format!(
            "#!/bin/sh\n# Generado por AutoFirma\nfor f in \"$@\"; do exec {} sign -gui -i \"$f\"; done\n",
            shell_quote(&ctx.app.exe.to_string_lossy())
        );
        v.push((
            ctx.paths.home.join(format!(".local/share/nautilus/scripts/{}", l.sign)),
            script,
            0o755,
        ));
    }
    v
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Ajusta `[Default Applications]` de un `mimeapps.list` (`Some(id)` fija, `None` quita si
/// apunta a `ours`). Devuelve el nuevo texto si cambia.
pub fn edit_mimeapps(text: &str, mime: &str, set: Option<&str>, ours: &str) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_defaults = false;
    let mut found_section = false;
    let mut done = false;
    let mut changed = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if in_defaults
                && !done
                && let Some(id) = set
            {
                out.push(format!("{mime}={id};"));
                done = true;
                changed = true;
            }
            in_defaults = t == "[Default Applications]";
            found_section |= in_defaults;
            out.push(line.to_string());
            continue;
        }
        if in_defaults
            && let Some((k, v)) = t.split_once('=')
            && k.trim() == mime
        {
            match set {
                Some(id) => {
                    let new = format!("{mime}={id};");
                    if t != new {
                        changed = true;
                    }
                    if !done {
                        out.push(new);
                    }
                    done = true;
                }
                None => {
                    if v.trim().trim_end_matches(';').split(';').any(|x| x.trim() == ours) {
                        changed = true;
                    } else {
                        out.push(line.to_string());
                    }
                }
            }
            continue;
        }
        out.push(line.to_string());
    }
    if let Some(id) = set
        && !done
    {
        if in_defaults {
            out.push(format!("{mime}={id};"));
        } else {
            if !found_section {
                if !out.is_empty() && !out.last().is_some_and(|l| l.is_empty()) {
                    out.push(String::new());
                }
                out.push("[Default Applications]".into());
            }
            out.push(format!("{mime}={id};"));
        }
        changed = true;
    }
    changed.then(|| out.join("\n") + "\n")
}

fn refresh_desktop_db(ctx: &Context, dir: &Path) {
    if ctx.runner.which("update-desktop-database").is_some() {
        let _ = ctx.runner.run(&Cmd::new("update-desktop-database").arg_path(dir));
    }
}

fn register_linux(ctx: &Context, opts: &ProtocolOptions) -> Result<Change> {
    if opts.scope == TrustScope::Machine && !ctx.elevated {
        return Err(SystemError::NotElevated(
            "registro del protocolo para todos los usuarios".into(),
        ));
    }
    let mut changed = false;
    let mut mime_changed = false;
    for (path, content, mode) in linux_files(ctx, opts) {
        if fsutil::read_text_opt(&path)?.as_deref() != Some(content.as_str()) {
            fsutil::write_atomic(&path, content.as_bytes(), Some(mode))?;
            changed = true;
            mime_changed |= path.extension().is_some_and(|e| e == "xml");
        }
    }
    let ml = linux_mimeapps(ctx, opts.scope);
    let id = format!("{}.desktop", ctx.app.desktop_id);
    let text = fsutil::read_text_opt(&ml)?.unwrap_or_default();
    if let Some(new) = edit_mimeapps(&text, &format!("x-scheme-handler/{SCHEME}"), Some(&id), &id) {
        fsutil::write_atomic(&ml, new.as_bytes(), Some(0o644))?;
        changed = true;
    }
    if changed {
        refresh_desktop_db(ctx, &linux_apps_dir(ctx, opts));
    }
    if mime_changed && ctx.runner.which("update-mime-database").is_some() {
        let mime_root = match opts.scope {
            TrustScope::Machine => ctx.sys("/usr/local/share/mime"),
            TrustScope::User => ctx.paths.home.join(".local/share/mime"),
        };
        let _ = ctx.runner.run(&Cmd::new("update-mime-database").arg_path(&mime_root));
    }
    Ok(if changed { Change::Changed } else { Change::Unchanged })
}

fn unregister_linux(ctx: &Context, opts: &ProtocolOptions) -> Result<Change> {
    let mut changed = false;
    let all = ProtocolOptions {
        menus: ContextMenus {
            sign: true,
            verify: true,
            hash: true,
        },
        write_desktop_file: true,
        ..opts.clone()
    };
    // Los scripts de Nautilus se buscan aunque el directorio padre se haya borrado.
    let mut files: Vec<PathBuf> = linux_files(ctx, &all).into_iter().map(|(p, _, _)| p).collect();
    files.push(
        ctx.paths
            .home
            .join(format!(".local/share/nautilus/scripts/{}", labels(&opts.locale).sign)),
    );
    for p in files {
        // Solo ficheros generados por nosotros.
        if let Some(t) = fsutil::read_text_opt(&p)?
            && (t.contains(&ctx.app.exe.to_string_lossy().to_string())
                || t.contains("Generado por AutoFirma")
                || t.contains("autofirma-csig")
                || t.contains(SCHEME))
        {
            changed |= fsutil::remove_file_if_exists(&p)?;
        }
    }
    let ml = linux_mimeapps(ctx, opts.scope);
    let id = format!("{}.desktop", ctx.app.desktop_id);
    if let Some(text) = fsutil::read_text_opt(&ml)?
        && let Some(new) = edit_mimeapps(&text, &format!("x-scheme-handler/{SCHEME}"), None, &id)
    {
        fsutil::write_atomic(&ml, new.as_bytes(), None)?;
        changed = true;
    }
    if changed {
        refresh_desktop_db(ctx, &linux_apps_dir(ctx, opts));
    }
    Ok(if changed { Change::Changed } else { Change::Unchanged })
}

fn status_linux(ctx: &Context) -> ProtocolStatus {
    let mime = format!("x-scheme-handler/{SCHEME}");
    // Prioridad XDG: usuario, sistema.
    let candidates = [
        ctx.paths.home.join(".config/mimeapps.list"),
        ctx.sys("/etc/xdg/mimeapps.list"),
        ctx.sys("/usr/local/share/applications/mimeapps.list"),
        ctx.sys("/usr/share/applications/mimeapps.list"),
    ];
    let mut handler = None;
    for c in &candidates {
        if let Ok(t) = std::fs::read_to_string(c) {
            let mut in_def = false;
            for line in t.lines() {
                let l = line.trim();
                if l.starts_with('[') {
                    in_def = l == "[Default Applications]";
                } else if in_def
                    && let Some((k, v)) = l.split_once('=')
                    && k.trim() == mime
                {
                    handler = v
                        .split(';')
                        .next()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
            }
        }
        if handler.is_some() {
            break;
        }
    }
    let dirs = [
        ctx.paths.home.join(".local/share/applications"),
        ctx.sys("/usr/local/share/applications"),
        ctx.sys("/usr/share/applications"),
    ];
    // Si no hay valor por defecto, cualquier .desktop que declare el tipo sirve.
    let desktop = handler.clone().or_else(|| {
        dirs.iter().find_map(|d| {
            std::fs::read_dir(d).ok()?.flatten().find_map(|e| {
                let t = std::fs::read_to_string(e.path()).ok()?;
                t.contains(&format!("{mime};"))
                    .then(|| e.file_name().to_string_lossy().into_owned())
            })
        })
    });
    let Some(desktop) = desktop else {
        return ProtocolStatus {
            registered: false,
            handler: None,
            points_to_current: false,
            scope: None,
            detail: "ningún fichero .desktop declara x-scheme-handler/afirma".into(),
        };
    };
    let file = dirs.iter().map(|d| d.join(&desktop)).find(|p| p.is_file());
    let exec = file
        .as_ref()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .and_then(|t| t.lines().find(|l| l.starts_with("Exec=")).map(|l| l[5..].to_string()));
    let points = exec
        .as_ref()
        .is_some_and(|e| e.contains(&*ctx.app.exe.to_string_lossy()));
    ProtocolStatus {
        registered: file.is_some(),
        handler: Some(desktop.clone()),
        points_to_current: points,
        scope: file.as_ref().map(|f| {
            if f.starts_with(&ctx.paths.home) {
                TrustScope::User
            } else {
                TrustScope::Machine
            }
        }),
        detail: match (&file, &exec) {
            (None, _) => format!("{desktop} no existe"),
            (Some(_), Some(e)) => format!("Exec={e}"),
            _ => String::new(),
        },
    }
}

// ---------------------------------------------------------------- macOS

/// Fragmento de `Info.plist` que declara el esquema `afirma` (como el lanzador de Java).
pub fn macos_info_plist_fragment() -> String {
    format!(
        "<key>CFBundleURLTypes</key>\n<array>\n\t<dict>\n\t\t<key>CFBundleURLName</key>\n\t\t<string>Protocolo de invocación de Autofirma</string>\n\t\t<key>CFBundleURLSchemes</key>\n\t\t<array>\n\t\t\t<string>{SCHEME}</string>\n\t\t</array>\n\t</dict>\n</array>\n"
    )
}

/// Herramienta `lsregister`.
pub const LSREGISTER: &str =
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

fn register_macos(ctx: &Context) -> Result<Change> {
    let bundle = ctx
        .app
        .macos_bundle
        .clone()
        .ok_or_else(|| SystemError::Other("la aplicación no se ejecuta desde un paquete .app".into()))?;
    let o = ctx
        .runner
        .run(&Cmd::new(LSREGISTER).args(["-f", "-R", "-trusted"]).arg_path(&bundle))
        .map_err(|e| SystemError::Command {
            program: "lsregister".into(),
            detail: e.to_string(),
        })?;
    if !o.success() {
        return Err(SystemError::Command {
            program: "lsregister".into(),
            detail: o.message(),
        });
    }
    // El manejador por defecto es por usuario; desde un instalador como root no tiene efecto
    // para los usuarios (la aplicación lo vuelve a fijar en su primer arranque).
    if !ctx.elevated {
        macos_ls::set_default_handler(SCHEME, &ctx.app.macos_bundle_id)?;
    }
    Ok(Change::Changed)
}

fn status_macos(ctx: &Context) -> ProtocolStatus {
    match macos_ls::default_handler(SCHEME) {
        Some(id) => ProtocolStatus {
            registered: true,
            points_to_current: id.eq_ignore_ascii_case(&ctx.app.macos_bundle_id),
            handler: Some(id),
            scope: Some(TrustScope::User),
            detail: String::new(),
        },
        None => ProtocolStatus {
            registered: false,
            handler: None,
            points_to_current: false,
            scope: None,
            detail: "LaunchServices no tiene manejador para afirma://".into(),
        },
    }
}

mod macos_ls {
    //! LaunchServices (`LSSetDefaultHandlerForURLScheme`, `LSCopyDefaultHandlerForURLScheme`).
    //! **FFI** con CoreFoundation/CoreServices: cadenas CF creadas y liberadas aquí.
    use crate::error::{Result, SystemError};

    #[cfg(target_os = "macos")]
    mod ffi {
        use std::ffi::c_void;
        pub type CFStringRef = *const c_void;
        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            pub fn CFStringCreateWithBytes(
                alloc: *const c_void,
                bytes: *const u8,
                len: isize,
                enc: u32,
                ext: u8,
            ) -> CFStringRef;
            pub fn CFStringGetCString(s: CFStringRef, buf: *mut u8, size: isize, enc: u32) -> u8;
            pub fn CFRelease(p: *const c_void);
        }
        #[link(name = "CoreServices", kind = "framework")]
        unsafe extern "C" {
            pub fn LSSetDefaultHandlerForURLScheme(scheme: CFStringRef, bundle: CFStringRef) -> i32;
            pub fn LSCopyDefaultHandlerForURLScheme(scheme: CFStringRef) -> CFStringRef;
        }
        pub const UTF8: u32 = 0x0800_0100;

        pub fn cf(s: &str) -> CFStringRef {
            // SAFETY: bytes válidos durante la llamada; el resultado se libera con CFRelease.
            unsafe { CFStringCreateWithBytes(std::ptr::null(), s.as_ptr(), s.len() as isize, UTF8, 0) }
        }
    }

    /// Fija la aplicación por defecto del esquema para el usuario actual.
    #[cfg(target_os = "macos")]
    pub fn set_default_handler(scheme: &str, bundle_id: &str) -> Result<()> {
        let s = ffi::cf(scheme);
        let b = ffi::cf(bundle_id);
        // SAFETY: cadenas CF válidas, liberadas después.
        let rv = unsafe {
            let rv = ffi::LSSetDefaultHandlerForURLScheme(s, b);
            ffi::CFRelease(s);
            ffi::CFRelease(b);
            rv
        };
        if rv == 0 {
            Ok(())
        } else {
            Err(SystemError::Other(format!(
                "LSSetDefaultHandlerForURLScheme: OSStatus {rv}"
            )))
        }
    }

    /// Identificador de la aplicación por defecto del esquema.
    #[cfg(target_os = "macos")]
    pub fn default_handler(scheme: &str) -> Option<String> {
        let s = ffi::cf(scheme);
        // SAFETY: cadena CF válida; el resultado (regla «Copy») se libera.
        unsafe {
            let r = ffi::LSCopyDefaultHandlerForURLScheme(s);
            ffi::CFRelease(s);
            if r.is_null() {
                return None;
            }
            let mut buf = vec![0u8; 512];
            let ok = ffi::CFStringGetCString(r, buf.as_mut_ptr(), buf.len() as isize, ffi::UTF8);
            ffi::CFRelease(r);
            if ok == 0 {
                return None;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..end]).into_owned())
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn set_default_handler(_scheme: &str, _bundle_id: &str) -> Result<()> {
        Err(SystemError::Unsupported("LaunchServices".into()))
    }

    #[cfg(not(target_os = "macos"))]
    pub fn default_handler(_scheme: &str) -> Option<String> {
        None
    }
}

/// Fija (por usuario) AutoFirma como aplicación de `afirma://` en macOS. Pensado para el
/// primer arranque de la aplicación, ya que el instalador se ejecuta como root.
pub fn macos_set_default_handler(ctx: &Context) -> Result<()> {
    macos_ls::set_default_handler(SCHEME, &ctx.app.macos_bundle_id)
}

// ---------------------------------------------------------------- API común

/// Registra el protocolo (y los menús). Idempotente.
pub fn register(ctx: &Context, opts: &ProtocolOptions) -> Result<Change> {
    match ctx.os {
        Os::Windows => {
            if opts.scope == TrustScope::Machine && !ctx.elevated {
                return Err(SystemError::NotElevated("registro del protocolo en HKLM".into()));
            }
            register_windows(ctx, opts)
        }
        Os::Linux => register_linux(ctx, opts),
        Os::MacOs => register_macos(ctx),
    }
}

/// Elimina el registro del protocolo y los menús propios.
pub fn unregister(ctx: &Context, opts: &ProtocolOptions) -> Result<Change> {
    match ctx.os {
        Os::Windows => unregister_windows(ctx, opts.scope),
        Os::Linux => unregister_linux(ctx, opts),
        // El esquema desaparece con el paquete .app.
        Os::MacOs => Ok(Change::Unchanged),
    }
}

/// Estado del registro del protocolo.
pub fn status(ctx: &Context) -> ProtocolStatus {
    match ctx.os {
        Os::Windows => status_windows(ctx),
        Os::Linux => status_linux(ctx),
        Os::MacOs => status_macos(ctx),
    }
}

/// Preferencias de Firefox para el protocolo (paquete `.deb` de Java, `AutoFirma.js`).
pub fn firefox_protocol_prefs(exe: &Path) -> String {
    format!(
        "pref(\"network.protocol-handler.expose.afirma\",false);\npref(\"network.protocol-handler.external.afirma\",true);\npref(\"network.protocol-handler.warn-external.afirma\",false);\npref(\"network.protocol-handler.app.afirma\",\"{}\");\n",
        exe.display()
    )
}

/// Directorios de preferencias por defecto de Firefox existentes (Linux).
pub fn firefox_pref_dirs(ctx: &Context) -> Vec<PathBuf> {
    [
        "/usr/lib/firefox/defaults/pref",
        "/usr/lib64/firefox/defaults/pref",
        "/usr/lib/firefox-esr/defaults/pref",
        "/usr/lib64/firefox-esr/defaults/pref",
        "/etc/firefox/pref",
        "/etc/firefox-esr/pref",
    ]
    .iter()
    .map(|d| ctx.sys(d))
    .filter(|d| d.is_dir())
    .collect()
}

/// Escribe `autofirma.js` en los directorios de preferencias de Firefox (paso de protocolo
/// de «Restaurar instalación» en Linux, que en Java fallaba siempre por un recurso ausente).
pub fn install_firefox_protocol_prefs(ctx: &Context) -> Result<Change> {
    if !ctx.elevated {
        return Err(SystemError::NotElevated("preferencias de Firefox del sistema".into()));
    }
    let content = firefox_protocol_prefs(&ctx.app.exe);
    let mut changed = false;
    for d in firefox_pref_dirs(ctx) {
        let p = d.join("autofirma.js");
        if fsutil::read_text_opt(&p)?.as_deref() != Some(content.as_str()) {
            fsutil::write_atomic(&p, content.as_bytes(), Some(0o644))?;
            changed = true;
        }
    }
    Ok(if changed { Change::Changed } else { Change::Unchanged })
}

/// Retira `autofirma.js` de los directorios de preferencias de Firefox.
pub fn remove_firefox_protocol_prefs(ctx: &Context) -> Result<Change> {
    let mut changed = false;
    for d in firefox_pref_dirs(ctx) {
        changed |= fsutil::remove_file_if_exists(&d.join("autofirma.js"))?;
    }
    Ok(if changed { Change::Changed } else { Change::Unchanged })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_entrecomilla_y_es_idempotente() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Windows, t.path());
        ctx.app.exe = PathBuf::from(r"C:\Program Files\Autofirma\Autofirma.exe");
        let opts = ProtocolOptions::default();
        assert_eq!(register(&ctx, &opts).unwrap(), Change::Changed);
        assert_eq!(register(&ctx, &opts).unwrap(), Change::Unchanged);
        let r = &ctx.registry;
        assert_eq!(
            r.read_string(Hive::CurrentUser, r"Software\Classes\afirma\shell\open\command", "")
                .unwrap()
                .unwrap(),
            "\"C:\\Program Files\\Autofirma\\Autofirma.exe\" \"%1\""
        );
        assert_eq!(
            r.read_string(Hive::CurrentUser, r"Software\Classes\*\shell\afirma.sign\command", "")
                .unwrap()
                .unwrap(),
            "\"C:\\Program Files\\Autofirma\\Autofirma.exe\" sign -gui -i \"%1\""
        );
        assert_eq!(
            r.read_string(Hive::CurrentUser, r"Software\Classes\.csig", "")
                .unwrap()
                .unwrap(),
            "Autofirma.csig"
        );
        let st = status(&ctx);
        assert!(st.registered && st.points_to_current && st.scope == Some(TrustScope::User));
        // Sin privilegios no se puede registrar para el equipo.
        assert!(
            register(
                &ctx,
                &ProtocolOptions {
                    scope: TrustScope::Machine,
                    ..Default::default()
                }
            )
            .is_err()
        );
        // Una extensión con otro propietario no se toca.
        r.write(
            Hive::CurrentUser,
            r"Software\Classes\.xsig",
            "",
            &RegValue::Sz("OtraApp.xsig".into()),
        )
        .unwrap();
        register(&ctx, &opts).unwrap();
        assert_eq!(
            r.read_string(Hive::CurrentUser, r"Software\Classes\.xsig", "")
                .unwrap()
                .unwrap(),
            "OtraApp.xsig"
        );
        assert_eq!(unregister(&ctx, &opts).unwrap(), Change::Changed);
        assert!(!r.key_exists(Hive::CurrentUser, r"Software\Classes\afirma").unwrap());
        assert_eq!(
            r.read_string(Hive::CurrentUser, r"Software\Classes\.xsig", "")
                .unwrap()
                .unwrap(),
            "OtraApp.xsig"
        );
        assert!(!r.key_exists(Hive::CurrentUser, r"Software\Classes\.csig").unwrap());
        assert!(!status(&ctx).registered);
    }

    #[test]
    fn windows_limpia_restos_de_java() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Windows, t.path());
        ctx.elevated = true;
        let r = &ctx.registry;
        r.write(
            Hive::LocalMachine,
            r"Software\Classes\.csig",
            "",
            &RegValue::Sz("Firma binaria CMS/CAdES".into()),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            r"Software\Classes\.csig\shell\Verify\command",
            "",
            &RegValue::Sz(r"C:\Program Files\Autofirma\Autofirma\Autofirma.exe verify -gui -i %1".into()),
        )
        .unwrap();
        register(
            &ctx,
            &ProtocolOptions {
                scope: TrustScope::Machine,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            !r.key_exists(Hive::LocalMachine, r"Software\Classes\.csig\shell\Verify")
                .unwrap()
        );
        assert_eq!(
            r.read_string(Hive::LocalMachine, r"Software\Classes\.csig", "")
                .unwrap()
                .unwrap(),
            "Autofirma.csig"
        );
    }

    #[test]
    fn linux_desktop_y_mimeapps() {
        let t = tempfile::tempdir().unwrap();
        let mut ctx = Context::for_tests(Os::Linux, t.path());
        ctx.app.exe = PathBuf::from("/opt/Auto Firma/autofirma");
        let home = ctx.paths.home.clone();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(home.join(".config/mimeapps.list"), "[Added Associations]\ntext/plain=gedit.desktop;\n\n[Default Applications]\nx-scheme-handler/afirma=afirma.desktop;\ntext/html=firefox.desktop;\n").unwrap();
        let opts = ProtocolOptions::default();
        assert_eq!(register(&ctx, &opts).unwrap(), Change::Changed);
        let d = std::fs::read_to_string(home.join(".local/share/applications/autofirma.desktop")).unwrap();
        assert!(d.contains("Exec=\"/opt/Auto Firma/autofirma\" %u"), "{d}");
        assert!(d.contains("MimeType=x-scheme-handler/afirma;"));
        let ml = std::fs::read_to_string(home.join(".config/mimeapps.list")).unwrap();
        assert!(
            ml.contains("x-scheme-handler/afirma=autofirma.desktop;")
                && ml.contains("text/html=firefox.desktop;")
                && ml.contains("text/plain=gedit.desktop;")
        );
        assert_eq!(ml.matches("x-scheme-handler/afirma").count(), 1);
        assert_eq!(register(&ctx, &opts).unwrap(), Change::Unchanged);
        let st = status(&ctx);
        assert!(st.registered && st.points_to_current, "{st:?}");
        assert!(home.join(".local/share/mime/packages/autofirma.xml").is_file());
        assert_eq!(unregister(&ctx, &opts).unwrap(), Change::Changed);
        let ml = std::fs::read_to_string(home.join(".config/mimeapps.list")).unwrap();
        assert!(!ml.contains("x-scheme-handler/afirma") && ml.contains("text/html=firefox.desktop;"));
        assert!(!home.join(".local/share/applications/autofirma.desktop").exists());
    }

    #[test]
    fn mimeapps_crea_seccion() {
        assert_eq!(
            edit_mimeapps("", "x-scheme-handler/afirma", Some("a.desktop"), "a.desktop").unwrap(),
            "[Default Applications]\nx-scheme-handler/afirma=a.desktop;\n"
        );
        let t = "[Added Associations]\nx=y;\n";
        assert_eq!(
            edit_mimeapps(t, "m", Some("a.desktop"), "a.desktop").unwrap(),
            "[Added Associations]\nx=y;\n\n[Default Applications]\nm=a.desktop;\n"
        );
        assert!(
            edit_mimeapps("[Default Applications]\nm=otra.desktop;\n", "m", None, "a.desktop").is_none(),
            "no se quita lo ajeno"
        );
    }

    #[test]
    fn plist_de_macos() {
        assert!(macos_info_plist_fragment().contains("<string>afirma</string>"));
        assert_eq!(desktop_exec_quote("/usr/bin/autofirma"), "/usr/bin/autofirma");
        assert_eq!(desktop_exec_quote("/a b/$x"), "\"/a b/\\\\$x\"");
    }
}
