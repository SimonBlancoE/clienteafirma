//! Lectura de las preferencias de la AutoFirma Java (`java.util.prefs`) para migrarlas y
//! para respetar los valores de administrador ya desplegados:
//!
//! * Windows: registro `HKCU|HKLM\Software\JavaSoft\Prefs\...` con el escapado de
//!   `WindowsPreferences` (mayúsculas precedidas de `/`, `/`↔`\`, `/uXXXX`, nombres `/!`+alt-base64).
//! * Linux/Unix: `~/.java/.userPrefs/<nodo>/prefs.xml` y `/etc/.java/.systemPrefs/<nodo>/prefs.xml`.
//! * macOS: `~/Library/Preferences/com.apple.java.util.prefs.plist` y
//!   `/Library/Preferences/com.apple.java.util.prefs.plist` (diccionarios anidados `"nodo/"`).

use std::io;
use std::path::{Path, PathBuf};

use quick_xml::events::Event;

use super::tree::{NODE_AFIRMA_ROOT, PrefsTree};
use crate::ctx::{Context, Os};
use crate::error::{Result, SystemError};
use crate::registry::{Hive, Registry};

/// Alfabeto «alt-base64» de `java.util.prefs.Base64` (seguro para nombres de fichero y de
/// registro insensibles a mayúsculas).
const ALT_B64: &[u8; 64] = b"!\"#$%&'(),-.:;<>@[]^`_{|}~abcdefghijklmnopqrstuvwxyz0123456789+?";

/// Codifica en alt-base64 (con relleno `=`, como el JDK).
pub fn alt_base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(ALT_B64[(b0 >> 2) as usize] as char);
        out.push(ALT_B64[(((b0 << 4) & 0x3f) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALT_B64[(((b1 << 2) & 0x3f) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALT_B64[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodifica alt-base64.
pub fn alt_base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        vals.push(ALT_B64.iter().position(|&a| a == c)? as u32);
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        if chunk.len() < 2 {
            return None;
        }
        out.push(((chunk[0] << 2) | (chunk[1] >> 4)) as u8);
        if chunk.len() > 2 {
            out.push((((chunk[1] & 0xf) << 4) | (chunk[2] >> 2)) as u8);
        }
        if chunk.len() > 3 {
            out.push((((chunk[2] & 3) << 6) | chunk[3]) as u8);
        }
    }
    Some(out)
}

fn utf16be_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

fn utf16be_string(b: &[u8]) -> Option<String> {
    if b.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = b
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Codifica un nombre (clave o nodo) como `WindowsPreferences.toWindowsName`.
pub fn win_encode_name(name: &str) -> String {
    if name.chars().any(|c| (c as u32) < 0x20 || (c as u32) > 0x7f) {
        return format!("/!{}", alt_base64_encode(&utf16be_bytes(name)));
    }
    let mut out = String::new();
    for c in name.chars() {
        match c {
            '\\' => out.push_str("//"),
            '/' => out.push('\\'),
            'A'..='Z' => {
                out.push('/');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Decodifica un nombre del registro (`WindowsPreferences.toJavaName`).
pub fn win_decode_name(win: &str) -> String {
    if let Some(rest) = win.strip_prefix("/!")
        && let Some(s) = alt_base64_decode(rest).and_then(|b| utf16be_string(&b))
    {
        return s;
    }
    decode_common(win, false)
}

/// Codifica un valor (`WindowsPreferences.toWindowsValueString`).
pub fn win_encode_value(value: &str) -> String {
    let mut out = String::new();
    for u in value.encode_utf16() {
        match u {
            0x5c => out.push_str("//"),
            0x2f => out.push('\\'),
            0x41..=0x5a => {
                out.push('/');
                out.push(u as u8 as char);
            }
            u if !(0x20..=0x7f).contains(&u) => out.push_str(&format!("/u{u:04x}")),
            u => out.push(u as u8 as char),
        }
    }
    out
}

/// Decodifica un valor del registro (`WindowsPreferences.toJavaValueString`).
pub fn win_decode_value(win: &str) -> String {
    decode_common(win, true)
}

fn decode_common(win: &str, values: bool) -> String {
    let chars: Vec<char> = win.chars().collect();
    let mut units: Vec<u16> = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '/' {
            let next = chars.get(i + 1).copied();
            if values && next == Some('u') {
                if i + 6 > chars.len() {
                    break; // Igual que Java: valor truncado.
                }
                let hex: String = chars[i + 2..i + 6].iter().collect();
                if let Ok(v) = u16::from_str_radix(&hex, 16) {
                    units.push(v);
                    i += 6;
                    continue;
                }
            }
            match next {
                Some(n @ 'A'..='Z') => {
                    units.push(n as u16);
                    i += 2;
                    continue;
                }
                Some('/') => {
                    units.push('\\' as u16);
                    i += 2;
                    continue;
                }
                _ => units.push('/' as u16),
            }
        } else if c == '\\' {
            units.push('/' as u16);
        } else {
            let mut buf = [0u16; 2];
            units.extend_from_slice(c.encode_utf16(&mut buf));
        }
        i += 1;
    }
    String::from_utf16_lossy(&units)
}

/// Clave base de `java.util.prefs` en el registro.
pub const WIN_PREFS_BASE: &str = r"Software\JavaSoft\Prefs";
/// Clave base para JVM de 32 bits en Windows de 64 bits (solo HKLM).
pub const WIN_PREFS_BASE_WOW: &str = r"Software\WOW6432Node\JavaSoft\Prefs";

/// Ruta de registro de un nodo Java.
pub fn win_node_key(base: &str, node: &str) -> String {
    let mut k = base.to_string();
    for comp in node.split('/').filter(|c| !c.is_empty()) {
        k.push('\\');
        k.push_str(&win_encode_name(comp));
    }
    k
}

/// Lee recursivamente el subárbol `node` de las preferencias Java del registro.
pub fn read_windows_tree(
    reg: &dyn Registry,
    hive: Hive,
    base: &str,
    node: &str,
) -> io::Result<PrefsTree> {
    let mut tree = PrefsTree::new();
    read_win_rec(reg, hive, &win_node_key(base, node), node, &mut tree, 0)?;
    Ok(tree)
}

fn read_win_rec(
    reg: &dyn Registry,
    hive: Hive,
    key: &str,
    node: &str,
    tree: &mut PrefsTree,
    depth: usize,
) -> io::Result<()> {
    if depth > 16 {
        return Ok(());
    }
    let Some(values) = reg.values(hive, key)? else {
        return Ok(());
    };
    let mut map = std::collections::BTreeMap::new();
    for (name, v) in values {
        if name.is_empty() {
            continue;
        }
        if let Some(s) = v.as_string() {
            // Java guarda las cadenas terminadas en NUL; el lector puede devolverlo.
            let s = s.trim_end_matches('\0');
            map.insert(win_decode_name(&name), win_decode_value(s));
        }
    }
    if !map.is_empty() {
        tree.node_mut(node).extend(map);
    }
    for sub in reg.subkeys(hive, key)?.unwrap_or_default() {
        let child = format!("{node}/{}", win_decode_name(&sub));
        read_win_rec(reg, hive, &format!("{key}\\{sub}"), &child, tree, depth + 1)?;
    }
    Ok(())
}

/// Nombre de directorio de un nodo (`FileSystemPreferences.dirName`).
pub fn unix_dir_name(node_name: &str) -> String {
    let ok = node_name
        .chars()
        .all(|c| c > '\u{1f}' && c < '\u{7f}' && c != '/' && c != '.' && c != '_');
    if ok {
        node_name.to_string()
    } else {
        format!("_{}", alt_base64_encode(&utf16be_bytes(node_name)))
    }
}

/// Nombre de nodo a partir del directorio (`FileSystemPreferences.nodeName`).
pub fn unix_node_name(dir_name: &str) -> String {
    match dir_name.strip_prefix('_') {
        Some(rest) => alt_base64_decode(rest)
            .and_then(|b| utf16be_string(&b))
            .unwrap_or_else(|| dir_name.to_string()),
        None => dir_name.to_string(),
    }
}

/// Analiza un `prefs.xml` de `java.util.prefs` (`<map><entry key="" value=""/></map>`).
pub fn parse_prefs_xml(
    data: &[u8],
) -> std::result::Result<std::collections::BTreeMap<String, String>, String> {
    let mut reader = quick_xml::Reader::from_reader(data);
    reader.config_mut().trim_text(true);
    let mut out = std::collections::BTreeMap::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) | Ok(Event::Start(e)) if e.name().as_ref() == b"entry" => {
                let mut k = None;
                let mut v = None;
                for a in e.attributes().flatten() {
                    let val = a.unescape_value().map_err(|e| e.to_string())?.into_owned();
                    match a.key.as_ref() {
                        b"key" => k = Some(val),
                        b"value" => v = Some(val),
                        _ => {}
                    }
                }
                if let (Some(k), Some(v)) = (k, v) {
                    out.insert(k, v);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(e.to_string()),
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

/// Serializa un mapa como `prefs.xml` (formato del JDK), para pruebas y exportación.
pub fn write_prefs_xml(map: &std::collections::BTreeMap<String, String>) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<!DOCTYPE map SYSTEM \"http://java.sun.com/dtd/preferences.dtd\">\n<map MAP_XML_VERSION=\"1.0\">\n",
    );
    for (k, v) in map {
        s.push_str(&format!(
            "  <entry key=\"{}\" value=\"{}\"/>\n",
            xml_attr(k),
            xml_attr(v)
        ));
    }
    s.push_str("</map>\n");
    s
}

fn xml_attr(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 => o.push_str(&format!("&#{};", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Lee el subárbol `node` de un árbol de preferencias Java en ficheros (`.userPrefs` o `.systemPrefs`).
pub fn read_unix_tree(root: &Path, node: &str) -> Result<PrefsTree> {
    let mut dir = root.to_path_buf();
    for comp in node.split('/').filter(|c| !c.is_empty()) {
        dir.push(unix_dir_name(comp));
    }
    let mut tree = PrefsTree::new();
    read_unix_rec(&dir, node, &mut tree, 0)?;
    Ok(tree)
}

fn read_unix_rec(dir: &Path, node: &str, tree: &mut PrefsTree, depth: usize) -> Result<()> {
    if depth > 16 || !dir.is_dir() {
        return Ok(());
    }
    let prefs = dir.join("prefs.xml");
    if let Some(data) = crate::fsutil::read_opt(&prefs)? {
        match parse_prefs_xml(&data) {
            Ok(m) if !m.is_empty() => tree.node_mut(node).extend(m),
            Ok(_) => {}
            Err(e) => tracing::warn!("prefs.xml no válido en {}: {e}", prefs.display()),
        }
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut subs: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    subs.sort();
    for s in subs {
        let name = s
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.starts_with('.') {
            continue;
        }
        read_unix_rec(
            &s,
            &format!("{node}/{}", unix_node_name(&name)),
            tree,
            depth + 1,
        )?;
    }
    Ok(())
}

/// Lee el subárbol `node` del plist de preferencias Java de macOS.
pub fn read_macos_tree(plist_path: &Path, node: &str) -> Result<PrefsTree> {
    let mut tree = PrefsTree::new();
    if !plist_path.is_file() {
        return Ok(tree);
    }
    let v = plist::Value::from_file(plist_path).map_err(|e| SystemError::Format {
        path: plist_path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let Some(root) = v.as_dictionary() else {
        return Ok(tree);
    };
    let mut cur = root
        .get("/")
        .and_then(|v| v.as_dictionary())
        .unwrap_or(root);
    for comp in node.split('/').filter(|c| !c.is_empty()) {
        match cur.get(&format!("{comp}/")).and_then(|v| v.as_dictionary()) {
            Some(d) => cur = d,
            None => return Ok(tree),
        }
    }
    read_mac_rec(cur, node, &mut tree, 0);
    Ok(tree)
}

fn read_mac_rec(dict: &plist::Dictionary, node: &str, tree: &mut PrefsTree, depth: usize) {
    if depth > 16 {
        return;
    }
    for (k, v) in dict {
        if let Some(child) = k.strip_suffix('/') {
            if let Some(d) = v.as_dictionary() {
                read_mac_rec(d, &format!("{node}/{child}"), tree, depth + 1);
            }
        } else if let Some(s) = v.as_string() {
            tree.put(node, k, s);
        } else if let Some(b) = v.as_boolean() {
            tree.put(node, k, if b { "true" } else { "false" });
        }
    }
}

/// Capa de las preferencias Java heredadas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyScope {
    /// Raíz de usuario.
    User,
    /// Raíz de sistema.
    System,
}

/// Lee todos los nodos de AutoFirma (`/es/gob/afirma/...`) de la ubicación Java heredada.
/// Devuelve el árbol y una descripción del origen. Los errores se registran y dan un árbol vacío.
pub fn read_legacy(ctx: &Context, scope: LegacyScope) -> (PrefsTree, String) {
    let res: Result<(PrefsTree, String)> = (|| match ctx.os {
        Os::Windows => {
            let hive = if scope == LegacyScope::User {
                Hive::CurrentUser
            } else {
                Hive::LocalMachine
            };
            let mut t = PrefsTree::new();
            if hive == Hive::LocalMachine {
                // JVM de 32 bits: vista WOW6432Node (menor prioridad).
                t = read_windows_tree(
                    ctx.registry.as_ref(),
                    hive,
                    WIN_PREFS_BASE_WOW,
                    NODE_AFIRMA_ROOT,
                )?;
            }
            let main = read_windows_tree(
                ctx.registry.as_ref(),
                hive,
                WIN_PREFS_BASE,
                NODE_AFIRMA_ROOT,
            )?;
            t.merge_from(&main);
            Ok((t, format!("{}\\{}", hive.short(), WIN_PREFS_BASE)))
        }
        Os::MacOs => {
            let p = match scope {
                LegacyScope::User => ctx
                    .paths
                    .home
                    .join("Library/Preferences/com.apple.java.util.prefs.plist"),
                LegacyScope::System => {
                    ctx.sys("/Library/Preferences/com.apple.java.util.prefs.plist")
                }
            };
            Ok((
                read_macos_tree(&p, NODE_AFIRMA_ROOT)?,
                p.display().to_string(),
            ))
        }
        Os::Linux => {
            let p = match scope {
                LegacyScope::User => ctx.paths.home.join(".java/.userPrefs"),
                LegacyScope::System => ctx.sys("/etc/.java/.systemPrefs"),
            };
            Ok((
                read_unix_tree(&p, NODE_AFIRMA_ROOT)?,
                p.display().to_string(),
            ))
        }
    })();
    match res {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("No se pudieron leer las preferencias Java heredadas ({scope:?}): {e}");
            (PrefsTree::new(), String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{MemoryRegistry, RegValue};

    #[test]
    fn escapado_windows_ejemplos_de_la_especificacion() {
        let cases = [
            ("preferencesBlocked", "true", "preferences/Blocked", "true"),
            (
                "signatureHashAlgorithm",
                "SHA512",
                "signature/Hash/Algorithm",
                "/S/H/A512",
            ),
            (
                "defaultSignatureFormatPdf",
                "PAdES",
                "default/Signature/Format/Pdf",
                "/P/Ad/E/S",
            ),
            (
                "xadesSignFormat",
                "XAdES Detached",
                "xades/Sign/Format",
                "/X/Ad/E/S /Detached",
            ),
            (
                "padesBasicFormat",
                "ETSI.CAdES.detached",
                "pades/Basic/Format",
                "/E/T/S/I./C/Ad/E/S.detached",
            ),
            ("default.locale", "es_ES", "default.locale", "es_/E/S"),
            (
                "configFileUrl",
                "https://intra/af.afconfig",
                "config/File/Url",
                r"https:\\intra\af.afconfig",
            ),
            (
                "defaultLocalKeystorePath",
                r"C:\certs\a.p12",
                "default/Local/Keystore/Path",
                "/C://certs//a.p12",
            ),
        ];
        for (k, v, wk, wv) in cases {
            assert_eq!(win_encode_name(k), wk);
            assert_eq!(win_encode_value(v), wv);
            assert_eq!(win_decode_name(wk), k);
            assert_eq!(win_decode_value(wv), v);
        }
        assert_eq!(win_encode_value("í"), "/u00ed");
        assert_eq!(win_decode_value("Firmado el d/u00eda"), "Firmado el día");
        let n = "Tarjeta España";
        let enc = win_encode_name(n);
        assert!(enc.starts_with("/!"));
        assert_eq!(win_decode_name(&enc), n);
    }

    #[test]
    fn alt_base64_ida_y_vuelta() {
        for s in [&b""[..], b"a", b"ab", b"abc", b"\x00\xff\x10\x20"] {
            assert_eq!(alt_base64_decode(&alt_base64_encode(s)).unwrap(), s);
        }
    }

    #[test]
    fn lectura_registro_java() {
        let r = MemoryRegistry::new();
        let k = win_node_key(WIN_PREFS_BASE, super::super::tree::NODE_MAIN);
        assert_eq!(
            k,
            r"Software\JavaSoft\Prefs\es\gob\afirma\standalone\ui\preferences"
        );
        r.write(
            Hive::LocalMachine,
            &k,
            "preferences/Blocked",
            &RegValue::Sz("true".into()),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            &k,
            "signature/Hash/Algorithm",
            &RegValue::Sz("/S/H/A512".into()),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            &format!(
                r"{}\1",
                win_node_key(WIN_PREFS_BASE, "/es/gob/afirma/core/keystores")
            ),
            "/Tarjeta",
            &RegValue::Sz(win_encode_value(r"C:\Windows\x.dll")),
        )
        .unwrap();
        let t =
            read_windows_tree(&r, Hive::LocalMachine, WIN_PREFS_BASE, NODE_AFIRMA_ROOT).unwrap();
        assert_eq!(
            t.get(super::super::tree::NODE_MAIN, "preferencesBlocked"),
            Some("true")
        );
        assert_eq!(
            t.get(super::super::tree::NODE_MAIN, "signatureHashAlgorithm"),
            Some("SHA512")
        );
        assert_eq!(
            t.get("/es/gob/afirma/core/keystores/1", "Tarjeta"),
            Some(r"C:\Windows\x.dll")
        );
    }

    #[test]
    fn lectura_xml_unix() {
        let d = tempfile::tempdir().unwrap();
        let node_dir = d.path().join("es/gob/afirma/standalone/ui/preferences");
        std::fs::create_dir_all(&node_dir).unwrap();
        let mut m = std::collections::BTreeMap::new();
        m.insert("preferencesBlocked".to_string(), "true".to_string());
        m.insert(
            "pdfLayer2Text".to_string(),
            "Firmado por <a> & \"b\"".to_string(),
        );
        std::fs::write(node_dir.join("prefs.xml"), write_prefs_xml(&m)).unwrap();
        let t = read_unix_tree(d.path(), NODE_AFIRMA_ROOT).unwrap();
        assert_eq!(t.node(super::super::tree::NODE_MAIN).unwrap(), &m);
    }
}
