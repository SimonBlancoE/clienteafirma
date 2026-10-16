//! Capa de directivas corporativas (nueva respecto a Java): valores impuestos por el
//! administrador que el usuario **no** puede cambiar (`mandatory`) y valores recomendados
//! que actúan como valores de sistema (`recommended`).
//!
//! Ubicaciones:
//!
//! | SO | Obligatorias | Recomendadas |
//! |---|---|---|
//! | Windows | `HKLM\SOFTWARE\Policies\AutoFirma` (y, con menor prioridad, `HKCU\SOFTWARE\Policies\AutoFirma`) | subclave `Recommended` |
//! | macOS | `/Library/Managed Preferences/<bundle-id>.plist` y `/Library/Managed Preferences/<usuario>/<bundle-id>.plist` (perfiles MDM) | clave `Recommended` (diccionario) del mismo plist |
//! | Linux | `/etc/autofirma/policy.json` y `/etc/autofirma/policy.d/*.json` (`{"mandatory":{...},"recommended":{...},"smartcards":{...}}`) | |
//!
//! Las tarjetas inteligentes impuestas se declaran en la subclave/clave `SmartCards`
//! (nombre → biblioteca PKCS#11).
//!
//! Los valores se aceptan como cadena, booleano (`REG_DWORD` 0/1, `<true/>`, `true`) o número
//! y se convierten a la representación textual de Java. Se comprueban contra el tipo de la
//! clave cuando es conocida; un valor no válido se descarta con un aviso.

use std::collections::BTreeMap;
use std::path::Path;

use super::keys::{self, Kind};
use crate::ctx::{Context, Os};
use crate::registry::{Hive, RegValue};

/// Clave de registro de las directivas de AutoFirma.
pub const WIN_POLICY_KEY: &str = r"SOFTWARE\Policies\AutoFirma";
/// Fichero principal de directivas en Linux.
pub const LINUX_POLICY_FILE: &str = "/etc/autofirma/policy.json";
/// Directorio de fragmentos de directivas en Linux.
pub const LINUX_POLICY_DIR: &str = "/etc/autofirma/policy.d";

/// Conjunto de directivas efectivas.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PolicySet {
    /// Valores obligatorios (bloqueados).
    pub mandatory: BTreeMap<String, String>,
    /// Valores recomendados (capa de sistema, el usuario puede cambiarlos).
    pub recommended: BTreeMap<String, String>,
    /// Tarjetas inteligentes impuestas (nombre → biblioteca).
    pub smartcards: BTreeMap<String, String>,
    /// Orígenes leídos.
    pub sources: Vec<String>,
    /// Avisos (valores descartados...).
    pub warnings: Vec<String>,
}

impl PolicySet {
    /// `true` si no hay ninguna directiva.
    pub fn is_empty(&self) -> bool {
        self.mandatory.is_empty() && self.recommended.is_empty() && self.smartcards.is_empty()
    }
}

/// Valor de directiva antes de normalizar.
#[derive(Debug, Clone)]
pub enum RawPolicyValue {
    Str(String),
    Bool(bool),
    Int(i64),
}

/// Normaliza un valor de directiva al texto de Java comprobando el tipo de la clave.
pub fn normalize(key: &str, raw: &RawPolicyValue) -> Result<String, String> {
    let info = keys::info(key);
    let text = match (raw, info.map(|i| i.kind)) {
        (RawPolicyValue::Bool(b), _) => b.to_string(),
        (RawPolicyValue::Int(i), Some(Kind::Bool)) => match i {
            0 => "false".into(),
            1 => "true".into(),
            _ => {
                return Err(format!(
                    "valor numérico {i} no válido para la clave booleana «{key}»"
                ));
            }
        },
        (RawPolicyValue::Int(i), _) => i.to_string(),
        (RawPolicyValue::Str(s), Some(Kind::Bool)) => {
            match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => "true".into(),
                "false" | "0" => "false".into(),
                _ => {
                    return Err(format!(
                        "valor «{s}» no válido para la clave booleana «{key}»"
                    ));
                }
            }
        }
        (RawPolicyValue::Str(s), _) => s.clone(),
    };
    if let Some(i) = info
        && !i.accepts(&text)
    {
        return Err(format!("valor «{text}» no válido para la clave «{key}»"));
    }
    Ok(text)
}

fn insert_checked(
    dst: &mut BTreeMap<String, String>,
    warnings: &mut Vec<String>,
    origin: &str,
    key: &str,
    raw: &RawPolicyValue,
    overwrite: bool,
) {
    if keys::info(key).is_none() {
        warnings.push(format!(
            "{origin}: clave desconocida «{key}» (se aplica igualmente)"
        ));
    }
    match normalize(key, raw) {
        Ok(v) => {
            if overwrite || !dst.contains_key(key) {
                dst.insert(key.to_string(), v);
            }
        }
        Err(e) => warnings.push(format!("{origin}: {e}")),
    }
}

/// Carga las directivas del sistema.
pub fn load(ctx: &Context) -> PolicySet {
    let mut ps = PolicySet::default();
    match ctx.os {
        Os::Windows => load_windows(ctx, &mut ps),
        Os::MacOs => load_macos(ctx, &mut ps),
        Os::Linux => load_linux(ctx, &mut ps),
    }
    ps
}

fn reg_to_raw(v: &RegValue) -> Option<RawPolicyValue> {
    match v {
        RegValue::Sz(s) | RegValue::ExpandSz(s) => Some(RawPolicyValue::Str(s.clone())),
        RegValue::Dword(d) => Some(RawPolicyValue::Int(*d as i64)),
        RegValue::Qword(d) => Some(RawPolicyValue::Int(*d as i64)),
        _ => None,
    }
}

fn load_windows(ctx: &Context, ps: &mut PolicySet) {
    // HKLM tiene prioridad sobre HKCU (se lee primero y no se sobrescribe).
    for hive in [Hive::LocalMachine, Hive::CurrentUser] {
        let origin = format!("{}\\{}", hive.short(), WIN_POLICY_KEY);
        let vals = match ctx.registry.values(hive, WIN_POLICY_KEY) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => {
                ps.warnings.push(format!("{origin}: {e}"));
                continue;
            }
        };
        ps.sources.push(origin.clone());
        for (name, v) in vals {
            if let Some(raw) = reg_to_raw(&v)
                && !name.is_empty()
            {
                insert_checked(
                    &mut ps.mandatory,
                    &mut ps.warnings,
                    &origin,
                    &name,
                    &raw,
                    false,
                );
            }
        }
        let rec_key = format!(r"{WIN_POLICY_KEY}\Recommended");
        if let Ok(Some(vals)) = ctx.registry.values(hive, &rec_key) {
            for (name, v) in vals {
                if let Some(raw) = reg_to_raw(&v)
                    && !name.is_empty()
                {
                    insert_checked(
                        &mut ps.recommended,
                        &mut ps.warnings,
                        &origin,
                        &name,
                        &raw,
                        false,
                    );
                }
            }
        }
        let sc_key = format!(r"{WIN_POLICY_KEY}\SmartCards");
        if let Ok(Some(vals)) = ctx.registry.values(hive, &sc_key) {
            for (name, v) in vals {
                if let Some(lib) = v.as_string()
                    && !name.is_empty()
                {
                    ps.smartcards.entry(name).or_insert(lib);
                }
            }
        }
    }
}

fn plist_to_raw(v: &plist::Value) -> Option<RawPolicyValue> {
    match v {
        plist::Value::String(s) => Some(RawPolicyValue::Str(s.clone())),
        plist::Value::Boolean(b) => Some(RawPolicyValue::Bool(*b)),
        plist::Value::Integer(i) => i.as_signed().map(RawPolicyValue::Int),
        _ => None,
    }
}

fn load_macos(ctx: &Context, ps: &mut PolicySet) {
    // Dominio propio primero; después el de la versión Java para que los perfiles MDM
    // ya desplegados sigan aplicándose. Lo primero leído tiene prioridad.
    let mut files = Vec::new();
    for id in [ctx.app.macos_bundle_id.as_str(), crate::ctx::LEGACY_MACOS_PREFS_DOMAIN] {
        files.push(ctx.sys(&format!("/Library/Managed Preferences/{id}.plist")));
        if let Some(u) = &ctx.paths.user_name {
            // Las preferencias gestionadas por usuario: menor prioridad que las de equipo.
            files.push(ctx.sys(&format!("/Library/Managed Preferences/{u}/{id}.plist")));
        }
    }
    files.dedup();
    for f in files {
        let Ok(v) = plist::Value::from_file(&f) else {
            continue;
        };
        let Some(d) = v.as_dictionary() else { continue };
        let origin = f.display().to_string();
        ps.sources.push(origin.clone());
        for (k, v) in d {
            match k.as_str() {
                "Recommended" => {
                    if let Some(rd) = v.as_dictionary() {
                        for (rk, rv) in rd {
                            if let Some(raw) = plist_to_raw(rv) {
                                insert_checked(
                                    &mut ps.recommended,
                                    &mut ps.warnings,
                                    &origin,
                                    rk,
                                    &raw,
                                    false,
                                );
                            }
                        }
                    }
                }
                "SmartCards" => {
                    if let Some(sd) = v.as_dictionary() {
                        for (n, l) in sd {
                            if let Some(l) = l.as_string() {
                                ps.smartcards
                                    .entry(n.clone())
                                    .or_insert_with(|| l.to_string());
                            }
                        }
                    }
                }
                // Claves de servicio de los perfiles de configuración.
                k if k.starts_with("PayloadUUID") || k == "PayloadType" => {}
                _ => {
                    if let Some(raw) = plist_to_raw(v) {
                        insert_checked(
                            &mut ps.mandatory,
                            &mut ps.warnings,
                            &origin,
                            k,
                            &raw,
                            false,
                        );
                    }
                }
            }
        }
    }
}

fn json_to_raw(v: &serde_json::Value) -> Option<RawPolicyValue> {
    match v {
        serde_json::Value::String(s) => Some(RawPolicyValue::Str(s.clone())),
        serde_json::Value::Bool(b) => Some(RawPolicyValue::Bool(*b)),
        serde_json::Value::Number(n) => n.as_i64().map(RawPolicyValue::Int),
        _ => None,
    }
}

/// Aplica un documento JSON de directivas (formato de `/etc/autofirma/policy.json`).
/// Los ficheros posteriores sobrescriben a los anteriores.
pub fn apply_json(ps: &mut PolicySet, origin: &str, doc: &serde_json::Value) {
    let Some(obj) = doc.as_object() else {
        ps.warnings
            .push(format!("{origin}: el documento no es un objeto JSON"));
        return;
    };
    for (section, v) in obj {
        let Some(m) = v.as_object() else {
            ps.warnings
                .push(format!("{origin}: la sección «{section}» no es un objeto"));
            continue;
        };
        match section.as_str() {
            "mandatory" | "recommended" => {
                for (k, val) in m {
                    let Some(raw) = json_to_raw(val) else {
                        ps.warnings
                            .push(format!("{origin}: tipo no admitido para «{k}»"));
                        continue;
                    };
                    let dst = if section == "mandatory" {
                        &mut ps.mandatory
                    } else {
                        &mut ps.recommended
                    };
                    insert_checked(dst, &mut ps.warnings, origin, k, &raw, true);
                }
            }
            "smartcards" => {
                for (n, l) in m {
                    if let Some(l) = l.as_str() {
                        ps.smartcards.insert(n.clone(), l.to_string());
                    }
                }
            }
            other => ps
                .warnings
                .push(format!("{origin}: sección desconocida «{other}»")),
        }
    }
}

fn load_linux(ctx: &Context, ps: &mut PolicySet) {
    let mut files = vec![ctx.sys(LINUX_POLICY_FILE)];
    if let Ok(rd) = std::fs::read_dir(ctx.sys(LINUX_POLICY_DIR)) {
        let mut extra: Vec<_> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        extra.sort();
        files.extend(extra);
    }
    for f in files {
        load_json_file(ps, &f);
    }
}

fn load_json_file(ps: &mut PolicySet, f: &Path) {
    let Ok(data) = std::fs::read(f) else { return };
    let origin = f.display().to_string();
    match serde_json::from_slice::<serde_json::Value>(&data) {
        Ok(doc) => {
            ps.sources.push(origin.clone());
            apply_json(ps, &origin, &doc);
        }
        Err(e) => ps.warnings.push(format!("{origin}: JSON no válido: {e}")),
    }
}

/// Plantilla de `/etc/autofirma/policy.json` documentada (para administradores).
pub fn linux_policy_template() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "mandatory": {
            "preferencesBlocked": true,
            "signatureHashAlgorithm": "SHA256",
            "secureConnections": true,
            "allowPersonalTruststore": false
        },
        "recommended": {
            "default.locale": "es_ES",
            "defaultSignatureFormatPdf": "PAdES"
        },
        "smartcards": {}
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directivas_windows_con_tipos() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Windows, t.path());
        let r = &ctx.registry;
        r.write(
            Hive::LocalMachine,
            WIN_POLICY_KEY,
            "preferencesBlocked",
            &RegValue::Dword(1),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            WIN_POLICY_KEY,
            "signatureHashAlgorithm",
            &RegValue::Sz("SHA512".into()),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            WIN_POLICY_KEY,
            "xadesSignFormat",
            &RegValue::Sz("XAdES Raro".into()),
        )
        .unwrap();
        r.write(
            Hive::CurrentUser,
            WIN_POLICY_KEY,
            "signatureHashAlgorithm",
            &RegValue::Sz("SHA1".into()),
        )
        .unwrap();
        r.write(
            Hive::CurrentUser,
            WIN_POLICY_KEY,
            "omitAskOnClose",
            &RegValue::Sz("1".into()),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            &format!(r"{WIN_POLICY_KEY}\Recommended"),
            "default.locale",
            &RegValue::Sz("ca_ES".into()),
        )
        .unwrap();
        r.write(
            Hive::LocalMachine,
            &format!(r"{WIN_POLICY_KEY}\SmartCards"),
            "Corp",
            &RegValue::Sz(r"C:\x.dll".into()),
        )
        .unwrap();
        let ps = load(&ctx);
        assert_eq!(
            ps.mandatory.get("preferencesBlocked").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            ps.mandatory
                .get("signatureHashAlgorithm")
                .map(String::as_str),
            Some("SHA512"),
            "HKLM gana a HKCU"
        );
        assert_eq!(
            ps.mandatory.get("omitAskOnClose").map(String::as_str),
            Some("true")
        );
        assert!(!ps.mandatory.contains_key("xadesSignFormat"));
        assert_eq!(ps.warnings.len(), 1);
        assert_eq!(
            ps.recommended.get("default.locale").map(String::as_str),
            Some("ca_ES")
        );
        assert_eq!(
            ps.smartcards.get("Corp").map(String::as_str),
            Some(r"C:\x.dll")
        );
    }

    #[test]
    fn directivas_linux_json_y_fragmentos() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::Linux, t.path());
        std::fs::create_dir_all(t.path().join("etc/autofirma/policy.d")).unwrap();
        std::fs::write(t.path().join("etc/autofirma/policy.json"), r#"{"mandatory":{"preferencesBlocked":true,"signatureHashAlgorithm":"SHA256"},"recommended":{"default.locale":"gl_ES"}}"#).unwrap();
        std::fs::write(t.path().join("etc/autofirma/policy.d/50-corp.json"), r#"{"mandatory":{"signatureHashAlgorithm":"SHA512"},"smartcards":{"Corp":"/usr/lib/corp.so"}}"#).unwrap();
        let ps = load(&ctx);
        assert_eq!(ps.mandatory["signatureHashAlgorithm"], "SHA512");
        assert_eq!(ps.mandatory["preferencesBlocked"], "true");
        assert_eq!(ps.recommended["default.locale"], "gl_ES");
        assert_eq!(ps.smartcards["Corp"], "/usr/lib/corp.so");
        assert_eq!(ps.sources.len(), 2);
    }

    #[test]
    fn directivas_macos_plist() {
        let t = tempfile::tempdir().unwrap();
        let ctx = Context::for_tests(Os::MacOs, t.path());
        let dir = t.path().join("Library/Managed Preferences");
        std::fs::create_dir_all(&dir).unwrap();
        let mut d = plist::Dictionary::new();
        d.insert("preferencesBlocked".into(), plist::Value::Boolean(true));
        d.insert("PayloadUUID".into(), plist::Value::String("x".into()));
        let mut rec = plist::Dictionary::new();
        rec.insert(
            "default.locale".into(),
            plist::Value::String("en_US".into()),
        );
        d.insert("Recommended".into(), plist::Value::Dictionary(rec));
        plist::Value::Dictionary(d)
            .to_file_xml(dir.join(format!("{}.plist", crate::ctx::MACOS_BUNDLE_ID)))
            .unwrap();
        let ps = load(&ctx);
        assert_eq!(ps.mandatory["preferencesBlocked"], "true");
        assert!(!ps.mandatory.contains_key("PayloadUUID"));
        assert_eq!(ps.recommended["default.locale"], "en_US");
    }
}
