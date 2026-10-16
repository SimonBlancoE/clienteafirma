//! Parámetros de firma a partir de las preferencias del usuario
//! (`ExtraParamsHelper`, spec 06 §4.8). Solo se usan en la aplicación de
//! escritorio; la línea de comandos y la web traen sus propios parámetros.

use afirma_core::ExtraParams;
use afirma_core::formats::SignerKind;

/// Construye los `extraParams` de un firmador con las preferencias. `pref`
/// devuelve el valor efectivo de una preferencia.
pub fn from_preferences(kind: SignerKind, pref: &dyn Fn(&str) -> Option<String>) -> ExtraParams {
    let mut p = ExtraParams::new();
    let get = |k: &str| pref(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let mut copy = |p: &mut ExtraParams, from: &str, to: &str| {
        if let Some(v) = get(from) {
            p.set(to, v);
        }
    };
    let policy = |p: &mut ExtraParams, prefix: &str, with_qualifier: bool| {
        if let Some(id) = get(&format!("{prefix}PolicyIdentifier")) {
            p.set("policyIdentifier", id);
            if let Some(v) = get(&format!("{prefix}PolicyIdentifierHash")) {
                p.set("policyIdentifierHash", v);
            }
            if let Some(v) = get(&format!("{prefix}PolicyIdentifierHashAlgorithm")) {
                p.set("policyIdentifierHashAlgorithm", v);
            }
            if with_qualifier {
                if let Some(v) = get(&format!("{prefix}PolicyQualifier")) {
                    p.set("policyQualifier", v);
                }
            }
        }
    };
    match kind {
        SignerKind::FacturaE => {
            policy(&mut p, "facturae", false);
            for f in ["City", "Province", "PostalCode", "Country"] {
                copy(&mut p, &format!("facturaeSignatureProduction{f}"), &format!("signatureProduction{f}"));
            }
            copy(&mut p, "facturaeSignerRole", "signerClaimedRoles");
        }
        SignerKind::Xades => {
            p.set("ignoreStyleSheets", "false");
            policy(&mut p, "xades", true);
            copy(&mut p, "xadesSignerClaimedRole", "signerClaimedRoles");
            for f in ["City", "Province", "PostalCode", "Country"] {
                copy(&mut p, &format!("xadesSignatureProduction{f}"), &format!("signatureProduction{f}"));
            }
            copy(&mut p, "xadesSignFormat", "format");
        }
        SignerKind::Pdf => {
            policy(&mut p, "pades", true);
            copy(&mut p, "padesSignReason", "signReason");
            copy(&mut p, "padesSignProductionCity", "signatureProductionCity");
            copy(&mut p, "padesSignerContact", "signerContact");
            copy(&mut p, "padesBasicFormat", "signatureSubFilter");
            let obfuscate = get("padesObfuscateCertInfo").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(true);
            p.set("obfuscateCertText", obfuscate.to_string());
        }
        // CAdES y cualquier otro firmador (OOXML y ODF reciben también estos
        // parámetros, como en Java).
        _ => {
            policy(&mut p, "cades", true);
            let implicit = get("cadesImplicitMode").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(true);
            p.set("mode", if implicit { "implicit" } else { "explicit" });
        }
    }
    p
}

/// Algoritmo de firma de la aplicación de escritorio
/// (`signatureHashAlgorithm`, por defecto SHA-256).
pub fn desktop_algorithm(pref: &dyn Fn(&str) -> Option<String>) -> String {
    match pref("signatureHashAlgorithm").as_deref().map(str::trim) {
        Some(a @ ("SHA1" | "SHA256" | "SHA384" | "SHA512")) => a.to_string(),
        _ => "SHA256".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pades_and_cades_params() {
        let prefs = |k: &str| match k {
            "padesSignReason" => Some("Conforme".to_string()),
            "padesPolicyIdentifier" => Some("urn:oid:2.16.724.1.3.1.1.2.1.9".to_string()),
            "padesPolicyIdentifierHash" => Some("G7roucf600+f03r/o0bAOQ6WAs0=".to_string()),
            "padesBasicFormat" => Some("ETSI.CAdES.detached".to_string()),
            "cadesImplicitMode" => Some("false".to_string()),
            _ => None,
        };
        let p = from_preferences(SignerKind::Pdf, &prefs);
        assert_eq!(p.get("signReason"), Some("Conforme"));
        assert_eq!(p.get("policyIdentifierHash"), Some("G7roucf600+f03r/o0bAOQ6WAs0="));
        assert_eq!(p.get("obfuscateCertText"), Some("true"));
        assert_eq!(p.get("signatureSubFilter"), Some("ETSI.CAdES.detached"));
        let c = from_preferences(SignerKind::Cades, &prefs);
        assert_eq!(c.get("mode"), Some("explicit"));
        assert!(c.get("policyIdentifier").is_none());
        assert_eq!(desktop_algorithm(&prefs), "SHA256");
    }
}
