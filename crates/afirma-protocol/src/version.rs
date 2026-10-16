//! Versiones del protocolo (`ProtocolVersion`) y comparación de la versión
//! mínima de AutoFirma exigida por la web (`mcv`, clase Java `Version`).

use std::cmp::Ordering;
use std::fmt;

/// Versión del protocolo de comunicación con el navegador (`X` o `X.Y`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    pub const V0: ProtocolVersion = ProtocolVersion::new(0, 0);
    pub const V1: ProtocolVersion = ProtocolVersion::new(1, 0);
    pub const V2: ProtocolVersion = ProtocolVersion::new(2, 0);
    pub const V3: ProtocolVersion = ProtocolVersion::new(3, 0);
    pub const V4: ProtocolVersion = ProtocolVersion::new(4, 0);
    pub const V4_1: ProtocolVersion = ProtocolVersion::new(4, 1);

    /// Versiones de operación soportadas por la aplicación (4.1, 3, 2 y 1).
    pub const SUPPORTED: [ProtocolVersion; 4] = [Self::V4_1, Self::V3, Self::V2, Self::V1];

    pub const fn new(major: u32, minor: u32) -> Self {
        ProtocolVersion { major, minor }
    }

    /// `ProtocolVersion.getInstance`: `X` o `X.Y` (enteros sin signo; se
    /// separa en el primer punto). Devuelve `None` si no es válida.
    pub fn parse(text: &str) -> Option<ProtocolVersion> {
        let parse_u = |s: &str| -> Option<u32> {
            // Integer.parseUnsignedInt admite un '+' inicial.
            let s = s.strip_prefix('+').unwrap_or(s);
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        };
        match text.find('.') {
            Some(i) if i > 0 => Some(ProtocolVersion::new(parse_u(&text[..i])?, parse_u(&text[i + 1..])?)),
            _ => Some(ProtocolVersion::new(parse_u(text)?, 0)),
        }
    }

    /// Versión de un parámetro `v`/`ver`: se recorta y, si no es válida o
    /// falta, es la 0.
    pub fn from_param(value: Option<&str>) -> ProtocolVersion {
        value.and_then(|v| Self::parse(v.trim())).unwrap_or(Self::V0)
    }

    /// Dos versiones son compatibles si tienen la misma versión principal.
    pub fn is_compatible_with(self, other: ProtocolVersion) -> bool {
        self.major == other.major
    }

    /// `hasSupportTo`: mayor versión principal, o igual con menor >=.
    pub fn has_support_to(self, other: ProtocolVersion) -> bool {
        self.major > other.major || (self.major == other.major && self.minor >= other.minor)
    }

    /// Regla de `reviewProtocolVersion`: la versión 4 con un JavaScript de
    /// código mayor que 3 (AutoScript 1.10) se trata como 4.1.
    pub fn reviewed(self, jvc: i32) -> ProtocolVersion {
        if self.major == 4 && jvc > 3 { Self::V4_1 } else { self }
    }

    /// `ProtocolInvocationLauncher.isCompatibleWith`: la aplicación admite
    /// cualquier versión con la misma versión principal que alguna soportada.
    pub fn is_supported_by_app(self) -> bool {
        Self::SUPPORTED.iter().any(|s| s.is_compatible_with(self))
    }

    /// Formato de error nuevo (`err-NN:=AF...`) desde la versión 4.1.
    pub fn uses_error_codes(self) -> bool {
        self.has_support_to(Self::V4_1)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minor == 0 {
            write!(f, "{}", self.major)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

/// `jvc`: entero; ausente o no válido → 1.
pub fn parse_jvc(value: Option<&str>) -> i32 {
    value.and_then(java_parse_int).unwrap_or(1)
}

/// `Integer.parseInt` (signo opcional, solo dígitos ASCII, rango de `i32`).
pub fn java_parse_int(text: &str) -> Option<i32> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i32>().ok()
}

/// Versión legible de la aplicación (`1.10`, `1.8.2`, `1.10 RC`...), con la
/// semántica de la clase Java `Version` del protocolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppVersion {
    parts: Vec<i64>,
    additional: String,
}

/// La versión no tiene un formato numérico válido (Java lanza
/// `NumberFormatException`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("versión no válida: {0}")]
pub struct InvalidVersion(pub String);

impl AppVersion {
    pub fn parse(text: &str) -> Result<AppVersion, InvalidVersion> {
        let err = || InvalidVersion(text.to_string());
        // String.split("\\.") elimina las cadenas vacías finales.
        let mut items: Vec<&str> = text.split('.').collect();
        while items.len() > 1 && items.last().is_some_and(|s| s.is_empty()) {
            items.pop();
        }
        let mut parts = Vec::new();
        for p in &items[..items.len() - 1] {
            parts.push(java_parse_long(p).ok_or_else(err)?);
        }
        let last = items[items.len() - 1];
        let limit = last.char_indices().find(|(_, c)| !c.is_ascii_digit()).map(|(i, _)| i);
        let additional = match limit {
            Some(l) if l > 0 => {
                parts.push(java_parse_long(&last[..l]).ok_or_else(err)?);
                last[l..].to_string()
            }
            _ => {
                parts.push(java_parse_long(last).ok_or_else(err)?);
                String::new()
            }
        };
        Ok(AppVersion { parts, additional })
    }

    /// `Version.greaterThan`.
    pub fn greater_than(&self, other: &AppVersion) -> bool {
        for (a, b) in self.parts.iter().zip(&other.parts) {
            match a.cmp(b) {
                Ordering::Greater => return true,
                Ordering::Less => return false,
                Ordering::Equal => {}
            }
        }
        match self.parts.len().cmp(&other.parts.len()) {
            Ordering::Greater => return true,
            Ordering::Less => return false,
            Ordering::Equal => {}
        }
        let a = &self.additional;
        let b = &other.additional;
        let starts_space = |s: &str| s.chars().next().is_some_and(is_java_space_char);
        if a.to_lowercase() == b.to_lowercase() {
            return false;
        }
        if (a.is_empty() || !starts_space(a)) && starts_space(b) {
            return true;
        }
        if (b.is_empty() || !starts_space(b)) && starts_space(a) {
            return false;
        }
        if a.is_empty() && !starts_space(b) {
            return false;
        }
        if b.is_empty() && !starts_space(a) {
            return true;
        }
        a.to_lowercase() > b.to_lowercase()
    }
}

fn java_parse_long(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let neg = text.starts_with('-');
    let v: i64 = digits.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// `Character.isSpaceChar` (separadores Unicode de espacio, línea y párrafo).
fn is_java_space_char(c: char) -> bool {
    matches!(
        c,
        ' ' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

/// Comprueba `mcv`: devuelve `Ok(true)` si la versión mínima pedida es
/// mayor que la de la aplicación (error 500005).
pub fn minimum_version_not_satisfied(mcv: &str, app_version: &str) -> Result<bool, InvalidVersion> {
    let requested = AppVersion::parse(mcv)?;
    let current = AppVersion::parse(app_version)?;
    Ok(requested.greater_than(&current))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_versions() {
        assert_eq!(ProtocolVersion::parse("4"), Some(ProtocolVersion::V4));
        assert_eq!(ProtocolVersion::parse("4.1"), Some(ProtocolVersion::V4_1));
        assert_eq!(ProtocolVersion::parse("4.1.2"), None);
        assert_eq!(ProtocolVersion::parse(".1"), None);
        assert_eq!(ProtocolVersion::parse("x"), None);
        assert_eq!(ProtocolVersion::parse("-1"), None);
        assert_eq!(ProtocolVersion::from_param(Some(" 3 ")), ProtocolVersion::V3);
        assert_eq!(ProtocolVersion::from_param(None), ProtocolVersion::V0);
        assert_eq!(ProtocolVersion::V4.reviewed(4), ProtocolVersion::V4_1);
        assert_eq!(ProtocolVersion::V4.reviewed(3), ProtocolVersion::V4);
        assert_eq!(ProtocolVersion::V3.reviewed(4), ProtocolVersion::V3);
        assert!(ProtocolVersion::V4_1.uses_error_codes());
        assert!(!ProtocolVersion::V4.uses_error_codes());
        assert!(ProtocolVersion::new(5, 0).uses_error_codes());
        assert!(ProtocolVersion::V4.is_supported_by_app());
        assert!(!ProtocolVersion::V0.is_supported_by_app());
        assert!(!ProtocolVersion::new(5, 0).is_supported_by_app());
        assert_eq!(ProtocolVersion::V4_1.to_string(), "4.1");
        assert_eq!(ProtocolVersion::V3.to_string(), "3");
        assert_eq!(parse_jvc(Some("4")), 4);
        assert_eq!(parse_jvc(Some("x")), 1);
        assert_eq!(parse_jvc(None), 1);
        assert_eq!(parse_jvc(Some("-2")), -2);
    }

    #[test]
    fn mcv_comparison() {
        let gt = |a: &str, b: &str| {
            AppVersion::parse(a)
                .unwrap()
                .greater_than(&AppVersion::parse(b).unwrap())
        };
        assert!(gt("1.11", "1.10"));
        assert!(!gt("1.10", "1.10"));
        assert!(!gt("1.9", "1.10"));
        assert!(gt("1.10.1", "1.10"));
        assert!(!gt("1.10", "1.10.1"));
        assert!(gt("2", "1.10"));
        // Sufijos.
        assert!(!gt("1.10 RC", "1.10"));
        assert!(gt("1.10", "1.10 RC"));
        assert!(gt("1.10-beta", "1.10"));
        assert!(!gt("1.10", "1.10-beta"));
        assert!(!gt("1.10-BETA", "1.10-beta"));
        assert!(gt("1.10-c", "1.10-b"));
        assert!(minimum_version_not_satisfied("1.11", "1.10").unwrap());
        assert!(!minimum_version_not_satisfied("1.8", "1.10").unwrap());
        assert!(minimum_version_not_satisfied("a.1", "1.10").is_err());
        assert!(minimum_version_not_satisfied("beta", "1.10").is_err());
        assert!(minimum_version_not_satisfied("", "1.10").is_err());
        assert!(!minimum_version_not_satisfied("1.10.", "1.10").unwrap());
    }
}
