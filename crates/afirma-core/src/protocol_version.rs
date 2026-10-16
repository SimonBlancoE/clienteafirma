//! Versión del protocolo `afirma://` (`es.gob.afirma.core.misc.protocol.ProtocolVersion`).

use std::fmt;
use std::str::FromStr;

/// Versión del protocolo (`mayor[.menor]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    /// Versión 4.1: la primera que devuelve códigos de error `AFxxxxxx`.
    pub const VERSION_4_1: ProtocolVersion = ProtocolVersion { major: 4, minor: 1 };

    /// Crea una versión.
    pub const fn new(major: u32, minor: u32) -> Self {
        ProtocolVersion { major, minor }
    }

    /// Misma versión mayor (`isCompatibleWith`).
    pub fn is_compatible_with(&self, other: &ProtocolVersion) -> bool {
        self.major == other.major
    }

    /// Versión mayor superior, o igual con versión menor igual o superior
    /// (`hasSupportTo`).
    pub fn has_support_to(&self, other: &ProtocolVersion) -> bool {
        self.major > other.major || (self.major == other.major && self.minor >= other.minor)
    }

    /// Indica si la versión admite los códigos de error de AutoFirma 1.9
    /// (`>= 4.1`).
    pub fn supports_error_codes(&self) -> bool {
        self.has_support_to(&Self::VERSION_4_1)
    }
}

/// Error al interpretar la versión.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("El identificador de la version de protocolo indicada no es valido")]
pub struct InvalidProtocolVersion;

impl FromStr for ProtocolVersion {
    type Err = InvalidProtocolVersion;

    /// `ProtocolVersion.getInstance`: enteros sin signo separados por el
    /// primer punto (si está en una posición mayor que 0).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse = |p: &str| -> Result<u32, InvalidProtocolVersion> {
            let p = p.strip_prefix('+').unwrap_or(p);
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(InvalidProtocolVersion);
            }
            p.parse().map_err(|_| InvalidProtocolVersion)
        };
        match s.find('.') {
            Some(i) if i > 0 => Ok(ProtocolVersion::new(parse(&s[..i])?, parse(&s[i + 1..])?)),
            _ => Ok(ProtocolVersion::new(parse(s)?, 0)),
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.minor != 0 {
            write!(f, "{}.{}", self.major, self.minor)
        } else {
            write!(f, "{}", self.major)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        let v: ProtocolVersion = "4.1".parse().unwrap();
        assert!(v.supports_error_codes());
        assert!(!"4".parse::<ProtocolVersion>().unwrap().supports_error_codes());
        assert!("5".parse::<ProtocolVersion>().unwrap().supports_error_codes());
        assert!("4.2".parse::<ProtocolVersion>().unwrap().supports_error_codes());
        assert!(!"3.9".parse::<ProtocolVersion>().unwrap().supports_error_codes());
        assert!("x".parse::<ProtocolVersion>().is_err());
        assert!(".1".parse::<ProtocolVersion>().is_err());
        assert!("4.".parse::<ProtocolVersion>().is_err());
        assert_eq!("4.0".parse::<ProtocolVersion>().unwrap().to_string(), "4");
        assert_eq!(v.to_string(), "4.1");
        assert!(v.is_compatible_with(&ProtocolVersion::new(4, 0)));
        for s in crate::constants::PROTOCOL_VERSIONS {
            assert!(s.parse::<ProtocolVersion>().is_ok());
        }
    }
}
