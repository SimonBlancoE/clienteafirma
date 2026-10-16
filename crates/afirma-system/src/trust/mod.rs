//! Instalación, retirada y comprobación de la CA local en los almacenes de confianza:
//!
//! * [`windows`]: `LocalMachine\ROOT` (con privilegios, sin avisos) o `CurrentUser\ROOT`.
//! * [`macos`]: llavero del sistema (`trustRoot` para la CA y `trustAsRoot` para el
//!   certificado SSL, como Java) o llavero de sesión.
//! * [`linux`]: anclas del sistema (Debian/Ubuntu, Fedora/RHEL, openSUSE/SLES, Arch).
//! * [`nss`]: bases de datos NSS (perfiles de Firefox de todas las variantes y
//!   `~/.pki/nssdb` de Chrome/Chromium), con `certutil` o directamente con el módulo
//!   PKCS#11 `softokn` de NSS ([`softokn`]).
//!
//! Todas las operaciones son idempotentes y solo retiran certificados de AutoFirma
//! (`CN=Autofirma ROOT`/`AutoFirma ROOT`, apodo `SocketAutoFirma`, o certificados emitidos
//! por esa CA).

pub mod linux;
pub mod macos;
pub mod nss;
pub mod softokn;
pub mod windows;

use x509_parser::prelude::*;

use crate::certs::LEGACY_CA_NAMES;

/// Ámbito de una instalación.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TrustScope {
    /// Todo el equipo (requiere privilegios).
    Machine,
    /// Solo el usuario actual.
    User,
}

/// Resultado de comprobar un almacén.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum TrustCheck {
    /// La CA actual está instalada y es de confianza.
    Trusted,
    /// No está instalada.
    Missing,
    /// Hay un certificado de AutoFirma distinto (antiguo) o sin la confianza adecuada.
    Mismatch(String),
    /// No se pudo comprobar.
    Unknown(String),
}

impl TrustCheck {
    /// `true` si está correcto.
    pub fn ok(&self) -> bool {
        matches!(self, TrustCheck::Trusted)
    }
}

/// Resultado de una operación de instalación/retirada.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Change {
    /// Se modificó el almacén.
    Changed,
    /// Ya estaba en el estado pedido.
    Unchanged,
}

fn cn_of(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|c| c.as_str().ok().map(str::to_string))
}

/// `true` si el certificado es una CA de AutoFirma (por el CN del sujeto) o fue emitido
/// por una (certificado SSL de `127.0.0.1` de versiones anteriores).
pub fn is_autofirma_cert(der: &[u8]) -> bool {
    let Ok((_, c)) = X509Certificate::from_der(der) else {
        return false;
    };
    let is_name = |n: Option<String>| n.is_some_and(|n| LEGACY_CA_NAMES.iter().any(|l| l.eq_ignore_ascii_case(&n)));
    is_name(cn_of(c.subject())) || is_name(cn_of(c.issuer()))
}

/// `true` si el certificado es la CA (sujeto `CN=Autofirma ROOT`).
pub fn is_autofirma_ca(der: &[u8]) -> bool {
    let Ok((_, c)) = X509Certificate::from_der(der) else {
        return false;
    };
    cn_of(c.subject()).is_some_and(|n| LEGACY_CA_NAMES.iter().any(|l| l.eq_ignore_ascii_case(&n)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconoce_certificados_de_autofirma() {
        let p = crate::certs::generate(&Default::default()).unwrap();
        assert!(is_autofirma_cert(&p.ca_der) && is_autofirma_ca(&p.ca_der));
        assert!(is_autofirma_cert(&p.ssl_der) && !is_autofirma_ca(&p.ssl_der));
        assert!(!is_autofirma_cert(b"basura"));
    }
}
