//! Modelos de presentación que usa la interfaz (independientes del motor de
//! firma, que los rellena).

use afirma_core::cert::CertInfo;
use chrono::{DateTime, Local, Utc};

use super::icons;
use super::theme::Palette;
use eframe::egui::Color32;

/// Familia del emisor de un certificado (para el icono), como
/// `CertificateIconManager` de AutoFirma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertFamily {
    Dnie,
    Fnmt,
    Accv,
    Cnp,
    Generic,
}

/// Estado temporal de un certificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertState {
    Valid,
    /// Caduca en menos de 7 días.
    ExpiringSoon,
    Expired,
    NotYetValid,
}

/// Vista de selección (`certView`): personal, representante o seudónimo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum CertListView {
    #[default]
    Personal,
    Representative,
    Pseudonym,
}

/// Certificado disponible en un almacén.
#[derive(Debug, Clone)]
pub struct CertItem {
    pub alias: String,
    pub der: Vec<u8>,
    pub info: CertInfo,
    /// Organización del titular (vista de representante).
    pub subject_o: Option<String>,
    /// Título o seudónimo (vista de seudónimo).
    pub pseudonym: Option<String>,
    pub subject_ou: Option<String>,
}

impl CertItem {
    pub fn from_der(alias: impl Into<String>, der: Vec<u8>) -> Option<CertItem> {
        let info = CertInfo::parse(&der)?;
        let (subject_o, subject_ou, pseudonym) = subject_extra(&der);
        Some(CertItem { alias: alias.into(), der, info, subject_o, pseudonym, subject_ou })
    }

    pub fn family(&self) -> CertFamily {
        let issuer = self.info.issuer_dn.to_uppercase();
        if issuer.contains("O=GENERALITAT VALENCIANA") && issuer.contains("OU=PKIGVA") {
            CertFamily::Accv
        } else if issuer.contains("O=DIRECCION GENERAL DE LA POLICIA") && issuer.contains("OU=DNIE") {
            CertFamily::Dnie
        } else if issuer.contains("O=DIRECCION GENERAL DE LA POLICIA") && issuer.contains("OU=CNP") {
            CertFamily::Cnp
        } else if issuer.contains("O=FNMT") {
            CertFamily::Fnmt
        } else {
            CertFamily::Generic
        }
    }

    pub fn state_at(&self, now: DateTime<Utc>) -> CertState {
        if now > self.info.not_after {
            CertState::Expired
        } else if now < self.info.not_before {
            CertState::NotYetValid
        } else if self.info.not_after - now < chrono::Duration::days(7) {
            CertState::ExpiringSoon
        } else {
            CertState::Valid
        }
    }

    pub fn state(&self) -> CertState {
        self.state_at(Utc::now())
    }

    /// Días hasta la caducidad (negativo si ya caducó).
    pub fn days_left(&self) -> i64 {
        (self.info.not_after - Utc::now()).num_days()
    }

    /// Texto de uso de la clave como `KeyUsage.toString` de AutoFirma.
    pub fn usage_text(&self) -> &'static str {
        let Some(ku) = self.info.key_usage else { return "Desconocido" };
        let (s, a, c) = (ku.non_repudiation, ku.digital_signature, ku.data_encipherment);
        match (s, a, c) {
            (true, true, true) => "Firma, autenticación y cifrado",
            (false, true, true) => "Autenticación y cifrado",
            (true, true, false) => "Firma y autenticación",
            (false, true, false) => "Autenticación",
            (true, false, false) => "Firma",
            (true, false, true) => "Firma y cifrado",
            (false, false, true) => "Cifrado",
            _ => "Otros",
        }
    }

    /// Nombre principal según la vista.
    pub fn title(&self, view: CertListView) -> String {
        match view {
            CertListView::Personal => self.info.subject_cn.clone(),
            CertListView::Representative => self.subject_o.clone().unwrap_or_else(|| self.info.subject_cn.clone()),
            CertListView::Pseudonym => self.pseudonym.clone().unwrap_or_else(|| self.info.subject_cn.clone()),
        }
    }

    /// Texto que busca el filtro de la lista.
    pub fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.info.subject_cn,
            self.info.issuer_cn,
            self.info.subject_serial_number.clone().unwrap_or_default(),
            self.subject_o.clone().unwrap_or_default(),
            self.alias
        )
        .to_lowercase()
    }

    pub fn family_icon(&self) -> &'static str {
        match self.family() {
            CertFamily::Dnie | CertFamily::Cnp => icons::IDENTIFICATION_BADGE,
            CertFamily::Fnmt => icons::CERTIFICATE,
            CertFamily::Accv => icons::SEAL,
            CertFamily::Generic => icons::IDENTIFICATION_CARD,
        }
    }
}

/// Colores (primer plano, fondo) para un estado de certificado.
pub fn state_colors(state: CertState, p: &Palette) -> (Color32, Color32) {
    match state {
        CertState::Valid => (p.info, p.info_soft),
        CertState::ExpiringSoon => (p.warning, p.warning_soft),
        CertState::Expired | CertState::NotYetValid => (p.danger, p.danger_soft),
    }
}

/// Organización, unidad y título/seudónimo del titular.
fn subject_extra(der: &[u8]) -> (Option<String>, Option<String>, Option<String>) {
    use x509_parser::prelude::*;
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return (None, None, None) };
    let get = |oid: &x509_parser::der_parser::oid::Oid| {
        cert.subject().iter_by_oid(oid).next().and_then(|a| afirma_core::cert::attr_string(a.attr_value()))
    };
    let o = get(&x509_parser::oid_registry::OID_X509_ORGANIZATION_NAME);
    let ou = get(&x509_parser::oid_registry::OID_X509_ORGANIZATIONAL_UNIT);
    let pseudonym = x509_parser::der_parser::oid::Oid::from(&[2, 5, 4, 65]).ok().and_then(|oid| get(&oid));
    let title = x509_parser::der_parser::oid::Oid::from(&[2, 5, 4, 12]).ok().and_then(|oid| get(&oid));
    let pseudo = match (title, pseudonym) {
        (Some(t), Some(p)) => Some(format!("{t} ({p})")),
        (Some(t), None) => Some(t),
        (None, Some(p)) => Some(p),
        _ => None,
    };
    (o, ou, pseudo)
}

/// Fecha en formato corto español.
pub fn fmt_date(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%d/%m/%Y").to_string()
}

/// Fecha y hora en formato español.
pub fn fmt_datetime(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%d/%m/%Y %H:%M").to_string()
}

/// Tamaño de fichero legible.
pub fn fmt_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[u]).replace('.', ",") }
}
