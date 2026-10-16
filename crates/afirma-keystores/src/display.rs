//! Datos de presentación de certificados para el diálogo de selección
//! (sección 8 de la especificación): textos de las tres vistas, uso de la
//! clave, estado de validez, familia del emisor para el icono y textos fijos
//! del diálogo. Es un modelo de datos puro: la interfaz gráfica decide cómo
//! pintarlo.
//!
//! Textos en español (`certdialogmessages_es_ES.properties`,
//! `coremessages_es_ES.properties`).

use chrono::{DateTime, Utc};

use crate::dn::{self, get_cn, get_rdn_value};
use crate::kind::Os;
use crate::store::CertEntry;

/// `CertificateSelectionDialog.0`
pub const DIALOG_TITLE: &str = "Diálogo de seguridad del almacén %0";
/// `CertificateSelectionPanel.0`
pub const HEADLINE: &str = "Seleccione un certificado";
/// `CertificateSelectionPanel.1` (un único certificado)
pub const SUBHEADLINE_ONE: &str =
    "Confirme el certificado pulsando Aceptar. Si no es este el certificado que desea usar pulse Cancelar.";
/// `CertificateSelectionPanel.8` (ningún certificado)
pub const SUBHEADLINE_NONE: &str = "No se han encontrado certificados válidos en el almacén. Inserte una tarjeta inteligente en el lector y pulse Recargar, o cargue un almacén externo.";
/// `CertificateSelectionPanel.5`
pub const PROPERTIES_LINK: &str = "Haga clic aquí para ver las propiedades del certificado";
/// `CertificateSelectionPanel.35`
pub const STORE_MENU_SYSTEM: &str = "Almacén de claves del sistema";
/// `CertificateSelectionPanel.36`
pub const STORE_MENU_FIREFOX: &str = "Almacén de claves de Mozilla Firefox";
/// `CertificateSelectionPanel.37`
pub const STORE_MENU_PKCS12: &str = "Almacén de claves en fichero (PFX/PKCS#12)";
/// `CertificateSelectionPanel.38`
pub const STORE_MENU_DNIE: &str = "DNI electrónico";
/// `UtilToolBar.1`
pub const TOOLTIP_REFRESH: &str = "Recargar la lista de certificados";
/// `UtilToolBar.2`
pub const TOOLTIP_CHANGE_STORE: &str = "Cambiar almacén de claves";
/// `UtilToolBar.3`
pub const TOOLTIP_HELP: &str = "Ayuda";
/// `UtilToolBar.4`
pub const TOOLTIP_VIEWS: &str = "Vistas de certificados";
/// URL base de la ayuda (`selectiondialogutil.properties`), a la que se
/// añade `-<idioma>-<PAÍS>` (p. ej. `-es-ES`).
pub const HELP_URL: &str = "https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-select-certs";
/// `CertificateSelectionPanel.30`
pub const STATE_VALID: &str = "vigente";
/// `CertificateSelectionPanel.31`
pub const STATE_INVALID: &str = "caducado o aún no válido";

/// Título del diálogo: `"Diálogo de seguridad del almacén <nombre>"` más
/// `" : <fichero>"` si se conoce el fichero o biblioteca.
pub fn dialog_title(store_name: &str, lib_name: Option<&str>) -> String {
    let mut t = DIALOG_TITLE.replace("%0", store_name);
    if let Some(lib) = lib_name.filter(|l| !l.is_empty()) {
        t.push_str(" : ");
        t.push_str(lib);
    }
    t
}

/// URL de la ayuda para un idioma (`es`, `ES` → `...-es-ES`).
pub fn help_url(language: &str, country: &str) -> String {
    format!("{HELP_URL}-{language}-{country}")
}

/// Texto del uso de la clave (`es.gob.afirma.core.keystores.KeyUsage.toString`),
/// evaluado en el orden de Java (incluida la rama inalcanzable
/// "Firma y cifrado"): SIGN = nonRepudiation, AUTH = digitalSignature,
/// CYPH = dataEncipherment.
pub fn key_usage_text(cert_der: &[u8]) -> &'static str {
    let ku = afirma_core::cert::CertInfo::parse(cert_der).and_then(|i| i.key_usage);
    key_usage_text_from(ku.as_ref())
}

/// Igual que [`key_usage_text`] a partir de los bits ya leídos.
pub fn key_usage_text_from(ku: Option<&afirma_core::cert::KeyUsageFlags>) -> &'static str {
    let Some(ku) = ku else { return "Desconocido" };
    let sign = ku.non_repudiation;
    let auth = ku.digital_signature;
    let cyph = ku.data_encipherment;
    if sign && auth && cyph {
        "Firma, autenticación y cifrado"
    } else if auth && cyph {
        "Autenticación y cifrado"
    // Java comprueba aquí otra vez SIGN ∧ AUTH ∧ CYPH para "Firma y cifrado"
    // (`KeyUsage.3`), rama inalcanzable: SIGN ∧ CYPH sin AUTH es "Firma".
    } else if sign && auth {
        "Firma y autenticación"
    } else if auth {
        "Autenticación"
    } else if sign {
        "Firma"
    } else if cyph {
        "Cifrado"
    } else {
        "Otros"
    }
}

/// Estado de validez para el icono.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityState {
    /// Vigente.
    Valid,
    /// Vigente pero caduca en menos de 7 días.
    ExpiringSoon,
    /// Caducado o aún no válido.
    Invalid,
}

/// Umbral de aviso de caducidad: 7 días exactos. (Java usa
/// `1000*60*60*25*7` ms = 7 días y 7 horas por error.)
pub const EXPIRY_WARNING: chrono::Duration = chrono::Duration::days(7);

/// Estado de validez (`CertificateIconManager.getIcon`): inválido si
/// `ahora >= notAfter` o `ahora <= notBefore`; aviso si quedan menos de
/// [`EXPIRY_WARNING`].
pub fn validity_state(not_before: DateTime<Utc>, not_after: DateTime<Utc>, now: DateTime<Utc>) -> ValidityState {
    if now >= not_after || now <= not_before {
        ValidityState::Invalid
    } else if not_after - now < EXPIRY_WARNING {
        ValidityState::ExpiringSoon
    } else {
        ValidityState::Valid
    }
}

/// `CertificateUtils.isExpired`: caducado o aún no válido.
pub fn is_expired(not_before: DateTime<Utc>, not_after: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now >= not_after || now <= not_before
}

/// Familia del emisor, para elegir el icono.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssuerFamily {
    /// Generalitat Valenciana (ACCV).
    Accv,
    /// DNI electrónico.
    Dnie,
    /// Carné profesional del Cuerpo Nacional de Policía.
    Cnp,
    /// FNMT-RCM.
    Fnmt,
    /// Cualquier otro.
    Other,
}

/// Familia del emisor según su `toString()` en mayúsculas
/// (`CertificateIconManager`). La comprobación de ACCV de Java compara con
/// texto en minúsculas y nunca coincide; aquí se corrige.
pub fn issuer_family(cert_der: &[u8]) -> IssuerFamily {
    let issuer = dn::java_issuer_string(cert_der).unwrap_or_default().to_uppercase();
    if issuer.contains("O=GENERALITAT VALENCIANA") && issuer.contains("OU=PKIGVA") {
        IssuerFamily::Accv
    } else if issuer.contains("O=DIRECCION GENERAL DE LA POLICIA") && issuer.contains("OU=DNIE") {
        IssuerFamily::Dnie
    } else if issuer.contains("O=DIRECCION GENERAL DE LA POLICIA") && issuer.contains("OU=CNP") {
        IssuerFamily::Cnp
    } else if issuer.contains("O=FNMT") {
        IssuerFamily::Fnmt
    } else {
        IssuerFamily::Other
    }
}

/// Nombre del recurso de icono de Java (`dnieicon_w.png`...).
pub fn icon_resource(family: IssuerFamily, state: ValidityState) -> &'static str {
    use IssuerFamily::*;
    use ValidityState::*;
    match (family, state) {
        (Accv, Valid) => "accvicon.png",
        (Accv, ExpiringSoon) => "accvicon_w.png",
        (Accv, Invalid) => "accvicon_e.png",
        (Dnie, Valid) => "dnieicon.png",
        (Dnie, ExpiringSoon) => "dnieicon_w.png",
        (Dnie, Invalid) => "dnieicon_e.png",
        (Cnp, Valid) => "cnpicon.png",
        (Cnp, ExpiringSoon) => "cnpicon_w.png",
        (Cnp, Invalid) => "cnpicon_e.png",
        (Fnmt, Valid) => "fnmticon.png",
        (Fnmt, ExpiringSoon) => "fnmticon_w.png",
        (Fnmt, Invalid) => "fnmticon_e.png",
        (Other, Valid) => "certicon.png",
        (Other, ExpiringSoon) => "certicon_w.png",
        (Other, Invalid) => "certicon_e.png",
    }
}

/// Descripción accesible del icono (`CertificateSelectionPanel.4,7,9,11,13,15–24`).
pub fn icon_description(family: IssuerFamily, state: ValidityState) -> &'static str {
    use IssuerFamily::*;
    use ValidityState::*;
    match (family, state) {
        (Accv, Valid) => "Certificado de ACCV dentro del periodo de validez",
        (Accv, ExpiringSoon) => "Certificado de ACCV a punto de caducar",
        (Accv, Invalid) => "Certificado de ACCV caducado o aún no válido",
        (Dnie, Valid) => "Certificado de DNIe dentro del periodo de validez",
        (Dnie, ExpiringSoon) => "Certificado de DNIe a punto de caducar",
        (Dnie, Invalid) => "Certificado de DNIe caducado o aun no válido",
        (Cnp, Valid) => "Certificado de CNP dentro del periodo de validez",
        (Cnp, ExpiringSoon) => "Certificado de CNP a punto de caducar",
        (Cnp, Invalid) => "Certificado de CNP caducado o aún no válido",
        (Fnmt, Valid) => "Certificado FNMT-RCM dentro del periodo de validez",
        (Fnmt, ExpiringSoon) => "Certificado FNMT-RCM a punto de caducar",
        (Fnmt, Invalid) => "Certificado FNMT-RCM caducado o aún no válido",
        (Other, Valid) => "Certificado dentro del periodo de validez",
        (Other, ExpiringSoon) => "Certificado a punto de caducar",
        (Other, Invalid) => "Certificado caducado o aún no válido",
    }
}

/// Vista del diálogo de selección (preferencia `certView` del nodo
/// `/es/gob/afirma/ui/core/jse/certificateselection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CertificateView {
    #[default]
    Personal,
    Representative,
    Pseudonym,
}

impl CertificateView {
    pub const ALL: [CertificateView; 3] = [
        CertificateView::Personal,
        CertificateView::Representative,
        CertificateView::Pseudonym,
    ];

    /// Valor persistido (`PERSONAL`, `REPRESENTATIVE`, `PSEUDONYM`).
    pub fn pref_value(self) -> &'static str {
        match self {
            CertificateView::Personal => "PERSONAL",
            CertificateView::Representative => "REPRESENTATIVE",
            CertificateView::Pseudonym => "PSEUDONYM",
        }
    }

    /// Lee el valor persistido; cualquier otro valor (o ausente) es la vista
    /// personal.
    pub fn from_pref(value: Option<&str>) -> CertificateView {
        match value {
            Some("REPRESENTATIVE") => CertificateView::Representative,
            Some("PSEUDONYM") => CertificateView::Pseudonym,
            _ => CertificateView::Personal,
        }
    }

    /// Texto del menú de vistas (`CertificateSelectionPanel.25–27`).
    pub fn label(self) -> &'static str {
        match self {
            CertificateView::Personal => "Vista de certificados personales",
            CertificateView::Representative => "Vista de certificados de representante",
            CertificateView::Pseudonym => "Vista de certificados de seudónimo",
        }
    }
}

/// Textos de una fila del diálogo de selección.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowText {
    /// Primera línea (negrita).
    pub line1: String,
    /// Segunda línea (emisor/uso, representante u organismo).
    pub line2: String,
    /// Tercera línea: `"Válido desde: dd/MM/yyyy hasta dd/MM/yyyy"`.
    pub dates: String,
    /// Enlace "Haga clic aquí para ver las propiedades del certificado"
    /// (`None` en las vistas de representante y seudónimo en macOS).
    pub link: Option<&'static str>,
    /// Texto emergente (y nombre accesible) de la fila.
    pub tooltip: String,
    pub validity: ValidityState,
    pub family: IssuerFamily,
}

/// Formato de fecha `dd/MM/yyyy` en la zona horaria local
/// (`SimpleDateFormat("dd/MM/yyyy")`).
pub fn format_date(t: DateTime<Utc>) -> String {
    t.with_timezone(&chrono::Local).format("%d/%m/%Y").to_string()
}

/// `PrincipalStructure.getRDNvalue` sobre el titular RFC 2253: como
/// [`get_rdn_value`] pero decodificando los valores `#hex` (salta `#`, la
/// etiqueta y una longitud de un octeto y lee UTF-8).
pub fn principal_structure_value(rfc2253: &str, rdn: &str) -> Option<String> {
    get_rdn_value(rdn, rfc2253).map(|v| recover_text(&v))
}

fn recover_text(value: &str) -> String {
    if value.chars().count() < 5 || !value.starts_with('#') {
        return value.to_string();
    }
    let hex: String = value.chars().skip(5).collect();
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| {
            let d = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
            (d(c[0]) << 4) | d(c[1])
        })
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Textos de la fila de un certificado en la vista indicada (§8.5).
/// `friendly_name` es el nombre calculado para la entrada
/// ([`CertEntry::friendly_name`]); `os` decide si se muestra el enlace en
/// las vistas de representante y seudónimo (no en macOS).
pub fn row_text(cert_der: &[u8], friendly_name: &str, view: CertificateView, os: Os, now: DateTime<Utc>) -> RowText {
    let info = afirma_core::cert::CertInfo::parse(cert_der);
    let (nb, na) = info.as_ref().map(|i| (i.not_before, i.not_after)).unwrap_or((now, now));
    let validity = validity_state(nb, na, now);
    let family = issuer_family(cert_der);
    let state_text = if is_expired(nb, na, now) {
        STATE_INVALID
    } else {
        STATE_VALID
    };
    let dates = format!("Válido desde: {} hasta {}", format_date(nb), format_date(na));
    let ku = key_usage_text_from(info.as_ref().and_then(|i| i.key_usage.as_ref()));
    let subject_cn = dn::certificate_cn(cert_der).unwrap_or_default();
    let subject_rfc = dn::rfc2253_subject_string(cert_der).unwrap_or_default();
    let link_other = if os == Os::MacOs { None } else { Some(PROPERTIES_LINK) };
    match view {
        CertificateView::Personal => {
            let issuer_cn = dn::rfc2253_issuer_string(cert_der)
                .map(|s| get_cn(&s))
                .unwrap_or_default();
            RowText {
                line1: friendly_name.to_string(),
                line2: format!("Emisor: {issuer_cn}. Uso: {ku}."),
                dates,
                link: Some(PROPERTIES_LINK),
                tooltip: format!("Certificado emitido para {subject_cn}. Estado: {state_text}."),
                validity,
                family,
            }
        }
        CertificateView::Representative => {
            let line1 = principal_structure_value(&subject_rfc, "O").unwrap_or_else(|| friendly_name.to_string());
            RowText {
                tooltip: format!("Certificado de {line1} emitido para {subject_cn}. Estado: {state_text}."),
                line2: format!("Representante: {subject_cn}"),
                line1,
                dates,
                link: link_other,
                validity,
                family,
            }
        }
        CertificateView::Pseudonym => {
            let title = principal_structure_value(&subject_rfc, "2.5.4.12");
            let pseudonym = principal_structure_value(&subject_rfc, "2.5.4.65");
            let line1 = match (&title, &pseudonym) {
                (Some(t), Some(p)) => format!("{t} ({p})"),
                (Some(t), None) => t.clone(),
                _ => friendly_name.to_string(),
            };
            let organization =
                principal_structure_value(&subject_rfc, "OU").or_else(|| principal_structure_value(&subject_rfc, "O"));
            let (line2, tooltip) = match &organization {
                Some(org) => (
                    format!("Organismo: {org}. Uso: {ku}."),
                    format!(
                        "Certificado de {} perteneciente a {org}. Estado: {state_text}.",
                        title.clone().unwrap_or_else(|| subject_cn.clone())
                    ),
                ),
                None => {
                    let issuer_cn = dn::java_issuer_string(cert_der).map(|s| get_cn(&s)).unwrap_or_default();
                    (
                        format!("Emisor: {issuer_cn}. Uso: {ku}."),
                        format!("Certificado emitido para {subject_cn}. Estado: {state_text}."),
                    )
                }
            };
            RowText {
                line1,
                line2,
                dates,
                link: link_other,
                tooltip,
                validity,
                family,
            }
        }
    }
}

/// [`row_text`] para una entrada del almacén.
pub fn entry_row_text(entry: &CertEntry, view: CertificateView, os: Os, now: DateTime<Utc>) -> RowText {
    row_text(&entry.certificate, &entry.friendly_name, view, os, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::path::Path;

    fn cert(rel: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata").join(rel);
        afirma_core::cert::decode_certificate(&std::fs::read(p).unwrap()).unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 16, 12, 0, 0).unwrap()
    }

    #[test]
    fn usage_texts() {
        assert_eq!(key_usage_text(&cert("pki/firmante-rsa.crt")), "Firma y autenticación");
        assert_eq!(key_usage_text(&cert("pki/autenticacion.crt")), "Autenticación");
        assert_eq!(
            key_usage_text(&cert("keystores/filters/sin-keyusage.der")),
            "Desconocido"
        );
        assert_eq!(
            key_usage_text(&cert("keystores/filters/ku-todos.der")),
            "Firma, autenticación y cifrado"
        );
        assert_eq!(key_usage_text(&cert("keystores/filters/ku-cifrado.der")), "Cifrado");
        assert_eq!(key_usage_text(&cert("keystores/filters/ku-agreement.der")), "Otros");
        assert_eq!(key_usage_text(&cert("keystores/filters/dnie-firma.der")), "Firma");
        let only_sign_cyph = afirma_core::cert::KeyUsageFlags {
            non_repudiation: true,
            data_encipherment: true,
            ..Default::default()
        };
        assert_eq!(key_usage_text_from(Some(&only_sign_cyph)), "Firma");
        let auth_cyph = afirma_core::cert::KeyUsageFlags {
            digital_signature: true,
            data_encipherment: true,
            ..Default::default()
        };
        assert_eq!(key_usage_text_from(Some(&auth_cyph)), "Autenticación y cifrado");
    }

    #[test]
    fn families_and_icons() {
        assert_eq!(
            issuer_family(&cert("keystores/filters/dnie-firma.der")),
            IssuerFamily::Dnie
        );
        assert_eq!(issuer_family(&cert("keystores/filters/cnp.der")), IssuerFamily::Cnp);
        assert_eq!(
            issuer_family(&cert("keystores/filters/pseudonimo.der")),
            IssuerFamily::Fnmt
        );
        assert_eq!(
            issuer_family(&cert("keystores/filters/accv-firma.der")),
            IssuerFamily::Accv
        );
        assert_eq!(issuer_family(&cert("pki/firmante-rsa.crt")), IssuerFamily::Other);
        assert_eq!(
            icon_resource(IssuerFamily::Dnie, ValidityState::ExpiringSoon),
            "dnieicon_w.png"
        );
        assert_eq!(
            icon_description(IssuerFamily::Dnie, ValidityState::Invalid),
            "Certificado de DNIe caducado o aun no válido"
        );
    }

    #[test]
    fn validity_thresholds() {
        let nb = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let na = Utc.with_ymd_and_hms(2026, 10, 23, 12, 0, 0).unwrap();
        // Exactamente 7 días: ya no es aviso.
        assert_eq!(validity_state(nb, na, now()), ValidityState::Valid);
        assert_eq!(
            validity_state(nb, na, now() + chrono::Duration::seconds(1)),
            ValidityState::ExpiringSoon
        );
        assert_eq!(validity_state(nb, na, na), ValidityState::Invalid);
        assert_eq!(validity_state(nb, na, nb), ValidityState::Invalid);
        assert_eq!(
            validity_state(now() + chrono::Duration::days(1), na, now()),
            ValidityState::Invalid
        );
    }

    #[test]
    fn personal_view() {
        let der = cert("keystores/filters/dnie-firma.der");
        let r = row_text(
            &der,
            "ESPAÑOL ESPAÑOL, JUAN (FIRMA)",
            CertificateView::Personal,
            Os::Linux,
            now(),
        );
        assert_eq!(r.line1, "ESPAÑOL ESPAÑOL, JUAN (FIRMA)");
        assert_eq!(r.line2, "Emisor: AC DNIE 004. Uso: Firma.");
        assert!(r.dates.starts_with("Válido desde: 01/01/2020 hasta "), "{}", r.dates);
        assert_eq!(r.link, Some(PROPERTIES_LINK));
        assert_eq!(
            r.tooltip,
            "Certificado emitido para ESPAÑOL ESPAÑOL, JUAN (FIRMA). Estado: vigente."
        );
        assert_eq!(r.validity, ValidityState::Valid);
        let exp = cert("pki/caducado.crt");
        let r = row_text(
            &exp,
            "CERTIFICADO CADUCADO",
            CertificateView::Personal,
            Os::Linux,
            now(),
        );
        assert_eq!(
            r.tooltip,
            "Certificado emitido para CERTIFICADO CADUCADO. Estado: caducado o aún no válido."
        );
        assert_eq!(r.validity, ValidityState::Invalid);
    }

    #[test]
    fn representative_view() {
        let der = cert("keystores/filters/representante.der");
        let r = row_text(&der, "fn", CertificateView::Representative, Os::Windows, now());
        // El valor RFC 2253 tiene la coma escapada y Java corta en ella.
        assert_eq!(r.line1, "EMPRESA DE PRUEBAS\\");
        assert_eq!(r.line2, "Representante: 44444444A JUAN PRUEBA (R: B12345678)");
        assert_eq!(
            r.tooltip,
            "Certificado de EMPRESA DE PRUEBAS\\ emitido para 44444444A JUAN PRUEBA (R: B12345678). Estado: vigente."
        );
        assert_eq!(r.link, Some(PROPERTIES_LINK));
        let r = row_text(&der, "fn", CertificateView::Representative, Os::MacOs, now());
        assert_eq!(r.link, None);
        let r = row_text(
            &cert("pki/firmante-rsa.crt"),
            "NOMBRE",
            CertificateView::Representative,
            Os::Linux,
            now(),
        );
        assert_eq!(r.line1, "NOMBRE");
    }

    #[test]
    fn pseudonym_view() {
        let der = cert("keystores/filters/pseudonimo.der");
        let r = row_text(&der, "fn", CertificateView::Pseudonym, Os::Linux, now());
        assert_eq!(r.line1, "JEFE DE SERVICIO (PSEUDO-0001)");
        assert_eq!(r.line2, "Organismo: UNIDAD DE PRUEBAS. Uso: Firma y autenticación.");
        assert_eq!(
            r.tooltip,
            "Certificado de JEFE DE SERVICIO perteneciente a UNIDAD DE PRUEBAS. Estado: vigente."
        );
        let r = row_text(
            &cert("keystores/filters/cnp.der"),
            "AGENTE CNP",
            CertificateView::Pseudonym,
            Os::Linux,
            now(),
        );
        assert_eq!(r.line1, "AGENTE CNP");
        assert_eq!(r.line2, "Emisor: AC CNP 001. Uso: Firma.");
        assert_eq!(r.tooltip, "Certificado emitido para AGENTE CNP. Estado: vigente.");
        let r = row_text(
            &cert("keystores/filters/solo-o.der"),
            "X",
            CertificateView::Pseudonym,
            Os::Linux,
            now(),
        );
        assert_eq!(r.line2, "Organismo: ORGANIZACION SIN CN. Uso: Firma.");
        assert_eq!(
            r.tooltip,
            "Certificado de ORGANIZACION SIN CN perteneciente a ORGANIZACION SIN CN. Estado: vigente."
        );
    }

    #[test]
    fn misc_texts() {
        assert_eq!(
            dialog_title("Windows", None),
            "Diálogo de seguridad del almacén Windows"
        );
        assert_eq!(
            dialog_title("PKCS#11", Some("opensc-pkcs11.so")),
            "Diálogo de seguridad del almacén PKCS#11 : opensc-pkcs11.so"
        );
        assert_eq!(
            help_url("es", "ES"),
            "https://github.com/ctt-gob-es/clienteafirma/wiki/Help-desktop-select-certs-es-ES"
        );
        assert_eq!(
            CertificateView::from_pref(Some("PSEUDONYM")),
            CertificateView::Pseudonym
        );
        assert_eq!(CertificateView::from_pref(Some("x")), CertificateView::Personal);
        assert_eq!(CertificateView::Representative.pref_value(), "REPRESENTATIVE");
    }
}
