//! Página "Preferencias".
//!
//! Edita las mismas claves que el diálogo de preferencias de AutoFirma (con
//! sus nombres y valores exactos, para que sigan funcionando la importación
//! y exportación de configuraciones y las directivas corporativas). Las
//! claves bloqueadas por la organización se muestran deshabilitadas con un
//! candado.

use std::collections::BTreeMap;

use eframe::egui::{self, Align, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use crate::ui::icons;
use crate::ui::theme::{Palette, semibold};
use crate::ui::widgets::{self, ButtonKind, CalloutKind};

/// Acceso a las preferencias (implementado por el almacén real de
/// preferencias del sistema o, en pruebas, en memoria).
pub trait PrefStore {
    /// Valor efectivo de una clave (usuario, sistema o valor por defecto).
    fn get(&self, key: &str) -> Option<String>;
    /// Escribe (o borra con `None`) una clave del usuario.
    fn set(&mut self, key: &str, value: Option<&str>);
    /// Indica si la organización ha bloqueado la clave.
    fn is_locked(&self, key: &str) -> bool;
    /// Valor por defecto de fábrica.
    fn default_value(&self, key: &str) -> Option<String>;
}

/// Preferencias en memoria (demostración y pruebas).
#[derive(Debug, Default, Clone)]
pub struct MemoryPrefs {
    pub values: BTreeMap<String, String>,
    pub defaults: BTreeMap<String, String>,
    pub locked: Vec<String>,
}

impl PrefStore for MemoryPrefs {
    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).or_else(|| self.defaults.get(key)).cloned()
    }
    fn set(&mut self, key: &str, value: Option<&str>) {
        match value {
            Some(v) => self.values.insert(key.to_string(), v.to_string()),
            None => self.values.remove(key),
        };
    }
    fn is_locked(&self, key: &str) -> bool {
        self.locked.iter().any(|k| k == key)
    }
    fn default_value(&self, key: &str) -> Option<String> {
        self.defaults.get(key).cloned()
    }
}

/// Todas las claves de preferencias que usa la aplicación.
pub const ALL_KEYS: &[&str] = &[
    "omitAskOnClose", "checkForUpdates", "enableProgressDialog", "vdiOptimization", "signatureHashAlgorithm",
    "defaultSignatureFormatPdf", "defaultSignatureFormatFacturae", "defaultSignatureFormatOoxml", "defaultSignatureFormatOdf",
    "defaultSignatureFormatXml", "defaultSignatureFormatBin", "confirmToSign", "allowInvalidSignatures", "massiveOverride",
    "secureConnections", "secureDomainsList", "proxyType", "proxyHost", "proxyPort", "proxyUsername", "proxyPassword",
    "proxyExcludedUrls", "padesPolicyIdentifier", "padesPolicyIdentifierHash", "padesPolicyIdentifierHashAlgorithm",
    "padesPolicyQualifier", "padesBasicFormat", "padesVisibleSignature", "padesObfuscateCertInfo", "padesVisibleStamp",
    "allowShadowAttack", "allowCertifiedPDF", "padesCertificationLevel", "padesSignReason", "padesSignProductionCity",
    "padesSignerContact", "pdfLayer2Text", "pdfLayer2FontFamily", "pdfLayer2FontSize", "pdfLayer2FontStyle",
    "pdfLayer2FontColor", "pdfSignatureRotation", "pdfSignatureImage", "cadesPolicyIdentifier", "cadesPolicyIdentifierHash",
    "cadesPolicyIdentifierHashAlgorithm", "cadesPolicyQualifier", "cadesImplicitMode", "cadesMultisign",
    "xadesPolicyIdentifier", "xadesPolicyIdentifierHash", "xadesPolicyIdentifierHashAlgorithm", "xadesPolicyQualifier",
    "xadesSignFormat", "xadesMultisign", "xadesSignatureProductionCity", "xadesSignatureProductionProvince",
    "xadesSignatureProductionPostalCode", "xadesSignatureProductionCountry", "xadesSignerClaimedRole", "facturaEPolicy",
    "facturaePolicyIdentifier", "facturaePolicyIdentifierHash", "facturaePolicyIdentifierHashAlgorithm",
    "facturaeSignerRole", "facturaeSignatureProductionCity", "facturaeSignatureProductionProvince",
    "facturaeSignatureProductionPostalCode", "facturaeSignatureProductionCountry", "defaultKeystore",
    "defaultLocalKeystorePath", "useDefaultStoreInBrowserCalls", "hideDnieStartScreen", "showExpiredCerts",
    "useOnlySignatureCertificates", "useOnlyAliasCertificates", "skipAuthCertDnie", "default.locale", "uiTheme", "uiScale",
];

/// Valores por defecto de AutoFirma (`preferences.properties`).
pub fn default_values() -> BTreeMap<String, String> {
    [
        ("omitAskOnClose", "false"),
        ("checkForUpdates", "true"),
        ("enableProgressDialog", "true"),
        ("vdiOptimization", "false"),
        ("signatureHashAlgorithm", "SHA256"),
        ("defaultSignatureFormatPdf", "PAdES"),
        ("defaultSignatureFormatFacturae", "FacturaE"),
        ("defaultSignatureFormatOoxml", "CAdES"),
        ("defaultSignatureFormatOdf", "CAdES"),
        ("defaultSignatureFormatXml", "XAdES"),
        ("defaultSignatureFormatBin", "CAdES"),
        ("confirmToSign", "true"),
        ("allowInvalidSignatures", "false"),
        ("massiveOverride", "false"),
        ("secureConnections", "true"),
        ("proxyType", "NONE"),
        ("padesBasicFormat", "ETSI.CAdES.detached"),
        ("padesVisibleSignature", "false"),
        ("padesObfuscateCertInfo", "true"),
        ("padesVisibleStamp", "false"),
        ("allowShadowAttack", "false"),
        ("allowCertifiedPDF", "false"),
        ("padesCertificationLevel", "0"),
        ("cadesImplicitMode", "true"),
        ("cadesMultisign", "cosign"),
        ("xadesSignFormat", "XAdES Detached"),
        ("xadesMultisign", "cosign"),
        ("facturaEPolicy", "3.1"),
        ("facturaeSignerRole", "Emisor"),
        ("defaultKeystore", "default"),
        ("useDefaultStoreInBrowserCalls", "false"),
        ("hideDnieStartScreen", "false"),
        ("showExpiredCerts", "false"),
        ("useOnlySignatureCertificates", "false"),
        ("useOnlyAliasCertificates", "false"),
        ("skipAuthCertDnie", "true"),
        ("default.locale", "es_ES"),
        ("uiTheme", "system"),
        ("uiScale", "1.0"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    General,
    Signature,
    Pdf,
    Xml,
    Binary,
    Invoice,
    Certificates,
    Network,
}

impl Section {
    const ALL: [Section; 8] = [
        Section::General,
        Section::Signature,
        Section::Pdf,
        Section::Xml,
        Section::Binary,
        Section::Invoice,
        Section::Certificates,
        Section::Network,
    ];

    fn label(self) -> &'static str {
        match self {
            Section::General => "General",
            Section::Signature => "Firma",
            Section::Pdf => "PDF (PAdES)",
            Section::Xml => "XML (XAdES)",
            Section::Binary => "Otros ficheros (CAdES)",
            Section::Invoice => "Factura electrónica",
            Section::Certificates => "Certificados",
            Section::Network => "Red y proxy",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Section::General => icons::SLIDERS_HORIZONTAL,
            Section::Signature => icons::PEN_NIB,
            Section::Pdf => icons::FILE_PDF,
            Section::Xml => icons::FILE_CODE,
            Section::Binary => icons::FILE,
            Section::Invoice => icons::RECEIPT,
            Section::Certificates => icons::IDENTIFICATION_CARD,
            Section::Network => icons::GLOBE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsAction {
    Save,
    Discard,
    Import,
    Export,
    RestoreDefaults,
    TestProxy,
}

/// Página de preferencias: trabaja sobre una copia que se guarda al pulsar
/// "Guardar" (como el Aceptar del original).
#[derive(Debug)]
pub struct SettingsPage {
    pub section: Section,
    /// Cambios pendientes: clave -> nuevo valor (`None` = borrar).
    pub pending: BTreeMap<String, Option<String>>,
    pub message: Option<(CalloutKind, String)>,
}

impl Default for SettingsPage {
    fn default() -> Self {
        SettingsPage { section: Section::General, pending: BTreeMap::new(), message: None }
    }
}

struct Ctx<'a> {
    p: &'a Palette,
    store: &'a dyn PrefStore,
    pending: &'a mut BTreeMap<String, Option<String>>,
}

impl Ctx<'_> {
    fn value(&self, key: &str) -> Option<String> {
        match self.pending.get(key) {
            Some(v) => v.clone(),
            None => self.store.get(key),
        }
    }

    fn bool(&self, key: &str) -> bool {
        self.value(key).is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    fn put(&mut self, key: &str, value: Option<String>) {
        if self.store.get(key) == value {
            self.pending.remove(key);
        } else {
            self.pending.insert(key.to_string(), value);
        }
    }

    fn locked(&self, key: &str) -> bool {
        self.store.is_locked(key)
    }
}

fn row_label(ui: &mut Ui, c: &Ctx, key: &str, title: &str, desc: Option<&str>) {
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).font(FontId::new(14.0, semibold())).color(c.p.text));
            if c.locked(key) {
                ui.label(widgets::icon_text(icons::LOCK_SIMPLE, 14.0, c.p.text_faint))
                    .on_hover_text("Tu organización ha fijado este valor");
            }
        });
        if let Some(d) = desc {
            ui.add(egui::Label::new(RichText::new(d).size(12.5).color(c.p.text_muted)).wrap());
        }
    });
}

fn bool_row(ui: &mut Ui, c: &mut Ctx, key: &str, title: &str, desc: Option<&str>) {
    ui.horizontal_top(|ui| {
        let mut v = c.bool(key);
        ui.add_enabled_ui(!c.locked(key), |ui| {
            if super::sign::toggle(ui, c.p, &mut v).changed() {
                c.put(key, Some(v.to_string()));
            }
        });
        ui.add_space(4.0);
        row_label(ui, c, key, title, desc);
    });
    ui.add_space(10.0);
}

fn combo_row(ui: &mut Ui, c: &mut Ctx, key: &str, title: &str, desc: Option<&str>, options: &[(&str, &str)]) {
    ui.horizontal(|ui| {
        row_label(ui, c, key, title, desc);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let current = c.value(key).unwrap_or_default();
            let label = options.iter().find(|(v, _)| *v == current).map(|(_, l)| *l).unwrap_or(current.as_str()).to_string();
            ui.add_enabled_ui(!c.locked(key), |ui| {
                egui::ComboBox::from_id_salt(("pref", key)).selected_text(label).width(230.0).show_ui(ui, |ui| {
                    for (v, l) in options {
                        if ui.selectable_label(current == *v, *l).clicked() {
                            c.put(key, Some((*v).to_string()));
                        }
                    }
                });
            });
        });
    });
    ui.add_space(10.0);
}

fn text_row(ui: &mut Ui, c: &mut Ctx, key: &str, title: &str, hint: &str) {
    ui.label(RichText::new(title).size(13.0).color(c.p.text_muted));
    let mut v = c.value(key).unwrap_or_default();
    let resp = ui.add_enabled(!c.locked(key), egui::TextEdit::singleline(&mut v).hint_text(hint).desired_width(f32::INFINITY));
    if resp.changed() {
        c.put(key, if v.trim().is_empty() { None } else { Some(v) });
    }
    ui.add_space(8.0);
}

fn group(ui: &mut Ui, p: &Palette, title: &str, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            widgets::section_title(ui, p, title);
            ui.add_space(10.0);
            add(ui);
        });
    ui.add_space(14.0);
}

/// Selector de política de firma (AGE 1.9 o a medida) para un formato.
fn policy_group(ui: &mut Ui, c: &mut Ctx, prefix: &str, xades: bool) {
    let id_key = format!("{prefix}PolicyIdentifier");
    let hash_key = format!("{prefix}PolicyIdentifierHash");
    let alg_key = format!("{prefix}PolicyIdentifierHashAlgorithm");
    let qual_key = format!("{prefix}PolicyQualifier");
    const AGE_ID: &str = "urn:oid:2.16.724.1.3.1.1.2.1.9";
    const AGE_HASH: &str = "G7roucf600+f03r/o0bAOQ6WAs0=";
    const AGE_QUAL: &str = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";
    let id = c.value(&id_key).unwrap_or_default();
    let kind = if id.is_empty() {
        0
    } else if id.trim_start_matches("urn:oid:") == AGE_ID.trim_start_matches("urn:oid:")
        && c.value(&hash_key).as_deref() == Some(AGE_HASH)
    {
        1
    } else {
        2
    };
    let locked = c.locked(&id_key);
    let mut selected = kind;
    ui.horizontal(|ui| {
        row_label(ui, c, &id_key, "Política de firma", Some("Algunas administraciones exigen firmar conforme a una política concreta."));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_enabled_ui(!locked, |ui| {
                egui::ComboBox::from_id_salt(("policy", prefix))
                    .selected_text(["Ninguna", "Política de la AGE 1.9", "Política a medida"][kind])
                    .width(230.0)
                    .show_ui(ui, |ui| {
                        for (i, l) in ["Ninguna", "Política de la AGE 1.9", "Política a medida"].iter().enumerate() {
                            ui.selectable_value(&mut selected, i, *l);
                        }
                    });
            });
        });
    });
    if selected != kind {
        match selected {
            0 => {
                for k in [&id_key, &hash_key, &alg_key, &qual_key] {
                    c.put(k, None);
                }
            }
            1 => {
                c.put(&id_key, Some(AGE_ID.into()));
                c.put(&hash_key, Some(AGE_HASH.into()));
                c.put(&alg_key, Some("SHA1".into()));
                c.put(&qual_key, Some(AGE_QUAL.into()));
            }
            _ => {
                c.put(&id_key, Some(if xades { "urn:oid:".into() } else { String::new() }));
                c.put(&hash_key, None);
            }
        }
    }
    if selected == 2 {
        ui.add_space(6.0);
        let id_hint = if xades { "urn:oid:1.2.3… (URI)" } else { "1.2.3… (OID)" };
        text_row(ui, c, &id_key, "Identificador", id_hint);
        text_row(ui, c, &hash_key, "Huella digital del documento de política (Base64)", "Vacío = se descarga y se calcula");
        let key = alg_key.clone();
        combo_row(ui, c, &key, "Algoritmo de la huella", None, &[("SHA1", "SHA-1"), ("SHA-256", "SHA-256"), ("SHA-384", "SHA-384"), ("SHA-512", "SHA-512")]);
        text_row(ui, c, &qual_key, "Calificador (URL del documento)", "https://…");
    }
    ui.add_space(6.0);
}

fn place_group(ui: &mut Ui, c: &mut Ctx, prefix: &str) {
    ui.columns(2, |cols| {
        text_row(&mut cols[0], c, &format!("{prefix}SignatureProductionCity"), "Ciudad", "Madrid");
        text_row(&mut cols[1], c, &format!("{prefix}SignatureProductionProvince"), "Provincia", "Madrid");
        text_row(&mut cols[0], c, &format!("{prefix}SignatureProductionPostalCode"), "Código postal", "28001");
        text_row(&mut cols[1], c, &format!("{prefix}SignatureProductionCountry"), "País", "España");
    });
}

impl SettingsPage {
    pub fn ui(&mut self, ui: &mut Ui, p: &Palette, store: &dyn PrefStore) -> Vec<SettingsAction> {
        let mut actions = Vec::new();
        widgets::page_header(ui, p, "Preferencias", Some("Ajusta cómo firma AutoFirma. Los cambios se aplican al pulsar Guardar."));
        ui.horizontal_top(|ui| {
            // Índice de secciones.
            ui.allocate_ui_with_layout(egui::vec2(200.0, 400.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(200.0);
                for s in Section::ALL {
                    if widgets::nav_item(ui, p, s.icon(), s.label(), self.section == s).clicked() {
                        self.section = s;
                    }
                }
            });
            ui.add_space(16.0);
            ui.vertical(|ui| {
                let mut c = Ctx { p, store, pending: &mut self.pending };
                section_ui(ui, &mut c, self.section, &mut actions);
            });
        });
        if let Some((kind, msg)) = &self.message {
            widgets::callout(ui, p, *kind, msg, None);
        }
        actions
    }

    /// Barra fija de cambios pendientes (se muestra en la parte inferior).
    pub fn pending_bar(&mut self, ui: &mut Ui, p: &Palette) -> Vec<SettingsAction> {
        let mut actions = Vec::new();
        ui.horizontal(|ui| {
            let n = self.pending.len();
            ui.label(widgets::icon_job(icons::INFO, &format!("Tienes {n} cambio{} sin guardar", if n == 1 { "" } else { "s" }), 14.0, p.primary, p.text));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::button(ui, p, ButtonKind::Primary, Some(icons::FLOPPY_DISK), "Guardar", true).clicked() {
                    actions.push(SettingsAction::Save);
                }
                if widgets::button(ui, p, ButtonKind::Secondary, None, "Descartar", true).clicked() {
                    actions.push(SettingsAction::Discard);
                }
            });
        });
        actions
    }
}

fn section_ui(ui: &mut Ui, c: &mut Ctx, section: Section, actions: &mut Vec<SettingsAction>) {
    let p = c.p;
    match section {
        Section::General => {
            group(ui, p, "Apariencia", |ui| {
                combo_row(ui, c, "uiTheme", "Tema", None, &[("system", "Como el sistema"), ("light", "Claro"), ("dark", "Oscuro"), ("contrast", "Alto contraste")]);
                combo_row(ui, c, "uiScale", "Tamaño de la interfaz", None, &[("0.9", "Pequeño"), ("1.0", "Normal"), ("1.15", "Grande"), ("1.3", "Muy grande")]);
                combo_row(
                    ui,
                    c,
                    "default.locale",
                    "Idioma",
                    Some("Se aplica al reiniciar la aplicación."),
                    &[("es_ES", "Español"), ("ca_ES", "Català"), ("gl_ES", "Galego"), ("eu_ES", "Euskara"), ("va_ES", "Valencià"), ("en_US", "English")],
                );
            });
            group(ui, p, "Comportamiento", |ui| {
                bool_row(ui, c, "omitAskOnClose", "No pedir confirmación al cerrar", None);
                bool_row(ui, c, "checkForUpdates", "Buscar actualizaciones al iniciar", None);
                bool_row(ui, c, "enableProgressDialog", "Mostrar el progreso en las firmas desde el navegador", None);
                if cfg!(windows) {
                    bool_row(ui, c, "vdiOptimization", "Optimizar para escritorios virtuales (VDI)", Some("No recomendado en otros entornos."));
                }
            });
            group(ui, p, "Configuración", |ui| {
                ui.label(RichText::new("Comparte tu configuración con otros equipos o vuelve a la de fábrica.").size(12.5).color(p.text_muted));
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::UPLOAD_SIMPLE), "Importar…", true).clicked() {
                        actions.push(SettingsAction::Import);
                    }
                    if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::DOWNLOAD_SIMPLE), "Exportar…", true).clicked() {
                        actions.push(SettingsAction::Export);
                    }
                    if widgets::button(ui, p, ButtonKind::Ghost, Some(icons::ARROW_COUNTER_CLOCKWISE), "Restaurar valores de fábrica", true).clicked() {
                        actions.push(SettingsAction::RestoreDefaults);
                    }
                });
            });
        }
        Section::Signature => {
            group(ui, p, "General", |ui| {
                combo_row(
                    ui,
                    c,
                    "signatureHashAlgorithm",
                    "Algoritmo de huella",
                    Some("SHA-256 es el recomendado. SHA-1 ya no se considera seguro."),
                    &[("SHA256", "SHA-256"), ("SHA384", "SHA-384"), ("SHA512", "SHA-512"), ("SHA1", "SHA-1 (no recomendado)")],
                );
                bool_row(ui, c, "confirmToSign", "Pedir confirmación antes de firmar", None);
                bool_row(ui, c, "allowInvalidSignatures", "Permitir añadir firmas a documentos con firmas no válidas", None);
                bool_row(ui, c, "massiveOverride", "Sobrescribir ficheros existentes al firmar varios documentos", Some("Si no, se añade (1), (2)… al nombre."));
            });
            group(ui, p, "Formato según el tipo de documento", |ui| {
                combo_row(ui, c, "defaultSignatureFormatPdf", "Documentos PDF", None, &[("PAdES", "PAdES"), ("CAdES", "CAdES"), ("XAdES", "XAdES")]);
                combo_row(ui, c, "defaultSignatureFormatFacturae", "Facturas electrónicas", None, &[("FacturaE", "FacturaE"), ("XAdES", "XAdES"), ("CAdES", "CAdES")]);
                combo_row(ui, c, "defaultSignatureFormatOoxml", "Microsoft Office (docx, xlsx…)", None, &[("OOXML (Office Open XML)", "OOXML"), ("CAdES", "CAdES"), ("XAdES", "XAdES")]);
                combo_row(ui, c, "defaultSignatureFormatOdf", "LibreOffice (odt, ods…)", None, &[("ODF (Open Document Format)", "ODF"), ("CAdES", "CAdES"), ("XAdES", "XAdES")]);
                combo_row(ui, c, "defaultSignatureFormatXml", "Otros XML", None, &[("XAdES", "XAdES"), ("CAdES", "CAdES")]);
                combo_row(ui, c, "defaultSignatureFormatBin", "Resto de ficheros", None, &[("CAdES", "CAdES"), ("XAdES", "XAdES")]);
            });
        }
        Section::Pdf => {
            group(ui, p, "Firma de PDF", |ui| {
                policy_group(ui, c, "pades", false);
                combo_row(
                    ui,
                    c,
                    "padesBasicFormat",
                    "Formato",
                    None,
                    &[("ETSI.CAdES.detached", "PAdES-BES (recomendado)"), ("adbe.pkcs7.detached", "PAdES básico")],
                );
                bool_row(ui, c, "padesVisibleSignature", "Firma visible por defecto", None);
                bool_row(ui, c, "padesObfuscateCertInfo", "Ocultar parte del DNI en la firma visible", Some("Muestra, p. ej., ***4567** en lugar del número completo."));
                bool_row(ui, c, "padesVisibleStamp", "Añadir una marca (imagen) por defecto", None);
                bool_row(ui, c, "allowShadowAttack", "Comprobar ataques de sombra al verificar PDF", Some("Detecta modificaciones ocultas; la verificación es más lenta."));
                bool_row(ui, c, "allowCertifiedPDF", "Permitir generar PDF certificados", None);
                if c.bool("allowCertifiedPDF") {
                    combo_row(
                        ui,
                        c,
                        "padesCertificationLevel",
                        "Tipo de certificación",
                        None,
                        &[("0", "Sin certificar"), ("1", "Certificado de autor"), ("2", "Autor, para formularios"), ("3", "Certificado común")],
                    );
                }
            });
            group(ui, p, "Datos de la firma", |ui| {
                text_row(ui, c, "padesSignReason", "Motivo de la firma", "Conformidad");
                text_row(ui, c, "padesSignProductionCity", "Lugar", "Madrid");
                text_row(ui, c, "padesSignerContact", "Contacto del firmante", "correo@ejemplo.es");
            });
        }
        Section::Xml => {
            group(ui, p, "Firma XML", |ui| {
                policy_group(ui, c, "xades", true);
                combo_row(
                    ui,
                    c,
                    "xadesSignFormat",
                    "Tipo de firma",
                    Some("Enveloped inserta la firma dentro del propio XML."),
                    &[("XAdES Detached", "Detached (separada)"), ("XAdES Enveloped", "Enveloped (dentro del XML)"), ("XAdES Enveloping", "Enveloping (envolvente)")],
                );
                combo_row(ui, c, "xadesMultisign", "Si el fichero ya está firmado", None, MULTISIGN);
            });
            group(ui, p, "Datos de la firma", |ui| {
                place_group(ui, c, "xades");
                text_row(ui, c, "xadesSignerClaimedRole", "Cargo del firmante", "Director/a");
            });
        }
        Section::Binary => {
            group(ui, p, "Firma CAdES", |ui| {
                policy_group(ui, c, "cades", false);
                bool_row(ui, c, "cadesImplicitMode", "Incluir una copia del documento en la firma", Some("Así la firma (.csig) contiene el documento y se puede verificar sola."));
                combo_row(ui, c, "cadesMultisign", "Si el fichero ya está firmado", None, MULTISIGN);
            });
        }
        Section::Invoice => {
            group(ui, p, "Factura electrónica", |ui| {
                combo_row(ui, c, "facturaEPolicy", "Política", None, &[("3.1", "Factura electrónica 3.1"), ("3.0", "Factura electrónica 3.0")]);
                combo_row(ui, c, "facturaeSignerRole", "Papel del firmante", None, &[("Emisor", "Emisor"), ("Receptor", "Receptor"), ("Tercero", "Tercero")]);
                place_group(ui, c, "facturae");
            });
        }
        Section::Certificates => {
            group(ui, p, "Almacén de certificados", |ui| {
                combo_row(
                    ui,
                    c,
                    "defaultKeystore",
                    "Almacén por defecto",
                    None,
                    &[("default", "El del sistema"), ("Mozilla / Firefox (unificado)", "Firefox"), ("PKCS#12 / PFX", "Fichero PKCS#12"), ("DNIe y tarjetas FNMT-TIF", "DNIe y tarjetas")],
                );
                bool_row(ui, c, "useDefaultStoreInBrowserCalls", "Usarlo también en las firmas desde el navegador", None);
                bool_row(ui, c, "hideDnieStartScreen", "No mostrar la pantalla de inicio del DNIe", None);
            });
            group(ui, p, "Qué certificados mostrar", |ui| {
                bool_row(ui, c, "showExpiredCerts", "Permitir certificados caducados", None);
                bool_row(ui, c, "useOnlySignatureCertificates", "Solo certificados de firma (no repudio)", None);
                bool_row(ui, c, "useOnlyAliasCertificates", "Solo certificados de seudónimo", None);
                bool_row(ui, c, "skipAuthCertDnie", "Ocultar el certificado de autenticación del DNIe", None);
            });
        }
        Section::Network => {
            group(ui, p, "Seguridad", |ui| {
                bool_row(
                    ui,
                    c,
                    "secureConnections",
                    "Aceptar solo conexiones seguras (recomendado)",
                    Some("Se comprueba el certificado de los servidores con el almacén de confianza del sistema."),
                );
                ui.label(RichText::new("Dominios de confianza adicionales (separados por comas)").size(13.0).color(p.text_muted));
                let mut v = c.value("secureDomainsList").unwrap_or_default();
                if ui
                    .add_enabled(!c.locked("secureDomainsList"), egui::TextEdit::multiline(&mut v).desired_rows(2).desired_width(f32::INFINITY).hint_text("*.miempresa.es, intranet*"))
                    .changed()
                {
                    c.put("secureDomainsList", if v.trim().is_empty() { None } else { Some(v) });
                }
            });
            group(ui, p, "Proxy", |ui| {
                combo_row(
                    ui,
                    c,
                    "proxyType",
                    "Conexión",
                    None,
                    &[("NONE", "Sin proxy"), ("SYSTEM", "Proxy del sistema"), ("CUSTOM", "Proxy manual")],
                );
                if c.value("proxyType").as_deref() == Some("CUSTOM") {
                    ui.columns(2, |cols| {
                        text_row(&mut cols[0], c, "proxyHost", "Servidor", "proxy.miempresa.es");
                        text_row(&mut cols[1], c, "proxyPort", "Puerto", "8080");
                        text_row(&mut cols[0], c, "proxyUsername", "Usuario", "");
                        text_row(&mut cols[1], c, "proxyPassword", "Contraseña", "");
                    });
                    text_row(ui, c, "proxyExcludedUrls", "Sin proxy para (separados por comas)", "localhost, *.intranet");
                    if widgets::button(ui, p, ButtonKind::Secondary, Some(icons::PLUGS_CONNECTED), "Probar conexión", true).clicked() {
                        actions.push(SettingsAction::TestProxy);
                    }
                }
            });
        }
    }
}

const MULTISIGN: &[(&str, &str)] = &[
    ("cosign", "Añadir mi firma (cofirma)"),
    ("countersignLeafs", "Contrafirmar las últimas firmas"),
    ("countersignTree", "Contrafirmar todas las firmas"),
];

#[allow(dead_code)]
fn _unused(_: CalloutKind) {}
