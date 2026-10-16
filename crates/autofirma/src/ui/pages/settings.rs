//! Página "Preferencias".
//!
//! Edita las mismas claves que el diálogo de preferencias de AutoFirma (con
//! sus nombres y valores exactos, para que sigan funcionando la importación
//! y exportación de configuraciones y las directivas corporativas). Las
//! claves bloqueadas por la organización se muestran deshabilitadas con un
//! candado.

use std::collections::BTreeMap;

use eframe::egui::{self, Align, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, Ui};

use crate::i18n::{LANGUAGES, tr, trf};
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
    /// Configuración efectiva como fichero `.afconfig`.
    fn export_config(&self) -> Result<String, String> {
        Err(tr("La exportación no está disponible en este modo").into())
    }
    /// Analiza un `.afconfig` y comprueba su firma (sin aplicarlo todavía).
    fn prepare_import(&self, _data: &[u8]) -> Result<afirma_system::prefs::PreparedImport, String> {
        Err(tr("La importación no está disponible en este modo").into())
    }
    /// Aplica una importación confirmada; devuelve un resumen.
    fn apply_import(&mut self, _prepared: &afirma_system::prefs::PreparedImport) -> Result<String, String> {
        Err(tr("La importación no está disponible en este modo").into())
    }
    /// Vuelve a los valores de fábrica (borra los del usuario; las tarjetas
    /// añadidas se conservan).
    fn restore_defaults(&mut self);
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
    fn restore_defaults(&mut self) {
        self.values.clear();
    }
}

/// Todas las claves de preferencias que usa la aplicación.
pub const ALL_KEYS: &[&str] = &[
    "omitAskOnClose",
    "checkForUpdates",
    "enableProgressDialog",
    "vdiOptimization",
    "signatureHashAlgorithm",
    "defaultSignatureFormatPdf",
    "defaultSignatureFormatFacturae",
    "defaultSignatureFormatOoxml",
    "defaultSignatureFormatOdf",
    "defaultSignatureFormatXml",
    "defaultSignatureFormatBin",
    "confirmToSign",
    "allowInvalidSignatures",
    "massiveOverride",
    "secureConnections",
    "secureDomainsList",
    "proxyType",
    "proxyHost",
    "proxyPort",
    "proxyUsername",
    "proxyPassword",
    "proxyExcludedUrls",
    "padesPolicyIdentifier",
    "padesPolicyIdentifierHash",
    "padesPolicyIdentifierHashAlgorithm",
    "padesPolicyQualifier",
    "padesBasicFormat",
    "padesVisibleSignature",
    "padesObfuscateCertInfo",
    "padesVisibleStamp",
    "allowShadowAttack",
    "allowCertifiedPDF",
    "padesCertificationLevel",
    "padesSignReason",
    "padesSignProductionCity",
    "padesSignerContact",
    "pdfLayer2Text",
    "pdfLayer2FontFamily",
    "pdfLayer2FontSize",
    "pdfLayer2FontStyle",
    "pdfLayer2FontColor",
    "pdfSignatureRotation",
    "pdfSignatureImage",
    "cadesPolicyIdentifier",
    "cadesPolicyIdentifierHash",
    "cadesPolicyIdentifierHashAlgorithm",
    "cadesPolicyQualifier",
    "cadesImplicitMode",
    "cadesMultisign",
    "xadesPolicyIdentifier",
    "xadesPolicyIdentifierHash",
    "xadesPolicyIdentifierHashAlgorithm",
    "xadesPolicyQualifier",
    "xadesSignFormat",
    "xadesMultisign",
    "xadesSignatureProductionCity",
    "xadesSignatureProductionProvince",
    "xadesSignatureProductionPostalCode",
    "xadesSignatureProductionCountry",
    "xadesSignerClaimedRole",
    "facturaEPolicy",
    "facturaePolicyIdentifier",
    "facturaePolicyIdentifierHash",
    "facturaePolicyIdentifierHashAlgorithm",
    "facturaeSignerRole",
    "facturaeSignatureProductionCity",
    "facturaeSignatureProductionProvince",
    "facturaeSignatureProductionPostalCode",
    "facturaeSignatureProductionCountry",
    "defaultKeystore",
    "defaultLocalKeystorePath",
    "useDefaultStoreInBrowserCalls",
    "hideDnieStartScreen",
    "showExpiredCerts",
    "useOnlySignatureCertificates",
    "useOnlyAliasCertificates",
    "skipAuthCertDnie",
    "default.locale",
    "uiTheme",
    "uiScale",
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
            Section::General => tr("General"),
            Section::Signature => tr("Firma"),
            Section::Pdf => "PDF (PAdES)",
            Section::Xml => "XML (XAdES)",
            Section::Binary => tr("Otros ficheros (CAdES)"),
            Section::Invoice => tr("Factura electrónica"),
            Section::Certificates => tr("Certificados"),
            Section::Network => tr("Red y proxy"),
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
    /// Certificados de confianza personales (`TrustedCertsKeystore.jks`).
    TrustedReload,
    TrustedImportFile,
    TrustedImportUrl(String),
    TrustedRemove(String),
}

/// Certificado del almacén de confianza personal.
#[derive(Debug, Clone)]
pub struct TrustedRow {
    pub alias: String,
    pub name: String,
    pub issuer: String,
    pub expires: String,
}

/// Página de preferencias: trabaja sobre una copia que se guarda al pulsar
/// "Guardar" (como el Aceptar del original).
#[derive(Debug)]
pub struct SettingsPage {
    pub section: Section,
    /// Cambios pendientes: clave -> nuevo valor (`None` = borrar).
    pub pending: BTreeMap<String, Option<String>>,
    pub message: Option<(CalloutKind, String)>,
    /// Certificados de confianza personales (`None` = sin cargar).
    pub trusted: Option<Vec<TrustedRow>>,
    pub trusted_url: String,
    pub trusted_busy: bool,
}

impl Default for SettingsPage {
    fn default() -> Self {
        SettingsPage {
            section: Section::General,
            pending: BTreeMap::new(),
            message: None,
            trusted: None,
            trusted_url: String::new(),
            trusted_busy: false,
        }
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
            // Con ajuste de línea: en otros idiomas los textos son más largos.
            ui.add(egui::Label::new(RichText::new(title).font(FontId::new(14.0, semibold())).color(c.p.text)).wrap());
            if c.locked(key) {
                ui.label(widgets::icon_text(icons::LOCK_SIMPLE, 14.0, c.p.text_faint))
                    .on_hover_text(tr("Tu organización ha fijado este valor"));
            }
        });
        if let Some(d) = desc {
            ui.add(egui::Label::new(RichText::new(d).size(12.5).color(c.p.text_muted)).wrap());
        }
    });
}

/// Etiqueta de una fila con un desplegable a la derecha: ocupa solo el ancho
/// que deja libre el desplegable, para que los textos largos pasen a la línea
/// siguiente en lugar de quedar debajo de él.
fn combo_label(ui: &mut Ui, c: &Ctx, key: &str, title: &str, desc: Option<&str>) {
    let width = (ui.available_width() - 230.0 - 24.0).max(140.0);
    ui.vertical(|ui| {
        ui.set_max_width(width);
        row_label(ui, c, key, title, desc);
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
        combo_label(ui, c, key, title, desc);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let current = c.value(key).unwrap_or_default();
            let label = options
                .iter()
                .find(|(v, _)| *v == current)
                .map(|(_, l)| *l)
                .unwrap_or(current.as_str())
                .to_string();
            ui.add_enabled_ui(!c.locked(key), |ui| {
                egui::ComboBox::from_id_salt(("pref", key))
                    .selected_text(label)
                    .width(230.0)
                    .show_ui(ui, |ui| {
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
    let resp = ui.add_enabled(
        !c.locked(key),
        egui::TextEdit::singleline(&mut v)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
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
        combo_label(
            ui,
            c,
            &id_key,
            tr("Política de firma"),
            Some(tr(
                "Algunas administraciones exigen firmar conforme a una política concreta.",
            )),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let labels = [tr("Ninguna"), tr("Política de la AGE 1.9"), tr("Política a medida")];
            ui.add_enabled_ui(!locked, |ui| {
                egui::ComboBox::from_id_salt(("policy", prefix))
                    .selected_text(labels[kind])
                    .width(230.0)
                    .show_ui(ui, |ui| {
                        for (i, l) in labels.iter().enumerate() {
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
        let id_hint = if xades {
            "urn:oid:1.2.3… (URI)"
        } else {
            "1.2.3… (OID)"
        };
        text_row(ui, c, &id_key, tr("Identificador"), id_hint);
        text_row(
            ui,
            c,
            &hash_key,
            tr("Huella digital del documento de política (Base64)"),
            tr("Vacío: se descarga y se calcula"),
        );
        let key = alg_key.clone();
        combo_row(
            ui,
            c,
            &key,
            tr("Algoritmo de la huella"),
            None,
            &[
                ("SHA1", "SHA-1"),
                ("SHA-256", "SHA-256"),
                ("SHA-384", "SHA-384"),
                ("SHA-512", "SHA-512"),
            ],
        );
        text_row(ui, c, &qual_key, tr("Calificador (URL del documento)"), "https://…");
    }
    ui.add_space(6.0);
}

fn place_group(ui: &mut Ui, c: &mut Ctx, prefix: &str) {
    ui.columns(2, |cols| {
        text_row(
            &mut cols[0],
            c,
            &format!("{prefix}SignatureProductionCity"),
            tr("Ciudad"),
            "Madrid",
        );
        text_row(
            &mut cols[1],
            c,
            &format!("{prefix}SignatureProductionProvince"),
            tr("Provincia"),
            "Madrid",
        );
        text_row(
            &mut cols[0],
            c,
            &format!("{prefix}SignatureProductionPostalCode"),
            tr("Código postal"),
            "28001",
        );
        text_row(
            &mut cols[1],
            c,
            &format!("{prefix}SignatureProductionCountry"),
            tr("País"),
            tr("España"),
        );
    });
}

impl SettingsPage {
    pub fn ui(&mut self, ui: &mut Ui, p: &Palette, store: &dyn PrefStore) -> Vec<SettingsAction> {
        let mut actions = Vec::new();
        widgets::page_header(
            ui,
            p,
            tr("Preferencias"),
            Some(tr(
                "Ajusta cómo firma AutoFirma. Los cambios se aplican al pulsar Guardar.",
            )),
        );
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
                let mut c = Ctx {
                    p,
                    store,
                    pending: &mut self.pending,
                };
                section_ui(ui, &mut c, self.section, &mut actions);
                let allowed = store.get("allowPersonalTruststore").as_deref() != Some("false")
                    && store.get("secureConnections").as_deref() != Some("false");
                if self.section == Section::Network && allowed {
                    self.trusted_group(ui, p, &mut actions);
                }
            });
        });
        if let Some((kind, msg)) = &self.message {
            widgets::callout(ui, p, *kind, msg, None);
        }
        actions
    }

    /// Certificados de confianza personales («Certificados de confianza» de AutoFirma).
    fn trusted_group(&mut self, ui: &mut Ui, p: &Palette, actions: &mut Vec<SettingsAction>) {
        if self.trusted.is_none() && !self.trusted_busy {
            actions.push(SettingsAction::TrustedReload);
        }
        group(ui, p, tr("Certificados de confianza"), |ui| {
            ui.label(
                RichText::new(tr(
                    "Certificados de servidores o autoridades en los que confías además de los del sistema (p. ej., de la intranet).",
                ))
                .size(12.5)
                .color(p.text_muted),
            );
            ui.add_space(4.0);
            match &self.trusted {
                Some(rows) if rows.is_empty() => {
                    ui.label(RichText::new(tr("No has importado ningún certificado.")).color(p.text_faint));
                }
                Some(rows) => {
                    for r in rows {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&r.name).font(FontId::new(13.5, semibold())));
                                ui.label(
                                    RichText::new(trf("Emitido por {0} · Caduca el {1}", &[&r.issuer, &r.expires]))
                                        .size(12.0)
                                        .color(p.text_muted),
                                );
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.link(tr("Eliminar")).clicked() {
                                    actions.push(SettingsAction::TrustedRemove(r.alias.clone()));
                                }
                            });
                        });
                        ui.add_space(4.0);
                    }
                }
                None => {
                    ui.spinner();
                }
            }
            ui.add_space(6.0);
            if widgets::button(
                ui,
                p,
                ButtonKind::Secondary,
                Some(icons::FILE_PLUS),
                tr("Importar fichero…"),
                !self.trusted_busy,
            )
            .clicked()
            {
                actions.push(SettingsAction::TrustedImportFile);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let can = !self.trusted_busy && !self.trusted_url.trim().is_empty();
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if self.trusted_busy {
                        ui.spinner();
                    }
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Secondary,
                        Some(icons::GLOBE),
                        tr("Obtener del servidor"),
                        can,
                    )
                    .clicked()
                    {
                        actions.push(SettingsAction::TrustedImportUrl(self.trusted_url.trim().to_string()));
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.trusted_url)
                            .hint_text("https://intranet.miempresa.es")
                            .desired_width(ui.available_width()),
                    );
                });
            });
        });
    }

    /// Barra fija de cambios pendientes (se muestra en la parte inferior).
    pub fn pending_bar(&mut self, ui: &mut Ui, p: &Palette) -> Vec<SettingsAction> {
        let mut actions = Vec::new();
        ui.horizontal(|ui| {
            let n = self.pending.len();
            let text = if n == 1 {
                tr("Tienes 1 cambio sin guardar").to_string()
            } else {
                trf("Tienes {0} cambios sin guardar", &[&n])
            };
            ui.label(widgets::icon_job(icons::INFO, &text, 14.0, p.primary, p.text));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::button(
                    ui,
                    p,
                    ButtonKind::Primary,
                    Some(icons::FLOPPY_DISK),
                    tr("Guardar"),
                    true,
                )
                .clicked()
                {
                    actions.push(SettingsAction::Save);
                }
                if widgets::button(ui, p, ButtonKind::Secondary, None, tr("Descartar"), true).clicked() {
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
            group(ui, p, tr("Apariencia"), |ui| {
                combo_row(
                    ui,
                    c,
                    "uiTheme",
                    tr("Tema"),
                    None,
                    &[
                        ("system", tr("Como el sistema")),
                        ("light", tr("Claro")),
                        ("dark", tr("Oscuro")),
                        ("contrast", tr("Alto contraste")),
                    ],
                );
                combo_row(
                    ui,
                    c,
                    "uiScale",
                    tr("Tamaño de la interfaz"),
                    None,
                    &[
                        ("0.9", tr("Pequeño")),
                        ("1.0", tr("Normal")),
                        ("1.15", tr("Grande")),
                        ("1.3", tr("Muy grande")),
                    ],
                );
                combo_row(
                    ui,
                    c,
                    "default.locale",
                    tr("Idioma"),
                    Some(tr("Se aplica al reiniciar la aplicación.")),
                    &LANGUAGES,
                );
            });
            group(ui, p, tr("Comportamiento"), |ui| {
                bool_row(ui, c, "omitAskOnClose", tr("No pedir confirmación al cerrar"), None);
                bool_row(ui, c, "checkForUpdates", tr("Buscar actualizaciones al iniciar"), None);
                bool_row(
                    ui,
                    c,
                    "enableProgressDialog",
                    tr("Mostrar el progreso en las firmas desde el navegador"),
                    None,
                );
                if cfg!(windows) {
                    bool_row(
                        ui,
                        c,
                        "vdiOptimization",
                        tr("Optimizar para escritorios virtuales (VDI)"),
                        Some(tr("No recomendado en otros entornos.")),
                    );
                }
            });
            group(ui, p, tr("Configuración"), |ui| {
                ui.label(
                    RichText::new(tr(
                        "Comparte tu configuración con otros equipos o vuelve a la de fábrica.",
                    ))
                    .size(12.5)
                    .color(p.text_muted),
                );
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Secondary,
                        Some(icons::UPLOAD_SIMPLE),
                        tr("Importar…"),
                        true,
                    )
                    .clicked()
                    {
                        actions.push(SettingsAction::Import);
                    }
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Secondary,
                        Some(icons::DOWNLOAD_SIMPLE),
                        tr("Exportar…"),
                        true,
                    )
                    .clicked()
                    {
                        actions.push(SettingsAction::Export);
                    }
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Ghost,
                        Some(icons::ARROW_COUNTER_CLOCKWISE),
                        tr("Restaurar valores de fábrica"),
                        true,
                    )
                    .clicked()
                    {
                        actions.push(SettingsAction::RestoreDefaults);
                    }
                });
            });
        }
        Section::Signature => {
            group(ui, p, tr("General"), |ui| {
                combo_row(
                    ui,
                    c,
                    "signatureHashAlgorithm",
                    tr("Algoritmo de huella"),
                    Some(tr("SHA-256 es el recomendado. SHA-1 ya no se considera seguro.")),
                    &[
                        ("SHA256", "SHA-256"),
                        ("SHA384", "SHA-384"),
                        ("SHA512", "SHA-512"),
                        ("SHA1", tr("SHA-1 (no recomendado)")),
                    ],
                );
                bool_row(ui, c, "confirmToSign", tr("Pedir confirmación antes de firmar"), None);
                bool_row(
                    ui,
                    c,
                    "allowInvalidSignatures",
                    tr("Permitir añadir firmas a documentos con firmas no válidas"),
                    None,
                );
                bool_row(
                    ui,
                    c,
                    "massiveOverride",
                    tr("Sobrescribir ficheros existentes al firmar varios documentos"),
                    Some(tr("Si no, se añade (1), (2)… al nombre.")),
                );
            });
            group(ui, p, tr("Formato según el tipo de documento"), |ui| {
                combo_row(
                    ui,
                    c,
                    "defaultSignatureFormatPdf",
                    tr("Documentos PDF"),
                    None,
                    &[("PAdES", "PAdES"), ("CAdES", "CAdES"), ("XAdES", "XAdES")],
                );
                combo_row(
                    ui,
                    c,
                    "defaultSignatureFormatFacturae",
                    tr("Facturas electrónicas"),
                    None,
                    &[("FacturaE", "FacturaE"), ("XAdES", "XAdES"), ("CAdES", "CAdES")],
                );
                combo_row(
                    ui,
                    c,
                    "defaultSignatureFormatOoxml",
                    tr("Microsoft Office (docx, xlsx…)"),
                    None,
                    &[
                        ("OOXML (Office Open XML)", "OOXML"),
                        ("CAdES", "CAdES"),
                        ("XAdES", "XAdES"),
                    ],
                );
                combo_row(
                    ui,
                    c,
                    "defaultSignatureFormatOdf",
                    tr("LibreOffice (odt, ods…)"),
                    None,
                    &[
                        ("ODF (Open Document Format)", "ODF"),
                        ("CAdES", "CAdES"),
                        ("XAdES", "XAdES"),
                    ],
                );
                combo_row(
                    ui,
                    c,
                    "defaultSignatureFormatXml",
                    tr("Otros XML"),
                    None,
                    &[("XAdES", "XAdES"), ("CAdES", "CAdES")],
                );
                combo_row(
                    ui,
                    c,
                    "defaultSignatureFormatBin",
                    tr("Resto de ficheros"),
                    None,
                    &[("CAdES", "CAdES"), ("XAdES", "XAdES")],
                );
            });
        }
        Section::Pdf => {
            group(ui, p, tr("Firma de PDF"), |ui| {
                policy_group(ui, c, "pades", false);
                combo_row(
                    ui,
                    c,
                    "padesBasicFormat",
                    tr("Formato"),
                    None,
                    &[
                        ("ETSI.CAdES.detached", tr("PAdES-BES (recomendado)")),
                        ("adbe.pkcs7.detached", tr("PAdES básico")),
                    ],
                );
                bool_row(ui, c, "padesVisibleSignature", tr("Firma visible por defecto"), None);
                bool_row(
                    ui,
                    c,
                    "padesObfuscateCertInfo",
                    tr("Ocultar parte del DNI en la firma visible"),
                    Some(tr("Muestra, p. ej., ***4567** en lugar del número completo.")),
                );
                bool_row(
                    ui,
                    c,
                    "padesVisibleStamp",
                    tr("Añadir una marca (imagen) por defecto"),
                    None,
                );
                bool_row(
                    ui,
                    c,
                    "allowShadowAttack",
                    tr("Comprobar ataques de sombra al verificar PDF"),
                    Some(tr("Detecta modificaciones ocultas; la verificación es más lenta.")),
                );
                bool_row(
                    ui,
                    c,
                    "allowCertifiedPDF",
                    tr("Permitir generar PDF certificados"),
                    None,
                );
                if c.bool("allowCertifiedPDF") {
                    combo_row(
                        ui,
                        c,
                        "padesCertificationLevel",
                        tr("Tipo de certificación"),
                        None,
                        &[
                            ("0", tr("Sin certificar")),
                            ("1", tr("Certificado de autor")),
                            ("2", tr("Autor, para formularios")),
                            ("3", tr("Certificado común")),
                        ],
                    );
                }
            });
            group(ui, p, tr("Datos de la firma"), |ui| {
                text_row(ui, c, "padesSignReason", tr("Motivo de la firma"), tr("Conformidad"));
                text_row(ui, c, "padesSignProductionCity", tr("Lugar"), "Madrid");
                text_row(
                    ui,
                    c,
                    "padesSignerContact",
                    tr("Contacto del firmante"),
                    tr("correo@ejemplo.es"),
                );
            });
        }
        Section::Xml => {
            group(ui, p, tr("Firma XML"), |ui| {
                policy_group(ui, c, "xades", true);
                combo_row(
                    ui,
                    c,
                    "xadesSignFormat",
                    tr("Tipo de firma"),
                    Some(tr("Enveloped inserta la firma dentro del propio XML.")),
                    &[
                        ("XAdES Detached", tr("Detached (separada)")),
                        ("XAdES Enveloped", tr("Enveloped (dentro del XML)")),
                        ("XAdES Enveloping", tr("Enveloping (envolvente)")),
                    ],
                );
                combo_row(
                    ui,
                    c,
                    "xadesMultisign",
                    tr("Si el fichero ya está firmado"),
                    None,
                    &multisign(),
                );
            });
            group(ui, p, tr("Datos de la firma"), |ui| {
                place_group(ui, c, "xades");
                text_row(
                    ui,
                    c,
                    "xadesSignerClaimedRole",
                    tr("Cargo del firmante"),
                    tr("Director/a"),
                );
            });
        }
        Section::Binary => {
            group(ui, p, tr("Firma CAdES"), |ui| {
                policy_group(ui, c, "cades", false);
                bool_row(
                    ui,
                    c,
                    "cadesImplicitMode",
                    tr("Incluir una copia del documento en la firma"),
                    Some(tr(
                        "Así la firma (.csig) contiene el documento y se puede verificar sola.",
                    )),
                );
                combo_row(
                    ui,
                    c,
                    "cadesMultisign",
                    tr("Si el fichero ya está firmado"),
                    None,
                    &multisign(),
                );
            });
        }
        Section::Invoice => {
            group(ui, p, tr("Factura electrónica"), |ui| {
                combo_row(
                    ui,
                    c,
                    "facturaEPolicy",
                    tr("Política"),
                    None,
                    &[
                        ("3.1", tr("Factura electrónica 3.1")),
                        ("3.0", tr("Factura electrónica 3.0")),
                    ],
                );
                combo_row(
                    ui,
                    c,
                    "facturaeSignerRole",
                    tr("Papel del firmante"),
                    None,
                    &[
                        ("Emisor", tr("Emisor")),
                        ("Receptor", tr("Receptor")),
                        ("Tercero", tr("Tercero")),
                    ],
                );
                place_group(ui, c, "facturae");
            });
        }
        Section::Certificates => {
            group(ui, p, tr("Almacén de certificados"), |ui| {
                combo_row(
                    ui,
                    c,
                    "defaultKeystore",
                    tr("Almacén por defecto"),
                    None,
                    &[
                        ("default", tr("El del sistema")),
                        ("Mozilla / Firefox (unificado)", "Firefox"),
                        ("PKCS#12 / PFX", tr("Fichero PKCS#12")),
                        ("DNIe y tarjetas FNMT-TIF", tr("DNIe y tarjetas")),
                    ],
                );
                bool_row(
                    ui,
                    c,
                    "useDefaultStoreInBrowserCalls",
                    tr("Usarlo también en las firmas desde el navegador"),
                    None,
                );
                bool_row(
                    ui,
                    c,
                    "hideDnieStartScreen",
                    tr("No mostrar la pantalla de inicio del DNIe"),
                    None,
                );
            });
            group(ui, p, tr("Qué certificados mostrar"), |ui| {
                bool_row(ui, c, "showExpiredCerts", tr("Permitir certificados caducados"), None);
                bool_row(
                    ui,
                    c,
                    "useOnlySignatureCertificates",
                    tr("Solo certificados de firma (no repudio)"),
                    None,
                );
                bool_row(
                    ui,
                    c,
                    "useOnlyAliasCertificates",
                    tr("Solo certificados de seudónimo"),
                    None,
                );
                bool_row(
                    ui,
                    c,
                    "skipAuthCertDnie",
                    tr("Ocultar el certificado de autenticación del DNIe"),
                    None,
                );
            });
        }
        Section::Network => {
            group(ui, p, tr("Seguridad"), |ui| {
                bool_row(
                    ui,
                    c,
                    "secureConnections",
                    tr("Aceptar solo conexiones seguras (recomendado)"),
                    Some(tr(
                        "Se comprueba el certificado de los servidores con el almacén de confianza del sistema.",
                    )),
                );
                ui.label(
                    RichText::new(tr("Dominios de confianza adicionales (separados por comas)"))
                        .size(13.0)
                        .color(p.text_muted),
                );
                let mut v = c.value("secureDomainsList").unwrap_or_default();
                if ui
                    .add_enabled(
                        !c.locked("secureDomainsList"),
                        egui::TextEdit::multiline(&mut v)
                            .desired_rows(2)
                            .desired_width(f32::INFINITY)
                            .hint_text("*.miempresa.es, intranet*"),
                    )
                    .changed()
                {
                    c.put("secureDomainsList", if v.trim().is_empty() { None } else { Some(v) });
                }
            });
            group(ui, p, tr("Proxy"), |ui| {
                combo_row(
                    ui,
                    c,
                    "proxyType",
                    tr("Conexión"),
                    None,
                    &[
                        ("NONE", tr("Sin proxy")),
                        ("SYSTEM", tr("Proxy del sistema")),
                        ("CUSTOM", tr("Proxy manual")),
                    ],
                );
                if c.value("proxyType").as_deref() == Some("CUSTOM") {
                    ui.columns(2, |cols| {
                        text_row(&mut cols[0], c, "proxyHost", tr("Servidor"), "proxy.miempresa.es");
                        text_row(&mut cols[1], c, "proxyPort", tr("Puerto"), "8080");
                        text_row(&mut cols[0], c, "proxyUsername", tr("Usuario"), "");
                        text_row(&mut cols[1], c, "proxyPassword", tr("Contraseña"), "");
                    });
                    text_row(
                        ui,
                        c,
                        "proxyExcludedUrls",
                        tr("Sin proxy para (separados por comas)"),
                        "localhost, *.intranet",
                    );
                    if widgets::button(
                        ui,
                        p,
                        ButtonKind::Secondary,
                        Some(icons::PLUGS_CONNECTED),
                        tr("Probar conexión"),
                        true,
                    )
                    .clicked()
                    {
                        actions.push(SettingsAction::TestProxy);
                    }
                }
            });
        }
    }
}

/// Opciones de `cadesMultisign` y `xadesMultisign`.
fn multisign() -> [(&'static str, &'static str); 3] {
    [
        ("cosign", tr("Añadir mi firma (cofirma)")),
        ("countersignLeafs", tr("Contrafirmar las últimas firmas")),
        ("countersignTree", tr("Contrafirmar todas las firmas")),
    ]
}

#[allow(dead_code)]
fn _unused(_: CalloutKind) {}
