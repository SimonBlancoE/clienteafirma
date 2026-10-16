//! Datos de demostración para revisar la interfaz sin almacenes reales.

use super::app::{AutoFirmaApp, Page};
use super::cert_picker::StoreOption;
use super::icons;
use super::model::CertItem;
use super::pages::certificates::StoreEntry;
use super::pages::sign::{FileItem, FileKind, FileStatus, Operation, Stage};
use super::pages::tools::{CheckRow, Tool};
use super::pages::verify::{PolicyInfo, SignatureDetail, SignatureReport};
use super::theme::ThemeChoice;
use crate::i18n::{tr, trf};
use eframe::egui;

fn test_certs() -> Vec<CertItem> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki");
    let mut certs = Vec::new();
    for name in ["firmante-rsa", "firmante-ec", "autenticacion", "caducado"] {
        if let Ok(pem) = std::fs::read(dir.join(format!("{name}.crt")))
            && let Some(der) = afirma_core::cert::decode_certificate(&pem)
            && let Some(c) = CertItem::from_der(name, der)
        {
            certs.push(c);
        }
    }
    certs
}

/// Estados de demostración para revisar la interfaz (capturas de pantalla).
/// Se activan con la variable de entorno `AF_DEMO`.
pub fn load(app: &mut AutoFirmaApp, demo: &str, ctx: &egui::Context) {
    if demo.contains("dark") {
        app.theme = ThemeChoice::Dark;
    }
    if demo.contains("hc") {
        app.theme = ThemeChoice::HighContrast;
    }
    let item = |name: &str, kind: FileKind, format: &str, formats: &[&str], size: u64| FileItem {
        path: std::path::PathBuf::from(format!("/home/usuario/Documentos/{name}")),
        name: name.into(),
        size,
        kind,
        format: format.into(),
        formats: formats.iter().map(|s| s.to_string()).collect(),
        operation: Operation::Sign,
        status: FileStatus::Pending,
        existing_signatures: None,
        data: Default::default(),
    };
    if demo.contains("ready") || demo.contains("finished") || demo.contains("picker") {
        app.sign.files = vec![
            item(
                "Solicitud de subvención 2026.pdf",
                FileKind::Pdf,
                "PAdES",
                &["PAdES", "CAdES", "XAdES"],
                284_312,
            ),
            item(
                "factura-0042.xsig",
                FileKind::FacturaE,
                "FacturaE",
                &["FacturaE", "XAdES", "CAdES"],
                18_204,
            ),
            item(
                "Contrato de servicios.docx",
                FileKind::Ooxml,
                "CAdES",
                &["CAdES", "OOXML", "XAdES"],
                61_877,
            ),
        ];
        let mut signed = item(
            "informe-tecnico.pdf.csig",
            FileKind::Signature("CAdES".into()),
            "CAdES",
            &["CAdES"],
            9_102,
        );
        signed.operation = Operation::Cosign;
        signed.existing_signatures = Some(trf("1 firma de {0}", &[&"PRUEBA MARIA"]));
        app.sign.files.push(signed);
        app.sign.stage = Stage::Ready;
        app.sign.visible_signature = true;
    }
    if demo.contains("finished") {
        for (i, f) in app.sign.files.iter_mut().enumerate() {
            f.status = if i == 2 {
                FileStatus::Failed("El certificado no permite firmar con el algoritmo SHA-1".into())
            } else {
                FileStatus::Done(f.path.with_extension("signed.pdf"))
            };
        }
        if demo.contains("single") {
            app.sign.files.truncate(1);
        }
        app.sign.stage = Stage::Finished;
    }
    if demo.contains("verify") {
        use afirma_core::validity::{SignValidity, Validity, ValidityError};
        app.page = Page::Verify;
        let t = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        let ok = || vec![SignValidity::ok()];
        let mut report = SignatureReport {
            file_name: "Resolución 2026-0117.pdf".into(),
            format: "PAdES".into(),
            data_location: Some(tr("La firma se encuentra dentro del PDF").into()),
            data_objects: vec![(String::new(), "PDF".into(), String::new())],
            overall: Some(SignValidity::ok()),
            has_embedded_data: true,
            ..Default::default()
        };
        report.signatures = vec![
            SignatureDetail {
                signer: "ESPAÑOL ESPAÑOL JUAN - 00000000T".into(),
                signer_id: Some("00000000T".into()),
                issuer: "AC FNMT Usuarios".into(),
                cert_not_after: Some(t("2028-05-11T10:00:00Z")),
                cert_status: tr("Correcto. No se ha comprobado la revocación del certificado.").into(),
                profile: Some("PAdES-B-B".into()),
                algorithm: Some("SHA256withRSA".into()),
                signing_time: Some(t("2026-10-14T09:31:00Z")),
                validity: ok(),
                policy: Some(PolicyInfo {
                    name: Some("AGE v1.9".into()),
                    identifier: "2.16.724.1.3.1.1.2.1.9".into(),
                    ..Default::default()
                }),
                metadata: vec![
                    ("Razón".into(), "Conformidad con la resolución".into()),
                    ("Lugar".into(), "Madrid".into()),
                ],
                ..Default::default()
            },
            SignatureDetail {
                signer: "PRUEBA MARIA - 99999999R".into(),
                issuer: "AC DNIE 004".into(),
                cert_not_after: Some(t("2029-01-01T00:00:00Z")),
                cert_status: tr("Correcto. No se ha comprobado la revocación del certificado.").into(),
                profile: Some("PAdES-T".into()),
                algorithm: Some("SHA512withECDSA".into()),
                signing_time: Some(t("2026-10-15T16:02:00Z")),
                timestamps: vec![("TSA de la AGE".into(), t("2026-10-15T16:02:03Z"))],
                validity: ok(),
                ..Default::default()
            },
            SignatureDetail {
                depth: 1,
                signer: "CERTIFICADO CADUCADO".into(),
                issuer: "AC Raiz de Pruebas".into(),
                cert_status: tr("Certificado caducado.").into(),
                signing_time: Some(t("2026-10-16T08:00:00Z")),
                validity: vec![SignValidity::ko(ValidityError::CertificateExpired)],
                ..Default::default()
            },
        ];
        if demo.contains("ko") {
            report.overall = Some(SignValidity::new(Validity::Ko, Some(ValidityError::CertificateExpired)));
        }
        app.verify.report = Some(report);
        app.verify.expanded = Some(0);
    }
    if demo.contains("picker") {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki");
        let mut certs = Vec::new();
        for name in ["firmante-rsa", "firmante-ec", "autenticacion", "caducado"] {
            if let Ok(pem) = std::fs::read(dir.join(format!("{name}.crt")))
                && let Some(der) = afirma_core::cert::decode_certificate(&pem)
                && let Some(c) = CertItem::from_der(name, der)
            {
                certs.push(c);
            }
        }
        app.picker.stores = vec![
            StoreOption {
                id: "system".into(),
                label: tr("Almacén del sistema").into(),
                icon: icons::VAULT,
            },
            StoreOption {
                id: "mozilla".into(),
                label: "Firefox".into(),
                icon: icons::BROWSER,
            },
            StoreOption {
                id: "dnie".into(),
                label: tr("DNI electrónico").into(),
                icon: icons::IDENTIFICATION_BADGE,
            },
            StoreOption {
                id: "pkcs12".into(),
                label: tr("Fichero PKCS#12 (.p12, .pfx)…").into(),
                icon: icons::FILE_LOCK,
            },
        ];
        app.picker.allow_change_store = true;
        app.picker.show_remember = demo.contains("web");
        if demo.contains("web") {
            app.picker.subtitle = Some("sede.ejemplo.gob.es solicita tu firma para 1 documento".into());
        }
        app.picker.open_with(tr("Almacén del sistema"), certs);
        if demo.contains("details") {
            app.picker.expanded = Some(0);
        }
    }
    if demo.contains("certs") {
        app.page = Page::Certificates;
        let mk =
            |id: &str, label: &str, desc: &str, icon: &'static str, certs: Option<Vec<CertItem>>, removable: bool| {
                StoreEntry {
                    id: id.into(),
                    label: label.into(),
                    description: desc.into(),
                    icon,
                    available: true,
                    certs,
                    error: None,
                    loading: false,
                    removable,
                }
            };
        app.certificates.stores = vec![
            mk(
                "system",
                tr("Sistema"),
                tr("Almacén de certificados del sistema operativo"),
                icons::VAULT,
                Some(test_certs()),
                false,
            ),
            mk(
                "mozilla",
                "Firefox",
                tr("Perfil predeterminado de Mozilla Firefox"),
                icons::BROWSER,
                None,
                false,
            ),
            mk(
                "dnie",
                tr("DNIe y tarjetas"),
                tr("DNI electrónico y tarjetas criptográficas"),
                icons::IDENTIFICATION_BADGE,
                Some(vec![]),
                false,
            ),
            mk(
                "p12:/home/usuario/certificado.p12",
                "certificado.p12",
                "/home/usuario/certificado.p12",
                icons::FILE_LOCK,
                None,
                true,
            ),
        ];
        app.certificates.default_store = Some("system".into());
        app.certificates.expanded = Some(1);
    }
    if demo.contains("tools") {
        app.page = Page::Tools;
        if demo.contains("doctor") {
            app.tools.open = Some(Tool::Doctor);
            let row = |ok: Option<bool>, t: &str, d: &str| CheckRow {
                ok,
                title: t.into(),
                detail: d.into(),
            };
            app.tools.doctor = vec![
                row(
                    Some(true),
                    "Protocolo afirma:// registrado",
                    "Los navegadores abrirán AutoFirma al firmar en una sede electrónica.",
                ),
                row(
                    Some(true),
                    "Certificado local de confianza instalado",
                    "Almacén del sistema y perfiles de Firefox (2 de 2).",
                ),
                row(
                    Some(false),
                    "Chrome pide confirmación al abrir AutoFirma",
                    "Aplica la directiva AutoLaunchProtocolsFromOrigins para evitar el aviso.",
                ),
                row(
                    Some(true),
                    "Puertos locales disponibles",
                    "63117, 63118 y 63119 libres.",
                ),
                row(
                    None,
                    "Lector de tarjetas",
                    "No se ha detectado ningún lector conectado.",
                ),
            ];
        }
        if demo.contains("hash") {
            app.tools.open = Some(Tool::HashFile);
            app.tools.input = Some("/home/usuario/Documentos/contrato.pdf".into());
        }
    }
    if demo.contains("visible") {
        app.visible_sig.stamp_enabled = demo.contains("stamp");
        app.visible_sig.open_with(
            "Solicitud de subvención 2026.pdf",
            std::sync::Arc::new(super::visible_sig::DemoPages),
        );
        app.visible_sig.set_rect_pdf(0, 330.0, 60.0, 545.0, 140.0);
        if demo.contains("stamp") {
            let logo = include_bytes!("../../../../packaging/icons/autofirma-128.png").to_vec();
            let _ = app.visible_sig.set_stamp_demo(ctx, logo);
        }
    }
    if demo.contains("settings") {
        app.page = Page::Settings;
        app.settings.section = if demo.contains("pdf") {
            super::pages::settings::Section::Pdf
        } else if demo.contains("net") {
            super::pages::settings::Section::Network
        } else {
            super::pages::settings::Section::Signature
        };
        app.settings
            .pending
            .insert("confirmToSign".into(), Some("false".into()));
    }
    if demo.contains("web") {
        use super::request_view::{RequestInfo, RequestOp, RequestStage, RequestView};
        let mut r = RequestView::new(RequestInfo {
            origin: Some("sede.ejemplo.gob.es".into()),
            op: if demo.contains("batch") {
                RequestOp::Batch
            } else {
                RequestOp::Sign
            },
            format: Some("PAdES".into()),
            file_name: Some("Solicitud de subvención 2026.pdf".into()),
            data_len: Some(284_312),
            doc_kind: Some("PDF".into()),
            batch_count: demo.contains("batch").then_some(12),
        });
        r.picker.stores = app.picker.stores.clone();
        r.picker.open_with(
            tr("Almacén del sistema"),
            test_certs().into_iter().filter(|c| c.alias != "caducado").collect(),
        );
        if demo.contains("done") {
            r.stage = RequestStage::Done(tr("Documento firmado").into());
        }
        app.request = Some(r);
        app.picker.open = false;
    }
}
