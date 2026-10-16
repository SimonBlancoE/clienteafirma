//! Página "Ayuda": guía rápida, preguntas frecuentes y "Acerca de".

use eframe::egui::{self, CollapsingHeader, FontId, RichText, Ui};

use crate::i18n::{tr, trf};
use crate::ui::icons;
use crate::ui::theme::{Palette, semibold};
use crate::ui::widgets::{self, ButtonKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelpAction {
    OpenUrl(String),
    OpenLogs,
    CopyDiagnostics,
}

/// Preguntas frecuentes (pregunta, respuesta), traducidas.
fn faq() -> [(&'static str, &'static str); 7] {
    [
        (
            tr("¿Cómo firmo un documento?"),
            tr(
                "En «Firmar», arrastra el documento a la ventana o pulsa «Seleccionar archivos». AutoFirma elige el formato de firma \
             adecuado (PAdES para PDF, XAdES para XML, FacturaE para facturas y CAdES para el resto). Pulsa «Firmar», elige tu \
             certificado y la firma se guardará junto al documento original.",
            ),
        ),
        (
            tr("¿Cómo firmo en una sede electrónica?"),
            tr(
                "La sede abre AutoFirma automáticamente cuando pulsas su botón de firma. Verás una ventana con el nombre de la sede y el \
             documento; elige tu certificado y pulsa «Firmar». Si el navegador no abre AutoFirma, ve a «Herramientas → Diagnóstico \
             del sistema» y pulsa «Reparar todo».",
            ),
        ),
        (
            tr("No aparece mi DNIe o mi tarjeta"),
            tr(
                "Comprueba que el lector está conectado y la tarjeta insertada, y pulsa «Recargar» en la lista de certificados. AutoFirma \
             usa los controladores PKCS#11 de la tarjeta (OpenSC o los oficiales del DNIe y la FNMT). Si tu tarjeta usa otro \
             controlador, añádelo en «Mis certificados → Añadir tarjeta».",
            ),
        ),
        (
            tr("¿Qué diferencia hay entre firmar, cofirmar y contrafirmar?"),
            tr(
                "Firmar crea una firma nueva. Cofirmar añade tu firma, al mismo nivel, a un documento ya firmado (por ejemplo, un \
             contrato entre dos partes). Contrafirmar es firmar sobre una firma existente para refrendarla (por ejemplo, un visto \
             bueno).",
            ),
        ),
        (
            tr("¿Qué es la firma visible en PDF?"),
            tr(
                "Es un recuadro con tu nombre y la fecha que se ve al abrir el PDF. Puedes colocarlo con el ratón, elegir en qué páginas \
             aparece, cambiar el texto y añadir tu rúbrica. La validez de la firma no depende de que sea visible.",
            ),
        ),
        (
            tr("¿Cómo compruebo que una firma es válida?"),
            tr(
                "En «Verificar firmas», arrastra el fichero firmado. Verás si la firma es válida, quién firmó y cuándo, y podrás extraer \
             el documento firmado. AutoFirma comprueba la integridad y la vigencia del certificado; no consulta la revocación \
             (puedes hacerlo en «Herramientas → Validar un certificado» o en VALIDe).",
            ),
        ),
        (
            tr("Uso en empresas y administraciones"),
            tr(
                "AutoFirma puede instalarse de forma silenciosa y configurarse mediante directivas (GPO, Intune, MDM): almacén por \
             defecto, políticas de firma, proxy y bloqueo de opciones. Consulta la guía de despliegue (docs/DEPLOYMENT.md).",
            ),
        ),
    ]
}

pub fn ui(ui: &mut Ui, p: &Palette) -> Vec<HelpAction> {
    let mut actions = Vec::new();
    widgets::page_header(
        ui,
        p,
        tr("Ayuda"),
        Some(tr("Guía rápida y respuestas a las dudas más habituales.")),
    );
    widgets::card(ui, p, |ui| {
        for (i, (q, a)) in faq().into_iter().enumerate() {
            CollapsingHeader::new(RichText::new(q).font(FontId::new(14.5, semibold())))
                .id_salt(("faq", i))
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(a).size(13.5).color(p.text_muted)).wrap());
                    ui.add_space(4.0);
                });
        }
    });
    ui.add_space(16.0);
    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            widgets::status_circle(ui, icons::PEN_NIB, 48.0, p.on_primary, p.primary);
            ui.vertical(|ui| {
                ui.label(RichText::new("AutoFirma").font(FontId::new(18.0, semibold())));
                ui.label(
                    RichText::new(trf(
                        "Versión {0} · reimplementación en Rust",
                        &[&env!("CARGO_PKG_VERSION")],
                    ))
                    .size(13.0)
                    .color(p.text_muted),
                );
            });
        });
        ui.add_space(8.0);
        ui.add(
            egui::Label::new(
                RichText::new(tr(
                    "Fork en Rust de AutoFirma (Cliente @firma, Gobierno de España), compatible con sus formatos de firma, \
                     su protocolo afirma:// y sus preferencias. Software libre con licencia GPL 2.0 o posterior y EUPL 1.1, \
                     como el original. Tipografía Inter (OFL) e iconos Phosphor (MIT).",
                ))
                .size(13.0)
                .color(p.text_muted),
            )
            .wrap(),
        );
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            if widgets::button(
                ui,
                p,
                ButtonKind::Secondary,
                Some(icons::FOLDER_OPEN),
                tr("Abrir registros"),
                true,
            )
            .clicked()
            {
                actions.push(HelpAction::OpenLogs);
            }
            if widgets::button(
                ui,
                p,
                ButtonKind::Secondary,
                Some(icons::COPY),
                tr("Copiar información del sistema"),
                true,
            )
            .clicked()
            {
                actions.push(HelpAction::CopyDiagnostics);
            }
            if widgets::button(
                ui,
                p,
                ButtonKind::Ghost,
                Some(icons::ARROW_SQUARE_OUT),
                tr("Proyecto original"),
                true,
            )
            .clicked()
            {
                actions.push(HelpAction::OpenUrl(
                    "https://github.com/ctt-gob-es/clienteafirma".into(),
                ));
            }
        });
    });
    actions
}
