//! Firma visible en PDF (`PdfSelectPreviewActivity`, `docs/spec/09-android.md` §3.5): el
//! documento de la vista previa (páginas dibujadas con el rasterizador de `afirma-pdf`, el
//! mismo que usa el editor de firma visible del escritorio) y la conversión del área elegida
//! en la pantalla a coordenadas PDF con las comprobaciones de tamaño mínimo del original.

use std::sync::{Mutex, PoisonError};

use afirma_core::error::codes;
use afirma_pdf::info::PdfInfo;
use afirma_pdf::render::RenderDocument;

use crate::local_sign::VisibleArea;

/// Ancho mínimo del área en puntos PDF (`LOWER_LIMIT_X`).
pub const MIN_WIDTH: i64 = 30;
/// Alto mínimo del área en puntos PDF (`LOWER_LIMIT_Y`).
pub const MIN_HEIGHT: i64 = 45;
/// Superficie mínima del área en puntos² (`AREA_LIMIT`).
pub const MIN_AREA: i64 = 1350;

/// Documento abierto para la vista previa.
pub struct PreviewDocument {
    render: Mutex<RenderDocument>,
    /// Tamaño de cada página tal como se muestra (con el giro aplicado), en puntos.
    pages: Vec<(f32, f32)>,
    /// Contraseña con la que se ha abierto (si estaba protegido).
    password: Option<String>,
}

/// Por qué no se puede abrir el PDF de la vista previa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewFailure {
    /// Protegido con contraseña (`PdfPasswordException` de Pdfium).
    NeedsPassword,
    /// La contraseña no es correcta.
    BadPassword,
    /// No se puede leer (resultado 106 del original, `ERROR_REQUEST_VISIBLE_SIGN`).
    Invalid(String),
}

/// Página dibujada: RGBA sin premultiplicar, filas de arriba abajo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageImage {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl PreviewDocument {
    /// Abre un PDF (con su contraseña, si la tiene). Bloquea: se usa desde un hilo de trabajo.
    pub fn open(data: &[u8], password: Option<&str>) -> Result<PreviewDocument, PreviewFailure> {
        let password = password.filter(|p| !p.is_empty());
        let info = PdfInfo::open(data, password).map_err(|e| match e.code {
            Some(c) if c == codes::SIGNING_PDF_WITHOUT_PASSWORD => PreviewFailure::NeedsPassword,
            Some(c) if c == codes::SIGNING_PDF_WITH_BAD_PASSWORD => PreviewFailure::BadPassword,
            _ => PreviewFailure::Invalid(e.to_string()),
        })?;
        if info.pages.is_empty() {
            return Err(PreviewFailure::Invalid("el PDF no tiene páginas".into()));
        }
        let render = RenderDocument::open(data, password).map_err(|e| PreviewFailure::Invalid(e.to_string()))?;
        Ok(PreviewDocument {
            pages: info.pages.iter().map(|p| (p.width as f32, p.height as f32)).collect(),
            render: Mutex::new(render),
            password: password.map(str::to_string),
        })
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Tamaño de una página (desde 0) en puntos, tal como se muestra.
    pub fn page_size(&self, page: usize) -> (f32, f32) {
        self.pages.get(page).copied().unwrap_or((595.0, 842.0))
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Dibuja una página (desde 0) con `width` píxeles de ancho. Bloquea.
    pub fn render(&self, page: usize, width: u32) -> Option<PageImage> {
        let (w, _) = self.page_size(page);
        let scale = (width.max(16) as f32 / w.max(1.0)).clamp(0.05, 8.0);
        let doc = self.render.lock().unwrap_or_else(PoisonError::into_inner);
        let image = doc.render_page(page, scale).ok()?;
        Some(PageImage {
            width: image.width,
            height: image.height,
            rgba: image.data,
        })
    }
}

/// Área elegida en la vista de la página, en las unidades de la vista (puntos de egui) desde
/// la esquina superior izquierda de la página. Inicio ≤ fin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewSelection {
    pub start_x: f32,
    pub start_y: f32,
    pub end_x: f32,
    pub end_y: f32,
}

impl ViewSelection {
    /// Rectángulo normalizado entre dos esquinas cualesquiera (`createClampedSelection`).
    pub fn between(a: (f32, f32), b: (f32, f32)) -> ViewSelection {
        ViewSelection {
            start_x: a.0.min(b.0),
            start_y: a.1.min(b.1),
            end_x: a.0.max(b.0),
            end_y: a.1.max(b.1),
        }
    }
}

/// Resultado de comprobar el área al pulsar «Continuar».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaCheck {
    /// Por debajo de 30×45 puntos o de 1350 puntos²: «Firma visible demasiado pequeña».
    TooSmall,
    Ok(VisibleArea),
}

/// Convierte el área elegida a puntos PDF con la fórmula del original (§3.5.3, §10 n.º 28,
/// «replicar»), con zoom 1: el área se recorta a la página, se escala del tamaño de la
/// página en la vista (`view`) al tamaño de la página PDF (`pdf`) y se pasa a origen abajo a
/// la izquierda. `page` es el número de página (desde 1).
///
/// El tamaño de la página PDF es el que se muestra (con el giro aplicado), como en el editor
/// de firma visible del escritorio; el original usaba la caja de medios sin girar y en las
/// páginas giradas el área quedaba fuera de sitio.
pub fn check_area(selection: ViewSelection, view: (f32, f32), pdf: (f32, f32), page: usize) -> AreaCheck {
    let (page_width, page_height) = view;
    let (pdf_width, pdf_height) = pdf;
    let ViewSelection {
        start_x,
        start_y,
        end_x,
        end_y,
    } = selection;
    let (width, height) = (end_x - start_x, end_y - start_y);
    // Recortes truncados a entero, como el `(int)` de Java.
    let area_height = (if height + start_y > page_height {
        page_height - start_y
    } else {
        height
    }) as i64 as f32;
    let area_width = (if width + start_x > page_width {
        page_width - start_x
    } else {
        width
    }) as i64 as f32;
    let llx = start_x * pdf_width / page_width;
    let urx = (start_x + area_width) * pdf_width / page_width;
    let lly = (page_height - area_height - start_y) * pdf_height / page_height;
    let ury = (page_height - start_y) * pdf_height / page_height;
    let dim_x = ((urx - llx) as i64).abs();
    let dim_y = ((ury - lly) as i64).abs();
    if dim_x < MIN_WIDTH || dim_y < MIN_HEIGHT || dim_x * dim_y < MIN_AREA {
        return AreaCheck::TooSmall;
    }
    // `Math.round(x * zoom)` con zoom 1.
    let round = |v: f32| v.round() as i64;
    AreaCheck::Ok(VisibleArea {
        page,
        llx: round(llx),
        lly: round(lly),
        urx: round(urx),
        ury: round(ury),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(path: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../testdata/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn area_en_coordenadas_pdf() {
        // Página A4 mostrada a 300×424.4 puntos de la vista (escala ~0,504).
        let view = (300.0, 300.0 * 842.0 / 595.0);
        let pdf = (595.0, 842.0);
        let sel = ViewSelection::between((150.0, 300.0), (30.0, 250.0));
        assert_eq!(sel.start_x, 30.0);
        match check_area(sel, view, pdf, 3) {
            AreaCheck::Ok(area) => {
                assert_eq!(area.page, 3);
                assert_eq!(area.llx, 60);
                assert_eq!(area.urx, 298);
                // Origen abajo: lly = (424.4 - 50 - 250) * 842 / 424.4.
                assert_eq!(area.lly, 247);
                assert_eq!(area.ury, 346);
            }
            other => panic!("área no válida: {other:?}"),
        }
        // El área se recorta a la página.
        let sel = ViewSelection::between((200.0, 380.0), (350.0, 500.0));
        match check_area(sel, view, pdf, 1) {
            AreaCheck::Ok(area) => {
                assert_eq!(area.urx, 595, "recortada al borde derecho");
                assert!(area.lly <= 1, "recortada al borde inferior: {area:?}");
            }
            other => panic!("área no válida: {other:?}"),
        }
    }

    #[test]
    fn minimos_de_30_por_45_y_1350() {
        let view = (595.0, 842.0);
        let pdf = (595.0, 842.0);
        let area =
            |w: f32, h: f32| check_area(ViewSelection::between((10.0, 10.0), (10.0 + w, 10.0 + h)), view, pdf, 1);
        assert_eq!(area(29.0, 100.0), AreaCheck::TooSmall);
        assert_eq!(area(100.0, 44.0), AreaCheck::TooSmall);
        assert!(matches!(area(30.0, 45.0), AreaCheck::Ok(_)));
        assert!(matches!(area(30.0, 46.0), AreaCheck::Ok(_)));
        // 30×45 = 1350 justo; el límite de superficie solo afecta si los lados lo cumplen.
        assert!(matches!(area(31.0, 45.0), AreaCheck::Ok(_)));
    }

    #[test]
    fn vista_previa_de_un_pdf() {
        let pdf = testdata("pades/rotated_pages.pdf");
        let doc = PreviewDocument::open(&pdf, None).unwrap();
        assert!(doc.page_count() >= 1);
        let (w, h) = doc.page_size(0);
        assert!(w > 0.0 && h > 0.0);
        let image = doc.render(0, 200).unwrap();
        assert_eq!(image.width, 200);
        assert_eq!(image.rgba.len(), (image.width * image.height * 4) as usize);
        assert!(doc.render(999, 200).is_none());
        assert_eq!(doc.password(), None);
    }

    #[test]
    fn pdf_protegido_y_no_pdf() {
        let pdf = testdata("pades/encrypted_aes128_user.pdf");
        assert_eq!(
            PreviewDocument::open(&pdf, None).err(),
            Some(PreviewFailure::NeedsPassword)
        );
        assert_eq!(
            PreviewDocument::open(&pdf, Some("mala")).err(),
            Some(PreviewFailure::BadPassword)
        );
        let doc = PreviewDocument::open(&pdf, Some("user")).unwrap();
        assert_eq!(doc.password(), Some("user"));
        assert!(doc.render(0, 100).is_some());
        assert!(matches!(
            PreviewDocument::open(b"hola", None),
            Err(PreviewFailure::Invalid(_))
        ));
    }
}
