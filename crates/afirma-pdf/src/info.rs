//! Información del PDF para la interfaz gráfica: páginas (tamaños y giro),
//! campos de firma vacíos y firmas existentes con su posición.

use afirma_core::{AfirmaError, ExtraParams};

use crate::pades::prepare::open_pdf;
use crate::pdf::doc::{FieldItem, PdfDoc, Rect};

/// Página del documento.
#[derive(Debug, Clone, PartialEq)]
pub struct PageInfo {
    /// Número de página (1..N).
    pub number: usize,
    pub media_box: Rect,
    pub crop_box: Rect,
    /// Rotación (0, 90, 180, 270).
    pub rotation: i32,
    /// Tamaño tal y como se muestra (`getPageSizeWithRotation`), en puntos.
    pub width: f64,
    pub height: f64,
}

impl PageInfo {
    /// Tamaño redondeado a enteros (`SignPdfUiUtil.getPageSizes`).
    pub fn rounded_size(&self) -> (i64, i64) {
        (self.width.round() as i64, self.height.round() as i64)
    }
}

/// Campo de firma (`SignatureField`).
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureFieldInfo {
    pub name: String,
    /// Página (1..N).
    pub page: usize,
    /// Rectángulo en coordenadas de la página mostrada, redondeado.
    pub llx: i64,
    pub lly: i64,
    pub urx: i64,
    pub ury: i64,
}

/// Información general del PDF.
#[derive(Debug, Clone, PartialEq)]
pub struct PdfInfo {
    pub pages: Vec<PageInfo>,
    /// Campos de firma vacíos (`getPdfEmptySignatureFields`).
    pub empty_signature_fields: Vec<SignatureFieldInfo>,
    /// Campos con firma.
    pub signature_fields: Vec<SignatureFieldInfo>,
    pub encrypted: bool,
    /// Nivel de certificación DocMDP (0 = no certificado).
    pub certification_level: i64,
    /// Versión de la cabecera.
    pub version: String,
}

/// Posición de un campo en la página mostrada (`AcroFields.getFieldPositions`).
fn field_position(doc: &PdfDoc, f: &FieldItem) -> Option<SignatureFieldInfo> {
    let r = doc.dict_get(&f.widget, b"Rect").and_then(Rect::from_object)?;
    let page_id = *doc.pages().get(f.page.checked_sub(1)?)?;
    let mb = doc.media_box(page_id);
    let r = match doc.rotation(page_id) {
        270 => Rect::new(mb.ury - r.lly, r.llx, mb.ury - r.ury, r.urx),
        180 => Rect::new(mb.urx - r.llx, mb.ury - r.lly, mb.urx - r.urx, mb.ury - r.ury),
        90 => Rect::new(r.lly, mb.urx - r.llx, r.ury, mb.urx - r.urx),
        _ => r,
    };
    Some(SignatureFieldInfo {
        name: f.name.clone(),
        page: f.page,
        llx: r.llx.round() as i64,
        lly: r.lly.round() as i64,
        urx: r.urx.round() as i64,
        ury: r.ury.round() as i64,
    })
}

impl PdfInfo {
    /// Analiza un PDF (con contraseña si está cifrado).
    pub fn open(data: &[u8], password: Option<&str>) -> Result<PdfInfo, AfirmaError> {
        let mut xp = ExtraParams::new();
        if let Some(p) = password {
            xp.set("ownerPassword", p);
        }
        let doc = open_pdf(data, &xp)?;
        Ok(Self::from_doc(&doc))
    }

    pub(crate) fn from_doc(doc: &PdfDoc) -> PdfInfo {
        let pages = doc
            .pages()
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let s = doc.page_size_with_rotation(p);
                PageInfo {
                    number: i + 1,
                    media_box: doc.media_box(p),
                    crop_box: doc.crop_box(p),
                    rotation: doc.rotation(p),
                    width: s.width(),
                    height: s.height(),
                }
            })
            .collect();
        let empty_signature_fields = doc
            .blank_signature_fields()
            .iter()
            .filter_map(|f| field_position(doc, f))
            .collect();
        let (sigs, _) = doc.signatures();
        let signature_fields = sigs.iter().filter_map(|s| field_position(doc, &s.field)).collect();
        PdfInfo {
            pages,
            empty_signature_fields,
            signature_fields,
            encrypted: doc.encrypted,
            certification_level: doc.certification_level(),
            version: doc.header_version.clone(),
        }
    }
}

/// Campos de firma vacíos (`PdfUtil.getPdfEmptySignatureFields`): los errores
/// (incluido un PDF cifrado) devuelven una lista vacía.
pub fn empty_signature_fields(data: &[u8]) -> Vec<SignatureFieldInfo> {
    PdfInfo::open(data, None)
        .map(|i| i.empty_signature_fields)
        .unwrap_or_default()
}

/// Comprueba el tamaño mínimo del área de firma visible elegida en la
/// interfaz (`checkSignatureDimensions`): ancho ≥ 30, alto ≥ 45 y área ≥ 1350.
pub fn check_signature_dimensions(llx: i64, lly: i64, urx: i64, ury: i64) -> bool {
    let (dx, dy) = ((urx - llx).abs(), (ury - lly).abs());
    !(dx < 30 || dy < 45 || dx * dy < 1350)
}

/// Valida el texto de selección de páginas de la interfaz
/// (`PdfUtil.checkPagesRangeInputFormat`).
pub fn check_pages_range_input(text: &str) -> bool {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit() || c == '-' || c == ',') {
        return false;
    }
    if text.ends_with(',') || text.contains("---") || text.contains(",,") {
        return false;
    }
    text.split(',')
        .all(|e| !(e.ends_with('-') || e.starts_with("--") || e == "-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_checks() {
        assert!(check_signature_dimensions(100, 100, 300, 180));
        assert!(!check_signature_dimensions(100, 100, 120, 180));
        assert!(!check_signature_dimensions(0, 0, 30, 44));
        assert!(check_pages_range_input("1-3,-1"));
        assert!(!check_pages_range_input("1,,2"));
        assert!(!check_pages_range_input("1-"));
        assert!(!check_pages_range_input("a"));
        assert!(!check_pages_range_input(""));
    }
}

/// Escalado de la imagen de una página en el panel de selección de área
/// (`SignPdfUiPanel.createPageLabel`): contenedor de 466×400 píxeles.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageLabel {
    /// Tamaño mostrado de la imagen.
    pub width: i64,
    pub height: i64,
    /// Escala mostrada al usuario (`Página %0 de %1 (escala: %2%)`).
    pub scale_percent: i64,
    /// Puntos PDF por píxel mostrado (`pdfRatio`).
    pub pdf_ratio: f64,
}

impl PageLabel {
    /// `image_*`: imagen renderizada (75 ppp en AutoFirma); `page_*`: tamaño
    /// de la página mostrada en puntos.
    pub fn new(image_w: i64, image_h: i64, page_w: f64, page_h: f64) -> PageLabel {
        let (mut w, mut h) = (image_w.max(1), image_h.max(1));
        while w > 466 || h > 400 {
            w = (w as f64 * 0.9).round() as i64;
            h = (h as f64 * 0.9).round() as i64;
        }
        let aspect = w as f64 / image_w.max(1) as f64;
        let width = (image_w as f64 * aspect).round() as i64;
        let height = (image_h as f64 * aspect).round() as i64;
        let pdf_ratio = if image_w <= image_h && page_w <= page_h {
            page_h / height.max(1) as f64
        } else {
            page_w / width.max(1) as f64
        };
        PageLabel {
            width,
            height,
            scale_percent: (100.0 * aspect).round() as i64,
            pdf_ratio,
        }
    }

    /// Convierte una selección en píxeles de la imagen mostrada (origen arriba
    /// a la izquierda) en el rectángulo PDF (`llx, lly, urx, ury`, enteros)
    /// de la página mostrada de tamaño `page_w`×`page_h` puntos. Usa el
    /// tamaño de la página actual (Java usa por error el de la anterior).
    pub fn to_pdf_area(
        &self,
        x: i64,
        y: i64,
        w: i64,
        h: i64,
        page_w: f64,
        page_h: f64,
    ) -> Option<(i64, i64, i64, i64)> {
        if w <= 0 || h <= 0 {
            return None;
        }
        let s = self.pdf_ratio;
        let (x, y, w, h) = (x as f64 * s, y as f64 * s, w as f64 * s, h as f64 * s);
        if x > page_w || y > page_h {
            return None;
        }
        let w = w.min(page_w - x);
        let h = h.min(page_h - y);
        Some((
            x.round() as i64,
            (page_h - y - h).round() as i64,
            (x + w).round() as i64,
            (page_h - y).round() as i64,
        ))
    }
}

/// Selección de páginas del panel de área.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageChoice {
    /// "Página actual" (1..N; N+1 = página en blanco añadida).
    Current(usize),
    /// "Todas las páginas".
    All,
    /// "Selección de páginas" (texto validado con [`check_pages_range_input`]).
    Range(String),
}

/// Parámetros que produce el panel de área (`signaturePages` y las cuatro
/// coordenadas). Si la página actual es la página en blanco añadida
/// (`pages + 1`) se pide `append` (Java añade `,append` al final, que el
/// firmante ignora, ver desviaciones).
pub fn visible_area_params(choice: &PageChoice, pages: usize, area: (i64, i64, i64, i64)) -> ExtraParams {
    let mut xp = ExtraParams::new();
    let value = match choice {
        PageChoice::All => "all".to_string(),
        PageChoice::Range(r) => r.clone(),
        PageChoice::Current(p) if *p > pages => "append".to_string(),
        PageChoice::Current(p) => p.to_string(),
    };
    xp.set("signaturePages", value);
    xp.set("signaturePositionOnPageLowerLeftX", area.0.to_string());
    xp.set("signaturePositionOnPageLowerLeftY", area.1.to_string());
    xp.set("signaturePositionOnPageUpperRightX", area.2.to_string());
    xp.set("signaturePositionOnPageUpperRightY", area.3.to_string());
    xp
}

#[cfg(test)]
mod ui_tests {
    use super::*;

    #[test]
    fn page_label_scaling() {
        // A4 a 75 ppp: 620x877 píxeles.
        let l = PageLabel::new(620, 877, 595.0, 842.0);
        assert!(l.width <= 466 && l.height <= 400);
        assert_eq!(l.scale_percent, (100.0 * l.width as f64 / 620.0).round() as i64);
        let (llx, lly, urx, ury) = l.to_pdf_area(0, 0, l.width, l.height, 595.0, 842.0).unwrap();
        assert_eq!((llx, lly), (0, 0));
        assert!((urx - 595).abs() <= 2 && (ury - 842).abs() <= 2);
        assert!(l.to_pdf_area(10, 10, 0, 5, 595.0, 842.0).is_none());
        let xp = visible_area_params(&PageChoice::Current(3), 2, (1, 2, 3, 4));
        assert_eq!(xp.get("signaturePages"), Some("append"));
        assert_eq!(
            visible_area_params(&PageChoice::All, 2, (1, 2, 3, 4)).get("signaturePositionOnPageUpperRightY"),
            Some("4")
        );
    }
}
