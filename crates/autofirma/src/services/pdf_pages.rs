//! Origen de páginas PDF para el editor de firma visible.

use std::sync::Mutex;

use afirma_pdf::render::RenderDocument;
use eframe::egui::{Color32, ColorImage};

use crate::ui::visible_sig::PageSource;

/// Páginas de un PDF renderizadas con el motor de `afirma-pdf`.
pub struct PdfPages {
    doc: Mutex<RenderDocument>,
    sizes: Vec<(f32, f32)>,
}

impl PdfPages {
    pub fn open(data: &[u8], password: Option<&str>) -> Result<PdfPages, String> {
        let doc = RenderDocument::open(data, password).map_err(|e| e.to_string())?;
        let sizes = (0..doc.page_count()).map(|i| doc.page_size(i).unwrap_or((595.0, 842.0))).collect();
        Ok(PdfPages { doc: Mutex::new(doc), sizes })
    }
}

impl PageSource for PdfPages {
    fn page_count(&self) -> usize {
        self.sizes.len()
    }

    fn page_size(&self, index: usize) -> (f32, f32) {
        self.sizes.get(index).copied().unwrap_or((595.0, 842.0))
    }

    fn render(&self, index: usize, scale: f32) -> Option<ColorImage> {
        let doc = self.doc.lock().ok()?;
        let img = doc.render_page(index, scale).ok()?;
        let pixels = img
            .data
            .chunks_exact(4)
            .map(|c| Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3]))
            .collect();
        Some(ColorImage::new([img.width as usize, img.height as usize], pixels))
    }
}
