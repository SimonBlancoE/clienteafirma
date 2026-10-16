//! Renderizado de páginas con `hayro` (rasterizador PDF en Rust puro): vista
//! previa para colocar la firma visible y comprobación de ataques de sombra.

use afirma_core::AfirmaError;
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{RenderCache, RenderSettings, render};

/// Imagen RGBA (no premultiplicada), filas de arriba abajo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbaImage {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

impl RgbaImage {
    /// Convierte a escala de grises (un byte por píxel, luminancia BT.601).
    pub fn to_gray(&self) -> Vec<u8> {
        self.data
            .chunks_exact(4)
            .map(|p| {
                ((u32::from(p[0]) * 299 + u32::from(p[1]) * 587 + u32::from(p[2]) * 114 + 500)
                    / 1000) as u8
            })
            .collect()
    }

    /// Codifica en PNG.
    pub fn to_png(&self) -> Result<Vec<u8>, AfirmaError> {
        let img = image::RgbaImage::from_raw(self.width, self.height, self.data.clone())
            .ok_or_else(|| AfirmaError::msg("Imagen no valida"))?;
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png)
            .map_err(|e| AfirmaError::msg(e.to_string()))?;
        Ok(out.into_inner())
    }

    pub fn save_png(&self, path: impl AsRef<std::path::Path>) -> Result<(), AfirmaError> {
        std::fs::write(path, self.to_png()?).map_err(|e| AfirmaError::msg(e.to_string()))
    }
}

/// Documento abierto para renderizar.
pub struct RenderDocument {
    pdf: Pdf,
}

impl RenderDocument {
    /// Abre un PDF (con contraseña si está cifrado).
    pub fn open(data: &[u8], password: Option<&str>) -> Result<RenderDocument, AfirmaError> {
        let pdf = Pdf::new_with_password(data.to_vec(), password.unwrap_or("")).map_err(|e| {
            AfirmaError::msg(format!(
                "No se ha podido abrir el PDF para renderizarlo: {e:?}"
            ))
        })?;
        Ok(RenderDocument { pdf })
    }

    pub fn page_count(&self) -> usize {
        self.pdf.pages().len()
    }

    /// Tamaño de la página (0..N-1) tal y como se muestra, en puntos.
    pub fn page_size(&self, index: usize) -> Option<(f32, f32)> {
        self.pdf.pages().get(index).map(|p| p.render_dimensions())
    }

    /// Renderiza la página `index` (0..N-1) con la escala indicada (1.0 =
    /// 72 ppp) sobre fondo blanco.
    pub fn render_page(&self, index: usize, scale: f32) -> Result<RgbaImage, AfirmaError> {
        let page = self
            .pdf
            .pages()
            .get(index)
            .ok_or_else(|| AfirmaError::msg(format!("La pagina {} no existe", index + 1)))?;
        let cache = RenderCache::new();
        let settings = hayro::hayro_interpret::InterpreterSettings::default();
        let pixmap = render(
            page,
            &cache,
            &settings,
            &RenderSettings::default(),
            &hayro::PixmapSettings {
                x_scale: scale,
                y_scale: scale,
                bg_color: WHITE,
            },
        );
        let (w, h) = (u32::from(pixmap.width()), u32::from(pixmap.height()));
        let data = pixmap.take_rgba8(hayro::vello_cpu::peniko::ImageAlphaType::Alpha);
        Ok(RgbaImage {
            width: w,
            height: h,
            data,
        })
    }

    /// Renderiza a una resolución en puntos por pulgada.
    pub fn render_page_dpi(&self, index: usize, dpi: f32) -> Result<RgbaImage, AfirmaError> {
        self.render_page(index, dpi / 72.0)
    }
}

/// PDF mínimo de una página en blanco de `w`×`h` puntos.
pub fn blank_pdf(w: i64, h: i64) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let objs = [
        "<</Type/Catalog/Pages 2 0 R>>".to_string(),
        "<</Type/Pages/Kids[3 0 R]/Count 1>>".to_string(),
        format!("<</Type/Page/Parent 2 0 R/MediaBox[0 0 {w} {h}]/Resources<<>>>>"),
    ];
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<</Size 4/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    out
}

/// Vista previa exacta de la apariencia de la firma visible: se genera la
/// firma (sin CMS) sobre una página en blanco del tamaño del área y se
/// renderiza. `params` son los `extraParams` de la apariencia (`layer2Text`,
/// `layer2Font*`, `signatureRubricImage`, `signatureRotation`...); sin
/// certificado, las etiquetas del certificado se muestran tal cual (como la
/// vista previa de AutoFirma).
pub fn preview_appearance(
    width: i64,
    height: i64,
    params: &afirma_core::ExtraParams,
    chain: &[Vec<u8>],
    sign_time: Option<crate::pdf::date::SignTime>,
    scale: f32,
) -> Result<RgbaImage, AfirmaError> {
    let pdf = blank_pdf(width.max(1), height.max(1));
    let mut xp = params.clone();
    for (k, v) in [
        ("LowerLeftX", 0),
        ("LowerLeftY", 0),
        ("UpperRightX", width),
        ("UpperRightY", height),
    ] {
        xp.set(format!("signaturePositionOnPage{k}"), v.to_string());
    }
    xp.remove("signatureField");
    xp.remove("signaturePages");
    xp.remove("signaturePage");
    let prepared = crate::pades::prepare::prepare(&crate::pades::prepare::PrepareInput {
        pdf: &pdf,
        chain,
        sign_time: sign_time.unwrap_or_else(crate::pdf::date::now),
        xp: &xp,
        secure_mode: true,
        kind: crate::pades::prepare::SigKind::Signature,
    })?;
    RenderDocument::open(&prepared.bytes, None)?.render_page(0, scale)
}
