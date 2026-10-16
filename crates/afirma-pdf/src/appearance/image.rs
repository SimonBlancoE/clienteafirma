//! Imágenes de la firma visible (rúbrica) y de la marca visible (`image`).
//!
//! Las imágenes JPEG se incrustan tal cual (`/DCTDecode`). El resto de
//! formatos (PNG, GIF, BMP) se decodifican y se incrustan sin pérdidas
//! (`/FlateDecode`), con el canal alfa como máscara suave (`/SMask`) si la
//! imagen tiene transparencias. AutoFirma Java convierte todas las imágenes
//! a JPEG y rellena las zonas transparentes de blanco (ver
//! `docs/deviations/afirma-pdf.md`).

use lopdf::{Dictionary, Object};

use crate::pdf::write::flate_stream;

/// Imagen preparada para incrustar en el PDF.
#[derive(Debug, Clone)]
pub struct PdfImage {
    /// Ancho y alto en píxeles (iText los usa como puntos a 72 ppp).
    pub width: u32,
    pub height: u32,
    /// Diccionario del XObject (sin `/Length`) y datos ya codificados.
    pub dict: Dictionary,
    pub data: Vec<u8>,
    /// Máscara de transparencia (escala de grises, 8 bits, sin comprimir).
    pub smask: Option<Vec<u8>>,
}

/// Error al cargar una imagen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    /// No es Base64.
    NotBase64,
    /// Formato no reconocido.
    Unsupported,
}

/// Lee las dimensiones y componentes de un JPEG (marcador SOFn) y si tiene
/// el marcador APP14 de Adobe (CMYK invertido).
fn jpeg_info(data: &[u8]) -> Option<(u32, u32, u8, bool)> {
    if data.len() < 4 || data[0] != 0xff || data[1] != 0xd8 {
        return None;
    }
    let mut i = 2;
    let mut adobe = false;
    while i + 4 <= data.len() {
        if data[i] != 0xff {
            i += 1;
            continue;
        }
        let marker = data[i + 1];
        if marker == 0xff {
            i += 1;
            continue;
        }
        if marker == 0xd8 || marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            i += 2;
            continue;
        }
        let len = usize::from(u16::from_be_bytes([data[i + 2], data[i + 3]]));
        if marker == 0xee && data.get(i + 4..i + 9) == Some(b"Adobe") {
            adobe = true;
        }
        let is_sof = matches!(marker, 0xc0..=0xcf) && !matches!(marker, 0xc4 | 0xc8 | 0xcc);
        if is_sof {
            let s = data.get(i + 4..i + 10)?;
            let h = u32::from(u16::from_be_bytes([s[1], s[2]]));
            let w = u32::from(u16::from_be_bytes([s[3], s[4]]));
            let comps = s[5];
            return Some((w, h, comps, adobe));
        }
        if marker == 0xda {
            return None;
        }
        i += 2 + len;
    }
    None
}

impl PdfImage {
    /// Prepara una imagen a partir de sus bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PdfImage, ImageError> {
        if let Some((w, h, comps, adobe)) = jpeg_info(bytes)
            && w > 0 && h > 0 {
                let mut d = Dictionary::new();
                d.set("Type", Object::Name(b"XObject".to_vec()));
                d.set("Subtype", Object::Name(b"Image".to_vec()));
                d.set("Width", Object::Integer(i64::from(w)));
                d.set("Height", Object::Integer(i64::from(h)));
                d.set("BitsPerComponent", Object::Integer(8));
                let cs: &[u8] = match comps {
                    1 => b"DeviceGray",
                    4 => b"DeviceCMYK",
                    _ => b"DeviceRGB",
                };
                d.set("ColorSpace", Object::Name(cs.to_vec()));
                if comps == 4 && adobe {
                    d.set(
                        "Decode",
                        Object::Array(
                            (0..4)
                                .flat_map(|_| [Object::Integer(1), Object::Integer(0)])
                                .collect(),
                        ),
                    );
                }
                d.set("Filter", Object::Name(b"DCTDecode".to_vec()));
                return Ok(PdfImage {
                    width: w,
                    height: h,
                    dict: d,
                    data: bytes.to_vec(),
                    smask: None,
                });
            }
        let img = image::load_from_memory(bytes).map_err(|_| ImageError::Unsupported)?;
        let rgba = img.to_rgba8();
        let (w, h) = (rgba.width(), rgba.height());
        if w == 0 || h == 0 {
            return Err(ImageError::Unsupported);
        }
        let has_alpha = rgba.pixels().any(|p| p.0[3] != 255);
        let gray = img.color().channel_count() <= 2;
        let mut data = Vec::with_capacity((w * h * 3) as usize);
        let mut alpha = Vec::with_capacity((w * h) as usize);
        for p in rgba.pixels() {
            if gray {
                data.push(p.0[0]);
            } else {
                data.extend_from_slice(&p.0[..3]);
            }
            alpha.push(p.0[3]);
        }
        let mut d = Dictionary::new();
        d.set("Type", Object::Name(b"XObject".to_vec()));
        d.set("Subtype", Object::Name(b"Image".to_vec()));
        d.set("Width", Object::Integer(i64::from(w)));
        d.set("Height", Object::Integer(i64::from(h)));
        d.set("BitsPerComponent", Object::Integer(8));
        d.set(
            "ColorSpace",
            Object::Name(if gray {
                b"DeviceGray".to_vec()
            } else {
                b"DeviceRGB".to_vec()
            }),
        );
        Ok(PdfImage {
            width: w,
            height: h,
            dict: d,
            data,
            smask: has_alpha.then_some(alpha),
        })
    }

    /// Prepara una imagen codificada en Base64.
    pub fn from_base64(b64: &str) -> Result<PdfImage, ImageError> {
        let bytes = afirma_core::base64_decode_lenient(b64).map_err(|_| ImageError::NotBase64)?;
        Self::from_bytes(&bytes)
    }

    /// Objetos a escribir: el XObject de la imagen y, si la hay, su máscara.
    /// `smask_id` es el identificador reservado para la máscara.
    pub fn objects(&self, smask_id: Option<lopdf::ObjectId>) -> (Object, Option<Object>) {
        let mut dict = self.dict.clone();
        let is_dct = dict.get(b"Filter").ok().and_then(|f| f.as_name().ok())
            == Some(b"DCTDecode".as_slice());
        let main = if is_dct {
            let mut d = dict.clone();
            d.set("Length", Object::Integer(self.data.len() as i64));
            Object::Stream(lopdf::Stream::new(d, self.data.clone()).with_compression(false))
        } else {
            if let (Some(_), Some(id)) = (&self.smask, smask_id) {
                dict.set("SMask", Object::Reference(id));
            }
            Object::Stream(flate_stream(dict, &self.data))
        };
        let mask = match (&self.smask, smask_id) {
            (Some(a), Some(_)) if !is_dct => {
                let mut d = Dictionary::new();
                d.set("Type", Object::Name(b"XObject".to_vec()));
                d.set("Subtype", Object::Name(b"Image".to_vec()));
                d.set("Width", Object::Integer(i64::from(self.width)));
                d.set("Height", Object::Integer(i64::from(self.height)));
                d.set("BitsPerComponent", Object::Integer(8));
                d.set("ColorSpace", Object::Name(b"DeviceGray".to_vec()));
                Some(Object::Stream(flate_stream(d, a)))
            }
            _ => None,
        };
        (main, mask)
    }

    pub fn needs_smask(&self) -> bool {
        self.smask.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_with_alpha() -> Vec<u8> {
        let mut img = image::RgbaImage::new(4, 2);
        for (x, _, p) in img.enumerate_pixels_mut() {
            *p = image::Rgba([255, 0, 0, if x < 2 { 0 } else { 255 }]);
        }
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn png_gets_smask() {
        let img = PdfImage::from_bytes(&png_with_alpha()).unwrap();
        assert_eq!((img.width, img.height), (4, 2));
        assert!(img.needs_smask());
        let (main, mask) = img.objects(Some((10, 0)));
        assert!(mask.is_some());
        assert_eq!(
            main.as_stream()
                .unwrap()
                .dict
                .get(b"SMask")
                .unwrap()
                .as_reference()
                .unwrap(),
            (10, 0)
        );
    }

    #[test]
    fn jpeg_passthrough() {
        let mut out = std::io::Cursor::new(Vec::new());
        image::RgbImage::new(3, 5)
            .write_to(&mut out, image::ImageFormat::Jpeg)
            .unwrap();
        let bytes = out.into_inner();
        let img = PdfImage::from_bytes(&bytes).unwrap();
        assert_eq!((img.width, img.height), (3, 5));
        assert_eq!(img.data, bytes);
        assert!(PdfImage::from_bytes(b"no es una imagen").is_err());
    }
}
