//! Fuentes TrueType incrustadas (Liberation 2.1.5, SIL OFL 1.1) para la firma
//! visible de los documentos PDF/A, que exigen incrustar todas las fuentes.
//!
//! AutoFirma Java incrusta GNU FreeFont (GPLv3) completa en los PDF/A-1; aquí
//! se usan las Liberation, métricamente compatibles con Helvetica
//! (Liberation Sans), Times (Liberation Serif) y Courier (Liberation Mono),
//! con la variante normal, negrita, cursiva o negrita cursiva según
//! `layer2FontStyle`. Se incrustan como subconjunto en una fuente compuesta
//! (`Type0` + `CIDFontType2`, `Identity-H`) con `ToUnicode` y `CIDSet`, que
//! es lo que admiten PDF/A-1b, 2b y 3b.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use lopdf::{Dictionary, Object, ObjectId, StringFormat};
use md5::{Digest, Md5};

use super::text::FontFamily;
use crate::pdf::write::{Update, flate_stream, num};

/// Variante de fuente incrustable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedFace {
    pub family: FontFamily,
    pub bold: bool,
    pub italic: bool,
}

static FONTS: [&[u8]; 12] = [
    include_bytes!("../../fonts/LiberationSans-Regular.ttf"),
    include_bytes!("../../fonts/LiberationSans-Bold.ttf"),
    include_bytes!("../../fonts/LiberationSans-Italic.ttf"),
    include_bytes!("../../fonts/LiberationSans-BoldItalic.ttf"),
    include_bytes!("../../fonts/LiberationSerif-Regular.ttf"),
    include_bytes!("../../fonts/LiberationSerif-Bold.ttf"),
    include_bytes!("../../fonts/LiberationSerif-Italic.ttf"),
    include_bytes!("../../fonts/LiberationSerif-BoldItalic.ttf"),
    include_bytes!("../../fonts/LiberationMono-Regular.ttf"),
    include_bytes!("../../fonts/LiberationMono-Bold.ttf"),
    include_bytes!("../../fonts/LiberationMono-Italic.ttf"),
    include_bytes!("../../fonts/LiberationMono-BoldItalic.ttf"),
];

const PS_NAMES: [&str; 12] = [
    "LiberationSans",
    "LiberationSans-Bold",
    "LiberationSans-Italic",
    "LiberationSans-BoldItalic",
    "LiberationSerif",
    "LiberationSerif-Bold",
    "LiberationSerif-Italic",
    "LiberationSerif-BoldItalic",
    "LiberationMono",
    "LiberationMono-Bold",
    "LiberationMono-Italic",
    "LiberationMono-BoldItalic",
];

/// Métricas de una fuente cargada.
struct Loaded {
    face: ttf_parser::Face<'static>,
    upem: f64,
}

fn loaded(index: usize) -> Option<&'static Loaded> {
    static CACHE: [OnceLock<Option<Loaded>>; 12] = [const { OnceLock::new() }; 12];
    CACHE[index]
        .get_or_init(|| {
            let face = ttf_parser::Face::parse(FONTS[index], 0).ok()?;
            let upem = f64::from(face.units_per_em().max(1));
            Some(Loaded { face, upem })
        })
        .as_ref()
}

impl EmbeddedFace {
    /// Variante para la familia y el estilo de `layer2FontFamily`/`layer2FontStyle`.
    pub fn new(family: FontFamily, bold: bool, italic: bool) -> EmbeddedFace {
        EmbeddedFace { family, bold, italic }
    }

    fn index(&self) -> usize {
        let base = match self.family {
            FontFamily::Helvetica => 0,
            FontFamily::TimesRoman => 4,
            FontFamily::Courier => 8,
        };
        base + usize::from(self.bold) + 2 * usize::from(self.italic)
    }

    /// Nombre PostScript de la fuente.
    pub fn postscript_name(&self) -> &'static str {
        PS_NAMES[self.index()]
    }

    /// Programa de la fuente completa (TrueType).
    pub fn font_data(&self) -> &'static [u8] {
        FONTS[self.index()]
    }

    /// Glifo de un carácter.
    pub fn glyph(&self, c: char) -> Option<u16> {
        let f = loaded(self.index())?;
        f.face.glyph_index(c).map(|g| g.0).filter(|g| *g != 0)
    }

    /// Ancho del glifo en unidades de 1/1000 del cuerpo (redondeado, que es
    /// el valor que se escribe en `/W`).
    pub fn glyph_width(&self, gid: u16) -> u16 {
        loaded(self.index())
            .and_then(|f| {
                f.face
                    .glyph_hor_advance(ttf_parser::GlyphId(gid))
                    .map(|a| (f64::from(a) * 1000.0 / f.upem).round() as u16)
            })
            .unwrap_or(0)
    }

    /// Ancho de un carácter en unidades de 1/1000 (0 si la fuente no lo tiene,
    /// en cuyo caso no se dibuja).
    pub fn char_width(&self, c: char) -> u16 {
        self.glyph(c).map(|g| self.glyph_width(g)).unwrap_or(0)
    }

    fn scaled(&self, v: f64) -> f64 {
        loaded(self.index()).map(|f| v * 1000.0 / f.upem).unwrap_or(v)
    }
}

/// Codificador del texto para los operadores `Tj`.
#[derive(Debug, Clone)]
pub enum TextEncoder {
    /// Fuente estándar con `WinAnsiEncoding` (cadenas literales).
    WinAnsi,
    /// Fuente compuesta `Identity-H`: carácter → CID del subconjunto.
    Cid(BTreeMap<char, u16>),
}

impl TextEncoder {
    /// Operando de `Tj` (con sus delimitadores) para un texto.
    pub fn operand(&self, text: &str) -> Vec<u8> {
        match self {
            TextEncoder::WinAnsi => {
                let mut out = Vec::new();
                crate::pdf::write::write_literal_string(&mut out, &crate::pdf::text::winansi_encode(text));
                out
            }
            TextEncoder::Cid(map) => {
                let mut s = String::from("<");
                for c in text.chars() {
                    if let Some(cid) = map.get(&c) {
                        s.push_str(&format!("{cid:04X}"));
                    }
                }
                s.push('>');
                s.into_bytes()
            }
        }
    }
}

/// Etiqueta de subconjunto (seis mayúsculas) determinista.
fn subset_tag(face: &EmbeddedFace, gids: &[u16]) -> String {
    let mut h = Md5::new();
    h.update(face.postscript_name().as_bytes());
    for g in gids {
        h.update(g.to_be_bytes());
    }
    h.finalize().iter().take(6).map(|b| char::from(b'A' + b % 26)).collect()
}

fn to_unicode_cmap(entries: &[(u16, char)]) -> String {
    let mut s = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo <</Registry (Adobe) /Ordering (UCS) /Supplement 0>> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    for chunk in entries.chunks(100) {
        s.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (cid, c) in chunk {
            let mut units = [0u16; 2];
            let hex: String = c.encode_utf16(&mut units).iter().map(|u| format!("{u:04X}")).collect();
            s.push_str(&format!("<{cid:04X}> <{hex}>\n"));
        }
        s.push_str("endbfchar\n");
    }
    s.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    s
}

/// Crea los objetos de la fuente (subconjunto con los caracteres de
/// `text`) y devuelve la referencia de la fuente `Type0` y el codificador.
pub fn add_font(update: &mut Update, face: EmbeddedFace, text: &str) -> (ObjectId, TextEncoder) {
    // Glifos usados (el 0 se conserva siempre).
    let mut used: BTreeMap<u16, char> = BTreeMap::new();
    for c in text.chars() {
        if let Some(g) = face.glyph(c) {
            used.entry(g).or_insert(c);
        }
    }
    let mut remapper = subsetter::GlyphRemapper::new();
    remapper.remap(0);
    let mut chars: BTreeMap<char, u16> = BTreeMap::new();
    let mut cids: Vec<(u16, u16, char)> = Vec::new(); // (cid, gid, char)
    for (&g, &c) in &used {
        let cid = remapper.remap(g);
        cids.push((cid, g, c));
    }
    for c in text.chars() {
        if let Some(cid) = face.glyph(c).and_then(|g| remapper.get(g)) {
            chars.insert(c, cid);
        }
    }
    let program = subsetter::subset(face.font_data(), 0, &remapper).unwrap_or_else(|_| face.font_data().to_vec());
    let gids: Vec<u16> = used.keys().copied().collect();
    let base_font = format!("{}+{}", subset_tag(&face, &gids), face.postscript_name());

    // Programa de la fuente.
    let mut ff = Dictionary::new();
    ff.set("Length1", Object::Integer(program.len() as i64));
    let ff_id = update.alloc();
    update.put(ff_id, Object::Stream(flate_stream(ff, &program)));

    // CIDSet: todos los CID del subconjunto (0..n). El subconjunto puede
    // contener más glifos que los pedidos (componentes de glifos compuestos).
    let n = ttf_parser::Face::parse(&program, 0)
        .map(|f| usize::from(f.number_of_glyphs()))
        .unwrap_or_else(|_| usize::from(remapper.num_gids()));
    let mut cidset = vec![0u8; n.div_ceil(8)];
    for cid in 0..n {
        cidset[cid / 8] |= 0x80 >> (cid % 8);
    }
    let cidset_id = update.alloc();
    update.put(cidset_id, Object::Stream(flate_stream(Dictionary::new(), &cidset)));

    // Descriptor.
    let (bbox, ascent, descent, cap, italic_angle, mono) = match loaded(face.index()) {
        Some(f) => {
            let b = f.face.global_bounding_box();
            (
                [
                    f64::from(b.x_min),
                    f64::from(b.y_min),
                    f64::from(b.x_max),
                    f64::from(b.y_max),
                ],
                f64::from(f.face.ascender()),
                f64::from(f.face.descender()),
                f64::from(f.face.capital_height().unwrap_or(f.face.ascender())),
                f64::from(f.face.italic_angle()),
                f.face.is_monospaced(),
            )
        }
        None => ([0.0; 4], 0.0, 0.0, 0.0, 0.0, false),
    };
    let mut flags = 32; // no simbólica
    if mono || face.family == FontFamily::Courier {
        flags |= 1;
    }
    if face.family == FontFamily::TimesRoman {
        flags |= 2;
    }
    if face.italic {
        flags |= 64;
    }
    let mut fd = Dictionary::new();
    fd.set("Type", Object::Name(b"FontDescriptor".to_vec()));
    fd.set("FontName", Object::Name(base_font.as_bytes().to_vec()));
    fd.set("Flags", Object::Integer(flags));
    fd.set(
        "FontBBox",
        Object::Array(bbox.iter().map(|v| num(face.scaled(*v).round())).collect()),
    );
    fd.set("ItalicAngle", num(italic_angle));
    fd.set("Ascent", num(face.scaled(ascent).round()));
    fd.set("Descent", num(face.scaled(descent).round()));
    fd.set("CapHeight", num(face.scaled(cap).round()));
    fd.set("StemV", Object::Integer(if face.bold { 140 } else { 80 }));
    fd.set("CIDSet", Object::Reference(cidset_id));
    fd.set("FontFile2", Object::Reference(ff_id));
    let fd_id = update.alloc();
    update.put(fd_id, Object::Dictionary(fd));

    // Anchos por CID.
    let mut w = Vec::new();
    for (cid, gid, _) in &cids {
        w.push(Object::Integer(i64::from(*cid)));
        w.push(Object::Array(vec![Object::Integer(i64::from(face.glyph_width(*gid)))]));
    }
    let mut csi = Dictionary::new();
    csi.set("Registry", Object::String(b"Adobe".to_vec(), StringFormat::Literal));
    csi.set("Ordering", Object::String(b"Identity".to_vec(), StringFormat::Literal));
    csi.set("Supplement", Object::Integer(0));
    let mut cid_font = Dictionary::new();
    cid_font.set("Type", Object::Name(b"Font".to_vec()));
    cid_font.set("Subtype", Object::Name(b"CIDFontType2".to_vec()));
    cid_font.set("BaseFont", Object::Name(base_font.as_bytes().to_vec()));
    cid_font.set("CIDSystemInfo", Object::Dictionary(csi));
    cid_font.set("FontDescriptor", Object::Reference(fd_id));
    cid_font.set("DW", Object::Integer(i64::from(face.glyph_width(0))));
    cid_font.set("W", Object::Array(w));
    cid_font.set("CIDToGIDMap", Object::Name(b"Identity".to_vec()));
    let cid_id = update.alloc();
    update.put(cid_id, Object::Dictionary(cid_font));

    // ToUnicode.
    let tu: Vec<(u16, char)> = cids.iter().map(|(cid, _, c)| (*cid, *c)).collect();
    let tu_id = update.alloc();
    update.put(
        tu_id,
        Object::Stream(flate_stream(Dictionary::new(), to_unicode_cmap(&tu).as_bytes())),
    );

    let mut t0 = Dictionary::new();
    t0.set("Type", Object::Name(b"Font".to_vec()));
    t0.set("Subtype", Object::Name(b"Type0".to_vec()));
    t0.set("BaseFont", Object::Name(base_font.into_bytes()));
    t0.set("Encoding", Object::Name(b"Identity-H".to_vec()));
    t0.set("DescendantFonts", Object::Array(vec![Object::Reference(cid_id)]));
    t0.set("ToUnicode", Object::Reference(tu_id));
    let t0_id = update.alloc();
    update.put(t0_id, Object::Dictionary(t0));
    (t0_id, TextEncoder::Cid(chars))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appearance::text::FontFamily;

    /// Las Liberation son métricamente compatibles con las fuentes estándar:
    /// los anchos redondeados de los caracteres WinAnsi coinciden con los AFM
    /// salvo cinco signos poco frecuentes (¯ ± µ · ÷) en Sans y Serif. Por eso,
    /// con fuente incrustada, la maquetación usa los anchos de la propia
    /// fuente (los mismos que se escriben en `/W`).
    #[test]
    fn liberation_widths_match_afm() {
        let mut mismatches = Vec::new();
        for fam in [FontFamily::Courier, FontFamily::Helvetica, FontFamily::TimesRoman] {
            let face = EmbeddedFace::new(fam, false, false);
            for b in 32u8..=255 {
                let c = match b {
                    0x80..=0x9f => match crate::appearance::afm::WINANSI_HIGH[usize::from(b - 0x80)] {
                        0 => continue,
                        u => char::from_u32(u32::from(u)).unwrap_or(' '),
                    },
                    _ => char::from(b),
                };
                let afm = fam.char_width(c);
                if afm == 0 {
                    continue;
                }
                let lib = face.char_width(c);
                if lib != afm {
                    mismatches.push((fam, c, afm, lib));
                }
            }
        }
        let odd: Vec<char> = mismatches.iter().map(|m| m.1).collect();
        assert!(mismatches.iter().all(|m| m.0 != FontFamily::Courier), "{mismatches:?}");
        assert!(odd.iter().all(|c| "¯±µ·÷".contains(*c)), "{mismatches:?}");
    }

    #[test]
    fn faces_and_cmap() {
        let f = EmbeddedFace::new(FontFamily::Helvetica, true, true);
        assert_eq!(f.postscript_name(), "LiberationSans-BoldItalic");
        assert!(f.glyph('Ж').is_some(), "las Liberation cubren el cirílico");
        let cmap = to_unicode_cmap(&[(1, 'A'), (2, '€')]);
        assert!(cmap.contains("<0001> <0041>") && cmap.contains("<0002> <20AC>"));
        let mut up = Update::new(10);
        let (_, enc) = add_font(&mut up, EmbeddedFace::new(FontFamily::Courier, false, false), "Hola Ñ");
        let op = String::from_utf8(enc.operand("Hola Ñ")).unwrap();
        assert_eq!(op.len(), 2 + 6 * 4, "{op}");
        assert!(op.starts_with('<') && op.ends_with('>'));
        // Los caracteres sin glifo se omiten.
        assert_eq!(enc.operand("\u{E000}"), b"<>");
    }
}
