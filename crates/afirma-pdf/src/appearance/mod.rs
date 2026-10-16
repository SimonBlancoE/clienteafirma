//! Apariencia de la firma visible (capas `n0`/`n2` y `FRM` como
//! `PdfSignatureAppearance` de iText 2.1.7 parcheado: `TOP_SECTION = 0`,
//! `MARGIN = 2`).

pub mod afm;
pub mod image;
pub mod text;
pub mod tokens;

use std::fmt::Write as _;

use lopdf::{Dictionary, Object, ObjectId};

use crate::pdf::write::{Update, flate_stream, format_number as f, num};
use image::PdfImage;
use text::{TextStyle, column_content, fit_text, latin1_bytes, layout_column};

/// Margen interior del texto.
pub const MARGIN: f64 = 2.0;

/// Programa del signo de interrogación de iText (capa `n1` heredada).
pub const QUESTION_MARK: &str = "% DSUnknown\nq\n1 G\n1 g\n0.1 0 0 0.1 9 0 cm\n0 J 0 j 4 M []0 d\n1 i \n0 g\n313 292 m\n313 404 325 453 432 529 c\n478 561 504 597 504 645 c\n504 736 440 760 391 760 c\n286 760 271 681 265 626 c\n265 625 l\n100 625 l\n100 828 253 898 381 898 c\n451 898 679 878 679 650 c\n679 555 628 499 538 435 c\n488 399 467 376 467 292 c\n313 292 l\nh\n308 214 170 -164 re\nf\n0.44 G\n1.2 w\n1 1 0.4 rg\n287 318 m\n287 430 299 479 406 555 c\n451 587 478 623 478 671 c\n478 762 414 786 365 786 c\n260 786 245 707 239 652 c\n239 651 l\n74 651 l\n74 854 227 924 355 924 c\n425 924 653 904 653 676 c\n653 581 602 525 512 461 c\n462 425 441 402 441 318 c\n287 318 l\nh\n282 240 170 -164 re\nB\nQ\n";

/// Contenido visible de la firma.
#[derive(Debug, Clone, Default)]
pub struct VisibleContent {
    /// Texto de la capa 2 ya resuelto (`None`: sin texto).
    pub text: Option<String>,
    pub style: TextStyle,
    /// Imagen de rúbrica.
    pub rubric: Option<PdfImage>,
    /// Giro del contenido en grados (`signatureRotation`), 0 = sin giro.
    pub rotation: i32,
    /// Capas heredadas n0..n4 (`includeQuestionMark=true`).
    pub legacy_layers: bool,
}

/// Apariencia a construir.
#[derive(Debug, Clone)]
pub struct AppearanceSpec {
    /// Ancho y alto del campo tal y como se muestra.
    pub width: f64,
    pub height: f64,
    /// Rotación de la página (`/Rotate`).
    pub page_rotation: i32,
    /// `None` = firma invisible.
    pub visible: Option<VisibleContent>,
}

/// Objetos de la apariencia creados.
#[derive(Debug, Clone, Copy)]
pub struct BuiltAppearance {
    /// Apariencia normal (`/AP /N`).
    pub napp: ObjectId,
    /// Plantilla `FRM` (para `/DR`).
    pub frm: Option<ObjectId>,
}

fn proc_set() -> Object {
    Object::Array(
        [b"PDF".as_slice(), b"Text", b"ImageB", b"ImageC", b"ImageI"]
            .iter()
            .map(|n| Object::Name(n.to_vec()))
            .collect(),
    )
}

/// XObject de formulario con el formato de iText.
pub fn form_xobject(bbox: [f64; 4], resources: Dictionary, content: &[u8]) -> Object {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"XObject".to_vec()));
    d.set("Subtype", Object::Name(b"Form".to_vec()));
    let mut res = Dictionary::new();
    res.set("ProcSet", proc_set());
    for (k, v) in resources.iter() {
        res.set(k.clone(), v.clone());
    }
    d.set("Resources", Object::Dictionary(res));
    d.set("BBox", Object::Array(bbox.iter().map(|v| num(*v)).collect()));
    d.set("FormType", Object::Integer(1));
    d.set(
        "Matrix",
        Object::Array(vec![1.into(), 0.into(), 0.into(), 1.into(), 0.into(), 0.into()]),
    );
    Object::Stream(flate_stream(d, content))
}

/// Diccionario de una fuente Type 1 estándar con WinAnsiEncoding.
pub fn std_font_dict(base: &str) -> Object {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"Font".to_vec()));
    d.set("Subtype", Object::Name(b"Type1".to_vec()));
    d.set("BaseFont", Object::Name(base.as_bytes().to_vec()));
    d.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
    Object::Dictionary(d)
}

fn xobject_res(entries: &[(&str, ObjectId)]) -> Dictionary {
    let mut x = Dictionary::new();
    for (n, id) in entries {
        x.set(n.as_bytes().to_vec(), Object::Reference(*id));
    }
    let mut r = Dictionary::new();
    r.set("XObject", Object::Dictionary(x));
    r
}

/// Añade una imagen (y su máscara) a la actualización.
pub fn add_image(update: &mut Update, img: &PdfImage) -> ObjectId {
    let id = update.alloc();
    let smask_id = img.needs_smask().then(|| update.alloc());
    let (main, mask) = img.objects(smask_id);
    update.put(id, main);
    if let (Some(mid), Some(m)) = (smask_id, mask) {
        update.put(mid, m);
    }
    id
}

/// Operadores para dibujar una imagen escalada y centrada en `w`×`h`
/// conservando la proporción (`imageScale = -1` de iText).
fn image_fit_ops(img: &PdfImage, w: f64, h: f64, name: &str) -> String {
    let (iw0, ih0) = (f64::from(img.width), f64::from(img.height));
    let s = (w / iw0).min(h / ih0);
    let (iw, ih) = (iw0 * s, ih0 * s);
    let (x, y) = ((w - iw) / 2.0, (h - ih) / 2.0);
    format!("q {} 0 0 {} {} {} cm /{name} Do Q\n", f(iw), f(ih), f(x), f(y))
}

/// Construye la apariencia y la añade a la actualización.
pub fn build(spec: &AppearanceSpec, update: &mut Update) -> BuiltAppearance {
    let (w, h) = (spec.width, spec.height);
    let Some(vis) = &spec.visible else {
        let napp = update.alloc();
        update.put(napp, form_xobject([0.0, 0.0, 0.0, 0.0], Dictionary::new(), b""));
        return BuiltAppearance { napp, frm: None };
    };

    // Capa n0.
    let n0 = update.alloc();
    update.put(
        n0,
        form_xobject([0.0, 0.0, 100.0, 100.0], Dictionary::new(), b"% DSBlank\n"),
    );

    // Capa n2.
    let n2 = update.alloc();
    let font_needed = vis.text.as_ref().is_some_and(|t| !t.is_empty());
    let mut style = vis.style;
    let rotation = ((vis.rotation % 360) + 360) % 360;
    let n2_obj = if rotation != 0 {
        // Plantilla sin girar (Xf1) con rúbrica y texto ajustado.
        let (cw, ch) = if rotation == 0 || rotation == 180 {
            (w, h)
        } else {
            (h, w)
        };
        let mut content = String::new();
        let mut res = Dictionary::new();
        let mut xobjs = Vec::new();
        if let Some(img) = &vis.rubric {
            let id = add_image(update, img);
            xobjs.push(("img0", id));
            content.push_str(&image_fit_ops(img, cw, ch, "img0"));
        }
        if let Some(t) = vis.text.as_ref().filter(|t| !t.is_empty()) {
            let font_id = update.alloc();
            update.put(font_id, std_font_dict(style.family.base_font()));
            let mut fonts = Dictionary::new();
            fonts.set("F1", Object::Reference(font_id));
            res.set("Font", Object::Dictionary(fonts));
            let _ = writeln!(content, "/F1 {} Tf", f(style.size));
            let rect = (MARGIN, MARGIN, cw - MARGIN, ch - MARGIN);
            let max = if style.size > 0.0 { style.size } else { 12.0 };
            style.size = fit_text(t, rect, max, &style);
            let layout = layout_column(t, rect, style.size, &style);
            column_content(&layout, &style, "F1", &mut content);
        }
        if !xobjs.is_empty() {
            for (k, v) in xobject_res(&xobjs).iter() {
                res.set(k.clone(), v.clone());
            }
        }
        let xf1 = update.alloc();
        update.put(xf1, form_xobject([0.0, 0.0, cw, ch], res, &latin1_bytes(&content)));
        // Plantilla exterior (Xf2) que dibuja Xf1 girada en sentido antihorario
        // y centrada en el campo.
        let theta = f64::from(rotation).to_radians();
        let (c, s) = (theta.cos(), theta.sin());
        let (c, s) = (clean(c), clean(s));
        // Centro de Xf1 llevado al centro del campo.
        let (cx, cy) = (cw / 2.0, ch / 2.0);
        let tx = w / 2.0 - (c * cx - s * cy);
        let ty = h / 2.0 - (s * cx + c * cy);
        let xf2 = update.alloc();
        let xf2_content = format!(
            "q {} {} {} {} {} {} cm /Xf1 Do Q\n",
            f(c),
            f(s),
            f(-s),
            f(c),
            f(tx),
            f(ty)
        );
        update.put(
            xf2,
            form_xobject([0.0, 0.0, w, h], xobject_res(&[("Xf1", xf1)]), xf2_content.as_bytes()),
        );
        form_xobject(
            [0.0, 0.0, w, h],
            xobject_res(&[("Xf2", xf2)]),
            b"q 1 0 0 1 0 0 cm /Xf2 Do Q\n",
        )
    } else {
        let mut content = String::new();
        let mut res = Dictionary::new();
        if let Some(img) = &vis.rubric {
            let id = add_image(update, img);
            for (k, v) in xobject_res(&[("img0", id)]).iter() {
                res.set(k.clone(), v.clone());
            }
            content.push_str(&image_fit_ops(img, w, h, "img0"));
        }
        if let (true, Some(t)) = (font_needed, vis.text.as_ref()) {
            let font_id = update.alloc();
            update.put(font_id, std_font_dict(style.family.base_font()));
            let mut fonts = Dictionary::new();
            fonts.set("F1", Object::Reference(font_id));
            res.set("Font", Object::Dictionary(fonts));
            let rect = (MARGIN, MARGIN, w - MARGIN, h - MARGIN);
            if style.size <= 0.0 {
                style.size = fit_text(t, rect, 12.0, &style);
            }
            let layout = layout_column(t, rect, style.size, &style);
            column_content(&layout, &style, "F1", &mut content);
        }
        form_xobject([0.0, 0.0, w, h], res, &latin1_bytes(&content))
    };
    update.put(n2, n2_obj);

    // Capas heredadas.
    let legacy = if vis.legacy_layers {
        let n1 = update.alloc();
        update.put(
            n1,
            form_xobject([0.0, 0.0, 100.0, 100.0], Dictionary::new(), QUESTION_MARK.as_bytes()),
        );
        let n3 = update.alloc();
        update.put(
            n3,
            form_xobject([0.0, 0.0, 100.0, 100.0], Dictionary::new(), b"% DSBlank\n"),
        );
        let n4 = update.alloc();
        update.put(n4, form_xobject([0.0, h, w, h], Dictionary::new(), b""));
        Some((n1, n3, n4))
    } else {
        None
    };

    // FRM.
    let rotated = rotate_size(w, h, spec.page_rotation);
    let mut frm_content = String::new();
    match spec.page_rotation {
        90 => {
            let _ = writeln!(frm_content, "0 1 -1 0 {} 0 cm", f(h));
        }
        180 => {
            let _ = writeln!(frm_content, "-1 0 0 -1 {} {} cm", f(w), f(h));
        }
        270 => {
            let _ = writeln!(frm_content, "0 -1 1 0 0 {} cm", f(w));
        }
        _ => {}
    }
    frm_content.push_str("q 1 0 0 1 0 0 cm /n0 Do Q\n");
    let mut frm_x: Vec<(&str, ObjectId)> = vec![("n0", n0)];
    if let Some((n1, n3, n4)) = legacy {
        let scale = w.min(h) * 0.9;
        let (x, y) = ((w - scale) / 2.0, (h - scale) / 2.0);
        let s = scale / 100.0;
        let _ = writeln!(frm_content, "q {} 0 0 {} {} {} cm /n1 Do Q", f(s), f(s), f(x), f(y));
        frm_content.push_str("q 1 0 0 1 0 0 cm /n2 Do Q\n");
        let _ = writeln!(frm_content, "q {} 0 0 {} {} {} cm /n3 Do Q", f(s), f(s), f(x), f(y));
        frm_content.push_str("q 1 0 0 1 0 0 cm /n4 Do Q\n");
        frm_x.extend([("n1", n1), ("n2", n2), ("n3", n3), ("n4", n4)]);
    } else {
        frm_content.push_str("q 1 0 0 1 0 0 cm /n2 Do Q\n");
        frm_x.push(("n2", n2));
    }
    let frm = update.alloc();
    update.put(
        frm,
        form_xobject(
            [0.0, 0.0, rotated.0, rotated.1],
            xobject_res(&frm_x),
            frm_content.as_bytes(),
        ),
    );
    let napp = update.alloc();
    update.put(
        napp,
        form_xobject(
            [0.0, 0.0, rotated.0, rotated.1],
            xobject_res(&[("FRM", frm)]),
            b"q 1 0 0 1 0 0 cm /FRM Do Q\n",
        ),
    );
    BuiltAppearance { napp, frm: Some(frm) }
}

/// Redondea senos y cosenos casi enteros (evita `6.1e-17`).
fn clean(v: f64) -> f64 {
    if v.abs() < 1e-9 {
        0.0
    } else if (v - 1.0).abs() < 1e-9 {
        1.0
    } else if (v + 1.0).abs() < 1e-9 {
        -1.0
    } else {
        v
    }
}

/// Tamaño del rectángulo girado según la rotación de la página.
pub fn rotate_size(w: f64, h: f64, page_rotation: i32) -> (f64, f64) {
    if page_rotation == 90 || page_rotation == 270 {
        (h, w)
    } else {
        (w, h)
    }
}
