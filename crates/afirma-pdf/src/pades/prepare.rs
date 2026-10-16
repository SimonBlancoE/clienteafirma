//! Construcción de la nueva revisión firmada con el hueco para el CMS
//! (`PdfSessionManager.getSessionData` + `PdfSignatureAppearance.preClose`).
//!
//! La revisión se añade **siempre** como actualización incremental: los
//! bytes originales nunca se modifican (ver `docs/deviations/afirma-pdf.md`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

use afirma_core::{AfirmaError, DigestAlgorithm, ExtraParams};
use lopdf::{Dictionary, Object, ObjectId, StringFormat};
use md5::{Digest, Md5};

use super::errors;
use super::params::*;
use crate::appearance::{
    self, AppearanceSpec, BuiltAppearance, VisibleContent,
    image::PdfImage,
    text::{FontFamily, TextStyle, color_by_name},
    tokens,
};
use crate::pdf::date::{SignTime, millis, pdf_date};
use crate::pdf::doc::{FieldItem, OpenError, PdfDoc, Rect, merge_different};
use crate::pdf::parse::XrefKind;
use crate::pdf::text::{decode_text_string, encode_text_string, text_object};
use crate::pdf::write::{TrailerInfo, Update, flate_stream, num, write_dict, write_literal_string, write_name};

/// Tipo de firma a preparar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    /// Firma PAdES (`/Type /Sig`).
    Signature,
    /// Sello de tiempo de documento (`/Type /DocTimeStamp`).
    DocTimeStamp,
}

/// Datos de entrada de la preparación.
pub struct PrepareInput<'a> {
    pub pdf: &'a [u8],
    /// Cadena de certificados (ya reducida si `includeOnlySignningCertificate`).
    pub chain: &'a [Vec<u8>],
    pub sign_time: SignTime,
    pub xp: &'a ExtraParams,
    pub secure_mode: bool,
    pub kind: SigKind,
}

/// PDF preparado con el hueco de `/Contents`.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub bytes: Vec<u8>,
    /// Posición del `<` de `/Contents`.
    pub contents_start: usize,
    /// Posición siguiente al `>` de `/Contents`.
    pub contents_end: usize,
    /// Tamaño reservado para el CMS (bytes).
    pub reserved: usize,
    /// Identificador `/ID` del trailer (los dos elementos).
    pub file_id: (Vec<u8>, Vec<u8>),
    /// Nombre del campo de firma.
    pub field_name: String,
}

impl Prepared {
    /// `/ByteRange` de la firma.
    pub fn byte_range(&self) -> [usize; 4] {
        [
            0,
            self.contents_start,
            self.contents_end,
            self.bytes.len() - self.contents_end,
        ]
    }

    /// Huella de los bytes cubiertos por la firma.
    pub fn digest(&self, d: DigestAlgorithm) -> Vec<u8> {
        let mut h = d.hasher();
        h.update(&self.bytes[..self.contents_start]);
        h.update(&self.bytes[self.contents_end..]);
        h.finalize()
    }

    /// Bytes cubiertos por la firma.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut v = self.bytes[..self.contents_start].to_vec();
        v.extend_from_slice(&self.bytes[self.contents_end..]);
        v
    }

    /// Inserta el CMS (o el sello) en `/Contents`.
    pub fn fill(&self, cms: &[u8]) -> Result<Vec<u8>, AfirmaError> {
        if cms.len() > self.reserved {
            return Err(errors::internal(format!(
                "El tamano de la firma ({}) supera el maximo permitido para un PDF ({})",
                cms.len(),
                self.reserved
            )));
        }
        let mut out = self.bytes.clone();
        let hexed = hex::encode(cms);
        let slot = &mut out[self.contents_start + 1..self.contents_end - 1];
        slot.fill(b'0');
        slot[..hexed.len()].copy_from_slice(hexed.as_bytes());
        Ok(out)
    }
}

/// Firmas con subfiltro registrado (`pdfHasUnregisteredSignatures`).
const REGISTERED_SUBFILTERS: [&[u8]; 4] = [
    b"ETSI.RFC3161",
    b"adbe.pkcs7.detached",
    b"ETSI.CAdES.detached",
    b"adbe.pkcs7.sha1",
];

/// Abre el PDF con las contraseñas de los parámetros y traduce los errores
/// como `PdfUtil.getPdfReader`.
pub fn open_pdf(pdf: &[u8], xp: &ExtraParams) -> Result<PdfDoc, AfirmaError> {
    let password = xp.get(OWNER_PASSWORD).or_else(|| xp.get(USER_PASSWORD));
    PdfDoc::open(pdf, password).map_err(|e| match e {
        OpenError::NotPdf(_) => errors::pdf_needed(),
        OpenError::NeedsPassword => errors::password_protected("El PDF esta protegido por contrasena para lectura"),
        OpenError::BadPassword => errors::bad_password("Se ha indicado una contrasena incorrecta para el PDF"),
    })
}

/// El documento contiene firmas con un subfiltro no registrado.
pub fn has_unregistered_signatures(doc: &PdfDoc) -> bool {
    doc.all_objects().any(|(_, o)| {
        let d = match o {
            Object::Dictionary(d) => d,
            _ => return false,
        };
        if d.get(b"Type").and_then(Object::as_name).ok() != Some(b"Sig".as_slice()) {
            return false;
        }
        match d.get(b"SubFilter").and_then(Object::as_name) {
            Ok(sf) => !REGISTERED_SUBFILTERS.contains(&sf),
            Err(_) => true,
        }
    })
}

/// Comprobación de PDF certificado (`PdfUtil.checkPdfCertification`).
pub fn check_certification(doc: &PdfDoc, xp: &ExtraParams) -> Result<(), AfirmaError> {
    if doc.certification_level() == 1 {
        match xp.get(ALLOW_SIGNING_CERTIFIED_PDFS) {
            None => return Err(errors::certified(false)),
            Some(v) if v.trim().eq_ignore_ascii_case("true") => {}
            Some(_) => return Err(errors::certified(true)),
        }
    }
    Ok(())
}

/// Comprobación de firmas no registradas.
pub fn check_unregistered(doc: &PdfDoc, xp: &ExtraParams) -> Result<(), AfirmaError> {
    if has_unregistered_signatures(doc) {
        match xp.get(ALLOW_COSIGNING_UNREGISTERED_SIGNATURES) {
            Some(v) if v.trim().eq_ignore_ascii_case("true") => {}
            Some(v) if !v.is_empty() => return Err(errors::unregistered(true)),
            _ => return Err(errors::unregistered(false)),
        }
    }
    Ok(())
}

/// Carga una imagen de los parámetros (Base64; o ruta si no está en modo
/// seguro y el valor es corto).
pub fn load_image_param(value: &str, secure_mode: bool, what: &str) -> Result<PdfImage, AfirmaError> {
    let bytes = if !secure_mode && value.len() < 500 && std::path::Path::new(value.trim()).exists() {
        std::fs::read(value.trim())
            .map_err(|_| AfirmaError::msg("El parametro de imagen no contiene una ruta valida a un recurso"))?
    } else {
        afirma_core::base64_decode_lenient(value).map_err(|_| {
            AfirmaError::msg(format!(
                "Se ha proporcionado una imagen de {what} que no esta codificada en Base64"
            ))
        })?
    };
    PdfImage::from_bytes(&bytes).map_err(|_| {
        AfirmaError::msg(format!(
            "Se ha proporcionado una imagen de {what} que no esta codificada en JPEG"
        ))
    })
}

/// Editor de objetos existentes y nuevos sobre un documento.
pub(crate) struct Edit<'a> {
    pub doc: &'a PdfDoc,
    pub update: Update,
    changed: BTreeMap<ObjectId, Object>,
}

impl<'a> Edit<'a> {
    pub fn new(doc: &'a PdfDoc) -> Self {
        Edit {
            doc,
            update: Update::new(doc.size),
            changed: BTreeMap::new(),
        }
    }

    /// Objeto (modificado o original).
    pub fn get(&self, id: ObjectId) -> Option<&Object> {
        self.changed.get(&id).or_else(|| self.doc.get(id))
    }

    /// Objeto modificable (se copia a la actualización).
    pub fn get_mut(&mut self, id: ObjectId) -> Option<&mut Object> {
        if !self.changed.contains_key(&id) {
            let o = self.doc.get(id)?.clone();
            self.changed.insert(id, o);
        }
        self.changed.get_mut(&id)
    }

    pub fn dict_mut(&mut self, id: ObjectId) -> Option<&mut Dictionary> {
        match self.get_mut(id)? {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&mut s.dict),
            _ => None,
        }
    }

    /// Resuelve un objeto (directo o referencia) con los cambios aplicados.
    pub fn resolve(&self, o: &Object) -> Object {
        let mut cur = o.clone();
        for _ in 0..32 {
            match cur {
                Object::Reference(id) => match self.get(id) {
                    Some(x) => cur = x.clone(),
                    None => return Object::Null,
                },
                other => return other,
            }
        }
        Object::Null
    }

    /// Añade un objeto nuevo que todavía puede modificarse.
    pub fn new_editable(&mut self, obj: Object) -> ObjectId {
        let id = self.update.alloc();
        self.changed.insert(id, obj);
        id
    }

    pub fn new_obj(&mut self, obj: Object) -> ObjectId {
        let id = self.update.alloc();
        self.update.put(id, obj);
        id
    }

    /// Pasa los objetos modificados a la actualización.
    pub fn flush(&mut self) {
        for (id, o) in std::mem::take(&mut self.changed) {
            self.update.put(id, o);
        }
    }
}

/// Nombre `SignatureN` libre.
fn next_signature_name(doc: &PdfDoc) -> String {
    let mut names: BTreeSet<String> = doc.form_fields().into_iter().map(|f| f.name).collect();
    if let Some(form) = doc.acroform()
        && let Some(Object::Array(fields)) = doc.dict_get(form, b"Fields")
    {
        fn walk(doc: &PdfDoc, o: &Object, prefix: &str, out: &mut BTreeSet<String>, depth: usize) {
            if depth > 32 {
                return;
            }
            let Some(d) = doc.dict(o) else { return };
            let t = doc
                .dict_get(d, b"T")
                .and_then(|t| t.as_str().ok())
                .map(decode_text_string);
            let full = match (&t, prefix.is_empty()) {
                (Some(t), true) => t.clone(),
                (Some(t), false) => format!("{prefix}.{t}"),
                (None, _) => prefix.to_string(),
            };
            if !full.is_empty() {
                out.insert(full.clone());
            }
            if let Some(Object::Array(kids)) = doc.dict_get(d, b"Kids") {
                for k in kids {
                    walk(doc, k, &full, out, depth + 1);
                }
            }
        }
        for f in fields {
            walk(doc, f, "", &mut names, 0);
        }
    }
    let mut k = 1;
    loop {
        let n = format!("Signature{k}");
        let prefix = format!("{n}.");
        if !names.iter().any(|x| *x == n || x.starts_with(&prefix)) {
            return n;
        }
        k += 1;
    }
}

/// Transforma un rectángulo dado sobre la página mostrada al espacio de la
/// página sin girar (como `PdfSignatureAppearance.preClose`).
fn unrotate_rect(r: &Rect, rotation: i32, page: &Rect) -> [f64; 4] {
    let (w, h) = (page.urx, page.ury);
    match rotation {
        90 => [h - r.lly, r.llx, h - r.ury, r.urx],
        180 => [w - r.llx, h - r.lly, w - r.urx, h - r.ury],
        270 => [r.lly, w - r.llx, r.ury, w - r.urx],
        _ => [r.llx, r.lly, r.urx, r.ury],
    }
}

/// Construye la apariencia visible a partir de los parámetros.
struct AppearanceParams {
    text: Option<String>,
    style: TextStyle,
    rubric: Option<PdfImage>,
    rotation: i32,
    legacy: bool,
}

#[allow(clippy::too_many_arguments)]
fn appearance_params(
    xp: &ExtraParams,
    chain: &[Vec<u8>],
    sign_time: &SignTime,
    reason: Option<&str>,
    city: Option<&str>,
    contact: Option<&str>,
    rubric: Option<PdfImage>,
    rotation: i32,
) -> Result<AppearanceParams, AfirmaError> {
    let cert = chain.first().and_then(|c| tokens::CertText::from_der(c));
    let obfuscate = match xp.get(OBFUSCATE_CERT_TEXT) {
        Some(v) => v.trim().eq_ignore_ascii_case("true"),
        None => !cert.as_ref().is_some_and(|c| c.pseudonym_cert),
    };
    let mask = obfuscate.then(|| match xp.get(OBFUSCATION_MASK) {
        Some(m) => tokens::TextMask::parse(m).unwrap_or_else(|e| {
            tracing::warn!("La mascara de ofuscacion no esta bien definida. Se usara la por defecto: {e}");
            tokens::TextMask::default()
        }),
        None => tokens::TextMask::default(),
    });
    let configured = match xp.get(LAYER2_TEXT) {
        Some(t) => Some(t.to_string()),
        None if rubric.is_none() => {
            let mut s = String::from("Firmado por $$SUBJECTCN$$\nFecha: $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$");
            if reason.is_some() {
                s.push_str("\nMotivo: $$REASON$$");
            }
            if city.is_some() {
                s.push_str("\nLugar de firma: $$LOCATION$$");
            }
            Some(s)
        }
        None => None,
    };
    let data = tokens::LayerTextData {
        cert: cert.as_ref(),
        sign_time: Some(*sign_time),
        reason,
        location: city,
        contact,
        mask,
    };
    let text = match configured {
        Some(t) => Some(tokens::layer_text(&t, &data).map_err(|_| {
            AfirmaError::invalid_argument("La etiqueta $$SIGNDATE del texto de la firma visible no esta cerrada")
        })?),
        None => None,
    };
    let int = |k: &str| xp.get(k).and_then(parse_java_int);
    let family = FontFamily::from_param(int(LAYER2_FONT_FAMILY).unwrap_or(0));
    let size = match int(LAYER2_FONT_SIZE) {
        Some(-1) | None => 12.0,
        Some(s) => s as f64,
    };
    let style_bits = match int(LAYER2_FONT_STYLE) {
        Some(-1) | None => 0,
        Some(s) => s,
    };
    let style = TextStyle {
        family,
        size,
        color: color_by_name(xp.get(LAYER2_FONT_COLOR)),
        ..TextStyle::default()
    }
    .with_style_bits(style_bits);
    Ok(AppearanceParams {
        text,
        style,
        rubric,
        rotation,
        legacy: is_true(xp, INCLUDE_QUESTION_MARK),
    })
}

/// Identificador de fichero determinista a partir de los datos de la firma.
fn make_file_id(doc: &PdfDoc, input: &PrepareInput<'_>) -> (Vec<u8>, Vec<u8>) {
    let mut h = Md5::new();
    h.update(DigestAlgorithm::Sha256.digest(&doc.bytes));
    h.update(millis(&input.sign_time).to_be_bytes());
    if let Some(c) = input.chain.first() {
        h.update(c);
    }
    h.update([input.kind as u8]);
    let second = h.finalize().to_vec();
    let first = match doc.file_id() {
        Some((a, _)) => a,
        None => {
            let mut h = Md5::new();
            h.update(b"afirma-pdf/ID0");
            h.update(&second);
            h.finalize().to_vec()
        }
    };
    (first, second)
}

/// Prepara la revisión con la firma (o el sello de documento) vacía.
pub fn prepare(input: &PrepareInput<'_>) -> Result<Prepared, AfirmaError> {
    let xp = input.xp;
    let has_pwd_param = xp.contains(OWNER_PASSWORD) || xp.contains(USER_PASSWORD);

    // 1. Parámetros básicos.
    let do_not_use_chain = is_true(xp, DO_NOT_USE_CERT_CHAIN_ON_POST_SIGN);
    let rotation = match xp.get(SIGNATURE_ROTATION) {
        Some(v) => {
            parse_java_int(v).ok_or_else(|| AfirmaError::invalid_argument(format!("For input string: \"{v}\"")))? as i32
        }
        None => 0,
    };
    let rubric = match (input.kind, xp.get(SIGNATURE_RUBRIC_IMAGE)) {
        (SigKind::Signature, Some(v)) => Some(load_image_param(v, input.secure_mode, "rubrica")?),
        _ => None,
    };
    let reason = xp.get(SIGN_REASON).map(str::to_string);
    let field_name = xp.get(SIGNATURE_FIELD).map(str::to_string);
    let city = xp.get(SIGNATURE_PRODUCTION_CITY).map(str::to_string);
    let contact = xp.get(SIGNER_CONTACT).map(str::to_string);

    // 2-3. Apertura.
    let mut doc = open_pdf(input.pdf, xp)?;
    if doc.encrypted && !doc.owner_access {
        return Err(if has_pwd_param {
            errors::bad_password("La contrasena del PDF es incorrecta")
        } else {
            errors::password_protected("El PDF esta protegido contra modificaciones")
        });
    }
    let (sigs, _) = doc.signatures();
    if doc.broken {
        if !sigs.is_empty() || doc.encrypted {
            return Err(errors::internal(
                "Append mode requires a document without errors even if recovery was possible.",
            ));
        }
        // Documento sin firmas con la tabla de referencias dañada: se
        // reconstruye por completo antes de añadir la firma (como hace Java
        // en la primera firma).
        let rebuilt = rebuild(&doc)?;
        doc = PdfDoc::open(&rebuilt, None).map_err(|_| errors::pdf_needed())?;
    }
    if doc.page_count() == 0 {
        return Err(errors::pdf_needed());
    }

    // 4-6. Subfiltro, certificación, PDF/A.
    let sub_filter = match input.kind {
        SigKind::Signature => sub_filter(xp),
        SigKind::DocTimeStamp => SUBFILTER_RFC3161.to_string(),
    };
    let cert_level = if input.kind == SigKind::Signature {
        certification_level(xp)
    } else {
        0
    };
    let is_pdfa = doc.is_pdfa();

    // 8. Comprobaciones de firmas existentes.
    check_certification(&doc, xp)?;
    if input.kind == SigKind::Signature {
        check_unregistered(&doc, xp)?;
    }

    let mut ed = Edit::new(&doc);
    let sig_id = ed.update.alloc();
    let root_id = doc.root_id().ok_or_else(errors::pdf_needed)?;

    // 9. Eliminación de los derechos de uso (/Perms /UR /UR3).
    remove_usage_rights(&mut ed, root_id);

    // 11. Páginas y posición.
    let visible = input.kind == SigKind::Signature && is_visible(xp);
    let n = doc.page_count();
    let pages = doc.pages();
    let field_name_out;
    let reserved = reserved_size(xp);

    let appearance_info = if visible {
        Some(appearance_params(
            xp,
            input.chain,
            &input.sign_time,
            reason.as_deref(),
            city.as_deref(),
            contact.as_deref(),
            rubric,
            rotation,
        )?)
    } else {
        None
    };

    // Marca visible (imagen sobre el contenido de las páginas).
    if input.kind == SigKind::Signature {
        add_stamp_image(&mut ed, xp, input.secure_mode, &pages)?;
        add_attachment(&mut ed, xp, root_id)?;
    }

    let mut annots_to_add: Vec<(ObjectId, ObjectId)> = Vec::new();
    let mut new_field_ref: Option<ObjectId> = None;
    let frm_for_dr: Option<ObjectId>;

    if let (Some(name), SigKind::Signature) = (&field_name, input.kind) {
        // Campo existente.
        let fields = doc.form_fields();
        let item: FieldItem = fields
            .into_iter()
            .find(|f| &f.name == name)
            .ok_or_else(|| AfirmaError::invalid_argument(format!("The field {name} does not exist.")))?;
        if doc.dict_get_name(&item.merged, b"FT") != Some(b"Sig") {
            return Err(AfirmaError::invalid_argument(format!(
                "The field {name} is not a signature field."
            )));
        }
        field_name_out = name.clone();
        let page_id = pages
            .get(item.page.max(1) - 1)
            .copied()
            .ok_or_else(errors::pdf_needed)?;
        let page_rot = doc.rotation(page_id);
        let r = doc
            .dict_get(&item.merged, b"Rect")
            .and_then(Rect::from_object)
            .unwrap_or_default();
        let (w, h) = if page_rot == 90 || page_rot == 270 {
            (r.height(), r.width())
        } else {
            (r.width(), r.height())
        };
        let ap = appearance_info.as_ref().map(|a| VisibleContent {
            text: a.text.clone(),
            style: a.style,
            rubric: a.rubric.clone(),
            rotation: 0,
            legacy_layers: a.legacy,
        });
        let built = appearance::build(
            &AppearanceSpec {
                width: w,
                height: h,
                page_rotation: page_rot,
                visible: ap,
            },
            &mut ed.update,
        );
        frm_for_dr = built.frm;
        let widget_id = item
            .widget_id
            .ok_or_else(|| errors::internal("El campo de firma no es un objeto indirecto"))?;
        if let Some(vid) = item.value_id
            && let Some(d) = ed.dict_mut(vid)
        {
            d.set("V", Object::Reference(sig_id));
        }
        if let Some(wd) = ed.dict_mut(widget_id) {
            wd.set("P", Object::Reference(page_id));
            let old_f = wd.get(b"F").and_then(Object::as_i64).unwrap_or(0);
            wd.set("F", Object::Integer(old_f | 128));
            let mut apd = Dictionary::new();
            apd.set("N", Object::Reference(built.napp));
            wd.set("AP", Object::Dictionary(apd));
            if item.value_id.is_none() {
                wd.set("V", Object::Reference(sig_id));
            }
        }
    } else {
        // Campo nuevo.
        field_name_out = next_signature_name(&doc);
        let mut sel = pages_for(xp, n);
        let mut rect = position(xp, "signature").filter(|_| visible);
        let mut page_ids: Vec<ObjectId> = Vec::new();
        if sel.append {
            let first = pages[0];
            let size = doc.page_size_with_rotation(first);
            let new_page = append_blank_page(&mut ed, &pages, size.width(), size.height())?;
            page_ids.push(new_page);
            sel.pages = vec![n + 1];
        }
        if let (Some(r), false) = (rect, sel.append) {
            // correctPositionSignature
            sel.pages.retain(|p| {
                let ps = doc.page_size_with_rotation(pages[p - 1]);
                !(ps.urx <= r.llx || ps.ury <= r.lly)
            });
            if sel.pages.is_empty() {
                return Err(errors::invalid_position());
            }
            let ps = doc.page_size_with_rotation(pages[sel.pages[0] - 1]);
            rect = Some(Rect {
                urx: r.urx.min(ps.urx),
                ury: r.ury.min(ps.ury),
                ..r
            });
        }
        if !sel.append {
            page_ids = if visible {
                sel.pages.iter().map(|p| pages[p - 1]).collect()
            } else {
                vec![pages[0]]
            };
        }
        let field_id = ed.update.alloc();
        new_field_ref = Some(field_id);
        // Como iText: un único diccionario campo/widget, con el giro y el
        // rectángulo de la primera página, referenciado desde las anotaciones
        // de todas las páginas seleccionadas.
        let main_page = page_ids[0];
        let (rot, page_box) = if sel.append {
            (0, Rect::new(0.0, 0.0, 0.0, 0.0))
        } else {
            (doc.rotation(main_page), doc.page_size_with_rotation(main_page))
        };
        let spec = match (&rect, &appearance_info) {
            (Some(r), Some(a)) => AppearanceSpec {
                width: r.width(),
                height: r.height(),
                page_rotation: rot,
                visible: Some(VisibleContent {
                    text: a.text.clone(),
                    style: a.style,
                    rubric: a.rubric.clone(),
                    rotation: a.rotation,
                    legacy_layers: a.legacy,
                }),
            },
            _ => AppearanceSpec {
                width: 0.0,
                height: 0.0,
                page_rotation: rot,
                visible: None,
            },
        };
        let built: BuiltAppearance = appearance::build(&spec, &mut ed.update);
        frm_for_dr = built.frm;
        let rect_nums = match &rect {
            Some(r) => unrotate_rect(r, rot, &page_box),
            None => [0.0; 4],
        };
        let mut wd = Dictionary::new();
        wd.set("FT", Object::Name(b"Sig".to_vec()));
        wd.set("T", text_object(&field_name_out));
        wd.set("V", Object::Reference(sig_id));
        wd.set("F", Object::Integer(132));
        wd.set("Type", Object::Name(b"Annot".to_vec()));
        wd.set("Subtype", Object::Name(b"Widget".to_vec()));
        wd.set("Rect", Object::Array(rect_nums.iter().map(|v| num(*v)).collect()));
        let mut apd = Dictionary::new();
        apd.set("N", Object::Reference(built.napp));
        wd.set("AP", Object::Dictionary(apd));
        wd.set("P", Object::Reference(main_page));
        let mut dr = Dictionary::new();
        if let Some(frm) = built.frm {
            let mut x = Dictionary::new();
            x.set("FRM", Object::Reference(frm));
            dr.set("XObject", Object::Dictionary(x));
        }
        wd.set("DR", Object::Dictionary(dr));
        ed.update.put(field_id, Object::Dictionary(wd));
        for &page_id in &page_ids {
            annots_to_add.push((page_id, field_id));
        }
    }

    // Anotaciones de las páginas.
    for (page_id, wid) in &annots_to_add {
        add_annotation(&mut ed, *page_id, *wid);
    }

    // AcroForm.
    update_acroform(&mut ed, root_id, new_field_ref, frm_for_dr);

    // Certificación (DocMDP).
    if cert_level > 0
        && let Some(cat) = ed.dict_mut(root_id)
    {
        let mut perms = Dictionary::new();
        perms.set("DocMDP", Object::Reference(sig_id));
        cat.set("Perms", Object::Dictionary(perms));
    }

    // Versión del documento.
    if let Some(v) = pdf_version(xp) {
        let header_minor = doc.header_version.strip_prefix("1.").and_then(|m| m.parse::<u8>().ok());
        let catalog_minor = doc
            .catalog()
            .and_then(|c| c.get(b"Version").ok())
            .and_then(|o| o.as_name().ok())
            .and_then(|n| std::str::from_utf8(n).ok()?.strip_prefix("1.")?.parse::<u8>().ok());
        let current = header_minor.max(catalog_minor).unwrap_or(7);
        if doc.header_version.starts_with("1.")
            && current < v
            && !is_pdfa
            && let Some(cat) = ed.dict_mut(root_id)
        {
            cat.set("Version", Object::Name(format!("1.{v}").into_bytes()));
        }
    }

    // Info /ModDate.
    let info_id = update_info(&mut ed, &input.sign_time);

    // XMP.
    update_xmp(
        &mut ed,
        root_id,
        &input.sign_time,
        is_pdfa && sigs.is_empty() && !doc.encrypted,
    );

    ed.flush();

    // Diccionario de firma.
    let name = if do_not_use_chain {
        None
    } else {
        input.chain.first().and_then(|c| signer_cn(c))
    };
    let enc = doc.encryption.as_ref();
    let raw = signature_dictionary(SigDictInput {
        kind: input.kind,
        sub_filter: &sub_filter,
        date: &pdf_date(&input.sign_time),
        name: name.as_deref().filter(|_| input.kind == SigKind::Signature),
        reason: reason.as_deref().filter(|_| input.kind == SigKind::Signature),
        location: city.as_deref().filter(|_| input.kind == SigKind::Signature),
        contact: contact.as_deref().filter(|_| input.kind == SigKind::Signature),
        reserved,
        docmdp: (cert_level > 0).then_some((cert_level, root_id)),
        encrypt: enc.map(|s| (s, sig_id)),
    });
    let (raw_bytes, br_rel, contents_rel) = raw;
    ed.update.put_raw(sig_id, raw_bytes);

    let file_id = make_file_id(&doc, input);
    let trailer = TrailerInfo {
        root: Some(root_id),
        info: info_id,
        encrypt: doc.encrypt_ref,
        id: Some(file_id.clone()),
    };
    let kind = match doc.xref_kind {
        XrefKind::Stream => XrefKind::Stream,
        _ => XrefKind::Table,
    };
    let update = std::mem::replace(&mut ed.update, Update::new(1));
    let written = update.write(&doc.bytes, doc.startxref, kind, &trailer, enc, doc.pdf_start);
    let sig_off = *written
        .offsets
        .get(&sig_id.0)
        .ok_or_else(|| errors::internal("No se ha escrito el diccionario de firma"))?;
    let header_len = format!("{} 0 obj\n", sig_id.0).len();
    let br_pos = sig_off + header_len + br_rel;
    let contents_start = sig_off + header_len + contents_rel;
    let contents_end = contents_start + 2 * reserved + 2;
    let mut bytes = written.bytes;
    let total = bytes.len();
    let br = format!("[0 {} {} {} ]", contents_start, contents_end, total - contents_end);
    if br.len() > 80 {
        return Err(errors::internal("El rango de bytes no cabe en el espacio reservado"));
    }
    let slot = &mut bytes[br_pos..br_pos + 80];
    slot.fill(b' ');
    slot[..br.len()].copy_from_slice(br.as_bytes());
    Ok(Prepared {
        bytes,
        contents_start,
        contents_end,
        reserved,
        file_id,
        field_name: field_name_out,
    })
}

fn pages_for(xp: &ExtraParams, n: usize) -> PageSelection {
    pages(xp, n)
}

/// CN del certificado (para `/Name`).
pub fn signer_cn(cert: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;
    let (_, c) = X509Certificate::from_der(cert).ok()?;
    let cn = c.subject().iter_common_name().next()?;
    afirma_core::cert::attr_string(cn.attr_value())
}

struct SigDictInput<'a> {
    kind: SigKind,
    sub_filter: &'a str,
    date: &'a str,
    name: Option<&'a str>,
    reason: Option<&'a str>,
    location: Option<&'a str>,
    contact: Option<&'a str>,
    reserved: usize,
    docmdp: Option<(i64, ObjectId)>,
    encrypt: Option<(&'a lopdf::EncryptionState, ObjectId)>,
}

/// Serializa el diccionario de firma con los huecos de `/ByteRange` (80
/// bytes) y `/Contents` (`2*S+2` bytes). Devuelve los bytes y las
/// posiciones relativas de ambos huecos.
fn signature_dictionary(i: SigDictInput<'_>) -> (Vec<u8>, usize, usize) {
    let enc_str = |s: Vec<u8>| -> Vec<u8> {
        match i.encrypt {
            Some((state, id)) => {
                let mut o = Object::String(s, StringFormat::Literal);
                let _ = lopdf::encryption::encrypt_object(state, id, &mut o);
                match o {
                    Object::String(v, _) => v,
                    _ => Vec::new(),
                }
            }
            None => s,
        }
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"<<");
    match i.kind {
        SigKind::Signature => out.extend_from_slice(b"/Type/Sig"),
        SigKind::DocTimeStamp => out.extend_from_slice(b"/Type/DocTimeStamp"),
    }
    out.extend_from_slice(b"/Filter/Adobe.PPKLite/SubFilter");
    write_name(&mut out, i.sub_filter.as_bytes());
    out.extend_from_slice(b"/M");
    write_literal_string(&mut out, &enc_str(i.date.as_bytes().to_vec()));
    for (key, val) in [
        (b"/Name".as_slice(), i.name),
        (b"/Reason", i.reason),
        (b"/Location", i.location),
        (b"/ContactInfo", i.contact),
    ] {
        if let Some(v) = val {
            out.extend_from_slice(key);
            write_literal_string(&mut out, &enc_str(encode_text_string(v)));
        }
    }
    out.extend_from_slice(b"/ByteRange ");
    let br_rel = out.len();
    let mut placeholder = b"[0 0 0 0 ]".to_vec();
    placeholder.resize(80, b' ');
    out.extend_from_slice(&placeholder);
    out.extend_from_slice(b"/Contents ");
    let contents_rel = out.len();
    out.push(b'<');
    out.extend(std::iter::repeat_n(b'0', 2 * i.reserved));
    out.push(b'>');
    if let Some((level, catalog)) = i.docmdp {
        let mut tp = Dictionary::new();
        tp.set("P", Object::Integer(level));
        tp.set("V", Object::Name(b"1.2".to_vec()));
        tp.set("Type", Object::Name(b"TransformParams".to_vec()));
        let mut r = Dictionary::new();
        r.set("TransformMethod", Object::Name(b"DocMDP".to_vec()));
        r.set("Type", Object::Name(b"SigRef".to_vec()));
        r.set("TransformParams", Object::Dictionary(tp));
        r.set(
            "DigestValue",
            Object::String(enc_str(b"aa".to_vec()), StringFormat::Literal),
        );
        r.set(
            "DigestLocation",
            Object::Array(vec![Object::Integer(0), Object::Integer(0)]),
        );
        r.set("DigestMethod", Object::Name(b"MD5".to_vec()));
        r.set("Data", Object::Reference(catalog));
        out.extend_from_slice(b"/Reference[");
        write_dict(&mut out, &r);
        out.push(b']');
    }
    out.extend_from_slice(b">>");
    (out, br_rel, contents_rel)
}

/// Elimina `/Perms /UR` y `/UR3` (`removeUsageRights`).
fn remove_usage_rights(ed: &mut Edit<'_>, root: ObjectId) {
    let Some(cat) = ed.doc.dict_id(root) else {
        return;
    };
    let Some(perms_obj) = cat.get(b"Perms").ok() else {
        return;
    };
    let Some(perms) = ed.doc.dict(perms_obj) else {
        return;
    };
    if !perms.has(b"UR") && !perms.has(b"UR3") {
        return;
    }
    let mut p = perms.clone();
    p.remove(b"UR");
    p.remove(b"UR3");
    if let Some(c) = ed.dict_mut(root) {
        if p.is_empty() {
            c.remove(b"Perms");
        } else {
            c.set("Perms", Object::Dictionary(p));
        }
    }
}

/// Añade una anotación a la página.
fn add_annotation(ed: &mut Edit<'_>, page: ObjectId, annot: ObjectId) {
    let annots = ed.get(page).and_then(|p| match p {
        Object::Dictionary(d) => d.get(b"Annots").ok().cloned(),
        _ => None,
    });
    match annots {
        Some(Object::Reference(arr_id)) if matches!(ed.get(arr_id), Some(Object::Array(_))) => {
            if let Some(Object::Array(a)) = ed.get_mut(arr_id) {
                a.push(Object::Reference(annot));
            }
        }
        Some(Object::Array(mut a)) => {
            a.push(Object::Reference(annot));
            if let Some(d) = ed.dict_mut(page) {
                d.set("Annots", Object::Array(a));
            }
        }
        _ => {
            if let Some(d) = ed.dict_mut(page) {
                d.set("Annots", Object::Array(vec![Object::Reference(annot)]));
            }
        }
    }
}

/// Añade una página en blanco al final (tamaño y giro de la página 1).
fn append_blank_page(ed: &mut Edit<'_>, pages: &[ObjectId], w: f64, h: f64) -> Result<ObjectId, AfirmaError> {
    let last = *pages.last().ok_or_else(errors::pdf_needed)?;
    let parent = ed
        .doc
        .dict_id(last)
        .and_then(|d| d.get(b"Parent").ok())
        .and_then(|p| p.as_reference().ok())
        .ok_or_else(|| errors::internal("La ultima pagina no tiene padre"))?;
    let mut res = Dictionary::new();
    res.set(
        "ProcSet",
        Object::Array(
            [b"PDF".as_slice(), b"Text", b"ImageB", b"ImageC", b"ImageI"]
                .iter()
                .map(|n| Object::Name(n.to_vec()))
                .collect(),
        ),
    );
    let mut pd = Dictionary::new();
    pd.set("Type", Object::Name(b"Page".to_vec()));
    pd.set("Resources", Object::Dictionary(res));
    pd.set("Rotate", Object::Integer(0));
    pd.set("MediaBox", Object::Array(vec![num(0.0), num(0.0), num(w), num(h)]));
    pd.set("Parent", Object::Reference(parent));
    let new_id = ed.new_editable(Object::Dictionary(pd));
    if let Some(d) = ed.dict_mut(parent)
        && let Ok(Object::Array(kids)) = d.get_mut(b"Kids")
    {
        kids.push(Object::Reference(new_id));
    }
    // Incremento de /Count en todos los ascendientes.
    let mut cur = Some(parent);
    let mut guard = 0;
    while let Some(id) = cur {
        guard += 1;
        if guard > 64 {
            break;
        }
        let next = ed.get(id).and_then(|o| match o {
            Object::Dictionary(d) => d.get(b"Parent").ok().and_then(|p| p.as_reference().ok()),
            _ => None,
        });
        if let Some(d) = ed.dict_mut(id) {
            let c = d.get(b"Count").and_then(Object::as_i64).unwrap_or(0);
            d.set("Count", Object::Integer(c + 1));
        }
        cur = next;
    }
    Ok(new_id)
}

/// Actualiza (o crea) el `/AcroForm`.
fn update_acroform(ed: &mut Edit<'_>, root: ObjectId, field: Option<ObjectId>, frm: Option<ObjectId>) {
    let cat = ed.get(root).and_then(|o| o.as_dict().ok()).cloned().unwrap_or_default();
    match cat.get(b"AcroForm").ok().cloned() {
        None | Some(Object::Null) => {
            let mut af = Dictionary::new();
            af.set(
                "Fields",
                Object::Array(field.map(Object::Reference).into_iter().collect()),
            );
            af.set("SigFlags", Object::Integer(3));
            af.set("DA", Object::String(b"/Helv 0 Tf 0 g ".to_vec(), StringFormat::Literal));
            let mut helv = Dictionary::new();
            helv.set("Type", Object::Name(b"Font".to_vec()));
            helv.set("Subtype", Object::Name(b"Type1".to_vec()));
            helv.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
            helv.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
            helv.set("Name", Object::Name(b"Helv".to_vec()));
            let mut zadb = Dictionary::new();
            zadb.set("Type", Object::Name(b"Font".to_vec()));
            zadb.set("Subtype", Object::Name(b"Type1".to_vec()));
            zadb.set("BaseFont", Object::Name(b"ZapfDingbats".to_vec()));
            zadb.set("Name", Object::Name(b"ZaDb".to_vec()));
            let helv_id = ed.new_obj(Object::Dictionary(helv));
            let zadb_id = ed.new_obj(Object::Dictionary(zadb));
            let mut fonts = Dictionary::new();
            fonts.set("Helv", Object::Reference(helv_id));
            fonts.set("ZaDb", Object::Reference(zadb_id));
            let mut dr = Dictionary::new();
            dr.set("Font", Object::Dictionary(fonts));
            if let Some(f) = frm {
                let mut x = Dictionary::new();
                x.set("FRM", Object::Reference(f));
                dr.set("XObject", Object::Dictionary(x));
            }
            af.set("DR", Object::Dictionary(dr));
            let af_id = ed.new_obj(Object::Dictionary(af));
            if let Some(c) = ed.dict_mut(root) {
                c.set("AcroForm", Object::Reference(af_id));
            }
        }
        Some(af_obj) => {
            let af_id = af_obj.as_reference().ok();
            let mut af = match ed.resolve(&af_obj) {
                Object::Dictionary(d) => d,
                _ => Dictionary::new(),
            };
            af.remove(b"NeedAppearances");
            let flags = ed
                .resolve(af.get(b"SigFlags").unwrap_or(&Object::Null))
                .as_i64()
                .unwrap_or(0);
            af.set("SigFlags", Object::Integer(flags | 3));
            if let Some(f) = field {
                match af.get(b"Fields").ok().cloned() {
                    Some(Object::Reference(arr)) if matches!(ed.get(arr), Some(Object::Array(_))) => {
                        if let Some(Object::Array(a)) = ed.get_mut(arr) {
                            a.push(Object::Reference(f));
                        }
                    }
                    Some(Object::Array(mut a)) => {
                        a.push(Object::Reference(f));
                        af.set("Fields", Object::Array(a));
                    }
                    _ => af.set("Fields", Object::Array(vec![Object::Reference(f)])),
                }
            }
            match af_id {
                Some(id) => {
                    if let Some(o) = ed.get_mut(id) {
                        *o = Object::Dictionary(af);
                    }
                }
                None => {
                    if let Some(c) = ed.dict_mut(root) {
                        c.set("AcroForm", Object::Dictionary(af));
                    }
                }
            }
        }
    }
}

/// Actualiza (o crea) el diccionario `/Info` con `/ModDate`.
fn update_info(ed: &mut Edit<'_>, t: &SignTime) -> Option<ObjectId> {
    let date = Object::String(pdf_date(t).into_bytes(), StringFormat::Literal);
    match ed.doc.info_id() {
        Some(id) if matches!(ed.doc.get(id), Some(Object::Dictionary(_))) => {
            if let Some(d) = ed.dict_mut(id) {
                d.set("ModDate", date);
            }
            Some(id)
        }
        _ => {
            let mut d = Dictionary::new();
            d.set("ModDate", date);
            Some(ed.new_obj(Object::Dictionary(d)))
        }
    }
}

/// Actualiza las fechas del XMP y, en PDF/A sin firmar, añade el historial.
fn update_xmp(ed: &mut Edit<'_>, root: ObjectId, t: &SignTime, add_history: bool) {
    let Some((id, data)) = ed.doc.xmp() else {
        return;
    };
    let Ok(text) = String::from_utf8(data.clone()) else {
        return;
    };
    let mut new_text = crate::xmp::update_dates(&text, t);
    if add_history && let Some(h) = crate::xmp::add_sign_history(&new_text, t) {
        new_text = h;
    }
    if new_text == text {
        return;
    }
    let _ = root;
    let Some(Object::Stream(s)) = ed.doc.get(id) else {
        return;
    };
    let mut dict = s.dict.clone();
    dict.remove(b"Filter");
    dict.remove(b"DecodeParms");
    dict.set("Length", Object::Integer(new_text.len() as i64));
    let stream = lopdf::Stream::new(dict, new_text.into_bytes()).with_compression(false);
    if let Some(o) = ed.get_mut(id) {
        *o = Object::Stream(stream);
    }
}

/// Marca visible: imagen añadida al contenido de las páginas (`image*`).
fn add_stamp_image(
    ed: &mut Edit<'_>,
    xp: &ExtraParams,
    secure_mode: bool,
    pages: &[ObjectId],
) -> Result<(), AfirmaError> {
    let Some(value) = xp.get(IMAGE) else {
        return Ok(());
    };
    let Some(page_param) = xp.get(IMAGE_PAGE) else {
        tracing::warn!("Se ha indicado una imagen sin pagina (imagePage); no se agrega");
        return Ok(());
    };
    let page = parse_java_int(page_param)
        .ok_or_else(|| AfirmaError::msg("No se pudo cargar la imagen para agregarla al PDF"))?;
    let Some(rect) = position(xp, "image") else {
        tracing::warn!("Se ha indicado una imagen sin posicion; no se agrega");
        return Ok(());
    };
    let img = load_image_param(value, secure_mode, "marca")
        .map_err(|_| AfirmaError::msg("No se pudo cargar la imagen para agregarla al PDF"))?;
    let targets: Vec<ObjectId> = match page {
        0 => pages.to_vec(),
        -1 => pages.last().copied().into_iter().collect(),
        p if p >= 1 && (p as usize) <= pages.len() => vec![pages[p as usize - 1]],
        p => {
            return Err(AfirmaError::new(
                afirma_core::error::codes::INVALID_SIGNATURE_PAGE,
                format!("La pagina {p} no existe en el documento"),
            ));
        }
    };
    let img_id = appearance::add_image(&mut ed.update, &img);
    let (w, h, x, y) = (
        (rect.width() as i64) as f64,
        (rect.height() as i64) as f64,
        (rect.llx as i64) as f64,
        (rect.lly as i64) as f64,
    );
    let q_id = ed.new_obj(Object::Stream(flate_stream(Dictionary::new(), b"q\n")));
    for page_id in targets {
        // Recursos efectivos de la página copiados como directos.
        let mut res = match ed.doc.inherited(page_id, b"Resources") {
            Some(Object::Dictionary(d)) => d.clone(),
            _ => Dictionary::new(),
        };
        let mut xobjs = match res.get(b"XObject").ok().map(|o| ed.resolve(o)) {
            Some(Object::Dictionary(d)) => d,
            _ => Dictionary::new(),
        };
        let mut k = 0;
        let name = loop {
            let n = format!("img{k}");
            if !xobjs.has(n.as_bytes()) {
                break n;
            }
            k += 1;
        };
        xobjs.set(name.as_bytes().to_vec(), Object::Reference(img_id));
        res.set("XObject", Object::Dictionary(xobjs));
        // Igual que el contenido "over" de iText: se cierra el `q` inicial y,
        // si la página está girada, se gira el sistema de coordenadas para
        // trabajar sobre la página tal y como se muestra.
        let ps = ed.doc.page_size_with_rotation(page_id);
        let rot = match ed.doc.rotation(page_id) {
            90 => format!("0 1 -1 0 {} 0 cm\n", num_str(ps.ury)),
            180 => format!("-1 0 0 -1 {} {} cm\n", num_str(ps.urx), num_str(ps.ury)),
            270 => format!("0 -1 1 0 0 {} cm\n", num_str(ps.urx)),
            _ => String::new(),
        };
        let content = format!(
            " Q\n{rot}q {} 0 0 {} {} {} cm /{name} Do Q\n",
            num_str(w),
            num_str(h),
            num_str(x),
            num_str(y)
        );
        let c_id = ed.new_obj(Object::Stream(flate_stream(Dictionary::new(), content.as_bytes())));
        let contents = ed
            .get(page_id)
            .and_then(|o| o.as_dict().ok())
            .and_then(|d| d.get(b"Contents").ok().cloned());
        let mut arr = vec![Object::Reference(q_id)];
        match contents.map(|c| (c.clone(), ed.resolve(&c))) {
            Some((_, Object::Array(a))) => arr.extend(a),
            Some((Object::Reference(r), _)) => arr.push(Object::Reference(r)),
            _ => {}
        }
        arr.push(Object::Reference(c_id));
        if let Some(d) = ed.dict_mut(page_id) {
            d.set("Contents", Object::Array(arr));
            d.set("Resources", Object::Dictionary(res));
        }
    }
    Ok(())
}

fn num_str(v: f64) -> String {
    crate::pdf::write::format_number(v)
}

/// Fichero adjunto (`attach`, `attachFileName`, `attachDescription`).
fn add_attachment(ed: &mut Edit<'_>, xp: &ExtraParams, root: ObjectId) -> Result<(), AfirmaError> {
    let (Some(data), Some(file_name)) = (xp.get(ATTACH), xp.get(ATTACH_FILE_NAME)) else {
        return Ok(());
    };
    let Ok(bytes) = afirma_core::base64_decode_lenient(data) else {
        tracing::warn!("El adjunto no esta en Base64; se ignora");
        return Ok(());
    };
    let description = xp.get(ATTACH_DESCRIPTION).unwrap_or("").to_string();
    let mut params = Dictionary::new();
    params.set("Size", Object::Integer(bytes.len() as i64));
    let mut sd = Dictionary::new();
    sd.set("Type", Object::Name(b"EmbeddedFile".to_vec()));
    sd.set("Params", Object::Dictionary(params));
    let ef_id = ed.new_obj(Object::Stream(flate_stream(sd, &bytes)));
    let mut ef = Dictionary::new();
    ef.set("F", Object::Reference(ef_id));
    ef.set("UF", Object::Reference(ef_id));
    let mut fs = Dictionary::new();
    fs.set("Type", Object::Name(b"Filespec".to_vec()));
    fs.set(
        "F",
        Object::String(crate::pdf::text::winansi_encode(file_name), StringFormat::Literal),
    );
    fs.set("UF", text_object(file_name));
    fs.set("EF", Object::Dictionary(ef));
    fs.set("Desc", text_object(&description));
    let fs_id = ed.new_obj(Object::Dictionary(fs));

    // Árbol de nombres /EmbeddedFiles (se lee y se reescribe plano).
    let cat = ed.get(root).and_then(|o| o.as_dict().ok()).cloned().unwrap_or_default();
    let names_obj = cat.get(b"Names").ok().cloned();
    let mut names_dict = match names_obj.as_ref().map(|o| ed.resolve(o)) {
        Some(Object::Dictionary(d)) => d,
        _ => Dictionary::new(),
    };
    let mut entries: Vec<(Vec<u8>, Object)> = Vec::new();
    if let Some(tree) = names_dict.get(b"EmbeddedFiles").ok().map(|o| ed.resolve(o)) {
        collect_name_tree(ed, &tree, &mut entries, 0);
    }
    let base = if description.is_empty() {
        "Unnamed".to_string()
    } else {
        description.clone()
    };
    let mut key = base.clone();
    let mut k = 1;
    while entries.iter().any(|(n, _)| decode_text_string(n) == key) {
        key = format!("{base} {k}");
        k += 1;
    }
    entries.push((encode_text_string(&key), Object::Reference(fs_id)));
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut arr = Vec::new();
    for (n, v) in entries {
        arr.push(Object::String(n, StringFormat::Literal));
        arr.push(v);
    }
    let mut tree = Dictionary::new();
    tree.set("Names", Object::Array(arr));
    let tree_id = ed.new_obj(Object::Dictionary(tree));
    names_dict.set("EmbeddedFiles", Object::Reference(tree_id));
    match names_obj {
        Some(Object::Reference(id)) => {
            if let Some(o) = ed.get_mut(id) {
                *o = Object::Dictionary(names_dict);
            }
        }
        _ => {
            if let Some(c) = ed.dict_mut(root) {
                c.set("Names", Object::Dictionary(names_dict));
            }
        }
    }
    Ok(())
}

fn collect_name_tree(ed: &Edit<'_>, node: &Object, out: &mut Vec<(Vec<u8>, Object)>, depth: usize) {
    if depth > 32 {
        return;
    }
    let Object::Dictionary(d) = node else { return };
    if let Ok(names) = d.get(b"Names")
        && let Object::Array(a) = ed.resolve(names)
    {
        for pair in a.chunks(2) {
            if let [Object::String(n, _), v] = pair {
                out.push((n.clone(), v.clone()));
            }
        }
    }
    if let Ok(kids) = d.get(b"Kids")
        && let Object::Array(a) = ed.resolve(kids)
    {
        for k in a {
            collect_name_tree(ed, &ed.resolve(&k), out, depth + 1);
        }
    }
}

/// Reconstruye un PDF dañado (sin firmas ni cifrado) como un fichero nuevo.
fn rebuild(doc: &PdfDoc) -> Result<Vec<u8>, AfirmaError> {
    let mut d = doc.doc.clone();
    let remove: Vec<ObjectId> = d
        .objects
        .iter()
        .filter(|(_, o)| matches!(o, Object::Stream(s) if s.dict.has_type(b"ObjStm") || s.dict.has_type(b"XRef")))
        .map(|(id, _)| *id)
        .collect();
    for id in remove {
        d.objects.remove(&id);
    }
    d.trailer.remove(b"Prev");
    d.trailer.remove(b"XRefStm");
    let mut out = Vec::new();
    d.save_to(&mut out)
        .map_err(|e| errors::internal(format!("No se ha podido reconstruir el PDF: {e}")))?;
    let _ = out.write_all(b"");
    Ok(out)
}

/// Combina diccionarios (para pruebas internas).
#[allow(dead_code)]
pub(crate) fn merged(a: &Dictionary, b: &Dictionary) -> Dictionary {
    let mut x = a.clone();
    merge_different(&mut x, b);
    x
}
