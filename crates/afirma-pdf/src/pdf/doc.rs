//! Documento PDF cargado: objetos (con `lopdf`, descifrados si hace falta),
//! información de la última sección de referencias cruzadas, páginas y
//! campos de formulario (con la misma lógica que `AcroFields` de iText).

use std::collections::{BTreeMap, HashSet};

use lopdf::{Dictionary, Document, EncryptionState, LoadOptions, Object, ObjectId};

use super::parse::{self, XrefKind};
use super::text::decode_text_string;

/// Error al abrir un PDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// Los datos no son un PDF legible.
    NotPdf(String),
    /// El PDF está cifrado y no se ha indicado contraseña (o la vacía no vale).
    NeedsPassword,
    /// La contraseña indicada no es correcta.
    BadPassword,
}

/// Rectángulo PDF (normalizado: `llx <= urx`, `lly <= ury`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Rect {
    pub llx: f64,
    pub lly: f64,
    pub urx: f64,
    pub ury: f64,
}

impl Rect {
    pub fn new(llx: f64, lly: f64, urx: f64, ury: f64) -> Self {
        Rect {
            llx: llx.min(urx),
            lly: lly.min(ury),
            urx: llx.max(urx),
            ury: lly.max(ury),
        }
    }
    pub fn width(&self) -> f64 {
        self.urx - self.llx
    }
    pub fn height(&self) -> f64 {
        self.ury - self.lly
    }
    /// Rectángulo girado 90º (intercambia ancho y alto), como
    /// `Rectangle.rotate()` de iText.
    pub fn rotate(&self) -> Rect {
        Rect {
            llx: self.lly,
            lly: self.llx,
            urx: self.ury,
            ury: self.urx,
        }
    }
    pub fn from_object(o: &Object) -> Option<Rect> {
        let a = o.as_array().ok()?;
        if a.len() < 4 {
            return None;
        }
        let v: Vec<f64> = a
            .iter()
            .take(4)
            .map(|x| x.as_float().map(f64::from))
            .collect::<Result<_, _>>()
            .ok()?;
        Some(Rect::new(v[0], v[1], v[2], v[3]))
    }
}

/// Campo de formulario tal y como lo ve `AcroFields` de iText.
#[derive(Debug, Clone)]
pub struct FieldItem {
    /// Nombre completo (`padre.hijo`).
    pub name: String,
    /// Diccionario del campo con `/T` más cercano (el "valor").
    pub value_id: Option<ObjectId>,
    pub value: Dictionary,
    /// Anotación (widget) y su referencia.
    pub widget_id: Option<ObjectId>,
    pub widget: Dictionary,
    /// Diccionario combinado (widget + ascendientes + `/AcroForm`).
    pub merged: Dictionary,
    /// Página (1..N) donde está el widget (0 si no está en ninguna página).
    pub page: usize,
    /// Índice del widget en `/Annots` de la página.
    pub annot_index: usize,
}

/// Firma existente (campo `/FT /Sig` con `/V` que tiene `/Contents` y
/// `/ByteRange`).
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub name: String,
    pub field: FieldItem,
    /// Diccionario de firma (`/V`).
    pub dict: Dictionary,
    pub dict_id: Option<ObjectId>,
    /// Longitud cubierta (suma de los dos últimos valores de `/ByteRange`).
    pub covered: usize,
    /// Revisión (1 = la más antigua).
    pub revision: usize,
    /// Valor de `/Contents` sin descifrar (en los PDF cifrados el valor de
    /// `/Contents` de las firmas no está cifrado, pero `lopdf` lo descifra).
    pub raw_contents: Vec<u8>,
}

impl SignatureEntry {
    pub fn byte_range(&self) -> Vec<i64> {
        self.dict
            .get(b"ByteRange")
            .and_then(Object::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_float().ok().map(|f| f as i64))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn contents(&self) -> Vec<u8> {
        self.raw_contents.clone()
    }
    pub fn sub_filter(&self) -> Option<Vec<u8>> {
        self.dict
            .get(b"SubFilter")
            .and_then(Object::as_name)
            .ok()
            .map(<[u8]>::to_vec)
    }
    pub fn type_name(&self) -> Option<Vec<u8>> {
        self.dict
            .get(b"Type")
            .and_then(Object::as_name)
            .ok()
            .map(<[u8]>::to_vec)
    }
}

/// PDF abierto.
pub struct PdfDoc {
    pub bytes: Vec<u8>,
    pub doc: Document,
    /// Versión de la cabecera (`1.4`...).
    pub header_version: String,
    /// Posición de la última sección de referencias cruzadas.
    pub startxref: Option<usize>,
    pub xref_kind: XrefKind,
    /// Trailer de la última sección (leído directamente de los bytes).
    pub last_trailer: Dictionary,
    /// La estructura de referencias cruzadas está dañada.
    pub broken: bool,
    pub encrypted: bool,
    pub encryption: Option<EncryptionState>,
    pub encrypt_ref: Option<ObjectId>,
    /// Se ha abierto con permisos de propietario (o no está cifrado).
    pub owner_access: bool,
    /// Primer número de objeto libre.
    pub size: u32,
    /// Posición de `%PDF-` (las posiciones de las tablas son relativas a ella).
    pub pdf_start: usize,
}

/// Comprueba la cabecera `%PDF-` al principio de los datos (como
/// `isPdfFile`).
pub fn has_pdf_header(data: &[u8]) -> bool {
    data.len() >= 5 && &data[..5] == b"%PDF-"
}

fn trailer_ref(d: &Dictionary, key: &[u8]) -> Option<ObjectId> {
    d.get(key).and_then(Object::as_reference).ok()
}

/// Busca el último objeto indirecto `num gen obj` en los bytes (para leer
/// el diccionario de cifrado antes de descifrar).
fn scan_object(data: &[u8], id: ObjectId) -> Option<Object> {
    let pat = format!("{} {} obj", id.0, id.1);
    let mut from = 0;
    let mut found = None;
    while let Some(p) = parse::find(data, pat.as_bytes(), from) {
        if p == 0 || parse::is_ws(data[p - 1]) {
            found = Some(p);
        }
        from = p + 1;
    }
    let mut p = parse::Parser::new(data, found?);
    p.object_header()?;
    p.object()
}

impl PdfDoc {
    /// Abre un PDF. `password` es la contraseña indicada (de propietario o
    /// de usuario).
    pub fn open(bytes: &[u8], password: Option<&str>) -> Result<PdfDoc, OpenError> {
        let start = parse::find(bytes, b"%PDF-", 0)
            .filter(|&p| p < 1024)
            .ok_or_else(|| OpenError::NotPdf("no es un PDF".into()))?;
        let header_version: String = bytes[start + 5..]
            .iter()
            .take(8)
            .take_while(|b| b.is_ascii_digit() || **b == b'.')
            .map(|&b| char::from(b))
            .collect();

        let startxref = parse::find_startxref(bytes).map(|(_, v)| v + start);
        let section = startxref.and_then(|o| parse::read_xref_section(bytes, o));
        let mut broken = section.is_none();
        let (xref_kind, last_trailer) = match &section {
            Some(s) => (s.kind, s.trailer.clone()),
            None => (XrefKind::Table, Dictionary::new()),
        };

        let encrypt_ref = trailer_ref(&last_trailer, b"Encrypt");
        let mut owner_access = true;
        let mut encrypted = false;
        let pwd = password.unwrap_or("");
        let doc = if let Some(enc_ref) = encrypt_ref {
            encrypted = true;
            let enc = scan_object(bytes, enc_ref).ok_or_else(|| {
                OpenError::NotPdf("no se encuentra el diccionario de cifrado".into())
            })?;
            if enc
                .as_dict()
                .ok()
                .and_then(|d| d.get(b"Filter").ok())
                .and_then(|f| f.as_name().ok())
                != Some(b"Standard".as_slice())
            {
                // Cifrado con certificado: no se puede abrir con contraseña.
                return Err(if password.is_some() {
                    OpenError::BadPassword
                } else {
                    OpenError::NeedsPassword
                });
            }
            let mut probe = Document::new();
            probe.trailer = last_trailer.clone();
            probe.objects.insert(enc_ref, enc);
            let owner_ok = probe.authenticate_owner_password(pwd).is_ok();
            let user_ok = owner_ok || probe.authenticate_user_password(pwd).is_ok();
            if !user_ok {
                return Err(if password.is_some() {
                    OpenError::BadPassword
                } else {
                    OpenError::NeedsPassword
                });
            }
            owner_access = owner_ok;
            let opts = LoadOptions {
                password: Some(pwd.to_string()),
                ..Default::default()
            };
            Document::load_mem_with_options(bytes, opts)
                .map_err(|e| OpenError::NotPdf(e.to_string()))?
        } else {
            Document::load_mem(bytes).map_err(|e| OpenError::NotPdf(e.to_string()))?
        };
        if encrypted && doc.encryption_state.is_none() {
            return Err(if password.is_some() {
                OpenError::BadPassword
            } else {
                OpenError::NeedsPassword
            });
        }

        // Como iText, solo se considera dañada la estructura si no se puede
        // leer la última sección de referencias cruzadas (las entradas
        // individuales erróneas se toleran).
        if !broken && doc.objects.is_empty() && !encrypted {
            broken = true;
        }

        // Objetos liberados en la sección vigente (lopdf los conservaría).
        let mut doc = doc;
        if let Some(sx) = startxref.filter(|_| !broken) {
            for n in parse::effectively_free_objects(bytes, start, sx) {
                let ids: Vec<ObjectId> = doc
                    .objects
                    .range((n, 0)..=(n, u16::MAX))
                    .map(|(id, _)| *id)
                    .collect();
                for id in ids {
                    doc.objects.remove(&id);
                }
            }
        }
        let max_obj = doc.objects.keys().next_back().map_or(0, |k| k.0);
        let trailer_size = last_trailer
            .get(b"Size")
            .and_then(Object::as_i64)
            .unwrap_or(0)
            .max(0) as u32;
        let size = trailer_size.max(doc.reference_table.size).max(max_obj + 1);
        let encryption = doc.encryption_state.clone();
        Ok(PdfDoc {
            bytes: bytes.to_vec(),
            doc,
            header_version,
            startxref,
            xref_kind,
            last_trailer,
            broken,
            encrypted,
            encryption,
            encrypt_ref,
            owner_access,
            size,
            pdf_start: start,
        })
    }

    // -- Acceso a objetos ----------------------------------------------------

    pub fn get(&self, id: ObjectId) -> Option<&Object> {
        self.doc.objects.get(&id)
    }

    /// Resuelve referencias (hasta 32 saltos).
    pub fn resolve<'a>(&'a self, mut o: &'a Object) -> &'a Object {
        for _ in 0..32 {
            match o {
                Object::Reference(id) => match self.doc.objects.get(id) {
                    Some(x) => o = x,
                    None => return &Object::Null,
                },
                _ => return o,
            }
        }
        &Object::Null
    }

    pub fn dict<'a>(&'a self, o: &'a Object) -> Option<&'a Dictionary> {
        match self.resolve(o) {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    pub fn dict_id(&self, id: ObjectId) -> Option<&Dictionary> {
        match self.doc.objects.get(&id)? {
            Object::Dictionary(d) => Some(d),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    pub fn dict_get<'a>(&'a self, d: &'a Dictionary, key: &[u8]) -> Option<&'a Object> {
        d.get(key)
            .ok()
            .map(|o| self.resolve(o))
            .filter(|o| !matches!(o, Object::Null))
    }

    pub fn dict_get_dict<'a>(&'a self, d: &'a Dictionary, key: &[u8]) -> Option<&'a Dictionary> {
        match self.dict_get(d, key)? {
            Object::Dictionary(x) => Some(x),
            Object::Stream(s) => Some(&s.dict),
            _ => None,
        }
    }

    pub fn dict_get_name<'a>(&'a self, d: &'a Dictionary, key: &[u8]) -> Option<&'a [u8]> {
        self.dict_get(d, key)?.as_name().ok()
    }

    pub fn dict_get_f64(&self, d: &Dictionary, key: &[u8]) -> Option<f64> {
        self.dict_get(d, key)?.as_float().ok().map(f64::from)
    }

    pub fn root_id(&self) -> Option<ObjectId> {
        trailer_ref(&self.last_trailer, b"Root").or_else(|| trailer_ref(&self.doc.trailer, b"Root"))
    }

    pub fn info_id(&self) -> Option<ObjectId> {
        trailer_ref(&self.last_trailer, b"Info").or_else(|| trailer_ref(&self.doc.trailer, b"Info"))
    }

    pub fn catalog(&self) -> Option<&Dictionary> {
        self.dict_id(self.root_id()?)
    }

    /// Primer elemento del `/ID` del trailer.
    pub fn file_id(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let a = self
            .last_trailer
            .get(b"ID")
            .or_else(|_| self.doc.trailer.get(b"ID"))
            .ok()?
            .as_array()
            .ok()?;
        let first = a.first()?.as_str().ok()?.to_vec();
        let second = a
            .get(1)
            .and_then(|o| o.as_str().ok())
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| first.clone());
        Some((first, second))
    }

    // -- Páginas -------------------------------------------------------------

    pub fn pages(&self) -> Vec<ObjectId> {
        self.doc.get_pages().into_values().collect()
    }

    pub fn page_count(&self) -> usize {
        self.doc.get_pages().len()
    }

    /// Atributo heredable de una página (`MediaBox`, `CropBox`, `Rotate`,
    /// `Resources`).
    pub fn inherited(&self, page: ObjectId, key: &[u8]) -> Option<&Object> {
        let mut d = self.dict_id(page)?;
        let mut seen = HashSet::new();
        for _ in 0..64 {
            if let Some(v) = self.dict_get(d, key) {
                return Some(v);
            }
            let parent = d.get(b"Parent").ok()?.as_reference().ok()?;
            if !seen.insert(parent) {
                return None;
            }
            d = self.dict_id(parent)?;
        }
        None
    }

    pub fn media_box(&self, page: ObjectId) -> Rect {
        self.inherited(page, b"MediaBox")
            .and_then(|o| self.rect_of(o))
            .unwrap_or(Rect::new(0.0, 0.0, 595.0, 842.0))
    }

    pub fn crop_box(&self, page: ObjectId) -> Rect {
        self.inherited(page, b"CropBox")
            .and_then(|o| self.rect_of(o))
            .unwrap_or_else(|| self.media_box(page))
    }

    fn rect_of(&self, o: &Object) -> Option<Rect> {
        let a = self.resolve(o).as_array().ok()?;
        if a.len() < 4 {
            return None;
        }
        let mut v = [0f64; 4];
        for (i, x) in a.iter().take(4).enumerate() {
            v[i] = f64::from(self.resolve(x).as_float().ok()?);
        }
        Some(Rect::new(v[0], v[1], v[2], v[3]))
    }

    /// Rotación de la página normalizada a 0, 90, 180 o 270.
    pub fn rotation(&self, page: ObjectId) -> i32 {
        let r = self
            .inherited(page, b"Rotate")
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(0);
        let r = (r % 360 + 360) % 360;
        (r - r % 90) as i32
    }

    /// Tamaño de la página tal y como se muestra (`getPageSizeWithRotation`).
    pub fn page_size_with_rotation(&self, page: ObjectId) -> Rect {
        let mut r = self.media_box(page);
        let mut n = self.rotation(page);
        while n > 0 {
            r = r.rotate();
            n -= 90;
        }
        r
    }

    // -- Formularios -----------------------------------------------------------

    pub fn acroform(&self) -> Option<&Dictionary> {
        let cat = self.catalog()?;
        self.dict_get_dict(cat, b"AcroForm")
    }

    /// Campos del formulario como `AcroFields.fill()` de iText (parcheado):
    /// se recorren los widgets de las páginas y solo se tienen en cuenta los
    /// declarados (ellos o su ascendiente superior) en `/AcroForm /Fields`.
    pub fn form_fields(&self) -> Vec<FieldItem> {
        let mut items: Vec<FieldItem> = Vec::new();
        let Some(top) = self.acroform() else {
            return items;
        };
        let declared: HashSet<u32> = match self
            .dict_get(top, b"Fields")
            .and_then(|o| o.as_array().ok())
        {
            Some(a) if !a.is_empty() => a
                .iter()
                .filter_map(|o| o.as_reference().ok().map(|r| r.0))
                .collect(),
            _ => return items,
        };
        for (pi, page) in self.pages().into_iter().enumerate() {
            let Some(pd) = self.dict_id(page) else {
                continue;
            };
            let Some(annots) = self.dict_get(pd, b"Annots").and_then(|o| o.as_array().ok()) else {
                continue;
            };
            for (ai, a) in annots.iter().enumerate() {
                let Some(annot) = self.dict(a) else { continue };
                if self.dict_get_name(annot, b"Subtype") != Some(b"Widget") {
                    continue;
                }
                let widget_id = a.as_reference().ok();
                let top_parent = self.top_parent_ref(annot);
                let found = widget_id.is_some_and(|w| declared.contains(&w.0))
                    || top_parent.is_some_and(|p| declared.contains(&p.0));
                if !found {
                    continue;
                }
                if !self.check_invalid_value_position(annot) {
                    continue;
                }
                let mut merged = annot.clone();
                let mut name = String::new();
                let mut value: Option<(Option<ObjectId>, Dictionary)> = None;
                let mut last_v: Option<Object> = None;
                let mut cur: Option<(Option<ObjectId>, &Dictionary)> = Some((widget_id, annot));
                let mut guard = 0;
                while let Some((cur_id, d)) = cur {
                    guard += 1;
                    if guard > 64 {
                        break;
                    }
                    if self.dict_get_name(d, b"FT") == Some(b"Sig") && merged.get(b"V").is_ok() {
                        merged.remove(b"V");
                    }
                    merge_different(&mut merged, d);
                    let t = self
                        .dict_get(d, b"T")
                        .and_then(|o| o.as_str().ok())
                        .map(decode_text_string);
                    if let Some(t) = &t {
                        name = format!("{t}.{name}");
                    }
                    if last_v.is_none()
                        && let Ok(v) = d.get(b"V") {
                            last_v = Some(self.resolve(v).clone());
                        }
                    if value.is_none() && t.is_some() {
                        let mut vd = d.clone();
                        if vd.get(b"V").is_err()
                            && let Some(lv) = &last_v {
                                vd.set("V", lv.clone());
                            }
                        value = Some((cur_id, vd));
                    }
                    cur = d.get(b"Parent").ok().and_then(|p| {
                        let id = p.as_reference().ok();
                        self.dict(p).map(|pd| (id, pd))
                    });
                }
                if !name.is_empty() {
                    name.pop();
                }
                merge_different(&mut merged, top);
                let (value_id, value_dict) = value.unwrap_or((widget_id, annot.clone()));
                if items.iter().any(|i| i.name == name) {
                    // Varios widgets del mismo campo: iText los acumula; aquí
                    // se conserva el primero.
                    continue;
                }
                items.push(FieldItem {
                    name,
                    value_id,
                    value: value_dict,
                    widget_id,
                    widget: annot.clone(),
                    merged,
                    page: pi + 1,
                    annot_index: ai,
                });
            }
        }
        // Algunas herramientas generan firmas invisibles sin entrada en las
        // anotaciones de las páginas: se buscan widgets de un solo nivel en
        // `/Fields` si `/SigFlags` tiene el bit 1 (iText).
        let sig_flags = self
            .dict_get(top, b"SigFlags")
            .and_then(|o| o.as_i64().ok())
            .unwrap_or(0);
        if sig_flags & 1 == 1
            && let Some(Object::Array(fields)) = self.dict_get(top, b"Fields") {
                for f in fields {
                    let Some(annot) = self.dict(f) else { continue };
                    if self.dict_get_name(annot, b"Subtype") != Some(b"Widget")
                        || self.dict_get(annot, b"Kids").is_some()
                    {
                        continue;
                    }
                    let Some(t) = self
                        .dict_get(annot, b"T")
                        .and_then(|o| o.as_str().ok())
                        .map(decode_text_string)
                    else {
                        continue;
                    };
                    if items.iter().any(|i| i.name == t) {
                        continue;
                    }
                    let id = f.as_reference().ok();
                    items.push(FieldItem {
                        name: t,
                        value_id: id,
                        value: annot.clone(),
                        widget_id: id,
                        widget: annot.clone(),
                        merged: annot.clone(),
                        page: 0,
                        annot_index: 0,
                    });
                }
            }
        items
    }

    fn top_parent_ref(&self, d: &Dictionary) -> Option<ObjectId> {
        let mut cur = d;
        let mut res = None;
        for _ in 0..32 {
            let Ok(p) = cur.get(b"Parent") else { break };
            if let Ok(r) = p.as_reference() {
                res = Some(r);
            }
            match self.dict(p) {
                Some(pd) => cur = pd,
                None => break,
            }
        }
        res
    }

    fn check_invalid_value_position(&self, target: &Dictionary) -> bool {
        let mut merged = target.clone();
        let mut cur = Some(target);
        let mut guard = 0;
        while let Some(d) = cur {
            guard += 1;
            if guard > 64 {
                break;
            }
            if self.dict_get_name(d, b"FT") == Some(b"Sig") && merged.get(b"V").is_ok() {
                if d.get(b"V").is_err() {
                    return false;
                }
                merged.remove(b"V");
            }
            merge_different(&mut merged, d);
            cur = d.get(b"Parent").ok().and_then(|p| self.dict(p));
        }
        true
    }

    /// Firmas del documento (incluye sellos de documento), ordenadas de la
    /// más reciente a la más antigua, y número total de revisiones.
    pub fn signatures(&self) -> (Vec<SignatureEntry>, usize) {
        let mut sigs = Vec::new();
        for f in self.form_fields() {
            if self.dict_get_name(&f.merged, b"FT") != Some(b"Sig") {
                continue;
            }
            let Some(vref) = f.merged.get(b"V").ok() else {
                continue;
            };
            let dict_id = vref.as_reference().ok();
            let Some(v) = self.dict(vref).cloned() else {
                continue;
            };
            if !matches!(
                v.get(b"Contents").map(|o| self.resolve(o)),
                Ok(Object::String(..))
            ) {
                continue;
            }
            let Some(br) = v
                .get(b"ByteRange")
                .ok()
                .map(|o| self.resolve(o))
                .and_then(|o| o.as_array().ok())
            else {
                continue;
            };
            if br.len() < 2 {
                continue;
            }
            let n = |o: &Object| self.resolve(o).as_float().map(|f| f as i64).unwrap_or(0);
            let covered = (n(&br[br.len() - 1]) + n(&br[br.len() - 2])).max(0) as usize;
            let mut raw_contents = v
                .get(b"Contents")
                .and_then(Object::as_str)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            if self.encrypted && br.len() == 4 {
                // Se toma el valor hexadecimal directamente del fichero.
                let (a, b) = (
                    n(&br[1]).max(0) as usize + self.pdf_start,
                    n(&br[2]).max(0) as usize + self.pdf_start,
                );
                if a < b
                    && b <= self.bytes.len()
                    && self.bytes[a] == b'<'
                    && self.bytes[b - 1] == b'>'
                {
                    let hexs: Vec<u8> = self.bytes[a + 1..b - 1]
                        .iter()
                        .copied()
                        .filter(u8::is_ascii_hexdigit)
                        .collect();
                    if let Ok(h) = hex::decode(if hexs.len() % 2 == 1 {
                        &hexs[..hexs.len() - 1]
                    } else {
                        &hexs[..]
                    }) {
                        raw_contents = h;
                    }
                }
            }
            sigs.push(SignatureEntry {
                name: f.name.clone(),
                field: f,
                dict: v,
                dict_id,
                covered,
                revision: 0,
                raw_contents,
            });
        }
        sigs.sort_by_key(|s| s.covered);
        let total = if sigs.is_empty() {
            0
        } else if sigs.last().is_some_and(|s| s.covered == self.bytes.len()) {
            sigs.len()
        } else {
            sigs.len() + 1
        };
        for (i, s) in sigs.iter_mut().enumerate() {
            s.revision = i + 1;
        }
        sigs.reverse();
        (sigs, total)
    }

    /// Campos de firma vacíos (`getBlankSignatureNames`).
    pub fn blank_signature_fields(&self) -> Vec<FieldItem> {
        let (sigs, _) = self.signatures();
        let names: HashSet<String> = sigs.into_iter().map(|s| s.name).collect();
        self.form_fields()
            .into_iter()
            .filter(|f| {
                self.dict_get_name(&f.merged, b"FT") == Some(b"Sig") && !names.contains(&f.name)
            })
            .collect()
    }

    /// Todos los objetos con un número dado (incluidos los no alcanzables),
    /// como el recorrido de `pdfHasUnregisteredSignatures`.
    pub fn all_objects(&self) -> impl Iterator<Item = (&ObjectId, &Object)> {
        self.doc.objects.iter()
    }

    /// Nivel de certificación del documento (`/Perms /DocMDP /Reference[0]
    /// /TransformParams /P`), 0 si no está certificado.
    pub fn certification_level(&self) -> i64 {
        (|| {
            let cat = self.catalog()?;
            let perms = self.dict_get_dict(cat, b"Perms")?;
            let mdp = self.dict_get_dict(perms, b"DocMDP")?;
            let refs = self.dict_get(mdp, b"Reference")?.as_array().ok()?;
            let r0 = self.dict(refs.first()?)?;
            let tp = self.dict_get_dict(r0, b"TransformParams")?;
            self.dict_get(tp, b"P")?.as_i64().ok()
        })()
        .unwrap_or(0)
    }

    /// Contenido XMP (`/Metadata` del catálogo).
    pub fn xmp(&self) -> Option<(ObjectId, Vec<u8>)> {
        let cat = self.catalog()?;
        let id = cat.get(b"Metadata").ok()?.as_reference().ok()?;
        let s = self.doc.objects.get(&id)?.as_stream().ok()?;
        let data = if s.dict.get(b"Filter").is_ok() {
            s.decompressed_content().ok()?
        } else {
            s.content.clone()
        };
        Some((id, data))
    }

    /// Indica si el documento declara PDF/A-1 en su XMP.
    pub fn is_pdfa1(&self) -> bool {
        self.xmp().is_some_and(|(_, x)| {
            let s: Vec<u8> = x.into_iter().filter(|b| !b.is_ascii_whitespace()).collect();
            parse::find(&s, b"<pdfaid:part>1</pdfaid:part>", 0).is_some()
                || parse::find(&s, b"pdfaid:part=\"1\"", 0).is_some()
        })
    }

    /// Indica si el XMP declara alguna parte PDF/A.
    pub fn is_pdfa(&self) -> bool {
        self.xmp()
            .is_some_and(|(_, x)| parse::find(&x, b"pdfaid:part", 0).is_some())
    }

    /// Mapa de objetos de las páginas (id → índice 1..N).
    pub fn page_index(&self) -> BTreeMap<ObjectId, usize> {
        self.pages()
            .into_iter()
            .enumerate()
            .map(|(i, p)| (p, i + 1))
            .collect()
    }
}

/// Añade a `dst` las claves de `src` que no tiene (`mergeDifferent`).
pub fn merge_different(dst: &mut Dictionary, src: &Dictionary) {
    for (k, v) in src.iter() {
        if !dst.has(k) {
            dst.set(k.clone(), v.clone());
        }
    }
}
