//! Serialización de objetos PDF (con el mismo formato que iText 2.1.7) y
//! escritura de actualizaciones incrementales.

use std::collections::BTreeMap;
use std::io::Write as _;

use lopdf::{Dictionary, Object, ObjectId, Stream, StringFormat};

use super::parse::XrefKind;

/// Formatea un número real como iText (`ByteBuffer.formatDouble` sin alta
/// precisión): `|d| < 0.000015` → `0`; `|d| < 1` → 5 decimales; `|d| ≤ 32767`
/// → 2 decimales; mayor → entero. Sin ceros finales.
pub fn format_number(d: f64) -> String {
    if !d.is_finite() {
        return "0".into();
    }
    let neg = d < 0.0;
    let a = d.abs();
    if a < 0.000015 {
        return "0".into();
    }
    let s = if a < 1.0 {
        let v = ((a + 0.000005) * 100000.0).floor() as u64;
        if v == 0 {
            return "0".into();
        }
        let s = format!("0.{v:05}");
        trim_zeros(s)
    } else if a <= 32767.0 {
        let v = ((a + 0.005) * 100.0).floor() as u64;
        let s = format!("{}.{:02}", v / 100, v % 100);
        trim_zeros(s)
    } else {
        format!("{}", (a + 0.5).floor() as u64)
    };
    if neg && s != "0" { format!("-{s}") } else { s }
}

fn trim_zeros(s: String) -> String {
    if s.contains('.') {
        let t = s.trim_end_matches('0').trim_end_matches('.');
        if t.is_empty() {
            "0".into()
        } else {
            t.to_string()
        }
    } else {
        s
    }
}

/// Número real como objeto (redondeado como iText).
pub fn num(d: f64) -> Object {
    let s = format_number(d);
    if !s.contains('.') {
        if let Ok(i) = s.parse::<i64>() {
            return Object::Integer(i);
        }
    }
    Object::Real(s.parse::<f32>().unwrap_or(0.0))
}

/// Formatea un real `f32` leído de un documento con la representación más
/// corta que lo identifica (así se conserva el valor original al reescribir
/// un objeto existente).
fn format_f32(f: f32) -> String {
    if !f.is_finite() {
        return "0".into();
    }
    let s = format!("{f}");
    if s == "-0" { "0".into() } else { s }
}

/// Escribe una cadena literal con los escapes de iText.
pub fn write_literal_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'(');
    for &b in bytes {
        match b {
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            8 => out.extend_from_slice(b"\\b"),
            12 => out.extend_from_slice(b"\\f"),
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            _ => out.push(b),
        }
    }
    out.push(b')');
}

/// Escribe un nombre PDF (con `#xx` para los caracteres especiales).
pub fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        if !(0x21..=0x7e).contains(&b)
            || matches!(
                b,
                b'#' | b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
            )
        {
            let _ = write!(out, "#{b:02x}");
        } else {
            out.push(b);
        }
    }
}

fn needs_space(o: &Object) -> bool {
    !matches!(
        o,
        Object::Array(_)
            | Object::Dictionary(_)
            | Object::Name(_)
            | Object::String(..)
            | Object::Stream(_)
    )
}

/// Serializa un objeto directo con el formato de iText (sin espacios antes
/// de nombres, cadenas, matrices y diccionarios).
pub fn write_object(out: &mut Vec<u8>, o: &Object) {
    match o {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Object::Integer(i) => {
            let _ = write!(out, "{i}");
        }
        Object::Real(f) => out.extend_from_slice(format_f32(*f).as_bytes()),
        Object::Name(n) => write_name(out, n),
        Object::String(s, StringFormat::Literal) => write_literal_string(out, s),
        Object::String(s, StringFormat::Hexadecimal) => {
            out.push(b'<');
            out.extend_from_slice(hex::encode(s).as_bytes());
            out.push(b'>');
        }
        Object::Array(items) => {
            out.push(b'[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 && needs_space(it) {
                    out.push(b' ');
                }
                write_object(out, it);
            }
            out.push(b']');
        }
        Object::Dictionary(d) => write_dict(out, d),
        Object::Stream(s) => write_stream(out, s),
        Object::Reference((n, g)) => {
            let _ = write!(out, "{n} {g} R");
        }
    }
}

pub fn write_dict(out: &mut Vec<u8>, d: &Dictionary) {
    out.extend_from_slice(b"<<");
    for (k, v) in d.iter() {
        write_name(out, k);
        if needs_space(v) {
            out.push(b' ');
        }
        write_object(out, v);
    }
    out.extend_from_slice(b">>");
}

fn write_stream(out: &mut Vec<u8>, s: &Stream) {
    let mut dict = s.dict.clone();
    dict.set("Length", Object::Integer(s.content.len() as i64));
    write_dict(out, &dict);
    out.extend_from_slice(b"stream\n");
    out.extend_from_slice(&s.content);
    out.extend_from_slice(b"\nendstream");
}

/// Comprime con Flate (nivel por defecto, como iText).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = enc.write_all(data);
    enc.finish().unwrap_or_default()
}

/// Flujo comprimido con `/FlateDecode`.
pub fn flate_stream(mut dict: Dictionary, data: &[u8]) -> Stream {
    dict.set("Filter", Object::Name(b"FlateDecode".to_vec()));
    let content = deflate(data);
    dict.set("Length", Object::Integer(content.len() as i64));
    Stream::new(dict, content).with_compression(false)
}

/// Contenido de un objeto de la actualización.
#[derive(Debug, Clone)]
pub enum Entry {
    /// Objeto que se serializa (y cifra si el documento está cifrado).
    Obj(Object),
    /// Bytes ya serializados (cuerpo del objeto, sin `N G obj`).
    Raw(Vec<u8>),
}

/// Datos del trailer de la nueva sección.
#[derive(Debug, Clone, Default)]
pub struct TrailerInfo {
    pub root: Option<ObjectId>,
    pub info: Option<ObjectId>,
    pub encrypt: Option<ObjectId>,
    pub id: Option<(Vec<u8>, Vec<u8>)>,
}

/// Actualización incremental en construcción.
#[derive(Debug, Clone)]
pub struct Update {
    next: u32,
    entries: BTreeMap<u32, (u16, Entry)>,
    /// Orden de escritura (por defecto, el de inserción).
    order: Vec<u32>,
}

/// Resultado de escribir la actualización.
pub struct Written {
    pub bytes: Vec<u8>,
    /// Posición de cada objeto escrito.
    pub offsets: BTreeMap<u32, usize>,
}

impl Update {
    /// `first_free`: primer número de objeto libre (el `/Size` anterior).
    pub fn new(first_free: u32) -> Self {
        Update {
            next: first_free.max(1),
            entries: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    /// Reserva un número de objeto nuevo.
    pub fn alloc(&mut self) -> ObjectId {
        let id = (self.next, 0);
        self.next += 1;
        id
    }

    /// Añade o sustituye un objeto.
    pub fn put(&mut self, id: ObjectId, obj: Object) {
        if self.entries.insert(id.0, (id.1, Entry::Obj(obj))).is_none() {
            self.order.push(id.0);
        }
    }

    /// Añade un objeto ya serializado.
    pub fn put_raw(&mut self, id: ObjectId, raw: Vec<u8>) {
        if self.entries.insert(id.0, (id.1, Entry::Raw(raw))).is_none() {
            self.order.push(id.0);
        }
    }

    /// Objeto añadido a la actualización (para modificarlo).
    pub fn get_mut(&mut self, num: u32) -> Option<&mut Object> {
        match self.entries.get_mut(&num) {
            Some((_, Entry::Obj(o))) => Some(o),
            _ => None,
        }
    }

    pub fn contains(&self, num: u32) -> bool {
        self.entries.contains_key(&num)
    }

    /// Siguiente número libre (será el nuevo `/Size`).
    pub fn size(&self) -> u32 {
        let max_entry = self.entries.keys().next_back().map_or(0, |k| k + 1);
        self.next.max(max_entry)
    }

    /// Escribe la actualización a continuación de `base`.
    ///
    /// - `prev`: posición de la sección de referencias cruzadas anterior.
    /// - `kind`: tipo de la sección anterior; se escribe un flujo de
    ///   referencias cruzadas si la anterior lo era (y no era híbrida) y una
    ///   tabla clásica en otro caso, como iText.
    /// - `encrypt`: estado de cifrado para cifrar los objetos nuevos.
    pub fn write(
        mut self,
        base: &[u8],
        prev: Option<usize>,
        kind: XrefKind,
        trailer: &TrailerInfo,
        encrypt: Option<&lopdf::EncryptionState>,
        shift: usize,
    ) -> Written {
        let mut out = Vec::with_capacity(base.len() + 64 * 1024);
        out.extend_from_slice(base);
        out.push(b'\n');
        let mut offsets = BTreeMap::new();
        let order = std::mem::take(&mut self.order);
        for num in order {
            let Some((gen_, entry)) = self.entries.remove(&num) else {
                continue;
            };
            offsets.insert(num, out.len());
            let _ = writeln!(out, "{num} {gen_} obj");
            match entry {
                Entry::Raw(raw) => out.extend_from_slice(&raw),
                Entry::Obj(mut obj) => {
                    if let Some(state) = encrypt {
                        let _ = lopdf::encryption::encrypt_object(state, (num, gen_), &mut obj);
                    }
                    write_object(&mut out, &obj);
                }
            }
            out.extend_from_slice(b"\nendobj\n");
        }
        let size = self
            .next
            .max(offsets.keys().next_back().map_or(0, |k| k + 1));
        let id_obj = trailer.id.as_ref().map(|(a, b)| {
            Object::Array(vec![
                Object::String(a.clone(), StringFormat::Hexadecimal),
                Object::String(b.clone(), StringFormat::Hexadecimal),
            ])
        });
        let xref_pos;
        if kind == XrefKind::Stream {
            // Flujo de referencias cruzadas: /W [1 4 2] (posiciones de hasta 4 GiB).
            let xref_num = size;
            let size = size + 1;
            xref_pos = out.len();
            offsets.insert(xref_num, xref_pos);
            let mut index = Vec::new();
            let mut data = Vec::new();
            let mut nums: Vec<u32> = std::iter::once(0).chain(offsets.keys().copied()).collect();
            nums.dedup();
            let mut i = 0;
            while i < nums.len() {
                let start = nums[i];
                let mut j = i;
                while j + 1 < nums.len() && nums[j + 1] == nums[j] + 1 {
                    j += 1;
                }
                index.push(Object::Integer(i64::from(start)));
                index.push(Object::Integer((j - i + 1) as i64));
                for &n in &nums[i..=j] {
                    if n == 0 {
                        data.extend_from_slice(&[0, 0, 0, 0, 0, 0xff, 0xff]);
                    } else {
                        let off =
                            offsets.get(&n).copied().unwrap_or(0).saturating_sub(shift) as u32;
                        data.push(1);
                        data.extend_from_slice(&off.to_be_bytes());
                        data.extend_from_slice(&[0, 0]);
                    }
                }
                i = j + 1;
            }
            let mut d = Dictionary::new();
            d.set("Type", Object::Name(b"XRef".to_vec()));
            d.set("Size", Object::Integer(i64::from(size)));
            if let Some(r) = trailer.root {
                d.set("Root", Object::Reference(r));
            }
            if let Some(r) = trailer.info {
                d.set("Info", Object::Reference(r));
            }
            if let Some(r) = trailer.encrypt {
                d.set("Encrypt", Object::Reference(r));
            }
            if let Some(id) = &id_obj {
                d.set("ID", id.clone());
            }
            d.set(
                "W",
                Object::Array(vec![
                    Object::Integer(1),
                    Object::Integer(4),
                    Object::Integer(2),
                ]),
            );
            d.set("Index", Object::Array(index));
            if let Some(p) = prev {
                d.set("Prev", Object::Integer(p.saturating_sub(shift) as i64));
            }
            let stream = flate_stream(d, &data);
            let _ = writeln!(out, "{xref_num} 0 obj");
            write_object(&mut out, &Object::Stream(stream));
            out.extend_from_slice(b"\nendobj\n");
        } else {
            xref_pos = out.len();
            out.extend_from_slice(b"xref\n");
            let mut nums: Vec<u32> = std::iter::once(0).chain(offsets.keys().copied()).collect();
            nums.dedup();
            let mut i = 0;
            while i < nums.len() {
                let mut j = i;
                while j + 1 < nums.len() && nums[j + 1] == nums[j] + 1 {
                    j += 1;
                }
                let _ = writeln!(out, "{} {}", nums[i], j - i + 1);
                for &n in &nums[i..=j] {
                    if n == 0 {
                        out.extend_from_slice(b"0000000000 65535 f \n");
                    } else {
                        let _ = writeln!(
                            out,
                            "{:010} {:05} n ",
                            offsets.get(&n).copied().unwrap_or(0).saturating_sub(shift),
                            0
                        );
                    }
                }
                i = j + 1;
            }
            let mut d = Dictionary::new();
            d.set("Size", Object::Integer(i64::from(size)));
            if let Some(r) = trailer.root {
                d.set("Root", Object::Reference(r));
            }
            if let Some(r) = trailer.info {
                d.set("Info", Object::Reference(r));
            }
            if let Some(r) = trailer.encrypt {
                d.set("Encrypt", Object::Reference(r));
            }
            if let Some(id) = &id_obj {
                d.set("ID", id.clone());
            }
            if let Some(p) = prev {
                d.set("Prev", Object::Integer(p.saturating_sub(shift) as i64));
            }
            out.extend_from_slice(b"trailer\n");
            write_dict(&mut out, &d);
            out.push(b'\n');
        }
        let _ = write!(
            out,
            "startxref\n{}\n%%EOF\n",
            xref_pos.saturating_sub(shift)
        );
        Written {
            bytes: out,
            offsets,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_format_matches_itext() {
        assert_eq!(format_number(0.0), "0");
        assert_eq!(format_number(66.0), "66");
        assert_eq!(format_number(189.444), "189.44");
        assert_eq!(format_number(14.56), "14.56");
        assert_eq!(format_number(128.0 / 255.0), "0.50196");
        assert_eq!(format_number(0.21256), "0.21256");
        assert_eq!(format_number(-90.5), "-90.5");
        assert_eq!(format_number(40000.4), "40000");
        assert_eq!(format_number(0.000001), "0");
    }

    #[test]
    fn serializes_like_itext() {
        let mut d = Dictionary::new();
        d.set("Type", Object::Name(b"Sig".to_vec()));
        d.set("F", Object::Integer(132));
        d.set(
            "Rect",
            Object::Array(vec![num(100.0), num(100.0), num(300.0), num(180.5)]),
        );
        d.set(
            "T",
            Object::String(b"Signature1".to_vec(), StringFormat::Literal),
        );
        d.set("P", Object::Reference((9, 0)));
        let mut out = Vec::new();
        write_object(&mut out, &Object::Dictionary(d));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<</Type/Sig/F 132/Rect[100 100 300 180.5]/T(Signature1)/P 9 0 R>>"
        );
    }
}
