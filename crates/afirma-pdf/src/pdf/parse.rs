//! Analizador mínimo de objetos PDF sobre bytes en bruto.
//!
//! `lopdf` se usa para cargar el documento completo, pero para decidir cómo
//! se escribe la actualización incremental hace falta leer directamente
//! algunas estructuras con sus posiciones exactas: el `startxref` final, el
//! tipo de la última sección de referencias cruzadas (tabla o flujo), su
//! diccionario de *trailer* y el diccionario de cifrado.

use lopdf::{Dictionary, Object, StringFormat};

/// Caracteres de espacio en blanco de PDF.
pub(crate) fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00)
}

/// Delimitadores de PDF.
pub(crate) fn is_delim(b: u8) -> bool {
    matches!(b, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

/// Lector de objetos sobre un búfer.
pub(crate) struct Parser<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], pos: usize) -> Self {
        Parser { data, pos, depth: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Salta espacios y comentarios.
    pub fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if is_ws(b) {
                self.pos += 1;
            } else if b == b'%' {
                while let Some(c) = self.peek() {
                    if c == b'\r' || c == b'\n' {
                        break;
                    }
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    /// Lee una palabra clave o número (secuencia de caracteres regulares).
    pub fn token(&mut self) -> &'a [u8] {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek() {
            if is_ws(b) || is_delim(b) {
                break;
            }
            self.pos += 1;
        }
        &self.data[start..self.pos]
    }

    /// Comprueba (sin consumir) si a continuación viene la palabra clave.
    pub fn at_keyword(&mut self, kw: &[u8]) -> bool {
        self.skip_ws();
        let end = self.pos + kw.len();
        if self.data.get(self.pos..end) != Some(kw) {
            return false;
        }
        self.data.get(end).is_none_or(|&b| is_ws(b) || is_delim(b))
    }

    /// Lee la cabecera `N G obj` y devuelve `(N, G)`.
    pub fn object_header(&mut self) -> Option<(u32, u16)> {
        let save = self.pos;
        let n = parse_uint(self.token());
        let g = parse_uint(self.token());
        let kw = self.token();
        match (n, g, kw) {
            (Some(n), Some(g), b"obj") => Some((u32::try_from(n).ok()?, u16::try_from(g).ok()?)),
            _ => {
                self.pos = save;
                None
            }
        }
    }

    /// Lee un objeto directo (sin flujos).
    pub fn object(&mut self) -> Option<Object> {
        self.skip_ws();
        if self.depth > 64 {
            return None;
        }
        let b = self.peek()?;
        match b {
            b'/' => {
                self.pos += 1;
                Some(Object::Name(self.name_body()))
            }
            b'(' => self.literal_string(),
            b'<' => {
                if self.data.get(self.pos + 1) == Some(&b'<') {
                    self.pos += 2;
                    self.depth += 1;
                    let d = self.dict_body();
                    self.depth -= 1;
                    d.map(Object::Dictionary)
                } else {
                    self.hex_string()
                }
            }
            b'[' => {
                self.pos += 1;
                self.depth += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek()? {
                        b']' => {
                            self.pos += 1;
                            break;
                        }
                        _ => items.push(self.object()?),
                    }
                }
                self.depth -= 1;
                Some(Object::Array(items))
            }
            _ => {
                let save = self.pos;
                let tok = self.token();
                match tok {
                    b"true" => return Some(Object::Boolean(true)),
                    b"false" => return Some(Object::Boolean(false)),
                    b"null" => return Some(Object::Null),
                    _ => {}
                }
                if tok.is_empty() {
                    self.pos = save + 1;
                    return None;
                }
                if let Some(n) = parse_int(tok) {
                    // ¿Referencia indirecta `N G R`?
                    let after = self.pos;
                    let g = self.token();
                    if let Some(g) = parse_uint(g) {
                        let r = self.token();
                        if r == b"R"
                            && let (Ok(n), Ok(g)) = (u32::try_from(n), u16::try_from(g))
                        {
                            return Some(Object::Reference((n, g)));
                        }
                    }
                    self.pos = after;
                    return Some(Object::Integer(n));
                }
                parse_real(tok).map(Object::Real)
            }
        }
    }

    fn name_body(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(b) = self.peek() {
            if is_ws(b) || is_delim(b) {
                break;
            }
            if b == b'#'
                && let Some(h) = self
                    .data
                    .get(self.pos + 1..self.pos + 3)
                    .and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())
            {
                out.push(h);
                self.pos += 3;
                continue;
            }
            out.push(b);
            self.pos += 1;
        }
        out
    }

    fn dict_body(&mut self) -> Option<Dictionary> {
        let mut d = Dictionary::new();
        loop {
            self.skip_ws();
            match self.peek()? {
                b'>' => {
                    if self.data.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        return Some(d);
                    }
                    return None;
                }
                b'/' => {
                    self.pos += 1;
                    let key = self.name_body();
                    let value = self.object()?;
                    d.set(key, value);
                }
                _ => return None,
            }
        }
    }

    fn hex_string(&mut self) -> Option<Object> {
        self.pos += 1;
        let mut digits = Vec::new();
        loop {
            let b = self.peek()?;
            self.pos += 1;
            if b == b'>' {
                break;
            }
            if b.is_ascii_hexdigit() {
                digits.push(b);
            }
        }
        if digits.len() % 2 == 1 {
            digits.push(b'0');
        }
        let bytes = digits
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("00"), 16).unwrap_or(0))
            .collect();
        Some(Object::String(bytes, StringFormat::Hexadecimal))
    }

    fn literal_string(&mut self) -> Option<Object> {
        self.pos += 1;
        let mut out = Vec::new();
        let mut nest = 0usize;
        loop {
            let b = self.peek()?;
            self.pos += 1;
            match b {
                b'(' => {
                    nest += 1;
                    out.push(b);
                }
                b')' => {
                    if nest == 0 {
                        break;
                    }
                    nest -= 1;
                    out.push(b);
                }
                b'\\' => {
                    let e = self.peek()?;
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'\r' => {
                            if self.peek() == Some(b'\n') {
                                self.pos += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut v = u32::from(e - b'0');
                            for _ in 0..2 {
                                match self.peek() {
                                    Some(d @ b'0'..=b'7') => {
                                        v = v * 8 + u32::from(d - b'0');
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push((v & 0xff) as u8);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(b),
            }
        }
        Some(Object::String(out, StringFormat::Literal))
    }
}

pub(crate) fn parse_uint(t: &[u8]) -> Option<u64> {
    if t.is_empty() || !t.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(t).ok()?.parse().ok()
}

pub(crate) fn parse_int(t: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(t).ok()?;
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

pub(crate) fn parse_real(t: &[u8]) -> Option<f32> {
    let s = std::str::from_utf8(t).ok()?;
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+')) {
        return None;
    }
    let s = if s.starts_with('.') || s.starts_with("-.") || s.starts_with("+.") {
        s.replacen('.', "0.", 1)
    } else {
        s.to_string()
    };
    let s = s.trim_end_matches('.');
    s.parse().ok()
}

/// Posición del último `startxref` y su valor.
pub(crate) fn find_startxref(data: &[u8]) -> Option<(usize, usize)> {
    let start = data.len().saturating_sub(4096);
    let tail = &data[start..];
    let idx = rfind(tail, b"startxref")? + start;
    let mut p = Parser::new(data, idx + 9);
    let value = parse_uint(p.token())?;
    Some((idx, usize::try_from(value).ok()?))
}

/// Última aparición de `needle` en `hay`.
pub(crate) fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Primera aparición de `needle` en `hay` a partir de `from`.
pub(crate) fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Tipo de una sección de referencias cruzadas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// Tabla clásica `xref` + `trailer`.
    Table,
    /// Tabla clásica con `/XRefStm` (fichero híbrido).
    Hybrid,
    /// Flujo de referencias cruzadas (`/Type /XRef`).
    Stream,
}

/// Sección de referencias cruzadas leída en una posición.
#[derive(Debug, Clone)]
pub(crate) struct XrefSection {
    pub kind: XrefKind,
    pub trailer: Dictionary,
}

/// Lee la sección de referencias cruzadas que empieza en `offset` (solo el
/// tipo y el diccionario de trailer; las entradas las resuelve `lopdf`).
pub(crate) fn read_xref_section(data: &[u8], offset: usize) -> Option<XrefSection> {
    if offset >= data.len() {
        return None;
    }
    let mut p = Parser::new(data, offset);
    if p.at_keyword(b"xref") {
        p.token();
        // Saltamos las subsecciones hasta `trailer`.
        loop {
            p.skip_ws();
            if p.at_keyword(b"trailer") {
                p.token();
                break;
            }
            let first = parse_uint(p.token())?;
            let count = usize::try_from(parse_uint(p.token())?).ok()?;
            let _ = first;
            for _ in 0..count {
                // Cada entrada: 10 dígitos, 5 dígitos, n|f.
                let off = p.token();
                let gen_ = p.token();
                let kind = p.token();
                if off.is_empty() || gen_.is_empty() || !(kind == b"n" || kind == b"f") {
                    return None;
                }
            }
        }
        let trailer = match p.object()? {
            Object::Dictionary(d) => d,
            _ => return None,
        };
        let kind = if trailer.has(b"XRefStm") {
            XrefKind::Hybrid
        } else {
            XrefKind::Table
        };
        Some(XrefSection { kind, trailer })
    } else {
        p.object_header()?;
        let dict = match p.object()? {
            Object::Dictionary(d) => d,
            _ => return None,
        };
        if dict.get(b"Type").and_then(Object::as_name).ok()? != b"XRef" {
            return None;
        }
        Some(XrefSection {
            kind: XrefKind::Stream,
            trailer: dict,
        })
    }
}

/// Estado efectivo de una entrada de referencias cruzadas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryState {
    InUse,
    Free,
}

fn xref_stream_entries(data: &[u8], offset: usize, dict: &lopdf::Dictionary) -> Option<Vec<(u32, EntryState)>> {
    // Datos del flujo: tras `stream` + EOL, con /Length directo.
    let len = usize::try_from(dict.get(b"Length").ok()?.as_i64().ok()?).ok()?;
    let kw = find(data, b"stream", offset)?;
    let mut start = kw + 6;
    if data.get(start) == Some(&b'\r') {
        start += 1;
    }
    if data.get(start) == Some(&b'\n') {
        start += 1;
    }
    let raw = data.get(start..start + len)?.to_vec();
    let stream = lopdf::Stream::new(dict.clone(), raw);
    let content = if dict.has(b"Filter") {
        stream.decompressed_content().ok()?
    } else {
        stream.content
    };
    let w: Vec<usize> = dict
        .get(b"W")
        .ok()?
        .as_array()
        .ok()?
        .iter()
        .filter_map(|o| o.as_i64().ok().map(|v| v.max(0) as usize))
        .collect();
    if w.len() != 3 {
        return None;
    }
    let size = dict.get(b"Size").ok()?.as_i64().ok()?;
    let index: Vec<i64> = match dict.get(b"Index").ok().and_then(|o| o.as_array().ok()) {
        Some(a) => a.iter().filter_map(|o| o.as_i64().ok()).collect(),
        None => vec![0, size],
    };
    let rec = w[0] + w[1] + w[2];
    if rec == 0 {
        return None;
    }
    let read = |b: &[u8]| b.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
    let mut out = Vec::new();
    let mut pos = 0;
    for pair in index.chunks(2) {
        let (first, count) = (pair[0], *pair.get(1)?);
        for k in 0..count {
            let r = content.get(pos..pos + rec)?;
            pos += rec;
            let t = if w[0] == 0 { 1 } else { read(&r[..w[0]]) };
            let state = if t == 0 { EntryState::Free } else { EntryState::InUse };
            out.push((u32::try_from(first + k).ok()?, state));
        }
    }
    Some(out)
}

/// Recorre la cadena de secciones de referencias cruzadas (de la más nueva
/// a la más antigua) y devuelve los objetos cuya entrada vigente es libre.
/// `lopdf` ignora las entradas libres al combinar secciones, por lo que un
/// objeto liberado en una actualización seguiría visible.
pub(crate) fn effectively_free_objects(data: &[u8], base: usize, startxref: usize) -> std::collections::BTreeSet<u32> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut state: BTreeMap<u32, EntryState> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut next = Some(startxref);
    while let Some(off) = next.take() {
        if !seen.insert(off) || seen.len() > 512 {
            break;
        }
        let mut p = Parser::new(data, off);
        let mut entries: Vec<(u32, EntryState)> = Vec::new();
        let trailer;
        if p.at_keyword(b"xref") {
            p.token();
            loop {
                p.skip_ws();
                if p.at_keyword(b"trailer") {
                    p.token();
                    break;
                }
                let (Some(first), Some(count)) = (parse_uint(p.token()), parse_uint(p.token())) else {
                    break;
                };
                for k in 0..count {
                    let _off = p.token();
                    let _gen = p.token();
                    let kind = p.token();
                    let st = if kind == b"f" {
                        EntryState::Free
                    } else {
                        EntryState::InUse
                    };
                    if let Ok(n) = u32::try_from(first + k) {
                        entries.push((n, st));
                    }
                }
            }
            trailer = match p.object() {
                Some(Object::Dictionary(d)) => d,
                _ => break,
            };
            if let Some(stm) = trailer.get(b"XRefStm").ok().and_then(|o| o.as_i64().ok()) {
                let so = stm as usize + base;
                let mut q = Parser::new(data, so);
                if q.object_header().is_some()
                    && let Some(Object::Dictionary(d)) = q.object()
                    && let Some(e) = xref_stream_entries(data, q.pos, &d)
                {
                    entries.extend(e);
                }
            }
        } else {
            if p.object_header().is_none() {
                break;
            }
            trailer = match p.object() {
                Some(Object::Dictionary(d)) => d,
                _ => break,
            };
            if let Some(e) = xref_stream_entries(data, p.pos, &trailer) {
                entries.extend(e);
            }
        }
        for (n, st) in entries {
            state.entry(n).or_insert(st);
        }
        next = trailer
            .get(b"Prev")
            .ok()
            .and_then(|o| o.as_i64().ok())
            .map(|v| v as usize + base);
    }
    state
        .into_iter()
        .filter(|(n, st)| *n != 0 && *st == EntryState::Free)
        .map(|(n, _)| n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_objects() {
        let data = b"<</Type/Sig/ByteRange [0 10 20 30]/Name(ESPA\\321OL \\(x\\))/H<414>/R 12 0 R/F 1.5/N null>>";
        let mut p = Parser::new(data, 0);
        let o = p.object().unwrap();
        let d = o.as_dict().unwrap();
        assert_eq!(d.get(b"Type").unwrap().as_name().unwrap(), b"Sig");
        assert_eq!(d.get(b"Name").unwrap().as_str().unwrap(), b"ESPA\xd1OL (x)");
        assert_eq!(d.get(b"H").unwrap().as_str().unwrap(), b"A@");
        assert_eq!(d.get(b"R").unwrap().as_reference().unwrap(), (12, 0));
        assert_eq!(d.get(b"ByteRange").unwrap().as_array().unwrap().len(), 4);
        assert!(matches!(d.get(b"F").unwrap(), Object::Real(f) if (*f - 1.5).abs() < 1e-6));
    }

    #[test]
    fn finds_startxref() {
        let data = b"%PDF-1.4\n...\nstartxref\n1234\n%%EOF\n";
        assert_eq!(find_startxref(data).unwrap().1, 1234);
    }
}
