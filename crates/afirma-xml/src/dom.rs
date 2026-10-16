//! DOM XML de solo lectura que conserva prefijos y posiciones.
//!
//! - Los finales de línea se normalizan a `\n` antes de analizar (como exige
//!   XML 1.0), y todas las posiciones se refieren a ese texto normalizado,
//!   accesible con [`Document::source`].
//! - No se resuelven entidades externas (protección XXE) y la expansión de
//!   entidades internas está limitada (protección "billion laughs").

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use encoding_rs::Encoding;

use crate::{Result, XmlError};

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Tamaño máximo del texto resultante de expandir entidades internas.
const MAX_ENTITY_EXPANSION: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub(crate) usize);

/// Atributo de un elemento (las declaraciones `xmlns` no se guardan aquí).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub prefix: Option<String>,
    pub local: String,
    pub ns: Option<String>,
    /// Valor ya normalizado y con referencias expandidas.
    pub value: String,
    /// Posición del atributo completo (`nombre="valor"`) en el texto.
    pub range: Range<usize>,
}

impl Attribute {
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }
}

/// Declaración de espacio de nombres (`prefix == None` es el espacio por defecto).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsDecl {
    pub prefix: Option<String>,
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub prefix: Option<String>,
    pub local: String,
    pub ns: Option<String>,
    pub attrs: Vec<Attribute>,
    pub ns_decls: Vec<NsDecl>,
    /// Posición de la etiqueta de apertura (`<...>` o `<.../>`).
    pub start_tag: Range<usize>,
    /// Posición de la etiqueta de cierre, si no era un elemento vacío `<a/>`.
    pub end_tag: Option<Range<usize>>,
}

impl Element {
    pub fn qname(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }

    /// Valor de un atributo sin espacio de nombres.
    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.ns.is_none() && a.local == local).map(|a| a.value.as_str())
    }

    /// Valor de un atributo con espacio de nombres.
    pub fn attr_ns(&self, ns: &str, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.ns.as_deref() == Some(ns) && a.local == local)
            .map(|a| a.value.as_str())
    }

    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local == local && self.ns.as_deref().unwrap_or("") == ns
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    Document,
    Element(Element),
    Text { text: String, cdata: bool },
    Comment(String),
    Pi { target: String, data: String },
}

#[derive(Debug, Clone)]
struct NodeData {
    kind: NodeKind,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    range: Range<usize>,
}

/// Declaración XML (`<?xml version="1.0" encoding="..."?>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlDecl {
    pub version: String,
    pub encoding: Option<String>,
    pub standalone: Option<String>,
    pub range: Range<usize>,
}

/// Documento XML analizado.
#[derive(Debug, Clone)]
pub struct Document {
    source: String,
    nodes: Vec<NodeData>,
    pub xml_decl: Option<XmlDecl>,
    pub doctype: Option<Range<usize>>,
}

/// Decodifica unos bytes XML según su BOM o su declaración de codificación.
pub fn decode(bytes: &[u8]) -> Result<(String, &'static Encoding)> {
    if let Some((enc, bom_len)) = Encoding::for_bom(bytes) {
        let (text, had_errors) = enc.decode_without_bom_handling(&bytes[bom_len..]);
        if had_errors {
            return Err(XmlError::Encoding(format!("datos no válidos en {}", enc.name())));
        }
        return Ok((text.into_owned(), enc));
    }
    // Sin BOM: la declaración XML está en ASCII.
    let head = &bytes[..bytes.len().min(256)];
    let head_str: String = head.iter().take_while(|&&b| b != b'>').map(|&b| b as char).collect();
    let mut enc = encoding_rs::UTF_8;
    if head_str.starts_with("<?xml") {
        if let Some(label) = pseudo_attr(&head_str, "encoding") {
            enc = Encoding::for_label(label.as_bytes())
                .ok_or_else(|| XmlError::Encoding(label.to_string()))?;
            // ISO-8859-1 se trata como windows-1252 (como en la web), que es un superconjunto.
        }
    }
    let (text, had_errors) = enc.decode_without_bom_handling(bytes);
    if had_errors {
        return Err(XmlError::Encoding(format!("datos no válidos en {}", enc.name())));
    }
    Ok((text.into_owned(), enc))
}

/// Codifica texto en la codificación dada (los caracteres no representables
/// se escriben como referencias numéricas de carácter).
pub fn encode(text: &str, enc: &'static Encoding) -> Vec<u8> {
    if enc == encoding_rs::UTF_8 {
        return text.as_bytes().to_vec();
    }
    if enc == encoding_rs::UTF_16LE || enc == encoding_rs::UTF_16BE {
        let mut out = Vec::with_capacity(text.len() * 2 + 2);
        let le = enc == encoding_rs::UTF_16LE;
        out.extend_from_slice(if le { &[0xff, 0xfe] } else { &[0xfe, 0xff] });
        for u in text.encode_utf16() {
            out.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
        }
        return out;
    }
    let mut out = Vec::with_capacity(text.len());
    let mut encoder = enc.new_encoder();
    let mut buf = vec![0u8; text.len() * 4 + 16];
    let (_, _, written, _) = encoder.encode_from_utf8(text, &mut buf, true);
    out.extend_from_slice(&buf[..written]);
    out
}

fn pseudo_attr<'s>(decl: &'s str, name: &str) -> Option<&'s str> {
    let idx = decl.find(name)?;
    let rest = decl[idx + name.len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(quote)?;
    Some(&rest[..end])
}

/// Normaliza los finales de línea (`\r\n` y `\r` -> `\n`).
pub fn normalize_newlines(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

impl Document {
    /// Analiza un documento a partir de bytes (detectando su codificación).
    pub fn parse_bytes(bytes: &[u8]) -> Result<(Document, &'static Encoding)> {
        let (text, enc) = decode(bytes)?;
        Ok((Document::parse(&text)?, enc))
    }

    /// Analiza un documento a partir de texto.
    pub fn parse(text: &str) -> Result<Document> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let source = normalize_newlines(text);
        Parser::new(source).run()
    }

    /// Texto (normalizado) del documento.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Nodo documento.
    pub fn root(&self) -> NodeId {
        NodeId(0)
    }

    /// Elemento raíz.
    pub fn document_element(&self) -> Option<NodeId> {
        self.children(self.root()).iter().copied().find(|&c| self.element(c).is_some())
    }

    pub fn kind(&self, id: NodeId) -> &NodeKind {
        &self.nodes[id.0].kind
    }

    pub fn element(&self, id: NodeId) -> Option<&Element> {
        match &self.nodes[id.0].kind {
            NodeKind::Element(e) => Some(e),
            _ => None,
        }
    }

    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.nodes[id.0].parent
    }

    pub fn children(&self, id: NodeId) -> &[NodeId] {
        &self.nodes[id.0].children
    }

    /// Posición del nodo completo en [`Document::source`].
    pub fn range(&self, id: NodeId) -> Range<usize> {
        self.nodes[id.0].range.clone()
    }

    /// Texto original del nodo.
    pub fn node_source(&self, id: NodeId) -> &str {
        &self.source[self.range(id)]
    }

    /// Ancestros del nodo (del padre hacia la raíz).
    pub fn ancestors(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        std::iter::successors(self.parent(id), move |&n| self.parent(n))
    }

    /// Descendientes en preorden, incluido el propio nodo.
    pub fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            out.push(n);
            for &c in self.children(n).iter().rev() {
                stack.push(c);
            }
        }
        out
    }

    /// Hijos que son elementos.
    pub fn child_elements(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.children(id).iter().copied().filter(|&c| self.element(c).is_some())
    }

    /// Primer hijo elemento con el espacio de nombres y nombre local dados.
    pub fn find_child(&self, id: NodeId, ns: &str, local: &str) -> Option<NodeId> {
        self.child_elements(id).find(|&c| self.element(c).is_some_and(|e| e.is(ns, local)))
    }

    /// Descendientes (sin incluir el propio nodo) con el nombre dado.
    pub fn find_descendants(&self, id: NodeId, ns: &str, local: &str) -> Vec<NodeId> {
        self.descendants(id)
            .into_iter()
            .skip(1)
            .filter(|&n| self.element(n).is_some_and(|e| e.is(ns, local)))
            .collect()
    }

    /// Busca un elemento por su atributo identificador (`Id`, `ID`, `id` o `xml:id`).
    pub fn find_by_id(&self, value: &str) -> Option<NodeId> {
        self.descendants(self.root()).into_iter().find(|&n| {
            self.element(n).is_some_and(|e| {
                e.attrs.iter().any(|a| {
                    a.value == value
                        && ((a.ns.is_none() && matches!(a.local.as_str(), "Id" | "ID" | "id"))
                            || (a.ns.as_deref() == Some(XML_NS) && a.local == "id"))
                })
            })
        })
    }

    /// Concatenación de todo el texto descendiente.
    pub fn text_content(&self, id: NodeId) -> String {
        let mut out = String::new();
        for n in self.descendants(id) {
            if let NodeKind::Text { text, .. } = self.kind(n) {
                out.push_str(text);
            }
        }
        out
    }

    /// Espacios de nombres en ámbito para un elemento (clave `""` = por
    /// defecto). No incluye el prefijo `xml`.
    pub fn in_scope_namespaces(&self, id: NodeId) -> BTreeMap<String, String> {
        let mut chain: Vec<NodeId> = self.ancestors(id).collect();
        chain.reverse();
        chain.push(id);
        let mut map = BTreeMap::new();
        for n in chain {
            if let Some(e) = self.element(n) {
                for d in &e.ns_decls {
                    let key = d.prefix.clone().unwrap_or_default();
                    if d.uri.is_empty() {
                        map.remove(&key);
                    } else {
                        map.insert(key, d.uri.clone());
                    }
                }
            }
        }
        map
    }

    /// Resuelve un prefijo (`None` = espacio por defecto) en el ámbito de un nodo.
    pub fn lookup_namespace(&self, id: NodeId, prefix: Option<&str>) -> Option<String> {
        if prefix == Some("xml") {
            return Some(XML_NS.to_string());
        }
        self.in_scope_namespaces(id).remove(prefix.unwrap_or(""))
    }

    /// Busca un prefijo declarado para un espacio de nombres en el ámbito de un
    /// nodo (`Some("")` si es el espacio por defecto).
    pub fn lookup_prefix(&self, id: NodeId, uri: &str) -> Option<String> {
        let scope = self.in_scope_namespaces(id);
        // Preferimos prefijos explícitos sobre el espacio por defecto.
        scope
            .iter()
            .filter(|(p, u)| u.as_str() == uri && !p.is_empty())
            .map(|(p, _)| p.clone())
            .next()
            .or_else(|| scope.get("").filter(|u| u.as_str() == uri).map(|_| String::new()))
    }
}

struct Parser {
    s: String,
    pos: usize,
    entities: HashMap<String, String>,
    nodes: Vec<NodeData>,
    stack: Vec<NodeId>,
    scopes: Vec<HashMap<String, Option<String>>>,
    xml_decl: Option<XmlDecl>,
    doctype: Option<Range<usize>>,
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_name_delim(c: u8) -> bool {
    is_ws(c) || matches!(c, b'/' | b'>' | b'=' | b'<' | b'"' | b'\'' | b'[' | b']' | b';' | b'&' | b'?')
}

impl Parser {
    fn new(s: String) -> Self {
        Parser {
            s,
            pos: 0,
            entities: HashMap::new(),
            nodes: vec![NodeData { kind: NodeKind::Document, parent: None, children: vec![], range: 0..0 }],
            stack: vec![NodeId(0)],
            scopes: vec![HashMap::new()],
            xml_decl: None,
            doctype: None,
        }
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T> {
        Err(XmlError::Malformed { pos: self.pos, msg: msg.into() })
    }

    fn bytes(&self) -> &[u8] {
        self.s.as_bytes()
    }

    fn starts_with(&self, p: &str) -> bool {
        self.s[self.pos..].starts_with(p)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && is_ws(self.bytes()[self.pos]) {
            self.pos += 1;
        }
    }

    fn find_from(&self, pat: &str) -> Option<usize> {
        self.s[self.pos..].find(pat).map(|i| self.pos + i)
    }

    fn read_name(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.s.len() && !is_name_delim(self.bytes()[self.pos]) {
            self.pos += 1;
        }
        if start == self.pos {
            return self.err("se esperaba un nombre");
        }
        // No cortar en medio de un carácter UTF-8 (los delimitadores son ASCII).
        Ok(self.s[start..self.pos].to_string())
    }

    fn add_node(&mut self, kind: NodeKind, range: Range<usize>) -> NodeId {
        let id = NodeId(self.nodes.len());
        let parent = *self.stack.last().expect("pila no vacía");
        self.nodes.push(NodeData { kind, parent: Some(parent), children: vec![], range });
        self.nodes[parent.0].children.push(id);
        id
    }

    fn in_root(&self) -> bool {
        self.stack.len() > 1
    }

    fn run(mut self) -> Result<Document> {
        if self.starts_with("<?xml") && self.s.len() > 5 && is_ws(self.bytes()[5]) {
            let end = match self.find_from("?>") {
                Some(e) => e + 2,
                None => return self.err("declaración XML sin cerrar"),
            };
            let decl = &self.s[self.pos..end];
            self.xml_decl = Some(XmlDecl {
                version: pseudo_attr(decl, "version").unwrap_or("1.0").to_string(),
                encoding: pseudo_attr(decl, "encoding").map(str::to_string),
                standalone: pseudo_attr(decl, "standalone").map(str::to_string),
                range: self.pos..end,
            });
            self.pos = end;
        }
        let mut seen_root = false;
        while self.pos < self.s.len() {
            if self.bytes()[self.pos] == b'<' {
                if self.starts_with("<!--") {
                    self.parse_comment()?;
                } else if self.starts_with("<![CDATA[") {
                    if !self.in_root() {
                        return self.err("sección CDATA fuera del elemento raíz");
                    }
                    self.parse_cdata()?;
                } else if self.starts_with("<!DOCTYPE") {
                    if seen_root || self.doctype.is_some() {
                        return self.err("DOCTYPE en posición no válida");
                    }
                    self.parse_doctype()?;
                } else if self.starts_with("<?") {
                    self.parse_pi()?;
                } else if self.starts_with("</") {
                    self.parse_end_tag()?;
                } else {
                    if !self.in_root() {
                        if seen_root {
                            return self.err("más de un elemento raíz");
                        }
                        seen_root = true;
                    }
                    self.parse_start_tag()?;
                }
            } else {
                self.parse_text()?;
            }
        }
        if self.in_root() {
            return self.err("documento incompleto: elementos sin cerrar");
        }
        if !seen_root {
            return self.err("el documento no tiene elemento raíz");
        }
        let len = self.s.len();
        self.nodes[0].range = 0..len;
        Ok(Document { source: self.s, nodes: self.nodes, xml_decl: self.xml_decl, doctype: self.doctype })
    }

    fn parse_comment(&mut self) -> Result<()> {
        let start = self.pos;
        let end = match self.s[start + 4..].find("-->") {
            Some(i) => start + 4 + i,
            None => return self.err("comentario sin cerrar"),
        };
        let text = self.s[start + 4..end].to_string();
        self.pos = end + 3;
        self.add_node(NodeKind::Comment(text), start..self.pos);
        Ok(())
    }

    fn parse_cdata(&mut self) -> Result<()> {
        let start = self.pos;
        let end = match self.s[start + 9..].find("]]>") {
            Some(i) => start + 9 + i,
            None => return self.err("sección CDATA sin cerrar"),
        };
        let text = self.s[start + 9..end].to_string();
        self.pos = end + 3;
        self.add_node(NodeKind::Text { text, cdata: true }, start..self.pos);
        Ok(())
    }

    fn parse_pi(&mut self) -> Result<()> {
        let start = self.pos;
        self.pos += 2;
        let target = self.read_name()?;
        if target.eq_ignore_ascii_case("xml") {
            return self.err("declaración XML en posición no válida");
        }
        let end = match self.find_from("?>") {
            Some(e) => e,
            None => return self.err("instrucción de proceso sin cerrar"),
        };
        let data = self.s[self.pos..end].trim_start_matches([' ', '\t', '\n']).to_string();
        self.pos = end + 2;
        self.add_node(NodeKind::Pi { target, data }, start..self.pos);
        Ok(())
    }

    fn parse_doctype(&mut self) -> Result<()> {
        let start = self.pos;
        self.pos += "<!DOCTYPE".len();
        let mut in_subset = false;
        while self.pos < self.s.len() {
            let c = self.bytes()[self.pos];
            match c {
                b'"' | b'\'' => {
                    let q = c as char;
                    match self.s[self.pos + 1..].find(q) {
                        Some(i) => self.pos += i + 2,
                        None => return self.err("literal sin cerrar en DOCTYPE"),
                    }
                }
                b'[' => {
                    in_subset = true;
                    self.pos += 1;
                }
                b']' => {
                    in_subset = false;
                    self.pos += 1;
                }
                b'<' if in_subset => {
                    if self.starts_with("<!--") {
                        match self.find_from("-->") {
                            Some(e) => self.pos = e + 3,
                            None => return self.err("comentario sin cerrar en DOCTYPE"),
                        }
                    } else if self.starts_with("<!ENTITY") {
                        self.parse_entity_decl()?;
                    } else {
                        // Otras declaraciones (ELEMENT, ATTLIST, NOTATION, PI): se ignoran.
                        self.skip_markup_decl()?;
                    }
                }
                b'>' if !in_subset => {
                    self.pos += 1;
                    self.doctype = Some(start..self.pos);
                    return Ok(());
                }
                _ => self.pos += 1,
            }
        }
        self.err("DOCTYPE sin cerrar")
    }

    fn skip_markup_decl(&mut self) -> Result<()> {
        while self.pos < self.s.len() {
            let c = self.bytes()[self.pos];
            match c {
                b'"' | b'\'' => {
                    let q = c as char;
                    match self.s[self.pos + 1..].find(q) {
                        Some(i) => self.pos += i + 2,
                        None => return self.err("literal sin cerrar"),
                    }
                }
                b'>' => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => self.pos += 1,
            }
        }
        self.err("declaración sin cerrar en DOCTYPE")
    }

    fn parse_entity_decl(&mut self) -> Result<()> {
        self.pos += "<!ENTITY".len();
        self.skip_ws();
        let parameter = if self.bytes().get(self.pos) == Some(&b'%') {
            self.pos += 1;
            self.skip_ws();
            true
        } else {
            false
        };
        let name = self.read_name()?;
        self.skip_ws();
        let c = self.bytes().get(self.pos).copied();
        if matches!(c, Some(b'"') | Some(b'\'')) {
            let q = c.unwrap() as char;
            let end = match self.s[self.pos + 1..].find(q) {
                Some(i) => self.pos + 1 + i,
                None => return self.err("valor de entidad sin cerrar"),
            };
            let value = self.s[self.pos + 1..end].to_string();
            self.pos = end + 1;
            if !parameter && !self.entities.contains_key(&name) {
                self.entities.insert(name, value);
            }
        }
        // Entidades externas (SYSTEM/PUBLIC): no se resuelven nunca.
        self.skip_markup_decl()
    }

    fn parse_text(&mut self) -> Result<()> {
        let start = self.pos;
        let end = self.find_from("<").unwrap_or(self.s.len());
        self.pos = end;
        let raw = &self.s[start..end];
        if !self.in_root() {
            if raw.trim_matches([' ', '\t', '\n', '\r']).is_empty() {
                return Ok(());
            }
            return self.err("texto fuera del elemento raíz");
        }
        let text = self.expand(raw, false, 0, &mut 0)?;
        if raw.contains("]]>") {
            return self.err("']]>' no permitido en texto");
        }
        self.add_node(NodeKind::Text { text, cdata: false }, start..end);
        Ok(())
    }

    /// Expande referencias de entidad y de carácter. En atributos se aplica
    /// además la normalización de espacios en blanco de XML 1.0.
    fn expand(&self, raw: &str, attr: bool, depth: usize, budget: &mut usize) -> Result<String> {
        if depth > 8 {
            return self.err("anidamiento de entidades excesivo");
        }
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(i) = rest.find(|c: char| c == '&' || (attr && matches!(c, '\t' | '\n' | '\r'))) {
            out.push_str(&rest[..i]);
            let c = rest.as_bytes()[i];
            if c != b'&' {
                out.push(' ');
                rest = &rest[i + 1..];
                continue;
            }
            let semi = match rest[i..].find(';') {
                Some(s) => i + s,
                None => return self.err("referencia sin ';'"),
            };
            let name = &rest[i + 1..semi];
            if let Some(num) = name.strip_prefix('#') {
                let cp = if let Some(hex) = num.strip_prefix('x') {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    num.parse::<u32>().ok()
                };
                match cp.and_then(char::from_u32) {
                    Some(ch) => out.push(ch),
                    None => return self.err(format!("referencia de carácter no válida: &{name};")),
                }
            } else {
                match name {
                    "lt" => out.push('<'),
                    "gt" => out.push('>'),
                    "amp" => out.push('&'),
                    "apos" => out.push('\''),
                    "quot" => out.push('"'),
                    _ => {
                        let value = match self.entities.get(name) {
                            Some(v) => v,
                            None => return self.err(format!("entidad no declarada: &{name};")),
                        };
                        if value.contains('<') {
                            return self.err(format!("la entidad &{name}; contiene marcado (no soportado)"));
                        }
                        let expanded = self.expand(value, attr, depth + 1, budget)?;
                        *budget += expanded.len();
                        if *budget > MAX_ENTITY_EXPANSION {
                            return self.err("expansión de entidades excesiva");
                        }
                        out.push_str(&expanded);
                    }
                }
            }
            rest = &rest[semi + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    fn resolve(&self, prefix: Option<&str>, is_attr: bool) -> Result<Option<String>> {
        match prefix {
            Some("xml") => Ok(Some(XML_NS.to_string())),
            Some(p) => {
                for scope in self.scopes.iter().rev() {
                    if let Some(v) = scope.get(p) {
                        return match v {
                            Some(uri) => Ok(Some(uri.clone())),
                            None => Err(XmlError::UndeclaredPrefix(p.to_string())),
                        };
                    }
                }
                Err(XmlError::UndeclaredPrefix(p.to_string()))
            }
            None if is_attr => Ok(None),
            None => {
                for scope in self.scopes.iter().rev() {
                    if let Some(v) = scope.get("") {
                        return Ok(v.clone());
                    }
                }
                Ok(None)
            }
        }
    }

    fn parse_start_tag(&mut self) -> Result<()> {
        let start = self.pos;
        self.pos += 1;
        let qname = self.read_name()?;
        let mut raw_attrs: Vec<(String, String, Range<usize>)> = Vec::new();
        let empty;
        loop {
            self.skip_ws();
            match self.bytes().get(self.pos) {
                Some(b'>') => {
                    self.pos += 1;
                    empty = false;
                    break;
                }
                Some(b'/') if self.bytes().get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    empty = true;
                    break;
                }
                None => return self.err("etiqueta sin cerrar"),
                _ => {}
            }
            let astart = self.pos;
            let name = self.read_name()?;
            self.skip_ws();
            if self.bytes().get(self.pos) != Some(&b'=') {
                return self.err(format!("se esperaba '=' tras el atributo {name}"));
            }
            self.pos += 1;
            self.skip_ws();
            let q = match self.bytes().get(self.pos) {
                Some(&c @ (b'"' | b'\'')) => c as char,
                _ => return self.err("valor de atributo sin comillas"),
            };
            let vend = match self.s[self.pos + 1..].find(q) {
                Some(i) => self.pos + 1 + i,
                None => return self.err("valor de atributo sin cerrar"),
            };
            let raw_value = self.s[self.pos + 1..vend].to_string();
            if raw_value.contains('<') {
                return self.err("'<' no permitido en valores de atributo");
            }
            self.pos = vend + 1;
            if raw_attrs.iter().any(|(n, _, _)| *n == name) {
                return self.err(format!("atributo duplicado: {name}"));
            }
            raw_attrs.push((name, raw_value, astart..self.pos));
        }

        // Declaraciones de espacios de nombres.
        let mut scope: HashMap<String, Option<String>> = HashMap::new();
        let mut ns_decls = Vec::new();
        for (name, raw_value, _) in &raw_attrs {
            let value = self.expand(raw_value, true, 0, &mut 0)?;
            if name == "xmlns" {
                scope.insert(String::new(), if value.is_empty() { None } else { Some(value.clone()) });
                ns_decls.push(NsDecl { prefix: None, uri: value });
            } else if let Some(p) = name.strip_prefix("xmlns:") {
                if value.is_empty() {
                    return self.err(format!("el prefijo {p} no puede declararse vacío"));
                }
                scope.insert(p.to_string(), Some(value.clone()));
                ns_decls.push(NsDecl { prefix: Some(p.to_string()), uri: value });
            }
        }
        self.scopes.push(scope);

        let split = |q: &str| -> (Option<String>, String) {
            match q.split_once(':') {
                Some((p, l)) => (Some(p.to_string()), l.to_string()),
                None => (None, q.to_string()),
            }
        };
        let (prefix, local) = split(&qname);
        let ns = self.resolve(prefix.as_deref(), false)?;
        let mut attrs = Vec::new();
        for (name, raw_value, range) in raw_attrs {
            if name == "xmlns" || name.starts_with("xmlns:") {
                continue;
            }
            let (ap, al) = split(&name);
            let ans = self.resolve(ap.as_deref(), true)?;
            if attrs.iter().any(|a: &Attribute| a.local == al && a.ns == ans) {
                return self.err(format!("atributo duplicado: {name}"));
            }
            let value = self.expand(&raw_value, true, 0, &mut 0)?;
            attrs.push(Attribute { prefix: ap, local: al, ns: ans, value, range });
        }
        let element = Element {
            prefix,
            local,
            ns,
            attrs,
            ns_decls,
            start_tag: start..self.pos,
            end_tag: None,
        };
        let id = self.add_node(NodeKind::Element(element), start..self.pos);
        if empty {
            self.scopes.pop();
        } else {
            self.stack.push(id);
        }
        Ok(())
    }

    fn parse_end_tag(&mut self) -> Result<()> {
        let start = self.pos;
        self.pos += 2;
        let name = self.read_name()?;
        self.skip_ws();
        if self.bytes().get(self.pos) != Some(&b'>') {
            return self.err("etiqueta de cierre mal formada");
        }
        self.pos += 1;
        if !self.in_root() {
            return self.err(format!("etiqueta de cierre sin apertura: {name}"));
        }
        let id = self.stack.pop().expect("pila no vacía");
        self.scopes.pop();
        let pos = self.pos;
        let node = &mut self.nodes[id.0];
        if let NodeKind::Element(e) = &mut node.kind {
            if e.qname() != name {
                let expected = e.qname();
                return Err(XmlError::Malformed {
                    pos: start,
                    msg: format!("se esperaba </{expected}> y se encontró </{name}>"),
                });
            }
            e.end_tag = Some(start..pos);
        }
        node.range.end = pos;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_with_positions_and_prefixes() {
        let src = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<!-- c -->\n<a:root xmlns:a=\"urn:a\" xmlns=\"urn:d\" x='1&amp;2'>\n  <child a:attr=\"v&#x9;w\tz\">t&lt;x<![CDATA[<raw>]]></child><e/>\n</a:root>";
        let doc = Document::parse(src).unwrap();
        assert!(!doc.source().contains('\r'));
        let root = doc.document_element().unwrap();
        let e = doc.element(root).unwrap();
        assert_eq!(e.qname(), "a:root");
        assert_eq!(e.ns.as_deref(), Some("urn:a"));
        assert_eq!(e.attr("x"), Some("1&2"));
        let child = doc.find_child(root, "urn:d", "child").unwrap();
        let ce = doc.element(child).unwrap();
        assert_eq!(ce.attr_ns("urn:a", "attr"), Some("v\tw z"));
        assert_eq!(doc.text_content(child), "t<x<raw>");
        assert_eq!(doc.node_source(child), "<child a:attr=\"v&#x9;w\tz\">t&lt;x<![CDATA[<raw>]]></child>");
        let ns = doc.in_scope_namespaces(child);
        assert_eq!(ns.get("a").map(String::as_str), Some("urn:a"));
        assert_eq!(ns.get("").map(String::as_str), Some("urn:d"));
        assert_eq!(doc.lookup_prefix(child, "urn:a").as_deref(), Some("a"));
    }

    #[test]
    fn internal_entities_and_limits() {
        let doc = Document::parse("<!DOCTYPE r [<!ENTITY e \"hola &amp; adios\">]><r>&e;</r>").unwrap();
        assert_eq!(doc.text_content(doc.document_element().unwrap()), "hola & adios");
        let bomb = "<!DOCTYPE r [<!ENTITY a \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\">\
<!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\"><!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\">\
<!ENTITY e \"&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;\"><!ENTITY f \"&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;\">]><r>&f;</r>";
        assert!(Document::parse(bomb).is_err());
        assert!(Document::parse("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>").is_err());
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["<a>", "<a></b>", "<a x='1' x='2'/>", "<p:a/>", "<a/><b/>", "text<a/>", "<a>&nope;</a>"] {
            assert!(Document::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn latin1_roundtrip() {
        let bytes = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>Espa\xf1a</r>";
        let (doc, enc) = Document::parse_bytes(bytes).unwrap();
        assert_eq!(doc.text_content(doc.document_element().unwrap()), "España");
        assert_eq!(encode(doc.source(), enc), bytes.to_vec());
    }
}
