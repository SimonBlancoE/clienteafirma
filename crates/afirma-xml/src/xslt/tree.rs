//! Árboles de la transformación: el documento de entrada y los fragmentos de
//! árbol de resultado, en un único [`Document`] con varios árboles.
//!
//! Cada nodo lleva el identificador (`handle`) que le daría el DTM de XSLTC,
//! que es lo que devuelve `generate-id()` (`"N" + handle`) y lo que desempata
//! las ordenaciones: el documento de entrada es el DTM 1 y cada fragmento
//! ocupa el siguiente; dentro de un DTM se numeran en orden de documento el
//! nodo raíz, cada elemento seguido de sus declaraciones de espacios de
//! nombres (el prefijo `xml` en el primer elemento) y de sus atributos, y los
//! nodos de texto (con el texto contiguo y las secciones CDATA unidos),
//! comentarios e instrucciones de proceso.

use std::collections::HashMap;

use super::XsltError;
use super::compile::Stylesheet;
use super::output::Handler;
use crate::dom::{Attribute, Document, Element, NodeId, NodeKind, NsDecl, XML_NS};
use crate::xpath::{XML_DECL, XNode};

type HResult<T = ()> = Result<T, XsltError>;

/// Destino de `disable-output-escaping` dentro de un fragmento (como hace
/// `ToXMLSAXHandler.setEscaping`).
pub(crate) const PI_DISABLE_ESCAPING: &str = "javax.xml.transform.disable-output-escaping";
pub(crate) const PI_ENABLE_ESCAPING: &str = "javax.xml.transform.enable-output-escaping";

/// Bosque de árboles con identificadores de DTM.
pub(crate) struct Forest {
    pub doc: Document,
    /// Identificador DTM de cada nodo de `doc`.
    handles: Vec<u32>,
    /// Elementos por valor de atributo ID (DTD) del documento de entrada.
    ids: HashMap<String, NodeId>,
    /// Entidades no analizadas de la DTD (nombre -> identificador de sistema).
    pub unparsed: HashMap<String, String>,
    /// Raíz del documento de entrada.
    pub source_root: NodeId,
    next_dtm: u32,
    max_nodes: usize,
}

impl Forest {
    fn new(max_nodes: usize) -> Forest {
        Forest {
            doc: Document::empty(),
            handles: vec![1 << 16],
            ids: HashMap::new(),
            unparsed: HashMap::new(),
            source_root: NodeId(0),
            next_dtm: 2,
            max_nodes,
        }
    }

    /// Identificador DTM de un nodo XPath.
    pub(crate) fn handle(&self, n: XNode) -> u32 {
        match n {
            XNode::Node(id) => self.handles[id.0],
            XNode::Ns(e, i) => {
                let base = self.handles[e.0];
                let has_xml = self.carries_xml_decl(e);
                if i == XML_DECL {
                    base + 1
                } else {
                    base + 1 + u32::from(has_xml) + i
                }
            }
            XNode::Attr(e, i) => {
                let base = self.handles[e.0];
                let decls = self.doc.element(e).map(|el| el.ns_decls.len()).unwrap_or(0) as u32;
                base + 1 + u32::from(self.carries_xml_decl(e)) + decls + i
            }
        }
    }

    /// El elemento lleva la declaración implícita del prefijo `xml` (es el
    /// primer elemento de su árbol).
    pub(crate) fn carries_xml_decl(&self, e: NodeId) -> bool {
        let root = self.doc.tree_root(e);
        self.doc
            .children(root)
            .iter()
            .copied()
            .find(|&c| self.doc.element(c).is_some())
            == Some(e)
    }

    /// Elemento con el ID dado en el árbol de `root` (solo el de entrada
    /// tiene DTD).
    pub(crate) fn element_by_id(&self, root: NodeId, id: &str) -> Option<NodeId> {
        if root != self.source_root {
            return None;
        }
        self.ids.get(id).copied()
    }

    fn check_size(&self) -> HResult {
        if self.doc.len() > self.max_nodes {
            return Err(XsltError::limit("nodos de los árboles de resultado"));
        }
        Ok(())
    }

    /// Añade un árbol construido aparte como árbol nuevo del bosque, con el
    /// siguiente identificador de DTM. Devuelve su raíz.
    pub(crate) fn adopt(&mut self, tree: &Document) -> Result<NodeId, XsltError> {
        if self.doc.len() + tree.len() > self.max_nodes {
            return Err(XsltError::limit("nodos de los árboles de resultado"));
        }
        let dtm = self.next_dtm;
        self.next_dtm += 1;
        let mut counter = 0u32;
        let root = self.copy_tree(tree, tree.root(), None, dtm, &mut counter, true);
        self.check_size()?;
        Ok(root)
    }

    fn copy_tree(
        &mut self,
        src: &Document,
        n: NodeId,
        parent: Option<NodeId>,
        dtm: u32,
        counter: &mut u32,
        first_element: bool,
    ) -> NodeId {
        let kind = src.kind(n).clone();
        let id = self.doc.push(parent, kind);
        self.handles.push((dtm << 16) + *counter);
        *counter += 1;
        if let Some(e) = self.doc.element(id) {
            *counter += e.ns_decls.len() as u32 + e.attrs.len() as u32;
            if first_element {
                *counter += 1;
            }
        }
        let mut first = matches!(src.kind(n), NodeKind::Document);
        for &c in src.children(n) {
            let is_el = src.element(c).is_some();
            self.copy_tree(src, c, Some(id), dtm, counter, first && is_el);
            if is_el {
                first = false;
            }
        }
        id
    }
}

// ---------------------------------------------------------------------------
// Documento de entrada
// ---------------------------------------------------------------------------

/// Declaraciones de la DTD interna que afectan al árbol (`ATTLIST`).
#[derive(Default, Debug)]
struct Dtd {
    /// Atributos por defecto: (elemento, atributo, valor) en orden de declaración.
    defaults: Vec<(String, String, String)>,
    /// Atributos de tipo ID: (elemento, atributo).
    id_attrs: Vec<(String, String)>,
    unparsed: HashMap<String, String>,
}

/// Separa los tokens de una declaración de la DTD (nombres, literales y
/// grupos entre paréntesis).
fn dtd_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '"' || c == '\'' {
            let start = i + 1;
            let mut j = start;
            while j < chars.len() && chars[j] != c {
                j += 1;
            }
            out.push(format!(
                "\u{0}{}",
                chars[start..j.min(chars.len())].iter().collect::<String>()
            ));
            i = j + 1;
        } else if c == '(' {
            let mut j = i;
            while j < chars.len() && chars[j] != ')' {
                j += 1;
            }
            out.push(chars[i..(j + 1).min(chars.len())].iter().collect());
            i = j + 1;
        } else {
            let start = i;
            while i < chars.len() && !chars[i].is_whitespace() && !matches!(chars[i], '"' | '\'' | '(') {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        }
    }
    out
}

fn parse_dtd(doctype: &str) -> Result<Dtd, XsltError> {
    let mut dtd = Dtd::default();
    let (head, subset) = match doctype.find('[') {
        Some(i) => (
            &doctype[..i],
            &doctype[i + 1..doctype.rfind(']').unwrap_or(doctype.len())],
        ),
        None => (doctype, ""),
    };
    // Subconjunto externo: Java no puede leerlo (accessExternalDTD vacío).
    let head_toks = dtd_tokens(head.trim_start_matches("<!DOCTYPE").trim_end_matches('>'));
    if head_toks.iter().any(|t| t == "SYSTEM" || t == "PUBLIC") {
        return Err(XsltError::Input(
            "DTD externa: no se permite el acceso a recursos externos".into(),
        ));
    }
    let mut rest = subset;
    while let Some(start) = rest.find("<!") {
        let after = &rest[start..];
        if after.starts_with("<!--") {
            match after.find("-->") {
                Some(e) => {
                    rest = &after[e + 3..];
                    continue;
                }
                None => break,
            }
        }
        // Fin de la declaración, respetando los literales.
        let mut end = None;
        let mut quote = None;
        for (i, c) in after.char_indices() {
            match quote {
                Some(q) if c == q => quote = None,
                Some(_) => {}
                None if c == '"' || c == '\'' => quote = Some(c),
                None if c == '>' => {
                    end = Some(i);
                    break;
                }
                None => {}
            }
        }
        let Some(end) = end else { break };
        let decl = &after[2..end];
        if let Some(body) = decl.strip_prefix("ATTLIST") {
            let toks = dtd_tokens(body);
            if let Some(elem) = toks.first() {
                let mut i = 1;
                while i + 1 < toks.len() {
                    let attr = toks[i].clone();
                    let ty = toks[i + 1].clone();
                    i += 2;
                    let mut default = None;
                    if i < toks.len() {
                        match toks[i].as_str() {
                            "#REQUIRED" | "#IMPLIED" => i += 1,
                            "#FIXED" => {
                                i += 1;
                                if i < toks.len() {
                                    default = toks[i].strip_prefix('\u{0}').map(str::to_string);
                                    i += 1;
                                }
                            }
                            t if t.starts_with('\u{0}') => {
                                default = Some(t[1..].to_string());
                                i += 1;
                            }
                            _ => {}
                        }
                    }
                    if ty == "ID" {
                        dtd.id_attrs.push((elem.clone(), attr.clone()));
                    }
                    if let Some(d) = default
                        && !dtd.defaults.iter().any(|(e, a, _)| e == elem && *a == attr)
                    {
                        dtd.defaults.push((elem.clone(), attr, normalize_attr(&d, &ty)));
                    }
                }
            }
        } else if let Some(body) = decl.strip_prefix("ENTITY") {
            let toks = dtd_tokens(body);
            if toks.len() >= 5 && toks[0] != "%" {
                let ndata = toks.iter().position(|t| t == "NDATA");
                let sys = toks.iter().position(|t| t == "SYSTEM" || t == "PUBLIC");
                if let (Some(_), Some(s)) = (ndata, sys) {
                    let id_index = if toks[s] == "PUBLIC" { s + 2 } else { s + 1 };
                    if let Some(sysid) = toks.get(id_index).and_then(|t| t.strip_prefix('\u{0}')) {
                        dtd.unparsed.entry(toks[0].clone()).or_insert_with(|| sysid.to_string());
                    }
                }
            }
        }
        rest = &after[end + 1..];
    }
    Ok(dtd)
}

/// Normalización del valor de un atributo según su tipo (los no CDATA
/// eliminan los espacios sobrantes).
fn normalize_attr(v: &str, ty: &str) -> String {
    let v: String = v
        .chars()
        .map(|c| if matches!(c, '\t' | '\n' | '\r') { ' ' } else { c })
        .collect();
    if ty == "CDATA" {
        v
    } else {
        v.split(' ').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
    }
}

/// Árbol de entrada preparado para la transformación.
pub(crate) struct Source {
    pub forest: Forest,
}

impl Source {
    /// Analiza los octetos de entrada como el analizador SAX de XSLTC y
    /// construye el árbol con la eliminación de espacios de la hoja.
    pub(crate) fn parse(input: &[u8], sheet: &Stylesheet, limits: &super::Limits) -> Result<Source, XsltError> {
        let (doc, _) = Document::parse_bytes(input).map_err(|e| XsltError::Input(e.to_string()))?;
        let dtd = match &doc.doctype {
            Some(r) => parse_dtd(&doc.source()[r.clone()])?,
            None => Dtd::default(),
        };
        let mut forest = Forest::new(limits.max_nodes.max(doc.len() * 2 + 16));
        forest.unparsed = dtd.unparsed.clone();
        let mut b = Builder {
            src: &doc,
            sheet,
            dtd: &dtd,
            forest: &mut forest,
            counter: 1,
            first_element: true,
            pending_text: None,
        };
        b.copy_children(doc.root(), NodeId(0), false)?;
        b.flush_text();
        drop(b);
        Ok(Source { forest })
    }
}

struct Builder<'a> {
    src: &'a Document,
    sheet: &'a Stylesheet,
    dtd: &'a Dtd,
    forest: &'a mut Forest,
    counter: u32,
    first_element: bool,
    /// Texto pendiente de unir: (padre, texto, eliminable).
    pending_text: Option<(NodeId, String, bool)>,
}

impl Builder<'_> {
    fn add(&mut self, parent: NodeId, kind: NodeKind) -> NodeId {
        let id = self.forest.doc.push(Some(parent), kind);
        self.forest.handles.push((1 << 16) + self.counter);
        self.counter += 1;
        id
    }

    fn flush_text(&mut self) {
        if let Some((parent, text, strip)) = self.pending_text.take() {
            let ws = text.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r'));
            if !(strip && ws) && !text.is_empty() {
                self.add(parent, NodeKind::Text { text, cdata: false });
            }
        }
    }

    fn copy_children(&mut self, src_parent: NodeId, parent: NodeId, strip: bool) -> HResult {
        let src = self.src;
        for &c in src.children(src_parent) {
            match src.kind(c) {
                NodeKind::Text { text, .. } => match &mut self.pending_text {
                    Some((_, t, _)) => t.push_str(text),
                    None => self.pending_text = Some((parent, text.clone(), strip)),
                },
                NodeKind::Element(e) => {
                    self.flush_text();
                    self.copy_element(c, e, parent, strip)?;
                }
                NodeKind::Comment(t) => {
                    self.flush_text();
                    self.add(parent, NodeKind::Comment(t.clone()));
                }
                NodeKind::Pi { target, data } => {
                    self.flush_text();
                    self.add(
                        parent,
                        NodeKind::Pi {
                            target: target.clone(),
                            data: data.clone(),
                        },
                    );
                }
                NodeKind::Document => {}
            }
        }
        self.flush_text();
        Ok(())
    }

    fn copy_element(&mut self, src_id: NodeId, e: &Element, parent: NodeId, parent_strip: bool) -> HResult {
        let mut el = e.clone();
        el.start_tag = 0..0;
        el.end_tag = None;
        // Atributos por defecto de la DTD, al final y en orden de declaración.
        let qn = e.qname();
        for (en, an, v) in &self.dtd.defaults {
            if *en != qn || el.attrs.iter().any(|a| a.qname() == *an) {
                continue;
            }
            let (prefix, local) = match an.split_once(':') {
                Some((p, l)) => (Some(p.to_string()), l.to_string()),
                None => (None, an.clone()),
            };
            let ns = match &prefix {
                Some(p) if p == "xml" => Some(XML_NS.to_string()),
                Some(p) => self.src.lookup_namespace(src_id, Some(p)),
                None => None,
            };
            el.attrs.push(Attribute {
                prefix,
                local,
                ns,
                value: v.clone(),
                range: 0..0,
            });
        }
        for a in &mut el.attrs {
            a.range = 0..0;
        }
        let first = std::mem::replace(&mut self.first_element, false);
        let n_decls = el.ns_decls.len() as u32 + el.attrs.len() as u32 + u32::from(first);
        let id = self.forest.doc.push(Some(parent), NodeKind::Element(el.clone()));
        self.forest.handles.push((1 << 16) + self.counter);
        self.counter += 1 + n_decls;
        for (en, an) in &self.dtd.id_attrs {
            if *en == qn
                && let Some(v) = el.attrs.iter().find(|a| a.qname() == *an)
            {
                self.forest.ids.entry(v.value.clone()).or_insert(id);
            }
        }
        // Eliminación de espacios: reglas de la hoja y xml:space.
        let mut strip = if self.sheet.has_strip_rules() {
            self.sheet.should_strip(el.ns.as_deref().unwrap_or(""), &el.local)
        } else {
            parent_strip
        };
        if self.sheet.has_strip_rules() && self.preserved(src_id) {
            strip = false;
        }
        self.copy_children(src_id, id, strip)?;
        if self.forest.doc.len() > self.forest.max_nodes {
            return Err(XsltError::limit("nodos del documento de entrada"));
        }
        Ok(())
    }

    /// `xml:space="preserve"` en el elemento o heredado (el más cercano
    /// manda; cualquier otro valor equivale a `default`).
    fn preserved(&self, src_id: NodeId) -> bool {
        std::iter::once(src_id)
            .chain(self.src.ancestors(src_id))
            .find_map(|a| self.src.element(a).and_then(|e| e.attr_ns(XML_NS, "space")))
            .is_some_and(|v| v == "preserve")
    }
}

// ---------------------------------------------------------------------------
// Fragmentos de árbol de resultado
// ---------------------------------------------------------------------------

/// Constructor de fragmentos de árbol (`ToXMLSAXHandler` sobre el DTM de
/// XSLTC): mismas reglas de declaración de espacios de nombres que la salida.
pub(crate) struct RtfBuilder {
    pub tree: Document,
    stack: Vec<NodeId>,
    /// Elemento abierto pendiente de crear: nombre, declaraciones y atributos.
    open: Option<OpenElement>,
    ns: Vec<Vec<(String, String)>>,
    escaping: bool,
    max_len: usize,
    len: usize,
}

struct OpenElement {
    qname: String,
    decls: Vec<NsDecl>,
    attrs: Vec<Attribute>,
}

impl RtfBuilder {
    pub(crate) fn new(max_len: usize) -> RtfBuilder {
        RtfBuilder {
            tree: Document::empty(),
            stack: vec![NodeId(0)],
            open: None,
            ns: vec![vec![(String::new(), String::new()), ("xml".into(), XML_NS.into())]],
            escaping: true,
            max_len,
            len: 0,
        }
    }

    fn lookup(&self, prefix: &str) -> Option<&str> {
        self.ns
            .iter()
            .rev()
            .flat_map(|s| s.iter().rev())
            .find(|(p, _)| p == prefix)
            .map(|(_, u)| u.as_str())
    }

    fn grow(&mut self, n: usize) -> HResult {
        self.len += n;
        if self.len > self.max_len {
            return Err(XsltError::limit("tamaño de los fragmentos de árbol"));
        }
        Ok(())
    }

    /// `startPrefixMapping(prefix, uri, false)` sobre el elemento abierto.
    fn push_namespace(&mut self, prefix: &str, uri: &str) {
        if prefix.starts_with("xml") {
            return;
        }
        if self.lookup(prefix) == Some(uri) {
            return;
        }
        if let Some(top) = self.ns.last_mut() {
            top.push((prefix.to_string(), uri.to_string()));
        }
        if let Some(o) = &mut self.open {
            o.decls.push(NsDecl {
                prefix: if prefix.is_empty() {
                    None
                } else {
                    Some(prefix.to_string())
                },
                uri: uri.to_string(),
            });
        }
    }

    fn flush_pending(&mut self) -> HResult {
        let Some(o) = self.open.take() else {
            return Ok(());
        };
        let (prefix, local) = match o.qname.split_once(':') {
            Some((p, l)) => (Some(p.to_string()), l.to_string()),
            None => (None, o.qname.clone()),
        };
        let uri = match &prefix {
            Some(p) => match self.lookup(p) {
                Some(u) => u.to_string(),
                None => {
                    return Err(XsltError::Runtime(format!(
                        "el prefijo de espacio de nombres '{p}' no se ha declarado"
                    )));
                }
            },
            None => self.lookup("").unwrap_or("").to_string(),
        };
        let parent = *self.stack.last().expect("pila");
        let id = self.tree.push(
            Some(parent),
            NodeKind::Element(Element {
                prefix,
                local,
                ns: if uri.is_empty() { None } else { Some(uri) },
                attrs: o.attrs,
                ns_decls: o.decls,
                start_tag: 0..0,
                end_tag: None,
            }),
        );
        self.stack.push(id);
        Ok(())
    }

    fn add_attr(&mut self, uri: &str, local: &str, qname: &str, value: &str) -> HResult {
        let Some(o) = &mut self.open else {
            return Ok(());
        };
        self.len += value.len();
        let prefix = qname.split_once(':').map(|(p, _)| p.to_string());
        let existing = if uri.is_empty() {
            o.attrs.iter_mut().find(|a| a.qname() == qname)
        } else {
            o.attrs
                .iter_mut()
                .find(|a| a.ns.as_deref() == Some(uri) && a.local == local)
        };
        match existing {
            Some(a) => a.value = value.to_string(),
            None => o.attrs.push(Attribute {
                prefix,
                local: local.to_string(),
                ns: if uri.is_empty() { None } else { Some(uri.to_string()) },
                value: value.to_string(),
                range: 0..0,
            }),
        }
        if self.len > self.max_len {
            return Err(XsltError::limit("tamaño de los fragmentos de árbol"));
        }
        Ok(())
    }

    fn append_text(&mut self, text: &str) -> HResult {
        self.flush_pending()?;
        self.grow(text.len())?;
        let parent = *self.stack.last().expect("pila");
        if let Some(&last) = self.tree.children(parent).last()
            && let Some(t) = self.tree.text_mut(last)
        {
            t.push_str(text);
            return Ok(());
        }
        self.tree.push(
            Some(parent),
            NodeKind::Text {
                text: text.to_string(),
                cdata: false,
            },
        );
        Ok(())
    }

    fn pi(&mut self, target: &str, data: &str) -> HResult {
        self.flush_pending()?;
        self.grow(target.len() + data.len())?;
        let parent = *self.stack.last().expect("pila");
        self.tree.push(
            Some(parent),
            NodeKind::Pi {
                target: target.to_string(),
                data: data.to_string(),
            },
        );
        Ok(())
    }
}

impl Handler for RtfBuilder {
    fn start_document(&mut self) -> HResult {
        Ok(())
    }

    fn end_document(&mut self) -> HResult {
        self.flush_pending()
    }

    fn start_element(&mut self, qname: &str) -> HResult {
        self.start_element_ns(None, qname)
    }

    fn start_element_ns(&mut self, uri: Option<&str>, qname: &str) -> HResult {
        self.flush_pending()?;
        self.grow(qname.len())?;
        self.ns.push(Vec::new());
        self.open = Some(OpenElement {
            qname: qname.to_string(),
            decls: Vec::new(),
            attrs: Vec::new(),
        });
        // `ensurePrefixIsDeclared`.
        if let Some(ns) = uri
            && !ns.is_empty()
        {
            let prefix = qname.split_once(':').map(|(p, _)| p).unwrap_or("");
            if self.lookup(prefix) != Some(ns) {
                let p = prefix.to_string();
                self.push_namespace(&p, ns);
            }
        }
        Ok(())
    }

    fn end_element(&mut self, _qname: &str) -> HResult {
        self.flush_pending()?;
        if self.stack.len() > 1 {
            self.stack.pop();
        }
        if self.ns.len() > 1 {
            self.ns.pop();
        }
        Ok(())
    }

    fn namespace_after_start_element(&mut self, prefix: Option<&str>, uri: &str) -> HResult {
        let Some(p) = prefix else {
            return Err(XsltError::Runtime("prefijo de espacio de nombres nulo".into()));
        };
        self.push_namespace(p, uri);
        Ok(())
    }

    fn add_attribute(&mut self, qname: &str, value: &str) -> HResult {
        if self.open.is_none() {
            return Ok(());
        }
        // `SerializerBase.addAttribute(name, value)`: patchName y
        // getNamespaceURI(name, false).
        let mut patched = qname.to_string();
        if let Some(last) = qname.rfind(':')
            && last > 0
        {
            let first = qname.find(':').expect("dos puntos");
            let prefix = &qname[..first];
            let local = &qname[last + 1..];
            if self.lookup(prefix) == Some("") {
                patched = local.to_string();
            } else if first != last {
                patched = format!("{prefix}:{local}");
            }
        }
        let local = match patched.rfind(':') {
            Some(i) if i > 0 => patched[i + 1..].to_string(),
            _ => patched.clone(),
        };
        let uri = match patched.rfind(':') {
            Some(i) if i > 0 => {
                let p = &patched[..i];
                match self.lookup(p) {
                    Some(u) => u.to_string(),
                    None if p == "xmlns" => String::new(),
                    None => {
                        return Err(XsltError::Runtime(format!(
                            "el prefijo de espacio de nombres '{p}' no se ha declarado"
                        )));
                    }
                }
            }
            _ => String::new(),
        };
        self.add_attr(&uri, &local, &patched, value)
    }

    fn add_attribute_ns(&mut self, uri: &str, local: &str, qname: &str, value: &str) -> HResult {
        self.add_attr(uri, local, qname, value)
    }

    fn add_unique_attribute(&mut self, qname: &str, value: &str, _flags: u32) -> HResult {
        self.add_attribute(qname, value)
    }

    fn characters(&mut self, text: &str) -> HResult {
        if text.is_empty() {
            return self.flush_pending();
        }
        self.append_text(text)
    }

    fn comment(&mut self, text: &str) -> HResult {
        self.flush_pending()?;
        self.grow(text.len())?;
        let parent = *self.stack.last().expect("pila");
        self.tree.push(Some(parent), NodeKind::Comment(text.to_string()));
        Ok(())
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> HResult {
        self.pi(target, data)
    }

    fn set_escaping(&mut self, escape: bool) -> bool {
        let old = std::mem::replace(&mut self.escaping, escape);
        let target = if escape {
            PI_ENABLE_ESCAPING
        } else {
            PI_DISABLE_ESCAPING
        };
        // Un error aquí solo puede ser el límite de tamaño, que se volverá a
        // detectar con el siguiente suceso.
        let _ = self.pi(target, "");
        old
    }

    fn output_namespace(&mut self, prefix: &str) -> HResult<Option<String>> {
        self.flush_pending()?;
        Ok(self.lookup(prefix).map(str::to_string))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtd_attlist_and_entities() {
        let d = parse_dtd(
            "<!DOCTYPE doc [<!ATTLIST e k ID #IMPLIED def CDATA \"valor\" t NMTOKENS \" a  b \"><!NOTATION gif SYSTEM \"image/gif\"><!ENTITY img SYSTEM \"foto.gif\" NDATA gif>]>",
        )
        .unwrap();
        assert_eq!(d.id_attrs, vec![("e".to_string(), "k".to_string())]);
        assert_eq!(d.defaults[0], ("e".into(), "def".into(), "valor".into()));
        assert_eq!(d.defaults[1].2, "a b");
        assert_eq!(d.unparsed.get("img").map(String::as_str), Some("foto.gif"));
        assert!(parse_dtd("<!DOCTYPE doc SYSTEM \"x.dtd\">").is_err());
    }
}
