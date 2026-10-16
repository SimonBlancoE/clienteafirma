//! Canonicalización XML: C14N 1.0, C14N 1.1 y C14N exclusiva (con y sin
//! comentarios), sobre subárboles o sobre conjuntos de nodos arbitrarios
//! (modelo de datos XPath de XMLDSig), como hace Apache Santuario.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::dom::{Document, NodeId, NodeKind, XML_NS};
use crate::xpath::{XNode, namespace_nodes};

pub const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_10_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";
pub const C14N_11_WITH_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Inclusive10,
    Inclusive11,
    Exclusive,
}

/// Método de canonicalización.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C14n {
    pub kind: Kind,
    pub with_comments: bool,
    /// Prefijos de `InclusiveNamespaces PrefixList` (solo C14N exclusiva;
    /// `#default` designa el espacio de nombres por defecto).
    pub inclusive_prefixes: Vec<String>,
}

/// Conjunto de nodos (modelo XPath): nodos del árbol, atributos y nodos de
/// espacio de nombres. Los atributos y los nodos de espacio de nombres se
/// incluyen por defecto si lo está su elemento; las excepciones se guardan
/// aparte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSet {
    nodes: Vec<bool>,
    attr_flip: HashSet<(usize, u32)>,
    ns_flip: HashSet<(usize, String)>,
}

impl NodeSet {
    /// Conjunto vacío.
    pub fn empty(doc: &Document) -> NodeSet {
        NodeSet {
            nodes: vec![false; doc.len()],
            attr_flip: HashSet::new(),
            ns_flip: HashSet::new(),
        }
    }

    /// Todo el documento (con o sin comentarios).
    pub fn whole(doc: &Document, with_comments: bool) -> NodeSet {
        NodeSet::subtree(doc, doc.root(), with_comments)
    }

    /// Un nodo y todos sus descendientes (con o sin comentarios).
    pub fn subtree(doc: &Document, node: NodeId, with_comments: bool) -> NodeSet {
        let mut s = NodeSet::empty(doc);
        for d in doc.descendants(node) {
            if with_comments || !matches!(doc.kind(d), NodeKind::Comment(_)) {
                s.nodes[d.0] = true;
            }
        }
        s
    }

    pub fn contains_node(&self, id: NodeId) -> bool {
        self.nodes.get(id.0).copied().unwrap_or(false)
    }

    pub fn contains_attr(&self, element: NodeId, idx: u32) -> bool {
        self.contains_node(element) != self.attr_flip.contains(&(element.0, idx))
    }

    pub fn contains_ns(&self, element: NodeId, prefix: &str) -> bool {
        self.contains_node(element) != self.ns_flip.contains(&(element.0, prefix.to_string()))
    }

    /// Pertenencia de un nodo XPath.
    pub fn contains(&self, doc: &Document, n: XNode) -> bool {
        match n {
            XNode::Node(id) => self.contains_node(id),
            XNode::Attr(e, i) => self.contains_attr(e, i),
            XNode::Ns(e, i) => match namespace_nodes(doc, e).get(i as usize) {
                Some((p, _)) => self.contains_ns(e, p),
                None => false,
            },
        }
    }

    /// Elimina un nodo y todo su subárbol (con sus atributos y espacios de nombres).
    pub fn remove_subtree(&mut self, doc: &Document, node: NodeId) {
        for d in doc.descendants(node) {
            self.nodes[d.0] = false;
        }
        let range: HashSet<usize> = doc.descendants(node).into_iter().map(|n| n.0).collect();
        self.attr_flip.retain(|(e, _)| !range.contains(e));
        self.ns_flip.retain(|(e, _)| !range.contains(e));
    }

    /// Todos los nodos XPath incluidos, en orden de documento.
    pub fn xnodes(&self, doc: &Document) -> Vec<XNode> {
        let mut out = Vec::new();
        for i in 0..doc.len() {
            let id = NodeId(i);
            if let Some(e) = doc.element(id) {
                if self.contains_node(id) {
                    out.push(XNode::Node(id));
                }
                for (k, (p, _)) in namespace_nodes(doc, id).iter().enumerate() {
                    if self.contains_ns(id, p) {
                        out.push(XNode::Ns(id, k as u32));
                    }
                }
                for k in 0..e.attrs.len() {
                    if self.contains_attr(id, k as u32) {
                        out.push(XNode::Attr(id, k as u32));
                    }
                }
            } else if self.contains_node(id) {
                out.push(XNode::Node(id));
            }
        }
        out
    }

    /// Construye el conjunto formado por los nodos de `base` que cumplen `pred`.
    pub fn filter(doc: &Document, base: &NodeSet, mut pred: impl FnMut(XNode) -> bool) -> NodeSet {
        let mut out = NodeSet::empty(doc);
        for i in 0..doc.len() {
            let id = NodeId(i);
            out.nodes[i] = base.contains_node(id) && pred(XNode::Node(id));
        }
        for i in 0..doc.len() {
            let id = NodeId(i);
            if let Some(e) = doc.element(id) {
                let el_in = out.nodes[i];
                for (k, (p, _)) in namespace_nodes(doc, id).iter().enumerate() {
                    let inc = base.contains_ns(id, p) && pred(XNode::Ns(id, k as u32));
                    if inc != el_in {
                        out.ns_flip.insert((i, p.clone()));
                    }
                }
                for k in 0..e.attrs.len() {
                    let inc = base.contains_attr(id, k as u32) && pred(XNode::Attr(id, k as u32));
                    if inc != el_in {
                        out.attr_flip.insert((i, k as u32));
                    }
                }
            }
        }
        out
    }
}

impl C14n {
    pub const fn new(kind: Kind, with_comments: bool) -> Self {
        C14n {
            kind,
            with_comments,
            inclusive_prefixes: Vec::new(),
        }
    }

    /// Método a partir de su URI de algoritmo.
    pub fn from_uri(uri: &str) -> Option<Self> {
        Some(match uri {
            C14N_10 => Self::new(Kind::Inclusive10, false),
            C14N_10_WITH_COMMENTS => Self::new(Kind::Inclusive10, true),
            C14N_11 => Self::new(Kind::Inclusive11, false),
            C14N_11_WITH_COMMENTS => Self::new(Kind::Inclusive11, true),
            EXC_C14N => Self::new(Kind::Exclusive, false),
            EXC_C14N_WITH_COMMENTS => Self::new(Kind::Exclusive, true),
            _ => return None,
        })
    }

    pub fn uri(&self) -> &'static str {
        match (self.kind, self.with_comments) {
            (Kind::Inclusive10, false) => C14N_10,
            (Kind::Inclusive10, true) => C14N_10_WITH_COMMENTS,
            (Kind::Inclusive11, false) => C14N_11,
            (Kind::Inclusive11, true) => C14N_11_WITH_COMMENTS,
            (Kind::Exclusive, false) => EXC_C14N,
            (Kind::Exclusive, true) => EXC_C14N_WITH_COMMENTS,
        }
    }

    pub fn with_inclusive_prefixes(mut self, prefixes: impl IntoIterator<Item = String>) -> Self {
        self.inclusive_prefixes = prefixes.into_iter().collect();
        self
    }

    /// Canonicaliza el nodo `node` (el documento completo, un elemento y sus
    /// descendientes, o un nodo de texto/comentario) excluyendo los subárboles
    /// de `exclude`.
    pub fn canonicalize(&self, doc: &Document, node: NodeId, exclude: &[NodeId]) -> Vec<u8> {
        let mut set = NodeSet::subtree(doc, node, true);
        for &x in exclude {
            set.remove_subtree(doc, x);
        }
        self.canonicalize_set(doc, &set)
    }

    /// Canonicaliza un conjunto de nodos del documento.
    pub fn canonicalize_set(&self, doc: &Document, set: &NodeSet) -> Vec<u8> {
        let mut w = Writer {
            doc,
            method: self,
            set,
            out: String::new(),
        };
        w.node(doc.root(), &BTreeMap::new());
        w.out.into_bytes()
    }
}

/// Atajo: canonicaliza con el algoritmo indicado por URI.
pub fn canonicalize_uri(
    uri: &str,
    doc: &Document,
    node: NodeId,
    exclude: &[NodeId],
) -> Option<Vec<u8>> {
    C14n::from_uri(uri).map(|m| m.canonicalize(doc, node, exclude))
}

struct Writer<'a> {
    doc: &'a Document,
    method: &'a C14n,
    set: &'a NodeSet,
    out: String,
}

fn escape_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

fn escape_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(c),
        }
    }
}

impl Writer<'_> {
    fn node(&mut self, id: NodeId, rendered: &BTreeMap<String, String>) {
        match self.doc.kind(id) {
            NodeKind::Document => {
                let root = self.doc.document_element();
                let mut after_root = false;
                for &c in self.doc.children(id) {
                    if Some(c) == root {
                        self.node(c, &BTreeMap::new());
                        after_root = true;
                        continue;
                    }
                    if !self.set.contains_node(c) {
                        continue;
                    }
                    let mut piece = String::new();
                    match self.doc.kind(c) {
                        NodeKind::Comment(t) if self.method.with_comments => {
                            piece.push_str("<!--");
                            piece.push_str(t);
                            piece.push_str("-->");
                        }
                        NodeKind::Pi { target, data } => {
                            Self::pi(&mut piece, target, data);
                        }
                        _ => continue,
                    }
                    if after_root {
                        self.out.push('\n');
                        self.out.push_str(&piece);
                    } else {
                        self.out.push_str(&piece);
                        self.out.push('\n');
                    }
                }
            }
            NodeKind::Text { text, .. } => {
                if self.set.contains_node(id) {
                    escape_text(&mut self.out, text)
                }
            }
            NodeKind::Comment(t) => {
                if self.method.with_comments && self.set.contains_node(id) {
                    self.out.push_str("<!--");
                    self.out.push_str(t);
                    self.out.push_str("-->");
                }
            }
            NodeKind::Pi { target, data } => {
                if self.set.contains_node(id) {
                    let mut piece = String::new();
                    Self::pi(&mut piece, target, data);
                    self.out.push_str(&piece);
                }
            }
            NodeKind::Element(_) => {
                if self.set.contains_node(id) {
                    self.element(id, rendered)
                } else {
                    for &c in self.doc.children(id) {
                        self.node(c, rendered);
                    }
                }
            }
        }
    }

    fn pi(out: &mut String, target: &str, data: &str) {
        out.push_str("<?");
        out.push_str(target);
        if !data.is_empty() {
            out.push(' ');
            out.push_str(data);
        }
        out.push_str("?>");
    }

    fn element(&mut self, id: NodeId, rendered: &BTreeMap<String, String>) {
        let doc = self.doc;
        let set = self.set;
        let e = doc.element(id).expect("es un elemento");
        let in_scope = doc.in_scope_namespaces(id);
        let ns_in = |p: &str| set.contains_ns(id, p);

        // Declaraciones de espacios de nombres a emitir (clave "" = por defecto).
        let mut to_render: BTreeMap<String, String> = BTreeMap::new();
        match self.method.kind {
            Kind::Inclusive10 | Kind::Inclusive11 => {
                for (p, u) in &in_scope {
                    if ns_in(p) && rendered.get(p) != Some(u) {
                        to_render.insert(p.clone(), u.clone());
                    }
                }
                let has_default = in_scope.contains_key("") && ns_in("");
                if !has_default && rendered.get("").is_some_and(|u| !u.is_empty()) {
                    to_render.insert(String::new(), String::new());
                }
            }
            Kind::Exclusive => {
                let mut utilized: BTreeSet<String> = BTreeSet::new();
                utilized.insert(e.prefix.clone().unwrap_or_default());
                for (k, a) in e.attrs.iter().enumerate() {
                    if let Some(p) = &a.prefix
                        && set.contains_attr(id, k as u32) {
                            utilized.insert(p.clone());
                        }
                }
                for p in &self.method.inclusive_prefixes {
                    let p = if p == "#default" {
                        String::new()
                    } else {
                        p.clone()
                    };
                    if in_scope.contains_key(&p) && ns_in(&p) {
                        utilized.insert(p);
                    }
                }
                for p in utilized {
                    if p == "xml" {
                        continue;
                    }
                    match in_scope.get(&p) {
                        Some(u) => {
                            if rendered.get(&p) != Some(u) {
                                to_render.insert(p, u.clone());
                            }
                        }
                        None => {
                            if p.is_empty() && rendered.get("").is_some_and(|u| !u.is_empty()) {
                                to_render.insert(String::new(), String::new());
                            }
                        }
                    }
                }
            }
        }

        // Atributos incluidos (más los xml:* heredados para C14N inclusiva
        // cuando el padre no está en el conjunto).
        let mut attrs: Vec<(String, String, String, String)> = e
            .attrs
            .iter()
            .enumerate()
            .filter(|(k, _)| set.contains_attr(id, *k as u32))
            .map(|(_, a)| {
                (
                    a.ns.clone().unwrap_or_default(),
                    a.local.clone(),
                    a.qname(),
                    a.value.clone(),
                )
            })
            .collect();
        let parent_rendered = doc
            .parent(id)
            .is_some_and(|p| doc.element(p).is_some() && set.contains_node(p));
        if !parent_rendered && self.method.kind != Kind::Exclusive {
            let inheritable = |local: &str| match self.method.kind {
                Kind::Inclusive10 => true,
                _ => matches!(local, "lang" | "space"),
            };
            for anc in doc.ancestors(id) {
                if let Some(ae) = doc.element(anc) {
                    for a in &ae.attrs {
                        if a.ns.as_deref() == Some(XML_NS)
                            && inheritable(&a.local)
                            && !e
                                .attrs
                                .iter()
                                .any(|o| o.ns.as_deref() == Some(XML_NS) && o.local == a.local)
                            && !attrs
                                .iter()
                                .any(|(ns, l, _, _)| ns == XML_NS && *l == a.local)
                        {
                            attrs.push((
                                XML_NS.to_string(),
                                a.local.clone(),
                                format!("xml:{}", a.local),
                                a.value.clone(),
                            ));
                        }
                    }
                }
            }
        }
        attrs.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));

        let qname = e.qname();
        self.out.push('<');
        self.out.push_str(&qname);
        for (p, u) in &to_render {
            if p.is_empty() {
                self.out.push_str(" xmlns=\"");
            } else {
                self.out.push_str(" xmlns:");
                self.out.push_str(p);
                self.out.push_str("=\"");
            }
            escape_attr(&mut self.out, u);
            self.out.push('"');
        }
        for (_, _, q, v) in &attrs {
            self.out.push(' ');
            self.out.push_str(q);
            self.out.push_str("=\"");
            escape_attr(&mut self.out, v);
            self.out.push('"');
        }
        self.out.push('>');

        let mut child_rendered = rendered.clone();
        for (p, u) in to_render {
            if u.is_empty() {
                child_rendered.remove(&p);
            } else {
                child_rendered.insert(p, u);
            }
        }
        for &c in doc.children(id) {
            self.node(c, &child_rendered);
        }
        self.out.push_str("</");
        self.out.push_str(&qname);
        self.out.push('>');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(src: &str, m: C14n) -> String {
        let doc = Document::parse(src).unwrap();
        String::from_utf8(m.canonicalize(&doc, doc.root(), &[])).unwrap()
    }

    // Ejemplo 3.1 de la recomendación C14N 1.0.
    const EX31: &str = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<!DOCTYPE doc SYSTEM \"doc.dtd\">\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->";

    #[test]
    fn w3c_3_1_pis_comments() {
        assert_eq!(
            c14n(EX31, C14n::new(Kind::Inclusive10, false)),
            "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
        );
        assert_eq!(
            c14n(EX31, C14n::new(Kind::Inclusive10, true)),
            "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
        );
    }

    #[test]
    fn w3c_3_3_start_end_tags() {
        let src = "<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>";
        // Sin aplicar valores por defecto del DTD (no se procesan ATTLIST).
        let expected = "<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6 xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9 xmlns:a=\"http://www.ietf.org\"></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>";
        assert_eq!(c14n(src, C14n::new(Kind::Inclusive10, false)), expected);
    }

    #[test]
    fn w3c_3_4_character_modifications() {
        let src = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";
        let expected = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";
        assert_eq!(c14n(src, C14n::new(Kind::Inclusive10, false)), expected);
    }

    #[test]
    fn subtree_inherits_namespaces_and_xml_attrs() {
        let src =
            "<r xmlns=\"urn:d\" xmlns:a=\"urn:a\" xml:lang=\"es\"><a:x b=\"1\"><y/></a:x></r>";
        let doc = Document::parse(src).unwrap();
        let x = doc.descendants(doc.root())[2];
        let inc = C14n::new(Kind::Inclusive10, false).canonicalize(&doc, x, &[]);
        assert_eq!(
            String::from_utf8(inc).unwrap(),
            "<a:x xmlns=\"urn:d\" xmlns:a=\"urn:a\" b=\"1\" xml:lang=\"es\"><y></y></a:x>"
        );
        let exc = C14n::new(Kind::Exclusive, false).canonicalize(&doc, x, &[]);
        assert_eq!(
            String::from_utf8(exc).unwrap(),
            "<a:x xmlns:a=\"urn:a\" b=\"1\"><y xmlns=\"urn:d\"></y></a:x>"
        );
        let exc_incl = C14n::new(Kind::Exclusive, false)
            .with_inclusive_prefixes(["#default".to_string()])
            .canonicalize(&doc, x, &[]);
        assert_eq!(
            String::from_utf8(exc_incl).unwrap(),
            "<a:x xmlns=\"urn:d\" xmlns:a=\"urn:a\" b=\"1\"><y></y></a:x>"
        );
    }

    #[test]
    fn exclusion_of_enveloped_signature() {
        let src = "<doc><a>1</a><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><x/></ds:Signature></doc>";
        let doc = Document::parse(src).unwrap();
        let sig = doc.find_descendants(
            doc.root(),
            "http://www.w3.org/2000/09/xmldsig#",
            "Signature",
        )[0];
        let out = C14n::new(Kind::Inclusive10, false).canonicalize(&doc, doc.root(), &[sig]);
        assert_eq!(String::from_utf8(out).unwrap(), "<doc><a>1</a></doc>");
    }

    #[test]
    fn nodeset_with_omitted_element() {
        // Ejemplo de conjunto de nodos: se omite <a> pero no su contenido.
        let src = "<doc xmlns=\"urn:x\"><a xml:lang=\"en\" k=\"v\"><b>t</b></a></doc>";
        let doc = Document::parse(src).unwrap();
        let a = doc.descendants(doc.root())[2];
        let base = NodeSet::whole(&doc, false);
        let set = NodeSet::filter(&doc, &base, |n| n != XNode::Node(a));
        let out = C14n::new(Kind::Inclusive10, false).canonicalize_set(&doc, &set);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<doc xmlns=\"urn:x\"><b xml:lang=\"en\">t</b></doc>"
        );
    }
}
