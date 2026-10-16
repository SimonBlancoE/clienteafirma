//! Canonicalización XML: C14N 1.0, C14N 1.1 y C14N exclusiva (con y sin
//! comentarios), sobre un subárbol del documento del que pueden excluirse
//! nodos (transformada "enveloped-signature").

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::dom::{Document, NodeId, NodeKind, XML_NS};

pub const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_10_WITH_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
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

impl C14n {
    pub const fn new(kind: Kind, with_comments: bool) -> Self {
        C14n { kind, with_comments, inclusive_prefixes: Vec::new() }
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
        let mut w = Writer {
            doc,
            method: self,
            exclude: exclude.iter().copied().collect(),
            out: String::new(),
        };
        w.node(node, &BTreeMap::new(), true);
        w.out.into_bytes()
    }
}

/// Atajo: canonicaliza con el algoritmo indicado por URI.
pub fn canonicalize_uri(uri: &str, doc: &Document, node: NodeId, exclude: &[NodeId]) -> Option<Vec<u8>> {
    C14n::from_uri(uri).map(|m| m.canonicalize(doc, node, exclude))
}

struct Writer<'a> {
    doc: &'a Document,
    method: &'a C14n,
    exclude: HashSet<NodeId>,
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
    fn node(&mut self, id: NodeId, rendered: &BTreeMap<String, String>, apex: bool) {
        if self.exclude.contains(&id) {
            return;
        }
        match self.doc.kind(id) {
            NodeKind::Document => {
                let root = self.doc.document_element();
                let mut after_root = false;
                for &c in self.doc.children(id) {
                    if Some(c) == root {
                        self.node(c, &BTreeMap::new(), true);
                        after_root = true;
                        continue;
                    }
                    if self.exclude.contains(&c) {
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
            NodeKind::Text { text, .. } => escape_text(&mut self.out, text),
            NodeKind::Comment(t) => {
                if self.method.with_comments {
                    self.out.push_str("<!--");
                    self.out.push_str(t);
                    self.out.push_str("-->");
                }
            }
            NodeKind::Pi { target, data } => {
                let mut piece = String::new();
                Self::pi(&mut piece, target, data);
                self.out.push_str(&piece);
            }
            NodeKind::Element(_) => self.element(id, rendered, apex),
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

    fn element(&mut self, id: NodeId, rendered: &BTreeMap<String, String>, apex: bool) {
        let doc = self.doc;
        let e = doc.element(id).expect("es un elemento");
        let in_scope = doc.in_scope_namespaces(id);

        // Declaraciones de espacios de nombres a emitir (clave "" = por defecto).
        let mut to_render: BTreeMap<String, String> = BTreeMap::new();
        match self.method.kind {
            Kind::Inclusive10 | Kind::Inclusive11 => {
                for (p, u) in &in_scope {
                    if rendered.get(p) != Some(u) {
                        to_render.insert(p.clone(), u.clone());
                    }
                }
                if !in_scope.contains_key("") && rendered.get("").is_some_and(|u| !u.is_empty()) {
                    to_render.insert(String::new(), String::new());
                }
            }
            Kind::Exclusive => {
                let mut utilized: BTreeSet<String> = BTreeSet::new();
                utilized.insert(e.prefix.clone().unwrap_or_default());
                for a in &e.attrs {
                    if let Some(p) = &a.prefix {
                        utilized.insert(p.clone());
                    }
                }
                for p in &self.method.inclusive_prefixes {
                    let p = if p == "#default" { String::new() } else { p.clone() };
                    if in_scope.contains_key(&p) {
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

        // Atributos (más los xml:* heredados en el ápice para C14N inclusiva).
        let mut attrs: Vec<(String, String, String, String)> = e
            .attrs
            .iter()
            .map(|a| (a.ns.clone().unwrap_or_default(), a.local.clone(), a.qname(), a.value.clone()))
            .collect();
        if apex && self.method.kind != Kind::Exclusive {
            let inheritable: &[&str] = match self.method.kind {
                Kind::Inclusive10 => &["lang", "space", "base", "id"],
                _ => &["lang", "space"],
            };
            for anc in doc.ancestors(id) {
                if let Some(ae) = doc.element(anc) {
                    for a in &ae.attrs {
                        if a.ns.as_deref() == Some(XML_NS)
                            && inheritable.contains(&a.local.as_str())
                            && !attrs.iter().any(|(ns, l, _, _)| ns == XML_NS && *l == a.local)
                        {
                            attrs.push((XML_NS.to_string(), a.local.clone(), format!("xml:{}", a.local), a.value.clone()));
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
            self.node(c, &child_rendered, false);
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
        let src = "<r xmlns=\"urn:d\" xmlns:a=\"urn:a\" xml:lang=\"es\"><a:x b=\"1\"><y/></a:x></r>";
        let doc = Document::parse(src).unwrap();
        let x = doc.descendants(doc.root())[2];
        let inc = C14n::new(Kind::Inclusive10, false).canonicalize(&doc, x, &[]);
        assert_eq!(
            String::from_utf8(inc).unwrap(),
            "<a:x xmlns=\"urn:d\" xmlns:a=\"urn:a\" b=\"1\" xml:lang=\"es\"><y></y></a:x>"
        );
        let exc = C14n::new(Kind::Exclusive, false).canonicalize(&doc, x, &[]);
        assert_eq!(String::from_utf8(exc).unwrap(), "<a:x xmlns:a=\"urn:a\" b=\"1\"><y xmlns=\"urn:d\"></y></a:x>");
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
        let sig = doc.find_descendants(doc.root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")[0];
        let out = C14n::new(Kind::Inclusive10, false).canonicalize(&doc, doc.root(), &[sig]);
        assert_eq!(String::from_utf8(out).unwrap(), "<doc><a>1</a></doc>");
    }
}
