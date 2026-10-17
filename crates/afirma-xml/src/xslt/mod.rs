//! Procesador XSLT 1.0 para la transformada XSLT de XMLDSig
//! (`http://www.w3.org/TR/1999/REC-xslt-19991116`).
//!
//! Reproduce lo que hace `TransformXSLT` de Apache Santuario con el XSLT del
//! JDK (XSLTC) bajo `FEATURE_SECURE_PROCESSING`, porque la huella de la
//! referencia se calcula sobre los octetos que produce:
//!
//! 1. la hoja (`xsl:stylesheet` o `xsl:transform`, hijo de `ds:Transform`) se
//!    reserializa con una transformación identidad desde su nodo DOM, lo que
//!    pierde las declaraciones de espacios de nombres de los ancestros que no
//!    se usan en nombres y ordena los atributos;
//! 2. la entrada son octetos (un conjunto de nodos se convierte antes con
//!    C14N 1.0 sin comentarios);
//! 3. la salida son los octetos del serializador del JDK ([`output`]).
//!
//! La hoja procede de una firma no confiable, así que no hay acceso a
//! recursos externos (`xsl:import`/`xsl:include`, `document()` con URI, DTD
//! externas), no hay funciones de extensión y hay límites de recursión, de
//! trabajo y de tamaño de la salida, además de los límites de XPath del JDK
//! (`jdk.xml.xpathExprGrpLimit`, `jdk.xml.xpathExprOpLimit` y
//! `jdk.xml.xpathTotalOpLimit`). La transformación se ejecuta en un hilo con
//! pila suficiente para el límite de recursión.
//!
//! AutoFirma 1.9 valida con la validación segura de Santuario, que prohíbe
//! esta transformada: [`crate::dsig::RefOptions`] decide si se rechaza (por
//! defecto, como Java) o se aplica.
//!
//! La paridad se comprueba con `tools/oracle/xslt/XsltOracle.java`: el corpus
//! de `testdata/xslt/cases/` con sus salidas del JDK en
//! `testdata/xslt/expected/` y las firmas de `testdata/xslt/signed/`.

mod collate;
mod collation_table;
mod compile;
mod exec;
mod floating_decimal;
mod javamap;
mod number;
mod output;
mod pattern;
mod tree;

use crate::dom::{Document, NodeId, NodeKind};

pub(crate) use compile::Stylesheet;

/// Espacio de nombres de XSLT.
pub const XSLT_NS: &str = "http://www.w3.org/1999/XSL/Transform";

/// Límites de recursos de una transformación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Profundidad máxima de llamadas a plantillas e instrucciones anidadas.
    pub max_depth: usize,
    /// Unidades de trabajo máximas (nodos recorridos, expresiones evaluadas,
    /// instrucciones ejecutadas).
    pub max_steps: u64,
    /// Tamaño máximo de la salida y de los fragmentos de árbol construidos
    /// (en caracteres).
    pub max_output: usize,
    /// Número máximo de nodos de los fragmentos de árbol de resultado.
    pub max_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 1000,
            max_steps: 50_000_000,
            max_output: 64 << 20,
            max_nodes: 2_000_000,
        }
    }
}

/// Error de la transformación XSLT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XsltError {
    /// La hoja no es válida (equivale a `TransformerConfigurationException`).
    #[error("hoja XSLT no válida: {0}")]
    Compile(String),
    /// Error durante la transformación (`TransformerException`).
    #[error("error al aplicar la hoja XSLT: {0}")]
    Runtime(String),
    /// Los datos de entrada no son XML válido o no se pueden usar.
    #[error("la entrada de la transformada XSLT no es válida: {0}")]
    Input(String),
    /// Se ha superado un límite de recursos.
    #[error("la transformación XSLT supera el límite de {0}")]
    Limit(String),
}

impl XsltError {
    pub(crate) fn limit(what: &str) -> XsltError {
        XsltError::Limit(what.to_string())
    }
}

/// Aplica una hoja ya compilada a unos octetos de entrada (en el hilo
/// actual: ver [`with_stack`]).
pub(crate) fn transform(sheet: &Stylesheet, input: &[u8], limits: &Limits) -> Result<Vec<u8>, XsltError> {
    let source = tree::Source::parse(input, sheet, limits)?;
    exec::run(sheet, source, limits)
}

/// Transformada XSLT de XMLDSig como `TransformXSLT` de Santuario: busca la
/// hoja entre los hijos de `transform` (primero `xsl:stylesheet`, después
/// `xsl:transform`), la reserializa desde el DOM, la compila y la aplica a
/// los octetos de entrada.
pub fn transform_xslt(
    doc: &Document,
    transform_el: NodeId,
    input: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>, XsltError> {
    let find = |local: &str| {
        doc.child_elements(transform_el)
            .find(|&c| doc.element(c).is_some_and(|e| e.is(XSLT_NS, local)))
    };
    let sheet_el = find("stylesheet")
        .or_else(|| find("transform"))
        .ok_or_else(|| XsltError::Compile("la transformada no contiene xslt:stylesheet".into()))?;
    transform_stylesheet(doc, sheet_el, input, limits)
}

/// Aplica la hoja cuyo elemento es `sheet_el` (reserializándola desde el DOM
/// como Santuario) a los octetos de entrada.
pub fn transform_stylesheet(
    doc: &Document,
    sheet_el: NodeId,
    input: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>, XsltError> {
    check_depth(doc, sheet_el, limits.max_depth)?;
    let text = reserialize(doc, sheet_el);
    with_stack(limits, || {
        let sheet_doc = Document::parse(&text).map_err(|e| XsltError::Compile(e.to_string()))?;
        let sheet = Stylesheet::compile(&sheet_doc, limits)?;
        transform(&sheet, input, limits)
    })
}

/// La compilación, la reserialización y la ejecución son recursivas: una hoja
/// más profunda que el límite de recursión se rechaza antes de recorrerla.
fn check_depth(doc: &Document, el: NodeId, max: usize) -> Result<(), XsltError> {
    // Los nodos del subárbol son contiguos y cada padre precede a sus hijos.
    let (start, end) = (el.0, doc.subtree_end(el));
    let mut depth = vec![0usize; end - start];
    for i in start + 1..end {
        let d = doc.parent(NodeId(i)).map_or(0, |p| depth[p.0 - start] + 1);
        if d > max {
            return Err(XsltError::limit("profundidad de la hoja"));
        }
        depth[i - start] = d;
    }
    Ok(())
}

/// Ejecuta `f` en un hilo con pila suficiente para `limits.max_depth` niveles
/// de recursión (las hojas no confiables no deben poder desbordar la pila del
/// hilo que valida).
fn with_stack<T: Send>(limits: &Limits, f: impl FnOnce() -> Result<T, XsltError> + Send) -> Result<T, XsltError> {
    const BASE: usize = 64 << 20;
    const PER_LEVEL: usize = 64 << 10;
    let size = BASE.saturating_add(limits.max_depth.saturating_mul(PER_LEVEL));
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("xslt".into())
            .stack_size(size)
            .spawn_scoped(scope, f)
            .map_err(|e| XsltError::Runtime(format!("no se ha podido crear el hilo de la transformación: {e}")))?;
        handle
            .join()
            .map_err(|_| XsltError::Runtime("la transformación XSLT ha terminado de forma anómala".into()))?
    })
}

/// Texto de un elemento tal como lo escribe la transformación identidad de
/// XSLTC desde un nodo DOM (`DOM2TO` con `ToXMLStream`): los atributos en el
/// orden de `NamedNodeMap` (por nombre) y solo las declaraciones de espacios
/// de nombres presentes en el subárbol o necesarias para sus nombres.
pub(crate) fn reserialize(doc: &Document, el: NodeId) -> String {
    let mut out = String::new();
    let mut scopes: Vec<Vec<(String, String)>> = vec![vec![(String::new(), String::new())]];
    reserialize_node(doc, el, &mut out, &mut scopes);
    out
}

fn lookup_scope<'a>(scopes: &'a [Vec<(String, String)>], prefix: &str) -> Option<&'a str> {
    scopes
        .iter()
        .rev()
        .flat_map(|s| s.iter().rev())
        .find(|(p, _)| p == prefix)
        .map(|(_, u)| u.as_str())
}

/// Orden de `String.compareTo` de Java (unidades UTF-16).
pub(crate) fn java_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn esc_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
    out
}

fn esc_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
    out
}

fn reserialize_node(doc: &Document, n: NodeId, out: &mut String, scopes: &mut Vec<Vec<(String, String)>>) {
    match doc.kind(n) {
        NodeKind::Element(e) => {
            let qname = e.qname();
            let mut decls: Vec<(String, String)> = Vec::new();
            let mut attrs_text = String::new();
            let declare =
                |prefix: &str, uri: &str, scopes: &Vec<Vec<(String, String)>>, decls: &mut Vec<(String, String)>| {
                    if prefix.starts_with("xml") {
                        return false;
                    }
                    let current = decls
                        .iter()
                        .rev()
                        .find(|(p, _)| p == prefix)
                        .map(|(_, u)| u.as_str())
                        .or_else(|| lookup_scope(scopes, prefix));
                    if current == Some(uri) {
                        return false;
                    }
                    decls.push((prefix.to_string(), uri.to_string()));
                    true
                };
            // Atributos del DOM en orden de nombre (las declaraciones xmlns
            // son atributos más).
            let mut ns_attrs: Vec<(String, String, String)> = e
                .ns_decls
                .iter()
                .map(|d| match &d.prefix {
                    Some(p) => (format!("xmlns:{p}"), p.clone(), d.uri.clone()),
                    None => ("xmlns".to_string(), String::new(), d.uri.clone()),
                })
                .collect();
            ns_attrs.sort_by(|a, b| java_cmp(&a.0, &b.0));
            let mut pending: Vec<String> = Vec::new();
            for (name, prefix, uri) in &ns_attrs {
                let _ = name;
                if declare(prefix, uri, scopes, &mut decls) {
                    pending.push(xmlns_attr(prefix, uri));
                }
            }
            let mut attrs: Vec<&crate::dom::Attribute> = e.attrs.iter().collect();
            attrs.sort_by(|a, b| java_cmp(&a.qname(), &b.qname()));
            for a in attrs {
                if let (Some(uri), Some(p)) = (&a.ns, &a.prefix)
                    && !uri.is_empty()
                    && declare(p, uri, scopes, &mut decls)
                {
                    pending.push(xmlns_attr(p, uri));
                }
                pending.push(format!(" {}=\"{}\"", a.qname(), esc_attr(&a.value)));
            }
            match &e.ns {
                Some(uri) => {
                    let p = e.prefix.clone().unwrap_or_default();
                    if declare(&p, uri, scopes, &mut decls) {
                        pending.push(xmlns_attr(&p, uri));
                    }
                }
                None => {
                    if declare("", "", scopes, &mut decls) {
                        pending.push(" xmlns=\"\"".to_string());
                    }
                }
            }
            for p in pending {
                attrs_text.push_str(&p);
            }
            out.push('<');
            out.push_str(&qname);
            out.push_str(&attrs_text);
            let children = doc.children(n);
            if children.is_empty() {
                out.push_str("/>");
                return;
            }
            out.push('>');
            scopes.push(decls);
            for &c in children {
                reserialize_node(doc, c, out, scopes);
            }
            scopes.pop();
            out.push_str("</");
            out.push_str(&qname);
            out.push('>');
        }
        NodeKind::Text { text, .. } => out.push_str(&esc_text(text)),
        NodeKind::Comment(c) => {
            out.push_str("<!--");
            out.push_str(c);
            out.push_str("-->");
        }
        NodeKind::Pi { target, data } => {
            out.push_str("<?");
            out.push_str(target);
            if !data.is_empty() {
                out.push(' ');
                out.push_str(data);
            }
            out.push_str("?>");
        }
        NodeKind::Document => {
            for &c in doc.children(n) {
                reserialize_node(doc, c, out, scopes);
            }
        }
    }
}

fn xmlns_attr(prefix: &str, uri: &str) -> String {
    if prefix.is_empty() {
        format!(" xmlns=\"{}\"", esc_attr(uri))
    } else {
        format!(" xmlns:{prefix}=\"{}\"", esc_attr(uri))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserialization_drops_unused_ancestor_namespaces() {
        let src = format!(
            "<ds:Transform xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:u=\"urn:u\" xmlns=\"urn:d\"><xsl:stylesheet xmlns:xsl=\"{XSLT_NS}\" version=\"1.0\" b=\"2\" a=\"1\"><xsl:template match=\"/\"><r u:x=\"1\"/></xsl:template></xsl:stylesheet></ds:Transform>"
        );
        let doc = Document::parse(&src).unwrap();
        let t = doc.document_element().unwrap();
        let s = doc.child_elements(t).next().unwrap();
        assert_eq!(
            reserialize(&doc, s),
            format!(
                "<xsl:stylesheet xmlns:xsl=\"{XSLT_NS}\" a=\"1\" b=\"2\" version=\"1.0\"><xsl:template match=\"/\"><r xmlns:u=\"urn:u\" u:x=\"1\" xmlns=\"urn:d\"/></xsl:template></xsl:stylesheet>"
            )
        );
    }
}
