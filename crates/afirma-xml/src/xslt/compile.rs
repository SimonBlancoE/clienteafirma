//! Compilación de la hoja: del DOM de la hoja a un árbol de instrucciones.
//!
//! Se reproducen las decisiones que XSLTC toma al compilar y que se notan en
//! la salida: qué espacios de nombres declara cada elemento literal y en qué
//! orden (una `Hashtable` de Java), qué atributos literales se escriben
//! directamente (`addUniqueAttribute`) y con qué indicadores HTML, las
//! exclusiones de prefijos, los alias de espacios de nombres, la prioridad de
//! las plantillas, los tipos enteros de XPath (`int` de Java, que desborda) y
//! los límites de operadores de XPath del JDK.

use std::cell::Cell;
use std::collections::HashMap;

use super::javamap::{JavaHashMapOrder, JavaHashtable};
use super::output::{ElemDesc, HTML_ATTREMPTY, HTML_ATTRURL, NO_BAD_CHARS, OutputSettings, elem};
use super::pattern::Pattern;
use super::{Limits, XSLT_NS, XsltError};
use crate::dom::{Document, NodeId, NodeKind, XML_NS};
use crate::xpath::{BinOp, Expr, NumKind, PathStart, XPath, operator_counts};

type CResult<T> = Result<T, XsltError>;

/// `SystemIDResolver.isAbsoluteURI` y `new URL(href)` de Java: `true` si el
/// URI es absoluto y su esquema no es válido o no tiene manejador.
fn href_is_ignored_by_java(href: &str) -> bool {
    let index_of = |c: char| href.find(c).map_or(-1, |i| i as i64);
    let (frag, query, slash, colon) = (index_of('#'), index_of('?'), index_of('/'), index_of(':'));
    let mut index = href.len() as i64 - 1;
    if frag > 0 {
        index = frag;
    }
    if query > 0 && query < index {
        index = query;
    }
    if slash > 0 && slash < index {
        index = slash;
    }
    if !(colon > 0 && colon < index) {
        // Relativo: se resuelve contra `user.dir` (esquema `file`).
        return false;
    }
    let scheme = href[..colon as usize].to_ascii_lowercase();
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'));
    !valid
        || !matches!(
            scheme.as_str(),
            "file" | "jar" | "jrt" | "jmod" | "http" | "https" | "ftp" | "mailto"
        )
}

fn cerr<T>(msg: impl Into<String>) -> CResult<T> {
    Err(XsltError::Compile(msg.into()))
}

/// Espacio de nombres de las extensiones propias de XSLTC.
pub(crate) const TRANSLET_URI: &str = "http://xml.apache.org/xalan/xsltc";
const REDIRECT_URI: &str = "http://xml.apache.org/xalan/redirect";
pub(crate) const EXSLT_COMMON: &str = "http://exslt.org/common";
pub(crate) const XALAN_URI: &str = "http://xml.apache.org/xalan";

/// Nombre expandido.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct QName {
    pub ns: Option<String>,
    pub local: String,
}

impl QName {
    pub(crate) fn local(l: &str) -> QName {
        QName {
            ns: None,
            local: l.to_string(),
        }
    }
}

/// Plantilla de valor de atributo.
#[derive(Clone, Debug)]
pub(crate) enum AvtPart {
    Lit(String),
    Expr(XPath),
}

#[derive(Clone, Debug)]
pub(crate) struct Avt {
    pub parts: Vec<AvtPart>,
}

impl Avt {
    pub(crate) fn lit(s: &str) -> Avt {
        Avt {
            parts: vec![AvtPart::Lit(s.to_string())],
        }
    }

    /// Valor si no contiene expresiones.
    pub(crate) fn literal(&self) -> Option<String> {
        let mut s = String::new();
        for p in &self.parts {
            match p {
                AvtPart::Lit(l) => s.push_str(l),
                AvtPart::Expr(_) => return None,
            }
        }
        Some(s)
    }
}

/// Valor de una variable, un parámetro o un `xsl:with-param`.
#[derive(Debug)]
pub(crate) enum VarValue {
    Select(XPath),
    Content(Vec<Instr>),
    /// Ni `select` ni contenido: la cadena vacía.
    Empty,
}

/// Declaración de variable o parámetro.
#[derive(Debug)]
pub(crate) struct VarDecl {
    pub name: QName,
    pub value: VarValue,
    pub is_param: bool,
    /// XSLTC no evalúa las variables a las que nada hace referencia.
    pub referenced: Cell<bool>,
    /// Tipo `int` de XSLTC (expresión `select` entera).
    pub is_int: bool,
}

#[derive(Debug)]
pub(crate) struct WithParam {
    pub name: QName,
    pub value: VarValue,
}

#[derive(Debug)]
pub(crate) struct SortSpec {
    pub select: XPath,
    pub order: Avt,
    pub data_type: Avt,
    pub lang: Avt,
    pub case_order: Avt,
}

/// Atributo de un elemento literal.
#[derive(Debug)]
pub(crate) enum LitAttr {
    /// `name="valor"`; `unique` lleva los indicadores de `addUniqueAttribute`.
    Attr {
        name: String,
        value: Avt,
        unique: Option<u32>,
    },
    UseSets(Vec<QName>),
}

#[derive(Debug)]
pub(crate) struct LiteralElem {
    pub name: String,
    /// Declaraciones (`_accessedPrefixes`) en orden de iteración de Java.
    pub namespaces: Vec<(String, String)>,
    pub attrs: Vec<LitAttr>,
    pub body: Vec<Instr>,
}

#[derive(Debug)]
pub(crate) struct XslElement {
    pub ignore: bool,
    pub literal: bool,
    pub name: Avt,
    pub prefix: String,
    pub namespace: Option<Avt>,
    pub use_sets: Vec<QName>,
    pub body: Vec<Instr>,
}

#[derive(Debug)]
pub(crate) enum Content {
    Text(String),
    Instrs(Vec<Instr>),
}

#[derive(Debug)]
pub(crate) struct XslAttribute {
    pub namespace: Option<(String, Avt)>,
    pub literal: bool,
    pub name: Avt,
    pub content: Content,
    pub unique: Option<u32>,
}

/// Nivel de `xsl:number`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NumberLevel {
    Single,
    Multiple,
    Any,
}

#[derive(Debug)]
pub(crate) struct NumberSpec {
    pub level: NumberLevel,
    pub count: Option<Pattern>,
    pub from: Option<Pattern>,
    pub value: Option<XPath>,
    pub format: Avt,
    pub lang: Avt,
    pub letter_value: Avt,
    pub grouping_separator: Option<Avt>,
    pub grouping_size: Option<Avt>,
}

/// Instrucción de una plantilla.
#[derive(Debug)]
pub(crate) enum Instr {
    Text {
        text: String,
        escaping: bool,
    },
    Literal(Box<LiteralElem>),
    ValueOf {
        select: XPath,
        escaping: bool,
    },
    CopyOf(XPath),
    Copy {
        use_sets: Vec<QName>,
        body: Vec<Instr>,
    },
    ApplyTemplates {
        select: Option<XPath>,
        mode: Option<QName>,
        sorts: Vec<SortSpec>,
        params: Vec<WithParam>,
    },
    CallTemplate {
        template: usize,
        params: Vec<WithParam>,
    },
    ApplyImports,
    ForEach {
        select: XPath,
        sorts: Vec<SortSpec>,
        body: Vec<Instr>,
    },
    If {
        test: XPath,
        body: Vec<Instr>,
    },
    Choose {
        whens: Vec<(XPath, Vec<Instr>)>,
        otherwise: Option<Vec<Instr>>,
    },
    Element(Box<XslElement>),
    Attribute(Box<XslAttribute>),
    Comment(Content),
    Pi {
        name: Avt,
        literal: bool,
        body: Vec<Instr>,
    },
    Number(Box<NumberSpec>),
    Variable(usize),
    Message {
        body: Vec<Instr>,
        terminate: bool,
    },
    /// Elemento no soportado sin `xsl:fallback`: error al ejecutarse.
    Unsupported {
        name: String,
        extension: bool,
    },
    /// Contenido de los `xsl:fallback` de un elemento no soportado.
    Fallback(Vec<Instr>),
}

#[derive(Debug)]
pub(crate) struct Template {
    pub mode: Option<QName>,
    pub pattern: Option<Pattern>,
    pub priority: f64,
    pub position: usize,
    pub params: Vec<usize>,
    pub body: Vec<Instr>,
}

/// Regla de plantilla: alternativa de un patrón con su prioridad.
#[derive(Debug, Clone)]
pub(crate) struct Rule {
    pub template: usize,
    pub alt: usize,
    pub priority: f64,
    pub position: usize,
}

#[derive(Debug)]
pub(crate) struct KeyDef {
    pub matches: Pattern,
    pub use_: XPath,
}

/// Símbolos de `xsl:decimal-format` (`DecimalFormatSymbols(Locale.US)`).
#[derive(Debug, Clone)]
pub(crate) struct DecimalSymbols {
    pub decimal_separator: char,
    pub grouping_separator: char,
    pub infinity: String,
    pub minus_sign: char,
    pub nan: String,
    pub percent: char,
    pub per_mille: char,
    pub zero_digit: char,
    pub digit: char,
    pub pattern_separator: char,
}

impl Default for DecimalSymbols {
    fn default() -> Self {
        DecimalSymbols {
            decimal_separator: '.',
            grouping_separator: ',',
            infinity: "Infinity".into(),
            minus_sign: '-',
            nan: "NaN".into(),
            percent: '%',
            per_mille: '\u{2030}',
            zero_digit: '0',
            digit: '#',
            pattern_separator: ';',
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct AttrSet {
    /// Conjuntos usados y atributos de cada definición, en orden.
    pub parts: Vec<(Vec<QName>, Vec<Instr>)>,
}

/// Acción de una regla de espacios en blanco.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WsAction {
    Strip,
    Preserve,
}

#[derive(Clone, Debug)]
struct WsRule {
    action: WsAction,
    namespace: String,
    element: String,
    /// 1 elemento, 2 espacio de nombres, 3 todos.
    strength: u8,
    priority: i32,
}

/// Hoja de estilo compilada.
#[derive(Debug)]
pub struct Stylesheet {
    pub(crate) templates: Vec<Template>,
    pub(crate) rules: HashMap<Option<QName>, Vec<Rule>>,
    pub(crate) vars: Vec<VarDecl>,
    /// Variables y parámetros globales, en orden de documento.
    pub(crate) globals: Vec<usize>,
    pub(crate) keys: HashMap<QName, Vec<KeyDef>>,
    pub(crate) decimal_formats: HashMap<Option<QName>, DecimalSymbols>,
    pub(crate) attr_sets: HashMap<QName, AttrSet>,
    ws_rules: Option<(Vec<WsRule>, WsAction)>,
    pub(crate) output: OutputSettings,
}

impl Stylesheet {
    /// Hay reglas `xsl:strip-space` (la hoja actúa como `StripFilter`).
    pub(crate) fn has_strip_rules(&self) -> bool {
        self.ws_rules.is_some()
    }

    /// Indica si se eliminan los nodos de texto en blanco hijos de un
    /// elemento con este nombre (`stripSpace` generado por XSLTC).
    pub(crate) fn should_strip(&self, ns: &str, local: &str) -> bool {
        let Some((rules, default)) = &self.ws_rules else {
            return false;
        };
        for r in rules {
            let hit = match r.strength {
                2 => r.namespace == ns,
                1 => r.element == local && r.namespace == ns,
                _ => false,
            };
            if hit {
                return r.action == WsAction::Strip;
            }
        }
        *default == WsAction::Strip
    }

    /// Compila la hoja (documento cuyo elemento raíz es `xsl:stylesheet`,
    /// `xsl:transform` o un elemento literal con `xsl:version`).
    pub fn compile(doc: &Document, limits: &Limits) -> Result<Stylesheet, XsltError> {
        let _ = limits;
        let root = doc
            .document_element()
            .ok_or_else(|| XsltError::Compile("hoja vacía".into()))?;
        let mut c = Compiler::new(doc);
        c.compile_root(root)?;
        c.finish()
    }
}

/// Funciones de la tabla de primitivas de XSLTC (`function-available`).
const PRIMOPS: &[&str] = &[
    "current",
    "last",
    "position",
    "true",
    "false",
    "not",
    "name",
    "generate-id",
    "ceiling",
    "floor",
    "round",
    "contains",
    "number",
    "boolean",
    "string",
    "translate",
    "string-length",
    "starts-with",
    "format-number",
    "unparsed-entity-uri",
    "key",
    "id",
    "namespace-uri",
    "function-available",
    "element-available",
    "document",
    "count",
    "sum",
    "local-name",
    "substring",
    "substring-after",
    "substring-before",
    "normalize-space",
    "system-property",
    "nodeset",
    "objectType",
    "cast",
    "+",
    "-",
    "*",
    "/",
    "%",
    "<",
    "<=",
    ">",
    ">=",
    "or",
    "and",
    "u-",
];

/// Funciones de XPath y XSLT que XSLTC implementa (con su aridad).
fn core_function_arity(name: &str, n: usize) -> Option<bool> {
    let ok = match name {
        "last" | "position" | "true" | "false" | "current" => n == 0,
        "count" | "not" | "boolean" | "floor" | "ceiling" | "round" | "sum" | "id" | "lang" => n == 1,
        "local-name" | "namespace-uri" | "name" | "string" | "string-length" | "normalize-space" | "number"
        | "generate-id" => n <= 1,
        "concat" => n >= 2,
        "starts-with" | "contains" | "substring-before" | "substring-after" => n == 2,
        "substring" => n == 2 || n == 3,
        "translate" => n == 3,
        "key" => n == 2,
        "format-number" => n == 2 || n == 3,
        "system-property" | "unparsed-entity-uri" | "element-available" | "function-available" => n == 1,
        "document" => n == 1 || n == 2,
        _ => return None,
    };
    Some(ok)
}

/// Métodos estáticos públicos de las clases de extensión del JDK para los
/// espacios de nombres conocidos (lo que XSLTC comprueba por reflexión).
fn extension_methods(ns: &str) -> Option<&'static [&'static str]> {
    Some(match ns {
        "http://exslt.org/math" => &[
            "max", "min", "highest", "lowest", "abs", "sqrt", "power", "log", "random", "sin", "cos", "tan", "asin",
            "acos", "atan", "atan2", "exp", "constant",
        ],
        "http://exslt.org/sets" => &[
            "difference",
            "intersection",
            "distinct",
            "hasSameNode",
            "leading",
            "trailing",
        ],
        "http://exslt.org/strings" => &["align", "concat", "padding", "split", "tokenize"],
        "http://exslt.org/dates-and-times" => &[
            "dateTime",
            "date",
            "time",
            "year",
            "leapYear",
            "monthInYear",
            "monthName",
            "monthAbbreviation",
            "weekInYear",
            "dayInYear",
            "dayInMonth",
            "dayOfWeekInMonth",
            "dayInWeek",
            "dayName",
            "dayAbbreviation",
            "hourInDay",
            "minuteInHour",
            "secondInMinute",
            "formatDate",
        ],
        EXSLT_COMMON => &["nodeSet", "objectType"],
        XALAN_URI => &[
            "nodeset",
            "intersection",
            "difference",
            "distinct",
            "hasSameNodes",
            "evaluate",
            "tokenize",
            "checkEnvironment",
        ],
        _ => return None,
    })
}

/// Espacio de nombres de llamadas Java (cualquier clase del JDK).
fn is_java_namespace(ns: &str) -> bool {
    ns.starts_with("http://xml.apache.org/xalan/java")
        || ns.starts_with("http://xml.apache.org/xslt/java")
        || ns.starts_with("http://xml.apache.org/xalan/xsltc/java")
        || ns.starts_with("xalan://")
        || ns.starts_with("java:")
}

fn replace_dash(s: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in s.chars() {
        if c == '-' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Resultado de clasificar una llamada a función con espacio de nombres.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtKind {
    /// `exsl:node-set` / `xalan:nodeset`.
    NodeSet,
    /// `exsl:object-type`.
    ObjectType,
    /// Función de extensión existente: error al llamarla (procesamiento seguro).
    Forbidden,
}

/// Clasifica una función con espacio de nombres; `None` si XSLTC no la
/// encuentra al compilar.
pub(crate) fn classify_extension(ns: &str, local: &str) -> Option<ExtKind> {
    let l = if local.find('-').is_some_and(|i| i > 0) {
        replace_dash(local)
    } else {
        local.to_string()
    };
    if (ns == EXSLT_COMMON && l == "nodeSet") || (ns == XALAN_URI && l == "nodeset") {
        return Some(ExtKind::NodeSet);
    }
    if ns == EXSLT_COMMON && l == "objectType" {
        return Some(ExtKind::ObjectType);
    }
    if ns == TRANSLET_URI {
        return None;
    }
    if is_java_namespace(ns) || local.contains('.') {
        return Some(ExtKind::Forbidden);
    }
    match extension_methods(ns) {
        Some(methods) if methods.contains(&l.as_str()) => Some(ExtKind::Forbidden),
        _ => None,
    }
}

/// `function-available` de XSLTC para un nombre ya resuelto.
fn function_available(ns: Option<&str>, local: &str) -> bool {
    match ns {
        None | Some("") | Some(TRANSLET_URI) => PRIMOPS.contains(&local),
        Some(ns) => {
            let l = if local.find('-').is_some_and(|i| i > 0) {
                replace_dash(local)
            } else {
                local.to_string()
            };
            if is_java_namespace(ns) {
                // Exigiría reflexión sobre clases arbitrarias del JDK.
                return false;
            }
            extension_methods(ns).is_some_and(|m| m.contains(&l.as_str()))
        }
    }
}

const XSLT_INSTRUCTIONS: &[&str] = &[
    "template",
    "stylesheet",
    "transform",
    "text",
    "if",
    "choose",
    "when",
    "otherwise",
    "for-each",
    "message",
    "number",
    "comment",
    "copy",
    "copy-of",
    "param",
    "with-param",
    "variable",
    "output",
    "sort",
    "key",
    "fallback",
    "attribute",
    "attribute-set",
    "value-of",
    "element",
    "call-template",
    "apply-templates",
    "apply-imports",
    "decimal-format",
    "import",
    "include",
    "strip-space",
    "preserve-space",
    "processing-instruction",
    "namespace-alias",
];

/// `element-available` de XSLTC.
fn element_available(ns: Option<&str>, local: &str) -> bool {
    match ns {
        Some(XSLT_NS) => XSLT_INSTRUCTIONS.contains(&local),
        Some(TRANSLET_URI) => local == "output",
        Some(REDIRECT_URI) => local == "write",
        _ => false,
    }
}

/// Hijo de un elemento de la hoja para la compilación.
#[derive(Clone, Debug)]
enum Child {
    Text(String),
    Element(NodeId),
}

/// Ámbito de variables durante la compilación.
struct Scope {
    names: Vec<(QName, usize)>,
}

struct Compiler<'a> {
    doc: &'a Document,
    templates: Vec<Template>,
    named: HashMap<QName, usize>,
    vars: Vec<VarDecl>,
    globals: Vec<usize>,
    global_names: HashMap<QName, usize>,
    keys: HashMap<QName, Vec<KeyDef>>,
    decimal_formats: HashMap<Option<QName>, DecimalSymbols>,
    attr_sets: HashMap<QName, AttrSet>,
    ws_rules: Vec<WsRule>,
    output: OutputSettings,
    output_seen: bool,
    method: Option<String>,
    /// Referencias pendientes de comprobar al final.
    pending_calls: Vec<(QName, usize)>,
    pending_sets: Vec<QName>,
    scopes: Vec<Scope>,
    /// URI excluidos con su cuenta de referencias (`SymbolTable._excludedURI`).
    excluded: HashMap<String, i32>,
    aliases: HashMap<String, String>,
    ns_counter: u32,
    forwards_compatible: bool,
    indent_explicit: Option<bool>,
    total_ops: usize,
    position: usize,
    /// Pila de elementos literales en compilación: prefijos accedidos.
    lre_stack: Vec<LreFrame>,
}

/// Datos de un elemento literal mientras se compila su contenido.
struct LreFrame {
    accessed: JavaHashtable<String>,
    /// El padre directo es otro elemento literal.
    parent_is_lre: bool,
    /// Atributos y `xsl:attribute` (para la comprobación de unicidad).
    attr_names: Vec<Option<String>>,
}

fn is_xslt(doc: &Document, n: NodeId, local: &str) -> bool {
    doc.element(n).is_some_and(|e| e.is(XSLT_NS, local))
}

fn is_ws(s: &str) -> bool {
    s.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

/// `XML11Char.isXML11ValidNCName` (aproximado a los nombres XML habituales).
pub(crate) fn is_ncname(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_alphabetic() || first == '_' || (first as u32) > 0x7f)
        && chars.all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.') || (c as u32) > 0x7f)
}

/// `XML11Char.isXML11ValidQName`.
pub(crate) fn is_qname(s: &str) -> bool {
    match s.split_once(':') {
        Some((p, l)) => is_ncname(p) && is_ncname(l),
        None => is_ncname(s),
    }
}

impl<'a> Compiler<'a> {
    fn new(doc: &'a Document) -> Self {
        Compiler {
            doc,
            templates: Vec::new(),
            named: HashMap::new(),
            vars: Vec::new(),
            globals: Vec::new(),
            global_names: HashMap::new(),
            keys: HashMap::new(),
            decimal_formats: HashMap::new(),
            attr_sets: HashMap::new(),
            ws_rules: Vec::new(),
            output: OutputSettings::default(),
            output_seen: false,
            method: None,
            pending_calls: Vec::new(),
            pending_sets: Vec::new(),
            scopes: Vec::new(),
            excluded: HashMap::new(),
            aliases: HashMap::new(),
            ns_counter: 0,
            forwards_compatible: false,
            indent_explicit: None,
            total_ops: 0,
            position: 0,
            lre_stack: Vec::new(),
        }
    }

    /// Atributo de un elemento de la hoja (prestado del documento, no del
    /// compilador).
    fn attr(&self, n: NodeId, name: &str) -> Option<&'a str> {
        let doc: &'a Document = self.doc;
        doc.element(n).and_then(|e| e.attr(name))
    }

    fn attr_or_empty(&self, n: NodeId, name: &str) -> String {
        self.attr(n, name).unwrap_or("").to_string()
    }

    /// Prefijos en ámbito de un elemento de la hoja (con `xml`).
    fn ns_map(&self, n: NodeId) -> HashMap<String, String> {
        let mut m: HashMap<String, String> = self.doc.in_scope_namespaces(n).into_iter().collect();
        m.insert("xml".into(), XML_NS.into());
        m
    }

    /// `SyntaxTreeNode.lookupNamespace` (el prefijo vacío sin declarar es "").
    fn lookup_ns(&self, n: NodeId, prefix: &str) -> Option<String> {
        if prefix == "xml" {
            return Some(XML_NS.into());
        }
        match self.doc.in_scope_namespaces(n).get(prefix) {
            Some(u) => Some(u.clone()),
            None if prefix.is_empty() => Some(String::new()),
            None => None,
        }
    }

    /// `SyntaxTreeNode.lookupPrefix`: el primer nodo, de dentro afuera, que
    /// declare el URI, recorriendo sus declaraciones en orden de `HashMap`.
    fn lookup_prefix(&self, n: NodeId, uri: &str) -> Option<String> {
        let mut cur = Some(n);
        while let Some(id) = cur {
            if let Some(e) = self.doc.element(id)
                && e.ns_decls.iter().any(|d| d.uri == uri)
            {
                let mut order = JavaHashMapOrder::default();
                for d in &e.ns_decls {
                    order.insert(d.prefix.as_deref().unwrap_or(""));
                }
                for p in order.iter() {
                    let d = e
                        .ns_decls
                        .iter()
                        .rev()
                        .find(|d| d.prefix.as_deref().unwrap_or("") == p)
                        .expect("declaración");
                    if d.uri == uri {
                        return Some(p.to_string());
                    }
                }
            }
            cur = self.doc.parent(id);
            if cur.is_some_and(|p| self.doc.element(p).is_none()) {
                break;
            }
        }
        if uri.is_empty() { Some(String::new()) } else { None }
    }

    /// Nombre cualificado sin espacio por defecto (`getQNameIgnoreDefaultNs`).
    fn qname(&self, n: NodeId, s: &str) -> CResult<QName> {
        let s = s.trim();
        match s.split_once(':') {
            Some((p, l)) => {
                let ns = self
                    .lookup_ns(n, p)
                    .ok_or_else(|| XsltError::Compile(format!("prefijo no declarado: {p}")))?;
                Ok(QName {
                    ns: Some(ns),
                    local: l.to_string(),
                })
            }
            None => Ok(QName::local(s)),
        }
    }

    fn qnames(&self, n: NodeId, s: &str) -> CResult<Vec<QName>> {
        s.split_whitespace().map(|t| self.qname(n, t)).collect()
    }

    // -- XPath -----------------------------------------------------------------

    /// Comprueba los límites de operadores de XPath del JDK.
    fn count_ops(&mut self, text: &str) -> CResult<()> {
        let (groups, ops) = operator_counts(text).map_err(|e| XsltError::Compile(e.to_string()))?;
        self.total_ops += ops;
        if groups > 10 {
            return cerr(format!(
                "la expresión '{text}' tiene {groups} grupos, más que el límite de 10 (jdk.xml.xpathExprGrpLimit)"
            ));
        }
        if ops > 100 {
            return cerr(format!(
                "la expresión '{text}' tiene {ops} operadores, más que el límite de 100 (jdk.xml.xpathExprOpLimit)"
            ));
        }
        if self.total_ops > 10000 {
            return cerr(format!(
                "la hoja tiene {} operadores XPath, más que el límite de 10000 (jdk.xml.xpathTotalOpLimit)",
                self.total_ops
            ));
        }
        Ok(())
    }

    fn xpath(&mut self, n: NodeId, text: &str) -> CResult<XPath> {
        self.count_ops(text)?;
        let ns = self.ns_map(n);
        let mut xp = XPath::compile(text, &ns).map_err(|e| XsltError::Compile(format!("'{text}': {e}")))?;
        self.check_expr(n, &mut xp.expr)?;
        Ok(xp)
    }

    fn xpath_attr(&mut self, n: NodeId, attr: &str) -> CResult<XPath> {
        let Some(text) = self.attr(n, attr).map(str::to_string) else {
            let name = self.doc.element(n).map(|e| e.qname()).unwrap_or_default();
            return cerr(format!("falta el atributo obligatorio '{attr}' en {name}"));
        };
        self.xpath(n, &text)
    }

    fn pattern(&mut self, n: NodeId, text: &str) -> CResult<Pattern> {
        self.count_ops(text)?;
        let ns = self.ns_map(n);
        let mut p = Pattern::parse(text, &ns)?;
        for alt in &mut p.alts {
            if let super::pattern::Start::Call(e) = &mut alt.start {
                self.check_expr(n, e)?;
            }
            for s in &mut alt.steps {
                for pr in &mut s.preds {
                    self.check_expr(n, pr)?;
                }
            }
        }
        Ok(p)
    }

    /// Resuelve variables, comprueba funciones y marca la aritmética entera.
    fn check_expr(&mut self, n: NodeId, e: &mut Expr) -> CResult<bool> {
        Ok(match e {
            Expr::Literal(_) => false,
            Expr::Number(v, kind) => match kind {
                // `Long.valueOf` falla en el analizador léxico de XSLTC.
                NumKind::BigInt => return cerr(format!("literal numérico fuera de rango: {v}")),
                NumKind::Int => *v != 0.0 && *v <= i32::MAX as f64,
                NumKind::Real => false,
            },
            Expr::Var(ns, local) => {
                let q = QName {
                    ns: ns.clone(),
                    local: local.clone(),
                };
                let id = self.resolve_var(&q)?;
                let v = &self.vars[id];
                v.referenced.set(true);
                !v.is_param && v.is_int
            }
            Expr::Neg(x) => self.check_expr(n, x)?,
            Expr::Bin(op, l, r) => {
                let li = self.check_expr(n, l)?;
                let ri = self.check_expr(n, r)?;
                if li && ri && matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul) {
                    let op = *op;
                    let l = std::mem::replace(l, Box::new(Expr::Literal(String::new())));
                    let r = std::mem::replace(r, Box::new(Expr::Literal(String::new())));
                    *e = Expr::IntBin(op, l, r);
                    true
                } else {
                    false
                }
            }
            Expr::IntBin(..) => true,
            Expr::Call(ns, name, args) => {
                for a in args.iter_mut() {
                    self.check_expr(n, a)?;
                }
                match ns {
                    None => {
                        match core_function_arity(name, args.len()) {
                            Some(true) => {}
                            Some(false) => {
                                return cerr(format!("número de argumentos incorrecto en {name}()"));
                            }
                            None => return cerr(format!("no se ha encontrado la función {name}()")),
                        }
                        if name == "function-available" || name == "element-available" {
                            let Expr::Literal(lit) = &args[0] else {
                                return cerr(format!("{name}() requiere un literal"));
                            };
                            let lit = lit.clone();
                            let (fns, flocal) = match lit.split_once(':') {
                                Some((p, l)) => (
                                    Some(
                                        self.lookup_ns(n, p)
                                            .ok_or_else(|| XsltError::Compile(format!("prefijo no declarado: {p}")))?,
                                    ),
                                    l.to_string(),
                                ),
                                None => (None, lit.clone()),
                            };
                            let result = if name == "function-available" {
                                function_available(fns.as_deref(), &flocal)
                            } else {
                                element_available(fns.as_deref(), &flocal)
                            };
                            *e = Expr::Call(None, if result { "true" } else { "false" }.into(), vec![]);
                            return Ok(false);
                        }
                        // Nombres de clave y de formato decimal: se expanden con los
                        // prefijos de la hoja.
                        let name_arg = match name.as_str() {
                            "key" => Some(0),
                            "format-number" if args.len() == 3 => Some(2),
                            _ => None,
                        };
                        if let Some(i) = name_arg
                            && let Expr::Literal(lit) = &args[i]
                            && let Some((p, l)) = lit.split_once(':')
                        {
                            let uri = self
                                .lookup_ns(n, p)
                                .ok_or_else(|| XsltError::Compile(format!("prefijo no declarado: {p}")))?;
                            args[i] = Expr::Literal(format!("{{{uri}}}{l}"));
                        }
                        matches!(name.as_str(), "position" | "last" | "count" | "string-length")
                    }
                    Some(uri) => {
                        let uri = uri.clone();
                        match classify_extension(&uri, name) {
                            Some(_) => false,
                            None => {
                                return cerr(format!("no se ha encontrado el método externo '{uri}.{name}'"));
                            }
                        }
                    }
                }
            }
            Expr::Filter(base, preds) => {
                self.check_expr(n, base)?;
                for p in preds {
                    self.check_expr(n, p)?;
                }
                false
            }
            Expr::Path(start, steps) => {
                if let PathStart::Expr(x) = start {
                    self.check_expr(n, x)?;
                }
                for s in steps {
                    for p in &mut s.preds {
                        self.check_expr(n, p)?;
                    }
                }
                false
            }
        })
    }

    fn resolve_var(&self, q: &QName) -> CResult<usize> {
        for s in self.scopes.iter().rev() {
            if let Some((_, id)) = s.names.iter().rev().find(|(n, _)| n == q) {
                return Ok(*id);
            }
        }
        if let Some(&id) = self.global_names.get(q) {
            return Ok(id);
        }
        cerr(format!("no se ha definido la variable o el parámetro '{}'", q.local))
    }

    /// Plantilla de valor de atributo (`AttributeValueTemplate`).
    fn avt(&mut self, n: NodeId, text: &str) -> CResult<Avt> {
        let bad = || XsltError::Compile(format!("plantilla de valor de atributo no válida: '{text}'"));
        let chars: Vec<char> = text.chars().collect();
        let mut parts = Vec::new();
        let mut lit = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            match c {
                '{' => {
                    if chars.get(i + 1) == Some(&'{') {
                        lit.push('{');
                        i += 2;
                        continue;
                    }
                    // Expresión hasta la '}' de cierre fuera de literales.
                    let mut j = i + 1;
                    let mut quote: Option<char> = None;
                    loop {
                        let Some(&d) = chars.get(j) else { return Err(bad()) };
                        match quote {
                            Some(q) if d == q => quote = None,
                            Some(_) => {}
                            None if d == '\'' || d == '"' => quote = Some(d),
                            None if d == '{' => return Err(bad()),
                            None if d == '}' => break,
                            None => {}
                        }
                        j += 1;
                    }
                    let expr: String = chars[i + 1..j].iter().collect();
                    if !lit.is_empty() {
                        parts.push(AvtPart::Lit(std::mem::take(&mut lit)));
                    }
                    if expr.trim().is_empty() {
                        return Err(bad());
                    }
                    parts.push(AvtPart::Expr(self.xpath(n, &expr)?));
                    i = j + 1;
                }
                '}' => {
                    if chars.get(i + 1) == Some(&'}') {
                        lit.push('}');
                        i += 2;
                    } else {
                        return Err(bad());
                    }
                }
                c => {
                    lit.push(c);
                    i += 1;
                }
            }
        }
        if !lit.is_empty() || parts.is_empty() {
            parts.push(AvtPart::Lit(lit));
        }
        Ok(Avt { parts })
    }

    fn avt_attr(&mut self, n: NodeId, attr: &str) -> CResult<Avt> {
        let text = self.attr_or_empty(n, attr);
        self.avt(n, &text)
    }

    // -- Exclusiones de espacios de nombres -------------------------------------

    fn exclude_uri(&mut self, uri: &str) {
        *self.excluded.entry(uri.to_string()).or_insert(0) += 1;
    }

    fn is_excluded(&self, uri: &str) -> bool {
        self.excluded.get(uri).is_some_and(|c| *c > 0)
    }

    fn exclude_prefixes(&mut self, n: NodeId, list: &str) {
        for p in list.split_whitespace() {
            let uri = if p == "#default" {
                self.lookup_ns(n, "")
            } else {
                self.lookup_ns(n, p)
            };
            if let Some(u) = uri {
                self.exclude_uri(&u);
            }
        }
    }

    fn unexclude_prefixes(&mut self, n: NodeId, list: &str) {
        for p in list.split_whitespace() {
            let uri = if p == "#default" {
                self.lookup_ns(n, "")
            } else {
                self.lookup_ns(n, p)
            };
            if let Some(u) = uri
                && let Some(c) = self.excluded.get_mut(&u)
            {
                *c -= 1;
            }
        }
    }

    fn generate_prefix(&mut self) -> String {
        let p = format!("ns{}", self.ns_counter);
        self.ns_counter += 1;
        p
    }

    // -- Hoja ------------------------------------------------------------------------

    fn compile_root(&mut self, root: NodeId) -> CResult<()> {
        let doc = self.doc;
        let e = doc.element(root).expect("elemento");
        if e.is(XSLT_NS, "stylesheet") || e.is(XSLT_NS, "transform") {
            let version = self.attr_or_empty(root, "version");
            self.forwards_compatible = !version.is_empty() && version != "1.0";
            self.exclude_uri(XSLT_NS);
            let excl = self.attr_or_empty(root, "exclude-result-prefixes");
            self.exclude_prefixes(root, &excl);
            let ext = self.attr_or_empty(root, "extension-element-prefixes");
            self.exclude_prefixes(root, &ext);
            let children: Vec<NodeId> = doc.child_elements(root).collect();
            // Método de salida definitivo (XSLTC lo consulta al generar el
            // código de las plantillas).
            let final_method = children
                .iter()
                .filter(|&&c| is_xslt(doc, c, "output"))
                .filter_map(|&c| self.attr(c, "method").filter(|m| !m.is_empty()).map(str::to_lowercase))
                .next_back();
            for &c in &children {
                if is_xslt(doc, c, "variable") || is_xslt(doc, c, "param") {
                    self.global_var(c)?;
                }
            }
            // Primero variables, parámetros y alias (como `parseOwnChildren`).
            let mut k = 0;
            for &c in &children {
                if is_xslt(doc, c, "variable") || is_xslt(doc, c, "param") {
                    let id = self.globals[k];
                    k += 1;
                    self.scopes.push(Scope { names: vec![] });
                    let (value, is_int) = self.var_value(c)?;
                    self.scopes.pop();
                    self.vars[id].value = value;
                    self.vars[id].is_int = is_int;
                } else if is_xslt(doc, c, "namespace-alias") {
                    let s = self.attr_or_empty(c, "stylesheet-prefix");
                    let r = self.attr_or_empty(c, "result-prefix");
                    self.aliases.insert(s, r);
                }
            }
            self.method = final_method;
            for &c in &children {
                self.top_level(c)?;
            }
            return Ok(());
        }
        // Hoja simplificada: el elemento literal es la plantilla de "/".
        let has_version = e.attr_ns(XSLT_NS, "version").is_some();
        if !has_version {
            return cerr("el elemento raíz de la hoja no es xsl:stylesheet");
        }
        self.exclude_uri(XSLT_NS);
        self.scopes.push(Scope { names: vec![] });
        let body = self.instr(root, false)?.into_iter().collect();
        self.scopes.pop();
        let pattern = Pattern::parse("/", &HashMap::new())?;
        self.templates.push(Template {
            mode: None,
            priority: pattern.priority(),
            pattern: Some(pattern),
            position: 0,
            params: vec![],
            body,
        });
        Ok(())
    }

    fn global_var(&mut self, n: NodeId) -> CResult<()> {
        let is_param = is_xslt(self.doc, n, "param");
        let name = self.attr_or_empty(n, "name");
        if name.is_empty() {
            return cerr("falta el atributo obligatorio 'name' en xsl:variable");
        }
        let q = self.qname(n, &name)?;
        if self.global_names.contains_key(&q) {
            return cerr(format!(
                "se ha definido varias veces la variable '{name}' en el mismo ámbito"
            ));
        }
        // La declaración se registra antes de compilar el valor para admitir
        // referencias adelantadas entre globales.
        let id = self.vars.len();
        self.vars.push(VarDecl {
            name: q.clone(),
            value: VarValue::Empty,
            is_param,
            referenced: Cell::new(false),
            is_int: false,
        });
        self.global_names.insert(q, id);
        self.globals.push(id);
        Ok(())
    }

    fn var_value(&mut self, n: NodeId) -> CResult<(VarValue, bool)> {
        if let Some(sel) = self.attr(n, "select").map(str::to_string)
            && !sel.is_empty()
        {
            self.count_ops(&sel)?;
            let ns = self.ns_map(n);
            let mut xp = XPath::compile(&sel, &ns).map_err(|e| XsltError::Compile(format!("'{sel}': {e}")))?;
            let is_int = self.check_expr(n, &mut xp.expr)?;
            return Ok((VarValue::Select(xp), is_int));
        }
        let body = self.body(n)?;
        if body.is_empty() && !self.has_content(n) {
            Ok((VarValue::Empty, false))
        } else {
            Ok((VarValue::Content(body), false))
        }
    }

    /// `hasContents()`: algún hijo, aunque sea texto en blanco ignorado.
    fn has_content(&self, n: NodeId) -> bool {
        self.doc
            .children(n)
            .iter()
            .any(|&c| matches!(self.doc.kind(c), NodeKind::Element(_) | NodeKind::Text { .. }))
    }

    fn top_level(&mut self, n: NodeId) -> CResult<()> {
        let doc = self.doc;
        let e = doc.element(n).expect("elemento");
        if e.ns.as_deref() != Some(XSLT_NS) {
            // Elementos de nivel superior ajenos a XSLT: se ignoran.
            return Ok(());
        }
        match e.local.as_str() {
            "variable" | "param" | "namespace-alias" => Ok(()),
            "template" => self.template(n),
            "output" => self.output_elem(n),
            "strip-space" | "preserve-space" => {
                let action = if e.local == "strip-space" {
                    WsAction::Strip
                } else {
                    WsAction::Preserve
                };
                let list = self.attr_or_empty(n, "elements");
                if list.trim().is_empty() {
                    return cerr("falta el atributo obligatorio 'elements'");
                }
                for token in list.split_whitespace() {
                    let (namespace, element) = match token.find(':') {
                        Some(col) => {
                            let ns = self.lookup_ns(n, &token[..col]);
                            match ns {
                                Some(u) => (u, token[col + 1..].to_string()),
                                None => (String::new(), token.to_string()),
                            }
                        }
                        None => (String::new(), token.to_string()),
                    };
                    let (strength, priority) = if element == "*" {
                        if namespace.is_empty() { (3u8, 2) } else { (2u8, 1) }
                    } else {
                        (1u8, 0)
                    };
                    self.ws_rules.push(WsRule {
                        action,
                        namespace,
                        element,
                        strength,
                        priority,
                    });
                }
                Ok(())
            }
            "key" => {
                let name = self.attr_or_empty(n, "name");
                let q = self.qname(n, &name)?;
                let m = self.attr_or_empty(n, "match");
                if m.is_empty() {
                    return cerr("falta el atributo obligatorio 'match' en xsl:key");
                }
                self.scopes.push(Scope { names: vec![] });
                let matches = self.pattern(n, &m)?;
                let use_ = self.xpath_attr(n, "use")?;
                self.scopes.pop();
                self.keys.entry(q).or_default().push(KeyDef { matches, use_ });
                Ok(())
            }
            "decimal-format" => {
                let name = self.attr_or_empty(n, "name");
                let q = if name.is_empty() {
                    None
                } else {
                    Some(self.qname(n, &name)?)
                };
                if self.decimal_formats.contains_key(&q) {
                    // Java avisa y conserva la primera.
                    return Ok(());
                }
                let mut d = DecimalSymbols::default();
                let ch = |v: Option<&str>, def: char| v.and_then(|s| s.chars().next()).unwrap_or(def);
                d.decimal_separator = ch(self.attr(n, "decimal-separator"), d.decimal_separator);
                d.grouping_separator = ch(self.attr(n, "grouping-separator"), d.grouping_separator);
                d.minus_sign = ch(self.attr(n, "minus-sign"), d.minus_sign);
                d.percent = ch(self.attr(n, "percent"), d.percent);
                d.per_mille = ch(self.attr(n, "per-mille"), d.per_mille);
                d.zero_digit = ch(self.attr(n, "zero-digit"), d.zero_digit);
                d.digit = ch(self.attr(n, "digit"), d.digit);
                d.pattern_separator = ch(self.attr(n, "pattern-separator"), d.pattern_separator);
                if let Some(v) = self.attr(n, "infinity").filter(|s| !s.is_empty()) {
                    d.infinity = v.to_string();
                }
                if let Some(v) = self.attr(n, "NaN").filter(|s| !s.is_empty()) {
                    d.nan = v.to_string();
                }
                self.decimal_formats.insert(q, d);
                Ok(())
            }
            "attribute-set" => {
                let name = self.attr_or_empty(n, "name");
                let q = self.qname(n, &name)?;
                let use_sets = self.qnames(n, &self.attr_or_empty(n, "use-attribute-sets"))?;
                self.pending_sets.extend(use_sets.iter().cloned());
                let mut attrs = Vec::new();
                self.scopes.push(Scope { names: vec![] });
                for c in doc.children(n).to_vec() {
                    match doc.kind(c) {
                        NodeKind::Element(_) if is_xslt(doc, c, "attribute") => {
                            if let Some(i) = self.xsl_attribute(c, false)? {
                                attrs.push(i);
                            }
                        }
                        NodeKind::Element(_) => {
                            return cerr("xsl:attribute-set solo puede contener xsl:attribute");
                        }
                        _ => {}
                    }
                }
                self.scopes.pop();
                self.attr_sets.entry(q).or_default().parts.push((use_sets, attrs));
                Ok(())
            }
            "import" | "include" => {
                let href = self.attr_or_empty(n, "href");
                // Con un URI que `java.net.URL` no admite, `Include` e
                // `Import` capturan la excepción y no incluyen nada; con
                // cualquier otro, la restricción de acceso externo
                // (`accessExternalStylesheet = ""`) es un error.
                if href_is_ignored_by_java(&href) {
                    return Ok(());
                }
                cerr(format!(
                    "no se ha podido leer la hoja '{href}': no se permite el acceso a recursos externos"
                ))
            }
            other => {
                if self.forwards_compatible {
                    Ok(())
                } else {
                    cerr(format!("elemento de XSL no soportado: {other}"))
                }
            }
        }
    }

    fn output_elem(&mut self, n: NodeId) -> CResult<()> {
        // XSLTC une los xsl:output: cada uno sustituye los atributos que fija.
        let mut o = std::mem::take(&mut self.output);
        let get = |a: &str| self.attr(n, a).filter(|s| !s.is_empty()).map(str::to_string);
        if let Some(v) = get("version") {
            o.version = Some(v);
        }
        if let Some(m) = get("method") {
            let m = m.to_lowercase();
            if !(m == "xml" || m == "html" || m == "text" || (is_qname(&m) && m.contains(':'))) {
                return cerr(format!("método de salida no válido: {m}"));
            }
            o.method = Some(m);
        }
        if let Some(v) = get("encoding") {
            o.encoding = Some(v);
        }
        if let Some(v) = self.attr(n, "omit-xml-declaration").filter(|s| !s.is_empty()) {
            o.omit_xml_declaration = v == "yes";
        }
        if let Some(v) = get("standalone") {
            o.standalone = Some(v);
        }
        if let Some(v) = get("doctype-system") {
            o.doctype_system = Some(v);
        }
        if let Some(v) = get("doctype-public") {
            o.doctype_public = Some(v);
        }
        if let Some(v) = get("cdata-section-elements") {
            for qn in v.split_whitespace() {
                if !is_qname(qn) {
                    return cerr(format!("nombre no válido en cdata-section-elements: {qn}"));
                }
                // `Parser.getQName` usa el espacio por defecto.
                let (uri, local) = match qn.split_once(':') {
                    Some((p, l)) => (self.lookup_ns(n, p).unwrap_or_default(), l.to_string()),
                    None => (self.lookup_ns(n, "").unwrap_or_default(), qn.to_string()),
                };
                o.cdata.push((uri, local));
            }
        }
        let indent = self.attr(n, "indent").filter(|s| !s.is_empty()).map(|v| v == "yes");
        if let Some(v) = indent {
            o.indent = v;
        }
        let amount = self
            .doc
            .element(n)
            .and_then(|e| {
                e.attr_ns(super::compile::XALAN_URI, "indent-amount")
                    .or_else(|| e.attr_ns("http://xml.apache.org/xslt", "indent-amount"))
            })
            .map(str::to_string);
        if let Some(a) = amount {
            o.indent_amount = Some(
                a.trim()
                    .parse()
                    .map_err(|_| XsltError::Compile(format!("indent-amount no válido: {a}")))?,
            );
        }
        if let Some(v) = get("media-type") {
            o.media_type = Some(v);
        }
        if indent.is_some() {
            self.indent_explicit = indent;
        }
        self.output = o;
        self.output_seen = true;
        Ok(())
    }

    fn template(&mut self, n: NodeId) -> CResult<()> {
        let name = self.attr_or_empty(n, "name");
        let mode = self.attr_or_empty(n, "mode");
        let m = self.attr_or_empty(n, "match");
        let priority = self.attr_or_empty(n, "priority");
        let name_q = if name.is_empty() {
            None
        } else {
            Some(self.qname(n, &name)?)
        };
        let mode_q = if mode.is_empty() {
            None
        } else {
            Some(self.qname(n, &mode)?)
        };
        self.scopes.push(Scope { names: vec![] });
        let pattern = if m.is_empty() { None } else { Some(self.pattern(n, &m)?) };
        let prio = if priority.is_empty() {
            pattern.as_ref().map(Pattern::priority).unwrap_or(f64::NAN)
        } else {
            let v = crate::xpath::java_string_to_double(&priority);
            if v.is_nan() && priority.trim() != "NaN" {
                return cerr(format!("prioridad no válida: {priority}"));
            }
            v
        };
        let position = self.position;
        self.position += 1;
        let idx = self.templates.len();
        if let Some(q) = &name_q {
            if self.named.contains_key(q) {
                return cerr(format!("la plantilla '{name}' ya se ha definido en esta hoja"));
            }
            self.named.insert(q.clone(), idx);
        }
        // Parámetros al principio y después el cuerpo.
        let mut params = Vec::new();
        let mut body = Vec::new();
        let mut in_params = true;
        for c in self.merged_children(n) {
            if let Child::Element(e) = c
                && in_params
                && is_xslt(self.doc, e, "param")
            {
                params.push(self.local_var(e, true)?);
                continue;
            }
            match &c {
                Child::Element(_) => in_params = false,
                Child::Text(t) if !is_ws(t) => in_params = false,
                _ => {}
            }
            if let Some(i) = self.child(n, c)? {
                body.push(i);
            }
        }
        self.scopes.pop();
        self.templates.push(Template {
            mode: mode_q,
            pattern,
            priority: prio,
            position,
            params,
            body,
        });
        Ok(())
    }

    /// `Text.parseContents`: el texto en blanco se conserva solo si el padre
    /// directo es un elemento literal con `xml:space="preserve"`.
    fn preserve_text(&self, parent: NodeId) -> bool {
        self.doc
            .element(parent)
            .is_some_and(|e| e.ns.as_deref() != Some(XSLT_NS) && e.attr_ns(XML_NS, "space") == Some("preserve"))
    }

    /// Declara una variable o parámetro local en el ámbito actual.
    fn local_var(&mut self, n: NodeId, is_param: bool) -> CResult<usize> {
        let name = self.attr_or_empty(n, "name");
        if name.is_empty() {
            return cerr("falta el atributo obligatorio 'name'");
        }
        let q = self.qname(n, &name)?;
        if self
            .scopes
            .last()
            .is_some_and(|s| s.names.iter().any(|(nm, _)| *nm == q))
        {
            return cerr(format!(
                "se ha definido varias veces la variable '{name}' en el mismo ámbito"
            ));
        }
        // El valor no ve la propia variable.
        let (value, is_int) = self.var_value(n)?;
        let id = self.vars.len();
        self.vars.push(VarDecl {
            name: q.clone(),
            value,
            is_param,
            referenced: Cell::new(false),
            is_int,
        });
        self.scopes.last_mut().expect("ámbito").names.push((q, id));
        Ok(id)
    }

    /// Compila el contenido de un elemento en un ámbito nuevo.
    fn body(&mut self, n: NodeId) -> CResult<Vec<Instr>> {
        self.scopes.push(Scope { names: vec![] });
        let mut out = Vec::new();
        for c in self.merged_children(n) {
            if let Some(i) = self.child(n, c)? {
                out.push(i);
            }
        }
        self.scopes.pop();
        Ok(out)
    }

    /// Compila un hijo (texto unido o elemento) de `parent`.
    fn child(&mut self, parent: NodeId, c: Child) -> CResult<Option<Instr>> {
        match c {
            Child::Text(text) => {
                if is_ws(&text) && !self.preserve_text(parent) {
                    return Ok(None);
                }
                Ok(Some(Instr::Text { text, escaping: true }))
            }
            Child::Element(e) => self.instr(e, false),
        }
    }

    /// Compila un nodo de una plantilla.
    fn instr(&mut self, n: NodeId, _top: bool) -> CResult<Option<Instr>> {
        let doc = self.doc;
        match doc.kind(n) {
            NodeKind::Text { text, .. } => {
                let parent = doc.parent(n).expect("padre");
                if is_ws(text) && !self.preserve_text(parent) {
                    return Ok(None);
                }
                Ok(Some(Instr::Text {
                    text: text.clone(),
                    escaping: true,
                }))
            }
            NodeKind::Comment(_) | NodeKind::Pi { .. } | NodeKind::Document => Ok(None),
            NodeKind::Element(e) => {
                if e.ns.as_deref() == Some(XSLT_NS) {
                    self.xslt_instr(n)
                } else {
                    let ext = self.is_extension_ns(n, e.ns.as_deref().unwrap_or(""));
                    if ext {
                        return self.unsupported(n, true);
                    }
                    Ok(Some(self.literal(n)?))
                }
            }
        }
    }

    /// Espacio de nombres declarado en `extension-element-prefixes` de la
    /// hoja (`Stylesheet.isExtension`; el atributo de los elementos
    /// literales solo excluye el espacio de nombres de la salida).
    fn is_extension_ns(&self, _n: NodeId, uri: &str) -> bool {
        if uri.is_empty() {
            return false;
        }
        if uri == TRANSLET_URI || uri == REDIRECT_URI {
            return true;
        }
        let Some(root) = self.doc.document_element() else {
            return false;
        };
        let Some(e) = self.doc.element(root) else {
            return false;
        };
        if e.ns.as_deref() != Some(XSLT_NS) {
            return false;
        }
        e.attr("extension-element-prefixes").is_some_and(|list| {
            list.split_whitespace().any(|p| {
                let u = if p == "#default" {
                    self.lookup_ns(root, "")
                } else {
                    self.lookup_ns(root, p)
                };
                u.as_deref() == Some(uri)
            })
        })
    }

    fn unsupported(&mut self, n: NodeId, extension: bool) -> CResult<Option<Instr>> {
        let doc = self.doc;
        let mut fallbacks = Vec::new();
        let mut has_fallback = false;
        for c in doc.children(n).to_vec() {
            if is_xslt(doc, c, "fallback") {
                has_fallback = true;
                fallbacks.extend(self.body(c)?);
            }
        }
        if has_fallback {
            return Ok(Some(Instr::Fallback(fallbacks)));
        }
        let e = doc.element(n).expect("elemento");
        Ok(Some(Instr::Unsupported {
            name: format!("{}:{}", e.ns.clone().unwrap_or_default(), e.local),
            extension,
        }))
    }

    fn sorts(&mut self, n: NodeId) -> CResult<Vec<SortSpec>> {
        let doc = self.doc;
        let mut out = Vec::new();
        for c in doc.child_elements(n).collect::<Vec<_>>() {
            if !is_xslt(doc, c, "sort") {
                continue;
            }
            let sel = self.attr(c, "select").map(str::to_string);
            let (select, is_int) = match sel {
                Some(s) if !s.is_empty() => {
                    self.count_ops(&s)?;
                    let ns = self.ns_map(c);
                    let mut xp = XPath::compile(&s, &ns).map_err(|e| XsltError::Compile(format!("'{s}': {e}")))?;
                    let is_int = self.check_expr(c, &mut xp.expr)?;
                    (xp, is_int)
                }
                _ => (self.xpath(c, "string(.)")?, false),
            };
            let order = match self.attr(c, "order") {
                Some(o) if !o.is_empty() => self.avt(c, o)?,
                _ => Avt::lit("ascending"),
            };
            let data_type = match self.attr(c, "data-type") {
                Some(d) if !d.is_empty() => self.avt(c, d)?,
                _ => Avt::lit(if is_int { "number" } else { "text" }),
            };
            let lang = self.avt_attr(c, "lang")?;
            let case_order = self.avt_attr(c, "case-order")?;
            out.push(SortSpec {
                select,
                order,
                data_type,
                lang,
                case_order,
            });
        }
        Ok(out)
    }

    fn with_params(&mut self, n: NodeId) -> CResult<Vec<WithParam>> {
        let doc = self.doc;
        let mut out = Vec::new();
        for c in doc.child_elements(n).collect::<Vec<_>>() {
            if !is_xslt(doc, c, "with-param") {
                continue;
            }
            let name = self.attr_or_empty(c, "name");
            if name.is_empty() {
                return cerr("falta el atributo obligatorio 'name' en xsl:with-param");
            }
            let q = self.qname(c, &name)?;
            let (value, _) = self.var_value(c)?;
            out.push(WithParam { name: q, value });
        }
        Ok(out)
    }

    /// Contenido de `xsl:attribute` y `xsl:comment`: un único hijo de texto
    /// (aunque sea blanco) se usa tal cual.
    fn content(&mut self, n: NodeId) -> CResult<Content> {
        let items = self.merged_children(n);
        if items.len() == 1
            && let Child::Text(t) = &items[0]
        {
            return Ok(Content::Text(t.clone()));
        }
        Ok(Content::Instrs(self.body(n)?))
    }

    /// Hijos como los ve el analizador de XSLTC: sin comentarios ni
    /// instrucciones de proceso y con el texto contiguo unido.
    fn merged_children(&self, n: NodeId) -> Vec<Child> {
        let mut out: Vec<Child> = Vec::new();
        for &c in self.doc.children(n) {
            match self.doc.kind(c) {
                NodeKind::Text { text, .. } => {
                    if let Some(Child::Text(t)) = out.last_mut() {
                        t.push_str(text);
                    } else {
                        out.push(Child::Text(text.clone()));
                    }
                }
                NodeKind::Element(_) => out.push(Child::Element(c)),
                _ => {}
            }
        }
        out
    }

    fn xslt_instr(&mut self, n: NodeId) -> CResult<Option<Instr>> {
        let doc = self.doc;
        let local = doc.element(n).expect("elemento").local.clone();
        Ok(Some(match local.as_str() {
            "text" => {
                let escaping = self.attr(n, "disable-output-escaping") != Some("yes");
                let text: String = doc
                    .children(n)
                    .iter()
                    .filter_map(|&c| match doc.kind(c) {
                        NodeKind::Text { text, .. } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                if text.is_empty() {
                    return Ok(None);
                }
                Instr::Text { text, escaping }
            }
            "value-of" => {
                let select = self.xpath_attr(n, "select")?;
                let escaping = self.attr(n, "disable-output-escaping") != Some("yes");
                Instr::ValueOf { select, escaping }
            }
            "copy-of" => Instr::CopyOf(self.xpath_attr(n, "select")?),
            "copy" => {
                let use_sets = self.qnames(n, &self.attr_or_empty(n, "use-attribute-sets"))?;
                self.pending_sets.extend(use_sets.iter().cloned());
                let body = self.body(n)?;
                Instr::Copy { use_sets, body }
            }
            "apply-templates" => {
                let select = match self.attr(n, "select") {
                    Some(s) if !s.is_empty() => Some(self.xpath(n, s)?),
                    _ => None,
                };
                let mode = match self.attr(n, "mode") {
                    Some(m) if !m.is_empty() => Some(self.qname(n, m)?),
                    _ => None,
                };
                self.scopes.push(Scope { names: vec![] });
                let sorts = self.sorts(n)?;
                let params = self.with_params(n)?;
                self.scopes.pop();
                Instr::ApplyTemplates {
                    select,
                    mode,
                    sorts,
                    params,
                }
            }
            "call-template" => {
                let name = self.attr_or_empty(n, "name");
                if name.is_empty() {
                    return cerr("falta el atributo obligatorio 'name' en xsl:call-template");
                }
                let q = self.qname(n, &name)?;
                let params = self.with_params(n)?;
                let idx = self.pending_calls.len();
                self.pending_calls.push((q, idx));
                Instr::CallTemplate {
                    template: usize::MAX - idx,
                    params,
                }
            }
            "apply-imports" => Instr::ApplyImports,
            "for-each" => {
                let select = self.xpath_attr(n, "select")?;
                self.scopes.push(Scope { names: vec![] });
                let sorts = self.sorts(n)?;
                let mut body = Vec::new();
                for c in self.merged_children(n) {
                    if let Child::Element(e) = c
                        && is_xslt(doc, e, "sort")
                    {
                        continue;
                    }
                    if let Some(i) = self.child(n, c)? {
                        body.push(i);
                    }
                }
                self.scopes.pop();
                Instr::ForEach { select, sorts, body }
            }
            "if" => {
                let test = self.xpath_attr(n, "test")?;
                let body = self.body(n)?;
                Instr::If { test, body }
            }
            "choose" => {
                let mut whens = Vec::new();
                let mut otherwise = None;
                for c in doc.child_elements(n).collect::<Vec<_>>() {
                    if is_xslt(doc, c, "when") {
                        let test = self.xpath_attr(c, "test")?;
                        let body = self.body(c)?;
                        whens.push((test, body));
                    } else if is_xslt(doc, c, "otherwise") {
                        otherwise = Some(self.body(c)?);
                    } else {
                        return cerr("xsl:choose solo admite xsl:when y xsl:otherwise");
                    }
                }
                if whens.is_empty() {
                    return cerr("xsl:choose necesita al menos un xsl:when");
                }
                Instr::Choose { whens, otherwise }
            }
            "element" => self.xsl_element(n)?,
            "attribute" => match self.xsl_attribute(n, true)? {
                Some(i) => i,
                None => return Ok(None),
            },
            "comment" => Instr::Comment(self.content(n)?),
            "processing-instruction" => {
                let name = self.attr_or_empty(n, "name");
                if name.is_empty() {
                    return cerr("falta el atributo obligatorio 'name' en xsl:processing-instruction");
                }
                let literal = !name.contains('{');
                if literal && !is_ncname(&name) {
                    return cerr(format!("nombre de instrucción de proceso no válido: {name}"));
                }
                if name == "xml" {
                    return cerr("instrucción de proceso no válida: xml");
                }
                let avt = self.avt(n, &name)?;
                let body = self.body(n)?;
                Instr::Pi {
                    name: avt,
                    literal,
                    body,
                }
            }
            "number" => Instr::Number(Box::new(self.number(n)?)),
            "variable" => Instr::Variable(self.local_var(n, false)?),
            "param" => {
                return cerr("xsl:param solo puede aparecer al principio de una plantilla o en el nivel superior");
            }
            "message" => {
                let terminate = self.attr(n, "terminate") == Some("yes");
                let body = self.body(n)?;
                Instr::Message { body, terminate }
            }
            "fallback" => return Ok(None),
            "sort" | "with-param" => return Ok(None),
            "when" | "otherwise" => return cerr(format!("xsl:{local} fuera de xsl:choose")),
            _ => {
                if self.forwards_compatible {
                    return self.unsupported(n, false);
                }
                return cerr(format!("elemento de XSL no soportado: {local}"));
            }
        }))
    }

    fn number(&mut self, n: NodeId) -> CResult<NumberSpec> {
        let level = match self.attr(n, "level") {
            Some("multiple") => NumberLevel::Multiple,
            Some("any") => NumberLevel::Any,
            _ => NumberLevel::Single,
        };
        // Un atributo presente aunque esté vacío se analiza (y una
        // expresión vacía es un error, como en `Parser.parseExpression`).
        let empty = |a: &str| format!("error al analizar la expresión XPath '' del atributo '{a}' de xsl:number");
        let count = match self.attr(n, "count") {
            Some("") => return cerr(empty("count")),
            Some(c) => Some(self.pattern(n, c)?),
            None => None,
        };
        let from = match self.attr(n, "from") {
            Some("") => return cerr(empty("from")),
            Some(c) => Some(self.pattern(n, c)?),
            None => None,
        };
        let value = match self.attr(n, "value") {
            Some("") => return cerr(empty("value")),
            Some(v) => Some(self.xpath(n, v)?),
            None => None,
        };
        let format = match self.attr(n, "format") {
            Some(f) => self.avt(n, f)?,
            None => Avt::lit("1"),
        };
        let lang = self.avt_attr(n, "lang")?;
        let letter_value = self.avt_attr(n, "letter-value")?;
        let grouping_separator = match self.attr(n, "grouping-separator") {
            Some(g) => Some(self.avt(n, g)?),
            None => None,
        };
        let grouping_size = match self.attr(n, "grouping-size") {
            Some(g) => Some(self.avt(n, g)?),
            None => None,
        };
        Ok(NumberSpec {
            level,
            count,
            from,
            value,
            format,
            lang,
            letter_value,
            grouping_separator,
            grouping_size,
        })
    }

    // -- Elementos literales ---------------------------------------------------------

    /// `LiteralElement.translateQName`: aplica alias y registra el prefijo.
    fn translate_qname(&mut self, n: NodeId, prefix: Option<&str>, local: &str) -> String {
        let mut prefix = prefix.unwrap_or("").to_string();
        if prefix == "xmlns" {
            return "xmlns".into();
        }
        if let Some(alt) = self.aliases.get(&prefix).cloned() {
            let p = prefix.clone();
            self.exclude_prefixes(n, &p);
            prefix = alt;
        }
        let Some(uri) = self.lookup_ns(n, &prefix) else {
            return local.to_string();
        };
        self.register_namespace(&prefix, &uri, false);
        if prefix.is_empty() {
            local.to_string()
        } else {
            format!("{prefix}:{local}")
        }
    }

    /// `LiteralElement.accessedNamespace` en los elementos literales
    /// antecesores directos.
    fn parent_accessed(&self, prefix: &str) -> Option<String> {
        let mut uri = None;
        let n = self.lre_stack.len();
        if n < 2 || !self.lre_stack[n - 1].parent_is_lre {
            return None;
        }
        // Cadena de padres literales desde el más externo.
        let mut start = n - 1;
        while start > 0 && self.lre_stack[start].parent_is_lre {
            start -= 1;
        }
        for f in &self.lre_stack[start..n - 1] {
            if let Some(u) = f.accessed.get(prefix)
                && uri.is_none()
            {
                uri = Some(u.clone());
            }
        }
        uri
    }

    /// `LiteralElement.registerNamespace`.
    fn register_namespace(&mut self, prefix: &str, uri: &str, declared: bool) {
        if let Some(parent_uri) = self.parent_accessed(prefix)
            && parent_uri == uri
        {
            return;
        }
        let mut prefix = prefix.to_string();
        let frame_empty = self.lre_stack.last().map(|f| f.accessed.is_empty()).unwrap_or(true);
        if !frame_empty && !declared {
            let old = self.lre_stack.last().and_then(|f| f.accessed.get(&prefix).cloned());
            if let Some(old) = old {
                if old == uri {
                    return;
                }
                prefix = self.generate_prefix();
            }
        }
        if prefix != "xml"
            && let Some(f) = self.lre_stack.last_mut()
        {
            f.accessed.put(&prefix, uri.to_string());
        }
    }

    /// Prefijos en ámbito por orden de `getNamespaceScope` (de dentro
    /// afuera, cada nivel en orden de `HashMap`).
    fn namespace_scope(&self, n: NodeId) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut cur = Some(n);
        while let Some(id) = cur {
            if let Some(e) = self.doc.element(id) {
                let mut order = JavaHashMapOrder::default();
                for d in &e.ns_decls {
                    order.insert(d.prefix.as_deref().unwrap_or(""));
                }
                // La hoja tiene además el prefijo xml.
                if self.doc.parent(id).is_some_and(|p| self.doc.element(p).is_none()) {
                    order.insert("xml");
                }
                for p in order.iter() {
                    if !out.iter().any(|x| x == p) {
                        out.push(p.to_string());
                    }
                }
            }
            cur = self.doc.parent(id);
        }
        out
    }

    fn literal(&mut self, n: NodeId) -> CResult<Instr> {
        let doc = self.doc;
        let e = doc.element(n).expect("elemento").clone();
        let parent_is_lre = doc
            .parent(n)
            .and_then(|p| doc.element(p))
            .is_some_and(|pe| pe.ns.as_deref() != Some(XSLT_NS) && !self.lre_stack.is_empty());
        self.lre_stack.push(LreFrame {
            accessed: JavaHashtable::new(),
            parent_is_lre,
            attr_names: Vec::new(),
        });
        let name = self.translate_qname(n, e.prefix.as_deref(), &e.local);
        let mut attrs: Vec<LitAttr> = Vec::new();
        let mut excl_lists: Vec<String> = Vec::new();
        // Atributos en orden de nombre (como llegan tras la reserialización).
        let mut sorted: Vec<&crate::dom::Attribute> = e.attrs.iter().collect();
        sorted.sort_by(|a, b| super::java_cmp(&a.qname(), &b.qname()));
        let mut lit_attrs: Vec<(String, String)> = Vec::new();
        for a in sorted {
            if a.ns.as_deref() == Some(XSLT_NS) {
                match a.local.as_str() {
                    "use-attribute-sets" => {
                        let sets = self.qnames(n, &a.value)?;
                        self.pending_sets.extend(sets.iter().cloned());
                        attrs.insert(0, LitAttr::UseSets(sets));
                    }
                    "extension-element-prefixes" | "exclude-result-prefixes" => {
                        self.exclude_prefixes(n, &a.value);
                        excl_lists.push(a.value.clone());
                    }
                    _ => {}
                }
                continue;
            }
            let qn = self.translate_qname(n, a.prefix.as_deref(), &a.local);
            lit_attrs.push((qn, a.value.clone()));
        }
        for (qn, v) in lit_attrs {
            let avt = self.avt(n, &v)?;
            self.lre_stack
                .last_mut()
                .expect("marco")
                .attr_names
                .push(Some(qn.clone()));
            attrs.push(LitAttr::Attr {
                name: qn,
                value: avt,
                unique: None,
            });
        }
        for p in self.namespace_scope(n) {
            if p == "xml" {
                continue;
            }
            if let Some(uri) = self.lookup_ns(n, &p)
                && !self.is_excluded(&uri)
            {
                self.register_namespace(&p, &uri, true);
            }
        }
        let body = self.body(n)?;
        for l in excl_lists {
            self.unexclude_prefixes(n, &l);
        }
        let frame = self.lre_stack.pop().expect("marco");
        // Unicidad de atributos (`checkAttributesUnique`) e indicadores HTML.
        let unique = !attrs.iter().any(|a| matches!(a, LitAttr::UseSets(_)))
            && !can_produce_attributes(&body, true)
            && unique_names(&frame.attr_names, &body);
        let desc = if self.html_output_known() {
            Some(ElemDesc::of(&name))
        } else {
            None
        };
        for a in &mut attrs {
            if let LitAttr::Attr {
                name: an,
                value,
                unique: u,
            } = a
                && unique
            {
                let mut flags = 0;
                let mut empty = false;
                if let Some(d) = desc {
                    if d.attr_flag(an, elem::ATTREMPTY) {
                        flags |= HTML_ATTREMPTY;
                        empty = true;
                    } else if d.attr_flag(an, elem::ATTRURL) {
                        flags |= HTML_ATTRURL;
                    }
                }
                if let Some(lit) = value.literal()
                    && !has_bad_chars(&lit)
                    && !empty
                {
                    flags |= NO_BAD_CHARS;
                }
                *u = Some(flags);
            }
        }
        // Los xsl:attribute hijos directos usan addUniqueAttribute si todos
        // los atributos son únicos.
        let mut body = body;
        if unique {
            for i in &mut body {
                if let Instr::Attribute(xa) = i {
                    let mut flags = 0;
                    if let (Some(d), true) = (desc, xa.literal)
                        && let Some(nm) = xa.name.literal()
                    {
                        if d.attr_flag(&nm, elem::ATTREMPTY) {
                            flags |= HTML_ATTREMPTY;
                        } else if d.attr_flag(&nm, elem::ATTRURL) {
                            flags |= HTML_ATTRURL;
                        }
                    }
                    xa.unique = Some(flags);
                }
            }
        }
        let namespaces = frame.accessed.entries();
        Ok(Instr::Literal(Box::new(LiteralElem {
            name,
            namespaces,
            attrs,
            body,
        })))
    }

    /// El método de salida HTML se conoce al compilar (último `xsl:output`).
    fn html_output_known(&self) -> bool {
        self.method.as_deref() == Some("html")
    }

    fn xsl_element(&mut self, n: NodeId) -> CResult<Instr> {
        let name = self.attr_or_empty(n, "name");
        let use_sets = self.qnames(n, &self.attr_or_empty(n, "use-attribute-sets"))?;
        self.pending_sets.extend(use_sets.iter().cloned());
        let mut ignore = false;
        let mut prefix = String::new();
        let mut namespace = None;
        let mut name_avt = Avt::lit(&name);
        let literal = !name.contains('{') && !name.contains('}');
        let has_ns = self.attr(n, "namespace").is_some();
        let ns_attr = self.attr_or_empty(n, "namespace");
        if name.is_empty() {
            ignore = true;
        } else if literal {
            if !is_qname(&name) {
                ignore = true;
            } else {
                let (p, local) = match name.split_once(':') {
                    Some((p, l)) => (p.to_string(), l.to_string()),
                    None => (String::new(), name.clone()),
                };
                if !has_ns {
                    match self.lookup_ns(n, &p) {
                        Some(uri) => {
                            prefix = p;
                            namespace = Some(Avt::lit(&uri));
                        }
                        None => ignore = true,
                    }
                } else {
                    let mut p = p;
                    let mut nm = name.clone();
                    if p.is_empty() {
                        if !ns_attr.contains('{') {
                            p = match self.lookup_prefix(n, &ns_attr) {
                                Some(x) => x,
                                None => self.generate_prefix(),
                            };
                        }
                        nm = if p.is_empty() {
                            local.clone()
                        } else {
                            format!("{p}:{local}")
                        };
                    }
                    prefix = p;
                    namespace = Some(self.avt(n, &ns_attr)?);
                    name_avt = Avt::lit(&nm);
                }
            }
        } else {
            name_avt = self.avt(n, &name)?;
            namespace = if ns_attr.is_empty() {
                None
            } else {
                Some(self.avt(n, &ns_attr)?)
            };
        }
        let body = self.body(n)?;
        Ok(Instr::Element(Box::new(XslElement {
            ignore,
            literal,
            name: name_avt,
            prefix,
            namespace,
            use_sets,
            body,
        })))
    }

    /// `xsl:attribute`; `in_template` es falso dentro de `xsl:attribute-set`.
    fn xsl_attribute(&mut self, n: NodeId, in_template: bool) -> CResult<Option<Instr>> {
        let _ = in_template;
        let mut name = self.attr_or_empty(n, "name");
        let namespace_attr = self.attr(n, "namespace").map(str::to_string);
        let literal = !name.contains('{') && !name.contains('}');
        let qprefix = name.split_once(':').map(|(p, _)| p.to_string());
        if qprefix.as_deref() == Some("xmlns") || name == "xmlns" {
            return cerr(format!("nombre de atributo no válido: {name}"));
        }
        if literal && !is_qname(&name) {
            return cerr(format!("nombre de atributo no válido: {name}"));
        }
        let local = name.rsplit(':').next().unwrap_or(&name).to_string();
        let mut prefix: Option<String> = None;
        let mut ns_avt: Option<Avt> = None;
        let mut ns_value: Option<String> = None;
        match namespace_attr {
            Some(ns) if !ns.is_empty() => {
                prefix = self.lookup_prefix(n, &ns);
                ns_avt = Some(self.avt(n, &ns)?);
                ns_value = Some(ns);
            }
            _ => {
                if let Some(p) = qprefix.clone().filter(|p| !p.is_empty()) {
                    prefix = Some(p.clone());
                    if let Some(uri) = self.lookup_ns(n, &p) {
                        ns_avt = Some(Avt::lit(&uri));
                        ns_value = Some(uri);
                    }
                }
            }
        }
        let mut generated = false;
        if ns_avt.is_some() {
            match &prefix {
                None => {
                    if let Some(p) = qprefix.clone() {
                        prefix = Some(p);
                    } else {
                        prefix = Some(self.generate_prefix());
                        generated = true;
                    }
                }
                Some(p) if p.is_empty() => {
                    if let Some(qp) = qprefix.clone() {
                        prefix = Some(qp);
                    } else {
                        prefix = Some(self.generate_prefix());
                        generated = true;
                    }
                }
                Some(p) => {
                    if let Some(qp) = &qprefix
                        && qp != p
                    {
                        prefix = Some(qp.clone());
                    }
                }
            }
            name = format!("{}:{local}", prefix.clone().unwrap_or_default());
            let parent_lre = self
                .doc
                .parent(n)
                .and_then(|p| self.doc.element(p))
                .is_some_and(|pe| pe.ns.as_deref() != Some(XSLT_NS));
            if parent_lre
                && !generated
                && let (Some(p), Some(u)) = (prefix.clone(), ns_value.clone())
            {
                self.register_namespace(&p, &u, false);
            }
        }
        // Nombre para la comprobación de unicidad del elemento literal padre.
        let parent_lre = self
            .doc
            .parent(n)
            .and_then(|p| self.doc.element(p))
            .is_some_and(|pe| pe.ns.as_deref() != Some(XSLT_NS));
        if parent_lre && let Some(f) = self.lre_stack.last_mut() {
            f.attr_names.push(if literal { Some(name.clone()) } else { None });
        }
        let name_avt = if literal { Avt::lit(&name) } else { self.avt(n, &name)? };
        let content = self.content(n)?;
        Ok(Some(Instr::Attribute(Box::new(XslAttribute {
            namespace: ns_avt.map(|a| (prefix.clone().unwrap_or_default(), a)),
            literal,
            name: name_avt,
            content,
            unique: None,
        }))))
    }

    fn finish(mut self) -> CResult<Stylesheet> {
        if self.output.method.as_deref() == Some("html") && self.indent_explicit.is_none() {
            self.output.indent = true;
        }
        // Llamadas a plantillas con nombre y conjuntos de atributos.
        let calls: Vec<(QName, usize)> = std::mem::take(&mut self.pending_calls);
        let mut targets = Vec::with_capacity(calls.len());
        for (q, _) in &calls {
            match self.named.get(q) {
                Some(&t) => targets.push(t),
                None => return cerr(format!("la plantilla '{}' no se ha definido en esta hoja", q.local)),
            }
        }
        for s in &self.pending_sets {
            if !self.attr_sets.contains_key(s) {
                return cerr(format!("el conjunto de atributos '{}' no está definido", s.local));
            }
        }
        for t in &mut self.templates {
            fix_calls(&mut t.body, &targets);
        }
        for v in &mut self.vars {
            if let VarValue::Content(b) = &mut v.value {
                fix_calls(b, &targets);
            }
        }
        // Reglas de plantilla por modo.
        let mut rules: HashMap<Option<QName>, Vec<Rule>> = HashMap::new();
        for (i, t) in self.templates.iter().enumerate() {
            if let Some(p) = &t.pattern {
                for alt in 0..p.alts.len() {
                    rules.entry(t.mode.clone()).or_default().push(Rule {
                        template: i,
                        alt,
                        priority: t.priority,
                        position: t.position,
                    });
                }
            }
        }
        for list in rules.values_mut() {
            // Mayor prioridad primero y, a igualdad, la última plantilla.
            list.sort_by(|a, b| {
                b.priority
                    .partial_cmp(&a.priority)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(b.position.cmp(&a.position))
            });
        }
        let ws_rules = prioritize_ws_rules(std::mem::take(&mut self.ws_rules));
        Ok(Stylesheet {
            templates: self.templates,
            rules,
            vars: self.vars,
            globals: self.globals,
            keys: self.keys,
            decimal_formats: self.decimal_formats,
            attr_sets: self.attr_sets,
            ws_rules,
            output: self.output,
        })
    }
}

fn fix_calls(body: &mut [Instr], targets: &[usize]) {
    for i in body {
        match i {
            Instr::CallTemplate { template, params } => {
                if *template > usize::MAX / 2 {
                    *template = targets[usize::MAX - *template];
                }
                for p in params {
                    if let VarValue::Content(b) = &mut p.value {
                        fix_calls(b, targets);
                    }
                }
            }
            Instr::Literal(l) => fix_calls(&mut l.body, targets),
            Instr::Copy { body, .. }
            | Instr::ForEach { body, .. }
            | Instr::If { body, .. }
            | Instr::Pi { body, .. }
            | Instr::Message { body, .. }
            | Instr::Fallback(body) => fix_calls(body, targets),
            Instr::ApplyTemplates { params, .. } => {
                for p in params {
                    if let VarValue::Content(b) = &mut p.value {
                        fix_calls(b, targets);
                    }
                }
            }
            Instr::Choose { whens, otherwise } => {
                for (_, b) in whens {
                    fix_calls(b, targets);
                }
                if let Some(b) = otherwise {
                    fix_calls(b, targets);
                }
            }
            Instr::Element(e) => fix_calls(&mut e.body, targets),
            Instr::Attribute(a) => {
                if let Content::Instrs(b) = &mut a.content {
                    fix_calls(b, targets);
                }
            }
            Instr::Comment(Content::Instrs(b)) => fix_calls(b, targets),
            _ => {}
        }
    }
}

/// `LiteralAttribute.hasBadChars`.
fn has_bad_chars(v: &str) -> bool {
    v.encode_utf16().any(|ch| {
        !(32..=126).contains(&ch)
            || ch == u16::from(b'<')
            || ch == u16::from(b'>')
            || ch == u16::from(b'&')
            || ch == u16::from(b'"')
    })
}

/// `LiteralElement.canProduceAttributeNodes`.
fn can_produce_attributes(body: &[Instr], ignore_xsl_attribute: bool) -> bool {
    for i in body {
        match i {
            Instr::Text { .. }
            | Instr::Literal(_)
            | Instr::ValueOf { .. }
            | Instr::Element(_)
            | Instr::Comment(_)
            | Instr::Number(_)
            | Instr::Pi { .. } => return false,
            Instr::Attribute(_) => {
                if !ignore_xsl_attribute {
                    return true;
                }
            }
            Instr::CallTemplate { .. } | Instr::ApplyTemplates { .. } | Instr::Copy { .. } | Instr::CopyOf(_) => {
                return true;
            }
            Instr::If { body, .. } | Instr::ForEach { body, .. } => {
                if can_produce_attributes(body, false) {
                    return true;
                }
            }
            Instr::Choose { whens, otherwise } => {
                for (_, b) in whens {
                    if can_produce_attributes(b, false) {
                        return true;
                    }
                }
                if let Some(b) = otherwise
                    && can_produce_attributes(b, false)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Resto de `checkAttributesUnique`: nombres de `xsl:attribute` literales
/// que no repiten un atributo anterior.
fn unique_names(names: &[Option<String>], body: &[Instr]) -> bool {
    let _ = body;
    let mut seen: Vec<&str> = Vec::new();
    for n in names {
        match n {
            None => return false,
            Some(s) => {
                if seen.contains(&s.as_str()) {
                    return false;
                }
                seen.push(s);
            }
        }
    }
    true
}

/// `Whitespace.quicksort` (Hoare con pivote central; no es estable).
fn ws_quicksort(rules: &mut [WsRule], p: isize, r: isize) {
    let mut p = p;
    while p < r {
        let q = ws_partition(rules, p, r);
        ws_quicksort(rules, p, q);
        p = q + 1;
    }
}

fn ws_partition(rules: &mut [WsRule], p: isize, r: isize) -> isize {
    let x = rules[((p + r) as usize) >> 1].priority;
    let (mut i, mut j) = (p - 1, r + 1);
    loop {
        loop {
            j -= 1;
            if x >= rules[j as usize].priority {
                break;
            }
        }
        loop {
            i += 1;
            if x <= rules[i as usize].priority {
                break;
            }
        }
        if i < j {
            rules.swap(i as usize, j as usize);
        } else {
            return j;
        }
    }
}

/// `Whitespace.prioritizeRules`, con sus mismas operaciones sobre la lista.
fn prioritize_ws_rules(mut rules: Vec<WsRule>) -> Option<(Vec<WsRule>, WsAction)> {
    if rules.is_empty() {
        return None;
    }
    let n = rules.len() as isize;
    ws_quicksort(&mut rules, 0, n - 1);
    if !rules.iter().any(|r| r.action == WsAction::Strip) {
        return None;
    }
    let mut default = WsAction::Preserve;
    let mut idx = 0;
    while idx < rules.len() {
        let contradicted = {
            let rule = &rules[idx];
            rules[..idx].iter().any(|cur| match cur.strength {
                3 => true,
                1 => cur.element == rule.element && cur.namespace == rule.namespace,
                2 => cur.namespace == rule.namespace,
                _ => false,
            })
        };
        if contradicted {
            rules.remove(idx);
        } else {
            if rules[idx].strength == 3 {
                default = rules[idx].action;
                // `for (i = idx; i < size; i++) rules.remove(i)`: borra una sí y otra no.
                let mut i = idx;
                while i < rules.len() {
                    rules.remove(i);
                    i += 1;
                }
            }
            idx += 1;
        }
    }
    while rules.last().is_some_and(|r| r.action == default) {
        rules.pop();
    }
    Some((rules, default))
}
