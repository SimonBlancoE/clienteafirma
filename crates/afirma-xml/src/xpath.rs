//! Evaluador XPath 1.0 sobre el DOM de [`crate::dom`].
//!
//! Cubre la gramática completa de XPath 1.0 (rutas, los trece ejes,
//! predicados, operadores y la biblioteca de funciones básica) más la función
//! `here()` de XMLDSig. Se usa para:
//!
//! - las transformadas XPath (filtro XPath 1.0) y XPath Filter 2.0 de las
//!   referencias XMLDSig;
//! - el parámetro `insertEnvelopedSignatureOnNodeByXPath` de XAdES, que Java
//!   evalúa sin contexto de espacios de nombres (equivale a evaluar con un
//!   mapa de prefijos vacío).
//!
//! No hay variables (`$x` es un error) y `id()` busca atributos `Id`/`ID`/`id`
//! (no hay DTD).

use std::collections::{BTreeMap, HashMap};

use crate::dom::{Document, NodeId, NodeKind, XML_NS};

/// Nodo del modelo de datos XPath.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XNode {
    /// Documento, elemento, texto, comentario o instrucción de proceso.
    Node(NodeId),
    /// Atributo `idx` (índice en `Element::attrs`) del elemento.
    Attr(NodeId, u32),
    /// Nodo de espacio de nombres `idx` (índice en [`namespace_nodes`]) del elemento.
    Ns(NodeId, u32),
}

impl XNode {
    /// Clave de orden de documento.
    pub fn order_key(self) -> (usize, u8, u32) {
        match self {
            XNode::Node(n) => (n.0, 0, 0),
            XNode::Ns(n, i) => (n.0, 1, i),
            XNode::Attr(n, i) => (n.0, 2, i),
        }
    }
}

/// Nodos de espacio de nombres de un elemento: `(prefijo, uri)`, con el
/// prefijo `xml` siempre presente y `""` para el espacio por defecto.
pub fn namespace_nodes(doc: &Document, element: NodeId) -> Vec<(String, String)> {
    let mut map: BTreeMap<String, String> = doc.in_scope_namespaces(element);
    map.insert("xml".to_string(), XML_NS.to_string());
    map.into_iter().collect()
}

/// Valor XPath.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Nodes(Vec<XNode>),
    Bool(bool),
    Num(f64),
    Str(String),
}

/// Error de análisis o evaluación XPath.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expresión XPath no válida: {0}")]
pub struct XPathError(pub String);

type XResult<T> = std::result::Result<T, XPathError>;

fn err<T>(msg: impl Into<String>) -> XResult<T> {
    Err(XPathError(msg.into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Axis {
    Ancestor,
    AncestorOrSelf,
    Attribute,
    Child,
    Descendant,
    DescendantOrSelf,
    Following,
    FollowingSibling,
    Namespace,
    Parent,
    Preceding,
    PrecedingSibling,
    #[allow(clippy::enum_variant_names)]
    SelfAxis,
}

impl Axis {
    fn from_name(n: &str) -> Option<Axis> {
        Some(match n {
            "ancestor" => Axis::Ancestor,
            "ancestor-or-self" => Axis::AncestorOrSelf,
            "attribute" => Axis::Attribute,
            "child" => Axis::Child,
            "descendant" => Axis::Descendant,
            "descendant-or-self" => Axis::DescendantOrSelf,
            "following" => Axis::Following,
            "following-sibling" => Axis::FollowingSibling,
            "namespace" => Axis::Namespace,
            "parent" => Axis::Parent,
            "preceding" => Axis::Preceding,
            "preceding-sibling" => Axis::PrecedingSibling,
            "self" => Axis::SelfAxis,
            _ => return None,
        })
    }

    fn is_reverse(self) -> bool {
        matches!(
            self,
            Axis::Ancestor | Axis::AncestorOrSelf | Axis::Preceding | Axis::PrecedingSibling
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
enum NodeTest {
    /// Nombre (espacio de nombres resuelto, nombre local).
    Name(Option<String>, String),
    /// `prefijo:*`.
    NsWildcard(String),
    /// `*`.
    Any,
    Node,
    Text,
    Comment,
    Pi(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
struct Step {
    axis: Axis,
    test: NodeTest,
    preds: Vec<Expr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Union,
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    Literal(String),
    Number(f64),
    Call(String, Vec<Expr>),
    /// Expresión primaria con predicados.
    Filter(Box<Expr>, Vec<Expr>),
    /// Ruta: base opcional (`None` = nodo de contexto; `Some(Root)`...) y pasos.
    Path(PathStart, Vec<Step>),
}

#[derive(Clone, Debug, PartialEq)]
enum PathStart {
    Context,
    Root,
    Expr(Box<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Name(String), // NCName o QName (con ':'), o '*' / 'p:*'
    Axis(String), // nombre de eje seguido de '::'
    Func(String), // nombre de función o tipo de nodo seguido de '('
    Literal(String),
    Number(f64),
    Op(&'static str), // operadores y puntuación
}

fn tokenize(s: &str) -> XResult<Vec<Tok>> {
    let chars: Vec<char> = s.chars().collect();
    let mut toks: Vec<Tok> = Vec::new();
    let mut i = 0;
    let is_name_start = |c: char| c.is_alphabetic() || c == '_' || (c as u32) > 0x7f;
    let is_name_char =
        |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '.') || (c as u32) > 0x7f;
    // Indica si el token anterior obliga a interpretar '*' y nombres como operadores.
    let prev_is_operand = |toks: &Vec<Tok>| -> bool {
        match toks.last() {
            None => false,
            Some(Tok::Op(o)) => matches!(*o, ")" | "]" | "." | ".."),
            Some(Tok::Axis(_)) | Some(Tok::Func(_)) => false,
            Some(_) => true,
        }
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
        match two.as_str() {
            "//" | "::" | ".." | "!=" | "<=" | ">=" => {
                if two == "::" {
                    return err("'::' inesperado");
                }
                toks.push(Tok::Op(match two.as_str() {
                    "//" => "//",
                    ".." => "..",
                    "!=" => "!=",
                    "<=" => "<=",
                    _ => ">=",
                }));
                i += 2;
                continue;
            }
            _ => {}
        }
        match c {
            '(' | ')' | '[' | ']' | '@' | ',' | '|' | '+' | '=' | '<' | '>' | '/' => {
                toks.push(Tok::Op(match c {
                    '(' => "(",
                    ')' => ")",
                    '[' => "[",
                    ']' => "]",
                    '@' => "@",
                    ',' => ",",
                    '|' => "|",
                    '+' => "+",
                    '=' => "=",
                    '<' => "<",
                    '>' => ">",
                    _ => "/",
                }));
                i += 1;
            }
            '-' => {
                toks.push(Tok::Op("-"));
                i += 1;
            }
            '*' => {
                if prev_is_operand(&toks) {
                    toks.push(Tok::Op("*"));
                } else {
                    toks.push(Tok::Name("*".into()));
                }
                i += 1;
            }
            '$' => return err("no se admiten variables"),
            '"' | '\'' => {
                let end = chars[i + 1..]
                    .iter()
                    .position(|&x| x == c)
                    .ok_or_else(|| XPathError("literal sin cerrar".into()))?;
                toks.push(Tok::Literal(chars[i + 1..i + 1 + end].iter().collect()));
                i += end + 2;
            }
            '.' if i + 1 < chars.len() && chars[i + 1].is_ascii_digit() => {
                let start = i;
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let n: String = chars[start..i].iter().collect();
                toks.push(Tok::Number(n.parse().map_err(|_| XPathError(n.clone()))?));
            }
            '.' => {
                toks.push(Tok::Op("."));
                i += 1;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let n: String = chars[start..i].iter().collect();
                toks.push(Tok::Number(n.parse().map_err(|_| XPathError(n.clone()))?));
            }
            c if is_name_start(c) => {
                let start = i;
                while i < chars.len() && is_name_char(chars[i]) {
                    i += 1;
                }
                let mut name: String = chars[start..i].iter().collect();
                // QName o prefijo:*
                if i + 1 < chars.len() && chars[i] == ':' && chars[i + 1] != ':' {
                    if chars[i + 1] == '*' {
                        name.push_str(":*");
                        i += 2;
                    } else if is_name_start(chars[i + 1]) {
                        i += 1;
                        let s2 = i;
                        while i < chars.len() && is_name_char(chars[i]) {
                            i += 1;
                        }
                        name.push(':');
                        name.extend(&chars[s2..i]);
                    }
                }
                // Operadores con nombre.
                if prev_is_operand(&toks) {
                    match name.as_str() {
                        "and" => toks.push(Tok::Op("and")),
                        "or" => toks.push(Tok::Op("or")),
                        "mod" => toks.push(Tok::Op("mod")),
                        "div" => toks.push(Tok::Op("div")),
                        _ => return err(format!("operador desconocido: {name}")),
                    }
                    continue;
                }
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if j + 1 < chars.len() && chars[j] == ':' && chars[j + 1] == ':' {
                    toks.push(Tok::Axis(name));
                    i = j + 2;
                } else if j < chars.len() && chars[j] == '(' {
                    toks.push(Tok::Func(name));
                    i = j + 1;
                } else {
                    toks.push(Tok::Name(name));
                }
            }
            _ => return err(format!("carácter inesperado: {c}")),
        }
    }
    Ok(toks)
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    ns: &'a HashMap<String, String>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(o)) if *o == op)
    }

    fn eat_op(&mut self, op: &str) -> bool {
        if self.peek_op(op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_op(&mut self, op: &str) -> XResult<()> {
        if self.eat_op(op) {
            Ok(())
        } else {
            err(format!("se esperaba '{op}'"))
        }
    }

    fn expr(&mut self) -> XResult<Expr> {
        self.or_expr()
    }

    fn bin_level(
        &mut self,
        ops: &[(&'static str, BinOp)],
        next: fn(&mut Self) -> XResult<Expr>,
    ) -> XResult<Expr> {
        let mut left = next(self)?;
        'outer: loop {
            for (o, b) in ops {
                if self.eat_op(o) {
                    let right = next(self)?;
                    left = Expr::Bin(*b, Box::new(left), Box::new(right));
                    continue 'outer;
                }
            }
            return Ok(left);
        }
    }

    fn or_expr(&mut self) -> XResult<Expr> {
        self.bin_level(&[("or", BinOp::Or)], Self::and_expr)
    }
    fn and_expr(&mut self) -> XResult<Expr> {
        self.bin_level(&[("and", BinOp::And)], Self::eq_expr)
    }
    fn eq_expr(&mut self) -> XResult<Expr> {
        self.bin_level(&[("=", BinOp::Eq), ("!=", BinOp::Ne)], Self::rel_expr)
    }
    fn rel_expr(&mut self) -> XResult<Expr> {
        self.bin_level(
            &[
                ("<=", BinOp::Le),
                (">=", BinOp::Ge),
                ("<", BinOp::Lt),
                (">", BinOp::Gt),
            ],
            Self::add_expr,
        )
    }
    fn add_expr(&mut self) -> XResult<Expr> {
        self.bin_level(&[("+", BinOp::Add), ("-", BinOp::Sub)], Self::mul_expr)
    }
    fn mul_expr(&mut self) -> XResult<Expr> {
        self.bin_level(
            &[("*", BinOp::Mul), ("div", BinOp::Div), ("mod", BinOp::Mod)],
            Self::unary_expr,
        )
    }

    fn unary_expr(&mut self) -> XResult<Expr> {
        if self.eat_op("-") {
            return Ok(Expr::Neg(Box::new(self.unary_expr()?)));
        }
        self.union_expr()
    }

    fn union_expr(&mut self) -> XResult<Expr> {
        self.bin_level(&[("|", BinOp::Union)], Self::path_expr)
    }

    fn path_expr(&mut self) -> XResult<Expr> {
        let is_primary = match self.peek() {
            Some(Tok::Literal(_)) | Some(Tok::Number(_)) => true,
            Some(Tok::Op("(")) => true,
            Some(Tok::Func(f)) => !matches!(
                f.as_str(),
                "node" | "text" | "comment" | "processing-instruction"
            ),
            _ => false,
        };
        if is_primary {
            let prim = self.primary()?;
            let mut preds = Vec::new();
            while self.peek_op("[") {
                preds.push(self.predicate()?);
            }
            let base = if preds.is_empty() {
                prim
            } else {
                Expr::Filter(Box::new(prim), preds)
            };
            if self.peek_op("/") || self.peek_op("//") {
                let mut steps = Vec::new();
                self.rel_steps_after_slash(&mut steps)?;
                return Ok(Expr::Path(PathStart::Expr(Box::new(base)), steps));
            }
            return Ok(base);
        }
        // Ruta de localización.
        let mut steps = Vec::new();
        if self.eat_op("/") {
            if self.starts_step() {
                self.rel_steps(&mut steps)?;
            }
            return Ok(Expr::Path(PathStart::Root, steps));
        }
        if self.eat_op("//") {
            steps.push(descendant_or_self_step());
            self.rel_steps(&mut steps)?;
            return Ok(Expr::Path(PathStart::Root, steps));
        }
        self.rel_steps(&mut steps)?;
        Ok(Expr::Path(PathStart::Context, steps))
    }

    fn starts_step(&self) -> bool {
        matches!(
            self.peek(),
            Some(Tok::Name(_))
                | Some(Tok::Axis(_))
                | Some(Tok::Op("@"))
                | Some(Tok::Op("."))
                | Some(Tok::Op(".."))
        ) || matches!(self.peek(), Some(Tok::Func(f)) if matches!(f.as_str(), "node" | "text" | "comment" | "processing-instruction"))
    }

    fn rel_steps_after_slash(&mut self, steps: &mut Vec<Step>) -> XResult<()> {
        loop {
            if self.eat_op("/") {
                steps.push(self.step()?);
            } else if self.eat_op("//") {
                steps.push(descendant_or_self_step());
                steps.push(self.step()?);
            } else {
                return Ok(());
            }
        }
    }

    fn rel_steps(&mut self, steps: &mut Vec<Step>) -> XResult<()> {
        steps.push(self.step()?);
        self.rel_steps_after_slash(steps)
    }

    fn step(&mut self) -> XResult<Step> {
        if self.eat_op(".") {
            return Ok(Step {
                axis: Axis::SelfAxis,
                test: NodeTest::Node,
                preds: vec![],
            });
        }
        if self.eat_op("..") {
            return Ok(Step {
                axis: Axis::Parent,
                test: NodeTest::Node,
                preds: vec![],
            });
        }
        let axis = if self.eat_op("@") {
            Axis::Attribute
        } else if let Some(Tok::Axis(a)) = self.peek().cloned() {
            self.pos += 1;
            Axis::from_name(&a).ok_or_else(|| XPathError(format!("eje desconocido: {a}")))?
        } else {
            Axis::Child
        };
        let test = match self.peek().cloned() {
            Some(Tok::Name(n)) => {
                self.pos += 1;
                self.name_test(&n)?
            }
            Some(Tok::Func(f)) => {
                self.pos += 1;
                let t = match f.as_str() {
                    "node" => NodeTest::Node,
                    "text" => NodeTest::Text,
                    "comment" => NodeTest::Comment,
                    "processing-instruction" => {
                        if let Some(Tok::Literal(l)) = self.peek().cloned() {
                            self.pos += 1;
                            NodeTest::Pi(Some(l))
                        } else {
                            NodeTest::Pi(None)
                        }
                    }
                    other => return err(format!("prueba de nodo desconocida: {other}")),
                };
                self.expect_op(")")?;
                t
            }
            _ => return err("se esperaba una prueba de nodo"),
        };
        let mut preds = Vec::new();
        while self.peek_op("[") {
            preds.push(self.predicate()?);
        }
        Ok(Step { axis, test, preds })
    }

    fn name_test(&self, n: &str) -> XResult<NodeTest> {
        if n == "*" {
            return Ok(NodeTest::Any);
        }
        if let Some(p) = n.strip_suffix(":*") {
            let uri = self
                .ns
                .get(p)
                .ok_or_else(|| XPathError(format!("prefijo no declarado: {p}")))?;
            return Ok(NodeTest::NsWildcard(uri.clone()));
        }
        match n.split_once(':') {
            Some((p, l)) => {
                let uri = self
                    .ns
                    .get(p)
                    .ok_or_else(|| XPathError(format!("prefijo no declarado: {p}")))?;
                Ok(NodeTest::Name(Some(uri.clone()), l.to_string()))
            }
            None => Ok(NodeTest::Name(None, n.to_string())),
        }
    }

    fn predicate(&mut self) -> XResult<Expr> {
        self.expect_op("[")?;
        let e = self.expr()?;
        self.expect_op("]")?;
        Ok(e)
    }

    fn primary(&mut self) -> XResult<Expr> {
        match self.peek().cloned() {
            Some(Tok::Literal(l)) => {
                self.pos += 1;
                Ok(Expr::Literal(l))
            }
            Some(Tok::Number(n)) => {
                self.pos += 1;
                Ok(Expr::Number(n))
            }
            Some(Tok::Op("(")) => {
                self.pos += 1;
                let e = self.expr()?;
                self.expect_op(")")?;
                Ok(e)
            }
            Some(Tok::Func(f)) => {
                self.pos += 1;
                let mut args = Vec::new();
                if !self.eat_op(")") {
                    loop {
                        args.push(self.expr()?);
                        if self.eat_op(")") {
                            break;
                        }
                        self.expect_op(",")?;
                    }
                }
                Ok(Expr::Call(f, args))
            }
            _ => err("expresión primaria esperada"),
        }
    }
}

fn descendant_or_self_step() -> Step {
    Step {
        axis: Axis::DescendantOrSelf,
        test: NodeTest::Node,
        preds: vec![],
    }
}

/// Expresión XPath compilada.
#[derive(Clone, Debug, PartialEq)]
pub struct XPath {
    expr: Expr,
}

/// Contexto de evaluación.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub node: XNode,
    pub position: usize,
    pub size: usize,
}

impl XPath {
    /// Compila una expresión con el mapa de prefijos dado (prefijo -> URI).
    pub fn compile(
        expr: &str,
        namespaces: &HashMap<String, String>,
    ) -> std::result::Result<XPath, XPathError> {
        let toks = tokenize(expr)?;
        let mut p = Parser {
            toks,
            pos: 0,
            ns: namespaces,
        };
        let e = p.expr()?;
        if p.pos != p.toks.len() {
            return err(format!("contenido sobrante en la expresión: {expr}"));
        }
        Ok(XPath { expr: e })
    }

    /// Evalúa la expresión. `here` es el nodo devuelto por la función `here()`.
    pub fn evaluate(
        &self,
        doc: &Document,
        node: XNode,
        here: Option<XNode>,
    ) -> std::result::Result<Value, XPathError> {
        let ev = Evaluator { doc, here };
        ev.eval(
            &self.expr,
            Context {
                node,
                position: 1,
                size: 1,
            },
        )
    }

    /// Evalúa y convierte a booleano.
    pub fn evaluate_bool(
        &self,
        doc: &Document,
        node: XNode,
        here: Option<XNode>,
    ) -> std::result::Result<bool, XPathError> {
        let ev = Evaluator { doc, here };
        let v = ev.eval(
            &self.expr,
            Context {
                node,
                position: 1,
                size: 1,
            },
        )?;
        Ok(ev.to_bool(&v))
    }

    /// Evalúa y exige un conjunto de nodos (en orden de documento).
    pub fn select(
        &self,
        doc: &Document,
        node: XNode,
        here: Option<XNode>,
    ) -> std::result::Result<Vec<XNode>, XPathError> {
        match self.evaluate(doc, node, here)? {
            Value::Nodes(n) => Ok(n),
            _ => err("la expresión no devuelve un conjunto de nodos"),
        }
    }
}

struct Evaluator<'a> {
    doc: &'a Document,
    here: Option<XNode>,
}

fn sort_dedup(nodes: &mut Vec<XNode>) {
    nodes.sort_by_key(|n| n.order_key());
    nodes.dedup();
}

impl<'a> Evaluator<'a> {
    fn eval(&self, e: &Expr, ctx: Context) -> XResult<Value> {
        Ok(match e {
            Expr::Literal(s) => Value::Str(s.clone()),
            Expr::Number(n) => Value::Num(*n),
            Expr::Neg(x) => Value::Num(-self.to_num(&self.eval(x, ctx)?)),
            Expr::Bin(op, l, r) => self.binary(*op, l, r, ctx)?,
            Expr::Call(name, args) => self.call(name, args, ctx)?,
            Expr::Filter(base, preds) => {
                let v = self.eval(base, ctx)?;
                let Value::Nodes(mut nodes) = v else {
                    return err("los predicados requieren un conjunto de nodos");
                };
                for p in preds {
                    nodes = self.apply_predicate(nodes, p, false)?;
                }
                Value::Nodes(nodes)
            }
            Expr::Path(start, steps) => {
                let mut nodes = match start {
                    PathStart::Context => vec![ctx.node],
                    PathStart::Root => vec![XNode::Node(self.doc.root())],
                    PathStart::Expr(x) => match self.eval(x, ctx)? {
                        Value::Nodes(n) => n,
                        _ => return err("una ruta requiere un conjunto de nodos"),
                    },
                };
                for s in steps {
                    let mut out = Vec::new();
                    for n in &nodes {
                        let mut sel = self.axis_nodes(s.axis, *n);
                        sel.retain(|c| self.matches(&s.test, s.axis, *c));
                        for p in &s.preds {
                            sel = self.apply_predicate(sel, p, s.axis.is_reverse())?;
                        }
                        out.extend(sel);
                    }
                    sort_dedup(&mut out);
                    nodes = out;
                }
                Value::Nodes(nodes)
            }
        })
    }

    /// Aplica un predicado; `nodes` está en orden de eje (inverso para ejes inversos).
    fn apply_predicate(&self, nodes: Vec<XNode>, p: &Expr, _reverse: bool) -> XResult<Vec<XNode>> {
        let size = nodes.len();
        let mut out = Vec::new();
        for (i, n) in nodes.iter().enumerate() {
            let v = self.eval(
                p,
                Context {
                    node: *n,
                    position: i + 1,
                    size,
                },
            )?;
            let keep = match v {
                Value::Num(x) => x == (i + 1) as f64,
                other => self.to_bool(&other),
            };
            if keep {
                out.push(*n);
            }
        }
        Ok(out)
    }

    fn binary(&self, op: BinOp, l: &Expr, r: &Expr, ctx: Context) -> XResult<Value> {
        match op {
            BinOp::Or => {
                let a = self.eval(l, ctx)?;
                if self.to_bool(&a) {
                    return Ok(Value::Bool(true));
                }
                let b = self.eval(r, ctx)?;
                Ok(Value::Bool(self.to_bool(&b)))
            }
            BinOp::And => {
                let a = self.eval(l, ctx)?;
                if !self.to_bool(&a) {
                    return Ok(Value::Bool(false));
                }
                let b = self.eval(r, ctx)?;
                Ok(Value::Bool(self.to_bool(&b)))
            }
            BinOp::Union => {
                let (Value::Nodes(mut a), Value::Nodes(b)) =
                    (self.eval(l, ctx)?, self.eval(r, ctx)?)
                else {
                    return err("'|' requiere conjuntos de nodos");
                };
                a.extend(b);
                sort_dedup(&mut a);
                Ok(Value::Nodes(a))
            }
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let a = self.eval(l, ctx)?;
                let b = self.eval(r, ctx)?;
                Ok(Value::Bool(self.compare(op, &a, &b)))
            }
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                let a = self.to_num(&self.eval(l, ctx)?);
                let b = self.to_num(&self.eval(r, ctx)?);
                Ok(Value::Num(match op {
                    BinOp::Add => a + b,
                    BinOp::Sub => a - b,
                    BinOp::Mul => a * b,
                    BinOp::Div => a / b,
                    _ => a % b,
                }))
            }
        }
    }

    fn compare(&self, op: BinOp, a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Nodes(x), Value::Nodes(y)) => {
                let ys: Vec<String> = y.iter().map(|n| self.string_value(*n)).collect();
                x.iter().any(|n| {
                    let s = self.string_value(*n);
                    ys.iter()
                        .any(|t| self.cmp_atoms(op, &Value::Str(s.clone()), &Value::Str(t.clone())))
                })
            }
            (Value::Nodes(x), other) => match other {
                Value::Bool(_) => self.cmp_atoms(op, &Value::Bool(!x.is_empty()), other),
                _ => x.iter().any(|n| {
                    let sv = Value::Str(self.string_value(*n));
                    let sv = if matches!(other, Value::Num(_)) {
                        Value::Num(self.to_num(&sv))
                    } else {
                        sv
                    };
                    self.cmp_atoms(op, &sv, other)
                }),
            },
            (other, Value::Nodes(y)) => match other {
                Value::Bool(_) => self.cmp_atoms(op, other, &Value::Bool(!y.is_empty())),
                _ => y.iter().any(|n| {
                    let sv = Value::Str(self.string_value(*n));
                    let sv = if matches!(other, Value::Num(_)) {
                        Value::Num(self.to_num(&sv))
                    } else {
                        sv
                    };
                    self.cmp_atoms(op, other, &sv)
                }),
            },
            _ => self.cmp_atoms(op, a, b),
        }
    }

    fn cmp_atoms(&self, op: BinOp, a: &Value, b: &Value) -> bool {
        match op {
            BinOp::Eq | BinOp::Ne => {
                let eq = if matches!(a, Value::Bool(_)) || matches!(b, Value::Bool(_)) {
                    self.to_bool(a) == self.to_bool(b)
                } else if matches!(a, Value::Num(_)) || matches!(b, Value::Num(_)) {
                    self.to_num(a) == self.to_num(b)
                } else {
                    self.to_str(a) == self.to_str(b)
                };
                if op == BinOp::Eq { eq } else { !eq }
            }
            _ => {
                let x = self.to_num(a);
                let y = self.to_num(b);
                match op {
                    BinOp::Lt => x < y,
                    BinOp::Le => x <= y,
                    BinOp::Gt => x > y,
                    _ => x >= y,
                }
            }
        }
    }

    pub(crate) fn to_bool(&self, v: &Value) -> bool {
        match v {
            Value::Bool(b) => *b,
            Value::Num(n) => *n != 0.0 && !n.is_nan(),
            Value::Str(s) => !s.is_empty(),
            Value::Nodes(n) => !n.is_empty(),
        }
    }

    fn to_num(&self, v: &Value) -> f64 {
        match v {
            Value::Num(n) => *n,
            Value::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Value::Str(s) => str_to_num(s),
            Value::Nodes(_) => str_to_num(&self.to_str(v)),
        }
    }

    fn to_str(&self, v: &Value) -> String {
        match v {
            Value::Str(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Num(n) => num_to_str(*n),
            Value::Nodes(n) => n.first().map(|x| self.string_value(*x)).unwrap_or_default(),
        }
    }

    fn string_value(&self, n: XNode) -> String {
        match n {
            XNode::Node(id) => match self.doc.kind(id) {
                NodeKind::Document | NodeKind::Element(_) => self.doc.text_content(id),
                NodeKind::Text { text, .. } => text.clone(),
                NodeKind::Comment(c) => c.clone(),
                NodeKind::Pi { data, .. } => data.clone(),
            },
            XNode::Attr(e, i) => self
                .doc
                .element(e)
                .and_then(|el| el.attrs.get(i as usize))
                .map(|a| a.value.clone())
                .unwrap_or_default(),
            XNode::Ns(e, i) => namespace_nodes(self.doc, e)
                .get(i as usize)
                .map(|(_, u)| u.clone())
                .unwrap_or_default(),
        }
    }

    fn parent_of(&self, n: XNode) -> Option<XNode> {
        match n {
            XNode::Node(id) => self.doc.parent(id).map(XNode::Node),
            XNode::Attr(e, _) | XNode::Ns(e, _) => Some(XNode::Node(e)),
        }
    }

    /// Nodos del eje en orden de eje.
    fn axis_nodes(&self, axis: Axis, n: XNode) -> Vec<XNode> {
        let doc = self.doc;
        match axis {
            Axis::SelfAxis => vec![n],
            Axis::Parent => self.parent_of(n).into_iter().collect(),
            Axis::Ancestor | Axis::AncestorOrSelf => {
                let mut out = Vec::new();
                if axis == Axis::AncestorOrSelf {
                    out.push(n);
                }
                let mut cur = self.parent_of(n);
                while let Some(p) = cur {
                    out.push(p);
                    cur = self.parent_of(p);
                }
                out
            }
            Axis::Child => match n {
                XNode::Node(id) => doc.children(id).iter().map(|&c| XNode::Node(c)).collect(),
                _ => vec![],
            },
            Axis::Descendant | Axis::DescendantOrSelf => match n {
                XNode::Node(id) => {
                    let all = doc.descendants(id);
                    let skip = usize::from(axis == Axis::Descendant);
                    all.into_iter().skip(skip).map(XNode::Node).collect()
                }
                _ => {
                    if axis == Axis::DescendantOrSelf {
                        vec![n]
                    } else {
                        vec![]
                    }
                }
            },
            Axis::Attribute => match n {
                XNode::Node(id) => match doc.element(id) {
                    Some(e) => (0..e.attrs.len())
                        .map(|i| XNode::Attr(id, i as u32))
                        .collect(),
                    None => vec![],
                },
                _ => vec![],
            },
            Axis::Namespace => match n {
                XNode::Node(id) if doc.element(id).is_some() => (0..namespace_nodes(doc, id).len())
                    .map(|i| XNode::Ns(id, i as u32))
                    .collect(),
                _ => vec![],
            },
            Axis::FollowingSibling | Axis::PrecedingSibling => match n {
                XNode::Node(id) => {
                    let Some(p) = doc.parent(id) else {
                        return vec![];
                    };
                    let sibs = doc.children(p);
                    let idx = sibs.iter().position(|&s| s == id).unwrap_or(0);
                    if axis == Axis::FollowingSibling {
                        sibs[idx + 1..].iter().map(|&c| XNode::Node(c)).collect()
                    } else {
                        sibs[..idx].iter().rev().map(|&c| XNode::Node(c)).collect()
                    }
                }
                _ => vec![],
            },
            Axis::Following => {
                // Nodos posteriores en orden de documento que no son descendientes.
                let base = match n {
                    XNode::Node(id) => id,
                    XNode::Attr(e, _) | XNode::Ns(e, _) => {
                        // Los descendientes del elemento sí siguen al atributo.
                        return doc
                            .descendants(doc.root())
                            .into_iter()
                            .filter(|&x| x.0 > e.0)
                            .map(XNode::Node)
                            .collect();
                    }
                };
                let desc_end = doc
                    .descendants(base)
                    .iter()
                    .map(|x| x.0)
                    .max()
                    .unwrap_or(base.0);
                doc.descendants(doc.root())
                    .into_iter()
                    .filter(|&x| x.0 > desc_end)
                    .map(XNode::Node)
                    .collect()
            }
            Axis::Preceding => {
                let base = match n {
                    XNode::Node(id) => id,
                    XNode::Attr(e, _) | XNode::Ns(e, _) => e,
                };
                let ancestors: Vec<NodeId> = doc.ancestors(base).collect();
                let mut out: Vec<XNode> = doc
                    .descendants(doc.root())
                    .into_iter()
                    .filter(|&x| x.0 < base.0 && !ancestors.contains(&x))
                    .map(XNode::Node)
                    .collect();
                out.reverse();
                out
            }
        }
    }

    fn matches(&self, test: &NodeTest, axis: Axis, n: XNode) -> bool {
        let doc = self.doc;
        match test {
            NodeTest::Node => true,
            NodeTest::Text => {
                matches!(n, XNode::Node(id) if matches!(doc.kind(id), NodeKind::Text { .. }))
            }
            NodeTest::Comment => {
                matches!(n, XNode::Node(id) if matches!(doc.kind(id), NodeKind::Comment(_)))
            }
            NodeTest::Pi(target) => match n {
                XNode::Node(id) => match doc.kind(id) {
                    NodeKind::Pi { target: t, .. } => target.as_ref().is_none_or(|x| x == t),
                    _ => false,
                },
                _ => false,
            },
            NodeTest::Any | NodeTest::NsWildcard(_) | NodeTest::Name(..) => {
                // Tipo de nodo principal del eje.
                let (ns, local): (Option<String>, String) = match (axis, n) {
                    (Axis::Attribute, XNode::Attr(e, i)) => {
                        let Some(a) = doc.element(e).and_then(|el| el.attrs.get(i as usize)) else {
                            return false;
                        };
                        (a.ns.clone(), a.local.clone())
                    }
                    (Axis::Attribute, _) => return false,
                    (Axis::Namespace, XNode::Ns(e, i)) => {
                        let nodes = namespace_nodes(doc, e);
                        let Some((p, _)) = nodes.get(i as usize) else {
                            return false;
                        };
                        (None, p.clone())
                    }
                    (Axis::Namespace, _) => return false,
                    (_, XNode::Node(id)) => match doc.element(id) {
                        Some(e) => (e.ns.clone(), e.local.clone()),
                        None => return false,
                    },
                    _ => return false,
                };
                match test {
                    NodeTest::Any => true,
                    NodeTest::NsWildcard(u) => ns.as_deref() == Some(u.as_str()),
                    NodeTest::Name(u, l) => *l == local && ns.as_deref() == u.as_deref(),
                    _ => false,
                }
            }
        }
    }

    fn call(&self, name: &str, args: &[Expr], ctx: Context) -> XResult<Value> {
        let arg = |i: usize| -> XResult<Value> {
            match args.get(i) {
                Some(a) => self.eval(a, ctx),
                None => err(format!("faltan argumentos en {name}()")),
            }
        };
        let str_arg = |i: usize| -> XResult<String> { Ok(self.to_str(&arg(i)?)) };
        let node_arg_or_ctx = |i: usize| -> XResult<Option<XNode>> {
            if args.len() > i {
                match arg(i)? {
                    Value::Nodes(n) => Ok(n.first().copied()),
                    _ => err(format!("{name}() requiere un conjunto de nodos")),
                }
            } else {
                Ok(Some(ctx.node))
            }
        };
        Ok(match name {
            "last" => Value::Num(ctx.size as f64),
            "position" => Value::Num(ctx.position as f64),
            "count" => match arg(0)? {
                Value::Nodes(n) => Value::Num(n.len() as f64),
                _ => return err("count() requiere un conjunto de nodos"),
            },
            "here" => Value::Nodes(self.here.into_iter().collect()),
            "id" => {
                let v = arg(0)?;
                let tokens: Vec<String> = match &v {
                    Value::Nodes(n) => n
                        .iter()
                        .flat_map(|x| {
                            self.string_value(*x)
                                .split_whitespace()
                                .map(str::to_string)
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                    other => self
                        .to_str(other)
                        .split_whitespace()
                        .map(str::to_string)
                        .collect(),
                };
                let mut out: Vec<XNode> = tokens
                    .iter()
                    .filter_map(|t| self.doc.find_by_id(t))
                    .map(XNode::Node)
                    .collect();
                sort_dedup(&mut out);
                Value::Nodes(out)
            }
            "local-name" | "name" | "namespace-uri" => {
                let Some(n) = node_arg_or_ctx(0)? else {
                    return Ok(Value::Str(String::new()));
                };
                let (prefix, local, ns) = match n {
                    XNode::Node(id) => match self.doc.kind(id) {
                        NodeKind::Element(e) => (e.prefix.clone(), e.local.clone(), e.ns.clone()),
                        NodeKind::Pi { target, .. } => (None, target.clone(), None),
                        _ => (None, String::new(), None),
                    },
                    XNode::Attr(e, i) => {
                        match self.doc.element(e).and_then(|el| el.attrs.get(i as usize)) {
                            Some(a) => (a.prefix.clone(), a.local.clone(), a.ns.clone()),
                            None => (None, String::new(), None),
                        }
                    }
                    XNode::Ns(e, i) => {
                        let p = namespace_nodes(self.doc, e)
                            .get(i as usize)
                            .map(|(p, _)| p.clone())
                            .unwrap_or_default();
                        (None, p, None)
                    }
                };
                Value::Str(match name {
                    "local-name" => local,
                    "namespace-uri" => ns.unwrap_or_default(),
                    _ => match prefix {
                        Some(p) => format!("{p}:{local}"),
                        None => local,
                    },
                })
            }
            "string" => {
                if args.is_empty() {
                    Value::Str(self.string_value(ctx.node))
                } else {
                    Value::Str(str_arg(0)?)
                }
            }
            "concat" => {
                let mut s = String::new();
                for i in 0..args.len() {
                    s.push_str(&str_arg(i)?);
                }
                Value::Str(s)
            }
            "starts-with" => Value::Bool(str_arg(0)?.starts_with(&str_arg(1)?)),
            "contains" => Value::Bool(str_arg(0)?.contains(&str_arg(1)?)),
            "substring-before" => {
                let s = str_arg(0)?;
                let t = str_arg(1)?;
                Value::Str(s.find(&t).map(|i| s[..i].to_string()).unwrap_or_default())
            }
            "substring-after" => {
                let s = str_arg(0)?;
                let t = str_arg(1)?;
                Value::Str(
                    s.find(&t)
                        .map(|i| s[i + t.len()..].to_string())
                        .unwrap_or_default(),
                )
            }
            "substring" => {
                let s: Vec<char> = str_arg(0)?.chars().collect();
                let start = round_half_up(self.to_num(&arg(1)?));
                let end = if args.len() > 2 {
                    start + round_half_up(self.to_num(&arg(2)?))
                } else {
                    f64::INFINITY
                };
                let out: String = s
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        let p = (*i + 1) as f64;
                        p >= start && p < end
                    })
                    .map(|(_, c)| *c)
                    .collect();
                Value::Str(out)
            }
            "string-length" => {
                let s = if args.is_empty() {
                    self.string_value(ctx.node)
                } else {
                    str_arg(0)?
                };
                Value::Num(s.chars().count() as f64)
            }
            "normalize-space" => {
                let s = if args.is_empty() {
                    self.string_value(ctx.node)
                } else {
                    str_arg(0)?
                };
                Value::Str(s.split_whitespace().collect::<Vec<_>>().join(" "))
            }
            "translate" => {
                let s = str_arg(0)?;
                let from: Vec<char> = str_arg(1)?.chars().collect();
                let to: Vec<char> = str_arg(2)?.chars().collect();
                Value::Str(
                    s.chars()
                        .filter_map(|c| match from.iter().position(|&f| f == c) {
                            Some(i) => to.get(i).copied(),
                            None => Some(c),
                        })
                        .collect(),
                )
            }
            "boolean" => Value::Bool(self.to_bool(&arg(0)?)),
            "not" => Value::Bool(!self.to_bool(&arg(0)?)),
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            "lang" => {
                let want = str_arg(0)?.to_ascii_lowercase();
                let start = match ctx.node {
                    XNode::Node(id) => Some(id),
                    XNode::Attr(e, _) | XNode::Ns(e, _) => Some(e),
                };
                let mut found = None;
                let mut cur = start;
                while let Some(id) = cur {
                    if let Some(v) = self.doc.element(id).and_then(|e| e.attr_ns(XML_NS, "lang")) {
                        found = Some(v.to_ascii_lowercase());
                        break;
                    }
                    cur = self.doc.parent(id);
                }
                Value::Bool(found.is_some_and(|l| l == want || l.starts_with(&format!("{want}-"))))
            }
            "number" => {
                if args.is_empty() {
                    Value::Num(str_to_num(&self.string_value(ctx.node)))
                } else {
                    Value::Num(self.to_num(&arg(0)?))
                }
            }
            "sum" => match arg(0)? {
                Value::Nodes(n) => {
                    Value::Num(n.iter().map(|x| str_to_num(&self.string_value(*x))).sum())
                }
                _ => return err("sum() requiere un conjunto de nodos"),
            },
            "floor" => Value::Num(self.to_num(&arg(0)?).floor()),
            "ceiling" => Value::Num(self.to_num(&arg(0)?).ceil()),
            "round" => Value::Num(round_half_up(self.to_num(&arg(0)?))),
            other => return err(format!("función desconocida: {other}()")),
        })
    }
}

fn round_half_up(x: f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        x
    } else {
        (x + 0.5).floor()
    }
}

fn str_to_num(s: &str) -> f64 {
    let t = s.trim_matches([' ', '\t', '\n', '\r']);
    if t.is_empty()
        || !t
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
    {
        return f64::NAN;
    }
    t.parse().unwrap_or(f64::NAN)
}

fn num_to_str(n: f64) -> String {
    if n.is_nan() {
        "NaN".into()
    } else if n.is_infinite() {
        if n > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else if n == n.trunc() && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn paths_and_predicates() {
        let doc = Document::parse("<bookstore><book><title>A</title></book><book><title>B</title><p x='1'/></book></bookstore>").unwrap();
        let root = XNode::Node(doc.document_element().unwrap());
        let xp = XPath::compile("/bookstore/book[1]/title", &HashMap::new()).unwrap();
        let r = xp.select(&doc, root, None).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            doc.text_content(match r[0] {
                XNode::Node(n) => n,
                _ => panic!(),
            }),
            "A"
        );
        let xp = XPath::compile("//book[last()]/title", &HashMap::new()).unwrap();
        let r = xp.select(&doc, root, None).unwrap();
        assert_eq!(
            doc.text_content(match r[0] {
                XNode::Node(n) => n,
                _ => panic!(),
            }),
            "B"
        );
        let xp = XPath::compile("count(//*) + 1 = 7 and //p/@x = '1'", &HashMap::new()).unwrap();
        assert!(xp.evaluate_bool(&doc, root, None).unwrap());
    }

    #[test]
    fn namespaces_and_functions() {
        let doc = Document::parse("<f:Facturae xmlns:f='urn:f'><a/><ds:Signature xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><b/></ds:Signature></f:Facturae>").unwrap();
        let root = XNode::Node(doc.document_element().unwrap());
        let xp = XPath::compile(
            "//*[namespace-uri()='urn:f'][local-name()='Facturae']",
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(xp.select(&doc, root, None).unwrap(), vec![root]);
        let xp = XPath::compile(
            "not(ancestor-or-self::ds:Signature)",
            &ns(&[("ds", "http://www.w3.org/2000/09/xmldsig#")]),
        )
        .unwrap();
        let b = doc
            .descendants(doc.root())
            .into_iter()
            .find(|&n| doc.element(n).is_some_and(|e| e.local == "b"))
            .unwrap();
        assert!(!xp.evaluate_bool(&doc, XNode::Node(b), None).unwrap());
        assert!(xp.evaluate_bool(&doc, root, None).unwrap());
        assert!(XPath::compile("p:x", &HashMap::new()).is_err());
        let xp = XPath::compile(
            "concat(substring('12345', 2, 3), translate('abc','b','B'))",
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(
            xp.evaluate(&doc, root, None).unwrap(),
            Value::Str("234aBc".into())
        );
        let xp = XPath::compile("count(namespace::*)", &HashMap::new()).unwrap();
        assert_eq!(xp.evaluate(&doc, root, None).unwrap(), Value::Num(2.0));
    }

    #[test]
    fn operators_vs_names() {
        let doc = Document::parse("<r><div>3</div><mod>2</mod></r>").unwrap();
        let root = XNode::Node(doc.document_element().unwrap());
        let xp = XPath::compile("div * mod", &HashMap::new()).unwrap();
        assert_eq!(xp.evaluate(&doc, root, None).unwrap(), Value::Num(6.0));
        let xp = XPath::compile("div div mod", &HashMap::new()).unwrap();
        assert_eq!(xp.evaluate(&doc, root, None).unwrap(), Value::Num(1.5));
    }
}
