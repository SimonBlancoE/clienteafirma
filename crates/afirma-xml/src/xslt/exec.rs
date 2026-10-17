//! Ejecución de la hoja compilada sobre el árbol de entrada.
//!
//! Las instrucciones emiten los mismos sucesos (`startElement`,
//! `namespaceAfterStartElement`, `addAttribute`...) que el código que genera
//! XSLTC, sobre el serializador de [`super::output`] o sobre el constructor de
//! fragmentos de árbol.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::HashMap;

use super::compile::{
    Avt, AvtPart, Content, ExtKind, Instr, LitAttr, NumberLevel, NumberSpec, QName, SortSpec, Stylesheet, VarValue,
    WithParam, classify_extension, is_ncname, is_qname,
};
use super::output::{Handler, Method, OutEncoding, OutputSettings, Stream, Unknown};
use super::pattern::Pattern;
use super::tree::{Forest, PI_DISABLE_ESCAPING, PI_ENABLE_ESCAPING, RtfBuilder, Source};
use super::{Limits, XsltError, collate, number};
use crate::dom::{NodeId, NodeKind};
use crate::xpath::{Context, Evaluator, Expr, Host, Value, XNode, XPath, XPathError, XResult, xsltc_namespace_nodes};

type EResult<T> = Result<T, XsltError>;

fn rt<T>(msg: impl Into<String>) -> EResult<T> {
    Err(XsltError::Runtime(msg.into()))
}

/// Contexto XSLT de la instrucción en curso.
#[derive(Clone, Copy, Debug)]
struct Ctx {
    node: XNode,
    position: usize,
    size: usize,
}

impl Ctx {
    fn xpath(self) -> Context {
        Context {
            node: self.node,
            position: self.position,
            size: self.size,
        }
    }
}

#[derive(Clone, Debug)]
enum GlobalState {
    Pending,
    Evaluating,
    Done(Value),
}

/// Índice de una clave en un árbol: valor -> nodos.
type KeyIndex = HashMap<String, Vec<XNode>>;

/// Destino de la salida.
enum Sink {
    Out(Box<dyn OutputHandler>),
    Rtf(Box<RtfBuilder>),
    Text(StringHandler),
}

/// Manejador de salida que además entrega los octetos al terminar.
trait OutputHandler: Handler {
    fn finish(self: Box<Self>) -> Vec<u8>;
}

impl OutputHandler for Stream {
    fn finish(self: Box<Self>) -> Vec<u8> {
        self.into_bytes()
    }
}

impl OutputHandler for Unknown {
    fn finish(self: Box<Self>) -> Vec<u8> {
        self.into_bytes()
    }
}

/// `StringValueHandler`: solo el texto que no está dentro de elementos.
#[derive(Default)]
struct StringHandler {
    buf: String,
    nested: usize,
    max_len: usize,
}

impl Handler for StringHandler {
    fn start_document(&mut self) -> EResult<()> {
        Ok(())
    }
    fn end_document(&mut self) -> EResult<()> {
        Ok(())
    }
    fn start_element(&mut self, _q: &str) -> EResult<()> {
        self.nested += 1;
        Ok(())
    }
    fn start_element_ns(&mut self, _u: Option<&str>, _q: &str) -> EResult<()> {
        // `EmptySerializer.startElement(uri, local, qname)` no cuenta el nivel.
        Ok(())
    }
    fn end_element(&mut self, _q: &str) -> EResult<()> {
        self.nested = self.nested.saturating_sub(1);
        Ok(())
    }
    fn namespace_after_start_element(&mut self, _p: Option<&str>, _u: &str) -> EResult<()> {
        Ok(())
    }
    fn add_attribute(&mut self, _q: &str, _v: &str) -> EResult<()> {
        Ok(())
    }
    fn add_attribute_ns(&mut self, _u: &str, _l: &str, _q: &str, _v: &str) -> EResult<()> {
        Ok(())
    }
    fn add_unique_attribute(&mut self, _q: &str, _v: &str, _f: u32) -> EResult<()> {
        Ok(())
    }
    fn characters(&mut self, text: &str) -> EResult<()> {
        if self.nested == 0 {
            self.buf.push_str(text);
            if self.buf.len() > self.max_len {
                return Err(XsltError::limit("tamaño de los valores construidos"));
            }
        }
        Ok(())
    }
    fn comment(&mut self, _t: &str) -> EResult<()> {
        Ok(())
    }
    fn processing_instruction(&mut self, _t: &str, _d: &str) -> EResult<()> {
        Ok(())
    }
    fn set_escaping(&mut self, escape: bool) -> bool {
        escape
    }
    fn output_namespace(&mut self, _p: &str) -> EResult<Option<String>> {
        Ok(None)
    }
}

/// Estado de una transformación.
struct Exec<'s> {
    sheet: &'s Stylesheet,
    forest: Forest,
    sinks: Vec<Sink>,
    /// Variables locales visibles: (nombre, valor).
    locals: Vec<(QName, Value)>,
    /// Inicio de las variables de la plantilla en curso.
    frame_base: usize,
    globals: RefCell<Vec<GlobalState>>,
    keys: RefCell<HashMap<(QName, NodeId), KeyIndex>>,
    /// Estado de cada `DecimalFormat` (por nombre de `xsl:decimal-format`).
    formatters: RefCell<HashMap<Option<QName>, number::Format>>,
    /// `_value` de los contadores por defecto que XSLTC comparte entre todos
    /// los `xsl:number` sin `count` ni `from` de cada nivel (y los que tienen
    /// `value`): una vez fijado, los siguientes de ese nivel lo repiten.
    default_counters: [Option<f64>; 3],
    steps: Cell<u64>,
    limits: Limits,
    depth: usize,
}

/// Anfitrión XPath de una evaluación (nodo actual de XSLT).
struct HostCtx<'a, 's> {
    ex: &'a Exec<'s>,
    current: XNode,
}

impl Host for HostCtx<'_, '_> {
    fn variable(&self, ns: Option<&str>, local: &str) -> XResult<Value> {
        let q = QName {
            ns: ns.map(str::to_string),
            local: local.to_string(),
        };
        if let Some((_, v)) = self.ex.locals[self.ex.frame_base..].iter().rev().find(|(n, _)| *n == q) {
            return Ok(v.clone());
        }
        self.ex.global_value(&q).map_err(|e| XPathError(e.to_string()))
    }

    fn function(
        &self,
        ev: &Evaluator<'_>,
        ns: Option<&str>,
        local: &str,
        args: &[Expr],
        ctx: Context,
    ) -> Option<XResult<Value>> {
        let arg = |i: usize| ev.eval(&args[i], ctx);
        match ns {
            None => {
                let r = match local {
                    "current" => Ok(Value::Nodes(vec![self.current])),
                    "key" => self.key(ev, args, ctx),
                    "generate-id" => {
                        let n = if args.is_empty() {
                            Some(ctx.node)
                        } else {
                            match arg(0) {
                                Ok(Value::Nodes(n)) => n.first().copied(),
                                Ok(Value::Rtf(r)) => Some(XNode::Node(r)),
                                Ok(_) => return Some(Err(XPathError("generate-id() requiere un nodo".into()))),
                                Err(e) => return Some(Err(e)),
                            }
                        };
                        Ok(Value::Str(match n {
                            Some(n) => format!("N{}", self.ex.forest.handle(n)),
                            None => String::new(),
                        }))
                    }
                    "format-number" => self.format_number(ev, args, ctx),
                    "system-property" => match arg(0) {
                        Ok(v) => {
                            let name = ev.to_str(&v);
                            match name.as_str() {
                                "xsl:version" => Ok(Value::Str("1.0".into())),
                                "xsl:vendor" => Ok(Value::Str("Apache Software Foundation (Xalan XSLTC)".into())),
                                "xsl:vendor-url" => Ok(Value::Str("http://xml.apache.org/xalan-j".into())),
                                _ => Err(XPathError(format!(
                                    "argumento '{name}' no válido en la llamada a system-property()"
                                ))),
                            }
                        }
                        Err(e) => Err(e),
                    },
                    "unparsed-entity-uri" => match arg(0) {
                        Ok(v) => {
                            let name = ev.to_str(&v);
                            Ok(Value::Str(
                                self.ex.forest.unparsed.get(&name).cloned().unwrap_or_default(),
                            ))
                        }
                        Err(e) => Err(e),
                    },
                    "document" => self.document(ev, args, ctx),
                    _ => return None,
                };
                Some(r)
            }
            Some(uri) => {
                let r = match classify_extension(uri, local) {
                    Some(ExtKind::NodeSet) => {
                        if args.len() != 1 {
                            return Some(Err(XPathError("node-set() requiere un argumento".into())));
                        }
                        match arg(0) {
                            Ok(Value::Rtf(r)) => Ok(Value::Nodes(vec![XNode::Node(r)])),
                            Ok(Value::Nodes(n)) => Ok(Value::Nodes(n)),
                            Ok(_) => Err(XPathError("node-set() requiere un fragmento de árbol".into())),
                            Err(e) => Err(e),
                        }
                    }
                    Some(ExtKind::ObjectType) => match arg(0) {
                        Ok(v) => Ok(Value::Str(
                            match v {
                                Value::Str(_) => "string",
                                Value::Bool(_) => "boolean",
                                Value::Num(_) => "number",
                                Value::Rtf(_) => "RTF",
                                Value::Nodes(_) => "node-set",
                            }
                            .into(),
                        )),
                        Err(e) => Err(e),
                    },
                    _ => Err(XPathError(format!(
                        "el uso de la función de extensión '{uri}:{local}' no está permitido con el procesamiento seguro"
                    ))),
                };
                Some(r)
            }
        }
    }

    fn element_by_id(&self, root: NodeId, id: &str) -> Option<NodeId> {
        self.ex.forest.element_by_id(root, id)
    }

    fn tick(&self, n: usize) -> XResult<()> {
        let s = self.ex.steps.get() + n as u64;
        self.ex.steps.set(s);
        if s > self.ex.limits.max_steps {
            return Err(XPathError(
                "se ha superado el límite de trabajo de la transformación".into(),
            ));
        }
        Ok(())
    }
}

impl HostCtx<'_, '_> {
    fn key(&self, ev: &Evaluator<'_>, args: &[Expr], ctx: Context) -> XResult<Value> {
        let name_v = ev.eval(&args[0], ctx)?;
        let name = ev.to_str(&name_v);
        // El nombre se resuelve con los prefijos de la hoja al compilar; aquí
        // solo se admite sin prefijo o ya expandido como "{uri}local".
        let q = parse_expanded(&name);
        let root = ev.doc.tree_root(ctx.node.owner());
        let v = ev.eval(&args[1], ctx)?;
        // XSLTC solo indexa el documento de entrada (`buildKeys`): una clave
        // sin definir o un árbol temporal dan un conjunto vacío.
        if !self.ex.sheet.keys.contains_key(&q) || root != self.ex.forest.source_root {
            return Ok(Value::Nodes(vec![]));
        }
        let values: Vec<String> = match &v {
            Value::Nodes(ns) => ns.iter().map(|n| ev.string_value(*n)).collect(),
            other => vec![ev.to_str(other)],
        };
        self.ex
            .ensure_key_index(&q, root)
            .map_err(|e| XPathError(e.to_string()))?;
        let keys = self.ex.keys.borrow();
        let index = keys.get(&(q, root)).expect("índice");
        let mut out: Vec<XNode> = Vec::new();
        for s in values {
            if let Some(nodes) = index.get(&s) {
                out.extend(nodes.iter().copied());
            }
        }
        out.sort_by_key(|n| n.order_key());
        out.dedup();
        Ok(Value::Nodes(out))
    }

    fn format_number(&self, ev: &Evaluator<'_>, args: &[Expr], ctx: Context) -> XResult<Value> {
        let value = ev.to_num(&ev.eval(&args[0], ctx)?);
        let pattern = ev.to_str(&ev.eval(&args[1], ctx)?);
        let fmt = if args.len() > 2 {
            let n = ev.to_str(&ev.eval(&args[2], ctx)?);
            Some(parse_expanded(&n))
        } else {
            None
        };
        // Un nombre sin `xsl:decimal-format` usa el formato por defecto
        // (`AbstractTranslet.getDecimalFormat`), y comparte su estado.
        let key = if self.ex.sheet.decimal_formats.contains_key(&fmt) {
            fmt
        } else {
            None
        };
        let symbols = self.ex.sheet.decimal_formats.get(&key).cloned().unwrap_or_default();
        let mut formatters = self.ex.formatters.borrow_mut();
        let current = formatters
            .entry(key)
            .or_insert_with(|| number::Format::initial(&symbols));
        // `BasisLibrary.formatNumber` compara el patrón por identidad con la
        // cadena vacía interna: un literal o una variable vacíos no se
        // aplican y se reutiliza el patrón anterior.
        let interned_empty = pattern.is_empty() && is_interned_source(&args[1]);
        if !interned_empty {
            *current = number::apply_pattern(current, &pattern, &symbols).map_err(|e| XPathError(e.to_string()))?;
        }
        Ok(Value::Str(number::format_with(value, current, &symbols)))
    }

    fn document(&self, ev: &Evaluator<'_>, args: &[Expr], ctx: Context) -> XResult<Value> {
        let v = ev.eval(&args[0], ctx)?;
        let uris: Vec<String> = match &v {
            Value::Nodes(ns) => ns.iter().map(|n| ev.string_value(*n)).collect(),
            other => vec![ev.to_str(other)],
        };
        if uris.iter().all(|u| u.is_empty()) {
            // La hoja se cargó sin URI base: XSLTC devuelve un conjunto vacío.
            return Ok(Value::Nodes(vec![]));
        }
        Err(XPathError(
            "document(): no se permite el acceso a recursos externos (accessExternalStylesheet)".into(),
        ))
    }
}

/// Expresiones cuyo resultado vacío es la cadena interna `""` de Java.
fn is_interned_source(e: &Expr) -> bool {
    match e {
        Expr::Literal(_) | Expr::Var(..) => true,
        Expr::Call(None, name, args) => name == "string" && args.len() == 1,
        _ => false,
    }
}

/// Nombre expandido de una clave o formato: `local` o `{uri}local`.
fn parse_expanded(s: &str) -> QName {
    if let Some(rest) = s.strip_prefix('{')
        && let Some((u, l)) = rest.split_once('}')
    {
        return QName {
            ns: Some(u.to_string()),
            local: l.to_string(),
        };
    }
    QName::local(s)
}

impl<'s> Exec<'s> {
    fn host(&self, current: XNode) -> HostCtx<'_, 's> {
        HostCtx { ex: self, current }
    }

    fn eval(&self, xp: &XPath, ctx: Ctx) -> EResult<Value> {
        let host = self.host(ctx.node);
        xp.eval_with(&self.forest.doc, ctx.xpath(), &host)
            .map_err(|e| XsltError::Runtime(e.0))
    }

    fn eval_str(&self, xp: &XPath, ctx: Ctx) -> EResult<String> {
        let host = self.host(ctx.node);
        let ev = Evaluator::with_host(&self.forest.doc, &host);
        let v = ev.eval(&xp.expr, ctx.xpath()).map_err(|e| XsltError::Runtime(e.0))?;
        Ok(ev.to_str(&v))
    }

    fn eval_bool(&self, xp: &XPath, ctx: Ctx) -> EResult<bool> {
        let host = self.host(ctx.node);
        let ev = Evaluator::with_host(&self.forest.doc, &host);
        let v = ev.eval(&xp.expr, ctx.xpath()).map_err(|e| XsltError::Runtime(e.0))?;
        Ok(ev.to_bool(&v))
    }

    fn avt(&self, avt: &Avt, ctx: Ctx) -> EResult<String> {
        let mut s = String::new();
        for p in &avt.parts {
            match p {
                AvtPart::Lit(l) => s.push_str(l),
                AvtPart::Expr(x) => s.push_str(&self.eval_str(x, ctx)?),
            }
        }
        Ok(s)
    }

    fn tick(&self, n: u64) -> EResult<()> {
        let s = self.steps.get() + n;
        self.steps.set(s);
        if s > self.limits.max_steps {
            return Err(XsltError::limit("trabajo de la transformación"));
        }
        Ok(())
    }

    fn out(&mut self) -> &mut dyn Handler {
        match self.sinks.last_mut().expect("salida") {
            Sink::Out(h) => h.as_mut(),
            Sink::Rtf(b) => b.as_mut(),
            Sink::Text(t) => t,
        }
    }

    // -- Variables globales y claves ----------------------------------------------

    fn global_index(&self, q: &QName) -> Option<usize> {
        self.sheet.globals.iter().position(|&id| self.sheet.vars[id].name == *q)
    }

    /// Valor de una global; las de `select` se evalúan bajo demanda.
    fn global_value(&self, q: &QName) -> EResult<Value> {
        let Some(k) = self.global_index(q) else {
            return rt(format!("variable no definida: {}", q.local));
        };
        let state = self.globals.borrow()[k].clone();
        match state {
            GlobalState::Done(v) => Ok(v),
            GlobalState::Evaluating => rt(format!("definición circular de la variable '{}'", q.local)),
            GlobalState::Pending => {
                let decl = &self.sheet.vars[self.sheet.globals[k]];
                let VarValue::Select(xp) = &decl.value else {
                    return rt(format!("la variable '{}' todavía no tiene valor", q.local));
                };
                self.globals.borrow_mut()[k] = GlobalState::Evaluating;
                let ctx = self.root_ctx();
                let v = self.eval(xp, ctx);
                match v {
                    Ok(v) => {
                        self.globals.borrow_mut()[k] = GlobalState::Done(v.clone());
                        Ok(v)
                    }
                    Err(e) => {
                        self.globals.borrow_mut()[k] = GlobalState::Pending;
                        Err(e)
                    }
                }
            }
        }
    }

    fn root_ctx(&self) -> Ctx {
        Ctx {
            node: XNode::Node(self.forest.source_root),
            position: 1,
            size: 1,
        }
    }

    fn ensure_key_index(&self, q: &QName, root: NodeId) -> EResult<()> {
        if self.keys.borrow().contains_key(&(q.clone(), root)) {
            return Ok(());
        }
        let defs = self.sheet.keys.get(q).expect("clave");
        let doc = &self.forest.doc;
        let mut index: HashMap<String, Vec<XNode>> = HashMap::new();
        let end = doc.subtree_end(root);
        for i in root.0..end {
            let id = NodeId(i);
            let mut nodes = vec![XNode::Node(id)];
            if let Some(e) = doc.element(id) {
                for k in 0..e.attrs.len() {
                    nodes.push(XNode::Attr(id, k as u32));
                }
            }
            for n in nodes {
                self.tick(1)?;
                for d in defs {
                    let host = self.host(n);
                    let ev = Evaluator::with_host(doc, &host);
                    if d.matches.matches(&ev, n)? {
                        let v = ev
                            .eval(&d.use_.expr, Context::of(n))
                            .map_err(|e| XsltError::Runtime(e.0))?;
                        let keys: Vec<String> = match &v {
                            Value::Nodes(ns) => ns.iter().map(|x| ev.string_value(*x)).collect(),
                            other => vec![ev.to_str(other)],
                        };
                        for k in keys {
                            let list = index.entry(k).or_default();
                            if !list.contains(&n) {
                                list.push(n);
                            }
                        }
                    }
                }
            }
        }
        self.keys.borrow_mut().insert((q.clone(), root), index);
        Ok(())
    }

    // -- Plantillas -------------------------------------------------------------

    /// Busca la regla de plantilla para un nodo en un modo.
    fn find_template(&self, mode: &Option<QName>, n: XNode) -> EResult<Option<usize>> {
        let Some(rules) = self.sheet.rules.get(mode) else {
            return Ok(None);
        };
        let host = self.host(n);
        let ev = Evaluator::with_host(&self.forest.doc, &host);
        for r in rules {
            self.tick(1)?;
            let t = &self.sheet.templates[r.template];
            let pat: &Pattern = t.pattern.as_ref().expect("patrón");
            if pat.alts[r.alt].matches(&ev, n)? {
                return Ok(Some(r.template));
            }
        }
        Ok(None)
    }

    fn apply_templates(&mut self, nodes: Vec<XNode>, mode: &Option<QName>, params: Vec<(QName, Value)>) -> EResult<()> {
        let size = nodes.len();
        for (i, n) in nodes.into_iter().enumerate() {
            let ctx = Ctx {
                node: n,
                position: i + 1,
                size,
            };
            match self.find_template(mode, n)? {
                Some(t) => self.call_template(t, ctx, params.clone())?,
                // Las reglas internas de XSLTC no abren un marco de
                // parámetros: los recibidos pasan a las plantillas de los hijos.
                None => self.builtin(ctx, mode, &params)?,
            }
        }
        Ok(())
    }

    fn builtin(&mut self, ctx: Ctx, mode: &Option<QName>, params: &[(QName, Value)]) -> EResult<()> {
        match ctx.node {
            XNode::Node(id) => match self.forest.doc.kind(id) {
                NodeKind::Document | NodeKind::Element(_) => {
                    let children: Vec<XNode> = self.forest.doc.children(id).iter().map(|&c| XNode::Node(c)).collect();
                    self.enter()?;
                    let r = self.apply_templates(children, mode, params.to_vec());
                    self.depth -= 1;
                    r
                }
                NodeKind::Text { text, .. } => {
                    let t = text.clone();
                    self.out().characters(&t)
                }
                _ => Ok(()),
            },
            XNode::Attr(..) => {
                let host = self.host(ctx.node);
                let v = Evaluator::with_host(&self.forest.doc, &host).string_value(ctx.node);
                self.out().characters(&v)
            }
            XNode::Ns(..) => Ok(()),
        }
    }

    fn enter(&mut self) -> EResult<()> {
        self.depth += 1;
        if self.depth > self.limits.max_depth {
            return Err(XsltError::limit("profundidad de recursión"));
        }
        Ok(())
    }

    fn call_template(&mut self, t: usize, ctx: Ctx, params: Vec<(QName, Value)>) -> EResult<()> {
        self.enter()?;
        let saved_base = self.frame_base;
        let saved_len = self.locals.len();
        self.frame_base = self.locals.len();
        let template = &self.sheet.templates[t];
        let result = (|| -> EResult<()> {
            for &p in &template.params {
                let decl = &self.sheet.vars[p];
                let value = match params.iter().find(|(n, _)| *n == decl.name) {
                    Some((_, v)) => v.clone(),
                    None => self.var_value(&decl.value, ctx)?,
                };
                self.locals.push((decl.name.clone(), value));
            }
            self.run_body(&template.body, ctx)
        })();
        self.locals.truncate(saved_len);
        self.frame_base = saved_base;
        self.depth -= 1;
        result
    }

    fn var_value(&mut self, v: &VarValue, ctx: Ctx) -> EResult<Value> {
        match v {
            VarValue::Select(xp) => self.eval(xp, ctx),
            VarValue::Empty => Ok(Value::Str(String::new())),
            VarValue::Content(body) => self.build_rtf(body, ctx),
        }
    }

    fn build_rtf(&mut self, body: &[Instr], ctx: Ctx) -> EResult<Value> {
        let max = self.limits.max_output;
        self.sinks.push(Sink::Rtf(Box::new(RtfBuilder::new(max))));
        let r = self.run_body(body, ctx);
        let Some(Sink::Rtf(mut b)) = self.sinks.pop() else {
            unreachable!("salida de fragmento")
        };
        r?;
        b.end_document()?;
        let root = self.forest.adopt(&b.tree)?;
        Ok(Value::Rtf(root))
    }

    fn string_content(&mut self, body: &[Instr], ctx: Ctx) -> EResult<String> {
        self.sinks.push(Sink::Text(StringHandler {
            max_len: self.limits.max_output,
            ..Default::default()
        }));
        let r = self.run_body(body, ctx);
        let Some(Sink::Text(h)) = self.sinks.pop() else {
            unreachable!("salida de texto")
        };
        r?;
        Ok(h.buf)
    }

    fn with_params(&mut self, params: &[WithParam], ctx: Ctx) -> EResult<Vec<(QName, Value)>> {
        let mut out = Vec::new();
        for p in params {
            let v = self.var_value(&p.value, ctx)?;
            out.push((p.name.clone(), v));
        }
        Ok(out)
    }

    // -- Instrucciones -------------------------------------------------------------

    fn run_body(&mut self, body: &[Instr], ctx: Ctx) -> EResult<()> {
        let saved = self.locals.len();
        let r = (|| -> EResult<()> {
            for i in body {
                self.run(i, ctx)?;
            }
            Ok(())
        })();
        self.locals.truncate(saved);
        r
    }

    fn select_nodes(&self, xp: &XPath, ctx: Ctx, what: &str) -> EResult<Vec<XNode>> {
        match self.eval(xp, ctx)? {
            Value::Nodes(n) => Ok(n),
            Value::Rtf(r) => Ok(vec![XNode::Node(r)]),
            _ => rt(format!("{what}: la expresión no devuelve un conjunto de nodos")),
        }
    }

    fn run(&mut self, i: &Instr, ctx: Ctx) -> EResult<()> {
        self.tick(1)?;
        match i {
            Instr::Text { text, escaping } => {
                if *escaping {
                    self.out().characters(text)
                } else {
                    let old = self.out().set_escaping(false);
                    self.out().characters(text)?;
                    self.out().set_escaping(old);
                    Ok(())
                }
            }
            Instr::ValueOf { select, escaping } => {
                let v = self.eval(select, ctx)?;
                let host = self.host(ctx.node);
                let ev = Evaluator::with_host(&self.forest.doc, &host);
                // Las expresiones de nodos escriben el valor de cadena del
                // primer nodo solo si no es vacío; las demás, siempre.
                let (text, always) = match &v {
                    Value::Nodes(n) => (n.first().map(|x| ev.string_value(*x)).unwrap_or_default(), false),
                    other => (ev.to_str(other), true),
                };
                if !always && text.is_empty() {
                    return Ok(());
                }
                if *escaping {
                    self.out().characters(&text)
                } else {
                    let old = self.out().set_escaping(false);
                    self.out().characters(&text)?;
                    self.out().set_escaping(old);
                    Ok(())
                }
            }
            Instr::Literal(l) => {
                self.enter()?;
                let r = self.literal(l, ctx);
                self.depth -= 1;
                r
            }
            Instr::CopyOf(xp) => {
                let v = self.eval(xp, ctx)?;
                match v {
                    Value::Nodes(ns) => {
                        for n in ns {
                            self.copy_node(n, false)?;
                        }
                        Ok(())
                    }
                    Value::Rtf(r) => self.copy_node(XNode::Node(r), false),
                    other => {
                        let host = self.host(ctx.node);
                        let s = Evaluator::with_host(&self.forest.doc, &host).to_str(&other);
                        self.out().characters(&s)
                    }
                }
            }
            Instr::Copy { use_sets, body } => self.copy(use_sets, body, ctx),
            Instr::ApplyTemplates {
                select,
                mode,
                sorts,
                params,
            } => {
                let nodes = match select {
                    Some(xp) => match self.eval(xp, ctx)? {
                        Value::Nodes(n) => n,
                        Value::Rtf(_) => {
                            return rt("apply-templates sobre un fragmento de árbol de resultado");
                        }
                        _ => return rt("apply-templates: la expresión no devuelve un conjunto de nodos"),
                    },
                    None => match ctx.node {
                        XNode::Node(id) => self.forest.doc.children(id).iter().map(|&c| XNode::Node(c)).collect(),
                        _ => vec![],
                    },
                };
                let nodes = self.sort(nodes, sorts, ctx)?;
                let params = self.with_params(params, ctx)?;
                self.enter()?;
                let r = self.apply_templates(nodes, mode, params);
                self.depth -= 1;
                r
            }
            Instr::CallTemplate { template, params } => {
                let params = self.with_params(params, ctx)?;
                self.call_template(*template, ctx, params)
            }
            Instr::ApplyImports => self.builtin(ctx, &None, &[]),
            Instr::ForEach { select, sorts, body } => {
                let nodes = self.select_nodes(select, ctx, "for-each")?;
                let nodes = self.sort(nodes, sorts, ctx)?;
                let size = nodes.len();
                self.enter()?;
                let mut r = Ok(());
                for (k, n) in nodes.into_iter().enumerate() {
                    let c = Ctx {
                        node: n,
                        position: k + 1,
                        size,
                    };
                    r = self.run_body(body, c);
                    if r.is_err() {
                        break;
                    }
                }
                self.depth -= 1;
                r
            }
            Instr::If { test, body } => {
                if self.eval_bool(test, ctx)? {
                    self.run_body(body, ctx)?;
                }
                Ok(())
            }
            Instr::Choose { whens, otherwise } => {
                for (test, body) in whens {
                    if self.eval_bool(test, ctx)? {
                        return self.run_body(body, ctx);
                    }
                }
                if let Some(b) = otherwise {
                    self.run_body(b, ctx)?;
                }
                Ok(())
            }
            Instr::Element(e) => {
                self.enter()?;
                let r = self.xsl_element(e, ctx);
                self.depth -= 1;
                r
            }
            Instr::Attribute(a) => self.xsl_attribute(a, ctx),
            Instr::Comment(c) => {
                let text = match c {
                    Content::Text(t) => t.clone(),
                    Content::Instrs(b) => self.string_content(b, ctx)?,
                };
                self.out().comment(&text)
            }
            Instr::Pi { name, literal, body } => {
                let n = self.avt(name, ctx)?;
                if !*literal && !is_ncname(&n) {
                    return rt(format!("nombre de instrucción de proceso no válido: {n}"));
                }
                let value = self.string_content(body, ctx)?;
                let value = if value.find("?>").is_some_and(|i| i > 0) {
                    value.replace("?>", "? >")
                } else {
                    value
                };
                self.out().processing_instruction(&n, &value)
            }
            Instr::Number(spec) => self.xsl_number(spec, ctx),
            Instr::Variable(id) => {
                let decl = &self.sheet.vars[*id];
                if !decl.referenced.get() {
                    return Ok(());
                }
                let v = self.var_value(&decl.value, ctx)?;
                self.locals.push((decl.name.clone(), v));
                Ok(())
            }
            Instr::Message { body, terminate } => {
                // El contenido se evalúa (puede fallar) pero no produce salida.
                let _ = self.build_message(body, ctx)?;
                if *terminate {
                    return rt("ejecución terminada por una instrucción xsl:message");
                }
                Ok(())
            }
            Instr::Unsupported { name, extension } => {
                if *extension {
                    rt(format!("extensión '{name}' de XSLTC no reconocida"))
                } else {
                    rt(format!("elemento '{name}' de XSL no soportado"))
                }
            }
            Instr::Fallback(body) => self.run_body(body, ctx),
        }
    }

    fn build_message(&mut self, body: &[Instr], ctx: Ctx) -> EResult<String> {
        self.string_content(body, ctx)
    }

    fn use_attribute_sets(&mut self, sets: &[QName], ctx: Ctx) -> EResult<()> {
        for s in sets {
            self.enter()?;
            let r = self.attribute_set(s, ctx);
            self.depth -= 1;
            r?;
        }
        Ok(())
    }

    fn attribute_set(&mut self, name: &QName, ctx: Ctx) -> EResult<()> {
        let sheet = self.sheet;
        let Some(set) = sheet.attr_sets.get(name) else {
            return rt(format!("conjunto de atributos no definido: {}", name.local));
        };
        // Las variables locales no son visibles dentro de un conjunto.
        let saved_base = self.frame_base;
        self.frame_base = self.locals.len();
        let r = (|| -> EResult<()> {
            for (uses, attrs) in &set.parts {
                self.use_attribute_sets(uses, ctx)?;
                for a in attrs {
                    self.run(a, ctx)?;
                }
            }
            Ok(())
        })();
        self.frame_base = saved_base;
        r
    }

    fn literal(&mut self, l: &super::compile::LiteralElem, ctx: Ctx) -> EResult<()> {
        self.out().start_element(&l.name)?;
        for (p, u) in &l.namespaces {
            self.out().namespace_after_start_element(Some(p), u)?;
        }
        for a in &l.attrs {
            match a {
                LitAttr::UseSets(sets) => self.use_attribute_sets(sets, ctx)?,
                LitAttr::Attr { name, value, unique } => {
                    let v = self.avt(value, ctx)?;
                    match unique {
                        Some(flags) => self.out().add_unique_attribute(name, &v, *flags)?,
                        None => self.out().add_attribute(name, &v)?,
                    }
                }
            }
        }
        self.run_body(&l.body, ctx)?;
        self.out().end_element(&l.name)
    }

    fn xsl_element(&mut self, e: &super::compile::XslElement, ctx: Ctx) -> EResult<()> {
        if e.ignore {
            // Java avisa y ejecuta el contenido salvo los xsl:attribute.
            let saved = self.locals.len();
            let r = (|| -> EResult<()> {
                for i in &e.body {
                    if matches!(i, Instr::Attribute(_)) {
                        continue;
                    }
                    self.run(i, ctx)?;
                }
                Ok(())
            })();
            self.locals.truncate(saved);
            return r;
        }
        let name;
        if e.literal {
            name = e.name.literal().expect("nombre literal");
            self.out().start_element(&name)?;
            if let Some(ns) = &e.namespace {
                let uri = self.avt(ns, ctx)?;
                self.out().namespace_after_start_element(Some(&e.prefix), &uri)?;
            }
        } else {
            let qname = self.avt(&e.name, ctx)?;
            if !is_qname(&qname) {
                return rt(format!("nombre de elemento no válido: {qname}"));
            }
            let namespace = match &e.namespace {
                Some(a) => Some(self.avt(a, ctx)?),
                None => None,
            };
            name = self.start_xsl_element(&qname, namespace, ctx)?;
        }
        self.use_attribute_sets(&e.use_sets, ctx)?;
        self.run_body(&e.body, ctx)?;
        self.out().end_element(&name)
    }

    /// `BasisLibrary.startXslElement`.
    fn start_xsl_element(&mut self, qname: &str, namespace: Option<String>, ctx: Ctx) -> EResult<String> {
        match qname.find(':') {
            Some(i) if i > 0 => {
                let prefix = &qname[..i];
                let ns = match namespace.filter(|n| !n.is_empty()) {
                    Some(n) => n,
                    None => {
                        // XSLTC resuelve el prefijo en el nodo de entrada actual.
                        let el = ctx.node.owner();
                        let found = if prefix == "xml" {
                            Some(crate::dom::XML_NS.to_string())
                        } else {
                            self.forest.doc.lookup_namespace(el, Some(prefix))
                        };
                        // Si no está, se busca en las declaraciones de la salida.
                        let found = match found {
                            Some(u) => Some(u),
                            None => self.out().output_namespace(prefix)?,
                        };
                        match found {
                            Some(u) => u,
                            None => {
                                return rt(format!(
                                    "el prefijo de espacio de nombres '{prefix}' no se ha declarado"
                                ));
                            }
                        }
                    }
                };
                self.out().start_element_ns(Some(&ns), qname)?;
                self.out().namespace_after_start_element(Some(prefix), &ns)?;
                Ok(qname.to_string())
            }
            _ => match namespace.filter(|n| !n.is_empty()) {
                Some(ns) => {
                    let prefix = self.generate_prefix();
                    let q = format!("{prefix}:{qname}");
                    self.out().start_element_ns(Some(&ns), &q)?;
                    self.out().namespace_after_start_element(Some(&prefix), &ns)?;
                    Ok(q)
                }
                None => {
                    self.out().start_element_ns(None, qname)?;
                    Ok(qname.to_string())
                }
            },
        }
    }

    fn generate_prefix(&mut self) -> String {
        let n = PREFIX_INDEX.with(|c| {
            let v = c.get();
            c.set(v + 1);
            v
        });
        format!("ns{n}")
    }

    fn xsl_attribute(&mut self, a: &super::compile::XslAttribute, ctx: Ctx) -> EResult<()> {
        if let Some((prefix, ns)) = &a.namespace {
            let uri = self.avt(ns, ctx)?;
            self.out().namespace_after_start_element(Some(prefix), &uri)?;
        }
        let name = self.avt(&a.name, ctx)?;
        if !a.literal {
            check_attrib_qname(&name)?;
        }
        let value = match &a.content {
            Content::Text(t) => t.clone(),
            Content::Instrs(b) => self.string_content(b, ctx)?,
        };
        match a.unique {
            Some(flags) => self.out().add_unique_attribute(&name, &value, flags),
            None => self.out().add_attribute(&name, &value),
        }
    }

    // -- Copias --------------------------------------------------------------------

    fn copy(&mut self, use_sets: &[QName], body: &[Instr], ctx: Ctx) -> EResult<()> {
        let n = ctx.node;
        match n {
            XNode::Node(id) => match self.forest.doc.kind(id).clone() {
                NodeKind::Element(_) => {
                    let name = self.copy_element_start(id)?;
                    self.copy_ns(id, true)?;
                    self.use_attribute_sets(use_sets, ctx)?;
                    self.enter()?;
                    let r = self.run_body(body, ctx);
                    self.depth -= 1;
                    r?;
                    self.out().end_element(&name)
                }
                NodeKind::Document => {
                    self.enter()?;
                    let r = self.run_body(body, ctx);
                    self.depth -= 1;
                    r
                }
                NodeKind::Text { text, .. } => self.out().characters(&text),
                NodeKind::Comment(c) => self.out().comment(&c),
                NodeKind::Pi { target, data } => self.out().processing_instruction(&target, &data),
            },
            XNode::Attr(e, k) => self.copy_attribute(e, k),
            XNode::Ns(..) => self.copy_namespace_node(n),
        }
    }

    fn copy_namespace_node(&mut self, n: XNode) -> EResult<()> {
        let host = self.host(n);
        let ev = Evaluator::with_host(&self.forest.doc, &host);
        if let Some((p, u)) = ev.ns_binding(n) {
            self.out().namespace_after_start_element(Some(&p), &u)?;
        }
        Ok(())
    }

    /// `copyElement`: nombre y espacio de nombres del elemento.
    fn copy_element_start(&mut self, id: NodeId) -> EResult<String> {
        let e = self.forest.doc.element(id).expect("elemento").clone();
        match &e.ns {
            None => {
                self.out().start_element(&e.local)?;
                Ok(e.local.clone())
            }
            Some(uri) => {
                let q = e.qname();
                self.out().start_element(&q)?;
                let prefix = e.prefix.clone().unwrap_or_default();
                self.out().namespace_after_start_element(Some(&prefix), uri)?;
                Ok(q)
            }
        }
    }

    /// `copyNS`: los espacios de nombres en ámbito (`in_scope`) o solo los
    /// declarados en el elemento.
    fn copy_ns(&mut self, id: NodeId, in_scope: bool) -> EResult<()> {
        let doc = &self.forest.doc;
        let list: Vec<XNode> = if in_scope {
            xsltc_namespace_nodes(doc, id)
        } else {
            let e = doc.element(id).expect("elemento");
            let mut v = Vec::new();
            if self.forest.carries_xml_decl(id) {
                v.push(XNode::Ns(id, crate::xpath::XML_DECL));
            }
            for k in 0..e.ns_decls.len() {
                v.push(XNode::Ns(id, k as u32));
            }
            v
        };
        for n in list {
            self.copy_namespace_node(n)?;
        }
        Ok(())
    }

    fn copy_attribute(&mut self, e: NodeId, k: u32) -> EResult<()> {
        let a = self.forest.doc.element(e).expect("elemento").attrs[k as usize].clone();
        let uri = a.ns.clone().unwrap_or_default();
        if !uri.is_empty() {
            let p = a.prefix.clone();
            self.out().namespace_after_start_element(p.as_deref(), &uri)?;
        }
        let name = if a.prefix.is_some() { a.qname() } else { a.local.clone() };
        self.out().add_attribute_ns(&uri, &a.local, &name, &a.value)
    }

    /// `SAXImpl.copy`: copia profunda (`is_child` en las llamadas recursivas).
    fn copy_node(&mut self, n: XNode, is_child: bool) -> EResult<()> {
        self.tick(1)?;
        match n {
            XNode::Node(id) => match self.forest.doc.kind(id).clone() {
                NodeKind::Document => {
                    let children = self.forest.doc.children(id).to_vec();
                    for c in children {
                        self.copy_node(XNode::Node(c), true)?;
                    }
                    Ok(())
                }
                NodeKind::Pi { target, data } => self.out().processing_instruction(&target, &data),
                NodeKind::Comment(c) => self.out().comment(&c),
                NodeKind::Text { text, .. } => self.out().characters(&text),
                NodeKind::Element(e) => {
                    let name = self.copy_element_start(id)?;
                    self.copy_ns(id, !is_child)?;
                    for k in 0..e.attrs.len() {
                        self.copy_attribute(id, k as u32)?;
                    }
                    let children = self.forest.doc.children(id).to_vec();
                    self.enter()?;
                    let r = (|| -> EResult<()> {
                        for c in children {
                            self.copy_node(XNode::Node(c), true)?;
                        }
                        Ok(())
                    })();
                    self.depth -= 1;
                    r?;
                    self.out().end_element(&name)
                }
            },
            XNode::Attr(e, k) => self.copy_attribute(e, k),
            XNode::Ns(..) => self.copy_namespace_node(n),
        }
    }

    // -- Ordenación ------------------------------------------------------------

    fn sort(&mut self, nodes: Vec<XNode>, sorts: &[SortSpec], ctx: Ctx) -> EResult<Vec<XNode>> {
        if sorts.is_empty() || nodes.len() < 2 {
            return Ok(nodes);
        }
        // Parámetros de cada clave (plantillas de valor de atributo evaluadas
        // en el contexto de la instrucción).
        let mut settings = Vec::new();
        for s in sorts {
            let order = self.avt(&s.order, ctx)?;
            let dtype = self.avt(&s.data_type, ctx)?;
            let lang = self.avt(&s.lang, ctx)?;
            let case = self.avt(&s.case_order, ctx)?;
            // `NodeSortRecordFactory` compara longitudes ("descending", "number").
            settings.push((order.chars().count() == 10, dtype.chars().count() == 6, lang, case));
        }
        let size = nodes.len();
        let mut keys: Vec<Vec<SortValue>> = Vec::with_capacity(size);
        for (i, &n) in nodes.iter().enumerate() {
            let c = Ctx {
                node: n,
                position: i + 1,
                size,
            };
            let mut row = Vec::with_capacity(sorts.len());
            for (s, (_, numeric, _, _)) in sorts.iter().zip(&settings) {
                let v = self.eval_str(&s.select, c)?;
                row.push(if *numeric {
                    SortValue::Num(java_parse_double(&v).unwrap_or(f64::NEG_INFINITY))
                } else {
                    SortValue::Str(v)
                });
            }
            keys.push(row);
        }
        let handles: Vec<u32> = nodes.iter().map(|&n| self.forest.handle(n)).collect();
        let mut idx: Vec<usize> = (0..size).collect();
        let mut err = None;
        idx.sort_by(|&a, &b| {
            for (level, (desc, _, lang, case)) in settings.iter().enumerate() {
                let c = match (&keys[a][level], &keys[b][level]) {
                    (SortValue::Num(x), SortValue::Num(y)) => java_double_compare(*x, *y),
                    (SortValue::Str(x), SortValue::Str(y)) => match collate::compare(x, y, lang, case) {
                        Ok(c) => c,
                        Err(e) => {
                            err.get_or_insert(e);
                            Ordering::Equal
                        }
                    },
                    _ => Ordering::Equal,
                };
                if c != Ordering::Equal {
                    return if *desc { c.reverse() } else { c };
                }
            }
            handles[a].cmp(&handles[b])
        });
        if let Some(e) = err {
            return Err(e);
        }
        self.tick(size as u64)?;
        Ok(idx.into_iter().map(|i| nodes[i]).collect())
    }

    // -- xsl:number ------------------------------------------------------------

    fn xsl_number(&mut self, spec: &NumberSpec, ctx: Ctx) -> EResult<()> {
        let format = self.avt(&spec.format, ctx)?;
        let _lang = self.avt(&spec.lang, ctx)?;
        let letter = self.avt(&spec.letter_value, ctx)?;
        let gsep = match &spec.grouping_separator {
            Some(a) => Some(self.avt(a, ctx)?),
            None => None,
        };
        let gsize = match &spec.grouping_size {
            Some(a) => Some(self.avt(a, ctx)?),
            None => None,
        };
        let slot = match spec.level {
            NumberLevel::Single => 0,
            NumberLevel::Multiple => 1,
            NumberLevel::Any => 2,
        };
        if let Some(v) = &spec.value {
            let x = {
                let host = self.host(ctx.node);
                let ev = Evaluator::with_host(&self.forest.doc, &host);
                let val = ev.eval(&v.expr, ctx.xpath()).map_err(|e| XsltError::Runtime(e.0))?;
                // XSLTC redondea con `Math.floor(valor + 0.5)`.
                (ev.to_num(&val) + 0.5).floor()
            };
            // `Integer.MIN_VALUE` es el valor «sin fijar» de `NodeCounter`.
            self.default_counters[slot] = (x != f64::from(i32::MIN)).then_some(x);
        }
        let shared = spec.value.is_some() || (spec.count.is_none() && spec.from.is_none());
        let fixed = if shared { self.default_counters[slot] } else { None };
        let text = match fixed {
            Some(x) => number::format_value(x, &format, &letter, gsep.as_deref(), gsize.as_deref())?,
            None => {
                let counts = self.count_nodes(spec, ctx.node)?;
                number::format_counts(&counts, &format, &letter, gsep.as_deref(), gsize.as_deref())?
            }
        };
        self.out().characters(&text)
    }

    /// Cuenta de `xsl:number` sin `value` (`NodeCounter` de XSLTC). `None`
    /// equivale a `Integer.MIN_VALUE` (nivel sin contar).
    fn count_nodes(&self, spec: &NumberSpec, node: XNode) -> EResult<Vec<Option<i32>>> {
        let host = self.host(node);
        let ev = Evaluator::with_host(&self.forest.doc, &host);
        let doc = &self.forest.doc;
        let default = spec.count.is_none() && spec.from.is_none();
        let matches_count = |n: XNode| -> EResult<bool> {
            match &spec.count {
                Some(p) => p.matches(&ev, n),
                None => Ok(same_type(&ev, n, node)),
            }
        };
        let matches_from = |n: XNode| -> EResult<bool> {
            match &spec.from {
                Some(p) => p.matches(&ev, n),
                None => Ok(false),
            }
        };
        let parent = |n: XNode| -> Option<XNode> {
            match n {
                XNode::Node(id) => doc.parent(id).map(XNode::Node),
                XNode::Attr(e, _) | XNode::Ns(e, _) => Some(XNode::Node(e)),
            }
        };
        let preceding_siblings = |n: XNode| -> Vec<XNode> {
            match n {
                XNode::Node(id) => match doc.parent(id) {
                    Some(p) => doc
                        .children(p)
                        .iter()
                        .take_while(|&&s| s != id)
                        .map(|&s| XNode::Node(s))
                        .collect(),
                    None => vec![],
                },
                _ => vec![],
            }
        };
        match spec.level {
            NumberLevel::Single => {
                if default {
                    // Hermanos anteriores del mismo tipo, más el propio nodo.
                    let mut c = 1;
                    for s in preceding_siblings(node) {
                        self.tick(1)?;
                        if same_type(&ev, s, node) {
                            c += 1;
                        }
                    }
                    return Ok(vec![Some(c)]);
                }
                let node_matches = matches_count(node)?;
                let mut next = Some(node);
                if !node_matches {
                    loop {
                        next = next.and_then(parent);
                        let Some(n) = next else { break };
                        if matches_count(n)? {
                            break;
                        }
                        if matches_from(n)? {
                            next = None;
                            break;
                        }
                    }
                }
                let Some(target) = next else { return Ok(vec![]) };
                if !node_matches && spec.from.is_some() {
                    let mut from = Some(target);
                    loop {
                        from = from.and_then(parent);
                        let Some(f) = from else { break };
                        if matches_from(f)? {
                            break;
                        }
                    }
                    if from.is_none() {
                        return Ok(vec![]);
                    }
                }
                let mut c = i32::from(matches_count(target)?);
                for s in preceding_siblings(target) {
                    self.tick(1)?;
                    if matches_count(s)? {
                        c += 1;
                    }
                }
                Ok(vec![Some(c)])
            }
            NumberLevel::Multiple => {
                let mut ancestors = vec![node];
                let mut next = parent(node);
                while let Some(n) = next {
                    if matches_from(n)? {
                        break;
                    }
                    ancestors.push(n);
                    next = parent(n);
                }
                let mut out = Vec::with_capacity(ancestors.len());
                for &a in ancestors.iter().rev() {
                    if matches_count(a)? {
                        let mut c = 1;
                        for s in preceding_siblings(a) {
                            self.tick(1)?;
                            if matches_count(s)? {
                                c += 1;
                            }
                        }
                        out.push(Some(c));
                    } else {
                        out.push(None);
                    }
                }
                Ok(out)
            }
            NumberLevel::Any => {
                // Nodos en orden inverso del DTM (incluidos atributos y
                // antecesores) hasta la raíz o el primero que cumple `from`.
                let root = doc.tree_root(node.owner());
                let order = node.order_key();
                let mut candidates: Vec<XNode> = Vec::new();
                for i in root.0..doc.subtree_end(root) {
                    let id = NodeId(i);
                    candidates.push(XNode::Node(id));
                    if let Some(e) = doc.element(id) {
                        for k in 0..e.attrs.len() {
                            candidates.push(XNode::Attr(id, k as u32));
                        }
                    }
                }
                let mut count = 0i32;
                for n in candidates.into_iter().rev() {
                    if n.order_key() > order {
                        continue;
                    }
                    self.tick(1)?;
                    if matches_from(n)? {
                        break;
                    }
                    if matches_count(n)? {
                        count += 1;
                    }
                }
                Ok(vec![Some(count)])
            }
        }
    }
}

thread_local! {
    /// `BasisLibrary.threadLocalPrefixIndex` (se reinicia en cada transformación).
    static PREFIX_INDEX: Cell<u32> = const { Cell::new(0) };
}

/// Mismo tipo y nombre expandido (la cuenta por defecto de `xsl:number`).
fn same_type(ev: &Evaluator<'_>, a: XNode, b: XNode) -> bool {
    let kind = |n: XNode| -> u8 {
        match n {
            XNode::Node(id) => match ev.doc.kind(id) {
                NodeKind::Document => 0,
                NodeKind::Element(_) => 1,
                NodeKind::Text { .. } => 3,
                NodeKind::Comment(_) => 4,
                NodeKind::Pi { .. } => 5,
            },
            XNode::Attr(..) => 2,
            XNode::Ns(..) => 6,
        }
    };
    if kind(a) != kind(b) {
        return false;
    }
    let (_, la, na) = ev.node_name(a);
    let (_, lb, nb) = ev.node_name(b);
    la == lb && na == nb
}

#[derive(Debug, Clone)]
enum SortValue {
    Num(f64),
    Str(String),
}

/// `Double.parseDouble` (error si la cadena no es un número de Java).
fn java_parse_double(s: &str) -> Option<f64> {
    let v = crate::xpath::java_string_to_double(s);
    if v.is_nan() {
        let t = s.trim_matches(|c: char| c <= ' ');
        let t = t.strip_prefix(['+', '-']).unwrap_or(t);
        if t == "NaN" { Some(f64::NAN) } else { None }
    } else {
        Some(v)
    }
}

/// `Double.compareTo`: -0.0 < 0.0 y NaN mayor que todo.
fn java_double_compare(a: f64, b: f64) -> Ordering {
    match (a.is_nan(), b.is_nan()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        _ => a.total_cmp(&b),
    }
}

/// `BasisLibrary.checkAttribQName`.
fn check_attrib_qname(name: &str) -> EResult<()> {
    let first = name.find(':');
    let last = name.rfind(':');
    let local = match last {
        Some(l) => &name[l + 1..],
        None => name,
    };
    if let (Some(f), Some(l)) = (first, last)
        && f > 0
    {
        let prefix = &name[..f];
        if f != l {
            let ori = &name[f + 1..l];
            if !is_ncname(ori) {
                return rt(format!("nombre no válido: {ori}:{local}"));
            }
        }
        if !is_ncname(prefix) {
            return rt(format!("nombre no válido: {prefix}:{local}"));
        }
    }
    if !is_ncname(local) || local == "xmlns" {
        return rt(format!("nombre no válido: {local}"));
    }
    Ok(())
}

/// Crea el serializador de salida como `TransletOutputHandlerFactory` y le
/// transfiere los parámetros de `xsl:output` (`transferOutputSettings`).
fn make_output(o: &OutputSettings, max: usize) -> Box<dyn OutputHandler> {
    let requested = o.encoding.clone().unwrap_or_else(|| "UTF-8".into());
    let enc = OutEncoding::resolve(&requested).unwrap_or_else(OutEncoding::utf8);
    match o.method.as_deref() {
        Some("xml") => {
            let mut s = Stream::new(Method::Xml, enc, max);
            s.set_standalone(o.standalone.as_deref());
            s.set_omit_xml_declaration(o.omit_xml_declaration);
            s.set_cdata_section_elements(&o.cdata);
            s.set_version(o.version.as_deref());
            s.set_indent(o.indent);
            if let Some(a) = o.indent_amount
                && a >= 0
            {
                s.set_indent_amount(a);
            }
            if o.doctype_system.is_some() {
                s.set_doctype(o.doctype_system.as_deref(), o.doctype_public.as_deref());
            }
            Box::new(s)
        }
        Some("html") => {
            let mut s = Stream::new(Method::Html, enc, max);
            s.set_indent(o.indent);
            s.set_doctype(o.doctype_system.as_deref(), o.doctype_public.as_deref());
            s.set_media_type(o.media_type.as_deref());
            Box::new(s)
        }
        Some("text") => Box::new(Stream::new(Method::Text, enc, max)),
        Some(_) => {
            // Método con nombre cualificado: XSLTC no crea serializador de flujo.
            Box::new(Stream::new(Method::Xml, enc, max))
        }
        None => {
            let mut u = Unknown::new(Stream::new(Method::Xml, enc, max));
            let s = u.stream_mut();
            s.set_cdata_section_elements(&o.cdata);
            s.set_version(o.version.as_deref());
            s.set_standalone(o.standalone.as_deref());
            s.set_omit_xml_declaration(o.omit_xml_declaration);
            s.set_indent(o.indent);
            s.set_doctype(o.doctype_system.as_deref(), o.doctype_public.as_deref());
            Box::new(u)
        }
    }
}

/// Ejecuta la hoja sobre el documento de entrada y devuelve los octetos.
pub(crate) fn run(sheet: &Stylesheet, source: Source, limits: &Limits) -> Result<Vec<u8>, XsltError> {
    PREFIX_INDEX.with(|c| c.set(0));
    let out = make_output(&sheet.output, limits.max_output);
    let mut ex = Exec {
        sheet,
        forest: source.forest,
        sinks: vec![Sink::Out(out)],
        locals: Vec::new(),
        frame_base: 0,
        globals: RefCell::new(vec![GlobalState::Pending; sheet.globals.len()]),
        keys: RefCell::new(HashMap::new()),
        formatters: RefCell::new(HashMap::new()),
        default_counters: [None; 3],
        steps: Cell::new(0),
        limits: *limits,
        depth: 0,
    };
    let root = ex.root_ctx();
    // Globales con contenido (fragmentos), en orden de documento; después,
    // las de `select` referenciadas y todos los parámetros.
    for k in 0..sheet.globals.len() {
        let decl = &sheet.vars[sheet.globals[k]];
        if !(decl.referenced.get() || decl.is_param) {
            continue;
        }
        let value = match &decl.value {
            VarValue::Content(body) => {
                ex.globals.borrow_mut()[k] = GlobalState::Evaluating;
                let v = ex.build_rtf(body, root)?;
                Some(v)
            }
            VarValue::Empty => Some(Value::Str(String::new())),
            VarValue::Select(_) => None,
        };
        if let Some(v) = value {
            ex.globals.borrow_mut()[k] = GlobalState::Done(v);
        }
    }
    for k in 0..sheet.globals.len() {
        let decl = &sheet.vars[sheet.globals[k]];
        if (decl.referenced.get() || decl.is_param) && matches!(decl.value, VarValue::Select(_)) {
            ex.global_value(&decl.name)?;
        }
    }
    ex.out().start_document()?;
    ex.apply_templates(vec![XNode::Node(ex.forest.source_root)], &None, vec![])?;
    ex.out().end_document()?;
    let Some(Sink::Out(h)) = ex.sinks.pop() else {
        unreachable!("salida principal")
    };
    let _ = (PI_DISABLE_ESCAPING, PI_ENABLE_ESCAPING);
    Ok(h.finish())
}
