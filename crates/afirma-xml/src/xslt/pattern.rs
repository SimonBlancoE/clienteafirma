//! Patrones de XSLT (`match`, `count`, `from`, `xsl:key`).
//!
//! Se analizan con la gramática de XPath y se comprueban de derecha a
//! izquierda. La prioridad por defecto sigue a XSLTC, que en una unión asigna
//! a todas las alternativas la menor de sus prioridades.

use std::collections::HashMap;

use super::XsltError;
use crate::xpath::{Axis, Context, Evaluator, Expr, NodeTest, PathStart, Step, Value, XNode, XPath};

/// Paso de un patrón.
#[derive(Clone, Debug)]
pub(crate) struct PStep {
    pub axis: Axis,
    pub test: NodeTest,
    pub preds: Vec<Expr>,
    /// Separador anterior `//` (cualquier ancestro) en lugar de `/` (padre).
    pub descendant: bool,
}

/// Inicio de un patrón de ruta.
#[derive(Clone, Debug)]
pub(crate) enum Start {
    /// Relativo: el paso más a la izquierda puede tener cualquier padre.
    Relative,
    /// `/...`: el primer paso cuelga de la raíz.
    Root,
    /// `id(...)` o `key(...)`: llamada con argumentos literales.
    Call(Expr),
}

/// Alternativa de un patrón.
#[derive(Clone, Debug)]
pub(crate) struct PathPattern {
    pub start: Start,
    pub steps: Vec<PStep>,
}

/// Patrón compilado.
#[derive(Clone, Debug)]
pub(crate) struct Pattern {
    pub alts: Vec<PathPattern>,
}

impl PathPattern {
    /// Prioridad por defecto de XSLTC (`StepPattern.getDefaultPriority`).
    pub(crate) fn default_priority(&self) -> f64 {
        if !matches!(self.start, Start::Relative) || self.steps.len() != 1 {
            return 0.5;
        }
        let s = &self.steps[0];
        if s.descendant {
            return 0.5;
        }
        if !s.preds.is_empty() {
            return 0.5;
        }
        match &s.test {
            NodeTest::Name(..) => 0.0,
            NodeTest::NsWildcard(_) => -0.25,
            NodeTest::Pi(Some(_)) => 0.0,
            NodeTest::Any | NodeTest::Node | NodeTest::Text | NodeTest::Comment | NodeTest::Pi(None) => -0.5,
        }
    }
}

impl Pattern {
    /// Prioridad por defecto del patrón completo (la menor de las alternativas).
    pub(crate) fn priority(&self) -> f64 {
        self.alts
            .iter()
            .map(PathPattern::default_priority)
            .fold(f64::INFINITY, |a, b| if b < a { b } else { a })
    }

    /// Analiza un patrón.
    pub(crate) fn parse(text: &str, ns: &HashMap<String, String>) -> Result<Pattern, XsltError> {
        let xp = XPath::compile(text, ns).map_err(|e| XsltError::Compile(format!("patrón '{text}': {e}")))?;
        let mut alts = Vec::new();
        collect(&xp.expr, &mut alts).map_err(|m| XsltError::Compile(format!("patrón '{text}' no válido: {m}")))?;
        Ok(Pattern { alts })
    }

    /// Indica si el nodo cumple el patrón.
    pub(crate) fn matches(&self, ev: &Evaluator<'_>, n: XNode) -> Result<bool, XsltError> {
        for alt in &self.alts {
            if alt.matches(ev, n)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn collect(e: &Expr, out: &mut Vec<PathPattern>) -> Result<(), String> {
    match e {
        Expr::Bin(crate::xpath::BinOp::Union, l, r) => {
            collect(l, out)?;
            collect(r, out)
        }
        Expr::Path(PathStart::Root, steps) => {
            if steps.is_empty() {
                out.push(PathPattern {
                    start: Start::Root,
                    steps: vec![],
                });
                return Ok(());
            }
            out.push(PathPattern {
                start: Start::Root,
                steps: convert_steps(steps)?,
            });
            Ok(())
        }
        Expr::Path(PathStart::Context, steps) => {
            out.push(PathPattern {
                start: Start::Relative,
                steps: convert_steps(steps)?,
            });
            Ok(())
        }
        Expr::Path(PathStart::Expr(base), steps) => {
            check_id_key(base)?;
            out.push(PathPattern {
                start: Start::Call((**base).clone()),
                steps: convert_steps(steps)?,
            });
            Ok(())
        }
        Expr::Call(..) => {
            check_id_key(e)?;
            out.push(PathPattern {
                start: Start::Call(e.clone()),
                steps: vec![],
            });
            Ok(())
        }
        _ => Err("se esperaba una ruta de localización".into()),
    }
}

fn check_id_key(e: &Expr) -> Result<(), String> {
    match e {
        Expr::Call(None, name, args) if name == "id" && args.len() == 1 => match &args[0] {
            Expr::Literal(_) | Expr::Var(..) => Ok(()),
            _ => Err("id() requiere un literal".into()),
        },
        Expr::Call(None, name, args) if name == "key" && args.len() == 2 => {
            if matches!(args[0], Expr::Literal(_)) && matches!(args[1], Expr::Literal(_) | Expr::Var(..)) {
                Ok(())
            } else {
                Err("key() requiere literales".into())
            }
        }
        _ => Err("solo se admiten id() y key() al inicio de un patrón".into()),
    }
}

fn convert_steps(steps: &[Step]) -> Result<Vec<PStep>, String> {
    let mut out = Vec::new();
    let mut descendant = false;
    for (i, s) in steps.iter().enumerate() {
        if s.axis == Axis::DescendantOrSelf && s.test == NodeTest::Node && s.preds.is_empty() && i + 1 < steps.len() {
            descendant = true;
            continue;
        }
        if !matches!(s.axis, Axis::Child | Axis::Attribute) {
            return Err("solo se admiten los ejes child y attribute".into());
        }
        out.push(PStep {
            axis: s.axis,
            test: s.test.clone(),
            preds: s.preds.clone(),
            descendant: std::mem::take(&mut descendant),
        });
    }
    if out.is_empty() {
        return Err("patrón vacío".into());
    }
    Ok(out)
}

impl PathPattern {
    pub(crate) fn matches(&self, ev: &Evaluator<'_>, n: XNode) -> Result<bool, XsltError> {
        self.match_from(ev, n, self.steps.len())
    }

    /// Comprueba los pasos `0..k` con el último sobre `n`.
    fn match_from(&self, ev: &Evaluator<'_>, n: XNode, k: usize) -> Result<bool, XsltError> {
        if k == 0 {
            return self.match_start(ev, n);
        }
        let step = &self.steps[k - 1];
        if !step_matches(ev, step, n)? {
            return Ok(false);
        }
        let parent = parent_of(ev, n);
        if k == 1 {
            return match &self.start {
                Start::Relative => {
                    // Un paso hijo necesita padre; el de atributo, su elemento.
                    Ok(parent.is_some())
                }
                Start::Root | Start::Call(_) => {
                    let Some(p) = parent else { return Ok(false) };
                    if step.descendant {
                        let mut cur = Some(p);
                        while let Some(c) = cur {
                            if self.match_start(ev, c)? {
                                return Ok(true);
                            }
                            cur = parent_of(ev, c);
                        }
                        Ok(false)
                    } else {
                        self.match_start(ev, p)
                    }
                }
            };
        }
        let Some(p) = parent else { return Ok(false) };
        if step.descendant {
            let mut cur = Some(p);
            while let Some(c) = cur {
                if self.match_from(ev, c, k - 1)? {
                    return Ok(true);
                }
                cur = parent_of(ev, c);
            }
            Ok(false)
        } else {
            self.match_from(ev, p, k - 1)
        }
    }

    fn match_start(&self, ev: &Evaluator<'_>, n: XNode) -> Result<bool, XsltError> {
        match &self.start {
            Start::Relative => Ok(true),
            Start::Root => Ok(matches!(n, XNode::Node(id) if ev.doc.parent(id).is_none())),
            Start::Call(e) => {
                let v = ev
                    .eval(e, Context::of(n))
                    .map_err(|e| XsltError::Runtime(e.to_string()))?;
                match v {
                    Value::Nodes(set) => Ok(set.contains(&n)),
                    _ => Ok(false),
                }
            }
        }
    }
}

fn parent_of(ev: &Evaluator<'_>, n: XNode) -> Option<XNode> {
    match n {
        XNode::Node(id) => ev.doc.parent(id).map(XNode::Node),
        XNode::Attr(e, _) | XNode::Ns(e, _) => Some(XNode::Node(e)),
    }
}

/// Comprueba un paso (tipo de nodo, prueba y predicados con la posición
/// entre los hermanos que cumplen la prueba).
fn step_matches(ev: &Evaluator<'_>, step: &PStep, n: XNode) -> Result<bool, XsltError> {
    let on_axis = match (step.axis, n) {
        (Axis::Attribute, XNode::Attr(..)) => true,
        (Axis::Child, XNode::Node(id)) => ev.doc.parent(id).is_some(),
        _ => false,
    };
    if !on_axis || !ev.matches(&step.test, step.axis, n) {
        return Ok(false);
    }
    if step.preds.is_empty() {
        return Ok(true);
    }
    let Some(parent) = parent_of(ev, n) else {
        return Ok(false);
    };
    let mut candidates: Vec<XNode> = ev
        .axis_nodes(step.axis, parent)
        .into_iter()
        .filter(|c| ev.matches(&step.test, step.axis, *c))
        .collect();
    for p in &step.preds {
        candidates = ev
            .apply_predicate(candidates, p)
            .map_err(|e| XsltError::Runtime(e.to_string()))?;
        if !candidates.contains(&n) {
            return Ok(false);
        }
    }
    Ok(candidates.contains(&n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priorities() {
        let ns: HashMap<String, String> = [("p".to_string(), "urn:p".to_string())].into_iter().collect();
        let pr = |t: &str| Pattern::parse(t, &ns).unwrap().priority();
        assert_eq!(pr("a"), 0.0);
        assert_eq!(pr("p:a"), 0.0);
        assert_eq!(pr("p:*"), -0.25);
        assert_eq!(pr("*"), -0.5);
        assert_eq!(pr("@*"), -0.5);
        assert_eq!(pr("node()"), -0.5);
        assert_eq!(pr("processing-instruction('x')"), 0.0);
        assert_eq!(pr("a[1]"), 0.5);
        assert_eq!(pr("a/b"), 0.5);
        assert_eq!(pr("//a"), 0.5);
        assert_eq!(pr("/"), 0.5);
        assert_eq!(pr("a[1] | a"), 0.0);
        assert!(Pattern::parse("ancestor::a", &ns).is_err());
        assert!(Pattern::parse("count(a)", &ns).is_err());
    }
}
