//! Filtros de búsqueda RFC 2254 sobre nombres X.500, reproduciendo
//! `es.gob.afirma.keystores.filters.rfc.SearchFilter` y
//! `RFC2254CertificateFilter` de Java con todas sus particularidades:
//!
//! - si el filtro no empieza por `(` se rodea de paréntesis (pero si empieza
//!   por espacios, la posición de lectura queda tras ellos y el análisis
//!   falla);
//! - `&`, `|`, `!`, `=` (con comodines `*`), `~=` (igual que `=`), `>=` y
//!   `<=` (comparación lexicográfica sensible a mayúsculas), presencia
//!   `attr=*`; `:=` es un error;
//! - el valor llega hasta el siguiente `)` sin decodificar escapes `\XX`;
//! - en las subcadenas con comodín, si el patrón no empieza por `*` el primer
//!   trozo se comprueba con "empieza por" pero la búsqueda de los siguientes
//!   vuelve a empezar en la posición 0 (`ab*b` acepta `ab`);
//! - un nombre sin atributos no cumple el filtro; un filtro que no se puede
//!   analizar deja pasar el certificado (falla en abierto).

use crate::dn::{DistinguishedName, LdapValue, java_lower, java_trim};

/// Error de análisis del filtro (en Java, `InvalidSearchFilterException` o
/// cualquier excepción del análisis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchFilterError(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchType {
    Equal,
    Approx,
    Greater,
    Less,
}

/// Nodo del filtro.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Atomic { attr: String, value: String, kind: MatchType },
}

/// Filtro RFC 2254 analizado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchFilter {
    root: Node,
}

/// `Character.isWhitespace` de Java.
fn java_is_whitespace(c: char) -> bool {
    match c {
        '\u{0009}'..='\u{000D}' | '\u{001C}'..='\u{001F}' => true,
        '\u{00A0}' | '\u{2007}' | '\u{202F}' => false,
        '\u{0085}' => false,
        c => c.is_whitespace(),
    }
}

struct Parser {
    f: Vec<char>,
    pos: usize,
}

type PResult<T> = Result<T, SearchFilterError>;

fn err(msg: impl Into<String>) -> SearchFilterError {
    SearchFilterError(msg.into())
}

impl Parser {
    fn cur(&self) -> PResult<char> {
        self.f.get(self.pos).copied().ok_or_else(|| err(format!("fin inesperado del filtro en la posicion {}", self.pos)))
    }

    fn skip_ws(&mut self) -> PResult<()> {
        while java_is_whitespace(self.cur()?) {
            self.pos += 1;
        }
        Ok(())
    }

    /// `relIndexOf`: índice relativo a `pos` de la primera aparición, o
    /// `-1 - pos` si no aparece.
    fn rel_index_of(&self, ch: char) -> isize {
        match self.f.iter().skip(self.pos).position(|&c| c == ch) {
            Some(i) => i as isize,
            None => -1 - self.pos as isize,
        }
    }

    fn rel_char_at(&self, i: isize) -> PResult<char> {
        let idx = self.pos as isize + i;
        if idx < 0 {
            return Err(err("indice negativo"));
        }
        self.f.get(idx as usize).copied().ok_or_else(|| err("indice fuera de rango"))
    }

    fn rel_substring(&self, b: isize, e: isize) -> PResult<String> {
        let (b, e) = (self.pos as isize + b, self.pos as isize + e);
        if b < 0 || e < b || e as usize > self.f.len() {
            return Err(err("subcadena fuera de rango"));
        }
        Ok(self.f[b as usize..e as usize].iter().collect())
    }

    fn create_next_filter(&mut self) -> PResult<Node> {
        self.skip_ws()?;
        if self.cur()? != '(' {
            return Err(err(format!("expected \"(\" at position {}", self.pos)));
        }
        self.pos += 1;
        self.skip_ws()?;
        let node = match self.cur()? {
            '&' => Node::And(self.parse_compound()?),
            '|' => Node::Or(self.parse_compound()?),
            '!' => {
                self.pos += 1;
                Node::Not(Box::new(self.create_next_filter()?))
            }
            _ => self.parse_atomic()?,
        };
        self.skip_ws()?;
        if self.cur()? != ')' {
            return Err(err(format!("expected \")\" at position {}", self.pos)));
        }
        self.pos += 1;
        Ok(node)
    }

    fn parse_compound(&mut self) -> PResult<Vec<Node>> {
        self.pos += 1;
        let mut subs = Vec::new();
        while self.cur()? != ')' {
            subs.push(self.create_next_filter()?);
            self.skip_ws()?;
        }
        Ok(subs)
    }

    fn parse_atomic(&mut self) -> PResult<Node> {
        self.skip_ws()?;
        let end_pos = self.rel_index_of(')');
        let i = self.rel_index_of('=');
        let qualifier = self.rel_char_at(i - 1)?;
        let (kind, attr, value) = match qualifier {
            '~' => (MatchType::Approx, self.rel_substring(0, i - 1)?, self.rel_substring(i + 1, end_pos)?),
            '>' => (MatchType::Greater, self.rel_substring(0, i - 1)?, self.rel_substring(i + 1, end_pos)?),
            '<' => (MatchType::Less, self.rel_substring(0, i - 1)?, self.rel_substring(i + 1, end_pos)?),
            ':' => return Err(err("Extensible match not supported")),
            _ => (MatchType::Equal, self.rel_substring(0, i)?, self.rel_substring(i + 1, end_pos)?),
        };
        if end_pos < 0 {
            return Err(err("falta \")\""));
        }
        self.pos = (self.pos as isize + end_pos) as usize;
        Ok(Node::Atomic { attr: java_trim(&attr), value: java_trim(&value), kind })
    }
}

impl SearchFilter {
    /// Analiza un filtro como el constructor de `SearchFilter`.
    pub fn parse(filter: &str) -> Result<SearchFilter, SearchFilterError> {
        let mut p = Parser { f: filter.chars().collect(), pos: 0 };
        // normalizeFilter(): la posición queda tras los espacios iniciales.
        p.skip_ws()?;
        if p.cur()? != '(' {
            let mut f = vec!['('];
            f.extend(filter.chars());
            f.push(')');
            p.f = f;
        }
        let root = p.create_next_filter()?;
        Ok(SearchFilter { root })
    }

    /// Evalúa el filtro sobre los atributos de un nombre (ver
    /// [`DistinguishedName::ldap_attributes`]).
    pub fn check(&self, attrs: &[(String, LdapValue)]) -> bool {
        check_node(&self.root, attrs)
    }
}

fn check_node(node: &Node, attrs: &[(String, LdapValue)]) -> bool {
    match node {
        Node::And(subs) => subs.iter().all(|s| check_node(s, attrs)),
        Node::Or(subs) => subs.iter().any(|s| check_node(s, attrs)),
        Node::Not(n) => !check_node(n, attrs),
        Node::Atomic { attr, value, kind } => {
            let attr_l = attr.to_lowercase();
            let Some((_, v)) = attrs.iter().find(|(t, _)| t.to_lowercase() == attr_l) else {
                return false;
            };
            // En Java un valor binario es un byte[] cuyo toString() es
            // "[B@<hash>".
            let val: &str = match v {
                LdapValue::Text(s) => s,
                LdapValue::Binary(_) => "[B@",
            };
            match kind {
                MatchType::Equal | MatchType::Approx => substring_match(value, val),
                MatchType::Greater => java_compare(val, value) != std::cmp::Ordering::Less,
                MatchType::Less => java_compare(val, value) != std::cmp::Ordering::Greater,
            }
        }
    }
}

/// `String.compareTo` (unidades UTF-16).
fn java_compare(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `AtomicFilter.substringMatch` de Java, con su particularidad.
fn substring_match(proto: &str, val: &str) -> bool {
    if proto == "*" {
        return true;
    }
    if !proto.contains('*') {
        return java_equals_ignore_case(proto, val);
    }
    let lval: Vec<char> = java_lower(val).chars().collect();
    let mut tokens = proto.split('*').filter(|t| !t.is_empty());
    let mut current_pos = 0usize;
    if !proto.starts_with('*') {
        let first: Vec<char> = tokens.next().map(|t| java_lower(t).chars().collect()).unwrap_or_default();
        if !lval.starts_with(&first) {
            return false;
        }
    }
    for tok in tokens {
        let t: Vec<char> = java_lower(tok).chars().collect();
        match (current_pos..=lval.len().saturating_sub(t.len())).find(|&i| lval.len() >= t.len() && lval[i..].starts_with(&t)) {
            Some(p) => current_pos = p + t.len(),
            None => return false,
        }
    }
    if !proto.ends_with('*') && current_pos != val.chars().count() {
        return false;
    }
    true
}

/// `String.equalsIgnoreCase`.
fn java_equals_ignore_case(a: &str, b: &str) -> bool {
    a.chars().count() == b.chars().count() && crate::dn::java_compare_ignore_case(a, b) == std::cmp::Ordering::Equal
}

/// Filtro sobre el titular o el emisor (`RFC2254CertificateFilter` sobre
/// un nombre): `true` si cumple el filtro o si el filtro no se puede
/// analizar; `false` si el nombre está vacío.
pub fn filter_name(filter: &Result<SearchFilter, SearchFilterError>, name: &DistinguishedName) -> bool {
    if name.is_empty() {
        return false;
    }
    match filter {
        Ok(f) => f.check(&name.ldap_attributes()),
        Err(e) => {
            tracing::warn!("No ha sido posible filtrar el certificado, no se eliminara del listado: {}", e.0);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> Vec<(String, LdapValue)> {
        pairs.iter().map(|(t, v)| (t.to_string(), LdapValue::Text(v.to_string()))).collect()
    }

    fn check(f: &str, a: &[(String, LdapValue)]) -> Option<bool> {
        SearchFilter::parse(f).ok().map(|f| f.check(a))
    }

    #[test]
    fn basic_operators() {
        let a = attrs(&[("CN", "AC DNIE 004"), ("OU", "DNIE"), ("O", "DIRECCION GENERAL DE LA POLICIA"), ("C", "ES")]);
        assert_eq!(check("(&(cn=AC DNIE *)(ou=DNIE)(o=DIRECCION GENERAL DE LA POLICIA)(c=ES))", &a), Some(true));
        assert_eq!(check("(&(cn=AC DNIE *)(ou=CNP))", &a), Some(false));
        assert_eq!(check("(|(o=FNMT-RCM)(o=direccion general de la policia))", &a), Some(true));
        assert_eq!(check("(!(c=ES))", &a), Some(false));
        assert_eq!(check("cn=ac dnie*", &a), Some(true));
        assert_eq!(check("(cn=*)", &a), Some(true));
        assert_eq!(check("(l=*)", &a), Some(false));
        assert_eq!(check("(c~=es)", &a), Some(true));
        assert_eq!(check("(c>=ER)", &a), Some(true));
        assert_eq!(check("(c<=ER)", &a), Some(false));
        // Comparación sensible a mayúsculas.
        assert_eq!(check("(c>=es)", &a), Some(false));
        assert_eq!(check("(&)", &a), Some(true));
        assert_eq!(check("(|)", &a), Some(false));
        assert_eq!(check("( & ( cn = AC DNIE 004 ) )", &a), Some(true));
    }

    #[test]
    fn wildcard_quirks() {
        assert!(substring_match("ab*b", "ab"));
        assert!(substring_match("*b*", "abc"));
        assert!(!substring_match("*b", "abc"));
        assert!(substring_match("a*c", "ABC"));
        assert!(!substring_match("a*c", "abcd"));
        assert!(substring_match("**", "x"));
        assert!(substring_match("a**", "a"));
        assert!(!substring_match("b*", "ab"));
        assert!(substring_match("*a*b*c*", "xaxbxc"));
        assert!(!substring_match("*c*b*", "abc"));
        assert!(substring_match("abc", "ABC"));
    }

    #[test]
    fn parse_errors() {
        assert!(SearchFilter::parse("(cn:=x)").is_err());
        assert!(SearchFilter::parse("(cn=x").is_err());
        assert!(SearchFilter::parse("").is_err());
        assert!(SearchFilter::parse("   ").is_err());
        // Espacios iniciales sin paréntesis: Java envuelve pero no
        // reposiciona y falla.
        assert!(SearchFilter::parse("  cn=x").is_err());
        assert!(SearchFilter::parse("(cn)(o=x)").is_err());
        assert!(SearchFilter::parse("(& )").is_err());
        // Basura al final: se ignora.
        assert!(SearchFilter::parse("(cn=x)basura").is_ok());
        // Sin '=': error.
        assert!(SearchFilter::parse("(cn)").is_err());
    }

    #[test]
    fn binary_values_and_missing() {
        let a = vec![("ST".to_string(), LdapValue::Binary(vec![0x1a, 0x01, 0x41])), ("CN".to_string(), LdapValue::Text("x".into()))];
        assert_eq!(check("(st=*)", &a), Some(true));
        assert_eq!(check("(st=A)", &a), Some(false));
        assert_eq!(check("(=x)", &a), Some(false));
        let empty = DistinguishedName::default();
        assert!(!filter_name(&SearchFilter::parse("(cn=*)"), &empty));
        let name = DistinguishedName { rdns: vec![] };
        assert!(!filter_name(&SearchFilter::parse("roto("), &name));
    }
}
