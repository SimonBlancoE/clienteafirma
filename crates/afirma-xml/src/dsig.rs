//! Núcleo XMLDSig: modelo de proceso de referencias (desreferencia de URI,
//! transformadas, huellas), canonicalización de `SignedInfo`, generación de
//! los elementos de firma como texto y compleción de firmas (cálculo de
//! huellas y del `SignatureValue` sobre el documento final).
//!
//! La firma se construye como texto insertado en el documento con marcadores
//! en los `DigestValue` y el `SignatureValue`; después se analiza el
//! documento resultante y se calculan los valores sobre él con el mismo código
//! que usa la validación, de modo que lo firmado es exactamente lo que se
//! entrega.

use std::collections::HashMap;
use std::rc::Rc;

use afirma_core::algorithms::{DigestAlgorithm, SignatureAlgorithm};
use afirma_core::error::{AfirmaError, ErrorCode, codes};
use afirma_core::key::SigningKey;

use crate::c14n::{C14n, Kind, NodeSet};
use crate::crypto::{self, PublicKey};
use crate::dom::{Document, NodeId, NodeKind};
use crate::util::{b64, esc_attr, esc_text};
use crate::xpath::{XNode, XPath};

pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const DSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
pub const OBJECT_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Object";
pub const MANIFEST_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Manifest";
pub const BASE64: &str = "http://www.w3.org/2000/09/xmldsig#base64";
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
pub const XPATH2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
pub const XSLT: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
pub const RELATIONSHIP_TRANSFORM: &str = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
pub const MDSSI_NS: &str = "http://schemas.openxmlformats.org/package/2006/digital-signature";
pub const OPC_RELS_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const EXC_C14N_NS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Error del motor XMLDSig.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DsigError {
    /// Estructura de firma incorrecta (equivale a `XMLSignatureException`/`MarshalException`).
    #[error("firma XML mal formada: {0}")]
    Malformed(String),
    /// Algoritmo o transformada no soportados.
    #[error("algoritmo no soportado: {0}")]
    Unsupported(String),
    /// No se puede obtener el contenido referenciado.
    #[error("no se puede desreferenciar '{0}'")]
    Dereference(String),
    /// Error al procesar las transformadas de una referencia.
    #[error("error al procesar una referencia: {0}")]
    Processing(String),
    /// No se ha encontrado la clave de verificación.
    #[error("No se ha encontrado la clave publica dentro del XML firmado")]
    KeyNotFound,
}

type DResult<T> = std::result::Result<T, DsigError>;

/// Algoritmo de huella a partir de su URI XMLDSig.
pub fn digest_from_uri(uri: &str) -> Option<DigestAlgorithm> {
    DigestAlgorithm::from_xml_uri(uri)
}

/// Algoritmo de firma a partir de su URI XMLDSig.
pub fn signature_from_uri(uri: &str) -> Option<SignatureAlgorithm> {
    SignatureAlgorithm::from_xml_uri(uri)
}

/// Contenido externo resuelto por un [`Resolver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum External {
    /// Octetos tal cual.
    Octets(Vec<u8>),
    /// XML que se analiza y se trata como conjunto de nodos (como hace
    /// `CustomUriDereferencer` con las URL http/https).
    Xml(Vec<u8>),
}

/// Resolución de URI externas de las referencias.
pub trait Resolver {
    fn resolve(&self, uri: &str) -> Option<External>;
}

impl<F: Fn(&str) -> Option<External>> Resolver for F {
    fn resolve(&self, uri: &str) -> Option<External> {
        self(uri)
    }
}

/// Resolutor que no resuelve nada.
pub struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(&self, _uri: &str) -> Option<External> {
        None
    }
}

/// Busca un elemento por un atributo cuyo nombre sea `Id` sin distinguir
/// mayúsculas (`CustomUriDereferencer.getElementById`): primero en orden de
/// documento.
pub fn find_by_id_ci(doc: &Document, id: &str) -> Option<NodeId> {
    doc.descendants(doc.root()).into_iter().find(|&n| {
        doc.element(n).is_some_and(|e| {
            e.attrs
                .iter()
                .any(|a| a.ns.is_none() && a.local.eq_ignore_ascii_case("id") && a.value == id)
        })
    })
}

/// Busca un elemento por su atributo `Id` exacto.
pub fn find_by_exact_id(doc: &Document, id: &str) -> Option<NodeId> {
    doc.descendants(doc.root())
        .into_iter()
        .find(|&n| doc.element(n).is_some_and(|e| e.attr("Id") == Some(id)))
}

/// Primer hijo elemento XMLDSig con el nombre local dado.
pub fn ds_child(doc: &Document, parent: NodeId, local: &str) -> Option<NodeId> {
    doc.find_child(parent, DSIG_NS, local)
}

/// Hijos elemento XMLDSig con el nombre local dado.
pub fn ds_children(doc: &Document, parent: NodeId, local: &str) -> Vec<NodeId> {
    doc.child_elements(parent)
        .filter(|&c| doc.element(c).is_some_and(|e| e.is(DSIG_NS, local)))
        .collect()
}

enum DocRef<'d> {
    Borrowed(&'d Document),
    Owned(Rc<Document>),
}

impl DocRef<'_> {
    fn get(&self) -> &Document {
        match self {
            DocRef::Borrowed(d) => d,
            DocRef::Owned(d) => d,
        }
    }
}

enum Data<'d> {
    Nodes(DocRef<'d>, NodeSet),
    Octets(Vec<u8>),
}

/// Opciones de proceso de las referencias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefOptions {
    /// Validación segura de Apache Santuario
    /// (`org.apache.jcp.xml.dsig.secureValidation`). AutoFirma 1.9 la tiene
    /// activa (es el valor por defecto de Santuario 3.0.5) y con ella la
    /// transformada XSLT se rechaza con una `TransformException`, de modo que
    /// la firma se informa como mal construida (`BAD_BUILD_SIGN`). Sin ella
    /// la transformada se aplica como `TransformXSLT`.
    pub secure_validation: bool,
    /// Límites del procesador XSLT cuando se aplica la transformada.
    pub xslt_limits: crate::xslt::Limits,
}

impl Default for RefOptions {
    /// Comportamiento de AutoFirma 1.9 (validación segura).
    fn default() -> Self {
        RefOptions {
            secure_validation: true,
            xslt_limits: crate::xslt::Limits::default(),
        }
    }
}

impl RefOptions {
    /// Sin validación segura: la transformada XSLT se aplica.
    pub fn allow_xslt() -> Self {
        RefOptions {
            secure_validation: false,
            ..RefOptions::default()
        }
    }
}

/// Contexto de proceso de una referencia.
pub struct RefContext<'a> {
    /// Documento que contiene la firma.
    pub doc: &'a Document,
    /// Elemento `Signature` que contiene la referencia.
    pub signature: NodeId,
    pub resolver: &'a dyn Resolver,
    pub options: RefOptions,
}

fn parse_octets(bytes: &[u8]) -> DResult<Rc<Document>> {
    let (d, _) = Document::parse_bytes(bytes)
        .map_err(|e| DsigError::Processing(format!("los datos transformados no son XML: {e}")))?;
    Ok(Rc::new(d))
}

fn to_nodes(data: Data<'_>) -> DResult<Data<'_>> {
    match data {
        Data::Octets(b) => {
            let d = parse_octets(&b)?;
            let set = NodeSet::whole(&d, true);
            Ok(Data::Nodes(DocRef::Owned(d), set))
        }
        n => Ok(n),
    }
}

fn to_octets(data: Data<'_>) -> Vec<u8> {
    match data {
        Data::Octets(b) => b,
        Data::Nodes(d, set) => C14n::new(Kind::Inclusive10, false).canonicalize_set(d.get(), &set),
    }
}

/// Mapa de prefijos en ámbito de un elemento (sin el espacio por defecto).
fn xpath_namespaces(doc: &Document, el: NodeId) -> HashMap<String, String> {
    doc.in_scope_namespaces(el)
        .into_iter()
        .filter(|(p, _)| !p.is_empty())
        .collect()
}

fn is_signature_exclusion(expr: &str, ns: &HashMap<String, String>) -> bool {
    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
    let Some(inner) = compact
        .strip_prefix("not(ancestor-or-self::")
        .and_then(|s| s.strip_suffix(":Signature)"))
    else {
        return false;
    };
    ns.get(inner).is_some_and(|u| u == DSIG_NS)
}

impl<'a> RefContext<'a> {
    /// Desreferencia una URI (modelo de proceso XMLDSig 4.3.3.2).
    fn dereference(&self, uri: Option<&str>) -> DResult<Data<'a>> {
        let doc = self.doc;
        let Some(uri) = uri else {
            // Sin URI: el desreferenciador de AutoFirma falla con un
            // NullPointerException (error no XMLDSig).
            return match self.resolver.resolve("") {
                Some(e) => self.external(e, ""),
                None => Err(DsigError::Unsupported("Reference sin URI".into())),
            };
        };
        if uri.is_empty() {
            return Ok(Data::Nodes(DocRef::Borrowed(doc), NodeSet::whole(doc, false)));
        }
        if let Some(frag) = uri.strip_prefix('#') {
            if frag == "xpointer(/)" {
                return Ok(Data::Nodes(DocRef::Borrowed(doc), NodeSet::whole(doc, true)));
            }
            if let Some(inner) = frag.strip_prefix("xpointer(id(").and_then(|s| s.strip_suffix("))")) {
                let id = inner.trim_matches(['\'', '"']);
                let el = find_by_id_ci(doc, id).ok_or_else(|| DsigError::Dereference(uri.to_string()))?;
                return Ok(Data::Nodes(DocRef::Borrowed(doc), NodeSet::subtree(doc, el, true)));
            }
            if let Some(el) = find_by_id_ci(doc, frag) {
                return Ok(Data::Nodes(DocRef::Borrowed(doc), NodeSet::subtree(doc, el, false)));
            }
        }
        match self.resolver.resolve(uri) {
            Some(e) => self.external(e, uri),
            None => Err(DsigError::Dereference(uri.to_string())),
        }
    }

    fn external(&self, e: External, uri: &str) -> DResult<Data<'a>> {
        match e {
            External::Octets(b) => Ok(Data::Octets(b)),
            External::Xml(b) => {
                let d = parse_octets(&b).map_err(|_| DsigError::Dereference(uri.to_string()))?;
                let set = NodeSet::whole(&d, false);
                Ok(Data::Nodes(DocRef::Owned(d), set))
            }
        }
    }

    fn apply_transform(&self, data: Data<'a>, transform: NodeId) -> DResult<Data<'a>> {
        let sdoc = self.doc;
        let alg = sdoc
            .element(transform)
            .and_then(|e| e.attr("Algorithm"))
            .ok_or_else(|| DsigError::Malformed("Transform sin Algorithm".into()))?
            .to_string();
        if let Some(mut method) = C14n::from_uri(&alg) {
            if method.kind == Kind::Exclusive
                && let Some(inc) = sdoc.find_child(transform, EXC_C14N_NS, "InclusiveNamespaces")
            {
                let list = sdoc.element(inc).and_then(|e| e.attr("PrefixList")).unwrap_or("");
                method = method.with_inclusive_prefixes(list.split_whitespace().map(str::to_string));
            }
            let data = to_nodes(data)?;
            let Data::Nodes(d, set) = data else { unreachable!() };
            return Ok(Data::Octets(method.canonicalize_set(d.get(), &set)));
        }
        match alg.as_str() {
            ENVELOPED => {
                let data = to_nodes(data)?;
                match data {
                    Data::Nodes(DocRef::Borrowed(d), mut set) => {
                        if std::ptr::eq(d, sdoc) {
                            set.remove_subtree(d, self.signature);
                        }
                        Ok(Data::Nodes(DocRef::Borrowed(d), set))
                    }
                    other => Ok(other),
                }
            }
            XPATH => {
                let xp_el = ds_child(sdoc, transform, "XPath")
                    .ok_or_else(|| DsigError::Malformed("Transform XPath sin XPath".into()))?;
                let expr = sdoc.text_content(xp_el);
                let ns = xpath_namespaces(sdoc, xp_el);
                let data = to_nodes(data)?;
                let Data::Nodes(d, set) = data else { unreachable!() };
                let doc = d.get();
                let new_set = if is_signature_exclusion(&expr, &ns) {
                    let mut s = set.clone();
                    for sig in doc.find_descendants(doc.root(), crate::dsig::DSIG_NS, "Signature") {
                        s.remove_subtree(doc, sig);
                    }
                    s
                } else {
                    let compiled = XPath::compile(&expr, &ns).map_err(|e| DsigError::Processing(e.to_string()))?;
                    let here = std::ptr::eq(doc, sdoc).then_some(XNode::Node(xp_el));
                    let mut failure = None;
                    let s = NodeSet::filter(doc, &set, |n| match compiled.evaluate_bool(doc, n, here) {
                        Ok(b) => b,
                        Err(e) => {
                            failure.get_or_insert(e);
                            false
                        }
                    });
                    if let Some(e) = failure {
                        return Err(DsigError::Processing(e.to_string()));
                    }
                    s
                };
                Ok(Data::Nodes(d, new_set))
            }
            XPATH2 => {
                let filters: Vec<NodeId> = sdoc
                    .child_elements(transform)
                    .filter(|&c| sdoc.element(c).is_some_and(|e| e.is(XPATH2, "XPath")))
                    .collect();
                if filters.is_empty() {
                    return Err(DsigError::Malformed("Transform XPath2 sin XPath".into()));
                }
                let data = to_nodes(data)?;
                let Data::Nodes(d, set) = data else { unreachable!() };
                let doc = d.get();
                let whole = NodeSet::whole(doc, true);
                let mut f = whole.clone();
                for fl in filters {
                    let el = sdoc.element(fl).expect("elemento");
                    let op = el.attr("Filter").unwrap_or("").to_string();
                    let expr = sdoc.text_content(fl);
                    let ns = xpath_namespaces(sdoc, fl);
                    let compiled = XPath::compile(&expr, &ns).map_err(|e| DsigError::Processing(e.to_string()))?;
                    let here = std::ptr::eq(doc, sdoc).then_some(XNode::Node(fl));
                    let result = compiled
                        .select(doc, XNode::Node(doc.root()), here)
                        .map_err(|e| DsigError::Processing(e.to_string()))?;
                    let mut covered = vec![false; doc.len()];
                    let mut extra: std::collections::HashSet<XNode> = std::collections::HashSet::new();
                    for r in &result {
                        match r {
                            XNode::Node(id) => {
                                for x in doc.descendants(*id) {
                                    covered[x.0] = true;
                                }
                            }
                            other => {
                                extra.insert(*other);
                            }
                        }
                    }
                    let in_s = |n: XNode| match n {
                        XNode::Node(id) => covered[id.0],
                        XNode::Attr(e, _) | XNode::Ns(e, _) => covered[e.0] || extra.contains(&n),
                    };
                    let prev = f.clone();
                    f = match op.as_str() {
                        "intersect" => NodeSet::filter(doc, &whole, |n| prev.contains(doc, n) && in_s(n)),
                        "subtract" => NodeSet::filter(doc, &whole, |n| prev.contains(doc, n) && !in_s(n)),
                        "union" => NodeSet::filter(doc, &whole, |n| prev.contains(doc, n) || in_s(n)),
                        other => {
                            return Err(DsigError::Malformed(format!("filtro XPath2 desconocido: {other}")));
                        }
                    };
                }
                let out = NodeSet::filter(doc, &set, |n| f.contains(doc, n));
                Ok(Data::Nodes(d, out))
            }
            BASE64 => {
                let text = match data {
                    Data::Octets(b) => String::from_utf8_lossy(&b).into_owned(),
                    Data::Nodes(d, set) => {
                        let doc = d.get();
                        let mut t = String::new();
                        for i in 0..doc.len() {
                            let id = NodeId(i);
                            if set.contains_node(id)
                                && let NodeKind::Text { text, .. } = doc.kind(id)
                            {
                                t.push_str(text);
                            }
                        }
                        t
                    }
                };
                let bytes = crate::util::b64_decode(&text)
                    .ok_or_else(|| DsigError::Processing("contenido Base64 no válido".into()))?;
                Ok(Data::Octets(bytes))
            }
            RELATIONSHIP_TRANSFORM => {
                let mut ids = Vec::new();
                let mut types = Vec::new();
                for c in sdoc.child_elements(transform) {
                    let e = sdoc.element(c).expect("elemento");
                    if e.is(MDSSI_NS, "RelationshipReference") {
                        if let Some(v) = e.attr("SourceId") {
                            ids.push(v.to_string());
                        }
                    } else if e.is(MDSSI_NS, "RelationshipsGroupReference")
                        && let Some(v) = e.attr("SourceType")
                    {
                        types.push(v.to_string());
                    }
                }
                let octets = to_octets(data);
                Ok(Data::Octets(relationship_transform(&octets, &ids, &types)?))
            }
            XSLT => {
                if self.options.secure_validation {
                    // `ApacheTransform.transformIt` con `secureValidation`.
                    return Err(DsigError::Processing(format!(
                        "la transformada {XSLT} está prohibida con la validación segura"
                    )));
                }
                // `TransformXSLT`: entrada en octetos (un conjunto de nodos se
                // canonicaliza antes) y salida en octetos.
                let input = to_octets(data);
                let out = crate::xslt::transform_xslt(sdoc, transform, &input, &self.options.xslt_limits)
                    .map_err(|e| DsigError::Processing(e.to_string()))?;
                Ok(Data::Octets(out))
            }
            other => Err(DsigError::Unsupported(format!("transformada {other}"))),
        }
    }

    /// Octetos sobre los que se calcula la huella de una referencia.
    pub fn reference_octets(&self, reference: NodeId) -> DResult<Vec<u8>> {
        let doc = self.doc;
        let uri = doc.element(reference).and_then(|e| e.attr("URI")).map(str::to_string);
        let mut data = self.dereference(uri.as_deref())?;
        if let Some(ts) = ds_child(doc, reference, "Transforms") {
            for t in ds_children(doc, ts, "Transform") {
                data = self.apply_transform(data, t)?;
            }
        }
        Ok(to_octets(data))
    }

    /// Algoritmo de huella declarado por la referencia.
    pub fn reference_digest_algorithm(&self, reference: NodeId) -> DResult<DigestAlgorithm> {
        let doc = self.doc;
        let dm = ds_child(doc, reference, "DigestMethod")
            .ok_or_else(|| DsigError::Malformed("Reference sin DigestMethod".into()))?;
        let uri = doc.element(dm).and_then(|e| e.attr("Algorithm")).unwrap_or("");
        match digest_from_uri(uri) {
            Some(d) => Ok(d),
            // Santuario conoce el algoritmo pero no hay implementación: error
            // al calcular la huella (`XMLSignatureException`).
            None if SANTUARIO_DIGESTS.contains(&uri) => {
                Err(DsigError::Processing(format!("huella no disponible {uri}")))
            }
            None => Err(DsigError::Unsupported(format!("huella {uri}"))),
        }
    }

    /// Huella calculada de una referencia.
    pub fn reference_digest(&self, reference: NodeId) -> DResult<Vec<u8>> {
        // SHA-3: AutoFirma nunca la genera, pero Java la valida (el JDK la
        // incluye). RIPEMD-160 y Whirlpool siguen sin implementación, como en Java.
        let uri = ds_child(self.doc, reference, "DigestMethod")
            .and_then(|dm| self.doc.element(dm))
            .and_then(|e| e.attr("Algorithm"))
            .unwrap_or("");
        if let Some(f) = sha3_digest(uri) {
            return Ok(f(&self.reference_octets(reference)?));
        }
        let alg = self.reference_digest_algorithm(reference)?;
        Ok(alg.digest(&self.reference_octets(reference)?))
    }

    /// Comprueba la huella de una referencia.
    pub fn check_reference(&self, reference: NodeId) -> DResult<bool> {
        let doc = self.doc;
        let dv = ds_child(doc, reference, "DigestValue")
            .ok_or_else(|| DsigError::Malformed("Reference sin DigestValue".into()))?;
        let declared = crate::util::b64_decode(&doc.text_content(dv))
            .ok_or_else(|| DsigError::Malformed("DigestValue no válido".into()))?;
        Ok(self.reference_digest(reference)? == declared)
    }
}

/// Transformada de relaciones OPC (ECMA-376 parte 2): conserva las relaciones
/// indicadas, añade `TargetMode="Internal"` si falta y las ordena por `Id`.
pub fn relationship_transform(input: &[u8], ids: &[String], types: &[String]) -> DResult<Vec<u8>> {
    let d = parse_octets(input)?;
    let root = d
        .document_element()
        .ok_or_else(|| DsigError::Malformed("relaciones vacías".into()))?;
    let re = d.element(root).expect("raíz");
    let mut kept: Vec<NodeId> = d
        .child_elements(root)
        .filter(|&c| {
            let e = d.element(c).expect("elemento");
            let id = e.attr("Id").unwrap_or("");
            let ty = e.attr("Type").unwrap_or("");
            ids.iter().any(|x| x == id) || types.iter().any(|x| x == ty)
        })
        .collect();
    kept.sort_by(|a, b| {
        let ia: Vec<u16> = d
            .element(*a)
            .and_then(|e| e.attr("Id"))
            .unwrap_or("")
            .encode_utf16()
            .collect();
        let ib: Vec<u16> = d
            .element(*b)
            .and_then(|e| e.attr("Id"))
            .unwrap_or("")
            .encode_utf16()
            .collect();
        ia.cmp(&ib)
    });
    let mut out = String::new();
    out.push('<');
    out.push_str(&re.qname());
    for ns in &re.ns_decls {
        match &ns.prefix {
            Some(p) => out.push_str(&format!(" xmlns:{p}=\"{}\"", esc_attr(&ns.uri))),
            None => out.push_str(&format!(" xmlns=\"{}\"", esc_attr(&ns.uri))),
        }
    }
    out.push('>');
    for k in kept {
        let e = d.element(k).expect("elemento");
        out.push('<');
        out.push_str(&e.qname());
        for ns in &e.ns_decls {
            match &ns.prefix {
                Some(p) => out.push_str(&format!(" xmlns:{p}=\"{}\"", esc_attr(&ns.uri))),
                None => out.push_str(&format!(" xmlns=\"{}\"", esc_attr(&ns.uri))),
            }
        }
        for a in &e.attrs {
            out.push_str(&format!(" {}=\"{}\"", a.qname(), esc_attr(&a.value)));
        }
        if e.attr("TargetMode").is_none() {
            out.push_str(" TargetMode=\"Internal\"");
        }
        out.push_str("/>");
    }
    out.push_str("</");
    out.push_str(&re.qname());
    out.push('>');
    Ok(out.into_bytes())
}

/// Canonicaliza `SignedInfo` con su `CanonicalizationMethod`.
pub fn canonicalize_signed_info(doc: &Document, signed_info: NodeId) -> DResult<Vec<u8>> {
    let cm = ds_child(doc, signed_info, "CanonicalizationMethod")
        .ok_or_else(|| DsigError::Malformed("SignedInfo sin CanonicalizationMethod".into()))?;
    let uri = doc.element(cm).and_then(|e| e.attr("Algorithm")).unwrap_or("");
    let mut method = C14n::from_uri(uri).ok_or_else(|| DsigError::Unsupported(format!("canonicalización {uri}")))?;
    if method.kind == Kind::Exclusive
        && let Some(inc) = doc.find_child(cm, EXC_C14N_NS, "InclusiveNamespaces")
    {
        let list = doc.element(inc).and_then(|e| e.attr("PrefixList")).unwrap_or("");
        method = method.with_inclusive_prefixes(list.split_whitespace().map(str::to_string));
    }
    let set = NodeSet::subtree(doc, signed_info, method.with_comments);
    Ok(method.canonicalize_set(doc, &set))
}

/// Busca la firma (`ds:Signature`) con el `Id` dado.
pub fn find_signature(doc: &Document, id: &str) -> Option<NodeId> {
    doc.find_descendants(doc.root(), DSIG_NS, "Signature")
        .into_iter()
        .chain(
            doc.document_element()
                .filter(|&r| doc.element(r).is_some_and(|e| e.is(DSIG_NS, "Signature"))),
        )
        .find(|&s| doc.element(s).and_then(|e| e.attr("Id")) == Some(id))
}

// ---------------------------------------------------------------------------
// Generación de texto
// ---------------------------------------------------------------------------

/// Transformada de una referencia a generar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformSpec {
    /// Transformada sin parámetros.
    Plain(String),
    /// Filtro XPath 1.0 (el prefijo XMLDSig se declara en el elemento `XPath`).
    XPath(String),
    /// XPath Filter 2.0 (`subtract`, `intersect` o `union`).
    XPath2 { filter: String, expr: String },
    /// Transformada de relaciones OPC con sus `SourceId`.
    Relationships(Vec<String>),
}

/// Referencia a generar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceSpec {
    pub id: Option<String>,
    pub ty: Option<String>,
    pub uri: Option<String>,
    pub transforms: Vec<TransformSpec>,
    pub digest_method: String,
    /// Huella conocida; `None` para calcularla al completar la firma.
    pub digest: Option<Vec<u8>>,
}

impl ReferenceSpec {
    pub fn new(uri: impl Into<String>, digest_method: &str) -> Self {
        ReferenceSpec {
            id: None,
            ty: None,
            uri: Some(uri.into()),
            transforms: vec![],
            digest_method: digest_method.to_string(),
            digest: None,
        }
    }
}

/// Nombres cualificados de XMLDSig con un prefijo dado (`ds` o vacío).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsNames {
    pub prefix: String,
}

impl DsNames {
    pub fn new(prefix: &str) -> Self {
        DsNames {
            prefix: prefix.to_string(),
        }
    }

    /// Nombre cualificado (`ds:Reference` o `Reference`).
    pub fn q(&self, local: &str) -> String {
        if self.prefix.is_empty() {
            local.to_string()
        } else {
            format!("{}:{local}", self.prefix)
        }
    }

    /// Declaración del espacio de nombres XMLDSig (` xmlns:ds="..."`).
    pub fn xmlns(&self) -> String {
        if self.prefix.is_empty() {
            format!(" xmlns=\"{DSIG_NS}\"")
        } else {
            format!(" xmlns:{}=\"{DSIG_NS}\"", self.prefix)
        }
    }
}

/// Generador de marcadores para los valores pendientes de cálculo.
#[derive(Debug, Clone)]
pub struct Placeholders {
    nonce: String,
    counter: usize,
}

impl Default for Placeholders {
    fn default() -> Self {
        Self::new()
    }
}

impl Placeholders {
    pub fn new() -> Self {
        Placeholders {
            nonce: crate::util::uuid_v4().replace('-', ""),
            counter: 0,
        }
    }

    pub fn next_digest(&mut self) -> String {
        self.counter += 1;
        format!("@@AFIRMA{}D{}@@", self.nonce, self.counter)
    }

    pub fn signature_value(&self) -> String {
        format!("@@AFIRMA{}SV@@", self.nonce)
    }

    fn is_placeholder(&self, s: &str) -> bool {
        s.starts_with(&format!("@@AFIRMA{}D", self.nonce))
    }
}

/// Texto XML de una referencia.
pub fn render_reference(n: &DsNames, r: &ReferenceSpec, ph: &mut Placeholders) -> String {
    let mut s = String::new();
    s.push('<');
    s.push_str(&n.q("Reference"));
    if let Some(id) = &r.id {
        s.push_str(&format!(" Id=\"{}\"", esc_attr(id)));
    }
    if let Some(t) = &r.ty {
        s.push_str(&format!(" Type=\"{}\"", esc_attr(t)));
    }
    if let Some(u) = &r.uri {
        s.push_str(&format!(" URI=\"{}\"", esc_attr(u)));
    }
    s.push('>');
    if !r.transforms.is_empty() {
        s.push_str(&format!("<{}>", n.q("Transforms")));
        for t in &r.transforms {
            match t {
                TransformSpec::Plain(alg) => {
                    s.push_str(&format!("<{} Algorithm=\"{}\"/>", n.q("Transform"), esc_attr(alg)))
                }
                TransformSpec::XPath(expr) => s.push_str(&format!(
                    "<{t} Algorithm=\"{XPATH}\"><{x}{ns}>{e}</{x}></{t}>",
                    t = n.q("Transform"),
                    x = n.q("XPath"),
                    ns = n.xmlns(),
                    e = esc_text(expr)
                )),
                TransformSpec::XPath2 { filter, expr } => s.push_str(&format!(
                    "<{t} Algorithm=\"{XPATH2}\"><XPath xmlns=\"{XPATH2}\" Filter=\"{f}\">{e}</XPath></{t}>",
                    t = n.q("Transform"),
                    f = esc_attr(filter),
                    e = esc_text(expr)
                )),
                TransformSpec::Relationships(ids) => {
                    s.push_str(&format!(
                        "<{} Algorithm=\"{RELATIONSHIP_TRANSFORM}\" xmlns:mdssi=\"{MDSSI_NS}\">",
                        n.q("Transform")
                    ));
                    for id in ids {
                        s.push_str(&format!("<mdssi:RelationshipReference SourceId=\"{}\"/>", esc_attr(id)));
                    }
                    s.push_str(&format!("</{}>", n.q("Transform")));
                }
            }
        }
        s.push_str(&format!("</{}>", n.q("Transforms")));
    }
    s.push_str(&format!(
        "<{} Algorithm=\"{}\"/>",
        n.q("DigestMethod"),
        esc_attr(&r.digest_method)
    ));
    let value = match &r.digest {
        Some(d) => b64(d),
        None => ph.next_digest(),
    };
    s.push_str(&format!("<{dv}>{value}</{dv}>", dv = n.q("DigestValue")));
    s.push_str(&format!("</{}>", n.q("Reference")));
    s
}

/// Texto de `SignedInfo`.
pub fn render_signed_info(
    n: &DsNames,
    c14n: &str,
    sig_method: &str,
    refs: &[ReferenceSpec],
    ph: &mut Placeholders,
) -> String {
    let mut s = format!(
        "<{si}><{cm} Algorithm=\"{c}\"/><{sm} Algorithm=\"{m}\"/>",
        si = n.q("SignedInfo"),
        cm = n.q("CanonicalizationMethod"),
        sm = n.q("SignatureMethod"),
        c = esc_attr(c14n),
        m = esc_attr(sig_method)
    );
    for r in refs {
        s.push_str(&render_reference(n, r, ph));
    }
    s.push_str(&format!("</{}>", n.q("SignedInfo")));
    s
}

/// Contenido de `ds:X509Data` con los certificados indicados.
pub fn render_x509_data(n: &DsNames, certs: &[Vec<u8>]) -> String {
    let mut s = format!("<{}>", n.q("X509Data"));
    for c in certs {
        s.push_str(&format!("<{x}>{}</{x}>", b64(c), x = n.q("X509Certificate")));
    }
    s.push_str(&format!("</{}>", n.q("X509Data")));
    s
}

/// `ds:KeyValue` de la clave del certificado (RSA en el espacio XMLDSig, EC
/// con `ECKeyValue` de XMLDSig 1.1 como hace Santuario). `None` si la clave no
/// está soportada.
pub fn render_key_value(n: &DsNames, cert: &[u8]) -> Option<String> {
    Some(match crypto::key_value_data(cert)? {
        crypto::KeyValueData::Rsa { modulus, exponent } => format!(
            "<{kv}><{r}><{m}>{}</{m}><{e}>{}</{e}></{r}></{kv}>",
            b64(&modulus),
            b64(&exponent),
            kv = n.q("KeyValue"),
            r = n.q("RSAKeyValue"),
            m = n.q("Modulus"),
            e = n.q("Exponent")
        ),
        crypto::KeyValueData::Ec { curve_oid, point } => format!(
            "<{kv}><ECKeyValue xmlns=\"{DSIG11_NS}\"><NamedCurve URI=\"urn:oid:{curve_oid}\"/><PublicKey>{}</PublicKey></ECKeyValue></{kv}>",
            b64(&point),
            kv = n.q("KeyValue")
        ),
    })
}

// ---------------------------------------------------------------------------
// Compleción de firmas
// ---------------------------------------------------------------------------

/// Parámetros para completar una firma ya insertada como texto.
pub struct Completion<'a> {
    pub key: &'a dyn SigningKey,
    pub algorithm: SignatureAlgorithm,
    /// `Id` del elemento `Signature` nuevo.
    pub signature_id: &'a str,
    pub resolver: &'a dyn Resolver,
    /// Verificar el `SignatureValue` con el certificado (`validatePkcs1`).
    pub verify: bool,
    /// Código de error para fallos internos.
    pub error_code: ErrorCode,
}

fn reparse(text: &str, code: ErrorCode) -> afirma_core::Result<Document> {
    Document::parse(text).map_err(|e| AfirmaError::new(code, format!("Error interno al generar la firma XML: {e}")))
}

/// Calcula las huellas pendientes (primero las de los `Manifest`, después las
/// de `SignedInfo`) y el `SignatureValue` de la firma con el `Id` indicado.
pub fn complete(mut text: String, ph: &Placeholders, c: &Completion<'_>) -> afirma_core::Result<String> {
    let err = |m: String| AfirmaError::new(c.error_code, m);
    for pass in 0..2 {
        let doc = reparse(&text, c.error_code)?;
        let sig =
            find_signature(&doc, c.signature_id).ok_or_else(|| err("No se encuentra la firma generada".into()))?;
        let si = ds_child(&doc, sig, "SignedInfo").ok_or_else(|| err("Firma sin SignedInfo".into()))?;
        let ctx = RefContext {
            doc: &doc,
            signature: sig,
            resolver: c.resolver,
            options: RefOptions::default(),
        };
        let mut subs = Vec::new();
        for r in doc.find_descendants(sig, DSIG_NS, "Reference") {
            let in_signed_info = doc.parent(r) == Some(si);
            if in_signed_info != (pass == 1) {
                continue;
            }
            let Some(dv) = ds_child(&doc, r, "DigestValue") else {
                continue;
            };
            let current = doc.text_content(dv);
            if !ph.is_placeholder(&current) {
                continue;
            }
            let digest = ctx
                .reference_digest(r)
                .map_err(|e| err(format!("Error al calcular la huella de una referencia: {e}")))?;
            subs.push((current, b64(&digest)));
        }
        for (k, v) in subs {
            text = text.replace(&k, &v);
        }
    }
    let doc = reparse(&text, c.error_code)?;
    let sig = find_signature(&doc, c.signature_id).ok_or_else(|| err("No se encuentra la firma generada".into()))?;
    let si = ds_child(&doc, sig, "SignedInfo").ok_or_else(|| err("Firma sin SignedInfo".into()))?;
    let canon = canonicalize_signed_info(&doc, si).map_err(|e| err(e.to_string()))?;
    let value = crypto::sign_xml(c.key, c.algorithm, &canon)?;
    if c.verify {
        let ok =
            PublicKey::from_cert(c.key.certificate()).is_some_and(|k| k.verify(c.algorithm.digest, &canon, &value));
        if !ok {
            return Err(AfirmaError::new(
                codes::UNKWNON_XML_SIGNING_ERROR,
                "El PKCS#1 de la firma no se ha generado con la clave publica indicada",
            ));
        }
    }
    Ok(text.replace(&ph.signature_value(), &b64(&value)))
}

// ---------------------------------------------------------------------------
// Validación criptográfica
// ---------------------------------------------------------------------------

/// Resultado de la validación criptográfica de una firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreValidation {
    /// Valor de firma correcto.
    pub signature_value: bool,
    /// Resultado de cada referencia de `SignedInfo` (URI, correcta).
    pub references: Vec<(String, bool)>,
}

impl CoreValidation {
    pub fn is_valid(&self) -> bool {
        self.signature_value && self.references.iter().all(|(_, ok)| *ok)
    }
}

/// Clave pública de una firma como `KeyValueKeySelector` de AutoFirma: el
/// primer `KeyValue` y, si no hay, el primer certificado de `X509Data`.
pub fn select_key(doc: &Document, sig: NodeId) -> Option<PublicKey> {
    let ki = ds_child(doc, sig, "KeyInfo")?;
    for c in doc.child_elements(ki) {
        let e = doc.element(c)?;
        if e.is(DSIG_NS, "KeyValue") {
            if let Some(k) = parse_key_value(doc, c) {
                return Some(k);
            }
        } else if e.is(DSIG_NS, "X509Data")
            && let Some(cert) = ds_child(doc, c, "X509Certificate")
            && let Some(der) = crate::util::b64_decode(&doc.text_content(cert))
            && let Some(k) = PublicKey::from_cert(&der)
        {
            return Some(k);
        }
    }
    None
}

fn parse_key_value(doc: &Document, kv: NodeId) -> Option<PublicKey> {
    if let Some(rsa) = ds_child(doc, kv, "RSAKeyValue") {
        let m = crate::util::b64_decode(&doc.text_content(ds_child(doc, rsa, "Modulus")?))?;
        let e = crate::util::b64_decode(&doc.text_content(ds_child(doc, rsa, "Exponent")?))?;
        return PublicKey::from_rsa(&m, &e);
    }
    let ec = doc
        .child_elements(kv)
        .find(|&c| doc.element(c).is_some_and(|e| e.local == "ECKeyValue"))?;
    let curve = doc
        .child_elements(ec)
        .find(|&c| doc.element(c).is_some_and(|e| e.local == "NamedCurve"))?;
    let uri = doc.element(curve)?.attr("URI")?;
    let oid = uri.strip_prefix("urn:oid:")?;
    let pk = doc
        .child_elements(ec)
        .find(|&c| doc.element(c).is_some_and(|e| e.local == "PublicKey"))?;
    let point = crate::util::b64_decode(&doc.text_content(pk))?;
    PublicKey::from_ec(oid, &point)
}

/// Función de huella.
type DigestFn = fn(&[u8]) -> Vec<u8>;

/// Huella SHA-3 de una URI de `DigestMethod` (RFC 6931).
fn sha3_digest(uri: &str) -> Option<DigestFn> {
    use sha3::Digest as _;
    Some(match uri {
        "http://www.w3.org/2007/05/xmldsig-more#sha3-224" => |d: &[u8]| sha3::Sha3_224::digest(d).to_vec(),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-256" => |d: &[u8]| sha3::Sha3_256::digest(d).to_vec(),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-384" => |d: &[u8]| sha3::Sha3_384::digest(d).to_vec(),
        "http://www.w3.org/2007/05/xmldsig-more#sha3-512" => |d: &[u8]| sha3::Sha3_512::digest(d).to_vec(),
        _ => return None,
    })
}

/// Algoritmos de huella que reconoce Apache Santuario al analizar una firma
/// aunque no siempre haya implementación (`DOMDigestMethod`).
const SANTUARIO_DIGESTS: &[&str] = &[
    "http://www.w3.org/2001/04/xmlenc#ripemd160",
    "http://www.w3.org/2001/04/xmldsig-more#whirlpool",
    "http://www.w3.org/2007/05/xmldsig-more#sha3-224",
    "http://www.w3.org/2007/05/xmldsig-more#sha3-256",
    "http://www.w3.org/2007/05/xmldsig-more#sha3-384",
    "http://www.w3.org/2007/05/xmldsig-more#sha3-512",
];

/// Transformadas que reconoce Apache Santuario al analizar una firma.
const SANTUARIO_TRANSFORMS: &[&str] = &[
    crate::c14n::C14N_10,
    crate::c14n::C14N_10_WITH_COMMENTS,
    crate::c14n::C14N_11,
    crate::c14n::C14N_11_WITH_COMMENTS,
    crate::c14n::EXC_C14N,
    crate::c14n::EXC_C14N_WITH_COMMENTS,
    BASE64,
    ENVELOPED,
    XPATH,
    XPATH2,
    XSLT,
];

/// Comprobaciones que hace JSR-105 al analizar (`unmarshalXMLSignature`) la
/// firma, antes de validar nada: `SignedInfo`, métodos de canonicalización y
/// de firma, y algoritmos de huella y transformadas de las referencias
/// reconocidos. Un fallo aquí es una `MarshalException` en Java.
pub fn unmarshal_check(doc: &Document, sig: NodeId) -> DResult<()> {
    let si = ds_child(doc, sig, "SignedInfo").ok_or_else(|| DsigError::Malformed("Signature sin SignedInfo".into()))?;
    let cm = ds_child(doc, si, "CanonicalizationMethod")
        .ok_or_else(|| DsigError::Malformed("SignedInfo sin CanonicalizationMethod".into()))?;
    let cm_uri = doc.element(cm).and_then(|e| e.attr("Algorithm")).unwrap_or("");
    C14n::from_uri(cm_uri).ok_or_else(|| DsigError::Unsupported(format!("canonicalización {cm_uri}")))?;
    let sm = ds_child(doc, si, "SignatureMethod")
        .ok_or_else(|| DsigError::Malformed("SignedInfo sin SignatureMethod".into()))?;
    let sm_uri = doc.element(sm).and_then(|e| e.attr("Algorithm")).unwrap_or("");
    signature_from_uri(sm_uri).ok_or_else(|| DsigError::Unsupported(format!("firma {sm_uri}")))?;
    ds_child(doc, sig, "SignatureValue").ok_or_else(|| DsigError::Malformed("Signature sin SignatureValue".into()))?;
    for r in ds_children(doc, si, "Reference") {
        let dm = ds_child(doc, r, "DigestMethod")
            .ok_or_else(|| DsigError::Malformed("Reference sin DigestMethod".into()))?;
        let uri = doc.element(dm).and_then(|e| e.attr("Algorithm")).unwrap_or("");
        let known = DigestAlgorithm::ALL.iter().any(|d| d.xml_uri() == uri) || SANTUARIO_DIGESTS.contains(&uri);
        if !known {
            return Err(DsigError::Unsupported(format!("huella {uri}")));
        }
        ds_child(doc, r, "DigestValue").ok_or_else(|| DsigError::Malformed("Reference sin DigestValue".into()))?;
        if let Some(ts) = ds_child(doc, r, "Transforms") {
            for t in ds_children(doc, ts, "Transform") {
                let a = doc.element(t).and_then(|e| e.attr("Algorithm")).unwrap_or("");
                if !SANTUARIO_TRANSFORMS.contains(&a) {
                    return Err(DsigError::Unsupported(format!("transformada {a}")));
                }
            }
        }
    }
    Ok(())
}

/// Comprueba el valor de firma de `SignedInfo` con la clave dada (o la
/// seleccionada de su `KeyInfo`).
pub fn verify_signature_value(doc: &Document, sig: NodeId, key: Option<PublicKey>) -> DResult<bool> {
    let si = ds_child(doc, sig, "SignedInfo").ok_or_else(|| DsigError::Malformed("Signature sin SignedInfo".into()))?;
    let sm = ds_child(doc, si, "SignatureMethod")
        .ok_or_else(|| DsigError::Malformed("SignedInfo sin SignatureMethod".into()))?;
    let sm_uri = doc.element(sm).and_then(|e| e.attr("Algorithm")).unwrap_or("");
    let alg = signature_from_uri(sm_uri).ok_or_else(|| DsigError::Unsupported(format!("firma {sm_uri}")))?;
    let sv = ds_child(doc, sig, "SignatureValue")
        .ok_or_else(|| DsigError::Malformed("Signature sin SignatureValue".into()))?;
    let value = crate::util::b64_decode(&doc.text_content(sv))
        .ok_or_else(|| DsigError::Malformed("SignatureValue no válido".into()))?;
    let key = key.or_else(|| select_key(doc, sig)).ok_or(DsigError::KeyNotFound)?;
    let canon = canonicalize_signed_info(doc, si)?;
    Ok(key.key_algorithm() == alg.key && key.verify(alg.digest, &canon, &value))
}

/// Validación criptográfica (núcleo XMLDSig) de una firma con la clave dada
/// (o la seleccionada de su `KeyInfo`), con la validación segura de
/// AutoFirma.
pub fn validate_core(
    doc: &Document,
    sig: NodeId,
    resolver: &dyn Resolver,
    key: Option<PublicKey>,
) -> DResult<CoreValidation> {
    validate_core_with(doc, sig, resolver, key, RefOptions::default())
}

/// [`validate_core`] con opciones de proceso de las referencias.
pub fn validate_core_with(
    doc: &Document,
    sig: NodeId,
    resolver: &dyn Resolver,
    key: Option<PublicKey>,
    options: RefOptions,
) -> DResult<CoreValidation> {
    let si = ds_child(doc, sig, "SignedInfo").ok_or_else(|| DsigError::Malformed("Signature sin SignedInfo".into()))?;
    let signature_value = verify_signature_value(doc, sig, key)?;
    let ctx = RefContext {
        doc,
        signature: sig,
        resolver,
        options,
    };
    let mut references = Vec::new();
    for r in ds_children(doc, si, "Reference") {
        let uri = doc.element(r).and_then(|e| e.attr("URI")).unwrap_or("").to_string();
        let ok = ctx.check_reference(r)?;
        references.push((uri, ok));
    }
    Ok(CoreValidation {
        signature_value,
        references,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_transform_sorts_and_filters() {
        let rels = b"<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId2\" Type=\"t2\" Target=\"b\"/><Relationship Id=\"rId1\" Type=\"t1\" Target=\"a\"/><Relationship Id=\"rId10\" Type=\"t\" Target=\"c\" TargetMode=\"External\"/></Relationships>";
        let out = relationship_transform(rels, &["rId2".into(), "rId10".into(), "rId1".into()], &[]).unwrap();
        let d = Document::parse(std::str::from_utf8(&out).unwrap()).unwrap();
        let c = C14n::new(Kind::Inclusive10, false).canonicalize(&d, d.root(), &[]);
        assert_eq!(
            String::from_utf8(c).unwrap(),
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Target=\"a\" TargetMode=\"Internal\" Type=\"t1\"></Relationship><Relationship Id=\"rId10\" Target=\"c\" TargetMode=\"External\" Type=\"t\"></Relationship><Relationship Id=\"rId2\" Target=\"b\" TargetMode=\"Internal\" Type=\"t2\"></Relationship></Relationships>"
        );
    }

    #[test]
    fn enveloped_digest_matches_spec_vector() {
        // XMLDSig Enveloped de <doc><a>1</a></doc>: SHA-1 = qTTy37gklsHItf7qbmMqqWzqRR8=
        let src = format!(
            "<doc><a>1</a><ds:Signature xmlns:ds=\"{DSIG_NS}\" Id=\"S\"><ds:SignedInfo><ds:Reference URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{XPATH}\"><ds:XPath xmlns:ds=\"{DSIG_NS}\">not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>x</ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature></doc>"
        );
        let doc = Document::parse(&src).unwrap();
        let sig = find_signature(&doc, "S").unwrap();
        let r = doc.find_descendants(sig, DSIG_NS, "Reference")[0];
        let ctx = RefContext {
            doc: &doc,
            signature: sig,
            resolver: &NoResolver,
            options: RefOptions::default(),
        };
        assert_eq!(b64(&ctx.reference_digest(r).unwrap()), "qTTy37gklsHItf7qbmMqqWzqRR8=");
    }

    #[test]
    fn object_digest_matches_spec_vector() {
        let src = format!(
            "<ds:Signature xmlns:ds=\"{DSIG_NS}\" Id=\"S\"><ds:SignedInfo><ds:Reference URI=\"#Object-186805e1-c6f2-4db7-80e5-9d3041c37cf1\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>x</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:Object Encoding=\"UTF-8\" Id=\"Object-186805e1-c6f2-4db7-80e5-9d3041c37cf1\" MimeType=\"text/xml\"><doc><a>1</a></doc></ds:Object></ds:Signature>"
        );
        let doc = Document::parse(&src).unwrap();
        let sig = find_signature(&doc, "S").unwrap();
        let r = doc.find_descendants(sig, DSIG_NS, "Reference")[0];
        let ctx = RefContext {
            doc: &doc,
            signature: sig,
            resolver: &NoResolver,
            options: RefOptions::default(),
        };
        assert_eq!(b64(&ctx.reference_digest(r).unwrap()), "7RVdV2qdgFdEC2G7Jt6VY5s6z0c=");
        // Vector de FIPS 202: SHA3-256("abc").
        let f = sha3_digest("http://www.w3.org/2007/05/xmldsig-more#sha3-256").unwrap();
        assert_eq!(
            f(b"abc").iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }
}
