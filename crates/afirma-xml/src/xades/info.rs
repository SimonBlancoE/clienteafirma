//! Detección de firmas XAdES, variantes, extracción de datos y árbol de
//! firmantes (`AOXAdESSigner.isSign/getData/getSignInfo/getSignersStructure`).

use afirma_core::error::AfirmaError;
use afirma_core::extra_params::ExtraParams;
use afirma_core::signer::{SignInfo, SignerNode, SignersTree, SimpleSignInfo};

use super::*;
use crate::dom::{Document, NodeId, NodeKind};
use crate::dsig::{self, DSIG_NS};
use crate::util;

const TIMESTAMP_TAG: &str = "Timestamp";

/// `XAdESUtil.isDataMandatory`.
pub fn is_data_mandatory(operation: &str, config: Option<&ExtraParams>) -> bool {
    let Some(c) = config else { return true };
    if !operation.eq_ignore_ascii_case("sign") {
        return true;
    }
    let ext = c.get("format") == Some(FORMAT_EXTERNALLY_DETACHED);
    !ext && !c.get_bool("useManifest", false)
}

/// Analiza un documento de firma (cualquier XML bien formado, con o sin DOCTYPE).
pub(crate) fn parse(sign: &[u8]) -> Option<Document> {
    Document::parse_bytes(sign).ok().map(|(d, _)| d)
}

fn local_name(doc: &Document, n: NodeId) -> Option<&str> {
    doc.element(n).map(|e| e.local.as_str())
}

/// Firmas a considerar (`isSign`): la raíz si se llama `Signature` y todas las
/// `ds:Signature` descendientes cuyo padre no sea `Timestamp`.
pub(crate) fn sign_nodes(doc: &Document) -> Vec<NodeId> {
    let Some(root) = doc.document_element() else {
        return vec![];
    };
    let mut out = Vec::new();
    if local_name(doc, root) == Some("Signature") {
        out.push(root);
    }
    for s in doc.find_descendants(root, DSIG_NS, "Signature") {
        if doc.parent(s).and_then(|p| local_name(doc, p)) != Some(TIMESTAMP_TAG) {
            out.push(s);
        }
    }
    out
}

/// `isSign(Document)`.
pub fn is_sign_doc(doc: &Document) -> bool {
    let nodes = sign_nodes(doc);
    if nodes.is_empty() {
        return false;
    }
    nodes.iter().all(|&s| {
        SUPPORTED_NAMESPACES.iter().any(|ns| {
            !doc.find_descendants(s, ns, "QualifyingProperties")
                .is_empty()
        })
    })
}

/// `isSign(byte[])`.
pub fn is_sign(data: &[u8]) -> bool {
    parse(data).is_some_and(|d| is_sign_doc(&d))
}

/// Primera firma: la raíz si se llama `Signature`, si no la primera
/// `ds:Signature` descendiente.
pub(crate) fn first_signature(doc: &Document) -> Option<NodeId> {
    let root = doc.document_element()?;
    if local_name(doc, root) == Some("Signature") {
        return Some(root);
    }
    doc.find_descendants(root, DSIG_NS, "Signature")
        .into_iter()
        .next()
}

/// `SignedInfo` (hijo directo) de una firma.
pub(crate) fn signed_info(doc: &Document, sig: NodeId) -> Option<NodeId> {
    dsig::ds_child(doc, sig, "SignedInfo")
}

/// `XAdESUtil.findElementById` (atributo `Id` exacto, recorrido en profundidad).
pub(crate) fn find_element_by_id(
    doc: &Document,
    id: &str,
    from: NodeId,
    omit_signatures: bool,
) -> Option<NodeId> {
    let e = doc.element(from)?;
    if e.attr("Id") == Some(id) {
        return Some(from);
    }
    if omit_signatures && e.local == "Signature" {
        return None;
    }
    for c in doc.child_elements(from) {
        if let Some(found) = find_element_by_id(doc, id, c, omit_signatures) {
            return Some(found);
        }
    }
    None
}

/// `XAdESUtil.getSignatureDataReferenceList`.
pub(crate) fn data_references(doc: &Document, sig: NodeId) -> Vec<NodeId> {
    let Some(si) = signed_info(doc, sig) else {
        return vec![];
    };
    let mut out = Vec::new();
    for r in doc.find_descendants(si, DSIG_NS, "Reference") {
        let e = doc.element(r).expect("elemento");
        let ty = e.attr("Type").unwrap_or("");
        if !ty.is_empty() {
            if !SIGNED_PROPERTIES_TYPES.contains(&ty) {
                out.push(r);
            }
            continue;
        }
        let uri = e.attr("URI").unwrap_or("");
        if let Some(id) = uri.strip_prefix('#') {
            match find_element_by_id(doc, id, sig, false) {
                None => out.push(r),
                Some(n) => {
                    let name = local_name(doc, n).unwrap_or("");
                    if name != "KeyInfo" && name != "SignedProperties" {
                        out.push(r);
                    }
                }
            }
        } else {
            out.push(r);
        }
    }
    out
}

fn transform_algorithms(doc: &Document, reference: NodeId) -> Vec<(NodeId, String)> {
    doc.find_descendants(reference, DSIG_NS, "Transform")
        .into_iter()
        .map(|t| {
            (
                t,
                doc.element(t)
                    .and_then(|e| e.attr("Algorithm"))
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect()
}

/// `XAdESUtil.isSignatureElementEnveloped`.
pub(crate) fn is_enveloped(doc: &Document, sig: NodeId, refs: &[NodeId]) -> bool {
    let prefix = doc
        .element(sig)
        .and_then(|e| e.prefix.clone())
        .unwrap_or_else(|| "null".to_string());
    let eq1 = format!("not(ancestor-or-self::{prefix}:Signature)");
    let eq2 = format!(
        "count(ancestor-or-self::{prefix}:Signature|here()/ancestor::{prefix}:Signature[1])>count(ancestor-or-self::{prefix}:Signature)"
    );
    for &r in refs {
        for (t, alg) in transform_algorithms(doc, r) {
            if alg == dsig::ENVELOPED {
                return true;
            }
            if alg == dsig::XPATH {
                let text: String = doc
                    .text_content(t)
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                if text == eq1 || text == eq2 {
                    return true;
                }
            }
        }
    }
    false
}

/// `XAdESUtil.isSignatureWithManifest`.
pub(crate) fn is_manifest(doc: &Document, refs: &[NodeId]) -> bool {
    refs.iter()
        .any(|&r| doc.element(r).and_then(|e| e.attr("Type")) == Some(dsig::MANIFEST_TYPE))
}

/// `XAdESUtil.isSignatureElementExternallyDetached`.
pub(crate) fn is_externally_detached(doc: &Document, refs: &[NodeId]) -> bool {
    refs.iter().any(|&r| {
        let u = doc
            .element(r)
            .and_then(|e| e.attr("URI"))
            .unwrap_or("")
            .to_ascii_lowercase();
        u.starts_with("http://") || u.starts_with("https://")
    })
}

/// `XAdESUtil.isSignatureElementInternallyDetached`.
pub(crate) fn is_internally_detached(doc: &Document, refs: &[NodeId]) -> bool {
    let Some(root) = doc.document_element() else {
        return false;
    };
    refs.iter().any(|&r| {
        doc.element(r)
            .and_then(|e| e.attr("URI"))
            .and_then(|u| u.strip_prefix('#'))
            .is_some_and(|id| find_element_by_id(doc, id, root, true).is_some())
    })
}

/// `XAdESUtil.isSignatureElementEnveloping`.
pub(crate) fn is_enveloping(doc: &Document, sig: NodeId, refs: &[NodeId]) -> bool {
    refs.iter().any(|&r| {
        doc.element(r)
            .and_then(|e| e.attr("URI"))
            .and_then(|u| u.strip_prefix('#'))
            .is_some_and(|id| find_element_by_id(doc, id, sig, false).is_some())
    })
}

/// Variante de la primera firma (`getSignInfo`).
pub fn variant(doc: &Document) -> Option<&'static str> {
    let sig = first_signature(doc)?;
    let refs = data_references(doc, sig);
    if is_enveloped(doc, sig, &refs) {
        Some(FORMAT_ENVELOPED)
    } else if is_externally_detached(doc, &refs) {
        Some(FORMAT_EXTERNALLY_DETACHED)
    } else if is_internally_detached(doc, &refs) {
        Some(FORMAT_DETACHED)
    } else if is_enveloping(doc, sig, &refs) {
        Some(FORMAT_ENVELOPING)
    } else {
        None
    }
}

/// `getSignInfo`.
pub fn sign_info(data: &[u8]) -> afirma_core::Result<SignInfo> {
    let doc = parse(data).ok_or_else(|| {
        AfirmaError::invalid_signature_format(
            "Los datos introducidos no se corresponden con un documento XML",
        )
    })?;
    if !is_sign_doc(&doc) {
        return Err(AfirmaError::invalid_signature_format(
            "Los datos introducidos no se corresponden con un objeto de firma",
        ));
    }
    Ok(SignInfo {
        format: FORMAT_XADES.into(),
        variant: variant(&doc).map(str::to_string),
        ..Default::default()
    })
}

/// Texto de un elemento como documento independiente: se añaden las
/// declaraciones de espacios de nombres heredadas que use (Java las omitiría).
pub(crate) fn standalone_element(doc: &Document, el: NodeId, remove: &[NodeId]) -> String {
    let src = doc.source();
    let e = doc.element(el).expect("elemento");
    let range = doc.range(el);
    // Prefijos usados en el subárbol.
    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for d in doc.descendants(el) {
        if remove.iter().any(|r| doc.descendants(*r).contains(&d)) {
            continue;
        }
        if let Some(x) = doc.element(d) {
            used.insert(x.prefix.clone().unwrap_or_default());
            for a in &x.attrs {
                if let Some(p) = &a.prefix {
                    used.insert(p.clone());
                }
            }
        }
    }
    let own: Vec<String> = e
        .ns_decls
        .iter()
        .map(|d| d.prefix.clone().unwrap_or_default())
        .collect();
    let inherited = doc
        .parent(el)
        .map(|p| {
            if doc.element(p).is_some() {
                doc.in_scope_namespaces(p)
            } else {
                Default::default()
            }
        })
        .unwrap_or_default();
    let mut extra = String::new();
    for (p, u) in inherited {
        if used.contains(&p) && !own.contains(&p) && p != "xml" {
            if p.is_empty() {
                extra.push_str(&format!(" xmlns=\"{}\"", util::esc_attr(&u)));
            } else {
                extra.push_str(&format!(" xmlns:{p}=\"{}\"", util::esc_attr(&u)));
            }
        }
    }
    let name_end = e.start_tag.start + 1 + e.qname().len();
    let mut out = String::new();
    let mut pos = range.start;
    out.push_str(&src[pos..name_end]);
    out.push_str(&extra);
    pos = name_end;
    let mut cuts: Vec<std::ops::Range<usize>> = remove.iter().map(|r| doc.range(*r)).collect();
    cuts.sort_by_key(|r| r.start);
    for c in cuts {
        if c.start >= pos && c.end <= range.end {
            out.push_str(&src[pos..c.start]);
            pos = c.end;
        }
    }
    out.push_str(&src[pos..range.end]);
    out
}

fn xml_bytes(text: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{text}").into_bytes()
}

fn base64_declared_for(doc: &Document, root: NodeId, id: &str) -> bool {
    if id.trim().is_empty() {
        return false;
    }
    let target = format!("#{id}");
    let reference = doc
        .find_descendants(root, DSIG_NS, "Reference")
        .into_iter()
        .find(|&r| doc.element(r).and_then(|e| e.attr("URI")) == Some(target.as_str()));
    match reference {
        Some(r) => base64_declared(doc, r),
        None => false,
    }
}

fn base64_declared(doc: &Document, reference: NodeId) -> bool {
    transform_algorithms(doc, reference)
        .iter()
        .any(|(_, a)| a == dsig::BASE64)
}

fn decode_or_raw(text: &str, decode: bool) -> afirma_core::Result<Vec<u8>> {
    if decode {
        util::b64_decode(text).ok_or_else(|| {
            AfirmaError::invalid_signature_format(
                "Error al leer el fichero de firmas: Base64 no valido",
            )
        })
    } else {
        Ok(text.as_bytes().to_vec())
    }
}

/// `getData`.
pub fn get_data(sign: &[u8]) -> afirma_core::Result<Option<Vec<u8>>> {
    let doc = parse(sign).ok_or_else(|| {
        AfirmaError::invalid_signature_format("Error al leer el fichero de firmas")
    })?;
    if !is_sign_doc(&doc) {
        return Err(AfirmaError::invalid_signature_format(
            "El documento no es un documento de firmas valido.",
        ));
    }
    let Some(sig) = first_signature(&doc) else {
        return Ok(None);
    };
    let refs = data_references(&doc, sig);
    let root = doc.document_element().expect("raíz");
    let bad = || AfirmaError::invalid_signature_format("Error al leer el fichero de firmas");
    if is_externally_detached(&doc, &refs) || is_manifest(&doc, &refs) {
        return Ok(None);
    }
    if is_enveloped(&doc, sig, &refs) {
        let r0 = *refs.first().ok_or_else(bad)?;
        let uri = doc.element(r0).and_then(|e| e.attr("URI")).unwrap_or("");
        let referenced = if uri.is_empty() {
            root
        } else {
            let id = uri.strip_prefix('#').ok_or_else(bad)?;
            find_element_by_id(&doc, id, root, false).ok_or_else(bad)?
        };
        // Se eliminan las firmas hijas directas del elemento referenciado.
        let sigs: Vec<NodeId> = doc
            .child_elements(referenced)
            .filter(|&c| local_name(&doc, c) == Some("Signature"))
            .collect();
        if referenced != root {
            if let Some(&first) = doc.children(referenced).first() {
                if matches!(doc.kind(first), NodeKind::Text { .. }) {
                    let mut text = String::new();
                    for c in doc.descendants(referenced) {
                        if sigs.iter().any(|s| doc.descendants(*s).contains(&c)) {
                            continue;
                        }
                        if let NodeKind::Text { text: t, .. } = doc.kind(c) {
                            text.push_str(t);
                        }
                    }
                    return decode_or_raw(&text, base64_declared(&doc, r0)).map(Some);
                }
            }
        }
        return Ok(Some(xml_bytes(&standalone_element(
            &doc, referenced, &sigs,
        ))));
    }
    if is_internally_detached(&doc, &refs) {
        let first = *doc.children(root).first().ok_or_else(bad)?;
        doc.element(first).ok_or_else(bad)?;
        let inner = *doc.children(first).first().ok_or_else(bad)?;
        if matches!(doc.kind(inner), NodeKind::Text { .. }) {
            let id = doc
                .element(first)
                .and_then(|e| e.attr("Id"))
                .unwrap_or("")
                .to_string();
            return decode_or_raw(
                &doc.text_content(first),
                base64_declared_for(&doc, root, &id),
            )
            .map(Some);
        }
        doc.element(inner).ok_or_else(bad)?;
        return Ok(Some(xml_bytes(&standalone_element(&doc, inner, &[]))));
    }
    if is_enveloping(&doc, sig, &refs) {
        let object = doc
            .find_descendants(doc.root(), DSIG_NS, "Object")
            .into_iter()
            .next()
            .ok_or_else(bad)?;
        let oe = doc.element(object).expect("elemento");
        if oe.attr("MimeType") == Some("text/xml") {
            let first = *doc.children(object).first().ok_or_else(bad)?;
            doc.element(first).ok_or_else(bad)?;
            return Ok(Some(xml_bytes(&standalone_element(&doc, first, &[]))));
        }
        let id = oe.attr("Id").unwrap_or("").to_string();
        return decode_or_raw(
            &doc.text_content(object),
            base64_declared_for(&doc, root, &id),
        )
        .map(Some);
    }
    Ok(None)
}

/// `Utils.getCounterSignerReferenceId`.
fn countersigned_reference_id(doc: &Document, sig: NodeId) -> String {
    let Some(r) = doc
        .find_descendants(sig, DSIG_NS, "Reference")
        .into_iter()
        .next()
    else {
        return String::new();
    };
    let uri = doc.element(r).and_then(|e| e.attr("URI")).unwrap_or("");
    let target: String = uri.chars().skip(1).collect();
    for sv in doc.find_descendants(doc.root(), DSIG_NS, "SignatureValue") {
        if doc.element(sv).and_then(|e| e.attr("Id")) == Some(target.as_str()) {
            return doc
                .parent(sv)
                .and_then(|p| doc.element(p))
                .and_then(|e| e.attr("Id"))
                .unwrap_or("")
                .to_string();
        }
    }
    String::new()
}

/// `Utils.getSimpleSignInfoNode`.
pub(crate) fn simple_sign_info(
    doc: &Document,
    sig: NodeId,
    xades_ns: Option<&str>,
) -> SimpleSignInfo {
    let certs: Vec<Vec<u8>> = doc
        .find_descendants(sig, DSIG_NS, "X509Certificate")
        .into_iter()
        .filter_map(|c| util::b64_decode(&doc.text_content(c)))
        .collect();
    let signing_time = xades_ns.and_then(|ns| {
        let st = doc
            .find_descendants(sig, ns, "SigningTime")
            .into_iter()
            .next()?;
        parse_java_local_time(doc.text_content(st).trim())
    });
    let sign_algorithm = doc
        .find_descendants(sig, DSIG_NS, "SignatureMethod")
        .into_iter()
        .next()
        .and_then(|m| {
            doc.element(m)
                .and_then(|e| e.attr("Algorithm"))
                .map(str::to_string)
        });
    let pkcs1 = doc
        .find_descendants(sig, DSIG_NS, "SignatureValue")
        .into_iter()
        .next()
        .and_then(|v| util::b64_decode(&doc.text_content(v)))
        .unwrap_or_default();
    SimpleSignInfo {
        certs,
        signing_time,
        sign_algorithm,
        pkcs1,
        sign_format: None,
        timestamping_time: vec![],
    }
}

/// `SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss")` en la zona local (se ignora el
/// desplazamiento que siga, como Java).
pub(crate) fn parse_java_local_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    let head = s.get(..19)?;
    let naive = chrono::NaiveDateTime::parse_from_str(head, "%Y-%m-%dT%H:%M:%S").ok()?;
    chrono::Local
        .from_local_datetime(&naive)
        .earliest()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// Árbol con la semántica de `AOTreeNode.add` (mover un nodo existente).
pub(crate) struct Arena {
    pub nodes: Vec<SimpleSignInfo>,
    parent: Vec<Option<usize>>,
    children: Vec<Vec<usize>>,
}

impl Arena {
    pub fn new(nodes: Vec<SimpleSignInfo>) -> Self {
        let n = nodes.len();
        Arena {
            nodes,
            parent: vec![None; n],
            children: vec![vec![]; n],
        }
    }

    fn is_ancestor(&self, a: usize, of: usize) -> bool {
        let mut cur = Some(of);
        while let Some(c) = cur {
            if c == a {
                return true;
            }
            cur = self.parent[c];
        }
        false
    }

    pub fn add(&mut self, parent: usize, child: usize) {
        if self.is_ancestor(child, parent) {
            return; // Java lanzaría IllegalArgumentException
        }
        if let Some(old) = self.parent[child] {
            self.children[old].retain(|&c| c != child);
        }
        self.children[parent].push(child);
        self.parent[child] = Some(parent);
    }

    pub fn build(&self, idx: usize) -> SignerNode {
        SignerNode {
            info: self.nodes[idx].clone(),
            countersigners: self.children[idx].iter().map(|&c| self.build(c)).collect(),
        }
    }
}

/// `generateSignsTree` (portado literalmente).
pub(crate) fn generate_signs_tree(
    i: usize,
    j: isize,
    arena: &mut Arena,
    ids: &[String],
    refs: &[String],
) {
    let max = ids.len();
    if i < max && j > 0 {
        let ju = j as usize;
        if ids[i] == refs[ju] {
            generate_signs_tree(i + 1, j - 1, arena, ids, refs);
        }
        if (i as isize) < j {
            generate_signs_tree(i, j - 1, arena, ids, refs);
        }
        if ids[i] != refs[ju] {
            return;
        }
        generate_signs_tree(ju, max as isize - 1, arena, ids, refs);
        arena.add(i, ju);
    }
}

/// `getSignersStructure`.
pub fn signers_structure(sign: &[u8]) -> afirma_core::Result<SignersTree> {
    let doc = parse(sign).ok_or_else(|| {
        AfirmaError::invalid_signature_format(
            "Los datos indicados no son una firma XAdES compatible",
        )
    })?;
    signers_structure_doc(&doc)
}

/// `getSignersStructure(Document)`.
pub fn signers_structure_doc(doc: &Document) -> afirma_core::Result<SignersTree> {
    if !is_sign_doc(doc) {
        return Err(AfirmaError::invalid_signature_format(
            "Los datos indicados no son una firma XAdES compatible",
        ));
    }
    let xades_ns = first_signature(doc)
        .and_then(|s| signed_properties(doc, s))
        .and_then(|sp| doc.element(sp).and_then(|e| e.ns.clone()));
    let mut all: Vec<NodeId> = doc.find_descendants(doc.root(), DSIG_NS, "Signature");
    all.retain(|&s| doc.parent(s).and_then(|p| local_name(doc, p)) != Some(TIMESTAMP_TAG));
    let mut ids = Vec::new();
    let mut refs = Vec::new();
    let mut infos = Vec::new();
    for &s in &all {
        ids.push(
            doc.element(s)
                .and_then(|e| e.attr("Id"))
                .unwrap_or("")
                .to_string(),
        );
        infos.push(simple_sign_info(doc, s, xades_ns.as_deref()));
        if doc.parent(s).and_then(|p| local_name(doc, p)) == Some("CounterSignature") {
            refs.push(countersigned_reference_id(doc, s));
        } else {
            refs.push(String::new());
        }
    }
    let mut arena = Arena::new(infos);
    let mut tops = Vec::new();
    for i in 0..refs.len() {
        if refs[i].is_empty() {
            generate_signs_tree(i, ids.len() as isize - 1, &mut arena, &ids, &refs);
            tops.push(i);
        }
    }
    let mut tree = SignersTree::default();
    for t in tops {
        tree.signers.push(arena.build(t));
    }
    Ok(tree)
}

/// Referencia a `SignedProperties` de una firma.
pub(crate) fn signed_properties_reference(doc: &Document, sig: NodeId) -> Option<NodeId> {
    let si = signed_info(doc, sig)?;
    doc.find_descendants(si, DSIG_NS, "Reference")
        .into_iter()
        .find(|&r| {
            doc.element(r)
                .and_then(|e| e.attr("Type"))
                .is_some_and(|t| SIGNED_PROPERTIES_TYPES.contains(&t))
        })
}

/// Elemento `SignedProperties` de una firma.
pub(crate) fn signed_properties(doc: &Document, sig: NodeId) -> Option<NodeId> {
    let r = signed_properties_reference(doc, sig)?;
    let uri = doc.element(r)?.attr("URI")?;
    let id = uri.strip_prefix('#')?;
    find_element_by_id(doc, id, sig, false)
}

/// `XAdESUtil.checkCompatibility`: comprueba que todas las firmas usan el
/// mismo espacio de nombres XAdES admitido y devuelve si son baseline
/// (segundo hijo de `SignedSignatureProperties` = `SigningCertificateV2`).
///
/// Java recorre los nodos hijo en bruto (los espacios en blanco cuentan, lo
/// que hace fallar el análisis de firmas indentadas); aquí se usan solo los
/// hijos elemento (desviación documentada).
pub fn check_compatibility(doc: &Document) -> afirma_core::Result<bool> {
    let mut baseline = false;
    let mut namespaces: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for s in sign_nodes(doc) {
        let qps: Vec<NodeId> = doc
            .descendants(s)
            .into_iter()
            .skip(1)
            .filter(|&n| {
                doc.element(n)
                    .is_some_and(|e| e.local == "QualifyingProperties")
            })
            .collect();
        for qp in qps {
            let ns = doc
                .element(qp)
                .and_then(|e| e.ns.clone())
                .unwrap_or_default();
            if !SUPPORTED_NAMESPACES.contains(&ns.as_str()) {
                return Err(AfirmaError::invalid_signature_format(
                    "Una de las firmas encontradas en el documento contiene una version inexistente de XAdES",
                ));
            }
            namespaces.insert(ns.clone());
            let second = doc
                .child_elements(qp)
                .next()
                .and_then(|sp| doc.child_elements(sp).next())
                .and_then(|ssp| doc.child_elements(ssp).nth(1));
            match second {
                Some(n) => {
                    if doc.element(n).is_some_and(|e| {
                        e.local == "SigningCertificateV2" && e.ns.as_deref() == Some(ns.as_str())
                    }) {
                        baseline = true;
                    }
                }
                None => {
                    return Err(AfirmaError::invalid_signature_format(
                        "Error al intentar analizar el nodo SigningCertificateV2",
                    ));
                }
            }
        }
        if namespaces.len() > 1 {
            return Err(AfirmaError::invalid_signature_format(
                "El documento contiene firmas con distintas versiones de XAdES",
            ));
        }
    }
    Ok(baseline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_mandatory() {
        assert!(is_data_mandatory("sign", None));
        let p = ExtraParams::parse("format=XAdES Externally Detached");
        assert!(!is_data_mandatory("sign", Some(&p)));
        assert!(is_data_mandatory("cosign", Some(&p)));
        assert!(!is_data_mandatory(
            "SIGN",
            Some(&ExtraParams::parse("useManifest=true"))
        ));
    }

    #[test]
    fn java_local_time() {
        assert!(parse_java_local_time("2026-10-16T13:39:15+02:00").is_some());
        assert!(parse_java_local_time("bad").is_none());
    }
}
