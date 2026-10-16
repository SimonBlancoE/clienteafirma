//! Cofirma (`XAdESCoSigner`) y contrafirma (`XAdESCounterSigner`) XAdES.

use afirma_core::error::{AfirmaError, ConfirmEffect, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::CounterSignTarget;

use super::info::{self, find_element_by_id};
use super::props::{
    self, DataObjectFormat, KeyInfoOptions, ObjectIdentifier, PolicySpec, SignedProps,
};
use super::sign::{check_digest_uri, encoding_param, key_info_certs};
use super::*;
use crate::c14n::{C14N_10, C14n};
use crate::dom::{Document, NodeId};
use crate::dsig::{self, DSIG_NS, DsNames, Placeholders, ReferenceSpec, TransformSpec};
use crate::mime;
use crate::splice;
use crate::util::{self, esc_attr, uuid_v4};

/// Parámetros comunes de cofirma y contrafirma.
struct MultiParams {
    p: ExtraParams,
    sig_uri: String,
    sig_alg: afirma_core::SignatureAlgorithm,
    digest_uri: String,
    c14n: String,
    key_value: bool,
    key_name: bool,
    issuer_serial: bool,
    keep_ki_unsigned: bool,
    only_cert: bool,
}

fn multi_params(
    extra: &ExtraParams,
    algorithm: &str,
    key: &dyn SigningKey,
    baseline: bool,
) -> afirma_core::Result<MultiParams> {
    let algorithm = if algorithm.trim().is_empty() {
        DEFAULT_SIGN_ALGO
    } else {
        algorithm
    };
    if algorithm.to_uppercase().starts_with("MD") {
        return Err(AfirmaError::invalid_argument(
            "XAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)",
        ));
    }
    let mut p = extra.clone();
    p.remove("validatePkcs1");
    // checkSignProfile: el perfil es siempre el de la firma existente.
    p.set("profile", if baseline { "baseline" } else { "advanced" });
    let (sig_uri, sig_alg) = resolve_algorithm(algorithm, key.key_algorithm()).map_err(|_| {
        AfirmaError::invalid_argument(format!(
            "Los formatos de firma XML no soportan el algoritmo de firma '{algorithm}'"
        ))
    })?;
    let digest_uri = p
        .get_or("referencesDigestMethod", DEFAULT_DIGEST_METHOD)
        .to_string();
    let c14n = p.get_or("canonicalizationAlgorithm", C14N_10).to_string();
    Ok(MultiParams {
        sig_uri,
        sig_alg,
        digest_uri,
        c14n,
        key_value: p.get_bool("addKeyInfoKeyValue", true),
        key_name: p.get_bool("addKeyInfoKeyName", false),
        issuer_serial: p.get_bool("addKeyInfoX509IssuerSerial", false),
        keep_ki_unsigned: p.get_bool("keepKeyInfoUnsigned", false),
        only_cert: p.get_bool("includeOnlySignningCertificate", false),
        p,
    })
}

fn local(doc: &Document, n: NodeId) -> &str {
    doc.element(n).map(|e| e.local.as_str()).unwrap_or("")
}

/// `XAdESUtil.checkArchiveSignatures`.
fn has_archive_timestamp(doc: &Document, sig: NodeId) -> bool {
    let Some(sp) = info::signed_properties(doc, sig) else {
        return false;
    };
    let Some(qp) = doc.parent(sp) else {
        return false;
    };
    let Some(up) = doc.find_child(qp, NS_XADES_132, "UnsignedProperties") else {
        return false;
    };
    let Some(usp) = doc.find_child(up, NS_XADES_132, "UnsignedSignatureProperties") else {
        return false;
    };
    [NS_XADES_141, NS_XADES_132, NS_XADES_122]
        .iter()
        .any(|ns| doc.find_child(usp, ns, "ArchiveTimeStamp").is_some())
}

fn check_archive(
    doc: &Document,
    sigs: &[NodeId],
    p: &ExtraParams,
    cosign: bool,
) -> afirma_core::Result<()> {
    let allow = p.get("allowSignLTSignature");
    if allow.is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Ok(());
    }
    if sigs.iter().any(|&s| has_archive_timestamp(doc, s)) {
        let err = if cosign {
            // Java marca como denegada la causa, no la excepción lanzada.
            AfirmaError::signing_lts(
                "La cofirma de firmas de archivo invalidara el sello de archivo",
                false,
            )
        } else {
            let e = AfirmaError::signing_lts(
                "La contrafirma de firmas de archivo podria invalidar el sello de archivo si se aplicase a contrafirmas internas",
                true,
            );
            if allow.is_some() { e.denied() } else { e }
        };
        return Err(err);
    }
    Ok(())
}

/// Algoritmos de transformada aceptados al copiar transformadas.
fn known_transform(alg: &str) -> bool {
    C14n::from_uri(alg).is_some()
        || matches!(
            alg,
            dsig::BASE64
                | dsig::ENVELOPED
                | dsig::XPATH
                | dsig::XPATH2
                | "http://www.w3.org/TR/1999/REC-xslt-19991116"
        )
}

/// `Utils.getObjectReferenceTransforms`.
pub(crate) fn copy_transforms(
    doc: &Document,
    reference: NodeId,
    prefix: &str,
) -> afirma_core::Result<Vec<TransformSpec>> {
    let qn = |l: &str| {
        if prefix.is_empty() {
            l.to_string()
        } else {
            format!("{prefix}:{l}")
        }
    };
    let named = |n: NodeId, l: &str| {
        doc.element(n)
            .is_some_and(|e| e.qname() == l || e.qname() == qn(l))
    };
    let mut out = Vec::new();
    let Some(ts) = doc
        .children(reference)
        .iter()
        .copied()
        .find(|&c| named(c, "Transforms"))
    else {
        return Ok(out);
    };
    for t in doc.child_elements(ts) {
        let alg = doc
            .element(t)
            .and_then(|e| e.attr("Algorithm"))
            .unwrap_or("")
            .to_string();
        if !known_transform(&alg) {
            return Err(AfirmaError::new(
                codes::INVALID_REFERENCES_HASH_ALGORITHM_URI,
                "Se ha declarado una transformacion personalizada de un tipo no soportado",
            ));
        }
        let bad = |m: &str| {
            AfirmaError::new(
                codes::INVALID_TRANSFORMATION,
                format!(
                    "Se han especificado parametros erroneos para una transformacion personalizada: {m}"
                ),
            )
        };
        match alg.as_str() {
            dsig::XPATH => {
                let x = doc
                    .children(t)
                    .iter()
                    .copied()
                    .find(|&c| named(c, "XPath"))
                    .ok_or_else(|| bad("XPath sin cuerpo"))?;
                out.push(TransformSpec::XPath(doc.text_content(x)));
            }
            dsig::XPATH2 => {
                let x = doc
                    .children(t)
                    .iter()
                    .copied()
                    .find(|&c| named(c, "XPath"))
                    .ok_or_else(|| bad("XPath2 sin cuerpo"))?;
                let f = doc
                    .element(x)
                    .and_then(|e| e.attr("Filter"))
                    .ok_or_else(|| bad("XPath2 sin subtipo"))?;
                if !matches!(f, "subtract" | "intersect" | "union") {
                    return Err(bad(f));
                }
                out.push(TransformSpec::XPath2 {
                    filter: f.to_string(),
                    expr: doc.text_content(x),
                });
            }
            _ => out.push(TransformSpec::Plain(alg)),
        }
    }
    Ok(out)
}

/// `DataObjectFormatParser.parseDataObjectFormat`.
fn parse_data_object_format(doc: &Document, dof: NodeId) -> DataObjectFormat {
    let mut out = DataObjectFormat {
        object_reference: doc
            .element(dof)
            .and_then(|e| e.attr("ObjectReference"))
            .unwrap_or("")
            .to_string(),
        description: None,
        object_identifier: None,
        mime_type: None,
        encoding: None,
    };
    for c in doc.child_elements(dof) {
        let text = doc.text_content(c);
        match local(doc, c) {
            "Description" if !text.is_empty() => out.description = Some(text.trim().to_string()),
            "MimeType" if !text.is_empty() => out.mime_type = Some(text),
            "Encoding" if !text.is_empty() => out.encoding = Some(text),
            "ObjectIdentifier" => {
                let mut oi = ObjectIdentifier {
                    identifier: String::new(),
                    qualifier: None,
                    description: None,
                    documentation_references: vec![],
                };
                for x in doc.child_elements(c) {
                    match local(doc, x) {
                        "Identifier" => {
                            oi.qualifier = Some(
                                doc.element(x)
                                    .and_then(|e| e.attr("Qualifier"))
                                    .unwrap_or("")
                                    .to_string(),
                            );
                            oi.identifier = doc.text_content(x);
                        }
                        "Description" => oi.description = Some(doc.text_content(x)),
                        "DocumentationReferences" => {
                            for d in doc.child_elements(x) {
                                if local(doc, d) == "DocumentationReference" {
                                    oi.documentation_references.push(doc.text_content(d));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                out.object_identifier = Some(oi);
            }
            _ => {}
        }
    }
    out
}

/// `XAdESCoSigner.addReferenceDataObjectFormat` (sin filtrar el OID por defecto).
fn cosign_dof(
    reference_id: &str,
    mime_type: Option<&str>,
    oid: Option<&str>,
    encoding: Option<&str>,
) -> DataObjectFormat {
    let oid = oid
        .map(str::to_string)
        .or_else(|| mime_type.map(mime::mime_to_oid));
    DataObjectFormat {
        object_reference: format!("#{reference_id}"),
        description: None,
        object_identifier: oid.map(|o| ObjectIdentifier::oid_as_urn(&o)),
        mime_type: mime_type.map(str::to_string),
        encoding: encoding.map(str::to_string),
    }
}

fn ds_object(
    ds: &DsNames,
    id: &str,
    mime: Option<&str>,
    encoding: Option<&str>,
    content: &str,
) -> String {
    let mut s = format!("<{}", ds.q("Object"));
    if let Some(e) = encoding {
        s.push_str(&format!(" Encoding=\"{}\"", esc_attr(e)));
    }
    s.push_str(&format!(" Id=\"{}\"", esc_attr(id)));
    if let Some(m) = mime {
        s.push_str(&format!(" MimeType=\"{}\"", esc_attr(m)));
    }
    s.push('>');
    s.push_str(content);
    s.push_str(&format!("</{}>", ds.q("Object")));
    s
}

fn signed_props(
    mp: &MultiParams,
    cert: &[u8],
    baseline: bool,
    dofs: Vec<DataObjectFormat>,
) -> afirma_core::Result<SignedProps> {
    let policy = props::policy_from_params(&mp.p)?;
    Ok(SignedProps {
        baseline,
        signing_time: util::xades_time(&util::now()),
        cert_der: cert.to_vec(),
        cert_digest_uri: mp.digest_uri.clone(),
        policy: policy.map(PolicySpec::Explicit).unwrap_or(PolicySpec::None),
        place: props::place_from_params(&mp.p),
        roles: props::roles_from_params(&mp.p),
        data_object_formats: dofs,
        commitments: vec![],
    })
}

/// `KeyInfo`, método de canonicalización y referencia a `KeyInfo` según
/// `includeOnlySignningCertificate` (jxades o AutoFirma).
fn key_info_setup(
    mp: &MultiParams,
    ds: &DsNames,
    key: &dyn SigningKey,
    sig_prefix: &str,
) -> (String, String, bool) {
    let id = format!("{sig_prefix}-KeyInfo");
    if mp.only_cert {
        (
            props::render_jxades_key_info(ds, &id, key.certificate()),
            C14N_10.to_string(),
            true,
        )
    } else {
        let ki = props::render_key_info(
            ds,
            &id,
            &KeyInfoOptions {
                certs: key_info_certs(key, false),
                key_value: mp.key_value,
                key_name: mp.key_name,
                issuer_serial: mp.issuer_serial,
            },
        );
        (ki, mp.c14n.clone(), !mp.keep_ki_unsigned)
    }
}

/// Cofirma XAdES.
pub fn cosign(
    sign: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    extra: &ExtraParams,
    resolver: &dyn dsig::Resolver,
) -> afirma_core::Result<Vec<u8>> {
    let doc = info::parse(sign).ok_or_else(|| {
        AfirmaError::invalid_signature_format("No se ha podido cargar el documento XML de firmas")
    })?;
    if !info::is_sign_doc(&doc) {
        return Err(AfirmaError::invalid_signature_format(
            "No se ha indicado una firma XAdES para cofirmar",
        ));
    }
    let baseline_sig = info::check_compatibility(&doc)?;
    let mut mp = multi_params(extra, algorithm, key, baseline_sig)?;
    mp.p.remove("xadesNamespace");
    mp.p.remove("signedPropertiesTypeUrl");
    let output_enc_param = mp.p.get("outputXmlEncoding").map(str::to_string);
    let oid = mp.p.get("contentTypeOid").map(str::to_string);
    let mut mime_type = mp.p.get("mimeType").map(str::to_string);
    let mut encoding = encoding_param(&mp.p)?;

    // Envoltorio si la raíz es una firma.
    let root0 = doc.document_element().expect("raíz");
    let wrapped = local(&doc, root0) == "Signature";
    let declared = doc.xml_decl.as_ref().and_then(|d| d.encoding.clone());
    let output_encoding = output_enc_param
        .clone()
        .or_else(|| if wrapped { None } else { declared.clone() })
        .unwrap_or_else(|| "UTF-8".into());
    let base_text = if wrapped {
        format!(
            "<AFIRMA Id=\"AfirmaRoot-{}\">{}</AFIRMA>",
            uuid_v4(),
            doc.node_source(root0)
        )
    } else {
        doc.source().to_string()
    };
    let doc = Document::parse(&base_text)
        .map_err(|e| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, e.to_string()))?;
    let root = doc.document_element().expect("raíz");
    let sigs: Vec<NodeId> = doc.find_descendants(root, DSIG_NS, "Signature");
    check_archive(&doc, &sigs, &mp.p, true)?;
    check_digest_uri(&mp.digest_uri)?;

    let first = *sigs
        .first()
        .ok_or_else(|| AfirmaError::invalid_signature_format("No se ha encontrado la firma"))?;
    let sp_ref = info::signed_properties_reference(&doc, first).ok_or_else(|| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            "No se ha encontrado la referencia a las propiedades firmadas",
        )
    })?;
    let sp_type = doc
        .element(sp_ref)
        .and_then(|e| e.attr("Type"))
        .filter(|t| !t.is_empty())
        .unwrap_or(SIGNED_PROPERTIES_TYPE)
        .to_string();
    let sp_el = info::signed_properties(&doc, first).ok_or_else(|| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            "No se han encontrado los atributos firmados de la firma original",
        )
    })?;
    let xades_ns = doc
        .element(sp_el)
        .and_then(|e| e.ns.clone())
        .unwrap_or_else(|| NS_XADES_132.to_string());
    let baseline = mp.p.get("profile") == Some("baseline") && is_baseline_compatible(&xades_ns);
    let xmlsig_prefix = doc
        .element(first)
        .and_then(|e| e.prefix.clone())
        .unwrap_or_default();
    let ds = DsNames::new(&xmlsig_prefix);

    let mut refs: Vec<ReferenceSpec> = Vec::new();
    let mut dofs: Vec<DataObjectFormat> = Vec::new();
    let mut new_object: Option<String> = None;
    let mut is_enveloping = false;
    for r in info::data_references(&doc, first) {
        let mut transforms = copy_transforms(&doc, r, &xmlsig_prefix)?;
        let re = doc.element(r).expect("elemento");
        let reference_id = if re
            .attr("Id")
            .is_some_and(|i| i.starts_with("StyleReference-"))
        {
            format!("StyleReference-{}", uuid_v4())
        } else {
            format!("Reference-{}", uuid_v4())
        };
        let uri = re.attr("URI").unwrap_or("").to_string();
        let ty = re
            .attr("Type")
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        if ty.as_deref() == Some(dsig::MANIFEST_TYPE) {
            let Some(mid) = uri.strip_prefix('#') else {
                return Err(AfirmaError::new(
                    codes::UNKWNON_XML_SIGNING_ERROR,
                    "La URI de la firma original que referencia al manifest debe ser local (empezar por '#')",
                ));
            };
            let manifest = find_element_by_id(&doc, mid, first, false).ok_or_else(|| {
                AfirmaError::new(
                    codes::UNKWNON_XML_SIGNING_ERROR,
                    "No se encontro el manifest dentro de la firma",
                )
            })?;
            let mut copied: Vec<DataObjectFormat> = Vec::new();
            if let Some(sdop) = doc
                .child_elements(sp_el)
                .find(|&c| local(&doc, c) == "SignedDataObjectProperties")
            {
                let ns = doc
                    .element(sdop)
                    .and_then(|e| e.ns.clone())
                    .unwrap_or_default();
                for d in doc.find_descendants(sdop, &ns, "DataObjectFormat") {
                    copied.push(parse_data_object_format(&doc, d));
                }
            }
            let new_manifest_id = format!("Manifest-{}", uuid_v4());
            let mut changes = vec![(manifest, new_manifest_id.clone())];
            let mns = doc
                .element(manifest)
                .and_then(|e| e.ns.clone())
                .unwrap_or_default();
            for mr in doc.find_descendants(manifest, &mns, "Reference") {
                let old = doc
                    .element(mr)
                    .and_then(|e| e.attr("Id"))
                    .unwrap_or("")
                    .to_string();
                let new_id = format!("Reference-{}", uuid_v4());
                for d in copied.iter_mut() {
                    if d.object_reference == format!("#{old}") {
                        d.object_reference = format!("#{new_id}");
                    }
                }
                changes.push((mr, new_id));
            }
            let manifest_text = splice::element_with_ids(&doc, manifest, &changes);
            new_object = Some(ds_object(
                &ds,
                &format!("ManifestObject-{}", uuid_v4()),
                mime_type.as_deref(),
                encoding.as_deref(),
                &manifest_text,
            ));
            let mut spec = ReferenceSpec::new(format!("#{new_manifest_id}"), &mp.digest_uri);
            spec.id = Some(reference_id);
            spec.ty = ty;
            spec.transforms = transforms;
            refs.push(spec);
            dofs.extend(copied);
            continue;
        }
        if uri.is_empty() {
            if mime_type.is_none() {
                mime_type = Some("text/xml".into());
            }
            let has_xpath = transforms
                .iter()
                .any(|t| matches!(t, TransformSpec::XPath(e) if e.contains("Signature")));
            if !has_xpath {
                match mp.p.get("allowXadesEnvelopedWithoutXPath") {
                    None => {
                        return Err(AfirmaError::needs_confirmation(
                            codes::XPATH_NOT_FOUND,
                            "Se ha encontrado una firma sin transformacion XPath que permita cofirmas",
                            "xPathNotFound",
                            "allowXadesEnvelopedWithoutXPath",
                            ConfirmEffect::SetParamTrue,
                        ));
                    }
                    Some(v) if !v.eq_ignore_ascii_case("true") => {
                        return Err(AfirmaError::from_code(codes::XPATH_NOT_FOUND));
                    }
                    Some(_) => {
                        let name = if xmlsig_prefix.is_empty() {
                            "Signature".to_string()
                        } else {
                            format!("{xmlsig_prefix}:Signature")
                        };
                        transforms.push(TransformSpec::XPath(format!(
                            "not(ancestor-or-self::{name})"
                        )));
                    }
                }
            }
            let mut spec = ReferenceSpec::new("", &mp.digest_uri);
            spec.id = Some(reference_id.clone());
            spec.ty = Some(dsig::OBJECT_TYPE.into());
            spec.transforms = transforms;
            refs.push(spec);
        } else {
            let data_id = uri.strip_prefix('#').unwrap_or(&uri).to_string();
            let mut found: Option<NodeId> = None;
            if doc.element(root).and_then(|e| e.attr("Id")) == Some(data_id.as_str()) {
                found = Some(root);
            } else {
                for &c in doc.children(root).iter().rev() {
                    if doc.element(c).and_then(|e| e.attr("Id")) == Some(data_id.as_str()) {
                        found = Some(c);
                        break;
                    }
                    if local(&doc, c) == "Signature"
                        && let Some(&sc) = doc.children(c).iter().rev().find(|&&sc| {
                            doc.element(sc).and_then(|e| e.attr("Id")) == Some(data_id.as_str())
                        }) {
                            found = Some(sc);
                            break;
                        }
                }
            }
            if let Some(f) = found {
                let fe = doc.element(f).expect("elemento");
                if mime_type.is_none() {
                    mime_type = Some(fe.attr("MimeType").unwrap_or("").to_string());
                }
                if encoding.is_none() {
                    encoding = Some(fe.attr("Encoding").unwrap_or("").to_string());
                }
            }
            if doc
                .child_elements(first)
                .any(|c| doc.element(c).and_then(|e| e.attr("Id")) == Some(data_id.as_str()))
            {
                is_enveloping = true;
            }
            match found {
                Some(f) if is_enveloping => {
                    if afirma_core::policy::is_age_policy_configured(mp.p.get("policyIdentifier")) {
                        match mp.p.get("avoidAGEPolicyIncompatibilities") {
                            None => {
                                return Err(AfirmaError::signature_policy_incompatibility(
                                    "La politica de la AGE no soporta la cofirma XAdES Enveloping",
                                    afirma_core::constants::OP_COSIGN,
                                ));
                            }
                            Some(v) if v.eq_ignore_ascii_case("true") => {
                                for k in [
                                    "policyIdentifier",
                                    "policyIdentifierHash",
                                    "policyIdentifierHashAlgorithm",
                                    "policyDescription",
                                    "policyQualifier",
                                ] {
                                    mp.p.remove(k);
                                }
                            }
                            Some(_) => {
                                return Err(AfirmaError::new(
                                    codes::SIGNING_WITH_POLICY_INCOMPATIBILITY,
                                    "La politica de la AGE no soporta la cofirma XAdES Enveloping",
                                ));
                            }
                        }
                    }
                    let content = doc
                        .children(f)
                        .first()
                        .map(|&c| doc.node_source(c).to_string())
                        .unwrap_or_default();
                    let object_id = format!("Object-{}", uuid_v4());
                    new_object = Some(ds_object(
                        &ds,
                        &object_id,
                        mime_type.as_deref(),
                        encoding.as_deref(),
                        &content,
                    ));
                    let mut spec = ReferenceSpec::new(format!("#{object_id}"), &mp.digest_uri);
                    spec.id = Some(reference_id.clone());
                    spec.ty = ty;
                    spec.transforms = transforms;
                    refs.push(spec);
                }
                _ => {
                    let mut spec = ReferenceSpec::new(uri.clone(), &mp.digest_uri);
                    spec.id = Some(reference_id.clone());
                    spec.ty = ty;
                    spec.transforms = transforms;
                    refs.push(spec);
                }
            }
        }
        dofs.push(cosign_dof(
            &reference_id,
            mime_type.as_deref(),
            oid.as_deref(),
            encoding.as_deref(),
        ));
    }

    let sig_prefix = format!("Signature-{}", uuid_v4());
    let (key_info, c14n_uri, ki_ref) = key_info_setup(&mp, &ds, key, &sig_prefix);
    let props = signed_props(&mp, key.certificate(), baseline, dofs)?;
    let ds_in_scope = doc.lookup_namespace(root, Some(&xmlsig_prefix)).as_deref() == Some(DSIG_NS)
        && !xmlsig_prefix.is_empty();
    let assembly = Assembly {
        ds: ds.clone(),
        xades_prefix: XADES_PREFIX.into(),
        xades_ns,
        sig_prefix,
        c14n_uri,
        sig_method_uri: mp.sig_uri.clone(),
        digest_uri: mp.digest_uri.clone(),
        signed_props_type: sp_type,
        data_refs: refs,
        objects_before: new_object.into_iter().collect(),
        props,
        key_info,
        keyinfo_reference: ki_ref,
        ds_in_scope,
        xades_in_scope: false,
    };
    let mut ph = Placeholders::new();
    let sig_text = assembly.render(&mut ph);
    let full = splice::insert_last_child(&doc, root, &sig_text);
    let signed = dsig::complete(
        full,
        &ph,
        &dsig::Completion {
            key,
            algorithm: mp.sig_alg,
            signature_id: &assembly.signature_id(),
            resolver,
            verify: !mp.only_cert,
            error_code: codes::UNKWNON_XML_SIGNING_ERROR,
        },
    )?;
    let out = if wrapped {
        splice::finish(&signed, &output_encoding)
    } else {
        let final_doc = Document::parse(&signed)
            .map_err(|e| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, e.to_string()))?;
        splice::finish_preserving(&final_doc, &signed, &output_encoding)
    };
    out.map_err(|m| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, m))
}

/// CN del primer certificado de una firma (`AOUtil.getCN`).
fn first_cert_cn(doc: &Document, sig: NodeId) -> Option<String> {
    let c = doc
        .find_descendants(sig, DSIG_NS, "X509Certificate")
        .into_iter()
        .next()?;
    let der = util::b64_decode(&doc.text_content(c))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(afirma_core::aoutil::get_cn(&crate::dn::java_name(
        cert.subject(),
    )))
}

/// Contrafirma XAdES.
pub fn countersign(
    sign: &[u8],
    algorithm: &str,
    target: &CounterSignTarget,
    key: &dyn SigningKey,
    extra: &ExtraParams,
) -> afirma_core::Result<Vec<u8>> {
    let doc = info::parse(sign).ok_or_else(|| {
        AfirmaError::invalid_signature_format("No se ha podido cargar el documento XML de firmas")
    })?;
    let baseline_sig = info::check_compatibility(&doc)?;
    if !info::is_sign_doc(&doc) {
        return Err(AfirmaError::invalid_signature_format(
            "No se ha indicado una firma XAdES para contrafirmar",
        ));
    }
    let mp = multi_params(extra, algorithm, key, baseline_sig)?;
    let declared = doc.xml_decl.as_ref().and_then(|d| d.encoding.clone());
    let output_encoding =
        mp.p.get("outputXmlEncoding")
            .map(str::to_string)
            .or_else(|| declared.clone())
            .unwrap_or_else(|| "UTF-8".into());
    let root0 = doc.document_element().expect("raíz");
    let wrapped = local(&doc, root0) == "Signature";
    // Codificación detectada del documento (Document.getInputEncoding()).
    let input_encoding = if wrapped {
        None
    } else {
        Some(declared.clone().unwrap_or_else(|| "UTF-8".into()))
    };
    let mut text = if wrapped {
        format!(
            "<AFIRMA Id=\"AfirmaRoot-{}\">{}</AFIRMA>",
            uuid_v4(),
            doc.node_source(root0)
        )
    } else {
        doc.source().to_string()
    };
    let cur = Document::parse(&text)
        .map_err(|e| AfirmaError::new(codes::INTERNAL_XML_SIGNING_ERROR, e.to_string()))?;
    let root = cur.document_element().expect("raíz");
    let sigs: Vec<NodeId> = cur.find_descendants(root, DSIG_NS, "Signature");
    check_archive(&cur, &sigs, &mp.p, false)?;
    let mut targets: Vec<NodeId> = match target {
        CounterSignTarget::Tree => sigs.clone(),
        CounterSignTarget::Leafs => sigs
            .iter()
            .copied()
            .filter(|&s| cur.find_descendants(s, DSIG_NS, "Signature").is_empty())
            .collect(),
        CounterSignTarget::Nodes(idx) => {
            let mut out = Vec::new();
            for &i in idx {
                let s = *sigs.get(i).ok_or_else(|| {
                    AfirmaError::new(
                        codes::INVALID_COUNTERSIGNATURE_INDEX,
                        "Posicion de nodo no valida.",
                    )
                })?;
                if !out.contains(&s) {
                    out.push(s);
                }
            }
            out
        }
        CounterSignTarget::Signers(names) => sigs
            .iter()
            .copied()
            .filter(|&s| first_cert_cn(&cur, s).is_some_and(|cn| names.contains(&cn)))
            .collect(),
    };
    // Se procesan de la última a la primera: así la posición de inicio de las
    // firmas pendientes no cambia al insertar contrafirmas.
    targets.sort_by_key(|&s| std::cmp::Reverse(cur.range(s).start));
    let starts: Vec<usize> = targets.iter().map(|&s| cur.range(s).start).collect();
    for start in starts {
        text = countersign_one(text, start, &mp, key, input_encoding.as_deref())?;
    }
    if wrapped {
        let d = Document::parse(&text)
            .map_err(|e| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, e.to_string()))?;
        let first = d
            .find_descendants(d.root(), DSIG_NS, "Signature")
            .into_iter()
            .next()
            .expect("firma");
        text = d.node_source(first).to_string();
        return splice::finish(&text, &output_encoding)
            .map_err(|m| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, m));
    }
    let d = Document::parse(&text)
        .map_err(|e| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, e.to_string()))?;
    splice::finish_preserving(&d, &text, &output_encoding)
        .map_err(|m| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, m))
}

fn reparse(text: &str) -> afirma_core::Result<Document> {
    Document::parse(text)
        .map_err(|e| AfirmaError::new(codes::UNKWNON_XML_SIGNING_ERROR, e.to_string()))
}

fn signature_at(doc: &Document, start: usize) -> afirma_core::Result<NodeId> {
    doc.find_descendants(doc.root(), DSIG_NS, "Signature")
        .into_iter()
        .find(|&s| doc.range(s).start == start)
        .ok_or_else(|| {
            AfirmaError::new(
                codes::UNKWNON_XML_SIGNING_ERROR,
                "No se ha podido localizar la firma a contrafirmar",
            )
        })
}

fn first_desc_local(doc: &Document, from: NodeId, name: &str) -> Option<NodeId> {
    doc.descendants(from)
        .into_iter()
        .skip(1)
        .find(|&n| doc.element(n).is_some_and(|e| e.local == name))
}

/// `XAdESCounterSigner.cs`: contrafirma la firma que empieza en `start`.
fn countersign_one(
    mut text: String,
    start: usize,
    mp: &MultiParams,
    key: &dyn SigningKey,
    input_encoding: Option<&str>,
) -> afirma_core::Result<String> {
    let doc = reparse(&text)?;
    let sig = signature_at(&doc, start)?;
    let sp_ref = info::signed_properties_reference(&doc, sig).ok_or_else(|| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            "No se han encontrado los atributos firmados de la firma original",
        )
    })?;
    let sp = info::signed_properties(&doc, sig).ok_or_else(|| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            "No se han encontrado los atributos firmados de la firma original",
        )
    })?;
    let mut xades_prefix = doc
        .element(sp)
        .and_then(|e| e.prefix.clone())
        .unwrap_or_default();
    let xades_ns = doc
        .element(sp)
        .and_then(|e| e.ns.clone())
        .unwrap_or_default();
    let sp_type = doc
        .element(sp_ref)
        .and_then(|e| e.attr("Type"))
        .unwrap_or("")
        .to_string();

    // Reubicación de UnsignedProperties/UnsignedSignatureProperties al final.
    let up = first_desc_local(&doc, sig, "UnsignedProperties");
    let mut usp_exists = false;
    if let Some(up) = up {
        xades_prefix = doc
            .element(up)
            .and_then(|e| e.prefix.clone())
            .unwrap_or_default();
        if let Some(usp) = first_desc_local(&doc, up, "UnsignedSignatureProperties") {
            xades_prefix = doc
                .element(usp)
                .and_then(|e| e.prefix.clone())
                .unwrap_or_default();
            usp_exists = true;
            text = splice::move_to_last_child(&doc, usp);
        }
        let d2 = reparse(&text)?;
        let s2 = signature_at(&d2, start)?;
        if let Some(up2) = first_desc_local(&d2, s2, "UnsignedProperties") {
            text = splice::move_to_last_child(&d2, up2);
        }
    }
    let doc = reparse(&text)?;
    let sig = signature_at(&doc, start)?;
    let qn = |l: &str| {
        if xades_prefix.is_empty() {
            l.to_string()
        } else {
            format!("{xades_prefix}:{l}")
        }
    };
    let sv = doc
        .find_descendants(sig, DSIG_NS, "SignatureValue")
        .into_iter()
        .next()
        .ok_or_else(|| {
            AfirmaError::new(
                codes::UNKWNON_XML_SIGNING_ERROR,
                "La firma no tiene SignatureValue",
            )
        })?;
    let sv_id = doc
        .element(sv)
        .and_then(|e| e.attr("Id"))
        .unwrap_or("")
        .to_string();

    if C14n::from_uri(&mp.c14n).is_none() {
        return Err(AfirmaError::new(
            codes::INTERNAL_XML_SIGNING_ERROR,
            "No se ha podido realizar la contrafirma",
        ));
    }
    check_digest_uri(&mp.digest_uri)?;
    let reference_id = format!("Reference-{}", uuid_v4());
    let mut r = ReferenceSpec::new(format!("#{sv_id}"), &mp.digest_uri);
    r.id = Some(reference_id.clone());
    if xades_ns != NS_XADES_111 && xades_ns != NS_XADES_122 {
        r.ty = Some(COUNTERSIGNED_TYPE.into());
    }
    r.transforms = vec![TransformSpec::Plain(mp.c14n.clone())];
    let baseline = mp.p.get("profile") == Some("baseline") && is_baseline_compatible(&xades_ns);
    let dofs = if baseline {
        vec![]
    } else {
        vec![DataObjectFormat {
            object_reference: format!("#{reference_id}"),
            description: None,
            object_identifier: Some(ObjectIdentifier::oid_as_urn("1.2.840.10003.5.109.10")),
            mime_type: Some("text/xml".into()),
            encoding: input_encoding.map(str::to_string),
        }]
    };
    let ds = DsNames::new(DS_PREFIX);
    let sig_prefix = format!("Signature-{}", uuid_v4());
    let (key_info, c14n_uri, ki_ref) = key_info_setup(mp, &ds, key, &sig_prefix);
    let props = signed_props(mp, key.certificate(), baseline, dofs)?;

    // Punto de inserción y elementos a crear.
    let up = first_desc_local(&doc, sig, "UnsignedProperties");
    let usp = up.and_then(|u| first_desc_local(&doc, u, "UnsignedSignatureProperties"));
    let qp = first_desc_local(&doc, sig, "QualifyingProperties").ok_or_else(|| {
        AfirmaError::new(
            codes::UNKWNON_XML_SIGNING_ERROR,
            "No se encuentra QualifyingProperties",
        )
    })?;
    let (parent, wrap_open, wrap_close) = match (up, usp, usp_exists) {
        (Some(_), Some(usp), true) => (
            usp,
            format!("<{}>", qn("CounterSignature")),
            format!("</{}>", qn("CounterSignature")),
        ),
        (Some(up), _, _) => (
            up,
            format!(
                "<{}><{}>",
                qn("UnsignedSignatureProperties"),
                qn("CounterSignature")
            ),
            format!(
                "</{}></{}>",
                qn("CounterSignature"),
                qn("UnsignedSignatureProperties")
            ),
        ),
        (None, _, _) => (
            qp,
            format!(
                "<{}><{}><{}>",
                qn("UnsignedProperties"),
                qn("UnsignedSignatureProperties"),
                qn("CounterSignature")
            ),
            format!(
                "</{}></{}></{}>",
                qn("CounterSignature"),
                qn("UnsignedSignatureProperties"),
                qn("UnsignedProperties")
            ),
        ),
    };
    let ds_in_scope = doc.lookup_namespace(parent, Some(DS_PREFIX)).as_deref() == Some(DSIG_NS);
    let xades_in_scope = !xades_prefix.is_empty()
        && doc.lookup_namespace(parent, Some(&xades_prefix)).as_deref() == Some(xades_ns.as_str());
    let assembly = Assembly {
        ds: ds.clone(),
        xades_prefix: if xades_prefix.is_empty() {
            XADES_PREFIX.into()
        } else {
            xades_prefix.clone()
        },
        xades_ns,
        sig_prefix,
        c14n_uri,
        sig_method_uri: mp.sig_uri.clone(),
        digest_uri: mp.digest_uri.clone(),
        signed_props_type: sp_type,
        data_refs: vec![r],
        objects_before: vec![],
        props,
        key_info,
        keyinfo_reference: ki_ref,
        ds_in_scope,
        xades_in_scope,
    };
    let mut ph = Placeholders::new();
    let sig_text = assembly.render(&mut ph);
    let full =
        splice::insert_last_child(&doc, parent, &format!("{wrap_open}{sig_text}{wrap_close}"));
    dsig::complete(
        full,
        &ph,
        &dsig::Completion {
            key,
            algorithm: mp.sig_alg,
            signature_id: &assembly.signature_id(),
            resolver: &dsig::NoResolver,
            verify: !mp.only_cert,
            error_code: codes::UNKWNON_XML_SIGNING_ERROR,
        },
    )
}
