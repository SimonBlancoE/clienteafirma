//! Firmador OOXML (`AOOOXMLSigner`): firma de paquetes Office Open XML
//! (ECMA-376 parte 2) con XAdES-EPES de política implícita en
//! `_xmlsignatures/sig-<uuid>.xml`, objetos `idPackageObject` (Manifest de
//! partes con la transformada de relaciones) e `idOfficeObject`
//! (`SignatureInfoV1`/`SignatureInfoV2`).

use afirma_core::error::{AfirmaError, codes};
use afirma_core::extra_params::ExtraParams;
use afirma_core::key::SigningKey;
use afirma_core::signer::{CounterSignTarget, SignInfo, Signer, SignersTree};

use super::{ZipBuilder, ZipEntry, check_size, read_zip};
use crate::c14n::C14N_10;
use crate::dom::Document;
use crate::dsig::{self, DsNames, External, Placeholders, ReferenceSpec, TransformSpec};
use crate::splice;
use crate::util::{esc_attr, esc_text, uuid_v4};
use crate::xades::props::{self, Place, PolicySpec, SignedProps};

pub const FORMAT_OOXML: &str = "OOXML (Office Open XML)";
const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const RELS_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const MS_DIGSIG_NS: &str = "http://schemas.microsoft.com/office/2006/digsig";
const RELS_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.relationships+xml";
const SIGNATURE_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";
const ORIGIN_CONTENT_TYPE: &str = "application/vnd.openxmlformats-package.digital-signature-origin";
const ORIGIN_REL_TYPE: &str = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
const SIGNATURE_REL_TYPE: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";

const EXCLUDED_RELATIONSHIPS: &[&str] = &[
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
    "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin",
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps",
];

/// Directorios de contenido firmados. Java usa `word`, `excel`, `xl` y
/// `powerpoint` (las presentaciones guardan sus partes en `ppt/`, que Java no
/// firma); aquí se añade `ppt` (desviación documentada).
const CONTENT_DIRS: &[&str] = &["word", "excel", "xl", "powerpoint", "ppt"];

/// Datos del entorno gráfico de `SignatureInfoV1` (Java los obtiene de AWT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenInfo {
    pub monitors: u32,
    pub width: u32,
    pub height: u32,
    pub color_depth: u32,
}

impl Default for ScreenInfo {
    fn default() -> Self {
        ScreenInfo {
            monitors: 1,
            width: 1920,
            height: 1080,
            color_depth: 32,
        }
    }
}

/// Firmador OOXML.
#[derive(Default)]
pub struct OoxmlSigner {
    pub screen: ScreenInfo,
}

impl OoxmlSigner {
    pub fn new() -> Self {
        Self::default()
    }
}

fn has_entry(names: &[String], a: &str, b: &str) -> bool {
    names.iter().any(|n| n == a || n == b)
}

/// `isValidDataFile`: ZIP con `[Content_Types].xml`, `_rels/.rels`,
/// `docProps/app.xml` y `docProps/core.xml`.
pub fn is_ooxml(data: &[u8]) -> bool {
    if !crate::mime::is_zip(data) {
        return false;
    }
    let Some(names) = crate::mime::zip_names(data) else {
        return false;
    };
    names.iter().any(|n| n == "[Content_Types].xml")
        && has_entry(&names, "_rels/.rels", "_rels\\.rels")
        && has_entry(&names, "docProps/app.xml", "docProps\\app.xml")
        && has_entry(&names, "docProps/core.xml", "docProps\\core.xml")
}

/// Relación de un `.rels`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Relationship {
    id: String,
    ty: String,
    target: String,
}

/// `RelationshipsParser` (tolerando nodos de espacio en blanco, desviación).
fn parse_relationships(data: &[u8]) -> Option<Vec<Relationship>> {
    let (doc, _) = Document::parse_bytes(data).ok()?;
    let root = doc.document_element()?;
    let re = doc.element(root)?;
    if re.qname() != "Relationships" || !re.ns_decls.iter().any(|d| d.prefix.is_none() && d.uri == RELS_NS) {
        return None;
    }
    let mut out = Vec::new();
    for &c in doc.children(root) {
        match doc.element(c) {
            Some(e) => {
                if e.qname() != "Relationship" {
                    return None;
                }
                out.push(Relationship {
                    id: e.attr("Id")?.to_string(),
                    ty: e.attr("Type")?.to_string(),
                    target: e.attr("Target")?.to_string(),
                });
            }
            None => {
                if !doc.text_content(c).trim().is_empty() {
                    return None;
                }
            }
        }
    }
    Some(out)
}

fn entry<'a>(entries: &'a [ZipEntry], a: &str, b: &str) -> Option<&'a ZipEntry> {
    entries
        .iter()
        .find(|e| e.name == a)
        .or_else(|| entries.iter().find(|e| e.name == b))
}

/// XML de las firmas del paquete (`OOXMLUtil.getOOXMLSignatures`).
pub fn ooxml_signatures(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(entries) = read_zip(data, codes::OOXML_DOCUMENT_NEEDED) else {
        return vec![];
    };
    let Some(rels) = entry(&entries, "_rels/.rels", "_rels\\.rels") else {
        return vec![];
    };
    let Some(rels) = parse_relationships(&rels.data) else {
        return vec![];
    };
    let Some(origin) = rels.iter().find(|r| r.ty == ORIGIN_REL_TYPE) else {
        return vec![];
    };
    if origin.target.len() < 15 {
        return vec![];
    }
    let (middle, name) = origin.target.split_at(15);
    let Some(srels) = entry(
        &entries,
        &format!("{middle}_rels/{name}.rels"),
        &format!("{middle}_rels\\{name}.rels"),
    ) else {
        return vec![];
    };
    let Some(srels) = parse_relationships(&srels.data) else {
        return vec![];
    };
    let mut out = Vec::new();
    for r in srels.iter().filter(|r| r.ty == SIGNATURE_REL_TYPE) {
        match entry(
            &entries,
            &format!("_xmlsignatures/{}", r.target),
            &format!("_xmlsignatures\\{}", r.target),
        ) {
            Some(e) => out.push(e.data.clone()),
            None => return vec![],
        }
    }
    out
}

/// Gestor de tipos de contenido (`ContentTypeManager`).
struct ContentTypes {
    defaults: Vec<(String, String)>,
    overrides: Vec<(String, String)>,
}

impl ContentTypes {
    fn parse(data: &[u8]) -> Option<ContentTypes> {
        let (doc, _) = Document::parse_bytes(data).ok()?;
        let root = doc.document_element()?;
        let mut ct = ContentTypes {
            defaults: vec![],
            overrides: vec![],
        };
        for c in doc.child_elements(root) {
            let e = doc.element(c)?;
            match e.qname().as_str() {
                "Default" => {
                    if let (Some(x), Some(t)) = (e.attr("Extension"), e.attr("ContentType")) {
                        ct.defaults.push((x.to_string(), t.to_string()));
                    }
                }
                "Override" => {
                    if let (Some(p), Some(t)) = (e.attr("PartName"), e.attr("ContentType")) {
                        ct.overrides.push((p.to_string(), t.to_string()));
                    }
                }
                _ => {}
            }
        }
        Some(ct)
    }

    fn content_type(&self, part: &str) -> Option<String> {
        let name = if part.starts_with('/') {
            part.to_string()
        } else {
            format!("/{part}")
        };
        if let Some((_, t)) = self.overrides.iter().rev().find(|(p, _)| *p == name) {
            return Some(t.clone());
        }
        let dot = name.rfind('.')?;
        if dot == name.len() - 1 {
            return None;
        }
        let ext = &name[dot + 1..];
        self.defaults
            .iter()
            .rev()
            .find(|(x, _)| x == ext)
            .map(|(_, t)| t.clone())
    }
}

/// `OOXMLURIDereferencer`: URL decodificada, sin `/` inicial ni consulta.
fn part_name(uri: &str) -> String {
    let mut bytes = Vec::new();
    let b = uri.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => bytes.push(b' '),
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&uri[i + 1..i + 3], 16) {
                Ok(v) => {
                    bytes.push(v);
                    i += 2;
                }
                Err(_) => bytes.push(b'%'),
            },
            c => bytes.push(c),
        }
        i += 1;
    }
    let s = String::from_utf8_lossy(&bytes).into_owned();
    let s = s.strip_prefix('/').unwrap_or(&s).to_string();
    match s.find('?') {
        Some(q) => s[..q].to_string(),
        None => s,
    }
}

/// Resolutor de las partes del paquete original.
pub fn package_resolver(entries: &[ZipEntry]) -> impl Fn(&str) -> Option<External> + '_ {
    move |uri: &str| {
        let name = part_name(uri);
        entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| External::Octets(e.data.clone()))
    }
}

/// `yyyy-MM-dd'T'hh:mm:ss'Z'` en hora local de 12 horas (como Java).
fn signature_time_value() -> String {
    chrono::Local::now().format("%Y-%m-%dT%I:%M:%SZ").to_string()
}

/// Nombre de la parte destino de una relación interna (`Target` relativo a
/// la carpeta de la parte origen del fichero `.rels`).
fn relationship_target(rels_name: &str, target: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !target.starts_with('/') {
        // `ppt/_rels/presentation.xml.rels` -> origen `ppt/presentation.xml`.
        let dir = rels_name.rsplit_once("_rels/").map(|(d, _)| d).unwrap_or("");
        parts.extend(dir.split('/').filter(|p| !p.is_empty()));
    }
    for seg in target.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/").replace("%20", " ")
}

fn manifest_references(entries: &[ZipEntry]) -> afirma_core::Result<Vec<ReferenceSpec>> {
    let mut refs: Vec<ReferenceSpec> = Vec::new();
    // Partes destino de relaciones excluidas (`presProps`, `viewProps`...):
    // no se firman, igual que sus relaciones (desviación: Java no firma
    // ninguna parte de `ppt/`).
    let mut excluded_parts: Vec<String> = Vec::new();
    for e in entries.iter().filter(|e| e.name.ends_with(".rels")) {
        let (doc, _) = Document::parse_bytes(&e.data).map_err(|x| {
            AfirmaError::new(
                codes::UNKWNON_OOXML_SIGNING_ERROR,
                format!("Relaciones no validas en {}: {x}", e.name),
            )
        })?;
        let Some(root) = doc.document_element() else {
            continue;
        };
        let mut ids: Vec<String> = Vec::new();
        for el in doc.child_elements(root).filter_map(|c| doc.element(c)) {
            if EXCLUDED_RELATIONSHIPS.contains(&el.attr("Type").unwrap_or("")) {
                if el.attr("TargetMode") != Some("External") {
                    excluded_parts.push(relationship_target(&e.name, el.attr("Target").unwrap_or("")));
                }
            } else {
                ids.push(el.attr("Id").unwrap_or("").to_string());
            }
        }
        let mut r = ReferenceSpec::new(format!("/{}?ContentType={RELS_CONTENT_TYPE}", e.name), SHA256);
        r.transforms = vec![TransformSpec::Relationships(ids), TransformSpec::Plain(C14N_10.into())];
        refs.push(r);
    }
    let ct_entry = entries
        .iter()
        .find(|e| e.name == "[Content_Types].xml")
        .ok_or_else(|| {
            AfirmaError::new(
                codes::UNKWNON_OOXML_SIGNING_ERROR,
                "El documento OOXML es invalido ya que no contiene el fichero [Content_Types].xml",
            )
        })?;
    let ct = ContentTypes::parse(&ct_entry.data)
        .ok_or_else(|| AfirmaError::new(codes::UNKWNON_OOXML_SIGNING_ERROR, "[Content_Types].xml no valido"))?;
    for e in entries {
        if !CONTENT_DIRS.iter().any(|d| e.name.starts_with(d)) || excluded_parts.contains(&e.name) {
            continue;
        }
        if let Some(t) = ct.content_type(&e.name) {
            let uri = format!("/{}?ContentType={t}", e.name);
            if !refs.iter().any(|r| r.uri.as_deref() == Some(uri.as_str())) {
                refs.push(ReferenceSpec::new(uri, SHA256));
            }
        }
    }
    Ok(refs)
}

fn office_object(sig_prefix: &str, p: &ExtraParams, screen: &ScreenInfo, with_cti: bool) -> String {
    let mut v1 = format!("<SignatureInfoV1 xmlns=\"{MS_DIGSIG_NS}\"><SetupID/><SignatureText/><SignatureImage/>");
    if let Some(c) = p.get("signatureComments") {
        v1.push_str(&format!("<SignatureComments>{}</SignatureComments>", esc_text(c)));
    }
    if cfg!(windows) {
        v1.push_str("<WindowsVersion>10.0</WindowsVersion>");
    }
    v1.push_str(&format!(
        "<OfficeVersion>16.0</OfficeVersion><ApplicationVersion>16.0</ApplicationVersion><Monitors>{}</Monitors><HorizontalResolutionElement>{}</HorizontalResolutionElement><VerticalResolutionElement>{}</VerticalResolutionElement><ColorDepth>{}</ColorDepth><SignatureProviderId>{{00000000-0000-0000-0000-000000000000}}</SignatureProviderId><SignatureProviderUrl/><SignatureProviderDetails>9</SignatureProviderDetails>",
        screen.monitors, screen.width, screen.height, screen.color_depth
    ));
    if with_cti {
        v1.push_str("<SignatureType>1</SignatureType>");
    }
    v1.push_str("</SignatureInfoV1>");
    let mut v2 = format!("<SignatureInfoV2 xmlns=\"{MS_DIGSIG_NS}\">");
    if let Some(a) = p.get("signatureAddress1") {
        v2.push_str(&format!("<Address1>{}</Address1>", esc_text(a)));
    }
    if let Some(a) = p.get("signatureAddress2") {
        v2.push_str(&format!("<Address2>{}</Address2>", esc_text(a)));
    }
    v2.push_str("</SignatureInfoV2>");
    format!(
        "<ds:Object Id=\"idOfficeObject\"><ds:SignatureProperties><ds:SignatureProperty Id=\"idOfficeV1Details\" Target=\"#{sig_prefix}\">{v1}{v2}</ds:SignatureProperty></ds:SignatureProperties></ds:Object>"
    )
}

/// XML de la firma OOXML (`OOXMLXAdESSigner.getSignedXML`).
fn signed_xml(
    entries: &[ZipEntry],
    algorithm: &str,
    key: &dyn SigningKey,
    p: &ExtraParams,
    screen: &ScreenInfo,
) -> afirma_core::Result<Vec<u8>> {
    let algorithm = if algorithm.trim().is_empty() {
        crate::xades::DEFAULT_SIGN_ALGO
    } else {
        algorithm
    };
    let (sig_uri, sig_alg) = crate::xades::resolve_algorithm(algorithm, key.key_algorithm()).map_err(|_| {
        AfirmaError::new(
            codes::UNKWNON_OOXML_SIGNING_ERROR,
            format!("Los formatos de firma XML no soportan el algoritmo de firma '{algorithm}'"),
        )
    })?;
    let ds = DsNames::new("ds");
    let sig_prefix = format!("xmldsig-{}", uuid_v4());
    let mut ph = Placeholders::new();
    // idPackageObject
    let mut manifest = String::from("<ds:Manifest>");
    for r in manifest_references(entries)? {
        manifest.push_str(&dsig::render_reference(&ds, &r, &mut ph));
    }
    manifest.push_str("</ds:Manifest>");
    let package_object = format!(
        "<ds:Object Id=\"idPackageObject\">{manifest}<ds:SignatureProperties Id=\"id-signature-time-{}\"><ds:SignatureProperty Id=\"idSignatureTime\" Target=\"#{sig_prefix}\"><mdssi:SignatureTime xmlns:mdssi=\"{}\"><mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format><mdssi:Value>{}</mdssi:Value></mdssi:SignatureTime></ds:SignatureProperty></ds:SignatureProperties></ds:Object>",
        uuid_v4(),
        dsig::MDSSI_NS,
        signature_time_value()
    );
    let ctis = props::commitments_from_params(p, None);
    let office = office_object(&sig_prefix, p, screen, !ctis.is_empty());
    let place = Place {
        city: p.get("signatureProductionCity").map(str::to_string),
        street: None,
        province: p.get("signatureProductionProvince").map(str::to_string),
        postal_code: p.get("signatureProductionPostalCode").map(str::to_string),
        country: p.get("signatureProductionCountry").map(str::to_string),
    };
    let props_spec = SignedProps {
        baseline: false,
        signing_time: crate::util::xades_time(&crate::util::now()),
        cert_der: key.certificate().to_vec(),
        cert_digest_uri: SHA512.into(),
        policy: PolicySpec::Implied,
        place: Some(place),
        roles: p
            .get("signerClaimedRoles")
            .map(|r| vec![r.to_string()])
            .unwrap_or_default(),
        data_object_formats: vec![],
        commitments: ctis,
    };
    let qp = props::render_qualifying_object(&ds, "xd", XADES_NS, &sig_prefix, &props_spec, false);
    let key_info = {
        let mut s = format!("<ds:KeyInfo Id=\"{}-KeyInfo\">", esc_attr(&sig_prefix));
        if let Some(kv) = dsig::render_key_value(&ds, key.certificate()) {
            s.push_str(&kv);
        }
        s.push_str(&dsig::render_x509_data(&ds, &[key.certificate().to_vec()]));
        s.push_str("</ds:KeyInfo>");
        s
    };
    let mut refs = Vec::new();
    for id in ["idPackageObject", "idOfficeObject"] {
        let mut r = ReferenceSpec::new(format!("#{id}"), SHA512);
        r.ty = Some(dsig::OBJECT_TYPE.into());
        refs.push(r);
    }
    let mut sp = ReferenceSpec::new(format!("#{sig_prefix}-SignedProperties"), SHA512);
    sp.ty = Some(crate::xades::SIGNED_PROPERTIES_TYPE.into());
    sp.transforms = vec![TransformSpec::Plain(C14N_10.into())];
    refs.push(sp);
    refs.push(ReferenceSpec::new(format!("#{sig_prefix}-KeyInfo"), SHA512));
    let mut sig = format!(
        "<ds:Signature xmlns:ds=\"{}\" Id=\"{sig_prefix}-Signature\">",
        dsig::DSIG_NS
    );
    sig.push_str(&dsig::render_signed_info(&ds, C14N_10, &sig_uri, &refs, &mut ph));
    sig.push_str(&format!(
        "<ds:SignatureValue Id=\"{sig_prefix}-SignatureValue\">{}</ds:SignatureValue>",
        ph.signature_value()
    ));
    sig.push_str(&key_info);
    sig.push_str(&package_object);
    sig.push_str(&office);
    sig.push_str(&qp);
    sig.push_str("</ds:Signature>");
    let resolver = package_resolver(entries);
    let signed = dsig::complete(
        sig,
        &ph,
        &dsig::Completion {
            key,
            algorithm: sig_alg,
            signature_id: &format!("{sig_prefix}-Signature"),
            resolver: &resolver,
            verify: false,
            error_code: codes::UNKWNON_OOXML_SIGNING_ERROR,
        },
    )?;
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{signed}").into_bytes())
}

/// Añade un elemento como último hijo de la raíz de un XML.
fn append_to_root(xml: &[u8], ns: &str, element: &str) -> afirma_core::Result<Vec<u8>> {
    let (doc, enc) =
        Document::parse_bytes(xml).map_err(|e| AfirmaError::new(codes::UNKWNON_OOXML_SIGNING_ERROR, e.to_string()))?;
    let root = doc.document_element().expect("raíz");
    let el = if doc.lookup_namespace(root, None).as_deref() == Some(ns) {
        element.to_string()
    } else {
        element.replacen(' ', &format!(" xmlns=\"{ns}\" "), 1)
    };
    let text = splice::insert_last_child(&doc, root, &el);
    Ok(crate::dom::encode(&text, enc))
}

fn root_has(xml: &[u8], name: &str, attr: &str, value: &str) -> bool {
    let Ok((doc, _)) = Document::parse_bytes(xml) else {
        return false;
    };
    let Some(root) = doc.document_element() else {
        return false;
    };
    doc.child_elements(root).any(|c| {
        doc.element(c)
            .is_some_and(|e| e.local == name && e.attr(attr) == Some(value))
    })
}

fn sign_ooxml(
    data: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    p: &ExtraParams,
    screen: &ScreenInfo,
) -> afirma_core::Result<Vec<u8>> {
    check_size(data)?;
    if !is_ooxml(data) {
        return Err(AfirmaError::new(
            codes::OOXML_DOCUMENT_NEEDED,
            "Los datos introducidos no se corresponden con un documento OOXML",
        ));
    }
    let entries = read_zip(data, codes::OOXML_DOCUMENT_NEEDED)?;
    let xml = signed_xml(&entries, algorithm, key, p, screen)?;
    let uuid = uuid_v4();
    let sig_entry = format!("_xmlsignatures/sig-{uuid}.xml");
    let sig_file = format!("sig-{uuid}.xml");
    let mut zb = ZipBuilder::new(codes::UNKWNON_OOXML_SIGNING_ERROR);
    let mut has_origin_rels = false;
    for e in &entries {
        let content = if e.name == "[Content_Types].xml" {
            let mut c = append_to_root(
                &e.data,
                CT_NS,
                &format!("<Override PartName=\"/{sig_entry}\" ContentType=\"{SIGNATURE_CONTENT_TYPE}\"/>"),
            )?;
            if !root_has(&c, "Default", "Extension", "sigs") {
                c = append_to_root(
                    &c,
                    CT_NS,
                    &format!("<Default Extension=\"sigs\" ContentType=\"{ORIGIN_CONTENT_TYPE}\"/>"),
                )?;
            }
            c
        } else if e.name == "_rels/.rels" {
            if root_has(&e.data, "Relationship", "Type", ORIGIN_REL_TYPE) {
                e.data.clone()
            } else {
                append_to_root(
                    &e.data,
                    RELS_NS,
                    &format!(
                        "<Relationship Id=\"rel-id-{}\" Type=\"{ORIGIN_REL_TYPE}\" Target=\"_xmlsignatures/origin.sigs\"/>",
                        uuid_v4()
                    ),
                )?
            }
        } else if e.name.starts_with("_xmlsignatures/_rels/") && e.name.ends_with(".rels") {
            has_origin_rels = true;
            append_to_root(
                &e.data,
                RELS_NS,
                &format!(
                    "<Relationship Id=\"rel-{}\" Type=\"{SIGNATURE_REL_TYPE}\" Target=\"{sig_file}\"/>",
                    uuid_v4()
                ),
            )?
        } else {
            e.data.clone()
        };
        zb.add(&e.name, &content, false, e.is_dir)?;
    }
    if !has_origin_rels {
        let rels = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><Relationships xmlns=\"{RELS_NS}\"><Relationship Id=\"rel-{}\" Type=\"{SIGNATURE_REL_TYPE}\" Target=\"{sig_file}\"/></Relationships>",
            uuid_v4()
        );
        zb.add("_xmlsignatures/_rels/origin.sigs.rels", rels.as_bytes(), false, false)?;
        zb.add("_xmlsignatures/origin.sigs", &[], false, false)?;
    }
    zb.add(&sig_entry, &xml, false, false)?;
    zb.finish()
}

impl Signer for OoxmlSigner {
    fn format_name(&self) -> &'static str {
        FORMAT_OOXML
    }

    fn sign(
        &self,
        data: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        sign_ooxml(data, algorithm, key, extra, &self.screen)
    }

    fn cosign(
        &self,
        _data: Option<&[u8]>,
        sign: &[u8],
        algorithm: &str,
        key: &dyn SigningKey,
        extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        sign_ooxml(sign, algorithm, key, extra, &self.screen)
    }

    fn countersign(
        &self,
        _sign: &[u8],
        _algorithm: &str,
        _target: &CounterSignTarget,
        _key: &dyn SigningKey,
        _extra: &ExtraParams,
    ) -> afirma_core::Result<Vec<u8>> {
        Err(AfirmaError::unsupported(
            "No es posible realizar contrafirmas de ficheros OOXML",
        ))
    }

    fn signers_structure(&self, sign: &[u8], _params: &ExtraParams) -> afirma_core::Result<SignersTree> {
        check_size(sign)?;
        if !self.is_sign(sign, &ExtraParams::new()) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos indicados no son una firma OOXML",
            ));
        }
        let mut tree = SignersTree::default();
        for xml in ooxml_signatures(sign) {
            let t = crate::xades::info::signers_structure(&xml)?;
            if let Some(first) = t.signers.into_iter().next() {
                tree.signers.push(first);
            }
        }
        Ok(tree)
    }

    fn is_sign(&self, data: &[u8], _params: &ExtraParams) -> bool {
        is_ooxml(data) && !ooxml_signatures(data).is_empty()
    }

    fn is_valid_data_file(&self, data: &[u8]) -> bool {
        is_ooxml(data)
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        let in_text = in_text.unwrap_or("");
        let Some(name) = original else {
            return format!("{in_text}.ooxml");
        };
        let lower = name.to_lowercase();
        for ext in [".docx", ".xlsx", ".pptx", ".ppsx"] {
            if lower.ends_with(ext) {
                return format!("{}{in_text}{ext}", &name[..name.len() - 5]);
            }
        }
        format!("{name}{in_text}.ooxml")
    }

    fn get_data(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<Option<Vec<u8>>> {
        if !self.is_sign(sign, params) {
            return Err(AfirmaError::invalid_signature_format(
                "Los datos introducidos no se corresponden con un documento OOXML firmado",
            ));
        }
        Ok(Some(sign.to_vec()))
    }

    fn sign_info(&self, sign: &[u8], params: &ExtraParams) -> afirma_core::Result<SignInfo> {
        if !self.is_sign(sign, params) {
            return Err(AfirmaError::new(
                codes::OOXML_DOCUMENT_NEEDED,
                "Los datos introducidos no se corresponden con un documento OOXML",
            ));
        }
        Ok(SignInfo {
            format: FORMAT_OOXML.into(),
            ..Default::default()
        })
    }
}

/// Valida criptográficamente las firmas OOXML de un paquete (sin
/// equivalente en Java, que no valida OOXML): devuelve, por firma, si es
/// válida y las URI de las referencias del `Manifest` que no coinciden.
pub fn verify_package(package: &[u8]) -> afirma_core::Result<Vec<(bool, Vec<String>)>> {
    let entries = read_zip(package, codes::OOXML_DOCUMENT_NEEDED)?;
    let resolver = package_resolver(&entries);
    let mut out = Vec::new();
    for xml in ooxml_signatures(package) {
        let (doc, _) = Document::parse_bytes(&xml).map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
        let Some(sig) = doc.document_element() else {
            continue;
        };
        let core = dsig::validate_core(&doc, sig, &resolver, None)
            .map_err(|e| AfirmaError::invalid_signature_format(e.to_string()))?;
        let ctx = dsig::RefContext {
            doc: &doc,
            signature: sig,
            resolver: &resolver,
        };
        let mut bad = Vec::new();
        for m in doc.find_descendants(sig, dsig::DSIG_NS, "Manifest") {
            for r in dsig::ds_children(&doc, m, "Reference") {
                if !ctx.check_reference(r).unwrap_or(false) {
                    bad.push(doc.element(r).and_then(|e| e.attr("URI")).unwrap_or("").to_string());
                }
            }
        }
        out.push((core.is_valid() && bad.is_empty(), bad));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_targets() {
        assert_eq!(
            relationship_target("ppt/_rels/presentation.xml.rels", "presProps.xml"),
            "ppt/presProps.xml"
        );
        assert_eq!(
            relationship_target("ppt/slides/_rels/slide1.xml.rels", "../slideLayouts/l1.xml"),
            "ppt/slideLayouts/l1.xml"
        );
        assert_eq!(
            relationship_target("_rels/.rels", "docProps/core.xml"),
            "docProps/core.xml"
        );
        assert_eq!(
            relationship_target("word/_rels/document.xml.rels", "/word/a%20b.xml"),
            "word/a b.xml"
        );
    }

    #[test]
    fn part_names() {
        assert_eq!(
            part_name("/word/document.xml?ContentType=application/x"),
            "word/document.xml"
        );
        assert_eq!(part_name("/a%20b.xml"), "a b.xml");
        assert_eq!(part_name("/_rels/.rels?ContentType=x"), "_rels/.rels");
    }

    #[test]
    fn signed_names() {
        let s = OoxmlSigner::new();
        assert_eq!(s.signed_name(Some("a.DOCX"), Some("_f")), "a_f.docx");
        assert_eq!(s.signed_name(Some("a.txt"), None), "a.txt.ooxml");
    }
}
