//! Validación de firmas PDF (`ValidatePdfSignature`): integridad de cada
//! firma, cambios en formularios, ataques de sombra (PDF Shadow Attack),
//! revisiones no permitidas en documentos certificados y perfil PAdES.

use afirma_core::error::codes;
use afirma_core::validity::{SignValidity, Validity, ValidityError, ko_priority};
use afirma_core::{AfirmaError, ExtraParams};
use lopdf::Object;

use crate::cms;
use crate::pades::errors;
use crate::pades::params::*;
use crate::pdf::doc::{PdfDoc, Rect, SignatureEntry};
use crate::pdf::write::write_object;

/// Perfiles cuya validez se comprueba por completo.
const CHECKED_PROFILES: [&str; 6] = [
    "PAdES-Basic",
    "No reconocido",
    "PAdES-BES",
    "PAdES B-Level",
    "PAdES B-B-Level",
    "PAdES-EPES",
];

fn ko(e: ValidityError) -> SignValidity {
    SignValidity::ko(e)
}

/// Valida las firmas de un PDF. Con `relaxed`, las situaciones que debe
/// decidir el usuario (formulario modificado, sospecha de PSA) se devuelven
/// como error con intervención (`RuntimeConfigNeededException`).
///
/// El primer elemento de la lista es el veredicto.
pub fn validate_pdf(
    pdf: &[u8],
    params: &ExtraParams,
    relaxed: bool,
) -> Result<Vec<SignValidity>, AfirmaError> {
    let password = params
        .get(OWNER_PASSWORD)
        .or_else(|| params.get(USER_PASSWORD));
    let no_sign = || vec![ko(ValidityError::NoSign).with_code(codes::INCOMPATIBLE_SIGNATURE)];
    let Ok(doc) = PdfDoc::open(pdf, password) else {
        return Ok(no_sign());
    };
    let (sigs, total) = doc.signatures();
    if sigs.is_empty() {
        return Ok(no_sign());
    }
    let mut list: Vec<SignValidity> = Vec::new();

    // Cambios en formularios.
    let allow_form = params.get(ALLOW_MODIFIED_FORM);
    let mut form_modified = false;
    if !allow_form.is_some_and(|v| v.eq_ignore_ascii_case("true")) && total > 1 {
        if let Some(oldest) = sigs.last() {
            if let Ok(orig) = PdfDoc::open(&pdf[..oldest.covered.min(pdf.len())], password) {
                let changes = form_changes(&orig, &doc);
                if !changes.is_empty() {
                    if relaxed {
                        return Err(errors::modified_form(allow_form.is_some()));
                    }
                    list.push(
                        ko(ValidityError::ModifiedForm)
                            .with_code(codes::SIGNING_PDF_WITH_MODIFIED_FORM)
                            .with_detail("Se han detectado cambios en un formulario posteriores a la primera firma"),
                    );
                    form_modified = true;
                }
            }
        }
    }

    // PDF Shadow Attack.
    let allow_psa = params.get(ALLOW_SHADOW_ATTACK);
    let psa_disabled = allow_form.is_some_and(|v| v.eq_ignore_ascii_case("true"))
        || form_modified
        || allow_psa.is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if !psa_disabled && total > 1 {
        let newest = &sigs[0];
        if newest.revision < total {
            let pages = params.get(PAGES_TO_CHECK_SHADOW_ATTACK).unwrap_or("10");
            if let Some(v) = check_shadow_attack(&doc, pdf, newest, pages, password) {
                if relaxed && v.validity == Validity::PendingConfirmByUser && allow_psa.is_none() {
                    return Err(errors::shadow_attack(
                        v.detail
                            .as_deref()
                            .unwrap_or("PDF sospechoso de haber sufrido PDF Shadow Attack"),
                        false,
                    ));
                }
                let v = if v.validity == Validity::PendingConfirmByUser {
                    SignValidity {
                        validity: Validity::Ko,
                        ..v
                    }
                } else {
                    v
                };
                list.push(v);
            }
        }
    }

    // Perfil y validación de cada firma.
    let profile = resolve_pdf_format(&doc, &sigs);
    let check_certs = is_true(params, CHECK_CERTIFICATES);
    for s in &sigs {
        for v in validate_sign(&doc, s, &profile, check_certs) {
            match v.validity {
                Validity::Unknown => list.insert(0, v),
                Validity::Ok => {}
                _ => list.push(v),
            }
        }
    }

    // Documentos certificados sin cambios permitidos.
    if list.is_empty() && doc.certification_level() == 1 {
        let cert_rev = sigs
            .iter()
            .find(|s| {
                s.dict
                    .get(b"Reference")
                    .ok()
                    .and_then(|r| doc.resolve(r).as_array().ok())
                    .and_then(|a| a.first())
                    .and_then(|r0| doc.dict(r0))
                    .is_some_and(|d| d.has(b"TransformMethod"))
            })
            .map(|s| s.revision);
        if let Some(cr) = cert_rev {
            for s in &sigs {
                if s.revision > cr {
                    list.push(
                        ko(ValidityError::CertifiedSignRevision)
                            .with_code(codes::SIGNING_PDF_WITH_CERTIFIED_SIGN),
                    );
                }
            }
        }
    }

    let list = long_standing_priority(ko_priority(list));
    Ok(if list.is_empty() {
        vec![SignValidity::ok()]
    } else {
        list
    })
}

/// `checkLongStandingValiditySign` exacto de Java: si los únicos KO son de
/// certificado caducado y hay un "perfil no comprobado", se intercambia el
/// primer elemento con el **último** de esos avisos.
///
/// (`afirma_core::validity::long_standing_priority` mueve el primero, lo que
/// da otro orden cuando hay varias firmas.)
pub fn long_standing_priority(list: Vec<SignValidity>) -> Vec<SignValidity> {
    let mut cert_ko = None;
    let mut warning = None;
    let mut other_ko = false;
    for (i, v) in list.iter().enumerate() {
        if v.validity == Validity::Ko {
            if v.error == Some(ValidityError::CertificateExpired) {
                cert_ko = Some(i);
            } else {
                other_ko = true;
            }
        } else if v.validity == Validity::Unknown
            && v.error == Some(ValidityError::SignProfileNotChecked)
        {
            warning = Some(i);
        }
    }
    let mut out = list;
    if let (false, Some(_), Some(w)) = (other_ko, cert_ko, warning) {
        out.swap(0, w);
    }
    out
}

/// Comprueba que el `/ByteRange` es coherente: empieza en 0, el hueco es
/// exactamente la cadena hexadecimal de `/Contents` y no sale del fichero.
fn byte_range_ok(pdf: &[u8], br: &[i64]) -> bool {
    if br.len() != 4 || br[0] != 0 {
        return false;
    }
    let (a, b, c) = (br[1], br[2], br[3]);
    if a <= 0 || b <= a || c < 0 || (b + c) as usize > pdf.len() {
        return false;
    }
    let (a, b) = (a as usize, b as usize);
    pdf.get(a) == Some(&b'<')
        && pdf.get(b - 1) == Some(&b'>')
        && pdf[a + 1..b - 1].iter().all(u8::is_ascii_hexdigit)
}

/// Huella de los bytes cubiertos por el `/ByteRange`.
fn byte_range_digest(pdf: &[u8], br: &[i64], d: afirma_core::DigestAlgorithm) -> Option<Vec<u8>> {
    let mut h = d.hasher();
    for pair in br.chunks(2) {
        let (start, len) = (
            usize::try_from(pair[0]).ok()?,
            usize::try_from(*pair.get(1)?).ok()?,
        );
        h.update(pdf.get(start..start.checked_add(len)?)?);
    }
    Some(h.finalize())
}

/// Datos de una firma PDF leídos de su `/Contents` (CMS o, para el
/// subfiltro `adbe.x509.rsa_sha1`, PKCS#1 con los certificados en `/Cert`).
pub struct SignatureData {
    /// Cadena de certificados empezando por el del firmante.
    pub chain: Vec<Vec<u8>>,
    /// Valor de la firma PKCS#1.
    pub pkcs1: Vec<u8>,
    /// Algoritmo de huella si es una huella "pura" (`getStrictHashAlgorithm`).
    pub strict_digest: Option<afirma_core::DigestAlgorithm>,
    /// Nombre del algoritmo (`SHA256withRSA`).
    pub algorithm_name: String,
    /// CMS leído (no existe en `adbe.x509.rsa_sha1`).
    pub cms: Option<cms::ParsedSignedData>,
    sub_filter: Vec<u8>,
}

impl SignatureData {
    /// Lee la firma de una entrada.
    pub fn read(doc: &PdfDoc, s: &SignatureEntry) -> Result<SignatureData, cms::CmsError> {
        let sub_filter = s.sub_filter().unwrap_or_default();
        let contents = s.contents();
        if sub_filter == b"adbe.x509.rsa_sha1" {
            let t = afirma_cms::asn1::Tlv::parse(&contents)?.0;
            let pkcs1 = t.octet_string_content()?;
            let chain: Vec<Vec<u8>> = match s.dict.get(b"Cert").ok().map(|c| doc.resolve(c)) {
                Some(Object::String(c, _)) => vec![c.clone()],
                Some(Object::Array(a)) => a
                    .iter()
                    .filter_map(|c| doc.resolve(c).as_str().ok().map(<[u8]>::to_vec))
                    .collect(),
                _ => Vec::new(),
            };
            if chain.is_empty() {
                return Err(cms::CmsError::Certificate(
                    "la firma no contiene certificados".into(),
                ));
            }
            return Ok(SignatureData {
                chain,
                pkcs1,
                strict_digest: None,
                algorithm_name: "SHA1withRSA".into(),
                cms: None,
                sub_filter,
            });
        }
        let sd = cms::parse_signed_data(&contents)?;
        let si = sd
            .signer_infos
            .first()
            .ok_or_else(|| cms::CmsError::Invalid("sin firmantes".into()))?;
        let chain = sd.chain_for(si);
        if chain.is_empty() {
            return Err(cms::CmsError::Certificate(
                "no se encuentra el certificado del firmante".into(),
            ));
        }
        Ok(SignatureData {
            chain,
            pkcs1: si.signature.clone(),
            strict_digest: si.digest_algorithm(),
            algorithm_name: si.algorithm_name(),
            sub_filter,
            cms: Some(sd),
        })
    }

    /// Verificación criptográfica de la firma sobre el rango de bytes
    /// (`PdfPKCS7.verify()`).
    pub fn verify(&self, pdf: &[u8], br: &[i64]) -> Result<bool, cms::CmsError> {
        let bad = || cms::CmsError::Invalid("rango de bytes no valido".into());
        let Some(sd) = &self.cms else {
            // adbe.x509.rsa_sha1: PKCS#1 sobre la huella SHA-1 del rango.
            let h =
                byte_range_digest(pdf, br, afirma_core::DigestAlgorithm::Sha1).ok_or_else(bad)?;
            return cms::verify_prehashed(
                &self.chain[0],
                afirma_core::DigestAlgorithm::Sha1,
                &h,
                &self.pkcs1,
            );
        };
        let si = &sd.signer_infos[0];
        let digest = si
            .digest_algorithm()
            .ok_or_else(|| cms::CmsError::Algorithm(si.digest_oid.clone()))?;
        let data_digest = if self.sub_filter == b"adbe.pkcs7.sha1" {
            // El contenido encapsulado es la huella SHA-1 del rango.
            let content = sd.econtent.clone().unwrap_or_default();
            let h =
                byte_range_digest(pdf, br, afirma_core::DigestAlgorithm::Sha1).ok_or_else(bad)?;
            if content != h {
                return Ok(false);
            }
            digest.digest(&content)
        } else {
            byte_range_digest(pdf, br, digest).ok_or_else(bad)?
        };
        let c = cms::verify_signer(sd, si, &data_digest)?;
        Ok(c.digest_ok && c.signature_ok)
    }
}

/// Validación de una firma (`validateSign`): se acumulan todos los
/// problemas encontrados.
fn validate_sign(
    doc: &PdfDoc,
    s: &SignatureEntry,
    profile: &str,
    check_certs: bool,
) -> Vec<SignValidity> {
    let pdf = &doc.bytes;
    let br = s.byte_range();
    let mut out = Vec::new();
    let data = match SignatureData::read(doc, s) {
        Ok(d) => d,
        Err(e) => return vec![ko(ValidityError::CorruptedSign).with_detail(e.to_string())],
    };
    if data.strict_digest.is_none() {
        out.push(ko(ValidityError::AlgorithmNotSupported));
    }
    let is_doc_ts = s.sub_filter().as_deref() == Some(b"ETSI.RFC3161".as_slice());
    if !byte_range_ok(pdf, &br) {
        // Comprobación adicional a la de Java: el hueco del /ByteRange debe
        // ser exactamente el valor de /Contents.
        out.push(
            ko(ValidityError::CorruptedSign)
                .with_detail("El /ByteRange de la firma no es coherente"),
        );
    } else if is_doc_ts {
        // Sello de documento: Java no lo verifica; aquí se comprueba la huella
        // del sello y su firma.
        match cms::timestamp_imprint(&s.contents()) {
            Some((alg, imprint)) => match afirma_core::DigestAlgorithm::from_oid(&alg) {
                Some(d)
                    if byte_range_digest(pdf, &br, d).as_deref() == Some(imprint.as_slice()) =>
                {
                    if let Some(sd) = &data.cms {
                        let si = &sd.signer_infos[0];
                        let ed = sd
                            .econtent
                            .as_ref()
                            .zip(si.digest_algorithm())
                            .map(|(e, d)| d.digest(e))
                            .unwrap_or_default();
                        match cms::verify_signer(sd, si, &ed) {
                            Ok(c) if c.digest_ok && c.signature_ok => {}
                            Ok(_) => out.push(ko(ValidityError::NoMatchData)),
                            Err(e) => out
                                .push(ko(ValidityError::CorruptedSign).with_detail(e.to_string())),
                        }
                    }
                }
                _ => out.push(ko(ValidityError::NoMatchData)),
            },
            None => out.push(ko(ValidityError::CorruptedSign)),
        }
    } else {
        match data.verify(pdf, &br) {
            Ok(true) => {}
            Ok(false) => out.push(ko(ValidityError::NoMatchData)),
            Err(e) => out.push(ko(ValidityError::CorruptedSign).with_detail(e.to_string())),
        }
    }
    if check_certs {
        if let Some(cert) = afirma_core::cert::CertInfo::parse(&data.chain[0]) {
            let now = chrono::Utc::now();
            if now > cert.not_after {
                out.push(ko(ValidityError::CertificateExpired));
            } else if now < cert.not_before {
                out.push(ko(ValidityError::CertificateNotValidYet));
            }
        }
    }
    if !CHECKED_PROFILES.contains(&profile) {
        out.push(SignValidity::unknown(ValidityError::SignProfileNotChecked));
    }
    if out.is_empty() {
        out.push(SignValidity::ok());
    }
    out
}

/// Perfil PAdES del documento (`SignatureFormatDetectorPadesCades.resolvePDFFormat`).
pub fn resolve_pdf_format(doc: &PdfDoc, sigs: &[SignatureEntry]) -> String {
    let doc_ts = sigs
        .iter()
        .filter(|s| {
            s.sub_filter()
                .is_some_and(|f| f.eq_ignore_ascii_case(b"ETSI.RFC3161"))
                && s.type_name().is_none_or(|t| t == b"DocTimeStamp")
        })
        .count();
    let has_dss = doc.catalog().is_some_and(|c| c.has(b"DSS"));
    let Some(s) = sigs.iter().find(|s| {
        s.sub_filter().as_deref() != Some(b"ETSI.RFC3161".as_slice())
            && s.type_name().is_none_or(|t| t == b"Sig")
    }) else {
        return "No reconocido".into();
    };
    let cades = s.sub_filter().as_deref() == Some(b"ETSI.CAdES.detached".as_slice());
    let parsed = if cades {
        cms::parse_signed_data(&s.contents()).ok()
    } else {
        None
    };
    if cades && parsed.as_ref().is_none_or(|sd| sd.signer_infos.is_empty()) {
        return "No reconocido".into();
    }
    if let (true, Some(sd)) = (cades && s.dict.has(b"M"), &parsed) {
        let si = &sd.signer_infos[0];
        let level = if sd
            .signer_infos
            .iter()
            .any(|x| x.signed_attr(cms::OID_SIGNING_CERTIFICATE).is_some())
        {
            Some("PAdES B-Level")
        } else if sd
            .signer_infos
            .iter()
            .any(|x| x.signed_attr(cms::OID_SIGNING_CERTIFICATE_V2).is_some())
        {
            Some("PAdES B-B-Level")
        } else {
            None
        };
        if let Some(level) = level {
            let sig_ts = si
                .unsigned_attr(cms::OID_SIGNATURE_TIMESTAMP)
                .map_or(0, |a| a.values.len());
            let t = !sd.certificates.is_empty()
                && ((sig_ts == 1 && doc_ts == 0) || (sig_ts == 0 && doc_ts == 1));
            if (sig_ts > 1 || doc_ts > 1) && has_dss {
                return "PAdES LTA-Level".into();
            }
            if t && has_dss {
                return "PAdES LT-Level".into();
            }
            if t {
                return "PAdES T-Level".into();
            }
            return level.into();
        }
    }
    if has_dss || doc_ts > 0 {
        return "PAdES-LTV".into();
    }
    match s.sub_filter().as_deref() {
        Some(b"ETSI.CAdES.detached") => {
            if parsed.as_ref().is_some_and(|sd| {
                sd.signer_infos
                    .iter()
                    .any(|x| x.signed_attr(cms::OID_SIG_POLICY_ID).is_some())
            }) {
                "PAdES-EPES".into()
            } else {
                "PAdES-BES".into()
            }
        }
        Some(b"adbe.pkcs7.detached") | Some(b"adbe.pkcs7.sha1") => "PAdES-Basic".into(),
        _ => "PDF".into(),
    }
}

// ---------------------------------------------------------------------------
// Formularios
// ---------------------------------------------------------------------------

fn repr(doc: &PdfDoc, o: Option<&Object>) -> Option<Vec<u8>> {
    let o = o?;
    let r = doc.resolve(o);
    if matches!(r, Object::Null) {
        return None;
    }
    let mut out = Vec::new();
    match r {
        Object::Stream(s) => {
            write_object(&mut out, &Object::Dictionary(s.dict.clone()));
            out.extend_from_slice(&s.content);
        }
        other => write_object(&mut out, other),
    }
    Some(out)
}

/// Valores de los campos (sin firmas), como `DataAnalizerUtil.getFieldValues`.
fn field_values(doc: &PdfDoc) -> Vec<(String, Option<Vec<u8>>)> {
    let mut out: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    if let Some(form) = doc.acroform() {
        if let Some(Object::Array(fields)) = doc.dict_get(form, b"Fields") {
            fn walk(
                doc: &PdfDoc,
                o: &Object,
                prefix: &str,
                ft: Option<Vec<u8>>,
                v: Option<Object>,
                out: &mut Vec<(String, Option<Vec<u8>>)>,
                depth: usize,
            ) {
                if depth > 32 {
                    return;
                }
                let Some(d) = doc.dict(o) else { return };
                let t = doc
                    .dict_get(d, b"T")
                    .and_then(|t| t.as_str().ok())
                    .map(crate::pdf::text::decode_text_string);
                let name = match (&t, prefix.is_empty()) {
                    (Some(t), true) => t.clone(),
                    (Some(t), false) => format!("{prefix}.{t}"),
                    (None, _) => prefix.to_string(),
                };
                let ft = doc.dict_get_name(d, b"FT").map(<[u8]>::to_vec).or(ft);
                let v = d.get(b"V").ok().cloned().or(v);
                let kids: Vec<&Object> = match doc.dict_get(d, b"Kids") {
                    Some(Object::Array(k)) => k
                        .iter()
                        .filter(|k| doc.dict(k).is_some_and(|kd| kd.has(b"T")))
                        .collect(),
                    _ => Vec::new(),
                };
                if kids.is_empty() {
                    if ft.as_deref() != Some(b"Sig".as_slice())
                        && !name.is_empty()
                        && !out.iter().any(|(n, _)| *n == name)
                    {
                        out.push((name, repr(doc, v.as_ref())));
                    }
                } else {
                    for k in kids {
                        walk(doc, k, &name, ft.clone(), v.clone(), out, depth + 1);
                    }
                }
            }
            for f in fields {
                walk(doc, f, "", None, None, &mut out, 0);
            }
        }
    }
    for (pi, page) in doc.pages().into_iter().enumerate() {
        let Some(pd) = doc.dict_id(page) else {
            continue;
        };
        let Some(Object::Array(annots)) = doc.dict_get(pd, b"Annots") else {
            continue;
        };
        for (ai, a) in annots.iter().enumerate() {
            let Some(ad) = doc.dict(a) else { continue };
            if doc.dict_get_name(ad, b"Subtype") != Some(b"Widget")
                || doc.dict_get_name(ad, b"FT") == Some(b"Sig")
            {
                continue;
            }
            let name = doc
                .dict_get(ad, b"T")
                .and_then(|t| t.as_str().ok())
                .map(crate::pdf::text::decode_text_string)
                .unwrap_or_else(|| format!("P{}A{ai}", pi + 1));
            if !out.iter().any(|(n, _)| *n == name) {
                out.push((name, repr(doc, ad.get(b"V").ok())));
            }
        }
    }
    out
}

/// Campos cuyo valor ha cambiado entre la revisión original y la actual.
pub fn form_changes(original: &PdfDoc, current: &PdfDoc) -> Vec<String> {
    let cur = field_values(current);
    let mut changes = Vec::new();
    for (name, v) in field_values(original) {
        match cur.iter().find(|(n, _)| *n == name) {
            None => changes.push(name),
            Some((_, cv)) => {
                if *cv != v {
                    changes.push(name);
                }
            }
        }
    }
    changes
}

// ---------------------------------------------------------------------------
// PDF Shadow Attack
// ---------------------------------------------------------------------------

/// Anotaciones de firma visibles solapadas en una página.
///
/// Java (`checkIsOverlapping`) solo comprueba si una anotación se solapa con
/// *todas* las siguientes y salta elementos; aquí se comprueba cada par de
/// widgets en el que al menos uno es un campo de firma y cuya intersección
/// tiene área positiva.
pub fn overlapping_signatures(doc: &PdfDoc, page: lopdf::ObjectId) -> bool {
    let Some(pd) = doc.dict_id(page) else {
        return false;
    };
    let Some(Object::Array(annots)) = doc.dict_get(pd, b"Annots") else {
        return false;
    };
    let mut widgets: Vec<(Rect, bool)> = Vec::new();
    for a in annots {
        let Some(ad) = doc.dict(a) else { continue };
        if doc.dict_get_name(ad, b"Subtype") != Some(b"Widget") {
            continue;
        }
        let Some(r) = doc.dict_get(ad, b"Rect").and_then(Rect::from_object) else {
            continue;
        };
        if r.width() == 0.0 || r.height() == 0.0 {
            continue;
        }
        let is_sig = doc.dict_get_name(ad, b"FT") == Some(b"Sig")
            || ad
                .get(b"Parent")
                .ok()
                .and_then(|p| doc.dict(p))
                .is_some_and(|p| doc.dict_get_name(p, b"FT") == Some(b"Sig"));
        widgets.push((r, is_sig));
    }
    for i in 0..widgets.len() {
        for j in i + 1..widgets.len() {
            let (a, sa) = widgets[i];
            let (b, sb) = widgets[j];
            if !(sa || sb) {
                continue;
            }
            let w = a.urx.min(b.urx) - a.llx.max(b.llx);
            let h = a.ury.min(b.ury) - a.lly.max(b.lly);
            if w > 0.0 && h > 0.0 {
                return true;
            }
        }
    }
    false
}

/// Comprobación de PDF Shadow Attack (`DataAnalizerUtil.checkPdfShadowAttack`):
/// compara el aspecto de las primeras páginas del documento actual con el de
/// la revisión cubierta por la firma más reciente.
#[allow(unused_variables)]
pub fn check_shadow_attack(
    doc: &PdfDoc,
    pdf: &[u8],
    newest: &SignatureEntry,
    pages_to_check: &str,
    password: Option<&str>,
) -> Option<SignValidity> {
    let n = doc.page_count();
    let pages = if pages_to_check.trim().eq_ignore_ascii_case("all") {
        n
    } else {
        parse_java_int(pages_to_check)?.max(0) as usize
    };
    let page_ids = doc.pages();
    #[cfg(feature = "render")]
    let (cur, rev) = {
        let cur = crate::render::RenderDocument::open(pdf, password).ok()?;
        let rev =
            crate::render::RenderDocument::open(&pdf[..newest.covered.min(pdf.len())], password)
                .ok()?;
        (cur, rev)
    };
    for i in 0..pages {
        // Java: IndexOutOfBoundsException capturada → sin hallazgo.
        let page_id = *page_ids.get(i)?;
        if overlapping_signatures(doc, page_id) {
            return Some(
                SignValidity::new(
                    Validity::PendingConfirmByUser,
                    Some(ValidityError::OverlappingSignature),
                )
                .with_code(codes::SIGNING_PDF_WITH_SUSPICION_OF_PSA)
                .with_detail("El documento incluye firmas visibles solapadas"),
            );
        }
        #[cfg(feature = "render")]
        {
            let a = cur.render_page_dpi(i, 40.0).ok()?;
            let b = rev.render_page_dpi(i, 40.0).ok()?;
            if a.width != b.width || a.height != b.height || a.to_gray() != b.to_gray() {
                return Some(
                    SignValidity::new(
                        Validity::PendingConfirmByUser,
                        Some(ValidityError::ModifiedDocument),
                    )
                    .with_code(codes::SIGNING_PDF_WITH_SUSPICION_OF_PSA)
                    .with_detail("El documento ha cambiado de aspecto"),
                );
            }
        }
    }
    None
}
