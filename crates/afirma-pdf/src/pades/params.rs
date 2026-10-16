//! Parámetros adicionales de PAdES (`PdfExtraParams`) con sus nombres,
//! valores por defecto y reglas de interpretación exactas.

use afirma_core::{AfirmaError, DigestAlgorithm, ExtraParams};

use crate::pdf::doc::Rect;

pub const SIGNATURE_SUBFILTER: &str = "signatureSubFilter";
pub const PROFILE: &str = "profile";
pub const INCLUDE_ONLY_SIGNING_CERTIFICATE: &str = "includeOnlySignningCertificate";
pub const SIGNING_CERTIFICATE_V2: &str = "signingCertificateV2";
pub const DO_NOT_INCLUDE_POLICY_ON_SIGNING_CERTIFICATE: &str =
    "doNotIncludePolicyOnSigningCertificate";
pub const POLICY_IDENTIFIER: &str = "policyIdentifier";
pub const POLICY_IDENTIFIER_HASH: &str = "policyIdentifierHash";
pub const POLICY_IDENTIFIER_HASH_ALGORITHM: &str = "policyIdentifierHashAlgorithm";
pub const POLICY_QUALIFIER: &str = "policyQualifier";
pub const COMMITMENT_TYPE_INDICATIONS: &str = "commitmentTypeIndications";
pub const SIGNER_CLAIMED_ROLES: &str = "signerClaimedRoles";
pub const INCLUDE_MIME_TYPE_ATTRIBUTE: &str = "includeMimeTypeAttribute";
pub const MIME_TYPE: &str = "mimeType";
pub const PRECALCULATED_HASH_ALGORITHM: &str = "precalculatedHashAlgorithm";
pub const SIGN_REASON: &str = "signReason";
pub const SIGNATURE_PRODUCTION_CITY: &str = "signatureProductionCity";
pub const SIGNER_CONTACT: &str = "signerContact";
pub const DO_NOT_USE_CERT_CHAIN_ON_POST_SIGN: &str = "doNotUseCertChainOnPostSign";
pub const SIGN_TIME: &str = "signTime";
pub const SIGNATURE_PAGES: &str = "signaturePages";
pub const SIGNATURE_PAGE: &str = "signaturePage";
pub const SIGNATURE_FIELD: &str = "signatureField";
pub const SIGNATURE_ROTATION: &str = "signatureRotation";
pub const LAYER2_TEXT: &str = "layer2Text";
pub const LAYER2_FONT_FAMILY: &str = "layer2FontFamily";
pub const LAYER2_FONT_SIZE: &str = "layer2FontSize";
pub const LAYER2_FONT_STYLE: &str = "layer2FontStyle";
pub const LAYER2_FONT_COLOR: &str = "layer2FontColor";
pub const LAYER4_TEXT: &str = "layer4Text";
pub const INCLUDE_QUESTION_MARK: &str = "includeQuestionMark";
pub const SIGNATURE_RUBRIC_IMAGE: &str = "signatureRubricImage";
pub const OBFUSCATE_CERT_TEXT: &str = "obfuscateCertText";
pub const OBFUSCATION_MASK: &str = "obfuscationMask";
pub const CERTIFICATION_LEVEL: &str = "certificationLevel";
pub const ALLOW_SIGNING_CERTIFIED_PDFS: &str = "allowSigningCertifiedPdfs";
pub const ALLOW_COSIGNING_UNREGISTERED_SIGNATURES: &str = "allowCosigningUnregisteredSignatures";
pub const ALWAYS_CREATE_REVISION: &str = "alwaysCreateRevision";
pub const PDF_VERSION: &str = "pdfVersion";
pub const COMPRESS_PDF: &str = "compressPdf";
pub const SIGN_RESERVED_SIZE: &str = "signReservedSize";
pub const IMAGE: &str = "image";
pub const IMAGE_PAGE: &str = "imagePage";
pub const ATTACH: &str = "attach";
pub const ATTACH_FILE_NAME: &str = "attachFileName";
pub const ATTACH_DESCRIPTION: &str = "attachDescription";
pub const OWNER_PASSWORD: &str = "ownerPassword";
pub const USER_PASSWORD: &str = "userPassword";
pub const HEADLESS: &str = "headless";
pub const TSA_URL: &str = "tsaURL";
pub const TS_TYPE: &str = "tsType";
pub const TSA_POLICY: &str = "tsaPolicy";
pub const TSA_HASH_ALGORITHM: &str = "tsaHashAlgorithm";
pub const TSA_REQUIRE_CERT: &str = "tsaRequireCert";
pub const TSA_USR: &str = "tsaUsr";
pub const TSA_PWD: &str = "tsaPwd";
pub const TSA_EXTENSION_OID: &str = "tsaExtensionOid";
pub const TSA_EXTENSION_VALUE_BASE64: &str = "tsaExtensionValueBase64";
pub const TSA_EXTENSION_CRITICAL: &str = "tsaExtensionCritical";
pub const ALLOW_SHADOW_ATTACK: &str = "allowShadowAttack";
pub const PAGES_TO_CHECK_SHADOW_ATTACK: &str = "pagesToCheckShadowAttack";
pub const ALLOW_MODIFIED_FORM: &str = "allowModifiedForm";
pub const CHECK_CERTIFICATES: &str = "checkCertificates";

/// Subfiltro PAdES-BES (por defecto).
pub const SUBFILTER_ETSI_CADES: &str = "ETSI.CAdES.detached";
/// Subfiltro PAdES básico.
pub const SUBFILTER_PKCS7: &str = "adbe.pkcs7.detached";
/// Subfiltro de sello de documento.
pub const SUBFILTER_RFC3161: &str = "ETSI.RFC3161";

/// Tamaño reservado por defecto para el CMS (bytes).
pub const DEFAULT_RESERVED_SIZE: usize = 27000;

/// `Boolean.parseBoolean` de un parámetro (ausente → `false`).
pub fn is_true(xp: &ExtraParams, key: &str) -> bool {
    xp.get(key).is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// `Integer.parseInt(value.trim())`.
pub fn parse_java_int(v: &str) -> Option<i64> {
    let t = v.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse::<i32>().ok().map(i64::from)
}

/// Normalizaciones de `AOPDFSigner.checkParams`.
pub fn check_params(algorithm: &str, xp: &mut ExtraParams) -> Result<(), AfirmaError> {
    if algorithm.to_uppercase().starts_with("MD") {
        return Err(AfirmaError::invalid_argument(
            "PAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)",
        ));
    }
    let baseline = xp
        .get(PROFILE)
        .is_some_and(|p| p.eq_ignore_ascii_case("baseline"));
    if baseline && xp.contains(SIGNATURE_SUBFILTER) {
        tracing::warn!(
            "El perfil baseline siempre usa el subfiltro ETSI.CAdES.detached; se ignora signatureSubFilter"
        );
        xp.remove(SIGNATURE_SUBFILTER);
    }
    if xp.contains(COMMITMENT_TYPE_INDICATIONS) && !baseline && !xp.contains(POLICY_IDENTIFIER) {
        tracing::warn!(
            "Los commitmentTypeIndications solo se permiten con politica o perfil baseline; se ignoran"
        );
        xp.remove(COMMITMENT_TYPE_INDICATIONS);
    }
    if xp.contains(SIGN_REASON) && xp.contains(POLICY_IDENTIFIER) {
        tracing::warn!("Se ignora el motivo de firma por haberse indicado una politica");
        xp.remove(SIGN_REASON);
    }
    if xp.contains(SIGN_REASON) && xp.contains(COMMITMENT_TYPE_INDICATIONS) {
        xp.remove(COMMITMENT_TYPE_INDICATIONS);
    }
    Ok(())
}

/// Subfiltro efectivo (con el forzado por política o perfil `baseline`).
pub fn sub_filter(xp: &ExtraParams) -> String {
    let forced = xp.contains(POLICY_IDENTIFIER) || xp.get(PROFILE) == Some("baseline");
    if forced {
        return SUBFILTER_ETSI_CADES.into();
    }
    match xp.get(SIGNATURE_SUBFILTER) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => SUBFILTER_ETSI_CADES.into(),
    }
}

/// Rectángulo de `<prefix>PositionOnPage{LowerLeftX,...}` (enteros; si
/// falta o no es válido alguno, `None`).
pub fn position(xp: &ExtraParams, prefix: &str) -> Option<Rect> {
    let get = |k: &str| {
        xp.get(&format!("{prefix}PositionOnPage{k}"))
            .and_then(parse_java_int)
    };
    let (llx, lly, urx, ury) = (
        get("LowerLeftX")?,
        get("LowerLeftY")?,
        get("UpperRightX")?,
        get("UpperRightY")?,
    );
    Some(Rect::new(llx as f64, lly as f64, urx as f64, ury as f64))
}

/// La firma es visible (`isVisibleSignature`).
pub fn is_visible(xp: &ExtraParams) -> bool {
    if xp.get(SIGNATURE_FIELD).is_some() {
        return true;
    }
    position(xp, "signature").is_some_and(|r| r.width() != 0.0 && r.height() != 0.0)
}

/// Selección de páginas (`PdfUtil.getPages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSelection {
    /// Páginas (1..N) ordenadas y sin duplicados.
    pub pages: Vec<usize>,
    /// Hay que añadir una página en blanco al final y firmar en ella.
    pub append: bool,
}

fn normalize_page(p: i64, n: usize) -> usize {
    let n = n as i64;
    let mut p = p;
    if p < 0 {
        p += n + 1;
    }
    if p <= 0 {
        p = 1;
    }
    if p > n {
        p = n;
    }
    p.max(1) as usize
}

/// Interpreta `signaturePages`/`signaturePage`.
pub fn pages(xp: &ExtraParams, n: usize) -> PageSelection {
    let value = xp.get(SIGNATURE_PAGES).or_else(|| xp.get(SIGNATURE_PAGE));
    let Some(value) = value else {
        return PageSelection {
            pages: vec![n],
            append: false,
        };
    };
    let elems: Vec<&str> = value.split(',').collect();
    let first = elems.first().map(|s| s.trim()).unwrap_or("");
    if first.eq_ignore_ascii_case("append") {
        return PageSelection {
            pages: vec![n + 1],
            append: true,
        };
    }
    if first.eq_ignore_ascii_case("all") {
        return PageSelection {
            pages: (1..=n).collect(),
            append: false,
        };
    }
    let mut out: Vec<usize> = Vec::new();
    for e in elems {
        let e: String = e.chars().filter(|c| *c != ' ').collect();
        if let Some(p) = parse_java_int(&e) {
            let p = normalize_page(p, n);
            if !out.contains(&p) {
                out.push(p);
            }
            continue;
        }
        // Rango `a-b` (si empieza por '-', el separador es el siguiente '-').
        let sep = if let Some(rest) = e.strip_prefix('-') {
            rest.find('-').map(|i| i + 1)
        } else {
            e.find('-')
        };
        let Some(sep) = sep else {
            tracing::warn!("Pagina de firma no valida: {e}");
            continue;
        };
        let (a, b) = (parse_java_int(&e[..sep]), parse_java_int(&e[sep + 1..]));
        let (Some(a), Some(b)) = (a, b) else {
            tracing::warn!("Rango de paginas no valido: {e}");
            continue;
        };
        let (a, b) = (normalize_page(a, n), normalize_page(b, n));
        if b < a {
            continue;
        }
        for p in a..=b {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out.sort_unstable();
    if out.is_empty() {
        out.push(n);
    }
    PageSelection {
        pages: out,
        append: false,
    }
}

/// Nivel de certificación (`certificationLevel`), 0 si no se certifica.
pub fn certification_level(xp: &ExtraParams) -> i64 {
    match xp.get(CERTIFICATION_LEVEL) {
        Some(v) => match parse_java_int(v) {
            Some(l) if l > 0 => l,
            Some(_) => 0,
            None => {
                tracing::warn!("Nivel de certificacion no valido: {v}");
                0
            }
        },
        None => 0,
    }
}

/// Tamaño reservado para el CMS.
pub fn reserved_size(xp: &ExtraParams) -> usize {
    match xp.get(SIGN_RESERVED_SIZE) {
        Some(v) => match parse_java_int(v) {
            Some(s) if s > 0 => s as usize,
            _ => {
                tracing::warn!("Tamano reservado no valido: {v}");
                DEFAULT_RESERVED_SIZE
            }
        },
        None => DEFAULT_RESERVED_SIZE,
    }
}

/// Versión PDF solicitada (`pdfVersion`, por defecto 7); `None` si está
/// fuera de rango (se conserva la del documento).
pub fn pdf_version(xp: &ExtraParams) -> Option<u8> {
    match xp.get(PDF_VERSION) {
        None => Some(7),
        Some(v) => match parse_java_int(v) {
            Some(n) if (2..=7).contains(&n) => Some(n as u8),
            Some(_) => None,
            None => Some(7),
        },
    }
}

/// Algoritmo de huella para los sellos de tiempo.
pub fn tsa_digest(xp: &ExtraParams) -> DigestAlgorithm {
    xp.get(TSA_HASH_ALGORITHM)
        .and_then(|v| {
            afirma_core::algorithms::java_digest_algorithm_name(v)
                .replace('-', "")
                .parse()
                .ok()
        })
        .unwrap_or(DigestAlgorithm::Sha512)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xp(pairs: &[(&str, &str)]) -> ExtraParams {
        pairs.iter().map(|(k, v)| (*k, *v)).collect()
    }

    #[test]
    fn page_lists() {
        let p = |v: &str, n| pages(&xp(&[(SIGNATURE_PAGES, v)]), n).pages;
        assert_eq!(pages(&ExtraParams::new(), 5).pages, vec![5]);
        assert_eq!(p("1", 5), vec![1]);
        assert_eq!(p("-1", 5), vec![5]);
        assert_eq!(p("0", 5), vec![1]);
        assert_eq!(p("999", 5), vec![5]);
        assert_eq!(p("-999", 5), vec![1]);
        assert_eq!(p("all", 3), vec![1, 2, 3]);
        assert_eq!(p("ALL,1", 3), vec![1, 2, 3]);
        assert_eq!(p("3,1, 2 ,1", 5), vec![1, 2, 3]);
        assert_eq!(p("2-4", 5), vec![2, 3, 4]);
        assert_eq!(p("-3--1", 5), vec![3, 4, 5]);
        assert_eq!(p("4-2", 5), vec![5]);
        assert_eq!(p("x", 5), vec![5]);
        assert_eq!(p("1,append", 5), vec![1]);
        let a = pages(
            &xp(&[(SIGNATURE_PAGES, "append"), (SIGNATURE_PAGE, "1")]),
            5,
        );
        assert!(a.append);
        assert_eq!(pages(&xp(&[(SIGNATURE_PAGE, "2")]), 5).pages, vec![2]);
    }

    #[test]
    fn positions() {
        let x = xp(&[
            ("signaturePositionOnPageLowerLeftX", " 100"),
            ("signaturePositionOnPageLowerLeftY", "100"),
            ("signaturePositionOnPageUpperRightX", "300"),
            ("signaturePositionOnPageUpperRightY", "180"),
        ]);
        let r = position(&x, "signature").unwrap();
        assert_eq!((r.llx, r.lly, r.urx, r.ury), (100.0, 100.0, 300.0, 180.0));
        assert!(is_visible(&x));
        let mut y = x.clone();
        y.set("signaturePositionOnPageUpperRightY", "180.5");
        assert!(position(&y, "signature").is_none());
        assert!(!is_visible(&y));
    }

    #[test]
    fn param_rules() {
        let mut x = xp(&[
            (SIGN_REASON, "r"),
            (POLICY_IDENTIFIER, "1.2.3"),
            (SIGNATURE_SUBFILTER, "adbe.pkcs7.detached"),
        ]);
        check_params("SHA256withRSA", &mut x).unwrap();
        assert!(!x.contains(SIGN_REASON));
        assert_eq!(sub_filter(&x), SUBFILTER_ETSI_CADES);
        assert!(check_params("MD5withRSA", &mut ExtraParams::new()).is_err());
        let mut b = xp(&[
            (PROFILE, "Baseline"),
            (SIGNATURE_SUBFILTER, "adbe.pkcs7.detached"),
        ]);
        check_params("SHA256withRSA", &mut b).unwrap();
        assert!(!b.contains(SIGNATURE_SUBFILTER));
        assert_eq!(
            sub_filter(&xp(&[(SIGNATURE_SUBFILTER, "adbe.pkcs7.detached")])),
            SUBFILTER_PKCS7
        );
        assert_eq!(
            sub_filter(&xp(&[(SIGNATURE_SUBFILTER, "")])),
            SUBFILTER_ETSI_CADES
        );
        assert_eq!(reserved_size(&xp(&[(SIGN_RESERVED_SIZE, "abc")])), 27000);
        assert_eq!(pdf_version(&xp(&[(PDF_VERSION, "9")])), None);
        assert_eq!(certification_level(&xp(&[(CERTIFICATION_LEVEL, "2")])), 2);
    }
}
