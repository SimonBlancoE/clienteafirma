//! Políticas de firma: expansión de `expPolicy` (`ExtraParamsProcessor`,
//! `AdESPolicyPropertiesManager`; §5.1-5.4) y objeto de política
//! (`AdESPolicy`; §5.5).
//!
//! Comportamiento verificado contra el oráculo Java
//! (`testdata/core/exppolicy.golden`).

use std::sync::OnceLock;

use crate::constants::{
    ADES_POLICY_DEFAULT_HASH_ALGORITHM, EXTRA_PARAM_EXP_POLICY, OP_SIGN, POLICY_ID_AGE, POLICY_ID_AGE_1_8,
    SIGN_FORMAT_CADES, SIGN_FORMAT_CADES_TRI, SIGN_FORMAT_PADES, SIGN_FORMAT_PADES_TRI, SIGN_FORMAT_PDF,
    SIGN_FORMAT_PDF_TRI, SIGN_FORMAT_XADES, SIGN_FORMAT_XADES_DETACHED, SIGN_FORMAT_XADES_ENVELOPED,
    SIGN_FORMAT_XADES_TRI, SIGN_MODE_EXPLICIT, SIGN_MODE_IMPLICIT, SIGN_PROFILE_ADVANCED, SIGN_PROFILE_BASELINE,
    SIZE_1MB,
};
use crate::error::{AfirmaError, Result};
use crate::extra_params::ExtraParams;
use crate::formats::equals_ignore_case;
use crate::http::{HttpClient, HttpRequest};

/// Contenido literal de `afirma-core/src/main/resources/policy.properties`.
pub const POLICY_PROPERTIES: &str = "FirmaAGE.policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9
FirmaAGE.policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf
FirmaAGE.policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1
FirmaAGE.policyIdentifierHash.XAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE.policyIdentifierHash.CAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE.policyIdentifierHash.PAdES=G7roucf600+f03r/o0bAOQ6WAs0=

FirmaAGE19.policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.9
FirmaAGE19.policyQualifier=https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf
FirmaAGE19.policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1
FirmaAGE19.policyIdentifierHash.XAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE19.policyIdentifierHash.CAdES=G7roucf600+f03r/o0bAOQ6WAs0=
FirmaAGE19.policyIdentifierHash.PAdES=G7roucf600+f03r/o0bAOQ6WAs0=

FirmaAGE18.policyIdentifier=urn:oid:2.16.724.1.3.1.1.2.1.8
FirmaAGE18.policyQualifier=https://sede.administracion.gob.es/PAG_Sede/dam/jcr:b0de3f91-5171-48e2-81f3-5c2407d9c091/politica_firma_AGE_v1_8.pdf
FirmaAGE18.policyIdentifierHashAlgorithm=http://www.w3.org/2000/09/xmldsig#sha1
FirmaAGE18.policyIdentifierHash.XAdES=V8lVVNGDCPen6VELRD1Ja8HARFk=
FirmaAGE18.policyIdentifierHash.CAdES=7SxX3erFuH31TvAw9LZ70N7p1vA=
FirmaAGE18.policyIdentifierHash.PAdES=7SxX3erFuH31TvAw9LZ70N7p1vA=
";

/// Familia de formato `CAdES` de `AdESPolicyPropertiesManager`.
pub const FORMAT_CADES: &str = "CAdES";
/// Familia de formato `XAdES`.
pub const FORMAT_XADES: &str = "XAdES";
/// Familia de formato `PAdES`.
pub const FORMAT_PADES: &str = "PAdES";

/// Parámetro: identificador de la política.
pub const PROPERTY_POLICY_IDENTIFIER: &str = "policyIdentifier";
/// Parámetro: algoritmo de la huella de la política.
pub const PROPERTY_POLICY_HASH_ALGORITHM: &str = "policyIdentifierHashAlgorithm";
/// Parámetro: huella de la política.
pub const PROPERTY_POLICY_HASH: &str = "policyIdentifierHash";
/// Parámetro: calificador (URL) de la política.
pub const PROPERTY_POLICY_QUALIFIER: &str = "policyQualifier";
/// Parámetro: descripción de la política.
pub const PROPERTY_POLICY_DESCRIPTION: &str = "policyDescription";

fn bundle() -> &'static ExtraParams {
    static B: OnceLock<ExtraParams> = OnceLock::new();
    B.get_or_init(|| ExtraParams::parse(POLICY_PROPERTIES))
}

/// `AdESPolicyPropertiesManager.getProperty`: busca, por orden,
/// `id.propiedad.formato`, `id.propiedad`, `propiedad.formato` y `propiedad`.
pub fn policy_property(id: Option<&str>, property: &str, format: Option<&str>) -> Option<&'static str> {
    let b = bundle();
    if let Some(id) = id {
        if let Some(f) = format
            && let Some(v) = b.get(&format!("{id}.{property}.{f}")) {
                return Some(v);
            }
        if let Some(v) = b.get(&format!("{id}.{property}")) {
            return Some(v);
        }
    }
    if let Some(f) = format
        && let Some(v) = b.get(&format!("{property}.{f}")) {
            return Some(v);
        }
    b.get(property)
}

/// `AdESPolicyPropertiesManager.setProperties`: establece (sobrescribiendo)
/// `policyIdentifier`, `policyIdentifierHashAlgorithm`, `policyIdentifierHash`,
/// `policyQualifier` y `policyDescription` de la política para la familia de
/// formato. Si la política no tiene huella pero sí identificador no se
/// establece nada (la comprobación de URL del original siempre es cierta).
pub fn set_policy_properties(params: &mut ExtraParams, policy_id: &str, format: &str) {
    let hash = policy_property(Some(policy_id), PROPERTY_POLICY_HASH, Some(format));
    if hash.is_none_or(|h| h.trim().is_empty())
        && policy_property(Some(policy_id), PROPERTY_POLICY_IDENTIFIER, Some(format)).is_some()
    {
        return;
    }
    for prop in [
        PROPERTY_POLICY_IDENTIFIER,
        PROPERTY_POLICY_HASH_ALGORITHM,
        PROPERTY_POLICY_HASH,
        PROPERTY_POLICY_QUALIFIER,
        PROPERTY_POLICY_DESCRIPTION,
    ] {
        if let Some(v) = policy_property(Some(policy_id), prop, Some(format)) {
            if params.contains(prop) {
                tracing::warn!(
                    "La siguiente propiedad se ignora en favor del valor derivado de la politica establecida: {prop}"
                );
            }
            params.set(prop, v);
        }
    }
}

/// `AdESPolicyPropertiesManager.isAgePolicyConfigurated`: el identificador
/// es el de alguna de las políticas AGE conocidas.
pub fn is_age_policy_configured(policy_id: Option<&str>) -> bool {
    let Some(id) = policy_id else { return false };
    bundle().iter().any(|(k, v)| k.ends_with(".policyIdentifier") && v == id)
}

/// Familia de formato para la expansión de políticas (`normalizeFormat`):
/// `CAdES`/`CAdEStri` → `CAdES`; `XAdES`/`XAdEStri`/`XAdES *` → `XAdES`;
/// `Adobe PDF`, `PAdES` y sus trifásicas → `PAdES`; cualquier otro, el mismo
/// texto (los formatos ASiC-S no se normalizan).
pub fn normalize_policy_format(format: &str) -> String {
    let eq = |c: &str| equals_ignore_case(format, c);
    if eq(SIGN_FORMAT_CADES) || eq(SIGN_FORMAT_CADES_TRI) {
        FORMAT_CADES.to_string()
    } else if eq(SIGN_FORMAT_XADES) || eq(SIGN_FORMAT_XADES_TRI) || format.to_lowercase().starts_with("xades ") {
        FORMAT_XADES.to_string()
    } else if eq(SIGN_FORMAT_PDF) || eq(SIGN_FORMAT_PADES) || eq(SIGN_FORMAT_PDF_TRI) || eq(SIGN_FORMAT_PADES_TRI) {
        FORMAT_PADES.to_string()
    } else {
        format.to_string()
    }
}

/// `String.format("%1s", s)` de Java: ancho mínimo con relleno a la izquierda.
fn pad_left(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width { s.to_string() } else { format!("{}{s}", " ".repeat(width - n)) }
}

/// `ExtraParamsProcessor.expandProperties(params, signedData, format)`:
/// devuelve una **copia** de los parámetros con `expPolicy` expandido
/// (los valores derivados de la política sustituyen a los del usuario) y sin
/// el propio `expPolicy`. Solo se admiten `FirmaAGE` (CAdES, XAdES y PAdES) y
/// `FirmaAGE18` (CAdES y XAdES); cualquier otra combinación produce el error
/// de incompatibilidad con la política (501008).
///
/// Si `expPolicy` está presente y no se indica el formato, Java falla con un
/// `NullPointerException`; aquí se devuelve un error 200115.
pub fn expand_properties(
    params: &ExtraParams,
    signed_data: Option<&[u8]>,
    format: Option<&str>,
) -> Result<ExtraParams> {
    let mut p = params.clone();
    let Some(policy_name) = p.get(EXTRA_PARAM_EXP_POLICY).map(str::to_string) else { return Ok(p) };
    if policy_name != POLICY_ID_AGE && policy_name != POLICY_ID_AGE_1_8 {
        return Err(AfirmaError::signature_policy_incompatibility(
            format!("No se soporta la expansion de atributos para la politica: {policy_name}"),
            OP_SIGN,
        ));
    }
    let Some(format) = format else {
        return Err(AfirmaError::new(
            crate::error::codes::UNKNOWN_SIGNING_ERROR,
            "No se ha indicado el formato de firma para expandir la politica",
        ));
    };
    let normalized = normalize_policy_format(format);
    if normalized == FORMAT_CADES {
        if !p.contains("mode")
            && let Some(d) = signed_data {
                p.set("mode", if d.len() < SIZE_1MB { SIGN_MODE_IMPLICIT } else { SIGN_MODE_EXPLICIT });
            }
        force_advanced_profile(&mut p);
        set_policy_properties(&mut p, &policy_name, FORMAT_CADES);
    } else if normalized == FORMAT_XADES {
        let xades_format = p.get("format").map(str::to_string);
        let ok = xades_format.as_deref().is_some_and(|f| {
            equals_ignore_case(f, SIGN_FORMAT_XADES_DETACHED) || equals_ignore_case(f, SIGN_FORMAT_XADES_ENVELOPED)
        });
        if !ok {
            if xades_format.is_some() {
                tracing::warn!(
                    "Se ignora la configuracion del parametro 'format' en favor de los requisitos establecidos por la politica de firma"
                );
            }
            p.set("format", SIGN_FORMAT_XADES_DETACHED);
        }
        force_advanced_profile(&mut p);
        set_policy_properties(&mut p, &policy_name, FORMAT_XADES);
    } else if normalized == FORMAT_PADES && policy_name == POLICY_ID_AGE {
        if p.get("signatureSubFilter").is_some_and(|s| s != crate::constants::PADES_SUBFILTER_BES) {
            return Err(AfirmaError::signature_policy_incompatibility(
                "En PAdES con politica firma AGE debe usarse siempre el filtro 'ETSI.CAdES.detached'",
                OP_SIGN,
            ));
        }
        p.set("signatureSubFilter", crate::constants::PADES_SUBFILTER_BES);
        set_policy_properties(&mut p, &policy_name, FORMAT_PADES);
    } else {
        return Err(AfirmaError::signature_policy_incompatibility(
            format!(
                "El formato de firma {} no esta soportado por la politica {}",
                pad_left(format, 1),
                pad_left(&policy_name, 2)
            ),
            OP_SIGN,
        ));
    }
    p.remove(EXTRA_PARAM_EXP_POLICY);
    Ok(p)
}

fn force_advanced_profile(p: &mut ExtraParams) {
    if p.get("profile").is_some_and(|v| v.eq_ignore_ascii_case(SIGN_PROFILE_BASELINE)) {
        tracing::warn!(
            "Se ignora la configuracion del parametro 'profile' en favor de los requisitos establecidos por la politica de firma"
        );
    }
    p.set("profile", SIGN_PROFILE_ADVANCED);
}

/// Política de firma AdES (`AdESPolicy`).
#[derive(Debug, Clone)]
pub struct AdESPolicy {
    identifier: String,
    hash: String,
    hash_algorithm: String,
    qualifier: Option<String>,
    predefined: bool,
}

/// Protocolos para los que `new java.net.URL(...)` tiene manejador.
const JAVA_URL_PROTOCOLS: [&str; 7] = ["http", "https", "ftp", "file", "jar", "mailto", "jrt"];

fn is_java_url(s: &str) -> bool {
    let Some(colon) = s.find(':') else { return false };
    let proto = &s[..colon];
    if proto.is_empty() || proto.contains('/') {
        return false;
    }
    JAVA_URL_PROTOCOLS.contains(&proto.to_ascii_lowercase().as_str())
}

impl AdESPolicy {
    /// `new AdESPolicy(identifier, identifierHash, identifierHashAlgorithm,
    /// qualifier)` usando el cliente HTTP del proceso para descargar la
    /// política si no se indica su huella.
    pub fn new(
        identifier: &str,
        hash: Option<&str>,
        hash_algorithm: Option<&str>,
        qualifier: Option<&str>,
    ) -> Result<Self> {
        Self::new_with_client(
            false,
            identifier,
            hash,
            hash_algorithm,
            qualifier,
            crate::http::installed_http_client().as_ref(),
        )
    }

    /// Constructor completo. Reglas:
    ///
    /// * Identificador vacío → error.
    /// * Sin huella (o huella `"0"`): se descarga el documento del
    ///   identificador (que debe ser una URL `http`, `https` o `file`) y se
    ///   calcula su huella con el algoritmo indicado (normalizado) o SHA-512.
    /// * Con huella: el algoritmo es obligatorio, la huella debe ser Base64 y
    ///   el algoritmo se guarda normalizado (`http://www.w3.org/2000/09/xmldsig#sha1`
    ///   → `SHA1`).
    /// * El calificador, si se indica, debe ser una URL válida.
    pub fn new_with_client(
        predefined: bool,
        identifier: &str,
        hash: Option<&str>,
        hash_algorithm: Option<&str>,
        qualifier: Option<&str>,
        client: &dyn HttpClient,
    ) -> Result<Self> {
        if identifier.is_empty() {
            return Err(AfirmaError::invalid_argument("El identificador de politica no puede ser nulo ni vacio"));
        }
        let (hash, hash_algorithm) = match hash {
            None | Some("0") => {
                let alg = hash_algorithm
                    .map(crate::algorithms::java_digest_algorithm_name)
                    .unwrap_or_else(|| ADES_POLICY_DEFAULT_HASH_ALGORITHM.to_string());
                let digest = download_policy(identifier, client).and_then(|content| {
                    let d: crate::DigestAlgorithm =
                        alg.parse().map_err(|_| format!("Algoritmo de huella no soportado: {alg}"))?;
                    Ok(crate::base64::encode(&d.digest(&content)))
                });
                match digest {
                    Ok(h) => (h, alg),
                    Err(e) => {
                        return Err(AfirmaError::invalid_argument(format!(
                            "Si no se especifica la huella digital de la politica es necesario que el identificador sea una URL accesible universalmente: {e}"
                        )));
                    }
                }
            }
            Some(h) => {
                let Some(alg) = hash_algorithm.filter(|a| !a.is_empty()) else {
                    return Err(AfirmaError::invalid_argument(
                        "Si se indica la huella digital del identificador de politica es obligatorio indicar tambien el algoritmo",
                    ));
                };
                if !crate::base64::is_base64_bytes(h.as_bytes()) {
                    return Err(AfirmaError::invalid_argument(
                        "La huella digital de la politica debe estar en formato Base64",
                    ));
                }
                (h.to_string(), crate::algorithms::java_digest_algorithm_name(alg))
            }
        };
        let qualifier = match qualifier {
            Some(q) if !q.is_empty() => {
                if !is_java_url(q) {
                    return Err(AfirmaError::invalid_argument("El calificador de la politica debe ser una URL valida"));
                }
                Some(q.to_string())
            }
            _ => None,
        };
        Ok(AdESPolicy { identifier: identifier.to_string(), hash, hash_algorithm, qualifier, predefined })
    }

    /// `AdESPolicy.buildAdESPolicy(extraParams)`: `None` si no hay
    /// `policyIdentifier`.
    pub fn from_extra_params(params: &ExtraParams) -> Result<Option<Self>> {
        Self::from_extra_params_with_client(params, crate::http::installed_http_client().as_ref())
    }

    /// Como [`AdESPolicy::from_extra_params`] con un cliente HTTP explícito.
    pub fn from_extra_params_with_client(params: &ExtraParams, client: &dyn HttpClient) -> Result<Option<Self>> {
        let Some(id) = params.get(PROPERTY_POLICY_IDENTIFIER) else { return Ok(None) };
        Self::new_with_client(
            false,
            id,
            params.get(PROPERTY_POLICY_HASH),
            params.get(PROPERTY_POLICY_HASH_ALGORITHM),
            params.get(PROPERTY_POLICY_QUALIFIER),
            client,
        )
        .map(Some)
    }

    /// Identificador (OID `urn:oid:...` o URL).
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Huella en Base64.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Algoritmo de huella normalizado (`SHA1`, `SHA-256`, `SHA-512`...).
    pub fn hash_algorithm(&self) -> &str {
        &self.hash_algorithm
    }

    /// Calificador (URL del documento de la política).
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// Indica si es una política predefinida (de las preferencias).
    pub fn is_predefined(&self) -> bool {
        self.predefined
    }

    /// `asExtraParams()`: parámetros equivalentes (el algoritmo, ya
    /// normalizado). Java guarda el calificador como objeto `URL`, invisible
    /// para `getProperty`; aquí se guarda como texto.
    pub fn as_extra_params(&self) -> ExtraParams {
        let mut p = ExtraParams::new();
        p.set(PROPERTY_POLICY_IDENTIFIER, self.identifier.clone());
        p.set(PROPERTY_POLICY_HASH, self.hash.clone());
        p.set(PROPERTY_POLICY_HASH_ALGORITHM, self.hash_algorithm.clone());
        if let Some(q) = &self.qualifier {
            p.set(PROPERTY_POLICY_QUALIFIER, q.clone());
        }
        p
    }
}

fn download_policy(identifier: &str, client: &dyn HttpClient) -> std::result::Result<Vec<u8>, String> {
    let lower = identifier.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        client.read_url(&HttpRequest::get(identifier)).map_err(|e| e.to_string())
    } else if lower.starts_with("file:") {
        let uri = crate::aoutil::create_uri(identifier).map_err(|e| e.to_string())?;
        crate::aoutil::load_file(&uri, client).map_err(|e| e.to_string())
    } else if is_java_url(identifier) {
        Err(format!("Protocolo no soportado: {identifier}"))
    } else {
        Err(format!("java.net.MalformedURLException: unknown protocol: {identifier}"))
    }
}

/// Igualdad de Java: identificador, huella y algoritmo (no el calificador).
impl PartialEq for AdESPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.identifier == other.identifier && self.hash == other.hash && self.hash_algorithm == other.hash_algorithm
    }
}

impl Eq for AdESPolicy {}

impl std::hash::Hash for AdESPolicy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.identifier.hash(state)
    }
}

impl std::fmt::Display for AdESPolicy {
    /// `toString()` de Java (incluida la comilla final que falta).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Politica de firma: identificador='{}', huella='{}', algoritmo de huella='{}', calificador='{}",
            self.identifier,
            self.hash,
            self.hash_algorithm,
            self.qualifier.as_deref().unwrap_or("null")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{esc, golden, sorted};

    #[test]
    fn expansion_matches_java_oracle() {
        for line in golden("exppolicy.golden").lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            let format = if cols[0] == "<null>" { None } else { Some(cols[0]) };
            let size: i64 = cols[1].parse().unwrap();
            let data = (size >= 0).then(|| vec![0u8; size as usize]);
            let mut p = ExtraParams::new();
            for kv in cols[2].split(';') {
                let (k, v) = kv.split_once('=').unwrap();
                p.set(k, v);
            }
            let got = match expand_properties(&p, data.as_deref(), format) {
                Ok(r) => sorted(&r),
                Err(e) => {
                    assert_eq!(e.code, Some(crate::error::codes::SIGNING_WITH_POLICY_INCOMPATIBILITY));
                    format!("ERR:SignaturePolicyIncompatibilityException:{}", esc(&e.message))
                }
            };
            assert_eq!(got, cols[3], "{line}");
            // El original no se modifica.
            assert!(cols[2].contains("expPolicy") == p.contains("expPolicy"));
        }
    }

    #[test]
    fn spec_tables() {
        assert_eq!(
            policy_property(Some("FirmaAGE18"), PROPERTY_POLICY_HASH, Some("XAdES")),
            Some("V8lVVNGDCPen6VELRD1Ja8HARFk=")
        );
        assert_eq!(
            policy_property(Some("FirmaAGE18"), PROPERTY_POLICY_HASH, Some("CAdES")),
            Some("7SxX3erFuH31TvAw9LZ70N7p1vA=")
        );
        assert_eq!(policy_property(Some("FirmaAGE"), PROPERTY_POLICY_DESCRIPTION, Some("CAdES")), None);
        assert_eq!(policy_property(Some("Otra"), PROPERTY_POLICY_HASH, Some("CAdES")), None);
        for (b64, hex_value) in [
            ("G7roucf600+f03r/o0bAOQ6WAs0=", "1bbae8b9c7fad34f9fd37affa346c0390e9602cd"),
            ("V8lVVNGDCPen6VELRD1Ja8HARFk=", "57c95554d18308f7a7e9510b443d496bc1c04459"),
            ("7SxX3erFuH31TvAw9LZ70N7p1vA=", "ed2c57ddeac5b87df54ef030f4b67bd0dee9d6f0"),
        ] {
            assert_eq!(hex::encode(crate::base64::decode(b64).unwrap()), hex_value);
        }
        assert!(is_age_policy_configured(Some("urn:oid:2.16.724.1.3.1.1.2.1.9")));
        assert!(is_age_policy_configured(Some("urn:oid:2.16.724.1.3.1.1.2.1.8")));
        assert!(!is_age_policy_configured(Some("urn:oid:1.2.3")));
        assert!(!is_age_policy_configured(None));
        assert_eq!(normalize_policy_format("XAdES-ASiC-S"), "XAdES-ASiC-S");
        assert_eq!(normalize_policy_format("adobe pdf triphase"), "PAdES");
        // Sin formato con expPolicy: error (NPE en Java).
        let mut p = ExtraParams::new();
        p.set("expPolicy", "FirmaAGE");
        assert!(expand_properties(&p, None, None).is_err());
        // Las marcas internas se conservan.
        p.set_internal_flag("confirmDifferentProfile");
        assert!(expand_properties(&p, None, Some("CAdES")).unwrap().has_internal_flag("confirmDifferentProfile"));
    }

    struct FakeHttp;
    impl HttpClient for FakeHttp {
        fn read_url(&self, r: &HttpRequest) -> std::result::Result<Vec<u8>, crate::http::HttpClientError> {
            if r.url.contains("existe") {
                Ok(b"documento de politica".to_vec())
            } else {
                Err(crate::http::HttpClientError::Io { url: r.url.clone(), message: "no encontrado".into() })
            }
        }
    }

    #[test]
    fn ades_policy() {
        let p = AdESPolicy::new_with_client(
            false,
            "urn:oid:2.16.724.1.3.1.1.2.1.9",
            Some("G7roucf600+f03r/o0bAOQ6WAs0="),
            Some("http://www.w3.org/2000/09/xmldsig#sha1"),
            Some("https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf"),
            &FakeHttp,
        )
        .unwrap();
        assert_eq!(p.hash_algorithm(), "SHA1");
        let ep = p.as_extra_params();
        assert_eq!(ep.get("policyIdentifierHashAlgorithm"), Some("SHA1"));
        assert_eq!(AdESPolicy::from_extra_params_with_client(&ep, &FakeHttp).unwrap().unwrap(), p);
        assert!(AdESPolicy::from_extra_params_with_client(&ExtraParams::new(), &FakeHttp).unwrap().is_none());
        assert!(
            p.to_string().starts_with("Politica de firma: identificador='urn:oid:2.16.724.1.3.1.1.2.1.9', huella=")
        );
        // Descarga cuando no hay huella (por defecto SHA-512).
        let d = AdESPolicy::new_with_client(false, "https://servidor/existe.pdf", None, None, None, &FakeHttp).unwrap();
        assert_eq!(d.hash_algorithm(), "SHA-512");
        assert_eq!(d.hash(), crate::base64::encode(&crate::DigestAlgorithm::Sha512.digest(b"documento de politica")));
        let d = AdESPolicy::new_with_client(
            false,
            "https://servidor/existe.pdf",
            Some("0"),
            Some("SHA-256"),
            None,
            &FakeHttp,
        )
        .unwrap();
        assert_eq!(d.hash(), crate::base64::encode(&crate::DigestAlgorithm::Sha256.digest(b"documento de politica")));
        // Errores.
        let e = AdESPolicy::new_with_client(false, "urn:oid:1.2.3", None, None, None, &FakeHttp).unwrap_err();
        assert!(e.message.starts_with("Si no se especifica la huella digital de la politica es necesario que el identificador sea una URL accesible universalmente: "));
        assert!(AdESPolicy::new_with_client(false, "https://servidor/falta", None, None, None, &FakeHttp).is_err());
        assert_eq!(
            AdESPolicy::new_with_client(false, "", None, None, None, &FakeHttp).unwrap_err().message,
            "El identificador de politica no puede ser nulo ni vacio"
        );
        assert_eq!(
            AdESPolicy::new_with_client(false, "urn:oid:1", Some("AAAA"), None, None, &FakeHttp).unwrap_err().message,
            "Si se indica la huella digital del identificador de politica es obligatorio indicar tambien el algoritmo"
        );
        assert_eq!(
            AdESPolicy::new_with_client(false, "urn:oid:1", Some("A=AA"), Some("SHA1"), None, &FakeHttp)
                .unwrap_err()
                .message,
            "La huella digital de la politica debe estar en formato Base64"
        );
        assert_eq!(
            AdESPolicy::new_with_client(false, "urn:oid:1", Some("AAAA"), Some("SHA1"), Some("urn:no-url"), &FakeHttp)
                .unwrap_err()
                .message,
            "El calificador de la politica debe ser una URL valida"
        );
        assert!(
            AdESPolicy::new_with_client(true, "urn:oid:1", Some("AAAA"), Some("SHA1"), Some("ftp://x"), &FakeHttp)
                .unwrap()
                .is_predefined()
        );
    }
}
