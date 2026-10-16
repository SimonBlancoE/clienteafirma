//! Ficheros de configuración `.afconfig` (lista de propiedades XML de Apple, subconjunto)
//! con firma XMLDSig opcional: análisis, exportación y comprobación de firma (§4.10).
//!
//! La verificación criptográfica de la firma XMLDSig se delega en un
//! [`ConfigSignatureVerifier`] que proporciona la aplicación (con `afirma-xml`); este
//! módulo aplica la lógica de AutoFirma: detección de firma, validez temporal del
//! certificado, exigencia de firma (`requireSignedPrerefences`, corregida) y certificado
//! autorizado (`certHashToSignedPrerefences`).

use std::collections::BTreeMap;

use base64::Engine as _;
use quick_xml::events::Event;
use sha2::Digest as _;

/// Códigos de error de importación (`ConfiguratorErrorCode`).
pub mod codes {
    /// Error desconocido.
    pub const IMPORTING_PREFERENCES_ERROR: u32 = 230300;
    /// No se pudo leer el fichero.
    pub const CANT_READ_PREFERENCES_FILE: u32 = 230301;
    /// No es un XML válido.
    pub const INVALID_XML_PREFERENCES_FILE: u32 = 230302;
    /// Formato de lista de propiedades no válido.
    pub const INVALID_FORMAT_PREFERENCES_FILE: u32 = 230303;
    /// Certificado firmante fuera de su periodo de validez.
    pub const INVALID_CERTIFICATE_SIGNER: u32 = 522001;
    /// Firma no válida.
    pub const INVALID_PREFERENCES_FILE_SIGNATURE: u32 = 522002;
    /// Firmante no autorizado.
    pub const INVALID_PREFERENCES_FILE_SIGNER: u32 = 522003;
    /// Fichero sin firmar cuando se exige firma.
    pub const UNSIGNED_PREFERENCES_FILE: u32 = 522004;
}

/// Error de importación con código de AutoFirma.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message} (código {code}){}", detail.as_ref().map(|d| format!(": {d}")).unwrap_or_default())]
pub struct ConfigError {
    /// Código (`codes::*`).
    pub code: u32,
    /// Mensaje para el usuario (`ImportPreferencesError.<código>`).
    pub message: String,
    /// Detalle técnico.
    pub detail: Option<String>,
}

impl ConfigError {
    /// Error con el mensaje estándar del código.
    pub fn new(code: u32) -> Self {
        let message = match code {
            codes::CANT_READ_PREFERENCES_FILE => "No se pudo leer el fichero de preferencias",
            codes::INVALID_XML_PREFERENCES_FILE => "El fichero de preferencias no es un XML válido",
            codes::INVALID_FORMAT_PREFERENCES_FILE => {
                "El fichero de preferencias no tiene un formato válido"
            }
            codes::INVALID_CERTIFICATE_SIGNER => {
                "El certificado firmante del fichero de configuración no es válido"
            }
            codes::INVALID_PREFERENCES_FILE_SIGNATURE => {
                "La firma del fichero de configuración no es válida"
            }
            codes::INVALID_PREFERENCES_FILE_SIGNER => {
                "El certificado firmante del fichero de configuración no está autorizado"
            }
            codes::UNSIGNED_PREFERENCES_FILE => {
                "No se permite la importación de ficheros de preferencias sin firmar"
            }
            _ => "Error desconocido importando las preferencias",
        };
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }

    /// Añade un detalle técnico.
    pub fn with_detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

/// Valor de una lista de propiedades.
#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    String(String),
    Bool(bool),
    Integer(i64),
    Real(f64),
    /// Fecha en texto (`yyyy-MM-dd'T'HH:mm:ss'Z'`).
    Date(String),
    Data(Vec<u8>),
    Array(Vec<PlistValue>),
    /// Diccionario (en el orden del fichero).
    Dict(Vec<(String, PlistValue)>),
}

/// Contenido útil de un `.afconfig`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AfconfigContent {
    /// Preferencias (booleanos convertidos a `"true"`/`"false"`).
    pub prefs: BTreeMap<String, String>,
    /// Tarjetas inteligentes (`smartcards`: nombre → biblioteca PKCS#11).
    pub smartcards: Option<BTreeMap<String, String>>,
    /// `true` si el documento contiene algún `ds:Signature`.
    pub has_signature: bool,
}

/// Clave especial con las tarjetas inteligentes.
pub const SMARTCARDS_KEY: &str = "smartcards";
const XMLDSIG_NS: &[u8] = b"http://www.w3.org/2000/09/xmldsig#";
/// Tamaño máximo admitido de un fichero de configuración.
pub const MAX_AFCONFIG_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Default)]
struct Elem {
    name: String,
    children: Vec<Elem>,
    text: String,
}

/// Analiza un `.afconfig`. Acepta (y descarta) la declaración `DOCTYPE` estándar de Apple
/// (Java la rechazaba con 230302); nunca resuelve entidades externas.
pub fn parse(xml: &[u8]) -> Result<AfconfigContent, ConfigError> {
    if xml.len() > MAX_AFCONFIG_SIZE {
        return Err(ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE)
            .with_detail("fichero demasiado grande"));
    }
    let (root, has_signature) = build_dom(xml)?;
    if !root.name.eq_ignore_ascii_case("plist") {
        return Err(ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE)
            .with_detail(format!("elemento raíz «{}»", root.name)));
    }
    let dict = root
        .children
        .iter()
        .find(|c| c.name == "dict")
        .ok_or_else(|| {
            ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE).with_detail("sin diccionario")
        })?;
    let PlistValue::Dict(entries) = parse_value(dict, 0)? else {
        return Err(ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE));
    };
    let mut content = AfconfigContent {
        has_signature,
        ..Default::default()
    };
    for (k, v) in entries {
        if k == SMARTCARDS_KEY {
            let PlistValue::Dict(cards) = v else {
                return Err(ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE)
                    .with_detail("«smartcards» no es un diccionario"));
            };
            let mut m = BTreeMap::new();
            for (name, lib) in cards {
                match lib {
                    PlistValue::String(s) => {
                        m.insert(name, s);
                    }
                    _ => {
                        return Err(ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE)
                            .with_detail(format!("tarjeta «{name}» sin biblioteca")));
                    }
                }
            }
            content.smartcards = Some(m);
            continue;
        }
        let s = match v {
            PlistValue::String(s) => s,
            PlistValue::Bool(b) => b.to_string(),
            _ => {
                return Err(
                    ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE).with_detail(format!(
                        "No se soporta el tipo del valor de «{k}» en un fichero de preferencias"
                    )),
                );
            }
        };
        content.prefs.insert(k, s);
    }
    Ok(content)
}

fn build_dom(xml: &[u8]) -> Result<(Elem, bool), ConfigError> {
    let bad_xml = |d: String| ConfigError::new(codes::INVALID_XML_PREFERENCES_FILE).with_detail(d);
    let mut reader = quick_xml::NsReader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Elem> = Vec::new();
    let mut root: Option<Elem> = None;
    let mut has_sig = false;
    let mut buf = Vec::new();
    loop {
        let ev = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|e| bad_xml(e.to_string()))?;
        match ev {
            (ns, Event::Start(e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if local == "Signature"
                    && matches!(ns, quick_xml::name::ResolveResult::Bound(n) if n.as_ref() == XMLDSIG_NS)
                {
                    has_sig = true;
                }
                if stack.len() > 64 {
                    return Err(bad_xml("anidamiento excesivo".into()));
                }
                stack.push(Elem {
                    name: local,
                    ..Default::default()
                });
            }
            (ns, Event::Empty(e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if local == "Signature"
                    && matches!(ns, quick_xml::name::ResolveResult::Bound(n) if n.as_ref() == XMLDSIG_NS)
                {
                    has_sig = true;
                }
                let el = Elem {
                    name: local,
                    ..Default::default()
                };
                match stack.last_mut() {
                    Some(p) => p.children.push(el),
                    None => root = Some(el),
                }
            }
            (_, Event::End(_)) => {
                let Some(el) = stack.pop() else {
                    return Err(bad_xml("cierre inesperado".into()));
                };
                match stack.last_mut() {
                    Some(p) => p.children.push(el),
                    None => root = Some(el),
                }
            }
            (_, Event::Text(t)) => {
                if let Some(cur) = stack.last_mut() {
                    let s = t.decode().map_err(|e| bad_xml(e.to_string()))?;
                    let s = quick_xml::escape::unescape(&s).map_err(|e| bad_xml(e.to_string()))?;
                    cur.text.push_str(&s);
                }
            }
            (_, Event::GeneralRef(r)) => {
                if let Some(cur) = stack.last_mut() {
                    let name = r.decode().map_err(|e| bad_xml(e.to_string()))?;
                    let resolved = match name.as_ref() {
                        "lt" => "<".to_string(),
                        "gt" => ">".to_string(),
                        "amp" => "&".to_string(),
                        "quot" => "\"".to_string(),
                        "apos" => "'".to_string(),
                        n if n.starts_with('#') => {
                            let code = if let Some(h) = n.strip_prefix("#x") {
                                u32::from_str_radix(h, 16).ok()
                            } else {
                                n[1..].parse().ok()
                            };
                            code.and_then(char::from_u32)
                                .map(String::from)
                                .ok_or_else(|| bad_xml(format!("referencia no válida &{n};")))?
                        }
                        n => return Err(bad_xml(format!("entidad no admitida &{n};"))),
                    };
                    cur.text.push_str(&resolved);
                }
            }
            (_, Event::CData(c)) => {
                if let Some(cur) = stack.last_mut() {
                    cur.text.push_str(&String::from_utf8_lossy(&c));
                }
            }
            (_, Event::Eof) => break,
            _ => {}
        }
        buf.clear();
    }
    if !stack.is_empty() {
        return Err(bad_xml("documento incompleto".into()));
    }
    root.map(|r| (r, has_sig))
        .ok_or_else(|| bad_xml("documento vacío".into()))
}

fn parse_value(e: &Elem, depth: usize) -> Result<PlistValue, ConfigError> {
    let fmt = |d: String| ConfigError::new(codes::INVALID_FORMAT_PREFERENCES_FILE).with_detail(d);
    if depth > 32 {
        return Err(fmt("anidamiento excesivo".into()));
    }
    Ok(match e.name.to_ascii_lowercase().as_str() {
        "string" => PlistValue::String(e.text.clone()),
        "true" => PlistValue::Bool(true),
        "false" => PlistValue::Bool(false),
        "integer" => PlistValue::Integer(
            e.text
                .trim()
                .parse()
                .map_err(|_| fmt(format!("entero no válido «{}»", e.text)))?,
        ),
        "real" => PlistValue::Real(
            e.text
                .trim()
                .parse()
                .map_err(|_| fmt(format!("real no válido «{}»", e.text)))?,
        ),
        "date" => PlistValue::Date(e.text.trim().to_string()),
        "data" => {
            let clean: String = e.text.chars().filter(|c| !c.is_whitespace()).collect();
            PlistValue::Data(
                base64::engine::general_purpose::STANDARD
                    .decode(clean)
                    .map_err(|_| fmt("datos Base64 no válidos".into()))?,
            )
        }
        "array" => PlistValue::Array(
            e.children
                .iter()
                .map(|c| parse_value(c, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        "dict" => {
            let mut out = Vec::new();
            let mut it = e.children.iter();
            while let Some(k) = it.next() {
                if k.name != "key" {
                    return Err(fmt(format!("se esperaba <key> y se encontró <{}>", k.name)));
                }
                let v = it
                    .next()
                    .ok_or_else(|| fmt(format!("clave «{}» sin valor", k.text)))?;
                out.push((k.text.clone(), parse_value(v, depth + 1)?));
            }
            PlistValue::Dict(out)
        }
        other => return Err(fmt(format!("tipo desconocido <{other}>"))),
    })
}

fn escape_xml(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c => o.push(c),
        }
    }
    o
}

fn push_elem(out: &mut String, name: &str, text: &str) {
    if text.is_empty() {
        out.push_str(&format!("<{name}/>"));
    } else {
        out.push_str(&format!("<{name}>{}</{name}>", escape_xml(text)));
    }
}

/// Exporta preferencias como `.afconfig` con el formato exacto de Java
/// (`PreferencesPlistHandler.exportPreferencesToXml`): sin `DOCTYPE`, compacto, los valores
/// exactamente `true`/`false` como `<true/>`/`<false/>` y el resto como `<string>`. Las claves
/// se ordenan alfabéticamente (Java usaba el orden de un `HashMap`).
pub fn export(prefs: &BTreeMap<String, String>, smartcards: &BTreeMap<String, String>) -> String {
    let mut out =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>");
    for (k, v) in prefs {
        push_elem(&mut out, "key", k);
        match v.as_str() {
            "true" => out.push_str("<true/>"),
            "false" => out.push_str("<false/>"),
            _ => push_elem(&mut out, "string", v),
        }
    }
    if !smartcards.is_empty() {
        push_elem(&mut out, "key", SMARTCARDS_KEY);
        out.push_str("<dict>");
        for (n, l) in smartcards {
            push_elem(&mut out, "key", n);
            push_elem(&mut out, "string", l);
        }
        out.push_str("</dict>");
    }
    out.push_str("</dict></plist>");
    out
}

/// Firmante de un fichero de configuración.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSigner {
    /// Certificado del firmante (DER).
    pub certificate_der: Vec<u8>,
}

impl ConfigSigner {
    /// CN del sujeto (o el DN completo si no tiene CN).
    pub fn common_name(&self) -> String {
        use x509_parser::prelude::*;
        match X509Certificate::from_der(&self.certificate_der) {
            Ok((_, c)) => c
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok().map(str::to_string))
                .unwrap_or_else(|| c.subject().to_string()),
            Err(_) => String::from("?"),
        }
    }

    /// Base64(SHA-256(DER)), el formato de `certHashToSignedPrerefences`.
    pub fn pin_hash(&self) -> String {
        base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(&self.certificate_der))
    }
}

/// Verificador criptográfico de firmas XMLDSig de ficheros de configuración.
///
/// Debe validar **todas** las firmas `ds:Signature` del documento (valor de firma y todas
/// las referencias, incluidas las del mismo documento con transformada *enveloped*) usando
/// la clave de `KeyInfo`, y devolver el primer certificado de `X509Data` de la primera
/// firma. Errores: [`codes::INVALID_PREFERENCES_FILE_SIGNATURE`].
pub trait ConfigSignatureVerifier: Send + Sync {
    /// Verifica las firmas del documento.
    fn verify(&self, xml: &[u8]) -> Result<ConfigSigner, ConfigError>;
}

/// Resultado de la comprobación de firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// Fichero sin firmar.
    Unsigned,
    /// Firma válida del firmante indicado.
    Signed(ConfigSigner),
}

/// Requisitos de firma del administrador.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignaturePolicy {
    /// `requireSignedPrerefences`.
    pub require_signed: bool,
    /// `certHashToSignedPrerefences`.
    pub pinned_cert_hash: Option<String>,
}

/// Aplica la lógica de firma de AutoFirma a un fichero ya analizado.
///
/// Desviación documentada: Java rechazaba los ficheros **firmados** cuando
/// `requireSignedPrerefences` era `true` (condición invertida); aquí se rechazan los no firmados.
pub fn check_signature(
    xml: &[u8],
    content: &AfconfigContent,
    verifier: Option<&dyn ConfigSignatureVerifier>,
    policy: &SignaturePolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SignatureStatus, ConfigError> {
    if !content.has_signature {
        if policy.require_signed {
            return Err(ConfigError::new(codes::UNSIGNED_PREFERENCES_FILE));
        }
        return Ok(SignatureStatus::Unsigned);
    }
    let Some(v) = verifier else {
        return Err(ConfigError::new(codes::INVALID_PREFERENCES_FILE_SIGNATURE)
            .with_detail("no hay un verificador de firmas XMLDSig disponible"));
    };
    let signer = v.verify(xml)?;
    {
        use x509_parser::prelude::*;
        let (_, cert) = X509Certificate::from_der(&signer.certificate_der).map_err(|e| {
            ConfigError::new(codes::INVALID_PREFERENCES_FILE_SIGNATURE).with_detail(e.to_string())
        })?;
        let ts = now.timestamp();
        let v = cert.validity();
        if ts < v.not_before.timestamp() || ts > v.not_after.timestamp() {
            return Err(ConfigError::new(codes::INVALID_CERTIFICATE_SIGNER));
        }
    }
    if let Some(pin) = policy
        .pinned_cert_hash
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        && signer.pin_hash() != pin
    {
        return Err(ConfigError::new(codes::INVALID_PREFERENCES_FILE_SIGNER));
    }
    Ok(SignatureStatus::Signed(signer))
}

/// Texto de confirmación de la importación desde la interfaz (§4.10.3, paso 5).
pub fn confirmation_text(status: &SignatureStatus) -> String {
    let base = "Si continua, se reemplazará la configuración actual con la indicada en el fichero, ¿Desea continuar? Si cancela la importación, no se aplicará ninguna configuración del fichero seleccionado.";
    match status {
        SignatureStatus::Signed(s) => format!(
            "{base}\n\nEl fichero de preferencias esta firmado digitalmente por: {}",
            s.common_name()
        ),
        SignatureStatus::Unsigned => format!(
            "{base}\n\nEl fichero de preferencias no esta firmado, no se hizo ningún cambio en la configuración"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>preferencesBlocked</key><true/>
  <key>signatureHashAlgorithm</key><string>SHA512</string>
  <key>defaultSignatureFormatOoxml</key><string>OOXML (Office Open XML)</string>
  <key>omitAskOnClose</key><string>false</string>
  <key>padesSignReason</key><string>Firma &amp; &lt;revisión&gt;</string>
  <key>smartcards</key>
  <dict>
    <key>Tarjeta corporativa</key><string>C:\Windows\System32\corp-pkcs11.dll</string>
  </dict>
</dict>
</plist>"#;

    #[test]
    fn analiza_el_ejemplo_de_la_especificacion() {
        let c = parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(c.prefs["preferencesBlocked"], "true");
        assert_eq!(c.prefs["omitAskOnClose"], "false");
        assert_eq!(c.prefs["padesSignReason"], "Firma & <revisión>");
        assert_eq!(
            c.smartcards.as_ref().unwrap()["Tarjeta corporativa"],
            r"C:\Windows\System32\corp-pkcs11.dll"
        );
        assert!(!c.has_signature);
    }

    #[test]
    fn acepta_doctype_y_detecta_firma() {
        let x = r#"<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>a</key><string>b</string></dict><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature></plist>"#;
        let c = parse(x.as_bytes()).unwrap();
        assert_eq!(c.prefs["a"], "b");
        assert!(c.has_signature);
    }

    #[test]
    fn errores_con_codigo() {
        assert_eq!(
            parse(b"no es xml <").unwrap_err().code,
            codes::INVALID_XML_PREFERENCES_FILE
        );
        assert_eq!(
            parse(b"<plist><array/></plist>").unwrap_err().code,
            codes::INVALID_FORMAT_PREFERENCES_FILE
        );
        assert_eq!(
            parse(b"<plist><dict><key>a</key><integer>3</integer></dict></plist>")
                .unwrap_err()
                .code,
            codes::INVALID_FORMAT_PREFERENCES_FILE
        );
        assert_eq!(
            parse(b"<html/>").unwrap_err().code,
            codes::INVALID_FORMAT_PREFERENCES_FILE
        );
        assert_eq!(
            parse(b"<plist><dict><key>a</key><string>&xxe;</string></dict></plist>")
                .unwrap_err()
                .code,
            codes::INVALID_XML_PREFERENCES_FILE
        );
    }

    #[test]
    fn exporta_como_java_y_relee() {
        let mut p = BTreeMap::new();
        p.insert("omitAskOnClose".to_string(), "true".to_string());
        p.insert("padesSignReason".to_string(), String::new());
        p.insert("x".to_string(), "a<b".to_string());
        let mut sc = BTreeMap::new();
        sc.insert("T".to_string(), "/usr/lib/t.so".to_string());
        let x = export(&p, &sc);
        assert_eq!(
            x,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>omitAskOnClose</key><true/><key>padesSignReason</key><string/><key>x</key><string>a&lt;b</string><key>smartcards</key><dict><key>T</key><string>/usr/lib/t.so</string></dict></dict></plist>"
        );
        let c = parse(x.as_bytes()).unwrap();
        assert_eq!(c.prefs, p);
        assert_eq!(c.smartcards.unwrap(), sc);
    }

    struct FixedVerifier(Vec<u8>);
    impl ConfigSignatureVerifier for FixedVerifier {
        fn verify(&self, _xml: &[u8]) -> Result<ConfigSigner, ConfigError> {
            Ok(ConfigSigner {
                certificate_der: self.0.clone(),
            })
        }
    }

    #[test]
    fn logica_de_firma() {
        let now = chrono::Utc::now();
        let unsigned = AfconfigContent::default();
        let req = SignaturePolicy {
            require_signed: true,
            pinned_cert_hash: None,
        };
        assert_eq!(
            check_signature(b"", &unsigned, None, &req, now)
                .unwrap_err()
                .code,
            codes::UNSIGNED_PREFERENCES_FILE
        );
        assert_eq!(
            check_signature(b"", &unsigned, None, &SignaturePolicy::default(), now).unwrap(),
            SignatureStatus::Unsigned
        );
        let signed = AfconfigContent {
            has_signature: true,
            ..Default::default()
        };
        assert_eq!(
            check_signature(b"", &signed, None, &SignaturePolicy::default(), now)
                .unwrap_err()
                .code,
            codes::INVALID_PREFERENCES_FILE_SIGNATURE
        );
        let pack = crate::certs::generate(&crate::certs::CertProfile::default()).unwrap();
        let v = FixedVerifier(pack.ca_der.clone());
        let st = check_signature(b"", &signed, Some(&v), &req, now).unwrap();
        let SignatureStatus::Signed(s) = &st else {
            panic!()
        };
        assert_eq!(s.common_name(), "Autofirma ROOT");
        let bad_pin = SignaturePolicy {
            require_signed: true,
            pinned_cert_hash: Some("AAAA".into()),
        };
        assert_eq!(
            check_signature(b"", &signed, Some(&v), &bad_pin, now)
                .unwrap_err()
                .code,
            codes::INVALID_PREFERENCES_FILE_SIGNER
        );
        let good_pin = SignaturePolicy {
            require_signed: true,
            pinned_cert_hash: Some(s.pin_hash()),
        };
        assert!(check_signature(b"", &signed, Some(&v), &good_pin, now).is_ok());
        let future = now + chrono::Duration::days(365 * 20);
        assert_eq!(
            check_signature(b"", &signed, Some(&v), &good_pin, future)
                .unwrap_err()
                .code,
            codes::INVALID_CERTIFICATE_SIGNER
        );
        assert!(confirmation_text(&st).contains("firmado digitalmente por: Autofirma ROOT"));
    }
}
