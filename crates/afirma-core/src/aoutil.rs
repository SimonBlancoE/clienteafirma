//! Utilidades de `es.gob.afirma.core.misc.AOUtil` y `AOFileUtils` (§7.2 y
//! §8.4): creación de URI y carga de recursos, serialización de
//! `extraParams` en Base64, nombres X.500, hexadecimal y división de textos.
//!
//! Comportamiento verificado contra el oráculo Java
//! (`testdata/core/uri.golden`, `props.golden` y `misc.golden`).

use crate::extra_params::{ExtraParams, PropertiesError};
use crate::http::{HttpClient, HttpRequest};

/// Error de las utilidades.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AoUtilError {
    /// `IllegalArgumentException`.
    #[error("{0}")]
    IllegalArgument(String),
    /// `URISyntaxException` (mensaje `motivo: entrada`).
    #[error("{0}")]
    UriSyntax(String),
    /// `IOException`.
    #[error("{0}")]
    Io(String),
}

impl From<PropertiesError> for AoUtilError {
    fn from(e: PropertiesError) -> Self {
        AoUtilError::IllegalArgument(e.to_string())
    }
}

impl From<crate::base64::Base64Error> for AoUtilError {
    fn from(e: crate::base64::Base64Error) -> Self {
        AoUtilError::IllegalArgument(e.to_string())
    }
}

/// URI creada por [`create_uri`] (equivalente a `java.net.URI`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaUri {
    text: String,
    scheme: String,
}

impl JavaUri {
    /// Texto de la URI (`URI.toString()`).
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Esquema (`http`, `https`, `file` o `urn`).
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Parte específica del esquema decodificada (`getSchemeSpecificPart()`):
    /// lo que sigue a `esquema:` sin el fragmento, con los `%XX` resueltos.
    pub fn scheme_specific_part(&self) -> String {
        let raw = &self.text[self.scheme.len() + 1..];
        let raw = raw.split('#').next().unwrap_or("");
        percent_decode(raw)
    }

    /// Ruta local de una URI `file` tal y como la abre `AOUtil.loadFile`: la
    /// parte específica del esquema sin un `//` inicial.
    pub fn file_path(&self) -> Option<String> {
        if self.scheme != "file" {
            return None;
        }
        let ssp = self.scheme_specific_part();
        Some(ssp.strip_prefix("//").map(str::to_string).unwrap_or(ssp))
    }
}

impl std::fmt::Display for JavaUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = [bytes[i + 1], bytes[i + 2]];
            if let Some(v) = std::str::from_utf8(&hex).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const SUPPORTED_URI_SCHEMES: [&str; 4] = ["http", "https", "file", "urn"];

/// Esquema de una referencia URI (`java.net.URI.getScheme()`): el texto
/// anterior al primer `:` si va antes de cualquier `/`, `?` o `#` y es un
/// esquema válido.
fn uri_scheme(s: &str) -> Option<&str> {
    let end = s.find([':', '/', '?', '#'])?;
    if s.as_bytes()[end] != b':' || end == 0 {
        return None;
    }
    let scheme = &s[..end];
    let mut chars = scheme.chars();
    let first = chars.next()?;
    (first.is_ascii_alphabetic() && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
        .then_some(scheme)
}

/// Comprobaciones sintácticas de `java.net.URI` sobre el texto ya escapado.
fn check_uri_syntax(s: &str) -> Result<(), AoUtilError> {
    let bytes = s.as_bytes();
    let mut hashes = 0;
    for (i, c) in s.char_indices() {
        let illegal = match c {
            '%' => {
                let ok = bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit);
                if !ok {
                    return Err(AoUtilError::UriSyntax(format!("Malformed escape pair at index {i}: {s}")));
                }
                false
            }
            '#' => {
                hashes += 1;
                hashes > 1
            }
            c if (c as u32) < 0x20 || c == '\u{7f}' => true,
            ' ' | '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}' => true,
            c if !c.is_ascii() => c.is_control() || c.is_whitespace(),
            _ => false,
        };
        if illegal {
            return Err(AoUtilError::UriSyntax(format!("Illegal character at index {i}: {s}")));
        }
    }
    Ok(())
}

/// `AOUtil.createURI`: crea una URI a partir de una ruta local (absoluta,
/// relativa o de Windows) o de una URL `http`, `https`, `file` o `urn`.
/// Las barras invertidas se convierten en `/` y se escapan los caracteres
/// ` <>"{}|^[]` y la comilla invertida; las rutas sin esquema (o con una
/// letra de unidad) pasan a `file://` (con `#` escapado).
pub fn create_uri(file: &str) -> Result<JavaUri, AoUtilError> {
    if file.is_empty() {
        return Err(AoUtilError::IllegalArgument("No se puede crear una URI a partir de un nulo".into()));
    }
    let filename = file.trim_matches(|c: char| c <= ' ');
    if filename.is_empty() {
        return Err(AoUtilError::IllegalArgument("La URI no puede ser una cadena vacia".into()));
    }
    let mut filename = filename.replace('\\', "/");
    for (from, to) in [
        (" ", "%20"),
        ("<", "%3C"),
        (">", "%3E"),
        ("\"", "%22"),
        ("{", "%7B"),
        ("}", "%7D"),
        ("|", "%7C"),
        ("^", "%5E"),
        ("[", "%5B"),
        ("]", "%5D"),
        ("`", "%60"),
    ] {
        filename = filename.replace(from, to);
    }
    check_uri_syntax(&filename)?;
    match uri_scheme(&filename) {
        Some(scheme) if SUPPORTED_URI_SCHEMES.contains(&scheme) => {
            Ok(JavaUri { scheme: scheme.to_string(), text: filename })
        }
        None => create_uri(&format!("file://{}", filename.replace('#', "%23"))),
        Some(scheme) if scheme.len() == 1 && scheme.chars().all(|c| c.is_alphabetic()) => {
            create_uri(&format!("file://{}", filename.replace('#', "%23")))
        }
        Some(_) => Err(AoUtilError::UriSyntax(format!("Tipo de URI no soportado: {filename}"))),
    }
}

/// `AOUtil.loadFile`: lee el contenido de una URI (`file` del disco;
/// `http`/`https` con el cliente HTTP indicado; otros esquemas, error).
pub fn load_file(uri: &JavaUri, client: &dyn HttpClient) -> Result<Vec<u8>, AoUtilError> {
    match uri.scheme() {
        "file" => {
            let path = uri.file_path().unwrap_or_default();
            std::fs::read(&path).map_err(|e| AoUtilError::Io(format!("{path} ({e})")))
        }
        "http" | "https" => {
            client.read_url(&HttpRequest::get(uri.as_str())).map_err(|e| AoUtilError::Io(e.to_string()))
        }
        other => Err(AoUtilError::Io(format!("unknown protocol: {other}"))),
    }
}

/// Carga un recurso a partir de una ruta o URL (`createURI` + `loadFile`)
/// con el cliente HTTP instalado en el proceso.
pub fn load_resource(path_or_url: &str) -> Result<Vec<u8>, AoUtilError> {
    let uri = create_uri(path_or_url)?;
    load_file(&uri, crate::http::installed_http_client().as_ref())
}

/// `ExtraParamsProcessor.loadByteArrayFromExtraParams`: contenido binario de
/// un parámetro. Fuera del modo seguro, un valor de 1 a 254 caracteres que no
/// sea Base64 se trata como ruta o URL y se carga; en otro caso se decodifica
/// como Base64 (alfabeto estándar).
pub fn load_byte_array_from_extra_params(
    extra_params: &ExtraParams,
    name: &str,
    secure_mode: bool,
    client: &dyn HttpClient,
) -> Result<Vec<u8>, AoUtilError> {
    let value = extra_params
        .get(name)
        .ok_or_else(|| AoUtilError::Io(format!("La propiedad '{name}' no se encuentra en el extraParams")))?;
    let len = value.encode_utf16().count();
    if !secure_mode && len > 0 && len < crate::constants::MAX_PATH_SIZE && !crate::base64::is_base64(value) {
        let uri = create_uri(value).map_err(|e| {
            AoUtilError::Io(format!("El propiedad '{name}' no contiene una ruta valida a un recurso: {e}"))
        })?;
        return load_file(&uri, client).map_err(|e| {
            AoUtilError::Io(format!("El propiedad '{name}' no contiene una ruta valida a un recurso: {e}"))
        });
    }
    crate::base64::decode(value).map_err(|e| AoUtilError::Io(e.to_string()))
}

/// `AOUtil.properties2Base64`: `Properties.store(Writer UTF-8, "")` en
/// Base64 URL-safe con relleno.
pub fn properties_to_base64(p: &ExtraParams) -> String {
    crate::base64::encode_url_safe(p.store(Some("")).as_bytes())
}

/// `AOUtil.base642Properties`: cambia `-`→`+` y `_`→`/`, decodifica con el
/// Base64 de Java y carga el resultado como `.properties` UTF-8. Un texto
/// vacío da unos parámetros vacíos.
pub fn base64_to_properties(b64: &str) -> Result<ExtraParams, AoUtilError> {
    if b64.is_empty() {
        return Ok(ExtraParams::new());
    }
    let bytes = crate::base64::decode_url_safe_as_standard(b64)?;
    Ok(ExtraParams::load_utf8(&bytes)?)
}

/// `AOUtil.propertiesAsString`.
pub fn properties_as_string(p: &ExtraParams) -> String {
    p.as_plain_string()
}

/// `ExtraParamsProcessor.convertToProperties`: `Properties.load` sobre los
/// bytes del texto en la codificación de la plataforma interpretados como
/// ISO-8859-1 (los caracteres no ASCII se corrompen salvo escritos como
/// `\uXXXX`). Los errores devuelven lo leído hasta el momento (aquí, vacío).
pub fn convert_to_properties(entries: Option<&str>) -> ExtraParams {
    let Some(entries) = entries else { return ExtraParams::new() };
    ExtraParams::load_iso_8859_1(entries.as_bytes()).unwrap_or_default()
}

const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";

/// `AOUtil.hexify(bytes, boolean)`: hexadecimal en mayúsculas; con separador,
/// `-` entre bytes y salto de línea cada 16 bytes.
pub fn hexify(data: &[u8], separator: bool) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    let mut i = 0;
    for (j, b) in data.iter().enumerate() {
        if separator && i > 0 {
            out.push('-');
        }
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0xf) as usize] as char);
        i += 1;
        if i == 16 {
            if separator && j < data.len() - 1 {
                out.push('\n');
            }
            i = 0;
        }
    }
    out
}

/// `AOUtil.hexify(bytes, String)`: hexadecimal en mayúsculas con el separador
/// entre cada byte.
pub fn hexify_with(data: &[u8], separator: Option<&str>) -> String {
    let mut out = String::new();
    for (j, b) in data.iter().enumerate() {
        if let (Some(sep), true) = (separator, j > 0) {
            out.push_str(sep);
        }
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    out
}

/// `AOUtil.split`: división literal que conserva los campos vacíos, también
/// el final (`"a$b$"` → `["a", "b", ""]`).
pub fn split(text: &str, sep: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut i = 0;
    if sep.is_empty() {
        return vec![text.to_string()];
    }
    while i != text.len() {
        match text[i..].find(sep) {
            Some(off) => {
                parts.push(text[i..i + off].to_string());
                i += off + sep.len();
            }
            None => break,
        }
    }
    if i == text.len() {
        parts.push(String::new());
    } else {
        parts.push(text[i..].to_string());
    }
    parts
}

/// `AOUtil.isOnlyNumber`: no vacío y solo dígitos ASCII.
pub fn is_only_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// `AOUtil.getRDNvalueFromLdapName`: valor de un atributo en un nombre X.500
/// textual (búsqueda sin distinguir mayúsculas; valores entre comillas o
/// hasta la siguiente coma, recortados). `None` si no aparece.
pub fn get_rdn_value_from_ldap_name(rdn: &str, principal: &str) -> Option<String> {
    let lower = principal.to_lowercase();
    let rdn_lower = rdn.to_lowercase();
    // Se trabaja con índices de caracteres para reproducir `charAt`.
    let chars: Vec<char> = principal.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();
    if lower_chars.len() != chars.len() {
        // Cambios de longitud al pasar a minúsculas: búsqueda simple.
        return get_rdn_simple(&rdn_lower, principal);
    }
    let rdn_chars: Vec<char> = rdn_lower.chars().collect();
    let find = |from: usize| -> Option<usize> {
        if rdn_chars.is_empty() {
            return Some(from.min(lower_chars.len()));
        }
        (from..lower_chars.len().saturating_sub(rdn_chars.len() - 1))
            .find(|&i| lower_chars[i..i + rdn_chars.len()] == rdn_chars[..])
    };
    let mut offset1 = 0;
    while let Some(found) = find(offset1) {
        offset1 = found;
        if offset1 > 0 && chars[offset1 - 1] != ',' && chars[offset1 - 1] != ' ' {
            offset1 += 1;
            continue;
        }
        offset1 += rdn_chars.len();
        while offset1 < chars.len() && chars[offset1] == ' ' {
            offset1 += 1;
        }
        if offset1 >= chars.len() {
            return None;
        }
        if chars[offset1] != '=' {
            continue;
        }
        offset1 += 1;
        while offset1 < chars.len() && chars[offset1] == ' ' {
            offset1 += 1;
        }
        if offset1 >= chars.len() {
            return Some(String::new());
        }
        if chars[offset1] == ',' {
            return Some(String::new());
        }
        if chars[offset1] == '"' {
            offset1 += 1;
            if offset1 >= chars.len() {
                return Some(String::new());
            }
            return match chars[offset1..].iter().position(|&c| c == '"') {
                Some(0) => Some(String::new()),
                Some(p) => Some(chars[offset1..offset1 + p].iter().collect()),
                None => Some(chars[offset1..].iter().collect()),
            };
        }
        let value: String = match chars[offset1..].iter().position(|&c| c == ',') {
            Some(p) => chars[offset1..offset1 + p].iter().collect(),
            None => chars[offset1..].iter().collect(),
        };
        return Some(value.trim_matches(|c: char| c <= ' ').to_string());
    }
    None
}

fn get_rdn_simple(rdn_lower: &str, principal: &str) -> Option<String> {
    principal.split(',').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim().to_lowercase() == rdn_lower).then(|| v.trim().trim_matches('"').to_string())
    })
}

/// `AOUtil.getCN(String)`: valor de `cn`, si no de `ou`, si no del primer
/// atributo; sin `=` devuelve el texto completo.
pub fn get_cn(principal: &str) -> String {
    if let Some(v) =
        get_rdn_value_from_ldap_name("cn", principal).or_else(|| get_rdn_value_from_ldap_name("ou", principal))
    {
        return v;
    }
    match principal.find('=') {
        Some(i) => get_rdn_value_from_ldap_name(&principal[..i], principal).unwrap_or_default(),
        None => principal.to_string(),
    }
}

/// `AOUtil.getOUS`: todos los valores `ou` del nombre.
pub fn get_ous(principal: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut aux = principal.to_string();
    let mut ou = get_rdn_value_from_ldap_name("ou", &aux);
    while let Some(v) = ou {
        if out.len() > 64 {
            break;
        }
        aux = aux
            .replace(&format!("OU={v}"), "")
            .replace(&format!("OU=\"{v}"), "\"")
            .replace(&format!("ou={v}"), "")
            .replace(&format!("ou=\"{v}"), "\"");
        out.push(v);
        ou = get_rdn_value_from_ldap_name("ou", &aux);
    }
    out
}

/// `AOFileUtils.pathLengthShortener`: acorta una ruta a `limit` caracteres
/// conservando el nombre del fichero y el principio de la ruta, con `...`
/// en medio (`C:\Users\...fichero.txt`).
pub fn path_length_shortener(path: &str, limit: usize) -> String {
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= limit {
        return path.to_string();
    }
    let ellipsis = ['.', '.', '.'];
    let mut short = vec!['\0'; limit];
    let mut i = 0;
    while i < limit {
        let c = chars[chars.len() - 1 - i];
        if c == '/' || c == '\\' {
            break;
        }
        short[limit - 1 - i] = c;
        i += 1;
    }
    let free = limit - i;
    if free < ellipsis.len() {
        for (k, e) in ellipsis.iter().enumerate().take(limit) {
            short[k] = *e;
        }
    } else {
        let mut j = 0;
        while j + ellipsis.len() < free {
            short[j] = chars[j];
            j += 1;
        }
        let mut k = 0;
        while j + k < free {
            short[j + k] = ellipsis[k];
            k += 1;
        }
    }
    short.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{esc, golden, sorted, unesc};

    #[test]
    fn create_uri_matches_java_oracle() {
        for line in golden("uri.golden").lines() {
            let cols: Vec<&str> = line.split('\t').collect();
            let input = unesc(cols[0]);
            let got = match create_uri(&input) {
                Ok(u) => format!("{}\t{}\t{}", esc(u.as_str()), esc(u.scheme()), esc(&u.scheme_specific_part())),
                Err(AoUtilError::IllegalArgument(m)) => format!("ERR:IllegalArgumentException:{}", esc(&m)),
                Err(AoUtilError::UriSyntax(m)) => format!("ERR:URISyntaxException:{}", esc(&m)),
                Err(e) => format!("ERR:{e}"),
            };
            assert_eq!(got, cols[1..].join("\t"), "entrada {input:?}");
        }
        assert!(create_uri("/tmp/100%.pdf").is_err());
        assert_eq!(create_uri("/a b.pdf").unwrap().file_path().unwrap(), "/a b.pdf");
        assert_eq!(create_uri("a.pdf").unwrap().file_path().unwrap(), "a.pdf");
        assert_eq!(create_uri("C:\\x\\y.pdf").unwrap().file_path().unwrap(), "C:/x/y.pdf");
        assert_eq!(create_uri("http://x/y").unwrap().file_path(), None);
    }

    #[test]
    fn base64_properties_match_java_oracle() {
        for line in golden("props.golden").lines().filter(|l| l.starts_with("B642P\t")) {
            let cols: Vec<&str> = line.split('\t').collect();
            let input = unesc(cols[1]);
            let got = match base64_to_properties(&input) {
                Ok(p) => sorted(&p),
                Err(e) => format!("ERR:IllegalArgumentException:{}", esc(&e.to_string())),
            };
            assert_eq!(got, cols[2], "entrada {input:?}");
        }
        let mut p = ExtraParams::new();
        p.set("format", "XAdES Detached");
        p.set("ciudad", "Logroño");
        let b64 = properties_to_base64(&p);
        assert!(!b64.contains('+') && !b64.contains('/'));
        let text = String::from_utf8(crate::base64::decode_url_safe(&b64).unwrap()).unwrap();
        assert!(text.starts_with("#\n#") || text.starts_with("#\r\n#"));
        assert!(text.contains("ciudad=Logroño"));
        assert_eq!(base64_to_properties(&b64).unwrap(), p);
        assert_eq!(properties_as_string(&p), "ciudad=Logroño\nformat=XAdES Detached\n");
        assert_eq!(convert_to_properties(Some("a=\\u00f1")).get("a"), Some("ñ"));
        assert!(convert_to_properties(None).is_empty());
    }

    #[test]
    fn misc_matches_java_oracle() {
        let g = golden("misc.golden");
        let b: Vec<u8> = (0..20u32).map(|i| (i * 13) as u8).collect();
        let hex_line = g.lines().find(|l| l.starts_with("HEXIFY\t")).unwrap();
        let cols: Vec<&str> = hex_line.split('\t').collect();
        assert_eq!(esc(&hexify(&b, true)), cols[1]);
        assert_eq!(hexify(&b, false), cols[2]);
        assert_eq!(hexify_with(&b, Some(":")), cols[3]);
        for line in g.lines().filter(|l| l.starts_with("SPLIT\t")) {
            let cols: Vec<&str> = line.split('\t').collect();
            let parts = split(cols[1], "$");
            assert_eq!(parts.join("|"), cols[2], "split {:?}", cols[1]);
            assert_eq!(parts.len().to_string(), cols[3]);
        }
        for line in g.lines().filter(|l| l.starts_with("CN\t")) {
            let cols: Vec<&str> = line.split('\t').collect();
            let principal = unesc(cols[1]);
            assert_eq!(esc(&get_cn(&principal)), cols[2], "getCN {principal:?}");
            assert_eq!(esc(&get_ous(&principal).join("|")), cols.get(3).copied().unwrap_or(""), "getOUS {principal:?}");
        }
        assert_eq!(hexify(&[], true), "");
        assert_eq!(hexify_with(&[0xab, 0x01], None), "AB01");
        assert!(is_only_number("0123"));
        assert!(!is_only_number(""));
        assert!(!is_only_number("12a"));
    }

    #[test]
    fn shortener() {
        assert_eq!(path_length_shortener("C:\\Users\\foo\\bar\\file.txt", 20), "C:\\Users\\...file.txt");
        assert_eq!(path_length_shortener("/corto", 20), "/corto");
        assert_eq!(path_length_shortener("/a/nombre-muy-largo.txt", 10), "...rgo.txt");
        assert_eq!(path_length_shortener("/abc/defghij.txt", 13), "...efghij.txt");
        assert_eq!(path_length_shortener("abcdef", 2), "..");
    }

    struct NoHttp;
    impl HttpClient for NoHttp {
        fn read_url(&self, r: &HttpRequest) -> Result<Vec<u8>, crate::http::HttpClientError> {
            Ok(r.url.clone().into_bytes())
        }
    }

    #[test]
    fn byte_array_params() {
        let dir = std::env::temp_dir().join(format!("afirma-core-aoutil-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("imagen con espacio.bin");
        std::fs::write(&f, [1u8, 2, 3]).unwrap();
        let mut p = ExtraParams::new();
        p.set("img", f.to_string_lossy());
        p.set("b64", "AQID");
        p.set("url", "https://servidor/recurso");
        p.set("mala", "no/existe/fichero.bin");
        assert_eq!(load_byte_array_from_extra_params(&p, "img", false, &NoHttp).unwrap(), vec![1, 2, 3]);
        assert!(load_byte_array_from_extra_params(&p, "img", true, &NoHttp).is_ok_and(|v| v != vec![1, 2, 3]));
        assert_eq!(load_byte_array_from_extra_params(&p, "b64", false, &NoHttp).unwrap(), vec![1, 2, 3]);
        assert_eq!(load_byte_array_from_extra_params(&p, "url", false, &NoHttp).unwrap(), b"https://servidor/recurso");
        let e = load_byte_array_from_extra_params(&p, "mala", false, &NoHttp).unwrap_err();
        assert!(e.to_string().starts_with("El propiedad 'mala' no contiene una ruta valida a un recurso"));
        let e = load_byte_array_from_extra_params(&p, "falta", false, &NoHttp).unwrap_err();
        assert_eq!(e.to_string(), "La propiedad 'falta' no se encuentra en el extraParams");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Error de [`BoundedLineReader`] al superar el número máximo de líneas.
pub const LINE_LIMIT_MESSAGE: &str = "BoundedBufferedReader - Line read limit has been reached.";

/// Lector de líneas con límites (`BoundedBufferedReader`): como máximo
/// `max_lines` líneas (4096 por defecto) de `max_line_len` caracteres (4096);
/// una línea más larga se parte y el resto se devuelve en la siguiente
/// llamada. Finales de línea: CR, LF y CRLF.
pub struct BoundedLineReader<I: Iterator<Item = char>> {
    chars: std::iter::Peekable<I>,
    max_lines: usize,
    max_line_len: usize,
    current_line: usize,
}

impl<I: Iterator<Item = char>> BoundedLineReader<I> {
    /// Lector con los límites por defecto (4096 líneas de 4096 caracteres).
    pub fn new(chars: I) -> Self {
        BoundedLineReader { chars: chars.peekable(), max_lines: 4096, max_line_len: 4096, current_line: 1 }
    }

    /// Lector con límites explícitos (ambos mayores que cero).
    pub fn with_limits(chars: I, max_lines: usize, max_line_len: usize) -> Result<Self, AoUtilError> {
        if max_lines == 0 || max_line_len == 0 {
            return Err(AoUtilError::IllegalArgument(
                "BoundedBufferedReader - maxLines and maxLineLen must be greater than 0".into(),
            ));
        }
        Ok(BoundedLineReader { chars: chars.peekable(), max_lines, max_line_len, current_line: 1 })
    }

    /// Lee la siguiente línea (`None` al final).
    pub fn read_line(&mut self) -> Result<Option<String>, AoUtilError> {
        if self.current_line > self.max_lines {
            return Err(AoUtilError::Io(LINE_LIMIT_MESSAGE.into()));
        }
        self.current_line += 1;
        let mut line = String::new();
        let mut count = 0;
        let mut current = self.chars.next();
        while let Some(c) = current {
            if c == '\r' || c == '\n' {
                break;
            }
            line.push(c);
            count += 1;
            if count < self.max_line_len {
                current = self.chars.next();
            } else {
                break;
            }
        }
        match current {
            None => return Ok((!line.is_empty()).then_some(line)),
            Some('\r') => {
                if self.chars.peek() == Some(&'\n') {
                    self.chars.next();
                }
            }
            Some('\n') => {}
            Some(_) => {
                // Línea cortada por longitud: se consume un fin de línea inmediato.
                match self.chars.peek() {
                    Some('\r') => {
                        self.chars.next();
                        if self.chars.peek() == Some(&'\n') {
                            self.chars.next();
                        }
                    }
                    Some('\n') => {
                        self.chars.next();
                    }
                    _ => {}
                }
            }
        }
        Ok(Some(line))
    }
}

#[cfg(test)]
mod bounded_reader_tests {
    use super::*;

    #[test]
    fn bounded_lines() {
        let mut r = BoundedLineReader::new("uno\r\ndos\rtres\ncuatro".chars());
        let mut lines = Vec::new();
        while let Some(l) = r.read_line().unwrap() {
            lines.push(l);
        }
        assert_eq!(lines, vec!["uno", "dos", "tres", "cuatro"]);
        let mut r = BoundedLineReader::with_limits("abcdef\r\ngh".chars(), 10, 3).unwrap();
        assert_eq!(r.read_line().unwrap().unwrap(), "abc");
        assert_eq!(r.read_line().unwrap().unwrap(), "def");
        assert_eq!(r.read_line().unwrap().unwrap(), "gh");
        assert_eq!(r.read_line().unwrap(), None);
        let mut r = BoundedLineReader::with_limits("a\nb\nc\n".chars(), 2, 10).unwrap();
        r.read_line().unwrap();
        r.read_line().unwrap();
        assert_eq!(r.read_line().unwrap_err().to_string(), LINE_LIMIT_MESSAGE);
        assert!(BoundedLineReader::with_limits("".chars(), 0, 1).is_err());
        let mut r = BoundedLineReader::new("\n\nx".chars());
        assert_eq!(r.read_line().unwrap().unwrap(), "");
        assert_eq!(r.read_line().unwrap().unwrap(), "");
        assert_eq!(r.read_line().unwrap().unwrap(), "x");
    }
}
