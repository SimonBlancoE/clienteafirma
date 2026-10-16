//! Documentos de huellas de directorio (§7.5.5): XML (`.hashfiles`,
//! `XmlHashDocument`) y texto (`.txthashfiles`, `TxtHashDocument`).
//!
//! La escritura reproduce byte a byte la salida de Java (salvo el orden de las
//! entradas, que aquí es determinista y alfabético). La lectura detecta el
//! formato por el contenido y valida la estructura como el esquema
//! `folderhashes.xsd`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use afirma_core::DigestAlgorithm;
use afirma_xml::dom::{Document, NodeId, NodeKind};
use base64::Engine as _;

use crate::HashError;
use crate::algorithm::{DEFAULT_ALGORITHM, is_xml_algorithm, parse_algorithm};
use crate::single::{decode_hex_text, hex_upper, hex_with_suffix};
use crate::xmlout::{XML_DECLARATION, push_attr};

/// Espacio de nombres `xsi` (sus atributos se toleran en la validación).
const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// Formato de un documento de huellas de directorio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DirDocumentFormat {
    /// XML (`.hashfiles`). Predeterminado.
    #[default]
    Xml,
    /// Texto plano (`.txthashfiles`).
    Txt,
}

impl DirDocumentFormat {
    /// Nombre del formato en la línea de comandos (`-hformat xml|txt`).
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Xml => "xml",
            Self::Txt => "txt",
        }
    }

    /// Formato correspondiente a un nombre de `-hformat` (ya en minúsculas).
    pub fn from_cli_name(name: &str) -> Option<Self> {
        match name {
            "xml" => Some(Self::Xml),
            "txt" => Some(Self::Txt),
            _ => None,
        }
    }

    /// Extensión (sin punto) de los documentos de este formato.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Xml => "hashfiles",
            Self::Txt => "txthashfiles",
        }
    }

    /// Descripción del filtro del diálogo de guardado.
    pub fn filter_description(self) -> &'static str {
        match self {
            Self::Xml => "Huellas digitales en formato XML (*.hashfiles)",
            Self::Txt => "Huellas digitales en formato TXT (*.txthashfiles)",
        }
    }

    /// Formato con el que se guarda según la extensión elegida en el diálogo
    /// de guardado (`CreateHashDirDialog`): `.txthashfiles` o `.txt` (sin
    /// distinguir mayúsculas) → TXT; cualquier otra (incluidas `.csv` y
    /// ninguna) → XML.
    pub fn from_save_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match name.rfind('.') {
            Some(pos) => {
                let ext = &name[pos + 1..];
                if ext.eq_ignore_ascii_case("txthashfiles") || ext.eq_ignore_ascii_case("txt") {
                    Self::Txt
                } else {
                    Self::Xml
                }
            }
            None => Self::Xml,
        }
    }

    /// Detecta el formato por el contenido: XML si (tras un BOM y espacios
    /// opcionales) empieza por `<`; texto en otro caso.
    pub fn sniff(content: &[u8]) -> Self {
        let mut data = content;
        for bom in [
            &[0xEF, 0xBB, 0xBF][..],
            &[0xFE, 0xFF][..],
            &[0xFF, 0xFE][..],
        ] {
            if let Some(rest) = data.strip_prefix(bom) {
                if bom.len() == 2 {
                    // UTF-16 con BOM: solo puede ser XML.
                    return Self::Xml;
                }
                data = rest;
                break;
            }
        }
        match data
            .iter()
            .find(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            Some(b'<') => Self::Xml,
            _ => Self::Txt,
        }
    }
}

impl fmt::Display for DirDocumentFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.cli_name())
    }
}

/// Error al cargar un documento de huellas.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DocumentError {
    /// El documento no tiene un formato soportado o no es válido
    /// (`DocumentException`).
    #[error("El documento de huellas no es válido o no está soportado: {0}")]
    Unsupported(String),
    /// El documento declara huellas inconsistentes (`CorruptedDocumentException`).
    #[error("El documento de huellas está corrupto o ha sido manipulado: {0}")]
    Corrupted(String),
}

impl DocumentError {
    /// Mensaje que muestra la interfaz gráfica (`CheckHashDialog.17` / `.18`).
    pub fn gui_message(&self) -> &'static str {
        match self {
            Self::Unsupported(_) => crate::messages::get("CheckHashDialog.17"),
            Self::Corrupted(_) => crate::messages::get("CheckHashDialog.18"),
        }
    }
}

fn unsupported(msg: impl Into<String>) -> DocumentError {
    DocumentError::Unsupported(msg.into())
}

fn corrupted(msg: impl Into<String>) -> DocumentError {
    DocumentError::Corrupted(msg.into())
}

/// Documento de huellas de un directorio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashDocument {
    /// Algoritmo de huella.
    pub algorithm: DigestAlgorithm,
    /// Si se recorrieron los subdirectorios.
    pub recursive: bool,
    /// Huellas por ruta relativa (con `/`), en orden alfabético.
    pub entries: BTreeMap<String, Vec<u8>>,
}

impl Default for HashDocument {
    fn default() -> Self {
        Self {
            algorithm: DEFAULT_ALGORITHM,
            recursive: false,
            entries: BTreeMap::new(),
        }
    }
}

impl HashDocument {
    /// Documento vacío con el algoritmo y la recursión indicados.
    pub fn new(algorithm: DigestAlgorithm, recursive: bool) -> Self {
        Self {
            algorithm,
            recursive,
            entries: BTreeMap::new(),
        }
    }

    /// Genera el documento en el formato indicado (siempre en UTF-8).
    pub fn generate(&self, format: DirDocumentFormat) -> Result<Vec<u8>, HashError> {
        match format {
            DirDocumentFormat::Xml => self.to_xml(),
            DirDocumentFormat::Txt => self.to_txt(),
        }
    }

    /// Documento XML (`.hashfiles`) con el formato exacto del transformador
    /// del JDK: declaración, sangrado de 4 espacios, atributos en orden
    /// alfabético y salto de línea final.
    ///
    /// Falla si el algoritmo no está admitido por `folderhashes.xsd`
    /// (SHA-224) o si una ruta contiene caracteres no representables en XML 1.0.
    pub fn to_xml(&self) -> Result<Vec<u8>, HashError> {
        if !is_xml_algorithm(self.algorithm) {
            return Err(HashError::Generation(format!(
                "el algoritmo {} no está admitido en los documentos XML de huellas",
                self.algorithm
            )));
        }
        let mut out = String::with_capacity(128 + self.entries.len() * 160);
        out.push_str(XML_DECLARATION);
        out.push_str("<entries hashAlgorithm=\"");
        out.push_str(self.algorithm.name());
        out.push_str("\" recursive=\"");
        out.push_str(if self.recursive { "true" } else { "false" });
        out.push('"');
        if self.entries.is_empty() {
            out.push_str("/>\n");
            return Ok(out.into_bytes());
        }
        out.push_str(">\n");
        for (name, digest) in &self.entries {
            out.push_str("    <entry hash=\"");
            out.push_str(&afirma_core::base64::encode_url_safe(digest));
            out.push_str("\" hexhash=\"");
            out.push_str(&hex_with_suffix(digest));
            out.push_str("\" name=\"");
            push_attr(&mut out, name).map_err(|c| HashError::UnrepresentableName {
                name: name.clone(),
                reason: format!(
                    "contiene el carácter U+{:04X}, no admitido en XML",
                    u32::from(c)
                ),
            })?;
            out.push_str("\"/>\n");
        }
        out.push_str("</entries>\n");
        Ok(out.into_bytes())
    }

    /// Documento de texto (`.txthashfiles`): cabeceras `;charset=`,
    /// `;hashAlgorithm=` y `;recursive=` y una línea `ruta;HEX` por fichero,
    /// todas terminadas en CRLF.
    ///
    /// Falla si una ruta contiene saltos de línea o empieza por `;` (no se
    /// podrían volver a leer).
    pub fn to_txt(&self) -> Result<Vec<u8>, HashError> {
        let mut out = String::with_capacity(64 + self.entries.len() * 140);
        out.push_str(";charset=UTF-8\r\n;hashAlgorithm=");
        out.push_str(self.algorithm.name());
        out.push_str("\r\n;recursive=");
        out.push_str(if self.recursive { "true" } else { "false" });
        out.push_str("\r\n");
        for (name, digest) in &self.entries {
            if name.contains(['\r', '\n']) || name.starts_with(';') {
                return Err(HashError::UnrepresentableName {
                    name: name.clone(),
                    reason: "las rutas de un documento TXT no pueden contener saltos de línea ni empezar por ';'"
                        .into(),
                });
            }
            out.push_str(name);
            out.push(';');
            out.push_str(&hex_upper(digest));
            out.push_str("\r\n");
        }
        Ok(out.into_bytes())
    }

    /// Carga un documento detectando su formato por el contenido.
    pub fn parse(content: &[u8]) -> Result<Self, DocumentError> {
        match DirDocumentFormat::sniff(content) {
            DirDocumentFormat::Xml => Self::parse_xml(content),
            DirDocumentFormat::Txt => Self::parse_txt(content),
        }
    }

    /// Carga un documento XML validando su estructura según `folderhashes.xsd`.
    ///
    /// Si una entrada declara `hash` y `hexhash` distintos el documento se
    /// considera corrupto ([`DocumentError::Corrupted`]).
    pub fn parse_xml(content: &[u8]) -> Result<Self, DocumentError> {
        let (doc, _) = Document::parse_bytes(content)
            .map_err(|e| unsupported(format!("el documento no es un XML válido: {e}")))?;
        let root = doc
            .document_element()
            .ok_or_else(|| unsupported("el documento XML no tiene elemento raíz"))?;
        let root_el = element_named(&doc, root, "entries")?;

        check_attributes(root_el, &["hashAlgorithm", "recursive"])?;
        let alg_name = root_el
            .attr("hashAlgorithm")
            .ok_or_else(|| unsupported("falta el atributo hashAlgorithm"))?;
        let algorithm = XML_ALGORITHM_NAMES
            .iter()
            .find(|(n, _)| *n == alg_name)
            .map(|(_, a)| *a)
            .ok_or_else(|| {
                unsupported(format!("algoritmo no admitido en el documento: {alg_name}"))
            })?;
        let recursive = match root_el.attr("recursive").map(str::trim) {
            Some("true" | "1") => true,
            Some("false" | "0") => false,
            Some(other) => {
                return Err(unsupported(format!(
                    "valor de recursive no válido: {other}"
                )));
            }
            None => return Err(unsupported("falta el atributo recursive")),
        };

        let mut entries = BTreeMap::new();
        for &child in doc.children(root) {
            match doc.kind(child) {
                NodeKind::Element(_) => {}
                NodeKind::Text { text, .. } => {
                    if !is_xml_whitespace(text) {
                        return Err(unsupported("el elemento entries contiene texto"));
                    }
                    continue;
                }
                _ => continue,
            }
            let el = element_named(&doc, child, "entry")?;
            check_attributes(el, &["hash", "name", "hexhash"])?;
            if doc
                .children(child)
                .iter()
                .any(|&c| doc.element(c).is_some())
            {
                return Err(unsupported("el elemento entry no puede contener elementos"));
            }
            let name = el
                .attr("name")
                .ok_or_else(|| unsupported("falta el atributo name de una entrada"))?;
            let b64 = el
                .attr("hash")
                .ok_or_else(|| unsupported(format!("falta el atributo hash de {name}")))?;
            let from_b64 = decode_url_safe_strict(b64);
            let digest = match el.attr("hexhash") {
                Some(hexhash) => {
                    let from_hex = decode_hex_text(hexhash.trim().as_bytes());
                    match (from_b64, from_hex) {
                        (Some(a), Some(b)) if a == b => a,
                        _ => {
                            return Err(corrupted(format!(
                                "la entrada {name} declara dos huellas distintas (hash y hexhash)"
                            )));
                        }
                    }
                }
                None => from_b64
                    .ok_or_else(|| unsupported(format!("huella Base64 no válida en {name}")))?,
            };
            insert_entry(&mut entries, name, digest, algorithm)?;
        }
        Ok(Self {
            algorithm,
            recursive,
            entries,
        })
    }

    /// Carga un documento de texto (`TxtHashDocument.load`).
    ///
    /// Se decodifica con el juego de caracteres de la cabecera `;charset=` de
    /// la primera línea (UTF-8 si no hay). Las líneas que empiezan por `;` al
    /// principio son cabeceras (las desconocidas se ignoran); el resto son
    /// `ruta;HEX` (con `h` final opcional). Las líneas vacías se ignoran.
    pub fn parse_txt(content: &[u8]) -> Result<Self, DocumentError> {
        let text = decode_txt(content)?;
        let mut algorithm = DEFAULT_ALGORITHM;
        let mut recursive = false;
        let mut entries = BTreeMap::new();
        let mut in_headers = true;
        let mut lines = 0usize;
        for line in split_lines(&text) {
            if in_headers && line.starts_with(';') {
                lines += 1;
                if let Some(v) = line.strip_prefix(";hashAlgorithm=") {
                    algorithm = parse_algorithm(v).map_err(|_| {
                        unsupported(format!("algoritmo no soportado en el documento: {v}"))
                    })?;
                } else if let Some(v) = line.strip_prefix(";recursive=") {
                    // `Boolean.parseBoolean`.
                    recursive = v.eq_ignore_ascii_case("true");
                }
                continue;
            }
            in_headers = false;
            let line = line.trim_end_matches([' ', '\t']);
            if line.is_empty() {
                continue;
            }
            lines += 1;
            // Se separa por el último `;` (la huella nunca lo contiene).
            let pos = line
                .rfind(';')
                .ok_or_else(|| unsupported(format!("línea de huella no válida: {line}")))?;
            if line.starts_with(';') || pos == line.len() - 1 {
                return Err(unsupported(format!("línea de huella no válida: {line}")));
            }
            let (name, hex) = (&line[..pos], &line[pos + 1..]);
            let digest = decode_hex_text(hex.as_bytes())
                .ok_or_else(|| unsupported(format!("huella hexadecimal no válida en {name}")))?;
            insert_entry(&mut entries, name, digest, algorithm)?;
        }
        if lines == 0 {
            return Err(unsupported("el documento de huellas TXT está vacío"));
        }
        Ok(Self {
            algorithm,
            recursive,
            entries,
        })
    }
}

/// Nombres de algoritmo exactos que admite el esquema XML.
const XML_ALGORITHM_NAMES: [(&str, DigestAlgorithm); 4] = [
    ("SHA-1", DigestAlgorithm::Sha1),
    ("SHA-256", DigestAlgorithm::Sha256),
    ("SHA-384", DigestAlgorithm::Sha384),
    ("SHA-512", DigestAlgorithm::Sha512),
];

fn insert_entry(
    entries: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    digest: Vec<u8>,
    algorithm: DigestAlgorithm,
) -> Result<(), DocumentError> {
    if name.is_empty() {
        return Err(unsupported("entrada con nombre vacío"));
    }
    if digest.len() != algorithm.output_len() {
        return Err(corrupted(format!(
            "la huella de {name} no tiene la longitud de {algorithm} ({} bytes)",
            digest.len()
        )));
    }
    if entries.insert(name.to_string(), digest).is_some() {
        return Err(unsupported(format!("entrada duplicada: {name}")));
    }
    Ok(())
}

fn element_named<'d>(
    doc: &'d Document,
    id: NodeId,
    local: &str,
) -> Result<&'d afirma_xml::dom::Element, DocumentError> {
    let el = doc
        .element(id)
        .ok_or_else(|| unsupported("se esperaba un elemento"))?;
    if el.local != local || el.ns.is_some() {
        return Err(unsupported(format!(
            "elemento inesperado: {} (se esperaba {local})",
            el.qname()
        )));
    }
    Ok(el)
}

fn check_attributes(el: &afirma_xml::dom::Element, allowed: &[&str]) -> Result<(), DocumentError> {
    for a in &el.attrs {
        let ok = match a.ns.as_deref() {
            None => allowed.contains(&a.local.as_str()),
            Some(ns) => ns == XSI_NS,
        };
        if !ok {
            return Err(unsupported(format!(
                "atributo no permitido en {}: {}",
                el.local,
                a.qname()
            )));
        }
    }
    Ok(())
}

fn is_xml_whitespace(s: &str) -> bool {
    s.chars().all(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Base64 URL-safe estricto con relleno opcional.
fn decode_url_safe_strict(s: &str) -> Option<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    let engine = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    engine.decode(s.trim()).ok()
}

/// Decodifica un documento TXT con el juego de caracteres de su primera línea.
fn decode_txt(content: &[u8]) -> Result<String, DocumentError> {
    let content = content.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(content);
    let mut encoding = encoding_rs::UTF_8;
    if let Some(rest) = content.strip_prefix(b";charset=") {
        let end = rest
            .iter()
            .position(|b| matches!(b, b'\r' | b'\n'))
            .unwrap_or(rest.len());
        let label = String::from_utf8_lossy(&rest[..end]);
        encoding = encoding_rs::Encoding::for_label(label.trim().as_bytes())
            .ok_or_else(|| unsupported(format!("juego de caracteres no soportado: {label}")))?;
    }
    let (text, had_errors) = encoding.decode_without_bom_handling(content);
    if had_errors {
        return Err(unsupported(format!(
            "el documento no está codificado en {}",
            encoding.name()
        )));
    }
    Ok(text.into_owned())
}

/// Divide en líneas como `BufferedReader.readLine` (`\r\n`, `\n` o `\r`).
fn split_lines(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match rest.find(['\r', '\n']) {
            Some(pos) => {
                let line = &rest[..pos];
                let skip = if rest[pos..].starts_with("\r\n") {
                    2
                } else {
                    1
                };
                rest = &rest[pos + skip..];
                Some(line)
            }
            None => {
                let line = rest;
                rest = "";
                Some(line)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HashDocument {
        let mut doc = HashDocument::new(DigestAlgorithm::Sha256, true);
        doc.entries
            .insert("vacio.txt".into(), DigestAlgorithm::Sha256.digest(b""));
        doc.entries.insert(
            "sub/hola.txt".into(),
            DigestAlgorithm::Sha256.digest(b"hola\n"),
        );
        doc
    }

    const SAMPLE_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n\
<entries hashAlgorithm=\"SHA-256\" recursive=\"true\">\n    \
<entry hash=\"Ez7piSk_knNjASgMbxTInVISAMF9zc7MowzSBwUzLUQ=\" hexhash=\"133EE989293F92736301280C6F14C89D521200C17DCDCECCA30CD20705332D44h\" name=\"sub/hola.txt\"/>\n    \
<entry hash=\"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=\" hexhash=\"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855h\" name=\"vacio.txt\"/>\n\
</entries>\n";

    const SAMPLE_TXT: &str = ";charset=UTF-8\r\n;hashAlgorithm=SHA-256\r\n;recursive=true\r\n\
sub/hola.txt;133EE989293F92736301280C6F14C89D521200C17DCDCECCA30CD20705332D44\r\n\
vacio.txt;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\r\n";

    #[test]
    fn xml_exacto_y_vuelta() {
        let doc = sample();
        let xml = doc.to_xml().unwrap();
        assert_eq!(String::from_utf8(xml.clone()).unwrap(), SAMPLE_XML);
        assert_eq!(HashDocument::parse(&xml).unwrap(), doc);
        assert_eq!(HashDocument::parse_xml(&xml).unwrap(), doc);
    }

    #[test]
    fn xml_vacio() {
        let doc = HashDocument::new(DigestAlgorithm::Sha1, false);
        let xml = doc.to_xml().unwrap();
        assert_eq!(
            String::from_utf8(xml.clone()).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n\
<entries hashAlgorithm=\"SHA-1\" recursive=\"false\"/>\n"
        );
        assert_eq!(HashDocument::parse(&xml).unwrap(), doc);
    }

    #[test]
    fn txt_exacto_y_vuelta() {
        let doc = sample();
        let txt = doc.to_txt().unwrap();
        assert_eq!(String::from_utf8(txt.clone()).unwrap(), SAMPLE_TXT);
        assert_eq!(HashDocument::parse(&txt).unwrap(), doc);
        // Solo cabeceras (Java fallaba con un NullPointerException).
        let empty = HashDocument::new(DigestAlgorithm::Sha512, false);
        assert_eq!(
            HashDocument::parse(&empty.to_txt().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn txt_tolerante() {
        // Separadores LF, `h` final, minúsculas, líneas vacías, `\` de Windows
        // conservado tal cual y `;` en la ruta.
        let txt = ";charset=UTF-8\n;hashAlgorithm=sha-256\n;recursive=TRUE\n;futuro=1\n\n\
sub\\hola.txt;133ee989293f92736301280c6f14c89d521200c17dcdceccA30CD20705332D44h  \n\
a;b.txt;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\n";
        let doc = HashDocument::parse(txt.as_bytes()).unwrap();
        assert_eq!(doc.algorithm, DigestAlgorithm::Sha256);
        assert!(doc.recursive);
        assert_eq!(
            doc.entries.keys().collect::<Vec<_>>(),
            ["a;b.txt", "sub\\hola.txt"]
        );
        // Sin cabeceras: SHA-256 y no recursivo.
        let doc = HashDocument::parse(
            b"x;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        )
        .unwrap();
        assert_eq!(
            (doc.algorithm, doc.recursive),
            (DigestAlgorithm::Sha256, false)
        );
    }

    #[test]
    fn txt_otros_juegos_de_caracteres() {
        let mut bytes =
            b";charset=ISO-8859-1\r\n;hashAlgorithm=SHA-256\r\n;recursive=false\r\n".to_vec();
        bytes.extend_from_slice(
            b"\xF1and\xFA.txt;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\r\n",
        );
        let doc = HashDocument::parse(&bytes).unwrap();
        assert_eq!(doc.entries.keys().collect::<Vec<_>>(), ["ñandú.txt"]);
    }

    #[test]
    fn txt_no_validos() {
        for bad in [
            &b""[..],
            b"\r\n\r\n",
            b";charset=NO-EXISTE\r\nx;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            b";hashAlgorithm=MD5\r\nx;D41D8CD98F00B204E9800998ECF8427E",
            b"sin-separador",
            b"x;",
            b"x;ZZ",
            b"x;ABC",
            b";charset=UTF-8\r\nx;E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\r\n;y;00",
            b"\xFF\xFE\xFD;00",
        ] {
            assert!(
                matches!(HashDocument::parse_txt(bad), Err(DocumentError::Unsupported(_))),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // Longitud de huella distinta de la del algoritmo.
        assert!(matches!(
            HashDocument::parse_txt(b"x;00112233"),
            Err(DocumentError::Corrupted(_))
        ));
        // Entrada duplicada.
        let dup = format!(
            "x;{0}\r\nx;{0}\r\n",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert!(matches!(
            HashDocument::parse_txt(dup.as_bytes()),
            Err(DocumentError::Unsupported(_))
        ));
    }

    #[test]
    fn xml_corrupto() {
        let bad = SAMPLE_XML.replace("hexhash=\"E3B0", "hexhash=\"F3B0");
        assert!(matches!(
            HashDocument::parse(bad.as_bytes()),
            Err(DocumentError::Corrupted(_))
        ));
        let bad = SAMPLE_XML.replace("hexhash=\"E3B0", "hexhash=\"XXB0");
        assert!(matches!(
            HashDocument::parse(bad.as_bytes()),
            Err(DocumentError::Corrupted(_))
        ));
        let bad = SAMPLE_XML.replace("47DEQpj8", "47DEQpj9");
        assert!(matches!(
            HashDocument::parse(bad.as_bytes()),
            Err(DocumentError::Corrupted(_))
        ));
        // Base64 estándar en vez de URL-safe: Java lo detecta como corrupto.
        let bad = SAMPLE_XML.replace("47DEQpj8HBSa-_TImW-5", "47DEQpj8HBSa+/TImW+5");
        assert!(matches!(
            HashDocument::parse(bad.as_bytes()),
            Err(DocumentError::Corrupted(_))
        ));
    }

    #[test]
    fn xml_tolerante() {
        // Sin hexhash, sin `h`, otros espacios, comentarios, recursive="1".
        let xml = "<?xml version='1.0' encoding='ISO-8859-1'?>\r\n<!-- c --><entries recursive=\"1\" \
hashAlgorithm=\"SHA-256\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
xsi:noNamespaceSchemaLocation=\"folderhashes.xsd\"><entry name=\"vacio.txt\" \
hash=\"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU\"/><!-- c --><entry name=\"sub/hola.txt\" \
hash=\"Ez7piSk_knNjASgMbxTInVISAMF9zc7MowzSBwUzLUQ=\" hexhash=\"133EE989293F92736301280C6F14C89D521200C17DCDCECCA30CD20705332D44\">texto</entry></entries>";
        assert_eq!(HashDocument::parse(xml.as_bytes()).unwrap(), sample());
    }

    #[test]
    fn xml_no_validos() {
        let cases = [
            SAMPLE_XML.replace("<entries ", "<otros "),
            SAMPLE_XML.replace(" hashAlgorithm=\"SHA-256\"", ""),
            SAMPLE_XML.replace(" recursive=\"true\"", ""),
            SAMPLE_XML.replace("SHA-256", "SHA-224"),
            SAMPLE_XML.replace("SHA-256", "sha-256"),
            SAMPLE_XML.replace("recursive=\"true\"", "recursive=\"yes\""),
            SAMPLE_XML.replace("<entries ", "<entries foo=\"x\" "),
            SAMPLE_XML.replace("<entry hash", "<entry foo=\"1\" hash"),
            SAMPLE_XML.replace(" name=\"vacio.txt\"", ""),
            SAMPLE_XML.replace("hash=\"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=\" ", ""),
            SAMPLE_XML.replace("<entries ", "<entries xmlns=\"urn:x\" "),
            SAMPLE_XML.replace("</entries>", "texto</entries>"),
            SAMPLE_XML.replace("</entries>", "<otro/></entries>"),
            SAMPLE_XML.replace("name=\"vacio.txt\"", "name=\"sub/hola.txt\""),
            SAMPLE_XML.replace("</entries>", ""),
            "no es xml".to_string(),
        ];
        for bad in cases {
            assert!(
                matches!(
                    HashDocument::parse_xml(bad.as_bytes()),
                    Err(DocumentError::Unsupported(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn caracteres_especiales_en_xml() {
        let mut doc = HashDocument::new(DigestAlgorithm::Sha1, false);
        let d = DigestAlgorithm::Sha1.digest(b"a");
        for n in [
            "a&b<c>d\"e'f.txt",
            "tab\tx.txt",
            "nl\nx.txt",
            "cr\rx.txt",
            "ñandú é.txt",
            "back\\slash.txt",
        ] {
            doc.entries.insert(n.into(), d.clone());
        }
        let xml = String::from_utf8(doc.to_xml().unwrap()).unwrap();
        assert!(xml.contains("name=\"a&amp;b&lt;c&gt;d&quot;e'f.txt\""));
        assert!(xml.contains("name=\"tab&#9;x.txt\""));
        assert!(xml.contains("name=\"nl&#10;x.txt\""));
        assert!(xml.contains("name=\"cr&#13;x.txt\""));
        assert!(xml.contains("name=\"ñandú é.txt\""));
        assert_eq!(HashDocument::parse(xml.as_bytes()).unwrap(), doc);
        // Caracteres de control no admitidos en XML 1.0.
        doc.entries.insert("ctl\u{1}x".into(), d);
        assert!(matches!(
            doc.to_xml(),
            Err(HashError::UnrepresentableName { .. })
        ));
    }

    #[test]
    fn rutas_no_representables_en_txt() {
        let d = DigestAlgorithm::Sha1.digest(b"a");
        for n in ["nl\nx", "cr\rx", ";x"] {
            let mut doc = HashDocument::new(DigestAlgorithm::Sha1, false);
            doc.entries.insert(n.into(), d.clone());
            assert!(
                matches!(doc.to_txt(), Err(HashError::UnrepresentableName { .. })),
                "{n:?}"
            );
        }
    }

    #[test]
    fn sha224_no_se_escribe_en_xml() {
        let doc = HashDocument::new(DigestAlgorithm::Sha224, false);
        assert!(matches!(doc.to_xml(), Err(HashError::Generation(_))));
        let txt = doc.to_txt().unwrap();
        assert_eq!(HashDocument::parse(&txt).unwrap(), doc);
    }

    #[test]
    fn deteccion_de_formato() {
        assert_eq!(DirDocumentFormat::sniff(b"<?xml"), DirDocumentFormat::Xml);
        assert_eq!(
            DirDocumentFormat::sniff(b"\xEF\xBB\xBF \n<entries/>"),
            DirDocumentFormat::Xml
        );
        assert_eq!(
            DirDocumentFormat::sniff(b"\xFF\xFE<\0"),
            DirDocumentFormat::Xml
        );
        assert_eq!(
            DirDocumentFormat::sniff(b";charset=UTF-8"),
            DirDocumentFormat::Txt
        );
        assert_eq!(DirDocumentFormat::sniff(b""), DirDocumentFormat::Txt);
        for (name, f) in [
            ("a.txthashfiles", DirDocumentFormat::Txt),
            ("a.TXT", DirDocumentFormat::Txt),
            ("a.hashfiles", DirDocumentFormat::Xml),
            ("a.csv", DirDocumentFormat::Xml),
            ("a", DirDocumentFormat::Xml),
            ("a.txt.xml", DirDocumentFormat::Xml),
        ] {
            assert_eq!(
                DirDocumentFormat::from_save_path(Path::new(name)),
                f,
                "{name}"
            );
        }
    }

    #[test]
    fn lineas_como_readline() {
        let v: Vec<_> = split_lines("a\r\nb\nc\rd\r\n\r\ne").collect();
        assert_eq!(v, ["a", "b", "c", "d", "", "e"]);
    }
}
