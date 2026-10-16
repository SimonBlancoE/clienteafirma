//! Análisis XML seguro equivalente a `SecureXmlBuilder`/`AOFileUtils.isXML`
//! (§6.3 y §8.8): consciente de espacios de nombres, sin validación, sin
//! entidades externas y **rechazando cualquier declaración DOCTYPE**.

use encoding_rs::Encoding;

/// Decodifica un documento XML según su BOM o su declaración de codificación
/// (UTF-8 por defecto). `None` si la codificación no está soportada o los
/// bytes no son válidos en ella.
pub fn decode_xml(data: &[u8]) -> Option<String> {
    if let Some(rest) = data.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return std::str::from_utf8(rest).ok().map(str::to_string);
    }
    if let Some(rest) = data.strip_prefix(&[0xff, 0xfe]) {
        return decode_with(encoding_rs::UTF_16LE, rest);
    }
    if let Some(rest) = data.strip_prefix(&[0xfe, 0xff]) {
        return decode_with(encoding_rs::UTF_16BE, rest);
    }
    if data.starts_with(&[0x00, 0x3c, 0x00, 0x3f]) {
        return decode_with(encoding_rs::UTF_16BE, data);
    }
    if data.starts_with(&[0x3c, 0x00, 0x3f, 0x00]) {
        return decode_with(encoding_rs::UTF_16LE, data);
    }
    let encoding = declared_encoding(data)
        .map(|label| {
            // Java trata ISO-8859-1 como Latin-1 estricto; WHATWG lo asimila a
            // windows-1252, que para comprobar la buena formación es equivalente.
            Encoding::for_label(label.trim().as_bytes())
        })
        .unwrap_or(Some(encoding_rs::UTF_8))?;
    if encoding == encoding_rs::UTF_8 {
        return std::str::from_utf8(data).ok().map(str::to_string);
    }
    decode_with(encoding, data)
}

fn decode_with(encoding: &'static Encoding, data: &[u8]) -> Option<String> {
    encoding.decode_without_bom_handling_and_without_replacement(data).map(|c| c.into_owned())
}

/// Valor del pseudoatributo `encoding` de la declaración XML, si la hay.
fn declared_encoding(data: &[u8]) -> Option<&str> {
    if !data.starts_with(b"<?xml") {
        return None;
    }
    let end = data.windows(2).position(|w| w == b"?>")?;
    let decl = std::str::from_utf8(&data[..end]).ok()?;
    let idx = decl.find("encoding")?;
    let rest = decl[idx + "encoding".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value = &rest[1..];
    value.find(quote).map(|e| &value[..e])
}

/// Indica si el prólogo del documento contiene una declaración `DOCTYPE`.
pub fn has_doctype(text: &str) -> bool {
    let mut s = text.trim_start_matches('\u{feff}');
    loop {
        s = s.trim_start_matches([' ', '\t', '\r', '\n']);
        if let Some(rest) = s.strip_prefix("<?") {
            match rest.find("?>") {
                Some(e) => s = &rest[e + 2..],
                None => return false,
            }
        } else if let Some(rest) = s.strip_prefix("<!--") {
            match rest.find("-->") {
                Some(e) => s = &rest[e + 3..],
                None => return false,
            }
        } else {
            return s.starts_with("<!DOCTYPE");
        }
    }
}

/// Analiza un documento XML de forma segura (sin DOCTYPE ni entidades
/// externas). Devuelve el texto decodificado para que el llamante cree el
/// árbol con [`roxmltree`].
pub fn secure_parse_text(data: &[u8]) -> Option<String> {
    let text = decode_xml(data)?;
    if has_doctype(&text) {
        return None;
    }
    // Comprobación de buena formación.
    roxmltree::Document::parse_with_options(&text, parsing_options()).ok()?;
    Some(text)
}

/// Opciones de análisis seguras: sin DTD.
pub fn parsing_options<'a>() -> roxmltree::ParsingOptions<'a> {
    roxmltree::ParsingOptions { allow_dtd: false, ..roxmltree::ParsingOptions::default() }
}

/// `AOFileUtils.isXML`: los datos son un XML bien formado sin DOCTYPE.
/// Cualquier error devuelve `false`; en particular, un documento con
/// `<!DOCTYPE ...>` **no** es XML para AutoFirma.
pub fn is_xml(data: &[u8]) -> bool {
    secure_parse_text(data).is_some()
}

/// Nombre cualificado (`prefijo:local` o `local`) de un nodo elemento, como
/// `Node.getNodeName()` de un DOM con espacios de nombres.
pub fn qualified_name(node: &roxmltree::Node<'_, '_>) -> String {
    let tag = node.tag_name();
    match tag.namespace().and_then(|ns| node.lookup_prefix(ns)) {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}:{}", tag.name()),
        _ => tag.name().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_detection() {
        assert!(is_xml(b"<a/>"));
        assert!(is_xml(b"<?xml version=\"1.0\"?>\n<!-- c --><a><b x='1'/></a>"));
        assert!(is_xml(b"\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>"));
        assert!(is_xml(b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>Le\xf3n</a>"));
        assert!(!is_xml(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><a>Le\xf3n</a>"));
        assert!(!is_xml(b"<?xml version=\"1.0\"?><!DOCTYPE a><a/>"));
        assert!(!is_xml(b"<!-- x --><!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>"));
        assert!(!is_xml(b"<a:b/>"));
        assert!(!is_xml(b"<a><b></a>"));
        assert!(!is_xml(b""));
        assert!(!is_xml(b"texto"));
        let utf16: Vec<u8> =
            [0xff, 0xfe].into_iter().chain("<a>ñ</a>".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert!(is_xml(&utf16));
        assert!(has_doctype("<?xml version='1.0'?>\n<!-- x -->\n<!DOCTYPE html>"));
        assert!(!has_doctype("<a><!DOCTYPE></a>"));
    }

    #[test]
    fn qualified_names() {
        let doc = roxmltree::Document::parse("<p:a xmlns:p='urn:x' xmlns='urn:y'><b/></p:a>").unwrap();
        let root = doc.root_element();
        assert_eq!(qualified_name(&root), "p:a");
        assert_eq!(qualified_name(&root.first_element_child().unwrap()), "b");
    }
}
