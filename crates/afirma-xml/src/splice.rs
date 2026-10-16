//! Inserción de texto en documentos XML existentes sin reserializarlos y
//! escritura de la salida (declaración XML y codificación).

use crate::dom::{Document, NodeId};

/// Inserta `content` como último hijo del elemento `el` del documento y
/// devuelve el texto completo resultante (un elemento vacío `<a/>` se
/// convierte en `<a>...</a>`).
pub fn insert_last_child(doc: &Document, el: NodeId, content: &str) -> String {
    let src = doc.source();
    let e = doc.element(el).expect("es un elemento");
    let mut out = String::with_capacity(src.len() + content.len() + 16);
    match &e.end_tag {
        Some(end) => {
            out.push_str(&src[..end.start]);
            out.push_str(content);
            out.push_str(&src[end.start..]);
        }
        None => {
            let st = e.start_tag.clone();
            let tag = &src[st.clone()];
            // `<a .../>` -> `<a ...>` + contenido + `</a>`
            let trimmed = tag.trim_end_matches('>').trim_end_matches('/');
            out.push_str(&src[..st.start]);
            out.push_str(trimmed);
            out.push('>');
            out.push_str(content);
            out.push_str("</");
            out.push_str(&e.qname());
            out.push('>');
            out.push_str(&src[st.end..]);
        }
    }
    out
}

/// Texto de un elemento con el atributo `Id` de algunos de sus descendientes
/// (o de él mismo) sustituido o añadido (`setAttribute("Id", ...)`).
pub fn element_with_ids(doc: &Document, el: NodeId, ids: &[(NodeId, String)]) -> String {
    let src = doc.source();
    let range = doc.range(el);
    let mut edits: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    for (n, value) in ids {
        let Some(e) = doc.element(*n) else { continue };
        let v = crate::util::esc_attr(value);
        match e.attrs.iter().find(|a| a.ns.is_none() && a.local == "Id") {
            Some(a) => edits.push((a.range.clone(), format!("Id=\"{v}\""))),
            None => {
                let at = e.start_tag.start + 1 + e.qname().len();
                edits.push((at..at, format!(" Id=\"{v}\"")));
            }
        }
    }
    edits.sort_by_key(|(r, _)| r.start);
    let mut out = String::new();
    let mut pos = range.start;
    for (r, text) in edits {
        if r.start < pos || r.end > range.end {
            continue;
        }
        out.push_str(&src[pos..r.start]);
        out.push_str(&text);
        pos = r.end;
    }
    out.push_str(&src[pos..range.end]);
    out
}

/// Mueve un elemento al final de su padre (`appendChild` de un hijo
/// existente) y devuelve el texto completo resultante.
pub fn move_to_last_child(doc: &Document, el: NodeId) -> String {
    let src = doc.source();
    let Some(parent) = doc.parent(el) else {
        return src.to_string();
    };
    let Some(pe) = doc.element(parent) else {
        return src.to_string();
    };
    let Some(end) = &pe.end_tag else {
        return src.to_string();
    };
    let r = doc.range(el);
    if doc.children(parent).last() == Some(&el) {
        return src.to_string();
    }
    let mut out = String::with_capacity(src.len());
    out.push_str(&src[..r.start]);
    out.push_str(&src[r.end..end.start]);
    out.push_str(&src[r.clone()]);
    out.push_str(&src[end.start..]);
    out
}

/// Codifica el documento final. `text` no lleva declaración XML: se añade
/// `<?xml version="1.0" encoding="ENC"?>` (como el serializador de Java).
pub fn finish(text: &str, encoding_name: &str) -> Result<Vec<u8>, String> {
    let enc = crate::util::encoding_for(encoding_name)
        .ok_or_else(|| format!("Codificacion no soportada: {encoding_name}"))?;
    let full = format!("<?xml version=\"1.0\" encoding=\"{encoding_name}\"?>{text}");
    Ok(crate::dom::encode(&full, enc))
}

/// Codifica un documento existente (con su prólogo) conservando su
/// declaración XML si ya indica la codificación de salida; en otro caso la
/// sustituye (o la añade) con la codificación indicada.
pub fn finish_preserving(
    doc: &Document,
    text: &str,
    encoding_name: &str,
) -> Result<Vec<u8>, String> {
    let enc = crate::util::encoding_for(encoding_name)
        .ok_or_else(|| format!("Codificacion no soportada: {encoding_name}"))?;
    let (decl_text, rest) = match &doc.xml_decl {
        Some(d) => {
            let same = d
                .encoding
                .as_deref()
                .is_some_and(|e| crate::util::encoding_for(e) == Some(enc));
            if same {
                (text[..d.range.end].to_string(), &text[d.range.end..])
            } else {
                (
                    format!(
                        "<?xml version=\"{}\" encoding=\"{encoding_name}\"?>",
                        d.version
                    ),
                    &text[d.range.end..],
                )
            }
        }
        None => (
            format!("<?xml version=\"1.0\" encoding=\"{encoding_name}\"?>"),
            text,
        ),
    };
    let full = format!("{decl_text}{rest}");
    Ok(crate::dom::encode(&full, enc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_into_empty_and_full_elements() {
        let d = Document::parse("<a><b/><c>x</c></a>").unwrap();
        let root = d.document_element().unwrap();
        assert_eq!(
            insert_last_child(&d, root, "<s/>"),
            "<a><b/><c>x</c><s/></a>"
        );
        let b = d.child_elements(root).next().unwrap();
        assert_eq!(
            insert_last_child(&d, b, "<s/>"),
            "<a><b><s/></b><c>x</c></a>"
        );
    }
}
