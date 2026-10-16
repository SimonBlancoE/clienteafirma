//! Escritura de XML a mano con el mismo formato que el transformador del JDK
//! (`OutputKeys.INDENT = yes`, UTF-8).

/// Declaración XML que escribe el JDK (seguida de salto de línea).
pub(crate) const XML_DECLARATION: &str =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n";

/// Añade el valor de un atributo escapado como lo hace el serializador del
/// JDK: `&`, `<`, `>`, `"` como entidades y tabulador, salto de línea y
/// retorno de carro como referencias numéricas. Devuelve el primer carácter
/// no representable en XML 1.0 (controles C0, U+FFFE, U+FFFF), con el que el
/// JDK también falla.
pub(crate) fn push_attr(out: &mut String, value: &str) -> Result<(), char> {
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c if is_xml_char(c) => out.push(c),
            c => return Err(c),
        }
    }
    Ok(())
}

/// Carácter admitido por la producción `Char` de XML 1.0 (salvo tabulador y
/// saltos de línea, que se tratan aparte).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapado_de_atributos() {
        let mut s = String::new();
        push_attr(&mut s, "a&b<c>d\"e'f\tg\nh\ri\u{85}j\u{2028}k").unwrap();
        assert_eq!(
            s,
            "a&amp;b&lt;c&gt;d&quot;e'f&#9;g&#10;h&#13;i\u{85}j\u{2028}k"
        );
        assert_eq!(push_attr(&mut s, "x\u{1}"), Err('\u{1}'));
        assert_eq!(push_attr(&mut s, "x\u{FFFE}"), Err('\u{FFFE}'));
    }
}
