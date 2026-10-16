//! Respuestas XML (`buildXmlResponse`, §5.10).
//!
//! Una sola línea, sin declaración XML:
//! `<afirma><result>true|false</result><response><msg>..</msg><sign>..</sign></response></afirma>`.
//! `<response>` se omite si no hay mensaje ni firma. A diferencia de Java,
//! el mensaje y los alias se escapan (`&`, `<`, `>`), lo que no cambia nada
//! para los valores normales.

/// Escapa `&`, `<` y `>`.
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

/// `buildXmlResponse(ok, msg, resBytes)`.
pub fn xml_response(ok: bool, msg: Option<&str>, sign: Option<&[u8]>) -> String {
    let mut sb = format!("<afirma><result>{ok}</result>");
    if msg.is_some() || sign.is_some() {
        sb.push_str("<response>");
        if let Some(m) = msg {
            sb.push_str(&format!("<msg>{}</msg>", xml_escape(m)));
        }
        if let Some(s) = sign {
            sb.push_str(&format!("<sign>{}</sign>", afirma_core::base64_encode(s)));
        }
        sb.push_str("</response>");
    }
    sb.push_str("</afirma>");
    sb
}

/// Respuesta XML de `listaliases` (`<result>ok</result>`).
pub fn xml_aliases(aliases: &[String]) -> String {
    let mut sb = String::from("<afirma><result>ok</result><response>");
    for a in aliases {
        sb.push_str(&format!("<alias>{}</alias>", xml_escape(a)));
    }
    sb.push_str("</response></afirma>");
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respuestas() {
        assert_eq!(
            xml_response(false, None, None),
            "<afirma><result>false</result></afirma>"
        );
        assert_eq!(
            xml_response(true, Some("ok "), None),
            "<afirma><result>true</result><response><msg>ok </msg></response></afirma>"
        );
        assert_eq!(
            xml_response(true, Some("a<b&c"), Some(b"hola")),
            "<afirma><result>true</result><response><msg>a&lt;b&amp;c</msg><sign>aG9sYQ==</sign></response></afirma>"
        );
        assert_eq!(
            xml_response(true, None, Some(b"")),
            "<afirma><result>true</result><response><sign></sign></response></afirma>"
        );
        assert_eq!(
            xml_aliases(&["a".into(), "b&c".into()]),
            "<afirma><result>ok</result><response><alias>a</alias><alias>b&amp;c</alias></response></afirma>"
        );
    }
}
