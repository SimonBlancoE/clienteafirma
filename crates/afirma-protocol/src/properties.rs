//! Serialización `java.util.Properties.store(Writer, "")` usada por
//! `AOUtil.properties2Base64` para el parámetro `params` de la firma
//! trifásica.

use afirma_core::ExtraParams;

/// Separador de línea de la plataforma (`line.separator`).
pub const LINE_SEPARATOR: &str = if cfg!(windows) { "\r\n" } else { "\n" };

fn escape(s: &str, is_key: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        match c {
            ' ' if i == 0 || is_key => out.push_str("\\ "),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// Texto de `Properties.store(writer, "")`: una línea `#`, una línea con la
/// fecha (`#Fri Oct 16 11:17:00 UTC 2026`) y las entradas `clave=valor` con
/// el escapado de Java (sin escapar los caracteres no ASCII, como con un
/// `Writer`).
pub fn store(params: &ExtraParams) -> String {
    let mut out = String::new();
    out.push('#');
    out.push_str(LINE_SEPARATOR);
    out.push('#');
    out.push_str(&chrono::Utc::now().format("%a %b %d %H:%M:%S UTC %Y").to_string());
    out.push_str(LINE_SEPARATOR);
    for (k, v) in params.iter() {
        out.push_str(&escape(k, true));
        out.push('=');
        out.push_str(&escape(v, false));
        out.push_str(LINE_SEPARATOR);
    }
    out
}

/// `AOUtil.properties2Base64`: Base64 URL-safe (con relleno) del UTF-8 de
/// [`store`].
pub fn store_base64_url(params: &ExtraParams) -> String {
    crate::jbase64::encode_url_safe(store(params).as_bytes())
}

/// `AOUtil.base642Properties`: `-`→`+`, `_`→`/`, Base64 estándar y
/// `Properties.load` en UTF-8. Un error de decodificación devuelve `None`.
pub fn load_base64(b64: &str) -> Option<ExtraParams> {
    if b64.is_empty() {
        return Some(ExtraParams::new());
    }
    let bytes = crate::jbase64::decode_normalized(b64).ok()?;
    Some(ExtraParams::parse(&String::from_utf8_lossy(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrip() {
        let mut p = ExtraParams::new();
        p.set("serverUrl", "https://h:8443/x?a=b");
        p.set("layer2Text", " Firmado por\n$$SUBJECTCN$$ #1 ñ");
        p.set("clave con espacio", "v\\w");
        let text = store(&p);
        let mut lines = text.split(LINE_SEPARATOR);
        assert_eq!(lines.next(), Some("#"));
        assert!(lines.next().unwrap().starts_with('#'));
        assert!(text.contains("serverUrl=https\\://h\\:8443/x?a\\=b"));
        assert!(text.contains("layer2Text=\\ Firmado por\\n$$SUBJECTCN$$ \\#1 ñ"));
        assert!(text.contains("clave\\ con\\ espacio=v\\\\w"));
        assert_eq!(ExtraParams::parse(&text), p);
        assert_eq!(load_base64(&store_base64_url(&p)).unwrap(), p);
        assert_eq!(load_base64("").unwrap(), ExtraParams::new());
        assert!(load_base64("a").is_none());
    }
}
