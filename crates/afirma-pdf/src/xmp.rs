//! Metadatos XMP: fecha de modificación (`xmp:ModifyDate`,
//! `xmp:MetadataDate`) e historial de firma de los PDF/A (`XmpHelper`).

use md5::{Digest, Md5};

use crate::pdf::date::{SignTime, millis, w3c_date};

const XAP_NS: &str = "http://ns.adobe.com/xap/1.0/";

/// Prefijo usado en el documento para el espacio de nombres XMP básico.
fn xap_prefix(xmp: &str) -> Option<String> {
    let needle = format!("=\"{XAP_NS}\"");
    let pos = xmp
        .find(&needle)
        .or_else(|| xmp.find(&format!("='{XAP_NS}'")))?;
    let before = &xmp[..pos];
    let start = before.rfind("xmlns:")? + 6;
    Some(before[start..].trim().to_string())
}

/// Sustituye el valor de un elemento `<p:name>valor</p:name>` o de un
/// atributo `p:name="valor"`. Devuelve si existía.
fn replace_value(xmp: &mut String, qname: &str, value: &str) -> bool {
    let open = format!("<{qname}>");
    let close = format!("</{qname}>");
    let mut found = false;
    let mut from = 0;
    while let Some(s) = xmp[from..].find(&open).map(|p| p + from) {
        let vs = s + open.len();
        let Some(e) = xmp[vs..].find(&close).map(|p| p + vs) else {
            break;
        };
        xmp.replace_range(vs..e, value);
        from = vs + value.len();
        found = true;
    }
    for q in ['"', '\''] {
        let attr = format!("{qname}={q}");
        let mut from = 0;
        while let Some(s) = xmp[from..].find(&attr).map(|p| p + from) {
            let vs = s + attr.len();
            let Some(e) = xmp[vs..].find(q).map(|p| p + vs) else {
                break;
            };
            xmp.replace_range(vs..e, value);
            from = vs + value.len();
            found = true;
        }
    }
    found
}

/// Actualiza `ModifyDate` (añadiéndolo si no existe) y `MetadataDate` (si
/// existe) con la fecha de firma, como `PdfStamperImp` de iText.
pub fn update_dates(xmp: &str, t: &SignTime) -> String {
    let date = w3c_date(t);
    let mut out = xmp.to_string();
    let prefix = xap_prefix(xmp).unwrap_or_else(|| "xmp".into());
    let had = replace_value(&mut out, &format!("{prefix}:ModifyDate"), &date);
    replace_value(&mut out, &format!("{prefix}:MetadataDate"), &date);
    if !had {
        // Se añade en la descripción que declara el espacio de nombres XMP.
        let decl = format!("xmlns:{prefix}=\"{XAP_NS}\"");
        if let Some(p) = out.find(&decl) {
            let tag_start = out[..p].rfind('<');
            let tag_end = out[p..].find('>').map(|e| e + p);
            if let (Some(ts), Some(te)) = (tag_start, tag_end)
                && out[ts..].starts_with("<rdf:Description") {
                    let elem = format!("<{prefix}:ModifyDate>{date}</{prefix}:ModifyDate>");
                    if out.as_bytes()[te - 1] == b'/' {
                        // `<rdf:Description .../>` → se abre y se cierra.
                        out.replace_range(te - 1..=te, &format!(">{elem}</rdf:Description>"));
                    } else {
                        out.insert_str(te + 1, &elem);
                    }
                }
        }
    }
    out
}

/// `UUID.nameUUIDFromBytes(BigInteger.valueOf(ms).toByteArray())`.
pub fn history_uuid(ms: i64) -> String {
    // Bytes mínimos en complemento a dos (como BigInteger.toByteArray).
    let bytes = ms.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, n) = (bytes[start], bytes[start + 1]);
        if (b == 0 && n & 0x80 == 0) || (b == 0xff && n & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    let mut h: [u8; 16] = Md5::digest(&bytes[start..]).into();
    h[6] = (h[6] & 0x0f) | 0x30;
    h[8] = (h[8] & 0x3f) | 0x80;
    let x = hex::encode(h);
    format!(
        "{}-{}-{}-{}-{}",
        &x[0..8],
        &x[8..12],
        &x[12..16],
        &x[16..20],
        &x[20..32]
    )
}

/// Añade la entrada de historial de firma de PDF/A. Devuelve `None` si el
/// XMP no tiene la estructura esperada (se deja como está).
pub fn add_sign_history(xmp: &str, t: &SignTime) -> Option<String> {
    if !xmp.contains("pdfaid:part") {
        return None;
    }
    let item = format!(
        "<rdf:li rdf:parseType=\"Resource\">\n  <stEvt:action>signed</stEvt:action>\n  <stEvt:instanceID>uuid:{}</stEvt:instanceID>\n  <stEvt:parameters>Firmado por el Cliente @firma</stEvt:parameters>\n  <stEvt:softwareAgent>Cliente @firma</stEvt:softwareAgent>\n  <stEvt:when>{}</stEvt:when>\n</rdf:li>",
        history_uuid(millis(t)),
        w3c_date(t)
    );
    let mut out = xmp.to_string();
    let hist_count = out.matches("<xmpMM:History").count();
    if hist_count == 1 {
        let hs = out.find("<xmpMM:History")?;
        let he = out[hs..].find("</xmpMM:History>").map(|p| p + hs)?;
        let section = &out[hs..he];
        if let Some(seq_end) = section.find("</rdf:Seq>") {
            out.insert_str(hs + seq_end, &item);
        } else {
            let seq = format!(
                "<rdf:Seq xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\">{item}</rdf:Seq>"
            );
            out.insert_str(he, &seq);
        }
        return Some(ensure_stevt_ns(out));
    }
    if hist_count > 1 {
        return None;
    }
    // Sin historial: se añade a la descripción que contiene pdfaid:conformance.
    let pos = out.find("pdfaid:conformance")?;
    let desc_end = out[pos..].find("</rdf:Description>").map(|p| p + pos)?;
    let hist = format!(
        "<xmpMM:History xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\"><rdf:Seq>{item}</rdf:Seq></xmpMM:History>"
    );
    out.insert_str(desc_end, &hist);
    Some(out)
}

/// Garantiza que el prefijo `stEvt` esté declarado.
fn ensure_stevt_ns(mut xmp: String) -> String {
    if !xmp.contains("xmlns:stEvt")
        && let Some(p) = xmp.find("<xmpMM:History") {
            xmp.insert_str(
                p + "<xmpMM:History".len(),
                " xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\"",
            );
        }
    xmp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modify_date_replaced() {
        let t = crate::pdf::date::fixed(2026, 10, 16, 13, 35, 34, 7200);
        let x = "<rdf:Description rdf:about='' xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:ModifyDate>2011-01-01T00:00:00Z</xmp:ModifyDate><xmp:MetadataDate>2011</xmp:MetadataDate></rdf:Description>";
        let o = update_dates(x, &t);
        assert!(o.contains("<xmp:ModifyDate>2026-10-16T13:35:34+02:00</xmp:ModifyDate>"));
        assert!(o.contains("<xmp:MetadataDate>2026-10-16T13:35:34+02:00</xmp:MetadataDate>"));
        let y = "<rdf:Description rdf:about='' xmlns:xap=\"http://ns.adobe.com/xap/1.0/\" xap:CreateDate=\"2011\"/>";
        let o = update_dates(y, &t);
        assert!(
            o.contains(
                "<xap:ModifyDate>2026-10-16T13:35:34+02:00</xap:ModifyDate></rdf:Description>"
            ),
            "{o}"
        );
    }

    #[test]
    fn uuid_v3() {
        // UUID.nameUUIDFromBytes(new byte[]{0}) = 93b885ad-fe0d-3089-8df6-34904fd59f71
        assert_eq!(history_uuid(0), "93b885ad-fe0d-3089-8df6-34904fd59f71");
        // Valores de Java (UUID.nameUUIDFromBytes(BigInteger.valueOf(v).toByteArray())).
        assert_eq!(
            history_uuid(1792150589000),
            "20486edf-a328-3a03-9254-0b52b2092519"
        );
        assert_eq!(history_uuid(-5), "ea8fd1aa-fd5a-3309-b7a2-e12e6ff986d5");
        assert_eq!(history_uuid(127), "83acb6e6-7e50-331d-b6ed-341dd2de1595");
        assert_eq!(history_uuid(128), "f23206ac-6155-3fc3-b5a2-122865ae0770");
    }

    #[test]
    fn history_added() {
        let t = crate::pdf::date::fixed(2026, 10, 16, 13, 35, 34, 7200);
        let x = "<rdf:Description rdf:about='' xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\"><pdfaid:part>2</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance></rdf:Description>";
        let o = add_sign_history(x, &t).unwrap();
        assert!(o.contains("<stEvt:action>signed</stEvt:action>"));
        assert!(o.contains("</xmpMM:History></rdf:Description>"));
        assert!(add_sign_history("<x/>", &t).is_none());
    }
}
