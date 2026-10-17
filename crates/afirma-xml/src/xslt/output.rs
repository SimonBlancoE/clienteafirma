//! Serialización de la salida de XSLT idéntica a la del JDK.
//!
//! Es un trasunto de los serializadores de `com.sun.org.apache.xml.internal.serializer`
//! que usa XSLTC (`ToXMLStream`, `ToHTMLStream`, `ToTextStream` y
//! `ToUnknownStream`, que elige HTML si el primer elemento es `html`): las
//! mismas decisiones de escape, de declaración de espacios de nombres, de
//! sangrado (con el comportamiento del JDK 9 y posteriores) y de codificación,
//! incluidas sus rarezas, porque la huella se calcula sobre estos octetos.

use std::collections::HashMap;

use super::XsltError;
use super::javamap::JavaHashMapOrder;

type HResult<T = ()> = Result<T, XsltError>;

/// `SerializationHandler.NO_BAD_CHARS`.
pub(crate) const NO_BAD_CHARS: u32 = 0x1;
/// `SerializationHandler.HTML_ATTREMPTY`.
pub(crate) const HTML_ATTREMPTY: u32 = 0x2;
/// `SerializationHandler.HTML_ATTRURL`.
pub(crate) const HTML_ATTRURL: u32 = 0x4;

const XMLNS_URI: &str = "http://www.w3.org/2000/xmlns/";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Receptor de la salida de las instrucciones (`SerializationHandler`).
pub(crate) trait Handler {
    fn start_document(&mut self) -> HResult;
    fn end_document(&mut self) -> HResult;
    /// `startElement(String)`.
    fn start_element(&mut self, qname: &str) -> HResult;
    /// `startElement(uri, localName, qname)` (nombres calculados de `xsl:element`).
    fn start_element_ns(&mut self, uri: Option<&str>, qname: &str) -> HResult;
    /// `endElement(String)`.
    fn end_element(&mut self, qname: &str) -> HResult;
    /// `namespaceAfterStartElement(prefix, uri)`; `None` = prefijo nulo de Java.
    fn namespace_after_start_element(&mut self, prefix: Option<&str>, uri: &str) -> HResult;
    /// `addAttribute(String name, String value)`.
    fn add_attribute(&mut self, qname: &str, value: &str) -> HResult;
    /// `addAttribute(uri, localName, rawName, "CDATA", value)` (copia de atributos).
    fn add_attribute_ns(&mut self, uri: &str, local: &str, qname: &str, value: &str) -> HResult;
    /// `addUniqueAttribute(name, value, flags)`.
    fn add_unique_attribute(&mut self, qname: &str, value: &str, flags: u32) -> HResult;
    fn characters(&mut self, text: &str) -> HResult;
    fn comment(&mut self, text: &str) -> HResult;
    fn processing_instruction(&mut self, target: &str, data: &str) -> HResult;
    /// `setEscaping(boolean)`: devuelve el valor anterior.
    fn set_escaping(&mut self, escape: bool) -> bool;
    /// `flushPending()` y prefijo en ámbito en la salida
    /// (`getNamespaceMappings().lookupNamespace`).
    fn output_namespace(&mut self, prefix: &str) -> HResult<Option<String>>;
}

// ---------------------------------------------------------------------------
// Codificaciones
// ---------------------------------------------------------------------------

/// Codificaciones de `Encodings.properties` del JDK: clave en mayúsculas
/// (nombre Java o nombre MIME), nombre MIME canónico y nombre Java.
const JAVA_KEYS: &[(&str, &str, &str)] = &[
    ("8859-1", "ISO-8859-1", "ISO-8859-1"),
    ("8859-2", "ISO-8859-2", "ISO-8859-2"),
    ("8859-3", "ISO-8859-3", "ISO-8859-3"),
    ("8859-4", "ISO-8859-4", "ISO-8859-4"),
    ("8859-5", "ISO-8859-5", "ISO-8859-5"),
    ("8859-6", "ISO-8859-6", "ISO-8859-6"),
    ("8859-7", "ISO-8859-7", "ISO-8859-7"),
    ("8859-8", "ISO-8859-8", "ISO-8859-8"),
    ("8859-9", "ISO-8859-9", "ISO-8859-9"),
    ("8859_1", "ISO-8859-1", "8859_1"),
    ("8859_2", "ISO-8859-2", "8859_2"),
    ("8859_3", "ISO-8859-3", "8859_3"),
    ("8859_4", "ISO-8859-4", "8859_4"),
    ("8859_5", "ISO-8859-5", "8859_5"),
    ("8859_6", "ISO-8859-6", "8859_6"),
    ("8859_7", "ISO-8859-7", "8859_7"),
    ("8859_8", "ISO-8859-8", "8859_8"),
    ("8859_9", "ISO-8859-9", "8859_9"),
    ("ASCII", "ASCII", "ASCII"),
    ("BIG5", "BIG5", "Big5"),
    ("CP1250", "WINDOWS-1250", "Cp1250"),
    ("CP1251", "WINDOWS-1251", "Cp1251"),
    ("CP1252", "WINDOWS-1252", "Cp1252"),
    ("CP850", "850", "Cp850"),
    ("CP860", "860", "Cp860"),
    ("EUC-CN", "GB2312", "EUC-CN"),
    ("EUC-JP", "EUC-JP", "EUC-JP"),
    ("EUC-KR", "EUC-KR", "EUC-KR"),
    ("EUCJIS", "EUC-JP", "EUCJIS"),
    ("EUC_CN", "GB2312", "EUC_CN"),
    ("EUC_JP", "EUC-JP", "EUC_JP"),
    ("EUC_KR", "EUC-KR", "EUC_KR"),
    ("GB2312", "GB2312", "GB2312"),
    ("ISO-8859-1", "ISO-8859-1", "ISO-8859-1"),
    ("ISO-8859-2", "ISO-8859-2", "ISO-8859-2"),
    ("ISO-8859-3", "ISO-8859-3", "ISO-8859-3"),
    ("ISO-8859-4", "ISO-8859-4", "ISO-8859-4"),
    ("ISO-8859-5", "ISO-8859-5", "ISO-8859-5"),
    ("ISO-8859-6", "ISO-8859-6", "ISO-8859-6"),
    ("ISO-8859-7", "ISO-8859-7", "ISO-8859-7"),
    ("ISO-8859-8", "ISO-8859-8", "ISO-8859-8"),
    ("ISO-8859-9", "ISO-8859-9", "ISO-8859-9"),
    ("ISO2022KR", "ISO-2022-KR", "ISO2022KR"),
    ("ISO8859-1", "ISO-8859-1", "ISO8859-1"),
    ("ISO8859-13", "ISO-8859-13", "ISO8859-13"),
    ("ISO8859-15", "ISO-8859-15", "ISO8859-15"),
    ("ISO8859-2", "ISO-8859-2", "ISO8859-2"),
    ("ISO8859-3", "ISO-8859-3", "ISO8859-3"),
    ("ISO8859-4", "ISO-8859-4", "ISO8859-4"),
    ("ISO8859-5", "ISO-8859-5", "ISO8859-5"),
    ("ISO8859-6", "ISO-8859-6", "ISO8859-6"),
    ("ISO8859-7", "ISO-8859-7", "ISO8859-7"),
    ("ISO8859-8", "ISO-8859-8", "ISO8859-8"),
    ("ISO8859-9", "ISO-8859-9", "ISO8859-9"),
    ("ISO8859_1", "ISO-8859-1", "ISO8859_1"),
    ("ISO8859_13", "ISO-8859-13", "ISO8859_13"),
    ("ISO8859_15", "ISO-8859-15", "ISO8859_15"),
    ("ISO8859_2", "ISO-8859-2", "ISO8859_2"),
    ("ISO8859_3", "ISO-8859-3", "ISO8859_3"),
    ("ISO8859_4", "ISO-8859-4", "ISO8859_4"),
    ("ISO8859_5", "ISO-8859-5", "ISO8859_5"),
    ("ISO8859_6", "ISO-8859-6", "ISO8859_6"),
    ("ISO8859_7", "ISO-8859-7", "ISO8859_7"),
    ("ISO8859_8", "ISO-8859-8", "ISO8859_8"),
    ("ISO8859_9", "ISO-8859-9", "ISO8859_9"),
    ("JIS", "ISO-2022-JP", "JIS"),
    ("KOI8_R", "KOI8-R", "KOI8_R"),
    ("KSC5601", "EUC-KR", "KSC5601"),
    ("SJIS", "SHIFT_JIS", "SJIS"),
    ("UNICODE", "UNICODE", "Unicode"),
    ("UTF8", "UTF-8", "UTF8"),
];

/// Claves MIME (`_encodingTableKeyMime`): clave, nombre MIME, nombre Java.
const MIME_KEYS: &[(&str, &str, &str)] = &[
    ("ASCII", "ASCII", "ASCII"),
    ("BIG5", "BIG5", "Big5"),
    ("EUC-JP", "EUC-JP", "EUC_JP"),
    ("EUC-KR", "EUC-KR", "EUC-KR"),
    ("GB2312", "GB2312", "EUC-CN"),
    ("ISO-2022-JP", "ISO-2022-JP", "JIS"),
    ("ISO-2022-KR", "ISO-2022-KR", "ISO2022KR"),
    ("ISO-8859-1", "ISO-8859-1", "ISO-8859-1"),
    ("ISO-8859-13", "ISO-8859-13", "ISO8859-13"),
    ("ISO-8859-15", "ISO-8859-15", "ISO8859-15"),
    ("ISO-8859-2", "ISO-8859-2", "ISO-8859-2"),
    ("ISO-8859-3", "ISO-8859-3", "ISO-8859-3"),
    ("ISO-8859-4", "ISO-8859-4", "ISO-8859-4"),
    ("ISO-8859-5", "ISO-8859-5", "ISO-8859-5"),
    ("ISO-8859-6", "ISO-8859-6", "ISO-8859-6"),
    ("ISO-8859-7", "ISO-8859-7", "ISO-8859-7"),
    ("ISO-8859-8", "ISO-8859-8", "ISO-8859-8"),
    ("ISO-8859-9", "ISO-8859-9", "ISO-8859-9"),
    ("KOI8-R", "KOI8-R", "KOI8_R"),
    ("SHIFT_JIS", "SHIFT_JIS", "SJIS"),
    ("UNICODE", "UNICODE", "Unicode"),
    ("US-ASCII", "US-ASCII", "ASCII"),
    ("UTF-16", "UTF-16", "Unicode"),
    ("UTF-8", "UTF-8", "UTF8"),
    ("WINDOWS-1250", "WINDOWS-1250", "Cp1250"),
    ("WINDOWS-1251", "WINDOWS-1251", "Cp1251"),
    ("WINDOWS-1252", "WINDOWS-1252", "Cp1252"),
];

/// Alias Java de ISO-8859-1 (el WHATWG los trata como windows-1252).
const LATIN1_ALIASES: &[&str] = &[
    "ISO-8859-1",
    "ISO8859-1",
    "ISO8859_1",
    "8859_1",
    "8859-1",
    "LATIN1",
    "L1",
    "ISO_8859_1",
    "ISO_8859-1",
    "ISO_8859-1:1987",
    "ISO-IR-100",
    "IBM819",
    "IBM-819",
    "CP819",
    "819",
    "CSISOLATIN1",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncKind {
    Utf8,
    /// `Unicode` de Java: UTF-16 big endian con BOM.
    Unicode,
    Utf16Be,
    Utf16Le,
    Latin1,
    Ascii,
    Other(&'static encoding_rs::Encoding),
}

/// Codificación de salida resuelta como `Encodings.getEncodingInfo`.
#[derive(Clone, Debug)]
pub(crate) struct OutEncoding {
    /// Valor de la propiedad `encoding` (tal como se indicó).
    pub name: String,
    /// Nombre Java (`EncodingInfo.javaName`).
    java: String,
    kind: EncKind,
}

impl OutEncoding {
    pub(crate) fn utf8() -> OutEncoding {
        OutEncoding {
            name: "UTF-8".into(),
            java: "UTF8".into(),
            kind: EncKind::Utf8,
        }
    }

    /// Resuelve un nombre; `None` si Java no lo conoce.
    pub(crate) fn resolve(name: &str) -> Option<OutEncoding> {
        let upper = name.to_ascii_uppercase();
        let java = JAVA_KEYS
            .iter()
            .chain(MIME_KEYS)
            .find(|(k, _, _)| *k == upper)
            .map(|(_, _, j)| j.to_string());
        let java = match java {
            Some(j) => j,
            None => {
                // `Charset.forName`: nombre dinámico.
                if LATIN1_ALIASES.contains(&upper.as_str())
                    || matches!(
                        upper.as_str(),
                        "UTF-16BE" | "UTF-16LE" | "UTF-16" | "US-ASCII" | "UTF-8"
                    )
                    || encoding_rs::Encoding::for_label(name.as_bytes()).is_some()
                {
                    name.to_string()
                } else {
                    return None;
                }
            }
        };
        let ju = java.to_ascii_uppercase();
        let kind = if ju == "UTF8" || ju == "UTF-8" {
            EncKind::Utf8
        } else if ju == "UNICODE" || ju == "UTF-16" {
            EncKind::Unicode
        } else if ju == "UTF-16BE" {
            EncKind::Utf16Be
        } else if ju == "UTF-16LE" {
            EncKind::Utf16Le
        } else if LATIN1_ALIASES.contains(&ju.as_str()) {
            EncKind::Latin1
        } else if ju == "ASCII" || ju == "US-ASCII" {
            EncKind::Ascii
        } else {
            let label = match ju.as_str() {
                "CP1250" => "windows-1250",
                "CP1251" => "windows-1251",
                "CP1252" => "windows-1252",
                "SJIS" => "shift_jis",
                "JIS" => "iso-2022-jp",
                "KOI8_R" => "koi8-r",
                "EUC_JP" | "EUCJIS" => "euc-jp",
                "EUC_KR" | "KSC5601" => "euc-kr",
                "EUC_CN" | "EUC-CN" => "gb2312",
                other => {
                    // ISO8859_n / ISO8859-n / 8859_n.
                    let digits = other
                        .strip_prefix("ISO8859_")
                        .or_else(|| other.strip_prefix("ISO8859-"))
                        .or_else(|| other.strip_prefix("8859_"))
                        .or_else(|| other.strip_prefix("8859-"));
                    match digits {
                        Some(d) => {
                            let l = format!("iso-8859-{d}");
                            let enc = encoding_rs::Encoding::for_label(l.as_bytes())?;
                            return Some(OutEncoding {
                                name: name.to_string(),
                                java,
                                kind: EncKind::Other(enc),
                            });
                        }
                        None => {
                            let enc = encoding_rs::Encoding::for_label(java.as_bytes())?;
                            return Some(OutEncoding {
                                name: name.to_string(),
                                java,
                                kind: EncKind::Other(enc),
                            });
                        }
                    }
                }
            };
            EncKind::Other(encoding_rs::Encoding::for_label(label.as_bytes())?)
        };
        Some(OutEncoding {
            name: name.to_string(),
            java,
            kind,
        })
    }

    /// `Encodings.getMimeEncoding`: nombre de la declaración XML.
    pub(crate) fn mime(&self) -> String {
        let upper = self.name.to_ascii_uppercase();
        JAVA_KEYS
            .iter()
            .find(|(k, _, _)| *k == upper)
            .map(|(_, m, _)| m.to_string())
            .unwrap_or_else(|| self.name.clone())
    }

    /// Primer octeto de `String.valueOf(c).getBytes(javaName)` (con el
    /// sustituto de la codificación para lo no representable).
    fn first_byte(&self, c: char) -> u8 {
        match self.kind {
            EncKind::Utf8 => {
                let mut b = [0u8; 4];
                c.encode_utf8(&mut b);
                b[0]
            }
            EncKind::Unicode => 0xfe,
            EncKind::Utf16Be => {
                let mut u = [0u16; 2];
                (c.encode_utf16(&mut u)[0] >> 8) as u8
            }
            EncKind::Utf16Le => {
                let mut u = [0u16; 2];
                (c.encode_utf16(&mut u)[0] & 0xff) as u8
            }
            EncKind::Latin1 => {
                if (c as u32) <= 0xff {
                    c as u8
                } else {
                    b'?'
                }
            }
            EncKind::Ascii => {
                if (c as u32) < 0x80 {
                    c as u8
                } else {
                    b'?'
                }
            }
            EncKind::Other(enc) => {
                let mut s = [0u8; 4];
                let bytes = encode_other(enc, c.encode_utf8(&mut s));
                bytes.first().copied().unwrap_or(0)
            }
        }
    }

    /// `EncodingInfo.isInEncoding(char)` para un carácter del plano básico.
    pub(crate) fn in_encoding(&self, c: char) -> bool {
        let cp = c as u32;
        if (1..127).contains(&cp)
            && (matches!(
                self.java.as_str(),
                "UTF8" | "UTF-16" | "ASCII" | "US-ASCII" | "Unicode" | "UNICODE"
            ) || self.java.starts_with("ISO8859"))
        {
            return true;
        }
        let b = self.first_byte(c);
        b != 0 && (b != b'?' || c == '?')
    }

    /// `isInEncoding` de un sustituto UTF-16 suelto (lo que Java comprueba
    /// antes de tratar un carácter fuera del plano básico).
    pub(crate) fn lone_surrogate_in_encoding(&self) -> bool {
        // El sustituto de los codificadores UTF-16 es U+FFFD (y el de
        // `Unicode` va precedido de la BOM); el de los demás, '?'.
        matches!(self.kind, EncKind::Unicode | EncKind::Utf16Be | EncKind::Utf16Le)
    }

    /// `isInEncoding(high, low)` de un carácter fuera del plano básico.
    pub(crate) fn pair_in_encoding(&self, c: char) -> bool {
        match self.kind {
            EncKind::Utf8 | EncKind::Unicode => true,
            EncKind::Utf16Be | EncKind::Utf16Le => {
                let b = self.first_byte(c);
                b != 0 && b != b'?'
            }
            EncKind::Latin1 | EncKind::Ascii => false,
            EncKind::Other(_) => {
                let b = self.first_byte(c);
                b != 0 && b != b'?'
            }
        }
    }

    /// Codifica el texto como el `Writer` de Java (sustituto '?').
    fn encode(&self, text: &str, low_byte_writer: bool) -> Vec<u8> {
        if low_byte_writer {
            // `WriterToASCI`: el octeto bajo de cada unidad UTF-16.
            let mut out = Vec::with_capacity(text.len());
            for u in text.encode_utf16() {
                out.push((u & 0xff) as u8);
            }
            return out;
        }
        match self.kind {
            EncKind::Utf8 => text.as_bytes().to_vec(),
            EncKind::Unicode | EncKind::Utf16Be | EncKind::Utf16Le => {
                let mut out = Vec::with_capacity(text.len() * 2 + 2);
                if self.kind == EncKind::Unicode {
                    out.extend_from_slice(&[0xfe, 0xff]);
                }
                for u in text.encode_utf16() {
                    if self.kind == EncKind::Utf16Le {
                        out.extend_from_slice(&u.to_le_bytes());
                    } else {
                        out.extend_from_slice(&u.to_be_bytes());
                    }
                }
                out
            }
            EncKind::Latin1 => text
                .chars()
                .map(|c| if (c as u32) <= 0xff { c as u8 } else { b'?' })
                .collect(),
            EncKind::Ascii => text
                .chars()
                .map(|c| if (c as u32) < 0x80 { c as u8 } else { b'?' })
                .collect(),
            EncKind::Other(enc) => encode_other(enc, text),
        }
    }
}

/// Codifica con `encoding_rs` sustituyendo lo no representable por '?'.
fn encode_other(enc: &'static encoding_rs::Encoding, text: &str) -> Vec<u8> {
    let mut encoder = enc.new_encoder();
    let mut out = Vec::with_capacity(text.len() + 16);
    let mut buf = vec![0u8; text.len() * 4 + 32];
    let mut rest = text;
    loop {
        let (result, read, written) = encoder.encode_from_utf8_without_replacement(rest, &mut buf, true);
        out.extend_from_slice(&buf[..written]);
        rest = &rest[read..];
        match result {
            encoding_rs::EncoderResult::InputEmpty => break,
            encoding_rs::EncoderResult::OutputFull => buf.resize(buf.len() * 2, 0),
            encoding_rs::EncoderResult::Unmappable(_) => out.push(b'?'),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// CharInfo y ElemDesc
// ---------------------------------------------------------------------------

/// Entidades de `HTMLEntities.properties` del JDK (sin las que el fichero
/// tiene comentadas: griegas, matemáticas y de latín extendido).
#[rustfmt::skip]
const HTML_ENTITIES: &[(u32, &str)] = &[
    (34, "quot"), (38, "amp"), (60, "lt"), (62, "gt"), (160, "nbsp"), (161, "iexcl"), (162, "cent"), (163, "pound"),
    (164, "curren"), (165, "yen"), (166, "brvbar"), (167, "sect"), (168, "uml"), (169, "copy"), (170, "ordf"),
    (171, "laquo"), (172, "not"), (173, "shy"), (174, "reg"), (175, "macr"), (176, "deg"), (177, "plusmn"),
    (178, "sup2"), (179, "sup3"), (180, "acute"), (181, "micro"), (182, "para"), (183, "middot"), (184, "cedil"),
    (185, "sup1"), (186, "ordm"), (187, "raquo"), (188, "frac14"), (189, "frac12"), (190, "frac34"), (191, "iquest"),
    (192, "Agrave"), (193, "Aacute"), (194, "Acirc"), (195, "Atilde"), (196, "Auml"), (197, "Aring"), (198, "AElig"),
    (199, "Ccedil"), (200, "Egrave"), (201, "Eacute"), (202, "Ecirc"), (203, "Euml"), (204, "Igrave"),
    (205, "Iacute"), (206, "Icirc"), (207, "Iuml"), (208, "ETH"), (209, "Ntilde"), (210, "Ograve"), (211, "Oacute"),
    (212, "Ocirc"), (213, "Otilde"), (214, "Ouml"), (215, "times"), (216, "Oslash"), (217, "Ugrave"),
    (218, "Uacute"), (219, "Ucirc"), (220, "Uuml"), (221, "Yacute"), (222, "THORN"), (223, "szlig"), (224, "agrave"),
    (225, "aacute"), (226, "acirc"), (227, "atilde"), (228, "auml"), (229, "aring"), (230, "aelig"), (231, "ccedil"),
    (232, "egrave"), (233, "eacute"), (234, "ecirc"), (235, "euml"), (236, "igrave"), (237, "iacute"),
    (238, "icirc"), (239, "iuml"), (240, "eth"), (241, "ntilde"), (242, "ograve"), (243, "oacute"), (244, "ocirc"),
    (245, "otilde"), (246, "ouml"), (247, "divide"), (248, "oslash"), (249, "ugrave"), (250, "uacute"),
    (251, "ucirc"), (252, "uuml"), (253, "yacute"), (254, "thorn"), (255, "yuml"), (8194, "ensp"), (8195, "emsp"),
    (8201, "thinsp"), (8204, "zwnj"), (8205, "zwj"), (8206, "lrm"), (8207, "rlm"), (8211, "ndash"), (8212, "mdash"),
    (8216, "lsquo"), (8217, "rsquo"), (8218, "sbquo"), (8220, "ldquo"), (8221, "rdquo"), (8222, "bdquo"),
    (8224, "dagger"), (8225, "Dagger"), (8226, "bull"), (8230, "hellip"), (8240, "permil"), (8242, "prime"),
    (8243, "Prime"), (8249, "lsaquo"), (8250, "rsaquo"), (8254, "oline"), (8260, "frasl"), (8364, "euro"),
    (8465, "image"), (8472, "weierp"), (8476, "real"), (8482, "trade"), (8501, "alefsym"), (8592, "larr"),
    (8593, "uarr"), (8594, "rarr"), (8595, "darr"), (8596, "harr"), (8629, "crarr"), (8656, "lArr"), (8657, "uArr"),
    (8658, "rArr"), (8659, "dArr"), (8660, "hArr"), (8704, "forall"), (8706, "part"), (8707, "exist"),
    (8709, "empty"), (8711, "nabla"), (8712, "isin"), (8713, "notin"), (8715, "ni"), (8719, "prod"), (8721, "sum"),
    (8722, "minus"), (8727, "lowast"), (8730, "radic"), (8733, "prop"), (8734, "infin"), (8736, "ang"),
    (8743, "and"), (8744, "or"), (8745, "cap"), (8746, "cup"), (8747, "int"), (8756, "there4"), (8764, "sim"),
    (8773, "cong"), (8776, "asymp"), (8800, "ne"), (8801, "equiv"), (8804, "le"), (8805, "ge"), (8834, "sub"),
    (8835, "sup"), (8836, "nsub"), (8838, "sube"), (8839, "supe"), (8853, "oplus"), (8855, "otimes"), (8869, "perp"),
    (8901, "sdot"), (8968, "lceil"), (8969, "rceil"), (8970, "lfloor"), (8971, "rfloor"), (9001, "lang"),
    (9002, "rang"), (9674, "loz"), (9824, "spades"), (9827, "clubs"), (9829, "hearts"), (9830, "diams"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CharInfo {
    Xml,
    Html,
}

impl CharInfo {
    /// `get(ch)`: carácter con entidad o salto de línea / retorno de carro.
    fn get(self, c: char) -> bool {
        let cp = c as u32;
        if cp == 10 || cp == 13 {
            return true;
        }
        match self {
            CharInfo::Xml => matches!(cp, 34 | 38 | 60 | 62),
            CharInfo::Html => HTML_ENTITIES.binary_search_by_key(&cp, |&(v, _)| v).is_ok(),
        }
    }

    fn is_text_ascii_clean(self, c: char) -> bool {
        let cp = c as u32;
        cp < 128 && (((cp >= 0x20 || cp == 10 || cp == 13 || cp == 9) && !self.get(c)) || c == '"')
    }

    fn is_special_text_char(self, c: char) -> bool {
        if (c as u32) < 128 {
            !self.is_text_ascii_clean(c)
        } else {
            self.get(c)
        }
    }

    fn is_special_attr_char(self, c: char) -> bool {
        if self == CharInfo::Xml && c == '\t' {
            return true;
        }
        self.get(c)
    }

    fn output_string(self, c: char) -> Option<String> {
        let cp = c as u32;
        let name = match self {
            CharInfo::Xml => match cp {
                34 => "quot",
                38 => "amp",
                60 => "lt",
                62 => "gt",
                _ => return None,
            },
            CharInfo::Html => HTML_ENTITIES
                .binary_search_by_key(&cp, |&(v, _)| v)
                .ok()
                .map(|i| HTML_ENTITIES[i].1)?,
        };
        Some(format!("&{name};"))
    }
}

/// Indicadores de `ElemDesc`.
pub(crate) mod elem {
    pub const EMPTY: u32 = 1 << 1;
    pub const BLOCK: u32 = 1 << 3;
    pub const BLOCKFORM: u32 = 1 << 4;
    pub const BLOCKFORMFIELDSET: u32 = 1 << 5;
    pub const RAW: u32 = 1 << 8;
    pub const INLINELABEL: u32 = 1 << 11;
    pub const FONTSTYLE: u32 = 1 << 12;
    pub const PHRASE: u32 = 1 << 13;
    pub const FORMCTRL: u32 = 1 << 14;
    pub const SPECIAL: u32 = 1 << 15;
    pub const ASPECIAL: u32 = 1 << 16;
    pub const HEADMISC: u32 = 1 << 17;
    pub const HEAD: u32 = 1 << 18;
    pub const LIST: u32 = 1 << 19;
    pub const PREFORMATTED: u32 = 1 << 20;
    pub const WHITESPACESENSITIVE: u32 = 1 << 21;
    pub const HEADELEM: u32 = 1 << 22;
    pub const ATTRURL: u32 = 1 << 1;
    pub const ATTREMPTY: u32 = 1 << 2;
}

/// Elementos HTML de `ToHTMLStream.initTagReference` y sus atributos URL o
/// booleanos.
type ElemEntry = (&'static str, u32, &'static [(&'static str, u32)]);

const HTML_ELEMS: &[ElemEntry] = {
    use elem::*;
    &[
        ("BASEFONT", EMPTY, &[]),
        (
            "FRAME",
            EMPTY | BLOCK,
            &[("SRC", ATTRURL), ("LONGDESC", ATTRURL), ("NORESIZE", ATTREMPTY)],
        ),
        ("FRAMESET", BLOCK, &[]),
        ("NOFRAMES", BLOCK, &[]),
        ("ISINDEX", EMPTY | BLOCK, &[]),
        ("APPLET", WHITESPACESENSITIVE, &[]),
        ("CENTER", BLOCK, &[]),
        ("DIR", BLOCK, &[("COMPACT", ATTREMPTY)]),
        ("MENU", BLOCK, &[("COMPACT", ATTREMPTY)]),
        ("TT", FONTSTYLE, &[]),
        ("I", FONTSTYLE, &[]),
        ("B", FONTSTYLE, &[]),
        ("BIG", FONTSTYLE, &[]),
        ("SMALL", FONTSTYLE, &[]),
        ("EM", PHRASE, &[]),
        ("STRONG", PHRASE, &[]),
        ("DFN", PHRASE, &[]),
        ("CODE", PHRASE, &[]),
        ("SAMP", PHRASE, &[]),
        ("KBD", PHRASE, &[]),
        ("VAR", PHRASE, &[]),
        ("CITE", PHRASE, &[]),
        ("ABBR", PHRASE, &[]),
        ("ACRONYM", PHRASE, &[]),
        ("SUP", SPECIAL | ASPECIAL, &[]),
        ("SUB", SPECIAL | ASPECIAL, &[]),
        ("SPAN", SPECIAL | ASPECIAL, &[]),
        ("BDO", SPECIAL | ASPECIAL, &[]),
        ("BR", SPECIAL | ASPECIAL | EMPTY | BLOCK, &[]),
        ("BODY", BLOCK, &[]),
        ("ADDRESS", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[]),
        (
            "DIV",
            BLOCK | BLOCKFORM | BLOCKFORMFIELDSET,
            &[("SRC", ATTRURL), ("NOWRAP", ATTREMPTY)],
        ),
        ("A", SPECIAL, &[("HREF", ATTRURL), ("NAME", ATTRURL)]),
        ("MAP", SPECIAL | ASPECIAL | BLOCK, &[]),
        ("AREA", EMPTY | BLOCK, &[("HREF", ATTRURL), ("NOHREF", ATTREMPTY)]),
        ("LINK", HEADMISC | EMPTY | BLOCK, &[("HREF", ATTRURL)]),
        (
            "IMG",
            SPECIAL | ASPECIAL | EMPTY | WHITESPACESENSITIVE,
            &[
                ("SRC", ATTRURL),
                ("LONGDESC", ATTRURL),
                ("USEMAP", ATTRURL),
                ("ISMAP", ATTREMPTY),
            ],
        ),
        (
            "OBJECT",
            SPECIAL | ASPECIAL | HEADMISC | WHITESPACESENSITIVE,
            &[
                ("CLASSID", ATTRURL),
                ("CODEBASE", ATTRURL),
                ("DATA", ATTRURL),
                ("ARCHIVE", ATTRURL),
                ("USEMAP", ATTRURL),
                ("DECLARE", ATTREMPTY),
            ],
        ),
        ("PARAM", EMPTY, &[]),
        (
            "HR",
            BLOCK | BLOCKFORM | BLOCKFORMFIELDSET | EMPTY,
            &[("NOSHADE", ATTREMPTY)],
        ),
        ("P", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[]),
        ("H1", HEAD | BLOCK, &[]),
        ("H2", HEAD | BLOCK, &[]),
        ("H3", HEAD | BLOCK, &[]),
        ("H4", HEAD | BLOCK, &[]),
        ("H5", HEAD | BLOCK, &[]),
        ("H6", HEAD | BLOCK, &[]),
        ("PRE", PREFORMATTED | BLOCK, &[]),
        ("Q", SPECIAL | ASPECIAL, &[("CITE", ATTRURL)]),
        (
            "BLOCKQUOTE",
            BLOCK | BLOCKFORM | BLOCKFORMFIELDSET,
            &[("CITE", ATTRURL)],
        ),
        ("INS", 0, &[("CITE", ATTRURL)]),
        ("DEL", 0, &[("CITE", ATTRURL)]),
        ("DL", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[("COMPACT", ATTREMPTY)]),
        ("DT", BLOCK, &[]),
        ("DD", BLOCK, &[]),
        ("OL", LIST | BLOCK, &[("COMPACT", ATTREMPTY)]),
        ("UL", LIST | BLOCK, &[("COMPACT", ATTREMPTY)]),
        ("LI", BLOCK, &[]),
        ("FORM", BLOCK, &[("ACTION", ATTRURL)]),
        ("LABEL", FORMCTRL, &[]),
        (
            "INPUT",
            FORMCTRL | INLINELABEL | EMPTY,
            &[
                ("SRC", ATTRURL),
                ("USEMAP", ATTRURL),
                ("CHECKED", ATTREMPTY),
                ("DISABLED", ATTREMPTY),
                ("ISMAP", ATTREMPTY),
                ("READONLY", ATTREMPTY),
            ],
        ),
        (
            "SELECT",
            FORMCTRL | INLINELABEL,
            &[("DISABLED", ATTREMPTY), ("MULTIPLE", ATTREMPTY)],
        ),
        ("OPTGROUP", 0, &[("DISABLED", ATTREMPTY)]),
        ("OPTION", 0, &[("SELECTED", ATTREMPTY), ("DISABLED", ATTREMPTY)]),
        (
            "TEXTAREA",
            FORMCTRL | INLINELABEL,
            &[("DISABLED", ATTREMPTY), ("READONLY", ATTREMPTY)],
        ),
        ("FIELDSET", BLOCK | BLOCKFORM, &[]),
        ("LEGEND", 0, &[]),
        ("BUTTON", FORMCTRL | INLINELABEL, &[("DISABLED", ATTREMPTY)]),
        ("TABLE", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[("NOWRAP", ATTREMPTY)]),
        ("CAPTION", BLOCK, &[]),
        ("THEAD", BLOCK, &[]),
        ("TFOOT", BLOCK, &[]),
        ("TBODY", BLOCK, &[]),
        ("COLGROUP", BLOCK, &[]),
        ("COL", EMPTY | BLOCK, &[]),
        ("TR", BLOCK, &[("NOWRAP", ATTREMPTY)]),
        ("TH", 0, &[("NOWRAP", ATTREMPTY)]),
        ("TD", 0, &[("NOWRAP", ATTREMPTY)]),
        ("HEAD", BLOCK | HEADELEM, &[("PROFILE", ATTRURL)]),
        ("TITLE", BLOCK, &[]),
        ("BASE", EMPTY | BLOCK, &[("HREF", ATTRURL)]),
        ("META", HEADMISC | EMPTY | BLOCK, &[]),
        ("STYLE", HEADMISC | RAW | BLOCK, &[]),
        (
            "SCRIPT",
            SPECIAL | ASPECIAL | HEADMISC | RAW,
            &[("SRC", ATTRURL), ("FOR", ATTRURL), ("DEFER", ATTREMPTY)],
        ),
        ("NOSCRIPT", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[]),
        ("HTML", BLOCK, &[]),
        ("FONT", FONTSTYLE, &[]),
        ("S", FONTSTYLE, &[]),
        ("STRIKE", FONTSTYLE, &[]),
        ("U", FONTSTYLE, &[]),
        ("NOBR", FONTSTYLE, &[]),
        (
            "IFRAME",
            BLOCK | BLOCKFORM | BLOCKFORMFIELDSET,
            &[("SRC", ATTRURL), ("LONGDESC", ATTRURL)],
        ),
        ("LAYER", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[("SRC", ATTRURL)]),
        ("ILAYER", BLOCK | BLOCKFORM | BLOCKFORMFIELDSET, &[("SRC", ATTRURL)]),
    ]
};

/// Descripción de un elemento HTML (`ToHTMLStream.getElemDesc`): los
/// desconocidos se tratan como bloque. La búsqueda no distingue mayúsculas
/// (solo para nombres ASCII).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ElemDesc {
    pub flags: u32,
    attrs: &'static [(&'static str, u32)],
}

impl ElemDesc {
    pub(crate) fn of(name: &str) -> ElemDesc {
        if name.is_ascii()
            && let Some((_, f, a)) = HTML_ELEMS.iter().find(|(n, _, _)| n.eq_ignore_ascii_case(name))
        {
            return ElemDesc { flags: *f, attrs: a };
        }
        ElemDesc {
            flags: elem::BLOCK,
            attrs: &[],
        }
    }

    /// `isAttrFlagSet` (sin distinguir mayúsculas).
    pub(crate) fn attr_flag(&self, name: &str, flag: u32) -> bool {
        self.attrs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .is_some_and(|(_, f)| f & flag != 0)
    }
}

// ---------------------------------------------------------------------------
// NamespaceMappings
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MappingRecord {
    prefix: String,
    uri: String,
    depth: i32,
}

/// `NamespaceMappings` del serializador.
#[derive(Clone, Debug)]
struct NamespaceMappings {
    count: u32,
    namespaces: HashMap<String, Vec<MappingRecord>>,
    /// Orden de inserción de las claves de `namespaces` (para recorrerlas
    /// como un `HashMap` de Java).
    keys: JavaHashMapOrder,
    node_stack: Vec<MappingRecord>,
}

impl NamespaceMappings {
    fn new() -> NamespaceMappings {
        let mut m = NamespaceMappings {
            count: 0,
            namespaces: HashMap::new(),
            keys: JavaHashMapOrder::default(),
            node_stack: Vec::new(),
        };
        m.put_stack("");
        m.namespaces.get_mut("").expect("pila").push(MappingRecord {
            prefix: String::new(),
            uri: String::new(),
            depth: 0,
        });
        m.put_stack("xml");
        m.namespaces.get_mut("xml").expect("pila").push(MappingRecord {
            prefix: "xml".into(),
            uri: XML_NS.into(),
            depth: 0,
        });
        m.node_stack.push(MappingRecord {
            prefix: String::new(),
            uri: String::new(),
            depth: -1,
        });
        m
    }

    fn put_stack(&mut self, prefix: &str) {
        if !self.namespaces.contains_key(prefix) {
            self.namespaces.insert(prefix.to_string(), Vec::new());
            self.keys.insert(prefix);
        }
    }

    fn lookup_namespace(&self, prefix: &str) -> Option<&str> {
        self.namespaces
            .get(prefix)
            .and_then(|s| s.last())
            .map(|r| r.uri.as_str())
    }

    fn mapping(&self, prefix: &str) -> Option<&MappingRecord> {
        self.namespaces.get(prefix).and_then(|s| s.last())
    }

    fn lookup_prefix(&self, uri: &str) -> Option<String> {
        for p in self.keys.iter() {
            if self.lookup_namespace(p) == Some(uri) {
                return Some(p.to_string());
            }
        }
        None
    }

    fn push_namespace(&mut self, prefix: &str, uri: &str, depth: i32) -> bool {
        if prefix.starts_with("xml") {
            return false;
        }
        self.put_stack(prefix);
        let stack = self.namespaces.get_mut(prefix).expect("pila");
        if stack.last().is_some_and(|r| r.uri == uri) {
            return false;
        }
        let rec = MappingRecord {
            prefix: prefix.to_string(),
            uri: uri.to_string(),
            depth,
        };
        stack.push(rec.clone());
        self.node_stack.push(rec);
        true
    }

    fn pop_namespaces(&mut self, depth: i32) {
        while let Some(top) = self.node_stack.last() {
            if top.depth < depth {
                return;
            }
            let rec = self.node_stack.pop().expect("registro");
            if !rec.prefix.starts_with("xml")
                && let Some(s) = self.namespaces.get_mut(&rec.prefix)
            {
                s.pop();
            }
        }
    }

    fn generate_next_prefix(&mut self) -> String {
        let p = format!("ns{}", self.count);
        self.count += 1;
        p
    }
}

// ---------------------------------------------------------------------------
// ToStream
// ---------------------------------------------------------------------------

/// Método de salida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Xml,
    Html,
    Text,
}

#[derive(Clone, Debug, Default)]
struct ElemContext {
    depth: i32,
    element_name: Option<String>,
    local_name: Option<String>,
    uri: Option<String>,
    start_tag_open: bool,
    is_cdata_section: bool,
    is_raw: bool,
    desc: Option<ElemDesc>,
}

#[derive(Clone, Debug)]
struct Attr {
    uri: String,
    local: String,
    qname: String,
    value: String,
}

#[derive(Clone, Debug)]
enum Buffered {
    Text(String),
    Raw(String),
}

/// Propiedades de salida que XSLTC transfiere al serializador.
#[derive(Clone, Debug, Default)]
pub(crate) struct OutputSettings {
    pub method: Option<String>,
    pub encoding: Option<String>,
    pub version: Option<String>,
    pub standalone: Option<String>,
    pub omit_xml_declaration: bool,
    pub indent: bool,
    pub indent_amount: Option<i32>,
    pub doctype_system: Option<String>,
    pub doctype_public: Option<String>,
    pub media_type: Option<String>,
    /// Elementos CDATA en notación `{uri}local` o `local`.
    pub cdata: Vec<(String, String)>,
}

/// Serializador sobre flujo (`ToStream` y subclases).
pub(crate) struct Stream {
    method: Method,
    out: String,
    /// Límite de tamaño de la salida (caracteres).
    max_len: usize,
    enc: OutEncoding,
    /// Codificación del `Writer` (distinta de `enc` cuando `ToUnknownStream`
    /// cambia a HTML conservando el escritor del serializador XML).
    writer_enc: OutEncoding,
    low_byte_writer: bool,
    char_info: CharInfo,
    disable_escaping: Vec<bool>,
    chars_buffer: Vec<Buffered>,
    child_node_num_stack: Vec<i32>,
    child_node_num: i32,
    preserve_spaces: Vec<bool>,
    is_preserve_space: bool,
    is_prev_text: bool,
    line_sep: &'static str,
    space_before_close: bool,
    start_new_line: bool,
    escaping: bool,
    cdata_tag_open: bool,
    attributes: Vec<Attr>,
    /// Marcos de `ElemContext` (se reutilizan como en Java).
    frames: Vec<ElemContext>,
    cur: usize,
    need_to_call_start_document: bool,
    need_to_output_doctype_decl: bool,
    doctype_system: Option<String>,
    doctype_public: Option<String>,
    standalone: Option<String>,
    standalone_was_specified: bool,
    is_standalone: bool,
    do_indent: bool,
    indent_amount: i32,
    version: Option<String>,
    media_type: Option<String>,
    prefix_map: NamespaceMappings,
    omit_xml_declaration: bool,
    cdata_elems: Option<HashMap<String, Vec<String>>>,
    // ToHTMLStream
    is_prev_block: bool,
    special_escape_urls: bool,
    omit_meta_tag: bool,
}

impl Stream {
    pub(crate) fn new(method: Method, enc: OutEncoding, max_len: usize) -> Stream {
        let low = matches!(enc.name.as_str(), "WINDOWS-1250" | "US-ASCII" | "ASCII");
        Stream {
            method,
            out: String::new(),
            max_len,
            writer_enc: enc.clone(),
            enc,
            low_byte_writer: low,
            char_info: if method == Method::Html {
                CharInfo::Html
            } else {
                CharInfo::Xml
            },
            disable_escaping: Vec::new(),
            chars_buffer: Vec::new(),
            child_node_num_stack: Vec::new(),
            child_node_num: 0,
            preserve_spaces: Vec::new(),
            is_preserve_space: false,
            is_prev_text: false,
            line_sep: "\n",
            space_before_close: false,
            start_new_line: false,
            escaping: true,
            cdata_tag_open: false,
            attributes: Vec::new(),
            frames: vec![ElemContext::default()],
            cur: 0,
            need_to_call_start_document: true,
            need_to_output_doctype_decl: true,
            doctype_system: None,
            doctype_public: None,
            standalone: None,
            standalone_was_specified: false,
            is_standalone: false,
            do_indent: false,
            indent_amount: 4,
            version: None,
            media_type: None,
            prefix_map: NamespaceMappings::new(),
            omit_xml_declaration: false,
            cdata_elems: None,
            is_prev_block: false,
            special_escape_urls: true,
            omit_meta_tag: false,
        }
    }

    /// Octetos producidos.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.writer_enc.encode(&self.out, self.low_byte_writer)
    }

    fn ctx(&self) -> &ElemContext {
        &self.frames[self.cur]
    }

    fn ctx_mut(&mut self) -> &mut ElemContext {
        &mut self.frames[self.cur]
    }

    fn depth(&self) -> i32 {
        self.frames[self.cur].depth
    }

    fn write(&mut self, s: &str) -> HResult {
        self.out.push_str(s);
        if self.out.len() > self.max_len {
            return Err(XsltError::limit("tamaño de la salida"));
        }
        Ok(())
    }

    fn write_char(&mut self, c: char) {
        self.out.push(c);
    }

    // -- Propiedades ---------------------------------------------------------

    pub(crate) fn set_indent(&mut self, v: bool) {
        self.do_indent = v;
    }

    pub(crate) fn set_indent_amount(&mut self, v: i32) {
        self.indent_amount = v;
    }

    pub(crate) fn set_version(&mut self, v: Option<&str>) {
        if let Some(v) = v {
            self.version = Some(v.to_string());
        }
    }

    pub(crate) fn set_standalone(&mut self, v: Option<&str>) {
        if let Some(v) = v {
            self.standalone_was_specified = true;
            self.standalone = Some(if v == "yes" { "yes" } else { "no" }.to_string());
        }
    }

    pub(crate) fn set_omit_xml_declaration(&mut self, v: bool) {
        self.omit_xml_declaration = v;
    }

    pub(crate) fn set_doctype(&mut self, system: Option<&str>, public: Option<&str>) {
        if let Some(s) = system {
            self.doctype_system = Some(s.to_string());
        }
        if let Some(p) = public {
            self.doctype_public = Some(p.to_string());
            if p.starts_with("-//W3C//DTD XHTML") {
                self.space_before_close = true;
            }
        }
    }

    pub(crate) fn set_media_type(&mut self, v: Option<&str>) {
        if let Some(v) = v {
            self.media_type = Some(v.to_string());
        }
    }

    /// `setCdataSectionElements`: pares (URI o vacío, nombre local).
    pub(crate) fn set_cdata_section_elements(&mut self, elems: &[(String, String)]) {
        if elems.is_empty() {
            return;
        }
        let map = self.cdata_elems.get_or_insert_with(HashMap::new);
        for (uri, local) in elems {
            map.entry(local.clone()).or_default().push(uri.clone());
        }
    }

    // -- Utilidades de ToStream -----------------------------------------------

    fn escaping_not_needed(&self, c: char) -> bool {
        let cp = c as u32;
        if cp < 127 {
            cp >= 0x20 || cp == 0x0a || cp == 0x0d || cp == 0x09
        } else if cp > 0xffff {
            self.enc.lone_surrogate_in_encoding()
        } else {
            self.enc.in_encoding(c)
        }
    }

    fn should_format_output(&self) -> bool {
        match self.method {
            Method::Html => self.do_indent,
            _ => self.do_indent && !self.is_preserve_space,
        }
    }

    fn should_indent(&self) -> bool {
        self.should_format_output() && (self.depth() > 0 || self.is_standalone)
    }

    fn should_indent_for_text(&self) -> bool {
        let base = self.should_indent() && self.child_node_num > 1;
        if self.method == Method::Html {
            base && self.is_prev_block
        } else {
            base
        }
    }

    fn indent_at(&mut self, depth: i32) -> HResult {
        if self.start_new_line {
            let sep = self.line_sep;
            self.write(sep)?;
        }
        let n = (depth * self.indent_amount).max(0) as usize;
        for _ in 0..n {
            self.write_char(' ');
        }
        Ok(())
    }

    fn indent(&mut self) -> HResult {
        self.indent_at(self.depth())
    }

    fn close_cdata(&mut self) -> HResult {
        self.write("]]>")?;
        self.cdata_tag_open = false;
        Ok(())
    }

    fn write_char_ref(&mut self, cp: u32) -> HResult {
        if self.cdata_tag_open {
            self.close_cdata()?;
        }
        self.write(&format!("&#{cp};"))
    }

    fn is_char_in_c0_or_c1(c: char) -> bool {
        let cp = c as u32;
        if cp == 9 || cp == 10 || cp == 13 {
            false
        } else {
            (0x7f..=0x9f).contains(&cp) || (0x01..=0x1f).contains(&cp)
        }
    }

    fn is_nel_or_lsep(c: char) -> bool {
        matches!(c as u32, 0x85 | 0x2028)
    }

    /// `accumDefaultEntity`: escribe la entidad del carácter si la hay.
    fn accum_default_entity(&mut self, c: char, from_text: bool, esc_lf: bool) -> HResult<bool> {
        if !esc_lf && c == '\n' {
            let sep = self.line_sep;
            self.write(sep)?;
            return Ok(true);
        }
        let special = if from_text {
            self.char_info.is_special_text_char(c)
        } else {
            self.char_info.is_special_attr_char(c)
        };
        if special && let Some(s) = self.char_info.output_string(c) {
            self.write(&s)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `accumDefaultEscape`.
    fn accum_default_escape(&mut self, c: char, from_text: bool, esc_lf: bool) -> HResult {
        if self.accum_default_entity(c, from_text, esc_lf)? {
            return Ok(());
        }
        if (c as u32) > 0xffff {
            return self.write_char_ref(c as u32);
        }
        let ver11 = self.version.as_deref() == Some("1.1");
        if !ver11 && is_invalid_xml_char(c) {
            return Err(XsltError::Runtime(format!("carácter no válido en XML: {:x}", c as u32)));
        }
        let special = if from_text {
            self.char_info.is_special_text_char(c)
        } else {
            self.char_info.is_special_attr_char(c)
        };
        if Self::is_char_in_c0_or_c1(c)
            || (ver11 && Self::is_nel_or_lsep(c))
            || ((!self.escaping_not_needed(c) || special) && self.depth() > 0)
        {
            self.write_char_ref(c as u32)
        } else {
            self.write_char(c);
            Ok(())
        }
    }

    fn process_dirty(&mut self, c: char, from_text: bool) -> HResult {
        if c == '\n' && from_text {
            let sep = self.line_sep;
            self.write(sep)
        } else {
            self.accum_default_escape(c, from_text, false)
        }
    }

    /// `ToStream.outputCharacters`.
    fn output_characters(&mut self, text: &str) -> HResult {
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < chars.len() && matches!(chars[i], ' ' | '\n' | '\r' | '\t') {
            let c = chars[i];
            if !self.char_info.is_text_ascii_clean(c) {
                self.process_dirty(c, true)?;
            } else {
                self.write_char(c);
            }
            i += 1;
        }
        let is_xml10 = self.version.as_deref() == Some("1.0");
        while i < chars.len() {
            let c = chars[i];
            if (c as u32) < 127 && self.char_info.is_text_ascii_clean(c) {
                self.write_char(c);
                i += 1;
                continue;
            }
            let clean = (!Self::is_char_in_c0_or_c1(c)
                && (is_xml10 || !Self::is_nel_or_lsep(c))
                && (self.escaping_not_needed(c) && !self.char_info.is_special_text_char(c)))
                || c == '"';
            if clean {
                self.write_char(c);
            } else {
                self.process_dirty(c, true)?;
            }
            i += 1;
        }
        self.is_prev_text = true;
        if self.out.len() > self.max_len {
            return Err(XsltError::limit("tamaño de la salida"));
        }
        Ok(())
    }

    fn characters_raw(&mut self, text: &str) -> HResult {
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        }
        self.write(text)
    }

    /// `writeNormalizedChars` de `ToStream` (CDATA y texto sin escapar de HTML).
    fn write_normalized_chars(&mut self, text: &str, is_cdata: bool) -> HResult {
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\n' {
                let sep = self.line_sep;
                self.write(sep)?;
            } else if is_cdata && !self.escaping_not_needed(c) {
                self.handle_escaping(c)?;
            } else if is_cdata && i + 2 < chars.len() && c == ']' && chars[i + 1] == ']' && chars[i + 2] == '>' {
                self.write("]]]]><![CDATA[>")?;
                i += 2;
            } else if self.escaping_not_needed(c) {
                if is_cdata && !self.cdata_tag_open {
                    self.write("<![CDATA[")?;
                    self.cdata_tag_open = true;
                }
                self.write_char(c);
            } else {
                self.handle_escaping(c)?;
            }
            i += 1;
        }
        Ok(())
    }

    fn handle_escaping(&mut self, c: char) -> HResult {
        if (c as u32) > 0xffff {
            if self.enc.pair_in_encoding(c) {
                self.write_char(c);
                Ok(())
            } else {
                self.write_char_ref(c as u32)
            }
        } else {
            self.write_char_ref(c as u32)
        }
    }

    /// `ToStream.cdata`.
    fn cdata(&mut self, text: &str) -> HResult {
        if self.method == Method::Html
            && let Some(name) = self.ctx().element_name.clone()
            && (name.eq_ignore_ascii_case("SCRIPT") || name.eq_ignore_ascii_case("STYLE"))
        {
            if self.ctx().start_tag_open {
                self.close_start_tag()?;
                self.ctx_mut().start_tag_open = false;
            }
            if self.should_indent() {
                self.indent()?;
            }
            return self.write_normalized_chars(text, true);
        }
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        }
        if !self.cdata_tag_open && self.should_indent_for_text() {
            self.indent()?;
        }
        let first = text.chars().next();
        let brackets = first.is_some_and(|c| self.escaping_not_needed(c));
        if brackets && !self.cdata_tag_open {
            self.write("<![CDATA[")?;
            self.cdata_tag_open = true;
        }
        if self.disable_escaping.last().copied().unwrap_or(false) {
            self.characters_raw(text)?;
        } else {
            self.write_normalized_chars(text, true)?;
        }
        if brackets && text.ends_with(']') {
            self.close_cdata()?;
        }
        self.is_prev_text = true;
        Ok(())
    }

    fn flush_characters_buffer(&mut self, is_text: bool) -> HResult {
        let result = (|| -> HResult {
            if self.should_format_output() && !self.chars_buffer.is_empty() {
                if self.ctx().is_cdata_section {
                    let text: String = self
                        .chars_buffer
                        .iter()
                        .map(|b| match b {
                            Buffered::Text(t) | Buffered::Raw(t) => t.as_str(),
                        })
                        .collect();
                    return self.cdata(&text);
                }
                if !is_text {
                    self.child_node_num += 1;
                }
                let mut skip = false;
                if self.should_indent_for_text() {
                    self.indent()?;
                    self.start_new_line = true;
                    skip = true;
                }
                let items = std::mem::take(&mut self.chars_buffer);
                for item in items {
                    let (text, raw) = match &item {
                        Buffered::Text(t) => (t.as_str(), false),
                        Buffered::Raw(t) => (t.as_str(), true),
                    };
                    let mut start = 0;
                    if skip {
                        let trimmed = text.trim_start_matches('\n');
                        if trimmed.is_empty() {
                            // Todo eran saltos de línea: se siguen saltando.
                            continue;
                        }
                        start = text.len() - trimmed.len();
                    }
                    skip = false;
                    if raw {
                        self.write(&text[start..])?;
                        self.is_prev_text = true;
                    } else {
                        self.output_characters(&text[start..])?;
                    }
                }
            }
            Ok(())
        })();
        self.chars_buffer.clear();
        result
    }

    fn close_start_tag(&mut self) -> HResult {
        if self.method == Method::Html {
            let attrs = std::mem::take(&mut self.attributes);
            let desc = self.ctx().desc;
            for a in &attrs {
                self.process_html_attribute(&a.qname, &a.value, desc)?;
            }
            self.write(">")?;
            if self.cdata_elems.is_some() {
                let b = self.is_cdata_section();
                self.ctx_mut().is_cdata_section = b;
            }
            return Ok(());
        }
        if self.ctx().start_tag_open {
            let attrs = std::mem::take(&mut self.attributes);
            for a in &attrs {
                self.write(" ")?;
                self.write(&a.qname)?;
                self.write("=\"")?;
                self.write_attr_string(&a.value)?;
                self.write("\"")?;
            }
            self.write(">")?;
            if self.cdata_elems.is_some() {
                let b = self.is_cdata_section();
                self.ctx_mut().is_cdata_section = b;
            }
        }
        Ok(())
    }

    /// `ToStream.writeAttrString`.
    fn write_attr_string(&mut self, value: &str) -> HResult {
        if self.method == Method::Html {
            return self.write_html_attr_string(value);
        }
        for c in value.chars() {
            if self.escaping_not_needed(c) && !self.char_info.is_special_attr_char(c) {
                self.write_char(c);
            } else {
                self.accum_default_escape(c, false, true)?;
            }
        }
        if self.out.len() > self.max_len {
            return Err(XsltError::limit("tamaño de la salida"));
        }
        Ok(())
    }

    /// `ToHTMLStream.writeAttrString`.
    fn write_html_attr_string(&mut self, value: &str) -> HResult {
        let chars: Vec<char> = value.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if (self.escaping_not_needed(c) && !self.char_info.is_special_attr_char(c))
                || c == '<'
                || c == '>'
                || (c == '&' && chars.get(i + 1) == Some(&'{'))
            {
                self.write_char(c);
                continue;
            }
            if self.accum_default_entity(c, false, true)? {
                continue;
            }
            if (c as u32) > 0xffff {
                if self.enc.pair_in_encoding(c) {
                    self.write_char(c);
                } else {
                    self.write_char_ref(c as u32)?;
                }
            } else if let Some(s) = self.char_info.output_string(c) {
                self.write(&s)?;
            } else if self.escaping_not_needed(c) {
                self.write_char(c);
            } else {
                self.write(&format!("&#{};", c as u32))?;
            }
        }
        Ok(())
    }

    /// `ToHTMLStream.writeAttrURI`.
    fn write_attr_uri(&mut self, value: &str, url_escaping: bool) -> HResult {
        for c in value.chars() {
            let cp = c as u32;
            if !(32..=126).contains(&cp) {
                if url_escaping {
                    let mut buf = [0u8; 4];
                    for b in c.encode_utf8(&mut buf).bytes() {
                        self.write(&format!("%{b:02X}"))?;
                    }
                } else if (cp <= 0xffff && self.escaping_not_needed(c)) || (cp > 0xffff && self.enc.pair_in_encoding(c))
                {
                    self.write_char(c);
                } else if cp > 0xffff {
                    // Java escribe cada unidad UTF-16 por separado.
                    let mut u = [0u16; 2];
                    for unit in c.encode_utf16(&mut u).iter() {
                        self.write(&format!("&#{unit};"))?;
                    }
                } else {
                    self.write(&format!("&#{cp};"))?;
                }
            } else if c == '"' {
                self.write(if url_escaping { "%22" } else { "&quot;" })?;
            } else if c == '&' {
                self.write("&amp;")?;
            } else {
                self.write_char(c);
            }
        }
        Ok(())
    }

    fn process_html_attribute(&mut self, name: &str, value: &str, desc: Option<ElemDesc>) -> HResult {
        self.write(" ")?;
        if (value.is_empty() || value.eq_ignore_ascii_case(name))
            && desc.is_some_and(|d| d.attr_flag(name, elem::ATTREMPTY))
        {
            return self.write(name);
        }
        self.write(name)?;
        self.write("=\"")?;
        if desc.is_some_and(|d| d.attr_flag(name, elem::ATTRURL)) {
            let esc = self.special_escape_urls;
            self.write_attr_uri(value, esc)?;
        } else {
            self.write_attr_string(value)?;
        }
        self.write("\"")
    }

    fn is_cdata_section(&mut self) -> bool {
        if self.cdata_elems.is_none() {
            return false;
        }
        if self.ctx().local_name.is_none() {
            let name = self.ctx().element_name.clone().unwrap_or_default();
            let local = local_part(&name).to_string();
            self.ctx_mut().local_name = Some(local);
        }
        let uri = self.ctx().uri.clone();
        match uri {
            None => {
                let u = self.element_uri();
                self.ctx_mut().uri = Some(u);
            }
            Some(u) if u.is_empty() => {
                let name = self.ctx().element_name.clone();
                let local = self.ctx().local_name.clone().unwrap_or_default();
                match name {
                    None => self.ctx_mut().element_name = Some(local),
                    Some(n) if local.len() < n.len() => {
                        let u = self.element_uri();
                        self.ctx_mut().uri = Some(u);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        let local = self.ctx().local_name.clone().unwrap_or_default();
        let uri = self.ctx().uri.clone().unwrap_or_default();
        self.cdata_elems
            .as_ref()
            .and_then(|m| m.get(&local))
            .is_some_and(|uris| uris.contains(&uri))
    }

    fn element_uri(&self) -> String {
        let name = self.ctx().element_name.clone().unwrap_or_default();
        let uri = match prefix_part(&name) {
            None => self.prefix_map.lookup_namespace(""),
            Some(p) => self.prefix_map.lookup_namespace(p),
        };
        uri.unwrap_or("").to_string()
    }

    // -- Documento -------------------------------------------------------------

    fn start_document_internal(&mut self) -> HResult {
        match self.method {
            Method::Xml => {
                if self.need_to_call_start_document {
                    self.need_to_call_start_document = false;
                    self.need_to_output_doctype_decl = true;
                    self.start_new_line = false;
                    if !self.omit_xml_declaration {
                        let encoding = self.enc.mime();
                        let version = self.version.clone().unwrap_or_else(|| "1.0".into());
                        let standalone = if self.standalone_was_specified {
                            format!(" standalone=\"{}\"", self.standalone.clone().unwrap_or_default())
                        } else {
                            String::new()
                        };
                        self.write(&format!(
                            "<?xml version=\"{version}\" encoding=\"{encoding}\"{standalone}?>"
                        ))?;
                        if (self.do_indent || self.is_standalone)
                            && (self.standalone_was_specified
                                || self.doctype_public.is_some()
                                || self.doctype_system.is_some()
                                || self.is_standalone)
                        {
                            let sep = self.line_sep;
                            self.write(sep)?;
                        }
                    }
                }
            }
            Method::Html => {
                self.need_to_call_start_document = false;
                self.need_to_output_doctype_decl = true;
                self.start_new_line = false;
                self.omit_xml_declaration = true;
                if self.doctype_system.is_some() || self.doctype_public.is_some() {
                    let decl = dtd_external_decl(self.doctype_public.as_deref(), self.doctype_system.as_deref());
                    self.write(&format!("<!DOCTYPE html{decl}>"))?;
                    let sep = self.line_sep;
                    self.write(sep)?;
                }
                self.need_to_output_doctype_decl = false;
            }
            Method::Text => {
                self.need_to_call_start_document = false;
            }
        }
        Ok(())
    }

    fn flush_pending(&mut self) -> HResult {
        if self.method == Method::Text {
            if self.need_to_call_start_document {
                self.start_document_internal()?;
                self.need_to_call_start_document = false;
            }
            return Ok(());
        }
        if self.need_to_call_start_document {
            self.start_document_internal()?;
            self.need_to_call_start_document = false;
        }
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        }
        if self.cdata_tag_open {
            self.close_cdata()?;
            self.cdata_tag_open = false;
        }
        Ok(())
    }

    fn output_doctype_decl(&mut self, name: &str) -> HResult {
        if self.cdata_tag_open {
            self.close_cdata()?;
        }
        self.write("<!DOCTYPE ")?;
        self.write(name)?;
        let decl = dtd_external_decl(self.doctype_public.as_deref(), self.doctype_system.as_deref());
        self.write(&decl)?;
        if self.doctype_system.is_some() {
            self.write(">")?;
            let sep = self.line_sep;
            self.write(sep)?;
        }
        Ok(())
    }

    fn push_context(&mut self, uri: Option<&str>, local: Option<&str>, qname: &str) {
        let depth = self.depth() + 1;
        self.cur += 1;
        if self.cur == self.frames.len() {
            self.frames.push(ElemContext {
                depth,
                ..Default::default()
            });
        }
        let f = &mut self.frames[self.cur];
        f.depth = depth;
        f.element_name = Some(qname.to_string());
        f.local_name = local.map(str::to_string);
        f.uri = uri.map(str::to_string);
        f.is_cdata_section = false;
        f.start_tag_open = true;
    }

    /// `ElemContext.push()` sin nombre: el marco reutilizado conserva los
    /// datos de su uso anterior.
    fn push_context_bare(&mut self) {
        let depth = self.depth() + 1;
        self.cur += 1;
        if self.cur == self.frames.len() {
            self.frames.push(ElemContext {
                depth,
                ..Default::default()
            });
        }
        self.frames[self.cur].depth = depth;
        self.frames[self.cur].start_tag_open = true;
    }

    fn pop_context(&mut self) {
        if self.cur > 0 {
            self.cur -= 1;
        }
    }

    /// `ToStream.startElement(uri, local, name, null)`.
    fn stream_start_element(&mut self, ns: Option<&str>, local: Option<&str>, name: &str) -> HResult {
        if self.do_indent {
            self.child_node_num += 1;
            self.flush_characters_buffer(false)?;
        }
        if self.need_to_call_start_document {
            self.start_document_internal()?;
            self.need_to_call_start_document = false;
        } else if self.cdata_tag_open {
            self.close_cdata()?;
        }
        if self.need_to_output_doctype_decl && self.doctype_system.is_some() {
            self.output_doctype_decl(name)?;
        }
        self.need_to_output_doctype_decl = false;
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        }
        if let Some(uri) = ns {
            self.ensure_prefix_is_declared(uri, name)?;
        }
        if self.should_indent() && self.start_new_line {
            self.indent()?;
        }
        self.start_new_line = true;
        self.write("<")?;
        self.write(name)?;
        if self.do_indent {
            self.is_preserve_space = self.preserve_spaces.last().copied().unwrap_or(false);
            self.preserve_spaces.push(self.is_preserve_space);
            self.child_node_num_stack.push(self.child_node_num);
            self.child_node_num = 0;
        }
        self.push_context(ns, local, name);
        self.is_prev_text = false;
        Ok(())
    }

    fn html_start_element(&mut self, name: &str) -> HResult {
        self.html_start_element_ns(None, name)
    }

    fn html_start_element_ns(&mut self, uri: Option<&str>, name: &str) -> HResult {
        if self.do_indent {
            self.child_node_num += 1;
            self.flush_characters_buffer(false)?;
        }
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        } else if self.cdata_tag_open {
            self.close_cdata()?;
            self.cdata_tag_open = false;
        } else if self.need_to_call_start_document {
            self.start_document_internal()?;
            self.need_to_call_start_document = false;
        }
        if let Some(u) = uri
            && !u.is_empty()
        {
            let local = local_part(name).to_string();
            return self.stream_start_element(Some(u), Some(&local), name);
        }
        let desc = ElemDesc::of(name);
        let flags = desc.flags;
        if self.do_indent {
            let is_block = flags & elem::BLOCK != 0;
            if self.ctx().element_name.is_some() && (is_block || (!(self.is_prev_text || !self.is_prev_block))) {
                self.start_new_line = true;
                self.indent()?;
            }
            self.is_prev_block = is_block;
        }
        self.is_prev_text = false;
        self.write("<")?;
        self.write(name)?;
        if self.do_indent {
            self.child_node_num_stack.push(self.child_node_num);
            self.child_node_num = 0;
        }
        if flags & elem::EMPTY != 0 {
            self.push_context_bare();
            let f = self.ctx_mut();
            f.element_name = Some(name.to_string());
            f.desc = Some(desc);
            return Ok(());
        }
        self.push_context(None, None, name);
        let f = self.ctx_mut();
        f.desc = Some(desc);
        f.is_raw = flags & elem::RAW != 0;
        if self.do_indent && flags & elem::BLOCK != 0 {
            self.start_new_line = true;
        }
        if flags & elem::HEADELEM != 0 {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
            if !self.omit_meta_tag {
                if self.do_indent {
                    self.indent()?;
                }
                let mime = self.enc.mime();
                self.write(&format!(
                    "<META http-equiv=\"Content-Type\" content=\"text/html; charset={mime}\">"
                ))?;
            }
        }
        Ok(())
    }

    fn stream_end_element(&mut self, name: &str) -> HResult {
        if self.do_indent {
            self.flush_characters_buffer(false)?;
        }
        let depth = self.depth();
        self.prefix_map.pop_namespaces(depth);
        if self.ctx().start_tag_open {
            let attrs = std::mem::take(&mut self.attributes);
            for a in &attrs {
                self.write(" ")?;
                self.write(&a.qname)?;
                self.write("=\"")?;
                self.write_attr_string(&a.value)?;
                self.write("\"")?;
            }
            self.write(if self.space_before_close { " />" } else { "/>" })?;
        } else {
            if self.cdata_tag_open {
                self.close_cdata()?;
            }
            if self.should_indent() && (self.child_node_num > 1 || !self.is_prev_text) {
                self.indent_at(depth - 1)?;
            }
            self.write("</")?;
            self.write(name)?;
            self.write(">")?;
        }
        if self.do_indent {
            self.preserve_spaces.pop();
            self.is_preserve_space = self.preserve_spaces.last().copied().unwrap_or(false);
            self.child_node_num = self.child_node_num_stack.pop().unwrap_or(0);
            self.is_prev_text = false;
        }
        self.pop_context();
        Ok(())
    }

    fn html_end_element(&mut self, name: &str) -> HResult {
        if self.do_indent {
            self.flush_characters_buffer(false)?;
        }
        if self.cdata_tag_open {
            self.close_cdata()?;
        }
        let desc = self.ctx().desc.unwrap_or(ElemDesc {
            flags: elem::BLOCK,
            attrs: &[],
        });
        let flags = desc.flags;
        let elem_empty = flags & elem::EMPTY != 0;
        if self.do_indent {
            let is_block = flags & elem::BLOCK != 0;
            let mut should_indent = false;
            if is_block || (!(self.is_prev_text || !self.is_prev_block)) {
                self.start_new_line = true;
                should_indent = true;
            }
            if !self.ctx().start_tag_open && should_indent && (self.child_node_num > 1 || !self.is_prev_text) {
                let d = self.depth() - 1;
                self.indent_at(d)?;
            }
            self.is_prev_block = is_block;
        }
        if !self.ctx().start_tag_open {
            self.write("</")?;
            self.write(name)?;
            self.write(">")?;
        } else {
            let attrs = std::mem::take(&mut self.attributes);
            let d = self.ctx().desc;
            for a in &attrs {
                self.process_html_attribute(&a.qname, &a.value, d)?;
            }
            if !elem_empty {
                self.write("></")?;
                self.write(name)?;
                self.write(">")?;
            } else {
                self.write(">")?;
            }
        }
        if self.do_indent {
            self.child_node_num = self.child_node_num_stack.pop().unwrap_or(0);
            self.is_prev_text = false;
        }
        self.pop_context();
        Ok(())
    }

    // -- Espacios de nombres y atributos ------------------------------------------

    fn start_prefix_mapping(&mut self, prefix: &str, uri: &str, should_flush: bool) -> HResult<bool> {
        if self.method == Method::Text {
            return Ok(false);
        }
        let depth = if should_flush {
            self.flush_pending()?;
            self.depth() + 1
        } else {
            self.depth()
        };
        let pushed = self.prefix_map.push_namespace(prefix, uri, depth);
        if pushed {
            if prefix.is_empty() {
                self.add_attribute_always(XMLNS_URI, "xmlns", "xmlns", uri, false)?;
            } else if !uri.is_empty() {
                let name = format!("xmlns:{prefix}");
                self.add_attribute_always(XMLNS_URI, prefix, &name, uri, false)?;
            }
        }
        Ok(pushed)
    }

    fn ensure_prefix_is_declared(&mut self, ns: &str, raw: &str) -> HResult {
        if ns.is_empty() {
            return Ok(());
        }
        let (no_prefix, prefix) = match raw.find(':') {
            None => (true, ""),
            Some(i) => (false, &raw[..i]),
        };
        let found = self.prefix_map.lookup_namespace(prefix).map(str::to_string);
        if found.as_deref() != Some(ns) {
            let p = prefix.to_string();
            self.start_prefix_mapping(&p, ns, true)?;
            let (local, name) = if no_prefix {
                ("xmlns".to_string(), "xmlns".to_string())
            } else {
                (p.clone(), format!("xmlns:{p}"))
            };
            self.add_attribute_always(XMLNS_URI, &local, &name, ns, false)?;
        }
        Ok(())
    }

    /// `ensureAttributesNamespaceIsDeclared`.
    fn ensure_attributes_namespace_is_declared(&mut self, ns: &str, raw: &str) -> HResult<Option<String>> {
        if ns.is_empty() {
            return Ok(None);
        }
        match raw.find(':') {
            Some(index) if index > 0 => {
                let p = raw[..index].to_string();
                if self.prefix_map.lookup_namespace(&p) == Some(ns) {
                    return Ok(None);
                }
                self.start_prefix_mapping(&p, ns, false)?;
                let name = format!("xmlns:{p}");
                self.add_attribute_6(XMLNS_URI, &p, &name, ns, false)?;
                Ok(Some(p))
            }
            _ => {
                let prefix = match self.prefix_map.lookup_prefix(ns) {
                    Some(p) => p,
                    None => {
                        let p = self.prefix_map.generate_next_prefix();
                        self.start_prefix_mapping(&p, ns, false)?;
                        let name = format!("xmlns:{p}");
                        self.add_attribute_6(XMLNS_URI, &p, &name, ns, false)?;
                        p
                    }
                };
                Ok(Some(prefix))
            }
        }
    }

    /// `ToStream.addAttributeAlways`.
    fn add_attribute_always(
        &mut self,
        uri: &str,
        local: &str,
        raw: &str,
        value: &str,
        xsl_attr: bool,
    ) -> HResult<bool> {
        if !self.chars_buffer.is_empty() {
            return Ok(!self.attributes.iter().any(|a| a.qname == raw));
        }
        let mut raw = raw.to_string();
        let was_added;
        if let Some(a) = self.attributes.iter_mut().find(|a| a.qname == raw) {
            a.value = value.to_string();
            was_added = false;
        } else {
            if xsl_attr && let Some(ci) = raw.find(':') {
                if ci > 0 {
                    let prefix = raw[..ci].to_string();
                    let depth = self.depth();
                    if let Some(m) = self.prefix_map.mapping(&prefix)
                        && m.depth == depth
                        && m.uri != uri
                    {
                        let p = match self.prefix_map.lookup_prefix(uri) {
                            Some(p) => p,
                            None => self.prefix_map.generate_next_prefix(),
                        };
                        raw = format!("{p}:{local}");
                    }
                }
                self.ensure_attributes_namespace_is_declared(uri, &raw)?;
            } else if xsl_attr {
                self.ensure_attributes_namespace_is_declared(uri, &raw)?;
            }
            self.attributes.push(Attr {
                uri: uri.to_string(),
                local: local.to_string(),
                qname: raw.clone(),
                value: value.to_string(),
            });
            was_added = true;
        }
        if self.do_indent && raw == "xml:space" {
            if value == "preserve" {
                self.is_preserve_space = true;
                if let Some(t) = self.preserve_spaces.last_mut() {
                    *t = true;
                }
            } else if value == "default" {
                self.is_preserve_space = false;
                if let Some(t) = self.preserve_spaces.last_mut() {
                    *t = false;
                }
            }
        }
        Ok(was_added)
    }

    /// `addAttribute(uri, localName, rawName, type, value, xslAttribute)` (6 argumentos).
    fn add_attribute_6(&mut self, uri: &str, local: &str, raw: &str, value: &str, xsl_attr: bool) -> HResult {
        match self.method {
            Method::Text => Ok(()),
            Method::Html => {
                if self.ctx().start_tag_open {
                    self.add_attribute_always(uri, local, raw, value, xsl_attr)?;
                }
                Ok(())
            }
            Method::Xml => {
                if self.ctx().start_tag_open {
                    let was_added = self.add_attribute_always(uri, local, raw, value, xsl_attr)?;
                    let mut raw = raw.to_string();
                    if was_added && !xsl_attr && !raw.starts_with("xmlns") {
                        let used = self.ensure_attributes_namespace_is_declared(uri, &raw)?;
                        if let Some(p) = used
                            && !raw.starts_with(&p)
                        {
                            raw = format!("{p}:{local}");
                        }
                    }
                    self.add_attribute_always(uri, local, &raw, value, xsl_attr)?;
                }
                // Fuera de una etiqueta de apertura Java solo avisa.
                Ok(())
            }
        }
    }

    fn patch_name(&self, qname: &str) -> String {
        if let Some(last) = qname.rfind(':')
            && last > 0
        {
            let first = qname.find(':').expect("dos puntos");
            let prefix = &qname[..first];
            let local = &qname[last + 1..];
            let uri = self.prefix_map.lookup_namespace(prefix);
            if uri == Some("") {
                return local.to_string();
            } else if first != last {
                return format!("{prefix}:{local}");
            }
        }
        qname.to_string()
    }

    /// `SerializerBase.getNamespaceURI(qname, false)`.
    fn namespace_uri_of(&self, qname: &str) -> HResult<String> {
        let col = qname.rfind(':');
        let prefix = match col {
            Some(c) if c > 0 => &qname[..c],
            _ => "",
        };
        if !prefix.is_empty() {
            match self.prefix_map.lookup_namespace(prefix) {
                Some(u) => return Ok(u.to_string()),
                None if prefix != "xmlns" => {
                    return Err(XsltError::Runtime(format!(
                        "el prefijo de espacio de nombres '{prefix}' no se ha declarado"
                    )));
                }
                None => return Ok(String::new()),
            }
        }
        Ok(String::new())
    }

    fn do_add_attribute_2(&mut self, qname: &str, value: &str) -> HResult {
        if self.method == Method::Text {
            return Ok(());
        }
        if self.ctx().start_tag_open {
            let patched = self.patch_name(qname);
            let local = local_part(&patched).to_string();
            let uri = self.namespace_uri_of(&patched)?;
            self.add_attribute_always(&uri, &local, &patched, value, false)?;
        }
        Ok(())
    }

    fn do_add_unique_attribute(&mut self, qname: &str, value: &str, flags: u32) -> HResult {
        match self.method {
            Method::Text => Ok(()),
            Method::Xml => {
                if self.ctx().start_tag_open {
                    let patched = self.patch_name(qname);
                    self.write(" ")?;
                    self.write(&patched)?;
                    self.write("=\"")?;
                    if flags & NO_BAD_CHARS > 0 {
                        self.write(value)?;
                    } else {
                        self.write_attr_string(value)?;
                    }
                    self.write("\"")?;
                }
                Ok(())
            }
            Method::Html => {
                if flags & NO_BAD_CHARS > 0 {
                    self.write(" ")?;
                    self.write(qname)?;
                    self.write("=\"")?;
                    self.write(value)?;
                    self.write("\"")
                } else if flags & HTML_ATTREMPTY > 0 && (value.is_empty() || value.eq_ignore_ascii_case(qname)) {
                    self.write(" ")?;
                    self.write(qname)
                } else {
                    self.write(" ")?;
                    self.write(qname)?;
                    self.write("=\"")?;
                    if flags & HTML_ATTRURL > 0 {
                        let esc = self.special_escape_urls;
                        self.write_attr_uri(value, esc)?;
                    } else {
                        self.write_attr_string(value)?;
                    }
                    self.write("\"")
                }
            }
        }
    }

    // -- Texto, comentarios, IP ----------------------------------------------------

    fn do_characters(&mut self, text: &str) -> HResult {
        if text.is_empty() {
            return Ok(());
        }
        match self.method {
            Method::Text => {
                self.flush_pending()?;
                return self.text_write_normalized(text);
            }
            Method::Html if self.ctx().is_raw => {
                if self.ctx().start_tag_open {
                    self.close_start_tag()?;
                    self.ctx_mut().start_tag_open = false;
                }
                self.write_normalized_chars(text, false)?;
                self.is_prev_text = true;
                return Ok(());
            }
            _ => {}
        }
        let should_not_format = !self.should_format_output();
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        } else if self.need_to_call_start_document {
            self.start_document_internal()?;
        }
        if self.ctx().is_cdata_section {
            return self.cdata(text);
        }
        if self.cdata_tag_open {
            self.close_cdata()?;
        }
        if self.disable_escaping.last().copied().unwrap_or(false) || !self.escaping {
            if should_not_format {
                self.characters_raw(text)?;
                self.is_prev_text = true;
            } else {
                self.chars_buffer.push(Buffered::Raw(text.to_string()));
            }
            return Ok(());
        }
        if should_not_format {
            self.output_characters(text)
        } else {
            self.chars_buffer.push(Buffered::Text(text.to_string()));
            Ok(())
        }
    }

    /// `ToTextStream.writeNormalizedChars`.
    fn text_write_normalized(&mut self, text: &str) -> HResult {
        for c in text.chars() {
            let cp = c as u32;
            if c == '\n' {
                let sep = self.line_sep;
                self.write(sep)?;
            } else if cp > 0xffff {
                if self.enc.lone_surrogate_in_encoding() || self.enc.pair_in_encoding(c) {
                    self.write_char(c);
                } else {
                    // `writeUTF16Surrogate` escribe una referencia de carácter.
                    self.write(&format!("&#{cp};"))?;
                }
            } else if self.enc.in_encoding(c) {
                self.write_char(c);
            } else {
                self.write(&format!("&#{cp};"))?;
            }
        }
        if self.out.len() > self.max_len {
            return Err(XsltError::limit("tamaño de la salida"));
        }
        Ok(())
    }

    fn do_comment(&mut self, text: &str) -> HResult {
        match self.method {
            Method::Text => return self.flush_pending(),
            Method::Html | Method::Xml => {}
        }
        if self.do_indent {
            self.child_node_num += 1;
            self.flush_characters_buffer(false)?;
        }
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        } else if self.need_to_call_start_document {
            self.start_document_internal()?;
            self.need_to_call_start_document = false;
        }
        if self.should_indent() && self.is_standalone {
            self.indent()?;
        }
        if self.cdata_tag_open {
            self.close_cdata()?;
        }
        if self.should_indent() && !self.is_standalone {
            self.indent()?;
        }
        self.write("<!--")?;
        let chars: Vec<char> = text.chars().collect();
        let mut start = 0;
        let mut was_dash = false;
        for i in 0..chars.len() {
            if was_dash && chars[i] == '-' {
                let s: String = chars[start..i].iter().collect();
                self.write(&s)?;
                self.write(" -")?;
                start = i + 1;
            }
            was_dash = chars[i] == '-';
        }
        if !chars.is_empty() {
            let s: String = chars[start..].iter().collect();
            self.write(&s)?;
            if chars[chars.len() - 1] == '-' {
                self.write(" ")?;
            }
        }
        self.write("-->")?;
        self.start_new_line = true;
        Ok(())
    }

    fn do_processing_instruction(&mut self, target: &str, data: &str) -> HResult {
        if self.method == Method::Text {
            return self.flush_pending();
        }
        if self.do_indent {
            self.child_node_num += 1;
            self.flush_characters_buffer(false)?;
        }
        self.flush_pending()?;
        if target == "javax.xml.transform.disable-output-escaping" {
            self.disable_escaping.push(true);
            return Ok(());
        }
        if target == "javax.xml.transform.enable-output-escaping" {
            self.disable_escaping.pop();
            return Ok(());
        }
        if self.ctx().start_tag_open {
            self.close_start_tag()?;
            self.ctx_mut().start_tag_open = false;
        } else if self.need_to_call_start_document {
            self.start_document_internal()?;
        }
        if self.should_indent() {
            self.indent()?;
        }
        self.write("<?")?;
        self.write(target)?;
        if data.chars().next().is_some_and(|c| !is_java_space_char(c)) {
            self.write(" ")?;
        }
        if self.method == Method::Html {
            self.write(data)?;
            self.write(">")?;
            if self.depth() <= 0 {
                let sep = self.line_sep;
                self.write(sep)?;
            }
        } else {
            match data.find("?>") {
                Some(idx) => {
                    if idx > 0 {
                        self.write(&data[..idx])?;
                    }
                    self.write("? >")?;
                    if idx + 2 < data.len() {
                        self.write(&data[idx + 2..])?;
                    }
                }
                None => self.write(data)?,
            }
            self.write("?>")?;
            if self.depth() <= 0 && self.is_standalone {
                let sep = self.line_sep;
                self.write(sep)?;
            }
        }
        self.start_new_line = true;
        Ok(())
    }

    fn do_end_document(&mut self) -> HResult {
        if self.method == Method::Text {
            return self.flush_pending();
        }
        if self.do_indent {
            self.flush_characters_buffer(false)?;
        }
        self.flush_pending()?;
        if self.do_indent && !self.is_prev_text {
            let sep = self.line_sep;
            self.write(sep)?;
        }
        Ok(())
    }

    fn do_namespace_after_start_element(&mut self, prefix: Option<&str>, uri: &str) -> HResult {
        if self.method == Method::Text {
            return Ok(());
        }
        if self.ctx().uri.is_none() {
            let name = self.ctx().element_name.clone().unwrap_or_default();
            let prefix1 = prefix_part(&name);
            if prefix1.is_none() && prefix == Some("") {
                self.ctx_mut().uri = Some(uri.to_string());
            }
        }
        // `NamespaceMappings.pushNamespace(null, ...)` lanza una excepción en Java.
        let Some(p) = prefix else {
            return Err(XsltError::Runtime("prefijo de espacio de nombres nulo".into()));
        };
        self.start_prefix_mapping(p, uri, false)?;
        Ok(())
    }
}

/// `XMLChar.isInvalid` (XML 1.0).
fn is_invalid_xml_char(c: char) -> bool {
    let cp = c as u32;
    !(cp == 0x9
        || cp == 0xa
        || cp == 0xd
        || (0x20..=0xd7ff).contains(&cp)
        || (0xe000..=0xfffd).contains(&cp)
        || (0x10000..=0x10ffff).contains(&cp))
}

/// `Character.isSpaceChar` (separadores Unicode Zs, Zl y Zp).
fn is_java_space_char(c: char) -> bool {
    matches!(
        c as u32,
        0x20 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000
    )
}

/// `JdkXmlUtils.getDTDExternalDecl`.
fn dtd_external_decl(public: Option<&str>, system: Option<&str>) -> String {
    let mut sb = String::new();
    if let Some(p) = public {
        sb.push_str(" PUBLIC ");
        sb.push_str(&quote_string(p));
    }
    if let Some(s) = system {
        if public.is_none() {
            sb.push_str(" SYSTEM ");
        } else {
            sb.push(' ');
        }
        sb.push_str(&quote_string(s));
    }
    sb
}

fn quote_string(s: &str) -> String {
    let q = if s.contains('"') { '\'' } else { '"' };
    format!("{q}{s}{q}")
}

fn local_part(qname: &str) -> &str {
    match qname.rfind(':') {
        Some(i) if i > 0 => &qname[i + 1..],
        _ => qname,
    }
}

fn prefix_part(qname: &str) -> Option<&str> {
    match qname.find(':') {
        Some(i) if i > 0 => Some(&qname[..i]),
        _ => None,
    }
}

impl Handler for Stream {
    fn start_document(&mut self) -> HResult {
        self.start_document_internal()?;
        self.need_to_call_start_document = false;
        Ok(())
    }

    fn end_document(&mut self) -> HResult {
        self.do_end_document()
    }

    fn start_element(&mut self, qname: &str) -> HResult {
        match self.method {
            Method::Xml => self.stream_start_element(None, None, qname),
            Method::Html => self.html_start_element(qname),
            Method::Text => {
                if self.need_to_call_start_document {
                    self.start_document_internal()?;
                }
                Ok(())
            }
        }
    }

    fn start_element_ns(&mut self, uri: Option<&str>, qname: &str) -> HResult {
        let local = local_part(qname).to_string();
        match self.method {
            Method::Xml => self.stream_start_element(uri, Some(&local), qname),
            Method::Html => self.html_start_element_ns(uri, qname),
            Method::Text => self.start_element(qname),
        }
    }

    fn end_element(&mut self, qname: &str) -> HResult {
        match self.method {
            Method::Xml => self.stream_end_element(qname),
            Method::Html => self.html_end_element(qname),
            Method::Text => Ok(()),
        }
    }

    fn namespace_after_start_element(&mut self, prefix: Option<&str>, uri: &str) -> HResult {
        self.do_namespace_after_start_element(prefix, uri)
    }

    fn add_attribute(&mut self, qname: &str, value: &str) -> HResult {
        self.do_add_attribute_2(qname, value)
    }

    fn add_attribute_ns(&mut self, uri: &str, local: &str, qname: &str, value: &str) -> HResult {
        if self.method == Method::Text {
            return Ok(());
        }
        if self.ctx().start_tag_open {
            self.add_attribute_always(uri, local, qname, value, false)?;
        }
        Ok(())
    }

    fn add_unique_attribute(&mut self, qname: &str, value: &str, flags: u32) -> HResult {
        self.do_add_unique_attribute(qname, value, flags)
    }

    fn characters(&mut self, text: &str) -> HResult {
        self.do_characters(text)
    }

    fn comment(&mut self, text: &str) -> HResult {
        self.do_comment(text)
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> HResult {
        self.do_processing_instruction(target, data)
    }

    fn set_escaping(&mut self, escape: bool) -> bool {
        std::mem::replace(&mut self.escaping, escape)
    }

    fn output_namespace(&mut self, prefix: &str) -> HResult<Option<String>> {
        self.flush_pending()?;
        Ok(self.prefix_map.lookup_namespace(prefix).map(str::to_string))
    }
}

// ---------------------------------------------------------------------------
// ToUnknownStream
// ---------------------------------------------------------------------------

/// Serializador sin método explícito: XML salvo que el primer elemento sea
/// `html` sin espacio de nombres (`ToUnknownStream`).
pub(crate) struct Unknown {
    handler: Stream,
    first_element_name: Option<String>,
    first_element_prefix: String,
    first_element_uri: Option<String>,
    first_tag_not_emitted: bool,
    wrapped_handler_not_initialized: bool,
    pending_attrs: Vec<Attr>,
    namespaces: Vec<(String, String)>,
    need_to_call_start_document: bool,
}

impl Unknown {
    pub(crate) fn new(xml: Stream) -> Unknown {
        Unknown {
            handler: xml,
            first_element_name: None,
            first_element_prefix: String::new(),
            first_element_uri: None,
            first_tag_not_emitted: true,
            wrapped_handler_not_initialized: false,
            pending_attrs: Vec::new(),
            namespaces: Vec::new(),
            need_to_call_start_document: false,
        }
    }

    pub(crate) fn stream_mut(&mut self) -> &mut Stream {
        &mut self.handler
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.handler.into_bytes()
    }

    fn is_first_elem_html(&self) -> bool {
        let name = self.first_element_name.as_deref().unwrap_or("");
        let local = {
            let l = match name.rfind(':') {
                Some(i) => &name[i + 1..],
                None => name,
            };
            match l.rfind('@') {
                Some(i) => &l[i + 1..],
                None => l,
            }
        };
        let mut is_html = local.eq_ignore_ascii_case("html");
        if is_html && self.first_element_uri.as_deref().is_some_and(|u| !u.is_empty()) {
            is_html = false;
        }
        if is_html {
            for (p, u) in &self.namespaces {
                if *p == self.first_element_prefix && !u.is_empty() {
                    is_html = false;
                    break;
                }
            }
        }
        is_html
    }

    fn init_stream_output(&mut self) -> HResult {
        if self.is_first_elem_html() {
            let old = &self.handler;
            let mut html = Stream::new(Method::Html, OutEncoding::utf8(), old.max_len);
            // Valores por defecto de la salida HTML y lo que se transfiere.
            html.do_indent = true;
            html.indent_amount = 4;
            html.media_type = Some("text/html".into());
            html.version = Some("4.0".into());
            html.standalone = Some("no".into());
            html.writer_enc = old.writer_enc.clone();
            html.low_byte_writer = old.low_byte_writer;
            html.out = std::mem::take(&mut self.handler.out);
            if let Some(v) = &self.handler.version {
                html.version = Some(v.clone());
            }
            html.doctype_system = self.handler.doctype_system.clone();
            html.doctype_public = self.handler.doctype_public.clone();
            if let Some(m) = &self.handler.media_type {
                html.media_type = Some(m.clone());
            }
            self.handler = html;
        }
        if self.need_to_call_start_document {
            self.handler.start_document()?;
            self.need_to_call_start_document = false;
        }
        self.wrapped_handler_not_initialized = false;
        Ok(())
    }

    fn emit_first_tag(&mut self) -> HResult {
        if let Some(name) = self.first_element_name.clone() {
            if self.wrapped_handler_not_initialized {
                self.init_stream_output()?;
                self.wrapped_handler_not_initialized = false;
            }
            let uri = self.first_element_uri.clone();
            match self.handler.method {
                Method::Xml => self.handler.stream_start_element(uri.as_deref(), None, &name)?,
                Method::Html => {
                    if uri.as_deref().is_some_and(|u| !u.is_empty()) {
                        self.handler.stream_start_element(uri.as_deref(), None, &name)?;
                    } else {
                        self.handler.html_start_element(&name)?;
                    }
                }
                Method::Text => {}
            }
            for a in std::mem::take(&mut self.pending_attrs) {
                self.handler
                    .add_attribute_always(&a.uri, &a.local, &a.qname, &a.value, false)?;
            }
            for (p, u) in std::mem::take(&mut self.namespaces) {
                self.handler.start_prefix_mapping(&p, &u, false)?;
            }
            self.first_tag_not_emitted = false;
        }
        Ok(())
    }

    fn flush(&mut self) -> HResult {
        if self.first_tag_not_emitted {
            self.emit_first_tag()?;
        }
        if self.need_to_call_start_document {
            self.handler.start_document()?;
            self.need_to_call_start_document = false;
        }
        Ok(())
    }
}

impl Handler for Unknown {
    fn start_document(&mut self) -> HResult {
        self.need_to_call_start_document = true;
        Ok(())
    }

    fn end_document(&mut self) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        self.handler.end_document()
    }

    fn start_element(&mut self, qname: &str) -> HResult {
        if self.first_tag_not_emitted {
            if self.first_element_name.is_some() {
                self.flush()?;
                self.handler.start_element(qname)
            } else {
                self.wrapped_handler_not_initialized = true;
                self.first_element_name = Some(qname.to_string());
                self.first_element_prefix = match qname.find(':') {
                    Some(i) if i > 0 => qname[..i].to_string(),
                    _ => String::new(),
                };
                self.first_element_uri = None;
                Ok(())
            }
        } else {
            self.handler.start_element(qname)
        }
    }

    fn start_element_ns(&mut self, uri: Option<&str>, qname: &str) -> HResult {
        if self.first_tag_not_emitted {
            if self.first_element_name.is_some() {
                self.flush()?;
                self.handler.start_element_ns(uri, qname)
            } else {
                self.start_element(qname)?;
                self.first_element_uri = uri.map(str::to_string);
                Ok(())
            }
        } else {
            self.handler.start_element_ns(uri, qname)
        }
    }

    fn end_element(&mut self, qname: &str) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        self.handler.end_element(qname)
    }

    fn namespace_after_start_element(&mut self, prefix: Option<&str>, uri: &str) -> HResult {
        let Some(prefix) = prefix else {
            return Err(XsltError::Runtime("prefijo de espacio de nombres nulo".into()));
        };
        if self.first_tag_not_emitted && self.first_element_uri.is_none() && self.first_element_name.is_some() {
            let name = self.first_element_name.clone().unwrap_or_default();
            if prefix_part(&name).is_none() && prefix.is_empty() {
                self.first_element_uri = Some(uri.to_string());
            }
        }
        // startPrefixMapping(prefix, uri, false)
        if self.first_tag_not_emitted {
            self.namespaces.push((prefix.to_string(), uri.to_string()));
            if self.first_element_uri.is_none() && prefix == self.first_element_prefix {
                self.first_element_uri = Some(uri.to_string());
            }
            Ok(())
        } else {
            self.handler.start_prefix_mapping(prefix, uri, false).map(|_| ())
        }
    }

    fn add_attribute(&mut self, qname: &str, value: &str) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        self.handler.add_attribute(qname, value)
    }

    fn add_attribute_ns(&mut self, uri: &str, local: &str, qname: &str, value: &str) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        // ToUnknownStream delega en la versión de seis argumentos.
        self.handler.add_attribute_6(uri, local, qname, value, false)
    }

    fn add_unique_attribute(&mut self, qname: &str, value: &str, flags: u32) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        self.handler.add_unique_attribute(qname, value, flags)
    }

    fn characters(&mut self, text: &str) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        self.handler.characters(text)
    }

    fn comment(&mut self, text: &str) -> HResult {
        if self.first_tag_not_emitted && self.first_element_name.is_some() {
            self.emit_first_tag()?;
        } else if self.need_to_call_start_document {
            self.handler.start_document()?;
            self.need_to_call_start_document = false;
        }
        self.handler.comment(text)
    }

    fn processing_instruction(&mut self, target: &str, data: &str) -> HResult {
        if self.first_tag_not_emitted {
            self.flush()?;
        }
        self.handler.processing_instruction(target, data)
    }

    fn set_escaping(&mut self, escape: bool) -> bool {
        self.handler.set_escaping(escape)
    }

    fn output_namespace(&mut self, prefix: &str) -> HResult<Option<String>> {
        self.flush()?;
        self.handler.output_namespace(prefix)
    }
}
