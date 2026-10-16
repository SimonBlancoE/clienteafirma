//! JSON al estilo de `org.json` (la biblioteca que usa AutoFirma):
//!
//! - Análisis permisivo (`JSONTokener`): claves sin comillas, cadenas con
//!   comillas simples, comas finales, `;` como separador...
//! - Los objetos conservan el orden del documento y se serializan en el
//!   orden de iteración del `HashMap` de Java ([`crate::javamap`]) y con el
//!   escapado de `JSONObject.quote`, de modo que las salidas coinciden con
//!   las de AutoFirma en los casos habituales.

use crate::javamap::java_hash_order;

/// Valor JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Str(String),
    /// Número (texto original).
    Num(String),
    Bool(bool),
    Null,
    Object(JsonObject),
    Array(Vec<JsonValue>),
}

/// Objeto JSON con las claves en orden de inserción.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct JsonObject(pub Vec<(String, JsonValue)>);

impl JsonObject {
    pub fn new() -> Self {
        JsonObject(Vec::new())
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// `put`: sustituye el valor si la clave existe (conservando su posición
    /// de inserción) o la añade al final.
    pub fn put(&mut self, key: impl Into<String>, value: JsonValue) {
        let key = key.into();
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<JsonValue> {
        let pos = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(pos).1)
    }

    /// `getString`: falla si falta o no es una cadena.
    pub fn get_string(&self, key: &str) -> Result<&str, String> {
        match self.get(key) {
            Some(JsonValue::Str(s)) => Ok(s),
            Some(_) => Err(format!("JSONObject[\"{key}\"] is not a string.")),
            None => Err(format!("JSONObject[\"{key}\"] not found.")),
        }
    }

    /// `optString(key, default)`: el valor textual (también de números y
    /// booleanos) o el valor por defecto.
    pub fn opt_string(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Some(JsonValue::Str(s)) => Some(s.clone()),
            Some(JsonValue::Num(n)) => Some(n.clone()),
            Some(JsonValue::Bool(b)) => Some(b.to_string()),
            _ => None,
        }
    }

    /// `getBoolean`: admite booleanos y las cadenas `"true"`/`"false"`.
    pub fn get_boolean(&self, key: &str) -> Result<bool, String> {
        match self.get(key) {
            Some(JsonValue::Bool(b)) => Ok(*b),
            Some(JsonValue::Str(s)) if s.eq_ignore_ascii_case("true") => Ok(true),
            Some(JsonValue::Str(s)) if s.eq_ignore_ascii_case("false") => Ok(false),
            Some(_) => Err(format!("JSONObject[\"{key}\"] is not a Boolean.")),
            None => Err(format!("JSONObject[\"{key}\"] not found.")),
        }
    }

    pub fn get_array(&self, key: &str) -> Result<&Vec<JsonValue>, String> {
        match self.get(key) {
            Some(JsonValue::Array(a)) => Ok(a),
            Some(_) => Err(format!("JSONObject[\"{key}\"] is not a JSONArray.")),
            None => Err(format!("JSONObject[\"{key}\"] not found.")),
        }
    }

    pub fn get_object(&self, key: &str) -> Result<&JsonObject, String> {
        match self.get(key) {
            Some(JsonValue::Object(o)) => Ok(o),
            Some(_) => Err(format!("JSONObject[\"{key}\"] is not a JSONObject.")),
            None => Err(format!("JSONObject[\"{key}\"] not found.")),
        }
    }

    /// Serialización compacta de `JSONObject.toString()`.
    pub fn to_org_json(&self) -> String {
        let mut out = String::new();
        write_object(self, &mut out);
        out
    }
}

impl JsonValue {
    pub fn as_object(&self) -> Option<&JsonObject> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn str(s: impl Into<String>) -> JsonValue {
        JsonValue::Str(s.into())
    }

    pub fn to_org_json(&self) -> String {
        let mut out = String::new();
        write_value(self, &mut out);
        out
    }
}

fn write_object(o: &JsonObject, out: &mut String) {
    out.push('{');
    let keys: Vec<&str> = o.0.iter().map(|(k, _)| k.as_str()).collect();
    for (n, i) in java_hash_order(&keys).into_iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        quote_into(&o.0[i].0, out);
        out.push(':');
        write_value(&o.0[i].1, out);
    }
    out.push('}');
}

fn write_value(v: &JsonValue, out: &mut String) {
    match v {
        JsonValue::Str(s) => quote_into(s, out),
        JsonValue::Num(n) => out.push_str(n),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Null => out.push_str("null"),
        JsonValue::Object(o) => write_object(o, out),
        JsonValue::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
    }
}

/// `JSONObject.quote`.
pub fn quote(s: &str) -> String {
    let mut out = String::new();
    quote_into(s, &mut out);
    out
}

fn quote_into(s: &str, out: &mut String) {
    out.push('"');
    let mut prev = '\0';
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            '/' => {
                if prev == '<' {
                    out.push('\\');
                }
                out.push(c);
            }
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' || ('\u{80}'..'\u{a0}').contains(&c) || ('\u{2000}'..'\u{2100}').contains(&c) => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
        prev = c;
    }
    out.push('"');
}

struct Tokener {
    chars: Vec<char>,
    pos: usize,
}

impl Tokener {
    fn next_clean(&mut self) -> Option<char> {
        while let Some(&c) = self.chars.get(self.pos) {
            self.pos += 1;
            if c > ' ' {
                return Some(c);
            }
        }
        None
    }

    fn back(&mut self) {
        self.pos = self.pos.saturating_sub(1);
    }

    fn next_string(&mut self, quote: char) -> Result<String, String> {
        let mut out = String::new();
        loop {
            let c = *self.chars.get(self.pos).ok_or("Unterminated string")?;
            self.pos += 1;
            match c {
                '\n' | '\r' => return Err("Unterminated string".into()),
                '\\' => {
                    let e = *self.chars.get(self.pos).ok_or("Unterminated string")?;
                    self.pos += 1;
                    match e {
                        'b' => out.push('\u{8}'),
                        't' => out.push('\t'),
                        'n' => out.push('\n'),
                        'f' => out.push('\u{c}'),
                        'r' => out.push('\r'),
                        'u' => {
                            let hex: String = self.chars.get(self.pos..self.pos + 4).ok_or("Illegal escape.")?.iter().collect();
                            self.pos += 4;
                            let v = u32::from_str_radix(&hex, 16).map_err(|_| "Illegal escape.")?;
                            // Pares sustitutos UTF-16.
                            if (0xD800..0xDC00).contains(&v) && self.chars.get(self.pos) == Some(&'\\') && self.chars.get(self.pos + 1) == Some(&'u') {
                                let hex2: String = self.chars.get(self.pos + 2..self.pos + 6).unwrap_or(&[]).iter().collect();
                                if let Ok(lo) = u32::from_str_radix(&hex2, 16)
                                    && (0xDC00..0xE000).contains(&lo) {
                                        self.pos += 6;
                                        let cp = 0x10000 + ((v - 0xD800) << 10) + (lo - 0xDC00);
                                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                                        continue;
                                    }
                            }
                            out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
                        }
                        '"' | '\'' | '\\' | '/' => out.push(e),
                        _ => return Err("Illegal escape.".into()),
                    }
                }
                c if c == quote => return Ok(out),
                c => out.push(c),
            }
        }
    }

    fn next_value(&mut self) -> Result<JsonValue, String> {
        let c = self.next_clean().ok_or("Missing value")?;
        match c {
            '"' | '\'' => Ok(JsonValue::Str(self.next_string(c)?)),
            '{' => {
                self.back();
                Ok(JsonValue::Object(self.object()?))
            }
            '[' => {
                let mut items = Vec::new();
                if self.next_clean() == Some(']') {
                    return Ok(JsonValue::Array(items));
                }
                self.back();
                loop {
                    if self.next_clean() == Some(',') {
                        self.back();
                        items.push(JsonValue::Null);
                    } else {
                        self.back();
                        items.push(self.next_value()?);
                    }
                    match self.next_clean() {
                        Some(',') => {
                            if self.next_clean() == Some(']') {
                                return Ok(JsonValue::Array(items));
                            }
                            self.back();
                        }
                        Some(']') => return Ok(JsonValue::Array(items)),
                        _ => return Err("Expected a ',' or ']'".into()),
                    }
                }
            }
            _ => {
                let mut s = String::new();
                let mut cur = Some(c);
                while let Some(x) = cur {
                    if x < ' ' || ",:]}/\\\"[{;=#".contains(x) {
                        self.back();
                        break;
                    }
                    s.push(x);
                    cur = self.chars.get(self.pos).copied();
                    self.pos += 1;
                }
                if cur.is_none() {
                    self.back();
                }
                let s = s.trim().to_string();
                if s.is_empty() {
                    return Err("Missing value".into());
                }
                Ok(string_to_value(s))
            }
        }
    }

    fn object(&mut self) -> Result<JsonObject, String> {
        if self.next_clean() != Some('{') {
            return Err("A JSONObject text must begin with '{'".into());
        }
        let mut obj = JsonObject::new();
        loop {
            match self.next_clean() {
                None => return Err("A JSONObject text must end with '}'".into()),
                Some('}') => return Ok(obj),
                Some(_) => {
                    self.back();
                    let key = match self.next_value()? {
                        JsonValue::Str(s) | JsonValue::Num(s) => s,
                        JsonValue::Bool(b) => b.to_string(),
                        JsonValue::Null => "null".into(),
                        _ => return Err("Expected a key".into()),
                    };
                    if self.next_clean() != Some(':') {
                        return Err("Expected a ':' after a key".into());
                    }
                    let value = self.next_value()?;
                    if obj.has(&key) {
                        return Err(format!("Duplicate key \"{key}\""));
                    }
                    obj.put(key, value);
                    match self.next_clean() {
                        Some(';') | Some(',') => {
                            if self.next_clean() == Some('}') {
                                return Ok(obj);
                            }
                            self.back();
                        }
                        Some('}') => return Ok(obj),
                        _ => return Err("Expected a ',' or '}'".into()),
                    }
                }
            }
        }
    }
}

/// `JSONObject.stringToValue` para los valores sin comillas.
fn string_to_value(s: String) -> JsonValue {
    if s.eq_ignore_ascii_case("true") {
        return JsonValue::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return JsonValue::Bool(false);
    }
    if s.eq_ignore_ascii_case("null") {
        return JsonValue::Null;
    }
    let first = s.chars().next().unwrap_or(' ');
    if (first.is_ascii_digit() || first == '-') && s.parse::<f64>().is_ok() {
        return JsonValue::Num(s);
    }
    JsonValue::Str(s)
}

/// Analiza un objeto JSON (texto completo; se ignora lo que siga al objeto,
/// como `new JSONObject(String)`).
pub fn parse_object(text: &str) -> Result<JsonObject, String> {
    let mut t = Tokener { chars: text.chars().collect(), pos: 0 };
    t.object()
}

/// Analiza unos bytes UTF-8 como objeto JSON.
pub fn parse_object_bytes(bytes: &[u8]) -> Result<JsonObject, String> {
    parse_object(&String::from_utf8_lossy(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn org_json_style_parsing() {
        let o = parse_object(r#"{algo:"DES", key:"12345678"}"#).unwrap();
        assert_eq!(o.get_string("algo"), Ok("DES"));
        let o = parse_object(r#"{"algo":"AES","key":"a+b/","iv":'x',"n":12,legacydes:"1"}"#).unwrap();
        assert_eq!(o.get_string("iv"), Ok("x"));
        assert_eq!(o.get("n"), Some(&JsonValue::Num("12".into())));
        assert!(o.get_string("n").is_err());
        let o = parse_object(r#"{a: [1, {b: "c"},], d: "ñ😀", e: TRUE, f: "true"}"#).unwrap();
        assert_eq!(o.get_string("d"), Ok("ñ😀"));
        assert_eq!(o.get_boolean("e"), Ok(true));
        assert_eq!(o.get_boolean("f"), Ok(true));
        assert!(parse_object("{a:").is_err());
        assert!(parse_object("x").is_err());
        assert!(parse_object(r#"{"a":"b""#).is_err());
        assert!(parse_object("{a:1,a:2}").is_err());
    }

    #[test]
    fn org_json_serialisation() {
        let o = parse_object(r#"{"format":"XAdES","signinfo":[{"id":"a","params":{"PRE":"x/y","NEED_PRE":"true"}}]}"#).unwrap();
        // Orden de HashMap de Java comprobado con una JVM.
        assert_eq!(o.to_org_json(), r#"{"signinfo":[{"id":"a","params":{"PRE":"x/y","NEED_PRE":"true"}}],"format":"XAdES"}"#);
        assert_eq!(quote("a</b\"\\\n\u{1}\u{85}"), r#""a<\/b\"\\\n\u0001\u0085""#);
    }
}
