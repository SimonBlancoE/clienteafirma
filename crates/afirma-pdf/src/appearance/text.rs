//! Fuentes estándar, maquetación de texto como `ColumnText`/`BidiLine` de
//! iText 2.1.7 y generación de los operadores de contenido.

use std::fmt::Write as _;

use super::afm::{COURIER_WIDTHS, HELVETICA_WIDTHS, TIMES_ROMAN_WIDTHS};
use crate::pdf::text::winansi_byte;
use crate::pdf::write::format_number as f;

/// Familia de fuente (`layer2FontFamily`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontFamily {
    /// 0 (y 3, 4 y cualquier otro valor, como en AutoFirma).
    #[default]
    Courier,
    /// 1
    Helvetica,
    /// 2
    TimesRoman,
}

impl FontFamily {
    pub fn from_param(v: i64) -> FontFamily {
        match v {
            1 => FontFamily::Helvetica,
            2 => FontFamily::TimesRoman,
            _ => FontFamily::Courier,
        }
    }

    pub fn base_font(self) -> &'static str {
        match self {
            FontFamily::Courier => "Courier",
            FontFamily::Helvetica => "Helvetica",
            FontFamily::TimesRoman => "Times-Roman",
        }
    }

    fn widths(self) -> &'static [u16; 256] {
        match self {
            FontFamily::Courier => &COURIER_WIDTHS,
            FontFamily::Helvetica => &HELVETICA_WIDTHS,
            FontFamily::TimesRoman => &TIMES_ROMAN_WIDTHS,
        }
    }

    /// Ancho de un carácter en unidades de 1/1000 (0 si no es representable).
    pub fn char_width(self, c: char) -> u16 {
        match winansi_byte(c) {
            Some(b) => self.widths()[usize::from(b)],
            None => 0,
        }
    }
}

/// Colores de `layer2FontColor` (RGB 0-255).
pub fn color_by_name(name: Option<&str>) -> (u8, u8, u8) {
    // Java busca `value.toLowerCase()` en una tabla con claves `lightGray` y
    // `darkGray`, por lo que esos dos colores salían siempre en negro. Aquí
    // se corrige (ver docs/deviations/afirma-pdf.md).
    match name.map(str::to_ascii_lowercase).as_deref() {
        Some("white") => (255, 255, 255),
        Some("lightgray") => (192, 192, 192),
        Some("gray") => (128, 128, 128),
        Some("darkgray") => (64, 64, 64),
        Some("red") => (255, 0, 0),
        Some("pink") => (255, 175, 175),
        _ => (0, 0, 0),
    }
}

/// Estilo del texto de la firma visible.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TextStyle {
    pub family: FontFamily,
    pub size: f64,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strike: bool,
    pub color: (u8, u8, u8),
    /// Fuente TrueType incrustada (documentos PDF/A). `None`: fuente estándar
    /// sin incrustar con métricas AFM y estilos simulados (como iText).
    pub embedded: Option<super::embedded::EmbeddedFace>,
}

impl Default for TextStyle {
    fn default() -> Self {
        TextStyle {
            family: FontFamily::Courier,
            size: 12.0,
            bold: false,
            italic: false,
            underline: false,
            strike: false,
            color: (0, 0, 0),
            embedded: None,
        }
    }
}

impl TextStyle {
    /// Estilo a partir de la máscara de `layer2FontStyle`.
    pub fn with_style_bits(mut self, bits: i64) -> Self {
        let bits = if bits < 0 { 0 } else { bits };
        self.bold = bits & 1 != 0;
        self.italic = bits & 2 != 0;
        self.underline = bits & 4 != 0;
        self.strike = bits & 8 != 0;
        self
    }

    /// Ancho en puntos de un carácter.
    pub fn char_width(&self, c: char) -> f64 {
        if no_print(c) {
            return 0.0;
        }
        let w = match &self.embedded {
            Some(face) => face.char_width(c),
            None => self.family.char_width(c),
        };
        f64::from(w) * self.size / 1000.0
    }

    pub fn text_width(&self, s: &str) -> f64 {
        s.chars().map(|c| self.char_width(c)).sum()
    }
}

/// Caracteres que iText no imprime.
fn no_print(c: char) -> bool {
    let u = c as u32;
    (0x200b..=0x200f).contains(&u) || (0x202a..=0x202e).contains(&u)
}

/// Caracteres de corte de línea (`DefaultSplitCharacter`).
fn is_split_char(c: char) -> bool {
    let u = c as u32;
    if c <= ' ' || c == '-' || c == '\u{2010}' {
        return true;
    }
    if u < 0x2002 {
        return false;
    }
    (0x2002..=0x200b).contains(&u)
        || (0x2e80..0xd7a0).contains(&u)
        || (0xf900..0xfb00).contains(&u)
        || (0xfe30..0xfe50).contains(&u)
        || (0xff61..0xffa0).contains(&u)
}

/// `Character.isWhitespace` de Java.
fn java_is_whitespace(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '\u{1c}'..='\u{1f}')
        || (c.is_whitespace() && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}') && c != '\u{85}')
}

fn is_ws(c: char) -> bool {
    c <= ' '
}

/// Párrafos del texto (separados por `\n`, `\r` o `\r\n`), con los
/// espacios finales eliminados. Un salto final no genera párrafo vacío.
fn paragraphs(text: &str) -> Vec<Vec<char>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0;
    let mut pending = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\r' || c == '\n' {
            if c == '\r' && chars.get(i + 1) == Some(&'\n') {
                i += 1;
            }
            out.push(std::mem::take(&mut cur));
            pending = false;
        } else {
            cur.push(c);
            pending = true;
        }
        i += 1;
    }
    if pending {
        out.push(cur);
    }
    for p in &mut out {
        // `trimRight` + `trimRightEx` de `BidiLine.getParagraph`.
        while p.last().is_some_and(|&c| is_ws(c) || no_print(c)) {
            p.pop();
        }
    }
    out
}

/// Línea maquetada.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub text: String,
    pub width: f64,
}

/// Maqueta el texto en líneas de ancho `width` como `BidiLine.processLine`
/// (sin límite de líneas).
pub fn break_lines(text: &str, width: f64, style: &TextStyle) -> Vec<Line> {
    let mut lines = Vec::new();
    for para in paragraphs(text) {
        if para.is_empty() {
            lines.push(Line {
                text: String::new(),
                width: 0.0,
            });
            continue;
        }
        let total = para.len();
        let mut current = 0usize;
        let mut first = true;
        while current < total {
            if !first {
                while current < total && (is_ws(para[current]) || no_print(para[current])) {
                    current += 1;
                }
                if current >= total {
                    break;
                }
            }
            first = false;
            let old = current;
            let mut w = width;
            let mut last_split: Option<usize> = None;
            let mut last_valid = false;
            while current < total {
                let c = para[current];
                if no_print(c) {
                    current += 1;
                    continue;
                }
                let cw = style.char_width(c);
                let split = is_split_char(c);
                if split && java_is_whitespace(c) {
                    last_split = Some(current);
                }
                if w - cw < 0.0 {
                    break;
                }
                if split {
                    last_split = Some(current);
                }
                w -= cw;
                last_valid = true;
                current += 1;
            }
            let range: (usize, usize);
            if !last_valid {
                // Ni un carácter cabe: se emite el primero.
                current += 1;
                range = (current - 1, current - 1);
            } else if current >= total {
                range = (old, total - 1);
            } else {
                let trim_right = |from: usize, to: usize| -> isize {
                    let mut idx = to as isize;
                    while idx >= from as isize {
                        let c = para[idx as usize];
                        if !is_ws(c) && !no_print(c) {
                            break;
                        }
                        idx -= 1;
                    }
                    idx
                };
                let new_cur = trim_right(old, current - 1);
                if new_cur < old as isize {
                    range = (old, current - 1);
                } else if last_split.is_none_or(|ls| ls as isize >= new_cur) {
                    range = (old, new_cur as usize);
                } else {
                    let ls = last_split.unwrap_or(0);
                    current = ls + 1;
                    let mut nc = trim_right(old, ls);
                    if nc < old as isize {
                        nc = current as isize - 1;
                    }
                    range = (old, nc as usize);
                }
            }
            let (a, b) = (range.0.min(total - 1), range.1.min(total - 1));
            let s: String = para[a..=b].iter().filter(|c| !no_print(**c)).collect();
            let lw = style.text_width(&s);
            lines.push(Line { text: s, width: lw });
        }
    }
    lines
}

/// Resultado de maquetar en una columna.
#[derive(Debug, Clone)]
pub struct ColumnLayout {
    /// Líneas con su línea base `(x, y)`.
    pub lines: Vec<(Line, f64, f64)>,
    /// Todo el texto ha cabido.
    pub complete: bool,
}

/// Maqueta en la columna `[llx, lly, urx, ury]` con interlineado fijo
/// (`ColumnText.setSimpleColumn` + `go`).
pub fn layout_column(text: &str, rect: (f64, f64, f64, f64), leading: f64, style: &TextStyle) -> ColumnLayout {
    let (llx, lly, urx, ury) = rect;
    let width = urx - llx;
    let all = break_lines(text, width, style);
    let mut y = ury;
    let mut out = Vec::new();
    let mut complete = true;
    for line in all {
        if y < lly || y > ury {
            complete = false;
            break;
        }
        y -= leading;
        if y < lly {
            complete = false;
            break;
        }
        out.push((line, llx, y));
    }
    if leading <= 0.0 && !out.is_empty() {
        complete = false;
    }
    ColumnLayout { lines: out, complete }
}

/// `fitText` de AutoFirma/iText: el mayor tamaño (≤ `max_size`) con el que
/// todo el texto cabe en el rectángulo.
pub fn fit_text(text: &str, rect: (f64, f64, f64, f64), max_size: f64, style: &TextStyle) -> f64 {
    let fits = |size: f64| {
        let st = TextStyle { size, ..*style };
        layout_column(text, rect, size, &st).complete
    };
    if fits(max_size) {
        return max_size;
    }
    let (mut min, mut max) = (0.0f64, max_size);
    let mut size = max_size;
    for _ in 0..50 {
        size = (min + max) / 2.0;
        if fits(size) {
            if max - min < size * 0.1 {
                return size;
            }
            min = size;
        } else {
            max = size;
        }
    }
    size
}

fn rgb(c: (u8, u8, u8)) -> String {
    format!(
        "{} {} {}",
        f(f64::from(c.0) / 255.0),
        f(f64::from(c.1) / 255.0),
        f(f64::from(c.2) / 255.0)
    )
}

/// Genera los operadores de un bloque de texto maquetado (subrayados y
/// tachados primero, como el lienzo gráfico de `ColumnText`, y después el
/// texto). `font_name` es el nombre del recurso de fuente (`F1`) y `enc`
/// codifica las cadenas para esa fuente. Con una fuente incrustada la
/// negrita y la cursiva son las de la propia fuente y no se simulan.
pub fn column_content(
    layout: &ColumnLayout,
    style: &TextStyle,
    font_name: &str,
    enc: &super::embedded::TextEncoder,
    out: &mut String,
) {
    if layout.lines.is_empty() {
        return;
    }
    let size = style.size;
    // Líneas de subrayado / tachado.
    for (line, x, y) in &layout.lines {
        if line.text.is_empty() || line.width <= 0.0 {
            continue;
        }
        for (enabled, shift) in [(style.underline, -size / 3.0), (style.strike, size / 3.0)] {
            if !enabled {
                continue;
            }
            let _ = writeln!(out, "{} RG", rgb(style.color));
            let _ = writeln!(out, "{} w", f(size / 15.0));
            let _ = writeln!(out, "{} {} m", f(*x), f(y + shift));
            let _ = writeln!(out, "{} {} l", f(x + line.width), f(y + shift));
            out.push_str("S\n0 G\n1 w\n");
        }
    }
    let simulate_bold = style.bold && style.embedded.is_none();
    let simulate_italic = style.italic && style.embedded.is_none();
    out.push_str("BT\n");
    let mut font_set = false;
    for (line, x, y) in &layout.lines {
        let _ = writeln!(out, "1 0 0 1 {} {} Tm", f(*x), f(*y));
        if line.text.is_empty() {
            continue;
        }
        if simulate_italic {
            let _ = writeln!(out, "1 0 0.21256 1 {} {} Tm", f(*x), f(*y));
        }
        if !font_set {
            let _ = writeln!(out, "/{font_name} {} Tf", f(size));
            font_set = true;
        }
        let stroke_width = size / 30.0;
        if simulate_bold {
            out.push_str("2 Tr\n");
            if (stroke_width - 1.0).abs() > f64::EPSILON {
                let _ = writeln!(out, "{} w", f(stroke_width));
            }
            let _ = writeln!(out, "{} RG", rgb(style.color));
        }
        let _ = writeln!(out, "{} rg", rgb(style.color));
        let bytes = enc.operand(&line.text);
        // Las cadenas PDF pueden contener bytes no UTF-8: se guardan como
        // caracteres Latin-1 y se recodifican al escribir el flujo.
        out.extend(bytes.iter().map(|&b| char::from(b)));
        out.push_str("Tj\n0 g\n");
        if simulate_bold {
            out.push_str("0 Tr\n0 G\n");
            if (stroke_width - 1.0).abs() > f64::EPSILON {
                out.push_str("1 w\n");
            }
        }
        if simulate_italic {
            // iText restablece la matriz tras un fragmento inclinado.
            let _ = writeln!(out, "1 0 0 1 {} {} Tm", f(x + line.width), f(*y));
            let _ = writeln!(out, "{} 0 Td", f(-line.width));
        }
    }
    out.push_str("ET\n");
}

/// Convierte el contenido generado (caracteres Latin-1) en bytes.
pub fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| if (c as u32) < 256 { c as u32 as u8 } else { b'?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_text_layout_matches_itext() {
        // Caso observado: caja 200x80, Courier 12, texto por defecto.
        let style = TextStyle::default();
        let text = "Firmado por PEREZ GARCIA JUAN - ***4567**\nFecha: 16/10/2026 13:36:29 CEST\nMotivo: Prueba\nLugar de firma: Madrid";
        let l = layout_column(text, (2.0, 2.0, 198.0, 78.0), 12.0, &style);
        let texts: Vec<&str> = l.lines.iter().map(|(l, _, _)| l.text.as_str()).collect();
        assert_eq!(
            texts,
            vec![
                "Firmado por PEREZ GARCIA",
                "JUAN - ***4567**",
                "Fecha: 16/10/2026 13:36:29",
                "CEST",
                "Motivo: Prueba",
                "Lugar de firma: Madrid"
            ]
        );
        let ys: Vec<f64> = l.lines.iter().map(|(_, _, y)| *y).collect();
        assert_eq!(ys, vec![66.0, 54.0, 42.0, 30.0, 18.0, 6.0]);
        assert!(l.complete);
    }

    #[test]
    fn long_words_and_truncation() {
        let style = TextStyle::default();
        // 7.2 pt por carácter: en 36 pt caben 5 caracteres.
        let lines = break_lines("ABCDEFGHIJ", 36.0, &style);
        assert_eq!(
            lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            vec!["ABCDE", "FGHIJ"]
        );
        let lines = break_lines("AB-CDEFG HI", 36.0, &style);
        assert_eq!(
            lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            vec!["AB-", "CDEFG", "HI"]
        );
        let l = layout_column("a\nb\nc\nd", (2.0, 2.0, 98.0, 28.0), 12.0, &style);
        assert_eq!(l.lines.len(), 2);
        assert!(!l.complete);
        assert_eq!(break_lines("a\n\nb\n", 100.0, &style).len(), 3);
        // Caracteres invisibles al final del párrafo.
        assert_eq!(break_lines("abc\u{200b}\u{200b}", 10.0, &style).len(), 3);
    }

    #[test]
    fn fit_text_shrinks() {
        let style = TextStyle::default();
        let s = fit_text("Texto bastante largo que no cabe", (2.0, 2.0, 78.0, 38.0), 12.0, &style);
        assert!(s < 12.0 && s > 3.0, "{s}");
        assert_eq!(fit_text("Hola", (2.0, 2.0, 78.0, 38.0), 12.0, &style), 12.0);
    }
}
