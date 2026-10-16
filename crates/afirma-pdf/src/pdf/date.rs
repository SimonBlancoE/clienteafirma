//! Fechas: formato PDF (`PdfDate` de iText), W3C (XMP), `signTime` y un
//! formateador compatible con `java.text.SimpleDateFormat` (configuración
//! regional `es_ES`, la habitual de los usuarios de AutoFirma).

use chrono::{
    DateTime, Datelike, Duration, FixedOffset, Local, NaiveDate, NaiveDateTime, Offset, TimeZone,
    Timelike,
};

/// Instante de firma con la zona horaria local en la que se representa.
pub type SignTime = DateTime<FixedOffset>;

/// Hora actual en la zona local.
pub fn now() -> SignTime {
    let l = Local::now();
    l.with_timezone(l.offset())
}

/// Convierte un instante a la zona local.
pub fn to_local(t: DateTime<chrono::Utc>) -> SignTime {
    let l = t.with_timezone(&Local);
    l.with_timezone(l.offset())
}

/// Fecha PDF (`D:YYYYMMDDHHmmSS+HH'mm'`), como `PdfDate` de iText: las
/// horas de desfase se truncan hacia cero, de modo que desfases entre -1 h y
/// 0 se escriben como `Z`.
pub fn pdf_date(t: &SignTime) -> String {
    let mut s = format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let off_min = t.offset().local_minus_utc() / 60;
    let hours = off_min / 60;
    if hours == 0 {
        s.push('Z');
    } else {
        s.push(if off_min < 0 { '-' } else { '+' });
        let mins = off_min.abs() - hours.abs() * 60;
        s.push_str(&format!("{:02}'{:02}'", hours.abs(), mins));
    }
    s
}

/// Fecha W3C (`YYYY-MM-DDTHH:mm:ss+HH:MM` o `Z`), como en XMP.
pub fn w3c_date(t: &SignTime) -> String {
    let mut s = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let off = t.offset().local_minus_utc() / 60;
    if off == 0 {
        s.push('Z');
    } else {
        s.push(if off < 0 { '-' } else { '+' });
        s.push_str(&format!("{:02}:{:02}", off.abs() / 60, off.abs() % 60));
    }
    s
}

/// Interpreta una fecha PDF (`D:YYYYMMDDHHmmSSOHH'mm'`, con partes
/// opcionales).
pub fn parse_pdf_date(s: &str) -> Option<SignTime> {
    let s = s.trim();
    let s = s.strip_prefix("D:").unwrap_or(s);
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return None;
    }
    let num = |a: usize, b: usize, def: u32| -> u32 {
        digits.get(a..b).and_then(|x| x.parse().ok()).unwrap_or(def)
    };
    let year: i32 = digits[0..4].parse().ok()?;
    let (mo, d, h, mi, se) = (
        num(4, 6, 1),
        num(6, 8, 1),
        num(8, 10, 0),
        num(10, 12, 0),
        num(12, 14, 0),
    );
    let rest = &s[digits.len()..];
    let offset = match rest.chars().next() {
        Some('+') | Some('-') => {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let nums: String = rest[1..].chars().filter(char::is_ascii_digit).collect();
            let oh: i32 = nums.get(0..2).and_then(|x| x.parse().ok()).unwrap_or(0);
            let om: i32 = nums.get(2..4).and_then(|x| x.parse().ok()).unwrap_or(0);
            FixedOffset::east_opt(sign * (oh * 3600 + om * 60))?
        }
        _ => FixedOffset::east_opt(0)?,
    };
    let naive =
        NaiveDate::from_ymd_opt(year, mo.max(1), d.max(1))?.and_hms_opt(h, mi, se.min(59))?;
    offset.from_local_datetime(&naive).single()
}

/// Interpreta el parámetro `signTime` (`yyyy:MM:dd:HH:mm:ss` en la zona
/// local), de forma permisiva como `SimpleDateFormat` (los valores fuera de
/// rango se acarrean: el mes 13 es enero del año siguiente).
pub fn parse_sign_time(value: &str) -> Option<SignTime> {
    let parts: Vec<&str> = value.trim().split(':').collect();
    if parts.len() < 6 {
        return None;
    }
    let mut nums = [0i64; 6];
    for (i, p) in parts.iter().take(6).enumerate() {
        nums[i] = p.trim().parse().ok()?;
    }
    let base = NaiveDate::from_ymd_opt(i32::try_from(nums[0]).ok()?, 1, 1)?.and_hms_opt(0, 0, 0)?;
    let months = nums[1] - 1;
    let years = months.div_euclid(12);
    let month0 = months.rem_euclid(12);
    let date = NaiveDate::from_ymd_opt(
        base.year() + i32::try_from(years).ok()?,
        u32::try_from(month0 + 1).ok()?,
        1,
    )?;
    let naive: NaiveDateTime = date.and_hms_opt(0, 0, 0)?
        + Duration::days(nums[2] - 1)
        + Duration::hours(nums[3])
        + Duration::minutes(nums[4])
        + Duration::seconds(nums[5]);
    let local = Local.from_local_datetime(&naive).earliest()?;
    Some(local.with_timezone(local.offset()))
}

// ---------------------------------------------------------------------------
// SimpleDateFormat (es_ES)
// ---------------------------------------------------------------------------

const MONTHS_FULL: [&str; 12] = [
    "enero",
    "febrero",
    "marzo",
    "abril",
    "mayo",
    "junio",
    "julio",
    "agosto",
    "septiembre",
    "octubre",
    "noviembre",
    "diciembre",
];
const MONTHS_SHORT: [&str; 12] = [
    "ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sept", "oct", "nov", "dic",
];
const DAYS_FULL: [&str; 7] = [
    "lunes",
    "martes",
    "miércoles",
    "jueves",
    "viernes",
    "sábado",
    "domingo",
];
const DAYS_SHORT: [&str; 7] = ["lun", "mar", "mié", "jue", "vie", "sáb", "dom"];

/// Patrón por defecto de `new SimpleDateFormat()` en `es_ES`.
pub const DEFAULT_PATTERN: &str = "d/M/yy, H:mm";

#[derive(Debug)]
enum Tok {
    Lit(String),
    Field(char, usize),
}

fn compile(pattern: &str) -> Option<Vec<Tok>> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut lit = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if chars.get(i + 1) == Some(&'\'') {
                lit.push('\'');
                i += 2;
                continue;
            }
            // Texto entrecomillado.
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        lit.push('\'');
                        i += 2;
                        continue;
                    }
                    closed = true;
                    i += 1;
                    break;
                }
                lit.push(chars[i]);
                i += 1;
            }
            if !closed {
                return None;
            }
            continue;
        }
        if c.is_ascii_alphabetic() {
            if !"GyYMLwWDdFEuaHkKhmsSzZX".contains(c) {
                return None;
            }
            if !lit.is_empty() {
                out.push(Tok::Lit(std::mem::take(&mut lit)));
            }
            let mut n = 1;
            while chars.get(i + n) == Some(&c) {
                n += 1;
            }
            if c == 'X' && n > 3 {
                return None;
            }
            out.push(Tok::Field(c, n));
            i += n;
            continue;
        }
        lit.push(c);
        i += 1;
    }
    if !lit.is_empty() {
        out.push(Tok::Lit(lit));
    }
    Some(out)
}

fn pad(v: i64, n: usize) -> String {
    format!("{v:0n$}")
}

/// Nombre corto de la zona horaria (como `z` de Java) para la fecha dada.
pub fn tz_short_name(t: &SignTime) -> String {
    tz_name(t, false)
}

fn tz_name(t: &SignTime, long: bool) -> String {
    let off = t.offset().local_minus_utc();
    let zone = iana_time_zone::get_timezone().unwrap_or_default();
    // (desfase normal en segundos, abreviatura normal, abreviatura de verano,
    // nombre largo normal, nombre largo de verano)
    let table: &[(&str, i32, &str, &str, &str, &str)] = &[
        (
            "Europe/Madrid",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Africa/Ceuta",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Europe/Paris",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Europe/Berlin",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Europe/Rome",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Europe/Brussels",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Europe/Amsterdam",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Europe/Andorra",
            3600,
            "CET",
            "CEST",
            "hora estándar de Europa central",
            "hora de verano de Europa central",
        ),
        (
            "Atlantic/Canary",
            0,
            "WET",
            "WEST",
            "hora estándar de Europa occidental",
            "hora de verano de Europa occidental",
        ),
        (
            "Europe/Lisbon",
            0,
            "WET",
            "WEST",
            "hora estándar de Europa occidental",
            "hora de verano de Europa occidental",
        ),
        (
            "Europe/London",
            0,
            "GMT",
            "BST",
            "hora del meridiano de Greenwich",
            "hora de verano británica",
        ),
        (
            "UTC",
            0,
            "UTC",
            "UTC",
            "tiempo universal coordinado",
            "tiempo universal coordinado",
        ),
        (
            "Etc/UTC",
            0,
            "UTC",
            "UTC",
            "tiempo universal coordinado",
            "tiempo universal coordinado",
        ),
    ];
    if let Some(&(_, std_off, s, d, ls, ld)) = table.iter().find(|e| e.0 == zone) {
        let dst = off != std_off;
        return match (long, dst) {
            (false, false) => s.into(),
            (false, true) => d.into(),
            (true, false) => ls.into(),
            (true, true) => ld.into(),
        };
    }
    gmt_offset(off)
}

fn gmt_offset(off: i32) -> String {
    if off == 0 {
        return "GMT".into();
    }
    let sign = if off < 0 { '-' } else { '+' };
    let a = off.abs() / 60;
    format!("GMT{sign}{:02}:{:02}", a / 60, a % 60)
}

/// Semana del año según ISO (lunes primer día, mínimo 4 días), como Java
/// en `es_ES`.
fn week_of_year(d: NaiveDate) -> u32 {
    d.iso_week().week()
}

fn week_of_month(d: NaiveDate) -> u32 {
    // Primer día de la semana: lunes; mínimo 4 días en la primera semana.
    let first = d.with_day(1).unwrap_or(d);
    let first_wd = first.weekday().num_days_from_monday() as i64; // 0 = lunes
    let days_in_first_week = 7 - first_wd;
    let offset = if days_in_first_week >= 4 {
        first_wd
    } else {
        first_wd - 7
    };
    ((i64::from(d.day()) - 1 + offset) / 7 + 1).max(0) as u32
}

/// Formatea con un patrón de `SimpleDateFormat`. Devuelve `None` si el
/// patrón no es válido.
pub fn java_format(t: &SignTime, pattern: &str) -> Option<String> {
    let toks = compile(pattern)?;
    let mut out = String::new();
    for tok in toks {
        match tok {
            Tok::Lit(s) => out.push_str(&s),
            Tok::Field(c, n) => {
                let s = match c {
                    'G' => "d. C.".to_string(),
                    'y' | 'Y' => {
                        let y = i64::from(if c == 'Y' {
                            t.iso_week().year()
                        } else {
                            t.year()
                        });
                        if n == 2 {
                            pad(y.rem_euclid(100), 2)
                        } else {
                            pad(y, n)
                        }
                    }
                    'M' | 'L' => {
                        let m = t.month0() as usize;
                        match n {
                            1 | 2 => pad(i64::from(t.month()), n),
                            3 => MONTHS_SHORT[m].into(),
                            _ => MONTHS_FULL[m].into(),
                        }
                    }
                    'w' => pad(i64::from(week_of_year(t.date_naive())), n),
                    'W' => pad(i64::from(week_of_month(t.date_naive())), n),
                    'D' => pad(i64::from(t.ordinal()), n),
                    'd' => pad(i64::from(t.day()), n),
                    'F' => pad(i64::from((t.day() - 1) / 7 + 1), n),
                    'E' => {
                        let wd = t.weekday().num_days_from_monday() as usize;
                        if n >= 4 {
                            DAYS_FULL[wd].into()
                        } else {
                            DAYS_SHORT[wd].into()
                        }
                    }
                    'u' => pad(i64::from(t.weekday().number_from_monday()), n),
                    'a' => (if t.hour() < 12 { "a. m." } else { "p. m." }).into(),
                    'H' => pad(i64::from(t.hour()), n),
                    'k' => pad(i64::from(if t.hour() == 0 { 24 } else { t.hour() }), n),
                    'K' => pad(i64::from(t.hour() % 12), n),
                    'h' => pad(
                        i64::from(if t.hour() % 12 == 0 {
                            12
                        } else {
                            t.hour() % 12
                        }),
                        n,
                    ),
                    'm' => pad(i64::from(t.minute()), n),
                    's' => pad(i64::from(t.second()), n),
                    'S' => pad(i64::from(t.timestamp_subsec_millis()), n),
                    'z' => tz_name(t, n >= 4),
                    'Z' => {
                        let off = t.offset().local_minus_utc() / 60;
                        let sign = if off < 0 { '-' } else { '+' };
                        format!("{sign}{:02}{:02}", off.abs() / 60, off.abs() % 60)
                    }
                    'X' => {
                        let off = t.offset().local_minus_utc() / 60;
                        if off == 0 {
                            "Z".into()
                        } else {
                            let sign = if off < 0 { '-' } else { '+' };
                            let (h, m) = (off.abs() / 60, off.abs() % 60);
                            match n {
                                1 => format!("{sign}{h:02}"),
                                2 => format!("{sign}{h:02}{m:02}"),
                                _ => format!("{sign}{h:02}:{m:02}"),
                            }
                        }
                    }
                    _ => return None,
                };
                out.push_str(&s);
            }
        }
    }
    Some(out)
}

/// Formatea con el patrón indicado o, si no es válido, con el patrón por
/// defecto (como hace AutoFirma con `$$SIGNDATE=…$$`).
pub fn java_format_or_default(t: &SignTime, pattern: &str) -> String {
    java_format(t, pattern).unwrap_or_else(|| java_format(t, DEFAULT_PATTERN).unwrap_or_default())
}

/// Milisegundos desde la época.
pub fn millis(t: &SignTime) -> i64 {
    t.timestamp_millis()
}

/// Instante a partir de milisegundos (zona local).
pub fn from_millis(ms: i64) -> Option<SignTime> {
    let utc = chrono::Utc.timestamp_millis_opt(ms).single()?;
    Some(to_local(utc))
}

/// Crea un instante con desfase fijo (útil en pruebas).
pub fn fixed(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32, offset_secs: i32) -> SignTime {
    let off = FixedOffset::east_opt(offset_secs).unwrap_or_else(|| chrono::Utc.fix());
    off.with_ymd_and_hms(y, mo, d, h, mi, s)
        .single()
        .unwrap_or_else(|| off.timestamp_opt(0, 0).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_dates() {
        let t = fixed(2026, 10, 16, 13, 35, 34, 7200);
        assert_eq!(pdf_date(&t), "D:20261016133534+02'00'");
        let t = fixed(2026, 1, 3, 1, 2, 3, 0);
        assert_eq!(pdf_date(&t), "D:20260103010203Z");
        let t = fixed(2026, 1, 3, 1, 2, 3, -1800);
        assert_eq!(pdf_date(&t), "D:20260103010203Z");
        let t = fixed(2026, 1, 3, 1, 2, 3, -(5 * 3600 + 1800));
        assert_eq!(pdf_date(&t), "D:20260103010203-05'30'");
        assert_eq!(
            w3c_date(&fixed(2026, 10, 16, 13, 35, 34, 7200)),
            "2026-10-16T13:35:34+02:00"
        );
        let p = parse_pdf_date("D:20261016133534+02'00'").unwrap();
        assert_eq!(p, fixed(2026, 10, 16, 13, 35, 34, 7200));
    }

    #[test]
    fn java_patterns_es() {
        // Valores observados con Java 21 en es_ES (zona Europe/Madrid).
        let t = fixed(2026, 10, 16, 9, 5, 7, 7200) + Duration::milliseconds(45);
        let w = fixed(2026, 1, 3, 21, 5, 7, 3600) + Duration::milliseconds(5);
        let cases = [
            ("dd/MM/yyyy", "16/10/2026", "03/01/2026"),
            ("d/M/yy", "16/10/26", "3/1/26"),
            (
                "EEEE d 'de' MMMM 'de' yyyy",
                "viernes 16 de octubre de 2026",
                "sábado 3 de enero de 2026",
            ),
            ("EEE, MMM d, ''yy", "vie, oct 16, '26", "sáb, ene 3, '26"),
            ("h:mm a", "9:05 a. m.", "9:05 p. m."),
            (
                "yyyy-MM-dd'T'HH:mm:ss.SSSZ",
                "2026-10-16T09:05:07.045+0200",
                "2026-01-03T21:05:07.005+0100",
            ),
            ("XXX X XX", "+02:00 +02 +0200", "+01:00 +01 +0100"),
            ("D F w W u k", "289 3 42 3 5 9", "3 1 1 1 6 21"),
            ("S SS SSSS", "45 45 0045", "5 05 0005"),
            (
                "yyyyy.MMMMM.dd GGG hh:mm aaa",
                "02026.octubre.16 d. C. 09:05 a. m.",
                "02026.enero.03 d. C. 09:05 p. m.",
            ),
        ];
        for (p, a, b) in cases {
            assert_eq!(java_format(&t, p).unwrap(), a, "{p}");
            assert_eq!(java_format(&w, p).unwrap(), b, "{p}");
        }
        assert!(java_format(&t, "dd/MM/yyyy q").is_none());
        assert_eq!(java_format_or_default(&t, "q"), "16/10/26, 9:05");
    }

    #[test]
    fn lenient_sign_time() {
        let t = parse_sign_time("2026:10:16:13:35:34").unwrap();
        assert_eq!(
            (
                t.year(),
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            ),
            (2026, 10, 16, 13, 35, 34)
        );
        let t = parse_sign_time("2025:13:01:00:00:00").unwrap();
        assert_eq!((t.year(), t.month(), t.day()), (2026, 1, 1));
        assert!(parse_sign_time("ayer").is_none());
    }
}
