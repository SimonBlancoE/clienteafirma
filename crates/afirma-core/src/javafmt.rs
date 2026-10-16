//! Formatos de fecha de Java usados en textos visibles: `Date.toString()`
//! (`AOTimestampInfo`, cabecera de `Properties.store`) y
//! `DateFormat.getDateTimeInstance(DEFAULT, SHORT)` en `es_ES`
//! (`AOSimpleSignInfo.toString()`, árbol de firmantes).
//!
//! Los formatos se han comprobado contra Java 21 (`testdata/core/misc.golden`).
//! Desviación: Java escribe la abreviatura de la zona horaria (`CEST`, `WET`...)
//! que Rust no puede obtener sin una base de datos de zonas; aquí se escribe
//! `GMT±hh:mm` (el formato de Java para zonas con desplazamiento fijo) o
//! `GMT` si el desplazamiento es cero, salvo que se indique la zona.

use chrono::{DateTime, Datelike, FixedOffset, Offset, TimeZone, Timelike};

const DAYS_EN: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS_EN: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/// Abreviaturas de mes de CLDR para `es` (JDK 17+; septiembre es `sept`).
const MONTHS_ES: [&str; 12] = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sept", "oct", "nov", "dic"];

/// Nombre de zona tipo Java para un desplazamiento fijo (`GMT+02:00`, `GMT`).
pub fn java_zone_label(offset: &FixedOffset) -> String {
    let secs = offset.local_minus_utc();
    if secs == 0 {
        return "GMT".into();
    }
    let sign = if secs < 0 { '-' } else { '+' };
    let abs = secs.unsigned_abs();
    format!("GMT{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
}

/// `java.util.Date.toString()` (`EEE MMM dd HH:mm:ss zzz yyyy`) en la zona de
/// la fecha recibida, con la zona escrita como `GMT±hh:mm`.
pub fn java_date_to_string<Tz: TimeZone>(dt: &DateTime<Tz>) -> String {
    let fixed = dt.fixed_offset();
    let label = java_zone_label(fixed.offset());
    java_date_to_string_with_zone(&fixed, &label)
}

/// `java.util.Date.toString()` con una etiqueta de zona explícita (p. ej.
/// `CEST`).
pub fn java_date_to_string_with_zone(dt: &DateTime<FixedOffset>, zone: &str) -> String {
    format!(
        "{} {} {:02} {:02}:{:02}:{:02} {} {}",
        DAYS_EN[dt.weekday().num_days_from_monday() as usize],
        MONTHS_EN[dt.month0() as usize],
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        zone,
        dt.year()
    )
}

/// `DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.SHORT)` en
/// `es_ES` con Java 17+ (`16 oct 2026, 13:17`), en la zona de la fecha.
pub fn java_default_short_datetime_es<Tz: TimeZone>(dt: &DateTime<Tz>) -> String {
    let d = dt.fixed_offset();
    format!("{} {} {}, {}:{:02}", d.day(), MONTHS_ES[d.month0() as usize], d.year(), d.hour(), d.minute())
}

/// Desplazamiento de la zona horaria local en el instante indicado.
pub fn local_offset_at(dt: &DateTime<chrono::Utc>) -> FixedOffset {
    dt.with_timezone(&chrono::Local).offset().fix()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn matches_java_oracle() {
        let golden =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/core/misc.golden")).unwrap();
        let instant = Utc.timestamp_millis_opt(1_792_149_420_000).unwrap();
        let zones = [
            ("Europe/Madrid", 7200, "CEST"),
            ("UTC", 0, "UTC"),
            ("GMT", 0, "GMT"),
            ("America/New_York", -14400, "EDT"),
            ("Atlantic/Canary", 3600, "WEST"),
        ];
        for line in golden.lines().filter(|l| l.starts_with("DATE\t")) {
            let cols: Vec<&str> = line.split('\t').collect();
            let (_, secs, abbr) = zones.iter().find(|z| z.0 == cols[1]).unwrap();
            let dt = instant.with_timezone(&FixedOffset::east_opt(*secs).unwrap());
            assert_eq!(java_date_to_string_with_zone(&dt, abbr), cols[2]);
            assert_eq!(java_default_short_datetime_es(&dt), cols[3]);
        }
        let months_line = golden.lines().find(|l| l.starts_with("MONTHS\t")).unwrap();
        let expected: Vec<&str> = months_line.split('\t').nth(1).unwrap().split('|').collect();
        for (m, exp) in expected.iter().enumerate() {
            let dt = Utc.with_ymd_and_hms(2026, m as u32 + 1, 5, 9, 5, 0).unwrap();
            assert_eq!(&java_default_short_datetime_es(&dt), exp);
        }
        let madrid = instant.with_timezone(&FixedOffset::east_opt(7200).unwrap());
        assert_eq!(java_date_to_string(&madrid), "Fri Oct 16 13:17:00 GMT+02:00 2026");
        assert_eq!(java_date_to_string(&instant), "Fri Oct 16 11:17:00 GMT 2026");
        assert_eq!(java_zone_label(&FixedOffset::west_opt(16200).unwrap()), "GMT-04:30");
    }
}
