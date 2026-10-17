//! Histórico de firmas (`docs/spec/09-android.md` §2.10 y §3.10).
//!
//! Mismo fichero que el original: `signsRecord.txt` en el directorio privado de la
//! aplicación, una línea por firma con los campos separados por `;`:
//!
//! ```text
//! <dd-MM-yyyy HH:mm:ss>;<tipo>;<operación>;<fichero>;<aplicación>
//! ```
//!
//! Los campos ausentes se escriben como `null`. Dos correcciones (§10 n.º 54): un `;` o un
//! salto de línea dentro de un nombre se sustituyen por un espacio al escribir (en el
//! original corrompían la línea) y una línea con menos de cinco campos se salta en lugar de
//! dejar sin leer el resto del fichero.

use std::cmp::Reverse;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::NaiveDateTime;

use crate::i18n::{tr, trf};

/// Nombre del fichero del histórico.
pub const HISTORY_FILE: &str = "signsRecord.txt";

const DATE_FORMAT: &str = "%d-%m-%Y %H:%M:%S";

/// Origen de la firma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// Firma de un fichero elegido en la aplicación.
    Local,
    /// Firma pedida por una página web (`afirma://`).
    Web,
    /// Firma pedida por otra aplicación (`SIGN_SERVICE`).
    App,
    /// Lote pedido por una página web.
    Batch,
    /// Lote pedido por otra aplicación.
    BatchApp,
}

impl RecordKind {
    fn tag(self) -> &'static str {
        match self {
            RecordKind::Local => "LOCAL",
            RecordKind::Web => "WEB",
            RecordKind::App => "APP",
            RecordKind::Batch => "BATCH",
            RecordKind::BatchApp => "BATCH_APP",
        }
    }

    fn from_tag(tag: &str) -> Option<RecordKind> {
        [
            RecordKind::Local,
            RecordKind::Web,
            RecordKind::App,
            RecordKind::Batch,
            RecordKind::BatchApp,
        ]
        .into_iter()
        .find(|k| k.tag() == tag)
    }
}

/// Operación de firma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOperation {
    Sign,
    Cosign,
    Countersign,
}

impl RecordOperation {
    fn tag(self) -> &'static str {
        match self {
            RecordOperation::Sign => "sign",
            RecordOperation::Cosign => "cosign",
            RecordOperation::Countersign => "countersign",
        }
    }

    fn from_tag(tag: &str) -> Option<RecordOperation> {
        [
            RecordOperation::Sign,
            RecordOperation::Cosign,
            RecordOperation::Countersign,
        ]
        .into_iter()
        .find(|o| o.tag() == tag)
    }

    fn label(self) -> &'static str {
        match self {
            RecordOperation::Sign => tr("sign"),
            RecordOperation::Cosign => tr("cosign"),
            RecordOperation::Countersign => tr("countersign"),
        }
    }
}

/// Una firma del histórico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRecord {
    /// Fecha y hora locales tal como están en el fichero.
    pub date: String,
    pub kind: RecordKind,
    pub operation: RecordOperation,
    /// Nombre del fichero firmado (sin ruta).
    pub file: Option<String>,
    /// Aplicación o página que pidió la firma (`appname` o paquete).
    pub app: Option<String>,
}

impl SignRecord {
    /// Registro con la hora local actual.
    pub fn now(kind: RecordKind, operation: RecordOperation, file: Option<&str>, app: Option<&str>) -> SignRecord {
        SignRecord {
            date: chrono::Local::now().format(DATE_FORMAT).to_string(),
            kind,
            operation,
            file: file.map(str::to_string),
            app: app.map(str::to_string),
        }
    }

    /// Línea del fichero (sin el salto final).
    pub fn to_line(&self) -> String {
        let field = |v: &Option<String>| match v {
            Some(v) if !v.is_empty() => v.replace([';', '\n', '\r'], " "),
            _ => "null".to_string(),
        };
        format!(
            "{};{};{};{};{}",
            self.date,
            self.kind.tag(),
            self.operation.tag(),
            field(&self.file),
            field(&self.app)
        )
    }

    /// Lee una línea del fichero (`None` si le faltan campos o no se entiende).
    pub fn parse_line(line: &str) -> Option<SignRecord> {
        let fields: Vec<&str> = line.trim_end_matches('\r').split(';').collect();
        if fields.len() < 5 {
            return None;
        }
        let optional = |v: &str| (!v.is_empty() && v != "null").then(|| v.to_string());
        Some(SignRecord {
            date: fields[0].to_string(),
            kind: RecordKind::from_tag(fields[1])?,
            operation: RecordOperation::from_tag(fields[2])?,
            file: optional(fields[3]),
            app: optional(fields[4]),
        })
    }

    /// Fecha leída, para ordenar.
    pub fn timestamp(&self) -> Option<NaiveDateTime> {
        NaiveDateTime::parse_from_str(&self.date, DATE_FORMAT).ok()
    }

    /// Descripción de la fila del histórico (tabla de §2.10).
    pub fn describe(&self) -> String {
        let op = self.operation.label();
        match (self.kind, self.app.as_deref(), self.file.as_deref()) {
            (RecordKind::Local, _, file) => trf("local_sign_record", &[&op, &file.unwrap_or("null")]),
            (RecordKind::Web, Some(app), Some(file)) => trf("web_sign_record_appname_and_file", &[&op, &app, &file]),
            (RecordKind::Web, Some(app), None) => trf("web_sign_record", &[&op, &app]),
            (RecordKind::Web, None, Some(file)) => trf("web_sign_record_file", &[&op, &file]),
            (RecordKind::Web, None, None) => trf("web_operation", &[&op]),
            (RecordKind::App, Some(app), Some(file)) => trf("app_sign_record_appname_and_file", &[&op, &app, &file]),
            (RecordKind::App, Some(app), None) => trf("app_sign_record", &[&op, &app]),
            (RecordKind::App, None, Some(file)) => trf("app_sign_record_file", &[&op, &file]),
            (RecordKind::App, None, None) => trf("app_operation", &[&op]),
            (RecordKind::Batch, Some(app), _) => trf("batch_sign_record", &[&app]),
            (RecordKind::BatchApp, Some(app), _) => trf("app_batch_sign_record", &[&app]),
            (RecordKind::Batch | RecordKind::BatchApp, None, _) => tr("title_activity_sign_batch").to_string(),
        }
    }
}

/// Fichero del histórico de firmas.
#[derive(Debug, Clone)]
pub struct SignsHistory {
    path: Option<PathBuf>,
}

impl SignsHistory {
    /// Histórico del directorio privado de la aplicación.
    pub fn open(dir: &Path) -> SignsHistory {
        SignsHistory {
            path: Some(dir.join(HISTORY_FILE)),
        }
    }

    /// Sin fichero (pruebas): siempre vacío y no guarda nada.
    pub fn disabled() -> SignsHistory {
        SignsHistory { path: None }
    }

    /// Firmas registradas, de la más reciente a la más antigua.
    pub fn load(&self) -> std::io::Result<Vec<SignRecord>> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut records: Vec<SignRecord> = text.lines().filter_map(SignRecord::parse_line).collect();
        // Orden estable: las fechas que no se entienden quedan al final.
        records.sort_by_key(|r| Reverse(r.timestamp()));
        Ok(records)
    }

    /// Añade una firma al final del fichero.
    pub fn append(&self, record: &SignRecord) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", record.to_line())
    }

    /// Vacía el histórico (deja el fichero vacío, como el original).
    pub fn clear(&self) -> std::io::Result<()> {
        match &self.path {
            Some(path) => std::fs::write(path, ""),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Language, set_language, test_lock};

    fn record(date: &str, kind: RecordKind, op: RecordOperation, file: Option<&str>, app: Option<&str>) -> SignRecord {
        SignRecord {
            date: date.into(),
            kind,
            operation: op,
            file: file.map(Into::into),
            app: app.map(Into::into),
        }
    }

    #[test]
    fn formato_de_linea() {
        let r = record(
            "05-03-2026 10:20:30",
            RecordKind::Web,
            RecordOperation::Cosign,
            None,
            Some("sede.ejemplo.es"),
        );
        assert_eq!(r.to_line(), "05-03-2026 10:20:30;WEB;cosign;null;sede.ejemplo.es");
        assert_eq!(SignRecord::parse_line(&r.to_line()), Some(r));
        // Un «;» en el nombre ya no rompe la línea.
        let r = record(
            "05-03-2026 10:20:30",
            RecordKind::Local,
            RecordOperation::Sign,
            Some("a;b.pdf"),
            None,
        );
        assert_eq!(r.to_line(), "05-03-2026 10:20:30;LOCAL;sign;a b.pdf;null");
        assert_eq!(SignRecord::parse_line("05-03-2026;LOCAL;sign"), None);
        assert_eq!(SignRecord::parse_line("x;OTRO;sign;a;b"), None);
        // Campos de más: se usan los cinco primeros, como el original.
        assert!(SignRecord::parse_line("05-03-2026 10:20:30;APP;sign;a;b;c").is_some());
    }

    #[test]
    fn descripciones_por_tipo() {
        let _lock = test_lock();
        set_language(Language::Es);
        let d = |kind, file, app| record("", kind, RecordOperation::Sign, file, app).describe();
        assert_eq!(
            d(RecordKind::Local, Some("a.pdf"), None),
            "Firma local del fichero a.pdf"
        );
        assert_eq!(
            d(RecordKind::Web, Some("a.pdf"), Some("sede")),
            "Firma web solicitada por sede del fichero a.pdf"
        );
        assert_eq!(d(RecordKind::Web, None, Some("sede")), "Firma web solicitada por sede");
        assert_eq!(d(RecordKind::Web, Some("a.pdf"), None), "Firma web del fichero a.pdf");
        assert_eq!(d(RecordKind::Web, None, None), "Firma web");
        assert_eq!(d(RecordKind::App, None, None), "Firma realizada desde otra aplicación");
        assert_eq!(
            d(RecordKind::App, Some("a.pdf"), None),
            "Firma solicitada desde otra aplicación del fichero a.pdf"
        );
        assert_eq!(
            d(RecordKind::Batch, None, Some("sede")),
            "Firma de lote web solicitada por sede"
        );
        assert_eq!(d(RecordKind::BatchApp, None, None), "Firma de lote");
        let cosign = record("", RecordKind::Web, RecordOperation::Countersign, None, None).describe();
        assert_eq!(cosign, "Contrafirma web");
    }

    #[test]
    fn fichero_ordenado_y_borrado() {
        let dir = tempfile::tempdir().unwrap();
        let history = SignsHistory::open(dir.path());
        assert!(history.load().unwrap().is_empty());
        let old = record(
            "01-01-2025 08:00:00",
            RecordKind::Local,
            RecordOperation::Sign,
            Some("a.pdf"),
            None,
        );
        let new = record(
            "02-01-2025 08:00:00",
            RecordKind::Web,
            RecordOperation::Sign,
            None,
            Some("sede"),
        );
        history.append(&old).unwrap();
        // Una línea corta en medio ya no impide leer las siguientes.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join(HISTORY_FILE))
            .unwrap();
        writeln!(f, "dañada;LOCAL").unwrap();
        history.append(&new).unwrap();
        assert_eq!(history.load().unwrap(), [new, old]);
        history.clear().unwrap();
        assert!(history.load().unwrap().is_empty());
        assert!(SignsHistory::disabled().load().unwrap().is_empty());
        let now = SignRecord::now(RecordKind::App, RecordOperation::Sign, None, Some("com.ejemplo"));
        assert!(now.timestamp().is_some());
    }
}
