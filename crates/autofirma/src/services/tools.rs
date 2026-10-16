//! Herramientas: huellas digitales, diagnóstico e integración con el sistema.

use std::path::{Path, PathBuf};

use afirma_hash::document::DirDocumentFormat;
use afirma_hash::single::FileHashFormat;
use afirma_system::{AppIdentity, Context};

use crate::ui::pages::tools::CheckRow;

/// Resultado de una herramienta.
pub enum ToolOutcome {
    /// Huella calculada: bytes a guardar, nombre propuesto, extensión y texto
    /// para el portapapeles.
    FileHash { content: Vec<u8>, proposed: String, ext: String, clipboard: String },
    DirHash { document: afirma_hash::document::HashDocument, proposed: String },
    Check { ok: bool, title: String, detail: Option<String>, report_xml: Option<Vec<u8>> },
    Doctor(Vec<CheckRow>),
    Error(String),
}

pub fn hash_file(path: &Path, algorithm: &str, format_label: &str) -> ToolOutcome {
    let run = || -> Result<ToolOutcome, String> {
        let alg = afirma_hash::algorithm::parse_algorithm(algorithm).map_err(|e| e.to_string())?;
        let format = FileHashFormat::from_preference(Some(format_label));
        let digest = afirma_hash::single::hash_file(path, alg).map_err(|e| e.to_string())?;
        Ok(ToolOutcome::FileHash {
            content: afirma_hash::single::encode_file_hash(&digest, format),
            proposed: afirma_hash::single::default_file_hash_name(path, format),
            ext: format.extension().to_string(),
            clipboard: afirma_hash::single::clipboard_text(&digest, format),
        })
    };
    run().unwrap_or_else(ToolOutcome::Error)
}

pub fn check_file(data: &Path, hash: &Path) -> ToolOutcome {
    match afirma_hash::single::check_file_hash_file(data, hash) {
        Ok(c) if c.matches => ToolOutcome::Check {
            ok: true,
            title: "Las huellas digitales coinciden".into(),
            detail: Some("El fichero no ha cambiado desde que se calculó la huella.".into()),
            report_xml: None,
        },
        Ok(_) => ToolOutcome::Check {
            ok: false,
            title: "Las huellas digitales no coinciden".into(),
            detail: Some("El fichero ha cambiado o la huella corresponde a otro fichero.".into()),
            report_xml: None,
        },
        Err(e) => ToolOutcome::Error(e.to_string()),
    }
}

pub fn hash_dir(dir: &Path, algorithm: &str, recursive: bool) -> ToolOutcome {
    let run = || -> Result<ToolOutcome, String> {
        let alg = afirma_hash::algorithm::parse_algorithm(algorithm).map_err(|e| e.to_string())?;
        let opts = afirma_hash::dir::HashOptions { threads: 0, cancel: None, progress: None };
        let document = afirma_hash::dir::hash_directory(dir, recursive, alg, &opts).map_err(|e| e.to_string())?;
        Ok(ToolOutcome::DirHash { document, proposed: afirma_hash::dir::default_directory_document_name(dir, DirDocumentFormat::Xml) })
    };
    run().unwrap_or_else(ToolOutcome::Error)
}

pub fn check_dir(dir: &Path, document: &Path) -> ToolOutcome {
    let opts = afirma_hash::dir::HashOptions { threads: 0, cancel: None, progress: None };
    match afirma_hash::dir::check_directory_with_file(dir, document, &opts) {
        Ok(r) => {
            let mut lines = Vec::new();
            lines.push(format!("{} ficheros coinciden", r.matching_hash.len()));
            if !r.not_matching_hash.is_empty() {
                lines.push(format!("Modificados: {}", r.not_matching_hash.join(", ")));
            }
            if !r.hash_without_file.is_empty() {
                lines.push(format!("Eliminados: {}", r.hash_without_file.join(", ")));
            }
            if !r.file_without_hash.is_empty() {
                lines.push(format!("Nuevos: {}", r.file_without_hash.join(", ")));
            }
            let ok = !r.has_errors();
            ToolOutcome::Check {
                ok,
                title: if ok { "Las huellas digitales coinciden".into() } else { "Se han encontrado diferencias en la carpeta".into() },
                detail: Some(lines.join("\n")),
                report_xml: r.to_xml().ok(),
            }
        }
        Err(e) => ToolOutcome::Error(e.to_string()),
    }
}

fn row_from(c: &afirma_system::doctor::Check) -> CheckRow {
    use afirma_system::doctor::CheckStatus;
    let ok = match c.status {
        CheckStatus::Ok | CheckStatus::Info => Some(true),
        CheckStatus::Warning | CheckStatus::Error => Some(false),
        CheckStatus::Skipped => None,
    };
    let mut detail = c.detail.clone();
    if let Some(f) = &c.fix {
        if ok == Some(false) {
            detail = format!("{detail} {f}");
        }
    }
    CheckRow { ok, title: c.title.clone(), detail }
}

pub fn doctor() -> ToolOutcome {
    let ctx = Context::detect(AppIdentity::current());
    let report = afirma_system::doctor::run(&ctx, &afirma_system::doctor::DoctorOptions::default());
    ToolOutcome::Doctor(report.checks.iter().map(row_from).collect())
}

/// Instala (o repara) la integración del usuario: certificado local,
/// confianza en los navegadores y protocolo `afirma://`.
pub fn repair() -> ToolOutcome {
    let ctx = Context::detect(AppIdentity::current());
    let plan = afirma_system::install::plan_install(&ctx, &afirma_system::install::InstallOptions::default());
    let report = afirma_system::install::execute(&ctx, &plan, false);
    let mut rows: Vec<CheckRow> = report
        .outcomes
        .iter()
        .map(|o| {
            let failed = matches!(o.status, afirma_system::install::Status::Failed(_));
            CheckRow {
                ok: Some(!failed),
                title: o.description.clone(),
                detail: match &o.status {
                    afirma_system::install::Status::Failed(e) => e.clone(),
                    _ => String::new(),
                },
            }
        })
        .collect();
    if let ToolOutcome::Doctor(mut after) = doctor() {
        rows.append(&mut after);
    }
    ToolOutcome::Doctor(rows)
}

/// Propuesta de ruta para guardar junto a `near`.
pub fn proposed_path(near: &Path, name: &str) -> PathBuf {
    near.parent().map(|d| d.join(name)).unwrap_or_else(|| PathBuf::from(name))
}

/// Formato de documento de huellas según la extensión elegida al guardar.
pub fn dir_format_for(path: &Path) -> DirDocumentFormat {
    DirDocumentFormat::from_save_path(path)
}
