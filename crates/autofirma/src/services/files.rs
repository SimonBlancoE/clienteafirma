//! Carga y análisis de los ficheros a firmar (`SignPanel.loadFiles`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use afirma_core::ExtraParams;
use afirma_core::formats::DataFileType;
use afirma_signers::{FileAnalysis, ProposedOperation};

use crate::i18n::{tr, trf};
use crate::ui::pages::sign::{FileItem, FileKind, FileStatus, Operation};

/// Expande la selección: ficheros tal cual y carpetas recorridas
/// recursivamente (como AutoFirma). Se ignoran entradas inexistentes o
/// ilegibles.
pub fn expand_selection(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut work: std::collections::VecDeque<PathBuf> = paths.iter().cloned().collect();
    while let Some(p) = work.pop_front() {
        if p.is_file() {
            out.push(p);
        } else if p.is_dir()
            && let Ok(rd) = std::fs::read_dir(&p) {
                let mut children: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
                children.sort();
                work.extend(children);
            }
    }
    out
}

fn kind_for(analysis: &FileAnalysis) -> FileKind {
    match analysis.file_type {
        DataFileType::Pdf => FileKind::Pdf,
        DataFileType::FacturaE => FileKind::FacturaE,
        DataFileType::Ooxml => FileKind::Ooxml,
        DataFileType::Odf => FileKind::Odf,
        DataFileType::Xml => FileKind::Xml,
        DataFileType::Binary => FileKind::Binary,
        DataFileType::SignXades | DataFileType::SignCades => FileKind::Signature(analysis.format.clone()),
    }
}

/// Operación de multifirma según las preferencias `cadesMultisign` /
/// `xadesMultisign` (`cosign`, `countersignLeafs` u otro = árbol).
pub fn multisign_operation(file_type: DataFileType, pref: &dyn Fn(&str) -> Option<String>) -> Operation {
    let key = if file_type == DataFileType::SignXades { "xadesMultisign" } else { "cadesMultisign" };
    match pref(key).as_deref().unwrap_or("cosign") {
        "cosign" => Operation::Cosign,
        "countersignLeafs" => Operation::CountersignLeafs,
        _ => Operation::CountersignTree,
    }
}

/// Lee y analiza un fichero.
pub fn load_file(path: &Path, pref: &dyn Fn(&str) -> Option<String>) -> Result<FileItem, String> {
    let data = std::fs::read(path).map_err(|e| trf("No se ha podido leer {0}: {1}", &[&path.display(), &e]))?;
    let analysis = afirma_signers::analyze_for_desktop(&data, pref);
    let mut operation = Operation::Sign;
    let mut existing = None;
    if analysis.operation == ProposedOperation::Multisign {
        operation = match analysis.file_type {
            DataFileType::SignXades | DataFileType::SignCades => multisign_operation(analysis.file_type, pref),
            _ => Operation::Cosign,
        };
        if let Some(signer) = afirma_signers::signer_for_format(&analysis.format)
            && let Ok(tree) = signer.signers_structure(&data, &ExtraParams::new()) {
                let names: Vec<String> = tree.signers.iter().map(|n| n.info.signer_name()).collect();
                existing = Some(match names.as_slice() {
                    [] => tr("Firmado").to_string(),
                    [one] => trf("1 firma de {0}", &[one]),
                    many => trf("{0} firmas", &[&many.len()]),
                });
            }
    }
    Ok(FileItem {
        path: path.to_path_buf(),
        name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        size: data.len() as u64,
        kind: kind_for(&analysis),
        format: analysis.format.clone(),
        formats: if analysis.alternatives.is_empty() { vec![analysis.format.clone()] } else { analysis.alternatives.clone() },
        operation,
        status: FileStatus::Pending,
        existing_signatures: existing,
        data: Arc::new(data),
    })
}

/// Carga varios ficheros; devuelve los cargados y los errores.
pub fn load_files(paths: &[PathBuf], pref: &dyn Fn(&str) -> Option<String>) -> (Vec<FileItem>, Vec<String>) {
    let mut items = Vec::new();
    let mut errors = Vec::new();
    for p in expand_selection(paths) {
        match load_file(&p, pref) {
            Ok(i) => items.push(i),
            Err(e) => errors.push(e),
        }
    }
    (items, errors)
}
