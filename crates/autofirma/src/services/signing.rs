//! Firma de uno o varios ficheros desde la aplicación de escritorio
//! (`SignPanelSignTask`).

use std::path::PathBuf;
use std::sync::Arc;

use afirma_core::error::{ConfirmEffect, ErrorKind, UserIntervention};
use afirma_core::formats::{self, SignerKind};
use afirma_core::{AfirmaError, CounterSignTarget, ExtraParams, SigningKey};
use afirma_keystores::KeyStore;

use super::bridge::UiBridge;
use crate::i18n::{tr, trf};
use crate::ui::pages::sign::{FileItem, Operation};

/// Datos de una firma múltiple o simple.
pub struct SignJobInput {
    pub files: Vec<FileItem>,
    pub store: Arc<dyn KeyStore>,
    pub entry_id: String,
    pub algorithm: String,
    /// Parámetros por firmador (desde las preferencias).
    pub params_for: Arc<dyn Fn(SignerKind) -> ExtraParams + Send + Sync>,
    /// Parámetros de la firma visible para los PDF.
    pub visible_params: Option<ExtraParams>,
    /// Carpeta de salida (firmas múltiples); `None` = junto al original.
    pub output_dir: Option<PathBuf>,
    pub overwrite: bool,
    pub bridge: UiBridge,
}

/// Progreso de la firma.
#[derive(Debug, Clone)]
pub enum SignProgress {
    KeyReady,
    Started(usize),
    Finished(usize, Result<PathBuf, String>),
}

/// Ejecuta la firma de todos los ficheros. Devuelve un error global si no se
/// pudo obtener la clave (PIN cancelado, tarjeta extraída…).
pub fn run(input: SignJobInput, progress: &dyn Fn(SignProgress)) -> Result<(), String> {
    let key = input.store.signing_key(&input.entry_id).map_err(|e| e.to_string())?;
    progress(SignProgress::KeyReady);
    for (i, file) in input.files.iter().enumerate() {
        progress(SignProgress::Started(i));
        let result = sign_one(&input, file, key.as_ref()).and_then(|signed| write_output(&input, file, &signed));
        progress(SignProgress::Finished(i, result.map_err(|e| describe(&e))));
    }
    Ok(())
}

/// Mensaje para el usuario a partir de un error.
pub fn describe(e: &AfirmaError) -> String {
    match &e.code {
        Some(code) => format!("{} (AF{:06})", e.message, code.code),
        None => e.message.clone(),
    }
}

fn sign_one(input: &SignJobInput, file: &FileItem, key: &dyn SigningKey) -> Result<Vec<u8>, AfirmaError> {
    let signer = afirma_signers::signer_for_format(&file.format)
        .ok_or_else(|| AfirmaError::unsupported(trf("Formato de firma no disponible: {0}", &[&file.format])))?;
    let kind = formats::signer_kind_for_format(&file.format).unwrap_or(SignerKind::Cades);
    let mut extra = (input.params_for)(kind);
    if kind == SignerKind::Pdf
        && let Some(v) = &input.visible_params
    {
        extra.extend(v);
    }
    // Bucle de intervención del usuario (`RuntimeConfigNeededException`).
    for _ in 0..4 {
        let r = match file.operation {
            Operation::Sign => signer.sign(&file.data, &input.algorithm, key, &extra),
            Operation::Cosign => signer.cosign(None, &file.data, &input.algorithm, key, &extra),
            Operation::CountersignLeafs => {
                signer.countersign(&file.data, &input.algorithm, &CounterSignTarget::Leafs, key, &extra)
            }
            Operation::CountersignTree => {
                signer.countersign(&file.data, &input.algorithm, &CounterSignTarget::Tree, key, &extra)
            }
        };
        match r {
            Err(AfirmaError {
                kind:
                    ErrorKind::NeedsIntervention {
                        intervention,
                        denied: false,
                    },
                message,
                ..
            }) => match intervention {
                UserIntervention::Confirm {
                    requestor_text,
                    param,
                    effect,
                } => {
                    let text = super::messages::intervention_text(&requestor_text).unwrap_or(&message);
                    if !input
                        .bridge
                        .confirm(format!("{} — {}", file.name, tr("Confirmación necesaria")), text)
                    {
                        return Err(AfirmaError::cancelled());
                    }
                    match effect {
                        ConfirmEffect::SetParamTrue => {
                            extra.set(param, "true");
                        }
                        ConfirmEffect::RemovePolicyParams => {
                            for k in [
                                "policyIdentifier",
                                "policyIdentifierHash",
                                "policyIdentifierHashAlgorithm",
                                "policyDescription",
                                "policyQualifier",
                            ] {
                                extra.remove(k);
                            }
                        }
                    }
                }
                UserIntervention::Password { requestor_text, param } => {
                    let prompt = super::messages::intervention_text(&requestor_text)
                        .unwrap_or(&message)
                        .to_string();
                    match input.bridge.ask_password(&prompt) {
                        Some(pw) => {
                            extra.set(param, pw);
                        }
                        None => return Err(AfirmaError::cancelled()),
                    }
                }
            },
            other => return other,
        }
    }
    Err(AfirmaError::msg(tr("La operación necesita demasiadas confirmaciones")))
}

fn write_output(input: &SignJobInput, file: &FileItem, signed: &[u8]) -> Result<PathBuf, AfirmaError> {
    let signer = afirma_signers::signer_for_format(&file.format)
        .ok_or_else(|| AfirmaError::unsupported(tr("Formato no disponible")))?;
    let path = if input.files.len() > 1 {
        let dir = input
            .output_dir
            .clone()
            .or_else(|| file.path.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        afirma_signers::naming::output_path(signer.as_ref(), &file.path, &dir, input.overwrite)
    } else {
        let proposed = afirma_signers::naming::single_output_path(signer.as_ref(), &file.path);
        if proposed.exists() {
            let dir = proposed.parent().map(|p| p.to_path_buf()).unwrap_or_default();
            afirma_signers::naming::unique_path(&dir, &proposed.file_name().unwrap_or_default().to_string_lossy())
        } else {
            proposed
        }
    };
    match write_atomic(&path, signed) {
        Ok(p) => Ok(p),
        Err(e) => {
            // Si la carpeta del original no admite escritura, se guarda en Documentos.
            if let Some(docs) = directories::UserDirs::new().and_then(|u| u.document_dir().map(|d| d.to_path_buf()))
                && let Ok(p) = write_atomic(&docs.join(path.file_name().unwrap_or_default()), signed)
            {
                return Ok(p);
            }
            Err(AfirmaError::new(
                afirma_core::error::codes::CANT_SAVE_FILE,
                trf("No se ha podido guardar la firma: {0}", &[&e]),
            ))
        }
    }
}

/// Escribe en un fichero temporal y lo renombra (no deja ficheros a medias).
fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<PathBuf> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    Ok(path.to_path_buf())
}
