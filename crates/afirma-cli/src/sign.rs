//! `sign`, `cosign` y `countersign` sin interfaz (`signByCommandLine` +
//! `sign`, §5.9.1) y la petición de interfaz de `sign -gui` (§5.9.2).

use std::path::Path;
use std::sync::Arc;

use afirma_core::algorithms::{compose_signature_algorithm_name, java_digest_algorithm_name};
use afirma_core::error::codes;
use afirma_core::formats::SignerKind;
use afirma_core::mime::MimeHelper;
use afirma_core::{AfirmaError, CounterSignTarget, ExtraParams, Signer, SigningKey};
use afirma_keystores::{KeyStore, KeyStoreError, VerifyingKey};

use crate::config::{parse_config, parse_config_lenient, remove_visible_signature_lines};
use crate::error::{CliError, absolute_path, java_io_message};
use crate::messages::Messages;
use crate::params::{Command, FORMAT_AUTO, Params};
use crate::response::xml_response;
use crate::{CliEnv, GuiOperation, GuiRequest, SignGuiRequest, store};

/// Firmador de un formato de `-format` (`getSigner`). PAdES se crea sin modo
/// seguro (`setSecureMode(false)`), como en la línea de comandos de Java,
/// para que `-config` pueda referirse a ficheros locales.
pub fn signer_for_cli_format(format: &str) -> Option<Box<dyn Signer>> {
    let kind = match format {
        "cades" => SignerKind::Cades,
        "xades" => SignerKind::Xades,
        "pades" => {
            return Some(Box::new(afirma_pdf::PadesSigner::new().with_secure_mode(false)));
        }
        "facturae" => SignerKind::FacturaE,
        "ooxml" => SignerKind::Ooxml,
        "odf" => SignerKind::Odf,
        _ => return None,
    };
    // El registro aún puede no tener ODF y OOXML: se recurre a afirma-xml.
    afirma_signers::signer(kind).or_else(|| match kind {
        SignerKind::Ooxml | SignerKind::Odf => afirma_xml::signer_for(format),
        _ => None,
    })
}

/// `selectFormatByData`: PDF → `pades`, XML → `xades`, cualquier otra cosa →
/// `cades` (OOXML, ODF y FacturaE no se eligen nunca automáticamente).
pub fn select_format_by_data(data: &[u8]) -> Result<&'static str, String> {
    let ext = MimeHelper::new(data).extension().map_err(|e| e.to_string())?;
    Ok(match ext.as_deref() {
        Some("pdf") => "pades",
        Some("xml") => "xades",
        _ => "cades",
    })
}

/// `signByCommandLine`.
pub fn sign_by_command_line(command: Command, p: &Params, env: &CliEnv, m: &Messages) -> Result<String, CliError> {
    let Some(input) = p.input.as_deref() else {
        return Err(CliError::syntax_plain(m.get(5)));
    };
    if p.alias.is_none() && p.filter.is_none() && !p.certgui {
        return Err(CliError::syntax_plain(m.get(17)));
    }
    if p.output.is_none() && !p.xml {
        return Err(CliError::syntax_plain(m.get(19)));
    }

    let store = store::open(p.store.as_deref(), p.password.as_deref(), env, m)?;
    let (store, alias) = if p.certgui {
        let config = parse_config(p.config.as_deref()).map_err(|e| config_error(&e.0))?;
        store::choose_with_gui(store, &config, p.filter.as_deref(), env)?
    } else if let Some(filter) = p.filter.as_deref() {
        let alias = store::filter_alias(store.as_ref(), filter, m)?;
        (store, alias)
    } else {
        let alias = p.alias.clone().unwrap_or_default();
        (store, alias)
    };

    let signature = sign(
        command,
        p.format(),
        p.algorithm(),
        p.config.as_deref(),
        input,
        &alias,
        &store,
        m,
    )?;

    if let Some(out) = p.output.as_deref() {
        std::fs::write(out, &signature).map_err(|e| CliError::plain(java_io_message(out, &e)))?;
    }
    let ok = m.get(22);
    Ok(if p.xml {
        if p.output.is_some() {
            xml_response(true, Some(&ok), None)
        } else {
            xml_response(true, Some(&ok), Some(&signature))
        }
    } else {
        ok
    })
}

/// Mensaje de una línea de `-config` mal formada.
pub fn config_error(line: &str) -> CliError {
    CliError::plain(format!(
        "La configuracion indicada no tiene el formato clave=valor: {line}"
    ))
}

/// Mensaje de un error de firma como `e.getMessage()` de Java.
fn signer_message(e: &AfirmaError) -> String {
    e.message.clone()
}

/// Indica si el error es de posición o página de firma visible no válida
/// (`InvalidSignaturePositionException`/`IncorrectPageException`).
fn is_visible_position_error(e: &AfirmaError) -> bool {
    matches!(e.code, Some(c) if c == codes::INVALID_SIGNATURE_POSITION || c == codes::INVALID_SIGNATURE_PAGE)
}

/// Clave privada de una entrada (`ksm.getKeyEntry(alias)`). Cada firma
/// PKCS#1 se verifica con el certificado, como hace `AOPkcs1Signer` en Java
/// (detecta tarjetas o controladores que firman mal).
pub(crate) fn key_entry(store: &Arc<dyn KeyStore>, alias: &str, m: &Messages) -> Result<Box<dyn SigningKey>, CliError> {
    match store.entry(alias) {
        Err(KeyStoreError::AliasNotFound(_)) => return Err(CliError::plain(m.fmt(148, &[alias]))),
        Err(e) => return Err(CliError::plain(e.to_string())),
        Ok(_) => {}
    }
    let key = store.signing_key(alias).map_err(|e| match e {
        KeyStoreError::AliasNotFound(_) => CliError::plain(m.fmt(148, &[alias])),
        // `.147` con causa: Java imprime el mensaje de la causa.
        other => CliError::plain(other.to_string()),
    })?;
    Ok(Box::new(VerifyingKey::new(key)))
}

/// `sign(...)`: lee la entrada, elige formato y firmador, compone el
/// algoritmo y ejecuta la operación (con el reintento sin firma visible).
#[allow(clippy::too_many_arguments)]
fn sign(
    command: Command,
    format: &str,
    algorithm: &str,
    config: Option<&str>,
    input: &Path,
    alias: &str,
    store: &Arc<dyn KeyStore>,
    m: &Messages,
) -> Result<Vec<u8>, CliError> {
    let key = key_entry(store, alias, m)?;
    let data = std::fs::read(input).map_err(|_| {
        CliError::plain(format!(
            "No se ha podido leer el fichero de entrada: {}",
            absolute_path(input).display()
        ))
    })?;
    let format = if format == FORMAT_AUTO {
        select_format_by_data(&data).map_err(CliError::plain)?
    } else {
        format
    };
    let Some(signer) = signer_for_cli_format(format) else {
        return Err(CliError::syntax_plain(m.fmt(4, &[format])));
    };
    let key_type = key.key_algorithm().java_key_type();
    let signature_algorithm = compose_signature_algorithm_name(Some(algorithm), Some(key_type))
        .map_err(|_| CliError::syntax_plain(m.fmt(141, &[key_type])))?;

    let mut config = config.map(str::to_string);
    let mut retried = false;
    loop {
        let xp = parse_config(config.as_deref()).map_err(|e| config_error(&e.0))?;
        match run_operation(command, signer.as_ref(), &data, &signature_algorithm, key.as_ref(), &xp) {
            Ok(sig) => return Ok(sig),
            Err(e) if is_visible_position_error(&e) && !retried => {
                // Se vuelve a firmar de forma invisible.
                tracing::info!("Posicion de firma visible no valida; se firma de forma invisible: {e}");
                config = remove_visible_signature_lines(config.as_deref());
                retried = true;
            }
            // `.149` con causa: Java imprime el mensaje de la causa.
            Err(e) if e.message.is_empty() => {
                return Err(CliError::Command {
                    message: None,
                    using_gui: false,
                });
            }
            Err(e) => return Err(CliError::plain(signer_message(&e))),
        }
    }
}

fn run_operation(
    command: Command,
    signer: &dyn Signer,
    data: &[u8],
    algorithm: &str,
    key: &dyn SigningKey,
    xp: &ExtraParams,
) -> Result<Vec<u8>, AfirmaError> {
    match command {
        Command::Cosign => signer.cosign(None, data, algorithm, key, xp),
        Command::Countersign => {
            let target = match xp.get("target") {
                Some(t) if t.eq_ignore_ascii_case("tree") => CounterSignTarget::Tree,
                _ => CounterSignTarget::Leafs,
            };
            signer.countersign(data, algorithm, &target, key, xp)
        }
        _ => signer.sign(data, algorithm, key, xp),
    }
}

/// `sign -gui` (`signByGui` + `loadSignConfig`).
///
/// Diferencia con Java: si se indica un formato distinto de `auto` se usa
/// ese formato (Java tenía la condición invertida: ignoraba el formato
/// pedido y elegía uno por el contenido).
pub fn sign_gui_request(command: Command, p: &Params, m: &Messages) -> Result<GuiRequest, CliError> {
    let Some(file) = p.input.clone() else {
        return Err(CliError::command(m.get(5), true));
    };
    let operation = match command {
        Command::Cosign => GuiOperation::Cosign,
        Command::Countersign => GuiOperation::CountersignLeafs,
        _ => GuiOperation::Sign,
    };
    let format = match p.format() {
        FORMAT_AUTO => None,
        f => Some(canonical_format(f).to_string()),
    };
    Ok(GuiRequest::Sign(SignGuiRequest {
        file,
        operation,
        format,
        extra_params: parse_config_lenient(p.config.as_deref()),
        digest_algorithm: java_digest_algorithm_name(p.algorithm()),
        algorithm_explicit: p.algorithm.is_some(),
    }))
}

/// Nombre de formato de AutoFirma para un valor de `-format`.
pub fn canonical_format(format: &str) -> &'static str {
    use afirma_core::constants as C;
    match format {
        "cades" => C::SIGN_FORMAT_CADES,
        "xades" => C::SIGN_FORMAT_XADES,
        "pades" => C::SIGN_FORMAT_PADES,
        "facturae" => C::SIGN_FORMAT_FACTURAE,
        "ooxml" => C::SIGN_FORMAT_OOXML,
        "odf" => C::SIGN_FORMAT_ODF,
        _ => C::SIGN_FORMAT_AUTO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formato_por_contenido() {
        assert_eq!(
            select_format_by_data(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\n"),
            Ok("pades")
        );
        assert_eq!(select_format_by_data(b"<?xml version=\"1.0\"?><a/>"), Ok("xades"));
        assert_eq!(select_format_by_data(b"hola"), Ok("cades"));
    }

    #[test]
    fn firmadores() {
        for f in ["cades", "xades", "pades", "facturae", "ooxml", "odf"] {
            assert!(signer_for_cli_format(f).is_some(), "{f}");
        }
        assert!(signer_for_cli_format("auto").is_none());
        assert_eq!(signer_for_cli_format("pades").unwrap().format_name(), "PAdES");
        for f in ["ooxml", "odf"] {
            let canonical = canonical_format(f);
            assert!(afirma_core::formats::find_format(canonical).is_some(), "{canonical}");
        }
    }
}
