//! `batchsign` (`batchByCommandLine`, §5.9.6): lote trifásico contra los
//! servicios de prefirma y postfirma de un servidor.
//!
//! Diferencias con Java (`docs/deviations/afirma-cli.md`):
//! - Java descarta la respuesta: no imprime nada y termina con estado 0
//!   incluso si falla el almacén, la lectura, la red o el servidor. Aquí se
//!   imprime el mensaje de éxito (o el error) con el estado correspondiente.
//! - Con `-xml` y sin `-o` Java falla (`Error no reconocido: null`); aquí el
//!   resultado del lote se devuelve en `<sign>` (Base64), como pretendía el
//!   código.
//! - Además del lote XML (`BatchSigner.signXML`), se admiten lotes JSON
//!   (`BatchSigner.signJSON`, los que ofrece el servidor trifásico actual)
//!   cuando el fichero empieza por `{`.

use afirma_protocol::HttpClient;
use afirma_protocol::batch::{BatchError, sign_json_batch, sign_xml_batch};

use crate::CliEnv;
use crate::config::parse_config;
use crate::error::{CliError, java_io_message};
use crate::messages::Messages;
use crate::params::Params;
use crate::response::xml_response;
use crate::sign::config_error;
use crate::store;

/// `batchByCommandLine`.
pub fn batch_by_command_line(p: &Params, env: &CliEnv, m: &Messages) -> Result<String, CliError> {
    let Some(input) = p.input.as_deref() else {
        return Err(CliError::syntax_plain(m.get(5)));
    };
    if p.alias.is_none() && p.filter.is_none() {
        return Err(CliError::syntax_plain(m.get(17)));
    }
    if p.output.is_none() && !p.xml {
        return Err(CliError::syntax_plain(m.get(19)));
    }
    let (Some(pre_url), Some(post_url)) = (p.pre_url.as_deref(), p.post_url.as_deref()) else {
        return Err(CliError::syntax_plain(m.get(60)));
    };

    // Errores que Java devolvía como texto (y descartaba): en XML si se pidió.
    let fail = |msg: String| -> CliError { CliError::plain(msg) };

    let store = store::open(p.store.as_deref(), p.password.as_deref(), env, m)?;
    let alias = match p.filter.as_deref() {
        Some(f) => store::filter_alias(store.as_ref(), f, m)?,
        None => p.alias.clone().unwrap_or_default(),
    };
    if store.entry(&alias).is_err() {
        return Err(CliError::plain(m.fmt(61, &[&alias])));
    }
    // Cada PKCS#1 se verifica con el certificado (`AOPkcs1Signer`).
    let key = afirma_keystores::VerifyingKey::new(store.signing_key(&alias).map_err(|e| fail(e.to_string()))?);

    let raw = std::fs::read(input).map_err(|e| fail(java_io_message(input, &e)))?;
    let batch = if afirma_core::base64::is_base64_bytes(&raw) {
        afirma_core::base64::decode_bytes(&raw, false).map_err(|e| fail(e.to_string()))?
    } else {
        raw
    };
    let config = parse_config(p.config.as_deref()).map_err(|e| config_error(&e.0))?;
    let http = env.http.clone().unwrap_or_else(HttpClient::installed);
    let result = if is_json(&batch) {
        sign_json_batch(&http, &batch, pre_url, post_url, &key, &config)
    } else {
        sign_xml_batch(&http, &batch, pre_url, post_url, &key, &config)
    }
    .map_err(|e| fail(batch_error_message(&e)))?;

    if let Some(out) = p.output.as_deref() {
        std::fs::write(out, result.as_bytes()).map_err(|e| fail(java_io_message(out, &e)))?;
    }
    let ok = m.get(22);
    Ok(if p.xml {
        if p.output.is_some() {
            xml_response(true, Some(&ok), None)
        } else {
            xml_response(true, Some(&ok), Some(result.as_bytes()))
        }
    } else {
        ok
    })
}

/// Indica si el lote es JSON (empieza por `{` tras espacios y BOM).
fn is_json(batch: &[u8]) -> bool {
    let b = batch.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(batch);
    b.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'{')
}

/// `e.getMessage()` de la excepción del lote.
fn batch_error_message(e: &BatchError) -> String {
    match e {
        BatchError::Afirma(a) => a.message.clone(),
        BatchError::Internal(s) | BatchError::InvalidArgument(s) => s.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deteccion_json() {
        assert!(is_json(b"  {\"algorithm\":\"SHA256withRSA\"}"));
        assert!(is_json(b"\xEF\xBB\xBF{}"));
        assert!(!is_json(b"<?xml version=\"1.0\"?><signbatch/>"));
        assert!(!is_json(b""));
    }
}
