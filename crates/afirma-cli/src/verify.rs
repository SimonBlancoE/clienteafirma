//! `verify` sin interfaz (`verifyByCommandLine`, §5.9.3): una línea por
//! resultado de validación (`SignValidity.toString()`), estado 0 sea cual
//! sea el resultado y sin XML.

use afirma_core::ExtraParams;
use afirma_core::validity::{SignValidity, ValidityError};
use afirma_signers::validate::{ValidatorKind, validator_for};

use crate::error::{CliError, java_io_message};
use crate::messages::Messages;
use crate::params::Params;

/// `verifyByCommandLine`.
pub fn verify_by_command_line(p: &Params, m: &Messages) -> Result<String, CliError> {
    let Some(input) = p.input.as_deref() else {
        return Err(CliError::syntax_plain(m.get(5)));
    };
    // Java envuelve el error de lectura y acaba imprimiendo el de la causa
    // (`<ruta> (<motivo>)`).
    let data = std::fs::read(input).map_err(|e| CliError::plain(java_io_message(input, &e)))?;
    let list = validate(&data);
    let mut out = String::new();
    for v in &list {
        out.push_str(&m.validity_text(v));
        out.push('\n');
    }
    Ok(out)
}

/// Validación como `verifyByCommandLine`: con validador, su resultado; un
/// ODF u OOXML (sin validador en AutoFirma) da "validación incompleta" solo
/// si está firmado y, si no, "formato no reconocido", como en Java.
pub fn validate(data: &[u8]) -> Vec<SignValidity> {
    let office = match validator_for(data) {
        ValidatorKind::Ooxml => Some("ooxml"),
        ValidatorKind::Odf => Some("odf"),
        _ => None,
    };
    if let Some(name) = office {
        let signed =
            afirma_xml::signer_for(name).is_some_and(|s| s.is_sign(data, &ExtraParams::new()));
        if !signed {
            return vec![SignValidity::ko(ValidityError::UnknownSignatureFormat)];
        }
    }
    afirma_signers::validate(data, &ExtraParams::new())
}
