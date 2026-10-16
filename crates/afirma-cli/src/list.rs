//! `listaliases` (`listAliasesByCommandLine`, §5.9.5): todos los alias del
//! almacén, sin filtrar, uno por línea o en XML (`<result>ok</result>`).

use crate::CliEnv;
use crate::error::CliError;
use crate::messages::Messages;
use crate::params::Params;
use crate::response::xml_aliases;
use crate::store;

/// `listAliasesByCommandLine`.
pub fn list_aliases(p: &Params, env: &CliEnv, m: &Messages) -> Result<String, CliError> {
    let store = store::open(p.store.as_deref(), p.password.as_deref(), env, m)?;
    let aliases: Vec<String> = store
        .entries()
        .map_err(|e| store::keystore_error(&e, m))?
        .into_iter()
        .map(|e| e.alias)
        .collect();
    if p.xml {
        return Ok(xml_aliases(&aliases));
    }
    let mut out = String::new();
    for a in aliases {
        out.push_str(&a);
        out.push('\n');
    }
    Ok(out)
}
