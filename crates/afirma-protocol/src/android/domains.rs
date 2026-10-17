//! Dominios de confianza de Autofirma App 1.9 (`secureDomainsList`,
//! `AndroidHttpManager.checkIsSecureDomain`, `TrustedDomainsActivity`;
//! `docs/spec/09-android.md` §2.9 y §5.10).
//!
//! «Dominio de confianza» = servidor al que se conecta **sin validar TLS** (la
//! misma semántica que los «dominios seguros» del escritorio, `01-protocol.md`
//! §12.6), pero la lista se guarda con **un dominio por línea** (`\n`).
//!
//! Reglas de coincidencia (se replican, §10 n.º 48): el *host* se pasa a
//! minúsculas; para cada entrada, el patrón es la entrada recortada, en
//! minúsculas y **sin ningún `*`**, y el tipo de comparación se decide con la
//! entrada **sin recortar**: `*x*` → el *host* contiene `x`; `*x` → termina en
//! `x`; `x*` → empieza por `x`; si no, igualdad exacta.
//!
//! Correcciones (documentadas): la ayuda de la pantalla dice que los dominios
//! se separan por comas, pero la app usa saltos de línea y una coma hacía
//! fallar la validación (§10 n.º 47); [`normalize_input`] acepta ambos
//! separadores y guarda siempre un dominio por línea, que es el formato que
//! lee la app original. Además, la decisión de no validar TLS se toma por
//! petición (Java cambiaba la configuración TLS global del proceso, sin
//! sincronizar, y las compilaciones de depuración nunca validaban TLS: §10
//! n.º 46); ver [`http_trust_overrides`].

use crate::triphase::data::java_trim;

/// Clave de la preferencia con la lista.
pub const PREF_SECURE_DOMAINS_LIST: &str = "secureDomainsList";
/// Clave de la preferencia «Validar conexiones SSL».
pub const PREF_VALIDATE_SSL_CHECKS: &str = "validateSslChecks";

/// Lista de dominios de confianza tal y como se guarda (`\n` entre entradas).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedDomains {
    entries: Vec<String>,
}

impl TrustedDomains {
    /// Interpreta el valor guardado. Como `String.split("\n")` de Java, se
    /// descartan las entradas vacías del final (las intermedias se conservan y
    /// solo coincidirían con un *host* vacío).
    pub fn parse(stored: &str) -> TrustedDomains {
        if stored.is_empty() {
            return TrustedDomains::default();
        }
        let mut entries: Vec<String> = stored.split('\n').map(str::to_string).collect();
        while entries.last().is_some_and(|e| e.is_empty()) {
            entries.pop();
        }
        TrustedDomains { entries }
    }

    /// Entradas sin recortar.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Indica si un *host* es de confianza.
    pub fn matches(&self, host: &str) -> bool {
        is_trusted_domain(host, &self.entries)
    }

    /// Entradas equivalentes para el cliente HTTP común
    /// ([`afirma_core::http::HttpSettings::secure_domains`], cuya comparación
    /// es la del escritorio: sin recortar ni pasar a minúsculas). El cliente
    /// común compara con el *host* ya normalizado en minúsculas, así que basta
    /// con normalizar cada patrón conservando los `*` de los extremos según la
    /// entrada sin recortar.
    pub fn to_secure_domains(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|e| {
                let pattern = java_trim(e).to_lowercase().replace('*', "");
                let pre = if e.starts_with('*') { "*" } else { "" };
                let post = if e.ends_with('*') { "*" } else { "" };
                format!("{pre}{pattern}{post}")
            })
            .collect()
    }
}

/// `checkIsSecureDomain` sobre una lista ya separada.
pub fn is_trusted_domain(host: &str, entries: &[String]) -> bool {
    let host = host.to_lowercase();
    entries.iter().any(|entry| {
        let pattern = java_trim(entry).to_lowercase().replace('*', "");
        let starts = entry.starts_with('*');
        let ends = entry.ends_with('*');
        if starts && ends {
            host.contains(&pattern)
        } else if starts {
            host.ends_with(&pattern)
        } else if ends {
            host.starts_with(&pattern)
        } else {
            host == pattern
        }
    })
}

/// Entrada con formato incorrecto (`DomainFormatException`): el diálogo de la
/// app muestra «AA200700 - El dominio "<entrada>" tiene un formato
/// incorrecto.».
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("El dominio \"{0}\" tiene un formato incorrecto.")]
pub struct DomainFormatError(pub String);

/// Código `AA` del error de formato.
pub const DOMAIN_FORMAT_ERROR_CODE: u32 = 200700;

/// Expresión de la pantalla: `^[a-z0-9*][a-z0-9-.:]{1,61}[a-z0-9*]$` sin
/// distinguir mayúsculas (3 a 63 caracteres).
pub fn is_valid_domain_entry(entry: &str) -> bool {
    let chars: Vec<char> = entry.chars().map(|c| c.to_ascii_lowercase()).collect();
    let n = chars.len();
    if !(3..=63).contains(&n) {
        return false;
    }
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '*';
    let inner = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | ':');
    edge(chars[0]) && edge(chars[n - 1]) && chars[1..n - 1].iter().all(|&c| inner(c))
}

/// Validación del botón «Guardar» (`checkCorrectDomainFormat`): recorta el
/// texto; si no está vacío valida cada línea no vacía (recortada) y devuelve
/// el texto que se guarda (vacío = borrar la preferencia).
///
/// Corrección: además de saltos de línea se aceptan comas como separador; el
/// texto guardado tiene siempre un dominio por línea (las líneas vacías
/// intermedias se eliminan).
pub fn normalize_input(text: &str) -> Result<String, DomainFormatError> {
    let trimmed = java_trim(text);
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let mut out = Vec::new();
    for entry in trimmed.split(['\n', ',']) {
        let e = java_trim(entry);
        if e.is_empty() {
            continue;
        }
        if !is_valid_domain_entry(e) {
            return Err(DomainFormatError(e.to_string()));
        }
        out.push(e.to_string());
    }
    Ok(out.join("\n"))
}

/// Configuración TLS del cliente HTTP para las preferencias de la app:
/// `validateSslChecks=false` desactiva la validación en todas las conexiones
/// ([`afirma_core::http::HttpSettings::disable_ssl_checks`]) y la lista de
/// dominios de confianza la desactiva solo para esos servidores
/// ([`afirma_core::http::HttpSettings::secure_domains`]). Se aplica por
/// petición en el cliente común (no globalmente, como hacía Java) y sin
/// excepciones para las compilaciones de depuración.
pub fn http_trust_overrides(validate_ssl_checks: bool, stored_domains: &str) -> (bool, Vec<String>) {
    (
        !validate_ssl_checks,
        TrustedDomains::parse(stored_domains).to_secure_domains(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(list: &str) -> TrustedDomains {
        TrustedDomains::parse(list)
    }

    #[test]
    fn spec_examples() {
        // §5.10.
        let l = d("*.redsara.es");
        assert!(l.matches("www.redsara.es"));
        assert!(!l.matches("redsara.es"));
        assert!(d("*redsara*").matches("pre.redsara.es"));
        assert!(d("sede.*").matches("sede.gob.es"));
        let l = d("a*b.es");
        assert!(l.matches("ab.es"));
        assert!(!l.matches("axb.es"));
    }

    #[test]
    fn untrimmed_decides_wildcards() {
        // Con espacio inicial ya no «empieza por *»: igualdad con ".redsara.es".
        let l = d(" *.redsara.es");
        assert!(!l.matches("www.redsara.es"));
        assert!(l.matches(".redsara.es"));
        // Con espacio final no «termina en *».
        assert!(!d("sede.* ").matches("sede.gob.es"));
        assert!(d("sede.* ").matches("sede."));
        // Retorno de carro (Windows): no termina en `*`, pero el patrón sí se recorta.
        assert!(d("*.a.es\r").matches("x.a.es"));
        // Mayúsculas en entrada y host.
        assert!(d("*.RedSara.ES").matches("WWW.redsara.es"));
        // `*` solo: cualquier host.
        assert!(d("*").matches("cualquiera.example"));
        // Varias líneas.
        let l = d("uno.es\n\n*.dos.es\n\n");
        assert_eq!(l.entries().len(), 3);
        assert!(l.matches("uno.es") && l.matches("a.dos.es") && !l.matches("tres.es"));
        assert!(!d("").matches(""));
    }

    #[test]
    fn conversion_for_core_client() {
        let l = d(" *.RedSara.es\nsede.*\n*mid*\nexacto.ES ");
        let conv = l.to_secure_domains();
        assert_eq!(conv, vec![".redsara.es", "sede.*", "*mid*", "exacto.es"]);
        for host in [
            "www.redsara.es",
            ".redsara.es",
            "sede.x",
            "amidb",
            "exacto.es",
            "otro.es",
        ] {
            assert_eq!(
                afirma_core::http::is_secure_domain(host, &conv),
                l.matches(host),
                "{host}"
            );
        }
        assert_eq!(http_trust_overrides(true, ""), (false, vec![]));
        assert_eq!(http_trust_overrides(false, "a.es\n").1, vec!["a.es"]);
    }

    #[test]
    fn screen_validation() {
        assert!(is_valid_domain_entry("*.redsara.es"));
        assert!(is_valid_domain_entry("SEDE.GOB.ES"));
        assert!(is_valid_domain_entry("host:8443"));
        assert!(!is_valid_domain_entry("ab"));
        assert!(!is_valid_domain_entry("a*b.es"));
        assert!(!is_valid_domain_entry("-a.es"));
        assert!(!is_valid_domain_entry(&"a".repeat(64)));
        assert_eq!(normalize_input("  \n "), Ok(String::new()));
        assert_eq!(normalize_input(" a.es \n\n *.b.es "), Ok("a.es\n*.b.es".into()));
        // Corrección: comas como en la ayuda.
        assert_eq!(normalize_input("a.es, *.b.es"), Ok("a.es\n*.b.es".into()));
        let e = normalize_input("a.es\nmal dominio").unwrap_err();
        assert_eq!(e.to_string(), "El dominio \"mal dominio\" tiene un formato incorrecto.");
    }
}
