//! Opción `-config`: texto con los parámetros adicionales de la operación
//! (§5.7).
//!
//! Java tiene dos analizadores: el de la firma sin interfaz
//! (`buildProperties`, que separa por la secuencia literal `\n` y no
//! recorta las claves salvo en la última línea; una línea sin `=` produce
//! `StringIndexOutOfBoundsException`) y el de `sign -gui` (que separa por
//! saltos de línea reales y descarta las líneas sin `=`). Aquí se usa un
//! único analizador con la recomendación de la especificación: se admiten
//! ambos separadores, se recortan claves y valores, se ignoran las líneas
//! vacías y las que empiezan por `#`, y una línea sin `=` es un error claro
//! (modo estricto) o se descarta (modo de la interfaz).

use afirma_core::ExtraParams;

/// Línea de `-config` sin el formato `clave=valor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLineError(pub String);

/// Líneas de `-config`: separadas por `\n` literal o por saltos de línea.
pub fn config_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split("\\n")
        .flat_map(|p| p.split('\n'))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Analiza `-config` (firma sin interfaz y `batchsign`).
pub fn parse_config(text: Option<&str>) -> Result<ExtraParams, ConfigLineError> {
    let mut xp = ExtraParams::new();
    let Some(text) = text else { return Ok(xp) };
    for line in config_lines(text) {
        match line.find('=') {
            Some(eq) if eq > 0 => {
                xp.set(line[..eq].trim(), line[eq + 1..].trim());
            }
            _ => return Err(ConfigLineError(line.to_string())),
        }
    }
    Ok(xp)
}

/// Analiza `-config` como `sign -gui` (`loadSignConfig`): las líneas sin
/// `=` en una posición mayor que 0 se descartan.
pub fn parse_config_lenient(text: Option<&str>) -> ExtraParams {
    let mut xp = ExtraParams::new();
    for line in text.into_iter().flat_map(config_lines) {
        if let Some(eq) = line.find('=').filter(|&eq| eq > 0) {
            xp.set(line[..eq].trim(), line[eq + 1..].trim());
        }
    }
    xp
}

/// Claves de la firma visible de PDF que se eliminan al reintentar una
/// firma con una posición o página no válidas (`removeSignaturePageProperties`;
/// Java compara con `indexOf`, así que cualquier línea que contenga el
/// nombre se elimina).
pub const VISIBLE_SIGNATURE_KEYS: [&str; 6] = [
    "signaturePage",
    "signaturePages",
    "signaturePositionOnPageLowerLeftX",
    "signaturePositionOnPageLowerLeftY",
    "signaturePositionOnPageUpperRightX",
    "signaturePositionOnPageUpperRightY",
];

/// `-config` sin las líneas de la firma visible (las demás se conservan;
/// Java perdía la primera por concatenarla a `null`).
pub fn remove_visible_signature_lines(text: Option<&str>) -> Option<String> {
    let text = text?;
    let kept: Vec<&str> = config_lines(text)
        .filter(|l| !VISIBLE_SIGNATURE_KEYS.iter().any(|k| l.contains(k)))
        .collect();
    Some(kept.join("\\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separadores_y_recorte() {
        let xp = parse_config(Some("  format=XAdES Enveloping\\nsignerClaimedRoles = Director \n#comentario\\n\\n xadesNamespace=http://uri.etsi.org/01903/v1.4.1#  ")).unwrap();
        assert_eq!(xp.get("format"), Some("XAdES Enveloping"));
        assert_eq!(xp.get("signerClaimedRoles"), Some("Director"));
        assert_eq!(
            xp.get("xadesNamespace"),
            Some("http://uri.etsi.org/01903/v1.4.1#")
        );
        assert_eq!(xp.len(), 3);
        // El valor puede contener '='.
        assert_eq!(parse_config(Some("a=b=c")).unwrap().get("a"), Some("b=c"));
        assert_eq!(parse_config(Some("a=")).unwrap().get("a"), Some(""));
        assert!(parse_config(None).unwrap().is_empty());
    }

    #[test]
    fn lineas_sin_igual() {
        assert_eq!(
            parse_config(Some("a=1\\nfoo")),
            Err(ConfigLineError("foo".into()))
        );
        assert_eq!(parse_config(Some("=x")), Err(ConfigLineError("=x".into())));
        let xp = parse_config_lenient(Some("a=1\nfoo\n=x\nb = 2"));
        assert_eq!(xp.get("a"), Some("1"));
        assert_eq!(xp.get("b"), Some("2"));
        assert_eq!(xp.len(), 2);
    }

    #[test]
    fn firma_visible() {
        let cfg = "layer2Text=Hola\\nsignaturePage=99\\nsignaturePositionOnPageLowerLeftX=10\\nsignaturePositionOnPageLowerLeftY=10\\nsignaturePositionOnPageUpperRightX=100\\nsignaturePositionOnPageUpperRightY=100\\nsignatureRenderingMode=1";
        let kept = remove_visible_signature_lines(Some(cfg)).unwrap();
        assert_eq!(kept, "layer2Text=Hola\\nsignatureRenderingMode=1");
        assert_eq!(remove_visible_signature_lines(None), None);
    }
}
