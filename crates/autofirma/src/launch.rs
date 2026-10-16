//! Clasificación de los argumentos de arranque (`SimpleAfirma.main`).

use std::path::PathBuf;

/// Cómo arrancar la aplicación (se crea una vez; el tamaño no importa).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Launch {
    /// Interfaz gráfica de escritorio.
    Gui(GuiStart),
    /// Invocación desde la web (`afirma://...`).
    Protocol(String),
    /// Línea de comandos.
    Cli(Vec<String>),
}

/// Estado inicial de la interfaz gráfica.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuiStart {
    /// Ficheros a cargar en la página de firma.
    pub sign_files: Vec<PathBuf>,
    /// Fichero de firma a verificar.
    pub verify_file: Option<PathBuf>,
    /// URL `afirma://` (modo protocolo, ventana compacta).
    pub protocol_url: Option<String>,
    /// Opciones de `sign|cosign|countersign -gui` (formato, `-config`...).
    pub cli_sign: Option<CliSign>,
    /// `createdigest`/`checkdigest -gui`.
    pub hash: Option<afirma_hash::cli::GuiRequest>,
}

/// Opciones de firma de la línea de comandos para la interfaz.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliSign {
    /// Formato pedido (`None`: el que elija la aplicación).
    pub format: Option<String>,
    pub cosign: bool,
    pub countersign: bool,
    /// Parámetros de `-config`, que se aplican sobre los de las preferencias.
    pub extra: afirma_core::ExtraParams,
    /// Algoritmo de huella (`SHA512`...) si se indicó `-algorithm`.
    pub algorithm: Option<String>,
}

impl GuiStart {
    /// Arranque sin nada que abrir (en macOS, la URL o los ficheros pueden
    /// llegar después como eventos del sistema).
    pub fn is_empty(&self) -> bool {
        self.sign_files.is_empty() && self.verify_file.is_none() && self.protocol_url.is_none() && self.hash.is_none()
    }
}

/// Clasifica los argumentos (sin el nombre del programa).
///
/// - Sin argumentos: interfaz gráfica.
/// - `afirma://...` (sin distinguir mayúsculas): protocolo.
/// - `sign|cosign|countersign|verify ... -gui` y demás órdenes: línea de
///   comandos, que puede pedir abrir la interfaz (menú contextual de Windows).
/// - Una o varias rutas de ficheros existentes: interfaz con esos ficheros
///   (mejora: asociación de ficheros y "Abrir con" en Linux y macOS).
/// - Cualquier otra cosa: línea de comandos.
pub fn classify(args: &[String]) -> Launch {
    let Some(first) = args.first() else {
        return Launch::Gui(GuiStart::default());
    };
    if first.to_lowercase().starts_with("afirma://") {
        return Launch::Protocol(first.clone());
    }
    // macOS añade -psn_X_Y al abrir desde el Finder.
    if first.starts_with("-psn_") {
        return Launch::Gui(GuiStart::default());
    }
    let paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
    if !first.starts_with('-') && paths.iter().all(|p| p.exists()) {
        return Launch::Gui(GuiStart {
            sign_files: paths,
            ..Default::default()
        });
    }
    Launch::Cli(args.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn classification() {
        assert_eq!(classify(&[]), Launch::Gui(GuiStart::default()));
        assert_eq!(
            classify(&s(&["AFIRMA://websocket?v=4"])),
            Launch::Protocol("AFIRMA://websocket?v=4".into())
        );
        assert_eq!(
            classify(&s(&["sign", "-gui", "-i", "/tmp/x.pdf"])),
            Launch::Cli(s(&["sign", "-gui", "-i", "/tmp/x.pdf"]))
        );
        assert_eq!(classify(&s(&["sign", "-i", "a"])), Launch::Cli(s(&["sign", "-i", "a"])));
        assert_eq!(classify(&s(&["-help"])), Launch::Cli(s(&["-help"])));
        assert_eq!(classify(&s(&["-psn_0_123"])), Launch::Gui(GuiStart::default()));
    }
}
