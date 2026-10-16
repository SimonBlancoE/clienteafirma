//! Clasificación de los argumentos de arranque (`SimpleAfirma.main`).

use std::path::PathBuf;

/// Cómo arrancar la aplicación.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// Clasifica los argumentos (sin el nombre del programa).
///
/// - Sin argumentos: interfaz gráfica.
/// - `afirma://...` (sin distinguir mayúsculas): protocolo.
/// - `sign|cosign|countersign ... -gui -i <fichero>`: interfaz con el fichero
///   cargado (lo que usa el menú contextual de Windows).
/// - `verify -gui -i <fichero>`: verificación en la interfaz.
/// - Una o varias rutas de ficheros existentes: interfaz con esos ficheros
///   (mejora: asociación de ficheros y "Abrir con" en Linux y macOS).
/// - Cualquier otra cosa: línea de comandos.
pub fn classify(args: &[String]) -> Launch {
    let Some(first) = args.first() else { return Launch::Gui(GuiStart::default()) };
    if first.to_lowercase().starts_with("afirma://") {
        return Launch::Protocol(first.clone());
    }
    // macOS añade -psn_X_Y al abrir desde el Finder.
    if first.starts_with("-psn_") {
        return Launch::Gui(GuiStart::default());
    }
    let cmd = first.to_lowercase();
    let has_gui = args.iter().skip(1).any(|a| a == "-gui");
    let input = args.windows(2).find(|w| w[0] == "-i").map(|w| PathBuf::from(&w[1]));
    if has_gui {
        match cmd.as_str() {
            "sign" | "cosign" | "countersign" => {
                return Launch::Gui(GuiStart { sign_files: input.into_iter().collect(), ..Default::default() });
            }
            "verify" => return Launch::Gui(GuiStart { verify_file: input, ..Default::default() }),
            _ => {}
        }
    }
    let paths: Vec<PathBuf> = args.iter().map(PathBuf::from).collect();
    if !first.starts_with('-') && paths.iter().all(|p| p.exists()) {
        return Launch::Gui(GuiStart { sign_files: paths, ..Default::default() });
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
        assert_eq!(classify(&s(&["AFIRMA://websocket?v=4"])), Launch::Protocol("AFIRMA://websocket?v=4".into()));
        assert_eq!(
            classify(&s(&["sign", "-gui", "-i", "/tmp/x.pdf"])),
            Launch::Gui(GuiStart { sign_files: vec!["/tmp/x.pdf".into()], ..Default::default() })
        );
        assert_eq!(
            classify(&s(&["verify", "-gui", "-i", "a.csig"])),
            Launch::Gui(GuiStart { verify_file: Some("a.csig".into()), ..Default::default() })
        );
        assert_eq!(classify(&s(&["sign", "-i", "a"])), Launch::Cli(s(&["sign", "-i", "a"])));
        assert_eq!(classify(&s(&["-help"])), Launch::Cli(s(&["-help"])));
        assert_eq!(classify(&s(&["-psn_0_123"])), Launch::Gui(GuiStart::default()));
    }
}
