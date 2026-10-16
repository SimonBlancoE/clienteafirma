//! Comandos `createdigest` y `checkdigest` de la línea de comandos (§7.5.10,
//! `HashParameters`, `CreateHashCommand`, `CheckHashCommand`).
//!
//! La aplicación solo tiene que delegar: [`dispatch`] (o [`run`]) analiza los
//! argumentos, ejecuta la operación y devuelve el texto a imprimir y el estado
//! de salida tal como lo hace `CommandLineLauncher` con el plugin de Java
//! (mensajes en español, prefijo `Error no reconocido: ` para los errores de
//! parámetros y respuesta XML de error con `-xml`). Con `-gui` se devuelve una
//! [`GuiRequest`] para que la aplicación muestre los diálogos.

use std::fs;
use std::path::{Path, PathBuf};

use crate::algorithm::parse_algorithm;
use crate::dir::{HashOptions, check_directory, hash_directory};
use crate::document::{DirDocumentFormat, DocumentError, HashDocument};
use crate::messages::{format, get};
use crate::single::{FileHashFormat, check_file_hash_file, encode_file_hash, hash_file};

/// Estado de salida correcto.
pub const STATUS_SUCCESS: i32 = 0;
/// Estado de salida de error (`-1`, que el sistema ve como 255 en POSIX).
pub const STATUS_ERROR: i32 = -1;
/// Estado de salida cuando las huellas no coinciden (solo sin paridad con Java,
/// que devuelve 0).
pub const STATUS_MISMATCH: i32 = 1;

/// Algoritmo por defecto de `-halgorithm`.
pub const DEFAULT_HASH_ALGORITHM: &str = "SHA-256";

/// Comando de huellas digitales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashCommand {
    /// `createdigest`: cálculo de huellas.
    CreateDigest,
    /// `checkdigest`: comprobación de huellas.
    CheckDigest,
}

impl HashCommand {
    /// Comandos en el orden en que se listan en la ayuda general.
    pub const ALL: [HashCommand; 2] = [Self::CreateDigest, Self::CheckDigest];

    /// Nombre del comando.
    pub fn op(self) -> &'static str {
        match self {
            Self::CreateDigest => "createdigest",
            Self::CheckDigest => "checkdigest",
        }
    }

    /// Comando correspondiente a un nombre (el lanzador lo pasa a minúsculas).
    pub fn parse(op: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.op().eq_ignore_ascii_case(op))
    }

    /// Descripción que muestra la ayuda general del lanzador (`plugin.json`;
    /// en Java sale con caracteres de sustitución por un error de codificación).
    pub fn description(self) -> &'static str {
        match self {
            Self::CreateDigest => "Creación de huellas digitales con interfaz gráfica",
            Self::CheckDigest => "Comprobación de huellas digitales con interfaz gráfica",
        }
    }

    fn main_file_needed(self) -> bool {
        self == Self::CreateDigest
    }

    /// Texto de ayuda del comando (`HashParameters.buildSyntaxError(cmd, null)`).
    pub fn help_text(self) -> String {
        syntax_text(self, None)
    }
}

/// Tipo de error de la línea de comandos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliErrorKind {
    /// Parámetros incorrectos (`IllegalArgumentException`): el lanzador lo
    /// imprime con el prefijo `Error no reconocido: `.
    IllegalArgument,
    /// Error controlado de la operación (`PluginControlledException`): se
    /// imprime el mensaje tal cual.
    Controlled,
}

/// Error de un comando de huellas.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    /// Tipo de error.
    pub kind: CliErrorKind,
    /// Mensaje (en español, como el plugin de Java).
    pub message: String,
}

impl CliError {
    fn illegal(message: String) -> Self {
        Self {
            kind: CliErrorKind::IllegalArgument,
            message,
        }
    }

    fn controlled(message: String) -> Self {
        Self {
            kind: CliErrorKind::Controlled,
            message,
        }
    }

    /// Mensaje tal como lo imprime el lanzador (locale es_ES).
    pub fn launcher_message(&self) -> String {
        match self.kind {
            CliErrorKind::IllegalArgument => format!("Error no reconocido: {}", self.message),
            CliErrorKind::Controlled => self.message.clone(),
        }
    }
}

/// Parámetros de los comandos (`HashParameters`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashParameters {
    /// Fichero o directorio principal (primer argumento).
    pub main_file: Option<PathBuf>,
    /// `-i`: fichero de huellas a comprobar.
    pub input_file: Option<PathBuf>,
    /// `-o`: fichero de salida (huella o informe).
    pub output_file: Option<PathBuf>,
    /// `-hformat` (en minúsculas).
    pub hash_format: Option<String>,
    /// `-halgorithm` tal como se indicó.
    pub hash_algorithm: Option<String>,
    /// `-xml` (solo afecta al formato de los errores).
    pub xml: bool,
    /// `-gui`.
    pub gui: bool,
    /// `-r`.
    pub recursive: bool,
    /// `-d` (oculto): con `-gui` y sin fichero principal, pedir un directorio.
    pub directory: bool,
}

impl HashParameters {
    /// Analiza los argumentos (sin el nombre del comando) como el constructor
    /// de `HashParameters`. Las opciones distinguen mayúsculas.
    pub fn parse(command: HashCommand, args: &[String]) -> Result<Self, CliError> {
        let mut p = Self::default();
        let mut i = 0;
        if command.main_file_needed() {
            let first = args
                .first()
                .ok_or_else(|| CliError::illegal(get("CommandLine.120").into()))?;
            p.main_file = Some(read_main_file(first)?);
            i = 1;
        }
        while i < args.len() {
            let arg = args[i].as_str();
            match arg {
                "-xml" => p.xml = true,
                "-gui" => p.gui = true,
                "-r" => p.recursive = true,
                "-d" => p.directory = true,
                "-halgorithm" => {
                    check_duplicate(p.hash_algorithm.is_some(), arg)?;
                    p.hash_algorithm = Some(option_value(args, i)?.to_string());
                    i += 1;
                }
                "-i" => {
                    check_duplicate(p.input_file.is_some(), arg)?;
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| CliError::illegal(get("CommandLine.74").into()))?;
                    let path = PathBuf::from(value);
                    if !exists(&path) {
                        return Err(CliError::illegal(format("CommandLine.0", &[value])));
                    }
                    if !can_read(&path) {
                        return Err(CliError::illegal(format("CommandLine.1", &[value])));
                    }
                    p.input_file = Some(path);
                    i += 1;
                }
                "-hformat" => {
                    check_duplicate(p.hash_format.is_some(), arg)?;
                    let value = option_value(args, i)?;
                    let lower = value.to_lowercase();
                    if !["hex", "bin", "b64", "xml", "txt"].contains(&lower.as_str()) {
                        return Err(CliError::illegal(format("CommandLine.89", &[value])));
                    }
                    p.hash_format = Some(lower);
                    i += 1;
                }
                "-o" => {
                    check_duplicate(p.output_file.is_some(), arg)?;
                    let value = args
                        .get(i + 1)
                        .ok_or_else(|| CliError::illegal(get("CommandLine.75").into()))?;
                    let path = PathBuf::from(value);
                    if !parent_writable(&path) {
                        return Err(CliError::illegal(format("CommandLine.3", &[value])));
                    }
                    p.output_file = Some(path);
                    i += 1;
                }
                // El fichero principal era opcional y se ha indicado.
                _ if i == 0 => p.main_file = Some(read_main_file(arg)?),
                _ => return Err(CliError::illegal(format("CommandLine.25", &[arg]))),
            }
            i += 1;
        }
        Ok(p)
    }

    /// Algoritmo indicado o `SHA-256`.
    pub fn hash_algorithm(&self) -> &str {
        self.hash_algorithm.as_deref().unwrap_or(DEFAULT_HASH_ALGORITHM)
    }

    /// Formato para un fichero (`getHashFileFormat`): hex por defecto.
    pub fn file_format(&self) -> Result<FileHashFormat, CliError> {
        match self.hash_format.as_deref() {
            None => Ok(FileHashFormat::Hex),
            Some(f) => {
                FileHashFormat::from_cli_name(f).ok_or_else(|| CliError::illegal(format("CommandLine.91", &[f])))
            }
        }
    }

    /// Formato para un directorio (`getHashDirectoryFormat`): XML por defecto.
    pub fn directory_format(&self) -> Result<DirDocumentFormat, CliError> {
        match self.hash_format.as_deref() {
            None => Ok(DirDocumentFormat::Xml),
            Some(f) => {
                DirDocumentFormat::from_cli_name(f).ok_or_else(|| CliError::illegal(format("CommandLine.90", &[f])))
            }
        }
    }
}

fn check_duplicate(already: bool, arg: &str) -> Result<(), CliError> {
    if already {
        Err(CliError::illegal(format("CommandLine.26", &[arg])))
    } else {
        Ok(())
    }
}

/// Valor de `-halgorithm`/`-hformat` (Java no lo comprueba y falla con un
/// `ArrayIndexOutOfBoundsException`).
fn option_value(args: &[String], i: usize) -> Result<&str, CliError> {
    args.get(i + 1)
        .map(String::as_str)
        .ok_or_else(|| CliError::illegal(format!("No se ha indicado valor para el parametro: {}", args[i])))
}

fn read_main_file(value: &str) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(value);
    if !exists(&path) {
        return Err(CliError::illegal(format("CommandLine.121", &[value])));
    }
    if !can_read(&path) {
        return Err(CliError::illegal(format("CommandLine.122", &[value])));
    }
    Ok(path)
}

/// `File.exists()` (sigue los enlaces simbólicos).
fn exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

/// Aproximación de `File.canRead()`: se intenta abrir el fichero o listar el directorio.
fn can_read(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => fs::read_dir(path).is_ok(),
        Ok(m) if m.is_file() => fs::File::open(path).is_ok(),
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Aproximación de `new File(parent).canWrite()` (si la ruta tiene padre).
fn parent_writable(path: &Path) -> bool {
    match path.parent() {
        None => true,
        Some(parent) if parent.as_os_str().is_empty() => true,
        Some(parent) => fs::metadata(parent).is_ok_and(|m| m.is_dir() && !m.permissions().readonly()),
    }
}

/// `File.getAbsolutePath()`.
fn absolute(path: &Path) -> String {
    if path.is_absolute() {
        return path.display().to_string();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path).display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// Operación que la aplicación debe hacer con la interfaz gráfica (`-gui`).
/// Tras completarla, Java termina siempre con estado 0 (`Runtime.halt(0)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuiRequest {
    /// `HashUIHelper.createHashUI`: calcular sin diálogo de opciones (diálogo
    /// de espera) y abrir el diálogo de guardado con `output` o el nombre por
    /// defecto. Fichero: formato de `format` (hex por defecto) y copia al
    /// portapapeles siempre activa. Directorio: XML por defecto y formato
    /// final según la extensión elegida al guardar.
    CreateDigest {
        /// Fichero o directorio.
        path: PathBuf,
        /// `-o`.
        output: Option<PathBuf>,
        /// `-halgorithm` (o `SHA-256`).
        algorithm: String,
        /// `-hformat` (en minúsculas), si se indicó.
        format: Option<String>,
        /// `-r`.
        recursive: bool,
    },
    /// `HashUIHelper.checkHashUI`: pedir lo que falte (fichero o, con
    /// `directory`, directorio de datos; fichero de huellas) y mostrar el
    /// resultado en diálogos.
    CheckDigest {
        /// Fichero o directorio de datos, si se indicó.
        path: Option<PathBuf>,
        /// `-i`, si se indicó.
        hash_file: Option<PathBuf>,
        /// `-d`.
        directory: bool,
    },
}

/// Respuesta correcta de un comando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandResponse {
    /// Texto de ayuda.
    Help(String),
    /// Texto a imprimir (huella, documento de huellas o mensaje de éxito).
    Text(String),
    /// Resultado de una comprobación y su mensaje.
    Check {
        /// `true` si todas las huellas coinciden.
        matches: bool,
        /// Mensaje (`CommandLine.123` o `.124`).
        message: String,
    },
    /// Hay que continuar con la interfaz gráfica.
    Gui(GuiRequest),
}

/// Ejecuta un comando con los argumentos que siguen a su nombre.
pub fn execute(command: HashCommand, args: &[String], options: &HashOptions<'_>) -> Result<CommandResponse, CliError> {
    let help = args.first().is_some_and(|a| a.eq_ignore_ascii_case("-help"));
    if help || (command == HashCommand::CheckDigest && args.is_empty()) {
        return Ok(CommandResponse::Help(command.help_text()));
    }
    let params = HashParameters::parse(command, args)?;
    if params.gui {
        let request = match command {
            HashCommand::CreateDigest => GuiRequest::CreateDigest {
                path: params.main_file.clone().unwrap_or_default(),
                output: params.output_file.clone(),
                algorithm: params.hash_algorithm().to_string(),
                format: params.hash_format.clone(),
                recursive: params.recursive,
            },
            HashCommand::CheckDigest => GuiRequest::CheckDigest {
                path: params.main_file.clone(),
                hash_file: params.input_file.clone(),
                directory: params.directory,
            },
        };
        return Ok(CommandResponse::Gui(request));
    }
    match command {
        HashCommand::CreateDigest => create_digest(&params, options).map(CommandResponse::Text),
        HashCommand::CheckDigest => {
            let matches = check_digest(&params, options)?;
            let message = get(if matches { "CommandLine.123" } else { "CommandLine.124" }).to_string();
            Ok(CommandResponse::Check { matches, message })
        }
    }
}

fn check_main_file(params: &HashParameters) -> Result<&Path, CliError> {
    let path = params
        .main_file
        .as_deref()
        .ok_or_else(|| CliError::illegal(get("CommandLine.5").into()))?;
    if !exists(path) {
        return Err(CliError::controlled(format("CommandLine.87", &[&absolute(path)])));
    }
    if !can_read(path) {
        return Err(CliError::controlled(format("CommandLine.88", &[&absolute(path)])));
    }
    Ok(path)
}

/// `CreateHashCommand.createHashByCommandLine`.
fn create_digest(params: &HashParameters, options: &HashOptions<'_>) -> Result<String, CliError> {
    let input = check_main_file(params)?;
    let calc_error = |_| CliError::controlled(get("CommandLine.94").into());
    let data = if input.is_dir() {
        let format = params.directory_format()?;
        let algorithm = parse_algorithm(params.hash_algorithm()).map_err(calc_error)?;
        let doc = hash_directory(input, params.recursive, algorithm, options).map_err(calc_error)?;
        doc.generate(format)
            .map_err(|_| CliError::controlled(get("CommandLine.93").into()))?
    } else {
        let format = params.file_format()?;
        let algorithm = parse_algorithm(params.hash_algorithm()).map_err(calc_error)?;
        let digest = hash_file(input, algorithm).map_err(calc_error)?;
        if format == FileHashFormat::Binary && params.output_file.is_none() {
            return Err(CliError::illegal(get("CommandLine.119").into()));
        }
        encode_file_hash(&digest, format)
    };
    match &params.output_file {
        Some(out) => {
            fs::write(out, &data).map_err(|_| CliError::controlled(format("CommandLine.21", &[&absolute(out)])))?;
            Ok(get("CommandLine.22").to_string())
        }
        None => Ok(String::from_utf8_lossy(&data).into_owned()),
    }
}

/// `CheckHashCommand.checkHashByCommandLine`.
fn check_digest(params: &HashParameters, options: &HashOptions<'_>) -> Result<bool, CliError> {
    let data = check_main_file(params)?;
    let hash_file = params
        .input_file
        .as_deref()
        .ok_or_else(|| CliError::illegal(get("CommandLine.6").into()))?;
    if !exists(hash_file) {
        return Err(CliError::controlled(format("CommandLine.98", &[&absolute(hash_file)])));
    }
    if !can_read(hash_file) {
        return Err(CliError::controlled(format("CommandLine.99", &[&absolute(hash_file)])));
    }
    if !data.is_dir() {
        let check =
            check_file_hash_file(data, hash_file).map_err(|_| CliError::controlled(get("CommandLine.94").into()))?;
        return Ok(check.matches);
    }
    let content = fs::read(hash_file).map_err(|_| CliError::controlled(get("CommandLine.101").into()))?;
    let doc = HashDocument::parse(&content).map_err(|e| match e {
        DocumentError::Unsupported(_) => CliError::controlled(get("CommandLine.102").into()),
        DocumentError::Corrupted(_) => CliError::controlled(get("CommandLine.103").into()),
    })?;
    let report =
        check_directory(data, &doc, options).map_err(|_| CliError::controlled(get("CommandLine.94").into()))?;
    if let Some(out) = &params.output_file {
        let xml = report
            .to_xml()
            .map_err(|_| CliError::controlled(get("CommandLine.104").into()))?;
        fs::write(out, xml).map_err(|_| CliError::controlled(format("CommandLine.21", &[&absolute(out)])))?;
    }
    Ok(!report.has_errors())
}

/// Opciones del comportamiento del lanzador.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CliOptions {
    /// Paridad estricta con Java: estado 0 aunque las huellas no coincidan
    /// (por defecto se devuelve [`STATUS_MISMATCH`]).
    pub java_exit_codes: bool,
}

/// Resultado de un comando listo para el lanzador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutcome {
    /// Estado de salida del proceso.
    pub status: i32,
    /// Texto a imprimir en la salida estándar seguido de `\n` (Java lo
    /// imprime todo, errores incluidos, por la salida estándar).
    pub output: Option<String>,
    /// Si no es `None`, la aplicación debe continuar con la interfaz gráfica
    /// y terminar con estado 0.
    pub gui: Option<GuiRequest>,
}

impl CliOutcome {
    /// Texto exacto que se escribe en la salida estándar (con el `\n` final).
    pub fn stdout_text(&self) -> String {
        self.output.as_ref().map(|o| format!("{o}\n")).unwrap_or_default()
    }
}

/// Ejecuta un comando como `CommandLineLauncher` (`args` son los argumentos
/// que siguen al nombre del comando).
pub fn run(command: HashCommand, args: &[String], cli: &CliOptions) -> CliOutcome {
    let xml = args.iter().any(|a| a.eq_ignore_ascii_case("-xml"));
    match execute(command, args, &HashOptions::default()) {
        Ok(CommandResponse::Help(text) | CommandResponse::Text(text)) => CliOutcome {
            status: STATUS_SUCCESS,
            output: Some(text),
            gui: None,
        },
        Ok(CommandResponse::Check { matches, message }) => CliOutcome {
            status: if matches || cli.java_exit_codes {
                STATUS_SUCCESS
            } else {
                STATUS_MISMATCH
            },
            output: Some(message),
            gui: None,
        },
        Ok(CommandResponse::Gui(request)) => CliOutcome {
            status: STATUS_SUCCESS,
            output: None,
            gui: Some(request),
        },
        Err(e) => {
            let msg = e.launcher_message();
            let output = if xml { xml_error_response(&msg) } else { msg };
            CliOutcome {
                status: STATUS_ERROR,
                output: Some(output),
                gui: None,
            }
        }
    }
}

/// Ejecuta la línea de comandos completa (`args[0]` es el comando) si
/// corresponde a un comando de huellas; si no, devuelve `None`.
pub fn dispatch(args: &[String], cli: &CliOptions) -> Option<CliOutcome> {
    let command = HashCommand::parse(args.first()?)?;
    Some(run(command, &args[1..], cli))
}

/// Respuesta XML de error del lanzador (`buildXmlResponse(false, msg, null)`),
/// con el mensaje escapado (Java no lo escapa).
pub fn xml_error_response(msg: &str) -> String {
    let mut escaped = String::with_capacity(msg.len());
    for c in msg.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            c => escaped.push(c),
        }
    }
    format!("<afirma><result>false</result><response><msg>{escaped}</msg></response></afirma>")
}

/// `buildOperationCreateHashSyntaxError` / `buildOperationCheckHashSyntaxError`.
fn syntax_text(command: HashCommand, error: Option<&str>) -> String {
    let op = command.op();
    let mut sb = String::new();
    if let Some(e) = error {
        sb.push_str(e);
        sb.push('\n');
    }
    let m = get;
    match command {
        HashCommand::CheckDigest => {
            sb += &format!("{}:\n", m("CommandLine.7"));
            sb += &format!(
                "  Autofirma {op} [FICHERO] [opciones...]\t\t- {}\n",
                m("CommandLine.108")
            );
            sb += &format!(
                "  Autofirma {op} [DIRECTORIO] [opciones...]\t- {}\n\n",
                m("CommandLine.109")
            );
            sb += &format!("{}:\n", m("CommandLine.114"));
            sb += &format!("  FICHERO\t\t({})\n", m("CommandLine.106"));
            sb += &format!("  DIRECTORIO\t\t({})\n\n", m("CommandLine.107"));
            sb += &format!("{}:\n", m("CommandLine.116"));
            sb += &format!("  -gui\t\t\t({})\n", m("CommandLine.100"));
            sb += &format!("  -i FICHERO\t\t({})\n\n", m("CommandLine.67"));
            sb += &format!("{}:\n", m("CommandLine.117"));
            sb += &format!("  -gui\t\t\t({})\n", m("CommandLine.100"));
            sb += &format!("  -i FICHERO\t\t({})\n", m("CommandLine.105"));
            sb += &format!("  -o FICHERO\t\t({})\n", m("CommandLine.97"));
        }
        HashCommand::CreateDigest => {
            sb += &format!("{}:\n", m("CommandLine.7"));
            sb += &format!("  Autofirma {op} FICHERO [opciones...]\t\t- {}\n", m("CommandLine.110"));
            sb += &format!(
                "  Autofirma {op} DIRECTORIO [opciones...]\t- {}\n\n",
                m("CommandLine.111")
            );
            sb += &format!("{}:\n", m("CommandLine.114"));
            sb += &format!("  FICHERO\t\t({})\n", m("CommandLine.112"));
            sb += &format!("  DIRECTORIO\t\t({})\n\n", m("CommandLine.113"));
            sb += &format!("{}:\n", m("CommandLine.116"));
            sb += &format!("  -gui\t\t\t ({})\n", m("CommandLine.95"));
            sb += &format!("  -o FICHERO\t\t ({})\n", m("CommandLine.118"));
            sb += &format!("  -halgorithm ALGORITMO\t ({})\n", m("CommandLine.77"));
            sb += &format!("  -hformat FORMATO\t ({})\n", m("CommandLine.78"));
            sb += &format!("  \t hex\t\t ({}) ({})\n", m("CommandLine.81"), m("CommandLine.79"));
            sb += &format!("  \t b64\t\t ({})\n", m("CommandLine.82"));
            sb += &format!("  \t bin\t\t ({})\n\n", m("CommandLine.83"));
            sb += &format!("{}:\n", m("CommandLine.117"));
            sb += &format!("  -gui\t\t\t ({})\n", m("CommandLine.95"));
            sb += &format!("  -o FICHERO\t\t ({})\n", m("CommandLine.96"));
            sb += &format!("  -halgorithm ALGORITMO\t ({})\n", m("CommandLine.77"));
            sb += &format!("  -hformat FORMATO\t ({})\n", m("CommandLine.78"));
            sb += &format!("  \t xml\t\t ({}) ({})\n", m("CommandLine.85"), m("CommandLine.79"));
            sb += &format!("  \t txt\t\t ({})\n", m("CommandLine.86"));
            sb += &format!("  -r\t\t ({})\n", m("CommandLine.92"));
        }
    }
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn ayuda() {
        let out = run(HashCommand::CheckDigest, &[], &CliOptions::default());
        assert_eq!(out.status, 0);
        assert!(
            out.output
                .unwrap()
                .starts_with("Sintaxis:\n  Autofirma checkdigest [FICHERO]")
        );
        let out = run(HashCommand::CreateDigest, &s(&["-HELP"]), &CliOptions::default());
        assert_eq!(out.status, 0);
        assert!(
            out.output
                .unwrap()
                .ends_with("  -r\t\t (Procesar los ficheros de los subdirectorios)\n")
        );
    }

    #[test]
    fn errores_de_parametros() {
        let o = CliOptions::default();
        let out = run(HashCommand::CreateDigest, &[], &o);
        assert_eq!(out.status, -1);
        assert_eq!(
            out.output.unwrap(),
            "Error no reconocido: No se ha indicado ningun fichero o directorio"
        );
        let out = run(HashCommand::CreateDigest, &s(&["/no/existe/nada"]), &o);
        assert_eq!(
            out.output.unwrap(),
            "Error no reconocido: El fichero o directorio indicado no existe: /no/existe/nada"
        );
        let out = run(HashCommand::CheckDigest, &s(&["-xml"]), &o);
        assert_eq!(
            out.output.unwrap(),
            "<afirma><result>false</result><response><msg>Error no reconocido: No se ha especificado un fichero de entrada</msg></response></afirma>"
        );
    }

    #[test]
    fn analisis_de_parametros() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("a.txt");
        fs::write(&f, b"a").unwrap();
        let fs_ = f.display().to_string();
        let p = HashParameters::parse(
            HashCommand::CreateDigest,
            &s(&[
                &fs_,
                "-gui",
                "-r",
                "-xml",
                "-d",
                "-halgorithm",
                "SHA-512",
                "-hformat",
                "B64",
                "-o",
                "salida",
            ]),
        )
        .unwrap();
        assert_eq!(p.main_file.as_deref(), Some(f.as_path()));
        assert!(p.gui && p.recursive && p.xml && p.directory);
        assert_eq!(p.hash_algorithm(), "SHA-512");
        assert_eq!(p.hash_format.as_deref(), Some("b64"));
        assert_eq!(p.output_file.as_deref(), Some(Path::new("salida")));

        let err = |args: &[&str]| {
            HashParameters::parse(HashCommand::CheckDigest, &s(args))
                .unwrap_err()
                .message
        };
        assert_eq!(err(&[&fs_, "-i", &fs_, "-i", &fs_]), "Parametro duplicado: -i");
        assert_eq!(err(&[&fs_, "-x"]), "No se reconoce el parametro -x");
        assert_eq!(err(&[&fs_, "-i"]), "No se ha indicado fichero de entrada");
        assert_eq!(err(&[&fs_, "-o"]), "No se ha indicado fichero de salida");
        assert_eq!(
            err(&[&fs_, "-hformat", "CSV"]),
            "Formato de salida de huella digital no soportado: CSV"
        );
        assert_eq!(
            err(&[&fs_, "-i", "no-existe"]),
            "El fichero de entrada no existe: no-existe"
        );
        assert_eq!(
            err(&[&fs_, "-o", "/no/existe/x"]),
            "No hay permisos de escritura en el directorio especificado para el fichero de salida: /no/existe/x"
        );
        assert_eq!(err(&["-gui", "-x"]), "No se reconoce el parametro -x");
        assert_eq!(
            err(&["-halgorithm"]),
            "No se ha indicado valor para el parametro: -halgorithm"
        );
        // En checkdigest el primer argumento no reconocido es el fichero principal.
        assert_eq!(err(&["-foo"]), "El fichero o directorio indicado no existe: -foo");
    }

    #[test]
    fn peticion_grafica() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().display().to_string();
        let out = run(HashCommand::CheckDigest, &s(&["-gui", "-d"]), &CliOptions::default());
        assert_eq!(out.status, 0);
        assert_eq!(out.output, None);
        assert_eq!(
            out.gui,
            Some(GuiRequest::CheckDigest {
                path: None,
                hash_file: None,
                directory: true
            })
        );
        let out = run(
            HashCommand::CreateDigest,
            &s(&[&d, "-gui", "-hformat", "TXT"]),
            &CliOptions::default(),
        );
        assert_eq!(
            out.gui,
            Some(GuiRequest::CreateDigest {
                path: tmp.path().to_path_buf(),
                output: None,
                algorithm: "SHA-256".into(),
                format: Some("txt".into()),
                recursive: false
            })
        );
    }

    #[test]
    fn despacho() {
        assert!(dispatch(&s(&["sign"]), &CliOptions::default()).is_none());
        assert!(dispatch(&[], &CliOptions::default()).is_none());
        let out = dispatch(&s(&["CheckDigest"]), &CliOptions::default()).unwrap();
        assert_eq!(out.status, 0);
        assert_eq!(out.stdout_text(), format!("{}\n", HashCommand::CheckDigest.help_text()));
    }

    #[test]
    fn respuesta_xml_escapada() {
        assert_eq!(
            xml_error_response("a<b&c"),
            "<afirma><result>false</result><response><msg>a&lt;b&amp;c</msg></response></afirma>"
        );
    }
}
