//! Línea de comandos de AutoFirma-rs (`CommandLineLauncher` de AutoFirma,
//! especificación `docs/spec/06-app-ui-cli-installer.md` §5).
//!
//! La aplicación llama a [`run`] con los argumentos (sin el nombre del
//! programa) y un [`CliEnv`] con lo que solo ella puede dar (contraseñas y
//! diálogos, preferencias, nombre del ejecutable, operaciones de sistema).
//! Recibe un [`CliOutcome`]: escribe `output` **tal cual** en la salida
//! estándar (ya incluye el salto de línea final; como en Java, todo va a la
//! salida estándar, errores incluidos) y termina con `status` (−1 en los
//! errores, que el sistema ve como 255). Si `gui` no es `None`, antes debe
//! abrir la interfaz que se pide ([`GuiRequest`]):
//!
//! - [`GuiRequest::Sign`] (`sign -gui`) y [`GuiRequest::Verify`]
//!   (`verify -gui`), y [`GuiRequest::Hash`] (`createdigest`/`checkdigest -gui`):
//!   la aplicación abre la ventana y termina con el estado de la interfaz
//!   (`status` es 0 y `output` está vacío).
//! - [`GuiRequest::ErrorDialog`]: errores de parámetros con `-gui`; la
//!   aplicación muestra el diálogo si puede, imprime `output` y termina con
//!   `status`.
//!
//! ```no_run
//! let args: Vec<String> = std::env::args().skip(1).collect();
//! let env = afirma_cli::CliEnv::new("autofirma")
//!     // Preferencias de la aplicación (`default.locale`...).
//!     .with_preferences(|_clave| None);
//! // También: `with_password_callback` (diálogo o terminal), `with_certificate_chooser`
//! // (`-certgui`) y `with_system` (`install`, `doctor`...).
//! let outcome = afirma_cli::run(&args, &env);
//! print!("{}", outcome.output);
//! if let Some(gui) = outcome.gui {
//!     // Abrir la interfaz pedida (o el diálogo de error) antes de terminar.
//!     let _ = gui;
//! }
//! std::process::exit(outcome.status);
//! ```
//!
//! Comandos:
//!
//! | Comando | Origen |
//! |---|---|
//! | `sign`, `cosign`, `countersign`, `listaliases`, `verify`, `batchsign` | integrados en Java |
//! | `createdigest`, `checkdigest` | plugin de huellas de Java, aquí integrados ([`afirma_hash::cli`]) |
//! | `install`, `uninstall`, `doctor`, `restore-config` | nuevos, para los instaladores ([`system`]) |
//! | `-version`, `--version`, `--help` | nuevos |
//!
//! Las diferencias con Java están en `docs/deviations/afirma-cli.md`.

// `AfirmaError` (compartido por todos los crates) es grande.
#![allow(clippy::result_large_err)]

mod batch;
pub mod config;
pub mod error;
pub mod help;
mod list;
pub mod messages;
pub mod params;
pub mod response;
mod sign;
pub mod store;
pub mod system;
#[cfg(feature = "afirma-system")]
pub mod system_adapter;
mod verify;

use std::path::PathBuf;
use std::sync::Arc;

use afirma_core::ExtraParams;
use afirma_hash::HashCommand;
use afirma_keystores::{NoPassword, PasswordCallback};

pub use error::CliError;
pub use help::SystemCommand;
pub use messages::{Language, Messages};
pub use params::Command;
pub use store::{CertificateChoice, CertificateChooser, CertificateRequest};
pub use system::{
    DoctorRequest, InstallRequest, RestoreRequest, Scope, SystemOps, SystemOutcome,
    UninstallRequest,
};

/// Estado de salida correcto.
pub const STATUS_SUCCESS: i32 = 0;
/// Estado de salida de error (`STATUS_ERROR` de Java; 255 en POSIX).
pub const STATUS_ERROR: i32 = -1;

/// Consulta de preferencias de la aplicación (`PreferencesManager.get`), p.
/// ej. `default.locale`.
pub type PreferenceLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Preferencia del idioma (`PreferencesManager.PREFERENCES_LOCALE`).
pub const PREFERENCE_LOCALE: &str = "default.locale";

/// Lo que la aplicación inyecta en la línea de comandos.
#[derive(Clone)]
pub struct CliEnv {
    /// Nombre del ejecutable en las ayudas (`DesktopUtil.getApplicationFilename()`,
    /// p. ej. `autofirma` o `AutofirmaCommandLine.exe`).
    pub app_name: String,
    /// Texto de `-version`/`--version`.
    pub version: String,
    /// Preferencias (por defecto, ninguna).
    pub preferences: PreferenceLookup,
    /// Configuración regional del sistema (por defecto, la de las variables
    /// `LC_ALL`/`LC_MESSAGES`/`LANG`); se usa si no hay `default.locale`.
    pub os_locale: Option<String>,
    /// Contraseñas y PIN cuando no se indica `-password` (Java mostraba los
    /// diálogos del almacén). Por defecto, sin interacción ([`NoPassword`]).
    pub password_callback: Arc<dyn PasswordCallback>,
    /// Diálogo de selección de certificado para `-certgui` (por defecto,
    /// ninguno: `-certgui` falla con un mensaje claro).
    pub certificate_chooser: Option<Arc<dyn CertificateChooser>>,
    /// Operaciones de integración con el sistema (por defecto, ninguna).
    pub system: Option<Arc<dyn SystemOps>>,
    /// Cliente HTTP de `batchsign` (por defecto, el instalado en el proceso).
    pub http: Option<afirma_protocol::HttpClient>,
    /// Directorio personal para la expansión de `~` en `-i`/`-o` (por
    /// defecto, `HOME`).
    pub home_dir: Option<PathBuf>,
    /// Paridad estricta de Java en `checkdigest`: estado 0 aunque las
    /// huellas no coincidan (por defecto, 1; ver `afirma-hash`).
    pub hash_java_exit_codes: bool,
}

impl std::fmt::Debug for CliEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CliEnv")
            .field("app_name", &self.app_name)
            .field("version", &self.version)
            .field("os_locale", &self.os_locale)
            .field("certificate_chooser", &self.certificate_chooser.is_some())
            .field("system", &self.system.is_some())
            .field("home_dir", &self.home_dir)
            .field("hash_java_exit_codes", &self.hash_java_exit_codes)
            .finish_non_exhaustive()
    }
}

impl Default for CliEnv {
    fn default() -> Self {
        Self::new("autofirma")
    }
}

impl CliEnv {
    /// Entorno no interactivo con el nombre de ejecutable indicado.
    pub fn new(app_name: impl Into<String>) -> Self {
        CliEnv {
            app_name: app_name.into(),
            version: format!("AutoFirma {}", env!("CARGO_PKG_VERSION")),
            preferences: Arc::new(|_| None),
            os_locale: messages::os_locale_from_env(),
            password_callback: Arc::new(NoPassword),
            certificate_chooser: None,
            system: None,
            http: None,
            home_dir: std::env::var_os("HOME").map(PathBuf::from),
            hash_java_exit_codes: false,
        }
    }

    /// Con una consulta de preferencias.
    pub fn with_preferences(
        mut self,
        lookup: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.preferences = Arc::new(lookup);
        self
    }

    /// Con un proveedor de contraseñas y PIN.
    pub fn with_password_callback(mut self, callback: Arc<dyn PasswordCallback>) -> Self {
        self.password_callback = callback;
        self
    }

    /// Con un selector gráfico de certificados (`-certgui`).
    pub fn with_certificate_chooser(mut self, chooser: Arc<dyn CertificateChooser>) -> Self {
        self.certificate_chooser = Some(chooser);
        self
    }

    /// Con las operaciones de sistema.
    pub fn with_system(mut self, ops: Arc<dyn SystemOps>) -> Self {
        self.system = Some(ops);
        self
    }

    /// Idioma de los mensajes: `default.locale` o el del sistema (§5.2).
    pub fn language(&self) -> Language {
        Language::resolve(
            (self.preferences)(PREFERENCE_LOCALE).as_deref(),
            self.os_locale.as_deref(),
        )
    }
}

/// Operación de la ventana principal para `sign -gui`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuiOperation {
    /// Firma (lo que siempre llega desde la línea de comandos).
    Sign,
    /// Cofirma.
    Cosign,
    /// Contrafirma de las hojas.
    CountersignLeafs,
}

/// `sign -gui -i <fichero>` (`SimpleAfirma.initGUI(fichero, SignOperationConfig)`):
/// abrir la ventana principal con el fichero cargado en la pantalla de firma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignGuiRequest {
    /// Fichero a firmar.
    pub file: PathBuf,
    /// Operación.
    pub operation: GuiOperation,
    /// Formato pedido con `-format` (nombre de AutoFirma: `PAdES`,
    /// `XAdES`...); `None` con `auto`: la interfaz elige según el fichero y
    /// las preferencias.
    pub format: Option<String>,
    /// Parámetros de `-config`. Java los descartaba (y también los de las
    /// preferencias); se recomienda aplicar las preferencias del formato y
    /// después estos.
    pub extra_params: ExtraParams,
    /// Algoritmo de huella (`getDigestAlgorithmName(-algorithm)`, p. ej.
    /// `SHA-512`). Como en Java, sin `-algorithm` es `SHA-512`.
    pub digest_algorithm: String,
    /// Si `-algorithm` se indicó (la aplicación puede preferir la preferencia
    /// de algoritmo cuando no).
    pub algorithm_explicit: bool,
}

/// Interfaz gráfica que la aplicación debe mostrar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuiRequest {
    /// `sign -gui`.
    Sign(SignGuiRequest),
    /// `verify -gui -i <fichero>`: visor de firmas con el fichero.
    Verify {
        /// Firma o documento firmado.
        file: PathBuf,
    },
    /// `createdigest ... -gui` / `checkdigest ... -gui`.
    Hash(afirma_hash::GuiRequest),
    /// Diálogo de error de parámetros (título `CommandLineLauncher.127`)
    /// que Java mostraba con `-gui`; después se imprime `output`.
    ErrorDialog {
        /// Título.
        title: String,
        /// Mensaje.
        message: String,
    },
}

/// Resultado de la línea de comandos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutcome {
    /// Estado de salida del proceso.
    pub status: i32,
    /// Texto exacto para la salida estándar (con el salto de línea final;
    /// vacío si no hay nada que imprimir).
    pub output: String,
    /// Interfaz que hay que abrir, si la hay.
    pub gui: Option<GuiRequest>,
}

impl CliOutcome {
    fn printed(status: i32, text: Option<String>, gui: Option<GuiRequest>) -> Self {
        CliOutcome {
            status,
            output: text.map(|t| t + "\n").unwrap_or_default(),
            gui,
        }
    }
}

/// Respuesta correcta de un comando integrado.
enum Reply {
    /// Texto a imprimir.
    Text(String),
    /// Interfaz gráfica.
    Gui(GuiRequest),
}

/// Ejecuta la línea de comandos (`args` sin el nombre del programa).
pub fn run(args: &[String], env: &CliEnv) -> CliOutcome {
    let m = Messages::new(env.language());
    let app = env.app_name.as_str();
    let Some(first) = args.first() else {
        return CliOutcome::printed(
            STATUS_SUCCESS,
            Some(help::general_help(&m, app, None)),
            None,
        );
    };
    if first.eq_ignore_ascii_case("-help") || first == "--help" {
        return CliOutcome::printed(
            STATUS_SUCCESS,
            Some(help::general_help(&m, app, None)),
            None,
        );
    }
    if first == "-version" || first == "--version" {
        return CliOutcome::printed(STATUS_SUCCESS, Some(env.version.clone()), None);
    }
    let op = first.to_lowercase();
    let need_xml = args.iter().skip(1).any(|a| a.eq_ignore_ascii_case("-xml"));

    if let Some(command) = Command::parse(&op) {
        return match process_command(command, args, env, &m) {
            Ok(Reply::Text(text)) => CliOutcome::printed(STATUS_SUCCESS, Some(text), None),
            Ok(Reply::Gui(gui)) => CliOutcome {
                status: STATUS_SUCCESS,
                output: String::new(),
                gui: Some(gui),
            },
            Err(e) => error_outcome(e, Some(command), need_xml, &m, app),
        };
    }
    if let Some(hash) = HashCommand::parse(&op) {
        let options = afirma_hash::CliOptions {
            java_exit_codes: env.hash_java_exit_codes,
        };
        let out = afirma_hash::cli::run(hash, &args[1..], &options);
        return CliOutcome {
            status: out.status,
            output: out.stdout_text(),
            gui: out.gui.map(GuiRequest::Hash),
        };
    }
    if let Some(sys) = SystemCommand::parse(&op) {
        let (status, text) = system::run(sys, &args[1..], env.system.as_deref(), &m, app);
        return CliOutcome::printed(status, Some(text), None);
    }
    let unknown = help::general_help(&m, app, Some(&m.fmt(15, &[first])));
    error_outcome(CliError::Unsupported(unknown), None, need_xml, &m, app)
}

/// `processCommand`.
fn process_command(
    command: Command,
    args: &[String],
    env: &CliEnv,
    m: &Messages,
) -> Result<Reply, CliError> {
    if args.get(1).is_some_and(|a| a.eq_ignore_ascii_case("-help")) {
        return Ok(Reply::Text(help::command_help(
            command,
            m,
            &env.app_name,
            None,
        )));
    }
    let parse_env = params::ParseEnv {
        home: env.home_dir.clone(),
    };
    let p = params::Params::parse(args, &parse_env, m)?;
    match command {
        Command::List => list::list_aliases(&p, env, m).map(Reply::Text),
        Command::Verify if p.gui => match p.input.clone() {
            Some(file) => Ok(Reply::Gui(GuiRequest::Verify { file })),
            None => Err(CliError::command(m.get(5), true)),
        },
        Command::Verify => verify::verify_by_command_line(&p, m).map(Reply::Text),
        Command::Sign if p.gui => sign::sign_gui_request(command, &p, m).map(Reply::Gui),
        Command::Sign | Command::Cosign | Command::Countersign => {
            sign::sign_by_command_line(command, &p, env, m).map(Reply::Text)
        }
        Command::BatchSign => batch::batch_by_command_line(&p, env, m).map(Reply::Text),
    }
}

/// Tratamiento de errores de `processCommandLine` (§5.11).
fn error_outcome(
    e: CliError,
    command: Option<Command>,
    need_xml: bool,
    m: &Messages,
    app: &str,
) -> CliOutcome {
    let wrap = |msg: Option<String>| -> Option<String> {
        if need_xml {
            Some(response::xml_response(false, msg.as_deref(), None))
        } else {
            msg
        }
    };
    let dialog = |message: &str| GuiRequest::ErrorDialog {
        title: m.get(127),
        message: message.to_string(),
    };
    match e {
        CliError::Syntax { message, using_gui } => {
            let text = match command {
                Some(c) => help::command_help(c, m, app, Some(&message)),
                None => message.clone(),
            };
            CliOutcome::printed(
                STATUS_ERROR,
                Some(text),
                using_gui.then(|| dialog(&message)),
            )
        }
        CliError::Command { message, using_gui } => {
            let gui = if using_gui {
                Some(dialog(message.as_deref().unwrap_or("")))
            } else {
                None
            };
            CliOutcome::printed(STATUS_ERROR, wrap(message), gui)
        }
        CliError::Unsupported(message) => {
            CliOutcome::printed(STATUS_ERROR, wrap(Some(message)), None)
        }
        CliError::Unexpected(message) => {
            CliOutcome::printed(STATUS_ERROR, wrap(Some(m.fmt(50, &[&message]))), None)
        }
    }
}
