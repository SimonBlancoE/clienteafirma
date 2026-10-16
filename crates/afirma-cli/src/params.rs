//! Analizador de opciones de los comandos integrados (`CommandLineParameters`).
//!
//! Reglas de Java (§5.4): opciones sensibles a mayúsculas, una opción con
//! valor consume siempre el token siguiente (aunque empiece por `-`), las
//! opciones repetidas son error (salvo los indicadores), `-alias` y
//! `-filter` son excluyentes y, al final, se comprueban el formato, el
//! formato de huella, las URL y los ficheros de entrada y salida.

use std::path::{Path, PathBuf};

use crate::error::CliError;
use crate::messages::Messages;

/// Comandos integrados (`CommandLineCommand`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// `listaliases`.
    List,
    /// `sign`.
    Sign,
    /// `cosign`.
    Cosign,
    /// `countersign`.
    Countersign,
    /// `verify`.
    Verify,
    /// `batchsign`.
    BatchSign,
}

impl Command {
    /// Todos los comandos, en el orden del enumerado de Java.
    pub const ALL: [Command; 6] = [
        Self::List,
        Self::Sign,
        Self::Cosign,
        Self::Countersign,
        Self::Verify,
        Self::BatchSign,
    ];

    /// Nombre del comando.
    pub fn op(self) -> &'static str {
        match self {
            Self::List => "listaliases",
            Self::Sign => "sign",
            Self::Cosign => "cosign",
            Self::Countersign => "countersign",
            Self::Verify => "verify",
            Self::BatchSign => "batchsign",
        }
    }

    /// Comando de un nombre ya pasado a minúsculas (`CommandLineCommand.parse`).
    pub fn parse(op: &str) -> Option<Command> {
        Self::ALL.into_iter().find(|c| c.op() == op)
    }
}

/// Formatos admitidos por `-format`.
pub const FORMATS: [&str; 7] = ["xades", "cades", "pades", "facturae", "ooxml", "odf", "auto"];
/// Formato por defecto.
pub const FORMAT_AUTO: &str = "auto";
/// Formatos de `-hformat` (heredado, sin uso en los comandos integrados).
pub const HASH_FORMATS: [&str; 5] = ["hex", "bin", "b64", "xml", "txt"];
/// Algoritmo por defecto de `-algorithm`.
pub const DEFAULT_ALGORITHM: &str = "sha512";

/// Opciones de un comando integrado.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    pub store: Option<String>,
    pub alias: Option<String>,
    pub filter: Option<String>,
    /// Fichero de entrada (ya con la expansión de `~`).
    pub input: Option<PathBuf>,
    /// Fichero de salida (ya con la expansión de `~`).
    pub output: Option<PathBuf>,
    /// Formato en minúsculas (`None` = `auto`).
    pub format: Option<String>,
    pub hash_format: Option<String>,
    pub password: Option<String>,
    pub algorithm: Option<String>,
    pub hash_algorithm: Option<String>,
    pub config: Option<String>,
    pub massive_op: Option<String>,
    pub xml: bool,
    pub gui: bool,
    pub certgui: bool,
    pub recursive: bool,
    pub pre_url: Option<String>,
    pub post_url: Option<String>,
}

/// Entorno del análisis (directorio personal para `~`).
#[derive(Debug, Clone, Default)]
pub struct ParseEnv {
    /// Directorio personal (`user.home`); `None` desactiva la expansión de `~`.
    pub home: Option<PathBuf>,
}

impl Params {
    /// Formato pedido o `auto`.
    pub fn format(&self) -> &str {
        self.format.as_deref().unwrap_or(FORMAT_AUTO)
    }

    /// Algoritmo pedido o `sha512`.
    pub fn algorithm(&self) -> &str {
        self.algorithm.as_deref().unwrap_or(DEFAULT_ALGORITHM)
    }

    /// Analiza `args` (`args[0]` es el comando).
    pub fn parse(args: &[String], env: &ParseEnv, m: &Messages) -> Result<Params, CliError> {
        let mut p = Params::default();
        let mut format_param: Option<String> = None;
        let mut hash_format_param: Option<String> = None;
        let mut input_param: Option<String> = None;
        let mut output_param: Option<String> = None;
        let mut i = 1;
        while i < args.len() {
            let a = args[i].as_str();
            let gui = p.gui;
            // Opción con valor: duplicado (.26), valor ausente (clave indicada).
            let mut take = |slot: &mut Option<String>, missing: u32| -> Result<(), CliError> {
                if slot.is_some() {
                    return Err(CliError::command(m.fmt(26, &[a]), gui));
                }
                if i + 1 >= args.len() {
                    return Err(CliError::command(m.get(missing), gui));
                }
                *slot = Some(args[i + 1].clone());
                i += 1;
                Ok(())
            };
            match a {
                "-xml" => p.xml = true,
                "-preurl" => take(&mut p.pre_url, 128)?,
                "-posturl" => take(&mut p.post_url, 129)?,
                "-gui" => p.gui = true,
                "-certgui" => p.certgui = true,
                "-r" => p.recursive = true,
                "-store" => take(&mut p.store, 130)?,
                "-operation" => take(&mut p.massive_op, 131)?,
                "-algorithm" => take(&mut p.algorithm, 132)?,
                "-halgorithm" => take(&mut p.hash_algorithm, 133)?,
                "-config" => take(&mut p.config, 134)?,
                "-password" => take(&mut p.password, 135)?,
                "-alias" => {
                    if p.alias.is_some() {
                        return Err(CliError::command(m.fmt(26, &[a]), gui));
                    }
                    if p.filter.is_some() {
                        return Err(CliError::command(m.get(28), gui));
                    }
                    take(&mut p.alias, 136)?;
                }
                "-filter" => {
                    if p.filter.is_some() {
                        return Err(CliError::command(m.fmt(26, &[a]), gui));
                    }
                    if p.alias.is_some() {
                        return Err(CliError::command(m.get(28), gui));
                    }
                    take(&mut p.filter, 137)?;
                }
                "-i" => take(&mut input_param, 74)?,
                "-format" => take(&mut format_param, 138)?,
                "-hformat" => take(&mut hash_format_param, 139)?,
                "-o" => take(&mut output_param, 75)?,
                _ => return Err(CliError::command(m.fmt(25, &[a]), gui)),
            }
            i += 1;
        }
        p.check(format_param, hash_format_param, input_param, output_param, env, m)?;
        Ok(p)
    }

    /// `checkParams()`.
    fn check(
        &mut self,
        format_param: Option<String>,
        hash_format_param: Option<String>,
        input_param: Option<String>,
        output_param: Option<String>,
        env: &ParseEnv,
        m: &Messages,
    ) -> Result<(), CliError> {
        let gui = self.gui;
        if let Some(f) = format_param {
            let lower = f.to_lowercase();
            if !FORMATS.contains(&lower.as_str()) {
                return Err(CliError::syntax(m.fmt(4, &[&f]), gui));
            }
            self.format = Some(lower);
        }
        if let Some(f) = hash_format_param {
            let lower = f.to_lowercase();
            if !HASH_FORMATS.contains(&lower.as_str()) {
                return Err(CliError::syntax(m.fmt(89, &[&f]), gui));
            }
            self.hash_format = Some(lower);
        }
        for url in [&self.pre_url, &self.post_url].into_iter().flatten() {
            if let Err(e) = check_java_url(url) {
                return Err(CliError::syntax(
                    m.fmt(59, &[url, &format!("java.net.MalformedURLException: {e}")]),
                    gui,
                ));
            }
        }
        if let Some(inp) = input_param {
            let file = expand_tilde(&inp, env);
            let Ok(meta) = std::fs::metadata(&file) else {
                return Err(CliError::command(m.fmt(0, &[&inp]), gui));
            };
            if !can_read(&file, &meta) {
                return Err(CliError::command(m.fmt(1, &[&inp]), gui));
            }
            self.input = Some(file);
        }
        if let Some(out) = output_param {
            let file = expand_tilde(&out, env);
            if let Some(parent) = java_parent(&file)
                && !can_write_dir(&parent)
            {
                return Err(CliError::command(m.fmt(3, &[&out]), gui));
            }
            self.output = Some(file);
        }
        Ok(())
    }
}

/// Expansión de `~` de Java en Unix: `new File(user.home, ruta.substring(1))`
/// (así `~bob/x` es `$HOME/bob/x`, como en Java).
pub fn expand_tilde(path: &str, env: &ParseEnv) -> PathBuf {
    if cfg!(unix)
        && let (Some(rest), Some(home)) = (path.strip_prefix('~'), env.home.as_ref())
    {
        let rest = rest.trim_start_matches('/');
        return if rest.is_empty() { home.clone() } else { home.join(rest) };
    }
    PathBuf::from(path)
}

/// `File.getParentFile()`: `None` para un nombre sin directorio.
fn java_parent(file: &Path) -> Option<PathBuf> {
    file.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

/// `File.canRead()` aproximado: un fichero se puede abrir; un directorio
/// existe (Java devuelve `true` y la lectura falla después).
fn can_read(file: &Path, meta: &std::fs::Metadata) -> bool {
    meta.is_dir() || std::fs::File::open(file).is_ok()
}

/// `File.canWrite()` de un directorio, aproximado: existe, es un directorio y
/// no está marcado como de solo lectura.
fn can_write_dir(dir: &Path) -> bool {
    std::fs::metadata(dir).is_ok_and(|m| m.is_dir() && !m.permissions().readonly())
}

/// Validación de `new java.net.URL(texto)`: devuelve el mensaje de
/// `MalformedURLException` (`no protocol: x`, `unknown protocol: x`).
pub fn check_java_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    let scheme = trimmed.split_once(':').map(|(s, _)| s).filter(|s| {
        let mut chars = s.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    });
    let Some(scheme) = scheme else {
        return Err(format!("no protocol: {url}"));
    };
    let lower = scheme.to_ascii_lowercase();
    if ["http", "https", "ftp", "file", "jar", "mailto", "jrt"].contains(&lower.as_str()) {
        Ok(())
    } else {
        Err(format!("unknown protocol: {lower}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CliError;
    use crate::messages::Language;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn parse(v: &[&str]) -> Result<Params, CliError> {
        Params::parse(
            &s(v),
            &ParseEnv {
                home: Some(PathBuf::from("/home/u")),
            },
            &Messages::new(Language::EsEs),
        )
    }

    fn err(v: &[&str]) -> CliError {
        parse(v).unwrap_err()
    }

    #[test]
    fn opciones_basicas() {
        let p = parse(&[
            "sign",
            "-store",
            "auto",
            "-alias",
            "a",
            "-password",
            "-raro",
            "-format",
            "PAdES",
            "-xml",
            "-config",
            "a=b",
            "-algorithm",
            "SHA-256",
        ])
        .unwrap();
        assert_eq!(p.store.as_deref(), Some("auto"));
        assert_eq!(p.alias.as_deref(), Some("a"));
        // El valor se consume aunque empiece por '-'.
        assert_eq!(p.password.as_deref(), Some("-raro"));
        assert_eq!(p.format(), "pades");
        assert!(p.xml && !p.gui && !p.certgui);
        assert_eq!(p.algorithm(), "SHA-256");
        let p = parse(&[
            "sign",
            "-gui",
            "-gui",
            "-certgui",
            "-r",
            "-operation",
            "x",
            "-hformat",
            "B64",
            "-halgorithm",
            "y",
        ])
        .unwrap();
        assert!(p.gui && p.certgui && p.recursive);
        assert_eq!(p.format(), "auto");
        assert_eq!(p.algorithm(), "sha512");
        assert_eq!(p.hash_format.as_deref(), Some("b64"));
    }

    #[test]
    fn errores_de_analisis() {
        assert_eq!(
            err(&["sign", "-foo"]),
            CliError::command("No se reconoce el parametro -foo".into(), false)
        );
        assert_eq!(
            err(&["sign", "-gui", "-I"]),
            CliError::command("No se reconoce el parametro -I".into(), true)
        );
        // El indicador depende del orden (quirk de Java).
        assert_eq!(
            err(&["sign", "-I", "-gui"]),
            CliError::command("No se reconoce el parametro -I".into(), false)
        );
        assert_eq!(
            err(&["sign", "-XML"]),
            CliError::command("No se reconoce el parametro -XML".into(), false)
        );
        assert_eq!(
            err(&["sign", "-store", "a", "-store", "b"]),
            CliError::command("Parametro duplicado: -store".into(), false)
        );
        assert_eq!(
            err(&["sign", "-alias", "a", "-filter", "b"]),
            CliError::command("Las opciones '-alias' y '-filter' son excluyentes".into(), false)
        );
        assert_eq!(
            err(&["sign", "-filter", "b", "-alias", "a"]),
            CliError::command("Las opciones '-alias' y '-filter' son excluyentes".into(), false)
        );
        assert_eq!(
            err(&["sign", "-alias", "a", "-alias", "b"]),
            CliError::command("Parametro duplicado: -alias".into(), false)
        );
        let missing = [
            ("-i", "No se ha indicado fichero de entrada"),
            ("-o", "No se ha indicado fichero de salida"),
            ("-store", "No se ha indicado el nombre del almacén de claves"),
            ("-operation", "No se ha indicado la operación de firma masiva"),
            ("-algorithm", "No se ha indicado el algoritmo de firma"),
            ("-halgorithm", "No se ha indicado el algoritmo de huella digital"),
            ("-config", "No se ha indicado la configuración del formato de firma"),
            ("-password", "No se ha indicado la contraseña del almacén"),
            ("-alias", "No se ha indicado el alias del certificado"),
            ("-filter", "No se ha indicado el filtro de certificados"),
            ("-format", "No se ha indicado el formato de firma"),
            ("-hformat", "No se ha indicado el formato de huella digital"),
            ("-preurl", "No se ha indicado URL de prefirma"),
            ("-posturl", "No se ha indicado URL de postfirma"),
        ];
        for (opt, msg) in missing {
            assert_eq!(err(&["sign", opt]), CliError::command(msg.into(), false), "{opt}");
        }
        // `-help` fuera de la primera posición es un parámetro desconocido.
        assert_eq!(
            err(&["sign", "-i", "x", "-help"]),
            CliError::command("No se reconoce el parametro -help".into(), false)
        );
    }

    #[test]
    fn comprobaciones_finales() {
        assert_eq!(
            err(&["sign", "-format", "foo"]),
            CliError::syntax("Formato de firma no soportado: foo".into(), false)
        );
        assert_eq!(
            err(&["sign", "-gui", "-format", "Foo"]),
            CliError::syntax("Formato de firma no soportado: Foo".into(), true)
        );
        assert_eq!(
            err(&["sign", "-hformat", "zz"]),
            CliError::syntax("Formato de salida de huella digital no soportado: zz".into(), false)
        );
        assert_eq!(
            err(&["batchsign", "-preurl", "foo"]),
            CliError::syntax(
                "La direccion indicada ('foo') debe ser una URL valida: java.net.MalformedURLException: no protocol: foo".into(),
                false
            )
        );
        assert_eq!(
            err(&["batchsign", "-posturl", "xyz:abc"]),
            CliError::syntax(
                "La direccion indicada ('xyz:abc') debe ser una URL valida: java.net.MalformedURLException: unknown protocol: xyz".into(),
                false
            )
        );
        assert_eq!(
            err(&["sign", "-i", "/no/existe/x"]),
            CliError::command("El fichero de entrada no existe: /no/existe/x".into(), false)
        );
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.txt");
        std::fs::write(&f, b"x").unwrap();
        let p = parse(&["sign", "-i", f.to_str().unwrap(), "-o", "relativo.csig"]).unwrap();
        assert_eq!(p.input.as_deref(), Some(f.as_path()));
        assert_eq!(p.output.as_deref(), Some(Path::new("relativo.csig")));
        let bad_out = "/no/existe/dir/x.csig";
        assert_eq!(
            err(&["sign", "-o", bad_out]),
            CliError::command(
                format!(
                    "No hay permisos de escritura en el directorio especificado para el fichero de salida: {bad_out}"
                ),
                false
            )
        );
    }

    #[test]
    fn expansion_de_tilde() {
        let env = ParseEnv {
            home: Some(PathBuf::from("/home/u")),
        };
        if cfg!(unix) {
            assert_eq!(expand_tilde("~/a.pdf", &env), PathBuf::from("/home/u/a.pdf"));
            assert_eq!(expand_tilde("~bob/x", &env), PathBuf::from("/home/u/bob/x"));
            assert_eq!(expand_tilde("~", &env), PathBuf::from("/home/u"));
        }
        assert_eq!(expand_tilde("a/~b", &env), PathBuf::from("a/~b"));
    }

    #[test]
    fn urls_java() {
        assert!(check_java_url("http://localhost:8080/x").is_ok());
        assert!(check_java_url("HTTPS://x").is_ok());
        assert_eq!(check_java_url("http//x"), Err("no protocol: http//x".into()));
        assert_eq!(check_java_url("1abc:x"), Err("no protocol: 1abc:x".into()));
    }

    #[test]
    fn comandos() {
        assert_eq!(Command::parse("countersign"), Some(Command::Countersign));
        assert_eq!(Command::parse("COSIGN"), None);
        assert_eq!(
            Command::ALL.map(|c| c.op()),
            ["listaliases", "sign", "cosign", "countersign", "verify", "batchsign"]
        );
    }
}
