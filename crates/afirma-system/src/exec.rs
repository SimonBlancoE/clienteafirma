//! Ejecución de mandatos externos (`certutil`, `security`, `update-ca-certificates`...)
//! abstraída tras el trait [`CommandRunner`] para poder probar sin tocar el sistema.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Mandato a ejecutar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    /// Programa (ruta absoluta o nombre a buscar en el `PATH`).
    pub program: String,
    /// Argumentos.
    pub args: Vec<String>,
    /// Datos para la entrada estándar (se cierra después).
    pub stdin: Option<Vec<u8>>,
    /// Variables de entorno adicionales.
    pub env: Vec<(String, String)>,
    /// Tiempo máximo de ejecución.
    pub timeout: Duration,
}

impl Cmd {
    /// Crea un mandato con un tiempo máximo de 60 s.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            env: Vec::new(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Añade un argumento.
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Añade un argumento con una ruta.
    pub fn arg_path(self, p: &Path) -> Self {
        self.arg(p.to_string_lossy().into_owned())
    }

    /// Añade varios argumentos.
    pub fn args<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(it.into_iter().map(Into::into));
        self
    }

    /// Fija la entrada estándar.
    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Añade una variable de entorno.
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }

    /// Fija el tiempo máximo.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Representación legible (para registros y planes de acciones).
    pub fn display(&self) -> String {
        let mut s = quote_arg(&self.program);
        for a in &self.args {
            s.push(' ');
            s.push_str(&quote_arg(a));
        }
        s
    }
}

fn quote_arg(a: &str) -> String {
    if !a.is_empty()
        && !a
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        a.to_string()
    } else {
        format!("\"{}\"", a.replace('"', "\\\""))
    }
}

/// Resultado de un mandato.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Código de salida (`None` si terminó por señal o por tiempo).
    pub code: Option<i32>,
    /// Salida estándar (UTF-8 con pérdidas).
    pub stdout: String,
    /// Salida de error (UTF-8 con pérdidas).
    pub stderr: String,
    /// `true` si se interrumpió por superar el tiempo máximo.
    pub timed_out: bool,
}

impl Output {
    /// Salida con código 0.
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            code: Some(0),
            stdout: stdout.into(),
            ..Default::default()
        }
    }

    /// Salida con error.
    pub fn fail(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            code: Some(code),
            stderr: stderr.into(),
            ..Default::default()
        }
    }

    /// `true` si terminó con código 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Texto combinado de salida y error, recortado (para mensajes).
    pub fn message(&self) -> String {
        let mut s = String::new();
        s.push_str(self.stderr.trim());
        if !self.stdout.trim().is_empty() {
            if !s.is_empty() {
                s.push_str(" | ");
            }
            s.push_str(self.stdout.trim());
        }
        if self.timed_out {
            s.push_str(" (tiempo agotado)");
        }
        if s.chars().count() > 600 {
            s = s.chars().take(600).collect::<String>() + "…";
        }
        s
    }
}

/// Ejecutor de mandatos.
pub trait CommandRunner: Send + Sync {
    /// Ejecuta el mandato y espera a que termine (o a que venza el tiempo máximo).
    fn run(&self, cmd: &Cmd) -> io::Result<Output>;
    /// Busca un programa en el `PATH` (y en los directorios `sbin` habituales en Unix).
    fn which(&self, program: &str) -> Option<PathBuf>;
}

/// Ejecutor real basado en `std::process`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, cmd: &Cmd) -> io::Result<Output> {
        let program = if Path::new(&cmd.program).is_absolute() {
            PathBuf::from(&cmd.program)
        } else {
            self.which(&cmd.program)
                .unwrap_or_else(|| PathBuf::from(&cmd.program))
        };
        let mut c = Command::new(&program);
        c.args(&cmd.args)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &cmd.env {
            c.env(k, v);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: sin ventana de consola.
            c.creation_flags(0x0800_0000);
        }
        let mut child = c.spawn()?;
        if let Some(data) = &cmd.stdin
            && let Some(mut si) = child.stdin.take()
        {
            let data = data.clone();
            std::thread::spawn(move || {
                let _ = si.write_all(&data);
            });
        }
        let mut so = child.stdout.take();
        let mut se = child.stderr.take();
        let t_out = std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(s) = so.as_mut() {
                let _ = s.take(8 * 1024 * 1024).read_to_end(&mut v);
            }
            v
        });
        let t_err = std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(s) = se.as_mut() {
                let _ = s.take(1024 * 1024).read_to_end(&mut v);
            }
            v
        });
        let start = Instant::now();
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break Some(st);
            }
            if start.elapsed() >= cmd.timeout {
                let _ = child.kill();
                timed_out = true;
                break child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(15));
        };
        let stdout = t_out.join().unwrap_or_default();
        let stderr = t_err.join().unwrap_or_default();
        Ok(Output {
            code: if timed_out {
                None
            } else {
                status.and_then(|s| s.code())
            },
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            timed_out,
        })
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        which_in_path(program)
    }
}

/// Busca un programa en el `PATH` del proceso y en los directorios `sbin` habituales.
pub fn which_in_path(program: &str) -> Option<PathBuf> {
    let p = Path::new(program);
    if p.is_absolute() {
        return p.is_file().then(|| p.to_path_buf());
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();
    if cfg!(unix) {
        for d in [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ] {
            dirs.push(PathBuf::from(d));
        }
    }
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".into())
            .split(';')
            .map(|s| s.to_string())
            .chain(std::iter::once(String::new()))
            .collect()
    } else {
        vec![String::new()]
    };
    for d in dirs {
        for e in &exts {
            let cand = d.join(format!("{program}{e}"));
            if is_executable(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

type Handler = dyn Fn(&Cmd) -> io::Result<Output> + Send + Sync;

/// Ejecutor simulado para pruebas: registra los mandatos y responde con un manejador.
pub struct FakeRunner {
    calls: Mutex<Vec<Cmd>>,
    handler: Box<Handler>,
    available: Mutex<BTreeSet<String>>,
}

impl std::fmt::Debug for FakeRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeRunner")
            .field("calls", &self.calls())
            .finish()
    }
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self::new(|_| Ok(Output::ok("")))
    }
}

impl FakeRunner {
    /// Crea el ejecutor con un manejador de respuestas.
    pub fn new(handler: impl Fn(&Cmd) -> io::Result<Output> + Send + Sync + 'static) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            handler: Box::new(handler),
            available: Mutex::new(BTreeSet::new()),
        }
    }

    /// Declara programas «instalados» (los encuentra `which`).
    pub fn with_programs(self, programs: &[&str]) -> Self {
        if let Ok(mut a) = self.available.lock() {
            a.extend(programs.iter().map(|s| s.to_string()));
        }
        self
    }

    /// Mandatos ejecutados hasta ahora.
    pub fn calls(&self) -> Vec<Cmd> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Mandatos ejecutados, en forma legible.
    pub fn call_lines(&self) -> Vec<String> {
        self.calls().iter().map(Cmd::display).collect()
    }
}

impl CommandRunner for FakeRunner {
    fn run(&self, cmd: &Cmd) -> io::Result<Output> {
        if let Ok(mut c) = self.calls.lock() {
            c.push(cmd.clone());
        }
        (self.handler)(cmd)
    }

    fn which(&self, program: &str) -> Option<PathBuf> {
        let a = self.available.lock().ok()?;
        a.contains(program)
            .then(|| PathBuf::from(format!("/usr/bin/{program}")))
    }
}
