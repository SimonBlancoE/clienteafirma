//! Ejecutable mínimo de prueba de la línea de comandos (sin interfaz
//! gráfica): `cargo run -p afirma-cli --example autofirma_cli -- sign -help`.
//! Muestra cómo debe usar la aplicación [`afirma_cli::run`].

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let env = afirma_cli::CliEnv::new("autofirma");
    let outcome = afirma_cli::run(&args, &env);
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(outcome.output.as_bytes());
    let _ = stdout.flush();
    if let Some(gui) = outcome.gui {
        eprintln!("(se pediría la interfaz gráfica: {gui:?})");
    }
    std::process::exit(outcome.status);
}
