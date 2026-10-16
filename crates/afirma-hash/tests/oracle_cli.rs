//! Comparación de la línea de comandos (`createdigest`/`checkdigest`) con la
//! salida del plugin de Java para los casos de `testdata/hash/cli-cases.txt`
//! (`java-cli.golden`, generado con `tools/oracle/hash_oracle.sh`).
//!
//! Esta prueba cambia el directorio de trabajo del proceso, por eso está en
//! su propio binario de pruebas.

mod common;

use afirma_hash::cli::{CliOptions, STATUS_MISMATCH, dispatch};
use common::{copy_dir, golden, make_tree, testdata};

/// Casos en los que nos apartamos de Java a propósito (ver
/// `docs/deviations/afirma-hash.md`): (caso, estado, salida).
const DEVIATIONS: &[(&str, i32, &str)] = &[
    // Hexadecimal sin `h`: Java lo toma por Base64 y no coincide.
    (
        "checkdigest sub/hola.txt -i ../h/hola-sin-h.hexhash",
        0,
        "Comprobacion de huella digital finalizada sin errores\n",
    ),
    // Salto de línea final: Java no reconoce el Base64.
    (
        "checkdigest sub/hola.txt -i ../h/hola-crlf.hashb64",
        0,
        "Comprobacion de huella digital finalizada sin errores\n",
    ),
    // Base64 URL-safe: Java lo decodifica con el alfabeto estándar.
    (
        "checkdigest sub/hola.txt -i ../h/hola-url.hashb64",
        0,
        "Comprobacion de huella digital finalizada sin errores\n",
    ),
    // Documento sin extensión: Java falla con un NullPointerException; aquí
    // el formato se detecta por el contenido.
    (
        "checkdigest $TREE -i ../h/sin-extension",
        0,
        "Comprobacion de huella digital finalizada sin errores\n",
    ),
];

struct Case {
    line: String,
    status: i32,
    output: String,
}

fn parse_golden(text: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    for block in text.split(">>> ").skip(1) {
        let (line, rest) = block.split_once('\n').unwrap();
        let (status, rest) = rest.split_once('\n').unwrap();
        let status = status.strip_prefix("status: ").unwrap().parse().unwrap();
        let output = rest.strip_suffix("<<<\n").unwrap().to_string();
        cases.push(Case {
            line: line.to_string(),
            status,
            output,
        });
    }
    cases
}

#[test]
fn casos_de_linea_de_comandos() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let tree = root.join("tree");
    make_tree(&tree);
    copy_dir(&testdata(), &root.join("h"));
    std::env::set_current_dir(&tree).unwrap();
    let tree_str = tree.display().to_string();

    let cases = parse_golden(&String::from_utf8(golden("java-cli.golden")).unwrap());
    assert!(cases.len() > 30);
    let parity = CliOptions {
        java_exit_codes: true,
    };
    for case in &cases {
        let args: Vec<String> = case
            .line
            .split(' ')
            .map(|a| a.replace("$TREE", &tree_str))
            .collect();
        let outcome = dispatch(&args, &parity).expect("comando de huellas");
        assert!(outcome.gui.is_none());
        let status = outcome.status & 0xff;
        let output = outcome.stdout_text().replace(&tree_str, "$TREE");
        let deviation = DEVIATIONS.iter().find(|(l, _, _)| *l == case.line);
        match deviation {
            Some((_, st, out)) => {
                assert_eq!((status, output.as_str()), (*st, *out), "{}", case.line);
                assert_ne!(
                    (case.status, case.output.as_str()),
                    (*st, *out),
                    "ya no es desviación: {}",
                    case.line
                );
            }
            None => assert_eq!(
                (status, output.as_str()),
                (case.status, case.output.as_str()),
                "{}",
                case.line
            ),
        }

        // Sin paridad, una comprobación que no coincide devuelve STATUS_MISMATCH.
        if deviation.is_none()
            && case
                .output
                .starts_with("Las huellas indicadas no se corresponden")
        {
            let outcome = dispatch(&args, &CliOptions::default()).unwrap();
            assert_eq!(outcome.status, STATUS_MISMATCH, "{}", case.line);
        }
    }
}
