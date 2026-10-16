//! Comparación con la AutoFirma Java de todas las órdenes de
//! `testdata/cli/cases.tsv` (golden generados con `tools/oracle/cli_goldens.py`).
//!
//! Para cada caso se comparan el estado de salida y la salida estándar
//! exacta (salvo las diferencias documentadas, que se aplican al texto de
//! Java antes de comparar) y, si el caso produce una firma, su estructura y
//! validez frente a la firma que generó Java para la misma orden.

mod common;

use common::*;

/// Líneas que la ayuda general añade a la de Java tras `batchsign`.
fn general_help_additions(locale: Option<&str>) -> String {
    let en = locale == Some("en_US");
    let (title, install, uninstall, doctor, restore) = if en {
        (
            "System integration commands",
            "installs the integration of Autofirma with the system and the browsers",
            "removes the integration of Autofirma with the system and the browsers",
            "diagnoses the installation and configuration of Autofirma",
            "restores the local certificates and the afirma:// protocol handler",
        )
    } else {
        (
            "Comandos de integracion con el sistema",
            "instala la integracion de Autofirma con el sistema y los navegadores",
            "elimina la integracion de Autofirma con el sistema y los navegadores",
            "diagnostica la instalacion y la configuracion de Autofirma",
            "restaura los certificados locales y el manejador del protocolo afirma://",
        )
    };
    format!(
        "  createdigest\t (Creación de huellas digitales con interfaz gráfica)\n  checkdigest\t (Comprobación de huellas digitales con interfaz gráfica)\n\n{title}:\n\n  install\t ({install})\n  uninstall\t ({uninstall})\n  doctor\t ({doctor})\n  restore-config\t ({restore})\n"
    )
}

/// Texto que esperamos a partir del de Java (diferencias documentadas en
/// `docs/deviations/afirma-cli.md`).
fn expected_from_java(java: &str, locale: Option<&str>) -> String {
    let mut text = java.to_string();
    // 1. Ayuda general: comandos de huellas integrados y de sistema.
    if let Some(pos) = text.find("  batchsign\t (") {
        let eol = pos + text[pos..].find('\n').unwrap() + 1;
        text.insert_str(eol, &general_help_additions(locale));
    }
    // 2. `-gui` de los comandos de firma sin `CommandLineLauncher.146`: el
    //    `%0` de `.23` se sustituye y no se imprime `!CommandLineLauncher.146!`.
    text = text
        .split_inclusive('\n')
        .map(|l| {
            if l.starts_with("  -gui\t\t\t (") && l.contains(" !CommandLineLauncher.146!") {
                l.replace(" !CommandLineLauncher.146!", "")
                    .replace("%0", "-certgui")
            } else {
                l.to_string()
            }
        })
        .collect();
    // 3. Entidades HTML de los textos de validación.
    afirma_cli::messages::decode_html_entities(&text)
}

#[test]
fn ordenes_contra_el_oraculo_java() {
    let mut failures = Vec::new();
    let mut checked = 0;
    let mut signatures = 0;
    for c in load_cases() {
        if c.has("dev") || (c.flag("os") == Some("linux") && !cfg!(target_os = "linux")) {
            continue;
        }
        let (java_status, java_text) = golden(&c.name);
        let (outcome, rust_text, out) = run_case(&c);
        let expected = expected_from_java(&java_text, c.flag("locale"));
        let status_ok = os_status(outcome.status) == java_status;
        let text_ok = match c.flag("cmp").unwrap_or("exact") {
            "status" => true,
            "prefix" => rust_text.starts_with(expected.trim_end_matches('\n')),
            _ if c.has("xmlsig") => mask_sign(&rust_text) == mask_sign(&expected),
            _ => rust_text == expected,
        };
        if !status_ok || !text_ok {
            failures.push(format!(
                "{}: estado {} (Java {java_status})\n--- Rust ---\n{rust_text}--- Java ---\n{expected}",
                c.name, outcome.status
            ));
            continue;
        }
        assert!(outcome.gui.is_none(), "{}", c.name);
        // Firmas: estructura y validez frente a la de Java.
        if let Some(file) = c.flag("sig") {
            let ext = std::path::Path::new(file)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();
            let rust = std::fs::read(out.path().join(file))
                .unwrap_or_else(|_| panic!("{}: sin firma", c.name));
            let java = std::fs::read(java_dir().join(format!("{}{ext}", c.name))).unwrap();
            compare_signatures(&c.name, &java, &rust);
            dump(&c.name, &ext, &rust);
            signatures += 1;
        }
        if c.has("xmlsig") {
            let rust = xml_sign(&rust_text).unwrap_or_else(|| panic!("{}: sin <sign>", c.name));
            let java = xml_sign(&java_text).unwrap();
            compare_signatures(&c.name, &java, &rust);
            dump(&c.name, ".csig", &rust);
            signatures += 1;
        }
        checked += 1;
    }
    assert!(
        failures.is_empty(),
        "{} casos distintos de Java:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    assert!(checked > 150, "{checked}");
    assert!(signatures > 30, "{signatures}");
}
