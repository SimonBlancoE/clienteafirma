//! Herramienta de pruebas: firma con los firmadores XML.
//!
//! Uso: `xsign <op> <formato> <p12> <entrada> <salida> [clave=valor...]`
//! - op: `sign`, `cosign`, `countersign-tree`, `countersign-leafs`
//! - formato: `xades`, `xmldsig`, `facturae`, `asic`, `odf`, `odf-java`, `ooxml`
//!
//! El algoritmo se indica con `algorithm=...` (por defecto `SHA256withRSA`).
use afirma_core::extra_params::ExtraParams;
use afirma_core::signer::{CounterSignTarget, Signer};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!("uso: xsign <op> <formato> <p12> <entrada> <salida> [clave=valor...]");
        std::process::exit(2);
    }
    let p12 = std::fs::read(&args[3]).expect("p12");
    let entries = afirma_keystores::pkcs12::open(&p12, "12341234").expect("pkcs12");
    let key = entries[0].signing_key().expect("clave");
    let input = std::fs::read(&args[4]).expect("entrada");
    let mut params = ExtraParams::new();
    for kv in &args[6..] {
        if let Some((k, v)) = kv.split_once('=') {
            params.set(k, v);
        }
    }
    let algorithm = params
        .remove("algorithm")
        .unwrap_or_else(|| "SHA256withRSA".into());
    let signer: Box<dyn Signer> = afirma_xml::signer_for(&args[2]).expect("formato desconocido");
    let out = match args[1].as_str() {
        "sign" => signer.sign(&input, &algorithm, &key, &params),
        "cosign" => signer.cosign(None, &input, &algorithm, &key, &params),
        "countersign-tree" => {
            signer.countersign(&input, &algorithm, &CounterSignTarget::Tree, &key, &params)
        }
        "countersign-leafs" => {
            signer.countersign(&input, &algorithm, &CounterSignTarget::Leafs, &key, &params)
        }
        other => panic!("operación desconocida: {other}"),
    };
    match out {
        Ok(o) => std::fs::write(&args[5], o).expect("salida"),
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}
