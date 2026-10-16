//! Herramienta de pruebas manuales y diferenciales de afirma-pdf.
//!
//! ```text
//! cargo run --example pades -- sign ALGORITMO CLAVE entrada.pdf salida.pdf [clave=valor ...]
//! cargo run --example pades -- tree entrada.pdf
//! cargo run --example pades -- validate entrada.pdf [relaxed] [clave=valor ...]
//! cargo run --example pades -- render entrada.pdf PAGINA ESCALA salida.png
//! cargo run --example pades -- fields entrada.pdf
//! ```
//! `CLAVE` es el nombre de una clave de `testdata/pki` (`firmante-rsa`,
//! `firmante-ec`). Los valores `@fichero` se sustituyen por el Base64 del
//! fichero y `\n` por un salto de línea.

#[path = "../tests/common/mod.rs"]
mod common;

use afirma_core::{ExtraParams, Signer};
use afirma_pdf::PadesSigner;

fn props(args: &[String]) -> ExtraParams {
    let mut xp = ExtraParams::new();
    for a in args {
        let Some((k, v)) = a.split_once('=') else {
            continue;
        };
        let mut v = v.replace("\\n", "\n");
        if let Some(f) = v.strip_prefix('@') {
            v = afirma_core::base64_encode(&std::fs::read(f).expect("fichero"));
        }
        xp.set(k, v);
    }
    xp
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sign") => {
            let key = common::TestKey::load(&args[2]);
            let data = std::fs::read(&args[3]).expect("entrada");
            let mut signer = PadesSigner::new();
            let xp = props(&args[5..]);
            if xp.get("__mockTsa").is_some() {
                let tsa_key = std::fs::read_to_string(common::pki("tsa.key")).unwrap();
                let pem = std::fs::read_to_string(common::pki("tsa.crt")).unwrap();
                let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
                let cert = afirma_core::base64_decode_lenient(&b64).unwrap();
                let mock = afirma_pdf::tsp::mock::MockTsa::new(&tsa_key, cert).unwrap();
                signer = signer.with_tsa_transport(std::sync::Arc::new(mock));
            }
            match signer.sign(&data, &args[1], &key, &xp) {
                Ok(out) => {
                    std::fs::write(&args[4], &out).expect("salida");
                    println!("OK {}", out.len());
                }
                Err(e) => {
                    println!("ERROR {e} {:?}", e.kind);
                    std::process::exit(2);
                }
            }
        }
        Some("tree") => {
            let data = std::fs::read(&args[1]).expect("entrada");
            let tree = afirma_pdf::pades::signers_structure(&data, &props(&args[2..]));
            for s in tree.signers {
                println!(
                    "{} | {:?} | {:?}",
                    s.info.signer_name(),
                    s.info.signing_time,
                    s.info.sign_algorithm
                );
            }
        }
        Some("validate") => {
            let data = std::fs::read(&args[1]).expect("entrada");
            let relaxed = args.get(2).is_some_and(|a| a == "relaxed");
            let xp = props(&args[if relaxed { 3 } else { 2 }..]);
            match afirma_pdf::validate::validate_pdf(&data, &xp, relaxed) {
                Ok(list) => {
                    for v in list {
                        println!(
                            "{:?} {:?}{}",
                            v.validity,
                            v.error,
                            v.detail.as_ref().map(|d| format!(" ({d})")).unwrap_or_default()
                        );
                    }
                }
                Err(e) => println!("NEEDS {e} {:?}", e.kind),
            }
        }
        #[cfg(feature = "render")]
        Some("render") => {
            let data = std::fs::read(&args[1]).expect("entrada");
            let page: usize = args[2].parse().unwrap();
            let scale: f32 = args[3].parse().unwrap();
            let doc = afirma_pdf::render::RenderDocument::open(&data, None).expect("pdf");
            let img = doc.render_page(page, scale).expect("render");
            img.save_png(&args[4]).expect("png");
            println!("OK {}x{}", img.width, img.height);
        }
        Some("fields") => {
            let data = std::fs::read(&args[1]).expect("entrada");
            let info = afirma_pdf::info::PdfInfo::open(&data, None).expect("pdf");
            for p in &info.pages {
                println!("pagina {:?}", p);
            }
            for f in &info.empty_signature_fields {
                println!("campo vacio {:?}", f);
            }
            for f in &info.signature_fields {
                println!("firma {:?}", f);
            }
        }
        Some("debug") => {
            let data = std::fs::read(&args[1]).expect("entrada");
            let doc = afirma_pdf::pdf::doc::PdfDoc::open(&data, args.get(2).map(String::as_str)).expect("pdf");
            println!(
                "version={} startxref={:?} kind={:?} broken={} encrypted={} owner={} size={} pages={}",
                doc.header_version,
                doc.startxref,
                doc.xref_kind,
                doc.broken,
                doc.encrypted,
                doc.owner_access,
                doc.size,
                doc.page_count()
            );
            if std::env::var("PADES_DEBUG_OBJS").is_ok() {
                println!("catalogo {:?}", doc.catalog());
                println!("acroform {:?}", doc.acroform());
                for p in doc.pages() {
                    println!("pagina {:?} {:?}", p, doc.dict_id(p));
                }
                for (k, v) in doc.doc.reference_table.entries.iter() {
                    println!("xref {k} {v:?}");
                }
            }
            for f in doc.form_fields() {
                println!("campo {} pagina {} widget {:?}", f.name, f.page, f.widget_id);
            }
            let (sigs, total) = doc.signatures();
            println!("revisiones {total}");
            for s in sigs {
                println!(
                    "firma {} rev {} cubre {} br {:?}",
                    s.name,
                    s.revision,
                    s.covered,
                    s.byte_range()
                );
            }
        }
        _ => eprintln!("uso: pades sign|tree|validate|render|fields|debug ..."),
    }
}
