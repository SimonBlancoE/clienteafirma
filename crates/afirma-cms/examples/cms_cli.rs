//! Línea de comandos de pruebas con la misma interfaz que
//! `tools/oracle/CmsOracle.java`, para comparar con la versión Java:
//!
//! ```text
//! cms_cli sign FORMATO ALGORITMO almacen.p12 datos salida [clave=valor ...]
//! cms_cli cosign FORMATO ALGORITMO almacen.p12 firma datos|- salida [clave=valor ...]
//! cms_cli countersign FORMATO ALGORITMO almacen.p12 firma tree|leafs|nodes|signers objetivos|- salida [clave=valor ...]
//! cms_cli tree FORMATO firma
//! cms_cli getdata FORMATO firma salida
//! cms_cli issign firma
//! cms_cli signinfo FORMATO firma
//! cms_cli validate firma [datos]
//! ```
#![allow(clippy::result_large_err)]

use afirma_cms::{CadesAsicsSigner, CadesSigner, CmsSigner};
use afirma_core::{CounterSignTarget, ExtraParams, Signer};

fn signer(format: &str) -> Box<dyn Signer> {
    match format {
        "CAdES" => Box::new(CadesSigner),
        "CMS/PKCS#7" => Box::new(CmsSigner),
        "CAdES-ASiC-S" => Box::new(CadesAsicsSigner),
        other => panic!("formato desconocido: {other}"),
    }
}

fn props(args: &[String]) -> ExtraParams {
    let mut p = ExtraParams::new();
    for a in args {
        let (k, v) = a.split_once('=').expect("clave=valor");
        p.set(k, v.replace("\\n", "\n"));
    }
    p
}

fn key(p12: &str) -> afirma_keystores::SoftwareKey {
    let entries = afirma_keystores::pkcs12::open(&std::fs::read(p12).expect("p12"), "12341234").expect("p12");
    entries[0].signing_key().expect("clave")
}

fn run(a: &[String]) -> afirma_core::Result<()> {
    match a[0].as_str() {
        "sign" => {
            let out = signer(&a[1]).sign(&std::fs::read(&a[4]).unwrap(), &a[2], &key(&a[3]), &props(&a[6..]))?;
            std::fs::write(&a[5], &out).unwrap();
            println!("OK {}", out.len());
        }
        "cosign" => {
            let data = if a[5] == "-" {
                None
            } else {
                Some(std::fs::read(&a[5]).unwrap())
            };
            let out = signer(&a[1]).cosign(
                data.as_deref(),
                &std::fs::read(&a[4]).unwrap(),
                &a[2],
                &key(&a[3]),
                &props(&a[7..]),
            )?;
            std::fs::write(&a[6], &out).unwrap();
            println!("OK {}", out.len());
        }
        "countersign" => {
            let mut target = CounterSignTarget::from_name(&a[5]).expect("objetivo");
            if a[6] != "-" {
                target = match target {
                    CounterSignTarget::Nodes(_) => {
                        CounterSignTarget::Nodes(a[6].split(',').map(|n| n.trim().parse().unwrap()).collect())
                    }
                    CounterSignTarget::Signers(_) => {
                        CounterSignTarget::Signers(a[6].split('|').map(String::from).collect())
                    }
                    t => t,
                };
            }
            let out = signer(&a[1]).countersign(
                &std::fs::read(&a[4]).unwrap(),
                &a[2],
                &target,
                &key(&a[3]),
                &props(&a[8..]),
            )?;
            std::fs::write(&a[7], &out).unwrap();
            println!("OK {}", out.len());
        }
        "tree" => {
            let tree = signer(&a[1]).signers_structure(&std::fs::read(&a[2]).unwrap(), &ExtraParams::new())?;
            print!("NAMES{}", tree.to_text("", "\t"));
            println!();
            let mut infos = String::new();
            for (depth, n) in tree.preorder() {
                infos.push('\n');
                infos.push_str(&"\t".repeat(depth));
                infos.push_str(&format!(
                    "{} | {} | {} | {}",
                    n.info.signer_name(),
                    n.info.sign_algorithm.clone().unwrap_or_default(),
                    n.info
                        .signing_time
                        .map(|t| t.timestamp().to_string())
                        .unwrap_or_else(|| "null".into()),
                    n.info.pkcs1.len()
                ));
            }
            println!("INFOS{infos}");
        }
        "getdata" => match signer(&a[1]).get_data(&std::fs::read(&a[2]).unwrap(), &ExtraParams::new())? {
            Some(d) => {
                std::fs::write(&a[3], &d).unwrap();
                println!("OK {}", d.len());
            }
            None => println!("NULL"),
        },
        "issign" => {
            let s = std::fs::read(&a[1]).unwrap();
            for f in ["CAdES", "CMS/PKCS#7", "CAdES-ASiC-S"] {
                println!("{f} {}", signer(f).is_sign(&s, &ExtraParams::new()));
            }
        }
        "summary" => {
            print!(
                "{}",
                afirma_cms::inspect::structure_summary(&std::fs::read(&a[1]).unwrap())?
            );
        }
        "signinfo" => {
            println!(
                "FORMAT {}",
                signer(&a[1])
                    .sign_info(&std::fs::read(&a[2]).unwrap(), &ExtraParams::new())?
                    .format
            );
        }
        "validate" => {
            let s = std::fs::read(&a[1]).unwrap();
            let d = a.get(2).map(|p| std::fs::read(p).unwrap());
            for v in afirma_cms::validation::validate(&s, d.as_deref(), true) {
                println!(
                    "VALIDITY {:?} {:?} {}",
                    v.validity,
                    v.error,
                    v.detail.unwrap_or_default()
                );
            }
        }
        other => panic!("operación desconocida: {other}"),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        println!("ERROR {e}");
        if let Some(c) = e.code {
            println!("CODE {}", c.code);
        }
        std::process::exit(2);
    }
}
