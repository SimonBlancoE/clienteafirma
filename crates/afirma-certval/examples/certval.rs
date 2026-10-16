//! Valida un certificado desde la línea de comandos.
//!
//! ```text
//! cargo run -p afirma-certval --example certval -- <certificado> [opciones]
//!   --issuer <fichero>   certificado del emisor (debe haberlo emitido)
//!   --chain <fichero>    certificados adicionales (PEM con varios bloques, DER o PKCS#7)
//!   --java               selección de Java (CertificateVerifierFactory)
//!   --get                consultas OCSP siempre por GET
//!   --no-crl-fallback    sin alternativa CRL si OCSP no responde
//!   --no-download        no descargar el emisor de la AIA
//!   --lax                aceptar respuestas sin verificar si no se conoce el emisor
//! ```
//!
//! Usa el cliente HTTP de AutoFirma con la configuración por defecto (proxy
//! del sistema y almacén de confianza del sistema).

use afirma_certval::{OcspHttpMethod, SelectionMode, ValidationOptions, validate_certificate_report};

fn read_certs(path: &str) -> Vec<Vec<u8>> {
    let data = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("No se puede leer {path}: {e}");
        std::process::exit(2);
    });
    let certs = afirma_certval::parse_certificates(&data);
    if certs.is_empty() {
        eprintln!("{path} no contiene certificados");
        std::process::exit(2);
    }
    certs
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut options = ValidationOptions::default();
    let mut cert = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--issuer" => options.issuer = it.next().map(|p| read_certs(p).remove(0)),
            "--chain" => {
                if let Some(p) = it.next() {
                    options.chain.extend(read_certs(p));
                }
            }
            "--java" => options.selection = SelectionMode::JavaFactory,
            "--get" => options.ocsp_method = OcspHttpMethod::Get,
            "--no-crl-fallback" => options.crl_fallback = false,
            "--no-download" => options.download_issuer = false,
            "--lax" => options.require_verified_revocation = false,
            "-h" | "--help" => {
                println!(
                    "uso: certval <certificado> [--issuer f] [--chain f]... [--java] [--get] [--no-crl-fallback] [--no-download] [--lax]"
                );
                return;
            }
            other => cert = Some(other.to_string()),
        }
    }
    let Some(cert) = cert else {
        eprintln!("Falta el certificado (use --help)");
        std::process::exit(2);
    };
    // Un PEM con la cadena completa: el primero es el certificado y el resto
    // se añaden a la cadena.
    let mut certs = read_certs(&cert);
    let leaf = certs.remove(0);
    options.chain.extend(certs);

    if let Some(id) = afirma_certval::java_issuer_identifier(&leaf) {
        println!("Identificador de emisor (Java): {id}");
    }
    let report = validate_certificate_report(&leaf, &options);
    println!(
        "Resultado:   {} ({}, codigo {})",
        report.result.name(),
        report.result,
        report.result.code()
    );
    println!("Dialogo:     {}: {}", report.dialog_title(), report.dialog_message());
    println!("Metodo:      {:?}", report.method);
    println!("Emisor:      {:?}", report.issuer_source);
    if let Some(rev) = &report.revocation {
        println!(
            "Revocacion:  {} ({})",
            rev.time
                .map(|t| t.to_rfc3339())
                .unwrap_or_else(|| "fecha desconocida".into()),
            rev.reason.map(|r| r.description()).unwrap_or("sin motivo")
        );
    }
    println!("Comprobado:  {}", report.checked_at.to_rfc3339());
    if let Some(d) = &report.detail {
        println!("Detalle:");
        for l in d.lines() {
            println!("  - {l}");
        }
    }
    std::process::exit(if report.is_ok() { 0 } else { 1 });
}
