//! TSA de pruebas (RFC 3161 sobre HTTP) con la clave `testdata/pki/tsa.p12`.
//! Imprime la URL y atiende `n` peticiones (por defecto 10).
use std::sync::Arc;

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    let p12 = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/pki/tsa.p12")).expect("tsa.p12");
    let key = afirma_keystores::pkcs12::open(&p12, "12341234").expect("pkcs12")[0]
        .signing_key()
        .expect("clave");
    let tsa = Arc::new(afirma_cms::tsp::mock::MockTsa::new(Box::new(key)));
    let (url, handle) = tsa.serve_http(n, None);
    println!("{url}");
    use std::io::Write;
    std::io::stdout().flush().ok();
    handle.join().ok();
}
