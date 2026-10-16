//! TSA de pruebas por HTTP: `mock_tsa almacen.p12 [peticiones]`. Escribe la URL
//! en la salida estándar y atiende el número de peticiones indicado.

use std::io::Write;
use std::sync::Arc;

use afirma_cms::tsp::mock::MockTsa;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let p12 = std::fs::read(&args[0]).expect("p12");
    let n: usize = args.get(1).and_then(|n| n.parse().ok()).unwrap_or(10);
    let key = afirma_keystores::pkcs12::open(&p12, "12341234").expect("p12")[0].signing_key().expect("clave");
    let (url, handle) = Arc::new(MockTsa::new(Box::new(key))).serve_http(n, None);
    println!("{url}");
    std::io::stdout().flush().ok();
    handle.join().ok();
}
