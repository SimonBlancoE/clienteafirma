//! Herramienta de depuración: canonicaliza un fichero XML.
//!
//! Uso: `c14n <uri-algoritmo> <fichero> [Id-del-nodo] [prefijos-inclusivos]`
use afirma_xml::c14n::C14n;
use afirma_xml::dom::Document;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let method = C14n::from_uri(&args[1]).expect("algoritmo desconocido");
    let method = match args.get(4) {
        Some(p) => method.with_inclusive_prefixes(p.split_whitespace().map(str::to_string)),
        None => method,
    };
    let bytes = std::fs::read(&args[2]).expect("no se puede leer el fichero");
    let (doc, _) = Document::parse_bytes(&bytes).expect("XML no válido");
    let node = match args.get(3).map(String::as_str) {
        None | Some("") => doc.root(),
        Some(id) => doc.find_by_id(id).expect("Id no encontrado"),
    };
    use std::io::Write;
    std::io::stdout()
        .write_all(&method.canonicalize(&doc, node, &[]))
        .unwrap();
}
