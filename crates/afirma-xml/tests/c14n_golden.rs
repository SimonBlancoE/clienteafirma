//! Compara la canonicalización con salidas de referencia generadas con Apache
//! Santuario (el motor XMLDSig de la AutoFirma Java), mediante
//! `tools/oracle/JC14n.java`.

use afirma_xml::c14n::C14n;
use afirma_xml::dom::Document;

const ALGS: &[(&str, &str)] = &[
    ("c14n10", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
    ("c14n10c", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"),
    ("exc", "http://www.w3.org/2001/10/xml-exc-c14n#"),
    ("excc", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"),
    ("c14n11", "http://www.w3.org/2006/12/xml-c14n11"),
];

#[test]
fn matches_santuario() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/c14n-corpus");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let Some((base, rest)) = name.split_once('.') else { continue };
        let Some(rest) = rest.strip_suffix(".golden") else { continue };
        let (alg, id) = rest.split_once('.').unwrap();
        let uri = ALGS.iter().find(|(s, _)| *s == alg).unwrap().1;
        let xml = std::fs::read(dir.join(format!("{base}.xml"))).unwrap();
        let (doc, _) = Document::parse_bytes(&xml).unwrap();
        let node = if id == "doc" { doc.root() } else { doc.find_by_id(id).unwrap() };
        let got = C14n::from_uri(uri).unwrap().canonicalize(&doc, node, &[]);
        let expected = std::fs::read(&path).unwrap();
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(&expected), "{name}");
        checked += 1;
    }
    assert!(checked > 40, "solo {checked} casos");
}
