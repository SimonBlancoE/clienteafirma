//! Firmas XMLDSig con la transformada XSLT generadas por el JDK
//! (`javax.xml.crypto.dsig` con `XSLTTransformParameterSpec`, ver
//! `tools/oracle/xslt/XsltOracle.java`, modo `sign`) y comprobadas por el
//! propio JDK sin validación segura. Aquí se validan con la API pública y se
//! comprueban los límites de seguridad del procesador XSLT.

use afirma_core::validity::{SignValidity, Validity, ValidityError};
use afirma_xml::dom::Document;
use afirma_xml::dsig::{self, DSIG_NS, NoResolver, RefOptions};
use afirma_xml::validation;
use afirma_xml::xslt::{Limits, XsltError, transform_stylesheet};

mod common;

const VECTORS: &[&str] = &[
    "enveloped-xslt",
    "enveloped-xslt-c14n",
    "object-text-html",
    "xpath-xslt",
    "id-enveloped-xslt-utf16",
    "xslt-xslt-exc-c14n",
];

fn vector(name: &str) -> Vec<u8> {
    common::read(&format!("testdata/xslt/signed/{name}.xml"))
}

fn allow() -> RefOptions {
    RefOptions::allow_xslt()
}

#[test]
fn jdk_vectors_are_valid_without_secure_validation() {
    let dir = common::root().join("testdata/xslt/signed");
    let count = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(count, VECTORS.len(), "vectores en {}", dir.display());
    for name in VECTORS {
        let v = validation::validate_with(&vector(name), true, &NoResolver, allow());
        assert_eq!(v, vec![SignValidity::ok()], "{name}");
        // Núcleo XMLDSig: valor de firma y cada referencia.
        let bytes = vector(name);
        let doc = Document::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
        let sig = doc.find_descendants(doc.root(), DSIG_NS, "Signature")[0];
        let core = dsig::validate_core_with(&doc, sig, &NoResolver, None, allow()).unwrap();
        assert!(core.signature_value, "{name}");
        assert!(!core.references.is_empty(), "{name}");
        assert!(
            core.references.iter().all(|(_, ok)| *ok),
            "{name}: {:?}",
            core.references
        );
    }
}

#[test]
fn secure_validation_rejects_xslt_like_autofirma() {
    // AutoFirma 1.9 (Santuario 3.0.5, validación segura activa por defecto)
    // informa estas firmas como mal construidas.
    for name in VECTORS {
        let v = validation::validate(&vector(name), true, &NoResolver);
        assert_eq!(v.len(), 1, "{name}: {v:?}");
        assert_eq!(v[0].validity, Validity::Ko, "{name}");
        assert_eq!(v[0].error, Some(ValidityError::BadBuildSign), "{name}");
        assert!(
            v[0].detail.as_deref().unwrap_or("").contains("validación segura"),
            "{name}: {v:?}"
        );
    }
}

fn tampered(name: &str, from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8(vector(name)).unwrap();
    assert!(text.contains(from), "{name}: no contiene {from}");
    text.replacen(from, to, 1).into_bytes()
}

#[test]
fn tampered_data_is_detected() {
    // Cambia un dato que la hoja lleva a la salida: la referencia no coincide.
    // (La hoja de `id-enveloped-xslt-utf16` solo saca la longitud del texto.)
    for name in VECTORS {
        let (from, to) = match *name {
            "id-enveloped-xslt-utf16" => (">Tornillos<", ">Tornillo<"),
            _ => ("precio=\"10.50\"", "precio=\"10.51\""),
        };
        let bad = tampered(name, from, to);
        let v = validation::validate_with(&bad, false, &NoResolver, allow());
        assert_eq!(v[0].validity, Validity::Ko, "{name}: {v:?}");
        assert_eq!(v[0].error, Some(ValidityError::NoMatchData), "{name}: {v:?}");
    }
    // Cambiar la hoja altera SignedInfo (valor de firma incorrecto).
    let bad = tampered("enveloped-xslt", "data-type=\"number\"", "data-type=\"text\"");
    let v = validation::validate_with(&bad, false, &NoResolver, allow());
    assert_eq!(v[0].error, Some(ValidityError::NoMatchData), "{v:?}");
}

#[test]
fn only_the_transform_output_is_signed() {
    // La hoja de `enveloped-xslt` no saca la nota ni el comentario: cambiarlos
    // no invalida la firma (es la semántica de la transformada XSLT).
    let bad = tampered("enveloped-xslt", "  texto   con  espacios ", "otro texto");
    assert_eq!(
        validation::validate_with(&bad, false, &NoResolver, allow()),
        vec![SignValidity::ok()]
    );
    // En `object-text-html` la nota sí forma parte de la salida de texto.
    let bad = tampered("object-text-html", "  texto   con  espacios ", "otro texto");
    let v = validation::validate_with(&bad, false, &NoResolver, allow());
    assert_eq!(v[0].error, Some(ValidityError::NoMatchData), "{v:?}");
}

fn run(xsl: &str, input: &str, limits: &Limits) -> Result<Vec<u8>, XsltError> {
    let doc = Document::parse(xsl).unwrap();
    let root = doc.document_element().unwrap();
    transform_stylesheet(&doc, root, input.as_bytes(), limits)
}

const XSL: &str = "xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"";

#[test]
fn recursion_is_limited() {
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><xsl:call-template name=\"f\"/></xsl:template>\
         <xsl:template name=\"f\"><x><xsl:call-template name=\"f\"/></x></xsl:template></xsl:stylesheet>"
    );
    let e = run(&xsl, "<a/>", &Limits::default()).unwrap_err();
    assert!(matches!(e, XsltError::Limit(_)), "{e:?}");
    // También la recursión de apply-templates sobre el mismo nodo.
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><xsl:apply-templates select=\".\" mode=\"m\"/></xsl:template>\
         <xsl:template match=\"/\" mode=\"m\"><xsl:apply-templates select=\".\" mode=\"m\"/></xsl:template></xsl:stylesheet>"
    );
    assert!(matches!(
        run(&xsl, "<a/>", &Limits::default()),
        Err(XsltError::Limit(_))
    ));
    // Una recursión razonable sigue funcionando.
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><r><xsl:call-template name=\"f\"><xsl:with-param name=\"n\" select=\"200\"/></xsl:call-template></r></xsl:template>\
         <xsl:template name=\"f\"><xsl:param name=\"n\"/><xsl:if test=\"$n &gt; 0\">.<xsl:call-template name=\"f\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template></xsl:if></xsl:template></xsl:stylesheet>"
    );
    let out = run(&xsl, "<a/>", &Limits::default()).unwrap();
    assert!(out.ends_with(format!("<r>{}</r>", ".".repeat(200)).as_bytes()));
}

#[test]
fn work_and_output_are_limited() {
    // Duplicación exponencial del resultado: 2^40 nodos.
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><xsl:call-template name=\"d\"><xsl:with-param name=\"n\" select=\"40\"/></xsl:call-template></xsl:template>\
         <xsl:template name=\"d\"><xsl:param name=\"n\"/><xsl:choose><xsl:when test=\"$n = 0\"><x>abcdefgh</x></xsl:when><xsl:otherwise>\
         <xsl:call-template name=\"d\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template>\
         <xsl:call-template name=\"d\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template></xsl:otherwise></xsl:choose></xsl:template></xsl:stylesheet>"
    );
    let small = Limits {
        max_output: 1 << 16,
        ..Limits::default()
    };
    assert!(matches!(run(&xsl, "<a/>", &small), Err(XsltError::Limit(_))));
    let few_steps = Limits {
        max_steps: 100_000,
        ..Limits::default()
    };
    assert!(matches!(run(&xsl, "<a/>", &few_steps), Err(XsltError::Limit(_))));
    // Fragmentos de árbol gigantes en variables (sin salida).
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><xsl:call-template name=\"v\"><xsl:with-param name=\"n\" select=\"30\"/></xsl:call-template></xsl:template>\
         <xsl:template name=\"v\"><xsl:param name=\"n\"/><xsl:variable name=\"t\"><xsl:if test=\"$n &gt; 0\">\
         <xsl:call-template name=\"v\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template>\
         <xsl:call-template name=\"v\"><xsl:with-param name=\"n\" select=\"$n - 1\"/></xsl:call-template></xsl:if><e/></xsl:variable>\
         <xsl:value-of select=\"count(document('')) + string-length($t)\"/></xsl:template></xsl:stylesheet>"
    );
    let few_nodes = Limits {
        max_nodes: 10_000,
        ..Limits::default()
    };
    assert!(matches!(run(&xsl, "<a/>", &few_nodes), Err(XsltError::Limit(_))));
}

#[test]
fn no_external_resources() {
    for (body, what) in [
        (
            "<xsl:copy-of select=\"document('file:///etc/passwd')\"/>",
            "document(file)",
        ),
        (
            "<xsl:copy-of select=\"document('http://127.0.0.1:9/x.xml')\"/>",
            "document(http)",
        ),
        ("<xsl:copy-of select=\"document('x.xml')\"/>", "document(relativo)"),
    ] {
        let xsl = format!(
            "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><r>{body}</r></xsl:template></xsl:stylesheet>"
        );
        assert!(
            matches!(run(&xsl, "<a/>", &Limits::default()), Err(XsltError::Runtime(_))),
            "{what}"
        );
    }
    for href in ["file:///etc/passwd", "http://127.0.0.1:9/x.xsl", "otra.xsl"] {
        for el in ["include", "import"] {
            let xsl = format!(
                "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:{el} href=\"{href}\"/><xsl:template match=\"/\"><r/></xsl:template></xsl:stylesheet>"
            );
            assert!(
                matches!(run(&xsl, "<a/>", &Limits::default()), Err(XsltError::Compile(_))),
                "{el} {href}"
            );
        }
    }
    // DTD externa y entidades externas en la entrada.
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL}><xsl:template match=\"/\"><r><xsl:value-of select=\".\"/></r></xsl:template></xsl:stylesheet>"
    );
    for input in [
        "<!DOCTYPE a SYSTEM \"file:///etc/passwd\"><a/>",
        "<!DOCTYPE a [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><a>&e;</a>",
    ] {
        assert!(run(&xsl, input, &Limits::default()).is_err(), "{input}");
    }
    // Sin funciones de extensión de Java.
    let xsl = format!(
        "<xsl:stylesheet version=\"1.0\" {XSL} xmlns:rt=\"http://xml.apache.org/xalan/java/java.lang.Runtime\"><xsl:template match=\"/\"><r><xsl:value-of select=\"rt:exec(rt:getRuntime(), 'true')\"/></r></xsl:template></xsl:stylesheet>"
    );
    assert!(run(&xsl, "<a/>", &Limits::default()).is_err());
}

#[test]
fn limits_apply_inside_signature_validation() {
    // Una hoja que no termina dentro de una firma: la validación acaba con
    // un error (firma mal construida) en lugar de colgarse.
    let mut text = String::from_utf8(vector("enveloped-xslt")).unwrap();
    let start = text.find("<xsl:template match=\"/\">").unwrap();
    let end = text.find("</xsl:stylesheet>").unwrap();
    text.replace_range(
        start..end,
        "<xsl:template match=\"/\"><xsl:apply-templates select=\".\"/></xsl:template>",
    );
    let options = RefOptions {
        secure_validation: false,
        xslt_limits: Limits {
            max_steps: 1_000_000,
            ..Limits::default()
        },
    };
    let v = validation::validate_with(text.as_bytes(), false, &NoResolver, options);
    // El valor de firma ya no coincide (SignedInfo cambiado), así que Java
    // también evalúa las referencias: la transformada aborta la validación.
    assert!(v.iter().any(|s| s.error == Some(ValidityError::BadBuildSign)), "{v:?}");
}
