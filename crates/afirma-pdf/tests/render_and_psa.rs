//! Renderizado de páginas (vista previa de la interfaz) y detección de
//! ataques de sombra sobre documentos generados.
#![cfg(feature = "render")]

mod common;

use afirma_core::validity::{Validity, ValidityError};
use afirma_core::{ExtraParams, Signer};
use afirma_pdf::PadesSigner;
use afirma_pdf::pdf::doc::PdfDoc;
use afirma_pdf::pdf::parse::XrefKind;
use afirma_pdf::pdf::write::{TrailerInfo, Update};
use afirma_pdf::render::RenderDocument;
use afirma_pdf::validate::validate_pdf;
use common::{TestKey, java_resource, params};
use lopdf::{Dictionary, Object, StringFormat};

fn sign_at(pdf: &[u8], llx: &str, lly: &str, urx: &str, ury: &str) -> Vec<u8> {
    PadesSigner::new()
        .sign(
            pdf,
            "SHA256withRSA",
            &TestKey::rsa(),
            &params(&[
                ("signaturePositionOnPageLowerLeftX", llx),
                ("signaturePositionOnPageLowerLeftY", lly),
                ("signaturePositionOnPageUpperRightX", urx),
                ("signaturePositionOnPageUpperRightY", ury),
            ]),
        )
        .unwrap()
}

/// Añade una revisión sin firmar que cambia el título del documento.
fn touch_info(pdf: &[u8]) -> Vec<u8> {
    let doc = PdfDoc::open(pdf, None).unwrap();
    let mut up = Update::new(doc.size);
    let mut info = Dictionary::new();
    info.set("Title", Object::String(b"Cambiado".to_vec(), StringFormat::Literal));
    let id = up.alloc();
    up.put(id, Object::Dictionary(info));
    let kind = if doc.xref_kind == XrefKind::Stream {
        XrefKind::Stream
    } else {
        XrefKind::Table
    };
    let t = TrailerInfo {
        root: doc.root_id(),
        info: Some(id),
        encrypt: None,
        id: doc.file_id(),
    };
    up.write(pdf, doc.startxref, kind, &t, None, doc.pdf_start).bytes
}

#[test]
fn renders_signed_page_with_appearance() {
    let signed = sign_at(&java_resource("TEST_PDF.pdf"), "100", "100", "300", "180");
    let doc = RenderDocument::open(&signed, None).unwrap();
    assert_eq!(doc.page_count(), 1);
    let (w, h) = doc.page_size(0).unwrap();
    assert!((w - 595.0).abs() < 1.0 && (h - 842.0).abs() < 1.0);
    let img = doc.render_page(0, 1.0).unwrap();
    assert_eq!((img.width, img.height), (595, 842));
    // Hay tinta dentro del recuadro de la firma (100..300 x 662..742 desde arriba).
    let gray = img.to_gray();
    let dark = (662..742)
        .flat_map(|y| (100..300).map(move |x| (x, y)))
        .filter(|(x, y)| gray[y * 595 + x] < 128)
        .count();
    assert!(dark > 200, "píxeles oscuros: {dark}");
    assert!(img.to_png().unwrap().starts_with(b"\x89PNG"));
    // Páginas giradas: el tamaño mostrado intercambia ancho y alto.
    let rotated = std::fs::read(common::testdata("rotated_pages.pdf")).unwrap();
    let r = RenderDocument::open(&rotated, None).unwrap();
    let (w1, h1) = r.page_size(1).unwrap();
    assert!(w1 > h1, "la página 2 está girada 90º");
    let info = afirma_pdf::info::PdfInfo::open(&rotated, None).unwrap();
    assert_eq!(
        info.pages.iter().map(|p| p.rotation).collect::<Vec<_>>(),
        vec![0, 90, 180, 270, 0]
    );
    assert_eq!(info.pages[1].rounded_size(), (w1.round() as i64, h1.round() as i64));
}

#[test]
fn renders_encrypted_documents() {
    let pdf = std::fs::read(common::testdata("encrypted_aes256.pdf")).unwrap();
    let doc = RenderDocument::open(&pdf, Some("owner")).unwrap();
    assert!(doc.render_page_dpi(0, 40.0).is_ok());
}

#[test]
fn shadow_attack_and_overlap_detection() {
    let pdf = java_resource("TEST_PDF.pdf");
    // Cambio posterior a la firma sin efecto visual: sin aviso.
    let signed = sign_at(&pdf, "100", "100", "300", "180");
    let touched = touch_info(&signed);
    let v = validate_pdf(&touched, &ExtraParams::new(), false).unwrap();
    assert_eq!(v[0].validity, Validity::Ok, "{v:?}");
    // Dos firmas visibles solapadas y un cambio posterior: aviso de solape.
    let two = sign_at(&signed, "150", "120", "350", "200");
    let touched = touch_info(&two);
    let v = validate_pdf(&touched, &ExtraParams::new(), false).unwrap();
    assert_eq!(
        (v[0].validity, v[0].error),
        (Validity::Ko, Some(ValidityError::OverlappingSignature)),
        "{v:?}"
    );
    // Firmas que no se solapan: sin aviso.
    let apart = sign_at(&signed, "350", "100", "550", "180");
    let v = validate_pdf(&touch_info(&apart), &ExtraParams::new(), false).unwrap();
    assert_eq!(v[0].validity, Validity::Ok, "{v:?}");
    // Una firma visible añadida tras la última firma cambia el aspecto.
    let mut doc_with_unsigned_change = signed.clone();
    {
        let doc = PdfDoc::open(&signed, None).unwrap();
        let page = doc.pages()[0];
        let mut up = Update::new(doc.size);
        let mut pd = doc.dict_id(page).unwrap().clone();
        let content_id = up.alloc();
        up.put(
            content_id,
            Object::Stream(afirma_pdf::pdf::write::flate_stream(
                Dictionary::new(),
                b"0 0 1 rg 50 50 200 200 re f\n",
            )),
        );
        let mut contents = match pd.get(b"Contents").unwrap() {
            Object::Array(a) => a.clone(),
            o => vec![o.clone()],
        };
        contents.push(Object::Reference(content_id));
        pd.set("Contents", Object::Array(contents));
        up.put(page, Object::Dictionary(pd));
        let kind = if doc.xref_kind == XrefKind::Stream {
            XrefKind::Stream
        } else {
            XrefKind::Table
        };
        let t = TrailerInfo {
            root: doc.root_id(),
            info: doc.info_id(),
            encrypt: None,
            id: doc.file_id(),
        };
        doc_with_unsigned_change = up
            .write(&doc_with_unsigned_change, doc.startxref, kind, &t, None, doc.pdf_start)
            .bytes;
    }
    let v = validate_pdf(&doc_with_unsigned_change, &ExtraParams::new(), false).unwrap();
    assert_eq!(
        (v[0].validity, v[0].error),
        (Validity::Ko, Some(ValidityError::ModifiedDocument)),
        "{v:?}"
    );
    let e = validate_pdf(&doc_with_unsigned_change, &ExtraParams::new(), true).unwrap_err();
    assert_eq!(e.code.unwrap().code, 212008);
}

#[test]
fn appearance_preview_for_the_gui() {
    let key = TestKey::rsa();
    let chain = afirma_core::SigningKey::certificate_chain(&key);
    let img = afirma_pdf::render::preview_appearance(
        200,
        80,
        &params(&[("layer2Text", "Firmado por $$SUBJECTCN$$"), ("layer2FontColor", "red")]),
        &chain,
        None,
        2.0,
    )
    .unwrap();
    assert_eq!((img.width, img.height), (400, 160));
    // Texto rojo en la parte superior izquierda.
    let red = img
        .data
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|p| p[0] > 200 && p[1] < 80 && p[2] < 80)
        .count();
    assert!(red > 100, "píxeles rojos: {red}");
    // Sin certificado (como la vista previa de Java) se muestran las etiquetas.
    assert!(afirma_pdf::render::preview_appearance(200, 80, &params(&[]), &[], None, 1.0).is_ok());
}
