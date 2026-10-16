//! Pruebas de firma PAdES de extremo a extremo.

mod common;

use std::sync::Arc;

use afirma_core::error::{ErrorKind, UserIntervention, codes};
use afirma_core::validity::{Validity, ValidityError};
use afirma_core::{ExtraParams, Signer};
use afirma_pdf::PadesSigner;
use afirma_pdf::cms;
use afirma_pdf::pdf::doc::PdfDoc;
use afirma_pdf::validate::validate_pdf;
use common::{TestKey, java_resource, params, testdata};

const POS: [(&str, &str); 4] = [
    ("signaturePositionOnPageLowerLeftX", "100"),
    ("signaturePositionOnPageLowerLeftY", "100"),
    ("signaturePositionOnPageUpperRightX", "300"),
    ("signaturePositionOnPageUpperRightY", "180"),
];

fn sign(pdf: &[u8], xp: &ExtraParams) -> Vec<u8> {
    PadesSigner::new()
        .sign(pdf, "SHA256withRSA", &TestKey::rsa(), xp)
        .expect("firma")
}

fn validity(pdf: &[u8], xp: &ExtraParams) -> Vec<(Validity, Option<ValidityError>)> {
    validate_pdf(pdf, xp, false)
        .unwrap()
        .into_iter()
        .map(|v| (v.validity, v.error))
        .collect()
}

fn visible(extra: &[(&str, &str)]) -> ExtraParams {
    let mut v: Vec<(&str, &str)> = POS.to_vec();
    v.extend_from_slice(extra);
    params(&v)
}

#[test]
fn default_signature_structure() {
    let original = java_resource("TEST_PDF.pdf");
    let out = sign(&original, &params(&[("signTime", "2026:10:16:13:36:29")]));
    // Actualización incremental: el original es prefijo exacto.
    assert_eq!(&out[..original.len()], &original[..]);
    let doc = PdfDoc::open(&out, None).unwrap();
    let (sigs, total) = doc.signatures();
    assert_eq!((sigs.len(), total), (1, 1));
    let s = &sigs[0];
    assert_eq!(s.name, "Signature1");
    assert_eq!(s.sub_filter().unwrap(), b"ETSI.CAdES.detached");
    assert_eq!(s.dict.get(b"Filter").unwrap().as_name().unwrap(), b"Adobe.PPKLite");
    assert_eq!(
        s.dict.get(b"Name").unwrap().as_str().unwrap(),
        "ESPAÑOL ESPAÑOL JUAN - 00000000T"
            .chars()
            .map(|c| c as u8)
            .collect::<Vec<_>>()
    );
    let m = String::from_utf8(s.dict.get(b"M").unwrap().as_str().unwrap().to_vec()).unwrap();
    assert!(m.starts_with("D:20261016133629"), "{m}");
    // /Contents de 54002 bytes y /ByteRange de 80 bytes como Java.
    let br = s.byte_range();
    assert_eq!(br[0], 0);
    assert_eq!(br[2] - br[1], 54002);
    assert_eq!((br[2] + br[3]) as usize, out.len());
    let raw = String::from_utf8_lossy(&out[out.len() - 60000..]).into_owned();
    let pos = raw.find("/ByteRange [").unwrap();
    assert_eq!(&raw[pos + 11..pos + 12], "[");
    assert_eq!(raw[pos + 11..pos + 91].trim_end().chars().last(), Some(']'));
    // CMS: contentType, messageDigest y signingCertificateV2 (sin signingTime).
    let sd = cms::parse_signed_data(&s.contents()).unwrap();
    let si = &sd.signer_infos[0];
    let oids: Vec<&str> = si.signed_attrs.iter().map(|a| a.oid.as_str()).collect();
    assert_eq!(oids.len(), 3);
    for o in [
        cms::OID_CONTENT_TYPE,
        cms::OID_MESSAGE_DIGEST,
        cms::OID_SIGNING_CERTIFICATE_V2,
    ] {
        assert!(oids.contains(&o), "{o}");
    }
    assert_eq!(si.signature_alg_oid, cms::OID_RSA_ENCRYPTION);
    assert_eq!(si.algorithm_name(), "SHA256withRSA");
    assert_eq!(sd.certificates.len(), 2);
    assert_eq!(
        validity(&out, &params(&[("checkCertificates", "true")])),
        vec![(Validity::Ok, None)]
    );
}

#[test]
fn cosign_and_signers_tree() {
    let once = sign(&java_resource("TEST_PDF.pdf"), &ExtraParams::new());
    let ec = TestKey::load("firmante-ec");
    let twice = PadesSigner::new()
        .cosign(None, &once, "SHA512withECDSA", &ec, &visible(&[]))
        .unwrap();
    assert_eq!(&twice[..once.len()], &once[..]);
    let tree = PadesSigner::new()
        .signers_structure(&twice, &ExtraParams::new())
        .unwrap();
    let names: Vec<String> = tree.signers.iter().map(|n| n.info.signer_name()).collect();
    assert_eq!(
        names,
        vec!["PRUEBA MARIA - 99999999R", "ESPAÑOL ESPAÑOL JUAN - 00000000T"]
    );
    assert_eq!(tree.signers[0].info.sign_algorithm.as_deref(), Some("SHA512withECDSA"));
    assert_eq!(validity(&twice, &ExtraParams::new()), vec![(Validity::Ok, None)]);
    let doc = PdfDoc::open(&twice, None).unwrap();
    assert_eq!(
        doc.signatures().0.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
        vec!["Signature2", "Signature1"]
    );
}

#[test]
fn cosign_java_signature() {
    let java = std::fs::read(testdata("java_signed_visible.pdf")).unwrap();
    let out = sign(&java, &visible(&[("signaturePage", "1")]));
    assert_eq!(&out[..java.len()], &java[..]);
    let v = validity(&out, &ExtraParams::new());
    assert_eq!(v, vec![(Validity::Ok, None)]);
    assert_eq!(
        PadesSigner::new()
            .signers_structure(&out, &ExtraParams::new())
            .unwrap()
            .signers
            .len(),
        2
    );
}

#[test]
fn signer_api() {
    let s = PadesSigner::new();
    let pdf = java_resource("TEST_PDF.pdf");
    assert!(s.is_valid_data_file(&pdf));
    assert!(!s.is_sign(&pdf, &ExtraParams::new()));
    assert!(s.get_data(&pdf, &ExtraParams::new()).is_err());
    let signed = sign(&pdf, &ExtraParams::new());
    assert!(s.is_sign(&signed, &ExtraParams::new()));
    assert_eq!(s.get_data(&signed, &ExtraParams::new()).unwrap().unwrap(), signed);
    assert_eq!(s.sign_info(&signed, &ExtraParams::new()).unwrap().format, "Adobe PDF");
    let e = s
        .countersign(
            &signed,
            "SHA256withRSA",
            &afirma_core::CounterSignTarget::Tree,
            &TestKey::rsa(),
            &ExtraParams::new(),
        )
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unsupported);
    assert!(!s.is_valid_data_file(b"%PDF-1.4 corto"));
    let e = s
        .sign(b"no es un pdf", "SHA256withRSA", &TestKey::rsa(), &ExtraParams::new())
        .unwrap_err();
    assert_eq!(e.code, Some(codes::PDF_DOCUMENT_NEEDED));
    let e = s
        .sign(&pdf, "MD5withRSA", &TestKey::rsa(), &ExtraParams::new())
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidArgument);
}

fn intervention(e: &afirma_core::AfirmaError) -> (u32, String, String, bool) {
    match &e.kind {
        ErrorKind::NeedsIntervention {
            intervention: UserIntervention::Confirm {
                requestor_text, param, ..
            },
            denied,
        } => (e.code.unwrap().code, requestor_text.clone(), param.clone(), *denied),
        ErrorKind::NeedsIntervention {
            intervention: UserIntervention::Password { requestor_text, param },
            denied,
        } => (e.code.unwrap().code, requestor_text.clone(), param.clone(), *denied),
        k => panic!("se esperaba intervención: {k:?} {e}"),
    }
}

#[test]
fn certified_documents() {
    let certified = java_resource("TEST_PDF_Certified.pdf");
    let s = PadesSigner::new();
    let key = TestKey::rsa();
    let e = s
        .sign(&certified, "SHA256withRSA", &key, &ExtraParams::new())
        .unwrap_err();
    assert_eq!(
        intervention(&e),
        (
            212007,
            "signingCertifiedPdf".into(),
            "allowSigningCertifiedPdfs".into(),
            false
        )
    );
    let e = s
        .sign(
            &certified,
            "SHA256withRSA",
            &key,
            &params(&[("allowSigningCertifiedPdfs", "false")]),
        )
        .unwrap_err();
    assert!(intervention(&e).3);
    let out = s
        .sign(
            &certified,
            "SHA256withRSA",
            &key,
            &params(&[("allowSigningCertifiedPdfs", "true")]),
        )
        .unwrap();
    let v = validity(&out, &ExtraParams::new());
    assert!(
        v.contains(&(Validity::Ko, Some(ValidityError::CertifiedSignRevision))),
        "{v:?}"
    );

    // Certificación propia (DocMDP).
    let own = sign(&java_resource("TEST_PDF.pdf"), &params(&[("certificationLevel", "2")]));
    let doc = PdfDoc::open(&own, None).unwrap();
    assert_eq!(doc.certification_level(), 2);
    let (sigs, _) = doc.signatures();
    let reference = sigs[0].dict.get(b"Reference").unwrap().as_array().unwrap();
    assert_eq!(
        reference[0]
            .as_dict()
            .unwrap()
            .get(b"TransformMethod")
            .unwrap()
            .as_name()
            .unwrap(),
        b"DocMDP"
    );
    // Nivel 2: se puede añadir otra firma sin avisos.
    let again = sign(&own, &ExtraParams::new());
    assert_eq!(validity(&again, &ExtraParams::new()), vec![(Validity::Ok, None)]);
}

#[test]
fn unregistered_signatures() {
    let pdf = java_resource("firma_CM.pdf");
    let s = PadesSigner::new();
    let e = s
        .sign(&pdf, "SHA256withRSA", &TestKey::rsa(), &ExtraParams::new())
        .unwrap_err();
    assert_eq!(
        intervention(&e),
        (
            212003,
            "signingPdfWithUnregisteredSigns".into(),
            "allowCosigningUnregisteredSignatures".into(),
            false
        )
    );
    let out = s
        .sign(
            &pdf,
            "SHA256withRSA",
            &TestKey::rsa(),
            &params(&[("allowCosigningUnregisteredSignatures", "true")]),
        )
        .unwrap();
    let tree = s.signers_structure(&out, &ExtraParams::new()).unwrap();
    assert_eq!(tree.signers.len(), 2);
    assert_eq!(tree.signers[1].info.sign_algorithm.as_deref(), Some("SHA1withRSA"));
}

#[test]
fn encrypted_documents() {
    let s = PadesSigner::new();
    let key = TestKey::rsa();
    for f in [
        "encrypted_rc4_40.pdf",
        "encrypted_rc4_128.pdf",
        "encrypted_aes128.pdf",
        "encrypted_aes256.pdf",
    ] {
        let pdf = std::fs::read(testdata(f)).unwrap();
        let e = s.sign(&pdf, "SHA256withRSA", &key, &ExtraParams::new()).unwrap_err();
        assert_eq!(intervention(&e).0, 212005, "{f}");
        let out = s
            .sign(&pdf, "SHA256withRSA", &key, &visible(&[("ownerPassword", "owner")]))
            .unwrap();
        assert_eq!(&out[..pdf.len()], &pdf[..]);
        assert_eq!(
            validity(&out, &params(&[("ownerPassword", "owner")])),
            vec![(Validity::Ok, None)],
            "{f}"
        );
        // Los textos del diccionario de firma se cifran; /Contents no.
        let doc = PdfDoc::open(&out, Some("owner")).unwrap();
        let (sigs, _) = doc.signatures();
        assert!(
            String::from_utf8_lossy(sigs[0].dict.get(b"M").unwrap().as_str().unwrap()).starts_with("D:"),
            "{f}"
        );
        assert!(cms::parse_signed_data(&sigs[0].contents()).is_ok(), "{f}");
    }
    let pdf = std::fs::read(testdata("encrypted_aes128_user.pdf")).unwrap();
    let e = s
        .sign(&pdf, "SHA256withRSA", &key, &params(&[("userPassword", "user")]))
        .unwrap_err();
    assert_eq!(
        intervention(&e),
        (212004, "pdfbadpassword".into(), "ownerPassword".into(), false)
    );
    let e = s.sign(&pdf, "SHA256withRSA", &key, &ExtraParams::new()).unwrap_err();
    assert_eq!(intervention(&e).1, "pdfpasswordprotected");
    assert!(
        s.sign(&pdf, "SHA256withRSA", &key, &params(&[("ownerPassword", "owner")]))
            .is_ok()
    );
}

#[test]
fn xref_variants_and_broken_files() {
    for f in ["xref_stream.pdf", "rotated_pages.pdf"] {
        let pdf = std::fs::read(testdata(f)).unwrap();
        let out = sign(&pdf, &visible(&[("signaturePages", "all")]));
        assert_eq!(validity(&out, &ExtraParams::new()), vec![(Validity::Ok, None)], "{f}");
        // La sección añadida es del mismo tipo que la anterior.
        let tail = String::from_utf8_lossy(&out[pdf.len()..]).into_owned();
        assert_eq!(tail.contains("/Type/XRef"), f == "xref_stream.pdf", "{f}");
    }
    // Basura tras %%EOF y varias revisiones sin firmar.
    let out = sign(&java_resource("TEST_PDF_Trailed.pdf"), &ExtraParams::new());
    assert_eq!(validity(&out, &ExtraParams::new()), vec![(Validity::Ok, None)]);
    // Tabla de referencias dañada en un PDF sin firmas: se reconstruye.
    let mut broken = java_resource("multipage.pdf");
    let p = broken.windows(9).rposition(|w| w == b"startxref").unwrap();
    broken.truncate(p);
    broken.extend_from_slice(b"startxref\n12345\n%%EOF\n");
    let out = sign(&broken, &ExtraParams::new());
    assert_eq!(validity(&out, &ExtraParams::new()), vec![(Validity::Ok, None)]);
}

#[test]
fn visible_signature_appearance() {
    let out = sign(
        &java_resource("TEST_PDF.pdf"),
        &visible(&[
            ("signTime", "2026:10:16:13:36:29"),
            ("signReason", "Prueba"),
            ("signatureProductionCity", "Madrid"),
        ]),
    );
    let doc = PdfDoc::open(&out, None).unwrap();
    let (sigs, _) = doc.signatures();
    let w = &sigs[0].field.widget;
    assert_eq!(w.get(b"F").unwrap().as_i64().unwrap(), 132);
    let rect: Vec<f32> = w
        .get(b"Rect")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o.as_float().unwrap())
        .collect();
    assert_eq!(rect, vec![100.0, 100.0, 300.0, 180.0]);
    // Contenido de la capa n2 idéntico al observado en Java.
    let expected = b"BT\n1 0 0 1 2 66 Tm\n/F1 12 Tf\n0 0 0 rg\n(Firmado por ESPA\xd1OL ESPA\xd1OL)Tj\n0 g\n1 0 0 1 2 54 Tm\n0 0 0 rg\n(JUAN - ***0000**)Tj\n0 g\n1 0 0 1 2 42 Tm\n0 0 0 rg\n(Fecha: 16/10/2026 13:36:29)Tj\n0 g\n1 0 0 1 2 30 Tm\n0 0 0 rg\n(CEST)Tj\n0 g\n1 0 0 1 2 18 Tm\n0 0 0 rg\n(Motivo: Prueba)Tj\n0 g\n1 0 0 1 2 6 Tm\n0 0 0 rg\n(Lugar de firma: Madrid)Tj\n0 g\nET\n";
    let found = doc.doc.objects.values().any(|o| {
        o.as_stream()
            .ok()
            .and_then(|s| s.decompressed_content().ok())
            .is_some_and(|c| c == expected)
    });
    // La zona horaria corta depende del sistema: solo se exige si es Madrid.
    if iana_like_madrid() {
        assert!(found, "no se encuentra la capa n2 esperada");
    }
    assert_eq!(validity(&out, &ExtraParams::new()), vec![(Validity::Ok, None)]);
}

fn iana_like_madrid() -> bool {
    std::fs::read_link("/etc/localtime")
        .map(|p| p.to_string_lossy().ends_with("Europe/Madrid"))
        .unwrap_or(false)
        && std::env::var("TZ").is_err()
}

#[test]
fn existing_field_and_stamp() {
    let pdf = java_resource("empty_signature_field.pdf");
    let info = afirma_pdf::info::PdfInfo::open(&pdf, None).unwrap();
    assert_eq!(info.empty_signature_fields.len(), 1);
    assert_eq!(info.empty_signature_fields[0].name, "EmptySignatureField");
    let out = sign(&pdf, &params(&[("signatureField", "EmptySignatureField")]));
    let doc = PdfDoc::open(&out, None).unwrap();
    let (sigs, _) = doc.signatures();
    assert_eq!(sigs[0].name, "EmptySignatureField");
    assert_eq!(sigs[0].field.widget.get(b"F").unwrap().as_i64().unwrap() & 128, 128);
    assert!(
        afirma_pdf::info::PdfInfo::open(&out, None)
            .unwrap()
            .empty_signature_fields
            .is_empty()
    );
    let e = PadesSigner::new()
        .sign(
            &pdf,
            "SHA256withRSA",
            &TestKey::rsa(),
            &params(&[("signatureField", "NoExiste")]),
        )
        .unwrap_err();
    assert_eq!(e.message, "The field NoExiste does not exist.");

    // Marca visible.
    let mut img = std::io::Cursor::new(Vec::new());
    image::RgbImage::from_pixel(20, 10, image::Rgb([255, 0, 0]))
        .write_to(&mut img, image::ImageFormat::Png)
        .unwrap();
    let b64 = afirma_core::base64_encode(&img.into_inner());
    let out = sign(
        &java_resource("multipage.pdf"),
        &params(&[
            ("image", &b64),
            ("imagePage", "0"),
            ("imagePositionOnPageLowerLeftX", "10"),
            ("imagePositionOnPageLowerLeftY", "10"),
            ("imagePositionOnPageUpperRightX", "110"),
            ("imagePositionOnPageUpperRightY", "60"),
        ]),
    );
    assert_eq!(validity(&out, &ExtraParams::new()), vec![(Validity::Ok, None)]);
}

#[test]
fn timestamps_with_mock_tsa() {
    let tsa_key = std::fs::read_to_string(common::pki("tsa.key")).unwrap();
    let pem = std::fs::read_to_string(common::pki("tsa.crt")).unwrap();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let cert = afirma_core::base64_decode_lenient(&b64).unwrap();
    let mock = afirma_pdf::tsp::mock::MockTsa::new(&tsa_key, cert).unwrap();
    let signer = PadesSigner::new().with_tsa_transport(Arc::new(mock));
    let pdf = java_resource("TEST_PDF.pdf");
    for (ts_type, docts, sigts) in [("1", 0, 1), ("2", 1, 0), ("3", 1, 1)] {
        let out = signer
            .sign(
                &pdf,
                "SHA256withRSA",
                &TestKey::rsa(),
                &params(&[("tsaURL", "http://tsa.invalid/"), ("tsType", ts_type)]),
            )
            .unwrap();
        let doc = PdfDoc::open(&out, None).unwrap();
        let (sigs, _) = doc.signatures();
        let n_doc = sigs
            .iter()
            .filter(|s| s.type_name().as_deref() == Some(b"DocTimeStamp".as_slice()))
            .count();
        assert_eq!(n_doc, docts, "tsType={ts_type}");
        let sig = sigs
            .iter()
            .find(|s| s.type_name().as_deref() == Some(b"Sig".as_slice()))
            .unwrap();
        let sd = cms::parse_signed_data(&sig.contents()).unwrap();
        let n_ts = sd.signer_infos[0]
            .unsigned_attr(cms::OID_SIGNATURE_TIMESTAMP)
            .map_or(0, |a| a.values.len());
        assert_eq!(n_ts, sigts, "tsType={ts_type}");
        let v = validity(&out, &ExtraParams::new());
        assert!(v.iter().all(|(v, _)| *v != Validity::Ko), "tsType={ts_type}: {v:?}");
    }
}

#[test]
fn triphase_flow() {
    let pdf = java_resource("TEST_PDF.pdf");
    let key = TestKey::rsa();
    let chain = afirma_core::SigningKey::certificate_chain(&key);
    let t = afirma_pdf::pdf::date::parse_sign_time("2026:10:16:13:36:29").unwrap();
    let xp = visible(&[]);
    let (pre1, s1) =
        afirma_pdf::triphase::presign(&pdf, "SHA256withRSA", afirma_core::KeyAlgorithm::Rsa, &chain, t, &xp).unwrap();
    let (pre2, s2) =
        afirma_pdf::triphase::presign(&pdf, "SHA256withRSA", afirma_core::KeyAlgorithm::Rsa, &chain, t, &xp).unwrap();
    assert_eq!(
        pre1.prepared.bytes, pre2.prepared.bytes,
        "la prefirma debe ser determinista"
    );
    assert_eq!(s1, s2);
    let params_list = s1.to_params();
    assert!(params_list.iter().any(|(k, v)| k == "NEED_PRE" && v == "true"));
    let mut session =
        afirma_pdf::triphase::PadesSession::from_params(params_list.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .unwrap();
    session.pk1 = Some(afirma_pdf::triphase::sign_pre(&session.pre, "SHA256withRSA", &key).unwrap());
    let out = afirma_pdf::triphase::postsign(
        &pdf,
        "SHA256withRSA",
        afirma_core::KeyAlgorithm::Rsa,
        &chain,
        &session,
        &xp,
    )
    .unwrap();
    assert_eq!(validity(&out, &ExtraParams::new()), vec![(Validity::Ok, None)]);
}

#[test]
fn signature_reserved_size() {
    let e = PadesSigner::new()
        .sign(
            &java_resource("TEST_PDF.pdf"),
            "SHA256withRSA",
            &TestKey::rsa(),
            &params(&[("signReservedSize", "100")]),
        )
        .unwrap_err();
    assert_eq!(e.code, Some(codes::INTERNAL_PADES_SIGNING_ERROR));
    let out = sign(&java_resource("TEST_PDF.pdf"), &params(&[("signReservedSize", "8000")]));
    let doc = PdfDoc::open(&out, None).unwrap();
    let br = doc.signatures().0[0].byte_range();
    assert_eq!(br[2] - br[1], 16002);
}
