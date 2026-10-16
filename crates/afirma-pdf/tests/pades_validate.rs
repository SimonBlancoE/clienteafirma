//! Validación de firmas PDF comparada con los resultados de AutoFirma Java
//! (`ValidatePdfSignature`, `checkCertificates=true`,
//! `pagesToCheckShadowAttack=all`) sobre los PDF de prueba del repositorio.

mod common;

use afirma_core::error::{ErrorKind, UserIntervention};
use afirma_core::validity::{Validity, ValidityError};
use afirma_pdf::validate::validate_pdf;
use common::{params, repo};

use Validity::{Ko, Ok as Valid, Unknown};
use ValidityError::*;

fn check(path: &str, expected: &[(Validity, Option<ValidityError>)]) {
    let data = std::fs::read(repo().join(path)).expect(path);
    let xp = params(&[
        ("checkCertificates", "true"),
        ("pagesToCheckShadowAttack", "all"),
    ]);
    let got: Vec<(Validity, Option<ValidityError>)> = validate_pdf(&data, &xp, false)
        .unwrap()
        .into_iter()
        .map(|v| (v.validity, v.error))
        .collect();
    assert_eq!(got, expected, "{path}");
}

const R: &str = "afirma-crypto-pdf/src/test/resources/";
const V: &str = "afirma-crypto-validation/src/test/resources/";

#[test]
fn java_parity_unsigned_and_simple() {
    check(&format!("{R}TEST_PDF.pdf"), &[(Ko, Some(NoSign))]);
    check(
        &format!("{R}empty_signature_field.pdf"),
        &[(Ko, Some(NoSign))],
    );
    check(
        &format!("{R}TEST_PDF_Signed.pdf"),
        &[(Ko, Some(CertificateExpired))],
    );
    check(
        &format!("{R}pades_basic.pdf"),
        &[(Ko, Some(CertificateExpired))],
    );
    check(
        &format!("{R}cosigned.pdf"),
        &[
            (Ko, Some(CertificateExpired)),
            (Ko, Some(CertificateExpired)),
        ],
    );
    check(
        &format!("{R}TEST_PDF_Certified.pdf"),
        &[(Ko, Some(CertificateExpired))],
    );
    check(
        &format!("{V}pades_epes.pdf"),
        &[(Ko, Some(CertificateExpired))],
    );
    check(
        "afirma-simple/src/test/resources/TSA-5989068450533665227.pdf",
        &[
            (Ko, Some(CertificateExpired)),
            (Ko, Some(CertificateExpired)),
        ],
    );
}

#[test]
#[cfg(feature = "render")]
fn java_parity_legacy_formats() {
    // adbe.x509.rsa_sha1 (firma no registrada), adbe.pkcs7.sha1 y sin
    // atributos firmados.
    check(
        &format!("{R}firma_CM.pdf"),
        &[
            (Ko, Some(CertificateExpired)),
            (Ko, Some(AlgorithmNotSupported)),
            (Unknown, Some(SignProfileNotChecked)),
        ],
    );
    check(
        &format!("{R}getSignersStructure_MARZO 2015 PRIMER ENVIO.pdf"),
        &[(Ko, Some(CertificateExpired))],
    );
    check(
        &format!("{R}getSignersStructure_Sentencia 343-2012.pdf"),
        &[(Ko, Some(CertificateExpired)), (Ko, Some(ModifiedDocument))],
    );
    // Firma con sello de tiempo: perfil longevo no comprobado (orden de Java).
    check(
        &format!("{R}pades-t.pdf"),
        &[
            (Unknown, Some(SignProfileNotChecked)),
            (Ko, Some(CertificateExpired)),
            (Unknown, Some(SignProfileNotChecked)),
            (Ko, Some(CertificateExpired)),
        ],
    );
}

#[test]
#[cfg(feature = "render")]
fn java_parity_shadow_attacks_and_forms() {
    check(
        &format!("{R}Ejemplo_PDF_Shadow_Attack_1.pdf"),
        &[
            (Ko, Some(CertificateExpired)),
            (Ko, Some(CertificateExpired)),
            (Ko, Some(ModifiedDocument)),
        ],
    );
    check(
        &format!("{R}Ejemplo_PDF_Shadow_Attack_2.pdf"),
        &[(Ko, Some(CertificateExpired)), (Ko, Some(ModifiedDocument))],
    );
    check(
        &format!("{V}RFE023 - Formulario_prueba_PDF_mod.pdf"),
        &[(Ko, Some(CertificateExpired)), (Ko, Some(ModifiedForm))],
    );
    check(
        &format!("{V}RFE023 - shadow form.pdf"),
        &[(Ko, Some(CertificateExpired)), (Ko, Some(ModifiedForm))],
    );
}

fn confirm(e: &afirma_core::AfirmaError) -> (String, String, bool) {
    match &e.kind {
        ErrorKind::NeedsIntervention {
            intervention:
                UserIntervention::Confirm {
                    requestor_text,
                    param,
                    ..
                },
            denied,
        } => (requestor_text.clone(), param.clone(), *denied),
        k => panic!("{k:?}"),
    }
}

#[test]
#[cfg(feature = "render")]
fn relaxed_mode_asks_the_user() {
    let data = std::fs::read(repo().join(format!("{R}Ejemplo_PDF_Shadow_Attack_2.pdf"))).unwrap();
    let e = validate_pdf(&data, &params(&[]), true).unwrap_err();
    assert_eq!(
        confirm(&e),
        (
            "pdfShadowAttackSuspect".into(),
            "allowShadowAttack".into(),
            false
        )
    );
    assert_eq!(e.code.unwrap().code, 212008);
    // Ya contestado que no: KO sin preguntar.
    let v = validate_pdf(&data, &params(&[("allowShadowAttack", "false")]), true).unwrap();
    assert!(
        v.iter()
            .any(|x| x.error == Some(ModifiedDocument) && x.validity == Ko)
    );
    // Permitido: sin comprobación.
    let v = validate_pdf(&data, &params(&[("allowShadowAttack", "true")]), true).unwrap();
    assert_eq!(v[0].validity, Valid);

    let form = std::fs::read(repo().join(format!("{V}RFE023 - shadow form.pdf"))).unwrap();
    let e = validate_pdf(&form, &params(&[]), true).unwrap_err();
    assert_eq!(
        confirm(&e),
        (
            "signingModifiedPdfForm".into(),
            "allowModifiedForm".into(),
            false
        )
    );
    let e = validate_pdf(&form, &params(&[("allowModifiedForm", "no")]), true).unwrap_err();
    assert!(confirm(&e).2, "denegado");
}

#[test]
#[cfg(feature = "render")]
fn pages_to_check_limits() {
    let data = std::fs::read(repo().join(format!("{R}Ejemplo_PDF_Shadow_Attack_2.pdf"))).unwrap();
    // 0 páginas: no se compara nada.
    let v = validate_pdf(&data, &params(&[("pagesToCheckShadowAttack", "0")]), false).unwrap();
    assert!(!v.iter().any(|x| x.error == Some(ModifiedDocument)));
    // Más páginas de las que tiene: Java ignora el error y no avisa.
    let v = validate_pdf(
        &data,
        &params(&[("pagesToCheckShadowAttack", "999")]),
        false,
    )
    .unwrap();
    let _ = v;
}
