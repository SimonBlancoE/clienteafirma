//! Textos de las confirmaciones que piden los firmadores
//! (`RuntimeConfigNeededException`), tomados de `simpleafirmamessages_es_ES`.

/// Texto para la clave `requestor_text` de una intervención.
pub fn intervention_text(key: &str) -> Option<&'static str> {
    Some(match key {
        "signingLts" => "La firma contiene sellos de archivo y quedará invalidada al agregar la nueva firma. ¿Desea continuar?",
        "signingLtsPossible" => "La firma contiene sellos de archivo y podría quedar invalidada al agregar la nueva firma. ¿Desea continuar?",
        "agePolicyIncompatibilitySign" => "La firma que desea generar no es compatible con la Política de firma de la AGE, ni será validada por los sistemas de validación de firma de la AGE.\n¿Desea completar la operación sin agregar la política de firma?",
        "agePolicyIncompatibilityCosign" => "La firma que desea cofirmar no es compatible con la Política de firma de la AGE, ni será validada por los sistemas de validación de firma de la AGE.\n¿Desea completar la operación sin agregar la política de firma?",
        "agePolicyIncompatibilityCounterSign" => "La firma que desea contrafirmar no es compatible con la Política de firma de la AGE, ni será validada por los sistemas de validación de firma de la AGE.\n¿Desea completar la operación sin agregar la política de firma?",
        "signingCertifiedPdf" => "El PDF que desea firmar está certificado y no admite nuevas firmas. Agregar nuevas firmas invalidará la firma anterior.\n¿Desea continuar?",
        "signingPdfWithUnregisteredSigns" => "El PDF que desea firmar contiene firmas previas en un formato antiguo. Agregar nuevas firmas podría invalidar las ya existentes.\n¿Desea continuar?",
        "signingModifiedPdfForm" => "El documento PDF contiene un formulario del cual se han modificado los campos después de haberse firmado.\n¿Desea continuar?",
        "pdfShadowAttackSuspect" => "El PDF es sospechoso de haber sido modificado tras la última firma. ¿Desea continuar?",
        "pdfpasswordprotected" => "El PDF está protegido por contraseña. Introduzca de la contraseña del PDF.",
        "pdfbadpassword" => "La contraseña introducida es incorrecta. Introduzca de la contraseña del PDF.",
        "xPathNotFound" => "La firma que desea cofirmar no admite nuevas firmas. Agregar una nueva firma invalidará la firma anterior. ¿Desea continuar?",
        _ => return None,
    })
}
