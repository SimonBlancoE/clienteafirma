//! Árbol de firmantes de una firma CMS/CAdES (`ReadNodesTree`).

use afirma_core::error::AfirmaError;
use afirma_core::{SignerNode, SignersTree, SimpleSignInfo};

use crate::alg;
use crate::asn1::tags;
use crate::cms::{SignedData, SignerInfo, parse_content_info};
use crate::oids;

/// Atributos no firmados que no contienen contrafirmas (sellos de tiempo y
/// datos de validación a largo plazo).
pub const NON_COUNTERSIGNATURE_ATTRS: [&str; 10] = [
    oids::SIGNATURE_TIMESTAMP_TOKEN,
    oids::ARCHIVE_TIMESTAMP,
    oids::ESC_TIMESTAMP,
    oids::REVOCATION_REFS,
    oids::REVOCATION_VALUES,
    oids::CERTIFICATE_REFS,
    oids::CERT_VALUES,
    oids::ARCHIVE_TIMESTAMP_V2,
    oids::ARCHIVE_TIMESTAMP_V3,
    oids::LONG_TERM_VALIDATION,
];

fn bad(msg: impl Into<String>) -> AfirmaError {
    AfirmaError::invalid_signature_format(msg)
}

/// Información de un firmante para el árbol.
pub fn simple_sign_info(sd: &SignedData<'_>, si: &SignerInfo<'_>) -> afirma_core::Result<SimpleSignInfo> {
    let (_, serial) = si
        .issuer_and_serial()
        .ok_or_else(|| bad("El identificador del firmante no es IssuerAndSerialNumber"))?;
    let certs = sd
        .find_certificate_by_serial(serial)
        .map(|c| vec![c.to_vec()])
        .unwrap_or_default();
    Ok(SimpleSignInfo {
        certs,
        signing_time: si.signing_time(),
        sign_algorithm: Some(alg::tree_signature_algorithm_name(
            &si.digest_oid.to_dotted(),
            &si.signature_oid.to_dotted(),
        )),
        pkcs1: si.signature_value(),
        sign_format: None,
        timestamping_time: Vec::new(),
    })
}

fn node(sd: &SignedData<'_>, si: &SignerInfo<'_>) -> afirma_core::Result<SignerNode> {
    let info = simple_sign_info(sd, si)?;
    let mut countersigners = Vec::new();
    for attr in si.unsigned_attributes().map_err(|e| bad(e.to_string()))? {
        if NON_COUNTERSIGNATURE_ATTRS.iter().any(|o| attr.is(o)) {
            continue;
        }
        for v in &attr.values {
            if v.tag == tags::SEQUENCE {
                let child = SignerInfo::parse(*v).map_err(|e| bad(format!("Contrafirma no valida: {e}")))?;
                countersigners.push(node(sd, &child)?);
            }
        }
    }
    Ok(SignerNode { info, countersigners })
}

/// Lee el árbol de firmantes. Los firmantes cuyo certificado no está en la
/// firma aparecen sin certificados (nombre vacío).
pub fn read_signers_tree(sign: &[u8]) -> afirma_core::Result<SignersTree> {
    let (_, content, ci) = parse_content_info(sign).map_err(|e| bad(e.to_string()))?;
    let Some(content) = content else {
        return Ok(SignersTree::default());
    };
    // Si el SignedData no se puede leer, AutoFirma devuelve un árbol vacío.
    let Ok(sd) = SignedData::parse_signed_data(ci, content) else {
        return Ok(SignersTree::default());
    };
    let mut signers = Vec::new();
    for si in &sd.signer_infos {
        signers.push(node(&sd, si)?);
    }
    Ok(SignersTree { signers })
}

/// Nombres (CN) de los firmantes en preorden, como
/// `ReadNodesTree.readNodesTree(sign, false)` (vacío si no se encuentra el
/// certificado).
pub fn signer_names_preorder(sign: &[u8]) -> afirma_core::Result<Vec<String>> {
    let tree = read_signers_tree(sign)?;
    Ok(tree.preorder().into_iter().map(|(_, n)| n.info.signer_name()).collect())
}
