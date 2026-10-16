//! Generación del valor de firma PKCS#1/ECDSA con autoverificación
//! (equivalente a `AOPkcs1Signer`).

use afirma_core::algorithms::SignatureAlgorithm;
use afirma_core::error::{AfirmaError, codes};
use afirma_core::key::SigningKey;

use crate::verify::verify_with_certificate;

/// Firma `data` con la clave y, si se conoce el certificado de firma,
/// comprueba que la firma generada se verifica con su clave pública
/// (ETSI TS 119 102-1), como hace AutoFirma.
pub fn sign(
    key: &dyn SigningKey,
    data: &[u8],
    alg: SignatureAlgorithm,
    signer_cert: Option<&[u8]>,
) -> afirma_core::Result<Vec<u8>> {
    let signature = key.sign(data, alg).map_err(AfirmaError::from)?;
    match signer_cert {
        Some(cert) => match verify_with_certificate(cert, alg, data, &signature) {
            Ok(true) => Ok(signature),
            Ok(false) => Err(AfirmaError::new(
                codes::INVALID_PKCS1_VALUE,
                "El PKCS#1 de firma obtenido no se genero con el certificado indicado",
            )),
            Err(e) => Err(
                AfirmaError::new(codes::VERIFING_PKCS1_ERROR, "No se pudo verificar la firma generada").with_cause(e),
            ),
        },
        None => {
            tracing::warn!("No se ha proporcionado el certificado de firma, no se verificara el PKCS#1 generado");
            Ok(signature)
        }
    }
}
