//! Firma PKCS#1 "en bruto" (formato `NONE`, `AOPkcs1Signer`).

use afirma_core::algorithms::compose_signature_algorithm;
use afirma_core::error::codes;
use afirma_core::{AfirmaError, CounterSignTarget, ExtraParams, Result, SignInfo, Signer, SignersTree, SigningKey};

/// Firmador `NONE`: devuelve la firma PKCS#1 (o ECDSA DER) de los datos.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pkcs1Signer;

impl Signer for Pkcs1Signer {
    fn format_name(&self) -> &'static str {
        "NONE"
    }

    fn sign(&self, data: &[u8], algorithm: &str, key: &dyn SigningKey, _extra: &ExtraParams) -> Result<Vec<u8>> {
        if algorithm.trim().is_empty() {
            return Err(AfirmaError::invalid_argument("Es necesario indicar el algoritmo de firma, no puede ser nulo"));
        }
        let alg = compose_signature_algorithm(algorithm, key.key_algorithm())?;
        let signature = key.sign(data, alg).map_err(AfirmaError::from)?;
        // Autocomprobación (ETSI TS 119 102-1), como hace AutoFirma.
        match afirma_cms::verify::verify_with_certificate(key.certificate(), alg, data, &signature) {
            Ok(true) => Ok(signature),
            Ok(false) => Err(AfirmaError::new(
                codes::INVALID_PKCS1_VALUE,
                "El PKCS#1 de firma obtenido no se genero con el certificado indicado",
            )),
            Err(e) => Err(AfirmaError::new(codes::VERIFING_PKCS1_ERROR, e.0)),
        }
    }

    fn cosign(&self, _: Option<&[u8]>, _: &[u8], _: &str, _: &dyn SigningKey, _: &ExtraParams) -> Result<Vec<u8>> {
        Err(AfirmaError::unsupported("No se soporta la cofirma PKCS#1"))
    }

    fn countersign(&self, _: &[u8], _: &str, _: &CounterSignTarget, _: &dyn SigningKey, _: &ExtraParams) -> Result<Vec<u8>> {
        Err(AfirmaError::unsupported("No se soporta la contrafirma PKCS#1"))
    }

    fn signers_structure(&self, _: &[u8], _: &ExtraParams) -> Result<SignersTree> {
        Err(AfirmaError::unsupported("No se soporta la obtencion de firmantes en PKCS#1"))
    }

    fn is_sign(&self, _: &[u8], _: &ExtraParams) -> bool {
        false
    }

    fn is_valid_data_file(&self, data: &[u8]) -> bool {
        !data.is_empty()
    }

    fn signed_name(&self, original: Option<&str>, in_text: Option<&str>) -> String {
        let inner = in_text.unwrap_or("");
        match original {
            None => "signature.p1".into(),
            Some(n) if n.to_ascii_lowercase().ends_with(".p1") => format!("{}{inner}.p1", &n[..n.len() - 3]),
            Some(n) => format!("{n}{inner}.p1"),
        }
    }

    fn get_data(&self, _: &[u8], _: &ExtraParams) -> Result<Option<Vec<u8>>> {
        Err(AfirmaError::unsupported("No se soporta la extraccion de datos en PKCS#1"))
    }

    fn sign_info(&self, _: &[u8], _: &ExtraParams) -> Result<SignInfo> {
        Err(AfirmaError::unsupported("No se soporta la informacion de firma en PKCS#1"))
    }
}
