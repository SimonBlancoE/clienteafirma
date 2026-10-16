//! Construcción de las respuestas correctas de cada operación (§7.1).

use afirma_core::error::codes;

use crate::cipher::ServerCipher;
use crate::errors::ProtocolError;
use crate::jbase64;

/// Respuesta de `save`.
pub const SAVE_OK: &str = "OK";

/// Texto JSON de los datos extra de la firma (`{"filename": "<nombre>"}`),
/// construido a mano y sin escapar, como Java.
pub fn extra_data_json(entries: &[(&str, &str)]) -> String {
    let body: Vec<String> = entries.iter().map(|(k, v)| format!("\"{k}\": \"{v}\"")).collect();
    format!("{{{}}}", body.join(", "))
}

fn cipher_or(cipher: Option<&ServerCipher>, data: &[u8], url_safe: bool, code: afirma_core::ErrorCode) -> Result<String, ProtocolError> {
    match cipher {
        Some(c) => c.cipher(data).map_err(|e| ProtocolError::operation(code, e.to_string())),
        None => Ok(if url_safe { jbase64::encode_url_safe(data) } else { jbase64::encode(data) }),
    }
}

/// Resultado de firma, cofirma, contrafirma y `signandsave`:
/// `cert|firma[|extra]`. El campo extra (nombre del fichero elegido por el
/// usuario) solo se añade con protocolo de versión principal >= 3.
pub fn sign_result(
    cert_der: &[u8],
    signature: &[u8],
    filename: Option<&str>,
    protocol_major: u32,
    cipher: Option<&ServerCipher>,
) -> Result<String, ProtocolError> {
    let mut out = cipher_or(cipher, cert_der, true, codes::ENCRIPTING_SIGNING_CERT)?;
    out.push('|');
    out.push_str(&cipher_or(cipher, signature, true, codes::ENCRIPTING_SIGNATURE)?);
    if let Some(name) = filename {
        if protocol_major >= 3 {
            out.push('|');
            out.push_str(&cipher_or(cipher, extra_data_json(&[("filename", name)]).as_bytes(), true, codes::ENCRIPTING_SIGNATURE_EXTRA_DATA)?);
        }
    }
    Ok(out)
}

/// Resultado de `selectcert`.
pub fn select_cert_result(cert_der: &[u8], cipher: Option<&ServerCipher>) -> Result<String, ProtocolError> {
    cipher_or(cipher, cert_der, true, codes::ENCRIPTING_SELECTED_CERT)
}

/// Resultado de `batch`: `resultado|cert` en Base64 **estándar** (o cifrado).
pub fn batch_result(result: &str, cert_der: Option<&[u8]>, cipher: Option<&ServerCipher>) -> Result<String, ProtocolError> {
    let mut out = cipher_or(cipher, result.as_bytes(), false, codes::ENCRIPTING_BATCH_RESULT)?;
    if let Some(cert) = cert_der {
        out.push('|');
        out.push_str(&cipher_or(cipher, cert, false, codes::ENCRIPTING_BATCH_SIGNING_CERT)?);
    }
    Ok(out)
}

/// Resultado de `load`: `nombre:Base64(contenido)` separados por `|` (nunca
/// cifrado).
pub fn load_result(files: &[(String, Vec<u8>)]) -> String {
    files.iter().map(|(name, data)| format!("{name}:{}", jbase64::encode(data))).collect::<Vec<_>>().join("|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::des_config;

    #[test]
    fn formats() {
        assert_eq!(sign_result(&[0xfb, 0xff], b"sig", None, 4, None).unwrap(), "-_8=|c2ln");
        assert_eq!(
            sign_result(b"c", b"s", Some("doc 1.pdf"), 4, None).unwrap(),
            format!("Yw==|cw==|{}", jbase64::encode_url_safe(b"{\"filename\": \"doc 1.pdf\"}"))
        );
        assert_eq!(sign_result(b"c", b"s", Some("x"), 2, None).unwrap(), "Yw==|cw==");
        let des = ServerCipher::from_config(&des_config("12345678")).unwrap().unwrap();
        assert_eq!(sign_result(b"hello world", b"abcdefgh", None, 4, Some(&des)).unwrap(), "5.KNugLrX23UdgQtrr-lloeg==|0.lNRDa8O1tpM=");
        assert_eq!(select_cert_result(&[0xfb, 0xff], None).unwrap(), "-_8=");
        assert_eq!(batch_result("{\"signs\":[]}", Some(&[0xfb, 0xff]), None).unwrap(), "eyJzaWducyI6W119|+/8=");
        assert_eq!(batch_result("x", None, None).unwrap(), "eA==");
        assert_eq!(load_result(&[("a.txt".into(), b"A".to_vec()), ("b".into(), vec![0xfb])]), "a.txt:QQ==|b:+w==");
        assert_eq!(extra_data_json(&[("filename", "a"), ("k", "v")]), "{\"filename\": \"a\", \"k\": \"v\"}");
    }
}
