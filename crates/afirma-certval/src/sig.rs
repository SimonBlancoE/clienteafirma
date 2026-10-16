//! Verificación de firmas X.509 (certificados, CRL y respuestas OCSP):
//! RSA PKCS#1 v1.5, RSASSA-PSS y ECDSA (P-256, P-384 y P-521).

use afirma_cms::asn1::{Tag, Tlv, tags};
use afirma_cms::verify::{verify_ecdsa, verify_rsa};
use afirma_core::algorithms::DigestAlgorithm;

const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const MGF1: &str = "1.2.840.113549.1.1.8";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";

/// Algoritmo de firma de un `AlgorithmIdentifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigAlg {
    RsaPkcs1(DigestAlgorithm),
    RsaPss { digest: DigestAlgorithm, salt_len: usize },
    Ecdsa(DigestAlgorithm),
}

fn digest_for_rsa_pkcs1(oid: &str) -> Option<DigestAlgorithm> {
    Some(match oid {
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => DigestAlgorithm::Sha1,
        "1.2.840.113549.1.1.14" => DigestAlgorithm::Sha224,
        "1.2.840.113549.1.1.11" => DigestAlgorithm::Sha256,
        "1.2.840.113549.1.1.12" => DigestAlgorithm::Sha384,
        "1.2.840.113549.1.1.13" => DigestAlgorithm::Sha512,
        _ => return None,
    })
}

fn digest_for_ecdsa(oid: &str) -> Option<DigestAlgorithm> {
    Some(match oid {
        "1.2.840.10045.4.1" => DigestAlgorithm::Sha1,
        "1.2.840.10045.4.3.1" => DigestAlgorithm::Sha224,
        "1.2.840.10045.4.3.2" => DigestAlgorithm::Sha256,
        "1.2.840.10045.4.3.3" => DigestAlgorithm::Sha384,
        "1.2.840.10045.4.3.4" => DigestAlgorithm::Sha512,
        _ => return None,
    })
}

/// OID y parámetros (si los hay) de un `AlgorithmIdentifier`.
fn split_alg_id(alg_id: &[u8]) -> Result<(String, Option<Tlv<'_>>), String> {
    let seq = Tlv::parse_single(alg_id)
        .and_then(|t| t.children())
        .map_err(|e| e.to_string())?;
    let oid = seq
        .first()
        .ok_or("AlgorithmIdentifier vacio")?
        .as_oid()
        .map_err(|e| e.to_string())?;
    Ok((oid.to_dotted(), seq.get(1).copied()))
}

/// Huella de un `AlgorithmIdentifier` de huella (parámetros de PSS).
fn digest_from_alg_id(t: &Tlv<'_>) -> Result<DigestAlgorithm, String> {
    let (oid, _) = split_alg_id(t.raw)?;
    DigestAlgorithm::from_oid(&oid).ok_or_else(|| format!("Huella no soportada en RSASSA-PSS: {oid}"))
}

/// Parámetros `RSASSA-PSS-params` (RFC 4055): solo se admite MGF1 con la
/// misma huella que el mensaje (lo único que usan las CA en la práctica).
fn pss_params(params: Option<Tlv<'_>>) -> Result<SigAlg, String> {
    let mut digest = DigestAlgorithm::Sha1;
    let mut mgf_digest = DigestAlgorithm::Sha1;
    let mut salt_len = 20usize;
    if let Some(p) = params.filter(|p| p.tag == tags::SEQUENCE) {
        for field in p.children().map_err(|e| e.to_string())? {
            let inner = field.children().map_err(|e| e.to_string())?;
            let Some(inner) = inner.first() else { continue };
            match field.tag {
                t if t == Tag::context(0, true) => digest = digest_from_alg_id(inner)?,
                t if t == Tag::context(1, true) => {
                    let (mgf, mgf_params) = split_alg_id(inner.raw)?;
                    if mgf != MGF1 {
                        return Err(format!("Funcion de mascara no soportada: {mgf}"));
                    }
                    let mgf_params = mgf_params.ok_or("MGF1 sin parametros")?;
                    mgf_digest = digest_from_alg_id(&mgf_params)?;
                }
                t if t == Tag::context(2, true) => {
                    salt_len = usize::try_from(inner.as_i64().map_err(|e| e.to_string())?)
                        .map_err(|_| "Longitud de sal no valida".to_string())?;
                }
                _ => {}
            }
        }
    }
    if digest != mgf_digest {
        return Err("RSASSA-PSS con huellas distintas para el mensaje y MGF1 no soportado".into());
    }
    Ok(SigAlg::RsaPss { digest, salt_len })
}

fn parse_sig_alg(alg_id: &[u8]) -> Result<SigAlg, String> {
    let (oid, params) = split_alg_id(alg_id)?;
    if let Some(d) = digest_for_rsa_pkcs1(&oid) {
        return Ok(SigAlg::RsaPkcs1(d));
    }
    if let Some(d) = digest_for_ecdsa(&oid) {
        return Ok(SigAlg::Ecdsa(d));
    }
    if oid == RSASSA_PSS {
        return pss_params(params);
    }
    Err(format!("Algoritmo de firma no soportado: {oid}"))
}

/// Verifica `signature` sobre `data` con el algoritmo `alg_id`
/// (AlgorithmIdentifier DER) y la clave `spki` (SubjectPublicKeyInfo DER).
pub(crate) fn verify(alg_id: &[u8], spki: &[u8], data: &[u8], signature: &[u8]) -> Result<(), String> {
    let alg = parse_sig_alg(alg_id)?;
    let spki = Tlv::parse_single(spki)
        .and_then(|t| t.children())
        .map_err(|e| e.to_string())?;
    let (key_oid, key_params) = split_alg_id(spki.first().ok_or("Clave publica vacia")?.raw)?;
    let key_bits = spki
        .get(1)
        .ok_or("Clave publica sin datos")?
        .bit_string_content()
        .map_err(|e| e.to_string())?;
    let ok = match alg {
        SigAlg::RsaPkcs1(d) => {
            if key_oid != RSA_ENCRYPTION {
                return Err(format!("Clave {key_oid} incompatible con una firma RSA"));
            }
            verify_rsa(key_bits, d, &d.digest(data), signature).map_err(|e| e.to_string())?
        }
        SigAlg::Ecdsa(d) => {
            if key_oid != EC_PUBLIC_KEY {
                return Err(format!("Clave {key_oid} incompatible con una firma ECDSA"));
            }
            let curve = key_params
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_dotted())
                .ok_or("Clave EC sin curva con nombre")?;
            verify_ecdsa(&curve, key_bits, &d.digest(data), signature).map_err(|e| e.to_string())?
        }
        SigAlg::RsaPss { digest, salt_len } => {
            if key_oid != RSA_ENCRYPTION && key_oid != RSASSA_PSS {
                return Err(format!("Clave {key_oid} incompatible con una firma RSASSA-PSS"));
            }
            verify_pss(key_bits, digest, salt_len, data, signature)?
        }
    };
    if ok {
        Ok(())
    } else {
        Err("La firma no es valida".into())
    }
}

fn verify_pss(
    pkcs1_key: &[u8],
    digest: DigestAlgorithm,
    salt_len: usize,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    let key = rsa::RsaPublicKey::from_pkcs1_der(pkcs1_key).map_err(|e| format!("Clave RSA no valida: {e}"))?;
    let hash = digest.digest(data);
    let scheme = match digest {
        DigestAlgorithm::Sha1 => rsa::Pss::new_with_salt::<sha1::Sha1>(salt_len),
        DigestAlgorithm::Sha224 => rsa::Pss::new_with_salt::<sha2::Sha224>(salt_len),
        DigestAlgorithm::Sha256 => rsa::Pss::new_with_salt::<sha2::Sha256>(salt_len),
        DigestAlgorithm::Sha384 => rsa::Pss::new_with_salt::<sha2::Sha384>(salt_len),
        DigestAlgorithm::Sha512 => rsa::Pss::new_with_salt::<sha2::Sha512>(salt_len),
    };
    Ok(key.verify(scheme, &hash, signature).is_ok())
}

/// Nombre JCA del algoritmo de firma (`X509Certificate.getSigAlgName()`),
/// que usa el identificador de emisor de `CertificateVerifierFactory`. Para
/// los OID que Java no conoce devuelve el propio OID.
pub(crate) fn jca_signature_name(alg_id: &[u8]) -> String {
    let Ok((oid, _)) = split_alg_id(alg_id) else {
        return String::new();
    };
    let name = match oid.as_str() {
        "1.2.840.113549.1.1.2" => "MD2withRSA",
        "1.2.840.113549.1.1.4" => "MD5withRSA",
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "SHA1withRSA",
        "1.2.840.113549.1.1.14" => "SHA224withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.113549.1.1.15" => "SHA512/224withRSA",
        "1.2.840.113549.1.1.16" => "SHA512/256withRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "SHA1withECDSA",
        "1.2.840.10045.4.3.1" => "SHA224withECDSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.2.840.10045.4.3.4" => "SHA512withECDSA",
        "1.2.840.10040.4.3" => "SHA1withDSA",
        "2.16.840.1.101.3.4.3.1" => "SHA224withDSA",
        "2.16.840.1.101.3.4.3.2" => "SHA256withDSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        _ => return oid,
    };
    name.to_string()
}
