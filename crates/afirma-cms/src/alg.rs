//! Algoritmos e identificadores de algoritmo tal y como los usa AutoFirma en
//! CMS/CAdES (`AOAlgorithmID`, `AOSignConstants`).

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm, java_digest_algorithm_name};
use afirma_core::error::{AfirmaError, codes};

use crate::asn1::{Oid, der};
use crate::oids;

/// Huella de un nombre de algoritmo con la semántica de
/// `AOAlgorithmID.getOID(AOSignConstants.getDigestAlgorithmName(nombre))`.
/// Devuelve `None` para algoritmos sin OID (MD5, RIPEMD160, SHA-3...).
pub fn digest_from_java_name(name: &str) -> Option<DigestAlgorithm> {
    let norm = java_digest_algorithm_name(name);
    match norm.as_str() {
        "SHA1" | "SHA-1" | "SHA" => Some(DigestAlgorithm::Sha1),
        "SHA-224" | "SHA224" => Some(DigestAlgorithm::Sha224),
        "SHA-256" | "SHA256" => Some(DigestAlgorithm::Sha256),
        "SHA-384" | "SHA384" => Some(DigestAlgorithm::Sha384),
        "SHA-512" | "SHA512" => Some(DigestAlgorithm::Sha512),
        other => DigestAlgorithm::from_oid(other),
    }
}

/// Como [`digest_from_java_name`] pero con el error de AutoFirma.
pub fn require_digest(name: &str) -> afirma_core::Result<DigestAlgorithm> {
    digest_from_java_name(name).ok_or_else(|| {
        AfirmaError::new(
            codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            format!("Se desconoce el algoritmo '{}'", java_digest_algorithm_name(name)),
        )
    })
}

/// `AlgorithmIdentifier` con parámetros `NULL` (`SigUtils.makeAlgId`).
pub fn alg_id_null(oid: &str) -> Vec<u8> {
    der::sequence([der::oid_str(oid), der::null()])
}

/// `AlgorithmIdentifier` de una huella con parámetros `NULL`.
pub fn digest_alg_id(d: DigestAlgorithm) -> Vec<u8> {
    alg_id_null(d.oid())
}

/// OID del algoritmo de firma completo según la tabla de `AOAlgorithmID`
/// (incluye las variantes DSA con SHA-384/512, que no son iguales a SHA-256).
pub fn signature_oid(alg: SignatureAlgorithm) -> &'static str {
    use DigestAlgorithm::*;
    match (alg.key, alg.digest) {
        (KeyAlgorithm::Dsa, Sha1) => "1.2.840.10040.4.3",
        (KeyAlgorithm::Dsa, Sha224) => "2.16.840.1.101.3.4.3.1",
        (KeyAlgorithm::Dsa, Sha256) => "2.16.840.1.101.3.4.3.2",
        (KeyAlgorithm::Dsa, Sha384) => "2.16.840.1.101.3.4.3.3",
        (KeyAlgorithm::Dsa, Sha512) => "2.16.840.1.101.3.4.3.4",
        _ => alg.oid(),
    }
}

/// OID del `signatureAlgorithm` de un SignerInfo creado por una firma simple
/// CAdES o por cualquier operación CMS: `rsaEncryption` si el nombre del
/// algoritmo contiene `withRSA`; si no, el OID del algoritmo de firma.
pub fn sign_signature_alg_oid(alg: SignatureAlgorithm) -> &'static str {
    if alg.java_name().contains("withRSA") {
        oids::RSA_ENCRYPTION
    } else {
        signature_oid(alg)
    }
}

/// OID del `signatureAlgorithm` en las cofirmas y contrafirmas CAdES:
/// huella del algoritmo compuesta con el tipo de clave del certificado.
pub fn multisign_signature_alg_oid(digest: DigestAlgorithm, cert_key: KeyAlgorithm) -> &'static str {
    signature_oid(SignatureAlgorithm::new(digest, cert_key))
}

/// Tipo de clave a partir del OID del algoritmo de clave pública.
pub fn key_algorithm_from_spki_oid(oid: &Oid) -> Option<KeyAlgorithm> {
    match oid.to_dotted().as_str() {
        oids::RSA_ENCRYPTION => Some(KeyAlgorithm::Rsa),
        oids::EC_PUBLIC_KEY => Some(KeyAlgorithm::Ec),
        oids::DSA => Some(KeyAlgorithm::Dsa),
        _ => None,
    }
}

const RSA_OIDS: [&str; 10] = [
    oids::RSA_ENCRYPTION,
    "1.2.840.113549.1.1.5",
    "1.2.840.113549.1.1.14",
    "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12",
    "1.2.840.113549.1.1.13",
    "2.16.840.1.101.3.4.3.13",
    "2.16.840.1.101.3.4.3.14",
    "2.16.840.1.101.3.4.3.15",
    "2.16.840.1.101.3.4.3.16",
];
const ECDSA_OIDS: [&str; 9] = [
    "1.2.840.10045.4.1",
    "1.2.840.10045.4.3.1",
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.10045.4.3.4",
    "2.16.840.1.101.3.4.3.9",
    "2.16.840.1.101.3.4.3.10",
    "2.16.840.1.101.3.4.3.11",
    "2.16.840.1.101.3.4.3.12",
];
const DSA_OIDS: [&str; 10] = [
    oids::DSA,
    "1.2.840.10040.4.3",
    "2.16.840.1.101.3.4.3.1",
    "2.16.840.1.101.3.4.3.2",
    "2.16.840.1.101.3.4.3.3",
    "2.16.840.1.101.3.4.3.4",
    "2.16.840.1.101.3.4.3.5",
    "2.16.840.1.101.3.4.3.6",
    "2.16.840.1.101.3.4.3.7",
    "2.16.840.1.101.3.4.3.8",
];

/// Tipo de clave de un OID de `signatureAlgorithm` (`AOAlgorithmID.isRSAOID`...).
pub fn key_algorithm_from_signature_oid(oid: &str) -> Option<KeyAlgorithm> {
    if RSA_OIDS.contains(&oid) {
        Some(KeyAlgorithm::Rsa)
    } else if ECDSA_OIDS.contains(&oid) {
        Some(KeyAlgorithm::Ec)
    } else if DSA_OIDS.contains(&oid) {
        Some(KeyAlgorithm::Dsa)
    } else {
        None
    }
}

/// Nombre del algoritmo de firma de un SignerInfo como lo informa
/// `ReadNodesTree.getSignatureAlgorithm` (`SHA256withRSA`; los OID
/// desconocidos se dejan tal cual).
pub fn tree_signature_algorithm_name(digest_oid: &str, signature_oid: &str) -> String {
    let d = match digest_oid {
        "2.16.840.1.101.3.4.2.3" => "SHA512".to_string(),
        "2.16.840.1.101.3.4.2.1" => "SHA256".to_string(),
        "2.16.840.1.101.3.4.2.2" => "SHA384".to_string(),
        "1.3.14.3.2.26" => "SHA1".to_string(),
        other => other.to_string(),
    };
    let e = match key_algorithm_from_signature_oid(signature_oid) {
        Some(KeyAlgorithm::Rsa) => "RSA".to_string(),
        Some(KeyAlgorithm::Dsa) => "DSA".to_string(),
        Some(KeyAlgorithm::Ec) => "ECDSA".to_string(),
        None => signature_oid.to_string(),
    };
    format!("{d}with{e}")
}

/// Algoritmo de firma de un SignerInfo deducido de su huella y su
/// `signatureAlgorithm` (para verificar). Si el OID de firma es
/// `rsaEncryption` (o un OID de clave pública) se usa la huella del SignerInfo.
pub fn signer_signature_algorithm(digest_oid: &str, signature_oid: &str) -> Option<SignatureAlgorithm> {
    let digest = DigestAlgorithm::from_oid(digest_oid)?;
    if let Some(full) = SignatureAlgorithm::from_oid(signature_oid) {
        // Los OID completos llevan su propia huella; si no coincide con la del
        // SignerInfo la verificación usará la del OID (como Bouncy Castle).
        return Some(full);
    }
    let key = match signature_oid {
        oids::RSA_ENCRYPTION => KeyAlgorithm::Rsa,
        oids::EC_PUBLIC_KEY => KeyAlgorithm::Ec,
        oids::DSA => KeyAlgorithm::Dsa,
        "2.16.840.1.101.3.4.3.3" | "2.16.840.1.101.3.4.3.4" => KeyAlgorithm::Dsa,
        _ => return None,
    };
    Some(SignatureAlgorithm::new(digest, key))
}

/// Lista de algoritmos SHA-2 para los que AutoFirma fuerza
/// `signingCertificateV2` (`AOSignConstants.isSHA2SignatureAlgorithm`).
pub fn is_sha2_signature_algorithm(java_name: &str) -> bool {
    matches!(
        java_name,
        "SHA256withRSA" | "SHA384withRSA" | "SHA512withRSA" | "SHA256withECDSA" | "SHA384withECDSA" | "SHA512withECDSA"
    )
}

/// Indica si un nombre de algoritmo usa SHA-1 (`AOSignConstants.isSHA1SignatureAlgorithm`).
pub fn is_sha1_signature_algorithm(name: &str) -> bool {
    java_digest_algorithm_name(name) == "SHA1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(digest_from_java_name("SHA256withRSA"), Some(DigestAlgorithm::Sha256));
        assert_eq!(digest_from_java_name("SHA-512"), Some(DigestAlgorithm::Sha512));
        assert_eq!(
            digest_from_java_name("http://www.w3.org/2000/09/xmldsig#sha1"),
            Some(DigestAlgorithm::Sha1)
        );
        assert_eq!(digest_from_java_name("1.3.14.3.2.26"), Some(DigestAlgorithm::Sha1));
        assert_eq!(digest_from_java_name("SHA224withRSA"), Some(DigestAlgorithm::Sha224));
        assert_eq!(digest_from_java_name("MD5withRSA"), None);
        assert_eq!(digest_from_java_name("urn:oid:1.3.14.3.2.26"), None);
        let rsa = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa);
        let ec = SignatureAlgorithm::new(DigestAlgorithm::Sha256, KeyAlgorithm::Ec);
        assert_eq!(sign_signature_alg_oid(rsa), oids::RSA_ENCRYPTION);
        assert_eq!(sign_signature_alg_oid(ec), "1.2.840.10045.4.3.2");
        assert_eq!(
            multisign_signature_alg_oid(DigestAlgorithm::Sha256, KeyAlgorithm::Rsa),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(
            tree_signature_algorithm_name("2.16.840.1.101.3.4.2.1", oids::RSA_ENCRYPTION),
            "SHA256withRSA"
        );
        assert_eq!(
            tree_signature_algorithm_name("2.16.840.1.101.3.4.2.4", "1.2.840.10045.4.3.1"),
            "2.16.840.1.101.3.4.2.4withECDSA"
        );
        assert_eq!(
            signer_signature_algorithm("2.16.840.1.101.3.4.2.1", oids::RSA_ENCRYPTION),
            Some(rsa)
        );
    }
}
