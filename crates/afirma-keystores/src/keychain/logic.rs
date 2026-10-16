//! Lógica del llavero independiente de Security.framework (alias,
//! eliminación de duplicados, algoritmos y traducción de errores), separada
//! para poder probarla en cualquier sistema.

use std::collections::HashSet;

use afirma_core::algorithms::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm};
use afirma_core::key::KeyError;
use x509_parser::prelude::*;

/// Asigna los alias como el `KeychainStore` de Java (`createKeyEntry`):
/// el alias es la etiqueta del certificado; si su versión en minúsculas ya
/// existe se prueba `"<etiqueta> 1"`, `"<etiqueta> 2"`… y el alias que se
/// expone es el guardado en el mapa, **en minúsculas** (`entries` se indexa
/// con `alias.toLowerCase()` y `aliases()` devuelve esas claves).
pub(crate) fn java_aliases<S: AsRef<str>>(labels: &[S]) -> Vec<String> {
    let mut used: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        let original = label.as_ref();
        let mut alias = original.to_string();
        let mut n = 1u32;
        while used.contains(&alias.to_lowercase()) {
            alias = format!("{original} {n}");
            n += 1;
        }
        let lower = alias.to_lowercase();
        used.insert(lower.clone());
        out.push(lower);
    }
    out
}

/// Número de serie del certificado normalizado como entero en complemento a
/// dos mínimo (dos números de serie son iguales si lo son sus valores, como
/// `BigInteger.equals`). `None` si el certificado no se puede analizar.
pub(crate) fn serial_key(cert_der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let mut s: &[u8] = cert.raw_serial();
    while s.len() > 1 && ((s[0] == 0x00 && s[1] & 0x80 == 0) || (s[0] == 0xff && s[1] & 0x80 != 0)) {
        s = &s[1..];
    }
    Some(s.to_vec())
}

/// Índices de las identidades que se conservan tras eliminar duplicados por
/// número de serie (`AppleKeyStoreManager.getAliasesWithoutDuplicates`): la
/// primera de cada número de serie; las que no se pueden analizar se
/// descartan (en Java `getCertificate` devuelve `null`).
pub(crate) fn dedup_by_serial<C: AsRef<[u8]>>(certs: &[C]) -> Vec<usize> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut keep = Vec::new();
    for (i, c) in certs.iter().enumerate() {
        match serial_key(c.as_ref()) {
            Some(serial) => {
                if seen.insert(serial) {
                    keep.push(i);
                } else {
                    tracing::info!(
                        "Se retira el certificado del llavero con indice {i} por tener un numero de serie duplicado"
                    );
                }
            }
            None => tracing::warn!("No se pudo analizar el certificado de la identidad {i} del llavero"),
        }
    }
    keep
}

/// Algoritmo de firma de Security.framework sobre una huella ya calculada
/// (`kSecKeyAlgorithm…SignatureDigest…`). Nunca se usan los algoritmos
/// `…Message…` para no depender de que el dispositivo calcule la huella y
/// para poder firmar huellas calculadas fuera (firma trifásica).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DigestSignAlgorithm {
    RsaPkcs1v15Sha1,
    RsaPkcs1v15Sha224,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha512,
    EcdsaX962Sha1,
    EcdsaX962Sha224,
    EcdsaX962Sha256,
    EcdsaX962Sha384,
    EcdsaX962Sha512,
}

impl DigestSignAlgorithm {
    /// Algoritmo para `SHAxxxwithRSA` / `SHAxxxwithECDSA` (DSA no está
    /// soportado por el llavero).
    pub(crate) fn for_signature(alg: SignatureAlgorithm) -> Result<Self, KeyError> {
        use DigestAlgorithm::*;
        Ok(match (alg.key, alg.digest) {
            (KeyAlgorithm::Rsa, Sha1) => Self::RsaPkcs1v15Sha1,
            (KeyAlgorithm::Rsa, Sha224) => Self::RsaPkcs1v15Sha224,
            (KeyAlgorithm::Rsa, Sha256) => Self::RsaPkcs1v15Sha256,
            (KeyAlgorithm::Rsa, Sha384) => Self::RsaPkcs1v15Sha384,
            (KeyAlgorithm::Rsa, Sha512) => Self::RsaPkcs1v15Sha512,
            (KeyAlgorithm::Ec, Sha1) => Self::EcdsaX962Sha1,
            (KeyAlgorithm::Ec, Sha224) => Self::EcdsaX962Sha224,
            (KeyAlgorithm::Ec, Sha256) => Self::EcdsaX962Sha256,
            (KeyAlgorithm::Ec, Sha384) => Self::EcdsaX962Sha384,
            (KeyAlgorithm::Ec, Sha512) => Self::EcdsaX962Sha512,
            (KeyAlgorithm::Dsa, _) => return Err(KeyError::Unsupported(alg.java_name())),
        })
    }

    /// Nombre de la constante de Security.framework.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn apple_name(self) -> &'static str {
        match self {
            Self::RsaPkcs1v15Sha1 => "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1",
            Self::RsaPkcs1v15Sha224 => "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224",
            Self::RsaPkcs1v15Sha256 => "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256",
            Self::RsaPkcs1v15Sha384 => "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384",
            Self::RsaPkcs1v15Sha512 => "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512",
            Self::EcdsaX962Sha1 => "kSecKeyAlgorithmECDSASignatureDigestX962SHA1",
            Self::EcdsaX962Sha224 => "kSecKeyAlgorithmECDSASignatureDigestX962SHA224",
            Self::EcdsaX962Sha256 => "kSecKeyAlgorithmECDSASignatureDigestX962SHA256",
            Self::EcdsaX962Sha384 => "kSecKeyAlgorithmECDSASignatureDigestX962SHA384",
            Self::EcdsaX962Sha512 => "kSecKeyAlgorithmECDSASignatureDigestX962SHA512",
        }
    }
}

/// Dominio de los `CFError` con un `OSStatus` como código.
pub(crate) const OSSTATUS_DOMAIN: &str = "NSOSStatusErrorDomain";
/// Dominio de los errores de CryptoTokenKit (`TKErrorDomain`).
pub(crate) const CTK_DOMAIN: &str = "CryptoTokenKit";
/// Dominio de los errores de LocalAuthentication (`LAErrorDomain`).
pub(crate) const LA_DOMAIN: &str = "com.apple.LocalAuthentication";

/// `errSecUserCanceled`
pub(crate) const ERR_SEC_USER_CANCELED: i64 = -128;
/// `errSecAuthFailed`
pub(crate) const ERR_SEC_AUTH_FAILED: i64 = -25293;
/// `errSecNoSuchKeychain`
pub(crate) const ERR_SEC_NO_SUCH_KEYCHAIN: i64 = -25294;
/// `errSecItemNotFound`
pub(crate) const ERR_SEC_ITEM_NOT_FOUND: i64 = -25300;
/// `errSecInteractionNotAllowed`
pub(crate) const ERR_SEC_INTERACTION_NOT_ALLOWED: i64 = -25308;

/// Traduce un error de Security.framework / CryptoTokenKit /
/// LocalAuthentication al modelo de errores de clave.
pub(crate) fn map_error(domain: &str, code: i64, description: &str) -> KeyError {
    match (domain, code) {
        (OSSTATUS_DOMAIN, ERR_SEC_USER_CANCELED) => KeyError::Cancelled,
        (OSSTATUS_DOMAIN, ERR_SEC_AUTH_FAILED) => KeyError::WrongPin,
        (OSSTATUS_DOMAIN, ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_ITEM_NOT_FOUND | ERR_SEC_NO_SUCH_KEYCHAIN) => {
            KeyError::DeviceUnavailable
        }
        // TKErrorCodeCanceledByUser
        (CTK_DOMAIN, -4) => KeyError::Cancelled,
        // TKErrorCodeAuthenticationFailed
        (CTK_DOMAIN, -5) => KeyError::WrongPin,
        // TKErrorCodeCommunicationError, TKErrorCodeObjectNotFound, TKErrorCodeTokenNotFound
        (CTK_DOMAIN, -2 | -6 | -7) => KeyError::DeviceUnavailable,
        // LAErrorUserCancel, LAErrorSystemCancel, LAErrorAppCancel
        (LA_DOMAIN, -2 | -4 | -9) => KeyError::Cancelled,
        // LAErrorAuthenticationFailed
        (LA_DOMAIN, -1) => KeyError::WrongPin,
        // LAErrorBiometryLockout
        (LA_DOMAIN, -8) => KeyError::PinLocked,
        _ => KeyError::Other(format!("{description} (dominio {domain}, código {code})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pki(name: &str) -> Vec<u8> {
        let pem = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/pki")
                .join(name),
        )
        .unwrap();
        afirma_core::cert::decode_certificate(&pem).unwrap()
    }

    #[test]
    fn aliases_like_java_keychainstore() {
        let a = java_aliases(&["Juan", "JUAN", "juan 1", "Otro", "juan"]);
        assert_eq!(a, vec!["juan", "juan 1", "juan 1 1", "otro", "juan 2"]);
        assert_eq!(java_aliases::<&str>(&[]), Vec::<String>::new());
        assert_eq!(java_aliases(&["ESPAÑOL ESPAÑOL JUAN"]), vec!["español español juan"]);
    }

    #[test]
    fn serial_dedup_keeps_first() {
        let rsa = pki("firmante-rsa.crt");
        let ec = pki("firmante-ec.crt");
        let certs = vec![rsa.clone(), b"basura".to_vec(), ec.clone(), rsa.clone()];
        assert_eq!(dedup_by_serial(&certs), vec![0, 2]);
        assert_ne!(serial_key(&rsa), serial_key(&ec));
        // 0x0badc0de del certificado caducado.
        assert_eq!(serial_key(&pki("caducado.crt")).unwrap(), vec![0x0b, 0xad, 0xc0, 0xde]);
    }

    #[test]
    fn algorithm_mapping() {
        use DigestAlgorithm::*;
        for d in DigestAlgorithm::ALL {
            let rsa = DigestSignAlgorithm::for_signature(SignatureAlgorithm::new(d, KeyAlgorithm::Rsa)).unwrap();
            assert!(
                rsa.apple_name()
                    .starts_with("kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA")
            );
            let ec = DigestSignAlgorithm::for_signature(SignatureAlgorithm::new(d, KeyAlgorithm::Ec)).unwrap();
            assert!(
                ec.apple_name()
                    .starts_with("kSecKeyAlgorithmECDSASignatureDigestX962SHA")
            );
        }
        assert_eq!(
            DigestSignAlgorithm::for_signature(SignatureAlgorithm::new(Sha256, KeyAlgorithm::Rsa))
                .unwrap()
                .apple_name(),
            "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256"
        );
        assert!(matches!(
            DigestSignAlgorithm::for_signature(SignatureAlgorithm::new(Sha1, KeyAlgorithm::Dsa)),
            Err(KeyError::Unsupported(_))
        ));
    }

    #[test]
    fn error_mapping() {
        assert_eq!(map_error(OSSTATUS_DOMAIN, -128, ""), KeyError::Cancelled);
        assert_eq!(map_error(OSSTATUS_DOMAIN, -25293, ""), KeyError::WrongPin);
        assert_eq!(map_error(OSSTATUS_DOMAIN, -25308, ""), KeyError::DeviceUnavailable);
        assert_eq!(map_error(CTK_DOMAIN, -7, ""), KeyError::DeviceUnavailable);
        assert_eq!(map_error(CTK_DOMAIN, -4, ""), KeyError::Cancelled);
        assert_eq!(map_error(LA_DOMAIN, -8, ""), KeyError::PinLocked);
        assert!(matches!(map_error(OSSTATUS_DOMAIN, -50, "param"), KeyError::Other(m) if m.contains("-50")));
    }
}
