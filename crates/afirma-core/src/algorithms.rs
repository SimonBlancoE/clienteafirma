//! Algoritmos de huella digital y de firma.

use std::fmt;
use std::str::FromStr;

use digest::Digest;

/// Algoritmo de huella digital.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    pub const ALL: [DigestAlgorithm; 5] = [Self::Sha1, Self::Sha224, Self::Sha256, Self::Sha384, Self::Sha512];

    /// Nombre normalizado (`SHA-256`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Nombre sin guion tal y como aparece en los nombres de algoritmo de
    /// firma de Java (`SHA256`).
    pub fn java_prefix(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha224 => "SHA224",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }

    /// OID del algoritmo.
    pub fn oid(self) -> &'static str {
        match self {
            Self::Sha1 => "1.3.14.3.2.26",
            Self::Sha224 => "2.16.840.1.101.3.4.2.4",
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
        }
    }

    pub fn from_oid(oid: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.oid() == oid)
    }

    /// URI XMLDSig del algoritmo.
    pub fn xml_uri(self) -> &'static str {
        match self {
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            Self::Sha224 => "http://www.w3.org/2001/04/xmldsig-more#sha224",
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
    }

    pub fn from_xml_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#sha384" => Some(Self::Sha384),
            "http://www.w3.org/2001/04/xmldsig-more#sha256" => Some(Self::Sha256),
            "http://www.w3.org/2001/04/xmldsig-more#sha512" => Some(Self::Sha512),
            _ => Self::ALL.into_iter().find(|d| d.xml_uri() == uri),
        }
    }

    /// Longitud de la huella en bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Calcula la huella de unos datos.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha224 => sha2::Sha224::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// Calculadora incremental (para ficheros grandes).
    pub fn hasher(self) -> Hasher {
        Hasher(match self {
            Self::Sha1 => HasherInner::Sha1(sha1::Sha1::new()),
            Self::Sha224 => HasherInner::Sha224(sha2::Sha224::new()),
            Self::Sha256 => HasherInner::Sha256(sha2::Sha256::new()),
            Self::Sha384 => HasherInner::Sha384(sha2::Sha384::new()),
            Self::Sha512 => HasherInner::Sha512(sha2::Sha512::new()),
        })
    }

    /// Prefijo DigestInfo (PKCS#1 v1.5) para este algoritmo.
    pub fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
            ],
            Self::Sha224 => &[
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00,
                0x04, 0x1c,
            ],
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
                0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
                0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
                0x04, 0x40,
            ],
        }
    }

    /// Estructura DigestInfo completa (prefijo + huella).
    pub fn digest_info(self, hash: &[u8]) -> Vec<u8> {
        let mut out = self.digest_info_prefix().to_vec();
        out.extend_from_slice(hash);
        out
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DigestAlgorithm {
    type Err = String;

    /// Acepta `SHA1`, `SHA-1`, `sha-256`, `SHA256`, `SHA512`... y sus OID.
    fn from_str(s: &str) -> Result<Self, String> {
        let norm: String = s
            .trim()
            .to_ascii_uppercase()
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .collect();
        Ok(match norm.as_str() {
            "SHA1" | "SHA" => Self::Sha1,
            "SHA224" => Self::Sha224,
            "SHA256" => Self::Sha256,
            "SHA384" => Self::Sha384,
            "SHA512" => Self::Sha512,
            _ => return Self::from_oid(s.trim()).ok_or_else(|| format!("algoritmo de huella no soportado: {s}")),
        })
    }
}

enum HasherInner {
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

/// Calculadora de huellas incremental.
pub struct Hasher(HasherInner);

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            HasherInner::Sha1(h) => h.update(data),
            HasherInner::Sha224(h) => h.update(data),
            HasherInner::Sha256(h) => h.update(data),
            HasherInner::Sha384(h) => h.update(data),
            HasherInner::Sha512(h) => h.update(data),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self.0 {
            HasherInner::Sha1(h) => h.finalize().to_vec(),
            HasherInner::Sha224(h) => h.finalize().to_vec(),
            HasherInner::Sha256(h) => h.finalize().to_vec(),
            HasherInner::Sha384(h) => h.finalize().to_vec(),
            HasherInner::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Tipo de clave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Rsa,
    /// ECDSA; el tamaño de curva se obtiene del certificado cuando hace falta.
    Ec,
    Dsa,
}

impl KeyAlgorithm {
    pub fn java_suffix(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Ec => "ECDSA",
            Self::Dsa => "DSA",
        }
    }
}

/// Algoritmo de firma: huella + tipo de clave (`SHA256withRSA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureAlgorithm {
    pub digest: DigestAlgorithm,
    pub key: KeyAlgorithm,
}

impl SignatureAlgorithm {
    pub const fn new(digest: DigestAlgorithm, key: KeyAlgorithm) -> Self {
        SignatureAlgorithm { digest, key }
    }

    /// Nombre al estilo Java (`SHA256withRSA`, `SHA512withECDSA`).
    pub fn java_name(self) -> String {
        format!("{}with{}", self.digest.java_prefix(), self.key.java_suffix())
    }

    /// OID del algoritmo de firma completo (p. ej. sha256WithRSAEncryption).
    pub fn oid(self) -> &'static str {
        use DigestAlgorithm::*;
        match (self.key, self.digest) {
            (KeyAlgorithm::Rsa, Sha1) => "1.2.840.113549.1.1.5",
            (KeyAlgorithm::Rsa, Sha224) => "1.2.840.113549.1.1.14",
            (KeyAlgorithm::Rsa, Sha256) => "1.2.840.113549.1.1.11",
            (KeyAlgorithm::Rsa, Sha384) => "1.2.840.113549.1.1.12",
            (KeyAlgorithm::Rsa, Sha512) => "1.2.840.113549.1.1.13",
            (KeyAlgorithm::Ec, Sha1) => "1.2.840.10045.4.1",
            (KeyAlgorithm::Ec, Sha224) => "1.2.840.10045.4.3.1",
            (KeyAlgorithm::Ec, Sha256) => "1.2.840.10045.4.3.2",
            (KeyAlgorithm::Ec, Sha384) => "1.2.840.10045.4.3.3",
            (KeyAlgorithm::Ec, Sha512) => "1.2.840.10045.4.3.4",
            (KeyAlgorithm::Dsa, Sha1) => "1.2.840.10040.4.3",
            (KeyAlgorithm::Dsa, Sha224) => "2.16.840.1.101.3.4.3.1",
            (KeyAlgorithm::Dsa, _) => "2.16.840.1.101.3.4.3.2",
        }
    }

    pub fn from_oid(oid: &str) -> Option<Self> {
        for key in [KeyAlgorithm::Rsa, KeyAlgorithm::Ec, KeyAlgorithm::Dsa] {
            for d in DigestAlgorithm::ALL {
                let s = SignatureAlgorithm::new(d, key);
                if s.oid() == oid {
                    return Some(s);
                }
            }
        }
        None
    }

    /// URI XMLDSig del algoritmo de firma.
    pub fn xml_uri(self) -> &'static str {
        use DigestAlgorithm::*;
        match (self.key, self.digest) {
            (KeyAlgorithm::Rsa, Sha1) => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            (KeyAlgorithm::Rsa, Sha224) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
            (KeyAlgorithm::Rsa, Sha256) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            (KeyAlgorithm::Rsa, Sha384) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            (KeyAlgorithm::Rsa, Sha512) => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            (KeyAlgorithm::Ec, Sha1) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
            (KeyAlgorithm::Ec, Sha224) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
            (KeyAlgorithm::Ec, Sha256) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            (KeyAlgorithm::Ec, Sha384) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            (KeyAlgorithm::Ec, Sha512) => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
            (KeyAlgorithm::Dsa, Sha1) => "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
            (KeyAlgorithm::Dsa, _) => "http://www.w3.org/2009/xmldsig11#dsa-sha256",
        }
    }

    pub fn from_xml_uri(uri: &str) -> Option<Self> {
        for key in [KeyAlgorithm::Rsa, KeyAlgorithm::Ec, KeyAlgorithm::Dsa] {
            for d in DigestAlgorithm::ALL {
                let s = SignatureAlgorithm::new(d, key);
                if s.xml_uri() == uri {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Interpreta un nombre de algoritmo de AutoFirma. Admite nombres
    /// completos (`SHA256withRSA`, `SHA-256withECDSA`, `SHA512WITHRSA`) y
    /// nombres de solo huella (`SHA256`), en cuyo caso el tipo de clave se toma
    /// de `key_hint`.
    pub fn parse(name: &str, key_hint: KeyAlgorithm) -> Result<Self, String> {
        let upper = name.trim().to_ascii_uppercase();
        if let Some(idx) = upper.find("WITH") {
            let digest: DigestAlgorithm = upper[..idx].parse()?;
            let key = match &upper[idx + 4..] {
                "RSA" | "RSAENCRYPTION" => KeyAlgorithm::Rsa,
                "ECDSA" | "EC" => KeyAlgorithm::Ec,
                "DSA" => KeyAlgorithm::Dsa,
                other => return Err(format!("tipo de clave no soportado: {other}")),
            };
            // Si la clave real no coincide con el nombre se usa la de la clave.
            let key = if key != key_hint { key_hint } else { key };
            Ok(SignatureAlgorithm::new(digest, key))
        } else {
            Ok(SignatureAlgorithm::new(upper.parse()?, key_hint))
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.java_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_names() {
        let a = SignatureAlgorithm::parse("SHA256withRSA", KeyAlgorithm::Rsa).unwrap();
        assert_eq!(a.java_name(), "SHA256withRSA");
        let b = SignatureAlgorithm::parse("SHA-512withECDSA", KeyAlgorithm::Ec).unwrap();
        assert_eq!(b, SignatureAlgorithm::new(DigestAlgorithm::Sha512, KeyAlgorithm::Ec));
        let c = SignatureAlgorithm::parse("sha384", KeyAlgorithm::Ec).unwrap();
        assert_eq!(c.java_name(), "SHA384withECDSA");
        let d = SignatureAlgorithm::parse("SHA256withRSA", KeyAlgorithm::Ec).unwrap();
        assert_eq!(d.key, KeyAlgorithm::Ec);
        assert!(SignatureAlgorithm::parse("MD5withRSA", KeyAlgorithm::Rsa).is_err());
    }

    #[test]
    fn digests() {
        assert_eq!(
            hex::encode(DigestAlgorithm::Sha256.digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut h = DigestAlgorithm::Sha1.hasher();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(hex::encode(h.finalize()), "a9993e364706816aba3e25717850c26c9cd0d89d");
        for d in DigestAlgorithm::ALL {
            assert_eq!(d.digest(b"").len(), d.output_len());
            assert_eq!(
                d.digest_info(&d.digest(b"")).len(),
                d.digest_info_prefix().len() + d.output_len()
            );
            assert_eq!(DigestAlgorithm::from_xml_uri(d.xml_uri()), Some(d));
            assert_eq!(d.name().parse::<DigestAlgorithm>().unwrap(), d);
        }
    }
}

/// Normaliza un nombre de algoritmo de huella como
/// `AOSignConstants.getDigestAlgorithmName` (devuelve `SHA1`, `SHA-256`,
/// `SHA-384`, `SHA-512`, `RIPEMD160` o el nombre original si no se reconoce).
pub fn java_digest_algorithm_name(pseudo_name: &str) -> String {
    let u = pseudo_name.to_uppercase();
    if u == "SHA"
        || u == "HTTP://WWW.W3.ORG/2000/09/XMLDSIG#SHA1"
        || u == "1.3.14.3.2.26"
        || u.starts_with("SHA1")
        || u.starts_with("SHA-1")
    {
        return "SHA1".into();
    }
    if u == "HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA256"
        || u == "2.16.840.1.101.3.4.2.1"
        || u.starts_with("SHA256")
        || u.starts_with("SHA-256")
    {
        return "SHA-256".into();
    }
    if u.starts_with("SHA384") || u == "2.16.840.1.101.3.4.2.2" || u.starts_with("SHA-384") {
        return "SHA-384".into();
    }
    if u == "HTTP://WWW.W3.ORG/2001/04/XMLENC#SHA512"
        || u == "2.16.840.1.101.3.4.2.3"
        || u.starts_with("SHA512")
        || u.starts_with("SHA-512")
    {
        return "SHA-512".into();
    }
    if u == "HTTP://WWW.W3.ORG/2001/04/XMLENC#RIPEMD160" || u.starts_with("RIPEMD160") || u.starts_with("RIPEMD-160") {
        return "RIPEMD160".into();
    }
    if let Some(idx) = pseudo_name.find("with") {
        return java_digest_algorithm_name(&pseudo_name[..idx]);
    }
    for prefix in [
        "http://www.w3.org/2001/04/xmldsig-more#",
        "http://www.w3.org/2000/09/xmldsig#",
        "http://www.w3.org/2009/xmldsig11#",
    ] {
        if pseudo_name.starts_with(prefix)
            && let Some(idx) = pseudo_name.rfind('-')
        {
            return java_digest_algorithm_name(&pseudo_name[idx + 1..]);
        }
    }
    pseudo_name.to_string()
}

/// Compone el algoritmo de firma a partir del nombre recibido y del tipo de
/// clave (`AOSignConstants.composeSignatureAlgorithmName`). Admite nombres de
/// huella (`SHA256`), de firma (`SHA512withRSA`, que con una clave EC pasa a
/// `SHA512withECDSA`) y URI XMLDSig.
pub fn compose_signature_algorithm(algorithm: &str, key: KeyAlgorithm) -> crate::error::Result<SignatureAlgorithm> {
    let digest_name = java_digest_algorithm_name(algorithm).replace('-', "");
    let digest: DigestAlgorithm = digest_name.parse().map_err(|_| {
        crate::error::AfirmaError::new(
            crate::error::codes::UNSUPPORTED_SIGNATURE_ALGORITHM,
            format!("No se soporta el algoritmo de firma: {algorithm}"),
        )
    })?;
    Ok(SignatureAlgorithm::new(digest, key))
}

#[cfg(test)]
mod java_name_tests {
    use super::*;

    #[test]
    fn java_normalisation() {
        assert_eq!(java_digest_algorithm_name("SHA512withRSA"), "SHA-512");
        assert_eq!(java_digest_algorithm_name("sha-256"), "SHA-256");
        assert_eq!(
            java_digest_algorithm_name("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
            "SHA-256"
        );
        assert_eq!(java_digest_algorithm_name("SHA1"), "SHA1");
        assert_eq!(java_digest_algorithm_name("MD5withRSA"), "MD5");
        let a = compose_signature_algorithm("SHA512withRSA", KeyAlgorithm::Ec).unwrap();
        assert_eq!(a.java_name(), "SHA512withECDSA");
        assert_eq!(
            compose_signature_algorithm("SHA-256", KeyAlgorithm::Rsa)
                .unwrap()
                .java_name(),
            "SHA256withRSA"
        );
        assert!(compose_signature_algorithm("MD5withRSA", KeyAlgorithm::Rsa).is_err());
    }
}

/// `AOSignConstants.composeSignatureAlgorithmName` con el resultado como
/// texto Java exacto. A diferencia de [`compose_signature_algorithm`], no
/// exige que la huella sea una de las soportadas: devuelve, por ejemplo,
/// `RIPEMD160withRSA`, `SHA224withECDSA` o `MD5withRSA`, igual que Java.
///
/// `key_type` es el valor de `Key.getAlgorithm()` de Java: `RSA`, `DSA` o un
/// texto que empiece por `EC`. Los errores reproducen las
/// `IllegalArgumentException` de Java.
pub fn compose_signature_algorithm_name(
    algorithm: Option<&str>,
    key_type: Option<&str>,
) -> crate::error::Result<String> {
    let algorithm = algorithm
        .ok_or_else(|| crate::error::AfirmaError::invalid_argument("El nombre del algoritmo no puede ser nulo"))?;
    let key_type = key_type.ok_or_else(|| {
        crate::error::AfirmaError::invalid_argument("El tipo de clave de certificado no puede ser nulo")
    })?;
    let digest = java_digest_algorithm_name(algorithm).replace('-', "");
    let suffix = if key_type == "RSA" {
        "withRSA"
    } else if key_type == "DSA" {
        "withDSA"
    } else if key_type.starts_with("EC") {
        "withECDSA"
    } else {
        return Err(crate::error::AfirmaError::invalid_argument(format!(
            "Tipo de clave de firma no soportado: {key_type}"
        )));
    };
    Ok(format!("{digest}{suffix}"))
}

/// `AOSignConstants.isSHA2SignatureAlgorithm`: nombre exacto (distinguiendo
/// mayúsculas) de RSA o ECDSA con SHA-256/384/512 (`SHA224withECDSA` no).
pub fn is_sha2_signature_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "SHA256withRSA" | "SHA384withRSA" | "SHA512withRSA" | "SHA256withECDSA" | "SHA384withECDSA" | "SHA512withECDSA"
    )
}

/// `AOSignConstants.isSHA1SignatureAlgorithm`.
pub fn is_sha1_signature_algorithm(algorithm: &str) -> bool {
    matches!(algorithm, "SHA1withRSA" | "SHA1withDSA" | "SHA1withECDSA")
}

/// `AOSignConstants.isDSAorECDSASignatureAlgorithm`: termina en `withECDSA`,
/// `withECDSAinP1363Format`, `withDSA` o `withDSAinP1363Format`.
pub fn is_dsa_or_ecdsa_signature_algorithm(algorithm: &str) -> bool {
    ["withECDSA", "withECDSAinP1363Format", "withDSA", "withDSAinP1363Format"]
        .iter()
        .any(|s| algorithm.ends_with(s))
}

impl KeyAlgorithm {
    /// Valor de `Key.getAlgorithm()` de Java para este tipo de clave (`RSA`,
    /// `EC`, `DSA`).
    pub fn java_key_type(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Ec => "EC",
            Self::Dsa => "DSA",
        }
    }
}

#[cfg(test)]
mod predicate_tests {
    use super::*;

    #[test]
    fn predicates() {
        assert!(is_sha2_signature_algorithm("SHA256withRSA"));
        assert!(is_sha2_signature_algorithm("SHA512withECDSA"));
        assert!(!is_sha2_signature_algorithm("SHA224withECDSA"));
        assert!(!is_sha2_signature_algorithm("sha256withrsa"));
        assert!(is_sha1_signature_algorithm("SHA1withDSA"));
        assert!(!is_sha1_signature_algorithm("SHA256withRSA"));
        assert!(is_dsa_or_ecdsa_signature_algorithm("SHA256withECDSA"));
        assert!(is_dsa_or_ecdsa_signature_algorithm("SHA256withECDSAinP1363Format"));
        assert!(is_dsa_or_ecdsa_signature_algorithm("SHA1withDSA"));
        assert!(!is_dsa_or_ecdsa_signature_algorithm("SHA1withRSA"));
    }

    #[test]
    fn compose_java_names() {
        let c = |a: &str, k: &str| compose_signature_algorithm_name(Some(a), Some(k)).unwrap();
        assert_eq!(c("SHA512withRSA", "EC"), "SHA512withECDSA");
        assert_eq!(c("SHA-256", "RSA"), "SHA256withRSA");
        assert_eq!(c("SHA224withECDSA", "EC"), "SHA224withECDSA");
        assert_eq!(c("MD5withRSA", "RSA"), "MD5withRSA");
        assert_eq!(
            c("http://www.w3.org/2001/04/xmlenc#ripemd160", "DSA"),
            "RIPEMD160withDSA"
        );
        assert_eq!(c("SHA1", "ECDSA"), "SHA1withECDSA");
        let e = compose_signature_algorithm_name(Some("SHA1"), Some("Ed25519")).unwrap_err();
        assert_eq!(e.message, "Tipo de clave de firma no soportado: Ed25519");
        assert!(compose_signature_algorithm_name(None, Some("RSA")).is_err());
        assert!(compose_signature_algorithm_name(Some("SHA1"), None).is_err());
        assert_eq!(KeyAlgorithm::Ec.java_key_type(), "EC");
        // GOTCHA documentado: el URI XML de SHA-384 se convierte en "more#sha384".
        assert_eq!(
            java_digest_algorithm_name("http://www.w3.org/2001/04/xmldsig-more#sha384"),
            "more#sha384"
        );
        assert_eq!(java_digest_algorithm_name("SHA224withECDSA"), "SHA224");
    }
}
