//! Almacenes PKCS#12 (`.p12`, `.pfx`).

use afirma_core::key::KeyError;
use x509_parser::prelude::*;

use crate::software::SoftwareKey;

/// Error al abrir un PKCS#12.
#[derive(Debug, thiserror::Error)]
pub enum Pkcs12Error {
    #[error("la contraseña del almacén no es correcta")]
    WrongPassword,
    #[error("el fichero no es un almacén PKCS#12 válido: {0}")]
    Invalid(String),
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// Entrada con clave privada de un PKCS#12.
#[derive(Clone)]
pub struct Pkcs12Entry {
    pub alias: String,
    /// PrivateKeyInfo (PKCS#8) en DER.
    pkcs8: Vec<u8>,
    /// Cadena (el primero es el certificado de la clave).
    pub chain: Vec<Vec<u8>>,
}

impl std::fmt::Debug for Pkcs12Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs12Entry").field("alias", &self.alias).field("chain", &self.chain.len()).finish()
    }
}

impl Pkcs12Entry {
    pub fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    #[cfg(test)]
    pub(crate) fn pkcs8_for_tests(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn signing_key(&self) -> Result<SoftwareKey, KeyError> {
        SoftwareKey::from_pkcs8(&self.pkcs8, self.chain.clone(), Some(self.alias.clone()))
    }
}

/// Abre un PKCS#12 y devuelve sus entradas con clave privada (error si no
/// tiene ninguna).
pub fn open(data: &[u8], password: &str) -> Result<Vec<Pkcs12Entry>, Pkcs12Error> {
    let out = open_entries(data, password)?;
    if out.is_empty() {
        return Err(Pkcs12Error::Invalid("no contiene ninguna clave privada con certificado".into()));
    }
    Ok(out)
}

/// Abre un PKCS#12 y devuelve sus entradas con clave privada (posiblemente
/// ninguna).
///
/// Alias como el `PKCS12KeyStore` de Java: el `friendlyName` de la bolsa de
/// la clave **en minúsculas** (Java indexa las entradas con
/// `alias.toLowerCase(Locale.ENGLISH)` y `aliases()` devuelve esas claves);
/// si no tiene, `"1"`, `"2"`… por orden de las claves sin nombre. A
/// diferencia de Java (que sobrescribe la entrada anterior), los alias
/// repetidos se conservan añadiendo `" (1)"`, `" (2)"`…
pub fn open_entries(data: &[u8], password: &str) -> Result<Vec<Pkcs12Entry>, Pkcs12Error> {
    let archive = p12_keystore::Pkcs12Archive::from_pkcs12(data, password).map_err(|e| match e {
        p12_keystore::error::Error::MacError(_) => Pkcs12Error::WrongPassword,
        p12_keystore::error::Error::UnpadError => Pkcs12Error::WrongPassword,
        other => Pkcs12Error::Invalid(other.to_string()),
    })?;
    let certs: Vec<(Option<Vec<u8>>, Vec<u8>)> =
        archive.certs.iter().map(|c| (c.local_key_id.clone(), c.cert.as_der().to_vec())).collect();
    let single_key = archive.keys.len() == 1;
    let mut out = Vec::new();
    let mut aliases = crate::store::AliasSet::new();
    let mut unfriendly = 0u32;
    for key in archive.keys {
        let pkcs8 = key.key.as_der().to_vec();
        // 1) Por localKeyId; 2) si solo hay una clave, el primer certificado
        // (rodeo de Java para PKCS#12 sin localKeyId); 3) por clave pública.
        let by_id = key.local_key_id.as_ref().and_then(|id| {
            certs.iter().find(|(cid, _)| cid.as_deref() == Some(id.0.as_slice())).map(|(_, der)| der.clone())
        });
        let leaf = by_id.or_else(|| {
            let spki = public_key_of_pkcs8(&pkcs8)?;
            certs.iter().find(|(_, der)| cert_spki_key(der).as_deref() == Some(spki.as_slice())).map(|(_, d)| d.clone())
        });
        let leaf = leaf.or_else(|| if single_key && key.local_key_id.is_none() { certs.first().map(|(_, d)| d.clone()) } else { None });
        let Some(leaf) = leaf else { continue };
        let chain = build_chain(&leaf, certs.iter().map(|(_, d)| d.as_slice()));
        let alias = match key.friendly_name.as_deref() {
            Some(n) => n.to_lowercase(),
            None => {
                unfriendly += 1;
                unfriendly.to_string()
            }
        };
        let alias = aliases.unique(&alias);
        out.push(Pkcs12Entry { alias, pkcs8, chain });
    }
    Ok(out)
}

/// Construye la cadena a partir del certificado final usando los
/// certificados disponibles (por emisor/sujeto).
pub fn build_chain<'a>(leaf: &[u8], pool: impl Iterator<Item = &'a [u8]> + Clone) -> Vec<Vec<u8>> {
    let mut chain = vec![leaf.to_vec()];
    let mut current = leaf.to_vec();
    for _ in 0..10 {
        let Ok((_, cert)) = X509Certificate::from_der(&current) else { break };
        if cert.subject().as_raw() == cert.issuer().as_raw() {
            break;
        }
        let issuer_raw = cert.issuer().as_raw().to_vec();
        let next = pool.clone().find(|cand| {
            X509Certificate::from_der(cand)
                .map(|(_, c)| c.subject().as_raw() == issuer_raw.as_slice())
                .unwrap_or(false)
        });
        match next {
            Some(n) if !chain.iter().any(|c| c.as_slice() == n) => {
                chain.push(n.to_vec());
                current = n.to_vec();
            }
            _ => break,
        }
    }
    chain
}

fn cert_spki_key(der: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    Some(cert.public_key().subject_public_key.data.to_vec())
}

/// Clave pública (contenido del BIT STRING de la SPKI) correspondiente a una
/// clave PKCS#8, para emparejarla con su certificado.
fn public_key_of_pkcs8(pkcs8: &[u8]) -> Option<Vec<u8>> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::DecodePrivateKey;
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8) {
        return k.to_public_key().to_pkcs1_der().ok().map(|d| d.as_bytes().to_vec());
    }
    if let Ok(k) = p256::SecretKey::from_pkcs8_der(pkcs8) {
        return Some(k.public_key().to_sec1_bytes().to_vec());
    }
    if let Ok(k) = p384::SecretKey::from_pkcs8_der(pkcs8) {
        return Some(k.public_key().to_sec1_bytes().to_vec());
    }
    if let Ok(k) = p521::SecretKey::from_pkcs8_der(pkcs8) {
        return Some(k.public_key().to_sec1_bytes().to_vec());
    }
    None
}

#[cfg(test)]
mod tests {
    use afirma_core::{DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm, SigningKey};

    fn testdata(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki").join(name)).unwrap()
    }

    fn verify(cert_der: &[u8], alg: SignatureAlgorithm, data: &[u8], sig: &[u8]) -> bool {
        use x509_parser::prelude::*;
        let (_, cert) = X509Certificate::from_der(cert_der).unwrap();
        let spki = cert.public_key().subject_public_key.data.to_vec();
        let ring_alg: &dyn ring::signature::VerificationAlgorithm = match (alg.key, alg.digest) {
            (KeyAlgorithm::Rsa, DigestAlgorithm::Sha1) => &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
            (KeyAlgorithm::Rsa, DigestAlgorithm::Sha256) => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            (KeyAlgorithm::Rsa, DigestAlgorithm::Sha512) => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            (KeyAlgorithm::Ec, DigestAlgorithm::Sha256) => &ring::signature::ECDSA_P256_SHA256_ASN1,
            (KeyAlgorithm::Ec, DigestAlgorithm::Sha384) => &ring::signature::ECDSA_P256_SHA384_ASN1,
            _ => unreachable!(),
        };
        ring::signature::UnparsedPublicKey::new(ring_alg, spki).verify(data, sig).is_ok()
    }

    #[test]
    fn opens_modern_and_legacy_p12_and_signs() {
        for (file, key, algs) in [
            ("firmante-rsa.p12", KeyAlgorithm::Rsa, vec![DigestAlgorithm::Sha256, DigestAlgorithm::Sha512, DigestAlgorithm::Sha1]),
            ("firmante-rsa-legacy.p12", KeyAlgorithm::Rsa, vec![DigestAlgorithm::Sha256]),
            ("firmante-ec.p12", KeyAlgorithm::Ec, vec![DigestAlgorithm::Sha256, DigestAlgorithm::Sha384]),
            ("firmante-ec-legacy.p12", KeyAlgorithm::Ec, vec![DigestAlgorithm::Sha256]),
        ] {
            let entries = super::open(&testdata(file), "12341234").unwrap();
            assert_eq!(entries.len(), 1, "{file}");
            let e = &entries[0];
            assert_eq!(e.chain.len(), 2, "{file}: cadena con la CA");
            let k = e.signing_key().unwrap();
            assert_eq!(k.key_algorithm(), key);
            for d in algs {
                let alg = SignatureAlgorithm::new(d, key);
                let sig = k.sign(b"datos a firmar", alg).unwrap();
                assert!(verify(k.certificate(), alg, b"datos a firmar", &sig), "{file} {alg}");
            }
        }
    }

    #[test]
    fn wrong_password() {
        assert!(matches!(super::open(&testdata("firmante-rsa.p12"), "mala"), Err(super::Pkcs12Error::WrongPassword)));
    }
}
