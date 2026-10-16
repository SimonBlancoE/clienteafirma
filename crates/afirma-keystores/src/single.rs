//! Almacén de certificados sueltos `SINGLE` ("PKCS#7 / X.509"): un fichero
//! con un certificado X.509 (DER, PEM o Base64) o un PKCS#7 (`.p7b`, DER o
//! PEM) con varios. No tiene claves privadas; los alias son el CN del
//! titular (`SingleCertKeyStore`).

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use afirma_core::key::SigningKey;

use crate::error::KeyStoreError;
use crate::kind::KeyStoreKind;
use crate::store::{AliasSet, CertEntry, EntryCapabilities, KeyStore};

/// Almacén de certificados sueltos.
pub struct SingleCertStore {
    path: PathBuf,
    entries: RwLock<Vec<CertEntry>>,
}

impl SingleCertStore {
    pub fn open(path: &Path) -> Result<SingleCertStore, KeyStoreError> {
        let entries = load(path)?;
        Ok(SingleCertStore {
            path: path.to_path_buf(),
            entries: RwLock::new(entries),
        })
    }
}

fn load(path: &Path) -> Result<Vec<CertEntry>, KeyStoreError> {
    let data = std::fs::read(path).map_err(|_| KeyStoreError::FileNotFound(path.to_path_buf()))?;
    let certs = parse_certificates(&data);
    if certs.is_empty() {
        return Err(KeyStoreError::load(
            KeyStoreKind::Single,
            "El fichero no contiene certificados X.509 ni PKCS#7",
        ));
    }
    let mut aliases = AliasSet::new();
    Ok(certs
        .into_iter()
        .map(|c| {
            let alias = aliases.unique(&afirma_core::cert::common_name(&c));
            CertEntry::new(
                alias,
                c.clone(),
                vec![c],
                EntryCapabilities::default(),
                KeyStoreKind::Single.display_name(),
            )
        })
        .collect())
}

/// Certificados de un fichero X.509 o PKCS#7 (DER o PEM).
pub fn parse_certificates(data: &[u8]) -> Vec<Vec<u8>> {
    if let Some(c) = afirma_core::cert::decode_certificate(data) {
        return vec![c];
    }
    let der = match std::str::from_utf8(data) {
        Ok(text) if text.contains("-----BEGIN") || !data.starts_with(&[0x30]) => {
            let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
            afirma_core::base64_decode_lenient(&b64).unwrap_or_default()
        }
        _ => data.to_vec(),
    };
    pkcs7_certificates(&der).unwrap_or_default()
}

/// `(etiqueta, contenido, TLV completo, resto)`.
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// Lee un TLV DER.
fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, hdr) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in input.get(2..2 + n)? {
            len = (len << 8) | usize::from(*b);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let content = input.get(hdr..end)?;
    Some((tag, content, &input[..end], &input[end..]))
}

/// Certificados del campo `certificates` de un `SignedData` PKCS#7.
fn pkcs7_certificates(der: &[u8]) -> Option<Vec<Vec<u8>>> {
    const SIGNED_DATA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    let (t, ci, _, _) = tlv(der)?;
    if t != 0x30 || !ci.starts_with(SIGNED_DATA) {
        return None;
    }
    let (t, explicit, _, _) = tlv(&ci[SIGNED_DATA.len()..])?;
    if t != 0xa0 {
        return None;
    }
    let (t, sd, _, _) = tlv(explicit)?;
    if t != 0x30 {
        return None;
    }
    let mut rest = sd;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (tag, content, _, next) = tlv(rest)?;
        if tag == 0xa0 {
            let mut certs = content;
            while !certs.is_empty() {
                let (ct, _, whole, n) = tlv(certs)?;
                if ct == 0x30 && afirma_core::cert::CertInfo::parse(whole).is_some() {
                    out.push(whole.to_vec());
                }
                certs = n;
            }
        }
        rest = next;
    }
    Some(out)
}

impl KeyStore for SingleCertStore {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Single
    }

    fn lib_name(&self) -> Option<String> {
        self.path.file_name().map(|n| n.to_string_lossy().into_owned())
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        Ok(self.entries.read().map(|e| e.clone()).unwrap_or_default())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        Err(KeyStoreError::NoPrivateKey(alias.to_string()))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        let new = load(&self.path);
        if let Ok(mut e) = self.entries.write() {
            match new {
                Ok(n) => *e = n,
                Err(err) => {
                    e.clear();
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pem_and_pkcs7() {
        let pki = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki");
        let s = SingleCertStore::open(&pki.join("firmante-rsa.crt")).unwrap();
        let e = s.entries().unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].alias, "ESPAÑOL ESPAÑOL JUAN - 00000000T");
        assert!(!e[0].capabilities.has_private_key);
        assert!(s.signing_key(&e[0].alias).is_err());
        // PKCS#7 generado con openssl crl2pkcs7 (si está disponible).
        let tmp = tempfile::tempdir().unwrap();
        let p7b = tmp.path().join("cadena.p7b");
        let ok = std::process::Command::new("openssl")
            .args(["crl2pkcs7", "-nocrl", "-certfile"])
            .arg(pki.join("firmante-rsa.crt"))
            .arg("-certfile")
            .arg(pki.join("ca.crt"))
            .arg("-outform")
            .arg("DER")
            .arg("-out")
            .arg(&p7b)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            let s = SingleCertStore::open(&p7b).unwrap();
            let aliases: Vec<String> = s.entries().unwrap().into_iter().map(|e| e.alias).collect();
            assert_eq!(
                aliases,
                vec![
                    "ESPAÑOL ESPAÑOL JUAN - 00000000T".to_string(),
                    "AC Raiz de Pruebas AutoFirma-rs".to_string()
                ]
            );
        }
    }
}
