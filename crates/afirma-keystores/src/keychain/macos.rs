//! Implementación sobre Security.framework (solo macOS).

use std::ffi::c_void;
use std::sync::RwLock;

use afirma_core::algorithms::{KeyAlgorithm, SignatureAlgorithm};
use afirma_core::key::{KeyError, SigningKey};
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::string::{CFString, CFStringRef};
use security_framework::certificate::SecCertificate;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::policy::SecPolicy;
use security_framework::trust::SecTrust;
use security_framework_sys::item::{kSecAttrLabel, kSecAttrTokenID, kSecValueRef};
use security_framework_sys::key::{SecKeyIsAlgorithmSupported, kSecKeyOperationTypeSign};

use super::KeychainOptions;
use super::logic::{self, DigestSignAlgorithm};
use crate::error::KeyStoreError;
use crate::kind::KeyStoreKind;
use crate::store::{CertEntry, EntryCapabilities, KeyStore, find_entry};

impl From<DigestSignAlgorithm> for Algorithm {
    fn from(a: DigestSignAlgorithm) -> Algorithm {
        match a {
            DigestSignAlgorithm::RsaPkcs1v15Sha1 => Algorithm::RSASignatureDigestPKCS1v15SHA1,
            DigestSignAlgorithm::RsaPkcs1v15Sha224 => Algorithm::RSASignatureDigestPKCS1v15SHA224,
            DigestSignAlgorithm::RsaPkcs1v15Sha256 => Algorithm::RSASignatureDigestPKCS1v15SHA256,
            DigestSignAlgorithm::RsaPkcs1v15Sha384 => Algorithm::RSASignatureDigestPKCS1v15SHA384,
            DigestSignAlgorithm::RsaPkcs1v15Sha512 => Algorithm::RSASignatureDigestPKCS1v15SHA512,
            DigestSignAlgorithm::EcdsaX962Sha1 => Algorithm::ECDSASignatureDigestX962SHA1,
            DigestSignAlgorithm::EcdsaX962Sha224 => Algorithm::ECDSASignatureDigestX962SHA224,
            DigestSignAlgorithm::EcdsaX962Sha256 => Algorithm::ECDSASignatureDigestX962SHA256,
            DigestSignAlgorithm::EcdsaX962Sha384 => Algorithm::ECDSASignatureDigestX962SHA384,
            DigestSignAlgorithm::EcdsaX962Sha512 => Algorithm::ECDSASignatureDigestX962SHA512,
        }
    }
}

/// Descripción del origen de las entradas del llavero.
const SOURCE: &str = "Llavero de Mac";

/// Identidad devuelta por `SecItemCopyMatching`.
struct Found {
    identity: SecIdentity,
    label: Option<String>,
    token_id: Option<String>,
}

/// Entrada cargada: datos para la interfaz y referencia a la identidad.
struct Item {
    entry: CertEntry,
    identity: SecIdentity,
}

/// Llavero de macOS.
///
/// Las referencias de Security.framework (`SecIdentity`, `SecKey`) son
/// seguras entre hilos (`Send + Sync` en `security-framework`), así que el
/// almacén puede compartirse entre el hilo de carga y el de la interfaz.
pub struct KeychainStore {
    options: KeychainOptions,
    /// Llaveros concretos en los que buscar (`None`: lista de búsqueda por
    /// defecto del usuario).
    keychains: Option<Vec<SecKeychain>>,
    items: RwLock<Vec<Item>>,
}

impl KeychainStore {
    /// Abre el llavero del usuario (lista de búsqueda por defecto) y, si se
    /// indica, las identidades de tarjetas y tokens de CryptoTokenKit.
    pub fn open(options: KeychainOptions) -> Result<KeychainStore, KeyStoreError> {
        Self::open_inner(options, None)
    }

    /// Abre solo los llaveros indicados (p. ej. un fichero `.keychain-db`
    /// abierto con `SecKeychain::open`); con `include_tokens` también se
    /// añaden las identidades de tokens.
    pub fn open_with_keychains(
        options: KeychainOptions,
        keychains: Vec<SecKeychain>,
    ) -> Result<KeychainStore, KeyStoreError> {
        Self::open_inner(options, Some(keychains))
    }

    fn open_inner(
        options: KeychainOptions,
        keychains: Option<Vec<SecKeychain>>,
    ) -> Result<KeychainStore, KeyStoreError> {
        let items = load(&options, keychains.as_deref())?;
        Ok(KeychainStore {
            options,
            keychains,
            items: RwLock::new(items),
        })
    }
}

impl KeyStore for KeychainStore {
    fn kind(&self) -> KeyStoreKind {
        KeyStoreKind::Apple
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        let items = self
            .items
            .read()
            .map_err(|_| KeyStoreError::load(KeyStoreKind::Apple, "estado del llavero no disponible"))?;
        Ok(items.iter().map(|i| i.entry.clone()).collect())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let items = self
            .items
            .read()
            .map_err(|_| KeyStoreError::load(KeyStoreKind::Apple, "estado del llavero no disponible"))?;
        let entries: Vec<CertEntry> = items.iter().map(|i| i.entry.clone()).collect();
        let entry = find_entry(&entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let item = items
            .iter()
            .find(|i| i.entry.id == entry.id)
            .ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let key_algorithm = entry
            .capabilities
            .key_algorithm
            .ok_or_else(|| KeyStoreError::Key(KeyError::Unsupported("tipo de clave del certificado".into())))?;
        let key = item.identity.private_key().map_err(|e| {
            match logic::map_error(logic::OSSTATUS_DOMAIN, i64::from(e.code()), &e.to_string()) {
                KeyError::Other(_) => KeyStoreError::NoPrivateKey(alias.to_string()),
                k => KeyStoreError::Key(k),
            }
        })?;
        Ok(Box::new(KeychainKey {
            key,
            chain: entry.chain.clone(),
            alias: entry.alias.clone(),
            key_algorithm,
        }))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        let loaded = load(&self.options, self.keychains.as_deref());
        let mut items = self
            .items
            .write()
            .map_err(|_| KeyStoreError::load(KeyStoreKind::Apple, "estado del llavero no disponible"))?;
        match loaded {
            Ok(new_items) => {
                *items = new_items;
                Ok(())
            }
            Err(e) => {
                // Como en Java: si falla la recarga, se ocultan sus entradas.
                items.clear();
                Err(e)
            }
        }
    }
}

/// Lee una cadena de un diccionario de atributos.
fn dict_string(dict: &CFDictionary, key: CFStringRef) -> Option<String> {
    let value = dict.find(key as *const c_void)?;
    // SAFETY: los valores de un CFDictionary devuelto por
    // SecItemCopyMatching son objetos CF válidos mientras viva el
    // diccionario; `wrap_under_get_rule` incrementa su contador.
    let value = unsafe { CFType::wrap_under_get_rule(*value) };
    value.downcast::<CFString>().map(|s| s.to_string())
}

/// Lee la identidad (`kSecValueRef`) de un diccionario de resultados.
fn dict_identity(dict: &CFDictionary) -> Option<SecIdentity> {
    // SAFETY: `kSecValueRef` es una constante CFString de Security.framework.
    let value = dict.find(unsafe { kSecValueRef } as *const c_void)?;
    // SAFETY: igual que en `dict_string`.
    let value = unsafe { CFType::wrap_under_get_rule(*value) };
    value.downcast::<SecIdentity>()
}

/// Ejecuta una búsqueda de identidades (`errSecItemNotFound` → vacía).
fn search(options: &ItemSearchOptions) -> Result<Vec<Found>, security_framework::base::Error> {
    let results = match options.search() {
        Ok(r) => r,
        Err(e) if i64::from(e.code()) == logic::ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::with_capacity(results.len());
    for r in results {
        match r {
            SearchResult::Dict(dict) => {
                let Some(identity) = dict_identity(&dict) else {
                    tracing::warn!("Resultado del llavero sin referencia a la identidad");
                    continue;
                };
                // SAFETY: constantes CFString de Security.framework.
                let (label_key, token_key) = unsafe { (kSecAttrLabel, kSecAttrTokenID) };
                out.push(Found {
                    identity,
                    label: dict_string(&dict, label_key),
                    token_id: dict_string(&dict, token_key),
                });
            }
            SearchResult::Ref(Reference::Identity(identity)) => out.push(Found {
                identity,
                label: None,
                token_id: None,
            }),
            _ => {}
        }
    }
    Ok(out)
}

/// Opciones de búsqueda de identidades.
fn identity_query(keychains: Option<&[SecKeychain]>, token: bool) -> ItemSearchOptions {
    let mut q = ItemSearchOptions::new();
    q.class(ItemClass::identity())
        .load_refs(true)
        .load_attributes(true)
        .limit(Limit::All);
    if token {
        q.access_group_token();
    } else if let Some(k) = keychains {
        q.keychains(k);
    }
    q
}

/// Carga las identidades y construye las entradas.
fn load(options: &KeychainOptions, keychains: Option<&[SecKeychain]>) -> Result<Vec<Item>, KeyStoreError> {
    let mut found = search(&identity_query(keychains, false)).map_err(|e| {
        KeyStoreError::load(
            KeyStoreKind::Apple,
            format!("No se han podido cargar los certificados del almacen Apple.KeychainStore: {e}"),
        )
    })?;
    if options.include_tokens {
        match search(&identity_query(keychains, true)) {
            Ok(tokens) => found.extend(tokens),
            Err(e) => tracing::warn!("No se han podido obtener las identidades de tarjetas del llavero: {e}"),
        }
    }

    struct Row {
        found: Found,
        cert: SecCertificate,
        der: Vec<u8>,
        label: String,
    }
    let mut rows = Vec::with_capacity(found.len());
    for f in found {
        let cert = match f.identity.certificate() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Se ignora una identidad del llavero sin certificado: {e}");
                continue;
            }
        };
        let der = cert.to_der();
        // Java aborta la carga completa si una identidad no tiene etiqueta;
        // aquí se usa el resumen del titular, que es la etiqueta por defecto
        // del llavero.
        let label = f
            .label
            .clone()
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| cert.subject_summary());
        rows.push(Row {
            found: f,
            cert,
            der,
            label,
        });
    }

    let aliases = logic::java_aliases(&rows.iter().map(|r| r.label.as_str()).collect::<Vec<_>>());
    let keep = logic::dedup_by_serial(&rows.iter().map(|r| r.der.as_slice()).collect::<Vec<_>>());

    let mut items = Vec::with_capacity(keep.len());
    for i in keep {
        let row = &rows[i];
        // Una tarjeta puede aparecer también como llavero "dinámico" en la
        // lista de búsqueda clásica (sin kSecAttrTokenID): si alguna
        // identidad descartada con el mismo número de serie es de un token,
        // la entrada se marca como de hardware.
        let serial = logic::serial_key(&row.der);
        let hardware = row.found.token_id.is_some()
            || rows
                .iter()
                .any(|r| r.found.token_id.is_some() && logic::serial_key(&r.der) == serial);
        let caps = EntryCapabilities {
            has_private_key: true,
            key_algorithm: None,
            hardware,
            pin_at_sign: hardware,
        };
        let source = match &row.found.token_id {
            Some(t) => format!("{SOURCE} ({t})"),
            None => SOURCE.to_string(),
        };
        let chain = build_chain(&row.cert, &row.der);
        let entry = CertEntry::new(aliases[i].clone(), row.der.clone(), chain, caps, source);
        items.push(Item {
            entry,
            identity: row.found.identity.clone(),
        });
    }
    Ok(items)
}

/// Construye la cadena con `SecTrust` (política X.509 básica, sin red).
#[allow(deprecated)] // SecTrustEvaluate/SecTrustGetCertificateAtIndex: disponibles en todas las versiones de macOS
fn build_chain(cert: &SecCertificate, leaf: &[u8]) -> Vec<Vec<u8>> {
    let fallback = || vec![leaf.to_vec()];
    let policy = SecPolicy::create_x509();
    let Ok(mut trust) = SecTrust::create_with_certificates(std::slice::from_ref(cert), &[policy]) else {
        return fallback();
    };
    if let Err(e) = trust.set_network_fetch_allowed(false) {
        tracing::debug!("No se pudo desactivar el acceso a red de SecTrust: {e}");
    }
    // El resultado de la evaluación no importa (puede no ser de confianza):
    // solo se quiere la cadena que construye.
    if let Err(e) = trust.evaluate() {
        tracing::debug!("No se pudo evaluar la cadena del certificado: {e}");
        return fallback();
    }
    let chain: Vec<Vec<u8>> = (0..trust.certificate_count())
        .filter_map(|i| trust.certificate_at_index(i))
        .map(|c| c.to_der())
        .collect();
    if chain.first().map(Vec::as_slice) != Some(leaf) {
        return fallback();
    }
    chain
}

/// Clave privada del llavero. Nunca se exporta: se firma con
/// `SecKeyCreateSignature` sobre la huella calculada en el proceso.
struct KeychainKey {
    key: SecKey,
    chain: Vec<Vec<u8>>,
    alias: String,
    key_algorithm: KeyAlgorithm,
}

impl SigningKey for KeychainKey {
    fn certificate(&self) -> &[u8] {
        &self.chain[0]
    }

    fn certificate_chain(&self) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self) -> KeyAlgorithm {
        self.key_algorithm
    }

    fn alias(&self) -> Option<&str> {
        Some(&self.alias)
    }

    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, KeyError> {
        if algorithm.key != self.key_algorithm {
            return Err(KeyError::Unsupported(format!(
                "{} con una clave {}",
                algorithm.java_name(),
                self.key_algorithm.java_suffix()
            )));
        }
        let sec_alg: Algorithm = DigestSignAlgorithm::for_signature(algorithm)?.into();
        // SAFETY: `self.key` es una referencia SecKey válida durante la
        // llamada y el algoritmo es una constante de Security.framework.
        let supported = unsafe {
            SecKeyIsAlgorithmSupported(self.key.as_concrete_TypeRef(), kSecKeyOperationTypeSign, sec_alg.into())
        };
        if supported == 0 {
            return Err(KeyError::Unsupported(format!(
                "{} no está soportado por la clave del llavero",
                algorithm.java_name()
            )));
        }
        let hash = algorithm.digest.digest(data);
        self.key.create_signature(sec_alg, &hash).map_err(|e| cf_error(&e))
    }
}

/// Traduce un `CFError` de Security.framework.
fn cf_error(e: &CFError) -> KeyError {
    logic::map_error(&e.domain().to_string(), e.code() as i64, &e.description().to_string())
}

#[cfg(test)]
mod tests {
    //! Pruebas que tocan el llavero: requieren macOS y se ejecutan con
    //! `cargo test -p afirma-keystores -- --ignored keychain`. Crean un
    //! llavero temporal, importan los PKCS#12 de `testdata/pki` y firman.
    //! Puede aparecer un diálogo de acceso al llavero la primera vez.
    use super::*;
    use afirma_core::DigestAlgorithm;
    use security_framework::os::macos::import_export::ImportOptions;
    use security_framework::os::macos::keychain::CreateOptions;

    fn testdata(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testdata/pki")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "necesita macOS con acceso al llavero"]
    fn keychain_temporary_import_and_sign() {
        let dir = tempfile::tempdir().unwrap();
        let mut kc = CreateOptions::new()
            .password("prueba")
            .create(dir.path().join("prueba.keychain-db"))
            .unwrap();
        kc.unlock(Some("prueba")).unwrap();
        for f in ["firmante-rsa.p12", "firmante-ec.p12"] {
            ImportOptions::new()
                .filename(f)
                .passphrase("12341234")
                .keychain(&kc)
                .import(&testdata(f))
                .unwrap();
        }
        let store = KeychainStore::open_with_keychains(KeychainOptions { include_tokens: false }, vec![kc]).unwrap();
        let entries = store.entries().unwrap();
        assert_eq!(entries.len(), 2, "{entries:?}");
        for e in &entries {
            assert_eq!(e.alias, e.alias.to_lowercase());
            assert!(e.capabilities.has_private_key);
            let key = store.signing_key(&e.alias).unwrap();
            let alg = SignatureAlgorithm::new(DigestAlgorithm::Sha256, key.key_algorithm());
            let sig = key.sign(b"datos a firmar", alg).unwrap();
            crate::verify::verify_signature(key.certificate(), alg, b"datos a firmar", &sig).unwrap();
        }
        store.refresh().unwrap();
        assert_eq!(store.entries().unwrap().len(), 2);
    }

    #[test]
    #[ignore = "necesita macOS con acceso al llavero"]
    fn keychain_default_search_list_opens() {
        let store = KeychainStore::open(KeychainOptions::default()).unwrap();
        for e in store.entries().unwrap() {
            println!("{} ({}) hardware={}", e.alias, e.source, e.capabilities.hardware);
        }
    }
}
