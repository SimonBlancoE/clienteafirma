//! Abstracción de almacén de claves y almacén agregado.
//!
//! Cada tipo de almacén (PKCS#12, PKCS#11, NSS, Windows, llavero de macOS)
//! implementa [`KeyStore`]. Lo que el usuario ve como "un almacén" puede ser
//! la unión de varios ([`AggregateStore`]): p. ej. Firefox = NSS interno +
//! módulos PKCS#11 externos, o Windows = almacén `MY` + DNIe.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use afirma_core::algorithms::KeyAlgorithm;
use afirma_core::cert::CertInfo;
use afirma_core::key::SigningKey;
use chrono::{DateTime, Utc};

use crate::error::KeyStoreError;
use crate::kind::KeyStoreKind;

/// Capacidades de una entrada del almacén.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EntryCapabilities {
    /// Tiene (o se espera que tenga, en tarjetas que ocultan las claves hasta
    /// introducir el PIN) clave privada utilizable.
    pub has_private_key: bool,
    /// Tipo de clave (del certificado).
    pub key_algorithm: Option<KeyAlgorithm>,
    /// La clave está en un dispositivo (tarjeta, token, TPM, llavero de
    /// tarjeta) y no puede exportarse.
    pub hardware: bool,
    /// El PIN se pedirá al firmar (DNIe/CERES) y no al abrir el almacén.
    pub pin_at_sign: bool,
}

/// Certificado del almacén con los datos necesarios para mostrarlo y
/// filtrarlo.
#[derive(Debug, Clone)]
pub struct CertEntry {
    /// Identificador único dentro del almacén (en un almacén agregado se
    /// prefija con el índice del subalmacén: `"1:alias"`).
    pub id: String,
    /// Alias nativo del almacén (el que muestra `listaliases` y acepta
    /// `-alias` en la línea de comandos).
    pub alias: String,
    /// Certificado en DER.
    pub certificate: Vec<u8>,
    /// Cadena de certificación (el primero es [`Self::certificate`]). Nunca
    /// vacía.
    pub chain: Vec<Vec<u8>>,
    /// Datos del certificado (`None` si no se pudo analizar).
    pub info: Option<CertInfo>,
    /// Nombre a mostrar (CN del titular según `AOUtil.getCN`; si no hay,
    /// el alias recortado).
    pub friendly_name: String,
    pub capabilities: EntryCapabilities,
    /// Descripción del origen (p. ej. `"Windows"`, `"NSS"`,
    /// `"opensc-pkcs11.so"`), para agrupar o mostrar una insignia.
    pub source: String,
    /// Huella SHA-1 del certificado en hexadecimal en mayúsculas sin
    /// separadores (formato de `deactivateEntry` de Java).
    pub sha1_upper: String,
}

impl CertEntry {
    /// Crea una entrada a partir de su alias nativo y su cadena (el primer
    /// elemento es el certificado de la entrada). Si `chain` está vacía se
    /// usa `[certificate]`.
    pub fn new(alias: impl Into<String>, certificate: Vec<u8>, chain: Vec<Vec<u8>>, capabilities: EntryCapabilities, source: impl Into<String>) -> Self {
        let alias = alias.into();
        let chain = if chain.is_empty() || chain[0] != certificate {
            let mut c = vec![certificate.clone()];
            c.extend(chain.into_iter().filter(|x| *x != certificate));
            c
        } else {
            chain
        };
        let info = CertInfo::parse(&certificate);
        let friendly_name = crate::dn::friendly_name(&certificate, &alias);
        let sha1_upper = hex::encode_upper(afirma_core::DigestAlgorithm::Sha1.digest(&certificate));
        let mut capabilities = capabilities;
        if capabilities.key_algorithm.is_none() {
            capabilities.key_algorithm = crate::verify::certificate_key_algorithm(&certificate);
        }
        CertEntry { id: alias.clone(), alias, certificate, chain, info, friendly_name, capabilities, source: source.into(), sha1_upper }
    }

    /// Huella SHA-256 en hexadecimal (minúsculas).
    pub fn sha256_hex(&self) -> String {
        hex::encode(afirma_core::DigestAlgorithm::Sha256.digest(&self.certificate))
    }

    /// Indica si el certificado está en vigor en el instante dado
    /// (`notBefore <= t <= notAfter`). Si no se pudo analizar, `false`.
    pub fn is_valid_at(&self, t: DateTime<Utc>) -> bool {
        self.info.as_ref().is_some_and(|i| i.is_valid_at(t))
    }

    /// Indica si `reference` designa a esta entrada: su identificador, su
    /// alias nativo, o `sha1:<hex>` / `sha256:<hex>` (mejora sobre Java para
    /// la línea de comandos).
    pub fn matches_reference(&self, reference: &str) -> bool {
        if self.id == reference || self.alias == reference {
            return true;
        }
        let lower = reference.to_ascii_lowercase();
        if let Some(h) = lower.strip_prefix("sha1:") {
            return normalize_hex(h).eq_ignore_ascii_case(&self.sha1_upper);
        }
        if let Some(h) = lower.strip_prefix("sha256:") {
            return normalize_hex(h) == self.sha256_hex();
        }
        false
    }
}

fn normalize_hex(h: &str) -> String {
    h.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase()
}

/// Busca una entrada por referencia: primero por identificador exacto,
/// después por alias nativo (la primera que coincida, como Java) y por
/// último por huella (`sha1:`/`sha256:`).
pub fn find_entry<'a>(entries: &'a [CertEntry], reference: &str) -> Option<&'a CertEntry> {
    entries
        .iter()
        .find(|e| e.id == reference)
        .or_else(|| entries.iter().find(|e| e.alias == reference))
        .or_else(|| entries.iter().find(|e| e.matches_reference(reference)))
}

/// Almacén de claves.
///
/// Los métodos toman `&self`: los almacenes se comparten entre hilos (carga
/// en segundo plano, diálogo de selección) y gestionan su estado
/// internamente.
pub trait KeyStore: Send + Sync {
    /// Tipo del almacén.
    fn kind(&self) -> KeyStoreKind;

    /// Nombre del almacén para el título del diálogo
    /// ("Diálogo de seguridad del almacén `<nombre>`"). Por defecto el nombre
    /// visible del tipo; las tarjetas registradas devuelven su nombre.
    fn name(&self) -> String {
        self.kind().display_name().to_string()
    }

    /// Nombre del fichero o biblioteca del almacén, si lo hay (sufijo
    /// `" : <fichero>"` del título del diálogo).
    fn lib_name(&self) -> Option<String> {
        None
    }

    /// Entradas del almacén (todas, con o sin clave privada; el filtrado se
    /// hace después). Se cachean hasta [`KeyStore::refresh`].
    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError>;

    /// Clave de firma de la entrada indicada (identificador, alias nativo o
    /// `sha1:`/`sha256:`). Puede pedir PIN o contraseña.
    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError>;

    /// Vuelve a abrir el almacén (Java `refresh()`, botón "Recargar"/F5).
    fn refresh(&self) -> Result<(), KeyStoreError>;

    /// Almacén "preferente" (tarjeta DNIe/CERES): al agregarlo oculta sus
    /// certificados en los subalmacenes añadidos antes.
    fn is_preferred(&self) -> bool {
        false
    }

    /// Alias nativos de las entradas con clave privada (`listaliases`).
    fn aliases(&self) -> Result<Vec<String>, KeyStoreError> {
        Ok(self.entries()?.into_iter().filter(|e| e.capabilities.has_private_key).map(|e| e.alias).collect())
    }

    /// Entrada indicada por referencia (ver [`find_entry`]).
    fn entry(&self, alias: &str) -> Result<CertEntry, KeyStoreError> {
        let entries = self.entries()?;
        find_entry(&entries, alias).cloned().ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))
    }
}

impl<T: KeyStore + ?Sized> KeyStore for Arc<T> {
    fn kind(&self) -> KeyStoreKind {
        (**self).kind()
    }
    fn name(&self) -> String {
        (**self).name()
    }
    fn lib_name(&self) -> Option<String> {
        (**self).lib_name()
    }
    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        (**self).entries()
    }
    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        (**self).signing_key(alias)
    }
    fn refresh(&self) -> Result<(), KeyStoreError> {
        (**self).refresh()
    }
    fn is_preferred(&self) -> bool {
        (**self).is_preferred()
    }
    fn aliases(&self) -> Result<Vec<String>, KeyStoreError> {
        (**self).aliases()
    }
    fn entry(&self, alias: &str) -> Result<CertEntry, KeyStoreError> {
        (**self).entry(alias)
    }
}

/// Generador de alias únicos.
#[derive(Debug, Default, Clone)]
pub struct AliasSet {
    used: HashSet<String>,
}

impl AliasSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Devuelve `alias` si no se ha usado o, si no, `alias (1)`, `alias (2)`…
    /// (regla de SunMSCAPI de Java 11+, `CKeyStore.storeWithUniqueAlias`),
    /// y lo marca como usado.
    pub fn unique(&mut self, alias: &str) -> String {
        if self.used.insert(alias.to_string()) {
            return alias.to_string();
        }
        let mut n = 1u32;
        loop {
            let cand = format!("{alias} ({n})");
            if self.used.insert(cand.clone()) {
                return cand;
            }
            n += 1;
        }
    }

    pub fn contains(&self, alias: &str) -> bool {
        self.used.contains(alias)
    }
}

/// Almacén formado por varios subalmacenes (`AggregatedKeyStoreManager`).
///
/// - Las entradas son la concatenación de las de los subalmacenes, en orden
///   de inserción; los que fallan se omiten (se registra el error).
/// - Si un subalmacén es preferente ([`KeyStore::is_preferred`]), sus
///   certificados (por huella SHA-1) se ocultan en los añadidos antes.
/// - Para evitar el fallo de Java con alias repetidos en dos subalmacenes,
///   el identificador de cada entrada se prefija con el índice del
///   subalmacén cuando hay más de uno (`"0:alias"`); el alias nativo se
///   conserva en [`CertEntry::alias`].
pub struct AggregateStore {
    kind: KeyStoreKind,
    name: Option<String>,
    lib_name: Option<String>,
    backends: RwLock<Vec<Arc<dyn KeyStore>>>,
    dedup_all: bool,
}

impl AggregateStore {
    pub fn new(kind: KeyStoreKind) -> Self {
        AggregateStore { kind, name: None, lib_name: None, backends: RwLock::new(Vec::new()), dedup_all: false }
    }

    /// Nombre para el título (por defecto, el del tipo).
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_lib_name(mut self, lib: impl Into<String>) -> Self {
        self.lib_name = Some(lib.into());
        self
    }

    /// Mejora opcional: eliminar duplicados (misma huella) entre todos los
    /// subalmacenes, prefiriendo el que tiene clave privada y, después, el
    /// de hardware. Desactivado por defecto (paridad con Java).
    pub fn with_dedup_all(mut self, dedup: bool) -> Self {
        self.dedup_all = dedup;
        self
    }

    /// Añade un subalmacén al final.
    pub fn add(&self, store: Arc<dyn KeyStore>) {
        if let Ok(mut b) = self.backends.write() {
            b.push(store);
        }
    }

    /// Subalmacenes, en orden.
    pub fn backends(&self) -> Vec<Arc<dyn KeyStore>> {
        self.backends.read().map(|b| b.clone()).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.backends.read().map(|b| b.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Indica si contiene algún subalmacén preferente (DNIe/CERES).
    pub fn has_preferred(&self) -> bool {
        self.backends().iter().any(|b| b.is_preferred())
    }

    /// Entradas con el subalmacén al que pertenecen.
    fn entries_with_backend(&self) -> Vec<(usize, CertEntry)> {
        let backends = self.backends();
        let many = backends.len() > 1;
        let mut per_backend: Vec<Vec<CertEntry>> = Vec::with_capacity(backends.len());
        for (i, b) in backends.iter().enumerate() {
            match b.entries() {
                Ok(e) => per_backend.push(e),
                Err(e) => {
                    tracing::warn!("Se omite el subalmacen {} ({}): {e}", i, b.name());
                    per_backend.push(Vec::new());
                }
            }
        }
        // Huellas de los subalmacenes preferentes, ocultas en los anteriores.
        let mut out = Vec::new();
        for (i, entries) in per_backend.iter().enumerate() {
            let hidden: HashSet<&str> = per_backend
                .iter()
                .enumerate()
                .skip(i + 1)
                .filter(|(j, _)| backends[*j].is_preferred())
                .flat_map(|(_, es)| es.iter().map(|e| e.sha1_upper.as_str()))
                .collect();
            for e in entries {
                if hidden.contains(e.sha1_upper.as_str()) {
                    continue;
                }
                let mut e = e.clone();
                if many {
                    e.id = format!("{i}:{}", e.id);
                }
                out.push((i, e));
            }
        }
        if self.dedup_all {
            let mut best: Vec<(usize, CertEntry)> = Vec::new();
            for (i, e) in out {
                let score = |x: &CertEntry| (x.capabilities.has_private_key as u8) * 2 + x.capabilities.hardware as u8;
                if let Some(pos) = best.iter().position(|(_, b)| b.sha1_upper == e.sha1_upper) {
                    if score(&e) > score(&best[pos].1) {
                        best[pos] = (i, e);
                    }
                } else {
                    best.push((i, e));
                }
            }
            return best;
        }
        out
    }
}

impl KeyStore for AggregateStore {
    fn kind(&self) -> KeyStoreKind {
        self.kind
    }

    fn name(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.kind.display_name().to_string())
    }

    fn lib_name(&self) -> Option<String> {
        self.lib_name.clone()
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        Ok(self.entries_with_backend().into_iter().map(|(_, e)| e).collect())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let all = self.entries_with_backend();
        let entries: Vec<CertEntry> = all.iter().map(|(_, e)| e.clone()).collect();
        let found = find_entry(&entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        let idx = entries.iter().position(|e| std::ptr::eq(e, found)).unwrap_or(0);
        let (backend_idx, entry) = &all[idx];
        let backend = self.backends().get(*backend_idx).cloned().ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        // Identificador sin el prefijo del agregado.
        let inner_id = if self.len() > 1 {
            entry.id.split_once(':').map(|(_, r)| r.to_string()).unwrap_or_else(|| entry.id.clone())
        } else {
            entry.id.clone()
        };
        backend.signing_key(&inner_id)
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        for b in self.backends() {
            if let Err(e) = b.refresh() {
                tracing::warn!("Error al resfrescar el almacén de claves {}: {e}", b.name());
            }
        }
        Ok(())
    }

    fn is_preferred(&self) -> bool {
        false
    }
}

/// Almacén en memoria con entradas fijas (pruebas, sello de tiempo,
/// certificados sueltos).
pub struct MemoryStore {
    kind: KeyStoreKind,
    entries: Vec<CertEntry>,
    keys: Vec<(String, Arc<dyn SigningKey>)>,
    preferred: bool,
}

impl MemoryStore {
    pub fn new(kind: KeyStoreKind) -> Self {
        MemoryStore { kind, entries: Vec::new(), keys: Vec::new(), preferred: false }
    }

    pub fn preferred(mut self, p: bool) -> Self {
        self.preferred = p;
        self
    }

    /// Añade una entrada con clave.
    pub fn add_key(&mut self, alias: &str, key: Arc<dyn SigningKey>) {
        let caps = EntryCapabilities { has_private_key: true, key_algorithm: Some(key.key_algorithm()), ..Default::default() };
        self.entries.push(CertEntry::new(alias, key.certificate().to_vec(), key.certificate_chain(), caps, self.kind.display_name()));
        self.keys.push((alias.to_string(), key));
    }

    /// Añade un certificado sin clave.
    pub fn add_certificate(&mut self, alias: &str, cert: Vec<u8>) {
        self.entries.push(CertEntry::new(alias, cert.clone(), vec![cert], EntryCapabilities::default(), self.kind.display_name()));
    }
}

impl KeyStore for MemoryStore {
    fn kind(&self) -> KeyStoreKind {
        self.kind
    }

    fn entries(&self) -> Result<Vec<CertEntry>, KeyStoreError> {
        Ok(self.entries.clone())
    }

    fn signing_key(&self, alias: &str) -> Result<Box<dyn SigningKey>, KeyStoreError> {
        let e = find_entry(&self.entries, alias).ok_or_else(|| KeyStoreError::AliasNotFound(alias.to_string()))?;
        self.keys
            .iter()
            .find(|(a, _)| *a == e.alias)
            .map(|(_, k)| Box::new(k.clone()) as Box<dyn SigningKey>)
            .ok_or_else(|| KeyStoreError::NoPrivateKey(alias.to_string()))
    }

    fn refresh(&self) -> Result<(), KeyStoreError> {
        Ok(())
    }

    fn is_preferred(&self) -> bool {
        self.preferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p12(name: &str) -> Arc<dyn SigningKey> {
        let data = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pki").join(name)).unwrap();
        let e = crate::pkcs12::open(&data, "12341234").unwrap().remove(0);
        Arc::new(e.signing_key().unwrap())
    }

    #[test]
    fn aliases_unique() {
        let mut s = AliasSet::new();
        assert_eq!(s.unique("a"), "a");
        assert_eq!(s.unique("a"), "a (1)");
        assert_eq!(s.unique("a"), "a (2)");
        assert_eq!(s.unique("b"), "b");
    }

    #[test]
    fn aggregate_preferred_hides_duplicates_and_namespaces() {
        let rsa = p12("firmante-rsa.p12");
        let ec = p12("firmante-ec.p12");
        let mut os = MemoryStore::new(KeyStoreKind::Windows);
        os.add_key("x", rsa.clone());
        os.add_key("y", ec.clone());
        let mut card = MemoryStore::new(KeyStoreKind::DnieJava).preferred(true);
        card.add_key("x", rsa.clone());
        let agg = AggregateStore::new(KeyStoreKind::Windows);
        agg.add(Arc::new(os));
        agg.add(Arc::new(card));
        let entries = agg.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "0:y");
        assert_eq!(entries[1].id, "1:x");
        assert_eq!(entries[1].alias, "x");
        // El alias nativo "x" resuelve al de la tarjeta (el del almacén del
        // sistema está oculto).
        let k = agg.signing_key("x").unwrap();
        assert_eq!(k.certificate(), rsa.certificate());
        let k = agg.signing_key("0:y").unwrap();
        assert_eq!(k.certificate(), ec.certificate());
        let sha1 = entries[0].sha1_upper.clone();
        assert!(agg.signing_key(&format!("sha1:{}", sha1.to_lowercase())).is_ok());
        assert!(matches!(agg.signing_key("nada"), Err(KeyStoreError::AliasNotFound(_))));
    }
}
