//! Lista de certificados candidatos para el diálogo de selección
//! (`KeyStoreUtilities.getAliasesByFriendlyName`, §4.1) y selección
//! automática (§8.1).
//!
//! Pasos, por entrada:
//! 1. Las entradas cuyo certificado no se puede analizar se omiten.
//! 2. Si no se muestran caducados, se omiten las que no están en vigor.
//! 3. Si se comprueban claves privadas, se omiten las que no tienen.
//! 4. Se aplican los filtros (combinados con O).
//! 5. El nombre a mostrar es [`CertEntry::friendly_name`].
//!
//! El resultado se ordena como el diálogo (§8.3): por nombre con
//! `compareToIgnoreCase`, después por fecha de caducidad descendente y por
//! huella (orden determinista).

use chrono::{DateTime, Utc};

use crate::filters::{CertFilter, CertFilterManager, LocalFilterPrefs, apply_filter_indices};
use crate::store::CertEntry;

/// Opciones de construcción de la lista.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateOptions {
    /// Ocultar las entradas sin clave privada (todos los flujos de
    /// AutoFirma lo activan).
    pub check_private_keys: bool,
    /// Mostrar certificados caducados o aún no válidos.
    pub show_expired: bool,
    /// Instante de referencia para la validez.
    pub now: DateTime<Utc>,
}

impl CandidateOptions {
    /// Flujos del protocolo y de la línea de comandos con `-certgui`
    /// (`checkPrivateKeys=true`, `showExpiredCertificates=true`: la caducidad
    /// la controla el filtro por defecto de [`CertFilterManager`]).
    pub fn protocol(now: DateTime<Utc>) -> Self {
        CandidateOptions { check_private_keys: true, show_expired: true, now }
    }

    /// Aplicación local: la caducidad la decide la preferencia
    /// `showExpiredCerts`.
    pub fn local(prefs: &LocalFilterPrefs, now: DateTime<Utc>) -> Self {
        CandidateOptions { check_private_keys: true, show_expired: prefs.show_expired_certs, now }
    }
}

/// Lista de candidatos con el recuento de entradas ocultas (para explicar al
/// usuario por qué no ve un certificado).
#[derive(Debug, Clone, Default)]
pub struct CandidateList {
    /// Candidatos ordenados.
    pub candidates: Vec<CertEntry>,
    /// Ocultas por no poder analizar el certificado.
    pub hidden_unreadable: usize,
    /// Ocultas por estar caducadas o no ser aún válidas.
    pub hidden_expired: usize,
    /// Ocultas por no tener clave privada.
    pub hidden_without_key: usize,
    /// Ocultas por los filtros.
    pub hidden_by_filters: usize,
}

impl CandidateList {
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Selección automática (§8.1): si la selección es obligatoria
    /// (`headless`/`mandatoryCertSelection=false`) y hay exactamente un
    /// candidato, se devuelve sin mostrar el diálogo.
    pub fn auto_select(&self, mandatory: bool) -> Option<&CertEntry> {
        auto_select(&self.candidates, mandatory)
    }
}

/// Construye la lista de candidatos con una lista de filtros (combinados con
/// O; vacía = sin filtrar).
pub fn select_candidates(entries: &[CertEntry], filters: &[CertFilter], opts: &CandidateOptions) -> CandidateList {
    let mut list = CandidateList::default();
    let mut kept: Vec<CertEntry> = Vec::new();
    for e in entries {
        if e.info.is_none() {
            list.hidden_unreadable += 1;
            continue;
        }
        if !opts.show_expired && !e.is_valid_at(opts.now) {
            list.hidden_expired += 1;
            continue;
        }
        if opts.check_private_keys && !e.capabilities.has_private_key {
            list.hidden_without_key += 1;
            continue;
        }
        kept.push(e.clone());
    }
    let accepted = apply_filter_indices(filters, &kept, opts.now);
    list.hidden_by_filters = kept.len() - accepted.len();
    list.candidates = accepted.into_iter().map(|i| kept[i].clone()).collect();
    sort_candidates(&mut list.candidates);
    list
}

/// Igual que [`select_candidates`] con los filtros de un gestor.
pub fn candidates_with_manager(entries: &[CertEntry], manager: &CertFilterManager, opts: &CandidateOptions) -> CandidateList {
    select_candidates(entries, manager.filters(), opts)
}

/// Ordena como el diálogo de selección: nombre (`compareToIgnoreCase`),
/// caducidad descendente y huella SHA-1.
pub fn sort_candidates(candidates: &mut [CertEntry]) {
    candidates.sort_by(|a, b| {
        crate::dn::java_compare_ignore_case(&a.friendly_name, &b.friendly_name)
            .then_with(|| {
                let na = a.info.as_ref().map(|i| i.not_after);
                let nb = b.info.as_ref().map(|i| i.not_after);
                nb.cmp(&na)
            })
            .then_with(|| a.sha1_upper.cmp(&b.sha1_upper))
    });
}

/// Selección automática: `Some` si `mandatory` y hay exactamente un
/// candidato.
pub fn auto_select(candidates: &[CertEntry], mandatory: bool) -> Option<&CertEntry> {
    (mandatory && candidates.len() == 1).then(|| &candidates[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::EntryCapabilities;
    use chrono::TimeZone;
    use std::path::Path;

    fn entry(rel: &str, alias: &str, key: bool) -> CertEntry {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata").join(rel);
        let der = afirma_core::cert::decode_certificate(&std::fs::read(p).unwrap()).unwrap();
        CertEntry::new(alias, der.clone(), vec![der], EntryCapabilities { has_private_key: key, ..Default::default() }, "pruebas")
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 16, 12, 0, 0).unwrap()
    }

    #[test]
    fn steps_and_counts() {
        let entries = vec![
            entry("pki/firmante-rsa.crt", "firmante", true),
            entry("pki/caducado.crt", "caducado", true),
            entry("pki/ca.crt", "ca", false),
            entry("pki/autenticacion.crt", "auth", true),
            entry("keystores/filters/futuro.der", "futuro", true),
        ];
        let mut bad = entries[0].clone();
        bad.certificate = b"basura".to_vec();
        bad.info = None;
        let mut all = entries.clone();
        all.push(bad);
        // Protocolo sin filtros explícitos: filtro por defecto de caducados.
        let m = CertFilterManager::from_extra_params(&afirma_core::ExtraParams::new()).unwrap();
        let l = candidates_with_manager(&all, &m, &CandidateOptions::protocol(now()));
        let names: Vec<&str> = l.candidates.iter().map(|e| e.alias.as_str()).collect();
        assert_eq!(names, ["auth", "firmante"]);
        assert_eq!(l.hidden_unreadable, 1);
        assert_eq!(l.hidden_without_key, 1);
        assert_eq!(l.hidden_by_filters, 2);
        assert_eq!(l.hidden_expired, 0);
        // Aplicación local por defecto: oculta caducados (preferencia) y el
        // certificado de autenticación del DNIe (no aplica a estos).
        let prefs = LocalFilterPrefs::default();
        let l = select_candidates(&all, &prefs.filters(), &CandidateOptions::local(&prefs, now()));
        assert_eq!(l.len(), 2);
        assert_eq!(l.hidden_expired, 2);
        assert!(l.auto_select(true).is_none());
        // Con un filtro que deja uno, selección automática.
        let m = CertFilterManager::from_lookup(|k| match k {
            "filters" => Some("subject.contains:00000000T;keyusage.nonrepudiation:true".into()),
            "headless" => Some("true".into()),
            _ => None,
        })
        .unwrap();
        let l = candidates_with_manager(&all, &m, &CandidateOptions::protocol(now()));
        assert_eq!(l.len(), 1);
        assert_eq!(l.auto_select(m.is_mandatory_certificate()).unwrap().alias, "firmante");
        assert!(l.auto_select(false).is_none());
    }

    #[test]
    fn sorting() {
        let mut v = vec![
            entry("keystores/filters/ku-todos.der", "b", true),
            entry("keystores/filters/cnp.der", "a", true),
            entry("keystores/filters/accv-firma.der", "c", true),
        ];
        v.push(entry("pki/firmante-ec.crt", "d", true));
        sort_candidates(&mut v);
        let names: Vec<&str> = v.iter().map(|e| e.friendly_name.as_str()).collect();
        assert_eq!(names, ["AGENTE CNP", "KU TODOS", "PERSONA ACCV FIRMA", "PRUEBA MARIA - 99999999R"]);
        // Mismo nombre: primero el que caduca más tarde.
        let mut a = entry("keystores/filters/ku-todos.der", "x", true);
        let mut b = a.clone();
        if let Some(i) = b.info.as_mut() {
            i.not_after = Utc.with_ymd_and_hms(2050, 1, 1, 0, 0, 0).unwrap();
        }
        b.sha1_upper = "00".into();
        a.friendly_name = "ku todos".into();
        let mut v = vec![a, b];
        sort_candidates(&mut v);
        assert_eq!(v[0].sha1_upper, "00");
    }
}
