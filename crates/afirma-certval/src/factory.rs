//! Selección del validador de Java (`CertificateVerifierFactory`): tabla de
//! emisores identificados por CRC32 (`validationfactory.properties`) y
//! certificados de CA que AutoFirma incluye para ellos.
//!
//! De los certificados de CA de Java solo se conservan los que siguen en
//! vigor (`AC_CAMERFIRMA`, `AC_CAMERFIRMA_CAMERALES` y
//! `AC_Componentes_Informaticos_SHA256`); los del DNIe (caducados en 2021) y
//! RACER (caducado en 2023) no aportan nada: cualquier certificado emitido
//! por ellos está caducado y se rechaza antes de llegar a usarlos.

use crate::x509::Cert;

/// Tipo de validador de una entrada de la tabla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifierKind {
    Ocsp,
    Crl,
}

/// Entrada de `validationfactory.properties`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FactoryEntry {
    /// Identificador del emisor (`<id>.validation.type`).
    pub id: &'static str,
    /// Prestador (comentario del fichero de Java).
    pub name: &'static str,
    pub kind: VerifierKind,
    /// Certificado de la CA configurado (`issuerCertFile`), si se conserva.
    pub issuer: Option<&'static [u8]>,
}

const AC_CAMERFIRMA: &[u8] = include_bytes!("../certs/AC_CAMERFIRMA.cer");
const AC_CAMERFIRMA_CAMERALES: &[u8] = include_bytes!("../certs/AC_CAMERFIRMA_CAMERALES.cer");
const AC_COMPONENTES_INFORMATICOS: &[u8] = include_bytes!("../certs/AC_Componentes_Informaticos_SHA256.cer");

/// Tabla de Java (las entradas de FNMT Usuarios, Representación y
/// Administración Pública están comentadas en el original).
pub(crate) const FACTORY_TABLE: [FactoryEntry; 10] = [
    FactoryEntry {
        id: "133042780",
        name: "Camerfirma (CA general)",
        kind: VerifierKind::Ocsp,
        issuer: Some(AC_CAMERFIRMA),
    },
    // AC_RACER.cer (caducado el 2023-12-04) no se incluye.
    FactoryEntry {
        id: "122ff5553",
        name: "Camerfirma (CA RACER)",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "188b56fd7",
        name: "Camerfirma (CA Certificados Camerales)",
        kind: VerifierKind::Crl,
        issuer: Some(AC_CAMERFIRMA_CAMERALES),
    },
    // Certificados de las AC del DNIe 001 a 003 (caducados el 2021-02-26) no incluidos.
    FactoryEntry {
        id: "feebeefc",
        name: "DNIe AC 001 SHA1",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "14c508540",
        name: "DNIe AC 001 SHA2",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "177f4be82",
        name: "DNIe AC 002 SHA1",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "1c55954c6",
        name: "DNIe AC 002 SHA2",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "128f5ce18",
        name: "DNIe AC 003 SHA1",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "1765a645c",
        name: "DNIe AC 003 SHA2",
        kind: VerifierKind::Ocsp,
        issuer: None,
    },
    FactoryEntry {
        id: "109af7fc9",
        name: "FNMT (AC Componentes)",
        kind: VerifierKind::Ocsp,
        issuer: Some(AC_COMPONENTES_INFORMATICOS),
    },
];

/// Certificados de CA incluidos (DER).
pub fn bundled_ca_certificates() -> Vec<&'static [u8]> {
    vec![AC_CAMERFIRMA, AC_CAMERFIRMA_CAMERALES, AC_COMPONENTES_INFORMATICOS]
}

/// CRC-32 (polinomio de `java.util.zip.CRC32`, el de zlib).
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Identificador del emisor de un certificado según
/// `CertificateVerifierFactory.getIssuerIdentifier`: suma (en 64 bits) del
/// CRC32 del nombre del emisor en DER y del CRC32 del nombre JCA del
/// algoritmo de firma (`SHA256withRSA`...), en hexadecimal en minúsculas y
/// sin ceros a la izquierda. `None` si el certificado no se puede analizar.
pub fn java_issuer_identifier(cert_der: &[u8]) -> Option<String> {
    Cert::parse(cert_der).ok().map(|c| issuer_identifier(&c))
}

pub(crate) fn issuer_identifier(cert: &Cert) -> String {
    let alg = crate::sig::jca_signature_name(&cert.sig_alg);
    format!(
        "{:x}",
        u64::from(crc32(&cert.issuer)) + u64::from(crc32(alg.as_bytes()))
    )
}

/// Entrada de la tabla de Java para el certificado, si la hay.
pub(crate) fn lookup(cert: &Cert) -> Option<&'static FactoryEntry> {
    let id = issuer_identifier(cert);
    FACTORY_TABLE.iter().find(|e| e.id == id)
}

/// `OcspCertificateVerifier.getBestResponder`: la primera URI de la AIA o,
/// si hay varias, la **última** que contenga "ocsp" (sin distinguir
/// mayúsculas).
pub(crate) fn java_best_responder(uris: &[String]) -> Option<String> {
    let mut best = uris.first()?.clone();
    for u in uris.iter().skip(1) {
        if u.to_lowercase().contains("ocsp") {
            best = u.clone();
        }
    }
    Some(best)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn bundled_cas_parse_and_match_table() {
        // El identificador de los certificados emitidos por cada CA incluida
        // (CRC del titular de la CA + algoritmo) coincide con la tabla.
        for (der, alg, id) in [
            (AC_COMPONENTES_INFORMATICOS, "SHA256withRSA", "109af7fc9"),
            (AC_CAMERFIRMA_CAMERALES, "SHA1withRSA", "188b56fd7"),
        ] {
            let ca = Cert::parse(der).unwrap();
            let computed = format!("{:x}", u64::from(crc32(&ca.subject)) + u64::from(crc32(alg.as_bytes())));
            assert_eq!(computed, id);
        }
        for der in bundled_ca_certificates() {
            assert!(Cert::parse(der).is_ok());
        }
    }

    #[test]
    fn best_responder() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(java_best_responder(&[]), None);
        assert_eq!(
            java_best_responder(&v(&["http://a/ca.crt"])).unwrap(),
            "http://a/ca.crt"
        );
        assert_eq!(
            java_best_responder(&v(&["http://ocsp.a/", "http://a/ca.crt"])).unwrap(),
            "http://ocsp.a/"
        );
        assert_eq!(
            java_best_responder(&v(&["http://a/ca.crt", "http://OCSP1/", "http://x/", "http://ocsp2/"])).unwrap(),
            "http://ocsp2/"
        );
    }
}
