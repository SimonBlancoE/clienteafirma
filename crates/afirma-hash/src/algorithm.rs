//! Algoritmos de huella y cálculo por flujo (`DigestManager`, `HashUtil`).
//!
//! Los ficheros se leen por trozos de 25 MiB como mucho (`DigestManager.SIZE_25MB`),
//! sin límite de tamaño. Para no reservar 25 MiB por cada fichero pequeño, el
//! búfer se dimensiona según el tamaño del fichero (con un mínimo de 64 KiB) y
//! se reutiliza entre ficheros en el cálculo de directorios.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use afirma_core::DigestAlgorithm;

use crate::HashError;

/// Tamaño máximo de cada lectura: 25 MiB (`25 * 1024 * 1024` = 26 214 400 bytes).
pub const CHUNK_SIZE: usize = 25 * 1024 * 1024;

/// Tamaño mínimo del búfer de lectura.
const MIN_BUFFER: usize = 64 * 1024;

/// Algoritmo por defecto (`SHA-256`) de la interfaz gráfica y de la línea de comandos.
pub const DEFAULT_ALGORITHM: DigestAlgorithm = DigestAlgorithm::Sha256;

/// Algoritmos que ofrecen los desplegables de la interfaz gráfica, en su orden
/// (el primero es el predeterminado).
pub const GUI_ALGORITHMS: [DigestAlgorithm; 4] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha1,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

/// Algoritmos admitidos por el esquema `folderhashes.xsd` en los documentos XML
/// de huellas de directorio (atributo `hashAlgorithm`).
pub const XML_ALGORITHMS: [DigestAlgorithm; 4] = [
    DigestAlgorithm::Sha1,
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

/// Interpreta un nombre de algoritmo como lo haría `MessageDigest.getInstance`
/// (sin distinguir mayúsculas: `SHA-256`, `sha256`, `SHA`, OID...).
///
/// Solo se admiten SHA-1, SHA-224, SHA-256, SHA-384 y SHA-512 (Java admitiría
/// también MD5, MD2, SHA-512/224, SHA3-*...; ver `docs/deviations/afirma-hash.md`).
pub fn parse_algorithm(name: &str) -> Result<DigestAlgorithm, HashError> {
    let trimmed = name.trim();
    // `FromStr` de afirma-core admite también `_` como separador, que JCA no
    // reconoce; se rechaza para no aceptar nombres que Java no aceptaría.
    if trimmed.is_empty() || trimmed.contains('_') {
        return Err(HashError::UnsupportedAlgorithm(name.to_string()));
    }
    let oid = trimmed
        .strip_prefix("OID.")
        .or_else(|| trimmed.strip_prefix("oid."))
        .unwrap_or(trimmed);
    oid.parse::<DigestAlgorithm>()
        .map_err(|_| HashError::UnsupportedAlgorithm(name.to_string()))
}

/// Deduce el algoritmo a partir de la longitud de una huella
/// (`CheckHashFileDialog.getHashAlgorithm`): 20 bytes → SHA-1 y, en otro
/// caso, `"SHA-" + 8·longitud` (28 → SHA-224, 32 → SHA-256, 48 → SHA-384,
/// 64 → SHA-512). Cualquier otra longitud no corresponde a ningún algoritmo.
pub fn algorithm_for_digest_len(len: usize) -> Option<DigestAlgorithm> {
    match len {
        20 => Some(DigestAlgorithm::Sha1),
        28 => Some(DigestAlgorithm::Sha224),
        32 => Some(DigestAlgorithm::Sha256),
        48 => Some(DigestAlgorithm::Sha384),
        64 => Some(DigestAlgorithm::Sha512),
        _ => None,
    }
}

/// Indica si el algoritmo puede declararse en un documento XML de huellas.
pub fn is_xml_algorithm(alg: DigestAlgorithm) -> bool {
    XML_ALGORITHMS.contains(&alg)
}

/// Tamaño de búfer adecuado para un fichero de `len` bytes.
pub(crate) fn buffer_size_for(len: u64) -> usize {
    usize::try_from(len).unwrap_or(CHUNK_SIZE).clamp(MIN_BUFFER, CHUNK_SIZE)
}

/// Calcula la huella de un flujo de datos leyendo con el búfer indicado y
/// comprobando la cancelación entre lecturas.
pub(crate) fn digest_stream<R: Read>(
    alg: DigestAlgorithm,
    reader: &mut R,
    buf: &mut [u8],
    cancel: Option<&AtomicBool>,
) -> Result<Vec<u8>, StreamError> {
    let mut hasher = alg.hasher();
    loop {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(StreamError::Cancelled);
        }
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(StreamError::Io(e)),
        }
    }
    Ok(hasher.finalize())
}

/// Error interno del cálculo por flujo.
pub(crate) enum StreamError {
    Io(std::io::Error),
    Cancelled,
}

/// Calcula la huella de cualquier flujo de datos (por trozos de hasta 25 MiB).
pub fn digest_reader<R: Read>(alg: DigestAlgorithm, mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; MIN_BUFFER];
    match digest_stream(alg, &mut reader, &mut buf, None) {
        Ok(d) => Ok(d),
        Err(StreamError::Io(e)) => Err(e),
        Err(StreamError::Cancelled) => Err(std::io::Error::other("operación cancelada")),
    }
}

/// Calcula la huella de un fichero (`HashUtil.getFileHash`).
pub fn digest_file(path: &Path, alg: DigestAlgorithm) -> Result<Vec<u8>, HashError> {
    digest_file_cancellable(path, alg, None)
}

/// Calcula la huella de un fichero comprobando periódicamente la marca de
/// cancelación (para ficheros muy grandes en la interfaz gráfica).
pub fn digest_file_cancellable(
    path: &Path,
    alg: DigestAlgorithm,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<u8>, HashError> {
    let mut buf = Vec::new();
    digest_file_with_buffer(path, alg, &mut buf, cancel)
}

/// Calcula la huella de un fichero reutilizando (y ampliando si hace falta) un búfer.
pub(crate) fn digest_file_with_buffer(
    path: &Path,
    alg: DigestAlgorithm,
    buf: &mut Vec<u8>,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<u8>, HashError> {
    let io_err = |source| HashError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = File::open(path).map_err(io_err)?;
    let len = file.metadata().map(|m| m.len()).unwrap_or(CHUNK_SIZE as u64);
    let wanted = buffer_size_for(len);
    if buf.len() < wanted {
        buf.resize(wanted, 0);
    }
    match digest_stream(alg, &mut file, &mut buf[..wanted], cancel) {
        Ok(d) => Ok(d),
        Err(StreamError::Io(e)) => Err(io_err(e)),
        Err(StreamError::Cancelled) => Err(HashError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nombres_de_algoritmo_como_jca() {
        for (name, alg) in [
            ("SHA-256", DigestAlgorithm::Sha256),
            ("sha-256", DigestAlgorithm::Sha256),
            ("SHA256", DigestAlgorithm::Sha256),
            ("SHA", DigestAlgorithm::Sha1),
            ("SHA-1", DigestAlgorithm::Sha1),
            ("SHA1", DigestAlgorithm::Sha1),
            ("SHA-224", DigestAlgorithm::Sha224),
            ("SHA-384", DigestAlgorithm::Sha384),
            ("SHA-512", DigestAlgorithm::Sha512),
            ("2.16.840.1.101.3.4.2.1", DigestAlgorithm::Sha256),
            ("OID.2.16.840.1.101.3.4.2.3", DigestAlgorithm::Sha512),
        ] {
            assert_eq!(parse_algorithm(name).ok(), Some(alg), "{name}");
        }
        for bad in ["", "MD5", "FOO", "SHA_256", "SHA3-256"] {
            assert!(parse_algorithm(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn algoritmo_por_longitud() {
        assert_eq!(algorithm_for_digest_len(20), Some(DigestAlgorithm::Sha1));
        assert_eq!(algorithm_for_digest_len(28), Some(DigestAlgorithm::Sha224));
        assert_eq!(algorithm_for_digest_len(32), Some(DigestAlgorithm::Sha256));
        assert_eq!(algorithm_for_digest_len(48), Some(DigestAlgorithm::Sha384));
        assert_eq!(algorithm_for_digest_len(64), Some(DigestAlgorithm::Sha512));
        assert_eq!(algorithm_for_digest_len(16), None);
        assert_eq!(algorithm_for_digest_len(0), None);
    }

    #[test]
    fn tamano_de_bufer() {
        assert_eq!(CHUNK_SIZE, 26_214_400);
        assert_eq!(buffer_size_for(0), MIN_BUFFER);
        assert_eq!(buffer_size_for(1_000_000), 1_000_000);
        assert_eq!(buffer_size_for(u64::MAX), CHUNK_SIZE);
    }

    #[test]
    fn huella_de_flujo_por_trozos() {
        // Más grande que el búfer mínimo para forzar varias lecturas.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let d = digest_reader(DigestAlgorithm::Sha256, &data[..]).unwrap();
        assert_eq!(d, DigestAlgorithm::Sha256.digest(&data));
    }
}
