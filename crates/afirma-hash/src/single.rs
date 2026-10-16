//! Huella digital de un único fichero: formatos de salida (§7.5.3) y
//! comprobación (§7.5.7, `CheckHashFileDialog.checkHash`).

use std::fmt;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use afirma_core::DigestAlgorithm;
use base64::Engine as _;

use crate::HashError;
use crate::algorithm::{algorithm_for_digest_len, digest_file_cancellable};

/// Formato de un fichero de huella de un único fichero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FileHashFormat {
    /// Hexadecimal ASCII en mayúsculas seguido de `h` (`.hexhash`). Predeterminado.
    #[default]
    Hex,
    /// Base64 estándar con relleno, en una línea (`.hashb64`).
    Base64,
    /// Bytes de la huella tal cual (`.hash`).
    Binary,
}

impl FileHashFormat {
    /// Formatos en el orden del desplegable de la interfaz gráfica.
    pub const ALL: [FileHashFormat; 3] = [Self::Hex, Self::Base64, Self::Binary];

    /// Nombre del formato en la línea de comandos (`-hformat`).
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Hex => "hex",
            Self::Base64 => "b64",
            Self::Binary => "bin",
        }
    }

    /// Formato correspondiente a un nombre de `-hformat` (ya en minúsculas).
    pub fn from_cli_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.cli_name() == name)
    }

    /// Extensión (sin punto) del fichero de huella.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Hex => "hexhash",
            Self::Base64 => "hashb64",
            Self::Binary => "hash",
        }
    }

    /// Texto del desplegable de la interfaz gráfica (también es el valor que
    /// Java guarda en la preferencia `createHashFormat`).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Hex => "Hexadecimal en ASCII (Base16)",
            Self::Base64 => "Base64",
            Self::Binary => "Binario",
        }
    }

    /// `HashFormat.fromString`: acepta el texto del desplegable (exacto) o
    /// `hex`/`b64`/`bin` sin distinguir mayúsculas; cualquier otro valor da el
    /// formato predeterminado (hexadecimal).
    pub fn from_preference(value: Option<&str>) -> Self {
        let Some(v) = value else { return Self::Hex };
        Self::ALL
            .into_iter()
            .find(|f| f.display_name() == v || f.cli_name().eq_ignore_ascii_case(v))
            .unwrap_or(Self::Hex)
    }

    /// Descripción del filtro del diálogo de guardado: `Huella digital (*.hexhash)`.
    pub fn filter_description(self) -> String {
        format!("Huella digital (*.{})", self.extension())
    }
}

impl fmt::Display for FileHashFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Hexadecimal en mayúsculas sin sufijo (`AOUtil.hexify(hash, false)`).
pub fn hex_upper(digest: &[u8]) -> String {
    hex::encode_upper(digest)
}

/// Hexadecimal en mayúsculas seguido de `h`, como se escribe en `.hexhash`
/// y en el atributo `hexhash` de los documentos XML.
pub fn hex_with_suffix(digest: &[u8]) -> String {
    let mut s = hex::encode_upper(digest);
    s.push('h');
    s
}

/// Contenido del fichero de huella en el formato indicado (sin salto de línea final).
pub fn encode_file_hash(digest: &[u8], format: FileHashFormat) -> Vec<u8> {
    match format {
        FileHashFormat::Hex => hex_with_suffix(digest).into_bytes(),
        FileHashFormat::Base64 => afirma_core::base64::encode(digest).into_bytes(),
        FileHashFormat::Binary => digest.to_vec(),
    }
}

/// Texto que se copia al portapapeles: el del formato elegido o, para el
/// formato binario, el hexadecimal con `h`.
pub fn clipboard_text(digest: &[u8], format: FileHashFormat) -> String {
    match format {
        FileHashFormat::Base64 => afirma_core::base64::encode(digest),
        FileHashFormat::Hex | FileHashFormat::Binary => hex_with_suffix(digest),
    }
}

/// Nombre propuesto para guardar la huella de un fichero:
/// `<nombre canónico del fichero>.<extensión>`.
pub fn default_file_hash_name(data_file: &Path, format: FileHashFormat) -> String {
    format!(
        "{}.{}",
        crate::canonical_file_name(data_file),
        format.extension()
    )
}

/// Calcula la huella de un fichero (`CreateHashFileDialog.calculateHash`).
pub fn hash_file(path: &Path, alg: DigestAlgorithm) -> Result<Vec<u8>, HashError> {
    digest_file_cancellable(path, alg, None)
}

/// Huella leída de un fichero de huella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFileHash {
    /// Bytes de la huella.
    pub digest: Vec<u8>,
    /// Codificación detectada.
    pub encoding: FileHashFormat,
    /// Algoritmo deducido de la longitud de la huella.
    pub algorithm: DigestAlgorithm,
}

/// Interpreta el contenido de un fichero de huella (`.hexhash`, `.hashb64` o `.hash`).
///
/// Variante robusta del algoritmo de Java (ver `docs/deviations/afirma-hash.md`):
/// 1. Si, sin los espacios y saltos de línea finales, el contenido es texto
///    hexadecimal de longitud par, opcionalmente terminado en `h`/`H`, se
///    decodifica como hexadecimal (solo se quita la `h` final).
/// 2. Si no, si es Base64 válido (estándar o URL-safe, con o sin relleno), se
///    decodifica como Base64.
/// 3. Si no, el contenido completo es la huella en binario.
///
/// En los dos primeros casos la interpretación textual solo se acepta si su
/// longitud corresponde a un algoritmo conocido; si no, se prueba la
/// siguiente. El algoritmo se deduce de la longitud (20 → SHA-1, 28 → SHA-224,
/// 32 → SHA-256, 48 → SHA-384, 64 → SHA-512).
pub fn decode_file_hash(content: &[u8]) -> Result<DecodedFileHash, HashError> {
    let text = trim_ascii_whitespace_end(content);
    if let Some(digest) = decode_hex_text(text) {
        if let Some(algorithm) = algorithm_for_digest_len(digest.len()) {
            return Ok(DecodedFileHash {
                digest,
                encoding: FileHashFormat::Hex,
                algorithm,
            });
        }
    }
    if let Some(digest) = decode_base64_text(text) {
        if let Some(algorithm) = algorithm_for_digest_len(digest.len()) {
            return Ok(DecodedFileHash {
                digest,
                encoding: FileHashFormat::Base64,
                algorithm,
            });
        }
    }
    match algorithm_for_digest_len(content.len()) {
        Some(algorithm) => Ok(DecodedFileHash {
            digest: content.to_vec(),
            encoding: FileHashFormat::Binary,
            algorithm,
        }),
        None => Err(HashError::UnknownDigestLength(content.len())),
    }
}

fn trim_ascii_whitespace_end(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |p| p + 1);
    &data[..end]
}

/// Decodifica hexadecimal estricto con `h`/`H` final opcional.
pub(crate) fn decode_hex_text(text: &[u8]) -> Option<Vec<u8>> {
    let digits = match text.last() {
        Some(b'h' | b'H') => &text[..text.len() - 1],
        _ => text,
    };
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    hex::decode(digits).ok()
}

/// Decodifica Base64 estricto (alfabeto estándar o URL-safe, relleno opcional).
fn decode_base64_text(text: &[u8]) -> Option<Vec<u8>> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    if text.is_empty() {
        return None;
    }
    let config =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let url_safe = text.iter().any(|b| matches!(b, b'-' | b'_'));
    let engine = if url_safe {
        GeneralPurpose::new(&base64::alphabet::URL_SAFE, config)
    } else {
        GeneralPurpose::new(&base64::alphabet::STANDARD, config)
    };
    engine.decode(text).ok()
}

/// Resultado de comprobar la huella de un fichero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashCheck {
    /// `true` si la huella calculada coincide con la del fichero de huella.
    pub matches: bool,
    /// Huella declarada en el fichero de huella.
    pub expected: DecodedFileHash,
    /// Huella calculada sobre el fichero de datos.
    pub computed: Vec<u8>,
}

/// Comprueba un fichero de datos contra el contenido de un fichero de huella.
pub fn check_file_hash(
    data_file: &Path,
    hash_file_content: &[u8],
    cancel: Option<&AtomicBool>,
) -> Result<FileHashCheck, HashError> {
    let expected = decode_file_hash(hash_file_content)?;
    let computed = digest_file_cancellable(data_file, expected.algorithm, cancel)?;
    Ok(FileHashCheck {
        matches: computed == expected.digest,
        expected,
        computed,
    })
}

/// Tamaño máximo que se lee de un fichero de huella: ninguna codificación
/// válida de una huella se acerca a este tamaño, y así no se carga en memoria
/// un fichero grande elegido por error.
pub const MAX_HASH_FILE_LEN: usize = 64 * 1024;

/// Lee un fichero de huella (como mucho [`MAX_HASH_FILE_LEN`] bytes).
pub fn read_hash_file(hash_file: &Path) -> Result<Vec<u8>, HashError> {
    use std::io::Read as _;
    let io_err = |source| HashError::Io {
        path: hash_file.to_path_buf(),
        source,
    };
    let file = std::fs::File::open(hash_file).map_err(io_err)?;
    let mut content = Vec::new();
    file.take(MAX_HASH_FILE_LEN as u64 + 1)
        .read_to_end(&mut content)
        .map_err(io_err)?;
    if content.len() > MAX_HASH_FILE_LEN {
        return Err(HashError::UnknownDigestLength(content.len()));
    }
    Ok(content)
}

/// Comprueba un fichero de datos contra un fichero de huella en disco.
pub fn check_file_hash_file(
    data_file: &Path,
    hash_file: &Path,
) -> Result<FileHashCheck, HashError> {
    let content = read_hash_file(hash_file)?;
    check_file_hash(data_file, &content, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 de un fichero vacío.
    const EMPTY_SHA256_HEX: &str =
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

    fn empty_sha256() -> Vec<u8> {
        DigestAlgorithm::Sha256.digest(b"")
    }

    #[test]
    fn vectores_de_la_especificacion() {
        let d = empty_sha256();
        assert_eq!(
            encode_file_hash(&d, FileHashFormat::Hex),
            format!("{EMPTY_SHA256_HEX}h").into_bytes()
        );
        assert_eq!(
            encode_file_hash(&d, FileHashFormat::Base64),
            b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_vec()
        );
        assert_eq!(encode_file_hash(&d, FileHashFormat::Binary), d);
        assert_eq!(
            afirma_core::base64::encode_url_safe(&d),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU="
        );
        assert_eq!(
            clipboard_text(&d, FileHashFormat::Binary),
            format!("{EMPTY_SHA256_HEX}h")
        );
        assert_eq!(
            clipboard_text(&d, FileHashFormat::Hex),
            format!("{EMPTY_SHA256_HEX}h")
        );
        assert_eq!(
            clipboard_text(&d, FileHashFormat::Base64),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }

    #[test]
    fn nombres_y_extensiones() {
        assert_eq!(FileHashFormat::Hex.extension(), "hexhash");
        assert_eq!(FileHashFormat::Base64.extension(), "hashb64");
        assert_eq!(FileHashFormat::Binary.extension(), "hash");
        assert_eq!(
            FileHashFormat::from_cli_name("b64"),
            Some(FileHashFormat::Base64)
        );
        assert_eq!(FileHashFormat::from_cli_name("xml"), None);
        assert_eq!(
            FileHashFormat::Hex.filter_description(),
            "Huella digital (*.hexhash)"
        );
        assert_eq!(
            FileHashFormat::from_preference(Some("Binario")),
            FileHashFormat::Binary
        );
        assert_eq!(
            FileHashFormat::from_preference(Some("B64")),
            FileHashFormat::Base64
        );
        assert_eq!(
            FileHashFormat::from_preference(Some("binario")),
            FileHashFormat::Hex
        );
        assert_eq!(FileHashFormat::from_preference(None), FileHashFormat::Hex);
    }

    #[test]
    fn decodificacion_de_ficheros_de_huella() {
        let d = empty_sha256();
        let cases: Vec<(Vec<u8>, FileHashFormat)> = vec![
            (
                format!("{EMPTY_SHA256_HEX}h").into_bytes(),
                FileHashFormat::Hex,
            ),
            // Sin `h` (Java lo tomaría por Base64 y no coincidiría).
            (EMPTY_SHA256_HEX.as_bytes().to_vec(), FileHashFormat::Hex),
            (
                EMPTY_SHA256_HEX.to_lowercase().into_bytes(),
                FileHashFormat::Hex,
            ),
            (
                format!("{EMPTY_SHA256_HEX}h\r\n").into_bytes(),
                FileHashFormat::Hex,
            ),
            (
                format!("{EMPTY_SHA256_HEX}H\n").into_bytes(),
                FileHashFormat::Hex,
            ),
            (
                b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".to_vec(),
                FileHashFormat::Base64,
            ),
            (
                b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\r\n".to_vec(),
                FileHashFormat::Base64,
            ),
            (
                b"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=".to_vec(),
                FileHashFormat::Base64,
            ),
            (
                b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".to_vec(),
                FileHashFormat::Base64,
            ),
            (d.clone(), FileHashFormat::Binary),
        ];
        for (content, enc) in cases {
            let dec = decode_file_hash(&content).unwrap();
            assert_eq!(dec.digest, d, "{:?}", String::from_utf8_lossy(&content));
            assert_eq!(dec.encoding, enc);
            assert_eq!(dec.algorithm, DigestAlgorithm::Sha256);
        }
        // SHA-1 en hexadecimal sin `h` (40 caracteres, múltiplo de 4).
        let sha1 = DigestAlgorithm::Sha1.digest(b"");
        let dec = decode_file_hash(hex::encode_upper(&sha1).as_bytes()).unwrap();
        assert_eq!((dec.digest, dec.algorithm), (sha1, DigestAlgorithm::Sha1));
        // Binario que termina en un salto de línea: no se recorta.
        let mut raw = vec![0x80u8; 31];
        raw.push(b'\n');
        let dec = decode_file_hash(&raw).unwrap();
        assert_eq!((dec.digest, dec.encoding), (raw, FileHashFormat::Binary));
    }

    #[test]
    fn comprobacion_con_ficheros() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("datos.txt");
        std::fs::write(&data, b"hola\n").unwrap();
        for alg in crate::GUI_ALGORITHMS {
            let digest = hash_file(&data, alg).unwrap();
            for format in FileHashFormat::ALL {
                let hf = tmp.path().join(default_file_hash_name(&data, format));
                std::fs::write(&hf, encode_file_hash(&digest, format)).unwrap();
                let check = check_file_hash_file(&data, &hf).unwrap();
                assert!(check.matches);
                assert_eq!(
                    (check.expected.algorithm, check.expected.encoding),
                    (alg, format)
                );
            }
        }
        assert_eq!(
            default_file_hash_name(&data, FileHashFormat::Base64),
            "datos.txt.hashb64"
        );
        let hf = tmp.path().join("otro.hexhash");
        std::fs::write(
            &hf,
            encode_file_hash(
                &DigestAlgorithm::Sha256.digest(b"adios\n"),
                FileHashFormat::Hex,
            ),
        )
        .unwrap();
        assert!(!check_file_hash_file(&data, &hf).unwrap().matches);
        // Fichero de huella demasiado grande.
        std::fs::write(&hf, vec![b'A'; MAX_HASH_FILE_LEN + 1]).unwrap();
        assert!(matches!(
            check_file_hash_file(&data, &hf),
            Err(HashError::UnknownDigestLength(_))
        ));
        // Fichero de datos inexistente.
        assert!(matches!(
            check_file_hash(
                &tmp.path().join("no"),
                b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                None
            ),
            Err(HashError::Io { .. })
        ));
    }

    #[test]
    fn longitudes_desconocidas() {
        assert!(matches!(
            decode_file_hash(b""),
            Err(HashError::UnknownDigestLength(0))
        ));
        assert!(matches!(
            decode_file_hash(b"ABCDh"),
            Err(HashError::UnknownDigestLength(5))
        ));
        // MD5 en hexadecimal: 16 bytes, no admitido (Java pediría "SHA-128").
        assert!(decode_file_hash(b"D41D8CD98F00B204E9800998ECF8427Eh").is_err());
    }
}
