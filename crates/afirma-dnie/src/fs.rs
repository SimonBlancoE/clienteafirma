//! Sistema de ficheros del DNIe: selección (`SELECT` por nombre y por identificador), longitud
//! desde el FCI y lectura completa con `READ BINARY` (especificación 10 §7.1 y §7.2).

use crate::apdu::{CommandApdu, ResponseApdu, sw};
use crate::error::DnieError;
use crate::tlv;

/// Envío de un comando por el contexto de mensajería segura activo.
pub type Sender<'a> = dyn FnMut(&CommandApdu) -> Result<ResponseApdu, DnieError> + 'a;

/// Nombre del fichero maestro (`Dnie.selectMasterFile`).
pub const MASTER_FILE_NAME: &[u8] = b"Master.File";
/// Tamaño máximo de bloque de lectura (`MAX_READ_CHUNK = 0xDE`): la respuesta protegida con PACE
/// cabe en 256 octetos.
pub const MAX_READ_CHUNK: usize = 0xDE;
/// Límite de tamaño de fichero cuando el FCI no lo indica.
const MAX_UNKNOWN_FILE: usize = 32 * 1024;

/// Ruta del CDF PKCS#15.
pub const CDF_PATH: [u8; 4] = [0x50, 0x15, 0x60, 0x04];
/// Ruta del PrKDF PKCS#15.
pub const PRKDF_PATH: [u8; 4] = [0x50, 0x15, 0x60, 0x01];
/// IDESP (número de soporte).
pub const IDESP_PATH: [u8; 2] = [0x00, 0x06];
/// Certificado X.509 de componente (canal CWA-14890).
pub const ICC_CERT_PATH: [u8; 2] = [0x60, 0x1F];

/// `SELECT` del fichero maestro por nombre (sin Le, como JMulticard).
pub fn select_mf_command() -> CommandApdu {
    CommandApdu::new(0x00, 0xA4, 0x04, 0x00).with_data(MASTER_FILE_NAME.to_vec())
}

/// Selecciona el fichero maestro.
pub fn select_mf(send: &mut Sender<'_>) -> Result<(), DnieError> {
    let r = send(&select_mf_command())?;
    if !r.is_ok() {
        return Err(DnieError::card("selección del fichero maestro", r.sw));
    }
    Ok(())
}

/// Selecciona un fichero por identificador y devuelve su tamaño si el FCI lo indica.
pub fn select_fid(send: &mut Sender<'_>, fid: [u8; 2]) -> Result<Option<usize>, DnieError> {
    let r = send(&CommandApdu::new(0x00, 0xA4, 0x00, 0x00).with_data(fid.to_vec()))?;
    match r.sw {
        sw::OK => Ok(fci_size(&r.data)),
        other => Err(DnieError::card(
            match other {
                sw::FILE_NOT_FOUND => "selección de fichero (no encontrado)",
                sw::SECURITY_STATUS => "selección de fichero (estado de seguridad no satisfecho)",
                _ => "selección de fichero",
            },
            other,
        )),
    }
}

/// Tamaño del fichero según el FCI (`6F …`): etiqueta `80` (datos) u `81` (total), o el campo
/// propietario FNMT `85 0A` (tamaño en los octetos 3–4 del valor, como JMulticard y OpenSC).
pub fn fci_size(data: &[u8]) -> Option<usize> {
    let (fci, _) = tlv::parse_one(data).ok()?;
    if fci.tag != 0x6F {
        return None;
    }
    let children = fci.children().ok()?;
    let be = |v: &[u8]| -> Option<usize> {
        (!v.is_empty() && v.len() <= 4).then(|| v.iter().fold(0usize, |a, b| (a << 8) | *b as usize))
    };
    for tag in [0x80, 0x81] {
        if let Some(t) = children.iter().find(|t| t.tag == tag) {
            return be(t.value);
        }
    }
    children
        .iter()
        .find(|t| t.tag == 0x85 && t.value.len() == 10)
        .map(|t| ((t.value[3] as usize) << 8) | t.value[4] as usize)
}

/// Lee un fichero completo en bloques de 222 octetos. Con `size = None` lee hasta que la
/// tarjeta devuelve menos datos de los pedidos, `6282` o `6B00`.
pub fn read_binary(send: &mut Sender<'_>, size: Option<usize>) -> Result<Vec<u8>, DnieError> {
    let limit = size.unwrap_or(MAX_UNKNOWN_FILE);
    let mut out = Vec::with_capacity(limit.min(4096));
    while out.len() < limit {
        let off = out.len();
        if off > 0x7FFF {
            return Err(DnieError::Read("Fichero demasiado grande para READ BINARY".into()));
        }
        let le = MAX_READ_CHUNK.min(limit - off);
        let r = send(&CommandApdu::new(0x00, 0xB0, (off >> 8) as u8, off as u8).with_le(le))?;
        match r.sw {
            sw::OK => {
                if r.data.is_empty() {
                    break;
                }
                let short = r.data.len() < le;
                out.extend_from_slice(&r.data[..r.data.len().min(limit - off)]);
                if short && size.is_none() {
                    break;
                }
            }
            sw::END_OF_FILE => {
                out.extend_from_slice(&r.data);
                break;
            }
            sw::WRONG_OFFSET => break,
            other => return Err(DnieError::card("lectura de fichero", other)),
        }
    }
    Ok(out)
}

/// Identificadores de una ruta (pares de octetos), sin el `3F00` del fichero maestro.
pub fn path_fids(path: &[u8]) -> Result<Vec<[u8; 2]>, DnieError> {
    if path.is_empty() || !path.len().is_multiple_of(2) {
        return Err(DnieError::Read(format!(
            "Ruta de fichero no válida: {}",
            hex::encode_upper(path)
        )));
    }
    Ok(path
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .filter(|f| *f != [0x3F, 0x00])
        .collect())
}

/// `SELECT MF` y selección de cada identificador de la ruta; devuelve el tamaño del último.
pub fn select_path(send: &mut Sender<'_>, path: &[u8]) -> Result<Option<usize>, DnieError> {
    let fids = path_fids(path)?;
    select_mf(send)?;
    let mut size = None;
    for fid in fids {
        size = select_fid(send, fid)?;
    }
    Ok(size)
}

/// Selecciona por ruta y lee el fichero completo (`selectFileByLocationAndRead`).
pub fn read_path(send: &mut Sender<'_>, path: &[u8]) -> Result<Vec<u8>, DnieError> {
    let size = select_path(send, path)?;
    read_binary(send, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fci_variants() {
        // Simulador: 6F 0B 81 02 tamaño 82 01 01 83 02 FID.
        assert_eq!(
            fci_size(&hex::decode("6F0B8102083482010183026004").unwrap()),
            Some(0x0834)
        );
        // §5.4 b: el FCI termina justo tras 81 (JMulticard fallaría con AIOOBE).
        assert_eq!(fci_size(&hex::decode("6F048102000A").unwrap()), Some(10));
        assert_eq!(fci_size(&hex::decode("6F04800201F4").unwrap()), Some(500));
        // Propietario FNMT: 85 0A tipo FID(2) tamaño(2) …
        assert_eq!(
            fci_size(&hex::decode("6F0C850A01601F01E80000000000").unwrap()),
            Some(0x01E8)
        );
        assert_eq!(fci_size(&[]), None);
        assert_eq!(fci_size(&hex::decode("6203820138").unwrap()), None);
    }

    #[test]
    fn read_in_chunks() {
        let content: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let mut sent = Vec::new();
        let mut send = |c: &CommandApdu| {
            sent.push(c.encode());
            let off = ((c.p1 as usize) << 8) | c.p2 as usize;
            let le = c.le().unwrap();
            let end = (off + le).min(content.len());
            let sw = if end - off < le { 0x6282 } else { 0x9000 };
            Ok(ResponseApdu::new(content[off..end].to_vec(), sw))
        };
        assert_eq!(read_binary(&mut send, Some(500)).unwrap(), content);
        assert_eq!(read_binary(&mut send, None).unwrap(), content);
        assert_eq!(sent[0], hex::decode("00B00000DE").unwrap());
        assert_eq!(sent[1], hex::decode("00B000DEDE").unwrap());
        assert_eq!(sent[2], hex::decode("00B001BC38").unwrap());
    }

    #[test]
    fn paths() {
        assert_eq!(path_fids(&[0x3F, 0x00, 0x50, 0x15]).unwrap(), vec![[0x50, 0x15]]);
        assert!(path_fids(&[0x50]).is_err());
    }
}
