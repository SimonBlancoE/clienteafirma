use std::fmt;
use std::str::FromStr;

use super::{Asn1Error, Result};

/// Identificador de objeto ASN.1 guardado en su forma codificada (contenido DER,
/// sin etiqueta ni longitud).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(Vec<u8>);

impl Oid {
    /// Crea un OID a partir de su contenido DER (sin cabecera).
    pub fn from_der_content(content: &[u8]) -> Result<Self> {
        if content.is_empty() || content[content.len() - 1] & 0x80 != 0 {
            return Err(Asn1Error::Invalid("OID mal codificado".into()));
        }
        Ok(Oid(content.to_vec()))
    }

    /// Crea un OID a partir de su notación con puntos. Entra en pánico si la
    /// cadena no es válida: pensado para constantes conocidas.
    pub fn new(dotted: &str) -> Self {
        dotted.parse().unwrap_or_else(|_| panic!("OID no válido: {dotted}"))
    }

    /// Contenido DER del OID (sin etiqueta ni longitud).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Arcos del OID.
    pub fn arcs(&self) -> Vec<u64> {
        let mut out = Vec::new();
        let mut value: u64 = 0;
        let mut first = true;
        for &b in &self.0 {
            value = (value << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                if first {
                    let (a, b2) = if value < 40 {
                        (0, value)
                    } else if value < 80 {
                        (1, value - 40)
                    } else {
                        (2, value - 80)
                    };
                    out.push(a);
                    out.push(b2);
                    first = false;
                } else {
                    out.push(value);
                }
                value = 0;
            }
        }
        out
    }

    /// Representación con puntos (`1.2.840.113549.1.7.2`).
    pub fn to_dotted(&self) -> String {
        self.arcs()
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Compara con una representación con puntos.
    pub fn is(&self, dotted: &str) -> bool {
        self.to_dotted() == dotted
    }
}

impl FromStr for Oid {
    type Err = Asn1Error;

    fn from_str(s: &str) -> Result<Self> {
        let arcs: Vec<u64> = s
            .trim()
            .split('.')
            .map(|a| a.parse::<u64>())
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| Asn1Error::Invalid(format!("OID no válido: {s}")))?;
        if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
            return Err(Asn1Error::Invalid(format!("OID no válido: {s}")));
        }
        let mut out = Vec::new();
        encode_arc(&mut out, arcs[0] * 40 + arcs[1]);
        for &arc in &arcs[2..] {
            encode_arc(&mut out, arc);
        }
        Ok(Oid(out))
    }
}

fn encode_arc(out: &mut Vec<u8>, mut value: u64) {
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for (idx, b) in tmp.iter().enumerate().skip(i) {
        out.push(if idx == last { *b } else { *b | 0x80 });
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_dotted())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.to_dotted())
    }
}
