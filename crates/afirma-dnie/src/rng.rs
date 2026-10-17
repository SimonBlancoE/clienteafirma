//! Fuente de números aleatorios inyectable.
//!
//! En producción se usa el generador del sistema ([`OsRandom`]); las pruebas inyectan valores
//! fijos para reproducir los vectores de la especificación (§4.6: «la implementación debe
//! permitir inyectar el RNG»). A diferencia de JMulticard (defecto C2: `DigestRandomGenerator`
//! SHA-1 sin semilla, que hace constantes `RND.IFD`, `K.IFD` y `PRND2`), todos los aleatorios
//! del protocolo (PACE y CWA-14890) salen de esta fuente.

use std::collections::VecDeque;

use crate::error::DnieError;

/// Fuente de aleatorios criptográficamente segura.
pub trait RandomSource: Send {
    /// Llena `dest` de octetos aleatorios.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), DnieError>;
}

/// Generador del sistema operativo (`getrandom`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), DnieError> {
        getrandom::fill(dest).map_err(|e| DnieError::Random(e.to_string()))
    }
}

/// Fuente que devuelve, en orden, bloques prefijados (para pruebas y vectores deterministas).
/// Cada petición consume un bloque, que debe tener exactamente la longitud pedida; cuando se
/// acaban, recurre al generador del sistema si se ha pedido con [`Self::then_os`].
#[derive(Debug, Clone, Default)]
pub struct ScriptedRandom {
    blocks: VecDeque<Vec<u8>>,
    fallback: bool,
}

impl ScriptedRandom {
    pub fn new(blocks: impl IntoIterator<Item = Vec<u8>>) -> Self {
        ScriptedRandom {
            blocks: blocks.into_iter().collect(),
            fallback: false,
        }
    }

    /// Cuando se agoten los bloques prefijados, usar el generador del sistema.
    pub fn then_os(mut self) -> Self {
        self.fallback = true;
        self
    }
}

impl RandomSource for ScriptedRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), DnieError> {
        match self.blocks.pop_front() {
            Some(b) if b.len() == dest.len() => {
                dest.copy_from_slice(&b);
                Ok(())
            }
            Some(b) => Err(DnieError::Random(format!(
                "bloque prefijado de {} octetos para una petición de {}",
                b.len(),
                dest.len()
            ))),
            None if self.fallback => OsRandom.fill(dest),
            None => Err(DnieError::Random("no quedan bloques prefijados".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_and_scripted() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRandom.fill(&mut a).unwrap();
        OsRandom.fill(&mut b).unwrap();
        assert_ne!(a, b);
        let mut s = ScriptedRandom::new([vec![1, 2], vec![3]]);
        let mut x = [0u8; 2];
        s.fill(&mut x).unwrap();
        assert_eq!(x, [1, 2]);
        assert!(s.fill(&mut x).is_err());
        assert!(s.fill(&mut x).is_err());
        let mut s = ScriptedRandom::new([]).then_os();
        s.fill(&mut x).unwrap();
    }
}
