//! Decodificación hexadecimal en tiempo de compilación para las constantes.

/// Convierte una cadena hexadecimal (mayúsculas o minúsculas, sin separadores) en un array de
/// `N` octetos. Falla la compilación si la longitud o algún carácter no son válidos.
pub(crate) const fn h<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert!(b.len() == 2 * N, "longitud hexadecimal incorrecta");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("carácter hexadecimal no válido"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn decode() {
        const X: [u8; 3] = super::h("0aFf10");
        assert_eq!(X, [0x0A, 0xFF, 0x10]);
    }
}
