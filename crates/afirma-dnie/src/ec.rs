//! Curva brainpoolP256r1 (RFC 5639; parámetro de dominio estandarizado 13 de PACE).
//!
//! **Por qué una implementación propia.** El crate `bp256` de RustCrypto compatible con la
//! versión de `elliptic-curve` del espacio de trabajo (0.13) es la 0.6, cuya aritmética está
//! marcada como `wip-arithmetic-do-not-use`; la 0.14 sí la trae, pero exige toda la generación
//! 0.14 de `elliptic-curve`/`primeorder`/`crypto-bigint` 0.7 (una segunda copia de la pila). PACE
//! solo necesita multiplicación escalar, suma y validación de puntos, así que se implementan aquí
//! sobre `crypto-bigint` 0.5 (la misma versión que ya usa el resto del espacio de trabajo):
//!
//! - Campo: residuos de Montgomery en tiempo constante (`crypto_bigint::modular::constant_mod`).
//! - Grupo: coordenadas proyectivas homogéneas con las **fórmulas completas** de
//!   Renes–Costello–Batina 2015 para `a` genérico (algoritmos 1 y 3, las mismas que
//!   `primeorder::EquationAIsGeneric`): no tienen casos excepcionales (identidad, P = Q,
//!   P = −Q), así que no hay ramas que dependan de datos secretos.
//! - Multiplicación escalar: ventana fija de 4 bits sobre los 256 bits del escalar, con
//!   selección de la tabla en tiempo constante (se recorren las 16 entradas).
//! - Conversión a afín con inversión en tiempo constante.
//!
//! Lo que es variable en tiempo solo depende de datos públicos (validación de puntos recibidos,
//! codificación).

use crypto_bigint::modular::constant_mod::Residue;
use crypto_bigint::{Encoding, U256, impl_modulus};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DnieError;
use crate::rng::RandomSource;

impl_modulus!(
    BrainpoolP256Field,
    U256,
    "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"
);

type Fe = Residue<BrainpoolP256Field, { U256::LIMBS }>;

/// Primo del cuerpo `p`.
pub const P: U256 = U256::from_be_hex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377");
/// Orden del grupo `n` (cofactor 1).
pub const N: U256 = U256::from_be_hex("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7");
const A: Fe = Fe::new(&U256::from_be_hex(
    "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
));
const B: Fe = Fe::new(&U256::from_be_hex(
    "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
));
const B3: Fe = B.add(&B).add(&B);
const GX: U256 = U256::from_be_hex("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
const GY: U256 = U256::from_be_hex("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997");

/// Punto en coordenadas proyectivas homogéneas `(X:Y:Z)`; la identidad es `(0:1:0)`.
#[derive(Clone, Copy, Debug)]
struct Projective {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl ConditionallySelectable for Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Projective {
            x: Fe::conditional_select(&a.x, &b.x, choice),
            y: Fe::conditional_select(&a.y, &b.y, choice),
            z: Fe::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Projective {
    const IDENTITY: Projective = Projective {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ZERO,
    };

    /// Suma completa (Renes–Costello–Batina 2015, algoritmo 1).
    fn add(&self, rhs: &Projective) -> Projective {
        let t0 = self.x.mul(&rhs.x); // 1
        let t1 = self.y.mul(&rhs.y); // 2
        let t2 = self.z.mul(&rhs.z); // 3
        let t3 = self.x.add(&self.y); // 4
        let t4 = rhs.x.add(&rhs.y); // 5
        let t3 = t3.mul(&t4); // 6
        let t4 = t0.add(&t1); // 7
        let t3 = t3.sub(&t4); // 8
        let t4 = self.x.add(&self.z); // 9
        let t5 = rhs.x.add(&rhs.z); // 10
        let t4 = t4.mul(&t5); // 11
        let t5 = t0.add(&t2); // 12
        let t4 = t4.sub(&t5); // 13
        let t5 = self.y.add(&self.z); // 14
        let x3 = rhs.y.add(&rhs.z); // 15
        let t5 = t5.mul(&x3); // 16
        let x3 = t1.add(&t2); // 17
        let t5 = t5.sub(&x3); // 18
        let z3 = A.mul(&t4); // 19
        let x3 = B3.mul(&t2); // 20
        let z3 = x3.add(&z3); // 21
        let x3 = t1.sub(&z3); // 22
        let z3 = t1.add(&z3); // 23
        let y3 = x3.mul(&z3); // 24
        let t1 = t0.add(&t0); // 25
        let t1 = t1.add(&t0); // 26
        let t2 = A.mul(&t2); // 27
        let t4 = B3.mul(&t4); // 28
        let t1 = t1.add(&t2); // 29
        let t2 = t0.sub(&t2); // 30
        let t2 = A.mul(&t2); // 31
        let t4 = t4.add(&t2); // 32
        let t0 = t1.mul(&t4); // 33
        let y3 = y3.add(&t0); // 34
        let t0 = t5.mul(&t4); // 35
        let x3 = t3.mul(&x3); // 36
        let x3 = x3.sub(&t0); // 37
        let t0 = t3.mul(&t1); // 38
        let z3 = t5.mul(&z3); // 39
        let z3 = z3.add(&t0); // 40
        Projective { x: x3, y: y3, z: z3 }
    }

    /// Doblado sin excepciones (Renes–Costello–Batina 2015, algoritmo 3).
    fn double(&self) -> Projective {
        let t0 = self.x.square(); // 1
        let t1 = self.y.square(); // 2
        let t2 = self.z.square(); // 3
        let t3 = self.x.mul(&self.y); // 4
        let t3 = t3.add(&t3); // 5
        let z3 = self.x.mul(&self.z); // 6
        let z3 = z3.add(&z3); // 7
        let x3 = A.mul(&z3); // 8
        let y3 = B3.mul(&t2); // 9
        let y3 = x3.add(&y3); // 10
        let x3 = t1.sub(&y3); // 11
        let y3 = t1.add(&y3); // 12
        let y3 = x3.mul(&y3); // 13
        let x3 = t3.mul(&x3); // 14
        let z3 = B3.mul(&z3); // 15
        let t2 = A.mul(&t2); // 16
        let t3 = t0.sub(&t2); // 17
        let t3 = A.mul(&t3); // 18
        let t3 = t3.add(&z3); // 19
        let z3 = t0.add(&t0); // 20
        let t0 = z3.add(&t0); // 21
        let t0 = t0.add(&t2); // 22
        let t0 = t0.mul(&t3); // 23
        let y3 = y3.add(&t0); // 24
        let t2 = self.y.mul(&self.z); // 25
        let t2 = t2.add(&t2); // 26
        let t0 = t2.mul(&t3); // 27
        let x3 = x3.sub(&t0); // 28
        let z3 = t2.mul(&t1); // 29
        let z3 = z3.add(&z3); // 30
        let z3 = z3.add(&z3); // 31
        Projective { x: x3, y: y3, z: z3 }
    }

    /// Multiplicación escalar en tiempo constante (ventana fija de 4 bits).
    fn mul(&self, k: &Scalar) -> Projective {
        let mut table = [Projective::IDENTITY; 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = if i % 2 == 0 {
                table[i / 2].double()
            } else {
                table[i - 1].add(self)
            };
        }
        let mut bytes = k.0.to_be_bytes();
        let mut acc = Projective::IDENTITY;
        for w in (0..64).rev() {
            for _ in 0..4 {
                acc = acc.double();
            }
            let byte = bytes[31 - w / 2];
            let nibble = if w % 2 == 0 { byte & 0x0F } else { byte >> 4 };
            let mut sel = Projective::IDENTITY;
            for (j, t) in table.iter().enumerate() {
                sel.conditional_assign(t, (j as u8).ct_eq(&nibble));
            }
            acc = acc.add(&sel);
        }
        bytes.zeroize();
        acc
    }

    /// Conversión a afín; `None` si es la identidad.
    fn to_affine(self) -> Option<Point> {
        let (zinv, ok) = self.z.invert();
        if !bool::from(Choice::from(ok)) {
            return None;
        }
        Some(Point {
            x: self.x.mul(&zinv).retrieve(),
            y: self.y.mul(&zinv).retrieve(),
        })
    }
}

/// Escalar (clave privada efímera, nonce PACE…). Se borra al liberarse.
#[derive(Clone)]
pub struct Scalar(U256);

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Scalar {}

impl std::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scalar(***)")
    }
}

impl Scalar {
    /// Entero sin signo big-endian de hasta 32 octetos (no se reduce módulo `n`: la
    /// multiplicación es correcta para cualquier valor).
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Scalar, DnieError> {
        if bytes.len() > 32 {
            return Err(DnieError::SecureMessaging("Escalar de más de 32 octetos".into()));
        }
        let mut buf = [0u8; 32];
        buf[32 - bytes.len()..].copy_from_slice(bytes);
        let s = Scalar(U256::from_be_slice(&buf));
        buf.zeroize();
        Ok(s)
    }

    /// Escalar aleatorio uniforme en `[1, n−1]` (muestreo por rechazo).
    pub fn random(rng: &mut dyn RandomSource) -> Result<Scalar, DnieError> {
        let mut buf = zeroize::Zeroizing::new([0u8; 32]);
        for _ in 0..64 {
            rng.fill(&mut buf[..])?;
            let k = Scalar(U256::from_be_slice(&buf[..]));
            let in_range = k.0.ct_lt(&N) & !k.0.ct_eq(&U256::ZERO);
            if bool::from(in_range) {
                return Ok(k);
            }
        }
        Err(DnieError::Random("el generador no produce escalares válidos".into()))
    }

    pub fn to_be_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.0.to_be_bytes())
    }
}

/// Punto afín de la curva, distinto de la identidad.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Point {
    x: U256,
    y: U256,
}

impl std::fmt::Debug for Point {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Point({})", hex::encode_upper(self.to_uncompressed()))
    }
}

impl Point {
    /// Generador `G`.
    pub fn generator() -> Point {
        Point { x: GX, y: GY }
    }

    fn projective(&self) -> Projective {
        Projective {
            x: Fe::new(&self.x),
            y: Fe::new(&self.y),
            z: Fe::ONE,
        }
    }

    /// Decodifica un punto no comprimido `04 ‖ X(32) ‖ Y(32)` y comprueba que está en la curva
    /// (SEC 1 §3.2.2; la identidad no es representable en esta codificación).
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Point, DnieError> {
        let bad = |m: &str| DnieError::SecureMessaging(format!("Punto de curva elíptica no válido: {m}"));
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(bad("se esperaba la codificación no comprimida de 65 octetos"));
        }
        let x = U256::from_be_slice(&bytes[1..33]);
        let y = U256::from_be_slice(&bytes[33..65]);
        if !bool::from(x.ct_lt(&P) & y.ct_lt(&P)) {
            return Err(bad("coordenada fuera del cuerpo"));
        }
        let p = Point { x, y };
        if !p.is_on_curve() {
            return Err(bad("no está en la curva brainpoolP256r1"));
        }
        Ok(p)
    }

    fn is_on_curve(&self) -> bool {
        let x = Fe::new(&self.x);
        let y = Fe::new(&self.y);
        let rhs = x.square().mul(&x).add(&A.mul(&x)).add(&B);
        bool::from(y.square().ct_eq(&rhs))
    }

    /// Codificación no comprimida `04 ‖ X ‖ Y`.
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x.to_be_bytes());
        out[33..65].copy_from_slice(&self.y.to_be_bytes());
        out
    }

    /// Coordenada X con longitud fija de 32 octetos (FE2OS, BSI TR-03111). Corrige el defecto
    /// P1 de JMulticard, que quitaba los ceros iniciales.
    pub fn x_bytes(&self) -> [u8; 32] {
        self.x.to_be_bytes()
    }

    /// `k · self`; `None` si el resultado es la identidad.
    pub fn mul(&self, k: &Scalar) -> Option<Point> {
        self.projective().mul(k).to_affine()
    }

    /// `self + other`; `None` si el resultado es la identidad.
    pub fn add(&self, other: &Point) -> Option<Point> {
        self.projective().add(&other.projective()).to_affine()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(h: &str) -> Scalar {
        Scalar::from_be_bytes(&hex::decode(h).unwrap()).unwrap()
    }

    #[test]
    fn generator_on_curve_and_order() {
        let g = Point::generator();
        assert!(g.is_on_curve());
        // n·G = O y (n−1)·G = −G.
        assert!(g.mul(&Scalar(N)).is_none());
        let minus_g = g.mul(&Scalar(N.wrapping_sub(&U256::ONE))).unwrap();
        assert_eq!(minus_g.x, g.x);
        assert!(g.add(&minus_g).is_none());
        // 2G por suma y por doblado coinciden.
        let two = g.mul(&sc("02")).unwrap();
        assert_eq!(g.add(&g).unwrap(), two);
        assert_eq!(two.mul(&sc("03")).unwrap(), g.mul(&sc("06")).unwrap());
        assert!(g.mul(&sc("00")).is_none());
    }

    #[test]
    fn icao_map_key() {
        // ICAO 9303-11, PACE ECDH-GM: PK_map_IFD = SK_map_IFD · G (§4.5).
        let pk = Point::generator()
            .mul(&sc("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99"))
            .unwrap();
        assert_eq!(
            hex::encode_upper(pk.to_uncompressed()),
            "047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E\
             544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"
        );
    }

    #[test]
    fn decoding_validation() {
        let g = Point::generator().to_uncompressed();
        assert_eq!(Point::from_uncompressed(&g).unwrap(), Point::generator());
        let mut off = g;
        off[64] ^= 1;
        assert!(Point::from_uncompressed(&off).is_err());
        let mut comp = g;
        comp[0] = 0x02;
        assert!(Point::from_uncompressed(&comp).is_err());
        assert!(Point::from_uncompressed(&g[..64]).is_err());
        let mut big = [0xFFu8; 65];
        big[0] = 4;
        assert!(Point::from_uncompressed(&big).is_err());
    }

    #[test]
    fn random_scalars_in_range() {
        struct Seq(u8);
        impl RandomSource for Seq {
            fn fill(&mut self, dest: &mut [u8]) -> Result<(), DnieError> {
                // Primero valores fuera de rango (0 y ≥ n), después uno válido.
                let v = match self.0 {
                    0 => 0x00,
                    1 => 0xFF,
                    _ => 0x11,
                };
                self.0 += 1;
                dest.fill(v);
                Ok(())
            }
        }
        let k = Scalar::random(&mut Seq(0)).unwrap();
        assert_eq!(k.to_be_bytes()[..], [0x11; 32]);
    }
}
