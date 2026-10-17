//! Conversión de `double` a decimal de `jdk.internal.math.FloatingDecimal`
//! (`BinaryToASCIIBuffer`), que es la que usa `java.text.DigitList` y, por
//! tanto, `format-number()`. No coincide siempre con `Double.toString` del
//! JDK 19+ (que da el decimal más corto): conserva el algoritmo antiguo,
//! con sus indicadores de exactitud y de redondeo hacia arriba.

use std::cmp::Ordering;

const EXP_SHIFT: i32 = 52;
const FRACT_HOB: u64 = 1 << EXP_SHIFT;
const EXP_ONE: u64 = 1023 << EXP_SHIFT;
const SIGNIF_BIT_MASK: u64 = FRACT_HOB - 1;
const EXP_BIT_MASK: u64 = 0x7ff << EXP_SHIFT;
const SIGN_BIT_MASK: u64 = 1 << 63;
const MAX_SMALL_BIN_EXP: i32 = 62;
const MIN_SMALL_BIN_EXP: i32 = -(63 / 3);

const N_5_BITS: [i32; 27] = [
    0, 3, 5, 7, 10, 12, 14, 17, 19, 21, 24, 26, 28, 31, 33, 35, 38, 40, 42, 45, 47, 49, 52, 54, 56, 59, 61,
];

const INSIGNIFICANT_DIGITS_NUMBER: [i32; 64] = [
    0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10,
    11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 17, 17, 17, 18, 18, 18, 19,
];

fn small_5_pow(i: i32) -> i32 {
    5i32.pow(i as u32)
}

fn long_5_pow(i: i32) -> i64 {
    5i64.pow(i as u32)
}

/// Resultado de `getBinaryToASCIIConverter(d)`.
pub(crate) struct JavaDecimal {
    /// `toJavaFormatString()`.
    pub text: String,
    /// `digitsRoundedUp()`.
    pub rounded_up: bool,
    /// `decimalDigitsExact()`.
    pub exact: bool,
}

/// Convierte un `double` finito como `FloatingDecimal` (formato compatible).
pub(crate) fn binary_to_ascii(d: f64) -> JavaDecimal {
    let bits = d.to_bits();
    let negative = bits & SIGN_BIT_MASK != 0;
    let mut fract_bits = bits & SIGNIF_BIT_MASK;
    let mut bin_exp = ((bits & EXP_BIT_MASK) >> EXP_SHIFT) as i32;
    let n_significant_bits;
    if bin_exp == 0 {
        if fract_bits == 0 {
            // B2AC_POSITIVE_ZERO / B2AC_NEGATIVE_ZERO.
            let buf = Buffer {
                negative,
                dec_exponent: 0,
                digits: vec![b'0'],
                rounded_up: false,
                exact: false,
            };
            return buf.finish();
        }
        let leading_zeros = fract_bits.leading_zeros() as i32;
        let shift = leading_zeros - (63 - EXP_SHIFT);
        fract_bits <<= shift;
        bin_exp = 1 - shift;
        n_significant_bits = 64 - leading_zeros;
    } else {
        fract_bits |= FRACT_HOB;
        n_significant_bits = EXP_SHIFT + 1;
    }
    bin_exp -= 1023;
    let mut buf = Buffer {
        negative,
        dec_exponent: 0,
        digits: Vec::new(),
        rounded_up: false,
        exact: false,
    };
    buf.dtoa(bin_exp, fract_bits, n_significant_bits);
    buf.finish()
}

struct Buffer {
    negative: bool,
    dec_exponent: i32,
    digits: Vec<u8>,
    rounded_up: bool,
    exact: bool,
}

impl Buffer {
    fn finish(self) -> JavaDecimal {
        let text = self.chars();
        JavaDecimal {
            text,
            rounded_up: self.rounded_up,
            exact: self.exact,
        }
    }

    fn develop_long_digits(&mut self, dec_exponent: i32, lvalue: i64, insignificant: i32) {
        let mut dec_exponent = dec_exponent;
        let mut lvalue = lvalue;
        if insignificant != 0 {
            let pow10 = long_5_pow(insignificant) << insignificant;
            let residue = lvalue % pow10;
            lvalue /= pow10;
            dec_exponent += insignificant;
            if residue >= (pow10 >> 1) {
                lvalue += 1;
            }
        }
        // Las cifras se generan de la menos significativa a la más, sin los
        // ceros finales.
        let mut rev: Vec<u8> = Vec::new();
        let mut c = lvalue % 10;
        lvalue /= 10;
        while c == 0 {
            dec_exponent += 1;
            c = lvalue % 10;
            lvalue /= 10;
        }
        while lvalue != 0 {
            rev.push(b'0' + c as u8);
            dec_exponent += 1;
            c = lvalue % 10;
            lvalue /= 10;
        }
        rev.push(b'0' + c as u8);
        rev.reverse();
        self.digits = rev;
        self.dec_exponent = dec_exponent + 1;
    }

    fn dtoa(&mut self, bin_exp: i32, fract_bits: u64, n_significant_bits: i32) {
        let tail_zeros = fract_bits.trailing_zeros() as i32;
        let n_fract_bits = EXP_SHIFT + 1 - tail_zeros;
        self.rounded_up = false;
        self.exact = false;
        let n_tiny_bits = (n_fract_bits - bin_exp - 1).max(0);
        if (MIN_SMALL_BIN_EXP..=MAX_SMALL_BIN_EXP).contains(&bin_exp)
            && n_tiny_bits < 27
            && n_fract_bits + N_5_BITS[n_tiny_bits as usize] < 64
            && n_tiny_bits == 0
        {
            let insignificant = if bin_exp > n_significant_bits {
                insignificant_digits_for_pow2(bin_exp - n_significant_bits - 1)
            } else {
                0
            };
            let v = if bin_exp >= EXP_SHIFT {
                fract_bits << (bin_exp - EXP_SHIFT)
            } else {
                fract_bits >> (EXP_SHIFT - bin_exp)
            };
            self.develop_long_digits(0, v as i64, insignificant);
            return;
        }
        let mut dec_exp = estimate_dec_exp(fract_bits, bin_exp);
        let b5 = (-dec_exp).max(0);
        let mut b2 = b5 + n_tiny_bits + bin_exp;
        let s5 = dec_exp.max(0);
        let mut s2 = s5 + n_tiny_bits;
        let m5 = b5;
        let mut m2 = b2 - n_significant_bits;
        let fract = fract_bits >> tail_zeros;
        b2 -= n_fract_bits - 1;
        let common2 = b2.min(s2);
        b2 -= common2;
        s2 -= common2;
        m2 -= common2;
        if n_fract_bits == 1 {
            m2 -= 1;
        }
        if m2 < 0 {
            b2 -= m2;
            s2 -= m2;
            m2 = 0;
        }
        let bbits = n_fract_bits + b2 + if b5 < 27 { N_5_BITS[b5 as usize] } else { b5 * 3 };
        let ten_sbits = s2
            + 1
            + if s5 + 1 < 27 {
                N_5_BITS[(s5 + 1) as usize]
            } else {
                (s5 + 1) * 3
            };
        let mut digits: Vec<u8> = Vec::new();
        let (low, high, low_digit_difference);
        if bbits < 64 && ten_sbits < 64 {
            if bbits < 32 && ten_sbits < 32 {
                let mut b = (fract as i32).wrapping_mul(small_5_pow(b5)).wrapping_shl(b2 as u32);
                let s = small_5_pow(s5).wrapping_shl(s2 as u32);
                let mut m = small_5_pow(m5).wrapping_shl(m2 as u32);
                let tens = s.wrapping_mul(10);
                let mut q = b / s;
                b = 10i32.wrapping_mul(b % s);
                m = m.wrapping_mul(10);
                let mut lo = b < m;
                let mut hi = b.wrapping_add(m) > tens;
                if q == 0 && !hi {
                    dec_exp -= 1;
                } else {
                    digits.push(b'0' + q as u8);
                }
                if !(-3..8).contains(&dec_exp) {
                    hi = false;
                    lo = false;
                }
                while !lo && !hi {
                    q = b / s;
                    b = 10i32.wrapping_mul(b % s);
                    m = m.wrapping_mul(10);
                    if m > 0 {
                        lo = b < m;
                        hi = b.wrapping_add(m) > tens;
                    } else {
                        lo = true;
                        hi = true;
                    }
                    digits.push(b'0' + q as u8);
                }
                low_digit_difference = i64::from(b.wrapping_shl(1).wrapping_sub(tens));
                self.exact = b == 0;
                low = lo;
                high = hi;
            } else {
                let mut b = (fract as i64).wrapping_mul(long_5_pow(b5)).wrapping_shl(b2 as u32);
                let s = long_5_pow(s5).wrapping_shl(s2 as u32);
                let mut m = long_5_pow(m5).wrapping_shl(m2 as u32);
                let tens = s.wrapping_mul(10);
                let mut q = b / s;
                b = 10i64.wrapping_mul(b % s);
                m = m.wrapping_mul(10);
                let mut lo = b < m;
                let mut hi = b.wrapping_add(m) > tens;
                if q == 0 && !hi {
                    dec_exp -= 1;
                } else {
                    digits.push(b'0' + q as u8);
                }
                if !(-3..8).contains(&dec_exp) {
                    hi = false;
                    lo = false;
                }
                while !lo && !hi {
                    q = b / s;
                    b = 10i64.wrapping_mul(b % s);
                    m = m.wrapping_mul(10);
                    if m > 0 {
                        lo = b < m;
                        hi = b.wrapping_add(m) > tens;
                    } else {
                        lo = true;
                        hi = true;
                    }
                    digits.push(b'0' + q as u8);
                }
                low_digit_difference = b.wrapping_shl(1).wrapping_sub(tens);
                self.exact = b == 0;
                low = lo;
                high = hi;
            }
        } else {
            // FDBigInteger: la normalización desplaza todos los operandos por
            // igual y no cambia ningún resultado.
            let sval = Nat::pow52(s5, s2);
            let mut bval = Nat::from_u64(fract);
            bval.mul_pow5(b5);
            bval.shl(b2);
            let mut mval = Nat::pow52(m5 + 1, m2 + 1);
            let ten_sval = Nat::pow52(s5 + 1, s2 + 1);
            let mut q = bval.quo_rem_iteration(&sval);
            let mut lo = bval.cmp(&mval) == Ordering::Less;
            let mut hi = ten_sval.cmp(&bval.add(&mval)) != Ordering::Greater;
            if q == 0 && !hi {
                dec_exp -= 1;
            } else {
                digits.push(b'0' + q as u8);
            }
            if !(-3..8).contains(&dec_exp) {
                hi = false;
                lo = false;
            }
            while !lo && !hi {
                q = bval.quo_rem_iteration(&sval);
                mval.mul_small(10);
                lo = bval.cmp(&mval) == Ordering::Less;
                hi = ten_sval.cmp(&bval.add(&mval)) != Ordering::Greater;
                digits.push(b'0' + q as u8);
            }
            if hi && lo {
                bval.shl(1);
                low_digit_difference = match bval.cmp(&ten_sval) {
                    Ordering::Less => -1,
                    Ordering::Equal => 0,
                    Ordering::Greater => 1,
                };
            } else {
                low_digit_difference = 0;
            }
            self.exact = bval.is_zero();
            low = lo;
            high = hi;
        }
        self.dec_exponent = dec_exp + 1;
        self.digits = digits;
        if high {
            if low {
                if low_digit_difference == 0 {
                    if self.digits.last().is_some_and(|d| d & 1 != 0) {
                        self.roundup();
                    }
                } else if low_digit_difference > 0 {
                    self.roundup();
                }
            } else {
                self.roundup();
            }
        }
    }

    fn roundup(&mut self) {
        let mut i = self.digits.len() - 1;
        let mut q = self.digits[i];
        if q == b'9' {
            while q == b'9' && i > 0 {
                self.digits[i] = b'0';
                i -= 1;
                q = self.digits[i];
            }
            if q == b'9' {
                // Todo nueves: no se marca `decimalDigitsRoundedUp`.
                self.dec_exponent += 1;
                self.digits[0] = b'1';
                return;
            }
        }
        self.digits[i] = q + 1;
        self.rounded_up = true;
    }

    /// `getChars`.
    fn chars(&self) -> String {
        let d = &self.digits;
        let n = d.len() as i32;
        let e = self.dec_exponent;
        let mut out = String::new();
        if self.negative {
            out.push('-');
        }
        let push = |out: &mut String, s: &[u8]| out.extend(s.iter().map(|&b| b as char));
        if e > 0 && e < 8 {
            let len = n.min(e);
            push(&mut out, &d[..len as usize]);
            if len < e {
                for _ in 0..e - len {
                    out.push('0');
                }
                out.push_str(".0");
            } else {
                out.push('.');
                if len < n {
                    push(&mut out, &d[len as usize..]);
                } else {
                    out.push('0');
                }
            }
        } else if e <= 0 && e > -3 {
            out.push_str("0.");
            for _ in 0..-e {
                out.push('0');
            }
            push(&mut out, d);
        } else {
            out.push(d[0] as char);
            out.push('.');
            if n > 1 {
                push(&mut out, &d[1..]);
            } else {
                out.push('0');
            }
            out.push('E');
            let exp = if e <= 0 {
                out.push('-');
                -e + 1
            } else {
                e - 1
            };
            out.push_str(&exp.to_string());
        }
        out
    }
}

fn insignificant_digits_for_pow2(p2: i32) -> i32 {
    if p2 > 1 && (p2 as usize) < INSIGNIFICANT_DIGITS_NUMBER.len() {
        INSIGNIFICANT_DIGITS_NUMBER[p2 as usize]
    } else {
        0
    }
}

// La constante es el literal de Java (no `LOG10_2` exacto): el resultado
// debe coincidir bit a bit.
#[allow(clippy::approx_constant)]
fn estimate_dec_exp(fract_bits: u64, bin_exp: i32) -> i32 {
    let d2 = f64::from_bits(EXP_ONE | (fract_bits & SIGNIF_BIT_MASK));
    let d = (d2 - 1.5) * 0.289529654 + 0.176091259 + f64::from(bin_exp) * 0.301029995663981;
    let d_bits = d.to_bits();
    let exponent = ((d_bits & EXP_BIT_MASK) >> EXP_SHIFT) as i32 - 1023;
    let negative = d_bits & SIGN_BIT_MASK != 0;
    if (0..52).contains(&exponent) {
        let mask = SIGNIF_BIT_MASK >> exponent;
        let r = (((d_bits & SIGNIF_BIT_MASK) | FRACT_HOB) >> (EXP_SHIFT - exponent)) as i32;
        if negative {
            if mask & d_bits == 0 { -r } else { -r - 1 }
        } else {
            r
        }
    } else if exponent < 0 {
        if d_bits & !SIGN_BIT_MASK == 0 {
            0
        } else if negative {
            -1
        } else {
            0
        }
    } else {
        d as i32
    }
}

/// Natural de precisión arbitraria (palabras de 32 bits, la menos
/// significativa primero).
#[derive(Clone, Debug)]
struct Nat(Vec<u32>);

impl Nat {
    fn from_u64(v: u64) -> Nat {
        let mut n = Nat(vec![v as u32, (v >> 32) as u32]);
        n.trim();
        n
    }

    fn pow52(p5: i32, p2: i32) -> Nat {
        let mut n = Nat::from_u64(1);
        n.mul_pow5(p5);
        n.shl(p2);
        n
    }

    fn trim(&mut self) {
        while self.0.len() > 1 && self.0.last() == Some(&0) {
            self.0.pop();
        }
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    fn mul_small(&mut self, m: u32) {
        let mut carry = 0u64;
        for w in &mut self.0 {
            let v = u64::from(*w) * u64::from(m) + carry;
            *w = v as u32;
            carry = v >> 32;
        }
        if carry > 0 {
            self.0.push(carry as u32);
        }
    }

    fn mul_pow5(&mut self, p: i32) {
        let mut p = p;
        while p >= 13 {
            self.mul_small(1_220_703_125); // 5^13
            p -= 13;
        }
        if p > 0 {
            self.mul_small(5u32.pow(p as u32));
        }
    }

    fn shl(&mut self, bits: i32) {
        if bits <= 0 {
            return;
        }
        let words = (bits / 32) as usize;
        let rest = bits % 32;
        if rest > 0 {
            let mut carry = 0u32;
            for w in &mut self.0 {
                let v = (*w << rest) | carry;
                carry = *w >> (32 - rest);
                *w = v;
            }
            if carry > 0 {
                self.0.push(carry);
            }
        }
        if words > 0 {
            let mut v = vec![0u32; words];
            v.extend_from_slice(&self.0);
            self.0 = v;
        }
    }

    fn add(&self, other: &Nat) -> Nat {
        let len = self.0.len().max(other.0.len());
        let mut out = Vec::with_capacity(len + 1);
        let mut carry = 0u64;
        for i in 0..len {
            let a = u64::from(*self.0.get(i).unwrap_or(&0));
            let b = u64::from(*other.0.get(i).unwrap_or(&0));
            let v = a + b + carry;
            out.push(v as u32);
            carry = v >> 32;
        }
        if carry > 0 {
            out.push(carry as u32);
        }
        let mut n = Nat(out);
        n.trim();
        n
    }

    /// `self -= other` con `self >= other`.
    fn sub_assign(&mut self, other: &Nat) {
        let mut borrow = 0i64;
        for i in 0..self.0.len() {
            let a = i64::from(self.0[i]);
            let b = i64::from(*other.0.get(i).unwrap_or(&0));
            let mut v = a - b - borrow;
            if v < 0 {
                v += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            self.0[i] = v as u32;
        }
        self.trim();
    }

    fn cmp(&self, other: &Nat) -> Ordering {
        let mut a = self.clone();
        let mut b = other.clone();
        a.trim();
        b.trim();
        if a.is_zero() && b.is_zero() {
            return Ordering::Equal;
        }
        if a.0.len() != b.0.len() {
            return a.0.len().cmp(&b.0.len());
        }
        for i in (0..a.0.len()).rev() {
            if a.0[i] != b.0[i] {
                return a.0[i].cmp(&b.0[i]);
            }
        }
        Ordering::Equal
    }

    /// `quoRemIteration`: `q = self / s`, `self = 10 * (self mod s)`.
    fn quo_rem_iteration(&mut self, s: &Nat) -> u32 {
        let mut q = 0;
        while self.cmp(s) != Ordering::Less {
            self.sub_assign(s);
            q += 1;
        }
        self.mul_small(10);
        self.trim();
        q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(d: f64) -> String {
        binary_to_ascii(d).text
    }

    #[test]
    fn formatos_de_java() {
        assert_eq!(text(0.0), "0.0");
        assert_eq!(text(12345.0), "12345.0");
        assert_eq!(text(0.0005), "5.0E-4");
        assert_eq!(text(0.001), "0.001");
        assert_eq!(text(1e7), "1.0E7");
        assert_eq!(text(1234567.0), "1234567.0");
        assert_eq!(text(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(text(2.0e-3), "0.002");
        assert_eq!(text(1.7976931348623157e308), "1.7976931348623157E308");
        assert_eq!(text(5e-324), "4.9E-324");
        assert_eq!(text(100.0), "100.0");
        let e = binary_to_ascii(12345.0);
        assert!(!e.exact && !e.rounded_up);
        let e = binary_to_ascii(0.5);
        assert!(e.exact);
    }
}
