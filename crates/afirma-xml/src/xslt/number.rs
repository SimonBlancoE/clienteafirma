//! Formato de números: `format-number()` con el `java.text.DecimalFormat` del
//! JDK (redondeo `HALF_EVEN` sobre el valor binario exacto) y `xsl:number`
//! con el `NodeCounter` de XSLTC.

use super::XsltError;
use super::compile::DecimalSymbols;

const QUOTE: char = '\'';
const CURRENCY_SIGN: char = '\u{a4}';
/// `DecimalFormat.DOUBLE_INTEGER_DIGITS` y `DOUBLE_FRACTION_DIGITS`.
const DOUBLE_INTEGER_DIGITS: usize = 309;
const DOUBLE_FRACTION_DIGITS: usize = 340;

// ---------------------------------------------------------------------------
// DigitList
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct DigitList {
    digits: Vec<u8>,
    decimal_at: i32,
    count: usize,
}

impl DigitList {
    fn is_zero(&self) -> bool {
        self.digits[..self.count].iter().all(|&d| d == b'0')
    }

    /// `DigitList.set(isNegative, double, maximumDigits, fixedPoint)`: se
    /// analiza el texto de `FloatingDecimal` como hace Java (las cifras
    /// incluyen el `0` final de textos como `5.0E-4` hasta después de
    /// decidir el redondeo de punto fijo).
    fn set_double(&mut self, source: f64, maximum_digits: i32, fixed_point: bool) {
        let jd = super::floating_decimal::binary_to_ascii(source);
        let (rounded_up, exact) = (jd.rounded_up, jd.exact);
        self.digits.clear();
        self.count = 0;
        let mut decimal_at: i32 = -1;
        let mut exponent: i32 = 0;
        let mut leading_zeros_after_decimal = 0;
        let mut non_zero_seen = false;
        let bytes = jd.text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            i += 1;
            if c == b'.' {
                decimal_at = self.count as i32;
            } else if c == b'e' || c == b'E' {
                exponent = jd.text[i..].parse().unwrap_or(0);
                break;
            } else if c != b'-' {
                if !non_zero_seen {
                    non_zero_seen = c != b'0';
                    if !non_zero_seen && decimal_at != -1 {
                        leading_zeros_after_decimal += 1;
                    }
                }
                if non_zero_seen {
                    self.digits.push(c);
                    self.count += 1;
                }
            }
        }
        if decimal_at == -1 {
            decimal_at = self.count as i32;
        }
        if non_zero_seen {
            decimal_at += exponent - leading_zeros_after_decimal;
        }
        self.decimal_at = decimal_at;
        if fixed_point {
            if -self.decimal_at > maximum_digits {
                self.count = 0;
                return;
            } else if -self.decimal_at == maximum_digits {
                if self.should_round_up(0, rounded_up, exact) {
                    self.digits = vec![b'1'];
                    self.count = 1;
                    self.decimal_at += 1;
                } else {
                    self.count = 0;
                }
                return;
            }
        }
        while self.count > 1 && self.digits[self.count - 1] == b'0' {
            self.count -= 1;
        }
        let max = if fixed_point {
            maximum_digits.saturating_add(self.decimal_at)
        } else {
            maximum_digits
        };
        self.round(max, rounded_up, exact);
    }

    fn round(&mut self, maximum_digits: i32, already_rounded: bool, exact: bool) {
        if maximum_digits >= 0 && (maximum_digits as usize) < self.count {
            let mut max = maximum_digits;
            if self.should_round_up(max as usize, already_rounded, exact) {
                loop {
                    max -= 1;
                    if max < 0 {
                        self.digits[0] = b'1';
                        self.decimal_at += 1;
                        max = 0;
                        break;
                    }
                    self.digits[max as usize] += 1;
                    if self.digits[max as usize] <= b'9' {
                        break;
                    }
                }
                max += 1;
            }
            self.count = max as usize;
            while self.count > 1 && self.digits[self.count - 1] == b'0' {
                self.count -= 1;
            }
        }
    }

    /// `shouldRoundUp` con `RoundingMode.HALF_EVEN`.
    fn should_round_up(&self, maximum_digits: usize, already_rounded: bool, exact: bool) -> bool {
        if maximum_digits < self.count {
            let d = self.digits[maximum_digits];
            if d > b'5' {
                return true;
            } else if d == b'5' {
                if maximum_digits == self.count - 1 {
                    if already_rounded {
                        return false;
                    }
                    if !exact {
                        return true;
                    }
                    return maximum_digits > 0 && !(self.digits[maximum_digits - 1] - b'0').is_multiple_of(2);
                }
                return self.digits[maximum_digits + 1..self.count].iter().any(|&x| x != b'0');
            }
        }
        false
    }

    /// `DigitList.set(isNegative, long)`.
    fn set_long(&mut self, v: i64) {
        let v = v.unsigned_abs();
        if v == 0 {
            self.digits.clear();
            self.count = 0;
            self.decimal_at = 0;
            return;
        }
        let s = v.to_string();
        self.digits = s.bytes().collect();
        self.decimal_at = self.digits.len() as i32;
        let mut c = self.digits.len();
        while c > 1 && self.digits[c - 1] == b'0' {
            c -= 1;
        }
        self.count = c;
    }
}

// ---------------------------------------------------------------------------
// DecimalFormat
// ---------------------------------------------------------------------------

/// Estado de un `java.text.DecimalFormat`: XSLTC reutiliza el mismo objeto
/// en toda la transformación y un patrón vacío no se vuelve a aplicar.
#[derive(Clone, Debug)]
pub(crate) struct Format {
    pos_prefix: String,
    pos_suffix: String,
    neg_prefix: String,
    neg_suffix: String,
    min_int: usize,
    max_int: usize,
    min_frac: usize,
    max_frac: usize,
    grouping_used: bool,
    grouping_size: usize,
    multiplier: i32,
    decimal_always: bool,
    exponential: bool,
    min_exp_digits: usize,
}

fn bad_pattern(p: &str) -> XsltError {
    XsltError::Runtime(format!("patrón de format-number() no válido: '{p}'"))
}

impl Format {
    /// `new DecimalFormat()` con la configuración regional `es_ES` (patrón
    /// `#,##0.###`) y después `setDecimalFormatSymbols(símbolos)`.
    pub(crate) fn initial(sym: &DecimalSymbols) -> Format {
        let blank = Format {
            pos_prefix: String::new(),
            pos_suffix: String::new(),
            neg_prefix: String::new(),
            neg_suffix: String::new(),
            min_int: 1,
            max_int: DOUBLE_INTEGER_DIGITS,
            min_frac: 0,
            max_frac: 3,
            grouping_used: true,
            grouping_size: 3,
            multiplier: 1,
            decimal_always: false,
            exponential: false,
            min_exp_digits: 0,
        };
        apply_pattern_with(&blank, "#,##0.###", sym, false).expect("patrón por defecto")
    }
}

/// `DecimalFormat.applyLocalizedPattern(pattern)` sobre el estado `prev`.
pub(crate) fn apply_pattern(prev: &Format, pattern: &str, sym: &DecimalSymbols) -> Result<Format, XsltError> {
    apply_pattern_with(prev, pattern, sym, true)
}

/// `DecimalFormat.applyPattern(pattern, localized)`.
fn apply_pattern_with(
    prev: &Format,
    pattern: &str,
    sym: &DecimalSymbols,
    localized: bool,
) -> Result<Format, XsltError> {
    let p: Vec<char> = pattern.chars().collect();
    let std = DecimalSymbols::default();
    let ps = if localized { sym } else { &std };
    let zero = ps.zero_digit;
    let grouping = ps.grouping_separator;
    let decimal = ps.decimal_separator;
    let percent = ps.percent;
    let per_mill = ps.per_mille;
    let digit = ps.digit;
    let separator = ps.pattern_separator;
    let exponent: Vec<char> = vec!['E'];
    let minus = ps.minus_sign;
    let region = |pos: usize| p.len() >= pos + exponent.len() && p[pos..pos + exponent.len()] == exponent[..];
    let mut f = prev.clone();
    f.decimal_always = false;
    f.exponential = false;
    let mut got_negative = false;
    let mut pos_prefix_pat = String::new();
    let mut pos_suffix_pat = String::new();
    let mut neg_prefix_pat = String::new();
    let mut neg_suffix_pat = String::new();
    let mut start = 0usize;
    let mut j: i32 = 1;
    while j >= 0 && start < p.len() {
        let mut in_quote = false;
        let mut prefix = String::new();
        let mut suffix = String::new();
        let mut decimal_pos: i32 = -1;
        let mut multiplier = 1;
        let (mut digit_left, mut zero_count, mut digit_right) = (0i32, 0i32, 0i32);
        let mut grouping_count: i32 = -1;
        let mut phase = 0;
        let mut in_suffix = false;
        let mut pos = start;
        while pos < p.len() {
            let ch = p[pos];
            let affix = if in_suffix { &mut suffix } else { &mut prefix };
            match phase {
                0 | 2 => {
                    if in_quote {
                        if ch == QUOTE {
                            if pos + 1 < p.len() && p[pos + 1] == QUOTE {
                                pos += 1;
                                affix.push_str("''");
                            } else {
                                in_quote = false;
                            }
                            pos += 1;
                            continue;
                        }
                    } else if ch == digit || ch == zero || ch == grouping || ch == decimal {
                        phase = 1;
                        continue;
                    } else if ch == CURRENCY_SIGN {
                        let doubled = pos + 1 < p.len() && p[pos + 1] == CURRENCY_SIGN;
                        if doubled {
                            pos += 1;
                        }
                        affix.push_str(if doubled { "'\u{a4}\u{a4}" } else { "'\u{a4}" });
                        pos += 1;
                        continue;
                    } else if ch == QUOTE {
                        if pos + 1 < p.len() && p[pos + 1] == QUOTE {
                            pos += 1;
                            affix.push_str("''");
                        } else {
                            in_quote = true;
                        }
                        pos += 1;
                        continue;
                    } else if ch == separator {
                        if phase == 0 || j == 0 {
                            return Err(bad_pattern(pattern));
                        }
                        start = pos + 1;
                        pos = p.len();
                        continue;
                    } else if ch == percent {
                        if multiplier != 1 {
                            return Err(bad_pattern(pattern));
                        }
                        multiplier = 100;
                        affix.push_str("'%");
                        pos += 1;
                        continue;
                    } else if ch == per_mill {
                        if multiplier != 1 {
                            return Err(bad_pattern(pattern));
                        }
                        multiplier = 1000;
                        affix.push_str("'\u{2030}");
                        pos += 1;
                        continue;
                    } else if ch == minus {
                        affix.push_str("'-");
                        pos += 1;
                        continue;
                    }
                    affix.push(ch);
                    pos += 1;
                }
                _ => {
                    if j == 0 {
                        // Patrón negativo: solo cuentan sus afijos.
                        while pos < p.len() {
                            let c = p[pos];
                            if c == digit || c == zero || c == grouping || c == decimal {
                                pos += 1;
                            } else if region(pos) {
                                pos += exponent.len();
                            } else {
                                phase = 2;
                                in_suffix = true;
                                break;
                            }
                        }
                        continue;
                    }
                    if ch == digit {
                        if zero_count > 0 {
                            digit_right += 1;
                        } else {
                            digit_left += 1;
                        }
                        if grouping_count >= 0 && decimal_pos < 0 {
                            grouping_count += 1;
                        }
                    } else if ch == zero {
                        if digit_right > 0 {
                            return Err(bad_pattern(pattern));
                        }
                        zero_count += 1;
                        if grouping_count >= 0 && decimal_pos < 0 {
                            grouping_count += 1;
                        }
                    } else if ch == grouping {
                        grouping_count = 0;
                    } else if ch == decimal {
                        if decimal_pos >= 0 {
                            return Err(bad_pattern(pattern));
                        }
                        decimal_pos = digit_left + zero_count + digit_right;
                    } else if region(pos) {
                        if f.exponential {
                            return Err(bad_pattern(pattern));
                        }
                        f.exponential = true;
                        f.min_exp_digits = 0;
                        pos += exponent.len();
                        while pos < p.len() && p[pos] == zero {
                            f.min_exp_digits += 1;
                            pos += 1;
                        }
                        if digit_left + zero_count < 1 || f.min_exp_digits < 1 {
                            return Err(bad_pattern(pattern));
                        }
                        phase = 2;
                        in_suffix = true;
                        continue;
                    } else {
                        phase = 2;
                        in_suffix = true;
                        continue;
                    }
                    pos += 1;
                }
            }
        }
        if zero_count == 0 && digit_left > 0 && decimal_pos >= 0 {
            let mut n = decimal_pos;
            if n == 0 {
                n += 1;
            }
            digit_right = digit_left - n;
            digit_left = n - 1;
            zero_count = 1;
        }
        if (decimal_pos < 0 && digit_right > 0)
            || (decimal_pos >= 0 && (decimal_pos < digit_left || decimal_pos > digit_left + zero_count))
            || grouping_count == 0
            || in_quote
        {
            return Err(bad_pattern(pattern));
        }
        if j == 1 {
            pos_prefix_pat = prefix;
            pos_suffix_pat = suffix;
            neg_prefix_pat = pos_prefix_pat.clone();
            neg_suffix_pat = pos_suffix_pat.clone();
            let total = digit_left + zero_count + digit_right;
            let eff_decimal = if decimal_pos >= 0 { decimal_pos } else { total };
            f.min_int = (eff_decimal - digit_left).max(0) as usize;
            f.max_int = if f.exponential {
                (digit_left as usize + f.min_int).min(DOUBLE_INTEGER_DIGITS)
            } else {
                DOUBLE_INTEGER_DIGITS
            };
            if f.min_int > f.max_int {
                f.min_int = f.max_int;
            }
            f.max_frac = if decimal_pos >= 0 {
                (total - decimal_pos) as usize
            } else {
                0
            };
            f.min_frac = if decimal_pos >= 0 {
                (digit_left + zero_count - decimal_pos).max(0) as usize
            } else {
                0
            };
            f.grouping_used = grouping_count > 0;
            f.grouping_size = if grouping_count > 0 { grouping_count as usize } else { 0 };
            f.multiplier = multiplier;
            f.decimal_always = decimal_pos == 0 || decimal_pos == total;
        } else {
            neg_prefix_pat = prefix;
            neg_suffix_pat = suffix;
            got_negative = true;
        }
        j -= 1;
    }
    if p.is_empty() {
        pos_prefix_pat.clear();
        pos_suffix_pat.clear();
        f.min_int = 0;
        f.max_int = DOUBLE_INTEGER_DIGITS;
        f.min_frac = 0;
        f.max_frac = DOUBLE_FRACTION_DIGITS;
    }
    f.max_frac = f.max_frac.min(DOUBLE_FRACTION_DIGITS);
    if f.min_frac > f.max_frac {
        f.min_frac = f.max_frac;
    }
    if !got_negative || (neg_prefix_pat == pos_prefix_pat && neg_suffix_pat == pos_suffix_pat) {
        neg_suffix_pat = pos_suffix_pat.clone();
        neg_prefix_pat = format!("'-{pos_prefix_pat}");
    }
    f.pos_prefix = expand_affix(&pos_prefix_pat, sym);
    f.pos_suffix = expand_affix(&pos_suffix_pat, sym);
    f.neg_prefix = expand_affix(&neg_prefix_pat, sym);
    f.neg_suffix = expand_affix(&neg_suffix_pat, sym);
    Ok(f)
}

/// `DecimalFormat.expandAffix` (símbolos de `Locale.US`).
fn expand_affix(pat: &str, sym: &DecimalSymbols) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let mut c = chars[i];
        i += 1;
        if c == QUOTE && i < chars.len() {
            c = chars[i];
            i += 1;
            match c {
                CURRENCY_SIGN => {
                    if i < chars.len() && chars[i] == CURRENCY_SIGN {
                        i += 1;
                        out.push_str("USD");
                    } else {
                        out.push('$');
                    }
                    continue;
                }
                '%' => {
                    out.push(sym.percent);
                    continue;
                }
                '\u{2030}' => {
                    out.push(sym.per_mille);
                    continue;
                }
                '-' => {
                    out.push(sym.minus_sign);
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
}

/// `format-number()` con un formateador nuevo: `DecimalFormat.applyLocalizedPattern` + `format`.
#[cfg(test)]
fn format_number(value: f64, pattern: &str, sym: &DecimalSymbols) -> Result<String, XsltError> {
    let f = apply_pattern(&Format::initial(sym), pattern, sym)?;
    Ok(format_with(value, &f, sym))
}

/// `DecimalFormat.format(double)`.
pub(crate) fn format_with(value: f64, f: &Format, sym: &DecimalSymbols) -> String {
    if value.is_nan() {
        return sym.nan.clone();
    }
    let mut number = value;
    let negative = number < 0.0 || (number == 0.0 && (1.0 / number) < 0.0);
    if f.multiplier != 1 {
        number *= f64::from(f.multiplier);
    }
    if number.is_infinite() {
        let (pre, suf) = if negative {
            (&f.neg_prefix, &f.neg_suffix)
        } else {
            (&f.pos_prefix, &f.pos_suffix)
        };
        return format!("{pre}{}{suf}", sym.infinity);
    }
    if negative {
        number = -number;
    }
    let mut dl = DigitList::default();
    let max_digits = if f.exponential {
        (f.max_int + f.max_frac) as i32
    } else {
        f.max_frac as i32
    };
    dl.set_double(number, max_digits, !f.exponential);
    let mut out = String::new();
    out.push_str(if negative { &f.neg_prefix } else { &f.pos_prefix });
    subformat(f, &mut dl, sym, &mut out);
    out.push_str(if negative { &f.neg_suffix } else { &f.pos_suffix });
    out
}

fn subformat(f: &Format, dl: &mut DigitList, sym: &DecimalSymbols, out: &mut String) {
    let zero = sym.zero_digit;
    let digit_char = |d: u8| char::from_u32(zero as u32 + u32::from(d)).unwrap_or(zero);
    if dl.is_zero() {
        dl.decimal_at = 0;
    }
    if f.exponential {
        let mut exponent = dl.decimal_at;
        let repeat = f.max_int as i32;
        let mut min_int = f.min_int as i32;
        if repeat > 1 && repeat > f.min_int as i32 {
            if exponent >= 1 {
                exponent = ((exponent - 1) / repeat) * repeat;
            } else {
                exponent = ((exponent - repeat) / repeat) * repeat;
            }
            min_int = 1;
        } else {
            exponent -= min_int;
        }
        let mut minimum_digits = (f.min_int + f.min_frac) as i32;
        let integer_digits = if dl.is_zero() {
            min_int
        } else {
            dl.decimal_at - exponent
        };
        if minimum_digits < integer_digits {
            minimum_digits = integer_digits;
        }
        let mut total = dl.count as i32;
        if minimum_digits > total {
            total = minimum_digits;
        }
        for i in 0..total {
            if i == integer_digits {
                out.push(sym.decimal_separator);
            }
            out.push(if (i as usize) < dl.count {
                digit_char(dl.digits[i as usize] - b'0')
            } else {
                zero
            });
        }
        if f.decimal_always && total == integer_digits {
            out.push(sym.decimal_separator);
        }
        out.push('E');
        if dl.is_zero() {
            exponent = 0;
        }
        if exponent < 0 {
            exponent = -exponent;
            out.push(sym.minus_sign);
        }
        let mut el = DigitList::default();
        el.set_long(i64::from(exponent));
        for _ in el.decimal_at..f.min_exp_digits as i32 {
            out.push(zero);
        }
        for i in 0..el.decimal_at {
            out.push(if (i as usize) < el.count {
                digit_char(el.digits[i as usize] - b'0')
            } else {
                zero
            });
        }
        return;
    }
    let mut count = f.min_int as i32;
    let mut digit_index: i32 = 0;
    if dl.decimal_at > 0 && count < dl.decimal_at {
        count = dl.decimal_at;
    }
    if count > f.max_int as i32 {
        count = f.max_int as i32;
        digit_index = dl.decimal_at - count;
    }
    let size_before = out.len();
    let mut i = count - 1;
    while i >= 0 {
        if i < dl.decimal_at && (digit_index as usize) < dl.count {
            out.push(digit_char(dl.digits[digit_index as usize] - b'0'));
            digit_index += 1;
        } else {
            out.push(zero);
        }
        if f.grouping_used && i > 0 && f.grouping_size != 0 && (i as usize).is_multiple_of(f.grouping_size) {
            out.push(sym.grouping_separator);
        }
        i -= 1;
    }
    let fraction_present = f.min_frac > 0 || (digit_index as usize) < dl.count;
    if !fraction_present && out.len() == size_before {
        out.push(zero);
    }
    if f.decimal_always || fraction_present {
        out.push(sym.decimal_separator);
    }
    for i in 0..f.max_frac as i32 {
        if i >= f.min_frac as i32 && (digit_index as usize) >= dl.count {
            break;
        }
        if -1 - i > dl.decimal_at - 1 {
            out.push(zero);
            continue;
        }
        if (digit_index as usize) < dl.count {
            out.push(digit_char(dl.digits[digit_index as usize] - b'0'));
            digit_index += 1;
        } else {
            out.push(zero);
        }
    }
}

// ---------------------------------------------------------------------------
// xsl:number
// ---------------------------------------------------------------------------

/// `Character.isLetterOrDigit` (aproximado con las categorías de Rust).
fn letter_or_digit(c: char) -> bool {
    c.is_alphabetic() || c.is_ascii_digit() || (c.is_numeric() && c.is_ascii_digit())
}

struct Tokens {
    separ: Vec<String>,
    formats: Vec<String>,
    separ_first: bool,
    separ_last: bool,
    n_separs: usize,
    n_formats: usize,
}

/// `NodeCounter.setTokens`.
fn tokens(format: &str) -> Tokens {
    let chars: Vec<char> = format.chars().collect();
    let mut t = Tokens {
        separ: Vec::new(),
        formats: Vec::new(),
        separ_first: true,
        separ_last: false,
        n_separs: 0,
        n_formats: 0,
    };
    let mut is_first = true;
    let length = chars.len();
    let mut i = 0;
    while i < length {
        let mut c = chars[i];
        let mut j = i;
        while letter_or_digit(c) {
            i += 1;
            if i == length {
                break;
            }
            c = chars[i];
        }
        if i > j {
            if is_first {
                t.separ.push(".".into());
                is_first = false;
                t.separ_first = false;
            }
            t.formats.push(chars[j..i].iter().collect());
        }
        if i == length {
            break;
        }
        c = chars[i];
        j = i;
        while !letter_or_digit(c) {
            i += 1;
            if i == length {
                break;
            }
            c = chars[i];
            is_first = false;
        }
        if i > j {
            t.separ.push(chars[j..i].iter().collect());
        }
    }
    t.n_separs = t.separ.len();
    t.n_formats = t.formats.len();
    if t.n_separs > t.n_formats {
        t.separ_last = true;
    }
    if t.separ_first {
        t.n_separs = t.n_separs.saturating_sub(1);
    }
    if t.separ_last {
        t.n_separs = t.n_separs.saturating_sub(1);
    }
    if t.n_separs == 0 {
        if t.separ.is_empty() {
            t.separ.push(".".into());
        } else {
            t.separ.insert(1, ".".into());
        }
        t.n_separs += 1;
    }
    if t.separ_first {
        t.n_separs += 1;
    }
    t
}

/// `NodeCounter.parseStringToAnInt`.
fn parse_group_size(s: Option<&str>) -> i32 {
    match s {
        Some(s) => s.parse::<i32>().ok().filter(|_| !s.starts_with('+')).unwrap_or(0),
        None => 0,
    }
}

const THOUSANDS: [&str; 4] = ["", "m", "mm", "mmm"];
const HUNDREDS: [&str; 10] = ["", "c", "cc", "ccc", "cd", "d", "dc", "dcc", "dccc", "cm"];
const TENS: [&str; 10] = ["", "x", "xx", "xxx", "xl", "l", "lx", "lxx", "lxxx", "xc"];
const ONES: [&str; 10] = ["", "i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix"];

fn roman(n: i32) -> String {
    if n <= 0 || n > 4000 {
        return n.to_string();
    }
    let n = n as usize;
    format!(
        "{}{}{}{}",
        THOUSANDS.get(n / 1000).copied().unwrap_or(""),
        HUNDREDS[(n / 100) % 10],
        TENS[(n / 10) % 10],
        ONES[n % 10]
    )
}

fn alpha(value: i32, min: u32, max: u32) -> String {
    if value <= 0 {
        return value.to_string();
    }
    let range = (max - min + 1) as i32;
    let last = char::from_u32(((value - 1) % range) as u32 + min).unwrap_or('?');
    if value > range {
        format!("{}{last}", alpha((value - 1) / range, min, max))
    } else {
        last.to_string()
    }
}

/// `NodeCounter.formatValue`.
fn format_one(value: i32, format: &str, letter_value: &str, group_sep: &str, group_size: i32, out: &mut String) {
    let c = format.chars().next().unwrap_or('1');
    if let Some(dv) = c.to_digit(10) {
        let zero = char::from_u32(c as u32 - dv).unwrap_or('0');
        let mut temp = String::new();
        let mut s = String::new();
        let mut n = value;
        while n > 0 {
            s.insert(0, char::from_u32(zero as u32 + (n % 10) as u32).unwrap_or('0'));
            n /= 10;
        }
        let fl = format.chars().count();
        let sl = s.chars().count();
        for _ in sl..fl {
            temp.push(zero);
        }
        temp.push_str(&s);
        if group_size > 0 {
            let chars: Vec<char> = temp.chars().collect();
            let len = chars.len();
            for (i, ch) in chars.iter().enumerate() {
                if i != 0 && (len - i).is_multiple_of(group_size as usize) {
                    out.push_str(group_sep);
                }
                out.push(*ch);
            }
        } else {
            out.push_str(&temp);
        }
    } else if c == 'i' && letter_value != "alphabetic" {
        out.push_str(&roman(value));
    } else if c == 'I' && letter_value != "alphabetic" {
        out.push_str(&roman(value).to_uppercase());
    } else {
        let min = c as u32;
        let mut max = c as u32;
        if (0x3b1..=0x3c9).contains(&min) {
            max = 0x3c9;
        } else {
            while char::from_u32(max + 1).is_some_and(letter_or_digit) {
                max += 1;
            }
        }
        out.push_str(&alpha(value, min, max));
    }
}

/// `NodeCounter.formatNumbers` (`None` = `Integer.MIN_VALUE`, se omite).
pub(crate) fn format_counts(
    values: &[Option<i32>],
    format: &str,
    letter_value: &str,
    group_sep: Option<&str>,
    group_size: Option<&str>,
) -> Result<String, XsltError> {
    if values.iter().all(Option::is_none) {
        return Ok(String::new());
    }
    let t = tokens(format);
    if t.formats.is_empty() {
        // `_formatToks.get(0)` lanza `IndexOutOfBoundsException` en Java.
        return Err(XsltError::Runtime(format!(
            "el formato de xsl:number '{format}' no tiene ningún indicador de numeración"
        )));
    }
    let gsize = parse_group_size(group_size);
    let gsep = group_sep.unwrap_or("");
    let mut out = String::new();
    if t.separ_first {
        out.push_str(&t.separ[0]);
    }
    let (mut ti, mut si) = (0usize, 1usize);
    let mut is_first = true;
    for v in values.iter().flatten() {
        if !is_first {
            out.push_str(t.separ.get(si).map(String::as_str).unwrap_or("."));
            si += 1;
        }
        let fmt = t.formats.get(ti).map(String::as_str).unwrap_or("1");
        ti += 1;
        format_one(*v, fmt, letter_value, gsep, gsize, &mut out);
        if ti >= t.n_formats {
            ti = t.n_formats.saturating_sub(1);
        }
        if si >= t.n_separs {
            si = t.n_separs.saturating_sub(1);
        }
        is_first = false;
    }
    if t.separ_last {
        out.push_str(t.separ.last().map(String::as_str).unwrap_or(""));
    }
    Ok(out)
}

/// `xsl:number value=...` (`getCounter` con `_value`).
pub(crate) fn format_value(
    x: f64,
    format: &str,
    letter_value: &str,
    group_sep: Option<&str>,
    group_size: Option<&str>,
) -> Result<String, XsltError> {
    if x == 0.0 {
        return Ok("0".into());
    }
    if x.is_nan() {
        return Ok("NaN".into());
    }
    if x.is_infinite() {
        return Ok(if x < 0.0 { "-Infinity".into() } else { "Infinity".into() });
    }
    let v = crate::xpath::java_int(x);
    format_counts(&[Some(v)], format, letter_value, group_sep, group_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(v: f64, p: &str) -> String {
        format_number(v, p, &DecimalSymbols::default()).unwrap()
    }

    #[test]
    fn decimal_format() {
        assert_eq!(fmt(1234567.891, "#,##0.00"), "1,234,567.89");
        assert_eq!(fmt(0.125, "0.00"), "0.12");
        assert_eq!(fmt(0.135, "0.00"), "0.14");
        assert_eq!(fmt(2.5, "0"), "2");
        assert_eq!(fmt(3.5, "0"), "4");
        assert_eq!(fmt(1.005, "0.00"), "1.00");
        assert_eq!(fmt(-0.001, "0.00"), "-0.00");
        assert_eq!(fmt(0.5, "#%"), "50%");
        assert_eq!(fmt(12345.0, "0.###E0"), "1.235E4");
        assert_eq!(fmt(-5.0, "#;(#)"), "(5)");
        assert_eq!(fmt(f64::NAN, "0"), "NaN");
        assert_eq!(fmt(f64::NEG_INFINITY, "0"), "-Infinity");
        assert_eq!(fmt(0.5, ""), ".5");
        assert!(format_number(1.0, "0.0.0", &DecimalSymbols::default()).is_err());
    }

    #[test]
    fn counters() {
        assert_eq!(format_counts(&[Some(3)], "1", "", None, None).unwrap(), "3");
        assert_eq!(
            format_counts(&[Some(1), Some(2)], "1.1", "", None, None).unwrap(),
            "1.2"
        );
        assert_eq!(
            format_counts(&[Some(1), None, Some(2)], "1.a)", "", None, None).unwrap(),
            "1.b)"
        );
        assert_eq!(format_counts(&[Some(4)], "i", "", None, None).unwrap(), "iv");
        assert_eq!(format_counts(&[Some(28)], "A", "", None, None).unwrap(), "AB");
        assert_eq!(format_counts(&[Some(5)], "001", "", None, None).unwrap(), "005");
        assert_eq!(
            format_counts(&[Some(1234567)], "1", "", Some("."), Some("3")).unwrap(),
            "1.234.567"
        );
        assert_eq!(format_value(2.7, "1", "", None, None).unwrap(), "2");
        assert_eq!(format_value(0.0, "a", "", None, None).unwrap(), "0");
    }
}
