//! Comparación de texto de `xsl:sort` como `java.text.RuleBasedCollator`.
//!
//! XSLTC ordena el texto con `Collator.getInstance(locale)` (el idioma de
//! `lang` o, sin él, el del sistema, que en AutoFirma es el español) y, sin
//! `case-order`, compara las `CollationKey`; con `case-order` usa
//! `StringComparable`. Se reproduce el algoritmo del JDK sobre su tabla de
//! elementos de colación ([`super::collation_table`]); el español añade la ñ
//! entre la n y la o. El resto de idiomas usa las reglas por defecto.

use std::cmp::Ordering;

use super::XsltError;
use super::collation_table::{MAX_SEC_ORDER, MAX_TER_ORDER, TABLE};

/// `CollationElementIterator.UNMAPPEDCHARVALUE`.
const UNMAPPED: u32 = 0x7fff_0000;
/// `Collator.SECONDARY` y `TERTIARY` (las únicas que usa XSLTC).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    Secondary,
    Tertiary,
}

#[derive(Clone, Copy, Debug)]
struct Collator {
    spanish: bool,
    strength: Strength,
}

/// Elemento de colación con la posición (en unidades UTF-16) del texto que
/// lo produce.
#[derive(Clone, Copy, Debug)]
struct Element {
    order: u32,
    start: usize,
    end: usize,
}

fn primary(o: u32) -> u32 {
    o >> 16
}

fn secondary(o: u32) -> u32 {
    (o & 0xff00) >> 8
}

fn tertiary(o: u32) -> u32 {
    o & 0xff
}

fn lookup(c: u16) -> Option<&'static [u32]> {
    TABLE
        .binary_search_by_key(&u32::from(c), |&(cp, _, _)| cp)
        .ok()
        .map(|i| {
            let (_, n, els) = &TABLE[i];
            &els[..*n as usize]
        })
}

impl Collator {
    /// Desplaza los primarios de la tabla por defecto para hacer hueco a la
    /// ñ (`& N < ñ, Ñ`), como reordena `RBTableBuilder`.
    fn adjust(&self, o: u32) -> u32 {
        if !self.spanish {
            return o;
        }
        let p = primary(o);
        if (0x61..0x7e00).contains(&p) { o + (1 << 16) } else { o }
    }

    fn mask(&self, o: u32) -> u32 {
        match self.strength {
            Strength::Secondary => o & 0xffff_ff00,
            Strength::Tertiary => o,
        }
    }

    /// Elementos de colación del texto (`CollationElementIterator`).
    fn elements(&self, s: &str) -> Vec<Element> {
        self.elements_with(s, false)
    }

    /// Con `canonical` las posiciones son las de la descomposición canónica
    /// (`CANONICAL_DECOMPOSITION`): mientras quedan caracteres de la
    /// descomposición de un carácter compuesto, la posición no avanza.
    fn elements_with(&self, s: &str, canonical: bool) -> Vec<Element> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = Vec::with_capacity(units.len());
        let mut i = 0;
        while i < units.len() {
            let c = units[i];
            let start = i;
            // Contracciones del español: n/N + tilde combinante.
            if self.spanish && (c == u16::from(b'n') || c == u16::from(b'N')) && units.get(i + 1) == Some(&0x303) {
                let o = if c == u16::from(b'n') { 0x61_0000 } else { 0x61_0001 };
                i += 2;
                out.push(Element {
                    order: self.mask(o),
                    start,
                    end: i,
                });
                continue;
            }
            if self.spanish && (c == 0xf1 || c == 0xd1) {
                let o = if c == 0xf1 { 0x61_0000 } else { 0x61_0001 };
                i += 1;
                out.push(Element {
                    order: self.mask(o),
                    start,
                    end: i,
                });
                continue;
            }
            // Carácter suplementario: no tiene entrada.
            if (0xd800..0xdc00).contains(&c) && units.get(i + 1).is_some_and(|l| (0xdc00..0xe000).contains(l)) {
                let low = units[i + 1];
                i += 2;
                for o in [UNMAPPED, u32::from(c) << 16, u32::from(low) << 16] {
                    out.push(Element {
                        order: o,
                        start,
                        end: i,
                    });
                }
                continue;
            }
            i += 1;
            match lookup(c) {
                Some(els) => {
                    // Carácter compuesto (base más acentos): cada elemento sale
                    // de un carácter de su descomposición.
                    let decomposed = canonical && els.len() > 1 && els[1..].iter().all(|&o| primary(o) == 0);
                    for (k, &o) in els.iter().enumerate() {
                        let (s0, e0) = if decomposed {
                            if k + 1 == els.len() { (start, i) } else { (start, start) }
                        } else if k == 0 {
                            (start, i)
                        } else {
                            // Los elementos siguientes de una expansión no avanzan.
                            (i, i)
                        };
                        out.push(Element {
                            order: self.mask(self.adjust(o)),
                            start: s0,
                            end: e0,
                        });
                    }
                }
                None => {
                    out.push(Element {
                        order: UNMAPPED,
                        start,
                        end: i,
                    });
                    out.push(Element {
                        order: u32::from(c) << 16,
                        start: i,
                        end: i,
                    });
                }
            }
        }
        out
    }

    /// `RuleBasedCollator.compare`.
    fn compare(&self, source: &str, target: &str) -> Ordering {
        if source == target {
            return Ordering::Equal;
        }
        let s_els = self.elements(source);
        let t_els = self.elements(target);
        let (mut si, mut ti) = (0usize, 0usize);
        let mut result = Ordering::Equal;
        let initial_check_sec_ter = self.strength >= Strength::Secondary;
        let mut check_sec_ter = initial_check_sec_ter;
        let mut check_tertiary = self.strength >= Strength::Tertiary;
        let (mut gets, mut gett) = (true, true);
        let (mut s_order, mut t_order) = (None, None);
        loop {
            if gets {
                s_order = s_els.get(si).map(|e| e.order);
                si += 1;
            } else {
                gets = true;
            }
            if gett {
                t_order = t_els.get(ti).map(|e| e.order);
                ti += 1;
            } else {
                gett = true;
            }
            let (Some(so), Some(to)) = (s_order, t_order) else {
                break;
            };
            let ps = primary(so);
            let pt = primary(to);
            if so == to {
                continue;
            }
            if ps != pt {
                if so == 0 {
                    gett = false;
                    continue;
                }
                if to == 0 {
                    gets = false;
                    continue;
                }
                if ps == 0 {
                    if check_sec_ter {
                        result = Ordering::Greater;
                        check_sec_ter = false;
                    }
                    gett = false;
                } else if pt == 0 {
                    if check_sec_ter {
                        result = Ordering::Less;
                        check_sec_ter = false;
                    }
                    gets = false;
                } else {
                    return ps.cmp(&pt);
                }
            } else if check_sec_ter {
                let (ss, st) = (secondary(so), secondary(to));
                if ss != st {
                    result = ss.cmp(&st);
                    check_sec_ter = false;
                } else if check_tertiary {
                    let (ts, tt) = (tertiary(so), tertiary(to));
                    if ts != tt {
                        result = ts.cmp(&tt);
                        check_tertiary = false;
                    }
                }
            }
        }
        if let Some(mut so) = s_order {
            loop {
                if primary(so) != 0 {
                    return Ordering::Greater;
                } else if secondary(so) != 0 && check_sec_ter {
                    result = Ordering::Greater;
                    check_sec_ter = false;
                }
                match s_els.get(si) {
                    Some(e) => {
                        so = e.order;
                        si += 1;
                    }
                    None => break,
                }
            }
        } else if let Some(mut to) = t_order {
            loop {
                if primary(to) != 0 {
                    return Ordering::Less;
                } else if secondary(to) != 0 && check_sec_ter {
                    result = Ordering::Less;
                    check_sec_ter = false;
                }
                match t_els.get(ti) {
                    Some(e) => {
                        to = e.order;
                        ti += 1;
                    }
                    None => break,
                }
            }
        }
        result
    }

    /// `RuleBasedCollator.getCollationKey` (como cadena UTF-16).
    fn key(&self, s: &str) -> Vec<u16> {
        let mut prim: Vec<u16> = Vec::new();
        let mut sec: Vec<u16> = Vec::new();
        let mut ter: Vec<u16> = Vec::new();
        let compare_sec = self.strength >= Strength::Secondary;
        let compare_ter = self.strength >= Strength::Tertiary;
        for e in self.elements(s) {
            let o = e.order;
            let so = secondary(o);
            let to = tertiary(o);
            if primary(o) != 0 {
                prim.push((primary(o) + 1) as u16);
                if compare_sec {
                    sec.push((so + 1) as u16);
                }
                if compare_ter {
                    ter.push((to + 1) as u16);
                }
            } else {
                if compare_sec && so != 0 {
                    sec.push((so + MAX_SEC_ORDER + 1) as u16);
                }
                if compare_ter && to != 0 {
                    ter.push((to + MAX_TER_ORDER + 1) as u16);
                }
            }
        }
        prim.push(0);
        sec.push(0);
        sec.extend(ter);
        prim.extend(sec);
        prim
    }

    /// `StringComparable.getFirstCaseDiff`: casos (mayúscula/minúscula) de
    /// la primera diferencia de caja, o `None`.
    fn first_case_diff(&self, text: &str, pattern: &str) -> Option<(Case, Case)> {
        let units_t: Vec<u16> = text.encode_utf16().collect();
        let units_p: Vec<u16> = pattern.encode_utf16().collect();
        let t_els = self.elements_with(text, true);
        let p_els = self.elements_with(pattern, true);
        let (mut ti, mut pi) = (0usize, 0usize);
        let (mut get_p, mut get_t) = (true, true);
        let mut pe: Option<Element> = None;
        let mut te: Option<Element> = None;
        loop {
            if get_p {
                pe = p_els.get(pi).copied();
                pi += 1;
            }
            if get_t {
                te = t_els.get(ti).copied();
                ti += 1;
            }
            get_t = true;
            get_p = true;
            let (Some(p), Some(t)) = (pe, te) else {
                return None;
            };
            if t.order == 0 {
                get_p = false;
            } else if p.order == 0 {
                get_t = false;
            } else if t.order != p.order && p.start < p.end && t.start < t.end {
                let sub_t = String::from_utf16_lossy(&units_t[t.start..t.end]);
                let sub_p = String::from_utf16_lossy(&units_p[p.start..p.end]);
                let up_t = sub_t.to_uppercase();
                let up_p = sub_p.to_uppercase();
                if self.compare(&up_t, &up_p) != Ordering::Equal {
                    continue;
                }
                let case_of = |s: &str, up: &str| {
                    if self.compare(s, up) == Ordering::Equal {
                        Case::Upper
                    } else if self.compare(s, &s.to_lowercase()) == Ordering::Equal {
                        Case::Lower
                    } else {
                        Case::Unknown
                    }
                };
                let d0 = case_of(&sub_t, &up_t);
                let d1 = case_of(&sub_p, &up_p);
                if (d0 == Case::Upper && d1 == Case::Lower) || (d0 == Case::Lower && d1 == Case::Upper) {
                    return Some((d0, d1));
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Upper,
    Lower,
    Unknown,
}

/// `LocaleUtility.langToLocale`: el idioma de dos letras o el del sistema
/// (español) si `lang` está vacío.
fn is_spanish(lang: &str) -> bool {
    if lang.is_empty() {
        return true;
    }
    let language = lang.split('-').next().unwrap_or("");
    language.len() == 2 && language.eq_ignore_ascii_case("es")
}

/// Compara dos claves de ordenación de texto como XSLTC.
pub(crate) fn compare(a: &str, b: &str, lang: &str, case_order: &str) -> Result<Ordering, XsltError> {
    let spanish = is_spanish(lang);
    let tertiary = Collator {
        spanish,
        strength: Strength::Tertiary,
    };
    if case_order.is_empty() {
        return Ok(tertiary.key(a).cmp(&tertiary.key(b)));
    }
    // `StringComparable.compareTo`.
    if a == b {
        return Ok(Ordering::Equal);
    }
    let secondary = Collator {
        spanish,
        strength: Strength::Secondary,
    };
    let c = secondary.compare(a, b);
    if c != Ordering::Equal {
        return Ok(c);
    }
    if let Some((d0, _)) = tertiary.first_case_diff(a, b) {
        let first = if case_order == "upper-first" {
            Case::Upper
        } else {
            Case::Lower
        };
        return Ok(if d0 == first { Ordering::Less } else { Ordering::Greater });
    }
    Ok(tertiary.compare(a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_order() {
        let mut v = vec!["b", "A", "a", "ñ", "o", "n", "B", "é", "e", "10", "9"];
        v.sort_by(|x, y| compare(x, y, "", "").unwrap());
        assert_eq!(v, vec!["10", "9", "a", "A", "b", "B", "e", "é", "n", "ñ", "o"]);
        let mut w = vec!["n", "ñ", "o"];
        w.sort_by(|x, y| compare(x, y, "en", "").unwrap());
        assert_eq!(w, vec!["n", "ñ", "o"]);
        assert_eq!(compare("a", "A", "", "upper-first").unwrap(), Ordering::Greater);
        assert_eq!(compare("a", "A", "", "lower-first").unwrap(), Ordering::Less);
    }
}
