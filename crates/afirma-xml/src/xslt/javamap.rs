//! Orden de iteración de `HashMap` y `Hashtable` de Java.
//!
//! XSLTC y el serializador del JDK recorren tablas hash para decidir el
//! orden de las declaraciones de espacios de nombres y la elección de
//! prefijos. Para reproducir la salida hay que recorrer las claves en el
//! mismo orden que Java, que depende de `String.hashCode` y de la capacidad
//! de la tabla.

/// `String.hashCode` de Java (sobre unidades UTF-16).
pub(crate) fn java_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for u in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(u));
    }
    h
}

/// Claves de un `java.util.HashMap<String, _>` sin borrados: se recorren por
/// cubeta (`(h ^ h >>> 16) & (capacidad - 1)`) y, dentro de cada cubeta, por
/// orden de inserción.
#[derive(Clone, Debug, Default)]
pub(crate) struct JavaHashMapOrder {
    keys: Vec<String>,
}

impl JavaHashMapOrder {
    /// Inserta una clave (sin efecto si ya estaba).
    pub(crate) fn insert(&mut self, key: &str) {
        if !self.keys.iter().any(|k| k == key) {
            self.keys.push(key.to_string());
        }
    }

    fn capacity(&self) -> usize {
        let mut cap = 16usize;
        while self.keys.len() > cap * 3 / 4 {
            cap *= 2;
        }
        cap
    }

    /// Claves en el orden de iteración de Java.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &str> {
        let mask = (self.capacity() - 1) as u32;
        let mut idx: Vec<(u32, usize)> = self
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let h = java_hash(k) as u32;
                ((h ^ (h >> 16)) & mask, i)
            })
            .collect();
        idx.sort();
        idx.into_iter().map(move |(_, i)| self.keys[i].as_str())
    }
}

/// Un `java.util.Hashtable<String, V>` con su estructura de cubetas, para
/// recorrerlo como `entrySet().iterator()` (de la última cubeta a la primera
/// y, en cada una, de la entrada más reciente a la más antigua).
#[derive(Clone, Debug)]
pub(crate) struct JavaHashtable<V> {
    buckets: Vec<Vec<(String, V)>>,
    count: usize,
    threshold: usize,
}

impl<V: Clone> Default for JavaHashtable<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Clone> JavaHashtable<V> {
    pub(crate) fn new() -> Self {
        JavaHashtable {
            buckets: vec![Vec::new(); 11],
            count: 0,
            threshold: 8,
        }
    }

    fn index(key: &str, len: usize) -> usize {
        ((java_hash(key) & 0x7fff_ffff) as usize) % len
    }

    pub(crate) fn get(&self, key: &str) -> Option<&V> {
        let i = Self::index(key, self.buckets.len());
        self.buckets[i].iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub(crate) fn put(&mut self, key: &str, value: V) {
        let i = Self::index(key, self.buckets.len());
        if let Some(slot) = self.buckets[i].iter_mut().find(|(k, _)| k == key) {
            slot.1 = value;
            return;
        }
        if self.count >= self.threshold {
            self.rehash();
        }
        let i = Self::index(key, self.buckets.len());
        // Cada cubeta se guarda con la entrada más reciente al principio.
        self.buckets[i].insert(0, (key.to_string(), value));
        self.count += 1;
    }

    fn rehash(&mut self) {
        let old = std::mem::take(&mut self.buckets);
        let new_cap = old.len() * 2 + 1;
        self.buckets = vec![Vec::new(); new_cap];
        for bucket in old.into_iter().rev() {
            for (k, v) in bucket {
                let i = Self::index(&k, new_cap);
                self.buckets[i].insert(0, (k, v));
            }
        }
        self.threshold = new_cap * 3 / 4;
    }

    /// Entradas en el orden de iteración de Java.
    pub(crate) fn entries(&self) -> Vec<(String, V)> {
        let mut out = Vec::with_capacity(self.count);
        for bucket in self.buckets.iter().rev() {
            for (k, v) in bucket {
                out.push((k.clone(), v.clone()));
            }
        }
        out
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_hash() {
        assert_eq!(java_hash(""), 0);
        assert_eq!(java_hash("xml"), 118807);
        assert_eq!(java_hash("hola"), 3208380);
    }

    #[test]
    fn hashmap_order() {
        let mut m = JavaHashMapOrder::default();
        for k in ["", "xml", "b", "a"] {
            m.insert(k);
        }
        // "" -> 0, "a" -> 97 & 15 = 1, "b" -> 2, "xml" -> 118807 ^ 1 = ... & 15 = 6
        assert_eq!(m.iter().collect::<Vec<_>>(), vec!["", "a", "b", "xml"]);
    }

    #[test]
    fn hashtable_order() {
        let mut t = JavaHashtable::new();
        for k in ["", "m", "b", "a", "z"] {
            t.put(k, ());
        }
        // Índices en 11: "" -> 0, "a" -> 97 % 11 = 9, "b" -> 10, "m" -> 109 % 11 = 10, "z" -> 122 % 11 = 1.
        let order: Vec<String> = t.entries().into_iter().map(|(k, _)| k).collect();
        assert_eq!(order, vec!["b", "m", "a", "z", ""]);
    }
}
