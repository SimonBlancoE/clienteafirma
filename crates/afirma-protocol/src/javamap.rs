//! Orden de iteración de `java.util.HashMap` / `ConcurrentHashMap` con
//! claves `String`.
//!
//! AutoFirma serializa varios mapas (parámetros de `TriphaseData`, objetos de
//! `org.json`) en el orden de iteración de estas tablas hash. Ese orden no
//! está especificado, pero reproducirlo permite comparar byte a byte con las
//! salidas de Java en los casos habituales (mapas pequeños).

/// `String.hashCode()` de Java (sobre unidades UTF-16, aritmética de 32 bits).
pub fn java_string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for u in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(u as i32);
    }
    h
}

/// Función de dispersión de `HashMap.hash` / `ConcurrentHashMap.spread`
/// (el bit de signo no influye en el índice para tablas de hasta 2^30).
fn spread(h: i32) -> u32 {
    let h = h as u32;
    h ^ (h >> 16)
}

/// Capacidad de la tabla de un `HashMap` creado con el constructor por
/// defecto tras insertar `n` elementos (16 y se duplica al superar el 75 %).
fn table_size(n: usize) -> usize {
    let mut cap = 16usize;
    while n > cap * 3 / 4 {
        cap *= 2;
    }
    cap
}

/// Devuelve los índices de `keys` (en orden de inserción) ordenados como los
/// recorrería un `HashMap` de Java. Dentro de cada cubeta se conserva el
/// orden de inserción.
pub fn java_hash_order<S: AsRef<str>>(keys: &[S]) -> Vec<usize> {
    let cap = table_size(keys.len());
    let mut idx: Vec<(usize, usize)> =
        keys.iter().enumerate().map(|(i, k)| ((spread(java_string_hash(k.as_ref())) as usize) & (cap - 1), i)).collect();
    idx.sort();
    idx.into_iter().map(|(_, i)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_match_java() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("PRE"), 79491);
        assert_eq!(java_string_hash("hello"), 99162322);
        assert_eq!(java_string_hash("NEED_PRE"), 1_649_584_986);
        assert_eq!(java_string_hash("ñ"), 241);
    }

    #[test]
    fn order_of_small_maps() {
        // HashMap<String,?> con "signinfo" y "format": el orden de Java es
        // {"signinfo":...,"format":...} (cubetas 3 y 10 respectivamente).
        let keys = ["format", "signinfo"];
        let order: Vec<&str> = java_hash_order(&keys).into_iter().map(|i| keys[i]).collect();
        assert_eq!(order, ["signinfo", "format"]);
        // Valores obtenidos con una JVM real (ConcurrentHashMap y HashMap
        // redimensionado a 32 cubetas).
        let keys = ["PRE", "NEED_PRE", "NEED_DATA", "TIME", "PID", "BASE", "ENCODING", "PK1", "CACHE_ID", "HMAC", "PK1_DECODED"];
        let order: Vec<&str> = java_hash_order(&keys).into_iter().map(|i| keys[i]).collect();
        assert_eq!(order, ["PRE", "ENCODING", "HMAC", "PK1", "CACHE_ID", "NEED_PRE", "TIME", "PID", "PK1_DECODED", "NEED_DATA", "BASE"]);
        let keys = [
            "id", "result", "signature", "description", "datareference", "format", "suboperation", "extraparams", "algorithm",
            "singlesigns", "stoponerror", "signs", "td", "results", "signid", "params",
        ];
        let order: Vec<&str> = java_hash_order(&keys).into_iter().map(|i| keys[i]).collect();
        assert_eq!(
            order,
            [
                "extraparams", "signature", "stoponerror", "format", "description", "suboperation", "params", "signid", "datareference",
                "result", "td", "singlesigns", "signs", "id", "results", "algorithm"
            ]
        );
    }
}
