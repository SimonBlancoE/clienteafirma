"""Genera crates/afirma-core/src/mime/magic_table.rs a partir del magic.xml de
JMimeMagic (afirma-lib-jmimemagic-0.0.10.jar), que es la biblioteca que usa
MimeHelper en AutoFirma Java. Solo importan las reglas de primer nivel: el
tipo MIME, la extensión y la descripción del resultado son los de la primera
regla de primer nivel que coincide (las subreglas solo añaden información que
AutoFirma no usa).

Uso: python3 -I tools/oracle/gen_magic_table.py magic.xml > crates/afirma-core/src/mime/magic_table.rs
"""
import sys
import xml.etree.ElementTree as ET


def parse_string_test(s):
    # JMimeMagic (MagicParser.convertOctals) solo interpreta escapes octales \\NNN;
    # cualquier otra barra invertida se conserva literalmente (p. ej. "{\\rtf").
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 3 < len(s) + 0 and all(ch in "01234567" for ch in s[i + 1:i + 4]) and len(s[i + 1:i + 4]) == 3:
            out.append(int(s[i + 1:i + 4], 8) & 0xFF)
            i += 4
            continue
        out.extend(c.encode("utf-8"))
        i += 1
    return bytes(out)


def rs_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rs_bytes(b):
    return 'b"' + "".join(
        chr(x) if 0x20 <= x < 0x7F and chr(x) not in '"\\' else "\\x%02x" % x for x in b
    ) + '"'


def num(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


root = ET.parse(sys.argv[1]).getroot()
rows = []
for m in root.find("match-list").findall("match"):
    mt = m.findtext("mimetype") or ""
    ext = m.findtext("extension") or ""
    desc = m.findtext("description") or ""
    t = m.find("test")
    typ = t.get("type")
    off = int(t.get("offset") or 0)
    mask = t.get("bitmask")
    cmp_ = t.get("comparator") or "="
    val = t.text or ""
    if typ == "string":
        test = "MagicTest::String { offset: %d, value: %s }" % (off, rs_bytes(parse_string_test(val)))
    elif typ in ("beshort", "leshort"):
        m_ = num(mask) if mask else 0xFFFF
        test = "MagicTest::Short { offset: %d, big_endian: %s, mask: 0x%04x, value: 0x%04x, cmp: b'%s' }" % (
            off, "true" if typ == "beshort" else "false", m_ & 0xFFFF, num(val) & 0xFFFF, cmp_)
    elif typ in ("belong", "lelong"):
        m_ = num(mask) if mask else 0xFFFFFFFF
        test = "MagicTest::Long { offset: %d, big_endian: %s, mask: 0x%08x, value: 0x%08x, cmp: b'%s' }" % (
            off, "true" if typ == "belong" else "false", m_, num(val), cmp_)
    elif typ == "regex":
        test = "MagicTest::Regex { offset: %d, pattern: %s }" % (off, rs_str(val))
    elif typ == "detector":
        test = "MagicTest::TextDetector"
    elif typ == "byte":
        m_ = num(mask) if mask else 0xFF
        test = "MagicTest::Byte { offset: %d, mask: 0x%02x, value: 0x%02x, cmp: b'%s' }" % (off, m_ & 0xFF, num(val) & 0xFF, cmp_)
    else:
        raise SystemExit("tipo no soportado: " + typ)
    rows.append("    MagicRule { mime: %s, extension: %s, description: %s, test: %s }," % (rs_str(mt), rs_str(ext), rs_str(desc), test))

print("// Generado por tools/oracle/gen_magic_table.py a partir del magic.xml de")
print("// afirma-lib-jmimemagic 0.0.10. No editar a mano.")
print("")
print("use super::magic::{MagicRule, MagicTest};")
print("")
print("/// Reglas de primer nivel de JMimeMagic, en el orden en que se evalúan.")
print("#[rustfmt::skip]")
print("pub(crate) static MAGIC_RULES: &[MagicRule] = &[")
print("\n".join(rows))
print("];")
