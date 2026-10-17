"""Convierte los strings.xml de firma-android al formato de catálogo `clave = texto`."""
import re, sys, json
import xml.etree.ElementTree as ET

RES = sys.argv[1]
DIRS = {"es": "values", "en": "values-en", "ca": "values-ca", "gl": "values-gl", "eu": "values-eu",
        "ca-valencia": "values-b+ca+ES+valencia"}

def inner_xml(el):
    s = el.text or ""
    for ch in el:
        s += f"<{ch.tag}>" + inner_xml(ch) + f"</{ch.tag}>" + (ch.tail or "")
    return s

def android_unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "u":
                out.append(chr(int(s[i + 2:i + 6], 16))); i += 6; continue
            out.append({"n": "\n", "t": "\t"}.get(n, n)); i += 2; continue
        out.append(c); i += 1
    return "".join(out)

def convert(raw):
    s = android_unescape(raw)
    if s.startswith('"') and s.endswith('"') and len(s) > 1:
        s = s[1:-1]
    # Marcas HTML -> marcado ligero.
    s = re.sub(r"<p>\s*", "", s)
    s = re.sub(r"\s*</p>\s*", "\n\n", s)
    s = re.sub(r"</?u>", "", s)
    s = re.sub(r"<b>(.*?)</b>", r"**\1**", s)
    # Marcadores de formato de Android -> {n}.
    s = re.sub(r"%(\d)\$[sd]", lambda m: "{%d}" % (int(m.group(1)) - 1), s)
    s = s.replace("%s", "{0}").replace("%d", "{0}")
    s = re.sub(r"[ \t]+", " ", s)
    s = "\n".join(line.strip() for line in s.split("\n"))
    return s.strip()

cats = {}
for lang, d in DIRS.items():
    root = ET.parse(f"{RES}/{d}/strings.xml").getroot()
    cat = {}
    for el in root.findall("string"):
        cat[el.get("name")] = convert(inner_xml(el))
    cats[lang] = cat
json.dump(cats, open(sys.argv[2], "w"), ensure_ascii=False, indent=1)
print({k: len(v) for k, v in cats.items()})
