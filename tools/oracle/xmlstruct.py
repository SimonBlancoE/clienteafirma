"""Estructura normalizada de una firma XML para comparar salidas de
AutoFirma-rs con las del oráculo Java: nombres de elementos, atributos y
textos, con UUID, huellas, valores de firma, certificados y fechas
sustituidos por marcadores.

Uso: python -I xmlstruct.py fichero.xml   (o dos ficheros para ver el diff)
"""
import re
import sys
import difflib
from lxml import etree

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
B64_ELEMS = {"DigestValue", "SignatureValue", "X509Certificate", "Modulus", "EncapsulatedTimeStamp", "PublicKey"}
TIME_ELEMS = {"SigningTime", "Value", "date"}
# Valores del entorno gráfico de OOXML (Java los toma de AWT).
ENV_ELEMS = {"Monitors", "HorizontalResolutionElement", "VerticalResolutionElement", "ColorDepth", "WindowsVersion"}


def norm(s):
    return UUID.sub("U", s or "")


def walk(el, depth, out):
    if not isinstance(el.tag, str):
        if isinstance(el, etree._Comment):
            out.append("  " * depth + "<!--" + el.text + "-->")
        return
    q = etree.QName(el)
    prefix = el.prefix + ":" if el.prefix else ""
    attrs = " ".join(f'{k}="{norm(v)}"' for k, v in sorted(el.attrib.items()))
    nsdecl = " ".join(sorted(f"xmlns{':' + p if p else ''}" for p in (set(el.nsmap) - set(el.getparent().nsmap if el.getparent() is not None else {}))))
    text = (el.text or "").strip()
    if q.localname in B64_ELEMS and text:
        text = "B64"
    elif q.localname in TIME_ELEMS and text:
        text = "T"
    elif q.localname in ENV_ELEMS:
        text = "ENV"
    else:
        text = norm(text)
        if len(text) > 120:
            text = "LONG(%d)" % len(text)
    out.append("  " * depth + f"{prefix}{q.localname} {{{q.namespace or ''}}} [{nsdecl}] {attrs} |{text}|")
    for c in el:
        walk(c, depth + 1, out)


def structure(path):
    tree = etree.parse(path, etree.XMLParser(remove_blank_text=False, resolve_entities=False))
    out = []
    walk(tree.getroot(), 0, out)
    return out


if __name__ == "__main__":
    a = structure(sys.argv[1])
    if len(sys.argv) > 2:
        b = structure(sys.argv[2])
        d = list(difflib.unified_diff(a, b, sys.argv[1], sys.argv[2], lineterm="", n=1))
        print("\n".join(d) if d else "IGUALES")
        sys.exit(1 if d else 0)
    print("\n".join(a))
