#!/usr/bin/env python3
"""Comprueba el diagnóstico (`autofirma doctor --json`) tras `install --system`.

Exige certificados del servidor local y CA de confianza en el sistema; el
manejador del protocolo debe estar registrado (en macOS solo si se ejecuta
desde un paquete .app, por eso allí basta con que no sea un error).
Uso: check_doctor.py doctor.json
"""
import json, platform, sys

raw = open(sys.argv[1], "rb").read()
# PowerShell puede escribir UTF-16 o con BOM.
for enc in ("utf-8-sig", "utf-16"):
    try:
        report = json.loads(raw.decode(enc))
        break
    except (UnicodeDecodeError, json.JSONDecodeError):
        continue
else:
    sys.exit(f"diagnóstico ilegible: {raw[:200]!r}")

checks = {}
for c in report["checks"]:
    checks.setdefault(c["id"], []).append(c)
for c in report["checks"]:
    print(f"[{c['status']:7}] {c['id']}: {c['title']} — {c.get('detail', '')}")

def require(cid, allowed):
    got = [c["status"] for c in checks.get(cid, [])]
    if not got or any(s not in allowed for s in got):
        sys.exit(f"{cid}: {got} (se esperaba {allowed})")

require("certs.files", {"Ok"})
require("trust.os", {"Ok"})
require("protocol", {"Ok", "Warning", "Info"} if platform.system() == "Darwin" else {"Ok"})
errors = [c["id"] for c in report["checks"] if c["status"] == "Error"]
if errors:
    sys.exit(f"errores en el diagnóstico: {errors}")
print("diagnóstico correcto")
