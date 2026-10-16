#!/usr/bin/env python3
"""Genera los ficheros golden de afirma-cli con la AutoFirma Java (oráculo).

Lee testdata/cli/cases.tsv, ejecuta cada caso con el autofirma.jar original
(modo sin interfaz, árbol de preferencias propio y vacío) y guarda:

  testdata/cli/golden/<caso>.txt   "status: N" + salida estándar exacta
  testdata/cli/java/<caso>.<ext>   la firma generada (marca sig=<fichero>)

Las rutas se sustituyen por @TD@ (testdata), @J@ (testdata/cli/java) y @OUT@
(directorio de salida del caso) para que las pruebas de Rust no dependan de
dónde está el repositorio. Los casos que usan firmas de Java (@J@/x) esperan
a que se haya ejecutado el caso x.

Uso:
  AFIRMA_JAR=/ruta/autofirma.jar python3 -I tools/oracle/cli_goldens.py [caso...]
  AFIRMA_JAR=... python3 -I tools/oracle/cli_goldens.py --verify DIR
      (valida con `autofirma verify` de Java cada firma de DIR, p. ej. las que
       deja `AFIRMA_CLI_DUMP=DIR cargo test -p afirma-cli`)
"""
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TD = os.path.join(ROOT, "testdata")
CLI = os.path.join(TD, "cli")
GOLD = os.path.join(CLI, "golden")
JAVA = os.path.join(CLI, "java")

PREFS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE map SYSTEM "http://java.sun.com/dtd/preferences.dtd">
<map MAP_XML_VERSION="1.0">
  <entry key="default.locale" value="{locale}"/>
</map>
"""


def macro(name):
    return ["-store", f"pkcs12:@TD@/pki/firmante-{name}.p12", "-password", "12341234", "-alias", f"firmante-{name}"]


def load_cases():
    cases = []
    with open(os.path.join(CLI, "cases.tsv"), encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            name, flags, args = parts[0], parts[1], parts[2:]
            fl = {}
            for item in flags.split(","):
                if item and item != "-":
                    k, _, v = item.partition("=")
                    fl[k] = v
            expanded = []
            for a in args:
                if a == "@RSA@":
                    expanded += macro("rsa")
                elif a == "@EC@":
                    expanded += macro("ec")
                else:
                    expanded.append(a)
            cases.append((name, fl, expanded))
    return cases


def deps(args):
    out = set()
    for a in args:
        m = re.match(r"@J@/([^.]+)\.", a)
        if m:
            out.add(m.group(1))
    return out


def java(args, locale=None, cwd=ROOT):
    jar = os.environ["AFIRMA_JAR"]
    prefs = tempfile.mkdtemp(prefix="afcli-prefs-")
    try:
        if locale:
            node = os.path.join(prefs, ".java", ".userPrefs", "es", "gob", "afirma", "standalone", "ui", "preferences")
            os.makedirs(node)
            with open(os.path.join(node, "prefs.xml"), "w") as f:
                f.write(PREFS_XML.format(locale=locale))
        cmd = ["java", "-Djava.awt.headless=true", f"-Djava.util.prefs.userRoot={prefs}",
               "-Duser.language=es", "-Duser.country=ES", "-jar", jar] + args
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
        return p.returncode, p.stdout
    finally:
        shutil.rmtree(prefs, ignore_errors=True)


def run_case(case):
    name, fl, args = case
    out = tempfile.mkdtemp(prefix="afcli-out-")
    try:
        real = [a.replace("@J@", JAVA).replace("@TD@", TD).replace("@OUT@", out) for a in args]
        status, stdout = java(real, fl.get("locale"))
        text = stdout.decode("utf-8", errors="replace")
        text = text.replace(out, "@OUT@").replace(JAVA, "@J@").replace(TD, "@TD@")
        with open(os.path.join(GOLD, name + ".txt"), "w", encoding="utf-8", newline="") as f:
            f.write(f"status: {status}\n{text}")
        if "sig" in fl:
            src = os.path.join(out, fl["sig"])
            ext = os.path.splitext(fl["sig"])[1]
            if os.path.exists(src):
                shutil.copyfile(src, os.path.join(JAVA, name + ext))
            else:
                print(f"AVISO: {name} no generó {fl['sig']}", file=sys.stderr)
        return name, status
    finally:
        shutil.rmtree(out, ignore_errors=True)


def generate(selected):
    os.makedirs(GOLD, exist_ok=True)
    os.makedirs(JAVA, exist_ok=True)
    cases = [c for c in load_cases() if not selected or c[0] in selected]
    done = set(c[0] for c in load_cases()) - set(c[0] for c in cases)
    pending = list(cases)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        while pending:
            ready = [c for c in pending if deps(c[2]) <= done]
            if not ready:
                raise SystemExit("dependencias circulares o ausentes: " + ", ".join(c[0] for c in pending))
            for name, status in ex.map(run_case, ready):
                print(f"{name}: {status}")
                done.add(name)
            pending = [c for c in pending if c not in ready]


BENIGN = ("Firma válida",
          "Validación incompleta: no se puede comprobar la validez por no tener los datos firmados",
          "Validación incompleta: no se puede comprobar la validez de la firma ODF",
          "Validación incompleta: no se puede comprobar la validez de la firma OOXML")


def verify_dir(path):
    """Valida con Java cada firma de un directorio. Si hay una firma de Java
    para el mismo caso (testdata/cli/java), el veredicto debe ser idéntico; si
    no, todas las líneas deben ser de firma válida (o validación incompleta
    por firma explícita, ODF u OOXML)."""
    bad = 0
    for f in sorted(os.listdir(path)):
        status, stdout = java(["verify", "-i", os.path.join(path, f)])
        text = stdout.decode("utf-8", errors="replace")
        ref = os.path.join(JAVA, f)
        if os.path.exists(ref):
            _, ref_out = java(["verify", "-i", ref])
            ok = status == 0 and text == ref_out.decode("utf-8", errors="replace")
            how = "igual que Java"
        else:
            ok = status == 0 and all(l in BENIGN for l in text.splitlines() if l)
            how = "sin firma de Java"
        bad += 0 if ok else 1
        print(f"{'OK ' if ok else 'MAL'} {f} ({how}): {' | '.join(l for l in text.splitlines() if l)}")
    print(f"{bad} firmas con veredicto distinto")
    return bad


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--verify":
        sys.exit(1 if verify_dir(sys.argv[2]) else 0)
    generate(set(sys.argv[1:]))
