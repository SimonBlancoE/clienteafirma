#!/usr/bin/env python3
"""Pruebas diferenciales Java/Rust de afirma-cms.

Ejecuta los casos de testdata/cades/cases.txt con la AutoFirma Java
(tools/oracle/CmsOracle.java) y con el ejemplo cms_cli de afirma-cms, y compara
el resumen estructural (inspect::structure_summary, con fechas y valores de
firma enmascarados) de ambas salidas. Con --update guarda las salidas Java como
ficheros golden (testdata/cades/<caso>.java.<ext>) para `cargo test`.

Uso:
  ORACLE="java -cp $AFIRMA_JAR:dir_clases CmsOracle" RUST=target/.../cms_cli \\
    python3 tools/oracle/cms_diff.py [--update] [caso ...]
"""
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CASES = os.path.join(ROOT, "testdata", "cades", "cases.txt")
DATA = os.path.join(ROOT, "testdata", "cades", "data")
GOLDEN = os.path.join(ROOT, "testdata", "cades")
PKI = os.path.join(ROOT, "testdata", "pki")


def load_cases():
    cases = []
    for line in open(CASES, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|", 9)]
        name, op, fmt, alg, store, sign_in, data, target, targets, params = parts
        cases.append(dict(name=name, op=op, fmt=fmt, alg=alg, store=store, sign_in=sign_in,
                          data=data, target=target, targets=targets,
                          params=shlex.split(params) if params else []))
    return cases


def ext(fmt):
    return "asics" if fmt == "CAdES-ASiC-S" else "csig"


def golden_path(name, fmt):
    return os.path.join(GOLDEN, f"{name}.java.{ext(fmt)}")


def args_for(case, sign_path, out):
    p12 = os.path.join(PKI, case["store"] + ".p12")
    data = os.path.join(DATA, case["data"]) if case["data"] != "-" else "-"
    if case["op"] == "sign":
        return ["sign", case["fmt"], case["alg"], p12, data, out] + case["params"]
    if case["op"] == "cosign":
        return ["cosign", case["fmt"], case["alg"], p12, sign_path, data, out] + case["params"]
    return ["countersign", case["fmt"], case["alg"], p12, sign_path, case["target"], case["targets"], out] + case["params"]


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in (r.stdout + r.stderr).splitlines()
             if l.startswith(("OK", "ERROR", "CODE", "NULL"))]
    return lines


def inner(path, fmt):
    if fmt != "CAdES-ASiC-S":
        return path
    with zipfile.ZipFile(path) as z:
        sig = z.read("META-INF/signature.p7s")
    fd, p = tempfile.mkstemp(suffix=".p7s")
    os.write(fd, sig)
    os.close(fd)
    return p


def summary(rust, path, fmt):
    r = subprocess.run([rust, "summary", inner(path, fmt)], capture_output=True, text=True)
    return r.stdout


DIGEST_ALG_IDS = {
    "SHA1": "300906052b0e03021a0500",
    "SHA256": "300d06096086480165030402010500",
    "SHA384": "300d06096086480165030402020500",
    "SHA512": "300d06096086480165030402030500",
}


def normalize(js, rs, case):
    """Desviación documentada: las cofirmas Rust añaden a digestAlgorithms la
    huella del nuevo firmante (Java no lo hace). Si es la única diferencia se acepta."""
    if case["op"] != "cosign":
        return rs
    line = lambda s: next((l for l in s.splitlines() if l.startswith(" digestAlgorithms:")), "")
    jl, rl = line(js), line(rs)
    if jl == rl:
        return rs
    ji = jl.split()[1:]
    ri = rl.split()[1:]
    extra = [x for x in ri if x not in ji]
    new = DIGEST_ALG_IDS.get(case["alg"].upper().replace("-", "").split("WITH")[0])
    if all(x in ri for x in ji) and extra == [new]:
        return rs.replace(rl, jl)
    return rs


def main():
    oracle = shlex.split(os.environ["ORACLE"])
    rust = os.environ["RUST"]
    update = "--update" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    tmp = tempfile.mkdtemp(prefix="cmsdiff")
    failures = 0
    for case in load_cases():
        if only and case["name"] not in only:
            continue
        sign_path = "-"
        if case["sign_in"].startswith("@"):
            base = case["sign_in"][1:]
            fmt = next(c["fmt"] for c in load_cases() if c["name"] == base)
            sign_path = golden_path(base, fmt)
        jout = os.path.join(tmp, case["name"] + ".java")
        rout = os.path.join(tmp, case["name"] + ".rust")
        jres = run(oracle + args_for(case, sign_path, jout))
        rres = run([rust] + args_for(case, sign_path, rout))
        jerr = [l for l in jres if l.startswith("CODE")]
        rerr = [l for l in rres if l.startswith("CODE")]
        jok = any(l.startswith("OK") for l in jres)
        rok = any(l.startswith("OK") for l in rres)
        if not jok or not rok:
            same = (jok == rok) and (jerr == rerr)
            status = "PASS" if same else "FAIL"
            print(f"{status} {case['name']}: java={jres} rust={rres}")
            failures += 0 if same else 1
            continue
        if update:
            shutil.copyfile(jout, golden_path(case["name"], case["fmt"]))
            jout = golden_path(case["name"], case["fmt"])
        js = summary(rust, jout, case["fmt"])
        rs = normalize(js, summary(rust, rout, case["fmt"]), case)
        if js == rs:
            print(f"PASS {case['name']}")
        else:
            failures += 1
            print(f"FAIL {case['name']}")
            import difflib
            for l in difflib.unified_diff(js.splitlines(), rs.splitlines(), "java", "rust", lineterm="", n=1):
                print("    " + l[:220])
    print(f"{failures} fallos")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
