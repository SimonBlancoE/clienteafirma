#!/usr/bin/env python3
"""Interoperabilidad Java <-> Rust de afirma-cms.

1. Para cada caso de testdata/cades/cases.txt genera la firma con Rust y hace
   que la AutoFirma Java la lea: árbol de firmantes (getSignersStructure con
   CN y con AOSimpleSignInfo), getData, isSign y ValidateBinarySignature; los
   resultados se comparan con los de Rust sobre el mismo fichero.
2. Multifirmas cruzadas: Java cofirma y contrafirma firmas Rust; el resultado
   se valida con Java, con Rust y con OpenSSL.
3. Validación de firmas manipuladas (datos distintos, firma alterada) con
   ambas implementaciones.

Uso: ORACLE="java -cp ... CmsOracle" RUST=.../cms_cli python3 tools/oracle/cms_cross.py
"""
import os
import shlex
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import cms_diff  # noqa: E402

ROOT = cms_diff.ROOT
PKI = cms_diff.PKI
DATA = cms_diff.DATA


def out(cmd):
    """Salida del comando sin las trazas de java.util.logging."""
    import re
    r = subprocess.run(cmd, capture_output=True, text=True)
    log = re.compile(r"^(INFO|ADVERTENCIA|WARNING|GRAVE|SEVERE|CONFIG|FINE)[:A-Z]|^[A-Za-z]{3}\.? \d+, \d{4} ")
    return [l for l in (r.stdout + r.stderr).splitlines() if not log.match(l)]


def block(lines, start):
    """Líneas del bloque que empieza por `start` (hasta el siguiente bloque)."""
    res, inside = [], False
    for l in lines:
        if l.startswith(("NAMES", "INFOS")):
            inside = l.startswith(start)
            continue
        if inside:
            res.append(l)
    return res


def validity(lines):
    v = []
    for l in lines:
        if l.startswith("VALIDITY"):
            p = l.split()
            kind = p[1].upper()
            err = p[2] if len(p) > 2 else "null"
            err = {"None": "null"}.get(err, err)
            if err.startswith("Some("):
                err = err[5:-1]
            v.append(f"{kind} {camel_to_java(err)}")
    return v


def camel_to_java(e):
    if e == "null" or e.isupper():
        return e
    import re
    s = re.sub(r"(?<!^)(?=[A-Z])", "_", e).upper()
    return {"UNKNOWN_ERROR": "UNKOWN_ERROR"}.get(s, s)


def main():
    oracle = shlex.split(os.environ["ORACLE"])
    rust = os.environ["RUST"]
    tmp = tempfile.mkdtemp(prefix="cmscross")
    cases = cms_diff.load_cases()
    fails = 0
    produced = {}
    for case in cases:
        sign_path = "-"
        if case["sign_in"].startswith("@"):
            base = case["sign_in"][1:]
            fmt = next(c["fmt"] for c in cases if c["name"] == base)
            sign_path = cms_diff.golden_path(base, fmt)
        rout = os.path.join(tmp, case["name"] + "." + cms_diff.ext(case["fmt"]))
        res = subprocess.run([rust] + cms_diff.args_for(case, sign_path, rout), capture_output=True, text=True).stdout
        if not res.startswith("OK"):
            continue
        produced[case["name"]] = (case, rout)
        fmt = case["fmt"]
        problems = []
        jt = out(oracle + ["tree", fmt, rout])
        rt = out([rust, "tree", fmt, rout])
        if block(jt, "NAMES") != block(rt, "NAMES"):
            problems.append(f"arbol (CN): java={block(jt, 'NAMES')} rust={block(rt, 'NAMES')}")
        if block(jt, "INFOS") != block(rt, "INFOS"):
            problems.append(f"arbol (info): java={block(jt, 'INFOS')} rust={block(rt, 'INFOS')}")
        jd = out(oracle + ["getdata", fmt, rout, rout + ".jdata"])
        rd = out([rust, "getdata", fmt, rout, rout + ".rdata"])
        if [l.split()[0] for l in jd if l[:2] in ("OK", "NU", "ER")] != [l.split()[0] for l in rd if l[:2] in ("OK", "NU", "ER")]:
            problems.append(f"getData: java={jd} rust={rd}")
        elif os.path.exists(rout + ".jdata") and open(rout + ".jdata", "rb").read() != open(rout + ".rdata", "rb").read():
            problems.append("getData: contenido distinto")
        ji = [l for l in out(oracle + ["issign", rout]) if l.startswith(("CAdES", "CMS"))]
        ri = [l for l in out([rust, "issign", rout]) if l.startswith(("CAdES", "CMS"))]
        if fmt == "CAdES-ASiC-S":
            # Desviación: Java nunca detecta CAdES-ASiC-S (isSign siempre falso).
            ji = [l.replace("CAdES-ASiC-S false", "CAdES-ASiC-S true") for l in ji]
        if ji != ri:
            problems.append(f"isSign: java={ji} rust={ri}")
        if fmt != "CAdES-ASiC-S":
            data_args = []
            if case["op"] == "sign" and case["data"] != "-" and "precalculated" not in " ".join(case["params"]):
                data_args = [os.path.join(DATA, case["data"])]
            jv = validity(out(oracle + ["validate", rout] + data_args))
            rv = validity(out([rust, "validate", rout] + data_args))
            if jv != rv:
                problems.append(f"validacion: java={jv} rust={rv}")
        if problems:
            fails += 1
            print(f"FAIL {case['name']}")
            for p in problems:
                print("    " + p[:400])
        else:
            print(f"PASS {case['name']} (lectura Java)")

    # 2. Multifirmas cruzadas: Java sobre firmas Rust.
    cross = [
        ("cades_impl_sha256", ["cosign", "CAdES", "SHA512withRSA", "firmante-rsa", "-"], None),
        ("cades_expl_sha256", ["cosign", "CAdES", "SHA256withRSA", "firmante-ec", "hola.txt"], "hola.txt"),
        ("cades_cosign_impl", ["countersign", "CAdES", "SHA256withRSA", "firmante-rsa", "tree", "-"], None),
        ("cades_counter_tree", ["countersign", "CAdES", "SHA384withRSA", "firmante-rsa", "leafs", "-"], None),
        ("cades_epes_age", ["cosign", "CAdES", "SHA256withRSA", "firmante-rsa", "-"], None),
        ("cms_impl", ["cosign", "CMS/PKCS#7", "SHA512withRSA", "firmante-rsa", "-"], None),
        ("cms_counter_tree", ["countersign", "CMS/PKCS#7", "SHA256withRSA", "firmante-rsa", "nodes", "2"], None),
        ("cms_expl", ["countersign", "CMS/PKCS#7", "SHA256withRSA", "firmante-rsa", "tree", "-"], "hola.txt"),
    ]
    for base, op, data in cross:
        if base not in produced:
            continue
        case, rpath = produced[base]
        jout = rpath + ".javamulti"
        cmd = list(op)
        p12 = os.path.join(PKI, cmd[3] + ".p12")
        if cmd[0] == "cosign":
            d = os.path.join(DATA, cmd[4]) if cmd[4] != "-" else "-"
            args = ["cosign", cmd[1], cmd[2], p12, rpath, d, jout]
        else:
            args = ["countersign", cmd[1], cmd[2], p12, rpath, cmd[4], cmd[5], jout]
        jr = out(oracle + args)
        if not any(l.startswith("OK") for l in jr):
            fails += 1
            print(f"FAIL Java {op[0]} sobre Rust {base}: {jr}")
            continue
        dargs = [os.path.join(DATA, data)] if data else []
        jv = validity(out(oracle + ["validate", jout] + dargs))
        rv = validity(out([rust, "validate", jout] + dargs))
        ossl = ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any", "-in", jout,
                "-CAfile", os.path.join(PKI, "ca.crt"), "-out", "/dev/null"]
        if data:
            ossl += ["-content", os.path.join(DATA, data)]
        o = subprocess.run(ossl, capture_output=True, text=True)
        # Rust también debe poder multifirmar el resultado de Java.
        r2 = subprocess.run([rust, "countersign", cmd[1], "SHA256withRSA", os.path.join(PKI, "firmante-rsa.p12"), jout,
                             "leafs", "-", jout + ".rust"], capture_output=True, text=True).stdout
        jv2 = validity(out(oracle + ["validate", jout + ".rust"] + dargs)) if r2.startswith("OK") else ["(sin firma)"]
        # Java no añade la huella del cofirmante a digestAlgorithms (G6): OpenSSL
        # no puede verificar esas cofirmas Java; es un fallo conocido de Java.
        ossl_ok = o.returncode == 0 or "no matching digest" in o.stderr
        ok = jv == rv and jv and jv[0].startswith("OK") and ossl_ok and r2.startswith("OK") and jv2[0].startswith("OK")
        print(f"{'PASS' if ok else 'FAIL'} Java {op[0]} {op[1]} sobre Rust {base}: java={jv} rust={rv} openssl={'OK' if o.returncode == 0 else o.stderr.strip()[:120]} rust-contrafirma-despues={jv2}")
        fails += 0 if ok else 1

    # 3. Firmas manipuladas.
    tampered = []
    for name in ("cades_expl_sha256", "cms_expl", "cades_ec_sha256", "cades_impl_sha256", "cms_impl"):
        if name not in produced:
            continue
        case, rpath = produced[name]
        raw = bytearray(open(rpath, "rb").read())
        bad = rpath + ".tampered"
        raw[-5] ^= 0x01  # último byte del valor de firma (último SignerInfo)
        open(bad, "wb").write(bytes(raw))
        tampered.append((name + " firma alterada", bad, []))
        tampered.append((name + " datos distintos", rpath, [os.path.join(DATA, "binario.bin")]))
    for label, path, dargs in tampered:
        jv = validity(out(oracle + ["validate", path] + dargs))
        rv = validity(out([rust, "validate", path] + dargs))
        ok = jv == rv
        fails += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'} validacion {label}: java={jv} rust={rv}")
    print(f"{fails} fallos")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
