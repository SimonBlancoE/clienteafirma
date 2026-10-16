"""Pruebas diferenciales de las firmas XML de AutoFirma-rs frente al oráculo
Java (AutoFirma original):

1. firma cada caso con Rust (`examples/xsign`) y con Java (`XmlOracle`);
2. valida ambas salidas con el validador JSR-105 (`XmlSigVerify`) y, para
   ODF/OOXML, con LibreOffice (`lo_verify.py`);
3. compara la estructura normalizada (`xmlstruct.py`; en ZIP, los XML de firma);
4. para cofirmas/contrafirmas, cada implementación opera sobre la salida de la
   otra (Rust sobre la firma Java y viceversa) y se validan;
5. guarda las salidas Java como *golden* en testdata/{xades,xmldsig,office}/java/.

Requisitos: `cargo build -p afirma-xml --examples` con
CARGO_TARGET_DIR=target/agents/afirma-xml (usa `xsign` y `mock_tsa`), y tres
envoltorios ejecutables:
  XO      `java -cp autofirma.jar:<clases> XmlOracle "$@"`
  XO_GUI  igual, con DISPLAY de un Xvfb (el firmador OOXML de Java necesita AWT)
  XV      `java -cp <clases> XmlSigVerify "$@"`

Uso (desde la raíz del repositorio):
  XO=... XO_GUI=... XV=... python -I tools/oracle/xml_differential.py [filtro]
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.getcwd()
sys.path.insert(0, os.path.join(ROOT, "tools", "oracle"))
import xmlstruct  # noqa: E402

XSIGN = os.path.join(ROOT, "target/agents/afirma-xml/debug/examples/xsign")
AFJ = os.path.join(ROOT, "tools/oracle/afj.sh")
XV = os.environ.get("XV")
INPUTS = os.path.join(ROOT, "testdata/xades/inputs")
GOLDEN = os.path.join(ROOT, "testdata/xades/java")
RSA = "testdata/pki/firmante-rsa.p12"
EC = "testdata/pki/firmante-ec.p12"

# (nombre, formato CLI, operación, entrada, parámetros, almacén)
CASES = [
    ("xades-enveloping-bin", "xades", "sign", "hello.txt", {}, RSA),
    ("xades-enveloping-xml", "xades", "sign", "doc.xml", {}, RSA),
    ("xades-enveloping-b64", "xades", "sign", "b64.txt", {"encoding": "base64"}, RSA),
    ("xades-enveloping-avoidb64", "xades", "sign", "hello.txt", {"avoidBase64Transforms": "true"}, RSA),
    ("xades-enveloped", "xades", "sign", "doc.xml", {"format": "XAdES Enveloped"}, RSA),
    ("xades-enveloped-ids", "xades", "sign", "xml_with_ids.xml", {"format": "XAdES Enveloped"}, RSA),
    ("xades-enveloped-node", "xades", "sign", "xml_with_ids.xml", {"format": "XAdES Enveloped", "nodeToSign": "1"}, RSA),
    ("xades-enveloped-xpath", "xades", "sign", "xpathnodenveloped.xml",
     {"format": "XAdES Enveloped", "insertEnvelopedSignatureOnNodeByXPath": "/bookstore/book[1]/title"}, RSA),
    ("xades-enveloped-xpathns", "xades", "sign", "xpathnodenvelopedwithns.xml",
     {"format": "XAdES Enveloped", "insertEnvelopedSignatureOnNodeByXPath":
      "//*[namespace-uri()='http://www.facturae.es/Facturae/2007/v3.0/Facturae'][local-name()='Facturae']"}, RSA),
    ("xades-enveloped-noxpath", "xades", "sign", "doc.xml", {"format": "XAdES Enveloped", "avoidXpathExtraTransformsOnEnveloped": "true", "canonicalizationAlgorithm": "none"}, RSA),
    ("xades-enveloped-latin1", "xades", "sign", "latin1.xml", {"format": "XAdES Enveloped"}, RSA),
    ("xades-detached-xml", "xades", "sign", "doc.xml", {"format": "XAdES Detached"}, RSA),
    ("xades-detached-bin", "xades", "sign", "hello.txt", {"format": "XAdES Detached"}, RSA),
    ("xades-detached-node", "xades", "sign", "internally_detached_node_sibling.xml", {"format": "XAdES Detached", "nodeToSign": "IDN"}, RSA),
    ("xades-detached-noderoot", "xades", "sign", "internally_detached_node_sibling.xml", {"format": "XAdES Detached", "nodeToSign": "ROOT"}, RSA),
    ("xades-extdet", "xades", "sign", "hello.txt", {"format": "XAdES Externally Detached", "uri": "https://example.org/doc.bin"}, RSA),
    ("xades-manifest", "xades", "sign", "hello.txt", {"useManifest": "true", "uri1": "urn:id:1", "md1": "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", "mimeType1": "text/plain", "uri2": "https://example.org/2", "md2": "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", "precalculatedHashAlgorithm": "SHA-256"}, RSA),
    ("xades-baseline-policy", "xades", "sign", "hello.txt", {
        "profile": "baseline", "policyIdentifier": "urn:oid:2.16.724.1.3.1.1.2.1.9",
        "policyIdentifierHash": "G7roucf600+f03r/o0bAOQ6WAs0=", "policyIdentifierHashAlgorithm": "http://www.w3.org/2000/09/xmldsig#sha1",
        "policyQualifier": "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
        "signatureProductionCity": "Madrid", "signatureProductionStreetAddress": "Calle 1", "signatureProductionProvince": "Madrid",
        "signatureProductionPostalCode": "28001", "signatureProductionCountry": "ES", "signerClaimedRoles": "Firmante|Revisor",
        "commitmentTypeIndications": "1", "commitmentTypeIndication0Identifier": "1", "commitmentTypeIndication0Description": "desc",
        "commitmentTypeIndication0DocumentationReferences": "http://a.es/x|http://b.es/y",
        "commitmentTypeIndication0CommitmentTypeQualifiers": "Q1|Q2"}, RSA),
    ("xades-epes-full", "xades", "sign", "hello.txt", {
        "policyIdentifier": "urn:oid:2.16.724.1.3.1.1.2.1.9", "policyIdentifierHash": "G7roucf600+f03r/o0bAOQ6WAs0=",
        "policyIdentifierHashAlgorithm": "http://www.w3.org/2000/09/xmldsig#sha1", "policyDescription": "Politica AGE",
        "policyQualifier": "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf",
        "signatureProductionCity": "Madrid", "signatureProductionProvince": "Madrid", "signatureProductionPostalCode": "28001",
        "signatureProductionCountry": "ES", "signerClaimedRoles": "Firmante|Revisor", "commitmentTypeIndications": "1",
        "commitmentTypeIndication0Identifier": "1", "commitmentTypeIndication1Identifier": "5", "addKeyInfoKeyName": "true",
        "addKeyInfoX509IssuerSerial": "true", "includeOnlySignningCertificate": "true", "keepKeyInfoUnsigned": "true",
        "contentTypeOid": "1.2.3.4", "mimeType": "application/x-foo"}, RSA),
    ("xades-ec", "xades", "sign", "hello.txt", {}, EC),
    ("xades-exc-sha1", "xades", "sign", "doc.xml", {"canonicalizationAlgorithm": "http://www.w3.org/2001/10/xml-exc-c14n#", "referencesDigestMethod": "http://www.w3.org/2000/09/xmldsig#sha1", "xadesNamespace": "http://uri.etsi.org/01903/v1.2.2#"}, RSA),
    ("xades-xpath2", "xades", "sign", "doc.xml", {"xmlTransforms": "1", "xmlTransform0Type": "http://www.w3.org/2002/06/xmldsig-filter2", "xmlTransform0Subtype": "subtract", "xmlTransform0Body": "/doc"}, RSA),
    ("xades-dtd", "xades", "sign", "sample-internal-dtd.xml", {}, RSA),
    ("xades-asic-root", "xades", "sign", "hello.txt", {"format": "XAdES Detached", "RootXmlNodeName": "asic:XAdESSignatures", "RootXmlNodeNamespace": "http://uri.etsi.org/02918/v1.2.1#", "RootXmlNodeNamespacePrefix": "xmlns:asic"}, RSA),
    # Multifirma: cada implementación opera sobre la salida de la otra ("@caso").
    ("xades-cosign-enveloping-bin", "xades", "cosign", "@xades-enveloping-bin", {}, EC),
    ("xades-cosign-enveloping-xml", "xades", "cosign", "@xades-enveloping-xml", {}, RSA),
    ("xades-cosign-enveloped", "xades", "cosign", "@xades-enveloped", {}, RSA),
    ("xades-cosign-enveloped-ids", "xades", "cosign", "@xades-enveloped-ids", {}, RSA),
    ("xades-cosign-detached-xml", "xades", "cosign", "@xades-detached-xml", {}, RSA),
    ("xades-cosign-detached-bin", "xades", "cosign", "@xades-detached-bin", {"includeOnlySignningCertificate": "true"}, RSA),
    ("xades-cosign-manifest", "xades", "cosign", "@xades-manifest", {}, RSA),
    ("xades-cosign-baseline", "xades", "cosign", "@xades-baseline-policy", {}, RSA),
    ("xades-cosign-noxpath", "xades", "cosign", "@xades-enveloped-noxpath", {"allowXadesEnvelopedWithoutXPath": "true"}, RSA),
    ("xades-countersign-tree", "xades", "countersign-tree", "@xades-enveloping-bin", {}, RSA),
    ("xades-countersign-tree-enveloped", "xades", "countersign-tree", "@xades-cosign-enveloped", {}, RSA),
    ("xades-countersign-leafs", "xades", "countersign-leafs", "@xades-countersign-tree", {}, EC),
    ("xades-countersign-detached", "xades", "countersign-tree", "@xades-detached-xml", {"includeOnlySignningCertificate": "true"}, RSA),
    ("xades-countersign-baseline", "xades", "countersign-tree", "@xades-baseline-policy", {}, RSA),
]
CASES += [
    ("facturae", "facturae", "sign", "facturae_32v1.xml", {}, RSA),
    ("facturae-30", "facturae", "sign", "sample-facturae.xml", {"signerClaimedRoles": "receptor", "signatureProductionCity": "Madrid"}, RSA),
    ("asic", "asic", "sign", "hello.txt", {}, RSA),
    ("asic-cosign", "asic", "cosign", "@asic", {}, EC),
    ("asic-countersign", "asic", "countersign-tree", "@asic", {}, RSA),
    ("xmldsig-enveloping-xml", "xmldsig", "sign", "doc.xml", {}, EC),
    ("xmldsig-enveloping-bin", "xmldsig", "sign", "hello.txt", {}, RSA),
    ("xmldsig-enveloping-b64", "xmldsig", "sign", "b64.txt", {}, RSA),
    ("xmldsig-enveloping-explicit", "xmldsig", "sign", "hello.txt", {"mode": "explicit"}, RSA),
    ("xmldsig-detached-xml", "xmldsig", "sign", "doc.xml", {"format": "XMLDSig Detached"}, RSA),
    ("xmldsig-detached-bin", "xmldsig", "sign", "hello.txt", {"format": "XMLDSig Detached"}, RSA),
    ("xmldsig-enveloped", "xmldsig", "sign", "doc.xml", {"format": "XMLDSig Enveloped"}, RSA),
    ("xmldsig-enveloped-dsig", "xmldsig", "sign", "doc.xml", {"format": "XMLDSig Enveloped", "xmlSignaturePrefix": "dsig", "canonicalizationAlgorithm": "http://www.w3.org/2001/10/xml-exc-c14n#", "referencesDigestMethod": "http://www.w3.org/2001/04/xmlenc#sha256"}, RSA),
    ("xmldsig-enveloped-latin1", "xmldsig", "sign", "latin1.xml", {"format": "XMLDSig Enveloped"}, RSA),
    ("xmldsig-extdet-hash", "xmldsig", "sign", "hello.txt", {"format": "XMLDSig Externally Detached", "mode": "explicit", "precalculatedHashAlgorithm": "SHA-256"}, RSA),
    ("xmldsig-xpath2", "xmldsig", "sign", "doc.xml", {"xmlTransforms": "1", "xmlTransform0Type": "http://www.w3.org/2002/06/xmldsig-filter2", "xmlTransform0Subtype": "subtract", "xmlTransform0Body": "/doc/a"}, RSA),
    ("xmldsig-cosign-enveloping", "xmldsig", "cosign", "@xmldsig-enveloping-xml", {}, RSA),
    ("xmldsig-cosign-detached", "xmldsig", "cosign", "@xmldsig-detached-xml", {}, RSA),
    ("xmldsig-cosign-enveloped", "xmldsig", "cosign", "@xmldsig-enveloped", {}, RSA),
    ("xmldsig-countersign-tree", "xmldsig", "countersign-tree", "@xmldsig-cosign-enveloping", {}, RSA),
    ("xmldsig-countersign-leafs", "xmldsig", "countersign-leafs", "@xmldsig-countersign-tree", {}, RSA),
]
# XAdES-T con la TSA de pruebas (ejemplo `mock_tsa` de afirma-xml).
CASES += [("xades-t", "xades", "sign", "hello.txt", {"tsaURL": "@TSA"}, RSA)]
OFFICE = os.path.join(ROOT, "testdata/office/inputs")
CASES += [
    ("odf-odt", "odf", "sign", "@@odt", {}, RSA),
    ("odf-ods-sha256", "odf", "sign", "@@ods", {"referencesDigestMethod": "http://www.w3.org/2001/04/xmlenc#sha256"}, RSA),
    ("odf-odp", "odf", "sign", "@@odp", {}, RSA),
    ("odf-cosign", "odf", "cosign", "@odf-odt", {}, RSA),
    ("ooxml-docx", "ooxml", "sign", "@@docx", {}, RSA),
    ("ooxml-docx-params", "ooxml", "sign", "@@docx", {"signatureProductionCity": "Madrid", "signatureProductionCountry": "ES", "signerClaimedRoles": "Rol|Uno", "signatureComments": "Prueba", "signatureAddress1": "Dir 1", "signatureAddress2": "Dir 2", "commitmentTypeIndications": "1", "commitmentTypeIndication0Identifier": "5", "commitmentTypeIndication0Description": "Aprobado"}, RSA),
    ("ooxml-xlsx", "ooxml", "sign", "@@xlsx", {}, RSA),
    ("ooxml-cosign", "ooxml", "cosign", "@ooxml-docx", {}, RSA),
]
# Casos cuya validación genérica no es posible (referencias externas o
# primera firma invalidada deliberadamente).
NO_VALIDATE = {"xades-extdet", "xades-cosign-noxpath", "xmldsig-extdet-hash", "asic", "asic-cosign", "asic-countersign"}


def run_rust(fmt, op, inp, out, params, store):
    algo = "SHA256withECDSA" if store == EC else "SHA256withRSA"
    # ODF: modo de paridad con Java (rsa-sha1) para comparar estructuras; el
    # modo por defecto (algoritmo pedido) se valida aparte con LibreOffice.
    fmt = "odf-java" if fmt == "odf" else fmt
    args = [XSIGN, op, fmt, store, inp, out, "algorithm=" + algo] + [f"{k}={v}" for k, v in params.items()]
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()


XO = os.environ.get("XO")


XO_GUI = os.environ.get("XO_GUI", XO)
LO = os.path.join(ROOT, "tools/oracle/lo_verify.py")


def lo_verify(path):
    env = dict(os.environ, PYTHONPATH="/usr/lib64/libreoffice/program")
    r = subprocess.run(["python3", LO, path], capture_output=True, text=True, env=env, timeout=300)
    return r.returncode == 0, r.stdout.strip()


def run_java(fmt, op, inp, out, params, store):
    """Firma con el firmador Java (XmlOracle) con el mismo almacén."""
    oracle = XO_GUI if fmt == "ooxml" else XO
    args = [oracle, fmt, op, store, inp, out] + [f"{k}={v}" for k, v in params.items()]
    r = subprocess.run(args, capture_output=True, text=True)
    ok = r.returncode == 0 and os.path.exists(out)
    return ok, (r.stdout + r.stderr).strip()[-400:]


ZIP_FORMATS = {"asic", "odf", "ooxml"}


def signature_xmls(path, fmt):
    """Rutas de los XML de firma de una salida (el propio fichero o los
    extraídos del contenedor)."""
    if fmt not in ZIP_FORMATS:
        return [path]
    import zipfile
    out = []
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n == "META-INF/signatures.xml" or n == "META-INF/documentsignatures.xml" or (n.startswith("_xmlsignatures/sig") and n.endswith(".xml")):
                dst = path + "." + n.replace("/", "_")
                with open(dst, "wb") as f:
                    f.write(z.read(n))
                out.append(dst)
    return sorted(out)


def verify(path):
    r = subprocess.run([XV, path], capture_output=True, text=True)
    lines = [ln for ln in r.stdout.splitlines() if " sig#" in ln]
    ok = bool(lines) and all(" valid=true" in ln for ln in lines)
    return ok, r.stdout.strip()


def main():
    flt = sys.argv[1] if len(sys.argv) > 1 else ""
    tmp = tempfile.mkdtemp(prefix="xmldiff-")
    os.makedirs(GOLDEN, exist_ok=True)
    failures = 0
    tsa = None
    for name, fmt, op, inp, params, store in CASES:
        if flt not in name:
            continue
        if "@TSA" in params.values():
            if tsa is None:
                exe = os.path.join(os.path.dirname(XSIGN), "mock_tsa")
                tsa = subprocess.Popen([exe, "1000"], stdout=subprocess.PIPE, text=True)
                tsa_url = tsa.stdout.readline().strip()
            params = {k: (tsa_url if v == "@TSA" else v) for k, v in params.items()}
        if inp.startswith("@@"):
            rsrc = jsrc = os.path.join(OFFICE, "in." + inp[2:])
        elif inp.startswith("@"):
            base = inp[1:]
            rsrc = os.path.join(tmp, base + ".java.xml")
            jsrc = os.path.join(tmp, base + ".rust.xml")
        else:
            rsrc = jsrc = os.path.join(INPUTS, inp)
        rout = os.path.join(tmp, name + ".rust.xml")
        jout = os.path.join(tmp, name + ".java.xml")
        rok, rerr = run_rust(fmt, op, rsrc, rout, params, store)
        jok, jerr = run_java(fmt, op, jsrc, jout, params, store)
        line = f"{name}: rust={'ok' if rok else 'FAIL ' + rerr} java={'ok' if jok else 'FAIL ' + jerr}"
        if rok and jok:
            rx = signature_xmls(rout, fmt)
            jx = signature_xmls(jout, fmt)
            rv, rvo = all(verify(x)[0] for x in rx) and bool(rx), "\n".join(verify(x)[1] for x in rx)
            jv, jvo = all(verify(x)[0] for x in jx) and bool(jx), "\n".join(verify(x)[1] for x in jx)
            if not jv:
                rvo += "\n[java] " + jvo
            sj = [ln for x in jx for ln in xmlstruct.structure(x)]
            sr = [ln for x in rx for ln in xmlstruct.structure(x)]
            diff = "\n".join(__import__("difflib").unified_diff(sj, sr, "java", "rust", lineterm="", n=1))
            line += f" valid(rust)={rv} valid(java)={jv} estructura={'IGUAL' if not diff else 'DIFERENTE'}"
            if rv is False:
                line += "\n" + rvo
            if diff:
                line += "\n" + diff
            if fmt in ("odf", "ooxml"):
                rv, rlo = lo_verify(rout)
                jv, jlo = lo_verify(jout)
                line += f" LibreOffice(rust)={rv} LibreOffice(java)={jv}"
                if not rv or not jv:
                    line += "\n" + rlo + "\n" + jlo
                    failures += 1
            elif name in NO_VALIDATE:
                rv = jv = None
            elif not rv or not jv:
                failures += 1
            if diff:
                failures += 1
            ext = {"asic": ".asics", "odf": ".zip", "ooxml": ".zip"}.get(fmt, ".xml")
            gdir = GOLDEN if fmt in ("xades", "facturae", "asic") else os.path.join(ROOT, "testdata/xmldsig/java") if fmt == "xmldsig" else os.path.join(ROOT, "testdata/office/java")
            os.makedirs(gdir, exist_ok=True)
            shutil.copy(jout, os.path.join(gdir, name + ext))
        elif rok != jok:
            failures += 1
        print(line, flush=True)
    if tsa is not None:
        tsa.kill()
    print(f"\nfallos: {failures}  (salidas en {tmp})")


if __name__ == "__main__":
    main()
