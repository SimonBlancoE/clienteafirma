"""Valida las firmas de documentos ODF y OOXML con LibreOffice (UNO).

Uso: PYTHONPATH=/usr/lib64/libreoffice/program python3 tools/oracle/lo_verify.py fichero...

Arranca un LibreOffice sin interfaz con un perfil temporal, abre cada
fichero como almacenamiento (ODF u OOXML según la extensión/contenido) y
llama a `DocumentDigitalSignatures.verifyDocumentContentSignatures`.
Imprime una línea por firma: `fichero firma#i valida=True|False estado_cert=N`.
"""
import os
import subprocess
import sys
import tempfile
import time
import zipfile

import uno
from com.sun.star.beans import PropertyValue


def connect(pipe):
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local)
    for _ in range(60):
        try:
            return resolver.resolve(f"uno:pipe,name={pipe};urp;StarOffice.ComponentContext")
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("no se puede conectar con LibreOffice")


def is_ooxml(path):
    with zipfile.ZipFile(path) as z:
        return "[Content_Types].xml" in z.namelist()


def main():
    profile = tempfile.mkdtemp(prefix="lo-profile-")
    pipe = "afirmaxml%d" % os.getpid()
    proc = subprocess.Popen(
        ["soffice", "--headless", "--invisible", "--nologo", "--norestore", "--nodefault",
         f"--accept=pipe,name={pipe};urp;", "-env:UserInstallation=" + uno.systemPathToFileUrl(profile)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ok_all = True
    try:
        ctx = connect(pipe)
        smgr = ctx.ServiceManager
        factory = smgr.createInstanceWithContext("com.sun.star.embed.StorageFactory", ctx)
        for path in sys.argv[1:]:
            url = uno.systemPathToFileUrl(os.path.abspath(path))
            ooxml = is_ooxml(path)
            pv = PropertyValue()
            pv.Name = "StorageFormat"
            pv.Value = "ZipFormat"
            storage = uno.invoke(factory, "createInstanceWithArguments",
                                 ((url, 1, uno.Any("[]com.sun.star.beans.PropertyValue", (pv,))),))
            sigs = smgr.createInstanceWithArgumentsAndContext(
                "com.sun.star.security.DocumentDigitalSignatures", ("1.2", True), ctx)
            stream = None
            if not ooxml:
                meta = storage.openStorageElement("META-INF", 1)
                stream = meta.openStreamElement("documentsignatures.xml", 1).getInputStream()
            infos = sigs.verifyDocumentContentSignatures(storage, stream)
            if not infos:
                print(f"{os.path.basename(path)} sin firmas")
                ok_all = False
            for i, info in enumerate(infos):
                print(f"{os.path.basename(path)} firma#{i} valida={info.SignatureIsValid} estado_cert={info.CertificateStatus}")
                ok_all &= bool(info.SignatureIsValid)
    finally:
        try:
            ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx).terminate()
        except Exception:
            pass
        proc.terminate()
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
