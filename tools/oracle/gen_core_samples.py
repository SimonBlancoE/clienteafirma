"""Genera los ficheros de muestra de testdata/core/mime para las pruebas de
detección de tipos de datos de afirma-core (MimeHelper/OfficeAnalizer).

Uso: python3 -I tools/oracle/gen_core_samples.py testdata/core/mime
Los ficheros resultantes se versionan; el oráculo Java (CoreOracle mime)
genera a partir de ellos el fichero golden mime.golden.
"""
import io
import os
import struct
import sys
import zipfile
import zlib

out = sys.argv[1]
os.makedirs(out, exist_ok=True)

FIXED_DATE = (2020, 1, 1, 0, 0, 0)


def w(name, data):
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)


def mkzip(entries, stored_first=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, (n, d) in enumerate(entries):
            info = zipfile.ZipInfo(n, FIXED_DATE)
            info.compress_type = zipfile.ZIP_STORED if (stored_first and i == 0) else zipfile.ZIP_DEFLATED
            z.writestr(info, d)
    return buf.getvalue()


def odf(mimetype):
    return mkzip([
        ("mimetype", mimetype),
        ("content.xml", '<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'),
        ("meta.xml", '<?xml version="1.0" encoding="UTF-8"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'),
        ("settings.xml", '<?xml version="1.0" encoding="UTF-8"?><office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'),
        ("styles.xml", '<?xml version="1.0" encoding="UTF-8"?><office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>'),
        ("META-INF/manifest.xml", '<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"/>'),
    ], stored_first=True)


def ooxml(main_ct, extra_overrides=()):
    overrides = "".join(
        '<Override PartName="%s" ContentType="%s"/>' % (p, c) for p, c in extra_overrides
    )
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
          + overrides +
          '<Override PartName="/main.xml" ContentType="%s"/>'
          '</Types>') % main_ct
    return mkzip([
        ("[Content_Types].xml", ct),
        ("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>'),
        ("docProps/app.xml", '<?xml version="1.0" encoding="UTF-8"?><Properties/>'),
        ("docProps/core.xml", '<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>'),
        ("main.xml", '<?xml version="1.0" encoding="UTF-8"?><doc/>'),
    ])


def png():
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


OLE = bytes.fromhex("D0CF11E0A1B11AE1") + bytes(504)

w("pdf.pdf", b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
w("pdf-binary.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
w("zip.zip", mkzip([("hola.txt", "hola")]))
w("odt.odt", odf("application/vnd.oasis.opendocument.text"))
w("ods.ods", odf("application/vnd.oasis.opendocument.spreadsheet"))
w("odp.odp", odf("application/vnd.oasis.opendocument.presentation"))
w("odg.odg", odf("application/vnd.oasis.opendocument.graphics"))
w("odt-template.ott", odf("application/vnd.oasis.opendocument.text-template"))
w("odf-unknown.odt", odf("application/x-desconocido"))
w("docx.docx", ooxml("application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"))
w("xlsx.xlsx", ooxml("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"))
w("pptx.pptx", ooxml("application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"))
w("docm.docm", ooxml("application/vnd.ms-word.document.macroEnabled.main+xml"))
w("dotm.dotm", ooxml("application/vnd.ms-word.template.macroEnabled.12"))
w("ooxml-unknown.docx", ooxml("application/x-desconocido+xml"))
w("doc.doc", OLE + b"Microsoft Office Word" + bytes(16))
w("xls.xls", OLE + b"Microsoft Excel" + bytes(16))
w("ppt.ppt", OLE + b"Microsoft Office PowerPoint" + bytes(16))
w("mpp.mpp", OLE + b"Microsoft Project" + bytes(16))
w("ole-unknown.bin", OLE + bytes(16))
w("xml-decl.xml", b'<?xml version="1.0" encoding="UTF-8"?>\n<raiz><hijo a="1">texto</hijo></raiz>\n')
w("xml-decl11.xml", b'<?xml version="1.1"?><a/>')
w("xml-nodecl.xml", b'<raiz><hijo/></raiz>')
w("xml-nodecl-utf8.xml", '<raiz>España</raiz>'.encode("utf-8"))
w("xml-doctype.xml", b'<?xml version="1.0"?>\n<!DOCTYPE raiz>\n<raiz/>')
w("xml-broken.xml", b'<?xml version="1.0"?>\n<raiz><hijo></raiz>')
w("xml-ns-unbound.xml", b'<?xml version="1.0"?>\n<a:raiz/>')
w("html.html", b'<html><body>hola</body></html>')
w("html-doctype.html", b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"><html></html>')
w("png.png", png())
w("jpeg.jpg", bytes.fromhex("FFD8FFE000104A46494600010100000100010000FFD9"))
w("gif.gif", b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
w("tiff-le.tif", b"II*\x00\x08\x00\x00\x00" + bytes(8))
w("tiff-be.tif", b"MM\x00*\x00\x00\x00\x08" + bytes(8))
w("rtf.rtf", b"{\\rtf1\\ansi Hola}")
w("ps2.ps", b"%!PS-Adobe-2.0\n%%EOF\n")
w("ps3.ps", b"%!PS-Adobe-3.0\n%%EOF\n")
w("txt-ascii.txt", b"Hola mundo\nSegunda linea\n")
w("txt-utf8.txt", "Hola España\n".encode("utf-8"))
w("txt-latin1.txt", "Hola España\n".encode("latin-1"))
w("txt-ascii-long-then-utf8.txt", b"a" * 5000 + "ñ".encode("utf-8"))
w("txt-control.txt", b"\x01\x02\x03abc")
w("bin.bin", bytes(range(256)))
w("gz.gz", bytes.fromhex("1F8B0800000000000003") + zlib.compress(b"hola")[2:-4] + bytes(8))
w("p7s.p7s", bytes.fromhex("308006092A864886F70D010702A0803080020101310F300D06096086480165030402010500"))
w("exe.exe", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
w("java.java", b"package es.gob;\nclass A {}\n")
w("sh.sh", b"#!/bin/sh\necho hola\n")
w("class.class", bytes.fromhex("CAFEBABE00000034"))
w("rar.rar", b"Rar!\x1a\x07\x00")
w("bz2.bz2", b"BZh91AY&SY")
w("mp3.mp3", bytes.fromhex("FFFB9064") + bytes(16))
w("empty.bin", b"")
w("one-byte.bin", b"\x00")
w("pk-truncated.zip", b"PK\x03\x04\x14\x00\x00\x00")
w("pk-empty.zip", bytes.fromhex("504B0506") + bytes(18))
w("sgml.sgml", b"<!DOCTYPE foo><foo/>")
w("comment.xml", b"<!-- comentario --><a/>")
w("facturae.xml", b'<?xml version="1.0" encoding="UTF-8"?><fe:Facturae xmlns:fe="http://www.facturae.es/Facturae/2014/v3.2.1/Facturae"><FileHeader/><Parties/><Invoices/></fe:Facturae>')
w("bom-xml.xml", b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?><a/>')
