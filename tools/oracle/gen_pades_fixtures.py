"""Genera los PDF de prueba de testdata/pades con pyHanko (giros de página,
cifrado RC4/AES, tablas y flujos de referencias cruzadas, documento
certificado).

uso: python -I tools/oracle/gen_pades_fixtures.py
"""
import io, os, sys
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.crypt import StandardSecurityHandler
from pyhanko.pdf_utils.crypt.standard import StandardSecuritySettingsRevision
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
RES = os.path.join(ROOT, 'afirma-crypto-pdf', 'src', 'test', 'resources')
OUT = os.path.join(ROOT, 'testdata', 'pades')


def load(name):
    return PdfFileReader(open(os.path.join(RES, name), 'rb'), strict=False)


def save(w, name):
    with open(os.path.join(OUT, name), 'wb') as f:
        w.write(f)
    print('generado', name)


def pages(w):
    out = []
    def walk(node):
        node = node.get_object()
        if node.get('/Type') == '/Pages':
            for k in node['/Kids']:
                walk(k)
        else:
            out.append(node)
    walk(w.root['/Pages'])
    return out


# Páginas giradas (0, 90, 180, 270) con tabla de referencias clásica.
w = copy_into_new_writer(load('multipage.pdf'))
w.stream_xrefs = False
for i, p in enumerate(pages(w)):
    p['/Rotate'] = generic.NumberObject((i % 4) * 90)
save(w, 'rotated_pages.pdf')

# Flujo de referencias cruzadas y flujos de objetos.
w = copy_into_new_writer(load('multipage.pdf'))
w.stream_xrefs = True
save(w, 'xref_stream.pdf')

# Cifrados con contraseña de propietario "owner" (usuario vacía o "user").
def encrypted(name, rev, aes, keylen, user=''):
    w = copy_into_new_writer(load('TEST_PDF.pdf'))
    w.stream_xrefs = False
    id1 = w.document_id[0]
    sh = StandardSecurityHandler.build_from_pw_legacy(rev, id1, 'owner', user, keylen_bytes=keylen, use_aes128=aes)
    w._assign_security_handler(sh)
    save(w, name)

encrypted('encrypted_rc4_40.pdf', StandardSecuritySettingsRevision.RC4_BASIC, False, 5)
encrypted('encrypted_rc4_128.pdf', StandardSecuritySettingsRevision.RC4_EXTENDED, False, 16)
encrypted('encrypted_aes128.pdf', StandardSecuritySettingsRevision.RC4_OR_AES128, True, 16)
encrypted('encrypted_aes128_user.pdf', StandardSecuritySettingsRevision.RC4_OR_AES128, True, 16, user='user')
w = copy_into_new_writer(load('TEST_PDF.pdf'))
w.encrypt('owner', '')
save(w, 'encrypted_aes256.pdf')
