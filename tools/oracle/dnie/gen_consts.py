"""Genera crates/afirma-dnie/src/consts.rs con las constantes CWA-14890 del DNIe 3.0/4.0
(certificados CV y claves de terminal) extraídas literalmente de los fuentes Java de
JMulticard 2.1 (commit 4ec9494f), y comprueba longitud y SHA-256 contra el apéndice A de
docs/spec/10-dnie-nfc.md.

Uso: python3 tools/oracle/dnie/gen_consts.py <checkout de jmulticard> > crates/afirma-dnie/src/consts.rs
(el checkout lo deja tools/oracle/dnie/run.sh en <directorio de trabajo>/jmulticard).
"""
import hashlib
import os
import re
import sys

SRC = os.path.join(sys.argv[1], 'jmulticard/src/main/java/es/gob/jmulticard/card/dnie')

# (clase, campo, nombre Rust, longitud, sha256) — apéndice A de la especificación 10.
FIELDS = [
    ('Dnie3Cwa14890Constants', 'REF_C_CV_CA_PUBLIC_KEY', 'REF_C_CV_CA_PUBLIC_KEY', 2,
     '58691fae609bc279e385057cde8bc1ac8d035264bc8e0f2bc9469b8548bc1e5d'),
    ('Dnie3Cwa14890Constants', 'REF_ICC_PRIVATE_KEY', 'REF_ICC_PRIVATE_KEY', 2,
     'a21b15937d09462bef92a1f7149400c0a067f30d85fb286fca412855d821a887'),
    ('Dnie3Cwa14890Constants', 'encoded', 'CA_COMPONENT_PUBLIC_KEY', 162,
     '789c9238e9e03bbcede1bbd8c318dc1270efbb212ba0207b88e21000ddbfb34b'),
    ('Dnie3r1Cwa14890Constants', 'C_CV_CA', 'R1_C_CV_CA', 210,
     '7a11af8b21afdfc593266b62f1837e744119b6538b9e5472db3e55fe61e1afc7'),
    ('Dnie3r1Cwa14890Constants', 'CHR_C_CV_CA', 'R1_CHR_C_CV_CA', 8,
     '8f8e54d21804ac8e377b462cf8edb70d2b017737590b9c12face38b78bfce771'),
    ('Dnie3r2Cwa14890Constants', 'C_CV_CA', 'R2_C_CV_CA', 210,
     'be18380faf8016d8b5a55b03cac343774462e1b021899378aa40be40d037af7b'),
    ('Dnie3r2Cwa14890Constants', 'CHR_C_CV_CA', 'R2_CHR_C_CV_CA', 8,
     '012757f92ceb3b7d42c6bb4d770a89b1e3c7e3eb1e15cc786e97b72998e58045'),
]
TERMINALS = [
    ('Dnie3PinCwa14890Constants', 'R1_PIN', [
        '1fddaade5d2d859a9920c982b54d6840d99221ff22a5e2b9285c533848ed84fe',
        '4319b7e1377c0d7b6b35f8172c3fd47254ed05d5bc81db26a791fc34ae932447',
        '53cfcd6284058e617903e26e3f4c2bc288e431fab4d770075e47559a016c6e4a',
        'ea90c2d3004f45ae7a94acc8f1f87a21561920829a6ada85c6ee05ef7793c447']),
    ('Dnie3UsrCwa14890Constants', 'R1_USR', [
        '4ec82246e8e8754bd909d7c72447bf37bddb275eb6d35fcad57374b34e8227fb',
        '14346ad58419c0302a86aee319c3a95ac853b3e9775180ff9cf5ea1e73925e05',
        '0cabe4dd79037bc3935968882034f774d1ebadcf5fbea8923e4192b6084c991a',
        'c22b6257ac263cd01f702f0b19ad4618bdb60234e4a3f7f1045f3ada7f3a37d1']),
    ('Dnie3r2PinCwa14890Constants', 'R2_PIN', [
        '1e9632d74a828612cb6a59870a48260c079e76ba226716fc5d44ec222d88eab6',
        'b71691d7a270afd667d4c16b4662ddad3d75730d87493a454bcf66663a9d5c28',
        'e4f064176f4c7ecc1152973623a5a7edee655e4e6c478bb3937e2397c507a2df',
        '599cc372e62f2a72b6835c12ee37e766b5d38255534c20aea8b0986dffe8b426']),
    ('Dnie3r2UsrCwa14890Constants', 'R2_USR', [
        '7b4456a27bf868a1a83497455249b5ae2f517cb1c77e2d425882acc56bf343f1',
        'c35f763c13010f863abee31b9b683f1955f18a5a705d04ce4bd45e93159bca02',
        '8a0c7fe56607219873741878dee013057f20c087cbeb4fac667f4f8ba61ed5f3',
        'e6b5643864f6acb3f4f3995cf513d6ba355284afb22b33dac13b6309e62c3845']),
]


def arr(cls, name):
    src = open(os.path.join(SRC, cls + '.java'), encoding='utf-8').read()
    m = re.search(r'\b' + name + r'\s*=\s*(?:new BigInteger\(1,\s*new byte\[\]\s*)?\{', src)
    if not m:
        raise SystemExit('No se encuentra %s.%s' % (cls, name))
    body = src[m.end():src.index('}', m.end())]
    return bytes(int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]{1,2})', body))


def check(label, data, length, sha):
    if len(data) != length or hashlib.sha256(data).hexdigest() != sha:
        raise SystemExit('Constante %s no coincide con el apéndice A (long. %d)' % (label, len(data)))


def emit(name, data, doc):
    h = data.hex().upper()
    print('/// %s' % doc)
    if len(h) <= 64:
        print('pub const %s: [u8; %d] = h("%s");' % (name, len(data), h))
    else:
        print('pub const %s: [u8; %d] = h(concat!(' % (name, len(data)))
        for i in range(0, len(h), 96):
            print('    "%s",' % h[i:i + 96])
        print('));')


print('//! Constantes del canal seguro CWA-14890 del DNIe 3.0/4.0 (especificación 10 §6.1, §6.2 y')
print('//! apéndice A): certificados CV de las CA intermedias y de los terminales «PIN» y «usuario»')
print('//! (juegos r1 y r2) y claves privadas RSA-1024 de esos terminales.')
print('//!')
print('//! Copiadas literalmente de JMulticard 2.1 (`es.gob.jmulticard.card.dnie.Dnie3*Cwa14890Constants`,')
print('//! © Gobierno de España, LGPL 2.1+ / EUPL 1.1+): son claves de terminal publicadas por la propia')
print('//! Administración para cualquier aplicación. Fichero generado con')
print('//! `tools/oracle/dnie/gen_consts.py`; no editar a mano.')
print()
print('use crate::hexconst::h;')
print()
for cls, field, rust, length, sha in FIELDS:
    data = arr(cls, field)
    check(cls + '.' + field, data, length, sha)
    emit(rust, data, '`%s.%s` (%d octetos).' % (cls, field, length))
    print()
for cls, prefix, shas in TERMINALS:
    parts = [('C_CV_IFD', 209), ('CHR_C_CV_IFD', 8), ('ifdModulus', 128), ('ifdPrivateExponent', 128)]
    names = ['C_CV_IFD', 'CHR', 'MODULUS', 'PRIVATE_EXPONENT']
    for (field, length), sha, nm in zip(parts, shas, names):
        data = arr(cls, field)
        check(cls + '.' + field, data, length, sha)
        emit('%s_%s' % (prefix, nm), data, '`%s.%s` (%d octetos).' % (cls, field, length))
        print()
