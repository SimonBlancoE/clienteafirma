import sys, os, zlib, struct, datetime, re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
out = sys.argv[1]; jsrc = sys.argv[2]
def name(cn): return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME,'ES'), x509.NameAttribute(NameOID.COMMON_NAME,cn)])
now = datetime.datetime(2024,1,1); later = datetime.datetime(2034,1,1)
def cert(subj, key, issuer, ikey, ca=False):
    b = (x509.CertificateBuilder().subject_name(name(subj)).issuer_name(name(issuer)).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(later)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(ikey, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
def keyprops(k, p):
    n = k.private_numbers()
    open(os.path.join(out, p), 'w').write('n=%X\nd=%X\ne=%X\n' % (n.public_numbers.n, n.d, n.public_numbers.e))
icc = rsa.generate_private_key(65537, 1024)
assert icc.private_numbers().public_numbers.n.bit_length() == 1024
open(os.path.join(out,'icc_cert.der'),'wb').write(cert('ICC SIMULADA', icc, 'ICC SIMULADA', icc, True)); keyprops(icc,'icc_key.properties')
ca = rsa.generate_private_key(65537, 2048)
auth = rsa.generate_private_key(65537, 2048); firma = rsa.generate_private_key(65537, 2048)
ders = {'7001': cert('SIM (AUTENTICACION)', auth, 'AC DNIE SIM', ca), '7002': cert('SIM (FIRMA)', firma, 'AC DNIE SIM', ca), '7003': cert('AC DNIE SIM', ca, 'AC RAIZ SIM', ca, True)}
for fid, der in ders.items():
    c = zlib.compress(der)
    open(os.path.join(out, 'cert_%s.bin' % fid), 'wb').write(struct.pack('<II', len(der), len(c)) + c)
    open(os.path.join(out, 'cert_%s.der' % fid), 'wb').write(der)
keyprops(auth, 'key_0101.properties'); keyprops(firma, 'key_0102.properties')
# IFD moduli from jmulticard constants, keyed by CHR
d = os.path.join(jsrc, 'jmulticard/src/main/java/es/gob/jmulticard/card/dnie')
lines = []
for cls in ['Dnie3PinCwa14890Constants','Dnie3UsrCwa14890Constants','Dnie3r2PinCwa14890Constants','Dnie3r2UsrCwa14890Constants']:
    src = open(os.path.join(d, cls + '.java')).read()
    def arr(nm):
        m = re.search(nm + r'\s*=\s*(?:new BigInteger\(1,\s*new byte\[\]\s*)?\{', src)
        body = src[m.end():src.index('}', m.end())]
        return bytes(int(v,16) for v in re.findall(r'0x([0-9a-fA-F]{1,2})', body))
    chr_ = arr('CHR_C_CV_IFD').hex().upper(); mod = arr('ifdModulus').hex().upper(); cv = arr('C_CV_IFD')
    lines.append('%s=%s' % (chr_, mod)); lines.append('%s.class=%s' % (chr_, cls))
    # tail of C_CV_IFD before CAR (42 08 ...): exponent
    lines.append('%s.cvtail=%s' % (chr_, cv[-16:].hex().upper()))
open(os.path.join(out, 'ifd.properties'), 'w').write('\n'.join(lines) + '\n')
print('ok')
