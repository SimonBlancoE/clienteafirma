from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
def pad(b, n): b = b + b'\x80'; return b + b'\0' * ((-len(b)) % n)
def tdes_cbc(k, data):  # IV 0, key K1K2K1
    k24 = k + k[:8] if len(k) == 16 else k
    e = Cipher(TripleDES(k24), modes.CBC(b'\0'*8)).encryptor(); return e.update(data) + e.finalize()
def des_ecb(k8, blk):
    e = Cipher(TripleDES(k8*3), modes.ECB()).encryptor(); return e.update(blk) + e.finalize()
def retail_mac(kmac, ssc, data_padded, maclen):
    k1 = kmac[:8]; t = des_ecb(k1, ssc); i = 0
    while i < len(data_padded) - 8:
        t = des_ecb(k1, bytes(x ^ y for x, y in zip(t, data_padded[i:i+8]))); i += 8
    last = bytes(x ^ y for x, y in zip(t, data_padded[i:i+8]))
    k24 = kmac[:16] + kmac[:8]
    e = Cipher(TripleDES(k24), modes.ECB()).encryptor(); return (e.update(last)+e.finalize())[:maclen]
def tlv(t, v):
    if len(v) < 128: return bytes([t, len(v)]) + v
    if len(v) < 256: return bytes([t, 0x81, len(v)]) + v
    return bytes([t, 0x82, len(v) >> 8, len(v) & 0xff]) + v
def cwa_protect(cla, ins, p1, p2, data, le, kenc, kmac, ssc, maclen):
    cla |= 0x0C
    body = b''
    if data: body += tlv(0x87, b'\x01' + tdes_cbc(kenc, pad(data, 8)))
    if le is not None: body += tlv(0x97, bytes([le]))
    mac = retail_mac(kmac, ssc, pad(pad(bytes([cla, ins, p1, p2]), 8) + body, 8), maclen)
    full = body + bytes([0x8E, maclen]) + mac
    return bytes([cla, ins, p1, p2, len(full)]) + full
def chk(name, got, exp): print(('OK  ' if got.hex().upper()==exp.upper() else 'FAIL'), name, got.hex().upper(), '' if got.hex().upper()==exp.upper() else 'exp '+exp.upper())
KENC = bytes.fromhex('598f26e36e11a8ec14b81e19bda223ca'); KMAC = bytes.fromhex('5de2939a1ea03a930b88206d8f73e8a7')
chk('jmc testPinEncryptionDes', cwa_protect(0,0x20,0,0,b'CRYPTOKI',None,KENC,KMAC,bytes.fromhex('d31ac8ec7ba0fe6f'),4), '0c20000019871101ce1ab937c332f3faee43336d4311ef338e046908df4e')
chk('jmc testEncryptionDes', cwa_protect(0,0xA4,4,0,b'Master.File',None,KENC,KMAC,bytes.fromhex('d31ac8ec7ba0fe75'),4), '0ca40400198711013e9ac315a8e855dd3722f291078ac2bd8e04b6f56963')
# ICAO 9303-11 BAC SM worked example (SELECT EF.COM)
kse=bytes.fromhex('979EC13B1CBFE9DCD01AB0FED307EAE5'); ksm=bytes.fromhex('F1CB1F1FB5ADF208806B89DC579DC1F8')
ssc=int('887022120C06C226',16)+1
chk('ICAO BAC SM select EF.COM (CWA format, no trailing Le)', cwa_protect(0,0xA4,2,0x0C,bytes.fromhex('011E'),None,kse,ksm,ssc.to_bytes(8,'big'),8), '0CA4020C158709016375432908C044F68E08BF8B92D635FF24F8')
ssc+=1
chk('ICAO BAC SM resp MAC', retail_mac(ksm, ssc.to_bytes(8,'big'), pad(bytes.fromhex('99029000'),8), 8), 'FA855A5D4C50A8ED')
# AES (PACE-style) with jmulticard TestApduEncrypter KENC2/KMAC2/SSC2
k2=bytes.fromhex('f1b0d6449cec48864c1efabb4957d64b'); m2=bytes.fromhex('1665a3adcb579053cc5d908720ce4dc1'); s2=bytes.fromhex('3de0c9658f836888bd352dbf46462f60')
e=Cipher(algorithms.AES(k2),modes.ECB()).encryptor(); iv=e.update(s2)+e.finalize()
e=Cipher(algorithms.AES(k2),modes.CBC(iv)).encryptor(); ct=e.update(pad(b'Master.File',16))+e.finalize()
chk('jmc testPartialEncryptionAes DO87 payload', ct, 'f5124ee2f53962e86e66a6d234827f0f')
do87=tlv(0x87,b'\x01'+ct)
macin=pad(s2+pad(bytes.fromhex('0CA40400'),16)+do87,16)
c=CMAC(algorithms.AES(m2)); c.update(macin); mac=c.finalize()[:8]
chk('jmc testCMacGeneration (disabled test) DO8E', mac, '70e6de5f679aee64')
print('PACE-wrapped SELECT Master.File (jmulticard SecureMessaging.wrap, SSC before wrap = SSC2-1):', ('0CA40400'+format(len(do87)+10,'02X')+do87.hex()+'8E08'+mac.hex()+'00').upper())
