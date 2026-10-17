import hashlib, sys
sys.path.insert(0, '/tmp/claude-1000/-home-octo-Projects-autofirma/3b2a3c91-9239-4ea8-b3f9-fa23261708cb/scratchpad/tools')
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
H=lambda s:int(s,16)
p=H('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377'); a=H('7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9'); b=H('26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6')
G=(H('8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262'),H('547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997'))
def add(P,Q):
    if P is None: return Q
    if Q is None: return P
    if P[0]==Q[0] and (P[1]+Q[1])%p==0: return None
    l=((3*P[0]*P[0]+a)*pow(2*P[1],-1,p) if P==Q else (Q[1]-P[1])*pow(Q[0]-P[0],-1,p))%p
    x=(l*l-P[0]-Q[0])%p; return (x,(l*(P[0]-x)-P[1])%p)
def mul(k,P):
    R=None
    while k:
        if k&1: R=add(R,P)
        P=add(P,P); k>>=1
    return R
enc=lambda P: b'\x04'+P[0].to_bytes(32,'big')+P[1].to_bytes(32,'big')
def aes_ecb(k,b): e=Cipher(algorithms.AES(k),modes.ECB()).encryptor(); return e.update(b)+e.finalize()
def aes_cbc_enc(k,iv,b): e=Cipher(algorithms.AES(k),modes.CBC(iv)).encryptor(); return e.update(b)+e.finalize()
def aes_cbc_dec(k,iv,b): d=Cipher(algorithms.AES(k),modes.CBC(iv)).decryptor(); return d.update(b)+d.finalize()
def cmac8(k,b): c=CMAC(algorithms.AES(k)); c.update(b); return c.finalize()[:8]
def pad16(b): b=b+b'\x80'; return b+b'\0'*((-len(b))%16)
def tlv(t,v):
    if len(v)<128: return bytes([t,len(v)])+v
    if len(v)<256: return bytes([t,0x81,len(v)])+v
    return bytes([t,0x82,len(v)>>8,len(v)&255])+v
X=lambda b: b.hex().upper()
CAN=b'123456'
Kpi=hashlib.sha1(CAN+b'\0\0\0\3').digest()[:16]
s=bytes.fromhex('3F00C4D39D153F2B2A214A078D899B22')  # reuse ICAO nonce
z=aes_cbc_enc(Kpi,b'\0'*16,s)
skMapIfd=H('7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99'); skMapIcc=H('498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560')
pkMapIfd=mul(skMapIfd,G); pkMapIcc=mul(skMapIcc,G); Hp=mul(skMapIfd,pkMapIcc)
Gm=add(mul(int.from_bytes(s,'big'),G),Hp)
skIfd=H('A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595'); skIcc=H('107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A')
pkIfd=mul(skIfd,Gm); pkIcc=mul(skIcc,Gm); K=mul(skIfd,pkIcc)[0].to_bytes(32,'big')
Kenc=hashlib.sha1(K+b'\0\0\0\1').digest()[:16]; Kmac=hashlib.sha1(K+b'\0\0\0\2').digest()[:16]
oid=bytes.fromhex('04007F00070202040202')
pkdata=lambda P: bytes.fromhex('7F494F060A')+oid+bytes.fromhex('8641')+enc(P)
Tifd=cmac8(Kmac,pkdata(pkIcc)); Ticc=cmac8(Kmac,pkdata(pkIfd))
print('== Vector sintetico PACE-CAN (CAN=123456, claves efimeras = las del ejemplo ICAO)')
print('Kpi', X(Kpi)); print('s', X(s)); print('z', X(z))
print('MSE', '0022C1A412800A04007F0007020204020283010284010D')
print('GA1 cmd', '108600000'+'27C00'); print('GA1 resp', X(b'\x7C\x12\x80\x10'+z)+'9000')
ga2=tlv(0x7C,tlv(0x81,enc(pkMapIfd))); print('GA2 cmd', '10860000'+format(len(ga2),'02X')+X(ga2)); print('GA2 resp', X(tlv(0x7C,tlv(0x82,enc(pkMapIcc))))+'9000')
print('H', X(enc(Hp))); print('Gmap', X(enc(Gm)))
ga3=tlv(0x7C,tlv(0x83,enc(pkIfd))); print('GA3 cmd', '10860000'+format(len(ga3),'02X')+X(ga3)); print('GA3 resp', X(tlv(0x7C,tlv(0x84,enc(pkIcc))))+'9000')
print('K', X(K)); print('KSenc', X(Kenc)); print('KSmac', X(Kmac))
print('T_IFD', X(Tifd), 'T_ICC', X(Ticc))
ga4=tlv(0x7C,tlv(0x85,Tifd)); print('GA4 cmd', '00860000'+format(len(ga4),'02X')+X(ga4)); print('GA4 resp', X(tlv(0x7C,tlv(0x86,Ticc)))+'9000')
# jmulticard SM wrap
ssc=0
def wrap(cmd_hdr, data, le):
    global ssc
    ssc+=1; S=ssc.to_bytes(16,'big')
    hdr=bytes([cmd_hdr[0]|0x0C])+cmd_hdr[1:4]
    do87=b''; do97=b''
    if data: do87=tlv(0x87,b'\x01'+aes_cbc_enc(Kenc,aes_ecb(Kenc,S),pad16(data)))
    if le is not None: do97=bytes([0x97,1,le&255])
    m=(pad16(hdr) if (do87 or do97) else hdr)+do87+do97
    mac=cmac8(Kmac,pad16(S+m))
    body=do87+do97+b'\x8E\x08'+mac
    return hdr+bytes([len(body)])+body+b'\x00'
def resp(data, sw):
    global ssc
    ssc+=1; S=ssc.to_bytes(16,'big')
    do87=tlv(0x87,b'\x01'+aes_cbc_enc(Kenc,aes_ecb(Kenc,S),pad16(data))) if data else b''
    do99=b'\x99\x02'+sw
    mac=cmac8(Kmac,pad16(S+do87+do99))
    return do87+do99+b'\x8E\x08'+mac+sw
print('== SM PACE (formato jmulticard) con KSenc/KSmac anteriores, SSC inicial 0')
c1=wrap(bytes.fromhex('00A40400'),b'Master.File',None); print('SELECT MF  cmd (SSC=1)', X(c1)); r1=resp(b'',bytes.fromhex('9000')); print('           resp (SSC=2)', X(r1))
c2=wrap(bytes.fromhex('00A40000'),bytes.fromhex('0006'),None); print('SELECT 0006 cmd (SSC=3)', X(c2)); fci=bytes.fromhex('6F048102000A'); r2=resp(fci,bytes.fromhex('9000')); print('           resp (SSC=4) FCI 6F048102000A', X(r2))
c3=wrap(bytes.fromhex('00B00000'),None,0x0A); print('READ BINARY Le=0A cmd (SSC=5)', X(c3)); r3=resp(b'BMP100002\x00',bytes.fromhex('9000')); print('           resp (SSC=6) data "BMP100002\\0"', X(r3))
c4=wrap(bytes.fromhex('00B00000'),None,0xDE); print('READ BINARY Le=DE cmd (SSC=7) len', len(c4), X(c4))
r4=resp(bytes(range(222)),bytes.fromhex('9000')); print('           resp (SSC=8) 222 bytes 00..DD len', len(r4), X(r4[:8])+'...'+X(r4[-14:]))
