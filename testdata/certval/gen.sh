#!/bin/sh
# Regenera la PKI de pruebas de `afirma-certval` (validación OCSP/CRL).
#
#   testdata/certval/gen.sh
#
# Necesita OpenSSL 3.x. Los certificados de usuario declaran servicios con
# nombres `*.certval.test` (que no existen): las pruebas los redirigen a
# servidores locales en 127.0.0.1 con un `HttpFetcher` que reescribe las URL.
#
# Contenido:
#   root.crt                Raíz (RSA 2048, autofirmada).
#   ca.crt/.key             CA emisora (RSA 2048) firmada por la raíz. Base de
#                           datos `index.txt` (la usa `openssl ocsp`).
#   ocsp.crt/.key           Respondedor OCSP delegado (EKU OCSPSigning) de `ca`.
#   rogue_ocsp.crt/.key     Certificado de `ca` SIN OCSPSigning (respondedor no autorizado).
#   other_ca.crt, other_ocsp.crt/.key  CA ajena y su respondedor.
#   fake_ca.crt/.key        Mismo nombre que `ca` pero otra clave (CRL falsificada).
#   ec_ca.crt/.key          CA ECDSA P-384 (firma CRL y OCSP directamente).
#   good.crt                Válido (AIA OCSP + caIssuers, CRLDP http).
#   revoked.crt             Revocado (keyCompromise).
#   expired.crt             Caducado (2020-2021).
#   notyet.crt              Aún no válido (2099-2100).
#   unknown.crt             Emitido por `ca` fuera de su base de datos (OCSP: unknown).
#   crlonly.crt             Sin AIA, con CRLDP http.
#   crlonly_revoked.crt     Ídem, revocado.
#   nothing.crt             Sin AIA ni CRLDP.
#   ldap.crt                CRLDP ldap:// únicamente.
#   multidp.crt             CRLDP: primero un servidor inaccesible y después el bueno.
#   aia_p7c.crt             caIssuers apuntando a un PKCS#7 (certs-only).
#   ec_good.crt             Emitido por `ec_ca`.
#   fnmt_fake.crt           CA falsa con el nombre de la "AC Componentes Informáticos" de la FNMT.
#   fnmt_noaia.crt          Emitido por `fnmt_fake` sin AIA (Java: sin mecanismo de validación).
#   fnmt_aia.crt            Emitido por `fnmt_fake` con AIA (Java: CA_NOT_SUPPORTED).
#   ca.crl / ca.crl.pem     CRL actual de `ca` (10 años).
#   ca_stale.crl            CRL caducada (nextUpdate 2020).
#   ca_pss.crl              CRL actual de `ca` firmada con RSASSA-PSS.
#   ca_fake.crl             CRL vacía firmada por `fake_ca`.
#   ec_ca.crl               CRL de `ec_ca`.
#   ca.p7c                  PKCS#7 certs-only con `ca.crt` (DER).
#   resp_*.der              Respuestas OCSP precalculadas (ver más abajo).
#   req_good_openssl.der    Petición OCSP de OpenSSL (sin nonce) para `good.crt`.
set -eu
cd "$(dirname "$0")"
rm -rf work && mkdir work
rm -f ./*.crt ./*.key ./*.crl ./*.pem ./*.der ./*.p7c index.txt* serial* crlnumber*

SUBJ_BASE="/O=AutoFirma-rs Pruebas/C=ES"

cat > work/ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/work
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_days = 7300
default_crl_days = 3650
policy = policy_any
unique_subject = no
copy_extensions = none
email_in_dn = no

[ policy_any ]
commonName = supplied
organizationName = optional
countryName = optional

[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = x

[ v3_root ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ v3_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ v3_ocsp ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
noCheck = ignored
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ v3_rogue ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ v3_leaf ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
authorityInfoAccess = OCSP;URI:http://ocsp.certval.test/, caIssuers;URI:http://aia.certval.test/ca.cer
crlDistributionPoints = URI:http://crl.certval.test/ca.crl

[ v3_crlonly ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://crl.certval.test/ca.crl

[ v3_nothing ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

[ v3_ldap ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
# OpenSSL separa la lista por comas: el DN va con las comas codificadas (%2C).
crlDistributionPoints = URI:ldap://ldap.certval.test/cn=CA%20CertVal%20Pruebas%2Co=AutoFirma-rs%20Pruebas%2Cc=ES?certificateRevocationList;binary?base?objectclass=cRLDistributionPoint

[ v3_multidp ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://down.certval.test/ca.crl, URI:http://crl.certval.test/ca.crl

[ v3_aia_p7c ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
authorityInfoAccess = OCSP;URI:http://ocsp.certval.test/, caIssuers;URI:http://aia.certval.test/ca.p7c
crlDistributionPoints = URI:http://crl.certval.test/ca.crl

[ v3_ec_leaf ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
authorityInfoAccess = OCSP;URI:http://ecocsp.certval.test/, caIssuers;URI:http://aia.certval.test/ec_ca.cer
crlDistributionPoints = URI:http://crl.certval.test/ec_ca.crl

[ crl_ext ]
authorityKeyIdentifier = keyid
EOF

# CA "ca": base de datos propia en el directorio actual.
: > index.txt
echo 1000 > serial
echo 01 > crlnumber

key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null; }
eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$2" -out "$1.key" 2>/dev/null; }

# Raíz y CA emisora.
key root
openssl req -new -x509 -config work/ca.cnf -key root.key -subj "/CN=Raiz CertVal Pruebas$SUBJ_BASE" \
  -days 10950 -sha256 -extensions v3_root -out root.crt
key ca
openssl req -new -config work/ca.cnf -key ca.key -subj "/CN=CA CertVal Pruebas$SUBJ_BASE" -out work/ca.csr
openssl x509 -req -in work/ca.csr -CA root.crt -CAkey root.key -set_serial 0x0100 -days 9125 -sha256 \
  -extfile work/ca.cnf -extensions v3_ca -out ca.crt

# Emite con `openssl ca` (queda en index.txt). $1 nombre, $2 extensiones, resto: opciones extra.
issue() {
  name=$1; ext=$2; shift 2
  key "$name"
  openssl req -new -config work/ca.cnf -key "$name.key" -subj "/CN=$name certval$SUBJ_BASE" -out "work/$name.csr"
  openssl ca -batch -config work/ca.cnf -cert ca.crt -keyfile ca.key -extensions "$ext" -notext \
    -in "work/$name.csr" -out "work/$name.pem" "$@" 2>/dev/null
  openssl x509 -in "work/$name.pem" -out "$name.crt"
}

issue ocsp v3_ocsp
issue rogue_ocsp v3_rogue
issue good v3_leaf
issue revoked v3_leaf
issue expired v3_leaf -startdate 20200101000000Z -enddate 20210101000000Z
issue notyet v3_leaf -startdate 20990101000000Z -enddate 21000101000000Z
issue crlonly v3_crlonly
issue crlonly_revoked v3_crlonly
issue nothing v3_nothing
issue ldap v3_ldap
issue multidp v3_multidp
issue aia_p7c v3_aia_p7c

openssl ca -batch -config work/ca.cnf -cert ca.crt -keyfile ca.key -revoke revoked.crt -crl_reason keyCompromise 2>/dev/null
openssl ca -batch -config work/ca.cnf -cert ca.crt -keyfile ca.key -revoke crlonly_revoked.crt -crl_reason superseded 2>/dev/null

# Certificado emitido por `ca` pero fuera de su base de datos.
key unknown
openssl req -new -config work/ca.cnf -key unknown.key -subj "/CN=unknown certval$SUBJ_BASE" -out work/unknown.csr
openssl x509 -req -in work/unknown.csr -CA ca.crt -CAkey ca.key -set_serial 0x7777 -days 7300 -sha256 \
  -extfile work/ca.cnf -extensions v3_leaf -out unknown.crt

# CRL.
openssl ca -batch -config work/ca.cnf -cert ca.crt -keyfile ca.key -gencrl -crldays 3650 -crlexts crl_ext -out ca.crl.pem 2>/dev/null
openssl crl -in ca.crl.pem -outform DER -out ca.crl
openssl ca -batch -config work/ca.cnf -cert ca.crt -keyfile ca.key -gencrl -crlexts crl_ext \
  -crl_lastupdate 20200101000000Z -crl_nextupdate 20200201000000Z -out work/ca_stale.pem 2>/dev/null
openssl crl -in work/ca_stale.pem -outform DER -out ca_stale.crl
# CRL firmada con RSASSA-PSS (SHA-256, MGF1 SHA-256, sal de 32 bytes).
openssl ca -batch -config work/ca.cnf -cert ca.crt -keyfile ca.key -gencrl -crldays 3650 -crlexts crl_ext \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out work/ca_pss.pem 2>/dev/null
openssl crl -in work/ca_pss.pem -outform DER -out ca_pss.crl

# PKCS#7 certs-only con la CA emisora.
openssl crl2pkcs7 -nocrl -certfile ca.crt -outform DER -out ca.p7c

# CA ajena con su respondedor.
key other_ca
openssl req -new -x509 -config work/ca.cnf -key other_ca.key -subj "/CN=Otra CA CertVal$SUBJ_BASE" \
  -days 9125 -sha256 -extensions v3_root -out other_ca.crt
key other_ocsp
openssl req -new -config work/ca.cnf -key other_ocsp.key -subj "/CN=Otro OCSP CertVal$SUBJ_BASE" -out work/other_ocsp.csr
openssl x509 -req -in work/other_ocsp.csr -CA other_ca.crt -CAkey other_ca.key -set_serial 0x0200 -days 7300 -sha256 \
  -extfile work/ca.cnf -extensions v3_ocsp -out other_ocsp.crt

# CA falsa con el mismo nombre que `ca`: CRL vacía firmada con otra clave.
key fake_ca
openssl req -new -x509 -config work/ca.cnf -key fake_ca.key -subj "/CN=CA CertVal Pruebas$SUBJ_BASE" \
  -days 9125 -sha256 -extensions v3_root -out fake_ca.crt
mkdir -p work/fake/work && : > work/fake/index.txt && echo 01 > work/fake/crlnumber
sed -e 's|^dir = .|dir = ./work/fake|' work/ca.cnf > work/fake.cnf
openssl ca -batch -config work/fake.cnf -cert fake_ca.crt -keyfile fake_ca.key -gencrl -crldays 3650 -out work/ca_fake.pem 2>/dev/null
openssl crl -in work/ca_fake.pem -outform DER -out ca_fake.crl

# CA ECDSA P-384 (base de datos propia en work/ec).
eckey ec_ca secp384r1
openssl req -new -config work/ca.cnf -key ec_ca.key -subj "/CN=CA EC CertVal Pruebas$SUBJ_BASE" -out work/ec_ca.csr
openssl x509 -req -in work/ec_ca.csr -CA root.crt -CAkey root.key -set_serial 0x0101 -days 9125 -sha256 \
  -extfile work/ca.cnf -extensions v3_ca -out ec_ca.crt
mkdir -p work/ec/work && : > work/ec/index.txt && echo 3000 > work/ec/serial && echo 01 > work/ec/crlnumber
sed -e 's|^dir = .|dir = ./work/ec|' -e 's|^default_md = sha256|default_md = sha384|' work/ca.cnf > work/ec.cnf
eckey ec_good prime256v1
openssl req -new -config work/ca.cnf -key ec_good.key -subj "/CN=ec_good certval$SUBJ_BASE" -out work/ec_good.csr
openssl ca -batch -config work/ec.cnf -cert ec_ca.crt -keyfile ec_ca.key -extensions v3_ec_leaf -notext \
  -in work/ec_good.csr -out work/ec_good.pem 2>/dev/null
openssl x509 -in work/ec_good.pem -out ec_good.crt
openssl ca -batch -config work/ec.cnf -cert ec_ca.crt -keyfile ec_ca.key -gencrl -crldays 3650 -out work/ec_ca.pem 2>/dev/null
openssl crl -in work/ec_ca.pem -outform DER -out ec_ca.crl
cp work/ec/index.txt ec_index.txt

# CA falsa con el nombre de "AC Componentes Informaticos" de la FNMT: los
# certificados que emite con SHA256withRSA tienen el identificador 109af7fc9
# de la tabla de CertificateVerifierFactory (OCSP, con la CA real configurada).
key fnmt_fake
openssl req -new -x509 -config work/ca.cnf -utf8 -key fnmt_fake.key \
  -subj "/C=ES/O=FNMT-RCM/OU=AC Componentes Informáticos" -days 9125 -sha256 -extensions v3_root -out fnmt_fake.crt
fnmt() {
  name=$1; ext=$2; serial=$3
  key "$name"
  openssl req -new -config work/ca.cnf -key "$name.key" -subj "/CN=$name certval$SUBJ_BASE" -out "work/$name.csr"
  openssl x509 -req -in "work/$name.csr" -CA fnmt_fake.crt -CAkey fnmt_fake.key -set_serial "$serial" -days 7300 \
    -sha256 -extfile work/ca.cnf -extensions "$ext" -out "$name.crt"
}
fnmt fnmt_noaia v3_crlonly 0x0901
fnmt fnmt_aia v3_leaf 0x0902

# Respuestas OCSP precalculadas (respondedor local de OpenSSL, sin red).
# $1 salida, $2 certificado consultado, resto: opciones del respondedor.
resp() {
  out=$1; cert=$2; shift 2
  openssl ocsp -index index.txt -CA ca.crt -issuer ca.crt -cert "$cert" -no_nonce "$@" -respout "$out" >/dev/null 2>&1
}
resp resp_good.der good.crt -rsigner ocsp.crt -rkey ocsp.key -ndays 3650
resp resp_good_keyid.der good.crt -rsigner ocsp.crt -rkey ocsp.key -ndays 3650 -resp_key_id
resp resp_good_nocerts.der good.crt -rsigner ocsp.crt -rkey ocsp.key -ndays 3650 -resp_no_certs
resp resp_good_by_ca.der good.crt -rsigner ca.crt -rkey ca.key -ndays 3650
resp resp_revoked.der revoked.crt -rsigner ocsp.crt -rkey ocsp.key -ndays 3650
resp resp_unknown.der unknown.crt -rsigner ocsp.crt -rkey ocsp.key -ndays 3650
resp resp_rogue.der good.crt -rsigner rogue_ocsp.crt -rkey rogue_ocsp.key -ndays 3650
resp resp_other.der good.crt -rsigner other_ocsp.crt -rkey other_ocsp.key -ndays 3650
resp resp_stale.der good.crt -rsigner ocsp.crt -rkey ocsp.key -ndays 1
resp resp_nonext.der good.crt -rsigner ocsp.crt -rkey ocsp.key
openssl ocsp -index ec_index.txt -CA ec_ca.crt -issuer ec_ca.crt -cert ec_good.crt -no_nonce \
  -rsigner ec_ca.crt -rkey ec_ca.key -ndays 3650 -respout resp_ec_good.der >/dev/null 2>&1

# Petición de referencia de OpenSSL (SHA-1, sin nonce).
openssl ocsp -issuer ca.crt -cert good.crt -no_nonce -reqout req_good_openssl.der >/dev/null 2>&1

# Para el respondedor en vivo de las pruebas solo hacen falta index.txt,
# ca.crt, ocsp.crt y ocsp.key.
rm -rf work serial.old index.txt.old index.txt.attr.old crlnumber.old
ls -1
