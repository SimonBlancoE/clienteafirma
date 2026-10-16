#!/bin/sh
# Genera la PKI de PRUEBAS usada por los tests de AutoFirma-rs.
# ¡Las claves privadas de este directorio son públicas y solo valen para tests!
set -eu
cd "$(dirname "$0")"
PASS=12341234
cat > ca.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[v3_sign]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
certificatePolicies=2.16.724.1.3.5.7.1,1.3.6.1.4.1.5734.3.10
[v3_auth]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[v3_tsa]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7300 -sha256 \
  -subj "/C=ES/O=AutoFirma-rs Pruebas/CN=AC Raiz de Pruebas AutoFirma-rs" -config ca.cnf -extensions v3_ca
issue() { # nombre subj ext keyalg
  name=$1; subj=$2; ext=$3; shift 3
  openssl req -utf8 -new -newkey "$@" -nodes -keyout "$name.key" -out "$name.csr" -subj "$subj" -config ca.cnf
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -set_serial "0x$(openssl rand -hex 12)" \
    -days 3650 -sha256 -out "$name.crt" -extfile ca.cnf -extensions "$ext"
  rm "$name.csr"
  openssl pkcs12 -export -inkey "$name.key" -in "$name.crt" -certfile ca.crt -name "$name" \
    -passout pass:$PASS -out "$name.p12"
  openssl pkcs12 -export -legacy -inkey "$name.key" -in "$name.crt" -certfile ca.crt -name "$name" \
    -passout pass:$PASS -out "$name-legacy.p12"
}
issue firmante-rsa "/C=ES/serialNumber=IDCES-00000000T/GN=JUAN/SN=ESPAÑOL ESPAÑOL/CN=ESPAÑOL ESPAÑOL JUAN - 00000000T" v3_sign rsa:2048
issue firmante-ec "/C=ES/serialNumber=IDCES-99999999R/GN=MARIA/SN=PRUEBA/CN=PRUEBA MARIA - 99999999R" v3_sign ec -pkeyopt ec_paramgen_curve:P-256
issue autenticacion "/C=ES/serialNumber=IDCES-00000000T/CN=ESPAÑOL ESPAÑOL JUAN (AUTENTICACIÓN)" v3_auth rsa:2048
issue tsa "/C=ES/O=AutoFirma-rs Pruebas/CN=TSA de Pruebas" v3_tsa rsa:2048
# Certificado caducado
openssl req -utf8 -new -newkey rsa:2048 -nodes -keyout caducado.key -out caducado.csr -subj "/C=ES/CN=CERTIFICADO CADUCADO" -config ca.cnf
openssl x509 -req -in caducado.csr -CA ca.crt -CAkey ca.key -set_serial 0x0badc0de -not_before 20200101000000Z -not_after 20210101000000Z \
  -sha256 -out caducado.crt -extfile ca.cnf -extensions v3_sign 2>/dev/null || \
  openssl x509 -req -in caducado.csr -CA ca.crt -CAkey ca.key -set_serial 0x0badc0de -days 1 -sha256 -out caducado.crt -extfile ca.cnf -extensions v3_sign
rm caducado.csr
openssl pkcs12 -export -inkey caducado.key -in caducado.crt -certfile ca.crt -name caducado -passout pass:$PASS -out caducado.p12
rm -f ca.srl
echo "PKI de pruebas generada (contraseña PKCS#12: $PASS)"
