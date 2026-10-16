#!/bin/sh
# Oráculo del plugin «Validación de certificados» de AutoFirma Java
# (tools/oracle/CertValOracle.java) y regeneración de los ficheros de referencia
# de testdata/certval/java-*.txt que usan las pruebas de crates/afirma-certval.
#
#   AFIRMA_JAR=/ruta/autofirma.jar \
#   CERTVAL_JAR=/ruta/afirma-ui-simpleafirma-plugin-validatecerts-1.2.jar \
#       tools/oracle/certval_oracle.sh [orden args...]
#
# Sin argumentos regenera los ficheros de referencia; con argumentos ejecuta
# una orden del oráculo (id, ocspreq, analyze, crl, period, validate, messages).
set -e
: "${AFIRMA_JAR:?Define AFIRMA_JAR con la ruta de autofirma.jar}"
: "${CERTVAL_JAR:?Define CERTVAL_JAR con la ruta del JAR del plugin de validación}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
D=$ROOT/testdata/certval
P=$ROOT/afirma-simple-plugin-validatecerts/src/main/resources/es/gob/afirma/plugin/certvalidation/validation
W=${W:-$(mktemp -d)}
CP="$AFIRMA_JAR:$CERTVAL_JAR"
mkdir -p "$W/classes"
javac -encoding UTF-8 -cp "$CP" -d "$W/classes" "$ROOT/tools/oracle/CertValOracle.java"
cv() {
  java -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Duser.language=es -Duser.country=ES \
    -cp "$CP:$W/classes" es.gob.afirma.plugin.certvalidation.validation.CertValOracle "$@" 2>/dev/null
}
if [ $# -gt 0 ]; then
  cv "$@"
  exit 0
fi

cd "$D"
# Textos de ValidationResult (toString/toJsonString).
cv messages > java-messages.txt
# Identificadores CRC de CertificateVerifierFactory y verificador elegido.
cv id "$P"/camerfirma/*.cer "$P"/dnie/*.crt "$P"/fnmt/componentes/*.cer \
  good.crt ec_good.crt ca.crt root.crt fnmt_noaia.crt fnmt_aia.crt > java-ids.txt
# Petición OCSP de BouncyCastle (sin nonce) para good.crt.
cv ocspreq good.crt ca.crt > java-ocspreq-good.txt
# Análisis de respuestas OCSP (Java no comprueba firma, CertID ni fechas).
cv analyze resp_*.der > java-analyze.txt
# CRL por file: (Java solo verifica la firma si conoce la clave del emisor).
{
  for c in good revoked crlonly crlonly_revoked; do
    echo "$c ca ca.crl $(cv crl $c.crt ca.crt ca.crl)"
    echo "$c - ca.crl $(cv crl $c.crt - ca.crl)"
    echo "$c ca ca_fake.crl $(cv crl $c.crt ca.crt ca_fake.crl)"
    echo "$c - ca_fake.crl $(cv crl $c.crt - ca_fake.crl)"
    echo "$c ca ca_stale.crl $(cv crl $c.crt ca.crt ca_stale.crl)"
    echo "$c ca noexiste.crl $(cv crl $c.crt ca.crt noexiste.crl)"
  done
} > java-crl.txt
# Validación completa sin red: tabla de Java (sin AIA -> error al crear el
# validador; CA de la tabla que no firmó el certificado -> CA_NOT_SUPPORTED) y
# periodo de validez.
cv validate fnmt_aia.crt fnmt_noaia.crt expired.crt notyet.crt > java-validate.txt
# Periodo de validez.
cv period good.crt expired.crt notyet.crt > java-period.txt
ls -1 java-*.txt
