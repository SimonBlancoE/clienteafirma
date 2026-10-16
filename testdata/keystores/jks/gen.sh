#!/bin/sh
# Regenera los ficheros de prueba del módulo `jks` de afirma-keystores
# (almacén de confianza ~/.afirma/TrustedCertsKeystore.jks).
#
#   [AFIRMA_JAR=/ruta/autofirma.jar] testdata/keystores/jks/gen.sh
#
# Necesita openssl y keytool. Con AFIRMA_JAR regenera además el almacén que
# crea AutoFirma Java (TrustStoreManager, tools/oracle/TrustStoreOracle.java).
#
#   a.crt, a2.crt   Mismo titular ("Raíz Pruebas JKS"), claves distintas.
#   b.crt           Otro titular.
#   emoji.crt       Titular con un carácter fuera del BMP (pares sustitutos en
#                   el UTF-8 modificado de JKS).
#   keytool.jks     Creado con keytool (JKS, "changeit"): "Mi Raíz" (a.crt),
#                   "otra" (b.crt) y una PrivateKeyEntry "clave".
#   keytool.txt     Salida de `keytool -list` (alias en minúsculas).
#   java-truststore.jks / .txt   Almacén de TrustStoreManager tras importar
#                   a, a2, b, emoji y a (repetido), y su lista "alias<TAB>SHA-256".
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../../.. && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

mk() {
  openssl req -new -x509 -utf8 -newkey rsa:2048 -nodes -keyout "$W/$1.key" -subj "$2" -days 7300 -sha256 \
    -out "$1.crt" 2>/dev/null
}
mk a "/C=ES/O=AutoFirma-rs Pruebas/CN=Raíz Pruebas JKS"
mk a2 "/C=ES/O=AutoFirma-rs Pruebas/CN=Raíz Pruebas JKS"
mk b "/C=ES/O=AutoFirma-rs Pruebas/CN=Otra CA JKS"
mk emoji "/C=ES/O=AutoFirma-rs Pruebas/CN=Prueba 😀 JKS"

KT="keytool -J-Duser.language=en -J-Dfile.encoding=UTF-8 -J-Dstdout.encoding=UTF-8"
rm -f keytool.jks
$KT -importcert -noprompt -keystore keytool.jks -storetype JKS -storepass changeit -alias "Mi Raíz" -file a.crt 2>/dev/null
$KT -importcert -noprompt -keystore keytool.jks -storetype JKS -storepass changeit -alias otra -file b.crt 2>/dev/null
$KT -genkeypair -keystore keytool.jks -storetype JKS -storepass changeit -keypass changeit -alias clave \
  -keyalg RSA -keysize 2048 -dname "CN=Clave JKS, C=ES" -validity 7300 2>/dev/null
$KT -list -keystore keytool.jks -storepass changeit 2>/dev/null | grep -E "Entry|entries" > keytool.txt

if [ -n "${AFIRMA_JAR:-}" ]; then
  # TrustStoreManager no crea ~/.afirma (lo crea la aplicación al arrancar).
  mkdir -p "$W/classes" "$W/home/.afirma"
  javac -encoding UTF-8 -cp "$AFIRMA_JAR" -d "$W/classes" "$ROOT/tools/oracle/TrustStoreOracle.java"
  J="java -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -Duser.home=$W/home -cp $AFIRMA_JAR:$W/classes TrustStoreOracle"
  $J import a.crt a2.crt b.crt emoji.crt a.crt 2>/dev/null
  cp "$W/home/.afirma/TrustedCertsKeystore.jks" java-truststore.jks
  $J list java-truststore.jks > java-truststore.txt 2>/dev/null
fi
ls -1
