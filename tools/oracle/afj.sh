#!/bin/sh
# Ejecuta la AutoFirma Java original (compilada desde los módulos afirma-* de
# este repositorio) en modo línea de comandos, como oráculo de pruebas.
#   AFIRMA_JAR=/ruta/autofirma.jar tools/oracle/afj.sh sign -i in -o out -format cades \
#       -store pkcs12:testdata/pki/firmante-rsa.p12 -password 12341234 -alias firmante-rsa
# Para compilarla: mvn install -DskipTests && mvn install -DskipTests -Denv=install -P autofirma
: "${AFIRMA_JAR:?Define AFIRMA_JAR con la ruta de autofirma.jar}"
exec java -Djava.awt.headless=true -jar "$AFIRMA_JAR" "$@" 2>&1 \
  | grep -v -E '^(INFO|WARNING|ADVERTENCIA|[A-Z][a-z]{2} [0-9]+, [0-9]{4})'
