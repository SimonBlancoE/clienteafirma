#!/bin/sh
# Oráculo de la línea de comandos de la AutoFirma Java para afirma-cli.
#
# A diferencia de afj.sh conserva el código de salida y separa stdout (la salida
# del mandato) de stderr (el registro de Java, que se descarta). Usa un árbol de
# preferencias propio y vacío (no se lee `default.locale` del usuario) y la
# configuración regional indicada en ORACLE_LOCALE (por defecto es_ES).
#   AFIRMA_JAR=/ruta/autofirma.jar tools/oracle/cli_oracle.sh sign -help
#   ORACLE_LOCALE=en_US AFIRMA_JAR=... tools/oracle/cli_oracle.sh -help
: "${AFIRMA_JAR:?Define AFIRMA_JAR con la ruta de autofirma.jar}"
LOC="${ORACLE_LOCALE:-es_ES}"
LANG_PART="${LOC%%_*}"
COUNTRY_PART="${LOC#*_}"
PREFS="${ORACLE_PREFS_DIR:-$(mktemp -d)}"
java -Djava.awt.headless=true -Djava.util.prefs.userRoot="$PREFS" \
  -Duser.language="$LANG_PART" -Duser.country="$COUNTRY_PART" \
  -jar "$AFIRMA_JAR" "$@" 2>/dev/null
STATUS=$?
[ -z "$ORACLE_PREFS_DIR" ] && rm -rf "$PREFS"
exit $STATUS
