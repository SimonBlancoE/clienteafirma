#!/bin/sh
# Ejecuta el oráculo Java de afirma-core (tools/oracle/CoreOracle.java) y
# regenera los ficheros golden de testdata/core/.
#   M2=/ruta/.m2 CORE_JAR=/ruta/afirma-core-1.9.1.jar tools/oracle/core_oracle.sh
set -e
: "${CORE_JAR:?Define CORE_JAR con la ruta de afirma-core-1.9.1.jar}"
: "${M2:?Define M2 con la ruta del repositorio Maven local}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$(mktemp -d)}
CP="$CORE_JAR:$M2/es/gob/afirma/lib/afirma-lib-jmimemagic/0.0.10/afirma-lib-jmimemagic-0.0.10.jar:$M2/es/gob/afirma/lib/afirma-lib-oro/0.0.10/afirma-lib-oro-0.0.10.jar"
javac -encoding UTF-8 -cp "$CP" -d "$OUT" "$ROOT/tools/oracle/CoreOracle.java"
run() { java -Dfile.encoding=UTF-8 -Duser.language=es -Duser.country=ES -cp "$CP:$OUT" CoreOracle "$@" 2>/dev/null; }
run mime "$ROOT/testdata/core/mime" > "$ROOT/testdata/core/mime.golden"
run base64 > "$ROOT/testdata/core/base64.golden"
run props > "$ROOT/testdata/core/props.golden"
run load > "$ROOT/testdata/core/load.golden"
run exp > "$ROOT/testdata/core/exppolicy.golden"
run uri > "$ROOT/testdata/core/uri.golden"
run misc > "$ROOT/testdata/core/misc.golden"
