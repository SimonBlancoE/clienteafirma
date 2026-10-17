#!/bin/sh
# Simulador de DNIe por NFC (tarjeta en software) contra el JMulticard real: compila
# JMulticard 2.1 en un commit fijo, ejecuta el flujo de firma de firma-android
# (DnieFactory -> DnieNfc) y deja las transcripciones de APDU anotadas por capa en
# <directorio de trabajo>/transcripts. Sirve de oráculo para la implementación en Rust.
# Cambian en cada ejecución (PACE usa números aleatorios); las de referencia que cita
# docs/spec/10-dnie-nfc.md están en testdata/dnie/.
#
# Uso: tools/oracle/dnie/run.sh [directorio de trabajo]   (STRESS=n para las pruebas de carga;
#      BUILD_ONLY=1 solo compila, para la prueba cruzada de crates/afirma-dnie/tests/oracle.rs)
# Requiere git y un JDK (javac/java).
set -eu
D=$(cd "$(dirname "$0")" && pwd)
W=${1:-${TMPDIR:-/tmp}/autofirma-dnie-oracle}
JMULTICARD_COMMIT=4ec9494f181a2e94d4aeaf62b63a30bcd98f4624
mkdir -p "$W"
if [ ! -d "$W/jmulticard" ]; then
    git clone -q https://github.com/ctt-gob-es/jmulticard.git "$W/jmulticard"
fi
git -C "$W/jmulticard" checkout -q "$JMULTICARD_COMMIT"
if [ ! -d "$W/classes" ]; then
    find "$W/jmulticard/jmulticard/src/main/java" "$W/jmulticard/jmulticard-crypto/src/main/java" \
        -name '*.java' >"$W/srcs.txt"
    javac -nowarn -encoding UTF-8 -d "$W/classes" @"$W/srcs.txt"
fi
mkdir -p "$W/out"
javac -nowarn -encoding UTF-8 -cp "$W/classes" -d "$W/out" "$D"/src/sim/*.java
# BUILD_ONLY=1: solo compilar (lo usa la prueba cruzada Rust, AFIRMA_DNIE_ORACLE=<directorio>).
if [ "${BUILD_ONLY:-0}" = 1 ]; then
    exit 0
fi
J="java -cp $W/out:$W/classes"
T="$W/transcripts"
mkdir -p "$T"
$J sim.Main flow "$D/data" "$T/transcript_full.txt"
$J sim.Main r1 "$D/data" "$T/transcript_r1.txt"
$J sim.Main wrongpin "$D/data" "$T/transcript_wrongpin.txt"
$J sim.Main outer63 "$D/data" "$T/transcript_outer63.txt"
$J sim.Main case1 "$D/data" "$T/transcript_case1.txt"
$J sim.Main detect "$D/data" "$T/transcript_detect.txt"
$J sim.Main rng "$D/data"
$J sim.Main stress "$D/data" "${STRESS:-3000}"
$J sim.Main signstress "$D/data" "${STRESS:-3000}"
