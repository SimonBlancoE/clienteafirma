#!/bin/sh
# Pruebas reales de afirma-keystores con SoftHSM2 (PKCS#11) y NSS dentro de
# un contenedor Debian derivado de la imagen autofirma-cross (que ya tiene
# Rust), con softhsm2, opensc y las herramientas de NSS (certutil, pk12util,
# modutil).
#
#   tools/oracle/keystores-softhsm.sh                 # todas las pruebas del crate
#   tools/oracle/keystores-softhsm.sh softhsm         # solo las de SoftHSM
#   AFIRMA_SOFTHSM_WS=/ruta/espacio tools/oracle/keystores-softhsm.sh
#       (espacio de trabajo alternativo; se monta en la misma ruta)
#
# Las pruebas PKCS#11 con token son opcionales: solo se ejecutan si existe la
# variable AFIRMA_TEST_SOFTHSM_LIB con la ruta de libsofthsm2.so y
# SOFTHSM2_CONF apunta a una configuración con un directorio de tokens
# escribible. Este script prepara ambas cosas. Los tokens ("afirma" y uno con
# etiqueta de DNIe) se inicializan y las claves de testdata/pki se importan
# desde las propias pruebas (C_InitToken, C_CreateObject).
#
# Fuera de Docker basta con instalar SoftHSM2 y exportar las dos variables:
#   export SOFTHSM2_CONF=/tmp/softhsm2.conf   # directories.tokendir = /tmp/tokens
#   export AFIRMA_TEST_SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so
#   cargo test -p afirma-keystores -- --test-threads=1
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WS=${AFIRMA_SOFTHSM_WS:-$ROOT}
IMAGE=afirma-softhsm:latest
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" - <<'DOCKERFILE'
FROM autofirma-cross:latest
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      softhsm2 opensc libnss3-tools libnss3 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi
FILTER=${1:-}
docker run --rm \
  -v "$ROOT":"$ROOT" -v "$WS":"$WS" \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR="$ROOT/target/agents/afirma-keystores-softhsm" \
  -w "$WS" "$IMAGE" sh -c "
    mkdir -p /tmp/softhsm/tokens &&
    printf 'directories.tokendir = /tmp/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > /tmp/softhsm/softhsm2.conf &&
    export SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf AFIRMA_TEST_SOFTHSM_LIB=/usr/lib/softhsm/libsofthsm2.so &&
    cargo test -p afirma-keystores -- --test-threads=1 $FILTER"
