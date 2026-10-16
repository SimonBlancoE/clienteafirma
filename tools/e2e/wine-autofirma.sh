#!/bin/sh
# Ejecuta el autofirma.exe de Windows en Wine (Docker) con la red y la
# pantalla del anfitrión, para usarlo como binario de tools/e2e/web_sign.py:
#
#   AUTOFIRMA_EXE=target/x86_64-pc-windows-gnu/debug/autofirma.exe \
#     tools/e2e/web_sign.py tools/e2e/wine-autofirma.sh /tmp/e2e-win
#
# Como en una instalación con el MSI, autofirma.pfx se coloca junto al .exe.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
EXE=$(realpath "${AUTOFIRMA_EXE:?indica AUTOFIRMA_EXE}")
APP=$(mktemp -d)
cp -f "$EXE" "$APP/autofirma.exe"
cp -f "$HOME/.afirma/Autofirma/autofirma.pfx" "$APP/autofirma.pfx"
exec docker run --rm --init --network host -v /tmp/.X11-unix:/tmp/.X11-unix -e DISPLAY="$DISPLAY" \
  -v "$ROOT:/src:ro" -v "$APP:/app" -e WINEDEBUG=-all \
  -e 'AF_STORE=pkcs12:Z:\src\testdata\pki\firmante-rsa.p12' \
  "${WINE_IMAGE:-autofirma-wine10}" wine /app/autofirma.exe "$1"
