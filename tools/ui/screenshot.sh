#!/bin/sh
# Lanza AutoFirma-rs en un servidor X virtual y guarda una captura de pantalla.
#   tools/ui/screenshot.sh <binario> <salida.png> [segundos] [args...]
# Variables: AF_SIZE (por defecto 1280x820), AF_THEME (light|dark), AF_PAGE.
set -eu
BIN=$1; OUT=$2; WAIT=${3:-4}; shift 3 || shift $#
SIZE=${AF_SIZE:-1280x820}
DISP=:$(( (RANDOM % 400) + 100 )) 2>/dev/null || DISP=:173
Xvfb "$DISP" -screen 0 "${SIZE}x24" -nolisten tcp >/dev/null 2>&1 &
XPID=$!
trap 'kill $APID $XPID 2>/dev/null || true' EXIT
sleep 1
DISPLAY=$DISP WAYLAND_DISPLAY= WINIT_UNIX_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1 "$BIN" "$@" >"${AF_LOG:-/dev/null}" 2>&1 &
APID=$!
sleep "$WAIT"
DISPLAY=$DISP import -window root "$OUT"
echo "captura: $OUT"
