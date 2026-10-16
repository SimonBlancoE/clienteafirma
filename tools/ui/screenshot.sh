#!/bin/bash
# Lanza AutoFirma-rs en un servidor X virtual propio y guarda una captura.
#   tools/ui/screenshot.sh <binario> <salida.png> [segundos] [args...]
# Variables: AF_SIZE (por defecto 1280x820), AF_LOG (registro de la app).
set -euo pipefail
BIN=$1; OUT=$2; WAIT=${3:-6}; shift 3 || shift $#
SIZE=${AF_SIZE:-1280x820}
# -displayfd elige un display libre (no choca con otros Xvfb en marcha).
DFILE=$(mktemp)
Xvfb -displayfd 3 -screen 0 "${SIZE}x24" -nolisten tcp 3>"$DFILE" 2>/dev/null &
XPID=$!
for _ in $(seq 1 50); do [ -s "$DFILE" ] && break; sleep 0.1; done
DISP=":$(head -1 "$DFILE")"; rm -f "$DFILE"
APID=""
trap 'kill $APID $XPID 2>/dev/null || true' EXIT
DISPLAY=$DISP WAYLAND_DISPLAY= WINIT_UNIX_BACKEND=x11 LIBGL_ALWAYS_SOFTWARE=1 "$BIN" "$@" >"${AF_LOG:-/dev/null}" 2>&1 &
APID=$!
sleep "$WAIT"
DISPLAY=$DISP import -window root "$OUT"
echo "captura: $OUT"
