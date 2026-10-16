#!/usr/bin/env bash
# Arranque de la interfaz en un X virtual: segundos hasta que aparece una
# ventana cuyo título contiene <título>, y memoria (RSS) del proceso tras 10 s.
# Guarda una captura en <captura.png>.
#
#   tools/bench/gui_startup.sh <título> <captura.png> <comando...>
set -euo pipefail
TITLE=$1; SHOT=$2; shift 2
W=$(mktemp -d); trap 'kill $APID $XPID 2>/dev/null || true; rm -rf "$W"' EXIT
Xvfb -displayfd 3 -screen 0 1280x860x24 -nolisten tcp 3>"$W/d" 2>/dev/null &
XPID=$!
for _ in $(seq 50); do [ -s "$W/d" ] && break; sleep 0.1; done
export DISPLAY=":$(head -1 "$W/d")" LIBGL_ALWAYS_SOFTWARE=1 WINIT_UNIX_BACKEND=x11
unset WAYLAND_DISPLAY
mkdir -p "$W/home"
start=$(date +%s.%N)
HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" XDG_DATA_HOME="$W/home/.local/share" "$@" >/dev/null 2>&1 &
APID=$!
shown=""
for _ in $(seq 1200); do
  if xdotool search --onlyvisible --name "$TITLE" >/dev/null 2>&1; then shown=$(date +%s.%N); break; fi
  sleep 0.05
done
[ -n "$shown" ] || { echo "la ventana no ha aparecido"; exit 1; }
sleep 10
rss=$(ps -o rss= --pid "$APID" | tr -d ' ')
# Procesos hijos (p. ej., el lanzador de Java).
for c in $(pgrep -P "$APID" || true); do rss=$((rss + $(ps -o rss= --pid "$c" | tr -d ' '))); done
import -window root "$SHOT"
awk -v a="$start" -v b="$shown" -v m="$rss" 'BEGIN { printf "ventana en %.2f s · memoria tras 10 s: %d MB\n", b-a, m/1024 }'
