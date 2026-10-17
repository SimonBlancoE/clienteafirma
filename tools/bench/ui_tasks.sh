#!/usr/bin/env bash
# Pasos por tarea en la interfaz gráfica: maneja AutoFirma Java y AutoFirma-rs
# con xdotool en un X virtual (Xvfb) y cuenta, en cada tarea, los clics, los
# campos que hay que escribir y los diálogos en los que hay que actuar. Al
# terminar cada tarea comprueba el resultado (firma válida y, en PDF, visible;
# preferencia guardada), imprime una tabla en Markdown y guarda las capturas de
# las pantallas clave en <capturas> (por defecto, docs/img).
#
#   AFIRMA_JAR=/ruta/autofirma.jar tools/bench/ui_tasks.sh <autofirma-rs> [capturas]
#
# AF_TASKS (pdf, multi, verify, prefs) y AF_APPS (java, rs) limitan lo que se
# ejecuta; AF_DEBUG=<carpeta> guarda allí una captura tras cada paso. Si un paso
# falla, la captura de la pantalla queda en <capturas>/fallo-<tarea>-<app>.png.
#
# Necesita Xvfb, xdotool, ImageMagick, java, dbus-daemon, xdg-desktop-portal y
# xdg-desktop-portal-gtk (el selector de ficheros de AutoFirma-rs es el del
# portal del escritorio); pngquant y pdftoppm son opcionales.
#
# Las dos aplicaciones arrancan con una ventana de 1100×740 centrada en una
# pantalla de 1280×900 y un perfil de usuario nuevo con las mismas preferencias
# (formato Java, que AutoFirma-rs migra): para firmar, el almacén por defecto es
# testdata/pki/firmante-rsa.p12 y las dos piden su contraseña; los diálogos de
# ficheros se abren en la carpeta de los documentos. Las coordenadas son las de
# esa disposición: un cambio de diseño obliga a revisarlas (con AF_DEBUG).
#
# Qué se cuenta: un clic por cada pulsación de ratón (botones, casillas, menús,
# ficheros de la lista), un arrastre al dibujar el recuadro de la firma visible,
# un desplazamiento por cada vez que hay que mover la página con la rueda, una
# entrada de teclado por cada campo escrito (la tecla Intro que lo confirma no
# cuenta aparte) y una ventana por cada ventana o diálogo, propio o superpuesto
# a la ventana principal, que se abre durante la tarea (no los de progreso).
# Son las interacciones necesarias, no tiempos de una persona.
set -euo pipefail
: "${AFIRMA_JAR:?Define AFIRMA_JAR con la ruta de autofirma.jar}"
RS=$(realpath "$1")
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SHOTS=$(realpath -m "${2:-$ROOT/docs/img}")
P12="$ROOT/testdata/pki/firmante-rsa.p12"
W=$(mktemp -d)
XPID=""; DPID=""; APID=""
cleanup() {
  [ -n "$APID" ] && kill "$APID" 2>/dev/null || true
  [ -n "$DPID" ] && { pkill -P "$DPID" 2>/dev/null || true; kill "$DPID" 2>/dev/null || true; }
  [ -n "$XPID" ] && kill "$XPID" 2>/dev/null || true
  pkill -f "$W/run" 2>/dev/null || true
  sleep 1
  # El portal de documentos y gvfs montan sistemas FUSE en $XDG_RUNTIME_DIR.
  local m
  for m in "$W/run/doc" "$W/run/gvfs"; do
    fusermount -uz "$m" 2>/dev/null || fusermount3 -uz "$m" 2>/dev/null || true
  done
  rm -rf "$W" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "$SHOTS"
[ -n "${AF_DEBUG:-}" ] && mkdir -p "$AF_DEBUG"

# X virtual propio (-displayfd elige un número libre).
Xvfb -displayfd 3 -screen 0 1280x900x24 -nolisten tcp 3>"$W/d" 2>/dev/null &
XPID=$!
for _ in $(seq 50); do [ -s "$W/d" ] && break; sleep 0.1; done
export DISPLAY=":$(head -1 "$W/d")" LIBGL_ALWAYS_SOFTWARE=1 WINIT_UNIX_BACKEND=x11 NO_AT_BRIDGE=1
unset WAYLAND_DISPLAY

# Bus de sesión propio con el portal GTK (selector de ficheros de AutoFirma-rs);
# así nunca se usa el escritorio real del usuario.
mkdir -p "$W/portal/cfg/xdg-desktop-portal" "$W/run"; chmod 700 "$W/run"
printf '[preferred]\ndefault=gtk\n' >"$W/portal/cfg/xdg-desktop-portal/portals.conf"
env HOME="$W/portal" XDG_CONFIG_HOME="$W/portal/cfg" XDG_RUNTIME_DIR="$W/run" \
  GSETTINGS_BACKEND=memory GIO_USE_VFS=local LANG=es_ES.UTF-8 GTK_A11Y=none \
  dbus-daemon --session --fork --print-address=1 --print-pid=1 >"$W/bus"
DPID=$(sed -n 2p "$W/bus")
export DBUS_SESSION_BUS_ADDRESS=$(head -1 "$W/bus") XDG_RUNTIME_DIR="$W/run"

# Almacén para la conexión con el navegador de AutoFirma Java: sin él muestra un
# error al arrancar (véase «Primer arranque» en docs/COMPARISON.md).
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/k.pem" -out "$W/c.pem" -days 30 \
  -subj "/CN=127.0.0.1" 2>/dev/null
openssl pkcs12 -export -inkey "$W/k.pem" -in "$W/c.pem" -out "$W/autofirma.pfx" \
  -passout pass:654321 -name socketautofirma

# ImageMagick 7 (magick) o 6 (convert/compare).
if command -v magick >/dev/null; then IM=(magick); CMP=(magick compare); else IM=(convert); CMP=(compare); fi

# --- Contadores y acciones ---------------------------------------------------
CLICKS=0; DRAGS=0; SCROLLS=0; KEYS=0; DIALOGS=0; STEP=0; FOCUS=""
reset_counts() { CLICKS=0; DRAGS=0; SCROLLS=0; KEYS=0; DIALOGS=0; STEP=0; }
debug_shot() {
  [ -n "${AF_DEBUG:-}" ] || return 0
  STEP=$((STEP + 1)); import -window root "$AF_DEBUG/$TASK-$APP-$(printf %02d $STEP).png"
}
click() { xdotool mousemove "$1" "$2" click 1; CLICKS=$((CLICKS + 1)); sleep "${3:-1}"; debug_shot; }
shift_click() {
  xdotool mousemove "$1" "$2" keydown shift click 1 keyup shift; CLICKS=$((CLICKS + 1)); sleep 0.5; debug_shot
}
drag() { # x1 y1 x2 y2
  xdotool mousemove "$1" "$2" mousedown 1
  for i in 1 2 3 4 5 6 7 8; do
    xdotool mousemove $(($1 + ($3 - $1) * i / 8)) $(($2 + ($4 - $2) * i / 8)); sleep 0.05
  done
  sleep 0.2; xdotool mouseup 1; DRAGS=$((DRAGS + 1)); sleep 1; debug_shot
}
scroll() { # x y muescas
  xdotool mousemove "$1" "$2"; for _ in $(seq "$3"); do xdotool click 5; sleep 0.15; done
  SCROLLS=$((SCROLLS + 1)); sleep 1; debug_shot
}
# Escribe un campo y lo confirma con Intro. Sin gestor de ventanas, el foco del
# teclado se da explícitamente a la ventana de egui (no cuenta como acción).
write() {
  [ -n "$FOCUS" ] && xdotool windowfocus --sync "$FOCUS" 2>/dev/null || true
  xdotool type --delay 40 "$1"; xdotool key Return; KEYS=$((KEYS + 1)); sleep 1.5; debug_shot
}
# Espera a que aparezca (o desaparezca) una ventana cuyo título casa con $1.
wait_win() {
  for _ in $(seq 300); do
    xdotool search --onlyvisible --name "$1" >/dev/null 2>&1 && { sleep 0.8; return 0; }
    sleep 0.1
  done
  fail "no aparece la ventana «$1»"
}
wait_gone() {
  for _ in $(seq 300); do
    xdotool search --onlyvisible --name "$1" >/dev/null 2>&1 || { sleep 0.5; return 0; }
    sleep 0.1
  done
}
# Una ventana o diálogo que se abre; con título, se espera a que sea visible.
dialog() { DIALOGS=$((DIALOGS + 1)); [ -n "${1:-}" ] && wait_win "$1"; return 0; }

# Captura recortada al conjunto de ventanas visibles, con la paleta reducida.
capture() {
  local x0=9999 y0=9999 x1=0 y1=0 id X Y WIDTH HEIGHT
  for id in $(xdotool search --onlyvisible --name . 2>/dev/null); do
    eval "$(xdotool getwindowgeometry --shell "$id")"
    [ "$WIDTH" -gt 50 ] && [ "$HEIGHT" -gt 50 ] || continue
    [ "$X" -lt "$x0" ] && x0=$X; [ "$Y" -lt "$y0" ] && y0=$Y
    [ $((X + WIDTH)) -gt "$x1" ] && x1=$((X + WIDTH)); [ $((Y + HEIGHT)) -gt "$y1" ] && y1=$((Y + HEIGHT))
  done
  x0=$((x0 < 0 ? 0 : x0)); y0=$((y0 < 0 ? 0 : y0)); x1=$((x1 > 1280 ? 1280 : x1)); y1=$((y1 > 900 ? 900 : y1))
  import -window root -crop "$((x1 - x0))x$((y1 - y0))+$x0+$y0" +repage "$W/shot.png"
  command -v pngquant >/dev/null &&
    pngquant --force --strip --quality=50-85 --output "$SHOTS/$1.png" "$W/shot.png" ||
    "${IM[@]}" "$W/shot.png" -colors 128 "$SHOTS/$1.png"
}

# --- Perfil, arranque y comprobaciones ---------------------------------------
pref_xml() { # fichero clave=valor...
  mkdir -p "$(dirname "$1")"; local f=$1; shift
  { echo '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
    echo '<!DOCTYPE map SYSTEM "http://java.sun.com/dtd/preferences.dtd">'
    echo '<map MAP_XML_VERSION="1.0">'
    for kv in "$@"; do echo "  <entry key=\"${kv%%=*}\" value=\"${kv#*=}\"/>"; done
    echo '</map>'; } >"$f"
}
# Perfil nuevo en $T/home y documentos en $T/docs. Con «p12», el almacén por
# defecto es el PKCS#12 de pruebas.
profile() {
  T="$W/$TASK-$APP"; H="$T/home"; DOCS="$T/docs"; mkdir -p "$H/.afirma/Autofirma" "$DOCS"
  local prefs="$H/.java/.userPrefs/es/gob/afirma"
  local main=(checkForUpdates=false)
  [ "${1:-}" = p12 ] && main+=("defaultKeystore=PKCS#12 / PFX" "defaultLocalKeystorePath=$P12")
  pref_xml "$prefs/standalone/ui/preferences/prefs.xml" "${main[@]}"
  pref_xml "$prefs/ui/core/jse/prefs.xml" "currentDir=$DOCS"
  [ "$APP" = java ] && cp "$W/autofirma.pfx" "$H/.afirma/Autofirma/"
  return 0
}
start_app() {
  local env=(env HOME="$H" XDG_CONFIG_HOME="$H/.config" XDG_DATA_HOME="$H/.local/share" XDG_CACHE_HOME="$H/.cache" LANG=es_ES.UTF-8)
  if [ "$APP" = java ]; then
    "${env[@]}" java -Duser.home="$H" -jar "$AFIRMA_JAR" >"$T/app.log" 2>&1 &
    APID=$!; wait_win '^Autofirma v'
    FOCUS=""; local win; win=$(xdotool search --onlyvisible --name '^Autofirma v' | head -1)
    xdotool windowsize "$win" 1100 740 windowmove "$win" 90 80
  else
    "${env[@]}" "$RS" >"$T/app.log" 2>&1 &
    APID=$!; wait_win '^AutoFirma$'
    FOCUS=$(xdotool search --onlyvisible --name '^AutoFirma$' | head -1)
    xdotool windowmove "$FOCUS" 90 80
  fi
  sleep 2; debug_shot
}
stop_app() { kill "$APID" 2>/dev/null || true; wait "$APID" 2>/dev/null || true; APID=""; sleep 1; }
fail() { echo "$TASK/$APP: $*" >&2; import -window root "$SHOTS/fallo-$TASK-$APP.png"; exit 1; }
valid() { "$RS" verify -i "$1" 2>/dev/null | grep -q '^Valid signature' || fail "firma no válida: $1"; }
# La firma es visible si la página 1 cambia al renderizarla.
visible() {
  command -v pdftoppm >/dev/null || return 0
  pdftoppm -r 30 -png -f 1 -l 1 -singlefile "$DOCS/documento.pdf" "$W/a"
  pdftoppm -r 30 -png -f 1 -l 1 -singlefile "$1" "$W/b"
  local n; n=$("${CMP[@]}" -metric AE "$W/a.png" "$W/b.png" null: 2>&1 || true)
  n=${n%% *}; [ "${n%%.*}" -gt 50 ] || fail "la firma de $1 no es visible"
}
declare -A ROW
record() { # resultado de la tarea en curso
  local c="$CLICKS"
  [ "$DRAGS" -gt 0 ] && c="$c + $DRAGS arrastre"
  [ "$SCROLLS" -gt 0 ] && c="$c + $SCROLLS desplazamiento"
  ROW[$TASK-$APP]="$c | $KEYS | $DIALOGS"
  return 0
}

# --- Tareas ------------------------------------------------------------------
# Las coordenadas son absolutas (ventana principal en 90,80). AutoFirma Java
# centra sus diálogos en la pantalla; el selector del portal GTK ocupa la
# pantalla desde la esquina superior izquierda.

# 1. Firmar un PDF con firma visible y guardar el resultado.
task_pdf_java() {
  profile p12; cp "$ROOT/testdata/protocol/plain.pdf" "$DOCS/documento.pdf"; start_app
  dialog 'Introduzca la contraseña'; write 12341234
  click 224 292; dialog 'Seleccione el fichero a firmar'
  click 432 137 0.4; click 759 377 2                # documento.pdf y «Abrir»
  click 400 519                                     # «Hacer la firma visible dentro del PDF»
  click 639 783; dialog '^Autorizar firma'; click 597 515
  dialog 'Propiedades de la firma visible PDF'
  drag 600 500 750 560; capture java-firma-pdf
  click 724 816 2                                   # «Siguiente»: apariencia
  click 735 774                                     # «Aceptar»
  dialog 'Diálogo de seguridad del almacén'; click 596 592
  dialog 'Guardar fichero firmado'; click 759 621 3 # «Guardar» (nombre propuesto)
  wait_win 'documento_signed.pdf'
  valid "$DOCS/documento_signed.pdf"; visible "$DOCS/documento_signed.pdf"
}
task_pdf_rs() {
  profile p12; cp "$ROOT/testdata/protocol/plain.pdf" "$DOCS/documento.pdf"; start_app
  click 756 411; dialog 'Selecciona los documentos'
  click 222 83 0.4; click 1134 884 2                # documento.pdf y «Abrir»
  click 398 403                                     # «Firma visible en el PDF»
  click 1043 641; dialog; click 817 506 3           # «Firmar documento»: «Continuar»
  dialog; drag 414 559 597 632; capture rs-firma-pdf  # editor de la firma visible
  click 1071 741 2                                  # «Aceptar»
  dialog; dialog; write 12341234                    # selector de certificado y contraseña
  click 886 608 4                                   # «Firmar»
  valid "$DOCS/documento_signed.pdf"; visible "$DOCS/documento_signed.pdf"
}

# 2. Firmar tres ficheros (PDF, XML y texto) con su formato por defecto.
three_files() {
  cp "$ROOT/testdata/protocol/plain.pdf" "$DOCS/documento.pdf"
  cp "$ROOT/testdata/xades/inputs/doc.xml" "$DOCS/datos.xml"
  printf 'Texto de prueba\n' >"$DOCS/notas.txt"
}
task_multi_java() {
  profile p12; three_files; start_app
  dialog 'Introduzca la contraseña'; write 12341234
  click 224 292; dialog 'Seleccione el fichero a firmar'
  click 432 137 0.4; shift_click 430 181; click 759 377 2
  click 639 783; dialog '^Autorizar firma'; click 597 515
  dialog 'Diálogo de seguridad del almacén'; click 596 592
  dialog 'Seleccione el directorio de salida'; click 761 621 4
  wait_win 'Autofirma v.* - /'
  valid "$DOCS/documento_signed.pdf"; valid "$DOCS/datos.xml_signed.xsig"; valid "$DOCS/notas.txt_signed.csig"
}
task_multi_rs() {
  profile p12; three_files; start_app
  click 756 411; dialog 'Selecciona los documentos'
  click 222 83 0.4; shift_click 222 129; click 1134 884 2
  click 1042 752; dialog; click 817 506 3           # «Firmar 3 documentos» y «Continuar»
  dialog; dialog; write 12341234; click 886 608 5   # certificado, contraseña y «Firmar»
  local f
  for f in documento_signed.pdf datos.xml_signed.xsig notas.txt_signed.csig; do valid "$DOCS/$f"; done
}

# 3. Verificar una firma CAdES (creada con la línea de comandos) y ver el firmante.
cades() {
  printf 'Texto de prueba\n' >"$W/notas.txt"
  "$RS" sign -i "$W/notas.txt" -o "$DOCS/notas.txt.csig" -format cades -config "mode=implicit" \
    -store "pkcs12:$P12" -password 12341234 -alias firmante-rsa >/dev/null
}
task_verify_java() {
  profile; cades; start_app
  click 122 115 0.6; click 130 156                  # «Archivo» > «Ver firma»
  dialog 'Abrir firma'; click 440 88 0.4; click 773 328 3
  dialog 'Visor de firmas'; capture java-verificar  # ventana aparte
}
task_verify_rs() {
  profile; cades; start_app
  click 203 244; click 756 406                      # «Verificar firmas» > «Seleccionar firma»
  dialog 'Selecciona la firma'; click 222 83 0.4; click 1134 884 3
  capture rs-verificar
}

# 4. Cambiar el formato por defecto de los ficheros que no son PDF, XML ni Office.
task_prefs_java() {
  profile; start_app
  click 202 115 0.6; click 199 178                  # «Herramientas» > «Preferencias»
  dialog 'Preferencias de configuración'
  click 776 410; dialog '^Formatos de firma'        # «Configurar formatos»
  click 777 501 0.6; click 690 540                  # «Resto de ficheros»: XAdES
  click 596 570; wait_gone '^Formatos de firma'; click 796 761
  grep -q 'key="defaultSignatureFormatBin" value="XAdES"' \
    "$H/.java/.userPrefs/es/gob/afirma/standalone/ui/preferences/prefs.xml" || fail "preferencia no guardada"
}
task_prefs_rs() {
  profile; start_app
  click 194 703; click 423 261                      # «Preferencias» > «Firma»
  scroll 860 600 3
  click 1019 716 0.6; click 950 674                 # «Resto de ficheros»: XAdES
  click 1093 787                                    # «Guardar»
  grep -q '"defaultSignatureFormatBin": "XAdES"' "$H/.config/autofirma/preferences.json" || fail "preferencia no guardada"
}

for TASK in ${AF_TASKS:-pdf multi verify prefs}; do
  for APP in ${AF_APPS:-java rs}; do
    reset_counts; "task_${TASK}_${APP}"; record; stop_app
    echo "$TASK/$APP: ${ROW[$TASK-$APP]}" >&2
  done
done

echo "| Tarea | Aplicación | Clics | Entradas de teclado | Ventanas y diálogos |"
echo "|---|---|---|---|---|"
for t in "pdf:Firmar un PDF con firma visible" "multi:Firmar tres ficheros" \
  "verify:Verificar una firma CAdES" "prefs:Formato por defecto de «otros ficheros»"; do
  echo "| ${t#*:} | AutoFirma Java | ${ROW[${t%%:*}-java]:-— | — | —} |"
  echo "| | AutoFirma-rs | ${ROW[${t%%:*}-rs]:-— | — | —} |"
done
