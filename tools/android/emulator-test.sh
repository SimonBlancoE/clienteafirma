#!/usr/bin/env bash
# Prueba de humo de AutoFirma-rs para Android en el emulador (x86_64, Android 15/API 35 con las
# API de Google), sin ventana, con KVM, dentro de la imagen Docker autofirma-android-emulator
# (tools/android/Dockerfile, objetivo «emulator»).
#
# Instala el APK, abre la aplicación y comprueba con logcat y capturas de pantalla (los
# elementos se pulsan en la posición que registra la aplicación, «Botón «id» en x=… y=…»):
#   1. que arranca (línea «AutoFirma-rs ... para Android iniciado»), egui dibuja el primer
#      fotograma y se pasa por arranque, bienvenida y condiciones (cambiando el idioma al
#      español en su selector) hasta Inicio (captura principal: captura.png);
#   2. Rust → Java: pulsa «Firmar fichero» y espera el selector de documentos del sistema
#      (selector.png);
#   3. Java → Rust: vuelve atrás y espera a que Rust registre la cancelación;
#   4. KeyChain: Certificados → «Ver un certificado», comprueba que se abre KeyChainActivity
#      (sin certificados instalados responde «ninguno» al momento; si muestra el diálogo, se
#      captura en keychain.png y se cierra) y que Rust recibe «sin certificado»;
#   5. intent VIEW afirma://sign?... → Rust lo recibe, lo reparte con afirma-protocol y abre
#      su pantalla (intent.png);
#   6. (opcional, --tls-check) descarga HTTPS con el cliente de afirma-core y la verificación
#      TLS del sistema (solo con el APK de depuración);
#   después recorre todas las pantallas de la interfaz y sus diálogos (Inicio, importación de
#   certificados, firma web, histórico, Ajustes y todas sus pantallas de configuración, ayuda e
#   información), escribe con el teclado en pantalla en «Dominios de confianza» (IME de
#   GameTextInput, Intro, Atrás cierra el teclado) y guarda, cambia el idioma a gallego y de
#   vuelta al español, comprueba con uiautomator que el árbol de accesibilidad (AccessKit)
#   llega a Android, y gira a horizontal y pasa a tema oscuro; y además:
#   7. Atrás en Inicio deja la app en segundo plano y al volver sigue el mismo proceso
#      (android_main no se ejecuta dos veces);
#   8. arranque en frío (tras `am force-stop`) con un enlace afirma://selectcert?..., con el
#      idioma guardado;
#   9. que no hay cierres inesperados (FATAL EXCEPTION, señales, pánicos de Rust).
#
# Deja en --out: captura.png (Inicio), selector.png, intent.png, keychain.png,
# accesibilidad.xml, logcat.txt, logcat-crash.txt y emulator.log; y en --shots una captura
# numerada de cada pantalla y diálogo.
#
# Uso: tools/android/emulator-test.sh [opciones]
#
#   --apk <ruta>        APK que se prueba (por defecto el de depuración de build.sh).
#   --out <dir>         Capturas, logcat y registro del emulador (por defecto
#                       $AUTOFIRMA_ANDROID_BUILD_DIR/emulator).
#   --shots <dir>       Captura de cada pantalla (por defecto <out>/pantallas).
#   --tls-check <url>   Comprobar también la verificación TLS descargando esta URL.
#   --rebuild-image     Reconstruir la imagen Docker aunque ya exista.
#
# Variables: AUTOFIRMA_ANDROID_BUILD_DIR (como en build.sh), AUTOFIRMA_ANDROID_EMULATOR_IMAGE
# (imagen, por defecto autofirma-android-emulator), AUTOFIRMA_EMULATOR_BOOT_TIMEOUT (segundos
# para el arranque, por defecto 600).
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=../package/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../package/common.sh"

BUILD_DIR="${AUTOFIRMA_ANDROID_BUILD_DIR:-$ROOT/target/android}"
IMAGE="${AUTOFIRMA_ANDROID_EMULATOR_IMAGE:-autofirma-android-emulator}"
APK=""
OUT=""
SHOTS=""
TLS_CHECK=""
REBUILD_IMAGE=0

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --apk) APK="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --shots) SHOTS="$2"; shift 2 ;;
        --tls-check) TLS_CHECK="$2"; shift 2 ;;
        --rebuild-image) REBUILD_IMAGE=1; shift ;;
        -h | --help) usage 0 ;;
        *) warn "opción desconocida: $1"; usage 2 ;;
    esac
done

APK="${APK:-$BUILD_DIR/dist/AutoFirma-$(workspace_version)-debug.apk}"
[ -f "$APK" ] || die "no existe el APK $APK (tools/android/build.sh --debug)"
APK="$(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")"
OUT="${OUT:-$BUILD_DIR/emulator}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
SHOTS="${SHOTS:-$OUT/pantallas}"
mkdir -p "$SHOTS"
SHOTS="$(cd "$SHOTS" && pwd)"
[ -e /dev/kvm ] || die "no hay /dev/kvm: el emulador x86_64 necesita KVM"
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    die "sin permiso de lectura y escritura en /dev/kvm"
fi

if [ "$REBUILD_IMAGE" = 1 ] || ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
    info "Construyendo la imagen $IMAGE (tools/android/Dockerfile)"
    docker build -f "$ROOT/tools/android/Dockerfile" --target emulator -t "$IMAGE" "$ROOT/tools/android"
fi

info "Prueba de $(basename "$APK") en el emulador; resultados en $OUT"
docker run --rm --device /dev/kvm \
    -v "$APK:/work/app.apk:ro" \
    -v "$ROOT/tools/android/emulator-smoke.sh:/work/emulator-smoke.sh:ro" \
    -v "$OUT:/out" \
    -v "$SHOTS:/shots" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -e TLS_CHECK="$TLS_CHECK" \
    -e BOOT_TIMEOUT="${AUTOFIRMA_EMULATOR_BOOT_TIMEOUT:-600}" \
    "$IMAGE" bash /work/emulator-smoke.sh
info "Prueba superada: $OUT/captura.png; capturas de las pantallas en $SHOTS"
