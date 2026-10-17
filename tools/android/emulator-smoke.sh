#!/usr/bin/env bash
# Parte de tools/android/emulator-test.sh que se ejecuta DENTRO del contenedor del emulador
# (imagen autofirma-android-emulator). Entradas: /work/app.apk; salidas en /out (captura.png,
# selector.png, intent.png, logcat.txt, emulator.log). Variables: HOST_UID/HOST_GID (dueño de
# las salidas), TLS_CHECK (URL opcional), BOOT_TIMEOUT (segundos).
set -euo pipefail
export LC_ALL=C.UTF-8

APK=/work/app.apk
OUT=/out
PKG=io.github.autofirma_rs.android
BOOT_TIMEOUT="${BOOT_TIMEOUT:-600}"
EMULATOR_PID=""

info() {
    printf '==> %s\n' "$*" >&2
}

finish() {
    local status=$?
    adb logcat -d -v threadtime > "$OUT/logcat.txt" 2> /dev/null || true
    adb logcat -d -b crash > "$OUT/logcat-crash.txt" 2> /dev/null || true
    if [ -n "$EMULATOR_PID" ]; then
        adb emu kill > /dev/null 2>&1 || kill "$EMULATOR_PID" 2> /dev/null || true
        wait "$EMULATOR_PID" 2> /dev/null || true
    fi
    if [ -n "${HOST_UID:-}" ]; then
        chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$OUT" 2> /dev/null || true
    fi
    if [ "$status" != 0 ]; then
        printf 'ERROR: la prueba ha fallado; últimas líneas de la aplicación:\n' >&2
        grep -E ' (AutoFirma|RustStdoutStderr|AndroidRuntime|DEBUG) ' "$OUT/logcat.txt" 2> /dev/null | tail -n 60 >&2 || true
    fi
    exit "$status"
}
trap finish EXIT

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# Mensajes de la aplicación (Rust y Java usan la etiqueta AutoFirma).
app_log() {
    adb logcat -d -s 'AutoFirma:*' 'RustStdoutStderr:*' 2> /dev/null | tr -d '\r'
}

# Espera hasta $2 segundos a que el registro de la aplicación contenga la expresión $1.
wait_log() {
    local pattern="$1" timeout="$2" i
    for ((i = 0; i < timeout; i++)); do
        if app_log | grep -Eq "$pattern"; then
            app_log | grep -E "$pattern" | tail -n 1 | sed 's/^/    /' >&2
            return 0
        fi
        check_alive
        sleep 1
    done
    fail "no apareció en logcat: $pattern"
}

check_alive() {
    if adb logcat -d -b crash 2> /dev/null | grep -q "$PKG"; then
        fail "la aplicación se ha cerrado inesperadamente (logcat -b crash)"
    fi
}

screenshot() {
    adb exec-out screencap -p > "$OUT/$1"
    [ -s "$OUT/$1" ] || fail "captura vacía: $1"
    info "Captura: $1"
}

# Pulsa el botón de la interfaz egui cuyo texto es $1, en la posición (píxeles) que registra
# la aplicación al dibujarlo.
tap_button() {
    local coords x y
    coords="$(app_log | grep -Eo "$1» en x=[0-9]+ y=[0-9]+" | tail -n 1)"
    [ -n "$coords" ] || fail "la aplicación no registró la posición del botón «$1»"
    x="$(sed -E 's/.*x=([0-9]+).*/\1/' <<< "$coords")"
    y="$(sed -E 's/.*y=([0-9]+).*/\1/' <<< "$coords")"
    adb shell input tap "$x" "$y"
}

# Ventana con el foco (paquete/actividad).
focused_window() {
    adb shell dumpsys window 2> /dev/null | tr -d '\r' | grep -E 'mCurrentFocus=' | tail -n 1
}

info "Arrancando el emulador (API ${AUTOFIRMA_SYSTEM_IMAGE_API:-?}, x86_64, KVM)"
emulator -avd autofirma -no-window -no-audio -no-boot-anim -no-snapshot -no-metrics \
    -gpu swiftshader_indirect -accel on -camera-back none -camera-front none \
    > "$OUT/emulator.log" 2>&1 &
EMULATOR_PID=$!

adb start-server > /dev/null 2>&1
booted=0
for ((i = 0; i < BOOT_TIMEOUT; i += 2)); do
    kill -0 "$EMULATOR_PID" 2> /dev/null || { tail -n 30 "$OUT/emulator.log" >&2; fail "el emulador ha terminado"; }
    if [ "$(adb shell getprop sys.boot_completed 2> /dev/null | tr -d '\r')" = 1 ]; then
        booted=1
        break
    fi
    sleep 2
done
[ "$booted" = 1 ] || fail "el emulador no arrancó en $BOOT_TIMEOUT s"
info "Emulador listo ($(adb shell getprop ro.build.version.release | tr -d '\r'), API $(adb shell getprop ro.build.version.sdk | tr -d '\r'))"
for scale in window_animation_scale transition_animation_scale animator_duration_scale; do
    adb shell settings put global "$scale" 0
done
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard > /dev/null 2>&1 || true

info "Instalando el APK"
adb install -r -g "$APK" > /dev/null
adb logcat -c
if [ -n "${TLS_CHECK:-}" ]; then
    # La comprobación se hace al arrancar la aplicación: antes, la red del emulador tiene que
    # estar lista (resuelve el nombre del servidor).
    host="$(sed -E 's|^[a-z]+://([^/:?#]+).*|\1|' <<< "$TLS_CHECK")"
    for ((i = 0; i < 60; i++)); do
        adb shell ping -c 1 -W 2 "$host" > /dev/null 2>&1 && break
        sleep 1
    done
    adb shell setprop debug.autofirma.tls_check "$TLS_CHECK"
fi

info "1. Arranque y primer fotograma"
adb shell am start -W -n "$PKG/.MainActivity" > /dev/null
wait_log 'AutoFirma-rs .* para Android iniciado' 60
wait_log 'Primer fotograma de la interfaz' 60
sleep 3
screenshot captura.png

info "2. Rust -> Java: botón «Abrir documento» -> selector del sistema"
tap_button 'Abrir documento'
wait_log 'Selector de documentos abierto' 30
for ((i = 0; i < 30; i++)); do
    focused_window | grep -qi 'documentsui' && break
    sleep 1
done
focused_window | grep -qi 'documentsui' || fail "no se abrió el selector de documentos ($(focused_window))"
sleep 2
screenshot selector.png

info "3. Java -> Rust: cancelar el selector"
adb shell input keyevent KEYCODE_BACK
wait_log 'Selector de documentos cancelado' 30

info "4. KeyChain: botón «Elegir certificado» -> selector del sistema -> cancelar"
tap_button 'Elegir certificado'
wait_log 'Selector de certificados abierto' 30
# Sin certificados instalados, KeyChainActivity se abre y responde «ninguno» al momento; si
# muestra el diálogo, se cierra con Atrás.
for ((i = 0; i < 10; i++)); do
    app_log | grep -q 'Selector de certificados cerrado sin elegir' && break
    if ! focused_window | grep -q "$PKG"; then
        info "    Ventana: $(focused_window | sed 's/^ *//')"
        sleep 2
        # KeyChainActivity es transparente y se cierra sola si no hay certificados.
        if ! focused_window | grep -q "$PKG"; then
            screenshot keychain.png
            adb shell input keyevent KEYCODE_BACK
        fi
        break
    fi
    sleep 1
done
wait_log 'Selector de certificados cerrado sin elegir' 30
adb logcat -d 2> /dev/null | grep -q 'Displayed com.android.keychain/.KeyChainActivity' \
    || fail "no se abrió la actividad de KeyChain del sistema"

info "5. Intent afirma://"
adb shell "am start -W -a android.intent.action.VIEW -d 'afirma://sign?op=sign&id=prueba' $PKG" > /dev/null
wait_log 'Petición web recibida: Operación «sign»' 30
sleep 2
screenshot intent.png

if [ -n "${TLS_CHECK:-}" ]; then
    info "6. Verificación TLS del sistema ($TLS_CHECK)"
    wait_log 'Comprobación TLS (correcta|fallida)' 60
    app_log | grep -q 'Comprobación TLS correcta' || fail "la comprobación TLS ha fallado"
fi

info "7. Atrás deja la aplicación en segundo plano y se vuelve a abrir sin reiniciarse"
pid="$(adb shell pidof "$PKG" | tr -d '\r')"
adb shell input keyevent KEYCODE_BACK
sleep 2
focused_window | grep -q "$PKG" && fail "la aplicación sigue en primer plano tras pulsar Atrás"
adb shell am start -W -n "$PKG/.MainActivity" > /dev/null
sleep 2
focused_window | grep -q "$PKG" || fail "la aplicación no volvió al primer plano ($(focused_window))"
[ "$(adb shell pidof "$PKG" | tr -d '\r')" = "$pid" ] || fail "el proceso de la aplicación se ha reiniciado"
[ "$(app_log | grep -c 'para Android iniciado')" = 1 ] || fail "android_main se ha ejecutado más de una vez"

info "8. Arranque en frío desde un enlace afirma://"
adb shell am force-stop "$PKG"
adb shell "am start -W -a android.intent.action.VIEW -d 'afirma://selectcert?id=prueba' $PKG" > /dev/null
wait_log 'Petición web recibida: Operación «selectcert»' 60
[ "$(app_log | grep -c 'para Android iniciado')" = 2 ] || fail "no se arrancó un proceso nuevo con el enlace"

info "9. Sin cierres inesperados"
sleep 2
check_alive
adb shell pidof "$PKG" > /dev/null || fail "el proceso de la aplicación ya no existe"
if app_log | grep -Eq 'Error interno \(pánico\)|panicked at'; then
    fail "pánico de Rust en el registro"
fi
info "Prueba de humo superada"
