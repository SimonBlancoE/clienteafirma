#!/usr/bin/env bash
# Parte de tools/android/emulator-test.sh que se ejecuta DENTRO del contenedor del emulador
# (imagen autofirma-android-emulator). Entradas: /work/app.apk; salidas en /out (captura.png,
# selector.png, intent.png, keychain.png, logcat.txt, emulator.log) y una captura por pantalla
# en /shots. Variables: HOST_UID/HOST_GID (dueño de las salidas), TLS_CHECK (URL opcional),
# BOOT_TIMEOUT (segundos).
set -euo pipefail
export LC_ALL=C.UTF-8

APK=/work/app.apk
OUT=/out
SHOTS=/shots
PKG=io.github.autofirma_rs.android
BOOT_TIMEOUT="${BOOT_TIMEOUT:-600}"
EMULATOR_PID=""
SHOT_NUMBER=0
MARK=0

info() {
    printf '==> %s\n' "$*" >&2
}

finish() {
    local status=$? pid
    adb logcat -d -v threadtime > "$OUT/logcat.txt" 2> /dev/null || true
    adb logcat -d -b crash > "$OUT/logcat-crash.txt" 2> /dev/null || true
    # Si falla con la aplicación viva (¿bloqueada?), pilas de todos sus hilos (Java y nativos;
    # la imagen es userdebug y admite adb root).
    if [ "$status" != 0 ]; then
        adb exec-out screencap -p > "$OUT/fallo.png" 2> /dev/null || true
        {
            adb shell settings get system accelerometer_rotation
            adb shell settings get system user_rotation
            adb shell dumpsys window displays | grep -E 'mRotation|mCurrentFocus|mUserRotation|mFocusedApp'
            adb shell dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'
        } > "$OUT/ventanas.txt" 2>&1 || true
    fi
    pid="$(adb shell pidof "$PKG" 2> /dev/null | tr -d '\r' || true)"
    if [ "$status" != 0 ] && [ -n "$pid" ]; then
        adb root > /dev/null 2>&1 && sleep 3 && adb wait-for-device > /dev/null 2>&1 || true
        adb shell debuggerd -b "$pid" > "$OUT/pilas.txt" 2>&1 || true
    fi
    if [ -n "$EMULATOR_PID" ]; then
        adb emu kill > /dev/null 2>&1 || kill "$EMULATOR_PID" 2> /dev/null || true
        wait "$EMULATOR_PID" 2> /dev/null || true
    fi
    if [ -n "${HOST_UID:-}" ]; then
        chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$OUT" "$SHOTS" 2> /dev/null || true
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

# ¿Contiene la entrada la expresión $1? Lee toda la entrada: con `grep -q` y pipefail, si
# grep termina antes, la orden que escribe recibe SIGPIPE y la tubería «falla».
contains() {
    grep -E "$1" > /dev/null
}

# Mensajes de la aplicación (Rust y Java usan la etiqueta AutoFirma).
app_log() {
    adb logcat -d -s 'AutoFirma:*' 'RustStdoutStderr:*' 2> /dev/null | tr -d '\r'
}

# Marca el registro: wait_new solo mira lo que llegue después.
mark() {
    MARK="$(app_log | wc -l)"
}

since_mark() {
    app_log | tail -n +"$((MARK + 1))"
}

check_alive() {
    if adb logcat -d -b crash 2> /dev/null | contains "$PKG"; then
        fail "la aplicación se ha cerrado inesperadamente (logcat -b crash)"
    fi
}

# Espera hasta $2 segundos a que el registro contenga la expresión $1 (desde el principio).
wait_log() {
    local pattern="$1" timeout="$2" i
    for ((i = 0; i < timeout; i++)); do
        if app_log | contains "$pattern"; then
            app_log | grep -E "$pattern" | tail -n 1 | sed 's/^/    /' >&2
            return 0
        fi
        check_alive
        sleep 1
    done
    fail "no apareció en logcat: $pattern"
}

# Espera hasta $2 segundos (20 por defecto) a que aparezca $1 después de la última marca.
wait_new() {
    local pattern="$1" timeout="${2:-20}" i
    for ((i = 0; i < timeout * 2; i++)); do
        if since_mark | contains "$pattern"; then
            since_mark | grep -E "$pattern" | tail -n 1 | sed 's/^/    /' >&2
            return 0
        fi
        check_alive
        sleep 0.5
    done
    fail "no apareció en logcat: $pattern"
}

# Espera a que se muestre la pantalla $1 (identificador de la aplicación, con « + diálogo»).
wait_screen() {
    wait_new "Pantalla «$1»$" "${2:-20}"
    # Fundido de entrada y posiciones de los elementos.
    sleep 0.8
}

screenshot() {
    adb exec-out screencap -p > "$OUT/$1"
    [ -s "$OUT/$1" ] || fail "captura vacía: $1"
    info "Captura: $1"
}

# Captura numerada de una pantalla en el directorio de capturas.
shot() {
    SHOT_NUMBER=$((SHOT_NUMBER + 1))
    local name
    name="$(printf '%02d-%s.png' "$SHOT_NUMBER" "$1")"
    adb exec-out screencap -p > "$SHOTS/$name"
    [ -s "$SHOTS/$name" ] || fail "captura vacía: $name"
    info "Captura de pantalla: $name"
}

# Posición «x y» (píxeles) del elemento $1 en la pantalla visible, según lo que registra la
# aplicación («Botón «id» en x=… y=…», «Botón «id» oculto» y «Pantalla «…»»).
position() {
    app_log | awk -v tid="$1" '
        index($0, "Pantalla «") { found = "" }
        index($0, "Botón «" tid "» oculto") { found = "" }
        index($0, "Botón «" tid "» en x=") {
            match($0, /x=[0-9]+ y=[0-9]+/)
            found = substr($0, RSTART, RLENGTH)
        }
        END { print found }' | sed -E 's/x=([0-9]+) y=([0-9]+)/\1 \2/'
}

# Pulsa el elemento $1; si no se ve, desplaza la pantalla (primero hacia abajo y luego hacia
# arriba) hasta encontrarlo.
tap() {
    local tid="$1" pos i
    for ((i = 0; i < 16; i++)); do
        pos="$(position "$tid")"
        if [ -n "$pos" ]; then
            # shellcheck disable=SC2086 # «x y»
            adb shell input tap $pos
            return 0
        fi
        if ((i < 6)); then
            adb shell input swipe 540 1700 540 1000 300
        else
            adb shell input swipe 540 900 540 1700 300
        fi
        sleep 1
    done
    fail "la aplicación no registró la posición de «$tid»"
}

# Pulsa $1 y espera la pantalla $2.
go() {
    mark
    tap "$1"
    wait_screen "$2"
}

# Atrás y espera la pantalla $1.
back_to() {
    mark
    adb shell input keyevent KEYCODE_BACK
    wait_screen "$1"
}

# Ventana con el foco (paquete/actividad).
focused_window() {
    adb shell dumpsys window 2> /dev/null | tr -d '\r' | grep -E 'mCurrentFocus=' | tail -n 1
}

keyboard_shown() {
    adb shell dumpsys input_method 2> /dev/null | tr -d '\r' | contains 'mInputShown=true'
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
adb shell settings put system accelerometer_rotation 0
adb shell settings put system user_rotation 0
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard > /dev/null 2>&1 || true

info "Instalando el APK"
adb install -r -g "$APK" > /dev/null
# Las aplicaciones de Google de una imagen recién arrancada llenan el búfer circular de
# logcat (256 KB) en segundos: sin agrandarlo se pierden líneas de la aplicación.
adb logcat -G 16M > /dev/null 2>&1 || true
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

info "1. Arranque, primer fotograma, bienvenida y condiciones"
adb shell am start -W -n "$PKG/.MainActivity" > /dev/null
wait_log 'AutoFirma-rs .* para Android iniciado' 60
wait_log 'Primer fotograma de la interfaz' 60
shot arranque
wait_log 'Pantalla «intro»' 30
sleep 1
shot bienvenida
go intro.start conditions
shot condiciones
# Cambio de idioma desde las condiciones (el emulador está en inglés): al español.
go conditions.language 'conditions \+ language_picker'
shot condiciones-idioma
mark
tap language.es
wait_new 'Idioma de la interfaz: es'
wait_screen conditions
shot condiciones-es
mark
tap conditions.privacy
sleep 0.5
tap conditions.legal
sleep 0.5
tap conditions.accept
wait_new 'Textos legales aceptados'
wait_screen home
screenshot captura.png
shot inicio
go home.help 'home \+ help'
shot inicio-ayuda
mark
tap dialog.ok
wait_screen home

info "2. Rust -> Java: «Firmar fichero» -> selector de documentos del sistema"
mark
tap home.sign_file
wait_new 'Selector de documentos abierto' 30
for ((i = 0; i < 30; i++)); do
    focused_window | contains '[Dd]ocuments[Uu][Ii]' && break
    sleep 1
done
focused_window | contains '[Dd]ocuments[Uu][Ii]' || fail "no se abrió el selector de documentos ($(focused_window))"
sleep 2
screenshot selector.png

info "3. Java -> Rust: cancelar el selector"
adb shell input keyevent KEYCODE_BACK
wait_new 'Selector de documentos cancelado' 30

info "4. KeyChain: Certificados -> «Ver un certificado» -> selector del sistema -> cancelar"
go home.certificates certificates
shot certificados
mark
tap certs.view
wait_new 'Selector de certificados abierto' 30
# Sin certificados instalados, KeyChainActivity se abre y responde «ninguno» al momento; si
# muestra el diálogo, se cierra con Atrás.
for ((i = 0; i < 10; i++)); do
    app_log | contains 'Selector de certificados cerrado sin elegir' && break
    if ! focused_window | contains "$PKG"; then
        info "    Ventana: $(focused_window | sed 's/^ *//')"
        sleep 2
        # KeyChainActivity es transparente y se cierra sola si no hay certificados.
        if ! focused_window | contains "$PKG"; then
            screenshot keychain.png
            adb shell input keyevent KEYCODE_BACK
        fi
        break
    fi
    sleep 1
done
wait_log 'Selector de certificados cerrado sin elegir' 30
adb logcat -d 2> /dev/null | contains 'Displayed com.android.keychain/.KeyChainActivity' \
    || fail "no se abrió la actividad de KeyChain del sistema"
back_to home

info "5. Intent afirma://"
mark
adb shell "am start -W -a android.intent.action.VIEW -d 'afirma://sign?op=sign&id=prueba' $PKG" > /dev/null
wait_new 'Petición web recibida: Operación «sign»' 30
wait_screen web_request
screenshot intent.png
shot peticion-web
back_to home

if [ -n "${TLS_CHECK:-}" ]; then
    info "6. Verificación TLS del sistema ($TLS_CHECK)"
    wait_log 'Comprobación TLS (correcta|fallida)' 60
    app_log | contains 'Comprobación TLS correcta' || fail "la comprobación TLS ha fallado"
fi

info "Interfaz: pantallas de Inicio"
go home.add_cert import_instructions_1
shot importar-1
go import.continue import_instructions_2
shot importar-2
go import.add unavailable
shot proximamente
back_to import_instructions_2
back_to import_instructions_1
back_to home
go home.web_signing web_signing
shot firma-web
back_to home
go home.history signs_record
shot historico
go history.delete 'signs_record \+ message'
shot historico-vacio
mark
tap dialog.ok
wait_screen signs_record
back_to home

info "Interfaz: Ajustes y todas sus pantallas"
go home.settings settings
shot ajustes
go settings.language language
shot idioma
back_to settings
go settings.sign_configuration sign_configuration
shot configuracion-firma
mark
tap signconf.visible
sleep 0.5
go signconf.cache 'sign_configuration \+ cache_minutes'
shot minutos-cache
mark
tap minutes.30
sleep 0.5
tap dialog.select
wait_screen sign_configuration
mark
tap signconf.save
wait_new 'Configuración de firma guardada'
wait_screen 'sign_configuration \+ message'
shot cambios-guardados
mark
tap dialog.ok
wait_screen sign_configuration
back_to settings

info "Teclado en pantalla: dominios de confianza"
go settings.trusted_domains trusted_domains
shot dominios
mark
tap domains.field
wait_new 'Teclado en pantalla abierto \(MultiLine\)'
for ((i = 0; i < 20; i++)); do
    keyboard_shown && break
    sleep 0.5
done
keyboard_shown || fail "no se mostró el teclado en pantalla"
adb shell "input text 'sede.ejemplo.es'"
adb shell input keyevent KEYCODE_ENTER
adb shell "input text '*.gob.es'"
sleep 1.5
shot dominios-teclado
# Atrás cierra el teclado (lo trata el sistema) y el campo suelta el foco.
mark
adb shell input keyevent KEYCODE_BACK
wait_new 'Teclado (cerrado por el usuario|en pantalla cerrado)'
sleep 1
keyboard_shown && fail "el teclado sigue abierto tras Atrás"
mark
tap domains.save
wait_new 'Dominios de confianza guardados: 2'
wait_screen 'trusted_domains \+ message'
shot dominios-guardados
mark
tap dialog.ok
wait_screen trusted_domains
back_to settings

go settings.history signs_record
back_to settings
go settings.faq faq
mark
tap faq.1
sleep 1
shot preguntas-frecuentes
back_to settings
for item in help_nfc:help_dnie_nfc help_visible_sign:help_visible_sign \
    help_trusted_domains:help_trusted_domains help_certs:help_import_certs \
    accessibility:accessibility legal:legal privacy:privacy version:version; do
    row="${item%%:*}"
    screen="${item##*:}"
    go "settings.$row" "$screen"
    shot "$screen"
    back_to settings
done

info "Idioma: gallego en Ajustes (se aplica al momento y se guarda) y vuelta al español"
go settings.language language
mark
tap language.gl
wait_new 'Idioma de la interfaz: gl'
sleep 1
shot idioma-gl
back_to settings
shot ajustes-gl
go settings.language language
mark
tap language.es
wait_new 'Idioma de la interfaz: es'
back_to settings
back_to home

info "Accesibilidad: árbol de AccessKit en Android (uiautomator)"
a11y=0
for ((i = 0; i < 5; i++)); do
    adb shell uiautomator dump /sdcard/ui.xml > /dev/null 2>&1 || true
    if adb shell cat /sdcard/ui.xml 2> /dev/null | contains 'content-desc="Firmar fichero"'; then
        a11y=1
        break
    fi
    sleep 2
done
[ "$a11y" = 1 ] || fail "TalkBack no vería la interfaz: falta «Firmar fichero» en uiautomator dump"
adb shell cat /sdcard/ui.xml > "$OUT/accesibilidad.xml" 2> /dev/null || true

info "Giro a horizontal y tema oscuro"
mark
# Sin giro automático (en el primer arranque el sistema puede volver a activarlo después de
# haberlo quitado al principio), user_rotation manda.
adb shell settings put system accelerometer_rotation 0
adb shell settings put system user_rotation 1
wait_new 'Botón «home.settings» en x=' 20
sleep 1
shot inicio-horizontal
mark
adb shell cmd uimode night yes > /dev/null
wait_new 'tema oscuro'
sleep 1.5
shot inicio-horizontal-oscuro
go home.settings settings
shot ajustes-horizontal-oscuro
back_to home
mark
adb shell cmd uimode night no > /dev/null
wait_new 'tema claro'
mark
adb shell settings put system user_rotation 0
wait_new 'Botón «home.settings» en x=' 20
# Que termine la transición del giro: durante ella el sistema puede ignorar moveTaskToBack.
sleep 4

info "7. Atrás en Inicio deja la aplicación en segundo plano y se vuelve a abrir sin reiniciarse"
pid="$(adb shell pidof "$PKG" | tr -d '\r')"
mark
adb shell input keyevent KEYCODE_BACK
wait_new 'la aplicación pasa a segundo plano'
sleep 2
if focused_window | contains "$PKG"; then
    # Si coincide con una transición de ventanas, el sistema puede no mover la tarea: otra vez.
    info "    sigue en primer plano: Atrás otra vez"
    adb shell input keyevent KEYCODE_BACK
    sleep 2
fi
focused_window | contains "$PKG" && fail "la aplicación sigue en primer plano tras pulsar Atrás"
adb shell am start -W -n "$PKG/.MainActivity" > /dev/null
sleep 2
focused_window | contains "$PKG" || fail "la aplicación no volvió al primer plano ($(focused_window))"
[ "$(adb shell pidof "$PKG" | tr -d '\r')" = "$pid" ] || fail "el proceso de la aplicación se ha reiniciado"
[ "$(app_log | grep -c 'para Android iniciado')" = 1 ] || fail "android_main se ha ejecutado más de una vez"

info "8. Arranque en frío (tras \`am force-stop\`) con un enlace afirma://"
adb shell am force-stop "$PKG"
mark
adb shell "am start -W -a android.intent.action.VIEW -d 'afirma://selectcert?id=prueba' $PKG" > /dev/null
wait_new 'Petición web recibida: Operación «selectcert»' 60
wait_screen web_request
shot peticion-web-en-frio
[ "$(app_log | grep -c 'para Android iniciado')" = 2 ] || fail "no se arrancó un proceso nuevo con el enlace"
# Las preferencias se han guardado: los dominios y el idioma siguen ahí.
since_mark | contains 'Idioma de la interfaz: es' || fail "no se recuperó el idioma guardado"
back_to home

info "9. Sin cierres inesperados"
sleep 2
check_alive
adb shell pidof "$PKG" > /dev/null || fail "el proceso de la aplicación ya no existe"
if app_log | contains 'Error interno \(pánico\)|panicked at'; then
    fail "pánico de Rust en el registro"
fi
info "Prueba de humo superada ($SHOT_NUMBER capturas en el directorio de capturas)"
