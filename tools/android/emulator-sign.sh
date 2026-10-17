# shellcheck shell=bash
# Firma local de extremo a extremo en el emulador. La carga emulator-smoke.sh (dentro del
# contenedor del emulador) cuando SIGN_E2E=1, al final de la prueba de humo, y usa sus
# funciones (tap, go, mark, wait_new, wait_screen, shot, focused_window, contains, fail...).
#
#   1. Importa la identidad de prueba con el botón de la aplicación («Añadir nuevo
#      certificado» → instrucciones → «Añadir certificado», CER-11/12): el selector de
#      documentos del sistema (DocumentsUI) y el instalador de certificados (contraseña,
#      tipo y nombre) se manejan con uiautomator.
#   2. Firma tres ficheros de Descargas: un PDF con firma visible (vista previa, área
#      dibujada arrastrando el dedo), un .txt (CAdES) y un .xml (XAdES), eligiendo el
#      certificado en el selector de KeyChain y guardando con el diálogo del sistema.
#   3. Comprueba que el histórico de firmas lista las tres.
#   4. Deja las firmas en /out/firmas (las verifica emulator-test.sh en el anfitrión con el
#      verificador del escritorio).
#
# Entradas en /work/data: documento.pdf, hola.txt, documento.xml y firmante-rsa-legacy.p12
# (contraseña 12341234). Se usa el PKCS#12 con cifrado «legacy» (3DES/RC2): el instalador de
# certificados de Android 15 no abre los PKCS#12 con PBES2/AES de OpenSSL 3
# (firmante-rsa.p12): responde «The certificate is not installed» (docs/ANDROID.md §8).

SIGN_DATA=/work/data
SIGN_OUT=/out/firmas
SIGN_P12=firmante-rsa-legacy.p12
SIGN_P12_PASSWORD=12341234
SIGN_ALIAS=firmante-rsa

# Árbol de la interfaz visible (uiautomator), una línea por nodo.
ui_nodes() {
    adb exec-out uiautomator dump /dev/tty 2> /dev/null | tr -d '\r' | grep -oE '<node [^>]*>' || true
}

# Centro «x y» del primer nodo cuyo texto o descripción es exactamente la expresión $1 (o, con
# $2 = id, cuyo resource-id termina en $1).
ui_center() {
    local attr='(text|content-desc)="('"$1"')"'
    if [ "${2:-}" = id ]; then
        attr='resource-id="[^"]*('"$1"')"'
    fi
    ui_nodes | grep -E "$attr" \
        | sed -nE 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/p' \
        | awk 'NR == 1 { printf "%d %d\n", ($1 + $3) / 2, ($2 + $4) / 2 }' || true
}

# Espera hasta $2 segundos (20 por defecto) a que aparezca un nodo ($3 = id: por resource-id).
ui_wait() {
    local pattern="$1" timeout="${2:-20}" i
    for ((i = 0; i < timeout; i++)); do
        [ -n "$(ui_center "$pattern" "${3:-}")" ] && return 0
        check_alive
        sleep 1
    done
    fail "no apareció en pantalla «$pattern» ($(focused_window | sed 's/^ *//'))"
}

# Espera a un nodo y lo pulsa.
ui_tap() {
    local pattern="$1" timeout="${2:-20}" pos
    ui_wait "$pattern" "$timeout" "${3:-}"
    pos="$(ui_center "$pattern" "${3:-}")"
    # shellcheck disable=SC2086 # «x y»
    adb shell input tap $pos
    sleep 1
}

# Espera a que la ventana con el foco sea de $1 (expresión).
wait_window() {
    local pattern="$1" i
    for ((i = 0; i < 30; i++)); do
        focused_window | contains "$pattern" && return 0
        check_alive
        sleep 1
    done
    fail "no se abrió $pattern ($(focused_window | sed 's/^ *//'))"
}

# Elige un fichero de Descargas en el selector de documentos del sistema.
pick_download() {
    local name="$1"
    wait_window '[Dd]ocuments[Uu][Ii]'
    sleep 1.5
    if [ -z "$(ui_center "$name")" ]; then
        ui_tap 'Show roots'
        ui_tap 'Downloads'
    fi
    ui_tap "$name"
}

# Instalador de certificados del sistema: contraseña, tipo («VPN y aplicaciones») y nombre.
install_identity() {
    wait_window 'certinstaller'
    ui_wait 'Extract certificate' 30
    shot instalador-contrasena
    ui_tap 'credential_password' 10 id
    adb shell input text "$SIGN_P12_PASSWORD"
    ui_tap 'OK'
    ui_wait 'Choose a certificate type' 30
    shot instalador-tipo
    ui_tap 'OK'
    ui_wait 'Name this certificate' 30
    shot instalador-nombre
    ui_tap 'OK'
}

# Selector de KeyChain: el certificado de prueba y «Seleccionar».
choose_identity() {
    wait_window 'keychain'
    ui_wait 'Choose certificate' 30
    ui_tap "$SIGN_ALIAS"
    ui_tap 'SELECT|Select'
}

# Firma un fichero de Descargas ($1) y guarda la firma ($2) en Descargas; con $3 = visible,
# dibuja antes el área de la firma visible en la vista previa.
sign_download() {
    local file="$1" signed="$2" visible="${3:-}" slug pos cx cy
    slug="${file%.*}-${file##*.}"
    info "Firma local de $file"
    mark
    tap home.sign_file
    wait_new 'Selector de documentos abierto' 30
    pick_download "$file"
    wait_new 'Firma local: documento de [0-9]+ bytes' 30
    if [ "$visible" = visible ]; then
        wait_screen visible_signature
        wait_new 'Vista previa: página 1 dibujada' 60
        sleep 1
        shot "firma-visible-$slug"
        pos="$(position preview.page)"
        [ -n "$pos" ] || fail "la aplicación no registró la página de la vista previa"
        read -r cx cy <<< "$pos"
        adb shell input swipe $((cx - 350)) $((cy + 150)) $((cx + 150)) $((cy + 400)) 800
        sleep 1.5
        shot "firma-visible-area-$slug"
        tap preview.continue
        wait_new 'Firma visible: página 1, área' 20
    fi
    wait_new 'Selector de certificados abierto' 30
    choose_identity
    wait_new "Diálogo de guardado abierto: «$signed»" 120
    wait_window '[Dd]ocuments[Uu][Ii]'
    ui_wait "$signed" 30
    shot "guardar-$slug"
    ui_tap 'SAVE|Save'
    wait_new "Firma guardada: «$signed»" 30
    wait_new 'Histórico de firmas: firma local registrada' 10
    wait_screen 'home \+ message'
    shot "firmado-$slug"
    mark
    tap dialog.ok
    wait_screen home
    adb pull "/sdcard/Download/$signed" "$SIGN_OUT/$signed" > /dev/null
    [ -s "$SIGN_OUT/$signed" ] || fail "no se ha guardado $signed"
    info "    $signed: $(wc -c < "$SIGN_OUT/$signed") bytes"
}

sign_e2e() {
    info "Firma local de extremo a extremo: importar la identidad de prueba"
    mkdir -p "$SIGN_OUT"
    for f in documento.pdf hola.txt documento.xml "$SIGN_P12"; do
        adb push "$SIGN_DATA/$f" "/sdcard/Download/$f" > /dev/null
    done
    go home.add_cert import_instructions_1
    go import.continue import_instructions_2
    mark
    tap import.add
    wait_new 'Selector de documentos abierto' 30
    pick_download "$SIGN_P12"
    wait_new 'Instalador de certificados abierto' 30
    install_identity
    wait_new 'Certificado instalado en KeyChain' 30
    wait_screen 'home \+ message'
    shot certificado-anadido
    mark
    tap dialog.ok
    wait_screen home

    # La configuración de firma del recorrido de la prueba de humo deja activada la firma
    # visible: el PDF pasa por la vista previa.
    sign_download documento.pdf documento_signed.pdf visible
    sign_download hola.txt hola.txt.csig
    sign_download documento.xml documento.xml.xsig

    info "Histórico de firmas"
    mark
    tap home.history
    wait_new 'Histórico de firmas: 3 registros' 10
    wait_screen signs_record
    shot historico-firmas
    # El árbol de accesibilidad (AccessKit) tarda en llegar a uiautomator tras cambiar de
    # pantalla: se reintenta.
    local tree missing attempt f
    for ((attempt = 0; attempt < 10; attempt++)); do
        tree="$(ui_nodes)"
        missing=""
        for f in documento.pdf hola.txt documento.xml; do
            contains "Firma local del fichero $f" <<< "$tree" || missing="$missing $f"
        done
        [ -z "$missing" ] && break
        sleep 2
    done
    if [ -n "$missing" ]; then
        printf '%s\n' "$tree" > "$OUT/historico.xml"
        fail "el histórico no lista:$missing (árbol en historico.xml)"
    fi
    back_to home
    info "Firma local de extremo a extremo superada: firmas en $SIGN_OUT"
}
