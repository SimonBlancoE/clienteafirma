#!/bin/sh
# Integración de AutoFirma-rs con el sistema desde los scripts de los paquetes
# (.deb postinst/prerm, .rpm %post/%preun y .pkg postinstall de macOS).
#
# Uso: configure-hook.sh install|uninstall <ruta-del-ejecutable>
#
# «install» ejecuta `autofirma install --system` y «uninstall» `autofirma uninstall --system`.
# Los dos son idempotentes. Opciones de despliegue (mismos nombres que las propiedades del
# MSI de Windows), leídas de las variables de entorno o, si no están definidas, del fichero
# install.conf del directorio de configuración del sistema (/etc/autofirma/install.conf en
# Linux, «/Library/Application Support/AutoFirma/install.conf» en macOS), con líneas
# CLAVE=valor:
#
#   SKIP_CONFIGURE=1           no configurar nada (el administrador lo hace por su cuenta)
#   BROWSER_POLICIES=1         escribir directivas de Chrome/Edge/Chromium/Firefox
#   ORIGINS=https://a,https://b  orígenes autorizados a abrir afirma:// sin preguntar
#   FIREFOX_SECURITY_ROOTS=1   Firefox confía en las CA del sistema
#   CONFIG_PATH=<ruta|https:…> fichero de preferencias (.afconfig) a importar
#   UPDATE_CONFIG=1            volver a descargar CONFIG_PATH (https) periódicamente
#   DEFAULT_LANGUAGE=es_ES     idioma por defecto (es_ES, ca_ES, gl_ES, eu_ES, va_ES, en_US)
#   KEYSTORE_PATH=<pfx>        par CA + SSL corporativo (PKCS#12, contraseña 654321) en
#   CERTIFICATE_PATH=<cer>     lugar de generar uno; deben indicarse los dos
#   STRICT=1                   un fallo de la configuración hace fallar la instalación
#
# Por defecto un fallo de la configuración solo se avisa (el paquete queda instalado y el
# usuario o el administrador puede repetirla con `autofirma install --system` o revisarla
# con `autofirma doctor`); con STRICT=1 se propaga el código de salida.
#
# También se aceptan variables de entorno con el prefijo AUTOFIRMA_ (por ejemplo
# `sudo AUTOFIRMA_BROWSER_POLICIES=1 apt install ./autofirma-rs_….deb`), que tienen
# prioridad sobre install.conf.

set -u

action="${1:-}"
exe="${2:-}"

log() { printf 'autofirma-rs: %s\n' "$*" >&2; }

if [ -z "$action" ] || [ -z "$exe" ]; then
    log "uso: $0 install|uninstall <ejecutable>"
    exit 2
fi
if [ ! -x "$exe" ]; then
    log "AVISO: no se encuentra el ejecutable $exe; no se configura el sistema"
    exit 0
fi

case "$(uname -s)" in
    Darwin) conf="/Library/Application Support/AutoFirma/install.conf" ;;
    *) conf="/etc/autofirma/install.conf" ;;
esac

# Valor de una clave de install.conf (última aparición; sin comillas envolventes).
conf_value() {
    [ -r "$conf" ] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$conf" | tail -n 1 \
        | sed -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# Opción: variable de entorno AUTOFIRMA_<CLAVE> y, si no está, install.conf.
opt() {
    eval "v=\${AUTOFIRMA_$1:-}"
    if [ -z "$v" ]; then
        v="$(conf_value "$1")"
    fi
    printf '%s' "$v"
}

is_true() {
    case "$1" in
        1 | [Tt][Rr][Uu][Ee] | [Yy][Ee][Ss] | [Ss][Ii]) return 0 ;;
        *) return 1 ;;
    esac
}

strict="$(opt STRICT)"

run() {
    log "$*"
    "$@"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        if is_true "$strict"; then
            log "ERROR: la configuración ha fallado (código $rc)"
            exit "$rc"
        fi
        log "AVISO: la configuración ha terminado con errores (código $rc)."
        log "       Revise el diagnóstico con: autofirma doctor"
        log "       y repita la configuración con: sudo autofirma install --system"
    fi
    return 0
}

case "$action" in
    install)
        if is_true "$(opt SKIP_CONFIGURE)"; then
            log "SKIP_CONFIGURE activo: no se configura el sistema"
            exit 0
        fi
        set -- install --system
        if is_true "$(opt BROWSER_POLICIES)"; then
            set -- "$@" --browser-policies
        fi
        origins="$(opt ORIGINS)"
        if [ -n "$origins" ]; then
            set -- "$@" --origins "$origins"
        fi
        if is_true "$(opt FIREFOX_SECURITY_ROOTS)"; then
            set -- "$@" --firefox-roots
        fi
        config_path="$(opt CONFIG_PATH)"
        if [ -n "$config_path" ]; then
            set -- "$@" --config-path "$config_path"
            if is_true "$(opt UPDATE_CONFIG)"; then
                set -- "$@" --update-config
            fi
        fi
        language="$(opt DEFAULT_LANGUAGE)"
        if [ -n "$language" ]; then
            set -- "$@" --default-language "$language"
        fi
        keystore="$(opt KEYSTORE_PATH)"
        certificate="$(opt CERTIFICATE_PATH)"
        if [ -n "$keystore" ] && [ -n "$certificate" ]; then
            set -- "$@" --keystore-path "$keystore" --certificate-path "$certificate"
        elif [ -n "$keystore$certificate" ]; then
            log "AVISO: KEYSTORE_PATH y CERTIFICATE_PATH deben indicarse juntos; se ignoran"
        fi
        run "$exe" "$@"
        ;;
    uninstall)
        if is_true "$(opt SKIP_CONFIGURE)"; then
            exit 0
        fi
        run "$exe" uninstall --system
        ;;
    *)
        log "acción desconocida: $action"
        exit 2
        ;;
esac
exit 0
