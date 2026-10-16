#!/bin/sh
# Desinstalación de AutoFirma en macOS (no hay desinstalador gráfico):
#   sudo "/Applications/AutoFirma.app/Contents/Resources/uninstall.sh"
# Retira la CA local de los llaveros y de Firefox, el registro del protocolo y las
# directivas creadas por AutoFirma, y después borra la aplicación y el recibo del paquete.
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "Ejecute este script con sudo." >&2
    exit 1
fi

app="$(cd "$(dirname "$0")/../.." && pwd)"
case "$app" in
    *.app) ;;
    *) echo "No se encuentra AutoFirma.app ($app)" >&2; exit 1 ;;
esac

"$app/Contents/MacOS/autofirma" uninstall --system || echo "AVISO: la desinstalación de la configuración ha terminado con errores" >&2
rm -rf "$app"
pkgutil --forget io.github.autofirma-rs.AutoFirma.pkg >/dev/null 2>&1 || true
echo "AutoFirma se ha desinstalado."
