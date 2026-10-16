#!/usr/bin/env bash
# Compilación cruzada de AutoFirma-rs para Windows desde Linux (imagen Docker
# autofirma-cross:latest, MinGW, destino x86_64-pc-windows-gnu) y empaquetado de PRUEBA:
# ZIP portable y, opcionalmente, el MSI.
#
# Las versiones publicadas se generan en Windows (MSVC, WiX v5, firma de código) con
# tools/package/windows.ps1 desde .github/workflows/release.yml.
#
# Uso: tools/package/windows-cross.sh [opciones]
#
#   --exe <ruta>     No compilar: empaquetar este autofirma.exe.
#   --msi            Generar además el MSI con la definición real
#                    (packaging/windows/autofirma.wxs) y WiX 5.0.2 ejecutado con Wine en
#                    la imagen autofirma-cross (descarga .NET 8 y WiX con SHA-256 fijado).
#   --wixl           Generar además un MSI de humo con wixl (msitools, sintaxis WiX v3,
#                    sin acciones personalizadas) en un contenedor Debian.
#   --out <dir>      Directorio de salida (por defecto target/dist).
#
# El ejecutable se compila en $CARGO_TARGET_DIR (por defecto target/cross, que debe estar
# dentro del repositorio para montarlo en el contenedor). Variables: AUTOFIRMA_CROSS_IMAGE
# (imagen), AUTOFIRMA_BUILD_NUMBER (cuarto componente de la versión del ejecutable).
set -euo pipefail

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TARGET="x86_64-pc-windows-gnu"
ARCH="x86_64"
EXE=""
MSI=0
WIXL=0
OUT="$ROOT/target/dist"
DOCKER_IMAGE="${AUTOFIRMA_CROSS_IMAGE:-autofirma-cross:latest}"

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --exe) EXE="$2"; shift 2 ;;
        --msi) MSI=1; shift ;;
        --wixl) WIXL=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        -h | --help) usage 0 ;;
        *) warn "opción desconocida: $1"; usage 2 ;;
    esac
done

VERSION="$(workspace_version)"
[ -n "$VERSION" ] || die "no se pudo leer la versión"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

if [ -z "$EXE" ]; then
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/cross}"
    mkdir -p "$CARGO_TARGET_DIR"
    rel_target="$(realpath --relative-to="$ROOT" "$CARGO_TARGET_DIR")"
    case "$rel_target" in
        ../* | /*) die "CARGO_TARGET_DIR debe estar dentro del repositorio ($ROOT)" ;;
    esac
    info "Compilando autofirma.exe ($TARGET) en $DOCKER_IMAGE"
    # Registro de crates en un volumen propio (no se escriben ficheros de root en ~/.cargo);
    # al terminar se devuelve la propiedad de los ficheros generados al usuario.
    docker run --rm \
        -v "$ROOT:/src" -w /src \
        -v autofirma-cargo-registry:/usr/local/cargo/registry \
        -e CARGO_TARGET_DIR="/src/$rel_target" \
        -e AUTOFIRMA_BUILD_NUMBER="${AUTOFIRMA_BUILD_NUMBER:-0}" \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "$DOCKER_IMAGE" bash -euc '
            trap "chown -R \"\$HOST_UID:\$HOST_GID\" \"\$CARGO_TARGET_DIR\"" EXIT
            cargo build --release -p autofirma --target '"$TARGET"'
        '
    EXE="$CARGO_TARGET_DIR/$TARGET/release/autofirma.exe"
fi
[ -f "$EXE" ] || die "no existe $EXE"
BIN_DIR="$(cd "$(dirname "$EXE")" && pwd)"

# Comprobación rápida de los recursos incrustados por crates/autofirma/build.rs: el
# manifiesto se guarda en UTF-8 y la información de versión en UTF-16LE.
info "Comprobando los recursos del ejecutable"
# Un manifiesto mal formado impide arrancar el programa en Windows (error 14001).
python3 -I -c 'import sys, xml.dom.minidom as m; m.parse(sys.argv[1])' \
    "$ROOT/packaging/windows/autofirma.exe.manifest" || die "autofirma.exe.manifest no es XML bien formado"
grep -q 'PerMonitorV2' "$EXE" || die "falta el manifiesto (PerMonitorV2) en $EXE"
grep -q 'asInvoker' "$EXE" || die "falta requestedExecutionLevel asInvoker en $EXE"
if command -v strings >/dev/null 2>&1; then
    strings -el "$EXE" | grep -qx 'AutoFirma' || die "falta la información de versión (ProductName) en $EXE"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/autofirma-win.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------ ZIP portable
base="AutoFirma-$VERSION-windows-$ARCH-portable"
dir="$WORK/$base"
mkdir -p "$dir/LICENSE"
cp "$EXE" "$dir/autofirma.exe"
if [ -f "$BIN_DIR/autofirma-cli.exe" ]; then
    cp "$BIN_DIR/autofirma-cli.exe" "$dir/autofirma-cli.exe"
fi
# Textos con fin de línea CRLF para el Bloc de notas antiguo.
sed 's/\r\{0,1\}$/\r/' "$ROOT/packaging/windows/README-portable.txt" >"$dir/README-portable.txt"
sed 's/\r\{0,1\}$/\r/' "$ROOT/license/gpl-2.0.txt" >"$dir/LICENSE/gpl-2.0.txt"
sed 's/\r\{0,1\}$/\r/' "$ROOT/license/LICENSE.txt" >"$dir/LICENSE/condiciones-autofirma.txt"
zip_file="$OUT/$base.zip"
rm -f "$zip_file"
python3 -I - "$WORK" "$base" "$zip_file" <<'PY'
import os, sys, zipfile
root, base, out = sys.argv[1:4]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for d, _, files in os.walk(os.path.join(root, base)):
        for f in sorted(files):
            p = os.path.join(d, f)
            z.write(p, os.path.relpath(p, root))
PY
info "ZIP portable: $zip_file"

# ------------------------------------------------------------------ MSI (WiX 5 con Wine)
# Versiones fijadas (las mismas que usa tools/package/windows.ps1 en Windows).
DOTNET_VERSION="8.0.32"
DOTNET_SHA="0132501a735fc584adff29d28084150083f6ba320f5ae52beb7c49f52ba793f7"
WIX_VERSION="5.0.2"
WIX_SHA="f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173"
WIX_UTIL_SHA="dda1cc1b4d3b2305b1246f167c6af6fcded5000be84b3bbff3dda4f442bf4740"

if [ "$MSI" = 1 ]; then
    cache="$(tools_cache_dir)/wix-wine"
    fetch_verified "https://builds.dotnet.microsoft.com/dotnet/Runtime/$DOTNET_VERSION/dotnet-runtime-$DOTNET_VERSION-win-x64.zip" \
        "$cache/dotnet-runtime-$DOTNET_VERSION-win-x64.zip" "$DOTNET_SHA"
    fetch_verified "https://api.nuget.org/v3-flatcontainer/wix/$WIX_VERSION/wix.$WIX_VERSION.nupkg" \
        "$cache/wix.$WIX_VERSION.nupkg" "$WIX_SHA"
    fetch_verified "https://api.nuget.org/v3-flatcontainer/wixtoolset.util.wixext/$WIX_VERSION/wixtoolset.util.wixext.$WIX_VERSION.nupkg" \
        "$cache/wixtoolset.util.wixext.$WIX_VERSION.nupkg" "$WIX_UTIL_SHA"
    mkdir -p "$WORK/wix/bin" "$WORK/wix/out"
    cp "$EXE" "$WORK/wix/bin/autofirma.exe"
    if [ -f "$BIN_DIR/autofirma-cli.exe" ]; then cp "$BIN_DIR/autofirma-cli.exe" "$WORK/wix/bin/"; fi
    has_cli=""
    if [ -f "$WORK/wix/bin/autofirma-cli.exe" ]; then has_cli='-d HasCli=1'; fi
    numver="$(numeric_version "$VERSION").${AUTOFIRMA_BUILD_NUMBER:-0}"
    msi="AutoFirma-$VERSION-windows-$ARCH.msi"
    info "Generando el MSI con WiX $WIX_VERSION (Wine)"
    docker run --rm \
        -v "$cache:/cache:ro" -v "$WORK/wix:/w" \
        -v "$ROOT/packaging:/src/packaging:ro" -v "$ROOT/license:/src/license:ro" \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "$DOCKER_IMAGE" bash -euc '
            trap "chown -R \"\$HOST_UID:\$HOST_GID\" /w/out" EXIT
            export PATH=/usr/lib/wine:$PATH WINEDEBUG=-all WINEPREFIX=/tmp/wineprefix DOTNET_CLI_TELEMETRY_OPTOUT=1
            mkdir -p /tmp/t/dotnet /tmp/t/wix /tmp/t/util
            cd /tmp/t
            python3 -c "import sys,zipfile; [zipfile.ZipFile(a).extractall(b) for a,b in zip(sys.argv[1::2], sys.argv[2::2])]" \
                /cache/dotnet-runtime-'"$DOTNET_VERSION"'-win-x64.zip dotnet \
                /cache/wix.'"$WIX_VERSION"'.nupkg wix \
                /cache/wixtoolset.util.wixext.'"$WIX_VERSION"'.nupkg util
            wine64 wineboot -i >/dev/null 2>&1 || true
            wine64 /tmp/t/dotnet/dotnet.exe /tmp/t/wix/tools/net6.0/any/wix.dll build \
                "Z:\\src\\packaging\\windows\\autofirma.wxs" -arch x64 \
                -ext "Z:\\tmp\\t\\util\\wixext5\\WixToolset.Util.wixext.dll" \
                -d Version='"$numver"' -d "BinDir=Z:\\w\\bin" '"$has_cli"' \
                -o "Z:\\w\\out\\autofirma.msi"
            test -s /w/out/autofirma.msi
        '
    mv "$WORK/wix/out/autofirma.msi" "$OUT/$msi"
    info "MSI (WiX $WIX_VERSION): $OUT/$msi"
fi

# ------------------------------------------------------------------ MSI de humo (wixl)
if [ "$WIXL" = 1 ]; then
    numver="$(numeric_version "$VERSION")"
    msi="AutoFirma-$VERSION-windows-$ARCH-wixl-smoke.msi"
    mkdir -p "$WORK/msi"
    cp "$EXE" "$WORK/msi/autofirma.exe"
    cp "$ROOT/packaging/icons/autofirma.ico" "$ROOT/license/gpl-2.0.txt" \
        "$ROOT/packaging/windows/wixl/autofirma-smoke.wxs" "$WORK/msi/"
    info "Generando el MSI de humo con wixl"
    docker run --rm -v "$WORK/msi:/w" -w /w -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" debian:trixie bash -euc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null && apt-get install -y -qq wixl msitools >/dev/null
        wixl -a x64 -D Version='"$numver"' -D BinDir=/w -D IconFile=/w/autofirma.ico \
             -D LicenseFile=/w/gpl-2.0.txt -o /w/out.msi /w/autofirma-smoke.wxs
        echo "--- Tablas:"; msiinfo tables out.msi | sort | tr "\n" " "; echo
        echo "--- File:"; msiinfo export out.msi File
        echo "--- Shortcut:"; msiinfo export out.msi Shortcut
        echo "--- Property:"; msiinfo export out.msi Property
        chown "$HOST_UID:$HOST_GID" out.msi
    '
    mv "$WORK/msi/out.msi" "$OUT/$msi"
    info "MSI de humo: $OUT/$msi"
fi
