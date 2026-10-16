#!/usr/bin/env bash
# Empaquetado de AutoFirma-rs para macOS: AutoFirma.app universal (arm64 + x86_64), .dmg y
# .pkg (con postinstall que ejecuta `autofirma install --system`), con firma de código y
# notarización si hay credenciales.
#
# Uso: tools/package/macos.sh [opciones]
#
#   --binary <ruta>      Ejecutable ya compilado (universal o de una arquitectura); si no se
#                        indica, se compilan aarch64-apple-darwin y x86_64-apple-darwin y se
#                        unen con lipo.
#   --arch <lista>       Arquitecturas a compilar (por defecto aarch64,x86_64).
#   --no-dmg, --no-pkg   No generar el .dmg o el .pkg.
#   --out <dir>          Directorio de salida (por defecto target/dist).
#
# Firma y notarización (se omiten si faltan las variables):
#   MACOS_SIGN_IDENTITY       «Developer ID Application: … (EQUIPO)» (codesign).
#   MACOS_INSTALLER_IDENTITY  «Developer ID Installer: … (EQUIPO)» (productbuild).
#   MACOS_KEYCHAIN            Llavero con los certificados (opcional).
#   APPLE_API_KEY_PATH, APPLE_API_KEY_ID, APPLE_API_ISSUER_ID   clave de App Store Connect
#     para notarytool; o bien APPLE_ID, APPLE_TEAM_ID y APPLE_APP_PASSWORD.
#
# Fuera de macOS (sin lipo/iconutil/hdiutil/pkgbuild) solo se monta el .app con --binary y
# se empaqueta en .tar.gz para revisarlo. Compatible con el bash 3.2 de macOS.
set -euo pipefail

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

BINARY=""
ARCHS="aarch64,x86_64"
DMG=1
PKG=1
OUT="$ROOT/target/dist"
MIN_MACOS="${MACOSX_DEPLOYMENT_TARGET:-10.15}"
BUNDLE_ID="io.github.autofirma-rs.AutoFirma"
PKG_ID="io.github.autofirma-rs.AutoFirma.pkg"

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY="$2"; shift 2 ;;
        --arch) ARCHS="$2"; shift 2 ;;
        --no-dmg) DMG=0; shift ;;
        --no-pkg) PKG=0; shift ;;
        --out) OUT="$2"; shift 2 ;;
        -h | --help) usage 0 ;;
        *) warn "opción desconocida: $1"; usage 2 ;;
    esac
done

IS_MACOS=0
[ "$(uname -s)" = Darwin ] && IS_MACOS=1

VERSION="$(workspace_version)"
[ -n "$VERSION" ] || die "no se pudo leer la versión"
SHORT_VERSION="$(numeric_version "$VERSION")"
BUNDLE_VERSION="${AUTOFIRMA_BUILD_NUMBER:-$SHORT_VERSION}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LOCKED=()
if [ -n "${CI:-}" ]; then LOCKED=(--locked); fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/autofirma-mac.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------ ejecutable
if [ -z "$BINARY" ]; then
    [ "$IS_MACOS" = 1 ] || die "fuera de macOS indique --binary"
    export MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS"
    slices=()
    IFS=',' read -r -a arch_list <<<"$ARCHS"
    for a in "${arch_list[@]}"; do
        t="$a-apple-darwin"
        info "Compilando $t (macOS >= $MIN_MACOS)"
        cargo build --release ${LOCKED[@]+"${LOCKED[@]}"} -p autofirma --target "$t"
        slices+=("$CARGO_TARGET_DIR/$t/release/autofirma")
    done
    BINARY="$WORK/autofirma"
    if [ "${#slices[@]}" -gt 1 ]; then
        lipo -create -output "$BINARY" "${slices[@]}"
    else
        cp "${slices[0]}" "$BINARY"
    fi
fi
[ -f "$BINARY" ] || die "no existe $BINARY"
if command -v lipo >/dev/null 2>&1; then
    info "Arquitecturas: $(lipo -archs "$BINARY")"
fi

# ------------------------------------------------------------------ AutoFirma.app
APP="$WORK/root/AutoFirma.app"
info "Montando AutoFirma.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
install -m 755 "$BINARY" "$APP/Contents/MacOS/autofirma"
sed -e "s/@SHORT_VERSION@/$SHORT_VERSION/g" -e "s/@BUNDLE_VERSION@/$BUNDLE_VERSION/g" -e "s/@MIN_MACOS@/$MIN_MACOS/g" \
    "$ROOT/packaging/macos/Info.plist" >"$APP/Contents/Info.plist"
printf 'APPL????' >"$APP/Contents/PkgInfo"
install -m 755 "$ROOT/packaging/macos/uninstall.sh" "$APP/Contents/Resources/uninstall.sh"
install -m 644 "$ROOT/license/gpl-2.0.txt" "$APP/Contents/Resources/LICENSE-gpl-2.0.txt"

if command -v iconutil >/dev/null 2>&1; then
    iconset="$WORK/AutoFirma.iconset"
    mkdir -p "$iconset"
    for n in 16 32 128 256 512; do
        cp "$ROOT/packaging/icons/autofirma-$n.png" "$iconset/icon_${n}x$n.png"
        cp "$ROOT/packaging/icons/autofirma-$((n * 2)).png" "$iconset/icon_${n}x${n}@2x.png"
    done
    iconutil -c icns -o "$APP/Contents/Resources/AutoFirma.icns" "$iconset"
else
    python3 -I "$ROOT/tools/package/mkicns.py" "$ROOT/packaging/icons" "$APP/Contents/Resources/AutoFirma.icns"
fi

# Info.plist válido y con el identificador esperado.
plist_id="$(python3 -I -c 'import plistlib,sys; print(plistlib.load(open(sys.argv[1],"rb"))["CFBundleIdentifier"])' "$APP/Contents/Info.plist")"
[ "$plist_id" = "$BUNDLE_ID" ] || die "CFBundleIdentifier inesperado: $plist_id"
if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$APP/Contents/Info.plist" >/dev/null
fi

# ------------------------------------------------------------------ firma de código
notarize() {
    local file="$1"
    local args=()
    if [ -n "${APPLE_API_KEY_PATH:-}" ] && [ -n "${APPLE_API_KEY_ID:-}" ] && [ -n "${APPLE_API_ISSUER_ID:-}" ]; then
        args=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID")
    elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
        args=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD")
    else
        return 1
    fi
    info "Notarizando $(basename "$file")"
    xcrun notarytool submit "$file" "${args[@]}" --wait --timeout 30m
}

can_notarize() {
    [ "$IS_MACOS" = 1 ] && [ -n "${MACOS_SIGN_IDENTITY:-}" ] && {
        { [ -n "${APPLE_API_KEY_PATH:-}" ] && [ -n "${APPLE_API_KEY_ID:-}" ] && [ -n "${APPLE_API_ISSUER_ID:-}" ]; } ||
            { [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; }
    }
}

KEYCHAIN_ARGS=()
if [ -n "${MACOS_KEYCHAIN:-}" ]; then KEYCHAIN_ARGS=(--keychain "$MACOS_KEYCHAIN"); fi

if [ "$IS_MACOS" = 1 ]; then
    if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
        info "Firmando AutoFirma.app ($MACOS_SIGN_IDENTITY)"
        codesign --force --timestamp --options runtime ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"} \
            --entitlements "$ROOT/packaging/macos/entitlements.plist" \
            --sign "$MACOS_SIGN_IDENTITY" "$APP"
    else
        warn "sin MACOS_SIGN_IDENTITY: firma ad hoc (Gatekeeper bloqueará la aplicación descargada)"
        codesign --force --sign - --entitlements "$ROOT/packaging/macos/entitlements.plist" "$APP"
    fi
    codesign --verify --strict --verbose=2 "$APP"
    if can_notarize; then
        ditto -c -k --keepParent "$APP" "$WORK/AutoFirma-app.zip"
        notarize "$WORK/AutoFirma-app.zip"
        xcrun stapler staple "$APP"
    else
        warn "sin credenciales de notarización: no se notariza"
    fi
fi

ARTIFACTS=()

if [ "$IS_MACOS" = 0 ]; then
    tarball="$OUT/AutoFirma-$VERSION-macos-app-layout.tar.gz"
    tar -C "$WORK/root" -czf "$tarball" AutoFirma.app
    ARTIFACTS+=("$tarball")
    warn "fuera de macOS solo se genera la estructura del .app ($tarball)"
    DMG=0
    PKG=0
fi

# ------------------------------------------------------------------ .dmg
if [ "$DMG" = 1 ]; then
    info "Generando .dmg"
    stage="$WORK/dmg"
    mkdir -p "$stage"
    ditto "$APP" "$stage/AutoFirma.app"
    ln -s /Applications "$stage/Aplicaciones"
    dmg="$OUT/AutoFirma-$VERSION-macos-universal.dmg"
    rm -f "$dmg"
    hdiutil create -volname "AutoFirma $VERSION" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"
    if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
        codesign --force --timestamp ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"} --sign "$MACOS_SIGN_IDENTITY" "$dmg"
    fi
    if can_notarize; then
        notarize "$dmg"
        xcrun stapler staple "$dmg"
    fi
    ARTIFACTS+=("$dmg")
fi

# ------------------------------------------------------------------ .pkg
if [ "$PKG" = 1 ]; then
    info "Generando .pkg"
    scripts="$WORK/scripts"
    mkdir -p "$scripts" "$WORK/pkgs" "$WORK/resources"
    install -m 755 "$ROOT/packaging/macos/scripts/postinstall" "$scripts/postinstall"
    install -m 755 "$ROOT/packaging/common/configure-hook.sh" "$scripts/configure-hook.sh"
    pkgbuild --root "$WORK/root" \
        --component-plist "$ROOT/packaging/macos/component.plist" \
        --install-location /Applications \
        --scripts "$scripts" \
        --identifier "$PKG_ID" \
        --version "$SHORT_VERSION" \
        "$WORK/pkgs/AutoFirma-component.pkg"
    sed -e "s/@VERSION@/$SHORT_VERSION/g" -e "s/@MIN_MACOS@/$MIN_MACOS/g" \
        "$ROOT/packaging/macos/distribution.xml" >"$WORK/distribution.xml"
    cp "$ROOT/license/gpl-2.0.txt" "$WORK/resources/LICENSE.txt"
    pkg="$OUT/AutoFirma-$VERSION-macos-universal.pkg"
    sign_args=()
    if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
        sign_args=(--sign "$MACOS_INSTALLER_IDENTITY" --timestamp ${KEYCHAIN_ARGS[@]+"${KEYCHAIN_ARGS[@]}"})
    else
        warn "sin MACOS_INSTALLER_IDENTITY: el .pkg no se firma (no se podrá desplegar por MDM)"
    fi
    productbuild --distribution "$WORK/distribution.xml" \
        --resources "$WORK/resources" \
        --package-path "$WORK/pkgs" \
        ${sign_args[@]+"${sign_args[@]}"} \
        "$pkg"
    if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
        pkgutil --check-signature "$pkg"
        if can_notarize; then
            notarize "$pkg"
            xcrun stapler staple "$pkg"
        fi
    fi
    ARTIFACTS+=("$pkg")
fi

info "Paquetes generados en $OUT:"
for a in "${ARTIFACTS[@]}"; do
    printf '  %s  %s\n' "$(sha256_of "$a")" "$(basename "$a")" >&2
done
