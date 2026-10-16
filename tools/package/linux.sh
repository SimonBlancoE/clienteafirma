#!/usr/bin/env bash
# Empaquetado de AutoFirma-rs para Linux: .deb (cargo-deb), .rpm (cargo-generate-rpm),
# .tar.gz portable y AppImage.
#
# Uso: tools/package/linux.sh [opciones]
#
#   --target <triple>    x86_64-unknown-linux-gnu o aarch64-unknown-linux-gnu
#                        (por defecto, el del anfitrión).
#   --builder <modo>     Cómo se obtiene el ejecutable:
#                          cargo     cargo build --release (glibc del anfitrión)
#                          zigbuild  cargo zigbuild con glibc mínima (--glibc), recomendado
#                                    para publicar: funciona en distribuciones antiguas
#                          docker    zigbuild dentro de la imagen autofirma-cross:latest
#                          none      usar --binary (p. ej., un ejecutable ya compilado)
#                        Por defecto: zigbuild si está instalado, si no cargo.
#   --glibc <versión>    glibc mínima con zigbuild/docker (por defecto 2.28).
#   --binary <ruta>      Ejecutable ya compilado (implica --builder none).
#   --formats <lista>    deb,rpm,tar,appimage (por defecto todos).
#   --out <dir>          Directorio de salida (por defecto target/dist).
#
# Herramientas: cargo-deb (deb), cargo-generate-rpm (rpm), curl (descarga appimagetool
# con SHA-256 fijado), desktop-file-validate y appstreamcli (validación, opcionales).
# CARGO_TARGET_DIR se respeta.
set -euo pipefail

# shellcheck source=common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TARGET=""
BUILDER=""
GLIBC="2.28"
BINARY=""
FORMATS="deb,rpm,tar,appimage"
OUT="$ROOT/target/dist"
DOCKER_IMAGE="${AUTOFIRMA_CROSS_IMAGE:-autofirma-cross:latest}"

# appimagetool y runtime de tipo 2 fijados (versión y SHA-256).
APPIMAGETOOL_VERSION="1.9.1"
APPIMAGE_RUNTIME_VERSION="20251108"
declare -A APPIMAGETOOL_SHA=(
    [x86_64]=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
    [aarch64]=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
)
declare -A APPIMAGE_RUNTIME_SHA=(
    [x86_64]=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
    [aarch64]=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
)

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --builder) BUILDER="$2"; shift 2 ;;
        --glibc) GLIBC="$2"; shift 2 ;;
        --binary) BINARY="$2"; BUILDER=none; shift 2 ;;
        --formats) FORMATS="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        -h | --help) usage 0 ;;
        *) warn "opción desconocida: $1"; usage 2 ;;
    esac
done

has_format() { [[ ",$FORMATS," == *",$1,"* ]]; }

HOST="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
TARGET="${TARGET:-${HOST:-x86_64-unknown-linux-gnu}}"
case "$TARGET" in
    x86_64-unknown-linux-gnu) ARCH=x86_64 ;;
    aarch64-unknown-linux-gnu) ARCH=aarch64 ;;
    *) die "destino no admitido: $TARGET" ;;
esac
if [ -z "$BUILDER" ]; then
    if cargo zigbuild --help >/dev/null 2>&1; then BUILDER=zigbuild; else BUILDER=cargo; fi
fi

VERSION="$(workspace_version)"
[ -n "$VERSION" ] || die "no se pudo leer la versión de $ROOT/Cargo.toml"
PKG_VERSION="$(pkg_version "$VERSION")"
NAME="autofirma-rs"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
LOCKED=()
if [ -n "${CI:-}" ]; then LOCKED=(--locked); fi

# ------------------------------------------------------------------ compilación
BIN_DIR="$CARGO_TARGET_DIR/$TARGET/release"
info "AutoFirma-rs $VERSION para $TARGET (compilación: $BUILDER)"
case "$BUILDER" in
    cargo)
        cargo build --release "${LOCKED[@]}" -p autofirma --target "$TARGET"
        ;;
    zigbuild)
        cargo zigbuild --release "${LOCKED[@]}" -p autofirma --target "$TARGET.$GLIBC"
        ;;
    docker)
        # El registro de crates va en un volumen propio para no dejar ficheros de root en
        # ~/.cargo; al final se devuelve la propiedad de target/ al usuario.
        mkdir -p "$CARGO_TARGET_DIR"
        rel_target="$(realpath --relative-to="$ROOT" "$CARGO_TARGET_DIR" 2>/dev/null || true)"
        case "$rel_target" in
            "" | ../* | /*) die "con --builder docker, CARGO_TARGET_DIR debe estar dentro del repositorio" ;;
        esac
        docker run --rm \
            -v "$ROOT:/src" -w /src \
            -v autofirma-cargo-registry:/usr/local/cargo/registry \
            -e CARGO_TARGET_DIR="/src/$rel_target" \
            -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
            "$DOCKER_IMAGE" bash -euc "
                trap 'chown -R \"\$HOST_UID:\$HOST_GID\" \"\$CARGO_TARGET_DIR\"' EXIT
                rustup target add $TARGET >/dev/null
                cargo zigbuild --release ${LOCKED[*]} -p autofirma --target $TARGET.$GLIBC
            "
        ;;
    none)
        if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then die "--binary no indica un fichero"; fi
        mkdir -p "$BIN_DIR"
        if [ "$(realpath "$BINARY")" != "$(realpath -m "$BIN_DIR/autofirma")" ]; then
            install -m 755 "$BINARY" "$BIN_DIR/autofirma"
        fi
        ;;
    *) die "modo de compilación desconocido: $BUILDER" ;;
esac
EXE="$BIN_DIR/autofirma"
[ -x "$EXE" ] || die "no existe $EXE"

# Versión de glibc que exige el binario (para los requisitos del RPM).
GLIBC_REQ="$GLIBC"
if command -v readelf >/dev/null 2>&1; then
    found="$(readelf --version-info --wide "$EXE" 2>/dev/null | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1 || true)"
    if [ -n "$found" ]; then
        GLIBC_REQ="$found"
    fi
fi
info "El ejecutable requiere glibc >= $GLIBC_REQ"

# Validación de los ficheros de escritorio (si las herramientas están disponibles).
DESKTOP="$ROOT/packaging/linux/autofirma.desktop"
METAINFO="$ROOT/packaging/linux/io.github.autofirma_rs.AutoFirma.metainfo.xml"
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate "$DESKTOP" || die "autofirma.desktop no es válido"
fi
if command -v appstreamcli >/dev/null 2>&1; then
    appstreamcli validate --no-net "$METAINFO" >/dev/null || die "los metadatos AppStream no son válidos"
fi
if ! grep -q "release version=\"$PKG_VERSION\"" "$METAINFO"; then
    warn "$METAINFO no tiene una entrada <release> para $PKG_VERSION"
fi
if ! grep -q "^autofirma-rs ($PKG_VERSION-" "$ROOT/packaging/linux/debian-changelog"; then
    warn "packaging/linux/debian-changelog no tiene una entrada para $PKG_VERSION"
fi

ICON_SIZES=(16 24 32 48 64 128 256 512)

# Árbol share/ común (tar.gz y AppImage).
stage_share() {
    local dest="$1"
    install -Dm644 "$DESKTOP" "$dest/applications/autofirma.desktop"
    install -Dm644 "$METAINFO" "$dest/metainfo/io.github.autofirma_rs.AutoFirma.metainfo.xml"
    local n
    for n in "${ICON_SIZES[@]}"; do
        install -Dm644 "$ROOT/packaging/icons/autofirma-$n.png" "$dest/icons/hicolor/${n}x$n/apps/autofirma.png"
    done
}

ARTIFACTS=()

# ------------------------------------------------------------------ .deb
if has_format deb; then
    cargo deb --version >/dev/null 2>&1 || die "falta cargo-deb (cargo install --locked cargo-deb)"
    info "Generando .deb"
    DEB_VARIANT=()
    if ! command -v dpkg-shlibdeps >/dev/null 2>&1 || [ "$TARGET" != "$HOST" ]; then
        # Sin dpkg-shlibdeps (o con un binario de otra arquitectura) no se pueden calcular
        # las dependencias: se usa la variante con dependencias fijas para glibc 2.28.
        if ! version_le "$GLIBC_REQ" 2.28; then
            die "el ejecutable requiere glibc $GLIBC_REQ: genere el .deb en Debian/Ubuntu (dpkg-shlibdeps) o compile con --builder zigbuild"
        fi
        DEB_VARIANT=(--variant glibc228)
    fi
    deb_log="$(cargo deb -p autofirma --no-build --no-strip --target "$TARGET" "${DEB_VARIANT[@]}" --output "$OUT/" 2>&1)" \
        || { printf '%s\n' "$deb_log" >&2; die "cargo-deb ha fallado"; }
    printf '%s\n' "$deb_log" >&2
    deb="$(printf '%s\n' "$deb_log" | grep '\.deb$' | tail -n 1)"
    [ -f "$deb" ] || die "cargo-deb no generó el paquete"
    ARTIFACTS+=("$deb")
fi

# ------------------------------------------------------------------ .rpm
if has_format rpm; then
    cargo generate-rpm --version >/dev/null 2>&1 || die "falta cargo-generate-rpm (cargo install --locked cargo-generate-rpm)"
    info "Generando .rpm"
    rpm_out="$OUT/$NAME-$PKG_VERSION-1.$ARCH.rpm"
    cargo generate-rpm -p crates/autofirma --target "$TARGET" --target-dir "$CARGO_TARGET_DIR" \
        -s "version = \"$PKG_VERSION\"" \
        -s "requires = { \"libc.so.6(GLIBC_$GLIBC_REQ)(64bit)\" = \"*\", \"libgcc_s.so.1()(64bit)\" = \"*\" }" \
        -o "$rpm_out"
    [ -f "$rpm_out" ] || die "cargo-generate-rpm no generó el paquete"
    ARTIFACTS+=("$rpm_out")
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/autofirma-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------ .tar.gz
if has_format tar; then
    info "Generando .tar.gz"
    base="$NAME-$VERSION-linux-$ARCH"
    dir="$WORK/$base"
    mkdir -p "$dir"
    while read -r b; do install -m755 "$BIN_DIR/$b" "$dir/$b"; done < <(packaged_binaries "$BIN_DIR")
    install -m644 "$ROOT/packaging/linux/README-portable.txt" "$dir/README-portable.txt"
    install -Dm644 "$ROOT/license/gpl-2.0.txt" "$dir/LICENSE/gpl-2.0.txt"
    install -Dm644 "$ROOT/license/LICENSE.txt" "$dir/LICENSE/condiciones-autofirma.txt"
    stage_share "$dir/share"
    tarball="$OUT/$base.tar.gz"
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${SOURCE_DATE_EPOCH:-$(date +%s)}" \
        -C "$WORK" -czf "$tarball" "$base"
    ARTIFACTS+=("$tarball")
fi

# ------------------------------------------------------------------ AppImage
if has_format appimage; then
    info "Generando AppImage"
    cache="$(tools_cache_dir)"
    host_arch="$(uname -m)"
    tool="$cache/appimagetool-$APPIMAGETOOL_VERSION-$host_arch.AppImage"
    runtime="$cache/appimage-runtime-$APPIMAGE_RUNTIME_VERSION-$ARCH"
    [ -n "${APPIMAGETOOL_SHA[$host_arch]:-}" ] || die "appimagetool no está disponible para $host_arch"
    fetch_verified "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$host_arch.AppImage" \
        "$tool" "${APPIMAGETOOL_SHA[$host_arch]}"
    fetch_verified "https://github.com/AppImage/type2-runtime/releases/download/$APPIMAGE_RUNTIME_VERSION/runtime-$ARCH" \
        "$runtime" "${APPIMAGE_RUNTIME_SHA[$ARCH]}"
    chmod +x "$tool"

    appdir="$WORK/AutoFirma.AppDir"
    mkdir -p "$appdir/usr/bin"
    while read -r b; do install -m755 "$BIN_DIR/$b" "$appdir/usr/bin/$b"; done < <(packaged_binaries "$BIN_DIR")
    stage_share "$appdir/usr/share"
    install -m755 "$ROOT/packaging/linux/appimage/AppRun" "$appdir/AppRun"
    install -m644 "$DESKTOP" "$appdir/autofirma.desktop"
    install -m644 "$ROOT/packaging/icons/autofirma-256.png" "$appdir/autofirma.png"
    ln -s autofirma.png "$appdir/.DirIcon"

    appimage="$OUT/AutoFirma-$VERSION-$ARCH.AppImage"
    # Sin FUSE (contenedores, CI): el propio appimagetool se ejecuta extrayéndose. Los
    # metadatos AppStream ya se han validado arriba.
    ARCH="$ARCH" APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream --runtime-file "$runtime" \
        "$appdir" "$appimage"
    ARTIFACTS+=("$appimage")
fi

info "Paquetes generados en $OUT:"
for a in "${ARTIFACTS[@]}"; do
    printf '  %s  %s\n' "$(sha256_of "$a")" "$(basename "$a")" >&2
done
