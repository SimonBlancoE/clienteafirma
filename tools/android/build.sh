#!/usr/bin/env bash
# Compilación reproducible de AutoFirma-rs para Android: APK de depuración y release para todas
# las ABI, en la imagen Docker de tools/android/Dockerfile (JDK 17, SDK 35, build-tools 36,
# NDK r29, Rust con los destinos de Android y cargo-ndk, todo con versión y SHA-256 fijados).
#
# Uso: tools/android/build.sh [opciones]
#
#   --debug             Solo el APK de depuración.
#   --release           Solo el APK release (firmado; véase AUTOFIRMA_ANDROID_KEYSTORE).
#   --abis <lista>      ABI separadas por comas (por defecto arm64-v8a,armeabi-v7a,x86_64).
#   --clippy            Pasar antes clippy (-D warnings) al crate para Android (arm64-v8a).
#   --out <dir>         Directorio de los APK (por defecto $AUTOFIRMA_ANDROID_BUILD_DIR/dist).
#   --rebuild-image     Reconstruir la imagen Docker aunque ya exista.
#   --no-docker         Usar las herramientas del anfitrión (JDK 17, ANDROID_HOME con
#                       build-tools 36.0.0 y la plataforma 35, NDK 29.0.14206865 y cargo-ndk).
#
# Variables de entorno:
#   AUTOFIRMA_ANDROID_BUILD_DIR   Salidas y cachés: Gradle, registro y objetivo de Cargo, HOME del
#                                 contenedor (por defecto target/android del repositorio). Puede
#                                 estar en otro disco, p. ej. /mnt/datos/autofirma-build/android.
#   AUTOFIRMA_ANDROID_KEYSTORE    Almacén PKCS#12 con el que se firma la release (por defecto
#                                 ~/.config/autofirma-rs/android/release-prueba.p12, fuera del
#                                 repositorio). Si no existe se genera uno DE PRUEBA.
#   AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD  Contraseña del almacén (por defecto «autofirma-prueba»).
#   AUTOFIRMA_ANDROID_KEY_ALIAS   Alias de la clave (por defecto «autofirma»).
#   AUTOFIRMA_ANDROID_IMAGE       Imagen de compilación (por defecto autofirma-android-build).
#   AUTOFIRMA_BUILD_NUMBER        versionCode del APK (por defecto 1).
set -euo pipefail

# shellcheck source-path=SCRIPTDIR source=../package/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../package/common.sh"

# SHA-256 oficial de gradle-wrapper.jar 9.8.1 (services.gradle.org/distributions/...-wrapper.jar.sha256).
GRADLE_WRAPPER_SHA256=3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98

VARIANTS=(debug release)
ABIS="arm64-v8a,armeabi-v7a,x86_64"
CLIPPY=0
OUT=""
REBUILD_IMAGE=0
USE_DOCKER=1
IMAGE="${AUTOFIRMA_ANDROID_IMAGE:-autofirma-android-build}"
BUILD_DIR="${AUTOFIRMA_ANDROID_BUILD_DIR:-$ROOT/target/android}"
KEYSTORE="${AUTOFIRMA_ANDROID_KEYSTORE:-${XDG_CONFIG_HOME:-$HOME/.config}/autofirma-rs/android/release-prueba.p12}"
KEYSTORE_PASSWORD="${AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD:-autofirma-prueba}"
KEY_ALIAS="${AUTOFIRMA_ANDROID_KEY_ALIAS:-autofirma}"
export AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD="$KEYSTORE_PASSWORD" AUTOFIRMA_ANDROID_KEY_ALIAS="$KEY_ALIAS"

usage() {
    sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --debug) VARIANTS=(debug); shift ;;
        --release) VARIANTS=(release); shift ;;
        --abis) ABIS="$2"; shift 2 ;;
        --clippy) CLIPPY=1; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --rebuild-image) REBUILD_IMAGE=1; shift ;;
        --no-docker) USE_DOCKER=0; shift ;;
        -h | --help) usage 0 ;;
        *) warn "opción desconocida: $1"; usage 2 ;;
    esac
done

VERSION="$(workspace_version)"
[ -n "$VERSION" ] || die "no se pudo leer la versión"
WRAPPER_JAR="$ROOT/android/gradle/wrapper/gradle-wrapper.jar"
[ "$(sha256_of "$WRAPPER_JAR")" = "$GRADLE_WRAPPER_SHA256" ] \
    || die "gradle-wrapper.jar no coincide con el SHA-256 oficial de Gradle 9.8.1"

mkdir -p "$BUILD_DIR"/{gradle,gradle-project,cargo-home,home,target}
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
OUT="${OUT:-$BUILD_DIR/dist}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

TASKS=()
for v in "${VARIANTS[@]}"; do
    TASKS+=("assemble${v^}")
done
SIGN_RELEASE=0
[[ " ${VARIANTS[*]} " == *" release "* ]] && SIGN_RELEASE=1

# Ejecuta una orden con las herramientas de Android: en el contenedor (con el usuario del
# anfitrión, el repositorio en /src y BUILD_DIR en /build) o en el anfitrión.
KEYSTORE_DIR="$(dirname "$KEYSTORE")"
run() {
    if [ "$USE_DOCKER" = 1 ]; then
        local ks_env=()
        if [ "$SIGN_RELEASE" = 1 ]; then
            # La contraseña pasa por el entorno, no por la línea de órdenes (visible en ps).
            ks_env=(-v "$KEYSTORE_DIR:/keystore"
                -e AUTOFIRMA_ANDROID_KEYSTORE="/keystore/$(basename "$KEYSTORE")"
                -e AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD -e AUTOFIRMA_ANDROID_KEY_ALIAS)
        fi
        docker run --rm --user "$(id -u):$(id -g)" \
            -v "$ROOT:/src" -v "$BUILD_DIR:/build" "${ks_env[@]}" \
            -e HOME=/build/home -e ANDROID_USER_HOME=/build/home/.android \
            -e CARGO_HOME=/build/cargo-home -e CARGO_TARGET_DIR=/build/target \
            -e GRADLE_USER_HOME=/build/gradle -e AUTOFIRMA_ANDROID_BUILD_DIR=/build \
            -e CARGO_PROFILE_DEV_DEBUG=line-tables-only -e CARGO_TERM_COLOR \
            -e AUTOFIRMA_BUILD_NUMBER="${AUTOFIRMA_BUILD_NUMBER:-1}" \
            -w "/src/${WORKDIR:-}" "$IMAGE" "$@"
    else
        (
            cd "$ROOT/${WORKDIR:-}"
            export CARGO_TARGET_DIR="$BUILD_DIR/target" GRADLE_USER_HOME="${GRADLE_USER_HOME:-$BUILD_DIR/gradle}"
            export AUTOFIRMA_ANDROID_BUILD_DIR="$BUILD_DIR" CARGO_PROFILE_DEV_DEBUG=line-tables-only
            export AUTOFIRMA_BUILD_NUMBER="${AUTOFIRMA_BUILD_NUMBER:-1}"
            if [ "$SIGN_RELEASE" = 1 ]; then
                export AUTOFIRMA_ANDROID_KEYSTORE="$KEYSTORE"
            fi
            "$@"
        )
    fi
}

# Herramientas del SDK y del NDK (rutas del contenedor o de ANDROID_HOME/ANDROID_NDK_HOME).
tool() {
    local sdk="/opt/android-sdk" ndk="/opt/android-sdk/ndk/29.0.14206865"
    if [ "$USE_DOCKER" = 0 ]; then
        sdk="${ANDROID_HOME:?}"
        ndk="${ANDROID_NDK_HOME:?}"
    fi
    case "$1" in
        zipalign | apksigner) printf '%s' "$sdk/build-tools/36.0.0/$1" ;;
        llvm-readelf) printf '%s' "$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf" ;;
        *) die "herramienta desconocida: $1" ;;
    esac
}

# Ruta de un fichero de BUILD_DIR tal como la ve `run`.
build_path() {
    if [ "$USE_DOCKER" = 1 ]; then
        printf '/build/%s' "${1#"$BUILD_DIR"/}"
    else
        printf '%s' "$1"
    fi
}

if [ "$USE_DOCKER" = 1 ]; then
    if [ "$REBUILD_IMAGE" = 1 ] || ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
        info "Construyendo la imagen $IMAGE (tools/android/Dockerfile)"
        docker build -f "$ROOT/tools/android/Dockerfile" --target build -t "$IMAGE" "$ROOT/tools/android"
    fi
fi

if [ "$SIGN_RELEASE" = 1 ] && [ ! -f "$KEYSTORE" ]; then
    info "Generando un almacén de claves DE PRUEBA en $KEYSTORE"
    mkdir -p "$KEYSTORE_DIR"
    chmod 700 "$KEYSTORE_DIR"
    if [ "$USE_DOCKER" = 1 ]; then
        docker run --rm --user "$(id -u):$(id -g)" -v "$KEYSTORE_DIR:/keystore" -e HOME=/tmp \
            -e AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD "$IMAGE" \
            keytool -genkeypair -keystore "/keystore/$(basename "$KEYSTORE")" -storetype PKCS12 \
            -alias "$KEY_ALIAS" -keyalg RSA -keysize 3072 -validity 10000 \
            -dname "CN=AutoFirma-rs (prueba), O=AutoFirma-rs, C=ES" \
            -storepass:env AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD -keypass:env AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD
    else
        keytool -genkeypair -keystore "$KEYSTORE" -storetype PKCS12 \
            -alias "$KEY_ALIAS" -keyalg RSA -keysize 3072 -validity 10000 \
            -dname "CN=AutoFirma-rs (prueba), O=AutoFirma-rs, C=ES" \
            -storepass:env AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD -keypass:env AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD
    fi
    chmod 600 "$KEYSTORE"
fi

if [ "$CLIPPY" = 1 ]; then
    info "clippy del crate autofirma-android para Android (arm64-v8a)"
    run cargo ndk --target arm64-v8a --platform 23 clippy --package autofirma-android --all-targets --locked \
        -- -D warnings
fi

# El empaquetado incremental de AGP reescribe el APK anterior y deja huecos dentro: los APK se
# generan siempre desde cero.
rm -rf "$BUILD_DIR/gradle/app/outputs/apk"

info "Compilando ${TASKS[*]} (ABI: $ABIS)"
WORKDIR=android run ./gradlew --no-daemon --console=plain \
    --project-cache-dir "$(build_path "$BUILD_DIR/gradle-project")" \
    "-Pautofirma.abis=$ABIS" "${TASKS[@]}"

APK_DIR="$BUILD_DIR/gradle/app/outputs/apk"
for v in "${VARIANTS[@]}"; do
    src="$APK_DIR/$v/app-$v.apk"
    if [ "$v" = release ] && [ ! -f "$src" ]; then
        src="$APK_DIR/$v/app-$v-unsigned.apk"
    fi
    [ -f "$src" ] || die "no se generó el APK $v ($src)"
    # Bibliotecas nativas sin comprimir y alineadas a 16 KB (páginas de 16 KB, Android 15+).
    run "$(tool zipalign)" -c -P 16 4 "$(build_path "$src")" || die "$src no está alineado a 16 KB"
    if [ "$v" = release ]; then
        run "$(tool apksigner)" verify --print-certs "$(build_path "$src")" | sed -n '1,2p' >&2
    fi
    dest="$OUT/AutoFirma-$VERSION-$v.apk"
    cp "$src" "$dest"
    info "$dest ($(du -h "$dest" | cut -f1))"
done

# Segmentos LOAD de las bibliotecas de 64 bits alineados a 16 KB.
for so in "$BUILD_DIR"/gradle/app/rustJniLibs/*/{arm64-v8a,x86_64}/libautofirma_android.so; do
    [ -f "$so" ] || continue
    run "$(tool llvm-readelf)" -lW "$(build_path "$so")" \
        | awk '$1 == "LOAD" { n++; if ($NF !~ /^0x(4000|8000|10000)$/) bad = 1 } END { exit (bad || !n) }' \
        || die "${so#"$BUILD_DIR"/}: segmentos LOAD sin alinear a 16 KB"
done
info "APK en $OUT"
