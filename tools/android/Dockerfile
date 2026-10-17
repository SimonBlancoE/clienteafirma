# syntax=docker/dockerfile:1
#
# Imágenes de compilación y de prueba de AutoFirma-rs para Android.
#
#   docker build -f tools/android/Dockerfile --target build    -t autofirma-android-build tools/android
#   docker build -f tools/android/Dockerfile --target emulator -t autofirma-android-emulator tools/android
#
# (tools/android/build.sh y tools/android/emulator-test.sh las construyen si no existen).
#
# Todas las piezas del SDK de Android se descargan de dl.google.com con versión fija y se
# comprueba su SHA-256 (las sumas se calcularon tras verificar el SHA-1 que publica Google en
# https://dl.google.com/android/repository/repository2-3.xml y sys-img/google_apis/sys-img2-3.xml).
# Para actualizar una pieza: cambiar el nombre del ZIP y su SHA-256 en los ARG de abajo.

ARG RUST_IMAGE=rust:1.98.0-bookworm
ARG BASE_IMAGE=debian:bookworm-slim

# ----------------------------------------------------------------------------------------
# Piezas comunes del SDK: herramientas de línea de órdenes (sdkmanager, avdmanager) y adb.
FROM ${BASE_IMAGE} AS sdk-common
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
ARG ANDROID_REPO=https://dl.google.com/android/repository
# cmdline-tools 23.0
ARG CMDLINE_TOOLS_ZIP=commandlinetools-linux-16111833_latest.zip
ARG CMDLINE_TOOLS_SHA256=0877a1d048fe4a24efe2eff536ca4223f7adeb58648bb81909d33c446918cfa8
# platform-tools 37.0.1 (adb)
ARG PLATFORM_TOOLS_ZIP=platform-tools_r37.0.1-linux.zip
ARG PLATFORM_TOOLS_SHA256=d230f13842f60f782a8645f9c813f8f845bf36089ea7289f28c48f17979313f1
# Descarga $1 en $3 y comprueba que su SHA-256 es $2.
RUN printf '%s\n' '#!/bin/bash' 'set -euo pipefail' \
        'curl -fsSL --retry 3 -o "$3" "$1"' \
        'echo "$2  $3" | sha256sum -c --quiet -' > /usr/local/bin/fetch-verified \
    && chmod +x /usr/local/bin/fetch-verified
ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
    && fetch-verified "$ANDROID_REPO/$CMDLINE_TOOLS_ZIP" "$CMDLINE_TOOLS_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d "$ANDROID_HOME/cmdline-tools" \
    && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
    && fetch-verified "$ANDROID_REPO/$PLATFORM_TOOLS_ZIP" "$PLATFORM_TOOLS_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d "$ANDROID_HOME" \
    && rm /tmp/pkg.zip

# ----------------------------------------------------------------------------------------
# SDK de compilación: plataforma, build-tools y NDK.
FROM sdk-common AS sdk-build
# Plataforma Android 35 (compileSdk), revisión 2
ARG PLATFORM_ZIP=platform-35_r02.zip
ARG PLATFORM_DIR=android-35
ARG PLATFORM_SHA256=0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0
# build-tools 36.0.0 (versión mínima y por defecto del plugin de Gradle 9.4)
ARG BUILD_TOOLS_ZIP=build-tools_r36_linux.zip
ARG BUILD_TOOLS_VERSION=36.0.0
ARG BUILD_TOOLS_SHA256=5d9ac77fb6ff43d9da518a337b4fcf8f9097113df531d99ccefe80ef7ce8250b
# NDK r29 (29.0.14206865)
ARG NDK_ZIP=android-ndk-r29-linux.zip
ARG NDK_VERSION=29.0.14206865
ARG NDK_SHA256=4abbbcdc842f3d4879206e9695d52709603e52dd68d3c1fff04b3b5e7a308ecf
RUN mkdir -p "$ANDROID_HOME/platforms" "$ANDROID_HOME/build-tools" "$ANDROID_HOME/ndk" \
    && fetch-verified "$ANDROID_REPO/$PLATFORM_ZIP" "$PLATFORM_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d "$ANDROID_HOME/platforms" \
    && test -f "$ANDROID_HOME/platforms/$PLATFORM_DIR/android.jar" \
    && fetch-verified "$ANDROID_REPO/$BUILD_TOOLS_ZIP" "$BUILD_TOOLS_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d /tmp/bt \
    && mv /tmp/bt/* "$ANDROID_HOME/build-tools/$BUILD_TOOLS_VERSION" \
    && grep -q "^Pkg.Revision=$BUILD_TOOLS_VERSION" "$ANDROID_HOME/build-tools/$BUILD_TOOLS_VERSION/source.properties" \
    && fetch-verified "$ANDROID_REPO/$NDK_ZIP" "$NDK_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d /tmp/ndk \
    && mv /tmp/ndk/* "$ANDROID_HOME/ndk/$NDK_VERSION" \
    && grep -q "^Pkg.Revision = $NDK_VERSION" "$ANDROID_HOME/ndk/$NDK_VERSION/source.properties" \
    && rm -rf /tmp/pkg.zip /tmp/bt /tmp/ndk

# ----------------------------------------------------------------------------------------
# SDK del emulador: emulador e imagen de sistema x86_64 con las API de Google.
FROM sdk-common AS sdk-emulator
# Emulador 37.2.12 (canal estable)
ARG EMULATOR_ZIP=emulator-linux_x64-16428233.zip
ARG EMULATOR_SHA256=b08fc43d8608d2955f607f1b287beb525041e730086bdca3af152accac3af9c1
# Imagen de sistema Android 35, google_apis, x86_64, revisión 9
ARG SYSTEM_IMAGE_ZIP=x86_64-35_r09.zip
ARG SYSTEM_IMAGE_API=35
ARG SYSTEM_IMAGE_SHA256=c67b9ba0ff5bc0eb6d046871bfa228af14d4d47b02f0cdae94f048e511b7566e
RUN fetch-verified "$ANDROID_REPO/$EMULATOR_ZIP" "$EMULATOR_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d "$ANDROID_HOME" \
    && test -x "$ANDROID_HOME/emulator/emulator" \
    && mkdir -p "$ANDROID_HOME/system-images/android-$SYSTEM_IMAGE_API/google_apis" \
    && fetch-verified "$ANDROID_REPO/sys-img/google_apis/$SYSTEM_IMAGE_ZIP" "$SYSTEM_IMAGE_SHA256" /tmp/pkg.zip \
    && unzip -q /tmp/pkg.zip -d "$ANDROID_HOME/system-images/android-$SYSTEM_IMAGE_API/google_apis" \
    && rm /tmp/pkg.zip

# ----------------------------------------------------------------------------------------
# Imagen de compilación: Rust con los destinos de Android, cargo-ndk, JDK 17 y el SDK.
FROM ${RUST_IMAGE} AS build
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jdk-headless unzip \
    && rm -rf /var/lib/apt/lists/*
ARG CARGO_NDK_VERSION=4.1.2
RUN rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android \
    && rustup component add clippy rustfmt \
    && cargo install --locked "cargo-ndk@$CARGO_NDK_VERSION" \
    && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git" \
    && chmod -R a+rX "$CARGO_HOME" "$RUSTUP_HOME"
COPY --from=sdk-build /opt/android-sdk /opt/android-sdk
ARG NDK_VERSION=29.0.14206865
ENV ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_NDK_HOME=/opt/android-sdk/ndk/${NDK_VERSION} \
    ANDROID_NDK_ROOT=/opt/android-sdk/ndk/${NDK_VERSION} \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    PATH=/opt/android-sdk/platform-tools:/opt/android-sdk/cmdline-tools/latest/bin:${PATH}
# Los scripts ejecutan el contenedor con el usuario del anfitrión (HOME, CARGO_HOME y
# GRADLE_USER_HOME apuntan a un directorio montado); el SDK y Rust quedan de solo lectura.
WORKDIR /src

# ----------------------------------------------------------------------------------------
# Imagen del emulador (sin interfaz, con KVM): adb, emulador e imagen de sistema.
FROM ${BASE_IMAGE} AS emulator
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
# Bibliotecas que el emulador carga incluso con -no-window, y utilidades de las pruebas.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates file procps \
        libasound2 libdbus-1-3 libdrm2 libegl1 libexpat1 libfontconfig1 libgbm1 libgl1 \
        libnss3 libpulse0 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 \
        libxext6 libxfixes3 libxi6 libxkbcommon0 libxkbfile1 libxrandr2 libxrender1 libxtst6 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=sdk-emulator /opt/android-sdk /opt/android-sdk
ARG SYSTEM_IMAGE_API=35
ENV ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_AVD_HOME=/root/.android/avd \
    AUTOFIRMA_SYSTEM_IMAGE_API=${SYSTEM_IMAGE_API} \
    PATH=/opt/android-sdk/platform-tools:/opt/android-sdk/emulator:${PATH}
# Dispositivo virtual (equivalente a `avdmanager create avd`, que necesitaría Java): pantalla
# de 1080x2400 a 420 ppp, 4 núcleos y 4 GiB, GPU por software (SwiftShader).
RUN mkdir -p "$ANDROID_AVD_HOME/autofirma.avd" \
    && printf '%s\n' 'avd.ini.encoding=UTF-8' "path=$ANDROID_AVD_HOME/autofirma.avd" \
        "target=android-$SYSTEM_IMAGE_API" > "$ANDROID_AVD_HOME/autofirma.ini" \
    && printf '%s\n' 'AvdId=autofirma' 'avd.ini.displayname=AutoFirma' 'avd.ini.encoding=UTF-8' \
        'abi.type=x86_64' 'hw.cpu.arch=x86_64' 'hw.cpu.ncore=4' 'hw.ramSize=4096' \
        'vm.heapSize=512' 'disk.dataPartition.size=4G' 'hw.lcd.width=1080' 'hw.lcd.height=2400' \
        'hw.lcd.density=420' 'hw.gpu.enabled=yes' 'hw.gpu.mode=swiftshader_indirect' \
        'hw.keyboard=yes' 'hw.audioInput=no' 'hw.audioOutput=no' 'hw.camera.back=none' \
        'hw.camera.front=none' 'hw.sensors.orientation=no' 'showDeviceFrame=no' \
        'PlayStore.enabled=false' 'tag.id=google_apis' 'tag.display=Google APIs' \
        "image.sysdir.1=system-images/android-$SYSTEM_IMAGE_API/google_apis/x86_64/" \
        > "$ANDROID_AVD_HOME/autofirma.avd/config.ini"
WORKDIR /work
