# Imagen con Wine 10 (Debian trixie) para probar el ejecutable de Windows:
#   docker build -t autofirma-wine10 tools/e2e/wine
FROM debian:trixie
RUN dpkg --add-architecture i386 && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends wine wine64 xvfb xauth ca-certificates && rm -rf /var/lib/apt/lists/*
ENV WINEDEBUG=-all WINEPREFIX=/root/.wine
RUN (wine wineboot -i || true) && wineserver -w || true
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends imagemagick x11-utils xdotool mesa-utils libgl1-mesa-dri && rm -rf /var/lib/apt/lists/*
