#!/bin/sh
# Ejecuta las pruebas de afirma-system para Windows con Wine dentro de la imagen
# autofirma-cross. Wine 8 no incluye bcryptprimitives.dll (ProcessPrng, que usa la
# biblioteca estándar de Rust), así que se compila un sustituto mínimo solo para las pruebas.
#
#   docker run --rm -v "$PWD":/src -v $HOME/.cargo/registry:/usr/local/cargo/registry \
#     -e CARGO_TARGET_DIR=/src/target/agents/afirma-system-cross -w /src autofirma-cross \
#     /src/tools/oracle/system/wine-test.sh --no-fail-fast
set -e
/usr/lib/wine/wine64 wineboot -i >/dev/null 2>&1 || true
x86_64-w64-mingw32-gcc -shared -O2 -o /tmp/bcryptprimitives.dll /src/tools/oracle/system/wine-bcryptprimitives.c -ladvapi32
cp /tmp/bcryptprimitives.dll "$HOME/.wine/drive_c/windows/system32/bcryptprimitives.dll"
export WINEDLLOVERRIDES="bcryptprimitives=n"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=/usr/lib/wine/wine64
export WINEDEBUG=-all
exec cargo test -p afirma-system --target x86_64-pc-windows-gnu "$@"
