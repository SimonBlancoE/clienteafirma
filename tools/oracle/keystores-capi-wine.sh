#!/bin/sh
# Ejecuta en Wine las pruebas de afirma-keystores compiladas para Windows
# (almacén de Windows, módulo `capi`). Se lanza dentro de la imagen
# autofirma-cross:
#
#   docker run --rm -v "$PWD":/src -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
#       -e CARGO_TARGET_DIR=/src/target/cross-capi autofirma-cross \
#       sh /src/tools/oracle/keystores-capi-wine.sh --include-ignored --nocapture capi
#
# Los argumentos se pasan al binario de pruebas. La prueba ignorada
# `smoke_import_sign_verify` importa certificados de testdata/pki en el
# almacén MY del prefijo de Wine (que se crea dentro del contenedor y se
# descarta al terminar). Wine 8 no implementa ProcessPrng
# (bcryptprimitives.dll), que importa la biblioteca estándar de Rust: se
# compila un sustituto desde tools/oracle/keystores-capi-bcryptprimitives.c.
set -e
cd /src
TARGET_DIR=${CARGO_TARGET_DIR:-/src/target}
cargo test --offline -p afirma-keystores --target x86_64-pc-windows-gnu --no-run 2>&1 | grep -E "^error|Executable" || true
EXE=$(ls -t "$TARGET_DIR"/x86_64-pc-windows-gnu/debug/deps/afirma_keystores-*.exe | head -1)
x86_64-w64-mingw32-gcc -shared -o "$(dirname "$EXE")/bcryptprimitives.dll" tools/oracle/keystores-capi-bcryptprimitives.c -ladvapi32
export WINEPREFIX=/root/wineprefix WINEDLLOVERRIDES="mscoree,mshtml=" WINEDEBUG=${WINEDEBUG:--all}
/usr/lib/wine/wine64 wineboot -i >/dev/null 2>&1
exec /usr/lib/wine/wine64 "$EXE" "$@"
