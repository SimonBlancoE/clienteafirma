#!/bin/sh
# Comprobación cruzada de afirma-keystores para Windows y macOS dentro de la
# imagen autofirma-cross (ver docs/AGENT-GUIDE.md):
#   - x86_64-pc-windows-gnu: cargo clippy (módulo `capi`, CNG/CryptoAPI);
#   - aarch64/x86_64-apple-darwin: cargo zigbuild de la biblioteca y clippy
#     (módulo `keychain`, Security.framework). Las pruebas de macOS no se
#     pueden enlazar sin el SDK de Apple.
#
#   tools/oracle/keystores-cross-check.sh            # usa el repositorio
#   AFIRMA_CROSS_WS=/ruta/espacio tools/oracle/keystores-cross-check.sh
#
# Para ejecutar además las pruebas de Windows en Wine:
#   tools/oracle/keystores-capi-wine.sh (ver su cabecera).
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WS=${AFIRMA_CROSS_WS:-$ROOT}
docker run --rm -v "$ROOT":"$ROOT" -v "$WS":"$WS" -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR="$ROOT/target/cross-keystores" -w "$WS" autofirma-cross sh -c '
    set -e
    echo "=== clippy x86_64-pc-windows-gnu"
    cargo clippy --offline -p afirma-keystores --target x86_64-pc-windows-gnu --all-targets 2>&1 | grep -E "^(warning|error)|-->|Finished" | grep -v "afirma-core" || true
    for T in aarch64-apple-darwin x86_64-apple-darwin; do
      echo "=== zigbuild $T"
      cargo zigbuild --offline --target $T -p afirma-keystores --lib 2>&1 | grep -E "^(warning|error)|-->|Finished" || true
      W=$(find / -xdev -name "zigcc-$T*" 2>/dev/null | head -1)
      A=$(find / -xdev -name "zigar*" 2>/dev/null | head -1)
      U=$(echo $T | tr - _)
      echo "=== clippy $T"
      env "CC_$U=$W" "AR_$U=$A" cargo clippy --offline --target $T -p afirma-keystores --all-targets 2>&1 | grep -E "^(warning|error)|-->|Finished" || true
    done'
