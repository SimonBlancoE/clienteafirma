#!/usr/bin/env bash
# Compara AutoFirma-rs con AutoFirma Java en las mismas operaciones de línea de
# comandos: mediana de N ejecuciones del tiempo total y de la memoria máxima
# (RSS). Imprime una tabla en Markdown.
#
#   AFIRMA_JAR=/ruta/autofirma.jar tools/bench/compare_java.sh <autofirma-rs> [N]
set -euo pipefail
: "${AFIRMA_JAR:?Define AFIRMA_JAR con la ruta de autofirma.jar}"
RS=$(realpath "$1"); N=${2:-5}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
P12="$ROOT/testdata/pki/firmante-rsa.p12"
STORE=(-store "pkcs12:$P12" -password 12341234 -alias firmante-rsa)
head -c 20000000 /dev/urandom > "$W/datos-20MB.bin"
# PDF de 2,5 MB de las pruebas de la versión Java.
PDF="$ROOT/afirma-ui-miniapplet/src/test/resources/PDF_LARGER_THAN_2MB.pdf"
XML="$ROOT/testdata/xades/inputs/$(ls "$ROOT/testdata/xades/inputs" | grep '\.xml$' | head -1)"
PREFS=$(mktemp -d -p "$W")

# Mediana de N valores (uno por línea).
median() { sort -n | awk '{a[NR]=$1} END {print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }

measure() { # java|rs args...
  local impl=$1; shift; local times=() mems=()
  for _ in $(seq "$N"); do
    if [ "$impl" = java ]; then
      /usr/bin/time -f "%e %M" -o "$W/t" java -Djava.awt.headless=true -Djava.util.prefs.userRoot="$PREFS" \
        -jar "$AFIRMA_JAR" "$@" >/dev/null 2>&1 || true
    else
      /usr/bin/time -f "%e %M" -o "$W/t" "$RS" "$@" >/dev/null 2>&1 || true
    fi
    read -r t m < <(tail -1 "$W/t"); times+=("$t"); mems+=("$m")
  done
  echo "$(printf '%s\n' "${times[@]}" | median) $(( $(printf '%s\n' "${mems[@]}" | median | cut -d. -f1) / 1024 ))"
}

row() { # descripción args...
  local desc=$1; shift
  # Solo se miden operaciones que terminan bien en las dos versiones.
  "$RS" "$@" >/dev/null 2>&1 || { echo "| $desc | — | fallo en AutoFirma-rs | |"; return; }
  java -Djava.awt.headless=true -Djava.util.prefs.userRoot="$PREFS" -jar "$AFIRMA_JAR" "$@" >/dev/null 2>&1 \
    || { echo "| $desc | fallo en Java | — | |"; return; }
  read -r jt jm < <(measure java "$@")
  read -r rt rm < <(measure rs "$@")
  # /usr/bin/time mide en centésimas: por debajo se indica la cota.
  local rts ratio
  rts=$(awk -v b="$rt" 'BEGIN{ if (b < 0.01) print "< 0,01"; else printf "%.2f", b }')
  ratio=$(awk -v a="$jt" -v b="$rt" 'BEGIN{ if (b < 0.01) printf "> %.0f", a/0.01; else printf "%.1f", a/b }')
  printf '| %s | %s s / %s MB | %s s / %s MB | ×%s |\n' "$desc" "$jt" "$jm" "$rts" "$rm" "$ratio"
}

echo "| Operación (mediana de $N) | AutoFirma Java (tiempo / RAM máx.) | AutoFirma-rs | Más rápido |"
echo "|---|---|---|---|"
row "Arranque (ayuda de la línea de comandos)" -help
row "Listar certificados de un PKCS#12" listaliases -store "pkcs12:$P12" -password 12341234
row "Firma CAdES de 20 MB" sign -i "$W/datos-20MB.bin" -o "$W/o.csig" -format cades "${STORE[@]}"
row "Firma XAdES de un XML" sign -i "$XML" -o "$W/o.xsig" -format xades "${STORE[@]}"
row "Firma PAdES de un PDF ($(du -k "$PDF" | cut -f1) KB)" sign -i "$PDF" -o "$W/o.pdf" -format pades "${STORE[@]}"
"$RS" sign -i "$W/datos-20MB.bin" -o "$W/v.csig" -format cades "${STORE[@]}" >/dev/null 2>&1
row "Verificar la firma CAdES" verify -i "$W/v.csig"
