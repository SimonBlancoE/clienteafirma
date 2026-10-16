#!/bin/sh
# Regenera los ficheros de referencia de testdata/hash/ con el plugin de huellas
# digitales de la AutoFirma Java (tools/oracle/HashOracle.java).
#   AFIRMA_JAR=/ruta/autofirma.jar HASH_JAR=/ruta/afirma-ui-simpleafirma-plugin-hash-1.2.jar \
#       tools/oracle/hash_oracle.sh
# Además deja en $W/run.sh (se imprime al final) un lanzador del oráculo que
# usan las pruebas diferenciales de crates/afirma-hash cuando se define
# AFIRMA_HASH_ORACLE=$W/run.sh.
set -e
: "${AFIRMA_JAR:?Define AFIRMA_JAR con la ruta de autofirma.jar}"
: "${HASH_JAR:?Define HASH_JAR con la ruta del JAR del plugin de huellas}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
D=$ROOT/testdata/hash
W=${W:-$(mktemp -d)}
CP="$AFIRMA_JAR:$HASH_JAR"
mkdir -p "$W/classes"
javac -encoding UTF-8 -cp "$CP" -d "$W/classes" "$ROOT/tools/oracle/HashOracle.java"
cat > "$W/run.sh" <<EOF
#!/bin/sh
exec java -Djava.awt.headless=true -Dfile.encoding=UTF-8 -Duser.language=es -Duser.country=ES -cp "$CP:$W/classes" HashOracle "\$@" 2>/dev/null
EOF
chmod +x "$W/run.sh"
ho() { "$W/run.sh" "$@"; }

T=$W/tree
rm -rf "$T" "$W/h" "$W/out"
mkdir -p "$T" "$W/out"
ho mktree "$D/tree.manifest" "$T"

# Documentos de huellas de directorio.
ho createdigest "$T" -r -o "$D/java-sha256-rec.hashfiles" >/dev/null
ho createdigest "$T" -halgorithm SHA-1 -o "$D/java-sha1-norec.hashfiles" >/dev/null
ho createdigest "$T" -r -halgorithm SHA-512 -hformat txt -o "$D/java-sha512-rec.txthashfiles" >/dev/null
ho createdigest "$T" -halgorithm SHA-384 -hformat TXT -o "$D/java-sha384-norec.txthashfiles" >/dev/null

# Huellas de un fichero.
H=$T/sub/hola.txt
ho createdigest "$H" -o "$D/java-hola-sha256.hexhash" >/dev/null
ho createdigest "$H" -hformat b64 -o "$D/java-hola-sha256.hashb64" >/dev/null
ho createdigest "$H" -hformat bin -o "$D/java-hola-sha256.hash" >/dev/null
ho createdigest "$H" -halgorithm SHA-1 -o "$D/java-hola-sha1.hexhash" >/dev/null
ho createdigest "$H" -halgorithm SHA-384 -hformat bin -o "$D/java-hola-sha384.hash" >/dev/null
ho createdigest "$H" -halgorithm SHA-512 -hformat b64 -o "$D/java-hola-sha512.hashb64" >/dev/null
ho createdigest "$T/sub/deep/grande.bin" -halgorithm SHA-512 -o "$D/java-grande-sha512.hexhash" >/dev/null

# Entradas derivadas para los casos de cli-cases.txt.
sed 's/h$//' "$D/java-hola-sha256.hexhash" | tr -d '\n' > "$D/hola-sin-h.hexhash"
printf '%s\r\n' "$(cat "$D/java-hola-sha256.hashb64")" > "$D/hola-crlf.hashb64"
tr '+/' '-_' < "$D/java-hola-sha256.hashb64" > "$D/hola-url.hashb64"
sed 's/hexhash="E3B0/hexhash="F3B0/' "$D/java-sha256-rec.hashfiles" > "$D/corrupto.hashfiles"
cp "$D/java-sha256-rec.hashfiles" "$D/sin-extension"

# Informes de comprobación sobre una copia modificada del árbol.
T2=$W/tree2
rm -rf "$T2"
cp -r "$T" "$T2"
printf 'adios\n' > "$T2/sub/hola.txt"
rm "$T2/vacio.txt"
printf 'n' > "$T2/nuevo.txt"
ho checkdigest "$T2" -i "$D/java-sha256-rec.hashfiles" -o "$D/java-report-sha256-rec.hashreport" >/dev/null
ho checkdigest "$T2" -i "$D/java-sha384-norec.txthashfiles" -o "$D/java-report-sha384-norec.hashreport" >/dev/null

# Casos de línea de comandos.
cp -r "$D" "$W/h"
G=$D/java-cli.golden
: > "$G"
grep -v '^#' "$D/cli-cases.txt" | grep -v '^$' | while IFS= read -r line; do
	args=$(printf '%s' "$line" | sed "s#\\\$TREE#$T#g")
	set +e
	# shellcheck disable=SC2086
	(cd "$T" && ho $args > "$W/case.out")
	status=$?
	set -e
	{
		printf '>>> %s\n' "$line"
		printf 'status: %s\n' "$status"
		sed "s#$T#\$TREE#g" "$W/case.out"
		printf '<<<\n'
	} >> "$G"
done

echo "Oráculo: AFIRMA_HASH_ORACLE=$W/run.sh"
