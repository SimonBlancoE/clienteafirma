#!/bin/sh
# Ejecuta el oráculo Java de la firma web de Autofirma App 1.9
# (tools/oracle/AndroidWebOracle.java) y regenera testdata/android-web/oracle.golden.
#
#   FIRMA_ANDROID=/ruta/firma-android JMIMEMAGIC_JAR=/ruta/afirma-lib-jmimemagic-0.0.10.jar \
#     tools/oracle/android_web_oracle.sh
#
# Compila afirma-core desde la etiqueta v1.9 de este repositorio (la versión que usa la
# app) y las clases de la app que intervienen (CipherDataManager, ErrorManager,
# IntermediateServerUtil), con un Logger vacío en lugar del de Android.
set -e
: "${FIRMA_ANDROID:?Define FIRMA_ANDROID con la ruta del repositorio firma-android}"
: "${JMIMEMAGIC_JAR:?Define JMIMEMAGIC_JAR con la ruta de afirma-lib-jmimemagic-0.0.10.jar}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$(mktemp -d)}
APP="$FIRMA_ANDROID/afirma-ui-android/app/src/main/java/es/gob/afirma/android"
mkdir -p "$WORK/src" "$WORK/core" "$WORK/app/es/gob/afirma/android" "$WORK/cls"
git -C "$ROOT" archive v1.9 afirma-core/src/main | tar -x -C "$WORK/src"
find "$WORK/src" -name '*.java' > "$WORK/core.txt"
javac -nowarn -encoding UTF-8 -cp "$JMIMEMAGIC_JAR" -d "$WORK/core" @"$WORK/core.txt"
cp -r "$WORK/src/afirma-core/src/main/resources/." "$WORK/core/"
cat > "$WORK/app/es/gob/afirma/android/Logger.java" <<'EOF'
package es.gob.afirma.android;
/** Sustituto sin dependencias de Android del Logger de la app. */
public final class Logger {
    private Logger() { }
    public static void i(final String t, final String m) { }
    public static void d(final String t, final String m) { }
    public static void w(final String t, final String m) { }
    public static void w(final String t, final String m, final Throwable e) { }
    public static void e(final String t, final String m) { }
    public static void e(final String t, final String m, final Throwable e) { }
}
EOF
javac -nowarn -encoding UTF-8 -cp "$WORK/core" -d "$WORK/cls" \
  "$WORK/app/es/gob/afirma/android/Logger.java" \
  "$APP/crypto/CipherDataManager.java" "$APP/errors/ErrorManager.java" "$APP/IntermediateServerUtil.java" \
  "$ROOT/tools/oracle/AndroidWebOracle.java"
java -Dfile.encoding=UTF-8 -Duser.language=es -Duser.country=ES -cp "$WORK/core:$WORK/cls:$JMIMEMAGIC_JAR" \
  AndroidWebOracle "$ROOT/testdata/android-web/cases.txt" > "$ROOT/testdata/android-web/oracle.golden"
echo "Generado testdata/android-web/oracle.golden"
