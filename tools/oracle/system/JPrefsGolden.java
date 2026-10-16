import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.prefs.Preferences;

/**
 * Genera ficheros de referencia para afirma-system:
 *  - un árbol java.util.prefs de usuario (FileSystemPreferences de Linux) con claves de
 *    AutoFirma, una tarjeta con nombre no ASCII y un nodo con punto (nombres alt-base64);
 *  - contraseñas de proxy cifradas con ProxyUtil.cipherPassword (AES) de la AutoFirma Java.
 *
 * Uso: java -Djava.util.prefs.userRoot=<dir> -cp autofirma.jar:. JPrefsGolden <fichero-proxy>
 */
public class JPrefsGolden {
    public static void main(String[] args) throws Exception {
        Preferences p = Preferences.userRoot().node("/es/gob/afirma/standalone/ui/preferences");
        p.putBoolean("preferencesBlocked", true);
        p.put("signatureHashAlgorithm", "SHA512");
        p.put("xadesSignFormat", "XAdES Detached");
        p.put("pdfLayer2Text", "Firmado por $$SUBJECTCN$$ el día <hoy> & \"mañana\"");
        p.put("defaultLocalKeystorePath", "/home/u/certs/a.p12");
        Preferences k = Preferences.userRoot().node("/es/gob/afirma/core/keystores/1");
        k.put("Tarjeta España", "/usr/lib/libpkcs11-españa.so");
        Preferences d = Preferences.userRoot().node("/es/gob/afirma/plugin/hash.v2");
        d.put("createHashAlgorithm", "SHA-256");
        Preferences.userRoot().flush();

        // Cifrado de la contraseña del proxy (Java real).
        Class<?> c = Class.forName("es.gob.afirma.standalone.ProxyUtil");
        Method m = c.getMethod("cipherPassword", char[].class);
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            for (String pwd : new String[] { "secreto", "contraseña con ñ", "a", "0123456789abcdef0123" }) {
                w.write(pwd + "\t" + m.invoke(null, (Object) pwd.toCharArray()) + "\n");
            }
        }
    }
}
