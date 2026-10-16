import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.RuntimeConfigNeededException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.afirma.signers.pades.PdfUtil;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.ValidatePdfSignature;

/**
 * Oráculo Java para las pruebas diferenciales de afirma-pdf (PAdES). Usa las
 * clases de la AutoFirma Java original (autofirma.jar).
 *
 * <pre>
 * CP="$AFIRMA_JAR:tools/oracle/build"
 * java -cp "$CP" PdfOracle sign ALGORITMO almacen.p12 entrada.pdf salida.pdf [clave=valor ...]
 * java -cp "$CP" PdfOracle validate entrada.pdf [relaxed] [clave=valor ...]
 * java -cp "$CP" PdfOracle tree entrada.pdf [clave=valor ...]
 * java -cp "$CP" PdfOracle issign entrada.pdf
 * java -cp "$CP" PdfOracle emptyfields entrada.pdf
 * </pre>
 * La contraseña de los almacenes es 12341234 y el alias es el nombre del
 * fichero sin extensión. Los valores "@fichero" se sustituyen por el Base64
 * del contenido del fichero (para signatureRubricImage, image...). Las
 * propiedades admiten "\n" escapado.
 */
public class PdfOracle {

    public static void main(final String[] a) throws Exception {
        try {
            run(a);
        }
        catch (final RuntimeConfigNeededException e) {
            System.out.println("NEEDS " + e.getClass().getSimpleName() + " " + e.getRequestorText() + " " + e.getParam()
                + " denied=" + e.isDenied());
            if (e.getErrorCode() != null) {
                System.out.println("CODE " + e.getErrorCode().getCode());
            }
            System.exit(3);
        }
        catch (final Exception e) {
            System.out.println("ERROR " + e.getClass().getName() + ": " + e.getMessage());
            if (e instanceof AOException && ((AOException) e).getErrorCode() != null) {
                System.out.println("CODE " + ((AOException) e).getErrorCode().getCode());
            }
            System.exit(2);
        }
    }

    private static Properties props(final String[] a, final int from) throws IOException {
        final Properties p = new Properties();
        for (int i = from; i < a.length; i++) {
            final int eq = a[i].indexOf('=');
            if (eq < 0) {
                continue;
            }
            String v = a[i].substring(eq + 1).replace("\\n", "\n");
            if (v.startsWith("@")) {
                v = Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get(v.substring(1))));
            }
            p.setProperty(a[i].substring(0, eq), v);
        }
        return p;
    }

    private static void run(final String[] a) throws Exception {
        switch (a[0]) {
            case "sign": {
                final String algo = a[1];
                final Path p12 = Paths.get(a[2]);
                final String alias = p12.getFileName().toString().replaceAll("\\.p12$", "");
                final KeyStore ks = KeyStore.getInstance("PKCS12");
                try (InputStream is = Files.newInputStream(p12)) {
                    ks.load(is, "12341234".toCharArray());
                }
                final PrivateKey key = (PrivateKey) ks.getKey(alias, "12341234".toCharArray());
                final java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
                final byte[] data = Files.readAllBytes(Paths.get(a[3]));
                final byte[] res = new AOPDFSigner().sign(data, algo, key, chain, props(a, 5));
                Files.write(Paths.get(a[4]), res);
                System.out.println("OK " + res.length);
                break;
            }
            case "validate": {
                final byte[] data = Files.readAllBytes(Paths.get(a[1]));
                final ValidatePdfSignature v = new ValidatePdfSignature();
                int from = 2;
                if (a.length > 2 && "relaxed".equals(a[2])) {
                    v.setRelaxed(true);
                    from = 3;
                }
                final List<SignValidity> res = v.validate(data, props(a, from));
                for (final SignValidity sv : res) {
                    System.out.println(sv.getValidity() + " " + sv.getError());
                }
                break;
            }
            case "tree": {
                final byte[] data = Files.readAllBytes(Paths.get(a[1]));
                final AOTreeModel tree = new AOPDFSigner().getSignersStructure(data, props(a, 2), false);
                final AOTreeNode root = (AOTreeNode) tree.getRoot();
                for (int i = 0; i < root.getChildCount(); i++) {
                    System.out.println(root.getChildAt(i).getUserObject());
                }
                break;
            }
            case "issign": {
                final byte[] data = Files.readAllBytes(Paths.get(a[1]));
                System.out.println(new AOPDFSigner().isSign(data));
                break;
            }
            case "emptyfields": {
                final byte[] data = Files.readAllBytes(Paths.get(a[1]));
                for (final Object f : PdfUtil.getPdfEmptySignatureFields(data)) {
                    System.out.println(f);
                }
                break;
            }
            default:
                throw new IllegalArgumentException("Operacion desconocida: " + a[0]);
        }
    }
}
