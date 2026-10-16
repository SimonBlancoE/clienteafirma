import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.*;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.ValidateBinarySignature;

/**
 * Oráculo Java para las pruebas diferenciales de afirma-cms (CMS, CAdES y
 * CAdES-ASiC-S). Usa las clases de la AutoFirma Java original.
 *
 * <pre>
 * CP="$AFIRMA_JAR:tools/oracle/build"
 * java -cp "$CP" CmsOracle sign FORMATO ALGORITMO almacen.p12 datos salida [clave=valor ...]
 * java -cp "$CP" CmsOracle cosign FORMATO ALGORITMO almacen.p12 firma datos|- salida [clave=valor ...]
 * java -cp "$CP" CmsOracle countersign FORMATO ALGORITMO almacen.p12 firma tree|leafs|nodes|signers objetivos|- salida [clave=valor ...]
 * java -cp "$CP" CmsOracle tree FORMATO firma
 * java -cp "$CP" CmsOracle getdata FORMATO firma salida
 * java -cp "$CP" CmsOracle issign firma
 * java -cp "$CP" CmsOracle signinfo FORMATO firma
 * java -cp "$CP" CmsOracle validate|validatenocheck firma [datos]
 * java -cp "$CP" CmsOracle tsa URL [clave=valor ...]
 * java -cp "$CP" CmsOracle addts URL firma salida [clave=valor ...]
 * </pre>
 * Los objetivos de nodes son índices separados por comas; los de signers,
 * nombres separados por '|'. Las propiedades clave=valor admiten "\n" escapado.
 */
public class CmsOracle {

    public static void main(final String[] a) throws Exception {
        try {
            run(a);
        }
        catch (final Exception e) {
            System.out.println("ERROR " + e.getClass().getName() + ": " + e.getMessage());
            if (e instanceof AOException && ((AOException) e).getErrorCode() != null) {
                System.out.println("CODE " + ((AOException) e).getErrorCode().getCode());
            }
            System.exit(2);
        }
    }

    private static void run(final String[] a) throws Exception {
        switch (a[0]) {
            case "sign": {
                final AOSigner s = AOSignerFactory.getSigner(a[1]);
                final KeyStore.PrivateKeyEntry pke = load(a[3]);
                final byte[] out = s.sign(read(a[4]), a[2], pke.getPrivateKey(), pke.getCertificateChain(), props(a, 6));
                Files.write(Paths.get(a[5]), out);
                System.out.println("OK " + out.length);
                break;
            }
            case "cosign": {
                final AOSigner s = AOSignerFactory.getSigner(a[1]);
                final KeyStore.PrivateKeyEntry pke = load(a[3]);
                final byte[] sign = read(a[4]);
                final byte[] out = "-".equals(a[5])
                    ? s.cosign(sign, a[2], pke.getPrivateKey(), pke.getCertificateChain(), props(a, 7))
                    : s.cosign(read(a[5]), sign, a[2], pke.getPrivateKey(), pke.getCertificateChain(), props(a, 7));
                Files.write(Paths.get(a[6]), out);
                System.out.println("OK " + out.length);
                break;
            }
            case "countersign": {
                final AOSigner s = AOSignerFactory.getSigner(a[1]);
                final KeyStore.PrivateKeyEntry pke = load(a[3]);
                final CounterSignTarget target = CounterSignTarget.getTarget(a[5]);
                Object[] targets = null;
                if (!"-".equals(a[6])) {
                    if (target == CounterSignTarget.NODES) {
                        final String[] parts = a[6].split(",");
                        targets = new Object[parts.length];
                        for (int i = 0; i < parts.length; i++) {
                            targets[i] = Integer.valueOf(parts[i].trim());
                        }
                    }
                    else {
                        targets = a[6].split("\\|");
                    }
                }
                final byte[] out = s.countersign(read(a[4]), a[2], target, targets, pke.getPrivateKey(), pke.getCertificateChain(), props(a, 8));
                if (out == null) {
                    System.out.println("NULL");
                    break;
                }
                Files.write(Paths.get(a[7]), out);
                System.out.println("OK " + out.length);
                break;
            }
            case "tree": {
                final AOSigner s = AOSignerFactory.getSigner(a[1]);
                final byte[] sign = read(a[2]);
                final AOTreeModel names = s.getSignersStructure(sign, false);
                System.out.println("NAMES" + (names == null ? " null" : AOTreeUtilShow(names)));
                final AOTreeModel infos = s.getSignersStructure(sign, true);
                if (infos == null) {
                    System.out.println("INFOS null");
                }
                else {
                    final StringBuilder sb = new StringBuilder();
                    walk((AOTreeNode) infos.getRoot(), 0, sb);
                    System.out.print("INFOS" + sb);
                    System.out.println();
                }
                break;
            }
            case "getdata": {
                final AOSigner s = AOSignerFactory.getSigner(a[1]);
                final byte[] d = s.getData(read(a[2]));
                if (d == null) {
                    System.out.println("NULL");
                }
                else {
                    Files.write(Paths.get(a[3]), d);
                    System.out.println("OK " + d.length);
                }
                break;
            }
            case "issign": {
                final byte[] sign = read(a[1]);
                for (final String f : new String[] { "CAdES", "CMS/PKCS#7", "CAdES-ASiC-S" }) {
                    System.out.println(f + " " + AOSignerFactory.getSigner(f).isSign(sign));
                }
                final AOSigner detected = AOSignerFactory.getSigner(sign);
                System.out.println("DETECTED " + (detected == null ? "null" : detected.getClass().getSimpleName()));
                break;
            }
            case "signinfo": {
                final AOSigner s = AOSignerFactory.getSigner(a[1]);
                System.out.println("FORMAT " + s.getSignInfo(read(a[2])).getFormat());
                break;
            }
            case "validate":
            case "validatenocheck": {
                final byte[] sign = read(a[1]);
                final boolean check = "validate".equals(a[0]);
                final List<SignValidity> l = ValidateBinarySignature.validate(sign, a.length > 2 ? read(a[2]) : null, check);
                for (final SignValidity v : l) {
                    System.out.println("VALIDITY " + v.getValidity() + " " + v.getError());
                }
                break;
            }
            case "tsa": {
                // Cliente RFC 3161 de AutoFirma (Bouncy Castle) contra una TSA.
                final Properties p = props(a, 2);
                p.setProperty("tsaURL", a[1]);
                final es.gob.afirma.signers.tsp.pkcs7.TsaParams tp = new es.gob.afirma.signers.tsp.pkcs7.TsaParams(p);
                final byte[] imprint = java.security.MessageDigest.getInstance(tp.getTsaHashAlgorithm()).digest("hola".getBytes());
                final byte[] tok = new es.gob.afirma.signers.tsp.pkcs7.CMSTimestamper(tp).getTimeStampToken(imprint, tp.getTsaHashAlgorithm(), Calendar.getInstance());
                System.out.println("OK " + tok.length);
                break;
            }
            case "addts": {
                // CAdES-T con CMSTimestamper.addTimestamp (la ruta que AutoFirma no llega a usar).
                final Properties p = props(a, 4);
                p.setProperty("tsaURL", a[1]);
                final es.gob.afirma.signers.tsp.pkcs7.TsaParams tp = new es.gob.afirma.signers.tsp.pkcs7.TsaParams(p);
                final byte[] out = new es.gob.afirma.signers.tsp.pkcs7.CMSTimestamper(tp).addTimestamp(read(a[2]), tp.getTsaHashAlgorithm(), Calendar.getInstance());
                Files.write(Paths.get(a[3]), out);
                System.out.println("OK " + out.length);
                break;
            }
            default:
                throw new IllegalArgumentException("Operacion desconocida: " + a[0]);
        }
    }

    private static String AOTreeUtilShow(final AOTreeModel m) {
        final StringBuilder sb = new StringBuilder();
        walkNames((AOTreeNode) m.getRoot(), 0, sb);
        return sb.toString();
    }

    private static void walkNames(final AOTreeNode n, final int depth, final StringBuilder sb) {
        for (int i = 0; i < n.getChildCount(); i++) {
            final AOTreeNode c = n.getChildAt(i);
            sb.append("\n");
            for (int d = 0; d < depth; d++) {
                sb.append("\t");
            }
            sb.append(c.getUserObject());
            walkNames(c, depth + 1, sb);
        }
    }

    private static void walk(final AOTreeNode n, final int depth, final StringBuilder sb) {
        for (int i = 0; i < n.getChildCount(); i++) {
            final AOTreeNode c = n.getChildAt(i);
            final AOSimpleSignInfo info = (AOSimpleSignInfo) c.getUserObject();
            sb.append("\n");
            for (int d = 0; d < depth; d++) {
                sb.append("\t");
            }
            sb.append(AOUtil.getCN(info.getCerts()[0]));
            sb.append(" | ").append(info.getSignAlgorithm());
            sb.append(" | ").append(info.getSigningTime() == null ? "null" : Long.toString(info.getSigningTime().getTime() / 1000));
            sb.append(" | ").append(info.getPkcs1() == null ? 0 : info.getPkcs1().length);
            walk(c, depth + 1, sb);
        }
    }

    private static byte[] read(final String p) throws IOException {
        return Files.readAllBytes(Paths.get(p));
    }

    private static Properties props(final String[] a, final int from) {
        final Properties p = new Properties();
        for (int i = from; i < a.length; i++) {
            final int eq = a[i].indexOf('=');
            p.setProperty(a[i].substring(0, eq), a[i].substring(eq + 1).replace("\\n", "\n"));
        }
        return p;
    }

    private static KeyStore.PrivateKeyEntry load(final String p12) throws Exception {
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = new FileInputStream(p12)) {
            ks.load(is, "12341234".toCharArray());
        }
        final Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                return (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection("12341234".toCharArray()));
            }
        }
        throw new IllegalStateException("Sin claves en " + p12);
    }
}
