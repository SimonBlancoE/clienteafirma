// Oráculo Java para las firmas XML: invoca directamente los firmadores de
// AutoFirma (clases del autofirma.jar) con un almacén PKCS#12 de pruebas.
//
//   java -cp "$AFIRMA_JAR:/tmp/xo" XmlOracle <firmador> <operación> <p12> <entrada> <salida> [clave=valor...]
//
// firmador: xades | xmldsig | facturae | asic | odf | ooxml
// operación: sign | cosign | countersign-tree | countersign-leafs | validate | tree | getdata | signinfo | issign
// Parámetro especial `algorithm=...` (por defecto SHA256withRSA, o SHA256withECDSA con clave EC).
// En `validate`, `tree`, `signinfo` e `issign` la salida es texto.
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import es.gob.afirma.core.signers.AOSignInfo;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;

public class XmlOracle {

    private static AOSigner signer(final String name) {
        switch (name) {
            case "xades": return new es.gob.afirma.signers.xades.AOXAdESSigner();
            case "xmldsig": return new es.gob.afirma.signers.xmldsig.AOXMLDSigSigner();
            case "facturae": return new es.gob.afirma.signers.xades.AOFacturaESigner();
            case "asic": return new es.gob.afirma.signers.xades.asic.AOXAdESASiCSSigner();
            case "odf": return new es.gob.afirma.signers.odf.AOODFSigner();
            case "ooxml": return new es.gob.afirma.signers.ooxml.AOOOXMLSigner();
            default: throw new IllegalArgumentException(name);
        }
    }

    private static void print(final AOTreeNode node, final int depth, final StringBuilder sb) {
        for (int i = 0; i < node.getChildCount(); i++) {
            final AOTreeNode c = node.getChildAt(i);
            sb.append("  ".repeat(depth)).append(c.getUserObject()).append('\n');
            print(c, depth + 1, sb);
        }
    }

    public static void main(final String[] a) throws Exception {
        java.util.logging.LogManager.getLogManager().reset();
        final AOSigner s = signer(a[0]);
        final String op = a[1];
        final byte[] in = Files.readAllBytes(new File(a[3]).toPath());
        final Properties p = new Properties();
        for (int i = 5; i < a.length; i++) {
            final int eq = a[i].indexOf('=');
            p.setProperty(a[i].substring(0, eq), a[i].substring(eq + 1));
        }
        String algorithm = (String) p.remove("algorithm");
        PrivateKey key = null;
        Certificate[] chain = null;
        if (!"-".equals(a[2])) {
            final KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(a[2])) {
                ks.load(fis, "12341234".toCharArray());
            }
            final Enumeration<String> aliases = ks.aliases();
            final String alias = aliases.nextElement();
            key = (PrivateKey) ks.getKey(alias, "12341234".toCharArray());
            chain = ks.getCertificateChain(alias);
            if (algorithm == null) {
                algorithm = "EC".equals(key.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
            }
        }
        byte[] out;
        switch (op) {
            case "sign": out = s.sign(in, algorithm, key, chain, p); break;
            case "cosign": out = s.cosign(in, algorithm, key, chain, p); break;
            case "countersign-tree": out = s.countersign(in, algorithm, CounterSignTarget.TREE, null, key, chain, p); break;
            case "countersign-leafs": out = s.countersign(in, algorithm, CounterSignTarget.LEAFS, null, key, chain, p); break;
            case "getdata": out = s.getData(in); break;
            case "validate":
            case "validate-certs": {
                final List<es.gob.afirma.signvalidation.SignValidity> r =
                    new es.gob.afirma.signvalidation.ValidateXMLSignature().validate(in, "validate-certs".equals(op));
                final StringBuilder sb = new StringBuilder();
                for (final es.gob.afirma.signvalidation.SignValidity v : r) {
                    sb.append(v.getValidity()).append(' ').append(v.getError()).append('\n');
                }
                out = sb.toString().getBytes("UTF-8");
                break;
            }
            case "tree": {
                final AOTreeModel t = s.getSignersStructure(in, false);
                final StringBuilder sb = new StringBuilder();
                print((AOTreeNode) t.getRoot(), 0, sb);
                out = sb.toString().getBytes("UTF-8");
                break;
            }
            case "signinfo": {
                final AOSignInfo si = s.getSignInfo(in);
                out = (si.getFormat() + "|" + si.getVariant() + "\n").getBytes("UTF-8");
                break;
            }
            case "issign": out = (s.isSign(in) + "\n").getBytes("UTF-8"); break;
            default: throw new IllegalArgumentException(op);
        }
        if (out == null) {
            out = "null".getBytes("UTF-8");
        }
        Files.write(new File(a[4]).toPath(), out);
    }
}
