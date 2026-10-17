// Oráculo Java de la transformada XSLT de XMLDSig
// (http://www.w3.org/TR/1999/REC-xslt-19991116).
//
// Reproduce exactamente `TransformXSLT` de Apache Santuario 3.0.5 (la versión
// que usa AutoFirma): fábrica JAXP del JDK (XSLTC) con
// FEATURE_SECURE_PROCESSING y sin acceso externo, la hoja se reserializa con
// una transformación identidad desde su elemento DOM, se fija
// `{http://xml.apache.org/xalan}line-separator` a "\n" y la entrada son
// octetos.
//
//   javac -d /tmp/xo tools/oracle/xslt/XsltOracle.java
//   java -Duser.language=es -Duser.country=ES -cp /tmp/xo XsltOracle cases testdata/xslt/cases testdata/xslt/expected
//   java -Duser.language=es -Duser.country=ES -cp /tmp/xo XsltOracle sign testdata/pki/firmante-rsa.p12 testdata/xslt/signed
//   java -cp /tmp/xo XsltOracle run hoja.xsl entrada.xml
//
// Formato de los ficheros `.cases`: cada caso empieza con una línea
// `#### nombre`; la hoja va a continuación y, opcionalmente, tras una línea
// `====` la entrada. Un caso llamado `@input` fija la entrada por defecto de
// los casos siguientes del fichero. Para cada caso se escribe
// `<fichero>.<nombre>.out` (octetos de salida) o `<fichero>.<nombre>.err`
// (mensaje de error de Java) en el directorio de salida.
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.crypto.dsig.spec.XSLTTransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XsltOracle {

    private static final String XSLT_NS = "http://www.w3.org/1999/XSL/Transform";

    private static DocumentBuilderFactory dbf() {
        final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        return f;
    }

    /** `TransformXSLT.enginePerformTransform` con validación segura (Santuario 3.0.5). */
    static byte[] transformXslt(final Element transformElement, final byte[] input) throws Exception {
        Element xsltElement = selectNode(transformElement.getFirstChild(), "stylesheet");
        if (xsltElement == null) {
            xsltElement = selectNode(transformElement.getFirstChild(), "transform");
        }
        if (xsltElement == null) {
            throw new Exception("xml.WrongContent xslt:stylesheet");
        }
        final TransformerFactory tFactory = TransformerFactory.newInstance();
        tFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.TRUE);
        try {
            tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (final IllegalArgumentException ex) {
            // Como Santuario: se ignora.
        }
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        tFactory.newTransformer().transform(new DOMSource(xsltElement), new StreamResult(os));
        final Transformer transformer =
            tFactory.newTransformer(new StreamSource(new ByteArrayInputStream(os.toByteArray())));
        transformer.setOutputProperty("{http://xml.apache.org/xalan}line-separator", "\n");
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        transformer.transform(new StreamSource(new ByteArrayInputStream(input)), new StreamResult(out));
        return out.toByteArray();
    }

    /** `XMLUtils.selectNode(sibling, XSLT_NS, name, 0)`. */
    private static Element selectNode(Node sibling, final String name) {
        while (sibling != null) {
            if (sibling.getNodeType() == Node.ELEMENT_NODE && XSLT_NS.equals(sibling.getNamespaceURI())
                    && name.equals(sibling.getLocalName())) {
                return (Element) sibling;
            }
            sibling = sibling.getNextSibling();
        }
        return null;
    }

    /** Ejecuta una hoja (texto de un documento cuyo elemento raíz es la hoja) como hija de `ds:Transform`. */
    static byte[] runStylesheet(final byte[] xsl, final byte[] input) throws Exception {
        final Document sd = dbf().newDocumentBuilder().parse(new ByteArrayInputStream(xsl));
        return transformXsltFrom(sd.getDocumentElement(), input);
    }

    private static byte[] transformXsltFrom(final Element stylesheet, final byte[] input) throws Exception {
        // `selectNode` empieza en el primer hijo del Transform: aquí, la propia hoja.
        final Document holder = dbf().newDocumentBuilder().newDocument();
        final Element t = holder.createElementNS(XMLSignature.XMLNS, "ds:Transform");
        holder.appendChild(t);
        t.appendChild(holder.importNode(stylesheet, true));
        return transformXslt(t, input);
    }

    private static String errorText(final Throwable e) {
        Throwable c = e;
        final StringBuilder sb = new StringBuilder();
        while (c != null) {
            sb.append(c.getClass().getName()).append(": ").append(c.getMessage()).append('\n');
            c = c.getCause() == c ? null : c.getCause();
        }
        return sb.toString();
    }

    private static final class Case {
        final String name;
        final String xsl;
        final String input;

        Case(final String name, final String xsl, final String input) {
            this.name = name;
            this.xsl = xsl;
            this.input = input;
        }
    }

    static List<Case> parseCases(final String text) {
        final List<Case> out = new ArrayList<>();
        String defaultInput = "<doc/>";
        final String[] lines = text.split("\n", -1);
        int i = 0;
        while (i < lines.length) {
            if (!lines[i].startsWith("#### ")) {
                i++;
                continue;
            }
            final String name = lines[i].substring(5).trim();
            i++;
            final StringBuilder xsl = new StringBuilder();
            StringBuilder in = null;
            while (i < lines.length && !lines[i].startsWith("#### ")) {
                if (in == null && lines[i].equals("====")) {
                    in = new StringBuilder();
                } else {
                    final StringBuilder sb = in == null ? xsl : in;
                    if (sb.length() > 0) {
                        sb.append('\n');
                    }
                    sb.append(lines[i]);
                }
                i++;
            }
            final String x = trimEnd(xsl.toString());
            if ("@input".equals(name)) {
                defaultInput = x;
                continue;
            }
            out.add(new Case(name, x, in == null ? defaultInput : trimEnd(in.toString())));
        }
        return out;
    }

    private static String trimEnd(final String s) {
        int e = s.length();
        while (e > 0 && s.charAt(e - 1) == '\n') {
            e--;
        }
        return s.substring(0, e);
    }

    private static void cases(final Path inDir, final Path outDir) throws Exception {
        Files.createDirectories(outDir);
        final List<Path> files = new ArrayList<>();
        try (var s = Files.list(inDir)) {
            s.filter(p -> p.toString().endsWith(".cases")).forEach(files::add);
        }
        Collections.sort(files);
        int ok = 0;
        int err = 0;
        for (final Path f : files) {
            final String base = f.getFileName().toString().replace(".cases", "");
            for (final Case c : parseCases(new String(Files.readAllBytes(f), StandardCharsets.UTF_8))) {
                final Path outFile = outDir.resolve(base + "." + c.name + ".out");
                final Path errFile = outDir.resolve(base + "." + c.name + ".err");
                Files.deleteIfExists(outFile);
                Files.deleteIfExists(errFile);
                try {
                    final byte[] r = runStylesheet(c.xsl.getBytes(StandardCharsets.UTF_8),
                        c.input.getBytes(StandardCharsets.UTF_8));
                    Files.write(outFile, r);
                    ok++;
                } catch (final Throwable e) {
                    Files.write(errFile, errorText(e).getBytes(StandardCharsets.UTF_8));
                    err++;
                }
            }
        }
        System.out.println("casos: " + ok + " con salida, " + err + " con error");
    }

    // -----------------------------------------------------------------------
    // Firmas XMLDSig con la transformada XSLT
    // -----------------------------------------------------------------------

    private static PrivateKey key;
    private static X509Certificate cert;

    private static Element stylesheetElement(final String xsl) throws Exception {
        return dbf().newDocumentBuilder().parse(new ByteArrayInputStream(xsl.getBytes(StandardCharsets.UTF_8)))
            .getDocumentElement();
    }

    private static Transform xslt(final XMLSignatureFactory fac, final String xsl) throws Exception {
        return fac.newTransform(Transform.XSLT, new XSLTTransformParameterSpec(new DOMStructure(stylesheetElement(xsl))));
    }

    private static Transform plain(final XMLSignatureFactory fac, final String alg) throws Exception {
        return fac.newTransform(alg, (TransformParameterSpec) null);
    }

    private interface RefBuilder {
        List<Reference> refs(XMLSignatureFactory fac) throws Exception;
    }

    private static void sign(final Path outDir, final String name, final String docXml, final RefBuilder rb,
            final List<XMLObject> objects, final boolean enveloping) throws Exception {
        final Document doc = enveloping ? dbf().newDocumentBuilder().newDocument()
            : dbf().newDocumentBuilder().parse(new ByteArrayInputStream(docXml.getBytes(StandardCharsets.UTF_8)));
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        final SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), rb.refs(fac));
        final KeyInfoFactory kif = fac.getKeyInfoFactory();
        final KeyInfo ki = kif.newKeyInfo(List.of(kif.newX509Data(List.of(cert))));
        final DOMSignContext sc = new DOMSignContext(key, enveloping ? doc : doc.getDocumentElement());
        sc.setDefaultNamespacePrefix("ds");
        // La validación segura del JDK también prohíbe XSLT al firmar.
        sc.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        if (!enveloping) {
            final NodeList all = doc.getElementsByTagName("*");
            for (int k = 0; k < all.getLength(); k++) {
                final Element e = (Element) all.item(k);
                if (e.hasAttribute("Id")) {
                    sc.setIdAttributeNS(e, null, "Id");
                }
            }
        }
        final XMLSignature sig = fac.newXMLSignature(si, ki, objects, "Signature-" + name, null);
        sig.sign(sc);
        final ByteArrayOutputStream os = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(os));
        final byte[] bytes = os.toByteArray();
        // Comprobación con el propio JDK (sin validación segura, que prohíbe XSLT).
        if (!verify(bytes)) {
            throw new IllegalStateException("la firma generada no valida: " + name);
        }
        Files.write(outDir.resolve(name + ".xml"), bytes);
        System.out.println("firmado " + name);
    }

    static boolean verify(final byte[] bytes) throws Exception {
        final Document d = dbf().newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
        final NodeList nl = d.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        final PublicKey pk = new PublicKey(cert.getPublicKey());
        final DOMValidateContext vc = new DOMValidateContext(pk.get(), nl.item(0));
        vc.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        final NodeList all = d.getElementsByTagName("*");
        for (int k = 0; k < all.getLength(); k++) {
            final Element e = (Element) all.item(k);
            if (e.hasAttribute("Id")) {
                vc.setIdAttributeNS(e, null, "Id");
            }
        }
        return fac.unmarshalXMLSignature(vc).validate(vc);
    }

    private static final class PublicKey {
        private final java.security.PublicKey k;

        PublicKey(final java.security.PublicKey k) {
            this.k = k;
        }

        java.security.PublicKey get() {
            return this.k;
        }
    }

    private static void signAll(final Path p12, final Path outDir) throws Exception {
        Files.createDirectories(outDir);
        final KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(p12.toFile())) {
            ks.load(in, "12341234".toCharArray());
        }
        final String alias = ks.aliases().nextElement();
        key = (PrivateKey) ks.getKey(alias, "12341234".toCharArray());
        cert = (X509Certificate) ks.getCertificate(alias);
        SignedVectors.build(outDir);
        SignedVectors.more(outDir);
    }

    /** Definición de los vectores firmados (ver `testdata/xslt/signed/`). */
    static final class SignedVectors {
        static final String XSL = "xmlns:xsl=\"" + XSLT_NS + "\"";
        // Como en Facturae, solo el elemento raíz tiene espacio de nombres. Las
        // hojas no declaran espacios de nombres que ya estén en el documento:
        // al serializar la firma el JDK quitaría la declaración redundante (o
        // añadiría xmlns=""), `TransformXSLT` reserializa la hoja solo con sus
        // propias declaraciones y la salida (y el resumen) cambiaría al validar.
        static final String DOC = "<f:factura xmlns:f=\"urn:ejemplo:factura\" Id=\"F1\"><emisor nif=\"00000000T\">Empresa &amp; Cía</emisor>"
            + "<linea n=\"2\" precio=\"10.50\">Tornillos</linea><linea n=\"1\" precio=\"3\">Tuercas</linea>"
            + "<linea n=\"3\" precio=\"0.25\">Arandelas</linea><!-- comentario --><nota>  texto   con  espacios </nota></f:factura>";

        static void build(final Path out) throws Exception {
            final String sumXsl = "<xsl:stylesheet version=\"1.0\" " + XSL + ">"
                + "<xsl:output method=\"xml\" indent=\"yes\"/>"
                + "<xsl:template match=\"/\"><resumen><xsl:for-each select=\"//linea\"><xsl:sort select=\"@n\" data-type=\"number\"/>"
                + "<l pos=\"{position()}\" importe=\"{format-number(@precio * @n, '#,##0.00')}\"><xsl:value-of select=\".\"/></l>"
                + "</xsl:for-each><total><xsl:value-of select=\"sum(//linea/@precio)\"/></total></resumen></xsl:template></xsl:stylesheet>";
            // 1. Enveloped + XSLT (salida XML indentada) sobre el documento completo.
            sign(out, "enveloped-xslt", DOC, fac -> List.of(fac.newReference("",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(plain(fac, Transform.ENVELOPED), xslt(fac, sumXsl)), null, null)), null, false);
            // 2. Enveloped + XSLT + C14N (la salida se vuelve a analizar como XML).
            sign(out, "enveloped-xslt-c14n", DOC, fac -> List.of(fac.newReference("",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(plain(fac, Transform.ENVELOPED), xslt(fac, sumXsl),
                    plain(fac, CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)), null, null)), null, false);
            // 3. Salida de texto y salida HTML, con referencias a un ds:Object por Id
            //    (la entrada de la hoja es el propio ds:Object canonicalizado).
            final String textXsl = "<xsl:stylesheet version=\"1.0\" " + XSL + ">"
                + "<xsl:output method=\"text\" encoding=\"ISO-8859-1\"/><xsl:strip-space elements=\"*\"/>"
                + "<xsl:template match=\"linea\"><xsl:number format=\"i) \"/><xsl:value-of select=\"concat(., ': ', @precio)\"/>"
                + "<xsl:text>&#10;</xsl:text></xsl:template>"
                + "<xsl:template match=\"emisor\">Emisor: <xsl:value-of select=\"translate(., 'í', 'i')\"/> ñ€<xsl:text>&#10;</xsl:text></xsl:template>"
                + "<xsl:template match=\"nota\"><xsl:value-of select=\"normalize-space()\"/></xsl:template></xsl:stylesheet>";
            final String htmlXsl = "<xsl:stylesheet version=\"1.0\" " + XSL + " xmlns:x=\"urn:ejemplo:otro\" exclude-result-prefixes=\"x\">"
                + "<xsl:template match=\"/\"><html><head><title>Factura</title></head><body><table>"
                + "<xsl:apply-templates select=\"//linea\"><xsl:sort select=\".\"/></xsl:apply-templates></table>"
                + "<p>Emisor: <xsl:value-of select=\"//emisor\"/> &#160; <br/></p></body></html></xsl:template>"
                + "<xsl:template match=\"linea\"><tr><td><xsl:value-of select=\".\"/></td><td><xsl:value-of select=\"@precio\"/></td></tr></xsl:template>"
                + "</xsl:stylesheet>";
            sign(out, "object-text-html", null, fac -> {
                final List<Reference> refs = new ArrayList<>();
                refs.add(fac.newReference("#Object-1", fac.newDigestMethod(DigestMethod.SHA256, null),
                    List.of(xslt(fac, textXsl)), null, null));
                refs.add(fac.newReference("#Object-1", fac.newDigestMethod(DigestMethod.SHA512, null),
                    List.of(xslt(fac, htmlXsl)), null, null));
                return refs;
            }, objects(DOC), true);
            // 4. XPath + XSLT con claves, modos, variables y espacios de nombres.
            final String keysXsl = "<xsl:stylesheet version=\"1.0\" " + XSL + " xmlns:o=\"urn:salida\">"
                + "<xsl:key name=\"porPrecio\" match=\"linea\" use=\"@precio &gt; 1\"/>"
                + "<xsl:variable name=\"caras\" select=\"key('porPrecio', 'true')\"/>"
                + "<xsl:template match=\"/\"><o:caras n=\"{count($caras)}\"><xsl:apply-templates select=\"$caras\" mode=\"m\"/></o:caras></xsl:template>"
                + "<xsl:template match=\"linea\" mode=\"m\"><xsl:copy><xsl:copy-of select=\"@*\"/><xsl:attribute name=\"id\"><xsl:value-of select=\"generate-id() = generate-id(.)\"/></xsl:attribute></xsl:copy></xsl:template>"
                + "</xsl:stylesheet>";
            sign(out, "xpath-xslt", DOC, fac -> List.of(fac.newReference("",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(plain(fac, Transform.ENVELOPED),
                    fac.newTransform(Transform.XPATH, new XPathFilterParameterSpec("not(self::comment())")),
                    xslt(fac, keysXsl), plain(fac, CanonicalizationMethod.EXCLUSIVE)), null, null)), null, false);
        }

        static void more(final Path out) throws Exception {
            // 5. Referencia por Id al elemento raíz (que contiene la firma):
            //    enveloped + XSLT con salida UTF-16 indentada.
            final String utf16Xsl = "<xsl:stylesheet version=\"1.0\" " + XSL + ">"
                + "<xsl:output method=\"xml\" encoding=\"UTF-16\" indent=\"yes\" standalone=\"yes\"/>"
                + "<xsl:template match=\"/*\"><raiz nombre=\"{local-name()}\" ns=\"{namespace-uri()}\">"
                + "<xsl:for-each select=\"*\"><xsl:element name=\"{name()}\"><xsl:value-of select=\"string-length(.)\"/></xsl:element></xsl:for-each>"
                + "<xsl:comment>ñ &#x10437;</xsl:comment><xsl:processing-instruction name=\"pi\">a b</xsl:processing-instruction></raiz></xsl:template>"
                + "</xsl:stylesheet>";
            sign(out, "id-enveloped-xslt-utf16", DOC, fac -> List.of(fac.newReference("#F1",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(plain(fac, Transform.ENVELOPED), xslt(fac, utf16Xsl)), null, null)), null, false);
            // 6. Dos XSLT encadenadas (la segunda analiza los octetos de la
            //    primera) y C14N exclusiva al final.
            final String first = "<xsl:stylesheet version=\"1.0\" " + XSL + ">"
                + "<xsl:output method=\"xml\" encoding=\"ISO-8859-1\"/>"
                + "<xsl:template match=\"/\"><paso1><xsl:for-each select=\"//linea\"><xsl:sort select=\"@precio\" data-type=\"number\" order=\"descending\"/>"
                + "<x p=\"{@precio}\"><xsl:value-of select=\"translate(., 'aeiou', 'AEIOU')\"/></x></xsl:for-each>"
                + "<e><xsl:value-of select=\"//emisor\"/></e></paso1></xsl:template></xsl:stylesheet>";
            final String second = "<xsl:stylesheet version=\"1.0\" " + XSL + " xmlns:r=\"urn:resultado\">"
                + "<xsl:template match=\"/paso1\"><r:paso2 total=\"{sum(x/@p)}\" n=\"{count(x)}\"><xsl:copy-of select=\"x[1]\"/>"
                + "<xsl:apply-templates select=\"e\"/></r:paso2></xsl:template>"
                + "<xsl:template match=\"e\"><r:emisor><xsl:value-of select=\"concat('[', ., ']')\"/></r:emisor></xsl:template></xsl:stylesheet>";
            sign(out, "xslt-xslt-exc-c14n", DOC, fac -> List.of(fac.newReference("",
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(plain(fac, Transform.ENVELOPED), xslt(fac, first), xslt(fac, second),
                    plain(fac, CanonicalizationMethod.EXCLUSIVE)), null, null)), null, false);
        }

        static List<XMLObject> objects(final String xml) throws Exception {
            final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            final Document d = dbf().newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            return List.of(fac.newXMLObject(List.of(new DOMStructure(d.getDocumentElement())), "Object-1", null, null));
        }
    }

    public static void main(final String[] a) throws Exception {
        switch (a[0]) {
            case "cases":
                cases(Paths.get(a[1]), Paths.get(a[2]));
                break;
            case "sign":
                signAll(Paths.get(a[1]), Paths.get(a[2]));
                break;
            case "run":
                try {
                    System.out.write(runStylesheet(Files.readAllBytes(Paths.get(a[1])), Files.readAllBytes(Paths.get(a[2]))));
                } catch (final Throwable e) {
                    System.out.print("ERROR: " + errorText(e));
                }
                System.out.flush();
                break;
            default:
                throw new IllegalArgumentException(a[0]);
        }
    }
}
