// Validador XMLDSig independiente (JSR-105 / Apache Santuario) para las firmas
// XML de AutoFirma-rs. Valida cada ds:Signature del documento (incluidas las
// contrafirmas anidadas) con la clave del primer certificado de su KeyInfo y
// el desreferenciador de AutoFirma (Id sin distinguir mayúsculas).
//
// Compilación y uso (classpath = jars de afirma-crypto-core-xml + xmlsec):
//   CP=$(ls $S/xades-run/lib/*.jar | tr '\n' :)$S/xades-run/classes
//   javac -cp "$CP" -d /tmp/xv tools/oracle/XmlSigVerify.java
//   java -cp "$CP:/tmp/xv" XmlSigVerify firma.xml [firma2.xml ...]
// Salida: una línea por firma `fichero sig#i valid=true|false ref[URI]=...`.
// Código de salida 1 si alguna firma no es válida.
import java.io.File;
import java.nio.file.Paths;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class XmlSigVerify {
    public static void main(final String[] args) throws Exception {
        java.util.logging.LogManager.getLogManager().reset();
        es.gob.afirma.signers.xml.XmlDSigProviderHelper.configureXmlDSigProvider();
        org.apache.xml.security.Init.init();
        boolean allOk = true;
        for (final String fn : args) {
            final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            final Document d = f.newDocumentBuilder().parse(new File(fn));
            final NodeList nl = d.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            for (int i = 0; i < nl.getLength(); i++) {
                final DOMValidateContext vc = new DOMValidateContext(new javax.xml.crypto.KeySelector() {
                    @Override
                    public javax.xml.crypto.KeySelectorResult select(final javax.xml.crypto.dsig.keyinfo.KeyInfo ki, final Purpose p,
                            final javax.xml.crypto.AlgorithmMethod m, final javax.xml.crypto.XMLCryptoContext c) {
                        for (final Object o : ki.getContent()) {
                            if (o instanceof javax.xml.crypto.dsig.keyinfo.X509Data) {
                                for (final Object x : ((javax.xml.crypto.dsig.keyinfo.X509Data) o).getContent()) {
                                    if (x instanceof java.security.cert.X509Certificate) {
                                        final java.security.PublicKey pk = ((java.security.cert.X509Certificate) x).getPublicKey();
                                        return () -> pk;
                                    }
                                }
                            }
                        }
                        return null;
                    }
                }, nl.item(i));
                final NodeList all = d.getElementsByTagName("*");
                for (int k = 0; k < all.getLength(); k++) {
                    final Element e = (Element) all.item(k);
                    if (e.hasAttribute("Id") && !e.getAttribute("Id").contains(":")) {
                        vc.setIdAttributeNS(e, null, "Id");
                    }
                }
                try {
                    vc.setURIDereferencer(new es.gob.afirma.signers.xml.dereference.CustomUriDereferencer());
                }
                catch (final Exception e) {
                    // sin desreferenciador a medida
                }
                try {
                    final XMLSignature sig = fac.unmarshalXMLSignature(vc);
                    final boolean ok = sig.validate(vc);
                    final StringBuilder sb = new StringBuilder();
                    for (final Object r : sig.getSignedInfo().getReferences()) {
                        sb.append(" ref[" + ((Reference) r).getURI() + "]=" + ((Reference) r).validate(vc));
                    }
                    System.out.println(Paths.get(fn).getFileName() + " sig#" + i + " valid=" + ok + sb);
                    allOk &= ok;
                }
                catch (final Exception e) {
                    System.out.println(Paths.get(fn).getFileName() + " sig#" + i + " valid=ERROR " + e);
                    allOk = false;
                }
            }
        }
        System.exit(allOk ? 0 : 1);
    }
}
