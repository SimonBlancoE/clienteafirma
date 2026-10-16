import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.nio.file.*;
import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;

public class JC14n {
    public static void main(String[] a) throws Exception {
        Init.init();
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        Document d = f.newDocumentBuilder().parse(Files.newInputStream(Paths.get(a[1])));
        Node n = d;
        if (a.length > 2 && !a[2].isEmpty()) {
            javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
            n = (Node) xp.evaluate("//*[@Id='" + a[2] + "']", d, javax.xml.xpath.XPathConstants.NODE);
        }
        Canonicalizer c = Canonicalizer.getInstance(a[0]);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        if (a.length > 3) c.canonicalizeSubtree(n, a[3], out); else c.canonicalizeSubtree(n, out);
        System.out.write(out.toByteArray());
        System.out.flush();
    }
}
