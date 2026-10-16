import java.io.File;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

/** Oráculo de nombres X.500 para afirma-keystores: imprime, para cada
 * certificado, las representaciones de Java usadas por los filtros y la
 * interfaz. Una línea por dato: {@code fichero<TAB>clave<TAB>valor}, con los
 * caracteres de control escapados ({@code \n}, {@code \r}, {@code \t}, {@code \\}).
 * Uso: java -cp afirma-core.jar:. FiltersDnOracle cert1.der cert2.der ... */
public final class FiltersDnOracle {

    private static String esc(final String s) {
        if (s == null) {
            return "<null>";
        }
        final StringBuilder sb = new StringBuilder();
        for (final char c : s.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String val(final Object o) {
        if (o instanceof byte[]) {
            final StringBuilder sb = new StringBuilder("bin:");
            for (final byte b : (byte[]) o) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        }
        return "str:" + esc(String.valueOf(o));
    }

    private static void ldap(final String file, final String key, final String dn) {
        try {
            final List<Rdn> rdns = new LdapName(dn).getRdns();
            final StringBuilder sb = new StringBuilder();
            for (final Rdn rdn : rdns) {
                if (sb.length() > 0) {
                    sb.append(" | ");
                }
                sb.append(rdn.getType()).append('=').append(val(rdn.getValue()));
            }
            System.out.println(file + "\t" + key + "\t" + esc(sb.toString()));
        }
        catch (final Exception e) {
            System.out.println(file + "\t" + key + "\t<error>");
        }
    }

    public static void main(final String[] args) throws Exception {
        Locale.setDefault(new Locale("es", "ES"));
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (final String path : args) {
            final File f = new File(path);
            final X509Certificate c = (X509Certificate) cf.generateCertificate(Files.newInputStream(f.toPath()));
            final String n = f.getName();
            final X500Principal s = c.getSubjectX500Principal();
            final X500Principal i = c.getIssuerX500Principal();
            System.out.println(n + "\tsubject.toString\t" + esc(s.toString()));
            System.out.println(n + "\tsubject.rfc2253\t" + esc(s.getName()));
            System.out.println(n + "\tissuer.toString\t" + esc(i.toString()));
            System.out.println(n + "\tissuer.rfc2253\t" + esc(i.getName()));
            System.out.println(n + "\tsubjectDN\t" + esc(c.getSubjectDN().toString()));
            System.out.println(n + "\tgetCN\t" + esc(es.gob.afirma.core.misc.AOUtil.getCN(c)));
            System.out.println(n + "\tgetCN.issuer.rfc2253\t" + esc(es.gob.afirma.core.misc.AOUtil.getCN(i.getName())));
            System.out.println(n + "\tgetCN.issuer.toString\t" + esc(es.gob.afirma.core.misc.AOUtil.getCN(i.toString())));
            System.out.println(n + "\tsubjectSN\t" + esc(es.gob.afirma.core.misc.AOUtil.getRDNvalueFromLdapName("2.5.4.5", s.getName())));
            System.out.println(n + "\tpseudonym\t" + es.gob.afirma.core.misc.AOUtil.isPseudonymCert(c));
            String ku;
            try {
                ku = new es.gob.afirma.core.keystores.KeyUsage(c).toString();
            }
            catch (final Exception e) {
                ku = "<error>";
            }
            System.out.println(n + "\tkeyusage.text\t" + esc(ku));
            System.out.println(n + "\tserial.hex\t" + es.gob.afirma.core.misc.AOUtil.hexify(c.getSerialNumber().toByteArray(), ""));
            ldap(n, "ldap.subject", s.toString());
            ldap(n, "ldap.issuer", i.toString());
        }
    }
}
