import java.io.File;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;

import javax.security.auth.callback.PasswordCallback;

import es.gob.afirma.core.keystores.KeyStoreManager;
import es.gob.afirma.keystores.KeyStoreUtilities;
import es.gob.afirma.keystores.filters.CertFilterManager;

/** Oráculo de filtros de certificados para afirma-keystores: aplica cada caso
 * de {@code filter-cases.txt} con {@code CertFilterManager} y
 * {@code KeyStoreUtilities.getAliasesByFriendlyName} (sin comprobar claves
 * privadas y mostrando caducados) sobre los certificados de prueba, y escribe
 * {@code nombre<TAB>alias,ordenados|mandatory=..|external=..} o {@code ERROR}.
 * Uso: java -cp ... FiltersApplyOracle casos.txt dir1 dir2 ... */
public final class FiltersApplyOracle {

    static final class MemoryKsm implements KeyStoreManager {
        final Map<String, X509Certificate[]> chains = new LinkedHashMap<>();
        @Override public void deactivateEntry(final String t) { /* no */ }
        @Override public boolean isKeyEntry(final String alias) { return true; }
        @Override public String[] getAliases() { return this.chains.keySet().toArray(new String[0]); }
        @Override public X509Certificate getCertificate(final String alias) {
            final X509Certificate[] c = this.chains.get(alias);
            return c == null ? null : c[0];
        }
        @Override public X509Certificate[] getCertificateChain(final String alias) { return this.chains.get(alias); }
        @Override public KeyStore.PrivateKeyEntry getKeyEntry(final String alias) { return null; }
        @Override public void refresh() { /* no */ }
        @Override public void setEntryPasswordCallBack(final PasswordCallback pwc) { /* no */ }
        @Override public void setParentComponent(final Object parent) { /* no */ }
    }

    public static void main(final String[] args) throws Exception {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        final MemoryKsm ksm = new MemoryKsm();
        final Map<String, X509Certificate> certs = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i++) {
            final File[] files = new File(args[i]).listFiles();
            java.util.Arrays.sort(files);
            for (final File f : files) {
                final String n = f.getName();
                if (!n.endsWith(".crt") && !n.endsWith(".der")) {
                    continue;
                }
                certs.put(n.substring(0, n.lastIndexOf('.')),
                    (X509Certificate) cf.generateCertificate(Files.newInputStream(f.toPath())));
            }
        }
        for (final Map.Entry<String, X509Certificate> e : certs.entrySet()) {
            final String alias = e.getKey();
            if (alias.startsWith("dnie-") && !alias.equals("dnie-ca")) {
                ksm.chains.put(alias, new X509Certificate[] { e.getValue(), certs.get("dnie-ca") });
            }
            else {
                ksm.chains.put(alias, new X509Certificate[] { e.getValue() });
            }
        }
        final List<String> lines = Files.readAllLines(new File(args[0]).toPath(), StandardCharsets.UTF_8);
        for (final String line : lines) {
            if (line.trim().isEmpty() || line.startsWith("#")) {
                continue;
            }
            final int tab = line.indexOf('\t');
            final String name = line.substring(0, tab);
            final String props = line.substring(tab + 1).replace("<NL>", "\n");
            String out;
            try {
                final Properties p = new Properties();
                p.load(new StringReader(props));
                final CertFilterManager m = new CertFilterManager(p);
                final Map<String, String> r = KeyStoreUtilities.getAliasesByFriendlyName(
                    ksm.getAliases(), ksm, false, true, m.getFilters());
                out = String.join(",", new TreeSet<>(r.keySet()))
                    + "|mandatory=" + m.isMandatoryCertificate()
                    + "|external=" + m.isExternalStoresOpeningAllowed();
            }
            catch (final Exception ex) {
                out = "ERROR";
            }
            System.out.println(name + "\t" + out);
        }
    }
}
