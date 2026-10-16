import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import es.gob.afirma.core.misc.http.TrustStoreManager;

/**
 * Oráculo del almacén de confianza de AutoFirma Java
 * (`es.gob.afirma.core.misc.http.TrustStoreManager`) para las pruebas del
 * módulo `jks` de `crates/afirma-keystores` (ver `testdata/keystores/jks/gen.sh`).
 *
 * Ejecutar con `-Duser.home=<dir>`: el almacén se crea en
 * `<dir>/.afirma/TrustedCertsKeystore.jks`.
 *
 *   import <cert>...   importa los certificados, uno a uno y en orden, con
 *                      TrustStoreManager.importCerts
 *   list <jks>         "<alias>\t<SHA-256 del certificado>" por entrada, ordenado
 */
public final class TrustStoreOracle {

	private static String hex(final byte[] b) {
		final StringBuilder sb = new StringBuilder();
		for (final byte x : b) {
			sb.append(String.format("%02x", x & 0xff));
		}
		return sb.toString();
	}

	public static void main(final String[] args) throws Exception {
		if ("import".equals(args[0])) {
			final CertificateFactory cf = CertificateFactory.getInstance("X.509");
			for (int i = 1; i < args.length; i++) {
				try (InputStream is = new FileInputStream(args[i])) {
					TrustStoreManager.getInstance().importCerts((X509Certificate) cf.generateCertificate(is));
				}
			}
		}
		else if ("list".equals(args[0])) {
			final KeyStore ks = KeyStore.getInstance("JKS");
			try (InputStream is = new FileInputStream(args[1])) {
				ks.load(is, "changeit".toCharArray());
			}
			final List<String> out = new ArrayList<>();
			for (final String alias : Collections.list(ks.aliases())) {
				final Certificate c = ks.getCertificate(alias);
				out.add(alias + "\t" + hex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded())));
			}
			Collections.sort(out);
			for (final String l : out) {
				System.out.println(l);
			}
		}
		else {
			throw new IllegalArgumentException("Orden desconocida: " + args[0]);
		}
	}
}
