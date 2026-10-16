package es.gob.afirma.plugin.certvalidation.validation;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Oráculo del plugin «Validación de certificados» de AutoFirma Java para las
 * pruebas diferenciales de `crates/afirma-certval` (ver
 * `tools/oracle/certval_oracle.sh`). Está en el paquete del plugin para poder
 * usar `OcspHelper` y `CrlHelper`, que no son públicos.
 *
 * Órdenes (una línea de salida por caso):
 *   id <cert>...                  -> "<fichero> <id CRC> <clase del verificador>"
 *   ocspreq <cert> <emisor>       -> petición OCSP (hex) de OcspHelper.createOcspRequest
 *   analyze <resp.der>...         -> "<fichero> <ValidationResult>" de OcspHelper.analyzeOcspResponse
 *   crl <cert> <emisor|-> <crl>   -> ValidationResult de CrlHelper con la CRL como file:
 *   period <cert>...              -> ValidationResult de CertificateVerifier sin revocación (solo periodo)
 *   validate <cert>...            -> "<fichero> <ValidationResult>" de la factoría y validateCertificate()
 *                                    (solo para casos que no llegan a la red) o ERROR:<excepción>
 *   messages                      -> "<código> <nombre> <toString()> | <toJsonString() en una línea>"
 */
public final class CertValOracle {

	private static X509Certificate load(final String path) throws Exception {
		try (InputStream is = new FileInputStream(path)) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
		}
	}

	public static void main(final String[] args) throws Exception {
		final String cmd = args[0];
		switch (cmd) {
			case "id": {
				final Method m = CertificateVerifierFactory.class.getDeclaredMethod("getIssuerIdentifier", X509Certificate.class);
				m.setAccessible(true);
				for (int i = 1; i < args.length; i++) {
					final X509Certificate c = load(args[i]);
					String verifier;
					try {
						verifier = CertificateVerifierFactory.getCertificateVerifier(c).getClass().getSimpleName();
					}
					catch (final Exception e) {
						verifier = "ERROR:" + e.getClass().getSimpleName();
					}
					System.out.println(new File(args[i]).getName() + " " + m.invoke(null, c) + " " + c.getSigAlgName() + " " + verifier);
				}
				break;
			}
			case "ocspreq": {
				final byte[] req = OcspHelper.createOcspRequest(load(args[1]), load(args[2]));
				final StringBuilder sb = new StringBuilder();
				for (final byte b : req) {
					sb.append(String.format("%02x", b & 0xff));
				}
				System.out.println(sb);
				break;
			}
			case "analyze": {
				for (int i = 1; i < args.length; i++) {
					String r;
					try {
						r = OcspHelper.analyzeOcspResponse(Files.readAllBytes(new File(args[i]).toPath())).name();
					}
					catch (final Exception e) {
						r = "ERROR:" + e.getClass().getSimpleName();
					}
					System.out.println(new File(args[i]).getName() + " " + r);
				}
				break;
			}
			case "crl": {
				final X509Certificate cert = load(args[1]);
				final PublicKey key = "-".equals(args[2]) ? null : load(args[2]).getPublicKey();
				final List<String> dps = new ArrayList<>();
				for (int i = 3; i < args.length; i++) {
					dps.add(args[i].startsWith("file:") || args[i].contains("://") ? args[i] : new File(args[i]).toURI().toString());
				}
				System.out.println(CrlHelper.verifyCertificateCRLs(cert, key, dps).name());
				break;
			}
			case "period": {
				for (int i = 1; i < args.length; i++) {
					final CertificateVerifier v = new CertificateVerifier() {
						@Override
						public ValidationResult verifyRevocation(final X509Certificate c) {
							return ValidationResult.VALID;
						}
					};
					System.out.println(new File(args[i]).getName() + " " + v.validateCertificate(load(args[i])).name());
				}
				break;
			}
			case "validate": {
				for (int i = 1; i < args.length; i++) {
					String r;
					try {
						r = CertificateVerifierFactory.getCertificateVerifier(load(args[i])).validateCertificate().name();
					}
					catch (final Exception e) {
						r = "ERROR:" + e.getClass().getSimpleName();
					}
					System.out.println(new File(args[i]).getName() + " " + r);
				}
				break;
			}
			case "messages": {
				for (final ValidationResult r : ValidationResult.values()) {
					System.out.println(r.ordinal() + " " + r.name() + " " + r + " | " + r.toJsonString().replace("\n", "\\n"));
				}
				break;
			}
			default:
				throw new IllegalArgumentException("Orden desconocida: " + cmd);
		}
	}
}
