import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import es.gob.afirma.plugin.hash.command.CheckHashCommand;
import es.gob.afirma.plugin.hash.command.CreateHashCommand;
import es.gob.afirma.standalone.plugins.PluginCommandAction;
import es.gob.afirma.standalone.plugins.PluginControlledException;

/**
 * Oráculo del plugin de huellas digitales (afirma-simple-plugin-hash).
 *
 * Ejecuta los comandos {@code createdigest} / {@code checkdigest} del plugin
 * como lo hace {@code CommandLineLauncher} (locale es_ES): imprime la
 * respuesta seguida de un salto de línea y termina con estado 0, o imprime el
 * mensaje de error ("Error no reconocido: ..." para las excepciones no
 * controladas) y termina con estado 255. No admite {@code -gui}.
 *
 * Uso: java -cp autofirma.jar:plugin-hash.jar:. HashOracle createdigest|checkdigest args...
 *      java -cp ... HashOracle mktree testdata/hash/tree.manifest DIRECTORIO
 * (normalmente a través de tools/oracle/hash_oracle.sh).
 */
public final class HashOracle {

	public static void main(final String[] args) throws Exception {
		final PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8.name());
		final String command = args[0];
		if ("mktree".equals(command)) {
			mkTree(Paths.get(args[1]), Paths.get(args[2]));
			return;
		}
		final boolean xml = Arrays.asList(args).subList(1, args.length).stream()
				.anyMatch("-xml"::equalsIgnoreCase);
		final PluginCommandAction action = "createdigest".equals(command)
				? new CreateHashCommand()
				: new CheckHashCommand();
		String msg;
		int status;
		try {
			msg = action.start(args);
			status = 0;
		}
		catch (final PluginControlledException | UnsupportedOperationException e) {
			msg = e.getMessage();
			if (xml) {
				msg = xmlResponse(msg);
			}
			status = 255;
		}
		catch (final Exception e) {
			msg = "Error no reconocido: " + e.getMessage(); //$NON-NLS-1$
			if (xml) {
				msg = xmlResponse(msg);
			}
			status = 255;
		}
		if (msg != null) {
			out.print(msg);
			out.print("\n"); //$NON-NLS-1$
		}
		out.flush();
		System.exit(status);
	}

	/** Crea el árbol de ficheros descrito en un manifiesto (testdata/hash/tree.manifest). */
	private static void mkTree(final Path manifest, final Path root) throws Exception {
		for (final String line : Files.readAllLines(manifest, StandardCharsets.UTF_8)) {
			if (line.isEmpty() || line.startsWith("#")) { //$NON-NLS-1$
				continue;
			}
			final int tab = line.indexOf('\t');
			final Path file = root.resolve(line.substring(0, tab));
			final String spec = line.substring(tab + 1);
			byte[] data;
			if (spec.startsWith("hex:")) { //$NON-NLS-1$
				final String hex = spec.substring(4);
				data = new byte[hex.length() / 2];
				for (int i = 0; i < data.length; i++) {
					data[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
				}
			}
			else {
				data = new byte[Integer.parseInt(spec.substring("pattern:".length()))]; //$NON-NLS-1$
				for (int i = 0; i < data.length; i++) {
					data[i] = (byte) (i % 251);
				}
			}
			Files.createDirectories(file.getParent());
			Files.write(file, data);
		}
	}

	private static String xmlResponse(final String msg) {
		final StringBuilder sb = new StringBuilder("<afirma><result>false</result>"); //$NON-NLS-1$
		if (msg != null) {
			sb.append("<response><msg>").append(msg).append("</msg></response>"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return sb.append("</afirma>").toString(); //$NON-NLS-1$
	}
}
