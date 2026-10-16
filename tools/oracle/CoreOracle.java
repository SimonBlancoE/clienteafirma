// Oráculo Java para afirma-core (AutoFirma-rs).
//
// Ejecuta las clases originales de afirma-core (MimeHelper, OfficeAnalizer,
// Base64, AOUtil, ExtraParamsProcessor...) sobre vectores de prueba y escribe
// los resultados en formato de texto para guardarlos como ficheros golden en
// testdata/core/. Uso (ver tools/oracle/core_oracle.sh):
//
//   java -cp <afirma-core.jar>:<jmimemagic.jar>:<oro.jar>:<dir> CoreOracle <cmd> [args]
//
// Comandos: mime <dir> | base64 | props | load | exp | uri | misc
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.TimeZone;
import java.util.TreeSet;

import es.gob.afirma.core.misc.AOFileUtils;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.misc.MimeHelper;
import es.gob.afirma.core.misc.OfficeAnalizer;
import es.gob.afirma.core.signers.ExtraParamsProcessor;

public final class CoreOracle {

    private static String hex(final byte[] b) {
        final StringBuilder sb = new StringBuilder();
        for (final byte x : b) {
            sb.append(String.format("%02x", Integer.valueOf(x & 0xff)));
        }
        return sb.toString();
    }

    private static byte[] unhex(final String s) {
        final byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** Escapa un texto para que quepa en una línea (\\, \n, \r, \t y no ASCII como \\uXXXX). */
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
            default:
                if (c < 0x20 || c > 0x7e) {
                    sb.append(String.format("\\u%04x", Integer.valueOf(c)));
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static String err(final Throwable t) {
        return "ERR:" + t.getClass().getSimpleName() + ":" + esc(t.getMessage());
    }

    private static String sortedProps(final Properties p) {
        final StringBuilder sb = new StringBuilder();
        for (final String k : new TreeSet<>(p.stringPropertyNames())) {
            if (sb.length() > 0) {
                sb.append('|');
            }
            sb.append(esc(k)).append('=').append(esc(p.getProperty(k)));
        }
        return sb.toString();
    }

    public static void main(final String[] args) throws Exception {
        switch (args[0]) {
        case "mime": mime(new File(args[1])); break;
        case "base64": base64(); break;
        case "props": props(); break;
        case "load": load(); break;
        case "exp": exp(); break;
        case "uri": uri(); break;
        case "misc": misc(); break;
        default: throw new IllegalArgumentException(args[0]);
        }
    }

    private static void mime(final File dir) throws Exception {
        final File[] files = dir.listFiles();
        Arrays.sort(files);
        for (final File f : files) {
            final byte[] data = Files.readAllBytes(f.toPath());
            final MimeHelper mh = new MimeHelper(data);
            String mime;
            String ext;
            String desc;
            try { mime = mh.getMimeType(); } catch (final Exception e) { mime = err(e); }
            try { ext = mh.getExtension(); } catch (final Exception e) { ext = err(e); }
            try { desc = mh.getDescription(); } catch (final Exception e) { desc = err(e); }
            final boolean zip = new MimeHelper(data).isZipData();
            final boolean ooxml = OfficeAnalizer.isOOXMLDocument(data);
            final boolean odf = OfficeAnalizer.isODFDocument(data);
            final boolean xml = AOFileUtils.isXML(data);
            System.out.println(f.getName() + "\t" + esc(mime) + "\t" + esc(ext) + "\t" + esc(desc)
                + "\t" + zip + "\t" + ooxml + "\t" + odf + "\t" + xml);
        }
    }

    private static final String[] B64_VECTORS = {
        "", "QQ==", "QUI=", "QUJD", "QUJDRA==", "QUJDREU=", "QUJDREVG", "QQ", "QQ=", "QUI", "QUJDR",
        "QQ==QUJD", "QUI=QUJD", "QUJDQQ==", "QQ=A", "Q Q = =", "QU\nJD", "QU\r\nJD\t", " QUJD ",
        "-_-_", "+/+/", "SGVsbG8gV29ybGQ", "SGVsbG8gV29ybGQ=", "SGVsbG8_V29ybGQ=", "SGVsbG8-V29ybGQ=",
        "=QUJD", "Q=UJD", "==QUJD", "====", "QUJD!", "QUJD\u00f1", "a", "ab", "abc", "abcd", "abcde",
        "abc~", "abc\n", "ab==\n", "ab=\n", "ab\t\t", "~~~~", "QUJD\n\n", "\n\nQUJD", "Zm9vYmFy", "Zm9vYg==",
        "Zm9vYmE=", "_w==", "/w==", "AAAA", "AA==AA==", "QUJDRA==\n", "QUJDRA=", "QUJDRA",
    };

    private static void base64() {
        for (final String v : B64_VECTORS) {
            final StringBuilder sb = new StringBuilder();
            sb.append(hex(v.getBytes(StandardCharsets.UTF_8)));
            for (final boolean urlSafe : new boolean[] { false, true }) {
                sb.append('\t');
                try {
                    sb.append(hex(Base64.decode(v, urlSafe)));
                } catch (final Exception e) {
                    sb.append(err(e));
                }
            }
            sb.append('\t').append(Base64.isBase64(v));
            System.out.println(sb);
        }
        // Codificación
        final String[] encodeVectors = { "", "00", "0001", "000102", "fbff", "fbffbf", "68656c6c6f20776f726c64",
            "ffffffffff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" };
        for (final String h : encodeVectors) {
            final byte[] d = unhex(h);
            System.out.println("ENC\t" + h + "\t" + Base64.encode(d) + "\t" + Base64.encode(d, true));
        }
    }

    private static void props() throws Exception {
        final List<String[][]> cases = new ArrayList<>();
        cases.add(new String[][] { { "mode", "implicit" } });
        cases.add(new String[][] { { "format", "XAdES Detached" }, { "headless", "true" } });
        cases.add(new String[][] { { "clave con espacios", " valor con espacio inicial" } });
        cases.add(new String[][] { { "esp", "a=b:c#d!e\\f" } });
        cases.add(new String[][] { { "ctl", "l1\nl2\rl3\tt\fend" } });
        cases.add(new String[][] { { "uni", "Logro\u00f1o \u20ac \ud83d\ude00" } });
        cases.add(new String[][] { { "k=:#!", "v" } });
        cases.add(new String[][] { { "", "vacia" }, { "vacio", "" } });
        cases.add(new String[][] { { "del", "\u007f\u0001" } });
        for (final String[][] c : cases) {
            final Properties p = new Properties();
            for (final String[] kv : c) {
                p.setProperty(kv[0], kv[1]);
            }
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final OutputStreamWriter osw = new OutputStreamWriter(baos, StandardCharsets.UTF_8);
            p.store(osw, "");
            final String stored = new String(baos.toByteArray(), StandardCharsets.UTF_8);
            final String[] lines = stored.split("\n", -1);
            // Se sustituye la línea de fecha (segunda) por un marcador.
            lines[1] = "#DATE";
            final String normalized = String.join("\n", lines);
            System.out.println(sortedProps(p) + "\t" + esc(normalized));
            // propertiesAsString con una sola clave es determinista
            if (c.length == 1) {
                System.out.println("ASSTRING\t" + esc(AOUtil.propertiesAsString(p)));
            }
        }
        // base642Properties
        final String[] b64 = {
            "bW9kZT1pbXBsaWNpdAo=", "bW9kZT1pbXBsaWNpdAo", "Zm9ybWF0PVhBZEVTIERldGFjaGVkCmhlYWRsZXNzPXRydWUK",
            "Y2l1ZGFkPUxvZ3Jvw7FvCg==", "Y2l1ZGFkPUxvZ3Jv8W8K", "a2V5PXZhbHVlXHUwMEYx", "a2V5PVx1MDBGeg==", "",
            "a2V5PXY_", "!!!!",
        };
        for (final String s : b64) {
            try {
                System.out.println("B642P\t" + esc(s) + "\t" + sortedProps(AOUtil.base642Properties(s)));
            } catch (final Exception e) {
                System.out.println("B642P\t" + esc(s) + "\t" + err(e));
            }
        }
    }

    private static final String[] LOAD_VECTORS = {
        "a=b", "a = b", "a:b", "a b", "a\tb", "a\fb", "  a=b  ", "a==b", "a=:b", "a :=b", "a= =b",
        "# comentario\na=b", "! comentario\na=b", "a=b\\\n  c", "a=b\\\r\n  c", "a=b\\\r  c", "a=b\\\\\nc=d",
        "a=b\\", "a=\\u00f1", "a=\\u00F1\\u00d1", "a\\ b=c", "a\\=b=c", "a\\:b=c", "a=\\t\\n\\r\\f\\x",
        "a=b\nb=c\na=d", "\n\n  \na=b\n\n", "a", "a=", "=b", ":b", " =b", "a=b\\\n# no comentario",
        "a=b\\\n\nc=d", "a=\\ud83d\\ude00", "k\u00f1=v\u00e9", "a=b\r\nc=d\re=f", "a=b\\\\\\\nc",
        "a=\\u00", "a=\\u00zz", "a=b\\\n   \\\n  c", "#a=b\\\nc=d",
    };

    private static void load() {
        for (final String v : LOAD_VECTORS) {
            final Properties p = new Properties();
            try {
                p.load(new StringReader(v));
                System.out.println(esc(v) + "\t" + sortedProps(p));
            } catch (final Exception e) {
                System.out.println(esc(v) + "\t" + err(e));
            }
        }
    }

    private static void exp() {
        final String[][] cases = {
            // formato | datos (tamaño o -1) | propiedades (k=v;k=v)
            { "CAdES", "10", "expPolicy=FirmaAGE" },
            { "CAdES", "1048575", "expPolicy=FirmaAGE" },
            { "CAdES", "1048576", "expPolicy=FirmaAGE" },
            { "CAdES", "-1", "expPolicy=FirmaAGE" },
            { "CAdES", "10", "expPolicy=FirmaAGE;mode=explicit;profile=baseline;policyIdentifier=x" },
            { "cadestri", "10", "expPolicy=FirmaAGE18" },
            { "CAdES-ASiC-S", "10", "expPolicy=FirmaAGE" },
            { "XAdES", "10", "expPolicy=FirmaAGE" },
            { "XAdES Enveloped", "10", "expPolicy=FirmaAGE18;format=xades enveloped" },
            { "XAdEStri", "10", "expPolicy=FirmaAGE;format=XAdES Enveloping;profile=BASELINE" },
            { "xades detached", "10", "expPolicy=FirmaAGE" },
            { "XAdES-ASiC-S", "10", "expPolicy=FirmaAGE" },
            { "PAdES", "10", "expPolicy=FirmaAGE" },
            { "Adobe PDF", "10", "expPolicy=FirmaAGE;signatureSubFilter=ETSI.CAdES.detached;profile=baseline" },
            { "PAdEStri", "10", "expPolicy=FirmaAGE;signatureSubFilter=adbe.pkcs7.detached" },
            { "Adobe PDF TriPhase", "10", "expPolicy=FirmaAGE18" },
            { "PAdES", "10", "expPolicy=FirmaAGE19" },
            { "CAdES", "10", "expPolicy=firmaage" },
            { "FacturaE", "10", "expPolicy=FirmaAGE" },
            { "auto", "10", "expPolicy=FirmaAGE" },
            { "", "10", "expPolicy=FirmaAGE" },
            { "CAdES", "10", "mode=implicit" },
            { "<null>", "10", "mode=implicit" },
            { "CAdES", "10", "expPolicy=" },
        };
        for (final String[] c : cases) {
            final Properties p = new Properties();
            for (final String kv : c[2].split(";")) {
                final int i = kv.indexOf('=');
                p.setProperty(kv.substring(0, i), kv.substring(i + 1));
            }
            final int size = Integer.parseInt(c[1]);
            final byte[] data = size < 0 ? null : new byte[size];
            final String format = "<null>".equals(c[0]) ? null : c[0];
            String res;
            try {
                res = sortedProps(ExtraParamsProcessor.expandProperties(p, data, format));
            } catch (final Exception e) {
                res = err(e);
            }
            System.out.println(c[0] + "\t" + c[1] + "\t" + c[2] + "\t" + res);
        }
    }

    private static final String[] URI_VECTORS = {
        "/home/user/a b.pdf", "a.pdf", "C:\\Users\\a b\\x.pdf", "c:/x.pdf", "http://www.a.es/a?b=c#d",
        "https://x/y z", "file:///tmp/a.txt", "file:/tmp/a.txt", "urn:oid:1.2.3", "ftp://x/y", "mailto:a@b",
        "/tmp/a#b.pdf", "/tmp/[x]{y}|^`.pdf", "  /tmp/a.pdf  ", "", "   ", "/tmp/a%20b.pdf", "rel/dir/f.txt",
        "\\\\servidor\\recurso\\f.pdf", "HTTP://X/Y", "jar:file:/a!/b",
    };

    private static void uri() {
        for (final String v : URI_VECTORS) {
            try {
                final URI u = AOUtil.createURI(v);
                System.out.println(esc(v) + "\t" + esc(u.toString()) + "\t" + esc(u.getScheme()) + "\t"
                    + esc(u.getSchemeSpecificPart()));
            } catch (final Exception e) {
                System.out.println(esc(v) + "\t" + err(e));
            }
        }
    }

    private static void misc() throws Exception {
        // hexify
        final byte[] b = new byte[20];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (i * 13);
        }
        System.out.println("HEXIFY\t" + esc(AOUtil.hexify(b, true)) + "\t" + esc(AOUtil.hexify(b, false)) + "\t"
            + esc(AOUtil.hexify(b, ":")));
        // split
        for (final String s : new String[] { "a$b$", "$a$$b", "", "$", "abc", "a$$" }) {
            System.out.println("SPLIT\t" + esc(s) + "\t" + esc(String.join("|", AOUtil.split(s, "$"))) + "\t"
                + AOUtil.split(s, "$").length);
        }
        // getCN / getRDNvalueFromLdapName
        for (final String s : new String[] {
            "CN=Juan Espa\u00f1ol, OU=Personas, O=FNMT, C=ES", "OU=Uno, OU=Dos, O=X", "O=Solo, C=ES", "sin igual",
            "CN=\"Con, coma\", O=X", "SERIALNUMBER=123, CN=  espacios  , C=ES", "CN=, O=X", "cn=minus", "XCN=no, CN=si",
            "CN=\"\", O=X", "CN=\"abierta", "OID.2.5.4.97=VATES-123, CN=Empresa",
        }) {
            System.out.println("CN\t" + esc(s) + "\t" + esc(AOUtil.getCN(s)) + "\t"
                + esc(String.join("|", AOUtil.getOUS(s))));
        }
        // Fechas
        final Date d = new Date(1792149420000L); // 2026-10-16T11:17:00Z
        for (final String tz : new String[] { "Europe/Madrid", "UTC", "GMT", "America/New_York", "Atlantic/Canary" }) {
            TimeZone.setDefault(TimeZone.getTimeZone(tz));
            Locale.setDefault(new Locale("es", "ES"));
            System.out.println("DATE\t" + tz + "\t" + d.toString() + "\t"
                + esc(DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.SHORT).format(d)));
        }
        final String[] months = new String[12];
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        for (int m = 0; m < 12; m++) {
            final Date dm = new Date(Date.UTC(126, m, 5, 9, 5, 0));
            months[m] = DateFormat.getDateTimeInstance(DateFormat.DEFAULT, DateFormat.SHORT).format(dm);
        }
        System.out.println("MONTHS\t" + esc(String.join("|", months)));
        System.out.println("JAVA\t" + System.getProperty("java.version"));
        // isBase64(byte[]) con bytes no ASCII
        System.out.println("ISB64BYTES\t" + Base64.isBase64(new byte[] { 'Q', 'Q', '=', '=' }) + "\t"
            + Base64.isBase64(new byte[] { 'Q', 'Q', (byte) 0xc3, (byte) 0xb1 }));
        new ByteArrayInputStream(new byte[0]).close();
    }
}
