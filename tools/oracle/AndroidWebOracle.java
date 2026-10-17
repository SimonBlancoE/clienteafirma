// Oráculo Java de la firma web de Autofirma App 1.9 (AutoFirma-rs).
//
// Ejecuta las clases originales que usa la app para el protocolo web:
//  - afirma-core 1.9 (etiqueta v1.9 de este repositorio): ProtocolInvocationUriParser,
//    ProtocolInvocationUriParserUtil, UrlParameters*, Base64;
//  - de firma-android (afirma-ui-android): CipherDataManager, ErrorManager e
//    IntermediateServerUtil (con un UrlHttpManager que registra la URL y la parte como
//    AndroidHttpManager con StringTokenizer("?"));
// y escribe los resultados de los casos de testdata/android-web/cases.txt en el formato de
// testdata/android-web/oracle.golden. extractParamsForBatch es una copia literal del método
// privado de WebSignBatchActivity (que es una actividad de Android).
//
// Uso: tools/oracle/android_web_oracle.sh (compila y regenera el fichero golden).
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.zip.GZIPOutputStream;

import es.gob.afirma.android.IntermediateServerUtil;
import es.gob.afirma.android.crypto.CipherDataManager;
import es.gob.afirma.android.errors.ErrorManager;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.misc.http.HttpErrorProcessor;
import es.gob.afirma.core.misc.http.SSLConfig;
import es.gob.afirma.core.misc.http.UrlHttpManager;
import es.gob.afirma.core.misc.http.UrlHttpManagerFactory;
import es.gob.afirma.core.misc.http.UrlHttpMethod;
import es.gob.afirma.core.misc.protocol.ProtocolInvocationUriParser;
import es.gob.afirma.core.misc.protocol.ProtocolInvocationUriParserUtil;
import es.gob.afirma.core.misc.protocol.UrlParameters;
import es.gob.afirma.core.misc.protocol.UrlParametersForBatch;
import es.gob.afirma.core.misc.protocol.UrlParametersToSave;
import es.gob.afirma.core.misc.protocol.UrlParametersToSelectCert;
import es.gob.afirma.core.misc.protocol.UrlParametersToSign;

public final class AndroidWebOracle {

    /** Escapa un valor para una línea: \\, \n, \r, \t, ;, = y no ASCII como \\uXXXX. */
    static String esc(final String s) {
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
                case ';': sb.append("\\;"); break;
                case '=': sb.append("\\="); break;
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

    static String hex(final byte[] b) {
        if (b == null) {
            return "<null>";
        }
        final StringBuilder sb = new StringBuilder();
        for (final byte x : b) {
            sb.append(String.format("%02x", Integer.valueOf(x & 0xff)));
        }
        return sb.toString();
    }

    static byte[] unhex(final String s) {
        final byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** Desescapa las entradas del fichero de casos (\\n, \\t, \\\\ y \\uXXXX). */
    static String unesc(final String s) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                final char n = s.charAt(++i);
                switch (n) {
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    case 'u': sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16)); i += 4; break;
                    default: sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Copia literal de WebSignBatchActivity.extractParamsForBatch. */
    private static Map<String, String> extractParamsForBatch(final String url) {
        final Map<String, String> params = new HashMap<>();
        final int initPos = url.indexOf('?') + 1;
        final String[] urlParams = url.substring(initPos).split("&"); //$NON-NLS-1$
        for (final String param : urlParams) {
            final int equalsPos = param.indexOf('=');
            if (equalsPos > 0) {
                try {
                    params.put(
                            param.substring(0, equalsPos),
                            URLDecoder.decode(param.substring(equalsPos + 1), "UTF-8"));
                } catch (final UnsupportedEncodingException e) {
                    // No ocurre.
                }
            }
        }
        return params;
    }

    static void common(final StringBuilder sb, final UrlParameters p) {
        sb.append("key=").append(p.getDesKey() == null ? "<null>" : esc(new String(p.getDesKey(), StandardCharsets.UTF_8)));
        sb.append(";data=").append(hex(p.getData()));
        sb.append(";fileid=").append(esc(p.getFileId()));
        sb.append(";rtservlet=").append(p.getRetrieveServletUrl() == null ? "<null>" : esc(p.getRetrieveServletUrl().toString()));
        sb.append(";id=").append(esc(p.getId()));
        sb.append(";stservlet=").append(p.getStorageServletUrl() == null ? "<null>" : esc(p.getStorageServletUrl().toString()));
        sb.append(";aw=").append(p.isActiveWaiting());
        sb.append(";mcv=").append(esc(p.getMinimumClientVersion()));
    }

    static String props(final Properties p) {
        final TreeSet<String> keys = new TreeSet<>(p.stringPropertyNames());
        final StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (final String k : keys) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(esc(k)).append(':').append(esc(p.getProperty(k)));
        }
        return sb.append('}').toString();
    }

    static String describe(final String kind, final Object r) {
        final StringBuilder sb = new StringBuilder();
        if (r instanceof UrlParametersToSign) {
            final UrlParametersToSign p = (UrlParametersToSign) r;
            sb.append("op=").append(esc(p.getOperation())).append(';');
            common(sb, p);
            sb.append(";ver=").append(esc(p.getMinimumProtocolVersion()));
            sb.append(";format=").append(esc(p.getSignatureFormat()));
            sb.append(";algorithm=").append(esc(p.getSignatureAlgorithm()));
            sb.append(";props=").append(props(p.getExtraParams()));
            sb.append(";sticky=").append(p.getSticky());
            sb.append(";resetsticky=").append(p.getResetSticky());
            sb.append(";appname=").append(esc(p.getAppName()));
        } else if (r instanceof UrlParametersToSelectCert) {
            final UrlParametersToSelectCert p = (UrlParametersToSelectCert) r;
            common(sb, p);
            sb.append(";ver=").append(esc(p.getMinimumProtocolVersion()));
            sb.append(";props=").append(props(p.getExtraParams()));
            sb.append(";sticky=").append(p.getSticky());
            sb.append(";resetsticky=").append(p.getResetSticky());
        } else if (r instanceof UrlParametersToSave) {
            final UrlParametersToSave p = (UrlParametersToSave) r;
            common(sb, p);
            sb.append(";ver=").append(esc(p.getMinimumProtocolVersion()));
            sb.append(";title=").append(esc(p.getTitle()));
            sb.append(";filename=").append(esc(p.getFileName()));
            sb.append(";exts=").append(esc(p.getExtensions()));
            sb.append(";desc=").append(esc(p.getFileTypeDescription()));
        } else if (r instanceof UrlParametersForBatch) {
            final UrlParametersForBatch p = (UrlParametersForBatch) r;
            common(sb, p);
            sb.append(";ver=").append(esc(p.getMinimumProtocolVersion()));
            sb.append(";appname=").append(esc(p.getAppName()));
            sb.append(";local=").append(p.isLocalBatchProcess());
            sb.append(";pre=").append(esc(p.getBatchPresignerUrl()));
            sb.append(";post=").append(esc(p.getBatchPostSignerUrl()));
            sb.append(";props=").append(props(p.getExtraParams()));
            sb.append(";sticky=").append(p.getSticky());
            sb.append(";resetsticky=").append(p.getResetSticky());
            sb.append(";needcert=").append(p.isCertNeeded());
            sb.append(";jsonbatch=").append(p.isJsonBatch());
        }
        return sb.toString();
    }

    static Object parseUrl(final String kind, final String url) throws Exception {
        switch (kind) {
            case "sign": return ProtocolInvocationUriParser.getParametersToSign(url, true);
            case "selectcert": return ProtocolInvocationUriParser.getParametersToSelectCert(url, true);
            case "save": return ProtocolInvocationUriParser.getParametersToSave(url, true);
            case "batch": return ProtocolInvocationUriParserUtil.getParametersToBatch(extractParamsForBatch(url), true);
            default: throw new IllegalArgumentException(kind);
        }
    }

    static Object parseXml(final String kind, final byte[] xml) throws Exception {
        switch (kind) {
            case "sign": return ProtocolInvocationUriParser.getParametersToSign(xml, true);
            case "selectcert": return ProtocolInvocationUriParser.getParametersToSelectCert(xml, true);
            case "save": return ProtocolInvocationUriParser.getParametersToSave(xml, true);
            case "batch": return ProtocolInvocationUriParser.getParametersToBatch(xml, true);
            default: throw new IllegalArgumentException(kind);
        }
    }

    /** Gestor HTTP que registra la URL pedida y responde OK. */
    static final class Recorder implements UrlHttpManager {
        String last;
        private byte[] rec(final String url) {
            this.last = url;
            return "OK".getBytes(StandardCharsets.UTF_8);
        }
        @Override public byte[] readUrl(final String url, final UrlHttpMethod m) { return rec(url); }
        @Override public byte[] readUrl(final String url, final UrlHttpMethod m, final HttpErrorProcessor p) { return rec(url); }
        @Override public byte[] readUrl(final String url, final UrlHttpMethod m, final HttpErrorProcessor p, final SSLConfig c) { return rec(url); }
        @Override public byte[] readUrl(final String url, final int t, final String ct, final String a, final UrlHttpMethod m) { return rec(url); }
        @Override public byte[] readUrl(final String url, final int t, final String ct, final String a, final UrlHttpMethod m, final HttpErrorProcessor p) { return rec(url); }
        @Override public byte[] readUrl(final String url, final int t, final String ct, final String a, final UrlHttpMethod m, final HttpErrorProcessor p, final SSLConfig c) { return rec(url); }
        @Override public byte[] readUrl(final String url, final int t, final UrlHttpMethod m, final Properties h) { return rec(url); }
        @Override public byte[] readUrl(final String url, final int t, final UrlHttpMethod m, final Properties h, final HttpErrorProcessor p) { return rec(url); }
        @Override public byte[] readUrl(final String url, final int t, final UrlHttpMethod m, final Properties h, final HttpErrorProcessor p, final SSLConfig c) { return rec(url); }
    }

    /** Partición de AndroidHttpManager.readUrl en POST: destino y cuerpo. */
    static String split(final String url) {
        final StringTokenizer st = new StringTokenizer(url, "?");
        final String request = st.nextToken();
        final String body = st.nextToken();
        return esc(request) + " " + esc(body);
    }

    static String gzipB64(final String text) throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return Base64.encode(bos.toByteArray(), true);
    }

    public static void main(final String[] args) throws Exception {
        final Recorder recorder = new Recorder();
        UrlHttpManagerFactory.install(recorder);
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(args[0]), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                final String[] f = line.split("\t", -1);
                String out;
                try {
                    switch (f[0]) {
                        case "url": out = describe(f[1], parseUrl(f[1], unesc(f[2]).replace("@GZIP@", gzipB64("comprimido")))); break;
                        case "xml": out = describe(f[1], parseXml(f[1], unesc(f[2]).getBytes(StandardCharsets.UTF_8))); break;
                        case "cipher": out = CipherDataManager.cipherData(unhex(f[2]), f[1].getBytes(StandardCharsets.UTF_8)); break;
                        case "decipher": out = hex(CipherDataManager.decipherData(unesc(f[2]).getBytes(StandardCharsets.UTF_8), f[1].getBytes(StandardCharsets.UTF_8))); break;
                        case "error": {
                            final String text = f[3].equals("-")
                                ? ErrorManager.genError(f[1], Integer.parseInt(f[2]))
                                : ErrorManager.genError(f[1], Integer.parseInt(f[2]), unesc(f[3]));
                            out = esc(text) + " " + esc(URLEncoder.encode(text, "UTF-8"));
                            break;
                        }
                        case "upload":
                            IntermediateServerUtil.sendData(unesc(f[3]), f[1], f[2]);
                            out = split(recorder.last);
                            break;
                        case "download":
                            IntermediateServerUtil.retrieveData(f[1], f[2]);
                            out = split(recorder.last);
                            break;
                        case "b64std": out = hex(Base64.decode(unesc(f[1]))); break;
                        default: throw new IllegalArgumentException(f[0]);
                    }
                    out = "OK " + out;
                } catch (final Throwable e) {
                    out = "ERR " + e.getClass().getSimpleName();
                }
                System.out.println(line + "\t" + out);
            }
        }
    }
}
