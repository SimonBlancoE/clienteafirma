package sim;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.FileWriter;
import java.math.BigInteger;

/** Utilidades y registro de traza. */
public final class Hex {
    private Hex() { }

    public static String h(final byte[] b) {
        if (b == null) { return "null"; }
        final StringBuilder sb = new StringBuilder();
        for (final byte x : b) { sb.append(String.format("%02X", x & 0xff)); }
        return sb.toString();
    }

    public static byte[] b(final String s) {
        final String c = s.replace(" ", "");
        final byte[] r = new byte[c.length() / 2];
        for (int i = 0; i < r.length; i++) { r[i] = (byte) Integer.parseInt(c.substring(2 * i, 2 * i + 2), 16); }
        return r;
    }

    public static byte[] cat(final byte[]... parts) {
        final ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (final byte[] p : parts) { if (p != null) { o.write(p, 0, p.length); } }
        return o.toByteArray();
    }

    public static byte[] sub(final byte[] a, final int off, final int len) {
        final byte[] r = new byte[len];
        System.arraycopy(a, off, r, 0, len);
        return r;
    }

    /** Relleno ISO 7816-4 (80 00..) hasta multiplo de n (siempre anade al menos un octeto). */
    public static byte[] pad(final byte[] d, final int n) {
        final int l = (d.length / n + 1) * n;
        final byte[] r = new byte[l];
        System.arraycopy(d, 0, r, 0, d.length);
        r[d.length] = (byte) 0x80;
        return r;
    }

    public static byte[] unpad(final byte[] d) {
        int i = d.length - 1;
        while (i >= 0 && d[i] == 0) { i--; }
        if (i < 0 || d[i] != (byte) 0x80) { throw new IllegalStateException("Relleno ISO incorrecto: " + h(d)); }
        return sub(d, 0, i);
    }

    public static byte[] tlv(final int tag, final byte[] v) {
        if (v.length < 128) { return cat(new byte[] { (byte) tag, (byte) v.length }, v); }
        if (v.length < 256) { return cat(new byte[] { (byte) tag, (byte) 0x81, (byte) v.length }, v); }
        return cat(new byte[] { (byte) tag, (byte) 0x82, (byte) (v.length >> 8), (byte) v.length }, v);
    }

    /** Big-endian sin signo de longitud fija. */
    public static byte[] fixed(final BigInteger v, final int len) {
        final byte[] t = v.toByteArray();
        if (t.length == len) { return t; }
        final byte[] r = new byte[len];
        if (t.length > len) { System.arraycopy(t, t.length - len, r, 0, len); }
        else { System.arraycopy(t, 0, r, len - t.length, t.length); }
        return r;
    }

    public static byte[] inc(final byte[] ssc) {
        final byte[] r = ssc.clone();
        for (int i = r.length - 1; i >= 0; i--) { r[i]++; if (r[i] != 0) { break; } }
        return r;
    }

    // ---------------- Traza ----------------
    private static PrintWriter out;
    public static boolean quiet = false;

    public static void openLog(final String file) throws Exception {
        out = new PrintWriter(new FileWriter(file), true);
    }

    public static void log(final String s) {
        if (quiet) { return; }
        if (out != null) { out.println(s); }
    }

    public static void closeLog() {
        if (out != null) { out.close(); out = null; }
    }
}
