package sim;

import static sim.Hex.b;
import static sim.Hex.cat;
import static sim.Hex.h;
import static sim.Hex.log;
import static sim.Hex.pad;
import static sim.Hex.sub;
import static sim.Hex.tlv;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.connection.AbstractApduConnectionIso7816;
import es.gob.jmulticard.connection.ApduConnection;
import es.gob.jmulticard.connection.ApduConnectionProtocol;

/** Simulador software de DNIe 3.0/4.0 por NFC (lado tarjeta), para ejercitar jmulticard. */
public final class SimCard extends AbstractApduConnectionIso7816 {

    // ------------------------------------------------------------------ configuracion
    public byte[] resetBytes = b("3B888001E1F35E117781A10003");
    public String can = "123456";
    public String pin = "1234abcd";
    public String idesp = "BMP100002";
    public boolean cwaOuterSwEqualsInner = false; // false: SW exterior 9000 y SW real en DO99
    public int retries = 3;
    public final byte[] serial = b("01020304050607");

    // ------------------------------------------------------------------ estadisticas
    public int maxCmd = 0;
    public int maxRsp = 0;
    public String maxCmdHex = "";
    public String maxRspHex = "";
    public boolean envelopeUsed = false;
    public int paceGa4Fail = 0;
    public boolean lastKxLeadingZero = false;
    public int apduCount = 0;
    public int intAuthCount = 0, intAuthNminus = 0, intAuthNminusShortSig = 0;
    public boolean lastIntAuthShort = false;

    private static final byte[] PACE_OID = b("04007F00070202040202");
    private final Random rnd;
    private final String dataDir;
    private boolean open = true;

    // ------------------------------------------------------------------ contexto SM
    private abstract class Ctx {
        final String name;
        Ctx(final String n) { name = n; }
        abstract Cmd unwrap(byte[] apdu) throws SmError;
        abstract byte[] wrap(byte[] data, int sw);
    }

    static final class SmError extends Exception {
        private static final long serialVersionUID = 1L;
        SmError(final String m) { super(m); }
    }

    static final class Cmd {
        int cla, ins, p1, p2;
        byte[] data;
        Integer le;
        String hex() {
            final byte[] hd = new byte[] { (byte) cla, (byte) ins, (byte) p1, (byte) p2 };
            if (data == null || data.length == 0) {
                return h(hd) + (le != null ? String.format("%02X", le & 0xff) : "");
            }
            return h(hd) + String.format("%02X", data.length) + h(data) + (le != null ? String.format("%02X", le & 0xff) : "");
        }
    }

    static Cmd parsePlain(final byte[] a) {
        final Cmd c = new Cmd();
        c.cla = a[0] & 0xff; c.ins = a[1] & 0xff; c.p1 = a[2] & 0xff; c.p2 = a[3] & 0xff;
        if (a.length == 5) { c.le = Integer.valueOf(a[4] & 0xff); }
        else if (a.length > 5) {
            final int lc = a[4] & 0xff;
            c.data = sub(a, 5, lc);
            if (a.length == 5 + lc + 1) { c.le = Integer.valueOf(a[5 + lc] & 0xff); }
        }
        return c;
    }

    /** Parte el cuerpo de una APDU protegida en sus TLV (87, 97, 8E, 99). */
    static Map<Integer, byte[]> tlvs(final byte[] body) {
        final Map<Integer, byte[]> m = new LinkedHashMap<>();
        int i = 0;
        while (i < body.length) {
            final int t = body[i] & 0xff;
            int l = body[i + 1] & 0xff;
            int off = i + 2;
            if (l == 0x81) { l = body[i + 2] & 0xff; off = i + 3; }
            else if (l == 0x82) { l = (body[i + 2] & 0xff) << 8 | body[i + 3] & 0xff; off = i + 4; }
            m.put(Integer.valueOf(t), sub(body, i, off - i + l)); // TLV completo
            i = off + l;
        }
        return m;
    }

    static byte[] valueOf(final byte[] fullTlv) {
        int l = fullTlv[1] & 0xff; int off = 2;
        if (l == 0x81) { l = fullTlv[2] & 0xff; off = 3; }
        else if (l == 0x82) { l = (fullTlv[2] & 0xff) << 8 | fullTlv[3] & 0xff; off = 4; }
        return sub(fullTlv, off, l);
    }

    /** SM PACE ICAO (AES-CBC + AES-CMAC/8, SSC 16 octetos). */
    final class PaceCtx extends Ctx {
        final byte[] kenc, kmac; byte[] ssc = new byte[16];
        PaceCtx(final byte[] e, final byte[] m) { super("PACE"); kenc = e; kmac = m; }
        @Override Cmd unwrap(final byte[] a) throws SmError {
            ssc = Hex.inc(ssc);
            final byte[] header = sub(a, 0, 4);
            final int lc = a[4] & 0xff;
            final Map<Integer, byte[]> t = tlvs(sub(a, 5, lc));
            final byte[] do87 = t.get(Integer.valueOf(0x87)), do97 = t.get(Integer.valueOf(0x97)), do8e = t.get(Integer.valueOf(0x8E));
            if (do8e == null) { throw new SmError("Falta DO8E"); }
            final byte[] icao = cmac(kmac, pad(cat(ssc, pad(header, 16), do87, do97), 16));
            if (!Arrays.equals(icao, valueOf(do8e))) {
                final byte[] jmc = cmac(kmac, pad(cat(ssc, header, do87, do97), 16));
                throw new SmError("MAC PACE incorrecto (ICAO=" + h(icao) + ", recibido=" + h(valueOf(do8e)) +
                    ", variante jmulticard sin relleno de cabecera=" + h(jmc) + (Arrays.equals(jmc, valueOf(do8e)) ? " COINCIDE" : " no coincide") + ")");
            }
            final Cmd c = new Cmd();
            c.cla = a[0] & 0xf3; c.ins = a[1] & 0xff; c.p1 = a[2] & 0xff; c.p2 = a[3] & 0xff;
            if (do87 != null) {
                final byte[] v = valueOf(do87);
                if (v[0] != 1) { throw new SmError("DO87 sin indicador 01"); }
                c.data = Hex.unpad(aesCbc(false, kenc, aesEcb(kenc, ssc), sub(v, 1, v.length - 1)));
            }
            if (do97 != null) { c.le = Integer.valueOf(valueOf(do97)[0] & 0xff); }
            return c;
        }
        @Override byte[] wrap(final byte[] data, final int sw) {
            ssc = Hex.inc(ssc);
            byte[] do87 = null;
            if (data != null && data.length > 0) {
                do87 = tlv(0x87, cat(new byte[] { 1 }, aesCbc(true, kenc, aesEcb(kenc, ssc), pad(data, 16))));
            }
            final byte[] do99 = tlv(0x99, new byte[] { (byte) (sw >> 8), (byte) sw });
            final byte[] mac = cmac(kmac, pad(cat(ssc, do87, do99), 16));
            return cat(do87, do99, tlv(0x8E, mac), new byte[] { (byte) 0x90, 0x00 });
        }
    }

    /** SM CWA-14890 V2 (3DES-CBC IV=0, MAC retail de 8 octetos, SSC 8 octetos). */
    final class CwaCtx extends Ctx {
        final byte[] kenc, kmac; byte[] ssc;
        CwaCtx(final String n, final byte[] e, final byte[] m, final byte[] s) { super(n); kenc = e; kmac = m; ssc = s; }
        @Override Cmd unwrap(final byte[] a) throws SmError {
            ssc = Hex.inc(ssc);
            final byte[] header = sub(a, 0, 4);
            final int lc = a[4] & 0xff;
            if (a.length != 5 + lc) { log("    [nota] APDU CWA con octetos tras el cuerpo (Le?): longitud " + a.length + " vs 5+Lc=" + (5 + lc)); }
            final Map<Integer, byte[]> t = tlvs(sub(a, 5, lc));
            final byte[] do87 = t.get(Integer.valueOf(0x87)), do97 = t.get(Integer.valueOf(0x97)), do8e = t.get(Integer.valueOf(0x8E));
            if (do8e == null) { throw new SmError("Falta DO8E"); }
            final byte[] mac = retailMac(kmac, ssc, pad(cat(pad(header, 8), do87, do97), 8));
            if (!Arrays.equals(mac, valueOf(do8e))) {
                throw new SmError("MAC CWA incorrecto (esperado " + h(mac) + ", recibido " + h(valueOf(do8e)) + ")");
            }
            final Cmd c = new Cmd();
            c.cla = a[0] & 0xf3; c.ins = a[1] & 0xff; c.p1 = a[2] & 0xff; c.p2 = a[3] & 0xff;
            if (do87 != null) {
                final byte[] v = valueOf(do87);
                if (v[0] != 1) { throw new SmError("DO87 sin indicador 01"); }
                c.data = Hex.unpad(tdesCbc(false, kenc, sub(v, 1, v.length - 1)));
            }
            if (do97 != null) { c.le = Integer.valueOf(valueOf(do97)[0] & 0xff); }
            return c;
        }
        @Override byte[] wrap(final byte[] data, final int sw) {
            ssc = Hex.inc(ssc);
            byte[] do87 = null;
            if (data != null && data.length > 0) {
                do87 = tlv(0x87, cat(new byte[] { 1 }, tdesCbc(true, kenc, pad(data, 8))));
            }
            final byte[] do99 = tlv(0x99, new byte[] { (byte) (sw >> 8), (byte) sw });
            final byte[] mac = retailMac(kmac, ssc, pad(cat(do87, do99), 8));
            final int outer = cwaOuterSwEqualsInner ? sw : 0x9000;
            return cat(do87, do99, tlv(0x8E, mac), new byte[] { (byte) (outer >> 8), (byte) outer });
        }
    }

    private Ctx ctx = null;
    private Ctx pending = null;

    // ------------------------------------------------------------------ PACE
    private static final X9ECParameters EC = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
    private byte[] paceS;
    private ECPoint gMapped, pkIfdEph, pkIccEph;
    private BigInteger skMap;
    private byte[] paceKenc, paceKmac;
    private int pacePwdType = -1;

    // ------------------------------------------------------------------ CWA
    private byte[] chrIfd, rndIfd, kicc, rndIcc;
    private String cwaChannelName;
    private BigInteger nIfd;
    private final BigInteger eIfd = BigInteger.valueOf(65537);
    private final BigInteger nIcc, dIcc;
    private final Properties ifd = new Properties();
    private boolean pinVerified = false;
    private String dstKey = null;

    // ------------------------------------------------------------------ sistema de ficheros
    static final class Node {
        final String fid; final byte[] content; final Map<String, Node> kids = new LinkedHashMap<>(); final boolean df;
        Node(final String f, final byte[] c, final boolean isDf) { fid = f; content = c; df = isDf; }
    }
    private final Node mf = new Node("3F00", null, true);
    private Node curDf = mf;
    private Node curEf = null;

    public SimCard(final String dir, final long seed) throws Exception {
        dataDir = dir;
        rnd = new Random(seed);
        final Properties icc = load("icc_key.properties");
        nIcc = new BigInteger(icc.getProperty("n"), 16);
        dIcc = new BigInteger(icc.getProperty("d"), 16);
        try (FileInputStream in = new FileInputStream(new File(dir, "ifd.properties"))) { ifd.load(in); }
        buildFs();
    }

    private Properties load(final String f) throws Exception {
        final Properties p = new Properties();
        try (FileInputStream in = new FileInputStream(new File(dataDir, f))) { p.load(in); }
        return p;
    }

    private byte[] file(final String f) throws Exception { return Files.readAllBytes(new File(dataDir, f).toPath()); }

    private void buildFs() throws Exception {
        mf.kids.clear();
        mf.kids.put("0006", new Node("0006", null, false)); // IDESP, contenido dinamico
        mf.kids.put("601F", new Node("601F", file("icc_cert.der"), false));
        final Node df5015 = new Node("5015", null, true);
        df5015.kids.put("6004", new Node("6004", file("CDF_ESPECIMEN.ber"), false));
        df5015.kids.put("6001", new Node("6001", file("PRKDF_ESPECIMEN.ber"), false));
        mf.kids.put("5015", df5015);
        final Node df6061 = new Node("6061", null, true);
        for (final String f : new String[] { "7001", "7002", "7003" }) { df6061.kids.put(f, new Node(f, file("cert_" + f + ".bin"), false)); }
        mf.kids.put("6061", df6061);
        mf.kids.put("3F11", new Node("3F11", null, true));
    }

    private byte[] content(final Node n) { return "0006".equals(n.fid) ? idesp.getBytes() : n.content; }

    // ------------------------------------------------------------------ ApduConnection
    @Override public int getMaxApduSize() { return 0xFF; }
    @Override public void setProtocol(final ApduConnectionProtocol p) { /* T=CL */ }
    @Override public void open() { if (!open) { log("  [conexion] open()"); } open = true; }
    @Override public void close() { log("  [conexion] close()"); open = false; }
    @Override public byte[] reset() { log("  [conexion] reset() -> " + (resetBytes.length == 0 ? "(vacio, como HLR NfcB vacio en Android)" : h(resetBytes)) + " (sin reiniciar el estado de la tarjeta)"); return resetBytes.clone(); }
    @Override public long[] getTerminals(final boolean onlyWithCardPresent) { return new long[] { 0 }; }
    @Override public String getTerminalInfo(final int terminal) { return "Simulador DNIe NFC"; }
    @Override public void setTerminal(final int t) { /* unico */ }
    @Override public boolean isOpen() { return open; }
    @Override public ApduConnection getSubConnection() { return null; }

    private byte[] envBuf = new byte[0];

    @Override
    protected ResponseApdu internalTransmit(final byte[] apdu) {
        apduCount++;
        if (apdu.length > maxCmd) { maxCmd = apdu.length; maxCmdHex = h(sub(apdu, 0, Math.min(8, apdu.length))); }
        final String layer = ctx == null ? "sin SM" : ctx.name;
        log(String.format("> C-APDU #%d [%d oct] (contexto SM activo: %s) %s", Integer.valueOf(apduCount), Integer.valueOf(apdu.length), layer, h(apdu)));
        byte[] r;
        if ((apdu[0] & 0xff) == 0x90 && (apdu[1] & 0xff) == 0xC2) {
            envelopeUsed = true;
            envBuf = cat(envBuf, sub(apdu, 5, apdu[4] & 0xff));
            log("    ENVELOPE 90 C2 recibido, acumulado " + envBuf.length);
            if (envBuf.length >= 5 && envBuf.length >= 5 + (envBuf[4] & 0xff)) {
                final byte[] full = envBuf; envBuf = new byte[0];
                r = process(full);
            }
            else { r = b("9000"); }
        }
        else {
            r = process(apdu);
        }
        if (r.length > maxRsp) { maxRsp = r.length; maxRspHex = h(sub(r, 0, Math.min(8, r.length))); }
        log(String.format("< R-APDU [%d oct] %s", Integer.valueOf(r.length), h(r)));
        return new ResponseApdu(r);
    }

    private byte[] process(final byte[] apdu) {
        final boolean sm = (apdu[0] & 0x0C) == 0x0C;
        if (ctx == null) {
            if (sm) { log("    !! APDU con SM sin contexto activo -> 6988"); return b("6988"); }
            final Cmd c = parsePlain(apdu);
            log("    claro: " + describe(c));
            final Resp rs = exec(c);
            if (pending != null) { ctx = pending; pending = null; log("    -> contexto SM activado: " + ctx.name); }
            return cat(rs.data, new byte[] { (byte) (rs.sw >> 8), (byte) rs.sw });
        }
        if (!sm) {
            log("    !! APDU en claro con SM activo (" + ctx.name + ") -> 6987, se descarta todo el estado SM");
            ctx = null; pending = null; pinVerified = false; dstKey = null;
            return b("6987");
        }
        final Cmd c;
        try {
            c = ctx.unwrap(apdu);
        }
        catch (final SmError e) {
            log("    !! error SM en " + ctx.name + ": " + e.getMessage() + " -> 6988 y se descarta el estado SM");
            ctx = null; pending = null; pinVerified = false;
            return b("6988");
        }
        log("    capa " + ctx.name + " -> comando interno: " + describe(c) + "  [" + c.hex() + "]");
        if ((c.cla & 0x0C) == 0x0C) { log("    !! el comando interno vuelve a llevar SM (anidamiento)"); }
        final Resp rs = exec(c);
        log("    respuesta interna: " + h(rs.data) + " SW=" + String.format("%04X", Integer.valueOf(rs.sw)));
        final byte[] w = ctx.wrap(rs.data, rs.sw);
        if (pending != null) { log("    -> contexto SM sustituido: " + ctx.name + " => " + pending.name); ctx = pending; pending = null; }
        return w;
    }

    static final class Resp {
        final byte[] data; final int sw;
        Resp(final byte[] d, final int s) { data = d; sw = s; }
    }
    private static Resp sw(final int s) { return new Resp(new byte[0], s); }
    private static Resp ok(final byte[] d) { return new Resp(d, 0x9000); }

    private static String describe(final Cmd c) {
        final String k = String.format("%02X %02X %02X %02X", Integer.valueOf(c.cla), Integer.valueOf(c.ins), Integer.valueOf(c.p1), Integer.valueOf(c.p2));
        String n;
        switch (c.ins) {
            case 0x22: n = c.p1 == 0xC1 ? "MSE:SET AT" : c.p1 == 0x81 ? "MSE:SET (clave publica verificacion)" : c.p1 == 0x41 ? "MSE:SET DST" : "MSE"; break;
            case 0x86: n = "GENERAL AUTHENTICATE"; break;
            case 0xA4: n = c.p1 == 4 ? "SELECT por nombre '" + new String(c.data) + "'" : "SELECT FID " + h(c.data); break;
            case 0xB0: n = "READ BINARY off=" + (c.p1 << 8 | c.p2) + " Le=" + c.le; break;
            case 0xB8: n = "GET CHIP INFO"; break;
            case 0x2A: n = c.p2 == 0xAE ? "PSO VERIFY CERTIFICATE" : c.p1 == 0x9E ? "PSO COMPUTE DIGITAL SIGNATURE" : "PSO"; break;
            case 0x88: n = "INTERNAL AUTHENTICATE"; break;
            case 0x84: n = "GET CHALLENGE"; break;
            case 0x82: n = "EXTERNAL AUTHENTICATE"; break;
            case 0x20: n = c.data == null ? "VERIFY (consulta de reintentos)" : "VERIFY PIN (" + c.data.length + " octetos)"; break;
            default: n = "INS desconocida";
        }
        return k + " " + n + (c.le != null ? " Le=" + String.format("%02X", c.le) : "");
    }

    // ------------------------------------------------------------------ ejecucion de comandos en claro
    private Resp exec(final Cmd c) {
        try {
            switch (c.ins) {
                case 0x22: return mse(c);
                case 0x86: return ga(c);
                case 0xA4: return select(c);
                case 0xB0: return read(c);
                case 0xB8: return ok(serial.clone());
                case 0x2A:
                    if (c.p2 == 0xAE) { return sw(0x9000); }
                    if (c.p1 == 0x9E && c.p2 == 0x9A) { return pso(c); }
                    return sw(0x6A86);
                case 0x88: return intAuth(c);
                case 0x84: rndIcc = rand(8); return ok(rndIcc.clone());
                case 0x82: return extAuth(c);
                case 0x20: return verify(c);
                default: return sw(0x6D00);
            }
        }
        catch (final Exception e) {
            log("    !! excepcion en el simulador: " + e);
            return sw(0x6F00);
        }
    }

    private byte[] rand(final int n) { final byte[] r = new byte[n]; rnd.nextBytes(r); return r; }

    private Resp mse(final Cmd c) {
        if (c.p1 == 0xC1 && c.p2 == 0xA4 && (c.data[0] & 0xff) == 0x80) {
            final Map<Integer, byte[]> t = tlvs(c.data);
            log("    PACE MSE:SET AT -> OID " + h(valueOf(t.get(Integer.valueOf(0x80)))) + ", password ref " + h(valueOf(t.get(Integer.valueOf(0x83)))) +
                (t.containsKey(Integer.valueOf(0x84)) ? ", domain param " + h(valueOf(t.get(Integer.valueOf(0x84)))) : "") +
                (t.containsKey(Integer.valueOf(0x7F)) ? ", CHAT presente" : ""));
            pacePwdType = valueOf(t.get(Integer.valueOf(0x83)))[0];
            paceS = null;
            return sw(0x9000);
        }
        if (c.p1 == 0xC1 && c.p2 == 0xA4) {
            final Map<Integer, byte[]> t = tlvs(c.data);
            final byte[] ref = valueOf(t.get(Integer.valueOf(0x83)));
            chrIfd = sub(ref, ref.length - 8, 8);
            final String chr = h(chrIfd);
            nIfd = new BigInteger(ifd.getProperty(chr), 16);
            cwaChannelName = ifd.getProperty(chr + ".class").contains("Pin") ? "CWA-PIN" : "CWA-USR";
            log("    CWA MSE:SET AT -> CHR IFD " + chr + " (" + ifd.getProperty(chr + ".class") + "), ref clave ICC " + h(valueOf(t.get(Integer.valueOf(0x84)))));
            return sw(0x9000);
        }
        if (c.p1 == 0x41 && c.p2 == 0xB6) {
            dstKey = h(valueOf(tlvs(c.data).get(Integer.valueOf(0x84))));
            log("    DST: clave privada " + dstKey);
            return sw(0x9000);
        }
        return sw(0x9000);
    }

    private Resp ga(final Cmd c) throws Exception {
        final byte[] inner = valueOf(c.data); // contenido de 7C
        final int tag = inner.length == 0 ? 0x80 : inner[0] & 0xff;
        if (inner.length == 0) {
            final byte[] kpi = sub(sha1(cat(can.getBytes(), b("00000003"))), 0, 16);
            paceS = rand(16);
            final byte[] z = aesEcb(kpi, paceS);
            log("    PACE paso 1: s=" + h(paceS) + " z=" + h(z));
            return ok(tlv(0x7C, tlv(0x80, z)));
        }
        final ECCurve curve = EC.getCurve();
        final BigInteger n = EC.getN();
        if (tag == 0x81) {
            final ECPoint pkIfdMap = curve.decodePoint(valueOf(inner));
            skMap = new BigInteger(1, rand(32)).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            final ECPoint pkMap = EC.getG().multiply(skMap).normalize();
            final ECPoint hPt = pkIfdMap.multiply(skMap).normalize();
            gMapped = EC.getG().multiply(new BigInteger(1, paceS)).add(hPt).normalize();
            log("    PACE paso 2: H.x=" + h(hPt.getAffineXCoord().getEncoded()) + " G~.x=" + h(gMapped.getAffineXCoord().getEncoded()));
            return ok(tlv(0x7C, tlv(0x82, pkMap.getEncoded(false))));
        }
        if (tag == 0x83) {
            pkIfdEph = curve.decodePoint(valueOf(inner));
            final BigInteger sk = new BigInteger(1, rand(32)).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            pkIccEph = gMapped.multiply(sk).normalize();
            final byte[] kx = pkIfdEph.multiply(sk).normalize().getAffineXCoord().getEncoded();
            lastKxLeadingZero = kx[0] == 0;
            paceKenc = sub(sha1(cat(kx, b("00000001"))), 0, 16);
            paceKmac = sub(sha1(cat(kx, b("00000002"))), 0, 16);
            log("    PACE paso 3: K.x=" + h(kx) + " KSenc=" + h(paceKenc) + " KSmac=" + h(paceKmac) + (lastKxLeadingZero ? " (K.x empieza por 00)" : ""));
            return ok(tlv(0x7C, tlv(0x84, pkIccEph.getEncoded(false))));
        }
        if (tag == 0x85) {
            final byte[] tIfd = valueOf(inner);
            final byte[] exp = cmac(paceKmac, cat(b("7F494F060A"), PACE_OID, b("8641"), pkIccEph.getEncoded(false)));
            if (!Arrays.equals(exp, tIfd)) {
                paceGa4Fail++;
                log("    PACE paso 4: T_IFD incorrecto (esperado " + h(exp) + ", recibido " + h(tIfd) + ")" + (lastKxLeadingZero ? " [K.x con 00 inicial: jmulticard deriva con 31 octetos]" : "") + " -> 6300");
                return sw(0x6300);
            }
            final byte[] tIcc = cmac(paceKmac, cat(b("7F494F060A"), PACE_OID, b("8641"), pkIfdEph.getEncoded(false)));
            log("    PACE paso 4: T_IFD correcto; T_ICC=" + h(tIcc) + "; SM PACE activo con SSC=0");
            pending = new PaceCtx(paceKenc, paceKmac);
            return ok(tlv(0x7C, tlv(0x86, tIcc)));
        }
        return sw(0x6A80);
    }

    private static byte[] fci(final Node nd, final int size) {
        return tlv(0x6F, cat(b("8102"), new byte[] { (byte) (size >> 8), (byte) size }, nd.df ? b("820138") : b("820101"), b("8302"), b(nd.fid)));
    }

    private Resp select(final Cmd c) {
        if (c.p1 == 4) {
            if ("Master.File".equals(new String(c.data))) { curDf = mf; curEf = null; return sw(0x9000); }
            return sw(0x6A82);
        }
        final String fid = h(c.data);
        Node nd = curDf.kids.get(fid);
        if (nd == null) { nd = mf.kids.get(fid); }
        if (nd == null) { return sw(0x6A82); }
        if (nd.df) { curDf = nd; curEf = null; return ok(fci(nd, 0)); }
        curEf = nd;
        return ok(fci(nd, content(nd).length));
    }

    private Resp read(final Cmd c) {
        if (curEf == null) { return sw(0x6986); }
        final byte[] ct = content(curEf);
        final int off = c.p1 << 8 | c.p2;
        if (off > ct.length) { return sw(0x6B00); }
        final int le = c.le == null || c.le.intValue() == 0 ? 256 : c.le.intValue();
        final int n = Math.min(le, ct.length - off);
        return new Resp(sub(ct, off, n), n < le ? 0x6282 : 0x9000);
    }

    private Resp intAuth(final Cmd c) throws Exception {
        rndIfd = sub(c.data, 0, 8);
        final byte[] sn = sub(c.data, 8, c.data.length - 8);
        final byte[] prnd1 = rand(74);
        kicc = rand(32);
        final byte[] m = cat(b("6A"), prnd1, kicc, sha1(cat(prnd1, kicc, rndIfd, sn)), b("BC"));
        final BigInteger sig = new BigInteger(1, m).modPow(dIcc, nIcc);
        final BigInteger sigMin = sig.min(nIcc.subtract(sig));
        final byte[] resp = Hex.fixed(sigMin.modPow(eIfd, nIfd), 128);
        intAuthCount++; lastIntAuthShort = false;
        if (!sigMin.equals(sig)) { intAuthNminus++; if (sig.bitLength() <= 1016) { intAuthNminusShortSig++; lastIntAuthShort = true; } }
        log("    CWA INTERNAL AUTH: RND.IFD=" + h(rndIfd) + " SN.IFD=" + h(sn) + " KICC=" + h(kicc) + (sigMin.equals(sig) ? " (SIGMIN=SIG)" : " (SIGMIN=N-SIG)"));
        return ok(resp);
    }

    private Resp extAuth(final Cmd c) throws Exception {
        final BigInteger sigMin = new BigInteger(1, c.data).modPow(dIcc, nIcc);
        byte[] m = Hex.fixed(sigMin.modPow(eIfd, nIfd), 128);
        if (m[0] != 0x6A || m[127] != (byte) 0xBC) { m = Hex.fixed(nIfd.subtract(sigMin).modPow(eIfd, nIfd), 128); }
        if (m[0] != 0x6A || m[127] != (byte) 0xBC) { log("    CWA EXTERNAL AUTH: relleno 6A..BC no encontrado -> 6300"); return sw(0x6300); }
        final byte[] prnd2 = sub(m, 1, 74), kifd = sub(m, 75, 32), hh = sub(m, 107, 20);
        final byte[] snIcc = cat(new byte[8 - serial.length], serial);
        if (!Arrays.equals(hh, sha1(cat(prnd2, kifd, rndIcc, snIcc)))) { log("    CWA EXTERNAL AUTH: hash incorrecto -> 6300"); return sw(0x6300); }
        final byte[] k = new byte[32];
        for (int i = 0; i < 32; i++) { k[i] = (byte) (kicc[i] ^ kifd[i]); }
        final byte[] ke = sub(sha1(cat(k, b("00000001"))), 0, 16), km = sub(sha1(cat(k, b("00000002"))), 0, 16);
        final byte[] ssc = cat(sub(rndIcc, 4, 4), sub(rndIfd, 4, 4));
        log("    CWA EXTERNAL AUTH correcto: KIFD=" + h(kifd) + " Kenc=" + h(ke) + " Kmac=" + h(km) + " SSC=" + h(ssc) + " -> nuevo canal " + cwaChannelName);
        pending = new CwaCtx(cwaChannelName, ke, km, ssc);
        return sw(0x9000);
    }

    private Resp verify(final Cmd c) {
        if (c.data == null || c.data.length == 0) {
            if (pinVerified) { return sw(0x9000); }
            return sw(retries == 0 ? 0x6983 : 0x63C0 | retries);
        }
        if (retries == 0) { return sw(0x6983); }
        if (new String(c.data).equals(pin)) { pinVerified = true; retries = 3; log("    PIN correcto"); return sw(0x9000); }
        retries--;
        log("    PIN incorrecto, reintentos=" + retries);
        return sw(retries == 0 ? 0x6983 : 0x63C0 | retries);
    }

    private Resp pso(final Cmd c) throws Exception {
        if (!pinVerified) { log("    !! PSO CDS sin PIN verificado"); return sw(0x6982); }
        if (ctx == null || !"CWA-USR".equals(ctx.name)) { log("    !! PSO CDS fuera de canal de usuario: " + (ctx == null ? "ninguno" : ctx.name)); }
        final Properties k = load("key_" + dstKey + ".properties");
        final BigInteger nn = new BigInteger(k.getProperty("n"), 16), dd = new BigInteger(k.getProperty("d"), 16);
        final int len = (nn.bitLength() + 7) / 8;
        final byte[] em = new byte[len];
        em[1] = 1;
        for (int i = 2; i < len - c.data.length - 1; i++) { em[i] = (byte) 0xFF; }
        System.arraycopy(c.data, 0, em, len - c.data.length, c.data.length);
        log("    PSO CDS: DigestInfo=" + h(c.data) + " con clave " + dstKey);
        return ok(Hex.fixed(new BigInteger(1, em).modPow(dd, nn), len));
    }

    // ------------------------------------------------------------------ primitivas
    static byte[] sha1(final byte[] d) throws Exception { return MessageDigest.getInstance("SHA-1").digest(d); }

    static byte[] aesEcb(final byte[] k, final byte[] d) {
        try { final Cipher c = Cipher.getInstance("AES/ECB/NoPadding"); c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES")); return c.doFinal(d); }
        catch (final Exception e) { throw new IllegalStateException(e); }
    }

    static byte[] aesCbc(final boolean enc, final byte[] k, final byte[] iv, final byte[] d) {
        try { final Cipher c = Cipher.getInstance("AES/CBC/NoPadding"); c.init(enc ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"), new IvParameterSpec(iv)); return c.doFinal(d); }
        catch (final Exception e) { throw new IllegalStateException(e); }
    }

    static byte[] cmac(final byte[] k, final byte[] d) {
        final CMac m = new CMac(AESEngine.newInstance(), 64);
        m.init(new KeyParameter(k));
        m.update(d, 0, d.length);
        final byte[] o = new byte[8];
        m.doFinal(o, 0);
        return o;
    }

    static byte[] k24(final byte[] k) { return cat(k, sub(k, 0, 8)); }

    static byte[] tdesCbc(final boolean enc, final byte[] k, final byte[] d) {
        try { final Cipher c = Cipher.getInstance("DESede/CBC/NoPadding"); c.init(enc ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(k24(k), "DESede"), new IvParameterSpec(new byte[8])); return c.doFinal(d); }
        catch (final Exception e) { throw new IllegalStateException(e); }
    }

    static byte[] desEcb(final byte[] k8, final byte[] d) {
        try { final Cipher c = Cipher.getInstance("DES/ECB/NoPadding"); c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k8, "DES")); return c.doFinal(d); }
        catch (final Exception e) { throw new IllegalStateException(e); }
    }

    static byte[] retailMac(final byte[] kmac, final byte[] ssc, final byte[] padded) {
        final byte[] k1 = sub(kmac, 0, 8);
        byte[] t = desEcb(k1, ssc);
        int i = 0;
        while (i < padded.length - 8) {
            final byte[] x = new byte[8];
            for (int j = 0; j < 8; j++) { x[j] = (byte) (t[j] ^ padded[i + j]); }
            t = desEcb(k1, x);
            i += 8;
        }
        final byte[] x = new byte[8];
        for (int j = 0; j < 8; j++) { x[j] = (byte) (t[j] ^ padded[i + j]); }
        try { final Cipher c = Cipher.getInstance("DESede/ECB/NoPadding"); c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k24(kmac), "DESede")); return c.doFinal(x); }
        catch (final Exception e) { throw new IllegalStateException(e); }
    }

    public String ctxName() { return ctx == null ? "ninguno" : ctx.name; }
}
