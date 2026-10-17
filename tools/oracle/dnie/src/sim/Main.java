package sim;

import static sim.Hex.h;
import static sim.Hex.log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;

import es.gob.jmulticard.apdu.CommandApdu;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.asn1.icao.CardAccess;
import es.gob.jmulticard.DigestAlgorithm;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.icao.WirelessInitializerCan;
import es.gob.jmulticard.connection.pace.PaceConnection;
import es.gob.jmulticard.connection.pace.SecureMessaging;
import es.gob.jmulticard.crypto.BcCryptoHelper;
import es.gob.jmulticard.crypto.BcPaceChannelHelper;

/** Programa de pruebas: ejecuta jmulticard real contra el simulador. */
public final class Main {

    static String dataDir;

    static CallbackHandler handler(final String can, final String pin) {
        return (final Callback[] cbs) -> {
            for (final Callback cb : cbs) {
                if (cb instanceof TextInputCallback) {
                    log("  [callback] " + cb.getClass().getName() + " prompt='" + ((TextInputCallback) cb).getPrompt() + "' -> CAN");
                    ((TextInputCallback) cb).setText(can);
                }
                else if (cb instanceof PasswordCallback) {
                    log("  [callback] " + cb.getClass().getName() + " prompt='" + ((PasswordCallback) cb).getPrompt().replace("\n", "\\n") + "' -> PIN");
                    ((PasswordCallback) cb).setPassword(pin.toCharArray());
                }
                else {
                    log("  [callback] no soportado: " + cb.getClass().getName());
                }
            }
        };
    }

    static String chain(final Throwable t) {
        final StringBuilder sb = new StringBuilder();
        Throwable x = t;
        while (x != null) { sb.append(x.getClass().getName()).append(": ").append(x.getMessage()).append("\n      causa-> "); x = x.getCause(); }
        return sb.toString();
    }

    static void signAndVerify(final Dnie card, final String label, final SimCard sim) throws Exception {
        final byte[] data = ("Datos de prueba " + label).getBytes();
        final PrivateKeyReference pk = card.getPrivateKey("CertFirmaDigital");
        log("### " + label + ": card.sign(datos, SHA256withRSA, CertFirmaDigital) -- contexto SM en tarjeta antes: " + sim.ctxName());
        final byte[] sig = card.sign(data, "SHA256withRSA", pk);
        final X509Certificate cert = card.getCertificate("CertFirmaDigital");
        final Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(cert.getPublicKey());
        v.update(data);
        log("### " + label + ": firma de " + sig.length + " octetos, verificacion con la clave publica del certificado: " + v.verify(sig) + " -- contexto SM en tarjeta despues: " + sim.ctxName());
    }

    public static void main(final String[] args) throws Exception {
        dataDir = args[1];
        final String mode = args[0];
        switch (mode) {
            case "flow": flow(args[2]); break;
            case "r1": r1(args[2]); break;
            case "wrongpin": wrongPin(args[2]); break;
            case "outer63": outer63(args[2]); break;
            case "case1": case1(args[2]); break;
            case "stress": stress(Integer.parseInt(args[2])); break;
            case "rng": rng(); break;
            case "signstress": signStress(Integer.parseInt(args[2])); break;
            case "detect": detect(args[2]); break;
            case "serve": serve(args); break;
            default: throw new IllegalArgumentException(mode);
        }
    }

    /**
     * Modo servidor para la prueba cruzada con el controlador Rust (crates/afirma-dnie/tests/oracle.rs):
     * lee por la entrada estándar una APDU por línea en hexadecimal y escribe la respuesta de la tarjeta
     * simulada en hexadecimal. Uso: {@code serve <datos> [semilla] [transcripción]}.
     * Órdenes: {@code ATR} (pseudo-ATR de reset()), {@code #idesp X}, {@code #can X}, {@code #pin X},
     * {@code #retries n}, {@code #outer63 true|false}, {@code #log texto}, {@code #stats} (contexto,
     * intentos, APDU, fallos de GA4 y sesiones PACE con X empezando por 00),
     * {@code QUIT}. Cada orden recibe exactamente una línea de respuesta.
     */
    static void serve(final String[] args) throws Exception {
        final long seed = args.length > 2 ? Long.parseLong(args[2]) : 1L;
        if (args.length > 3) {
            Hex.openLog(args[3]);
            log("##### Modo servidor (host Rust), semilla " + seed);
        }
        else {
            Hex.quiet = true;
        }
        final SimCard sim = new SimCard(dataDir, seed);
        int kx00 = 0;
        final BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
        final PrintStream out = new PrintStream(System.out, true, "US-ASCII");
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            if ("QUIT".equals(line)) {
                break;
            }
            if ("ATR".equals(line)) {
                out.println(h(sim.resetBytes));
                continue;
            }
            if (line.startsWith("#")) {
                final String[] kv = line.substring(1).split(" ", 2);
                final String v = kv.length > 1 ? kv[1] : "";
                switch (kv[0]) {
                    case "idesp": sim.idesp = v; break;
                    case "can": sim.can = v; break;
                    case "pin": sim.pin = v; break;
                    case "retries": sim.retries = Integer.parseInt(v); break;
                    case "outer63": sim.cwaOuterSwEqualsInner = Boolean.parseBoolean(v); break;
                    case "log": log(v); break;
                    case "stats":
                        out.println("ctx=" + sim.ctxName() + " retries=" + sim.retries + " apdus=" + sim.apduCount
                            + " maxCmd=" + sim.maxCmd + " maxRsp=" + sim.maxRsp + " envelope=" + sim.envelopeUsed
                            + " ga4fail=" + sim.paceGa4Fail + " kx00=" + kx00);
                        continue;
                    default: out.println("ERROR orden desconocida " + kv[0]); continue;
                }
                out.println("OK");
                continue;
            }
            final byte[] apdu = Hex.b(line);
            final ResponseApdu r = sim.internalTransmit(apdu);
            // Sesiones PACE cuya X del secreto compartido empieza por 00 (GA3: 7C 43 83 41).
            if (apdu.length > 8 && apdu[1] == (byte) 0x86 && apdu[7] == (byte) 0x83 && sim.lastKxLeadingZero) {
                kx00++;
            }
            out.println(h(r.getBytes()));
        }
        Hex.closeLog();
    }

    static void flow(final String out) throws Exception {
        Hex.openLog(out);
        final SimCard sim = new SimCard(dataDir, 1L);
        log("##### Flujo completo: DnieFactory.getDnie(conn, null, BcCryptoHelper, handler, false), reset() = pseudo-ATR PC/SC");
        final Dnie card = DnieFactory.getDnie(sim, null, new BcCryptoHelper(), handler("123456", "1234abcd"), false);
        log("### Tarjeta creada: " + card.getClass().getName() + " / " + card.getCardName() + " / IDESP=" + card.getIdesp());
        for (final String a : card.getAliases()) {
            log("### alias: " + a + " -> " + card.getCertificate(a).getSubjectX500Principal() + " / clave: " + card.getPrivateKey(a));
        }
        log("### certificado sin clave (oculto en alias): CertCAIntermediaDGP -> " + (card.getCertificate("CertCAIntermediaDGP") != null ? card.getCertificate("CertCAIntermediaDGP").getSubjectX500Principal() : "null"));
        signAndVerify(card, "FIRMA 1", sim);
        signAndVerify(card, "FIRMA 2", sim);
        log("### APDUs totales: " + sim.apduCount + "; C-APDU maxima " + sim.maxCmd + " oct (" + sim.maxCmdHex + "...); R-APDU maxima " + sim.maxRsp + " oct (" + sim.maxRspHex + "...); ENVELOPE 90C2 usado: " + sim.envelopeUsed);
        Hex.closeLog();
        System.out.println("flow OK apdus=" + sim.apduCount + " maxCmd=" + sim.maxCmd + " maxRsp=" + sim.maxRsp + " envelope=" + sim.envelopeUsed);
    }

    static void r1(final String out) throws Exception {
        Hex.openLog(out);
        final SimCard sim = new SimCard(dataDir, 2L);
        sim.idesp = "AAA000001";
        log("##### IDESP=AAA000001 (constantes r1 esperadas), via DnieFactory.getDnieNfc");
        final Dnie card = DnieFactory.getDnieNfc(sim, new BcCryptoHelper(), handler("123456", "1234abcd"));
        log("### Tarjeta: " + card.getClass().getName() + " IDESP=" + card.getIdesp());
        signAndVerify(card, "FIRMA r1", sim);
        Hex.closeLog();
        System.out.println("r1 OK");
    }

    static void wrongPin(final String out) throws Exception {
        Hex.openLog(out);
        final SimCard sim = new SimCard(dataDir, 3L);
        log("##### PIN incorrecto");
        final Dnie card = DnieFactory.getDnie(sim, null, new BcCryptoHelper(), handler("123456", "0000wxyz"), false);
        try {
            signAndVerify(card, "FIRMA con PIN erroneo", sim);
        }
        catch (final Exception e) {
            log("### excepcion: " + chain(e));
            System.out.println("wrongpin: " + chain(e));
        }
        log("### contexto SM en tarjeta tras el error: " + sim.ctxName() + ", reintentos restantes en tarjeta: " + sim.retries);
        // Segundo intento con el mismo objeto
        try {
            signAndVerify(card, "SEGUNDO intento con PIN erroneo (mismo objeto Dnie)", sim);
        }
        catch (final Exception e) {
            log("### excepcion (2): " + chain(e));
            System.out.println("wrongpin(2): " + chain(e));
        }
        log("### contexto SM: " + sim.ctxName() + ", reintentos: " + sim.retries);
        Hex.closeLog();
    }

    static void outer63(final String out) throws Exception {
        Hex.openLog(out);
        final SimCard sim = new SimCard(dataDir, 4L);
        sim.cwaOuterSwEqualsInner = true;
        log("##### Respuestas CWA con SW exterior = SW interior (63C3 en la consulta de reintentos)");
        final Dnie card = DnieFactory.getDnie(sim, null, new BcCryptoHelper(), handler("123456", "1234abcd"), false);
        try {
            signAndVerify(card, "FIRMA (SW exterior = interior)", sim);
            System.out.println("outer63 OK");
        }
        catch (final Exception e) {
            log("### excepcion: " + chain(e));
            System.out.println("outer63: " + chain(e));
        }
        Hex.closeLog();
    }

    static void case1(final String out) throws Exception {
        Hex.openLog(out);
        final SimCard sim = new SimCard(dataDir, 5L);
        log("##### Comando caso 1 (sin datos ni Le) por PaceConnection");
        final BcCryptoHelper ch = new BcCryptoHelper();
        final BcPaceChannelHelper pch = new BcPaceChannelHelper(ch,
            new CardAccess(CardAccess.PaceAlgorithm.PACE_ECDH_GM_AES_CBC_CMAC_128, CardAccess.PaceAlgorithmParam.BRAINPOOL_256_R1, DigestAlgorithm.SHA1), null);
        final SecureMessaging sm = pch.openPaceChannel((byte) 0, new WirelessInitializerCan("123456"), sim);
        final PaceConnection pc = new PaceConnection(sim, ch, sm);
        // Caso 2 de control
        final ResponseApdu r0 = pc.transmit(new CommandApdu((byte) 0x90, (byte) 0xB8, (byte) 0, (byte) 0, null, Integer.valueOf(7)));
        log("### control caso 2 (GET CHIP INFO) -> " + h(r0.getBytes()));
        try {
            final ResponseApdu r = pc.transmit(new CommandApdu((byte) 0x00, (byte) 0x44, (byte) 0, (byte) 0, null, null));
            log("### caso 1 -> " + h(r.getBytes()));
            System.out.println("case1 respuesta " + h(r.getBytes()));
        }
        catch (final Exception e) {
            log("### caso 1 excepcion: " + chain(e));
            System.out.println("case1: " + chain(e));
        }
        Hex.closeLog();
    }

    static void stress(final int n) throws Exception {
        Hex.quiet = true;
        int fail = 0, zeroLead = 0, failZero = 0, other = 0;
        String failInfo = null;
        final BcCryptoHelper ch = new BcCryptoHelper();
        final CardAccess ca = new CardAccess(CardAccess.PaceAlgorithm.PACE_ECDH_GM_AES_CBC_CMAC_128, CardAccess.PaceAlgorithmParam.BRAINPOOL_256_R1, DigestAlgorithm.SHA1);
        for (int i = 0; i < n; i++) {
            final SimCard sim = new SimCard(dataDir, 1000L + i);
            try {
                new BcPaceChannelHelper(ch, ca, null).openPaceChannel((byte) 0, new WirelessInitializerCan("123456"), sim);
            }
            catch (final Exception e) {
                fail++;
                if (sim.lastKxLeadingZero) { failZero++; } else { other++; }
                if (failInfo == null) { failInfo = chain(e); }
            }
            if (sim.lastKxLeadingZero) { zeroLead++; }
        }
        System.out.println("stress n=" + n + " fallos=" + fail + " (con K.x empezando por 00: " + failZero + ", otros: " + other + "); sesiones con K.x empezando por 00: " + zeroLead);
        System.out.println("primer fallo: " + failInfo);
    }

    static void signStress(final int n) throws Exception {
        Hex.quiet = true;
        java.util.Map<String, Integer> cls = new java.util.TreeMap<>();
        int ok = 0, shortFail = 0, kxFail = 0, totalIntAuth = 0, nminus = 0, nminusShort = 0;
        SimCard sim = null; Dnie card = null; long seed = 50000;
        for (int i = 0; i < n; i++) {
            try {
                if (card == null) {
                    sim = new SimCard(dataDir, seed++);
                    card = DnieFactory.getDnie(sim, null, new BcCryptoHelper(), handler("123456", "1234abcd"), false);
                }
                card.sign(("x" + i).getBytes(), "SHA256withRSA", card.getPrivateKey("CertFirmaDigital"));
                ok++;
            }
            catch (final Throwable e) {
                Throwable r = e; while (r.getCause() != null) { r = r.getCause(); }
                final String k = e.getClass().getSimpleName() + " <- " + r.getClass().getSimpleName() + ": " + String.valueOf(r.getMessage()).split("\n")[0];
                cls.merge(k.length() > 160 ? k.substring(0, 160) : k, Integer.valueOf(1), Integer::sum);
                if (sim != null && sim.lastIntAuthShort) { shortFail++; }
                if (sim != null && sim.lastKxLeadingZero) { kxFail++; }
                if (sim != null) { totalIntAuth += sim.intAuthCount; nminus += sim.intAuthNminus; nminusShort += sim.intAuthNminusShortSig; }
                card = null;
                continue;
            }
        }
        if (sim != null) { totalIntAuth += sim.intAuthCount; nminus += sim.intAuthNminus; nminusShort += sim.intAuthNminusShortSig; }
        System.out.println("signstress n=" + n + " ok=" + ok + " fallos=" + (n - ok) + " (con INTERNAL AUTH SIGMIN=N-SIG y SIG<2^1016: " + shortFail + "; con K.x 00: " + kxFail + ")");
        System.out.println("  INTERNAL AUTH aprox: " + totalIntAuth + ", con SIGMIN=N-SIG: " + nminus + ", de ellos SIG corto: " + nminusShort);
        for (final java.util.Map.Entry<String, Integer> en : cls.entrySet()) { System.out.println("  " + en.getValue() + " x " + en.getKey()); }
    }

    static void rng() throws Exception {
        final BcCryptoHelper a = new BcCryptoHelper();
        System.out.println("rng A1 " + h(a.generateRandomBytes(8)) + " A2 " + h(a.generateRandomBytes(8)) + " B1(32) " + h(new BcCryptoHelper().generateRandomBytes(32)) + " C(74) " + h(new BcCryptoHelper().generateRandomBytes(74)));
    }

    static void detect(final String out) throws Exception {
        Hex.openLog(out);
        for (final String r : new String[] { "", "3B888001E1F35E117781A10003", "3B8C800150428E932AE1F35E1177818102", "E1F35E117781A100", "3B8C800150D71A03F3E1F35E117781A16A", "0102", "AABBCC", "3B8F8001804F0CA000000306030001000000006A", "3B8180018080" }) {
            final SimCard sim = new SimCard(dataDir, 6L);
            sim.resetBytes = Hex.b(r);
            Hex.quiet = true;
            String res;
            try {
                final Dnie d = DnieFactory.getDnie(sim, null, new BcCryptoHelper(), handler("123456", "1234abcd"), false);
                res = "detectado " + d.getClass().getSimpleName();
            }
            catch (final Exception e) {
                res = "NO: " + e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            Hex.quiet = false;
            log("reset()='" + r + "' -> " + res);
            System.out.println("detect '" + r + "' -> " + res);
        }
        Hex.closeLog();
    }
}
