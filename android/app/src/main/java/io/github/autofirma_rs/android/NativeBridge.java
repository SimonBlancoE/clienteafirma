package io.github.autofirma_rs.android;

/**
 * Llamadas de Java a la parte de Rust ({@code crates/autofirma-android/src/android/java.rs}).
 *
 * <p>Todas vuelven enseguida: copian los datos, los encolan para la interfaz y la despiertan.
 * Se pueden llamar desde cualquier hilo una vez cargada la biblioteca nativa (lo hace
 * {@code GameActivity.onCreate}).
 */
final class NativeBridge {

    private NativeBridge() {
    }

    /** Intent {@code VIEW} con una URL ({@code afirma://...}). */
    static native void onViewIntent(String uri);

    /**
     * Documento elegido con el selector del sistema. Se cede el descriptor de fichero (lo
     * cierra Rust).
     */
    static native void onDocumentOpened(long request, String uri, String name, int fd);

    /** Alias elegido en el selector de KeyChain ({@code null} si no se eligió ninguno). */
    static native void onCertificateChosen(long request, String alias);

    /**
     * Tarjeta ISO-DEP detectada y conectada por el lector NFC, con los datos que necesita la
     * identificación del DNIe (pueden ser nulos según la tecnología, NFC-A o NFC-B).
     */
    static native void onNfcTag(long request, byte[] tagId, byte[] historicalBytes,
            byte[] hiLayerResponse, byte[] nfcbApplicationData, byte[] nfcbProtocolInfo);

    /** La petición no terminó: cancelada por el usuario o con error. */
    static native void onRequestFailed(long request, boolean cancelled, String message);

    /** Zona segura (barras del sistema, recortes de pantalla y teclado) en píxeles. */
    static native void onInsets(int left, int top, int right, int bottom);
}
