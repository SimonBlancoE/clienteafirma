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

    /** Botón o gesto «Atrás» (la pila de pantallas está en Rust). */
    static native void onBackPressed();

    /**
     * Configuración del dispositivo: idioma ({@code Locale.toLanguageTag()}), tema oscuro,
     * escala del texto de accesibilidad y si hay NFC.
     */
    static native void onConfiguration(String locale, boolean night, float fontScale, boolean hasNfc);

    /**
     * Estado del editor del teclado en pantalla (GameTextInput): texto, selección y región de
     * composición, con índices de la String (UTF-16; -1 si no hay).
     */
    static native void onTextInput(String text, int selStart, int selEnd, int composingStart, int composingEnd);

    /** Tecla de acción del teclado ({@code EditorInfo.IME_ACTION_*}). */
    static native void onEditorAction(int action);

    /** El teclado en pantalla se ha mostrado u ocultado. */
    static native void onImeVisibility(boolean visible);
}
