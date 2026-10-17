package io.github.autofirma_rs.android;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.database.Cursor;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcB;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.security.KeyChain;
import android.util.Log;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.view.inputmethod.EditorInfo;
import android.widget.FrameLayout;

import androidx.activity.EdgeToEdge;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.graphics.Insets;
import androidx.core.os.ConfigurationCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.androidgamesdk.GameActivity;
import com.google.androidgamesdk.GameTextInputAccess;
import com.google.androidgamesdk.gametextinput.State;

import java.io.Closeable;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Actividad única de AutoFirma-rs para Android.
 *
 * <p>La interfaz es nativa: {@link GameActivity} carga {@code libautofirma_android.so}
 * (meta-dato {@code android.app.lib_name}) y {@code android-activity} ejecuta
 * {@code android_main} en un hilo propio con egui. Esta clase solo aporta lo que únicamente
 * existe en el SDK de Android:
 *
 * <ul>
 *   <li>Métodos públicos que llama Rust por JNI (desde cualquier hilo): selector de documentos
 *       y diálogo de guardado (SAF), KeyChain (selector, cadena, firma e instalador de
 *       certificados), lector NFC (IsoDep), teclado en pantalla, enlaces y dejar la aplicación
 *       en segundo plano.</li>
 *   <li>Avisos a Rust por {@link NativeBridge}: intents {@code afirma://}, resultados de las
 *       actividades del sistema, la zona segura de la ventana, la configuración (idioma, tema,
 *       escala del texto), el botón «Atrás» y el estado del editor del teclado.</li>
 * </ul>
 *
 * <p>Los métodos que bloquean ({@link #certificateChain}, {@link #sign}, {@link #nfcTransceive})
 * se llaman desde hilos de trabajo de Rust, nunca desde el hilo principal.
 */
public final class MainActivity extends GameActivity {

    private static final String TAG = "AutoFirma";

    /** Tiempo máximo de una APDU por NFC (las firmas del DNIe tardan más de un segundo). */
    private static final int NFC_TIMEOUT_MS = 5000;

    /** E/S de la capa Java (abrir documentos): fuera del hilo principal. */
    private final ExecutorService io = Executors.newSingleThreadExecutor();

    private final ActivityResultLauncher<String[]> openDocumentLauncher =
            registerForActivityResult(new ActivityResultContracts.OpenDocument(), this::onDocumentChosen);

    private final ActivityResultLauncher<Intent> createDocumentLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), this::onDocumentCreated);

    private final ActivityResultLauncher<Intent> installCertificateLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
                    this::onCertificateInstallResult);

    /** Pantalla raíz sin diálogo en Rust: «Atrás» deja la aplicación en segundo plano. */
    private volatile boolean backAtRoot;

    /** Petición del selector de documentos en curso (0 si no hay). Solo en el hilo principal. */
    private long pendingOpenDocument;

    /** Petición del diálogo de guardado en curso (0 si no hay). Solo en el hilo principal. */
    private long pendingCreateDocument;

    /** Petición del instalador de certificados en curso (0 si no hay). Solo en el hilo principal. */
    private long pendingInstallCertificate;

    private final Object nfcLock = new Object();
    /** Tarjeta conectada por el lector NFC (protegida por {@link #nfcLock}). */
    private IsoDep isoDep;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // De borde a borde en todas las versiones (en Android 15 es obligatorio): la superficie
        // ocupa toda la ventana y la zona segura llega a Rust con onApplyWindowInsets.
        EdgeToEdge.enable(this);
        // Carga la biblioteca nativa y arranca android_main.
        super.onCreate(savedInstanceState);
        // «Atrás» lo decide Rust (pila de pantallas). En una pantalla raíz sin diálogo (Rust lo
        // avisa con setBackAtRoot) la aplicación pasa a segundo plano aquí mismo, en lugar de
        // destruir la actividad (winit no puede crear un segundo bucle de eventos en el mismo
        // proceso): hecho más tarde desde Rust, el sistema a veces no movía la tarea.
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (backAtRoot) {
                    Log.i(TAG, "Atrás en una pantalla raíz: la aplicación pasa a segundo plano");
                    moveTaskToBack(true);
                } else {
                    NativeBridge.onBackPressed();
                }
            }
        });
        sendConfiguration(getResources().getConfiguration());
        if (savedInstanceState == null) {
            deliverViewIntent(getIntent());
        }
    }

    /**
     * Igual que el de GameActivity, pero con un contenedor que no pasa eventos de accesibilidad
     * cuando la accesibilidad está desactivada. accesskit_android (0.8) sigue enviándolos
     * cuando se desconecta un servicio (TalkBack apagado, uiautomator) y
     * {@code AccessibilityManager.sendAccessibilityEvent} lanza «Accessibility off» en el hilo
     * principal: el {@code unwrap} de Rust haría abortar el proceso.
     */
    @Override
    protected void onCreateSurfaceView() {
        mSurfaceView = createSurfaceView();
        if (mSurfaceView == null) {
            return;
        }
        FrameLayout frame = new AccessibilityGuardLayout(this);
        contentViewId = ViewCompat.generateViewId();
        frame.setId(contentViewId);
        frame.addView(mSurfaceView);
        setContentView(frame);
        mSurfaceView.getHolder().addCallback(this);
        ViewCompat.setOnApplyWindowInsetsListener(mSurfaceView, this);
    }

    /** Contenedor de la superficie que descarta los eventos de accesibilidad sin servicios activos. */
    private static final class AccessibilityGuardLayout extends FrameLayout {
        private final AccessibilityManager accessibility;

        AccessibilityGuardLayout(Context context) {
            super(context);
            accessibility = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
        }

        @Override
        public boolean requestSendAccessibilityEvent(View child, AccessibilityEvent event) {
            if (accessibility == null || !accessibility.isEnabled()) {
                return false;
            }
            try {
                return super.requestSendAccessibilityEvent(child, event);
            } catch (IllegalStateException e) {
                // Se ha desactivado entre la comprobación y el envío.
                return false;
            }
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        deliverViewIntent(intent);
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        // Colores de los iconos de las barras del sistema según el tema (claro u oscuro).
        EdgeToEdge.enable(this);
        sendConfiguration(newConfig);
    }

    /** Idioma, tema, escala del texto y NFC para la interfaz de Rust. */
    private void sendConfiguration(Configuration configuration) {
        Locale locale = ConfigurationCompat.getLocales(configuration).get(0);
        boolean night = (configuration.uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        boolean hasNfc = NfcAdapter.getDefaultAdapter(this) != null;
        NativeBridge.onConfiguration(
                locale != null ? locale.toLanguageTag() : "", night, configuration.fontScale, hasNfc);
    }

    @Override
    protected void onDestroy() {
        stopNfcReader();
        io.shutdownNow();
        super.onDestroy();
    }

    private static void deliverViewIntent(Intent intent) {
        if (intent == null || !Intent.ACTION_VIEW.equals(intent.getAction()) || intent.getData() == null) {
            return;
        }
        if ((intent.getFlags() & Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0) {
            return; // Intent antiguo, reabierto desde «Recientes»: ya se atendió.
        }
        NativeBridge.onViewIntent(intent.getDataString());
    }

    @Override
    public WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat insets) {
        WindowInsetsCompat result = super.onApplyWindowInsets(view, insets);
        Insets safe = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                | WindowInsetsCompat.Type.displayCutout()
                | WindowInsetsCompat.Type.ime());
        NativeBridge.onInsets(safe.left, safe.top, safe.right, safe.bottom);
        return result;
    }

    // -------------------------------------------------------------------------------------
    // Navegación y enlaces

    /** Desde Rust: «Atrás» dejaría la aplicación en segundo plano (pantalla raíz sin diálogo). */
    public void setBackAtRoot(boolean atRoot) {
        backAtRoot = atRoot;
    }

    /** Desde Rust: «Atrás» en la pantalla principal; la actividad sigue viva. */
    public void leaveApp() {
        runOnUiThread(() -> moveTaskToBack(true));
    }

    /** Desde Rust: abre una URL en el navegador. No bloquea. */
    public void openUrl(long request, String url) {
        runOnUiThread(() -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))
                        .addCategory(Intent.CATEGORY_BROWSABLE));
            } catch (ActivityNotFoundException e) {
                NativeBridge.onRequestFailed(request, false, "no hay ninguna aplicación para abrir el enlace");
            }
        });
    }

    // -------------------------------------------------------------------------------------
    // Teclado en pantalla (GameTextInput)
    //
    // Mientras el teclado está activo, GameTextInput se queda con las pulsaciones y con lo que
    // escribe el teclado y avisa del estado completo del editor (stateChanged), que winit
    // descarta. Aquí se pasa ese estado a Rust y Rust abre, actualiza y cierra el teclado
    // (src/ime.rs). Todo en el hilo principal. Los índices son de la String de Java (UTF-16).

    /** Desde Rust: abre el teclado para un campo (tipo de entrada, acción y opciones de EditorInfo). */
    public void imeShow(int inputType, int actionId, int imeOptions, String text, int selStart, int selEnd) {
        runOnUiThread(() -> {
            setImeEditorInfoFields(inputType, actionId, imeOptions);
            setEditorState(text, selStart, selEnd);
            GameTextInputAccess.setSoftKeyboardActive(this, true);
        });
    }

    /** Desde Rust: el campo ha cambiado el texto o la selección. */
    public void imeUpdate(String text, int selStart, int selEnd) {
        runOnUiThread(() -> setEditorState(text, selStart, selEnd));
    }

    /** Desde Rust: ningún campo tiene el foco. */
    public void imeHide() {
        runOnUiThread(() -> GameTextInputAccess.setSoftKeyboardActive(this, false));
    }

    private void setEditorState(String text, int selStart, int selEnd) {
        // El teclado lee la selección inicial de EditorInfo al volver a conectarse.
        EditorInfo info = getImeEditorInfo();
        info.initialSelStart = selStart;
        info.initialSelEnd = selEnd;
        setTextInputState(new State(text, selStart, selEnd, -1, -1));
    }

    // No se llama a super en estos tres: android-activity los encolaría para winit, que los
    // descarta registrando el evento (con el texto, que puede ser una contraseña o un PIN).

    @Override
    public void stateChanged(State newState, boolean dismissed) {
        NativeBridge.onTextInput(newState.text, newState.selectionStart, newState.selectionEnd,
                newState.composingRegionStart, newState.composingRegionEnd);
    }

    @Override
    public void onEditorAction(int action) {
        NativeBridge.onEditorAction(action);
    }

    @Override
    public void onSoftwareKeyboardVisibilityChanged(boolean visible) {
        NativeBridge.onImeVisibility(visible);
    }

    // -------------------------------------------------------------------------------------
    // Selector de documentos (Storage Access Framework)

    /**
     * Desde Rust: abre el selector de documentos del sistema con los tipos MIME que se pueden
     * elegir, separados por comas (todos, o {@code application/x-pkcs12} para importar
     * certificados). No bloquea.
     */
    public void openDocument(long request, String mimeTypes) {
        runOnUiThread(() -> {
            if (pendingOpenDocument != 0) {
                NativeBridge.onRequestFailed(request, false, "ya hay un selector de documentos abierto");
                return;
            }
            pendingOpenDocument = request;
            try {
                openDocumentLauncher.launch(mimeTypes.split(","));
            } catch (ActivityNotFoundException e) {
                pendingOpenDocument = 0;
                NativeBridge.onRequestFailed(request, false, "no hay ninguna aplicación para elegir documentos");
            }
        });
    }

    private void onDocumentChosen(Uri uri) {
        long request = pendingOpenDocument;
        pendingOpenDocument = 0;
        if (request == 0) {
            Log.w(TAG, "Documento elegido sin petición pendiente (¿proceso reiniciado?)");
            return;
        }
        if (uri == null) {
            NativeBridge.onRequestFailed(request, true, null);
            return;
        }
        io.execute(() -> {
            try {
                String name = displayName(uri);
                ParcelFileDescriptor document = getContentResolver().openFileDescriptor(uri, "r");
                if (document == null) {
                    throw new IOException("el proveedor no ha devuelto el documento");
                }
                // Rust lee y cierra el descriptor.
                NativeBridge.onDocumentOpened(request, uri.toString(), name, document.detachFd());
            } catch (IOException | RuntimeException e) {
                NativeBridge.onRequestFailed(request, false, e.toString());
            }
        });
    }

    /**
     * Desde Rust: abre el diálogo del sistema para guardar un documento nuevo
     * ({@code ACTION_CREATE_DOCUMENT}) con el tipo MIME y el nombre propuesto. No bloquea. Rust
     * escribe los datos en el descriptor que se le pasa con {@code onDocumentCreated}.
     */
    public void createDocument(long request, String mimeType, String name) {
        runOnUiThread(() -> {
            if (pendingCreateDocument != 0) {
                NativeBridge.onRequestFailed(request, false, "ya hay un diálogo de guardado abierto");
                return;
            }
            pendingCreateDocument = request;
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .setType(mimeType)
                    .putExtra(Intent.EXTRA_TITLE, name);
            try {
                createDocumentLauncher.launch(intent);
            } catch (ActivityNotFoundException e) {
                pendingCreateDocument = 0;
                NativeBridge.onRequestFailed(request, false, "no hay ninguna aplicación para guardar documentos");
            }
        });
    }

    private void onDocumentCreated(ActivityResult result) {
        long request = pendingCreateDocument;
        pendingCreateDocument = 0;
        if (request == 0) {
            Log.w(TAG, "Documento creado sin petición pendiente (¿proceso reiniciado?)");
            return;
        }
        Uri uri = result.getResultCode() == RESULT_OK && result.getData() != null
                ? result.getData().getData() : null;
        if (uri == null) {
            NativeBridge.onRequestFailed(request, true, null);
            return;
        }
        io.execute(() -> {
            try {
                ParcelFileDescriptor document;
                try {
                    // «wt»: si el proveedor reutiliza un documento, se trunca.
                    document = getContentResolver().openFileDescriptor(uri, "wt");
                } catch (IllegalArgumentException | UnsupportedOperationException e) {
                    document = getContentResolver().openFileDescriptor(uri, "w");
                }
                if (document == null) {
                    throw new IOException("el proveedor no ha devuelto el documento");
                }
                // Rust escribe los datos y cierra el descriptor.
                NativeBridge.onDocumentCreated(request, uri.toString(), displayName(uri), document.detachFd());
            } catch (IOException | RuntimeException e) {
                NativeBridge.onRequestFailed(request, false, e.toString());
            }
        });
    }

    private String displayName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(
                uri, new String[] {OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst() && !cursor.isNull(0)) {
                return cursor.getString(0);
            }
        } catch (RuntimeException e) {
            Log.w(TAG, "No se pudo leer el nombre del documento", e);
        }
        return uri.getLastPathSegment();
    }

    // -------------------------------------------------------------------------------------
    // KeyChain

    /** Desde Rust: abre el selector de certificados del sistema. No bloquea. */
    public void chooseCertificate(long request) {
        runOnUiThread(() -> KeyChain.choosePrivateKeyAlias(
                this,
                alias -> NativeBridge.onCertificateChosen(request, alias),
                new String[] {"RSA", "EC"},
                null,
                null,
                null));
    }

    /**
     * Desde Rust: abre el instalador de certificados del sistema con un PKCS#12 (el sistema pide
     * la contraseña y el nombre). No bloquea; responde {@code onCertificateInstalled} o
     * {@code onRequestFailed} (cancelado).
     */
    public void installCertificate(long request, byte[] pkcs12) {
        runOnUiThread(() -> {
            if (pendingInstallCertificate != 0) {
                NativeBridge.onRequestFailed(request, false, "ya hay una instalación de certificado en curso");
                return;
            }
            pendingInstallCertificate = request;
            Intent intent = KeyChain.createInstallIntent();
            intent.putExtra(KeyChain.EXTRA_PKCS12, pkcs12);
            try {
                installCertificateLauncher.launch(intent);
            } catch (ActivityNotFoundException e) {
                pendingInstallCertificate = 0;
                NativeBridge.onRequestFailed(request, false, "no hay instalador de certificados");
            }
        });
    }

    private void onCertificateInstallResult(ActivityResult result) {
        long request = pendingInstallCertificate;
        pendingInstallCertificate = 0;
        if (request == 0) {
            Log.w(TAG, "Resultado del instalador sin petición pendiente (¿proceso reiniciado?)");
            return;
        }
        if (result.getResultCode() == RESULT_OK) {
            NativeBridge.onCertificateInstalled(request);
        } else {
            NativeBridge.onRequestFailed(request, true, null);
        }
    }

    /** Desde Rust (hilo de trabajo, bloquea): cadena de certificados DER del alias. */
    public byte[][] certificateChain(String alias) throws Exception {
        X509Certificate[] chain = KeyChain.getCertificateChain(this, alias);
        if (chain == null || chain.length == 0) {
            throw new KeyStoreException("el certificado " + alias + " no está disponible");
        }
        byte[][] encoded = new byte[chain.length][];
        for (int i = 0; i < chain.length; i++) {
            encoded[i] = chain[i].getEncoded();
        }
        return encoded;
    }

    /**
     * Desde Rust (hilo de trabajo, bloquea): firma {@code data} con la clave privada del alias.
     * {@code algorithm} es el nombre Java ({@code SHA256withRSA}, {@code SHA256withECDSA}...).
     * La clave puede estar en el TEE o en StrongBox y no sale de ahí: {@code Signature} elige el
     * proveedor que la admite (AndroidKeyStore) al iniciarse con ella. Errores: alias sin clave
     * o sin permiso ({@code KeyChainException}, {@code KeyStoreException}), algoritmo que la
     * clave no admite ({@code InvalidKeyException}).
     */
    public byte[] sign(String alias, String algorithm, byte[] data) throws Exception {
        PrivateKey key = KeyChain.getPrivateKey(this, alias);
        if (key == null) {
            throw new KeyStoreException("la clave de " + alias + " no está disponible");
        }
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }

    // -------------------------------------------------------------------------------------
    // Lector NFC (DNIe)

    /** Desde Rust: activa el modo lector para tarjetas ISO 14443-4 (ISO-DEP). No bloquea. */
    public void startNfcReader(long request) {
        runOnUiThread(() -> {
            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
            if (adapter == null) {
                NativeBridge.onRequestFailed(request, false, "este dispositivo no tiene NFC");
                return;
            }
            if (!adapter.isEnabled()) {
                NativeBridge.onRequestFailed(request, false, "el NFC está desactivado");
                return;
            }
            Bundle options = new Bundle();
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000);
            adapter.enableReaderMode(
                    this,
                    tag -> onNfcTag(request, tag),
                    NfcAdapter.FLAG_READER_NFC_A
                            | NfcAdapter.FLAG_READER_NFC_B
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
                            | NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        });
    }

    /** Hilo del lector NFC: conecta con la tarjeta y avisa a Rust. */
    private void onNfcTag(long request, Tag tag) {
        IsoDep tagIsoDep = IsoDep.get(tag);
        if (tagIsoDep == null) {
            Log.i(TAG, "Etiqueta NFC sin ISO-DEP: se ignora");
            return;
        }
        try {
            tagIsoDep.connect();
            tagIsoDep.setTimeout(NFC_TIMEOUT_MS);
        } catch (IOException e) {
            NativeBridge.onRequestFailed(request, false, e.toString());
            return;
        }
        synchronized (nfcLock) {
            closeQuietly(isoDep);
            isoDep = tagIsoDep;
        }
        NfcB nfcB = NfcB.get(tag);
        NativeBridge.onNfcTag(
                request,
                tag.getId(),
                tagIsoDep.getHistoricalBytes(),
                tagIsoDep.getHiLayerResponse(),
                nfcB != null ? nfcB.getApplicationData() : null,
                nfcB != null ? nfcB.getProtocolInfo() : null);
    }

    /** Desde Rust (hilo de trabajo, bloquea): envía una APDU y devuelve la respuesta. */
    public byte[] nfcTransceive(byte[] apdu) throws IOException {
        IsoDep tagIsoDep;
        synchronized (nfcLock) {
            tagIsoDep = isoDep;
        }
        if (tagIsoDep == null) {
            throw new IOException("no hay ninguna tarjeta conectada");
        }
        return tagIsoDep.transceive(apdu);
    }

    /** Desde Rust (o al destruir la actividad): desactiva el lector y cierra la conexión. */
    public void stopNfcReader() {
        runOnUiThread(() -> {
            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
            if (adapter != null) {
                try {
                    adapter.disableReaderMode(this);
                } catch (IllegalStateException e) {
                    Log.w(TAG, "No se pudo desactivar el lector NFC", e);
                }
            }
        });
        synchronized (nfcLock) {
            closeQuietly(isoDep);
            isoDep = null;
        }
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (IOException e) {
            Log.w(TAG, "No se pudo cerrar la conexión NFC", e);
        }
    }
}
