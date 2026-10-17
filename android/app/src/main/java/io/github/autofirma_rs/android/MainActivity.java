package io.github.autofirma_rs.android;

import android.content.ActivityNotFoundException;
import android.content.Intent;
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

import androidx.activity.EdgeToEdge;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.graphics.Insets;
import androidx.core.view.WindowInsetsCompat;

import com.google.androidgamesdk.GameActivity;

import java.io.Closeable;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
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
 *       (SAF), KeyChain (selector, cadena y firma) y lector NFC (IsoDep).</li>
 *   <li>Avisos a Rust por {@link NativeBridge}: intents {@code afirma://}, resultados de las
 *       actividades del sistema y la zona segura de la ventana.</li>
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

    /** Petición del selector de documentos en curso (0 si no hay). Solo en el hilo principal. */
    private long pendingOpenDocument;

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
        // Atrás deja la aplicación en segundo plano en lugar de destruir la actividad (winit no
        // puede crear un segundo bucle de eventos en el mismo proceso).
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                moveTaskToBack(true);
            }
        });
        if (savedInstanceState == null) {
            deliverViewIntent(getIntent());
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        deliverViewIntent(intent);
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
    // Selector de documentos (Storage Access Framework)

    /** Desde Rust: abre el selector de documentos del sistema. No bloquea. */
    public void openDocument(long request) {
        runOnUiThread(() -> {
            if (pendingOpenDocument != 0) {
                NativeBridge.onRequestFailed(request, false, "ya hay un selector de documentos abierto");
                return;
            }
            pendingOpenDocument = request;
            try {
                openDocumentLauncher.launch(new String[] {"*/*"});
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
