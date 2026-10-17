package com.google.androidgamesdk;

/**
 * Acceso al {@code InputConnection} de GameTextInput, que GameActivity guarda en un campo de
 * paquete ({@code InputEnabledSurfaceView.mInputConnection}). Está en el paquete de
 * GameActivity para poder llegar a él sin reflexión; R8 conserva el paquete entero
 * ({@code proguard-rules.pro}).
 *
 * <p>Es lo que hace {@code GameActivity_showSoftInput} desde C, pero en el hilo principal y en
 * orden con el tipo de entrada y el texto del campo ({@code MainActivity.imeShow}).
 */
public final class GameTextInputAccess {

    private GameTextInputAccess() {
    }

    /** Activa (muestra el teclado y conecta el editor) o desactiva el teclado en pantalla. */
    public static void setSoftKeyboardActive(GameActivity activity, boolean active) {
        if (activity.mSurfaceView == null || activity.mSurfaceView.mInputConnection == null) {
            return;
        }
        activity.mSurfaceView.mInputConnection.setSoftKeyboardActive(active, 0);
    }
}
