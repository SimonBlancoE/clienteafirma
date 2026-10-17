# Reglas de R8 para la versión release.

# La biblioteca nativa llama a los métodos públicos de MainActivity por su nombre (JNI) y
# NativeBridge declara los métodos nativos: no se pueden renombrar ni eliminar.
-keep class io.github.autofirma_rs.android.** { *; }
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# rustls-platform-verifier: su parte de Rust busca estas clases por nombre.
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }

# GameActivity: android-activity llama a sus métodos y campos desde C.
-keep class com.google.androidgamesdk.** { *; }

# Sin registros de depuración en la release: GameTextInput registra con Log.d el texto del
# editor en cada pulsación (contraseñas, PIN, CAN).
-assumenosideeffects class android.util.Log {
    public static int d(...);
    public static int v(...);
}
