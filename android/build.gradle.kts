plugins {
    id("com.android.application") version "9.4.1" apply false
}

// Salidas de Gradle fuera del árbol de fuentes si se pide (AUTOFIRMA_ANDROID_BUILD_DIR), para
// compilar en otro disco o desde un contenedor con el repositorio montado.
providers.environmentVariable("AUTOFIRMA_ANDROID_BUILD_DIR").orNull?.let { dir ->
    allprojects {
        layout.buildDirectory.set(file("$dir/gradle/${project.name}"))
    }
}
