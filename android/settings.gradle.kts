// Proyecto Gradle de AutoFirma-rs para Android (véase docs/ANDROID.md).
//
// La aplicación es una GameActivity (Java) que carga libautofirma_android.so, compilada con
// cargo-ndk desde crates/autofirma-android por la tarea cargoNdk<Variante> de app/.
// Compilación reproducible: tools/android/build.sh (imagen Docker con JDK, SDK, NDK y Rust).

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Componente Java de rustls-platform-verifier: repositorio Maven que el proyecto
        // publica en GitHub. La versión se toma de Cargo.lock (app/build.gradle.kts).
        maven {
            url = uri("https://github.com/rustls/rustls-platform-verifier/raw/maven-archive/android-release-support/maven/")
            content { includeGroup("org.rustls") }
        }
    }
}

rootProject.name = "AutoFirma"
include(":app")
