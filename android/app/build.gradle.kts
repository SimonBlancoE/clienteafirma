import javax.inject.Inject

plugins {
    id("com.android.application")
}

// API mínima: la misma que la app oficial «Cliente @firma móvil» (Android 6.0). KeyChain con
// Uri en choosePrivateKeyAlias, ACTION_OPEN_DOCUMENT y el modo lector NFC ya existen en 23.
val minSdkVersion = 23

// ABI que se compilan con cargo-ndk (gradle.properties o -Pautofirma.abis=x86_64).
val rustAbis: List<String> = providers.gradleProperty("autofirma.abis")
    .getOrElse("arm64-v8a,armeabi-v7a,x86_64")
    .split(',')
    .map { it.trim() }
    .filter { it.isNotEmpty() }

val workspaceDir = rootProject.layout.projectDirectory.dir("..")

// Versión del espacio de trabajo de Cargo ([workspace.package] version): única fuente.
val workspaceVersion: String = providers.fileContents(workspaceDir.file("Cargo.toml")).asText.map { toml ->
    Regex("""(?ms)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"""").find(toml)?.groupValues?.get(1)
        ?: throw GradleException("No se encontró [workspace.package] version en Cargo.toml")
}.get()

// versionCode: número de compilación (CI) o 1 en las compilaciones locales.
val buildNumber: Int = providers.gradleProperty("autofirma.versionCode")
    .orElse(providers.environmentVariable("AUTOFIRMA_BUILD_NUMBER"))
    .map { it.toInt() }
    .getOrElse(1)

// El componente Java de rustls-platform-verifier debe tener la misma versión que el crate
// rustls-platform-verifier-android de Cargo.lock.
val rustlsPlatformVerifierVersion: String = providers.fileContents(workspaceDir.file("Cargo.lock")).asText.map { lock ->
    Regex("""name = "rustls-platform-verifier-android"\s*\nversion = "([^"]+)"""").find(lock)?.groupValues?.get(1)
        ?: throw GradleException("rustls-platform-verifier-android no está en Cargo.lock")
}.get()

// Firma de la versión release: almacén de claves fuera del repositorio (tools/android/build.sh
// genera uno de prueba). Sin estas variables, el APK release sale sin firmar.
val releaseKeystore: String? = providers.environmentVariable("AUTOFIRMA_ANDROID_KEYSTORE").orNull

android {
    namespace = "io.github.autofirma_rs.android"
    compileSdk = 35
    buildToolsVersion = "36.0.0"
    // NDK con el que AGP quita los símbolos de las bibliotecas nativas (el mismo que usa
    // cargo-ndk en tools/android/Dockerfile).
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "io.github.autofirma_rs.android"
        minSdk = minSdkVersion
        targetSdk = 35
        versionCode = buildNumber
        versionName = workspaceVersion
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = providers.environmentVariable("AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("AUTOFIRMA_ANDROID_KEY_ALIAS").getOrElse("autofirma")
                keyPassword = providers.environmentVariable("AUTOFIRMA_ANDROID_KEY_PASSWORD")
                    .orElse(providers.environmentVariable("AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD"))
                    .get()
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (releaseKeystore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        // Bibliotecas nativas sin comprimir y alineadas a 16 KB dentro del APK (se cargan
        // directamente del APK; obligatorio para dispositivos con páginas de 16 KB).
        jniLibs.useLegacyPackaging = false
    }

    lint {
        // lint descarga sus propias dependencias; se ejecuta aparte (./gradlew lint).
        checkReleaseBuilds = false
    }
}

dependencies {
    // Debe ser la versión cuyo código C incluye android-activity 0.6 (GameActivity 4.4.0).
    implementation("androidx.games:games-activity:4.4.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.core:core:1.13.1")
    implementation("org.rustls:rustls-platform-verifier:$rustlsPlatformVerifierVersion")
}

/**
 * Compila libautofirma_android.so para cada ABI con cargo-ndk y la deja en la estructura de
 * jniLibs (`<abi>/libautofirma_android.so`). Se ejecuta siempre: Cargo decide qué recompilar.
 */
abstract class CargoNdkTask @Inject constructor(private val exec: ExecOperations) : DefaultTask() {
    @get:Input abstract val abis: ListProperty<String>
    @get:Input abstract val release: Property<Boolean>
    @get:Input abstract val platform: Property<Int>
    @get:Input abstract val cargo: Property<String>
    @get:Internal abstract val workspace: DirectoryProperty
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        val args = mutableListOf("ndk", "--platform", platform.get().toString(), "--output-dir", out.absolutePath)
        abis.get().forEach { args += listOf("--target", it) }
        args += listOf("build", "--package", "autofirma-android", "--locked")
        if (release.get()) {
            args += "--release"
        }
        exec.exec {
            workingDir = workspace.get().asFile
            commandLine(listOf(cargo.get()) + args)
        }
    }
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar { it.uppercase() }
        val cargoTask = tasks.register<CargoNdkTask>("cargoNdk$name") {
            group = "build"
            description = "Compila la biblioteca nativa de Rust (${variant.name}) con cargo-ndk"
            abis.set(rustAbis)
            release.set(variant.buildType == "release")
            platform.set(minSdkVersion)
            cargo.set(providers.gradleProperty("autofirma.cargo").getOrElse("cargo"))
            workspace.set(workspaceDir)
            outputDir.set(layout.buildDirectory.dir("rustJniLibs/${variant.name}"))
            outputs.upToDateWhen { false }
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoTask, CargoNdkTask::outputDir)
    }
}
