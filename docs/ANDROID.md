# AutoFirma-rs para Android

Base técnica de la versión Android de AutoFirma-rs, el equivalente en Rust de la app oficial
«Cliente @firma móvil» (Autofirma App, `es.gob.afirma`). El comportamiento que hay que
reproducir está en [`spec/09-android.md`](spec/09-android.md) (la app) y
[`spec/10-dnie-nfc.md`](spec/10-dnie-nfc.md) (DNIe por NFC); este documento explica **cómo** está
construida la app: arquitectura, hilos, puente con Java, reutilización de los crates,
compilación reproducible y pruebas.

Estado: hay una pantalla real (nombre y versión, «Abrir documento», «Elegir certificado» y la
última petición `afirma://`) que prueba las llamadas en los dos sentidos entre Rust y Java, los
hilos de trabajo, la verificación TLS del sistema y que los crates de firma funcionan en Android.
Las pantallas de firma, el flujo web y el DNIe están por hacer (§8).

## 1. Decisiones

| Tema | Decisión | Motivo |
|---|---|---|
| Lenguaje de la app | Biblioteca nativa de Rust (`crates/autofirma-android`, `cdylib`) con la interfaz en egui/eframe 0.37 | La misma lógica de firma que el escritorio (`afirma-*`) sin JVM de por medio y la misma biblioteca de interfaz |
| Actividad | `GameActivity` (AndroidX `games-activity` 4.4.0) con `android-activity` 0.6.1 | Ver §1.1 |
| Dibujo | `glow` (OpenGL ES 2/3 por EGL) | Presente en todos los dispositivos con API 23 y en el emulador (SwiftShader); `wgpu` añade varios MB sin ventaja para una interfaz 2D |
| Capa Java | Java (sin Kotlin) en dos clases: `MainActivity` y `NativeBridge` | Solo lo que únicamente existe en el SDK: KeyChain, selector de documentos (SAF), intents, NFC y las inserciones de ventana |
| Puente | crate `jni` 0.22 (el mismo que usan winit y rustls-platform-verifier) | Sin versiones duplicadas |
| Identificador | `io.github.autofirma_rs.android` | El del escritorio (`io.github.autofirma-rs.AutoFirma`) no vale como paquete Java (guion); se sigue el de AppStream (`io.github.autofirma_rs`). Distinto del oficial `es.gob.afirma` para poder convivir con él |
| API mínima | `minSdk` 23 (Android 6.0), como la app oficial | Todo lo necesario existe en 23: `KeyChain.choosePrivateKeyAlias` con `Uri`, `ACTION_OPEN_DOCUMENT`, `NfcAdapter.enableReaderMode`; Rust, NDK r29, AndroidX y el componente de rustls admiten 23 |
| API objetivo | `targetSdk` 35, `compileSdk` 35 | Lo pedido. **Ojo:** Google Play pide cada agosto la API del año anterior; para publicar actualizaciones a partir del 31-8-2026 hará falta `targetSdk` 36 (comprobar la norma vigente al publicar) |
| Páginas de 16 KB | Bibliotecas alineadas a 16 KB, sin comprimir en el APK | Obligatorio en Google Play para Android 15+; `build.sh` lo comprueba (§5.3) |
| TLS | `rustls-platform-verifier` (el que ya usa `ureq` en afirma-core) con su componente Java | Usa el almacén de Android: CA del sistema y del usuario, `network_security_config`, revocación |

### 1.1 GameActivity frente a NativeActivity

eframe 0.37 admite las dos (`android-game-activity` y `android-native-activity`, que pasan a
winit 0.30.13 y android-activity 0.6.1):

| | `NativeActivity` | `GameActivity` (elegida) |
|---|---|---|
| Código Java propio | Opcional | Hace falta (subclase), cosa que necesitamos igualmente para KeyChain, SAF y NFC |
| Clase base | `android.app.Activity` | `AppCompatActivity`: `registerForActivityResult`, `OnBackPressedDispatcher`, `EdgeToEdge`, `WindowInsetsCompat` |
| Teclado en pantalla | Solo eventos de tecla (ASCII básico; sin tildes ni «ñ» con muchos teclados) | `GameTextInput` (IME completo; ver §8: winit 0.30 aún no lo reenvía) |
| Accesibilidad (`accesskit`) | eframe lo prohíbe (`compile_error!`) | Posible (`accesskit_android`) |
| Dependencias | Ninguna | `androidx.games:games-activity:4.4.0` (versión exacta del código C que incluye android-activity 0.6.1, `GAMEACTIVITY_*_VERSION` 4.4.0), `appcompat` y `core` |

Una app de firma necesita escribir PIN, CAN, contraseñas de PKCS#12 y textos con tildes (motivo
y lugar de la firma visible), y las administraciones están obligadas a la accesibilidad (RD
1112/2018): `GameActivity` es la única de las dos que deja hacerlo bien. No se compila la capa
C++ «prefab» de GameActivity (android-activity trae la suya).

## 2. Piezas

```
android/                                  Proyecto Gradle (AGP 9.4.1, Gradle 9.8.1, Kotlin DSL)
  app/build.gradle.kts                    versión desde Cargo.toml, firma, R8, tarea cargoNdk<Variante>
  app/src/main/AndroidManifest.xml        actividad única, singleTask, afirma://, NFC, INTERNET
  app/src/main/java/io/github/autofirma_rs/android/
    MainActivity.java                     GameActivity + métodos que llama Rust
    NativeBridge.java                     métodos nativos (Java → Rust)
crates/autofirma-android/                 libautofirma_android.so
  src/bridge.rs                           eventos, ids de petición, rasgo Platform, zona segura
  src/screen.rs                           pantalla (estado + egui), probada en el anfitrión
  src/document.rs                         análisis del documento con afirma-signers
  src/keychain.rs                         KeyChainKey: afirma_core::SigningKey sobre KeyChain
  src/android/{mod,java,logcat}.rs        solo Android: entradas, JNI, logcat
tools/android/Dockerfile                  imágenes de compilación y de emulador (versiones y SHA-256)
tools/android/build.sh                    APK de depuración y release
tools/android/emulator-test.sh            prueba de humo en el emulador (+ emulator-smoke.sh)
.github/workflows/android.yml             CI
```

`build.gradle.kts` lee la versión de `[workspace.package]` en `Cargo.toml` (`versionName`); el
`versionCode` es `AUTOFIRMA_BUILD_NUMBER` (número de ejecución en CI) o 1. La tarea
`cargoNdk<Variante>` ejecuta `cargo ndk --platform 23 -t <abi>… build -p autofirma-android
--locked [--release]` y deja las `.so` como fuente generada de `jniLibs` (API de variantes de
AGP), así que `./gradlew assembleDebug` compila todo, también desde Android Studio.

## 3. Rust y Java

### 3.1 Arranque

1. `GameActivity.onCreate` carga `libautofirma_android.so` (meta-dato `android.app.lib_name`).
2. `android_on_create` (hilo principal de Java, con `onCreate` en la pila, así que el cargador de
   clases de la app está disponible): registro en logcat, gancho de pánicos e inicio de
   `rustls_platform_verifier::android::init_with_env` con el contexto de la aplicación.
3. `android_main` (hilo nativo propio que crea android-activity): `eframe::run_native` con
   `NativeOptions::android_app` y el renderizador `glow`. La interfaz es `screen::MainScreen`.
4. Cuando la actividad se destruye, `run_native` vuelve y el proceso termina
   (`std::process::exit(0)`): winit no permite crear un segundo bucle de eventos en el mismo
   proceso, y si Android vuelve a crear la actividad lo hace en un proceso nuevo.

Para que la actividad casi nunca se destruya: `launchMode="singleTask"` (los `afirma://` llegan
por `onNewIntent` a la misma instancia), `configChanges` con todos los cambios de configuración
(girar, tamaño, idioma, tema; egui se adapta solo) y «Atrás» hace `moveTaskToBack(true)`. La
prueba del emulador comprueba que tras «Atrás» y volver a abrir sigue el mismo proceso y
`android_main` no se ejecuta dos veces.

### 3.2 Rust → Java

Métodos públicos de instancia de `MainActivity`, llamados sobre la referencia global de la
actividad que mantiene android-activity (`AndroidApp::activity_as_ptr`) con
`JavaVM::attach_current_thread` (el hilo se engancha una vez y se suelta solo al terminar). Se
llaman sobre el objeto, no con `FindClass`, porque `FindClass` desde un hilo nativo usa el
cargador del sistema y no encuentra las clases de la app.

| Rasgo `Platform` (Rust) | `MainActivity` (Java) | Bloquea | Respuesta |
|---|---|---|---|
| `open_document(id)` | `openDocument(long)` → `ACTION_OPEN_DOCUMENT` (`registerForActivityResult`) | No | `onDocumentOpened` / `onRequestFailed` |
| `choose_certificate(id)` | `chooseCertificate(long)` → `KeyChain.choosePrivateKeyAlias` (RSA y EC) | No | `onCertificateChosen` |
| `certificate_chain(alias)` | `byte[][] certificateChain(String)` → `KeyChain.getCertificateChain` | Sí | valor devuelto |
| `sign(alias, alg, datos)` | `byte[] sign(String, String, byte[])` → `KeyChain.getPrivateKey` + `Signature` (`SHA256withRSA`, `SHA256withECDSA`...) | Sí | valor devuelto |
| `start_nfc_reader(id)` | `startNfcReader(long)` → `enableReaderMode` (NFC-A/B, sin NDEF, sondeo 1000 ms) | No | `onNfcTag` / `onRequestFailed` |
| `nfc_transceive(apdu)` | `byte[] nfcTransceive(byte[])` → `IsoDep.transceive` (tiempo máximo 5000 ms) | Sí | valor devuelto |
| `stop_nfc_reader()` | `stopNfcReader()` | No | — |

Las excepciones de Java vuelven como `PlatformError("clase: mensaje")`. La clave privada no sale
nunca de Android (puede estar en el TEE o en StrongBox): `keychain::KeyChainKey` implementa
`afirma_core::SigningKey` llamando a `sign`, así que CAdES, XAdES y PAdES firman con KeyChain
igual que con PKCS#12 o PKCS#11 en el escritorio.

### 3.3 Java → Rust

Métodos `static native` de `NativeBridge`, exportados en Rust con `#[jni_mangle]` (el `_` de
`autofirma_rs` se codifica como `_1`). Todos vuelven enseguida: convierten los datos, encolan un
`PlatformEvent` en `Bridge::global()` y despiertan a egui con `Context::request_repaint`. Usan
`EnvUnowned::with_env` (sin pánicos a través de JNI) y la política `LogErrorAndDefault`.

| `NativeBridge` | Evento |
|---|---|
| `onViewIntent(String uri)` | `ViewIntent` (se reparte con `afirma_protocol::request::dispatch`) |
| `onDocumentOpened(long id, String uri, String nombre, int fd)` | `DocumentOpened`: Java cede el descriptor (`ParcelFileDescriptor.detachFd`) y Rust lo lee (máx. 256 MB) y lo cierra; nada de copias por el montón de Java |
| `onCertificateChosen(long id, String alias)` | `CertificateChosen` (`alias` nulo: no se eligió) |
| `onNfcTag(long id, byte[] tagId, byte[] históricos, byte[] hiLayer, byte[] datosNfcB, byte[] protocoloNfcB)` | `NfcTag` con `NfcTagInfo`: identificador, `getHistoricalBytes` (NFC-A), `getHiLayerResponse`, `NfcB.getApplicationData`/`getProtocolInfo` (NFC-B), lo que necesita la identificación del DNIe (`spec/10-dnie-nfc.md` §3) |
| `onRequestFailed(long id, boolean cancelada, String mensaje)` | `RequestFailed` |
| `onInsets(int izq, int arr, int der, int aba)` | zona segura (barras, recortes y teclado) |

### 3.4 Hilos

```
 hilo principal de Java                 hilo android_main (Rust)          hilos de trabajo (Rust)
 ───────────────────────                ────────────────────────          ───────────────────────
 onCreate, onNewIntent,      evento     bucle de winit + egui      spawn   leer y analizar documentos,
 resultados de SAF/KeyChain ─────────►  MainScreen::pump()       ───────►  firmar, cadena de KeyChain,
 onApplyWindowInsets         (cola +    MainScreen::ui()                   APDU por NFC (bloquean; JNI)
        ▲                    repaint)        │                                   │
        │ runOnUiThread                      │ open_document / choose_…          │ evento con el resultado
        └────────────────────────────────────┘ (no bloquean)                     └──► cola del puente
 ejecutor de E/S de Java: abre el documento y llama a onDocumentOpened (Rust lee el descriptor ahí)
 hilo del lector NFC (binder): conecta IsoDep y llama a onNfcTag
```

Reglas: el hilo de la interfaz nunca bloquea (las llamadas que abren actividades del sistema solo
encolan trabajo con `runOnUiThread`); el hilo principal de Java nunca ejecuta trabajo largo de
Rust; todo lo que bloquea (KeyChain no se puede usar en el hilo principal, `transceive`, firma,
red) va en hilos de trabajo, que publican su resultado en la cola. `MainScreen` lleva un mapa de
peticiones pendientes por `RequestId` y descarta respuestas inesperadas.

### 3.5 Ventana

La actividad es de borde a borde en todas las versiones (`EdgeToEdge.enable`; en Android 15 con
`targetSdk` 35 es obligatorio). `onApplyWindowInsets` envía a Rust las inserciones de
`systemBars | displayCutout | ime` en píxeles; `raw_input_hook` las pasa a puntos y las pone en
`RawInput::safe_area_insets`, y la pantalla dibuja dentro de `Context::content_rect()`. winit no
da a egui la zona segura en Android, por eso viene de Java.

### 3.6 Registro

`tracing` (y los `log` de winit, eframe y egui, por `tracing-log`) va a logcat con la etiqueta
`AutoFirma` por `__android_log_write`, con la prioridad del nivel; los mensajes largos se parten.
Los pánicos se registran con su traza. La salida estándar y de error las redirige
android-activity (etiqueta `RustStdoutStderr`). Las pruebas del emulador se basan en estas
líneas: «AutoFirma-rs … para Android iniciado», «Primer fotograma de la interfaz», «Botón
«Abrir documento» en x=… y=…» (en píxeles, para pulsarlo con `adb`), etc.

### 3.7 TLS

`ureq` (afirma-core, afirma-cms) verifica con `rustls-platform-verifier`, que en Android llama a
la JVM: hay que inicializarlo (§3.1) e incluir su componente Java, que se publica como repositorio
Maven en GitHub (`org.rustls:rustls-platform-verifier`, versión igual a la del crate
`rustls-platform-verifier-android` de `Cargo.lock`; la lee `build.gradle.kts`). Sin eso, la
primera conexión HTTPS hace que el proceso aborte. El componente está escrito en Kotlin y su POM
no declara `kotlin-stdlib`: llega por `androidx.core`. Su `network_security_config` (texto en
claro solo para descargar CRL de las CA) se fusiona en el manifiesto; si algún día hace falta
HTTP en claro para un servidor intermedio, habrá que escribir uno propio que lo incluya.

En compilaciones de depuración, `adb shell setprop debug.autofirma.tls_check https://…` hace que
la app descargue esa URL al arrancar con el cliente de afirma-core y registre el resultado (lo
usa la prueba del emulador).

## 4. Reutilización de los crates

Comprobado con `cargo ndk -t arm64-v8a -P 23 check -p <crate>` (NDK r29, Rust 1.98):

| Crate | ¿Compila para Android? | Uso en Android |
|---|---|---|
| `afirma-core` | Sí | Todo. Dos detalles: `http::proxy` detecta el proxy del sistema con variables de entorno y órdenes de escritorio (`scutil`, `gsettings`) que en Android no existen (el proxy habrá que pedirlo a Java, `ProxySelector`), y las rutas no pueden salir de `directories` (devuelve `None` sin `HOME`): hay que usar `AndroidApp::internal_data_path()` o `Context.getFilesDir()` |
| `afirma-cms`, `afirma-xml`, `afirma-pdf`, `afirma-signers` | Sí | Firma CAdES, XAdES, PAdES (con `hayro` para la vista previa), detección de formato. Ya enlazados en la app (análisis del documento) |
| `afirma-protocol` | Sí | Análisis de `afirma://`, servidor intermedio, cifrado, trifásica y lotes. En Android solo se usa el servidor intermedio (`spec/09-android.md` §5): ni WebSocket ni socket de servicio |
| `afirma-hash`, `afirma-certval` | Sí | Huellas y validación OCSP/CRL, si se ofrecen |
| `afirma-keystores` | Sí (PKCS#11 con los enlaces genéricos de `cryptoki-sys`) | Solo PKCS#12 y los filtros de certificados. Los almacenes de Android son KeyChain (`keychain::KeyChainKey`) y el DNIe por NFC |
| `afirma-system` | Sí, pero no tiene sentido | Instalación, CA local, almacenes de confianza y manejador de protocolo del escritorio. No se enlaza |
| `afirma-cli` | Sí | No se usa |
| `autofirma` (escritorio) | **No** | eframe sin rasgo `android-*` (android-activity: «Either "game-activity" or "native-activity" must be enabled»), además de `rfd` con portal XDG, `afirma-system`, X11/Wayland. Es la app de escritorio y no tiene que compilar para Android |

Propuestas de `cfg` para cuando se avance:

- **Interfaz compartida.** Sacar de `crates/autofirma` (binario) a una biblioteca `autofirma-ui`
  lo que no depende del escritorio (tema, componentes, textos, páginas de firma y verificación,
  vista previa de la firma visible), para usarla en las dos apps. Lo de escritorio (`rfd`,
  `afirma-system`, instancia única, actualizaciones) se queda en el binario.
- **`afirma-keystores`:** rasgos `pkcs11` y `nss` (o `cfg(not(target_os = "android"))`) para no
  enlazar `cryptoki` ni `libloading` en Android, donde no hay módulos PKCS#11 ni NSS.
- **`afirma-core`:** `cfg(target_os = "android")` en `http::proxy::system_proxy_for` (sin
  `std::process::Command`), y rutas inyectadas por la app.
- **`afirma-system`:** que no dependa de él nada que use Android (hoy solo `autofirma` y el rasgo
  opcional de `afirma-cli`).

### 4.1 El crate nuevo en el espacio de trabajo

`crates/autofirma-android` está en `members` (por `crates/*`) y compila en el anfitrión sin
NDK: las dependencias de Android (`eframe`, `android-activity`, `jni`,
`rustls-platform-verifier`, `android-properties`, `tracing-subscriber`) están en
`[target.'cfg(target_os = "android")'.dependencies]` y el módulo `android` lleva
`#[cfg(target_os = "android")]`. En Linux, Windows y macOS se compila (como `cdylib` + `rlib`)
y se prueba lo independiente de Android —puente, pantalla con egui (incluido pulsar el botón con
eventos simulados), análisis de documentos, `KeyChainKey`— con una `Platform` falsa. Así no hace
falta `default-members` ni excluirlo, y como las dependencias de Android son de destino, sus
rasgos no se mezclan con los de la app de escritorio (que activa X11 y Wayland en eframe).
Lo específico de Android lo comprueba `build.sh --clippy` (clippy con `-D warnings` para
`arm64-v8a`).

## 5. Compilación

### 5.1 Con Docker (reproducible)

```sh
tools/android/build.sh                       # depuración + release, arm64-v8a, armeabi-v7a, x86_64
tools/android/build.sh --debug --abis x86_64 # rápido, para el emulador
tools/android/build.sh --release --clippy    # lo que hace la CI
```

Salida: `$AUTOFIRMA_ANDROID_BUILD_DIR/dist/AutoFirma-<versión>-{debug,release}.apk`.
`AUTOFIRMA_ANDROID_BUILD_DIR` (por defecto `target/android`) guarda también las cachés de
Gradle y Cargo, el objetivo de Cargo y el `HOME` del contenedor (con el almacén de depuración
de AGP, que así es estable). En este equipo:
`AUTOFIRMA_ANDROID_BUILD_DIR=/mnt/datos/autofirma-build/android`. El contenedor se ejecuta con
el usuario del anfitrión y no escribe nada en el repositorio.

La release se firma con `AUTOFIRMA_ANDROID_KEYSTORE` (PKCS#12; por defecto
`~/.config/autofirma-rs/android/release-prueba.p12`, fuera del repositorio), contraseña
`AUTOFIRMA_ANDROID_KEYSTORE_PASSWORD` (por defecto `autofirma-prueba`) y alias
`AUTOFIRMA_ANDROID_KEY_ALIAS` (`autofirma`). Si el fichero no existe se genera uno **de
prueba** (RSA 3072, 10 000 días). La clave de publicación real queda pendiente (§8).

La release usa R8 (`proguard-rules.pro` conserva las clases de la app, los métodos nativos,
GameActivity y el componente de rustls) y reduce recursos; el perfil de Cargo es `release`
(LTO fino, símbolos quitados). La de depuración usa el perfil `dev` con
`CARGO_PROFILE_DEV_DEBUG=line-tables-only`; AGP quita los símbolos al empaquetar (las `.so`
completas quedan en `gradle/app/rustJniLibs/` para `ndk-stack`).

### 5.2 Sin Docker / Android Studio

Abrir `android/` en Android Studio. Hace falta: JDK 17+, SDK con plataforma 35 y build-tools
36.0.0, NDK 29.0.14206865, Rust con `aarch64-linux-android`, `armv7-linux-androideabi` y
`x86_64-linux-android`, y `cargo install --locked cargo-ndk@4.1.2`. `cargo` se busca en el
`PATH` (o `-Pautofirma.cargo=/ruta/a/cargo`); las ABI se eligen con `-Pautofirma.abis=x86_64`.
`tools/android/build.sh --no-docker` hace lo mismo con las herramientas del anfitrión
(`ANDROID_HOME`, `ANDROID_NDK_HOME`).

### 5.3 Versiones fijadas

| Pieza | Versión | Cómo se fija |
|---|---|---|
| Imagen base de compilación | `rust:1.98.0-bookworm` (Rust 1.98.0) | etiqueta |
| JDK | OpenJDK 17 de Debian 12 (`openjdk-17-jdk-headless`) | paquete de la distribución |
| cargo-ndk | 4.1.2 | `cargo install --locked` |
| Destinos de Rust | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | `rustup target add` |
| NDK | r29 (`29.0.14206865`) | ZIP + SHA-256 |
| cmdline-tools | 23.0 (`commandlinetools-linux-16111833`) | ZIP + SHA-256 |
| platform-tools | 37.0.1 | ZIP + SHA-256 |
| Plataforma | `android-35` revisión 2 | ZIP + SHA-256 |
| build-tools | 36.0.0 (mínima y por defecto de AGP 9.4) | ZIP + SHA-256 |
| Emulador | 37.2.12 (`emulator-linux_x64-16428233`, canal estable) | ZIP + SHA-256 |
| Imagen de sistema | `android-35;google_apis;x86_64` revisión 9 | ZIP + SHA-256 |
| Gradle | 9.8.1 | `distributionSha256Sum` en el envoltorio; `build.sh` comprueba el SHA-256 oficial de `gradle-wrapper.jar` |
| Android Gradle Plugin | 9.4.1 | `android/build.gradle.kts` |
| GameActivity | `androidx.games:games-activity:4.4.0` | igual que el código C de android-activity 0.6.1 |
| AndroidX | `appcompat` 1.7.1, `core` 1.13.1 | `app/build.gradle.kts` |
| Componente de rustls | `org.rustls:rustls-platform-verifier` 0.2.0 | desde `Cargo.lock` |
| Crates | `eframe`/`egui` 0.37.0, `winit` 0.30.13, `android-activity` 0.6.1, `jni` 0.22.4, `rustls-platform-verifier` 0.7.1 | `Cargo.lock` |

Los SHA-256 de las piezas del SDK se calcularon tras comprobar el SHA-1 que publica Google en
`repository2-3.xml` y `sys-img/google_apis/sys-img2-3.xml`; para actualizar una pieza basta con
cambiar el nombre del ZIP y su SHA-256 en los `ARG` del `Dockerfile`. Las descargas de Maven
(AGP, AndroidX) no tienen todavía verificación de dependencias de Gradle (§8).

Comprobaciones de `build.sh` sobre el resultado: `zipalign -c -P 16` (bibliotecas sin comprimir y
alineadas a 16 KB dentro del APK), `apksigner verify` de la release y `llvm-readelf -l` de las
`.so` de 64 bits (segmentos `LOAD` alineados a 0x4000; el NDK r29 ya enlaza así).

### 5.4 Tamaños

Con las tres ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`):

| APK | Tamaño | Bibliotecas nativas (sin comprimir) | Código Java |
|---|---|---|---|
| release | 55,8 MB (53,2 MiB) | `arm64-v8a` 18,9 MB, `armeabi-v7a` 14,8 MB, `x86_64` 21,4 MB | `classes.dex` 0,7 MB (R8) |
| depuración | 76,9 MB (73,3 MiB) | 24,7 MB, 19,3 MB y 29,5 MB (perfil `dev`, sin símbolos) | 7,1 MB (sin R8) |

Comprimida, la `.so` de `arm64-v8a` ocupa unos 9,2 MB: un APK o AAB por ABI se descargaría en
unos 10 MB. La biblioteca incluye egui, las fuentes por defecto, el rasterizador PDF (`hayro`),
tokio, rustls/ring y todos los firmadores; se podría reducir con `opt-level = "s"` y LTO completo
para Android.

Las `.so` van sin comprimir (se cargan directamente del APK), así que el APK pesa más que la
descarga desde Google Play, que comprime y además reparte por ABI si se publica como AAB.

## 6. Prueba en el emulador

```sh
tools/android/emulator-test.sh                                   # APK de depuración de build.sh
tools/android/emulator-test.sh --tls-check https://github.com/   # y verificación TLS
tools/android/emulator-test.sh --apk ruta/al/release.apk --out /tmp/emu
```

Arranca, dentro de la imagen `autofirma-android-emulator` y con `--device /dev/kvm`, un
dispositivo virtual x86_64 de 1080×2400 a 420 ppp con Android 15 (API 35, Google APIs), sin
ventana y con GPU por software (SwiftShader). Después:

1. instala y abre la app, y espera «… para Android iniciado» y «Primer fotograma de la
   interfaz»; guarda `captura.png`;
2. **Rust → Java**: pulsa «Abrir documento» en la posición que registra la app y espera a que el
   selector del sistema (DocumentsUI) tenga el foco (`selector.png`);
3. **Java → Rust**: pulsa Atrás y espera «Selector de documentos cancelado» de Rust;
4. **KeyChain**: pulsa «Elegir certificado», comprueba que se abre `KeyChainActivity` (sin
   certificados instalados responde «ninguno» al momento) y que Rust recibe el alias nulo;
5. lanza `afirma://sign?op=sign&id=prueba` con `am start` y espera a que Rust lo reparta
   (`intent.png`);
6. con `--tls-check`, espera «Comprobación TLS correcta»;
7. pulsa Atrás en la app, la vuelve a abrir y comprueba que es el mismo proceso y que
   `android_main` no se ha ejecutado dos veces;
8. detiene la app (`am force-stop`) y la arranca en frío con `afirma://selectcert?…`, como lo
   haría el navegador;
9. comprueba que no hay cierres (`logcat -b crash`), que el proceso sigue vivo y que no hay
   pánicos de Rust.

Deja en `--out` las capturas, `logcat.txt`, `logcat-crash.txt` y `emulator.log`. En este
equipo (20 núcleos, KVM) tarda alrededor de un minuto, arranque incluido.

### 6.1 CI

`.github/workflows/android.yml` (en `main`, en las PR que tocan `crates/`, `android/`,
`tools/android/`, `Cargo.*`… y a mano): activa KVM con una regla de udev (como
`reactivecircus/android-emulator-runner`), construye las dos imágenes, compila la release con
clippy para Android y las tres ABI (firmada con un almacén de prueba efímero) y la de depuración
para x86_64, sube los APK como artefacto (`autofirma-android-apk`) y pasa la prueba de humo a
los dos APK (la de depuración con `--tls-check`; la release comprueba que R8 no rompe JNI).
Las capturas y el logcat se suben siempre (`autofirma-android-emulador`). `ci.yml` pasa
`shellcheck` también a `tools/android/*.sh`.

## 7. Cómo se añade una función de plataforma

1. Método público en `MainActivity` (si abre algo del sistema: `runOnUiThread`, sin bloquear, y
   respuesta por `NativeBridge`; si bloquea: devolverlo directamente y documentarlo).
2. Método en el rasgo `Platform` (`bridge.rs`) y su implementación JNI en `android/java.rs`; si
   hay respuesta asíncrona, una variante de `PlatformEvent` y un `native` en `NativeBridge`.
3. Implementación en la `FakePlatform` de las pruebas (`keychain.rs`) y prueba en el anfitrión.
4. Si R8 pudiera quitar algo que solo se usa desde Rust, regla en `proguard-rules.pro` (el
   paquete de la app ya se conserva entero).

## 8. Problemas abiertos y siguientes pasos

- **Teclado en pantalla.** winit 0.30 no trata los eventos de texto de `GameTextInput`
  (`InputEvent::TextEvent`): `set_ime_allowed` muestra el teclado, pero lo escrito no llega a
  egui (salvo teclados que envían eventos de tecla). Opciones: leer
  `AndroidApp::text_input_state()` en `raw_input_hook` y despertar a egui desde un
  `GameActivity.stateChanged` sobrescrito, o pedir el PIN, el CAN y las contraseñas con diálogos
  nativos de Java (`inputType` de contraseña, sin sugerencias del teclado), que además es más
  seguro. Hay que decidirlo antes de las pantallas con texto.
- **Accesibilidad.** `accesskit` no está activado (eframe solo lo admite con GameActivity;
  `accesskit_android` trae su propio dex).
- **Funciones de plataforma pendientes:** guardar con SAF (`ACTION_CREATE_DOCUMENT`, con el
  descriptor en modo `wt`), compartir (`ACTION_SEND` con `FileProvider`), portapapeles, abrir
  enlaces, proxy del sistema, idioma del sistema, devolver el resultado al navegador.
- **Flujo web:** conectar `afirma_protocol::OperationHandler` con la interfaz; solo servidor
  intermedio y las operaciones de `spec/09-android.md` §5.3 (la pantalla actual marca
  `websocket` y `service` como no disponibles en Android).
- **DNIe por NFC:** el transporte (modo lector, `IsoDep`, `transceive`) está hecho en Java y Rust
  pero sin probar con hardware (el emulador no tiene NFC). Falta lo de
  `spec/10-dnie-nfc.md`: identificación, PACE con CAN, mensajería segura, canal CWA-14890, PIN
  y firma. Hay que comprobar en API 23–27 que las sondas de presencia del modo lector no cortan
  el canal (JMulticard usaba un *watchdog* por reflexión).
- **KeyChain en las pruebas:** el emulador no tiene certificados y instalar uno exige
  interacción (y bloqueo de pantalla); la prueba automática comprueba que se abre el selector y
  que vuelve la respuesta, pero no `certificateChain` ni `sign` con una clave real (sí con la
  `Platform` falsa en el anfitrión). Se puede probar a mano instalando un PKCS#12 de
  `testdata/pki` en Ajustes → Seguridad → Cifrado y credenciales.
- **Estado al morir el proceso:** no se guarda (`onSaveInstanceState` no se reenvía a Rust);
  las peticiones en curso se pierden si Android mata el proceso mientras está abierto el
  selector.
- **Publicación:** clave de firma real (o Play App Signing), esquema de `versionCode`, AAB por
  ABI, `targetSdk` 36 para Google Play, icono adaptativo, verificación de dependencias de
  Gradle (`verification-metadata.xml`) para que las descargas de Maven también tengan suma
  fijada.
- **Ruido conocido en la compilación:** «Exception while marshalling …/package.xml. Probably the
  SDK is read-only» (los paquetes del SDK se instalan desde los ZIP verificados, sin
  `package.xml`, y el SDK del contenedor es de solo lectura a propósito: AGP no puede descargar
  ni cambiar nada), «Unable to initialize metrics, ensure ?/.android is writable» (el usuario del
  anfitrión no existe en el contenedor) y el aviso de Gradle por `Configuration.setVisible`, que
  viene de AGP 9.4.1.
- **Tiempo de CI:** compilar las tres ABI en release desde cero tarda bastante en un runner de
  4 núcleos; se puede añadir caché del registro de Cargo, de Gradle y del objetivo de Cargo.
