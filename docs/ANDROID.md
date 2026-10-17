# AutoFirma-rs para Android

Base técnica de la versión Android de AutoFirma-rs, el equivalente en Rust de la app oficial
«Cliente @firma móvil» (Autofirma App, `es.gob.afirma`). El comportamiento que hay que
reproducir está en [`spec/09-android.md`](spec/09-android.md) (la app) y
[`spec/10-dnie-nfc.md`](spec/10-dnie-nfc.md) (DNIe por NFC); este documento explica **cómo** está
construida la app: arquitectura, hilos, puente con Java, reutilización de los crates,
compilación reproducible y pruebas.

Estado: está hecha la «carcasa» de la app (§9): arranque, bienvenida, condiciones, Inicio,
Ajustes con todas sus pantallas (idioma, configuración de firma, dominios de confianza,
histórico, preguntas frecuentes, ayudas, aviso legal, privacidad, accesibilidad y versión), los
diálogos, la navegación con «Atrás», los seis idiomas del original, las preferencias, el
teclado en pantalla y la accesibilidad (TalkBack). También la **firma local** completa (§9.8):
selector de documentos, PAdES con firma visible (vista previa de las páginas y área elegida con
el dedo), CAdES y XAdES, contraseña de los PDF protegidos, certificados de KeyChain con sus
avisos, guardado con el diálogo del sistema, histórico y mensajes de resultado y de error con
los códigos `AA` del original; y la **importación de certificados** `.p12`/`.pfx` en KeyChain.
Quedan la interfaz de la firma web (el protocolo ya está en `afirma_protocol::android`, §10) y
el DNIe por NFC (§8).

## 1. Decisiones

| Tema | Decisión | Motivo |
|---|---|---|
| Lenguaje de la app | Biblioteca nativa de Rust (`crates/autofirma-android`, `cdylib`) con la interfaz en egui/eframe 0.37 | La misma lógica de firma que el escritorio (`afirma-*`) sin JVM de por medio y la misma biblioteca de interfaz |
| Actividad | `GameActivity` (AndroidX `games-activity` 4.4.0) con `android-activity` 0.6.1 | Ver §1.1 |
| Dibujo | `glow` (OpenGL ES 2/3 por EGL) | Presente en todos los dispositivos con API 26 y en el emulador (SwiftShader); `wgpu` añade varios MB sin ventaja para una interfaz 2D |
| Capa Java | Java (sin Kotlin) en dos clases: `MainActivity` y `NativeBridge` | Solo lo que únicamente existe en el SDK: KeyChain, selector de documentos (SAF), intents, NFC y las inserciones de ventana |
| Puente | crate `jni` 0.22 (el mismo que usan winit y rustls-platform-verifier) | Sin versiones duplicadas |
| Identificador | `io.github.autofirma_rs.android` | El del escritorio (`io.github.autofirma-rs.AutoFirma`) no vale como paquete Java (guion); se sigue el de AppStream (`io.github.autofirma_rs`). Distinto del oficial `es.gob.afirma` para poder convivir con él |
| API mínima | `minSdk` 26 (Android 8.0); la app oficial admite desde la 23 (6.0) | La accesibilidad (§9.6): `accesskit_android` carga su clase Java con `InMemoryDexClassLoader` (API 26) al crear la ventana, y eframe la crea siempre que tiene el rasgo `accesskit`, así que con 23–25 la app no arrancaría. Android 6 y 7 no reciben parches de seguridad desde 2018–2019 (poco recomendable para firmar) y son ~2 % de los dispositivos. Todo lo demás (`KeyChain.choosePrivateKeyAlias` con `Uri`, `ACTION_OPEN_DOCUMENT`, `NfcAdapter.enableReaderMode`) existe desde la 23: volver a 23 es quitar el rasgo `accesskit` de eframe y la dependencia de `accesskit_winit` (`crates/autofirma-android/Cargo.toml`) y bajar `minSdkVersion` en `android/app/build.gradle.kts` |
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
| Teclado en pantalla | Solo eventos de tecla (ASCII básico; sin tildes ni «ñ» con muchos teclados) | `GameTextInput` (IME completo; winit 0.30 no lo reenvía: puente propio, §9.4) |
| Accesibilidad (`accesskit`) | eframe lo prohíbe (`compile_error!`) | Activada (`accesskit_android`, §9.6) |
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
  app/src/main/java/com/google/androidgamesdk/GameTextInputAccess.java
                                          acceso al InputConnection de GameTextInput (§9.4)
  app/src/main/res/values-night/          fondo de la ventana en tema oscuro
crates/autofirma-android/                 libautofirma_android.so
  locales/*.txt                           textos en los seis idiomas (§9.2)
  src/bridge.rs                           eventos, ids de petición, rasgo Platform, zona segura
  src/shell.rs                            la aplicación: pila de pantallas, diálogos, eventos
  src/nav.rs                              pantallas y navegación («Atrás»)
  src/ui/                                 tema, componentes táctiles, iconos, pantallas
  src/i18n.rs, prefs.rs, history.rs       idiomas, preferencias, histórico de firmas
  src/ime.rs                              teclado en pantalla para los campos de egui
  src/features.rs                         «Ver un certificado», enlaces, afirma://
  src/flow.rs                             firma local e importación de certificados (§9.8)
  src/local_sign.rs                       formato, parámetros, firma y nombre del fichero firmado
  src/visible.rs                          vista previa de la firma visible y área en puntos PDF
  src/errors.rs                           errores AA para la interfaz (§8.1 de la spec; los de la
                                          firma y la web, de afirma_protocol::android::errors)
  src/keychain.rs                         KeyChainKey (afirma_core::SigningKey sobre KeyChain) y
                                          textos de los avisos sobre el certificado
  src/android/{mod,java,logcat}.rs        solo Android: entradas, JNI, logcat
tools/android/Dockerfile                  imágenes de compilación y de emulador (versiones y SHA-256)
tools/android/build.sh                    APK de depuración y release
tools/android/emulator-test.sh            prueba de humo en el emulador (+ emulator-smoke.sh y,
                                          con --sign, la firma de extremo a extremo emulator-sign.sh)
.github/workflows/android.yml             CI
```

`build.gradle.kts` lee la versión de `[workspace.package]` en `Cargo.toml` (`versionName`); el
`versionCode` es `AUTOFIRMA_BUILD_NUMBER` (número de ejecución en CI) o 1. La tarea
`cargoNdk<Variante>` ejecuta `cargo ndk --platform 26 -t <abi>… build -p autofirma-android
--locked [--release]` y deja las `.so` como fuente generada de `jniLibs` (API de variantes de
AGP), así que `./gradlew assembleDebug` compila todo, también desde Android Studio.

## 3. Rust y Java

### 3.1 Arranque

1. `GameActivity.onCreate` carga `libautofirma_android.so` (meta-dato `android.app.lib_name`).
2. `android_on_create` (hilo principal de Java, con `onCreate` en la pila, así que el cargador de
   clases de la app está disponible): registro en logcat, gancho de pánicos e inicio de
   `rustls_platform_verifier::android::init_with_env` con el contexto de la aplicación.
3. `android_main` (hilo nativo propio que crea android-activity): `eframe::run_native` con
   `NativeOptions::android_app` y el renderizador `glow`. La interfaz es `shell::Shell`, con
   las preferencias y el histórico en el directorio privado (`AndroidApp::internal_data_path`,
   que es el `getFilesDir()` que GameActivity pasa desde Java).
4. Cuando la actividad se destruye, `run_native` vuelve y el proceso termina
   (`std::process::exit(0)`): winit no permite crear un segundo bucle de eventos en el mismo
   proceso, y si Android vuelve a crear la actividad lo hace en un proceso nuevo.

Para que la actividad casi nunca se destruya: `launchMode="singleTask"` (los `afirma://` llegan
por `onNewIntent` a la misma instancia), `configChanges` con todos los cambios de configuración
(girar, tamaño, idioma, tema; egui se adapta solo) y «Atrás» lo decide Rust (pila de pantallas,
§9.1), salvo en una pantalla raíz sin diálogo: Rust lo avisa con `setBackAtRoot` y Java hace
`moveTaskToBack(true)` en el mismo gesto (hecho después, desde Rust, el emulador a veces
respondía con una transición vacía y la app no se movía). La
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
| `open_document(id, tipos)` | `openDocument(long, String)` → `ACTION_OPEN_DOCUMENT` con los tipos MIME (separados por comas; `*/*` o `application/x-pkcs12`) | No | `onDocumentOpened` / `onRequestFailed` |
| `create_document(id, tipo, nombre)` | `createDocument(long, String, String)` → `ACTION_CREATE_DOCUMENT` (`CATEGORY_OPENABLE`, `EXTRA_TITLE`); los datos esperan en el puente (`Bridge::stash_write`) | No | `onDocumentCreated` / `onRequestFailed` (cancelado) |
| `install_certificate(id, pkcs12)` | `installCertificate(long, byte[])` → `KeyChain.createInstallIntent` con `EXTRA_PKCS12` | No | `onCertificateInstalled` / `onRequestFailed` (cancelado) |
| `choose_certificate(id)` | `chooseCertificate(long)` → `KeyChain.choosePrivateKeyAlias` (RSA y EC) | No | `onCertificateChosen` |
| `certificate_chain(alias)` | `byte[][] certificateChain(String)` → `KeyChain.getCertificateChain` | Sí | valor devuelto |
| `sign(alias, alg, datos)` | `byte[] sign(String, String, byte[])` → `KeyChain.getPrivateKey` + `Signature` (`SHA256withRSA`, `SHA256withECDSA`...) | Sí | valor devuelto |
| `start_nfc_reader(id)` | `startNfcReader(long)` → `enableReaderMode` (NFC-A/B, sin NDEF, sondeo 1000 ms) | No | `onNfcTag` / `onRequestFailed` |
| `nfc_transceive(apdu)` | `byte[] nfcTransceive(byte[])` → `IsoDep.transceive` (tiempo máximo 5000 ms) | Sí | valor devuelto |
| `stop_nfc_reader()` | `stopNfcReader()` | No | — |
| `set_back_at_root(raíz)` | `setBackAtRoot(boolean)`: «Atrás» hará `moveTaskToBack(true)` en Java | No | — |
| `leave_app()` | `leaveApp()` → `moveTaskToBack(true)` (si Java aún no sabía que era la raíz) | No | — |
| `open_url(id, url)` | `openUrl(long, String)` → `ACTION_VIEW` | No | `onRequestFailed` si no hay navegador |
| `ime_show(petición)` | `imeShow(inputType, actionId, imeOptions, texto, selIni, selFin)` | No | `onTextInput`, `onEditorAction`, `onImeVisibility` |
| `ime_update(estado)` | `imeUpdate(texto, selIni, selFin)` | No | — |
| `ime_hide()` | `imeHide()` | No | — |

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
| `onDocumentOpened(long id, String uri, String nombre, int fd)` | `DocumentOpened`: Java cede el descriptor (`ParcelFileDescriptor.detachFd`) y Rust lo lee (máx. 256 MB; si es mayor, `RequestFailed` con `DOCUMENT_TOO_LARGE`, error AA200105) y lo cierra; nada de copias por el montón de Java |
| `onDocumentCreated(long id, String uri, String nombre, int fd)` | `DocumentSaved`: Java cede el descriptor del documento nuevo (modo `wt`, o `w` si el proveedor no trunca) y Rust escribe en él, en el hilo de E/S de Java, los datos que esperaban en el puente con ese id (`Bridge::complete_write`) y lo cierra |
| `onCertificateInstalled(long id)` | `CertificateInstalled` (el instalador ha devuelto `RESULT_OK`) |
| `onCertificateChosen(long id, String alias)` | `CertificateChosen` (`alias` nulo: no se eligió) |
| `onNfcTag(long id, byte[] tagId, byte[] históricos, byte[] hiLayer, byte[] datosNfcB, byte[] protocoloNfcB)` | `NfcTag` con `NfcTagInfo`: identificador, `getHistoricalBytes` (NFC-A), `getHiLayerResponse`, `NfcB.getApplicationData`/`getProtocolInfo` (NFC-B), lo que necesita la identificación del DNIe (`spec/10-dnie-nfc.md` §3) |
| `onRequestFailed(long id, boolean cancelada, String mensaje)` | `RequestFailed` |
| `onInsets(int izq, int arr, int der, int aba)` | zona segura (barras, recortes y teclado) |
| `onBackPressed()` | `Back` (`OnBackPressedDispatcher`; la pila de pantallas está en Rust) |
| `onConfiguration(String idioma, boolean oscuro, float escalaTexto, boolean nfc)` | `Configuration` (en `onCreate` y `onConfigurationChanged`) |
| `onTextInput(String texto, int selIni, int selFin, int compIni, int compFin)` | `ImeState` (`GameTextInput` `stateChanged`; índices UTF-16) |
| `onEditorAction(int acción)` | `ImeAction` |
| `onImeVisibility(boolean visible)` | `ImeVisibility` |

### 3.4 Hilos

```
 hilo principal de Java                 hilo android_main (Rust)          hilos de trabajo (Rust)
 ───────────────────────                ────────────────────────          ───────────────────────
 onCreate, onNewIntent,      evento     bucle de winit + egui      spawn   leer y analizar documentos,
 resultados de SAF/KeyChain ─────────►  Shell::pump()            ───────►  firmar, cadena de KeyChain,
 onApplyWindowInsets         (cola +    Shell::ui()                        APDU por NFC (bloquean; JNI)
        ▲                    repaint)        │                                   │
        │ runOnUiThread                      │ open_document / choose_…          │ evento con el resultado
        └────────────────────────────────────┘ (no bloquean)                     └──► cola del puente
 ejecutor de E/S de Java: abre el documento y llama a onDocumentOpened (Rust lee el descriptor ahí);
                         abre el documento creado y llama a onDocumentCreated (Rust escribe ahí)
 hilo del lector NFC (binder): conecta IsoDep y llama a onNfcTag
```

Hilos de trabajo de la firma local (`flow.rs`): cadena del certificado (`certificateChain`),
firma (`local_sign::sign`, que llama a `sign` de Java por cada PKCS#1), apertura del PDF de la
vista previa y dibujo de cada página. La textura de la página se sube a egui en el hilo de la
interfaz (`Flows::upload_textures`).

Reglas: el hilo de la interfaz nunca bloquea (las llamadas que abren actividades del sistema solo
encolan trabajo con `runOnUiThread`); el hilo principal de Java nunca ejecuta trabajo largo de
Rust; todo lo que bloquea (KeyChain no se puede usar en el hilo principal, `transceive`, firma,
red) va en hilos de trabajo, que publican su resultado en la cola. `Features` lleva un mapa de
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
líneas: «AutoFirma-rs … para Android iniciado», «Primer fotograma de la interfaz», «Pantalla
«settings»» (la pantalla visible y su diálogo: «settings + message»), «Botón «home.sign_file» en
x=… y=…» (centro de cada elemento pulsable visible, con un identificador estable que no depende
del idioma, en píxeles para pulsarlo con `adb`; «Botón «…» oculto» cuando deja de verse al
desplazar), etc. Nunca se registra lo que se escribe en un campo (contraseñas, PIN, CAN): el
teclado solo deja «Teclado en pantalla abierto (Password)» y similares. En la release R8 quita
los `Log.d`/`Log.v` de todo el código Java, incluido GameTextInput, que registra el texto del
editor en cada pulsación.

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
| `afirma-cms`, `afirma-xml`, `afirma-pdf`, `afirma-signers` | Sí | Firma local CAdES, XAdES y PAdES (`afirma-signers`); vista previa de la firma visible con el rasterizador de `afirma-pdf` (`hayro`, el mismo que el editor de firma visible del escritorio) y `afirma_pdf::info::PdfInfo` para los tamaños de página y las contraseñas |
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
| release | 62,8 MB (59,9 MiB) | `arm64-v8a` 21,3 MB, `armeabi-v7a` 16,9 MB, `x86_64` 23,9 MB | `classes.dex` 0,6 MB (R8) |
| depuración | 85,1 MB (81,1 MiB) | 27,5 MB, 21,7 MB y 32,6 MB (perfil `dev`, sin símbolos) | 7,1 MB (sin R8) |

Con la carcasa de la interfaz (§9) la `.so` creció unos 2,4 MB por ABI: Inter y Phosphor
(1,3 MB, las mismas fuentes que el escritorio), AccessKit y las pantallas.

Comprimida, la `.so` de `arm64-v8a` ocupa unos 10,2 MB: un APK o AAB por ABI se descargaría en
unos 11 MB. La biblioteca incluye egui, sus fuentes y las del escritorio, el rasterizador PDF (`hayro`),
tokio, rustls/ring y todos los firmadores; se podría reducir con `opt-level = "s"` y LTO completo
para Android.

Las `.so` van sin comprimir (se cargan directamente del APK), así que el APK pesa más que la
descarga desde Google Play, que comprime y además reparte por ABI si se publica como AAB.

## 6. Prueba en el emulador

```sh
tools/android/emulator-test.sh                                   # APK de depuración de build.sh
tools/android/emulator-test.sh --tls-check https://github.com/   # y verificación TLS
tools/android/emulator-test.sh --apk ruta/al/release.apk --out /tmp/emu
tools/android/emulator-test.sh --sign                            # y firma local de extremo a extremo
```

Arranca, dentro de la imagen `autofirma-android-emulator` y con `--device /dev/kvm`, un
dispositivo virtual x86_64 de 1080×2400 a 420 ppp con Android 15 (API 35, Google APIs, en
inglés), sin ventana y con GPU por software (SwiftShader). Los elementos se pulsan en la
posición que registra la app («Botón «id» en x=… y=…», §3.6), desplazando la pantalla si hace
falta. Después:

1. instala y abre la app, espera «… para Android iniciado» y «Primer fotograma de la
   interfaz» y pasa por el arranque, la bienvenida y las condiciones (cambiando el idioma al
   español en su selector y marcando las dos casillas) hasta Inicio (`captura.png`);
2. **Rust → Java**: pulsa «Firmar fichero» y espera a que el selector del sistema (DocumentsUI)
   tenga el foco (`selector.png`);
3. **Java → Rust**: pulsa Atrás y espera «Selector de documentos cancelado» de Rust;
4. **KeyChain**: Certificados → «Ver un certificado», comprueba que se abre `KeyChainActivity`
   (sin certificados instalados responde «ninguno» al momento) y que Rust recibe el alias nulo;
5. lanza `afirma://sign?op=sign&id=prueba` con `am start` y espera a que Rust lo reparta y abra
   su pantalla (`intent.png`);
6. con `--tls-check`, espera «Comprobación TLS correcta»;

después recorre la interfaz entera: las pantallas de Inicio (importar certificado en sus dos
páginas y «Añadir certificado», que abre el selector de `.p12` del sistema, firma web, histórico
y su diálogo «sin registros»), Ajustes y cada
una de sus pantallas (idioma; configuración de firma con el diálogo de minutos y «Cambios
guardados»; dominios de confianza; histórico; preguntas frecuentes con una desplegada; las
cuatro ayudas; accesibilidad, aviso legal, privacidad y versión); **escribe con el teclado en
pantalla** en «Dominios de confianza» (`input text`, Intro para la segunda línea, Atrás cierra
el teclado y el campo suelta el foco) y guarda («Dominios de confianza guardados: 2»); cambia el
idioma a gallego y vuelve al español; comprueba con `uiautomator dump` que el árbol de
accesibilidad de AccessKit llega a Android («Firmar fichero» como nodo, `accesibilidad.xml`);
**gira** a horizontal y pasa al **tema oscuro** y vuelta; y además:

7. pulsa Atrás en Inicio, comprueba que la app pasa a segundo plano, la vuelve a abrir y
   comprueba que es el mismo proceso y que `android_main` no se ha ejecutado dos veces (al
   minuto de arrancar el emulador, el sistema responde a veces a `moveTaskToBack` con una
   transición vacía, por eso va después del recorrido);
8. detiene la app (`am force-stop`) y la arranca en frío con `afirma://selectcert?…`, como lo
   haría el navegador, y comprueba que se recupera el idioma guardado;
9. comprueba que no hay cierres (`logcat -b crash`), que el proceso sigue vivo y que no hay
   pánicos de Rust;
10. con `--sign`, la **firma local de extremo a extremo** (`emulator-sign.sh`, §6.1).

Deja en `--out` las capturas, `accesibilidad.xml`, `logcat.txt`, `logcat-crash.txt` y
`emulator.log`, y en `--shots` (por defecto `<out>/pantallas`) una captura numerada de cada
pantalla y diálogo (38). Si falla, guarda además `fallo.png`, el estado de las ventanas
(`ventanas.txt`) y, si la app sigue viva, las pilas de todos sus hilos (`pilas.txt`, con
`debuggerd -b` tras `adb root`). Agranda el búfer de logcat a 16 MB: en una imagen recién
arrancada las aplicaciones de Google lo llenan en segundos. En este equipo (20 núcleos, KVM)
tarda unos 5 minutos, arranque incluido.

### 6.1 Firma local de extremo a extremo (`--sign`)

`emulator-sign.sh` se ejecuta al final de la prueba de humo y maneja las actividades del sistema
con `uiautomator dump` (busca los nodos por su texto y los pulsa):

1. copia en Descargas `testdata/cades/data/documento.pdf`, `hola.txt`, `documento.xml` y la
   identidad de prueba `testdata/pki/firmante-rsa-legacy.p12`;
2. la **importa con el botón de la app** (Inicio → «Añadir nuevo certificado» → «Continuar» →
   «Añadir certificado»): DocumentsUI (raíz «Descargas» si hace falta), el instalador de
   certificados (contraseña `12341234`, «Certificado de usuario de VPN y aplicaciones», nombre)
   y el diálogo «Certificado añadido» de la app;
3. firma el PDF con **firma visible** (la configuración de firma del recorrido la deja
   activada): vista previa, área dibujada con `input swipe` sobre la página (su centro lo
   registra la app como `preview.page`), «Continuar», selector de KeyChain («firmante-rsa» →
   «Seleccionar»), diálogo de guardado del sistema («Guardar») y «Fichero firmado»; después
   `hola.txt` (CAdES) y `documento.xml` (XAdES) igual, sin vista previa;
4. abre el histórico y comprueba con `uiautomator` que lista las tres firmas
   («Firma local del fichero …»);
5. saca las firmas con `adb pull` a `<out>/firmas/`.

Al terminar el contenedor, `emulator-test.sh` las verifica en el anfitrión con
`autofirma verify -i` (la aplicación de escritorio del espacio de trabajo; `--verifier` para
usar un binario ya compilado) y exige «Firma válida» en las tres (`<out>/verificacion.txt`).
Las capturas de la importación, la vista previa, el guardado, los resultados y el histórico
quedan en el directorio de capturas.

Se usa el PKCS#12 «legacy» (3DES/RC2): el instalador de certificados de Android 15 no abre los
PKCS#12 con PBES2/AES-256 que genera OpenSSL 3 por defecto (`firmante-rsa.p12`; responde «The
certificate is not installed» y el resultado llega a la app como cancelación, §8).

### 6.2 CI

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

- **Teclado:** la selección que el teclado cambia sin cambiar el texto (cursor movido desde el
  teclado) no llega a Rust: GameTextInput solo avisa en `endBatchEdit`. Seleccionar texto
  arrastrando en egui es básico (tocar coloca el cursor). En las compilaciones de depuración
  GameTextInput escribe en logcat lo que se teclea (en la release lo quita R8, §3.6).
- **Accesibilidad:** el adaptador de `accesskit_android` 0.8 hace `unwrap` de excepciones de
  Java; la más probable (enviar eventos con la accesibilidad apagada) la evita
  `MainActivity.AccessibilityGuardLayout` (§9.6). Falta revisar a mano la navegación con
  TalkBack pantalla a pantalla (la prueba solo comprueba que el árbol llega).
- **Funciones de plataforma pendientes:** compartir (`ACTION_SEND` con `FileProvider`),
  portapapeles, proxy del sistema, devolver el resultado al navegador, ajustes de NFC del
  sistema.
- **Pantallas de fases posteriores:** la firma web dice «Próximamente»; en «¿Con qué
  firmarás?» (solo con el DNIe habilitado) «DNI electrónico» explica que llegará en una
  próxima versión y vuelve a la elección (`FlowAction::CertType(CertType::Dnie)` en
  `flow.rs` es donde se enganchará el DNIe de `afirma-dnie`).
- **PKCS#12 modernos:** el instalador de certificados de Android 15 (`com.android.certinstaller`)
  no abre los PKCS#12 cifrados con PBES2/AES (lo que exportan OpenSSL 3 y muchos navegadores
  actuales): dice «The certificate is not installed» y devuelve `RESULT_CANCELED`, que la app
  trata como cancelación (como el original). Los «legacy» (3DES/RC2) se instalan bien. Se
  podría pedir la contraseña en la app y volver a cifrar el almacén en «legacy» antes de pasarlo
  al instalador (cambia el flujo del original, que delegaba todo en el sistema).
- **Lector USB, tarjetas y DNIe por NFC** (§4.4, §4.5 y §4.9 de la especificación): fase
  posterior. La firma local vacía la caché de certificado de la firma web
  (`afirma_protocol::android::sticky::StickyKeyCache`, `Flows::cache`): la interfaz web tiene
  que usar esa misma instancia.
- **Flujo web:** el lado de protocolo está hecho (`afirma_protocol::android`, §10); falta
  implementar `AndroidWebHandler` con la interfaz (diálogos, SAF, vista previa), registrar los
  `afirma://` e intents en el manifiesto y llamar a `AndroidWebLauncher::run` (la pantalla
  actual marca `websocket` y `service` como no disponibles en Android).
- **DNIe por NFC:** el transporte (modo lector, `IsoDep`, `transceive`) está hecho en Java y Rust
  pero sin probar con hardware (el emulador no tiene NFC). Falta lo de
  `spec/10-dnie-nfc.md`: identificación, PACE con CAN, mensajería segura, canal CWA-14890, PIN
  y firma. Hay que comprobar en API 26–27 que las sondas de presencia del modo lector no cortan
  el canal (JMulticard usaba un *watchdog* por reflexión).
- **KeyChain en las pruebas:** la prueba de humo sin `--sign` solo comprueba que se abre el
  selector y que vuelve la respuesta; con `--sign` se instala la identidad de prueba (sin
  bloqueo de pantalla: Android 15 no lo pide para certificados de usuario) y se firma con ella
  (§6.1). Las claves del TEE/StrongBox no se pueden probar en el emulador.
- **Accesibilidad en depuración:** `accesskit_android` 0.8.0 resta 1 a la longitud de un texto
  vacío al avisar de un cambio de texto; con las comprobaciones de desbordamiento de la
  compilación de depuración, la app abortaba si había un servicio de accesibilidad activo
  (`uiautomator dump` lo activa) y un nodo pasaba de no tener texto a tenerlo. El `Cargo.toml`
  del espacio de trabajo quita esas comprobaciones solo a ese crate en el perfil `dev` (en
  release la resta da la vuelta y el resultado es el correcto). Hay que comunicarlo a AccessKit.
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

## 9. Interfaz de la aplicación

### 9.1 Pantallas y navegación

`nav::Screen` tiene una variante por actividad del original (`spec/09-android.md` §2.1) con su
estado (las casillas de las condiciones, el borrador de «Configuración de firma», el texto de
los dominios, las preguntas desplegadas...), y `nav::Navigator` es la pila: entrar apila,
«Atrás» desapila y la pantalla de debajo conserva su estado. `shell::Shell` atiende los
eventos de Android, dibuja la pantalla actual y el diálogo abierto (hojas inferiores,
`ui::screens::Dialog`) y ejecuta después de dibujar lo que piden (`ui::screens::Action`):
navegar, guardar preferencias, abrir el selector de documentos... Arranque (1,5 s, se salta
tocando; con un enlace `afirma://` en frío se salta solo) → bienvenida si no se ha visto →
condiciones si no se han aceptado → Inicio, como en §2.4.

«Atrás» (§2.13): cierra primero el diálogo; en las instrucciones de importación vuelve a la
página 1; si hay pantalla debajo, vuelve a ella; en una pantalla raíz (arranque, bienvenida,
condiciones, Inicio) deja la app en segundo plano (desde Java, §3.1). La firma local es una
operación de varios pasos (`flow.rs`, §9.8) que abre la vista previa de la firma visible
(`Screen::VisibleSignature`) y diálogos sobre Inicio, como la `LocalSignActivity`
transparente del original.

### 9.2 Idiomas

`locales/<idioma>.txt` (`es`, `en`, `ca`, `gl`, `eu`, `ca-valencia`): el mismo formato
`clave = texto` que los catálogos del escritorio, pero con las claves de
`res/values*/strings.xml` del original (la especificación cita los textos por esas claves). La
primera parte son las 272 claves del original (las marcas HTML pasadas a un marcado mínimo:
`**negrita**`, párrafos, `## título`, `- lista`; `%1$s` → `{0}`); la segunda (desde
`# [autofirma-rs]`), los textos propios. `i18n::tr("clave")` / `trf` buscan en el idioma
activo (y en español si faltara). Las claves que pasan por una variable se escriben
`k!("clave")`. La prueba `catalogos_completos` comprueba que los seis catálogos tienen las
mismas claves (272 del original más las propias), sin textos vacíos ni marcadores distintos, que
existen todas las claves del código y que se usan todos los textos propios.

Correcciones de los textos del original (§10 n.º 59), cada una con un comentario
«Corregido: …» en el catálogo: nombre de la app (en euskera «Aplikazio automatikoa»;
«Autofirma App» pasa a «AutoFirma», el nombre de esta app, también con las declinaciones del
euskera), errata «segura/segura» y textos en español del catalán («No usar DNIe», «Guardar»,
«Contrafirma», «Hasta»…), del valenciano y del gallego (escape roto en la pregunta del NFC,
«claves», «Hasta», «Operacion»; el resto de los «~50» de la especificación se escriben igual en
gallego o son normativos: «firma», «cargando»…), traducciones erróneas del inglés que se ven en
la carcasa («enclosed», «a option», «Impair», «historical»), el punto de más de «.pfx. en» y los
nombres de los idiomas («Català», «Euskara»). El texto de ayuda de los dominios dice
«separados por comas»: se admiten comas y saltos de línea (§10 n.º 47).

El idioma por defecto es el del sistema (`Locale.toLanguageTag()` que envía Java; un idioma sin
traducción usa el español, como `values/`); al elegir uno se aplica en la siguiente pasada de
egui y se guarda (`localeConfig`); «Idioma del sistema» vuelve a seguirlo. A diferencia del
original, todas las pantallas usan el idioma elegido (§10 n.º 2) y las condiciones no lo
devuelven al español (§10 n.º 3).

### 9.3 Preferencias e histórico

`prefs::Prefs` guarda las claves de §7 con sus tipos y valores por defecto en
`afirma.client.json` (directorio privado; escritura atómica en cada cambio; un fichero dañado o
una clave desconocida vuelven al valor por defecto). Es un manejador que se puede clonar y
leer desde cualquier hilo (`prefs.get().use_nfc`, `prefs.update(|p| …)`).
`history::SignsHistory` lee y escribe `signsRecord.txt` con el formato de §3.10 (sin romper la
línea con un `;` en el nombre y sin dejar de leer el resto tras una línea corta, §10 n.º 54).

### 9.4 Teclado en pantalla

winit 0.30 descarta los eventos de texto de GameTextInput, y mientras el teclado está activo
GameTextInput se queda con las pulsaciones (`InputConnection.onKey` → `processKeyEvent`), así
que el puente es por **estado** (`src/ime.rs`):

- `MainActivity` sobrescribe `stateChanged`, `onEditorAction` y
  `onSoftwareKeyboardVisibilityChanged` sin llamar a `super` (android-activity los encolaría
  para winit, que los descarta registrando el texto) y los envía a Rust: texto, selección y
  composición con índices UTF-16, que `ImeState::from_java` pasa a índices de carácter.
- Mientras un campo (`ui::widgets::text_field`) tiene el foco, el teclado manda: antes de
  dibujarlo se copia su estado al `String` y al cursor del `TextEdit` de egui. Lo que cambia en
  egui (tocar para mover el cursor) se envía al teclado con `imeUpdate`.
- `ImeController` abre el teclado (`imeShow`, en el hilo principal: `EditorInfo` con el tipo del
  campo —contraseña sin sugerencias ni aprendizaje, numérico, multilínea, acción «Hecho»—, el
  estado y `InputConnection.setSoftKeyboardActive`, al que se llega con
  `com.google.androidgamesdk.GameTextInputAccess` porque el campo es de paquete) y lo cierra
  cuando ningún campo tiene el foco. eframe no interviene: la interfaz quita la salida `ime` de
  egui en cada pasada para que no llame a `set_ime_allowed` desde el hilo de Rust.
- Cada campo tiene un `FieldSpec` (tipo y longitud máxima): lo que no admite (letras en el CAN)
  se quita y se devuelve al teclado. La tecla de acción llega dos veces (GameTextInput la envía
  al pulsar y al soltar Intro) y se cuenta una. Si el usuario cierra el teclado (Atrás o su
  botón), el campo suelta el foco y tocarlo lo vuelve a abrir. El campo con el foco se desplaza
  a la vista cuando aparece el teclado (la zona segura incluye el teclado).

Probado en el emulador con Gboard: `input text`, Intro, borrar y escribir con las teclas del
teclado (`deleteSurroundingText`, `commitText`), Atrás.

### 9.5 Aspecto

La paleta clara y oscura, Inter y los iconos Phosphor del escritorio (las fuentes se incluyen
desde `crates/autofirma/assets/fonts`), con tamaños táctiles: elementos de al menos 48 dp,
texto de 16 dp multiplicado por la escala de texto del sistema (`fontScale`, hasta ×2), listas
agrupadas en tarjetas, hojas inferiores con fondo oscurecido, botones fijos abajo en los
formularios, fundido al cambiar de pantalla y contenido centrado con un ancho máximo en
horizontal y en tabletas. El tema sigue al del sistema (`uiMode`, también la ventana de
arranque con `values-night` y los iconos de las barras con `EdgeToEdge.enable` en cada cambio).
La app gira (el original se bloqueaba en vertical en los móviles; WCAG 1.3.4 pide no hacerlo).

### 9.6 Accesibilidad

eframe con el rasgo `accesskit` y el adaptador de Android de `accesskit_winit` (es opcional y
eframe no lo activa: lo activa la dependencia directa del crate). TalkBack recibe el árbol de
egui: cada componente propio declara su función y su texto (`WidgetInfo`: botón, interruptor,
casilla, opción, enlace, título). Exige `minSdk` 26 (§1). `accesskit_android` 0.8 envía eventos
aunque se haya desconectado el servicio (TalkBack apagado, `uiautomator`) y
`AccessibilityManager` lanza «Accessibility off» en el hilo principal: el `unwrap` aborta el
proceso. `MainActivity` sustituye el contenedor de la superficie de GameActivity
(`onCreateSurfaceView`) por uno que no reenvía los eventos con la accesibilidad apagada.

### 9.7 Diferencias con el original

Además de las correcciones de §10 citadas arriba (n.º 2, 3, 4, 47, 54, 59), y por ser una app
independiente y no la del Gobierno: el arranque no muestra los logotipos institucionales; el
aviso legal, la política de privacidad y la declaración de accesibilidad son textos propios
(los del original dicen que la app la opera la Agencia Estatal de Administración Digital), en
los seis idiomas y dentro de la app; la pantalla de versión explica qué es AutoFirma para
Android, su licencia y dónde está el código. Se añaden «Idioma del sistema», el resumen de los
certificados de KeyChain y accesos en Inicio a la firma web, los certificados y el histórico.

### 9.8 Firma local y certificados

La firma local (`flow.rs`, `local_sign.rs`, `visible.rs`) sigue el orden de `LocalSignActivity`
(`spec/09-android.md` §3) sobre la pantalla de Inicio, con diálogos y una sola pantalla propia
(la vista previa); cada paso que espera a Android o a un hilo de trabajo guarda el identificador
de su petición y descarta las respuestas que no espera:

1. **Documento:** `ACTION_OPEN_DOCUMENT` (`*/*`) en todas las versiones (con `minSdk` 26 no hacen
   falta el selector propio ni el permiso de almacenamiento de Android < 11). Cancelar no dice
   nada; un error de lectura da AA200102 y uno de más de 256 MB, AA200105.
2. **Formato** por el nombre (como el original, §10 n.º 20): `.pdf` → PAdES, `.xml` → XAdES
   (añadido: el original no tenía XAdES monofásica y firmaba los XML en CAdES), el resto →
   CAdES implícita; SHA-256, `mode=implicit`, siempre firma (nunca cofirma).
3. **Firma visible** (PAdES con «Hacer firma visible»): la vista previa abre el PDF y dibuja la
   página visible con el rasterizador de `afirma-pdf` en un hilo de trabajo (a la resolución de
   la pantalla); el área se dibuja arrastrando el dedo (sin zoom ni desplazamiento, como el
   original), con los botones de primera, anterior, siguiente y última página; cambiar de
   página borra el área. «Continuar» aplica la fórmula y los mínimos del original (30×45 puntos
   y 1350 puntos², §10 n.º 28) con el tamaño de la página tal como se muestra (el original usaba
   la caja de medios sin girar y en las páginas giradas el área quedaba fuera de sitio); sin
   área o con un área pequeña ofrece seguir sin firma visible (§10 n.º 25). Parámetros:
   `signaturePages`, `signaturePositionOnPage*`, `layer2Text` con la plantilla del idioma (la de
   seudónimo si el certificado lo es) y `obfuscateCertText` según la preferencia.
4. **Contraseña del PDF:** si la vista previa o la firma la necesitan, «El documento está
   encriptado» con campo oculto (icono del ojo para verla), «La contraseña del PDF no puede
   estar vacía:» y «Contraseña incorrecta:»; la firma se repite con `ownerPassword`. La
   contraseña de la vista previa vale también para la firma invisible (el original la perdía y
   la volvía a pedir, §10 n.º 26).
5. **Almacén:** con «Permitir firmar con DNIe por NFC», «¿Con qué firmarás?» (la X cancela; el
   DNIe dice que llegará en una próxima versión y vuelve a preguntar); si no, directamente el
   selector de KeyChain (claves RSA y EC). Sin elegir certificado: con el DNIe habilitado se
   vuelve a preguntar; si no, se cancela sin mensaje.
6. **Certificado:** la cadena se lee en un hilo de trabajo («Cargando certificado») y se
   avisa, en este orden, de certificado caducado, aún no válido (el original lo trataba como
   error genérico, §10 n.º 13), próximo a caducar (menos de 7 días) y de seudónimo: «Continuar»
   sigue y «Cancelar» vuelve a la elección de almacén. Los avisos se calculan con
   `afirma_protocol::android::launcher::certificate_warnings`, como en la firma web. La firma
   local vacía la caché de certificado (`StickyKeyCache` de la firma web, §4.7).
7. **Firma** en un hilo de trabajo («Realizando firma»): los firmadores de `afirma-signers` con
   `KeyChainKey`, que firma cada PKCS#1 en Java (`Signature` con la clave de
   `KeyChain.getPrivateKey`, que puede estar en el TEE o en StrongBox). Un error da AA200002; uno
   del certificado o de KeyChain, AA200000.
8. **Guardado** con `ACTION_CREATE_DOCUMENT`: nombre `<nombre>_signed.pdf`, `<nombre>.csig` o
   `<nombre>.xsig` y tipo `application/<extensión>`, como el original; Rust escribe la firma en
   el descriptor que devuelve Java. El histórico (`LOCAL`, `sign`, nombre del fichero) se
   escribe **después** de guardar: si se cancela el guardado no se registra (§10 n.º 21). Un
   error de escritura da AA200301. El nombre del `save` web sin «datosdatos.pdf» (§10 n.º 49)
   lo propone `afirma_protocol::android::launcher::proposed_save_name`; el diálogo de guardado
   (`Platform::create_document`) es el mismo.
9. **Resultado:** «Fichero firmado» / «El fichero ha sido firmado correctamente.» o «¡Algo salió
   mal!» con «AA<código> - <texto>» (`errors.rs`: las categorías de
   `afirma_protocol::android::errors` más las que solo muestra la interfaz —dominios,
   importación, DNIe—, con el texto de los catálogos de la app en el idioma activo).

**Importación** (`spec` §4.8): «Añadir certificado» en la segunda página de las instrucciones
las cierra y abre el selector de documentos con `application/x-pkcs12` (uno solo: el original
abría dos seguidos desde Inicio, §10 n.º 15); el almacén se pasa a
`KeyChain.createInstallIntent` y el sistema pide la contraseña, el tipo y el nombre. Instalado →
«Certificado añadido»; cancelado → nada; error al leer → «No hemos podido añadir tu
certificado» con AA201100 y «Volver a intentarlo». Los textos de las instrucciones son los de
la página visible (§10 n.º 16).

Pruebas: en el anfitrión, `shell::tests` recorre la firma local con una KeyChain falsa que firma
de verdad con la clave de `testdata/pki/firmante-rsa.p12` (PDF con firma visible, CAdES, XAdES,
guardado cancelado, PDF protegido, avisos del certificado, elección de almacén, importación,
errores de lectura) y valida las firmas con `afirma_signers::validate`, el verificador del
escritorio; en el emulador, §6.1.

## 10. Firma desde la web: API del protocolo (`afirma_protocol::android`)

El lado de protocolo de la firma web del original (`spec/09-android.md` §5, §6 y §8) está en
el módulo `android` de `afirma-protocol`, sin dependencias de Android ni de interfaz: reutiliza
del crate el análisis de consultas y sobres, la validación de URL de servicio, el cliente
trifásico, los lotes y el cliente HTTP, y `autofirma-android` ya depende de él (un crate aparte
obligaría a hacer públicas esas piezas internas). Reproduce la app 1:1 (análisis con
`afirma-core` **1.9**, peticiones al servidor intermedio, respuestas y errores) salvo los fallos
que §10 de la especificación manda corregir, listados en
`docs/deviations/afirma-protocol.md` (sección Android, A1–A21).

**Uso.** Una sola instancia por proceso (guarda la caché de certificado *sticky* entre
invocaciones):

```rust
let mut cfg = AndroidWebConfig::new(HttpClient::new(Arc::new(cliente_ureq)));
cfg.language = WebLanguage::from_tag(&prefs.locale).unwrap_or_default(); // localeConfig
cfg.obfuscate_cert_text = prefs.pades_obfuscate_cert_info;               // padesObfuscateCertInfo
cfg.sticky_timeout = Duration::from_secs(60 * prefs.sticky_minutes);     // stickySignatureTimeout
let web = AndroidWebLauncher::new(handler, signer, cfg);
// En un hilo de trabajo, con la URL del intent (afirma://… o la de SIGN_SERVICE):
let out = web.run(&url, InvocationMode::Browser); // o App { calling_package }
```

- **Cliente HTTP**: el de `afirma-core` (`UreqHttpClient`) como en el original: sin proxy
  (`ProxyMode::None`), sin tiempos de espera y con la confianza TLS de las preferencias:
  `domains::http_trust_overrides(validateSslChecks, secureDomainsList)` devuelve
  `disable_ssl_checks` y `secure_domains` para `HttpSettings` (las reglas de coincidencia de la
  app, por líneas, convertidas al formato del cliente común; se aplican por petición).
- **`signer`**: un `afirma_protocol::LocalSigner` con `afirma-signers` (el mismo que el del
  escritorio, `sign` y `detect_format`). Solo le llegan los formatos monofásicos de la app
  (`CAdES`, `CAdES-ASiC-S`, `PAdES`, `Adobe PDF`, `NONE`); XAdES y FacturaE van siempre por la
  trifásica (necesitan `serverUrl`) y los `*tri` los hace el crate (`android::formats`).
- **`handler`** (`AndroidWebHandler`, se llama desde el hilo de trabajo y debe esperar a la
  interfaz):

| Método | Interfaz del original |
|---|---|
| `select_key(KeyRequest) -> SelectedKey { key, source }` | `ChooseCertTypeDialog` + KeyChain / DNIe por NFC / lector USB; `source` decide los avisos (solo `SystemKeyStore`) y la caché (nunca `DnieNfc`). Los errores (`KeySelectionError`) dan `ERR-11`, `ERR-23`, `ERR-21` o `ERR-13` como en §5.12 |
| `confirm_certificate_warning` | Avisos de caducado / aún no válido / próximo a caducar / seudónimo; `false` vuelve a la elección |
| `choose_file` | SAF `ACTION_OPEN_DOCUMENT` cuando la web no manda datos |
| `visible_signature` | `PdfSelectPreviewActivity` (área en puntos PDF, contraseña) |
| `pdf_password` | `PDFPasswordDialog` |
| `save_file` | SAF `ACTION_CREATE_DOCUMENT` de `save` (nombre propuesto ya calculado) |
| `show_error`, `progress` | «¡Algo salió mal!» con «AA… - …»; «Firmando», «Cargando almacén de claves» |

- **Resultado** (`WebOutcome`): `reply` (`Uploaded` o `UploadFailed` con el `dat` exacto
  subido, `Intent` con los extras de `RESULT_OK`/`RESULT_CANCELED` para la modalidad
  `SIGN_SERVICE`/`SIGN_BATCH_SERVICE`, o `NotSent`) y `history` (registro `WEB`, `APP`,
  `BATCH`, `BATCH_APP` que la app escribe con `history::SignsHistory`). Tras `Uploaded` o
  `Intent`, la app se cierra y vuelve al navegador (`finishAffinity`/`setResult`).
- **Atrás** mientras se descarga o firma: `request_cancel()` → `ERR-11` (si ya se respondió,
  nada: una sola respuesta por invocación). Con un diálogo abierto, la cancelación es la
  respuesta del diálogo.
- **Piezas sueltas**: `request::parse_url` (análisis 1.9), `errors` (catálogo `AA` y `ERR-NN`
  con los textos de usuario en los seis idiomas y `URLEncoder`), `cipher` (`CipherDataManager`
  y el Base64 de Android con saltos de línea), `intermediate` (subida, descarga con 10
  reintentos ante `ERR-06`, `#WAIT` cada 10 s en lotes con sobre), `domains`, `formats`,
  `sticky` (`StickyKeyCache`; la firma local debe vaciarla o compartir la de `keychain`) y
  `batch` (lotes JSON como `BatchSigner`, con `org.json` de Android).

**Pruebas** (`cargo test -p afirma-protocol`): unitarias de cada pieza; `tests/android_oracle.rs`
compara 89 casos (análisis de URL y sobres, DES, errores, cuerpos de las peticiones al
servidor intermedio) con lo que producen las clases Java originales (`afirma-core` 1.9 de la
etiqueta `v1.9` y `CipherDataManager`, `ErrorManager` e `IntermediateServerUtil` de la app;
`tools/oracle/android_web_oracle.sh` regenera `testdata/android-web/oracle.golden`); y
`tests/android_web_e2e.rs` ejecuta cada operación (firma, cofirma con sobre y `ERR-06`,
contrafirma, XAdES trifásica, PAdES con firma visible y contraseña, `selectcert` con caché,
`save`, lotes JSON con espera activa, XML/local, errores, cancelación, intent) contra un
StorageService/RetrieveService y un servicio de lotes simulados sobre TCP con el cliente HTTP
real y los firmadores de `afirma-signers`.
