# 09 — Cliente @firma móvil para Android (Autofirma App 1.9)

> Especificación de comportamiento para reimplementar 1:1 la aplicación Android del Gobierno de España
> «Cliente @firma móvil», publicada como **Autofirma App** (`es.gob.afirma`, versión `1.9`, `versionCode 27`).
> Fuente: repositorio `firma-android`, módulo `afirma-ui-android` (último commit `6f6554b` «Actualización SDK
> objetivo»). Está escrita para que la app se pueda reimplementar sin leer el Java; las clases se citan solo para
> trazabilidad.

## Índice

| § | Contenido |
|---|---|
| 0 | Alcance, convenciones, bibliotecas y mapa de clases; avisos que conviene leer primero |
| 1 | Ficha técnica: identificador, SDK, permisos, manifiesto, seguridad de red, dependencias, compilación |
| 2 | Estructura de la app: pantallas, diálogos, grafo de navegación, arranque, inicio, ajustes, ayudas, idiomas |
| 3 | Firma local de ficheros (selección, formato, firma visible PDF, guardado, resultado, histórico) |
| 4 | Certificados y almacenes (KeyChain, lector USB, tarjetas, caché, avisos, importación, DNIe por NFC) |
| 5 | Firma desde la web (`afirma://`): operaciones, servidor intermedio, cifrado, HTTP, respuestas y errores |
| 6 | Firma por lotes |
| 7 | Preferencias |
| 8 | Catálogo de errores (`AA` + 6 dígitos, `ERR-NN`) |
| 9 | Textos de la interfaz por pantalla e idiomas |
| 10 | Peculiaridades y errores de la app original |
| 11 | Lista de paridad |

---

## 0. Alcance y convenciones

### 0.1 Qué cubre y qué no

Cubre toda la aplicación Android: pantallas, navegación, firma local, gestión de certificados, flujo de usuario del
DNIe por NFC, invocación desde la web y desde otras apps, lotes, preferencias, textos y errores.

Fuera de alcance (se remite a otros documentos):

* El protocolo de la tarjeta (PACE con el CAN, canal seguro, APDU, PIN, `DnieProvider`, `CeresProvider`,
  `AndroidNfcConnection`, `AndroidCCIDConnection`): especificación de JMulticard (`10-dnie-nfc.md`). Aquí
  solo se describe el flujo de pantallas y qué hace la app con cada resultado.
* La estructura de las firmas CAdES/PAdES/XAdES y la trifásica: `02-cms-cades.md`, `04-pades.md`,
  `03-xml-signatures.md`, `01-protocol.md` §10.
* El protocolo `afirma://` del escritorio: `01-protocol.md`. Aquí solo se detallan las **diferencias y añadidos**
  de Android (§5), remitiendo a las secciones de `01`.

### 0.2 Convenciones

* `clave` = recurso de texto de `res/values/strings.xml` (español, idioma de referencia). Los textos de interfaz se
  citan como «texto» (`clave`). §9 lista todos los recursos.
* **Android ≥ 11** significa API 30 (`Build.VERSION_CODES.R`), que es el corte que usa el código para el acceso a
  ficheros. **< 11** = API 23–29.
* «SAF» = Storage Access Framework (`ACTION_OPEN_DOCUMENT` / `ACTION_CREATE_DOCUMENT`).
* ⚠ **Peculiaridad** marca comportamiento sorprendente o erróneo del original que la reimplementación debe decidir
  si replica. §10 los reúne todos.
* Los códigos de error de la app son `AA` + 6 dígitos (`AA500001`), distintos de los `AF…` del escritorio.

### 0.3 Bibliotecas de @firma usadas: 1.9, no 1.9.1

La app compila contra los artefactos Maven `es.gob.afirma:*:1.9`, que corresponden a la etiqueta `v1.9` del
repositorio Java, **no** a la 1.9.1 que describen `01`–`07`. La diferencia importa en el análisis de URLs
(`afirma-core`, paquete `misc.protocol`): en 1.9 no existen los parámetros `cipher` ni `servicetimeout`, la
operación sale del *host* de la URL y la clave DES es la única forma de cifrado. §5.2 detalla todas las
diferencias.

### 0.4 Mapa de clases

| Paquete | Contenido |
|---|---|
| `es.gob.afirma.android` | Actividades (pantallas), `MainApplication`, `MainFragment`, `LocaleHelper`, `KeyEntryCache`, `DeleteCertCacheService`, `IntermediateServerUtil`, `ActiveWaitingThread`, `NfcHelper`, `CheckConnectionsHelper`, adaptadores de listas, `Logger` |
| `…android.gui` | Diálogos (`CustomDialog`, `ChooseCertTypeDialog`, `SelectAliasDialog`, `PinDialog`, `PDFPasswordDialog`, `PDFPasswordVisibleSignDialog`, `SelectCacheMinutesDialog`, `HelpDialog`, `CompatibleDniDialog`, `ConfigNfcDialog`, `MessageDialog`), fragmentos del DNIe y de importación, tareas HTTP (`SendDataTask`, `DownloadFileTask`), `AppConfig` (preferencias), `CertificateInfoForAliasSelect`, selector de ficheros (`FileArrayAdapter`, `FileOption`) |
| `…android.crypto` | Carga de almacenes (`KeyStoreManagerFactory`, `LoadKeyStoreManagerTask`, `LoadNfcKeyStoreManagerTask`, `LoadCertificatesTask`, `LoadDeviceKeystoreAsyncTask`), gestores (`Android4KeyStoreManager`, `AndroidJcaKeyStoreManager`), `SignTask`, `CipherDataManager`, `AndroidHttpManager`, `DnieConnectionManager`, retrollamadas del DNIe |
| `…android.batch`, `…batch.client` | Firma de lotes JSON (`SignBatchFragmentActivity`, `SignBatchTask`, `BatchSigner`, analizadores JSON) |
| `…android.errors` | Catálogo de errores `AA` (`ErrorCategory`, `*Errors`) y cadenas `ERR-NN` (`ErrorManager`) |
| `…android.exceptions`, `…android.util` | Excepciones auxiliares; `FileUtil`, `CertificateUtil`, `Utils`, `WebSignUtil` |
| `com.sun.net.ssl` | Interfaz vacía `HostnameVerifier` para que compilen dependencias de escritorio |

Código muerto (no lo usa nada): `MainApplication` (no declarada en el manifiesto), `MessageDialog`,
`ReadLocalFileTask`, `WebSignUtil`, `GIFView` (ni el GIF
`dni_nfc.gif`), `BatchResult`, `CustomAuthorizeCallback` (la de la app; JMulticard usa la suya), `CanResult.canObtained`,
los layouts `activity_save_data`, `activity_sign_data`, `activity_signed_file`, `dialog_list`, y 41 textos (§9.22).

### 0.5 Leer primero (lo que más sorprende)

1. **Solo servidor intermedio.** En Android no hay WebSocket ni servicio local: AutoScript abre
   `afirma://<op>?…` (o `intent://…;package=es.gob.afirma;end` en Chrome) y la app responde subiendo el resultado
   al `StorageService` (§5).
2. **Operaciones registradas:** `sign`, `cosign`, `countersign`, `batch`, `selectcert`, `save`. No existen
   `signandsave`, `load`, `websocket` ni `service` (§5.3).
3. **XAdES y FacturaE siempre trifásicas** (la app no lleva firmadores XML monofásicos). CMS, XMLDSig, ODF y OOXML
   no están disponibles (§3.7.1).
4. **Solo cifrado DES** con el parámetro `key`; se ignora `cipher` (AES) (§5.9).
5. **Errores con prefijo `AA` y texto localizado**: `ERR-11:=AA500001 - Operacion cancelada` (§5.12).
6. **Los filtros de certificados de la web no se aplican**: se usa el selector del sistema (`KeyChain`) sin
   filtros (§4.3).
7. **La caché de certificado (*sticky*) persiste entre invocaciones** mientras viva el proceso y caduca a los N
   minutos configurados (5 por defecto) (§4.7).
8. **Firma visible pedida por la web**: solo funciona si el usuario elige el PDF en la app; con los datos en `dat`
   la app se cierra por error y con los datos en el sobre (`fileid`) se ignora (§5.5, §10).

---

## 1. Ficha técnica

### 1.1 Identidad y SDK (`app/build.gradle`)

| Elemento | Valor |
|---|---|
| `applicationId` / `namespace` | `es.gob.afirma` |
| `versionName` / `versionCode` | `1.9` / `27` |
| `minSdkVersion` / `targetSdkVersion` / `compileSdk` | 23 (Android 6.0) / 35 / 35 |
| Nombre visible | «Autofirma App» (`app_name`; en euskera «Aplikazio automatikoa» ⚠) |
| Icono | `@mipmap/ic_launcher` y `ic_launcher_round` (adaptativo en API 26+) |
| Java | `sourceCompatibility`/`targetCompatibility` 1.8; `multiDexEnabled true`; `buildConfig true` |
| Compilación | AGP 8.2.2, Gradle 8.2, plugin `org.sonarqube` 3.0; `lint.checkReleaseBuilds false` |
| *Release* | `minifyEnabled false` (sin ofuscar); sin `signingConfigs`: la firma del APK se hace fuera del proyecto |
| Empaquetado | `pickFirsts 'ACRAIZ-SHA2.crt'`, excluye `META-INF/versions/9/OSGI-INF/MANIFEST.MF`; excluye `com/**/package-info.*` de las fuentes |
| `gradle.properties` | `android.useAndroidX=true`, `android.nonTransitiveRClass=false`, `android.nonFinalResIds=false` |

### 1.2 Dependencias y para qué se usan

| Dependencia | Uso en la app |
|---|---|
| `com.google.android.material:material:1.12.0` | `MaterialToolbar`, `BottomSheetDialog` (todos los diálogos propios), `TextInputLayout` (CAN/PIN) |
| `androidx.fragment:fragment:1.8.6` (+ `viewpager2` transitivo) | Fragmentos de inicio, pasos del DNIe y asistente de importación |
| `es.gob.afirma.jmulticard:jmulticard-android:2.0` (sin `support-v4` ni `android`) | `AndroidNfcConnection` (NFC) y `AndroidCCIDConnection` (lector USB) |
| `es.gob.afirma.jmulticard:jmulticard-jse:2.0` | `DnieProvider` (almacén `DNI`), `CeresProvider` (almacén `CERES`), excepciones de PIN/CAN/bloqueo |
| `es.gob.afirma:afirma-core:1.9` | Análisis de URLs `afirma://`, `AOSignerFactory`, `AOPkcs1Signer`, `TriphaseDataSigner`, `Base64`, `AOUtil`, `MimeHelper`, gestor HTTP enchufable |
| `afirma-core-keystores:1.9` (sin JMulticard) | Transitiva; la app no la usa directamente |
| `afirma-crypto-cades`, `-cades-multi`, `-core-pkcs7`, `-core-pkcs7-tsp` 1.9 | CAdES monofásica (firma, cofirma, contrafirma) |
| `afirma-crypto-cadestri-client`, `-xadestri-client`, `-padestri-client` 1.9 | Firmadores trifásicos cliente (CAdEStri, CAdES‑ASiC‑S‑tri, XAdEStri, XAdES‑ASiC‑S‑tri, FacturaEtri, PAdEStri) |
| `afirma-crypto-pdf:1.9` (sin `afirma-lib-itext`) + `es.gob.afirma.lib:afirma-lib-itext-android:1.6` | PAdES monofásica; `PdfReader` para leer el tamaño de página en la firma visible |
| `com.github.mhiew:android-pdf-viewer:3.2.0-beta.3` (PdfiumAndroid) | Vista previa del PDF (`PDFView`) y detección de PDF cifrado (`PdfPasswordException`) |
| `com.google.code.gson:gson:2.10` | Declarada, **no usada** (el JSON de lotes usa `org.json` de Android) |

### 1.3 Permisos y características (`AndroidManifest.xml`)

| Elemento | Uso real |
|---|---|
| `INTERNET` | Servidor intermedio, servidores trifásicos y de lotes, descarga de `dat` por URL |
| `NFC` | DNIe por NFC |
| `ACCESS_NETWORK_STATE` | Declarado, no usado |
| `WRITE_EXTERNAL_STORAGE` | Se pide en tiempo de ejecución solo en Android < 11, antes de firmar un fichero local, importar un certificado, elegir un fichero para la web o guardar datos de la web |
| `USE_CREDENTIALS` | Obsoleto, «por compatibilidad» |
| `org.simalliance.openmobileapiAET.SMARTCARD` | Propietario, para el proveedor AET de tarjetas microSD (§4.4) |
| `uses-feature android.hardware.usb.accessory` | Sin `required="false"` ⚠: en Google Play filtraría dispositivos sin esa característica |
| `supports-screens` | small, normal, large, xlarge, anyDensity |

Atributos de `<application>`: `allowBackup="false"` (las preferencias no se copian), `requestLegacyExternalStorage="true"`,
`supportsRtl="true"`, tema `Theme.AppCompat.NoActionBar`, `usesCleartextTraffic="true"`,
`networkSecurityConfig="@xml/network_security_config"`. Declara también `configChanges="locale|orientation"` en
`<application>`, donde Android lo ignora.

`FileProvider` `androidx.core.content.FileProvider`, autoridad `es.gob.afirma.fileprovider`, no exportado,
`grantUriPermissions`, rutas `files-path name="main" path="/"` y `external-path name="external-storage" path="/"`.
Ningún código lo usa.

### 1.4 Componentes del manifiesto

Todas las actividades salvo `SplashScreenActivity` declaran `screenOrientation="locked"`, y casi todas (también el
splash) llaman además a `Utils.setPortraitSmartphone`: vertical en móviles y orientación libre (`SENSOR`) en
tabletas (pantalla `LARGE` o `XLARGE`).

| Actividad | `exported` | Tema / extras | Filtro de intents |
|---|---|---|---|
| `SplashScreenActivity` | sí | — | `MAIN` + `LAUNCHER` |
| `HomeActivity`, `IntroScreenActivity`, `ConditionsActivity`, `SettingsActivity`, `LanguageActivity`, `PdfSelectPreviewActivity`, `TrustedDomainsActivity`, `SignsRecordActivity`, `FaqActivity`, `ActivateDnieWithNFCHelpActivity`, `VisibleSignHelpActivity`, `TrustedDomainsHelpActivity`, `ImportCertsHelpActivity`, `LegalActivity`, `PrivacyPolicyActivity`, `VersionActivity`, `CertImportInstructionsActivity`, `IntroUseDnieActivity`, `StepsInsertDataDnieActivity`, `SignConfigurationActivity` | sí ⚠ (sin filtro: cualquier app puede abrirlas) | — | — |
| `NFCDetectorActivity` | no | `label=nfc_approach` | `android.nfc.action.TECH_DISCOVERED` con `nfc_tech_list` = `IsoDep`, `NfcA`, `NfcB` (en la práctica se usa *foreground dispatch*, §4.9.6) |
| `FileChooserActivity` | no (implícito) | `configChanges orientation\|screenSize`, `label=title_activity_cert_chooser` | — |
| `LocalSignActivity` | no | `Theme.Transparent`, `label=title_activity_save_data` | — |
| `WebSignActivity` | sí | `Theme.Transparent`, `label=title_activity_sign_data` | acciones `VIEW` y `es.gob.afirma.android.SIGN_SERVICE`; categorías `DEFAULT`, `BROWSABLE`; `scheme=afirma`, `host` = `sign` \| `cosign` \| `countersign` |
| `WebSignBatchActivity` | sí | `Theme.Transparent`, `label=title_activity_sign_batch` | acciones `VIEW` y `es.gob.afirma.android.SIGN_BATCH_SERVICE`; `afirma://batch` |
| `WebSelectCertificateActivity` | sí | `Theme.Transparent`, `label=title_activity_select_certificate` | `VIEW`; `afirma://selectcert` |
| `WebSaveDataActivity` | sí | `Theme.Transparent`, `finishOnCloseSystemDialogs`, `finishOnTaskLaunch`, `label=title_activity_save_data` | `VIEW`; `afirma://save` |

`Theme.Transparent`: ventana translúcida, flotante, sin título ni oscurecimiento: las operaciones web y la firma
local se ven como diálogos sobre la pantalla anterior (el navegador o el inicio).

### 1.5 Seguridad de red (`res/xml/network_security_config.xml`)

`base-config cleartextTrafficPermitted="true"` con anclas de confianza: `system`, **`user`** (las CA instaladas por
el usuario también valen, cosa que Android no hace por defecto desde API 24) y 26 certificados incluidos en
`res/raw`:

| Fichero | Sujeto |
|---|---|
| `ac_aca_ca3.crt`, `ac_aca_root.crt` | ACA CA3; Autoridad de Certificacion de la Abogacia |
| `ac_acc_root.cer`, `ac_acc_sectorpublic.cer` | EC-ACC; EC-SectorPublic (AOC Cataluña) |
| `ac_accv_110.crt`, `ac_accv_110_sha2.crt`, `ac_accv_root.crt` | ACCVCA-110 (dos versiones); ACCVRAIZ1 |
| `ac_anf_root.cer`, `ac_anf_secureserver.cer` | ANF Secure Server Root CA; ANF Secure Server CA |
| `ac_eadtrust_qualifiedweb_4096.cer`, `…_8192.cer`, `ac_eadtrust_root_4096.cer`, `…_8192.cer` | EADTrust RSA 4096/8192 SubCA y Root CA For Qualified Web DV/OV Cert 2019 |
| `ac_firmaprofesional_infraestructura.cer`, `…_root.cer`, `…_root256.crt`, `…_secureweb2021.cer` | AC Firmaprofesional - INFRAESTRUCTURA; Autoridad de Certificacion Firmaprofesional (dos); AC Firmaprofesional - Secure Web 2021 |
| `ac_fnmt_componentes.cer`, `ac_fnmt_root.cer`, `ac_fnmt_servseguros_root.cer`, `ac_fnmt_servseguros_tipo1.cer` | FNMT AC Componentes Informáticos; AC RAIZ FNMT-RCM; AC RAIZ FNMT-RCM SERVIDORES SEGUROS; AC SERVIDORES SEGUROS TIPO1 |
| `ac_izenpe_root.cer`, `ac_izenpe_ssl.cer` | Izenpe.com; CA de Certificados SSL EV |
| `ac_logalty_g2.cer`, `ac_logalty_root.cer` | Logalty Qualified CA G2; Logalty CA ROOT 03 |

Encima de esto, `AndroidHttpManager` puede desactivar la validación TLS (§5.10).

### 1.6 Recursos no textuales

* Fuentes: Merriweather Bold (títulos de barra, estilo `ToolbarTitle` 18 sp), Nunito Sans y Nunito Sans Bold.
* Colores (`values/colors.xml`): rojo de botones `#95191C`, barra `#EFF3F5`, gris claro `#F9FAFB` (fila
  seleccionada), azul `#0000FF`, gris `#B5A19F`; `primary #9A28A1` y `primaryDark #5C1760` sin uso visible.
  Botones: rojo (habilitado, texto blanco), gris (deshabilitado, texto `#767676`), negro (con foco).
* Imágenes: logos (Gobierno de España, «Financiado por la Unión Europea», «Plan de Recuperación», «España Digital
  2026», Autofirma), ilustraciones de ayuda (`can_example`, `pin_dni`, `read_dni_screen`, `dnie_with_nfc_help_2`,
  `visible_sign_help_3`, `step_1_import_cert`, `step_2_import_cert`) e iconos del selector de ficheros.
* `assets/`: textos legales en HTML por idioma, `aviso_<idioma>.html` y `politica_<idioma>.html` con
  `<idioma>` ∈ {`es`, `en`, `ca`, `gl`, `eu`, `ca-ES-valencia`} (§2.12).

### 1.7 Registro (logs)

`Logger` envuelve `android.util.Log` y **no escribe nada en *release*** (`BuildConfig.DEBUG == false`). La etiqueta
es siempre `es.gob.afirma`. No hay fichero de log ni operación para recuperarlo.

---

## 2. Estructura de la app y navegación

### 2.1 Pantallas

| Actividad (layout) | Título de la barra | Qué muestra |
|---|---|---|
| `SplashScreenActivity` (`afirma_splash_screen_file`) | — | Logo del Gobierno, separador, logos FUE/PRTR/ED2026, rueda de progreso, logo de Autofirma. 2 s |
| `IntroScreenActivity` (`intro_screen_file`) | — | Ilustración `read_dni_screen`, «Firma fácil y segura» (`intro_title`), `intro_text`, botón «Comenzar» (`start`) |
| `ConditionsActivity` (`activity_conditions`) | «Aceptación de textos legales» | Selector de idioma, WebView con política + aviso legal, dos casillas, botón «Aceptar» |
| `HomeActivity` + `MainFragment` (`activity_home`, `fragment_main`) | logo de Autofirma; iconos Información y Ajustes | Logo, «Te damos la bienvenida», `presentation_text`, «Seleccione una opción», botones «Firmar fichero» y «Añadir nuevo certificado» |
| `SettingsActivity` (`activity_settings`) | «Ajustes» | Tres secciones de enlaces (§2.6) y logos FUE/PRTR/ED2026 |
| `LanguageActivity` (`activity_language`) | «Idioma» | Lista de seis idiomas con marca en el actual |
| `SignConfigurationActivity` (`activity_sign_configuration`) | «Configuración de firma» | Tres interruptores, botón de minutos de caché, «Guardar» |
| `TrustedDomainsActivity` (`activity_trusted_domains`) | «Dominios de confianza» | Interruptor «Validar conexiones SSL», texto multilínea de dominios, «Guardar» |
| `SignsRecordActivity` (`activity_signs_record`) | «Histórico de firmas» + icono papelera | Lista de firmas o «No se encuentran registros» |
| `FaqActivity` (`activity_faq`) | «Preguntas frecuentes» | Lista desplegable de 3 preguntas |
| `ActivateDnieWithNFCHelpActivity` (`activity_use_dnie_nfc_help`) | «Activar el uso del DNIe por NFC» | Texto, «Ir a configuración», texto, imagen |
| `VisibleSignHelpActivity` (`activity_visible_sign_help`) | «Cómo hacer firma visible» | Textos 1–2, «Ir a configuración», texto 3, imagen, texto 4 |
| `TrustedDomainsHelpActivity` (`activity_trusted_domains_help`) | «Dominios de confianza» | Textos 1–2, «Ir a configuración» |
| `ImportCertsHelpActivity` (`activity_import_certs_help`) | «¿Cómo instalar certificados?» | Textos 1–3, «Añadir un certificado» |
| `LegalActivity` (`activity_legal`) | «Aviso legal» | WebView con `aviso_<idioma>.html` |
| `PrivacyPolicyActivity` (`activity_policy`) | «Política de privacidad» | WebView con `politica_<idioma>.html` |
| `VersionActivity` (`activity_version`) | «Versión v1.9» | Cuatro párrafos y tres enlaces |
| `CertImportInstructionsActivity` (`activity_intro_import_cert`) | (solo flecha atrás) | Asistente de 2 páginas (§4.8) |
| `LocalSignActivity` (sin layout) | — | Transparente; orquesta la firma local (§3) |
| `FileChooserActivity` (`activity_file_chooser`) | (título de ventana) | Selector de ficheros propio para Android < 11 (§3.3) |
| `PdfSelectPreviewActivity` (`activity_pdfview`) | «Firma visible» | Vista previa del PDF y selección de área (§3.5) |
| `IntroUseDnieActivity` (`activity_intro_sign_dnie`) | (flecha atrás) | «Identificación con DNIe» (§4.9) |
| `StepsInsertDataDnieActivity` (`activity_steps_sign_dnie`) | (flecha atrás y X) | Pasos 1–3 del DNIe (§4.9) |
| `NFCDetectorActivity` (`activity_detect_nfc`) | — | «Buscando DNIe» (§4.9.6) |
| `WebSignActivity`, `WebSignBatchActivity`, `WebSelectCertificateActivity`, `WebSaveDataActivity` (sin layout) | — | Transparentes; operaciones web (§5, §6) |

### 2.2 Diálogos y fragmentos

| Componente | Tipo | Uso |
|---|---|---|
| `CustomDialog` (`custom_dialog`) | *Bottom sheet* expandida, no cancelable | Diálogo genérico: icono, título, mensaje, botón principal (por defecto «Entendido») y, opcional, un botón secundario subrayado (por defecto «Cancelar»). Ambos botones lo ocultan salvo que se les asigne otra acción |
| `HelpDialog` (`help_dialog`) | *Bottom sheet*, cancelable tocando fuera | Ayuda de inicio (§2.5) |
| `ConfigNfcDialog` | `AlertDialog` (fragmento) | Pregunta de primera ejecución sobre el NFC (§2.5) |
| `SelectCacheMinutesDialog` (`select_cache_minutes_dialog`) | *Bottom sheet* | Minutos de caché (§2.8) |
| `ChooseCertTypeDialog` (`choose_cert_type_dialog`) | *Bottom sheet* | Certificado electrónico / DNI electrónico (§4.2) |
| `SelectAliasDialog` (`dialog_aliases`) | `AlertDialog` (fragmento) | Lista de certificados de un almacén JCA (§4.5) |
| `PinDialog` (`dialog_pin`) | `AlertDialog` (fragmento) | PIN de la tarjeta microSD AET (§4.4) |
| `PDFPasswordDialog`, `PDFPasswordVisibleSignDialog` (`dialog_pdf_password`) | *Bottom sheet* | Contraseña de PDF (§3.5.6, §3.7.3) |
| `CompatibleDniDialog` (`compatible_dni_dialog`) | *Bottom sheet* | «¿Es mi DNI compatible?» (§4.9.2) |
| Diálogo «DNIe bloqueado» | `AlertDialog` | §4.5 |
| `ProgressDialog` (Android) | Modal indeterminado, sin título | «Cargando almacén de claves», «Cargando certificados», «Realizando firma», «Firmando», «Cargando almacén de claves del dispositivo» |
| `MainFragment` | Fragmento | Contenido de inicio |
| `InsertDataDnieStep1/2/3Fragment` | Fragmentos | Pasos del DNIe |
| `ImportCertStep1/2Fragment` | Fragmentos | Imágenes del asistente de importación |
| Selector del sistema `KeyChain.choosePrivateKeyAlias` | Sistema | Elección de certificado del almacén de Android |
| Instalador `KeyChain.createInstallIntent` | Sistema | Instalación de `.p12/.pfx` |
| Selectores SAF | Sistema | Abrir y crear documentos |

### 2.3 Grafo de navegación

```
                         ┌───────────────┐ 2 s
 Icono ─────────────────►│ Splash        ├──┬─(intro no vista)──────────► Intro ──«Comenzar»──► Condiciones
                         └───────────────┘  ├─(intro vista, cond. no)───────────────────────► Condiciones
                                            └─(ambas vistas)──────────────────────────┐            │«Aceptar»
                                                                                       ▼            ▼
                                      ┌────────────────────────── Inicio (HomeActivity + MainFragment) ◄─────┐
                                      │ «Firmar fichero» ─► LocalSign ─► [selector] ─► [vista previa PDF] ─► │
                                      │                      [almacén/certificado/DNIe] ─► [guardar] ─► Inicio
                                      │ «Añadir nuevo certificado» ─► Instrucciones (2 pág.) ─► Inicio ─►    │
                                      │                      [selector .p12] ─► [instalador del sistema]     │
                                      │ (i) ─► HelpDialog                                                    │
                                      │ ⚙ ─► Ajustes ──┬─ Idioma (atrás → Ajustes nuevo)                     │
                                      │                ├─ Configuración de firma ─► SelectCacheMinutes       │
                                      │                ├─ Dominios de confianza                              │
                                      │                ├─ Histórico de firmas                                │
                                      │                ├─ Preguntas frecuentes                               │
                                      │                ├─ Ayuda DNIe NFC ─► Configuración de firma           │
                                      │                ├─ Ayuda firma visible ─► Configuración de firma      │
                                      │                ├─ Ayuda dominios ─► Dominios de confianza            │
                                      │                ├─ Ayuda certificados ─► Instrucciones de importación │
                                      │                ├─ Declaración de accesibilidad (navegador)           │
                                      │                ├─ Aviso legal / Política de privacidad               │
                                      │                └─ Versión ─► 3 enlaces (navegador)                   │
                                      │       atrás en Ajustes ─► Inicio nuevo ──────────────────────────────┘
                                      └──────────────────────────────────────────────────────────────────────
 Navegador / otra app ─► afirma://sign|cosign|countersign ─► WebSign ─► [descarga] [selector] [vista previa]
                         afirma://batch ─► WebSignBatch       [almacén/certificado/DNIe] ─► subir resultado ─► cerrar app
                         afirma://selectcert ─► WebSelectCertificate
                         afirma://save ─► WebSaveData ─► [crear documento SAF]
 Flujo del almacén (todas las firmas): [ChooseCertType] ─► KeyChain | lector USB | DNIe: Intro DNIe ─► Pasos 1-3 ─► Buscando DNIe
```

### 2.4 Arranque

1. No hay clase `Application` propia en uso: existe `MainApplication` (aplicaría el idioma al arrancar), pero el
   manifiesto no la declara (`<application>` sin `android:name`), así que es código muerto. ⚠ Si se activase
   fallaría: llama a `attachBaseContext(this)` dentro de `onCreate`, y Android no permite fijar el contexto base dos
   veces.
2. El idioma se aplica **por actividad**: casi todas sobrescriben `attachBaseContext` con `LocaleHelper.onAttach`,
   que lee `localeConfig` (defecto `es`), lo vuelve a guardar, fija `Locale.setDefault`, devuelve un contexto con
   ese idioma y **regenera los textos de los catálogos de error** (§8). La primera lectura de preferencias inicializa
   además el almacén estático de `AppConfig`, del que dependen los accesos posteriores sin contexto.
   ⚠ No lo hacen `SplashScreenActivity`, `IntroScreenActivity`, `LegalActivity`, `PrivacyPolicyActivity` ni
   `WebSaveDataActivity`: sus textos siguen el idioma del sistema (el HTML legal sí usa el idioma guardado). Y si
   `WebSaveDataActivity` arranca en un proceso nuevo (lanzada desde el navegador), los catálogos de error están
   vacíos y cualquier ruta de error que los consulte (cancelar, fallo de escritura) termina en
   `NullPointerException` (§5.7, §10).
3. **Splash** (`SplashScreenActivity`): muestra el layout y, a los **2000 ms**, decide destino y se cierra:
   * `skipIntroScreen == false` → Bienvenida.
   * `skipIntroScreen == true` y `skipConditionsScreen == false` → Condiciones.
   * ambos `true` → Inicio.
4. **Bienvenida** (`IntroScreenActivity`): «Comenzar» pone `skipIntroScreen = true` y abre Condiciones (sin cerrar
   la bienvenida). Atrás no hace nada.
5. **Condiciones** (`ConditionsActivity`):
   * Al crearse aplica **siempre** el español (`changeLang("es")`), y el selector, que arranca en la posición 0,
     vuelve a elegir español. ⚠ Por tanto, cada vez que aparece esta pantalla el idioma guardado pasa a `es`.
   * Selector «Idioma» con «Español», «English», «Catalá», «Galego», «Euskera», «Valencià» →
     `es`, `en`, `ca`, `gl`, `eu`, `ca-ES-valencia`. Al elegir: guarda el idioma, actualiza los textos de la pantalla
     con los recursos de ese idioma (título, «Idioma», casillas, botón) y recarga el WebView con
     `politica_<idioma>.html` seguido de `aviso_<idioma>.html` (concatenados, cargados como `text/html` en Base64).
     Con foco, el selector cambia a borde blanco; sin foco, negro.
   * Casillas «He leído y estoy de acuerdo con la Política de Privacidad» y «He leído y estoy de acuerdo con el
     Aviso Legal y los Términos y Condiciones de Uso». Su estado sobrevive a la rotación.
   * «Aceptar» solo está habilitado con las dos marcadas (fondo rojo y texto blanco; si no, gris y `#767676`).
     Pulsarlo pone `skipConditionsScreen = true` y abre Inicio. Atrás no hace nada.

### 2.5 Inicio (`HomeActivity` + `MainFragment`)

* Barra con el logo de Autofirma y dos iconos: **Información** (abre `HelpDialog`) y **Ajustes** (abre
  `SettingsActivity`). Los títulos de los elementos de menú están fijos en español en el XML: «Informacion»,
  «Ajustes».
* Atrás no hace nada.
* Extras que admite el intent (los borra tras leerlos):

| Extra | Efecto |
|---|---|
| `showSigningResult=true` + `errorSigning=false` | `CustomDialog` con icono de verificación, «Fichero firmado» / «El fichero ha sido firmado correctamente.» / «Entendido» |
| `showSigningResult=true` + `errorSigning=true` + `errorTitle`, `errorMessage` | `CustomDialog` con icono de aviso, el título y mensaje recibidos, «Entendido» |
| `startImportCert=true` | Arranca el selector de certificado a importar (§4.8) |
| `CLOSE_ACTIVITY=true` | `finishAffinity()`: cierra todas las actividades de la tarea (se usa para «cerrar la app» tras una operación web) |

* **Primera ejecución**: si el dispositivo tiene NFC (`NfcManager.getDefaultAdapter() != null`) y
  `firstExecution == true`, muestra `ConfigNfcDialog`: «Se ha detectado que su dispositivo dispone de NFC. ¿Desea
  habilitarlo para la firma con el DNIe por NFC?» con «No» y «Sí». «Sí» pone `useNfc = true`. Al mostrarse y al
  cerrarse pone `firstExecution = false`.
* Botón «Firmar fichero»: en Android < 11, si no hay permiso de escritura, lo pide; concedido → firma local;
  denegado → *toast* largo «Es necesario conceder permisos sobre la memoria para hacer firmas locales»
  (`nostorageperm`). Con permiso (o Android ≥ 11) abre `LocalSignActivity` (§3).
* Botón «Añadir nuevo certificado»: misma comprobación de permiso; abre `CertImportInstructionsActivity` (§4.8).
* **`HelpDialog`**: título «¿Para qué sirve Autofirma?» con botón X; texto `what_is_autofirma_for_desc`;
  «¿Cómo instalar certificados?»; dos líneas con icono: `load_cert` y `allowed_extensions`; botón «Más
  información» oculto (`visibility=gone`, y si se mostrase solo cerraría); botón «Entendido». Todos cierran.

### 2.6 Ajustes (`SettingsActivity`)

Atrás (botón del sistema o flecha de la barra) **abre un `HomeActivity` nuevo** en lugar de volver ⚠.

| Sección | Elemento (icono) | Acción |
|---|---|---|
| «MI CONFIGURACIÓN» | «Idioma» (globo) + etiqueta a la derecha con la abreviatura en mayúsculas del idioma actual: `ES`, `EN`, `CA`, `GL`, `EU`, `VA` | `LanguageActivity` |
| | «Configuración de firma» | `SignConfigurationActivity` |
| | «Dominios de confianza» | `TrustedDomainsActivity` |
| | «Histórico de firmas» (reloj) | `SignsRecordActivity` |
| «AYUDA» | «Preguntas frecuentes» | `FaqActivity` |
| | «Activar el uso del DNIe por NFC» (tarjeta) | `ActivateDnieWithNFCHelpActivity` |
| | «Cómo hacer firma visible» | `VisibleSignHelpActivity` |
| | «Cómo configurar dominios de confianza» | `TrustedDomainsHelpActivity` |
| | «Cómo instalar certificados» (bandeja) | `ImportCertsHelpActivity` |
| «INFORMACIÓN GENERAL» | «Declaración de accesibilidad» + icono de enlace externo | Abre en el navegador `accessibility_statement_url` (por idioma: `http://estaticos.redsara.es/comunes/clientefirmaandroid/1/8/0/declaracion_accesibilidad.pdf`; en otros idiomas `…/translated(en\|ca\|gl\|eu\|val)_declaracion_accesibilidad.pdf`) |
| | «Aviso legal» | `LegalActivity` |
| | «Política de privacidad» | `PrivacyPolicyActivity` |
| | «Versión v1.9» (`appversion` con `BuildConfig.VERSION_NAME`) | `VersionActivity` |
| Pie | Logos FUE, PRTR, ED2026 en color | — |

### 2.7 Idioma (`LanguageActivity`, `LanguageAdapter`, `LocaleHelper`)

* Lista con «Español», «English», «Catalá», «Galego», «Euskera», «Valencià» (cada nombre en el idioma actual de la
  interfaz, aunque en todos los idiomas son iguales salvo detalles). La fila del idioma actual lleva fondo
  `#F9FAFB` y una marca roja.
* Tocar una fila: posición 1 → `en`, 2 → `ca`, 3 → `gl`, 4 → `eu`, 5 → `ca-ES-valencia`, cualquier otra → `es`.
  Guarda el idioma y recrea la actividad (`recreate()`).
* Atrás **abre un `SettingsActivity` nuevo** ⚠.
* `LocaleHelper.setLocale(tag)`: guarda `localeConfig`, construye `Locale.forLanguageTag(tag)`, lo pone como
  predeterminado del proceso, actualiza la configuración (idioma y dirección de texto) y regenera los textos de
  todos los catálogos de error con los recursos del nuevo idioma. En API < 24 usa `updateConfiguration`.
* Recursos: `values` (es), `values-en`, `values-ca`, `values-gl`, `values-eu`, `values-b+ca+ES+valencia`. El mapa
  interno también conoce `fr` («Français»), pero no hay recursos ni forma de elegirlo.

### 2.8 Configuración de firma (`SignConfigurationActivity`)

| Control | Preferencia | Inicial |
|---|---|---|
| Interruptor «Permitir firmar con DNIe por NFC» | `useNfc` | Valor guardado; **deshabilitado** si el dispositivo no tiene NFC |
| Interruptor «Hacer firma visible» | `padesVisibleSignature` | Valor guardado (defecto `false`) |
| Interruptor «Ofuscar identificadores de usuario de los certificados de las firmas visibles» | `padesObfuscateCertInfo` | Valor guardado (defecto `true`) |
| «Minutos para la eliminación de caché de certificado» + botón «`N` Min» | `stickySignatureTimeout` | Valor guardado (defecto 5) |
| Botón «Guardar» | — | Guarda los cuatro valores y muestra `CustomDialog` «Cambios guardados» / «Los cambios se han guardado correctamente.» / «Entendido» |

Nada se guarda sin pulsar «Guardar». Atrás vuelve sin guardar.

**`SelectCacheMinutesDialog`**: título «Selecciona un valor en minutos» con X; lista 5, 15, 30, 60, 120; la fila del
5 lleva la etiqueta «Por defecto»; la seleccionada lleva fondo gris claro y marca roja (al abrir se marca el valor
actual). «Seleccionar» copia el valor al botón («`N` Min») y a una variable estática; no persiste hasta «Guardar».
Tocar fuera o la X cierra sin cambios.

### 2.9 Dominios de confianza (`TrustedDomainsActivity`)

* Interruptor «Validar conexiones SSL» (`validateSslChecks`, defecto `true`): **se guarda al instante** al
  pulsarlo.
* Texto «Introduzca en el siguiente apartado los dominios de confianza para la aplicación», etiqueta «Dominios de
  confianza» y un campo multilínea con el valor de `secureDomainsList` (un dominio por línea).
* «Guardar»: recorta el texto; si no está vacío, valida cada línea no vacía (recortada) con la expresión
  `^[a-z0-9*][a-z0-9-.:]{1,61}[a-z0-9*]$` sin distinguir mayúsculas (3 a 63 caracteres; `*` solo al principio o al
  final; dentro, letras, dígitos, `-`, `.` y `:`).
  * Todas válidas → guarda el texto recortado (si está vacío, **borra** la preferencia) y muestra «Cambios
    guardados».
  * Alguna inválida → no guarda y muestra `CustomDialog` con icono de aviso, «¡Algo salió mal!» y
    «AA200700 - El dominio "`<línea>`" tiene un formato incorrecto.», botón «Entendido».
* ⚠ La ayuda (`trusted_domains_help_text_1`) dice que se separen **por comas**, pero la app separa **por saltos de
  línea**; una coma hace fallar la validación.
* Semántica y reglas de coincidencia: §5.10.

### 2.10 Histórico de firmas (`SignsRecordActivity`)

Ver formato del fichero en §3.10. La pantalla:

1. Lee `signsRecord.txt` línea a línea, separa por `;` y crea un registro con los 5 primeros campos. ⚠ Una línea
   con menos de 5 campos aborta la lectura del resto (la excepción se captura fuera del bucle).
2. Ordena de más reciente a más antigua por la fecha `dd-MM-yyyy HH:mm:ss` (si no se puede leer una fecha, la
   comparación da 0).
3. Cada fila: la fecha y una descripción según tipo y operación (`sign` → «Firma», `cosign` → «Cofirma»,
   `countersign` → «Contrafirma»; los nombres `null` o `"null"` cuentan como ausentes):

| Tipo | Aplicación y fichero | Solo aplicación | Solo fichero | Ninguno |
|---|---|---|---|---|
| `LOCAL` | — | — | «`<op>` local del fichero `<fichero>`» (siempre esta forma) | — |
| `WEB` | «`<op>` web solicitada por `<app>` del fichero `<fichero>`» | «`<op>` web solicitada por `<app>`» | «`<op>` web del fichero `<fichero>`» | «`<op>` web» |
| `APP` | «`<op>` solicitada por `<app>` del fichero `<fichero>`» | «`<op>` solicitada por `<app>`» | «`<op>` solicitada desde otra aplicación del fichero `<fichero>`» | «`<op>` realizada desde otra aplicación» |
| `BATCH` | — | «Firma de lote web solicitada por `<app>`» | — | «Firma de lote» |
| `BATCH_APP` | — | «Firma de lote solicitada por `<app>`» | — | «Firma de lote» |

4. Si no hay registros se muestra «No se encuentran registros».
5. Icono papelera («Eliminar»): sin registros → `CustomDialog` papelera roja «No se encuentran registros» / «No hay
   firmas registradas que eliminar.» / «Aceptar». Con registros → «Eliminar histórico» / «Si eliminas el histórico
   no podrás recuperarlo.» con botón «Eliminar histórico» (vacía la lista y deja el fichero vacío) y «Cancelar».

### 2.11 Ayudas y preguntas frecuentes

* **`FaqActivity`**: lista desplegable con `question_1..3`; cada una tiene un hijo con `response_1..3` interpretado
  como HTML (`Html.fromHtml`; la respuesta 1 usa `<p>`). Chevron abajo/arriba según estado.
* **Ayuda DNIe NFC**: `dnie_with_nfc_help_text_1`, botón «Ir a configuración » → `SignConfigurationActivity`,
  `dnie_with_nfc_help_text_2`, imagen.
* **Ayuda firma visible**: `visible_sign_help_text_1`, `…_2`, «Ir a configuración » → `SignConfigurationActivity`,
  `…_3`, imagen, `…_4`.
* **Ayuda dominios**: `trusted_domains_help_text_1`, `…_2`, «Ir a configuración » → `TrustedDomainsActivity`.
* **Ayuda certificados**: `import_certs_help_text_1..3`, «Añadir un certificado » → `CertImportInstructionsActivity`
  (sin esperar resultado).

Las cuatro pantallas tienen flecha atrás normal (vuelven a Ajustes).

### 2.12 Información general

* **Aviso legal** / **Política de privacidad**: WebView con el HTML del idioma guardado (`aviso_<idioma>.html` o
  `politica_<idioma>.html`), leído línea a línea y concatenado **sin** saltos de línea, cargado como Base64 sin
  relleno. Si falta el fichero, se muestra vacío.
* **Versión**: título «Versión v1.9»; párrafos `version_desc_p1` (con la versión), `…_p2`, enlace
  `https://eupl.eu/1.1/es`, `…_p3`, enlace `http://forja-ctt.administracionelectronica.gob.es`, `…_p4`, enlace
  `https://administracionelectronica.gob.es/ctt/clienteafirma/mas#.Xxp7T0I7mhc`. Los enlaces se abren en el
  navegador.

### 2.13 Pila de actividades y botón Atrás

| Pantalla | Atrás |
|---|---|
| Splash | por defecto (sale) |
| Bienvenida, Condiciones, Inicio | **ignorado** |
| Ajustes | abre un `HomeActivity` **nuevo** (la pila crece) |
| Idioma | abre un `SettingsActivity` **nuevo** |
| Resto de pantallas de ajustes/ayuda | vuelve |
| `CertImportInstructionsActivity` | página 2 → página 1; página 1 → vuelve |
| `StepsInsertDataDnieActivity` | paso 3 → paso 2, paso 2 → paso 1, paso 1 → cancela (§4.9) |
| `IntroUseDnieActivity` | `RESULT_CANCELED` |
| `FileChooserActivity` | sube un directorio; en el inicial, cancela |
| Operaciones web | `sign`, `selectcert`, `batch`: envían cancelación `ERR-11` a la web y cierran (§5.12); `save`: cierra sin responder (fuera del diálogo de guardado, cuya cancelación sí envía `ERR-11`) |

Tras una firma local, la app abre un `HomeActivity` nuevo encima de la pila sin cerrar el anterior ni
`LocalSignActivity` (§3.9).

---

## 3. Firma local de ficheros

`LocalSignActivity` (transparente) extiende `SignFragmentActivity` → `LoadKeyStoreFragmentActivity`. Se abre desde
«Firmar fichero» (§2.5) y encadena: elegir fichero → (vista previa PDF) → almacén y certificado (§4) → firma →
guardar → resultado.

### 3.1 Selección del fichero

Al crearse (si no está ya firmando):

| Versión | Selector |
|---|---|
| Android ≥ 11 | SAF `ACTION_OPEN_DOCUMENT`, categoría `OPENABLE`, tipo `*/*` |
| Android < 11 | `FileChooserActivity` (§3.3) con título «Seleccione el fichero a firmar» (`title_activity_choose_sign_file`), directorios excluidos de §3.3 y **sin** filtro de extensiones |

Resultado:

* Cancelado → la actividad se cierra sin mensaje (vuelve a Inicio).
* Android ≥ 11: nombre = `DISPLAY_NAME` del proveedor (si no hay, el último segmento de la ruta del URI);
  contenido = bytes del URI; y además se copia a un **fichero temporal** en el directorio de caché con el nombre
  original (`FileUtil.from`: `createTempFile(<base>_temp, <ext>)`, renombrado al nombre original, sustituyendo
  uno anterior; `deleteOnExit`). Su ruta se usa para la vista previa PDF y su nombre para el histórico.
* Android < 11: ruta absoluta devuelta por el selector; se lee el fichero.
* `OutOfMemoryError` al leer → Inicio con error «¡Algo salió mal!» / «AA200105 - El fichero seleccionado es
  demasiado grande y no hay memoria suficiente para completar la operación de lectura».
* `IOException` → Inicio con error «AA200102 - Hemos intentado procesar tu solicitud, pero no ha podido ser
  completada con éxito. Por favor revisa la documentación.».

### 3.2 Permisos

En Android < 11 el permiso `WRITE_EXTERNAL_STORAGE` se pide antes, en Inicio (§2.5). En Android ≥ 11 no se pide
ningún permiso (todo va por SAF).

### 3.3 `FileChooserActivity` (solo Android < 11)

`ListActivity` propia. Extras de entrada: `es.gob.afirma.android.title` (título de ventana; con el tema sin barra
puede no verse), `es.gob.afirma.android.exts` (lista separada por comas, p. ej. `.p12,.pfx`),
`es.gob.afirma.android.excludedDirs` (nombres de directorio a ocultar).

* Directorio inicial: el almacenamiento externo si está montado (`Environment.getExternalStorageDirectory()`); si
  no, `Environment.getDownloadCacheDirectory()`. Su **nombre** se recuerda como «inicial».
* Cabecera: «Directorio actual: `<nombre>`» (`file_chooser_directorio_actual`), marcada como encabezado de
  accesibilidad.
* Contenido de un directorio:
  * Se omiten entradas cuyo nombre empieza por `.`.
  * Directorios: se muestran salvo que su nombre esté en la lista de excluidos (comparación exacta, en cualquier
    nivel). Lista usada por la firma: `cache`, `config`, `d`, `dev`, `etc`, `lib`, `proc`, `sbin`, `sys`, `system`,
    `LOST.DIR`, `log`, `Android`.
  * Ficheros (y directorios excluidos ⚠, que caen en esta rama): sin filtro, todos; con filtro, los que terminan
    (en minúsculas) por alguna de las extensiones.
  * Orden: directorios y luego ficheros, cada grupo por nombre sin distinguir mayúsculas.
  * Si el **nombre** del directorio actual difiere del inicial, primero una entrada `..` que apunta al padre.
    ⚠ Un subdirectorio que se llame igual que el inicial (p. ej. `0`) no muestra `..` y Atrás cancela.
* Fila (`array_adapter_file_chooser`): icono (carpeta, carpeta‑atrás o fichero), nombre, y segunda línea:
  «Directorio padre» (para `..`), «Directorio», o «Tamaño: `<tamaño>`». Tamaño: `< 1024` → «`N` bytes»;
  `< 1024 KiB` → «`N` KB» con `N = bytes/1024`; si no, «`M`,`FF` MB» con `M = KiB/1024` y `FF` = los dos primeros
  caracteres de `(KiB % 1024)` en decimal ⚠ (no es una fracción real). Los enteros llevan punto de millares cada
  tres dígitos. Descripciones de accesibilidad: «Volver a directorio padre», «Directorio `<n>`», «Fichero `<n>`».
* Tocar un directorio entra en él; tocar un fichero devuelve `RESULT_OK` con el extra `filename` = ruta absoluta.
* Atrás: si el nombre del actual es el inicial → `RESULT_CANCELED`; si no, sube al padre.
* Conserva el directorio actual y el inicial al rotar.

### 3.4 Formato y parámetros

* **Formato**: si el nombre del fichero termina en `.pdf` (sin distinguir mayúsculas) → `PAdES`; en cualquier otro
  caso → `CAdES`. No se mira el contenido: un PDF renombrado se firma en CAdES y viceversa.
* **Operación**: siempre firma (`SIGN`, guardada como `sign`); nunca cofirma ni contrafirma aunque el fichero ya sea
  una firma.
* **Algoritmo**: `SHA256`, compuesto con el tipo de clave al firmar: `SHA256withRSA`, `SHA256withECDSA`
  (`EC…`) o `SHA256withDSA` (otro tipo → error «Tipo de clave de firma no soportado»).
* **ExtraParams**: siempre `mode=implicit` (también en PAdES, donde no tiene efecto). En PAdES visible, además los
  de §3.5.5. No se añade política, sello de tiempo ni nada más: valen los valores por defecto de `02-cms-cades.md`
  y `04-pades.md`.
* Si es PAdES **y** la preferencia `padesVisibleSignature` está activa → vista previa (§3.5). Si no → firma directa
  (§3.6).

### 3.5 Firma visible en PDF (`PdfSelectPreviewActivity`)

Se usa en la firma local (si la preferencia lo pide) y en la web (§5.5). Extras de entrada: `filePath` (ruta del
PDF; obligatoria) e `isRequiredVisibleSignature` (booleano, solo web con `visibleSignature=want`).

#### 3.5.1 Pantalla

* Barra «Firma visible» con flecha atrás (= cancelar, `RESULT_CANCELED`).
* Texto «Seleccione el área de firma».
* Vista del PDF (`PDFView`, Pdfium) que muestra **una página**: `defaultPage(página)`, renderizado de anotaciones,
  `fitEachPage`, sin `autoSpacing`; política de ajuste `BOTH`, o `WIDTH` si la página es apaisada. Al cambiar de
  página se recarga el documento entero en esa página y se muestra una barra de progreso hasta el primer pintado.
* Barra inferior: «primera» (⏮), «anterior» (‹), «Página `n` de `N`» (`page_number`), «siguiente» (›), «última»
  (⏭). «Anterior» y «siguiente» se deshabilitan mientras carga; primera/última no. Fuera de rango no hacen nada.
* Botón «Continuar» (`drag_on`).

#### 3.5.2 Selección del área

* Toda la gestión táctil es propia: el *listener* consume todos los eventos, así que **no hay zoom ni
  desplazamiento** del visor (zoom efectivo 1).
* `zoom = pdfView.getZoom()`, `xOffset = pdfView.getCurrentXOffset()`, y `horizontal = anchoVista > altoVista`
  (se recalcula en cada toque).
* `ACTION_DOWN`: `startX = (x − xOffset)/zoom` si horizontal, si no `x/zoom`; `startY = y/zoom`.
* `ACTION_MOVE`: igual para `endX`, `endY`; el área es el rectángulo normalizado (mín/máx) entre inicio y fin; se
  repinta.
* `ACTION_UP`: calcula el fin y normaliza: si `startX > endX` intercambia; si `startY > endY` intercambia.
* Se dibuja relleno y borde en `#80000000` (negro al 50 %), trazo 5 px, encima de la página.
* Cambiar de página borra la selección.

#### 3.5.3 Validación al pulsar «Continuar»

1. Página = `índice + 1` (base 1) → extra `signaturePages`. Si hay contraseña de PDF no vacía → extra
   `ownerPassword` (bytes).
2. `pageWidth = anchoPáginaVista × zoom`, `pageHeight = altoPáginaVista × zoom`. Si `horizontal`, suma `xOffset` a
   `startX` y a `endX` ⚠ (deshace lo restado al tocar).
3. **Sin área**:

| Caso | Diálogo (`CustomDialog`, icono info) | Botón principal | Botón secundario |
|---|---|---|---|
| Firma visible obligatoria (web `want`) | «Área no seleccionada» / «No se ha seleccionado ningún área donde realizar la firma visible.» | «Volver a seleccionar un área» (cierra el diálogo) | «Cancelar» → `RESULT_CANCELED` |
| Opcional (local o web `optional`) | igual | «Continuar» → `RESULT_OK` solo con página y contraseña → **firma invisible** | «Volver a seleccionar un área» (cierra) |

4. Alto/ancho del área recortados a la página: `areaH = (alto + startY > pageHeight) ? pageHeight − startY : alto`,
   `areaW` igual con `startX`/`pageWidth` (truncados a entero).
5. Tamaño real de la página con iText (`PdfReader`, con la contraseña si la hay): `pdfW`, `pdfH` de
   `getPageSize(página)` (caja de medios, sin rotación). Si falla (incluido `OutOfMemoryError`) → resultado
   `106` (`ERROR_REQUEST_VISIBLE_SIGN`) y cierre ⚠ (el código sigue ejecutándose y puede mostrar además el diálogo de
   área pequeña sobre una actividad que se cierra).
6. Conversión a puntos PDF (origen abajo a la izquierda):
   ```
   llx = startX × pdfW / pageWidth
   urx = (startX + areaW) × pdfW / pageWidth
   lly = (pageHeight − areaH − startY) × pdfH / pageHeight
   ury = (pageHeight − startY) × pdfH / pageHeight
   dimX = |int(urx − llx)|      dimY = |int(ury − lly)|
   ```
7. **Área pequeña** si `dimX < 30` **o** `dimY < 45` **o** `dimX × dimY < 1350`:

| Caso | Diálogo | Principal | Secundario |
|---|---|---|---|
| Obligatoria | «Firma visible demasiado pequeña» / «El área seleccionada para mostrar la firma tiene un tamaño demasiado pequeño.» | «Volver a seleccionar un área» | «Cancelar» → `RESULT_CANCELED` |
| Opcional | igual | «Continuar» → `RESULT_OK` **sin coordenadas** → firma invisible ⚠ | «Volver a seleccionar un área» |

8. Correcto → `RESULT_OK` con `signaturePositionOnPageLowerLeftX = round(llx × zoom)`,
   `…LowerLeftY = round(lly × zoom)`, `…UpperRightX = round(urx × zoom)`, `…UpperRightY = round(ury × zoom)` (como
   texto entero), más página y contraseña.
9. Si el PDF no se puede abrir (`IOException` al cargar) → resultado `106` y cierre.

#### 3.5.4 Uso del resultado en la firma local

* `RESULT_CANCELED` → `LocalSignActivity` se cierra sin mensaje.
* `106` → Inicio con «¡Algo salió mal!» / «AA200102 - Hemos intentado procesar tu solicitud…».
* `RESULT_OK` → extraParams `mode=implicit` y, **solo si llegan las cuatro coordenadas**, se añaden los de §3.5.5.
  ⚠ La contraseña devuelta solo se usa en ese caso; en la firma invisible se pierde y el PDF cifrado provoca
  después la petición de contraseña de §3.7.3.

#### 3.5.5 Parámetros de la firma visible

| ExtraParam | Valor |
|---|---|
| `obfuscateCertText` | `true`/`false` según `padesObfuscateCertInfo` (defecto `true`) |
| `signaturePages` | página elegida (base 1) |
| `layer2Text` | `pdf_visible_sign_template` del idioma: «Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$». En firma **local** con certificado de seudónimo se sustituye por `pdf_visible_sign_pseudonym_template`: «Firmado por $$PSEUDONYM$$ - $$OUS$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$» |
| `signaturePositionOnPageLowerLeftX/Y`, `…UpperRightX/Y` | §3.5.3 paso 8 |
| `ownerPassword` | contraseña introducida en la vista previa, si la hubo |

Plantillas en otros idiomas (traducidas en `values-*`, p. ej. en: «Signed by $$SUBJECTCN$$ on $$SIGNDATE=dd/MM/yyyy$$
with a certificate issued by $$ISSUERCN$$»). La sustitución de variables y la ofuscación: `04-pades.md` §8.

#### 3.5.6 PDF protegido en la vista previa (`PDFPasswordVisibleSignDialog`)

Si Pdfium lanza `PdfPasswordException` al cargar:

* *Bottom sheet* no cancelable: icono info, «El documento está encriptado», «Por favor, introduce la contraseña del
  documento para poder continuar con el proceso de firma», línea de error (solo a partir del segundo intento:
  «Contraseña incorrecta:»), campo «Contraseña» oculto con icono de ojo para mostrar/ocultar, «Cancelar»
  (subrayado) y «Aceptar».
* «Aceptar» con campo vacío → error «La contraseña del PDF no puede estar vacía:» sin cerrar. Si no, guarda la
  contraseña y recarga el PDF con ella (un fallo vuelve a mostrar el diálogo con el error).
* «Cancelar» → equivale a Atrás (`RESULT_CANCELED`).

### 3.6 Certificado y firma

`sign("SIGN", datos, formato, "SHA256", isLocalSign=true, extraParams)`:

1. Marca la operación como de firma (no de autenticación: el título del selector de tipo será «¿Con qué firmarás?»).
2. Carga el almacén y obtiene la clave (§4). En la firma local **no** se usa la caché de certificado (la firma
   local no activa *sticky*), pero sí se vacía (§4.7).
3. Avisos de caducidad/seudónimo (§4.6).
4. Si el almacén es JCA (tarjeta), añade `Provider.<clase de la clave privada> = <nombre del proveedor>` a los
   extraParams para que el PKCS#1 use ese proveedor.
5. Firma en segundo plano (§3.7).

### 3.7 Ejecución de la firma (`SignTask`)

#### 3.7.1 Firmador según formato (común a firma local y web)

| Formato pedido (sin distinguir mayúsculas) | Firmador |
|---|---|
| empieza por `xades` (incluye `XAdES`, `XAdEStri`, `XAdES Detached`, `XAdES Enveloped`, `XAdES Enveloping`, `XAdES-ASiC-S`, `XAdES-ASiC-S-tri`) | **`XAdEStri`** (`AOXAdESTriPhaseSigner`) ⚠ el sufijo ASiC se pierde |
| empieza por `facturae` (`FacturaE`, `FacturaEtri`) | **`FacturaEtri`** |
| `AUTO` en cofirma o contrafirma | detección sobre los datos entre los firmadores con identificación disponibles: CAdES, CAdES‑ASiC‑S y PAdES (los de CMS, XAdES, XMLDSig, FacturaE, ODF y OOXML no están en la app y se saltan) |
| cualquier otro | `AOSignerFactory.getSigner(formato)`: funcionan `CAdES`, `CAdEStri`, `CAdES-ASiC-S`, `CAdES-ASiC-S-tri`, `PAdES`, `Adobe PDF`, `PAdEStri`, `Adobe PDF TriPhase`, `NONE`, `NONEtri`. `CMS/PKCS#7`, `XMLDSig*`, `ODF*`, `OOXML*`, `Factura-e`, `AUTO` en firma → sin firmador |

Sin firmador → error `AOUnsupportedSignFormatException` «No se ha indicado un formato de firma soportado o el fichero
indicado no se reconoce como fichero de firma».

#### 3.7.2 Operación

* Muestra un `ProgressDialog` «Realizando firma» (`signing`).
* `sign` → `signer.sign`; `cosign` → `signer.cosign` (versión sin datos originales); `countersign` →
  `signer.countersign` con destino `TREE` si el extraParam `target` (recortado) es exactamente `tree`, si no
  `LEAFS`; sin selección de firmantes concretos.
* Algoritmo: el pedido compuesto con el tipo de clave (`SHA256withRSA`…).
* Error de PIN de tarjeta: si la excepción es `AOException` cuya causa es `AOException` → `SignatureAuthException` →
  `BadPinException`, se convierte en «PIN incorrecto» (`MSCBadPinException`), que vuelve a pedir el DNIe (§4.9.8).

#### 3.7.3 PDF protegido al firmar (`PDFPasswordDialog`)

Si la firma falla con `PdfIsPasswordProtectedException` o `BadPdfPasswordException` de tipo contraseña:

* Mismo diálogo que §3.5.6; con `BadPdfPasswordException` aparece desde el principio «Contraseña incorrecta:».
* «Aceptar» (no vacío) → pone `ownerPassword=<contraseña>` y quita `userPassword` de los extraParams y relanza la
  firma con los mismos datos y clave. ⚠ El reintento pasa el algoritmo **sin componer** (`SHA256` en local; el de
  la URL en web); funciona porque el PKCS#1 lo compone.
* «Cancelar» → error de cancelación (local: cierre silencioso; web: `ERR-11`).
* Si el diálogo no se puede mostrar → *toast* «El documento está protegido con contraseña.» y error de firma.

#### 3.7.4 Errores de la firma local

| Situación | Resultado |
|---|---|
| Cancelación en cualquier paso (selector de tipo cerrado, `KeyChain` sin elegir sin NFC preferido, contraseña PDF cancelada, diálogo de aviso…) | Cierre silencioso |
| Error al firmar (`SIGN`) | Inicio con «¡Algo salió mal!» / «AA200002 - Hemos intentado procesar tu solicitud, pero no ha podido ser completada con éxito. Por favor revisa la documentación.» |
| Error de almacén o certificado | Inicio con «¡Algo salió mal!» / «AA200000 - Hemos intentado procesar…» |

### 3.8 Guardado del resultado

Nombre propuesto (`AOSigner.getSignedName`):

* PAdES: `<nombre sin .pdf>_signed.pdf` (si no termina en `.pdf`, `<nombre>_signed.pdf`).
* CAdES: `<nombre completo>.csig` (p. ej. `informe.docx.csig`).
* Tipo MIME: `application/` + extensión (`application/pdf`, `application/csig`).

Antes de guardar se escribe el registro del histórico (§3.10) ⚠ aunque luego se cancele el guardado.

| Versión | Guardado |
|---|---|
| Android ≥ 11 | SAF `ACTION_CREATE_DOCUMENT` con ese tipo y el nombre propuesto. OK → escribe la firma en el URI y muestra el éxito; si no se puede abrir el flujo o falla la escritura → Inicio con «AA200301 - Hemos intentado procesar…». Cancelado → cierre sin mensaje |
| Android < 11 | Directorio = el del fichero original si se puede escribir; si no, la carpeta pública de Descargas si existe y se puede escribir; si no → error «AA200302 - Hemos intentado procesar…». Si el nombre existe se prueba `<base>(1).<ext>`, `(2)`… (el índice se inserta antes del **último** punto). Escribe el fichero, muestra el éxito y avisa al `MediaScanner` del fichero y del directorio (un fallo aquí muestra «AA200301…» después del éxito ⚠). Fallo de escritura → «AA200301…» |

### 3.9 Pantallas de resultado

`LocalSignActivity` abre un `HomeActivity` **nuevo** con los extras de §2.5 (sin cerrarse ella misma ni el inicio
anterior):

* Éxito: icono de verificación, «Fichero firmado», «El fichero ha sido firmado correctamente.», «Entendido».
* Error: icono de aviso, «¡Algo salió mal!», «AA`<código>` - `<texto>`», «Entendido».

No se informa de dónde se guardó la firma (los textos `signedfile_*_location` existen pero no se usan).

### 3.10 Histórico de firmas: formato

Fichero de texto `signsRecord.txt` en el almacenamiento interno de la app (`getFilesDir()`, es decir
`/data/data/es.gob.afirma/files/signsRecord.txt`), en la codificación por defecto (UTF‑8). Una línea por firma
terminada en `\n`, campos separados por `;` sin escapar:

```
<dd-MM-yyyy HH:mm:ss>;<tipo>;<operación>;<fichero>;<aplicación>
```

| Campo | Valores |
|---|---|
| fecha | hora local al registrar: en la firma local, tras firmar y antes de guardar; en la web y en lotes, justo después de lanzar la subida del resultado (sin esperar a que termine) |
| tipo | `LOCAL`, `WEB`, `APP` (firma pedida por otra app con `SIGN_SERVICE`), `BATCH`, `BATCH_APP` |
| operación | `sign`, `cosign`, `countersign` (en lotes siempre `sign`) |
| fichero | nombre (sin ruta) del fichero firmado; `null` si los datos no vinieron de un fichero elegido en la app (web) o en lotes |
| aplicación | local: `null`; web: el parámetro `appname` (normalmente el dominio de la página) o `null`; app: `appname` o, si falta, el paquete que llamó (`getCallingPackage()`, puede ser `null`); lotes: igual |

Los `null` se escriben como el texto `null`. Un `;` en un nombre corrompe la línea ⚠. Si no se puede crear o
escribir el fichero, solo se registra en el log (AA200001); la firma no falla. No se registran `selectcert` ni
`save`.

---

## 4. Certificados y almacenes

### 4.1 Decisión del almacén (`LoadKeyStoreFragmentActivity.loadKeyStore`)

Lo usan la firma local, la firma web, la selección de certificado web y los lotes.

```
¿caché sticky utilizable? (solo web: sticky=true, resetsticky≠true, entrada en caché) ── sí ─► usar la clave en caché, sin avisos
        │ no
        ▼
¿useNfc == true? ── sí ─► ChooseCertTypeDialog (§4.2)
        │                    ├─ «Certificado electrónico» ─► (almacén local, abajo)
        │                    ├─ «DNI electrónico» ─► flujo DNIe NFC (§4.9)
        │                    └─ X / Atrás ─► cancelación (SELECT_CERTIFICATE)
        │ no
        ▼
almacén local:
  ¿hay un dispositivo USB con clase 0 y la interfaz 0 de clase CCID (0x0B)? ── sí ─► pedir permiso USB ─► tarjeta por USB (§4.4)
        │ no
        ▼
  ¿proveedor AET de microSD por reflexión? ── sí ─► PinDialog (§4.4)
        │ no (siempre, en la práctica)
        ▼
  almacén de Android: selector del sistema KeyChain (§4.3)
```

Diálogos de progreso: «Cargando almacén de claves» mientras se inicializa el almacén; «Cargando certificados»
mientras se leen los de una tarjeta.

Tras un error de PIN (`MSCBadPinException`), `loadKeyStore` se llama con esa excepción: con `useNfc` activo va
directo al DNIe NFC mostrando «PIN incorrecto» (§4.9.8); si no, vuelve a empezar por el almacén local.

### 4.2 `ChooseCertTypeDialog`

*Bottom sheet* no cancelable tocando fuera, siempre expandida. Título «¿Con qué firmarás?» en firma y lotes, o
«¿Con qué te identificarás?» en `selectcert` (modo autenticación); botón X; dos opciones de texto: «Certificado
electrónico» y «DNI electrónico». El título y las opciones se fuerzan al idioma guardado (⚠ con
`new Locale(<etiqueta>)`, que para `ca-ES-valencia` no resuelve el valenciano).

* «Certificado electrónico» → `isDNIeCert = false` → almacén local.
* «DNI electrónico» → `isDNIeCert = true` → DNIe por NFC.
* X o Atrás → `onKeyStoreError(SELECT_CERTIFICATE, "Dialogo seleccion de almacen cancelado", CanceledException)`
  → cancelación de la operación.

### 4.3 Almacén de Android (`Android4KeyStoreManager`)

* `KeyChain.choosePrivateKeyAlias(actividad, callback, keyTypes=null, issuers=null, host=null, port=-1,
  alias=null)`: el selector del sistema muestra todos los certificados con clave instalados y, si no hay, permite
  instalar uno.
* **No se aplica ningún filtro** de los que pueda pedir la web (`filters`, `headless`, emisor, seudónimo,
  caducidad…): los `properties` de la URL solo llegan al firmador.
* Alias elegido → `KeyChain.getPrivateKey` + `KeyChain.getCertificateChain` → evento de selección **con** avisos de
  seudónimo y caducidad activados (§4.6).
* Sin alias (el usuario cancela) → `AOCancelledOperationException`: si `useNfc` está activo vuelve a mostrar
  `ChooseCertTypeDialog`; si no, cancelación.
* Error al extraer la clave (`KeyChainException`): en Android 4.1/4.1.1 se trata como el error de alias con
  caracteres especiales (`error_android_4_1`); en otro caso, error de selección. (Con `minSdk 23` el caso 4.1 es
  inalcanzable.)
* `AssertionError` (Android pide elegir dos veces tras instalar desde el selector) → se ignora sin hacer nada.

### 4.4 Lector USB y tarjeta microSD

**Lector CCID por USB** (`KeyStoreManagerFactory.initKeyStoreManager`):

1. Se busca el primer `UsbDevice` con `deviceClass == 0` y `getInterface(0).getInterfaceClass() == 0x0B` (CCID).
2. Se registra un receptor para la acción `es.gob.afirma.android.USB_PERMISSION` y se pide permiso al usuario
   (`PendingIntent` inmutable). ⚠ Con `targetSdk 35`, registrar un receptor sin `RECEIVER_EXPORTED/NOT_EXPORTED`
   lanza excepción en Android 14+; el receptor nunca se da de baja.
3. Con o sin permiso (si se deniega, se olvidan dispositivo y gestor) se carga el almacén:
   * Con dispositivo: se intenta `CeresProvider` sobre `AndroidCCIDConnection` → `KeyStore.getInstance("CERES")`;
     si falla, `DnieProvider` → `KeyStore.getInstance("DNI")`. Si alguno se obtiene, se cargan sus certificados
     (§4.5).
   * Si ambos fallan, sigue con la microSD y, al final, con `KeyChain`.
   * ⚠ No hay pantalla de PIN para tarjetas por USB: el *handler* de §4.5 entrega el último PIN introducido para el
     DNIe por NFC en este proceso; si no hay ninguno, la petición de PIN falla (`NullPointerException` dentro del
     *handler*) y la carga o la firma acaban en error. En la práctica el lector USB solo funciona tras haber usado el
     DNIe por NFC con el mismo PIN (ambigüedad: depende de cuándo pida JMulticard el PIN).

**Tarjeta microSD AET** (todo por reflexión; las clases `com.aet.android.javaprovider.*` no se incluyen en el APK,
así que en la práctica siempre falla y se pasa a `KeyChain`): si se pudiera instanciar `AETProvider` (contexto
MICROSD, tipo JAVA) y obtener `PKCS11KeyStore`, se mostraría `PinDialog`:

* `AlertDialog` con «Para poder utilizar el certificado introduzca su código de seguridad.», campo oculto con pista
  «Código CAN. » ⚠ (texto equivocado), botones «No usar DNIe» (negativo, cancela) y «Aceptar».
* PIN vacío → error de carga «Error, el PIN del DNI es nulo.». PIN → carga el almacén con
  `ks.load(null, pin)` en segundo plano («Cargando almacén de claves del dispositivo», texto fijo en español),
  descarta los alias sin clave privada y muestra `SelectAliasDialog` (§4.5).

### 4.5 Carga de certificados de tarjetas (`LoadCertificatesTask`)

Para almacenes JCA (DNIe por NFC, CERES o DNIe por USB):

1. Prepara (una vez por proceso, en `DnieConnectionManager`) un `CallbackHandler` que responde: al
   `PasswordCallback` con el PIN guardado; al `CustomTextInputCallback` con el CAN guardado; ignora el resto.
2. `ks.load(CallbackHandlerProtection(handler))`.
   * `InvalidAccessCodeException` (CAN erróneo) → borra CAN, PIN y *handler* → error (§4.9.8).
   * Otra excepción → `InitializingNfcCardException` si había CAN (NFC) o `LoadingCertificateException` si no
     (USB). ⚠ Con `LoadingCertificateException` la app **reintenta la carga sin límite** (vuelve a
     `loadKeyStore()`).
3. Lee los alias y sus certificados (CN, validez, CN del emisor). Si un certificado lanza
   `AuthenticationModeLockedException` → diálogo `AlertDialog` «Error en la lectura de tu DNIe» / «AA300106 - El
   DNIe tiene el PIN bloqueado. Puedes acudir a una comisaría de Policía Nacional a un Punto de Actualización del
   DNIe (PAD) para desbloquearlo.» / «Aceptar», y error de carga «300106 - Su DNI está bloquedado, deberá acudir a
   los Puntos de Actualización…».
4. **Selección automática**: se busca el alias exactamente `CertFirmaDigital` (certificado de firma del DNIe) y se
   usa sin mostrar lista. ⚠ Si no existe (p. ej. CERES con otros alias), no ocurre nada más: la operación queda
   colgada sin respuesta. ⚠ En `selectcert` también se devuelve el certificado de **firma**, no el de
   autenticación.
5. La entrada se obtiene con `ks.getEntry(alias, null)` (el PIN lo pide el *handler*). El evento de selección de
   tarjetas **no** activa los avisos de caducidad ni de seudónimo.

`SelectAliasDialog` (solo se muestra con la microSD AET; con tarjetas USB/NFC se usa la selección automática):

* Sin certificados → `AlertDialog` «No existe ningún certificado» / «No se han encontrado certificados instalados en
  su dispositivo.» / «Aceptar» → error de carga.
* Con certificados → título «Seleccione un certificado», un botón de radio por certificado con el texto
  «`<CN>`⏎Válido: `<dd/MM/yyyy>`⏎Hasta: `<dd/MM/yyyy>`⏎Emisor: `<CN emisor>`» (`dialog_alias_cert_text`), botones
  «Permitir» (sin selección → cancelación y error) y «Cancelar»; Atrás cancela.

### 4.6 Avisos sobre el certificado elegido

Solo para certificados del almacén de Android elegidos en el selector (no en caché ni tarjetas). En firma y lotes
(no en `selectcert`):

1. **Caducado** (`checkValidity` lanza `CertificateExpiredException`): «Certificado caducado» / «El certificado no
   es válido, ya que está caducado.». ⚠ Un certificado aún no válido (`NotYetValid`) no se detecta aquí: se trata
   como error genérico de selección.
2. **Próximo a caducar** (`notAfter − ahora < 7 días`, `604 800 000` ms): «Certificado próximo a caducar» / «El
   certificado seleccionado está próximo a caducar. Contacte con la autoridad emisora para renovarlo.».
3. **Seudónimo** (`AOUtil.isPseudonymCert`, atributo `2.5.4.65` en el sujeto): «Certificado de seudónimo» / «El
   certificado escogido es un certificado de seudónimo. En la firma no aparecerán sus datos personales».

Cada aviso es un `CustomDialog` con icono info, botón «Continuar» y «Cancelar» subrayado. «Continuar» sigue (si
venía de caducidad, aún puede saltar el de seudónimo; si venía de seudónimo, ya no se repite la caducidad).
«Cancelar» **reinicia la operación desde la elección de almacén** (para elegir otro certificado). Orden:
caducidad (1 o 2) y luego seudónimo.

### 4.7 Caché de certificado (*sticky*) — `KeyEntryCache`, `DeleteCertCacheService`

* Una sola entrada estática (clave privada + cadena) en el proceso. El proceso de Android sobrevive entre
  invocaciones, así que la caché funciona **entre operaciones web sucesivas** (en escritorio solo dentro de una
  misma sesión WebSocket).
* Uso: en `sign`/`cosign`/`countersign`, `selectcert` y `batch`, si `sticky=true`, `resetsticky≠true` y hay entrada,
  se usa sin mostrar nada (ni `ChooseCertTypeDialog`, ni avisos, ni proveedor JCA).
* Actualización tras elegir certificado: si la operación lleva `sticky=true` **y no es DNIe** → se guarda; en
  cualquier otro caso (incluida la firma local) → se borra. El DNIe nunca se guarda.
* Caducidad: al guardar una entrada se (re)inicia un temporizador de `stickySignatureTimeout` minutos (5, 15, 30, 60
  o 120; defecto 5); al vencer, la entrada se borra. Borrar la entrada no detiene el temporizador (al vencer borra
  otra vez, sin efecto).
* No hay forma manual de vaciarla salvo matar el proceso.

### 4.8 Importación de certificados (.p12 / .pfx)

1. **Instrucciones** (`CertImportInstructionsActivity`, abierta desde Inicio esperando resultado o desde la ayuda
   sin esperarlo): `ViewPager2` de dos páginas con imagen a pantalla completa y puntos indicadores.
   * Página 1: «Localiza el archivo» / «Localiza el archivo .p12 o .pfx. en tu teléfono» y botón «Continuar» (va
     a la página 2).
   * Página 2: «Envía al dispositivo» / «Si no lo encuentras, envíalo a tu móvil desde otro dispositivo mediante
     correo electrónico u otras aplicaciones en la nube.» y botón «Añadir certificado».
   * ⚠ Los textos se actualizan cuando el adaptador crea el fragmento o pide su id, no al cambiar de página, así
     que pueden no corresponder a la página visible.
   * «Añadir certificado» abre un `HomeActivity` nuevo con `startImportCert=true`, devuelve `RESULT_OK` y se
     cierra. ⚠ Si venía de Inicio, el inicio original también recibe el `RESULT_OK` y lanza el selector: se abren
     dos selectores seguidos.
2. **Selector**: Android ≥ 11 → SAF `ACTION_OPEN_DOCUMENT` tipo `application/x-pkcs12`; < 11 → `FileChooserActivity`
   con título «Importar certificado» y filtro `.p12,.pfx`.
3. Lee el fichero completo. Error → `CustomDialog` aviso «No hemos podido añadir tu certificado» / «AA201100 - No
   hemos podido añadir tu certificado a la aplicación de Autofirma de manera correcta. Inténtalo de nuevo más tarde»
   con «Volver a intentarlo» (repite el selector) y «Cancelar».
4. `KeyChain.createInstallIntent()` con `EXTRA_PKCS12 = bytes`: el sistema pide la contraseña y el nombre y lo
   instala.
5. Instalado (`RESULT_OK`) → «Certificado añadido» / «El certificado se ha añadido correctamente» / «Entendido».
   Cancelado → nada.

### 4.9 DNIe por NFC: flujo de pantallas

#### 4.9.1 Activación

* Requisitos: el dispositivo tiene NFC y `useNfc == true` (diálogo de primera ejecución §2.5 o Configuración de
  firma §2.8). Entonces cada operación muestra `ChooseCertTypeDialog`.
* Al elegir «DNI electrónico»: si el NFC del sistema está desactivado → *toast* «Por favor, active el NFC para usar
  DNIe y pulsa atrás para volver» y abre `Settings.ACTION_WIRELESS_SETTINGS`. Al volver: NFC activo → pantalla de
  introducción; si no → *toast* «No se ha habilitado NFC.» y de nuevo la elección de almacén.

#### 4.9.2 Introducción (`IntroUseDnieActivity`)

Flecha atrás; título «Identificación con DNIe»; texto «Para identificarte mediante DNIe es necesario que tengas un
DNI electrónico con **certificados vigentes** y conozcas el **código PIN**.»; botón subrayado «¿Es mi DNI
compatible?» y botón «Empezar».

* «¿Es mi DNI compatible?» → `CompatibleDniDialog`: icono info, título «¿Es mi DNI compatible?», texto «Los DNIe
  compatibles con este proceso son los **DNI 3.0 y 4.0**. Si tienes dudas de cuál es el tuyo, puedes consultarlo en
  el siguiente enlace:», enlace subrayado «Portal del DNI electrónico. Cuerpo Nacional de Policía» (abre
  `https://www.dnielectronico.es/PortalDNIe/`) y «Entendido».
* «Empezar» → pasos (§4.9.3). Si los pasos terminan bien, devuelve `RESULT_OK` con CAN y PIN.
* Atrás → `RESULT_CANCELED`.
* Si se abrió por un error, muestra primero un `CustomDialog` aviso con «Aceptar» (§4.9.8).

#### 4.9.3 Pasos (`StepsInsertDataDnieActivity`)

Barra con flecha atrás y X («Cerrar proceso de firma con DNIe»); subtítulo «Identificación con DNIe»; título del
paso; «Paso `n` de 3»; barra de progreso (máx. 3); contenedor del fragmento.

| Paso | Título | Contenido | Validación | Botón |
|---|---|---|---|---|
| 1 | «Introduzca el CAN del DNI» | «El CAN es un número situado en la parte inferior derecha del DNI. Es necesario para la lectura del DNI con NFC.»; campo numérico de máx. 6 cifras con pista «Escribe tu código CAN del DNI», precargado con el último CAN usado en el proceso; imagen de ejemplo | longitud exactamente 6; si no, error en el campo «Introduzca un CAN válido» | «Continuar» |
| 2 | «Introduce el PIN» | «Al hacerte el DNIe recibiste un código PIN que puedes recuperar o cambiar en comisarías sin cita previa.»; campo oculto con pista «Escribe tu código PIN»; imagen | longitud ≥ 4; si no, «Introduzca un pin válido» | «Continuar» |
| 3 | «Lee tu DNIe con el móvil» | «Coloca tu DNIe en una superficie lisa y sitúa tu móvil **sin funda** sobre él hasta que detecte el chip.»; ilustración | — | «Leer DNIe» → `RESULT_OK` con `canValue`, `pinValue` |

* Atrás: paso 3 → paso 2 (PIN vacío); paso 2 → paso 1 (con el CAN guardado); paso 1 → cierra la actividad con
  `RESULT_CANCELED` → la introducción **sigue abierta** (hay que volver a pulsar atrás para cancelar).
* X → abre un `HomeActivity` nuevo ⚠ sin cancelar la operación en curso (la web no recibe respuesta).
* Con el extra `errorReadingCard=true` (tras un fallo de lectura, §4.9.8) se entra directamente en el paso 3 con el
  CAN y PIN anteriores y un diálogo de error.

#### 4.9.4 Tras introducir los datos

`LoadKeyStoreFragmentActivity` recibe CAN y PIN, los guarda en `DnieConnectionManager` (en memoria, vida del
proceso) y abre `NFCDetectorActivity` con el CAN.

#### 4.9.5 Cancelaciones

* Introducción cancelada → error de carga «Operacion cancelada» con `CanceledException` → con `useNfc` activo vuelve
  a `ChooseCertTypeDialog` (cerrar éste sí cancela la operación).
* Detector cancelado → con `useNfc` activo, vuelve a `ChooseCertTypeDialog`; si no, cierra la actividad.
* Detector con otro resultado → borra CAN y PIN y vuelve a la elección de almacén.

#### 4.9.6 Detección (`NFCDetectorActivity`)

* Al crearse: reinicia la conexión (`DnieConnectionManager.reset()`: cierra la conexión NFC anterior y olvida el
  *handler*; conserva CAN y PIN).
* Pantalla: icono de lupa, «Buscando DNIe», «Pon tu móvil sobre el DNIe lo más cerca posible del lector NFC.»,
  rueda de progreso y «Cancelar» (`RESULT_CANCELED`).
* *Foreground dispatch* activo mientras está en primer plano: filtros `TAG_DISCOVERED`, `NDEF_DISCOVERED`,
  `TECH_DISCOVERED` y tecnologías `NfcV`, `NfcF`, `NfcA`, `NfcB`.
* Al recibir una etiqueta con CAN disponible: la guarda en `DnieConnectionManager` y devuelve `RESULT_OK` con el CAN
  (extra `pc`).
* No hay tiempo límite: espera indefinidamente.

#### 4.9.7 Carga del almacén

`LoadNfcKeyStoreManagerTask` («Cargando almacén de claves»): crea `AndroidNfcConnection` sobre la etiqueta y
`DnieProvider` → almacén `DNI`. `KeyStoreException` → tarjeta no soportada (AA300100); otra excepción → error de
conexión (AA300102). Después `LoadCertificatesTask` («Cargando certificados»), selección automática de
`CertFirmaDigital` (§4.5) y firma. CAN y PIN no se vuelven a pedir: el `CallbackHandler` de §4.5 se los entrega a
JMulticard cuando los solicita (en qué momento lo hace es asunto del documento de JMulticard).

#### 4.9.8 Errores

| Error | Pantalla |
|---|---|
| Tarjeta no soportada (`UnsupportedNfcCardException`) | Introducción con diálogo «¡Algo salió mal!» / «AA300100 - La tarjeta que has proporcionado no parece ser un DNIe. Por favor inténtalo de nuevo» |
| CAN incorrecto (`InvalidAccessCodeException`) | Introducción con diálogo «CAN incorrecto» / «AA300108 - Error al iniciar la conexión con la tarjeta. Es posible que el CAN sea incorrecto. Inténtelo de nuevo.» |
| Error al leer (`InitializingNfcCardException`) | Paso 3 con diálogo «Error en la lectura de tu DNIe» / «AA300103 - Se ha producido un error al intentar leer tu DNIe. Por favor, vuelve a intentarlo. Recuerda mantenerlo en una superficie lisa y mantener tu teléfono móvil unos segundos fijo sobre la tarjeta para su correcta lectura.» con «Volver a intentarlo» (cierra el diálogo) y «Cancelar» (cancela los pasos) |
| PIN incorrecto al firmar (`MSCBadPinException`) | Introducción con diálogo «PIN incorrecto» / «AA300105 - El PIN del dispositivo criptográfico es incorrecto. Tenga en cuenta que varios intentos fallidos consecutivos podrían bloquearlo.» |
| DNIe bloqueado | Diálogo de §4.5 paso 3 y error de almacén |

Tras cerrar el diálogo, el usuario repite «Empezar» y los pasos.

### 4.10 Resumen de errores de almacén y certificado

Qué hace cada operación con los errores de §4 está en §3.7.4 (local), §5.12 (web) y §6 (lotes). Puntos comunes:

* La cancelación al cargar el almacén (`PinDialog` o `SelectAliasDialog` cancelados) se notifica como **error de
  carga del almacén**, no como cancelación ⚠ (en la web llega `ERR-23`).
* Un almacén sin certificados: con la microSD AET se notifica como error de carga del almacén; con tarjetas USB/NFC
  (sin alias `CertFirmaDigital`) la operación se queda colgada (§4.5).
* Con `KeyChain` sin certificados, el selector del sistema solo permite instalar uno o cancelar (cancelación).

---

## 5. Firma desde la web (`afirma://`)

### 5.1 Entrada

* **Cómo llega**: AutoScript, al detectar Android, usa siempre el modo servidor intermedio (`01-protocol.md` §1,
  modo C): en Chrome abre `intent://<op>?…#Intent;scheme=afirma;package=es.gob.afirma;end`, que Android convierte en
  `afirma://<op>?…` dirigido a este paquete; en otros navegadores, `afirma://<op>?…` directamente. La app nunca
  abre puertos locales.
* **Filtros**: §1.4. Cada operación tiene su actividad. Las cuatro son transparentes, se ejecutan en la tarea que
  las lanza y usan `AndroidHttpManager` (§5.10) como gestor HTTP de `afirma-core` (instalado al cargar la clase).
* **Comprobaciones comunes al crearse** (sign, batch, selectcert; save solo la segunda y la tercera):
  1. Intent sin datos (`getData() == null`) → se registra «AA600006…» y se cierra la app (§5.4.6) sin responder.
  2. Lanzada desde la lista de recientes (`FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY`) → abre Inicio
     (`CLEAR_TOP | NEW_TASK`) y no hace nada más (no repite la operación).
  3. Recreada con estado guardado (rotación) → no hace nada (la operación sigue en curso).
* **Desde otra app**: `WebSignActivity` y `WebSignBatchActivity` aceptan además las acciones
  `es.gob.afirma.android.SIGN_SERVICE` y `es.gob.afirma.android.SIGN_BATCH_SERVICE` con el mismo URI `afirma://…`
  como datos; la respuesta vuelve por el resultado de la actividad en lugar de por el servidor intermedio (§5.13).

### 5.2 Diferencias con el protocolo de escritorio (`01-protocol.md`)

La app usa `afirma-core` **1.9** para analizar las URL (§0.3). Frente a lo especificado en `01` (1.9.1):

| Aspecto | Escritorio (`01`) | Android |
|---|---|---|
| Transporte | WebSocket, servicio local o servidor intermedio | Solo servidor intermedio (o resultado por intent) |
| Operación | parámetro `op` (§3.4) | **el *host* de la URL** (`afirma://cosign?…` ⇒ `cosign`; `parserUri` sobrescribe cualquier `op=`). En los sobres XML descargados (`fileid`), el nombre del elemento raíz, sobrescrito por `<e k="op">` si existe (`01` §4.1) |
| Operaciones | `sign`, `cosign`, `countersign`, `signandsave`, `selectcert`, `batch`, `save`, `load`, `websocket`, `service` | `sign`, `cosign`, `countersign`, `selectcert`, `batch`, `save` (§5.3) |
| Cifrado | `key` (DES) y `cipher` (AES con DES de respaldo) (§8) | **Solo DES** con `key` (8 caracteres; otra longitud → error de parámetros). `cipher` se ignora (§5.9) |
| `servicetimeout` | tiempo de lectura de servidores trifásicos/lotes | **No existe**: no hay tiempos de espera (§5.10) |
| `appname` | decodificado dos veces | decodificado una vez; solo se usa en el histórico |
| `ver`, `jvc`, `mcv` | negociación de versión, comprobación de versión mínima, formato de errores | Se leen pero **no se comprueban**; el formato de error es siempre el de §5.12 |
| `dlgload` | oculta diálogos de progreso | Ignorado |
| `ksb64` / `keystore` | almacén a usar | Ignorados: siempre la lógica de §4.1 |
| `properties` | extraParams del firmador **y** filtros/opciones del diálogo de certificados (`filters`, `headless`, `mandatoryCertSelection`…) | Solo extraParams del firmador. `headless=true` únicamente evita la vista previa de firma visible (§5.5) |
| `aw` (espera activa) | `#WAIT` cada 10 s en modo directo | Solo en `batch` y solo si el lote se descargó por `fileid` (§6.3) |
| `filenameExts`, `checkSignatures`, `profile`, complementos | soportados | No |
| `extra` (`{"filename": …}`) en la respuesta de firma | si el usuario eligió el fichero (versión ≥ 3) | **Nunca** (§5.11) |
| Errores de parámetros | códigos 6xxxxx específicos, en diálogo, no subidos | Todos «AA600006», en diálogo; tampoco se suben (el intento falla por `NullPointerException` capturada); en la modalidad por intent sí se devuelven como `ERR-22` (§5.12) |
| Errores devueltos | `err-NN:=AF<código> - <descripción fija>` o `SAF_NN` | `ERR-NN:=AA<código> - <texto de usuario localizado>` (§5.12) |
| *Sticky* | solo dentro de un proceso WebSocket | entre invocaciones, con caducidad configurable (§4.7) |
| Formatos | todos los de `01` §3.4 | §3.7.1: XAdES y FacturaE forzados a trifásica; sin CMS, XMLDSig, ODF, OOXML |

Se mantienen igual que en `01`: análisis del *query string* (`01` §2.1, con URL‑decoding UTF‑8), `dat` en Base64
(o URL `http(s)` que se descarga) y `gzip` (§2.3), validación de URLs de servlets (§2.6: solo `http`/`https`, no
`localhost` ni `127.0.0.1`, sin `?` ni `=`), identificadores (§2.7: ≤ 20 caracteres alfanuméricos), obligatoriedad de
`format` y `algorithm` y lista de algoritmos admitidos (§3.4), y los parámetros de `batch` (§3.7) y `save` (§3.8).

#### 5.2.1 Parámetros que la app usa realmente

Validación y significado de cada parámetro: `01` §3.1–§3.8 (con las diferencias de la tabla anterior).

| Operación | Parámetros con efecto en Android | Leídos y validados pero sin efecto |
|---|---|---|
| `sign`, `cosign`, `countersign` | `dat`, `gzip`, `fileid`, `rtservlet`, `key`, `id`, `stservlet`, `format`, `algorithm`, `properties` (al firmador), `sticky`, `resetsticky`, `appname` (histórico) | `ver`, `mcv`, `aw`, `ksb64`/`keystore`, `op` (lo pisa el *host*), parámetros desconocidos |
| `selectcert` | `fileid`, `rtservlet`, `key`, `id`, `stservlet`, `sticky`, `resetsticky` | `dat`, `properties` (no se usan para nada), `ver`, `mcv`, `aw`, `ksb64`/`keystore` |
| `save` | `dat`, `gzip`, `fileid`, `rtservlet`, `key`, `id`, `stservlet`, `filename` | `title`, `exts`, `desc` (un `filename` o `exts` con caracteres prohibidos sigue siendo error de parámetros), `ver`, `mcv`, `aw` |
| `batch` | `dat`, `fileid`, `rtservlet`, `key`, `id`, `stservlet`, `batchpresignerurl`, `batchpostsignerurl`, `jsonbatch`, `needcert`, `sticky`, `resetsticky`, `appname` (histórico), `aw` (solo en el sobre) | `localBatchProcess` (provoca error), `properties`, `ver`, `mcv`, `ksb64`/`keystore` |

### 5.3 Operaciones

| URI | Actividad | Estado en Android |
|---|---|---|
| `afirma://sign?…`, `afirma://cosign?…`, `afirma://countersign?…` | `WebSignActivity` | Soportadas (§5.4) |
| `afirma://selectcert?…` | `WebSelectCertificateActivity` | Soportada (§5.6) |
| `afirma://save?…` | `WebSaveDataActivity` | Soportada (§5.7) |
| `afirma://batch?…` | `WebSignBatchActivity` | Solo lotes JSON contra servidor (§6) |
| `afirma://signandsave`, `afirma://load`, `afirma://websocket`, `afirma://service` | — | Sin actividad registrada: el sistema no abre la app |

### 5.4 `sign`, `cosign`, `countersign` (`WebSignActivity`)

#### 5.4.1 Análisis

`getParametersToSign(uri, servicesRequired=true)`. Cualquier error (parámetro ausente o inválido, clave de longitud
incorrecta, `stservlet` inválida, `dat` no descargable…) → diálogo «¡Algo salió mal!» / «AA600006 - Hemos intentado
procesar tu solicitud, pero no ha podido ser completada con éxito. Por favor revisa la documentación.». La app
intenta además responder `ERR-22`, pero como los parámetros no llegaron a crearse el envío lanza una
`NullPointerException` que se captura: **la web no recibe nada** y acaba por tiempo (como en el escritorio). Solo en
la modalidad por intent (§5.13) se devuelve el error. ⚠ Si la petición es válida pero no trae `stservlet` (no es
obligatorio sin `id`), cualquier respuesta posterior falla con `NullPointerException` en segundo plano y la app se
cierra.

#### 5.4.2 Origen de los datos

| Caso | Acción |
|---|---|
| sin `dat` y sin `fileid` | El usuario elige el fichero (§5.4.3) |
| sin `dat`, con `fileid` (y `rtservlet`) | Descarga del sobre (§5.8.2) → descifrado con `key` (§5.9) → análisis del XML con `servicesRequired=true` → si el sobre trae `dat`, diálogo «Firmando» y se firma **directamente** (⚠ sin los pasos 2–4 de §5.4.4: no se expande la política, no se comprueba que sea PDF y se ignora la firma visible); si no, el usuario elige el fichero |
| con `dat` | Se firma directamente |

Errores de la descarga: diálogo «AA401100 - Hemos intentado procesar…» (sin respuesta a la web, que acabará por
tiempo). Errores de descifrado o del XML: diálogo «AA600006 - …» (sin respuesta).

#### 5.4.3 Elección del fichero por el usuario

* Android < 11 sin permiso de escritura → se pide; denegado → error de firma (`ERR-14`, §5.12).
* Android ≥ 11 → SAF `ACTION_OPEN_DOCUMENT`, tipo `*/*`. Android < 11 → `FileChooserActivity` con título «Seleccione
  el fichero a firmar», directorios excluidos de §3.3 y filtro `.pdf` si el formato es exactamente `PAdES` o
  `PAdEStri`.
* Cancelado → `ERR-11` (cancelación).
* Lectura (igual que §3.1, con fichero temporal en Android ≥ 11). `OutOfMemoryError` → diálogo «AA200105 - El fichero
  seleccionado es demasiado grande…» (sin respuesta). `IOException` → *toast* «Ocurrió un error cargando el
  fichero`<nombre>`» (sin espacio ⚠) y se vuelve a abrir el selector. Otro error → el mismo *toast* sin reabrir.
* Los datos se ponen en los parámetros y se procesa la petición (§5.4.4). ⚠ Un error lanzado en ese procesamiento
  solo se muestra en un *toast* con el texto de usuario de AA200002 y no se responde a la web.

#### 5.4.4 Procesamiento

Se aplica cuando los datos vienen en `dat` o los eligió el usuario (con datos del sobre, ver §5.4.2):

1. Diálogo de progreso «Firmando».
2. Si el formato es exactamente `CAdES` o `PAdES` (con mayúsculas), se expanden los extraParams según la política
   (`expandExtraParams`, `07-core.md` §5). Incompatibilidad → diálogo + `ERR-22` con AA600109. En los demás formatos
   (trifásicos) lo hará el servidor.
3. Si el formato es `PAdES`, `PAdEStri`, `Adobe PDF` o `Adobe PDF TriPhase` (exacto) y los datos no son PDF
   (menos de 70 bytes o sin cabecera `%PDF-`) → diálogo + `ERR-07` con AA200106 «Para poder realizar esta operación
   es necesario seleccionar un fichero PDF» si lo eligió el usuario, o AA200107 si venía de la web. ⚠ **La ejecución
   continúa** y se intenta firmar igualmente.
4. Firma visible (§5.5) si procede; si no, firma.
5. Firma con `sign(operación, datos, formato, algoritmo, local=false, sticky, resetsticky, extraParams)`: caché
   (§4.7), elección de almacén y certificado (§4), avisos (§4.6), proveedor JCA en extraParams, `SignTask` (§3.7).

#### 5.4.5 Respuesta

* Con clave (`key` no vacía): `C(certificado) "|" C(firma)` con `C` = DES de §5.9. Error al cifrar la firma →
  `ERR-16` (AA200100). Error al cifrar el certificado → se registra y se envía `null` como certificado ⚠
  (`"null|<firma>"`).
* Sin clave: `B64(certificado) "|" B64(firma)` con `android.util.Base64` en modo `URL_SAFE` **con saltos de línea**
  (cada 76 caracteres y al final) ⚠, a diferencia del Base64 sin saltos del escritorio.
* El certificado es el DER del certificado de firma (primero de la cadena).
* Se sube a `stservlet` con el `id` (§5.8.1). Éxito → cierra la app (§5.4.6). Fallo → diálogo «AA401200 - Hemos
  intentado procesar…».
* Registro en el histórico: tipo `WEB`, operación, nombre del fichero si lo eligió el usuario, `appname` (§3.10).
  Se escribe tras lanzar el envío, independientemente de su resultado.

#### 5.4.6 Cierre

«Cerrar la app» = abrir `HomeActivity` con `FLAG_ACTIVITY_CLEAR_TOP` y `CLOSE_ACTIVITY=true` (que hace
`finishAffinity()`) y terminar la actividad web. El usuario vuelve al navegador. `selectcert` y `save` hacen
directamente `finishAffinity()`.

### 5.5 Firma visible pedida por la web

* Se muestra la vista previa (§3.5) si el formato es `PAdES`, `PAdEStri`, `Adobe PDF` o `Adobe PDF TriPhase`
  (exacto), el extraParam `visibleSignature` vale `want` u `optional` (sin distinguir mayúsculas) y `headless` no es
  `true`. Con `want`, la selección es obligatoria (`isRequiredVisibleSignature`).
* ⚠ La vista previa necesita la ruta del fichero, que **solo existe si el usuario eligió el PDF en la app**. Si los
  datos vienen en `dat`, la ruta es nula y `PdfSelectPreviewActivity` termina con `NullPointerException` (la app se
  cierra). Si vienen en el sobre descargado (`fileid`, lo habitual para documentos de más de ~1,5 KB), la firma
  visible se ignora y se firma sin ella (§5.4.2).
* Resultado:
  * `RESULT_OK`: si trae contraseña → `ownerPassword`. Si trae las cuatro coordenadas → se añaden
    `obfuscateCertText` (preferencia), `signaturePages`, `layer2Text` = plantilla de la app (**sustituye** la que
    enviase la página; no se usa la plantilla de seudónimo) y las coordenadas (sustituyen las de la página). El
    resto de parámetros de apariencia de la página se conservan. Sin coordenadas y `want` → `ERR-11`; sin
    coordenadas y `optional` → firma invisible.
  * `RESULT_CANCELED` → `ERR-11`.
  * `106` (error al cargar el PDF) → diálogo + `ERR-07` con AA200102.

### 5.6 `selectcert` (`WebSelectCertificateActivity`)

1. Análisis con `getParametersToSelectCert(uri, true)`; error → diálogo AA600006 (sin respuesta, §5.4.1).
2. Si `sticky=true`, `resetsticky≠true` y hay caché → devuelve ese certificado sin interfaz.
3. Si hay `fileid` → descarga, descifrado y análisis del sobre (errores solo en diálogo: AA401101 en la descarga,
   AA600006 en el resto) y vuelve a este punto.
4. Diálogo «Cargando almacén de claves» y elección de almacén y certificado en **modo autenticación** (título
   «¿Con qué te identificarás?»). Sin avisos de caducidad ni seudónimo. Con DNIe se devuelve el certificado de
   **firma** (`CertFirmaDigital`) ⚠.
5. Caché: se guarda si `sticky=true` y no es DNIe; si no, se borra.
6. Respuesta: con clave `C(certificado)`; sin clave Base64 URL‑safe de `afirma-core` (sin saltos). Error al cifrar
   → debería ser `ERR-16` con AA200200, pero el código busca la categoría con la clave equivocada (`ENCRYPTING_CERT`
   en lugar de `CYPHERING_CERT`) y termina en `NullPointerException` ⚠ (en la práctica inalcanzable: una clave de 8
   caracteres siempre es una clave DES válida). Éxito al subir → `finishAffinity()`.
7. No se registra en el histórico.

### 5.7 `save` (`WebSaveDataActivity`)

1. Android < 11 sin permiso → se pide; denegado → diálogo «AA200304 - El Cliente de firma no tiene permisos de
   escritura en disco.» con botón «Volver a intentarlo» que en realidad **cierra** la app ⚠; no se responde.
2. Análisis con `getParametersToSave(uri, true)`. Error → la actividad se cierra **sin responder** ⚠.
3. Sin `dat` y con `fileid` → descarga y descifrado; error de descarga → diálogo y `ERR-18` (AA400001); error de
   descifrado o XML → diálogo y `ERR-22` (AA600006).
4. SAF `ACTION_CREATE_DOCUMENT` (también en Android < 11), tipo `*/*`, nombre propuesto = `filename` de la petición
   o, si falta, `datos` (`default_saved_filename`) más la extensión detectada con `MimeHelper`, con el error ⚠
   `nombre += nombre + "." + ext` → «datosdatos.pdf». `title`, `exts` y `desc` se ignoran.
5. Guardado correcto → envía `OK` (sin cifrar) y cierra. Fallo al escribir → diálogo «AA200305 - Ocurrió un error al
   guardar los datos» y `ERR-26`. Cancelado → `ERR-11`.
6. ⚠ Esta actividad no aplica el idioma guardado y, en un proceso recién creado, sus catálogos de error están
   vacíos: la cancelación y los errores provocan `NullPointerException` en vez de responder (§2.4).

### 5.8 Servidor intermedio

#### 5.8.1 Subida (`SendDataTask`, `IntermediateServerUtil.sendData`)

`POST <stservlet>` con cuerpo `op=put&v=1_0&id=<id>&dat=<datos>`. Los datos se concatenan **tal cual** (como en el
escritorio, `01` §6.2). Las cadenas de error se pasan antes por `URLEncoder.encode(…, "UTF-8")` (espacios → `+`,
acentos → `%C3%B3`…), así que el servlet, que decodifica una vez, guarda el texto original ⚠ (el escritorio las
envía sin codificar). `OK` se envía sin codificar.

Resultado: éxito solo si la respuesta, recortada, es exactamente `OK`; cualquier otra respuesta o error de red es
fallo. Si el envío era «crítico» (resultados y errores marcados como tal), el fallo muestra el diálogo AA401200; si
no lo era, la app se cierra igualmente (salvo en lotes, §6.5).

#### 5.8.2 Descarga (`DownloadFileTask`)

`POST <rtservlet>` con cuerpo `op=get&v=1_0&id=<fileid>`. Si los 4 primeros bytes (UTF‑8) son `ERR-` sin distinguir
mayúsculas:

* si la respuesta empieza por `ERR-06` (aún no disponible), espera **2000 ms** y reintenta, hasta **10 reintentos**
  (11 peticiones en total);
* si no, o agotados los reintentos, error «El servidor devolvio el siguiente error al descargar los datos: …».

Respuestas de menos de 4 bytes provocan una excepción que se trata como error desconocido. La tarea se cancela si
la actividad se destruye. (El escritorio no reintenta.)

#### 5.8.3 Espera activa

`ActiveWaitingThread`: cada **10 000 ms** sube `#WAIT` al `stservlet` con el `id`, bajo un cerrojo global, hasta que
se interrumpe justo antes de subir el resultado. Solo lo usa `batch` (§6.3). ⚠ `sign`, `selectcert` y `save` no
mandan `#WAIT` aunque `aw=true`: si el usuario tarda más de lo que AutoScript espera en móvil (16 consultas cada
4 s, `01` §5.3), la página da la operación por perdida.

#### 5.8.4 Cookies

Al cargar las tareas HTTP se instala un `CookieManager` global con `ACCEPT_ALL`: todas las conexiones del proceso
(servidor intermedio, trifásico, lotes) comparten cookies en memoria.

### 5.9 Cifrado (`CipherDataManager`)

Equivale al DES de `01` §8.2 con estas particularidades:

* Clave: los 8 caracteres de `key` como bytes; `DES/ECB/NoPadding` con relleno de ceros hasta múltiplo de 8.
* Cifrar: `<d>.<Base64 URL‑safe con '='>` con `d = (8 − len % 8) % 8`.
* Descifrar (sobres descargados): texto UTF‑8 con `_`→`/` y `-`→`+`; si hay `.`, `d` = número antes del **primer**
  punto (no solo en la posición 1); el resto se vuelve a pasar a URL‑safe y se decodifica (los saltos de línea se
  ignoran); se descifra y se quitan `d` bytes.
* Sin clave: se intenta decodificar el Base64 tras pasarlo al alfabeto estándar pero con el decodificador
  URL‑safe ⚠, que rechaza `+` y `/`: en la práctica, un sobre sin clave casi nunca se puede leer (en el escritorio
  tampoco funciona sin clave).
* AES no existe: si la página envía `cipher`, se ignora y se usa DES con `key`. AutoScript descifra con AES y, si
  falla, con DES, así que la respuesta se entiende.

### 5.10 Cliente HTTP (`AndroidHttpManager`)

Se usa para el servidor intermedio, la descarga de `dat` por URL, los servidores trifásicos y los de lotes.

* `POST`: la URL se parte con `StringTokenizer(url, "?")`: el primer trozo es la dirección y el **segundo** el
  cuerpo ⚠ (lo que haya tras un segundo `?` se pierde; una URL sin `?` provoca `NoSuchElementException`). El cuerpo
  se escribe con la codificación por defecto (UTF‑8); no se fija `Content-Type` salvo que el llamante lo pida.
* Sin proxy (`Proxy.NO_PROXY`), aunque el sistema tenga uno configurado.
* Sin tiempos de espera explícitos (se usan los de la plataforma); `servicetimeout` no existe.
* Estado 4xx/5xx → `HttpError(código, mensaje, url)`.
* **Validación TLS**: se desactiva (fábrica de *sockets* que confía en todo y verificador de nombres que acepta
  todo, instalados **globalmente** y restaurados al terminar la petición ⚠ no es seguro entre hilos) si se cumple
  cualquiera de:
  * compilación de depuración y URL `https`;
  * `validateSslChecks == false`;
  * el *host* coincide con la lista `secureDomainsList`.
* **Coincidencia de dominios**: la lista se parte por `\n`; *host* en minúsculas (`Locale.ROOT`); para cada entrada,
  `patrón` = entrada recortada, en minúsculas y **sin ningún `*`**, y según la entrada **sin recortar**:
  * empieza y termina por `*` → el *host* **contiene** el patrón;
  * empieza por `*` → el *host* **termina** en el patrón;
  * termina por `*` → el *host* **empieza** por el patrón;
  * si no → igualdad exacta.
  Ejemplos: `*.redsara.es` (patrón `.redsara.es`) acepta `www.redsara.es` pero no `redsara.es`; `*redsara*` acepta
  `pre.redsara.es`; `sede.*` acepta `sede.gob.es`; `a*b.es` (patrón `ab.es`, ni empieza ni acaba en `*`) solo acepta
  `ab.es`.
* La semántica es la del escritorio («dominios seguros» = sin comprobación TLS, `01` §12.6), pero la lista va por
  líneas, no por comas.
* No hay ningún aviso al usuario: ni diálogo para importar el certificado TLS de un servidor ni confirmación de
  dominios. Si la validación TLS falla, la petición falla y se trata como error de red de la operación (p. ej.
  AA401100 al descargar o AA401200 al subir).
* ⚠ Las preferencias se leen de un almacén estático que solo existe si alguna pantalla lo inicializó en el proceso;
  en un proceso nuevo lanzado para `save` se usan los valores por defecto (validación activa, lista vacía).

### 5.11 Respuestas de éxito (comparación con `01` §7.1)

| Operación | Con `key` | Sin `key` | Diferencia con escritorio |
|---|---|---|---|
| `sign`, `cosign`, `countersign` | `C(cert) "\|" C(firma)` | `B64U⏎(cert) "\|" B64U⏎(firma)` (Base64 URL‑safe de Android con saltos de línea) | sin tercer campo `extra`; saltos de línea sin clave |
| `selectcert` | `C(cert)` | `B64U(cert)` | igual |
| `batch` | `C(resultado) ["\|" C(cert)]` | `B64S(resultado) ["\|" B64S(cert)]` (estándar) | igual (resultado primero) |
| `save` | `OK` | `OK` | igual |

`C` = DES de §5.9; `B64U` = Base64 URL‑safe con relleno; `B64S` = Base64 estándar. Las respuestas no se suben dos
veces (el escritorio sube dos veces `selectcert` y `batch`).

### 5.12 Errores devueltos a la web

**Formato** (`ErrorManager.genError`): `ERR-NN:=AA<código> - <mensaje>`, donde `<mensaje>` es el texto de usuario
de la categoría (localizado, §8.1) o, si no se da, el texto fijo en español de `ERR-NN` (§8.2). Ejemplo:
`ERR-11:=AA500001 - Operacion cancelada` (el texto español de `operation_cancelled` no lleva tilde). Se codifica con `URLEncoder` antes de subirlo (§5.8.1).

AutoScript lo interpreta como en `01` §7.2: prefijo `err-`, separador `:=`, código `AA500001` (los 8 caracteres
antes de « - »); `err-11` = cancelación.

**`WebSignActivity`**:

| Situación | Diálogo | Respuesta |
|---|---|---|
| Error de parámetros | AA600006 | ninguna (intento fallido, §5.4.1); por intent `ERR-22` AA600006 |
| `fileid` sin `rtservlet` (inalcanzable: el análisis ya falla) | — | `ERR-22` AA600100 |
| Fichero no elegido | — | `ERR-11` AA500001 |
| PAdES sobre datos no PDF | AA200106 / AA200107 | `ERR-07` (y la firma sigue ⚠) |
| Política incompatible | AA600109 | `ERR-22` AA600109 |
| Vista previa cancelada / sin área obligatoria | — | `ERR-11` AA500001 |
| Error al cargar el PDF en la vista previa | AA200102 | `ERR-07` AA200102 |
| Error al cargar el almacén (incluida la cancelación de `PinDialog`/`SelectAliasDialog` ⚠ y almacén JCA vacío) | — | `ERR-23` AA201101 |
| Selección: error de alias Android 4.1 | — | `ERR-21` AA201102 |
| Selección: `KeyChainException` | — | `ERR-13` AA201103 |
| Selección cancelada (selector de tipo cerrado, `KeyChain` sin elegir sin NFC preferido, aviso cancelado…) | — | `ERR-11` AA500001 |
| Selección: otro error | — | `ERR-13` AA201105 |
| Formato sin firmador | AA600105 | `ERR-10` AA600105 |
| Firma cancelada (p. ej. contraseña PDF) | — | `ERR-11` AA500001 |
| Error de firma (`AOException` u otro) | — | `ERR-14` AA200002 |
| Permiso de almacenamiento denegado | — | `ERR-14` AA200002 |
| Error al cifrar la firma | — | `ERR-16` AA200100 |
| Error al subir | AA401200 | — |
| Atrás | — | `ERR-11` AA500001 y cierre |

**`WebSelectCertificateActivity`**:

| Situación | Diálogo | Respuesta |
|---|---|---|
| Error de parámetros | AA600006 | ninguna (mismo fallo que en firma) |
| Error al cargar el almacén (incl. cancelaciones de carga) | — | `ERR-23` AA201101 |
| Selección: alias Android 4.1 | — | `ERR-21` AA201103 |
| Selección: `KeyChainException` | — | `ERR-13` AA201103 |
| Selección cancelada | — | `ERR-11` **AA201104** «Certificado no seleccionado» |
| Selección: otro error | — | `ERR-13` AA201106 |
| Otro error de almacén | — | `ERR-25` AA201106 |
| Error al cifrar | — | `NullPointerException` (categoría mal buscada; previsto `ERR-16` AA200200) |
| Descarga / sobre | AA401101 / AA600006 | — |
| Error al subir | AA401200 | — |
| Atrás | — | `ERR-11` AA500001 |

**`WebSaveDataActivity`** (mensajes con el texto fijo de `ERR-NN`, no localizado):

| Situación | Respuesta |
|---|---|
| Cancelado o no guardado | `ERR-11:=AA500001 - Operacion cancelada` |
| Error al escribir | `ERR-26:=AA200305 - Error al guardar los datos en el dispositivo` |
| Error de descarga | `ERR-18:=AA400001 - Error de comunicacion con el servicio` |
| Error de descifrado / XML del sobre | `ERR-22:=AA600006 - No se ha realizado correctamente la invocacion de la aplicacion` |

Comportamiento común: los errores con diálogo y respuesta suben la respuesta y, al confirmarse la subida, cierran
la app (el diálogo apenas se ve). ⚠ Si el usuario pulsa Atrás después de un error ya subido, se sube además una
cancelación `ERR-11` con el mismo `id`, que puede sustituir al error si la página aún no lo leyó. La tecla Inicio
está programada para enviar `ERR-11`, pero Android no la entrega a las apps.

### 5.13 Invocación desde otras apps

Con la acción `es.gob.afirma.android.SIGN_SERVICE` (firma) o `…SIGN_BATCH_SERVICE` (lotes), el URI en los datos y
`startActivityForResult`:

* Se analizan los parámetros igual (con `servicesRequired=true`: si hay `id`, también hace falta `stservlet`).
* Éxito firma: `RESULT_OK` con extras `cert` (`byte[]` DER, si se pudo codificar) y `signature` (`byte[]`), sin
  cifrar. Éxito lote: `cert` (`byte[]` o `null` si no se pidió `needcert`) y `batchresult` (`byte[]` del JSON).
* Error: `RESULT_CANCELED` con `errorId` (`ERR-NN`) y `errorMsg` (`ERR-NN:=AA… - …`).
* No se usa el servidor intermedio ni se cierra la app con `finishAffinity`.
* Histórico: tipo `APP`/`BATCH_APP`; aplicación = `appname` o el paquete llamante.
* `selectcert` y `save` no tienen esta modalidad.

### 5.14 Trifásica

Los firmadores trifásicos cliente (`CAdEStri`, `CAdES-ASiC-S-tri`, `XAdEStri`, `XAdES-ASiC-S-tri`, `FacturaEtri`,
`PAdEStri`, `NONEtri`) siguen `01-protocol.md` §10 (URL del servidor en el extraParam `serverUrl`, prefirma, PKCS#1
local, postfirma) usando `AndroidHttpManager`. La firma XAdES y FacturaE pedida como monofásica también va por este
camino (§3.7.1), así que **necesita** `serverUrl` en los `properties`; sin él falla con `ERR-14`.

### 5.15 Tiempos y límites

| Elemento | Valor |
|---|---|
| Reintentos de descarga del sobre | 10 reintentos cada 2000 ms ante `ERR-06` |
| Espera activa (`#WAIT`) | cada 10 000 ms, solo lotes descargados |
| Tiempos de conexión/lectura HTTP | ninguno explícito |
| Detección del DNIe | sin límite |
| Caché de certificado | 5 / 15 / 30 / 60 / 120 min (defecto 5) |
| Aviso de caducidad | menos de 7 días |
| Identificadores | ≤ 20 alfanuméricos |
| Clave DES | 8 caracteres |
| Tamaño de datos | todo en memoria; `OutOfMemoryError` → AA200105 |

---

## 6. Firma por lotes (`WebSignBatchActivity`, `SignBatchFragmentActivity`, `BatchSigner`)

### 6.1 Alcance

Solo **lotes JSON contra un servidor** de lotes (`01-protocol.md` §9.2). No hay lote XML (`01` §9.3) ni lote local
(`localBatchProcess`, `01` §9.4): ambos acaban en error genérico de firma (`ERR-14` AA200002).

### 6.2 Análisis

* La URL se trocea con un analizador propio (`extractParamsForBatch`): lo que sigue al primer `?`, partido por `&`,
  cada `clave=valor` en el primer `=` (se descartan los trozos sin `=` o con `=` en la posición 0), valores con
  `URLDecoder` UTF‑8. A diferencia de las demás operaciones, **no** se añade `op` desde el *host*.
* `getParametersToBatch(mapa, servicesRequired=true)` (`01` §3.7, versión 1.9): `id`/`fileid`, `ver`, `appname`; si
  hay `fileid`, se para ahí; si no, `localBatchProcess`, `batchpostsignerurl` y `batchpresignerurl` (obligatorios
  salvo lote local; se validan como URLs de servlet), `stservlet`, `properties`, `sticky`, `resetsticky`, `needcert`,
  `jsonbatch`.
* Error → diálogo AA600006; el intento de responder falla igual que en §5.4.1 (no llega nada a la web).
* La versión `ver` se guarda en una variable estática la primera vez en el proceso y no se usa.

### 6.3 Lote descargado (`fileid`)

1. `rtservlet` presente → descarga (§5.8.2); ausente → `ERR-22` AA600401 (inalcanzable: el análisis ya exige
   `rtservlet`).
2. Descifrado DES y análisis del sobre XML con `getParametersToBatch(xml, true)`.
3. Si el sobre trae `aw=true` → arranca la espera activa (`#WAIT` cada 10 s, §5.8.3).
4. Se procesa el lote.

⚠ Los errores de la descarga (diálogo AA401100 y respuesta `ERR-14` AA401100) y del descifrado/sobre (diálogo y
`ERR-22` AA600006) intentan responder usando los parámetros de la URL, que no tienen `stservlet` (el análisis se
detuvo en `fileid`): la subida lanza `NullPointerException` en segundo plano y **la app se cierra**.

### 6.4 Proceso

1. Diálogo «Firmando». Elección de almacén y certificado como en la firma (§4.1), con caché *sticky* (§4.7) y avisos
   de caducidad/seudónimo para certificados de `KeyChain` (§4.6). ⚠ Si el usuario cancela el selector de `KeyChain`,
   el lote se cancela aunque haya NFC preferido (la firma simple volvería a ofrecer el DNIe).
2. Caché: se guarda si `sticky=true` y no es DNIe; si no, se borra.
3. Si el almacén es JCA, extraParams del PKCS#1: `Provider.<clase de clave> = <proveedor>`.
4. `jsonbatch` debe ser `true`; si no → `IllegalStateException` «600407 - El data de la operacion de firma batch no es
   un JSON valido» → `ERR-14` AA200002.
5. `BatchSigner.signJSON(B64U(datos), pre, post, cadena, clave, extraParams PKCS#1)`:
   1. Validaciones: datos vacíos → AA600400; sin prefirmador → AA600405; sin postfirmador → AA600406; sin
      certificados → AA501001 (todas como `IllegalArgumentException`).
   2. `json` = Base64 URL‑safe (con `=`) de los bytes decodificados de `dat`; `certs` = cada certificado de la
      cadena en Base64 URL‑safe, unidos por `;`.
   3. Prefirma: `POST <pre>` con `json=<json>&certs=<certs>`.
   4. Respuesta JSON: `td` (objeto con `signs[].signinfo[]` o `signinfo[]` plano; cada entrada `id` y `params`, todos
      los valores como texto) y/o `results` (lista de `{id, result, description?}`; lista vacía = ausente; `result`
      debe ser un nombre válido: `NOT_STARTED`, `DONE_AND_SAVED`, `DONE_BUT_NOT_SAVED_YET`, `DONE_BUT_SAVED_SKIPPED`,
      `DONE_BUT_ERROR_SAVING`, `ERROR_PRE`, `ERROR_POST`, `SKIPPED`, `SAVE_ROLLBACKED`).
   5. Ni `td` ni `results` → devuelve `{"signs":[]}`. Solo `results` → devuelve
      `{"signs":[{"id":…,"result":…[,"description":…]},…]}` sin postfirma.
   6. Con `results` y `td`: en el JSON del lote, cada `singlesigns[i]` cuyo `id` coincida pierde `datareference`,
      `format`, `suboperation` y `extraparams` y gana `result` (y `description`); se vuelve a codificar en URL‑safe.
   7. Algoritmo = campo `algorithm` del JSON del lote (JSON inválido → AA600407; sin `algorithm` → AA600408),
      compuesto con el tipo de clave en cada PKCS#1 (`TriphaseDataSigner`, `01` §10.4).
   8. Postfirma: `POST <post>` con `json=<json>&certs=<certs>&tridata=<B64U(UTF‑8 de {"format":…,"signinfo":[{"id":…,"params":{…}}]})>`.
      ⚠ A diferencia del escritorio, el `signid` de cada `signinfo` se pierde (no se lee ni se reenvía).
   9. Resultado = cuerpo de la respuesta de la postfirma tal cual.
   10. Errores HTTP (prefirma: se registra AA300400; postfirma: AA300404): 400 → `IllegalArgumentException`
       (AA600006); otro 4xx → `HttpError`; 5xx → `AOException` (AA200002).
6. PIN incorrecto de tarjeta (`AOException` con causa `ActivityNotFoundException` o
   `SignatureAuthException`→`BadPinException`) → se repite la carga del almacén indicando PIN incorrecto (§4.9.8).

### 6.5 Respuesta

* `needcert=true` → se añade el DER del certificado de firma (error al codificar → `ERR-14` AA200401).
* Con `key`: `C(resultado) ["|" C(cert)]`; error de cifrado → `ERR-14` AA200400. Sin `key`: Base64 **estándar** de
  `afirma-core` (sin saltos).
* Por intent (`SIGN_BATCH_SERVICE`): `RESULT_OK` con `cert` y `batchresult` (§5.13).
* Si no, se interrumpe la espera activa y se sube (crítico). Éxito → cierra la app (§5.4.6). Fallo crítico →
  diálogo AA401200. ⚠ Fallo de una subida no crítica (p. ej. una cancelación) → la actividad se queda abierta.
* Histórico: `BATCH` (o `BATCH_APP` por intent), operación `sign`, fichero `null`, aplicación = `appname` (o
  paquete llamante).

### 6.6 Errores

| Situación | Respuesta |
|---|---|
| Error al cargar el almacén (incl. cancelación de carga ⚠) | `ERR-23` AA201101 |
| Selección: alias Android 4.1 | `ERR-21` AA201102 (desde el evento de clave) o AA201103 (desde el almacén) |
| Selección: `KeyChainException` | `ERR-13` AA201103 |
| Selección cancelada | `ERR-11` AA500001 |
| Selección: otro error | `ERR-13` AA201105 (evento de clave) o AA201106 (almacén) |
| Otro error de almacén | `ERR-25` AA201106 |
| Firma cancelada | `ERR-11` AA500001 |
| Formato no soportado | diálogo + `ERR-10` AA600105 |
| Política incompatible | diálogo + `ERR-22` AA600109 |
| `HttpError` (4xx distinto de 400) | `ERR-18` AA400001 |
| `AOException` u otro (incl. lote XML/local, 400, 5xx, JSON inválido) | `ERR-14` AA200002 |
| Atrás | `ERR-11` AA500001 |

---

## 7. Preferencias

`SharedPreferences` privadas con nombre **`afirma.client`** (`/data/data/es.gob.afirma/shared_prefs/afirma.client.xml`),
gestionadas por `AppConfig`. No se copian (`allowBackup=false`). No hay importación/exportación, bloqueo ni
configuración remota.

| Clave | Tipo | Defecto | Dónde se cambia | Efecto |
|---|---|---|---|---|
| `firstExecution` | boolean | `true` | Inicio (al mostrar y cerrar `ConfigNfcDialog`) | Muestra una vez la pregunta sobre el NFC (§2.5) |
| `useNfc` | boolean | `false` | `ConfigNfcDialog` «Sí»; Configuración de firma «Permitir firmar con DNIe por NFC» (al Guardar) | Muestra `ChooseCertTypeDialog` y habilita el DNIe por NFC (§4.1) |
| `skipIntroScreen` | boolean | `false` | Bienvenida «Comenzar» | Splash salta la bienvenida |
| `skipConditionsScreen` | boolean | `false` | Condiciones «Aceptar» | Splash salta las condiciones |
| `validateSslChecks` | boolean | `true` | Dominios de confianza «Validar conexiones SSL» (al instante) | `false` desactiva la validación TLS en todas las conexiones (§5.10) |
| `secureDomainsList` | string (un dominio por línea, `\n`) | ausente (= vacío) | Dominios de confianza (al Guardar; vacío borra la clave) | Dominios sin validación TLS (§5.10) |
| `padesVisibleSignature` | boolean | `false` | Configuración de firma «Hacer firma visible» (al Guardar) | Vista previa y firma visible en la firma **local** de PDF (§3.4) |
| `padesObfuscateCertInfo` | boolean | `true` | Configuración de firma «Ofuscar identificadores…» (al Guardar) | `obfuscateCertText` en firmas visibles local y web (§3.5.5) |
| `stickySignatureTimeout` | string con entero | `"5"` | Configuración de firma, minutos de caché (al Guardar) | Vida de la caché de certificado: 5, 15, 30, 60 o 120 min (§4.7) |
| `localeConfig` | string | `"es"` | Idioma; Condiciones (y **cada vez** que se abren, a `es` ⚠) | Idioma de la interfaz y de los HTML legales: `es`, `en`, `ca`, `gl`, `eu`, `ca-ES-valencia` |

Otros datos persistentes: el histórico `files/signsRecord.txt` (§3.10) y los ficheros temporales de Android ≥ 11 en
la caché (§3.1). CAN, PIN, etiqueta NFC y caché de certificado viven solo en memoria.

---

## 8. Catálogo de errores

### 8.1 Categorías `AA` (`errors/*Errors.java`)

Cada categoría tiene código, texto de usuario (recurso localizado, regenerado al cambiar de idioma) y texto de
administración (fijo, en español, solo para el log). Al usuario se muestra «AA`<código>` - `<texto de usuario>`»;
al log, «AA`<código>` - `<texto de administración>`». «*Genérico*» = `not_completed_request`: «Hemos intentado procesar
tu solicitud, pero no ha podido ser completada con éxito. Por favor revisa la documentación.».

| Código | Clave interna | Texto de usuario (`clave`) | Texto de administración |
|---|---|---|---|
| 102000 | `RESET_NFC` | *Genérico* | Error al resetear la tarjeta NFC |
| 200000 | `SOFTWARE_GENERAL` | *Genérico* | Error general de software |
| 200001 | `CANT_SAVE_SIGN_RECORD` | *Genérico* | La firma se ha realizado correctamente pero no se ha podido guardar en el histórico de firmas |
| 200002 | `ERROR_SIGNING` | *Genérico* | Error durante la firma |
| 200100 | `CYPHERING_SIGN` | *Genérico* | Error al cifrar la firma para enviarla al servidor intermedio |
| 200101 | `ENCRYPTING_CERT` | *Genérico* | Error al cifrar el certificado para enviarlo al servidor intermedio |
| 200102 | `LOADING_LOCAL_FILE` | *Genérico* | Error al cargar el fichero local para realizar la firma |
| 200105 | `OUT_OF_MEMORY` | `file_read_out_of_memory` | Error de memoria al cargar el fichero |
| 200106 | `USER_SELECT_NOT_PDF` | `necessary_pdf_file` | El usuario selecciono un documento no PDF sobre el que realizar una firma PAdES |
| 200107 | `PADES_NO_PDF_SIGN` | *Genérico* | No es posible hacer firma PAdES sobre datos no PDF |
| 200200 | `CYPHERING_CERT` | *Genérico* | Error al cifrar el certificado para enviarlo al servidor intermedio |
| 200301 | `SAVING_DATA_DISK` | *Genérico* | No se ha podido guardar el fichero en disco |
| 200302 | `NO_DEVICE_STORE` | *Genérico* | No se ha encontrado donde guardar la firma generada |
| 200303 | `CANT_OBTAIN_DATA_FLOW` | `error_saving_signature` | No se pudo obtener el flujo para el guardado de los datos (sin uso) |
| 200304 | `NO_STORAGE_PERMISSIONS` | `error_no_storage_permissions` | No dispone de permisos de escritura |
| 200305 | `SAVING_DATA_OP` | `error_saving_data` | Error al guardar datos |
| 200400 | `CYPHERING_SIGN_INFO_TO_SEND` | *Genérico* | Error al cifrar la información de las firmas del lote para enviarla al servidor intermedio |
| 200401 | `CYPHERING_CERT_TO_SEND` | *Genérico* | Error al cifrar el certificado para enviarlo al sevidor intermedio |
| 200700 | `DOMAIN_FORMAT_INCORRECT` | `error_format_trusted_domains` (con `%s` sin sustituir; la pantalla compone su propio texto) | Se han encontrado entradas no validas en el listado de dominios |
| 201100 | `LOAD_CERT_TO_IMPORT` | `cant_add_cert_message` | Error en la carga de certificado para importar |
| 201101 | `LOAD_KEYSTORE` | `error_loading_keystore` | Error al cargar el almacen de certificados |
| 201102 | `ALIAS_NOT_VALID` | `error_loading_cert` | Error al cargar el certificado, posiblemente relacionado por usar un alias de certificado no valido |
| 201103 | `LOAD_KEY` | `error_loading_cert` | Error al cargar la clave del certificado |
| 201104 | `USER_NOT_SELECT_CERT` | `not_selected_cert` | El usuario no selecciono un certificado |
| 201105 | `UNEXPECTED_RECOVERING_KEY` | `error_loading_cert` | Error inesperado al recuperar la clave del certificado de firma |
| 201106 | `LOAD_CERT` | `error_loading_cert` | Error al cargar certificado |
| 300100 | `UNKNOWN_OR_NOT_SUPPORTED_CARD` | `unsupported_card` | La tarjeta identificada en el lector es desconocida o no esta soportada |
| 300102 | `CANT_CONNECT_CARD` | `unsupported_card` | No se ha podido conectar con la tarjeta |
| 300103 | `ERROR_INITIALIZING_CARD` | `error_reading_dnie_try_again` | La conexion con la tarjeta no esta inicializada |
| 300104 | `UNEXPECTED` | `error_reading_dnie_try_again` | Ocurrio un error inesperado durante la operacion (sin uso) |
| 300105 | `INCORRECT_PIN` | `error_msc_pin` | (`incorrect_pin`) PIN incorrecto |
| 300106 | `BLOCKED_CARD` | `error_dni_blocked_dlg` | Tarjeta bloqueada |
| 300108 | `CAN_VALIDATION` | `nfc_card_initializing_error` | Error durante la validacion del CAN |
| 300110 | `NOT_HAVE_CERTIFICATE` | `error_reading_dnie_no_cert` | No se dispone de certificado de firma digital (sin uso) |
| 300400 | `HTTP_PRESIGN` | *Genérico* | Error HTTP al realizar la operacion de prefirma |
| 300404 | `HTTP_POSTSIGN` | *Genérico* | Error HTTP al realizar la operacion de posfirma |
| 400000 | `UNKNOWN_ERROR` | *Genérico* | Error desconocido al enviar el error obtenido al servidor |
| 400001 | `COMMUNICATION_WITH_SERVICE` | *Genérico* | Error durante la descarga de la configuracion para la seleccion de certificado |
| 401100 | `DOWNLOAD_SIGN` | *Genérico* | Error en la descarga de la firma |
| 401101 | `DOWNLOAD_CONFIG_CERT` | *Genérico* | Error durante la descarga de la configuracion para la seleccion de certificado |
| 401200 | `UPLOAD_DATA` | *Genérico* | Error en el envio de datos |
| 500001 | `CANCELED_BY_USER` | `operation_cancelled` | Operacion cancelada por el usuario |
| 501001 | `NO_CERTIFICATES` | `error_desc_keystore_empty` | Error en la operacion, no hay certificados |
| 600002 | `NOT_SUPPORTED_OPERATION` | *Genérico* | La operacion no esta soportada |
| 600006 | `REQUEST_PARAM_NOT_VALID` | *Genérico* | Los parametros de la peticion no eran validos |
| 600007 | `ENCODING_CERT` | *Genérico* | Error en la codificacion del certificado |
| 600008 | `INVOCATION_WITHOUT_URL` | *Genérico* | Se ha invocado sin URL a la actividad de firma por protocolo |
| 600100 | `NO_DATA_NO_ID` | *Genérico* | No se ha recibido los datos en la petición ni el id del fichero a descargar para la operacion de firma |
| 600105 | `FORMAT_NOT_VALID` | *Genérico* | El formato de firma no es valido para la operacion de firma |
| 600106 | `NOT_SUPPORTED_OPERATION` (en `SIGN_REQUEST`) | *Genérico* | No se ha recibido el algoritmo de firma para la operación de firma (sin uso) |
| 600108 | `CANT_DECODE_DATA` | *Genérico* | Los datos de la operacion no se han podido decodificar para la operacion de firma |
| 600109 | `PARAM_NOT_COMPATIBLE_POLICY` | *Genérico* | Los parametros configurados son incompatibles con la politica de firma |
| 600400 | `NO_DATA_NO_ID_BATCH` | *Genérico* | No se ha recibido los datos en la petición ni el id del fichero a descargar para la operacion de firma de lotes |
| 600401 | `URL_DOWNLOAD_NOT_FOUND_BATCH` | *Genérico* | Es necesario descargar la informacion del servidor intermedio, ha llegado el id de fichero pero no ha llegado la url del servidor de descarga para la operacion de firma de lotes |
| 600403 | `FILE_ID_NOT_FOUND_BATCH` | *Genérico* | No se ha recibido el id del fichero a guardar para la operacion de firma de lotes (sin uso) |
| 600405 | `BATCHPRESIGNERURL_NOT_FOUND_BATCH` | *Genérico* | No se ha recibido el batchpresignerurl en la firma batch |
| 600406 | `BATCHPOSTSIGNERURL_NOT_FOUND_BATCH` | *Genérico* | No se ha recibido el batchpostsignerurl en la firma batch |
| 600407 | `JSON_NOT_FORMED_CORRECTLY` | *Genérico* | El data de la operacion de firma batch no es un JSON valido |
| 600408 | `ALGORITHM_NOT_FOUND_BATCH` | *Genérico* | No se ha recibido el algoritmo de firma en la firma batch |

Los catálogos están vacíos hasta que una actividad aplica el idioma (§2.4).

### 8.2 Identificadores `ERR-NN` (`ErrorManager`)

Texto fijo (sin acentos) que se usa como mensaje cuando no se da otro (solo `save` lo usa):

| Id | Texto | Id | Texto |
|---|---|---|---|
| `ERR-00` | No se ha indicado codigo de operacion | `ERR-13` | No se pudo recuperar la clave del certificado |
| `ERR-01` | Codigo de operacion no soportado | `ERR-14` | Ocurrio un error en la operacion de firma |
| `ERR-02` | No se han proporcionado los datos de la operacion | `ERR-15` | La clave de cifrado proporcionada no es valida |
| `ERR-03` | Se ha recibido un XML mal formado | `ERR-16` | Error durante el proceso de cifrado de los datos |
| `ERR-04` | Se ha recibido un certificado corrupto | `ERR-17` | No se selecciono ningun certificado de firma |
| `ERR-05` | No se ha proporcionado un identificador para los datos | `ERR-18` | Error de comunicacion con el servicio |
| `ERR-06` | El identificador para los datos es invalido | `ERR-21` | Android 4.1 y 4.1.1 no permiten que los nombres de certificados contengan caracteres especiales (espacios, guiones...). Modifique el alias de sus certificados al importarlos para evitar este error. |
| `ERR-07` | Los datos solicitados o enviados son invalidos | `ERR-22` | No se ha realizado correctamente la invocacion de la aplicacion |
| `ERR-08` | No se ha proporcionado el sevlet para la comunicacion de los datos | `ERR-23` | No se ha podido establecer un almacen de certificados para su uso |
| `ERR-09` | La ruta del servlet es invalida | `ERR-24` | Error en la firma. Compruebe que el PIN de su dispositivo criptografico es correcto. Varios intentos incorrectos pueden bloquearlo. |
| `ERR-10` | Se ha configurado un formato de firma no soportado | `ERR-25` | Ocurrio un error en la seleccion del certificado |
| `ERR-11` | Operacion cancelada | `ERR-26` | Error al guardar los datos en el dispositivo |
| `ERR-12` | Error en la codificacion del base 64 | — | Id desconocido: «Error generico» |

Plantilla: `%#%:=AA%ECC% - %MSG%` → `<id>:=AA<código> - <mensaje>`.

---

## 9. Textos de la interfaz

### 9.1 Idiomas

| Carpeta | Idioma (etiqueta guardada) | Estado |
|---|---|---|
| `values` | español (`es`), referencia y respaldo | 272 textos |
| `values-en` | inglés (`en`) | 272; completo |
| `values-ca` | catalán (`ca`) | 272; completo salvo «No usar DNIe», «Guardar» y «Contrafirma», que siguen en español. ⚠ `intro_title` «Signatura fàcil i segura/segura» |
| `values-gl` | gallego (`gl`) | 272 claves, pero unas 50 siguen en español; algunas se escriben igual en gallego («Aceptar», «Cancelar», «Entendido»), otras no están traducidas: «Cargando almacén de claves», «Realizando firma», «Histórico de firmas», «Cofirma», «Contrafirma», «Operacion cancelada», «Selecciona un valor en minutos», «Por defecto»… |
| `values-eu` | euskera (`eu`) | 272; completo. ⚠ `app_name` «Aplikazio automatikoa» (traducción automática del nombre: es el nombre que muestra el lanzador con el sistema en euskera) |
| `values-b+ca+ES+valencia` | valenciano (`ca-ES-valencia`, abreviatura `VA`) | 272; completo salvo «No usar DNIe» y los textos sin uso «Error en la firma»/«Firma correcta» |

Todas las carpetas tienen exactamente las mismas claves (ninguna cae al español por falta de clave); además de lo
indicado, coinciden con el español las URLs, los nombres de idioma y las unidades (`bytes`, `KB`, `MB`). El inglés tiene
`disclaimer` mal escapado («España» literal), sin uso. `privacy_policy_url` y `accessibility_statement_url`
varían por idioma (§2.6). Los HTML legales existen para los seis idiomas (§1.6).

### 9.2 Textos fuera de `strings.xml`

| Dónde | Texto |
|---|---|
| `res/values/extra.xml` (no traducibles) | `extra_can` = `canValue`, `extra_pin` = `pinValue`, `extra_keystore` = `keystore`, `extra_value_keystore_dnie` = `dnie`, `extra_value_keystore_local` = `local` (los tres últimos sin uso) |
| `menu/home_toolbar.xml` | «Informacion», «Ajustes» (títulos fijos en español) |
| `menu/sign_dnie_toolbar.xml` | «Cerrar proceso de firma con DNIe»; descripción «Cierra el proceso de firma con DNIe» |
| `menu/sign_records_toolbar.xml` | «Eliminar» |
| `LoadDeviceKeystoreAsyncTask` | «Cargando almacén de claves del dispositivo» |
| `SignConfigurationActivity`, `SelectCacheMinutesDialog` | «`N` Min» |
| `custom_dialog.xml` | marcadores «Titulo» y «Mensaje» (siempre sustituidos) |
| `activity_settings.xml` | «ES» (sustituido por la abreviatura del idioma) |
| Plantillas `ErrorManager` | §8.2 |

En las tablas siguientes, «⏎» representa un salto de línea (`\n`) y se conservan las etiquetas HTML de los textos que
las llevan (`<u>`, `<b>`, `<p>`).

### 9.3 Comunes (botones, títulos y mensajes compartidos)

| Clave | Texto (es) |
|---|---|
| `app_name` | Autofirma App |
| `main_logo_content_desc` | Autofirma App |
| `ok` | Aceptar |
| `cancel` | Cancelar |
| `cancel_underline` | <u>Cancelar</u> |
| `yes` | Sí |
| `no` | No |
| `allow` | Permitir |
| `understood` | Entendido |
| `drag_on` | Continuar |
| `start` | Comenzar |
| `begin` | Empezar |
| `try_again` | Volver a intentarlo |
| `save_changes` | Guardar |
| `changes_saved` | Cambios guardados |
| `changes_saved_correctly` | Los cambios se han guardado correctamente. |
| `error_ocurred` | ¡Algo salió mal! |
| `not_completed_request` | Hemos intentado procesar tu solicitud, pero no ha podido ser completada con éxito. Por favor revisa la documentación. |
| `operation_cancelled` | Operacion cancelada |

### 9.4 Bienvenida (`IntroScreenActivity`)

| Clave | Texto (es) |
|---|---|
| `intro_title` | Firma fácil y segura |
| `intro_text` | Firma documentos de forma segura y legal identificándote con tu certificado digital o DNI electrónico. |

### 9.5 Aceptación de condiciones (`ConditionsActivity`)

| Clave | Texto (es) |
|---|---|
| `acceptance_conditions` | Aceptación de textos legales |
| `language` | Idioma |
| `read_and_accept_privacy` | He leído y estoy de acuerdo con la Política de Privacidad |
| `read_and_accept_legal` | He leído y estoy de acuerdo con el Aviso Legal y los Términos y Condiciones de Uso |

### 9.6 Inicio (`MainFragment`, menú, `HelpDialog`, `ConfigNfcDialog`)

| Clave | Texto (es) |
|---|---|
| `presentation_title` | Te damos la bienvenida |
| `presentation_text` | Esta aplicación permite realizar firmas electrónicas en las páginas de los proveedores de servicios que lo soporten.⏎⏎Para funcionar correctamente debe tener un certificado electrónico y su clave privada instalados en su dispositivo, consulte la documentación de su sistema Android y con su proveedor de servicios de certificación. |
| `accesibility_select_option` | Seleccione una opción |
| `sign_file` | Firmar fichero |
| `add_new_cert` | Añadir nuevo certificado |
| `signed_file_title` | Fichero firmado |
| `signed_file_message` | El fichero ha sido firmado correctamente. |
| `nostorageperm` | Es necesario conceder permisos sobre la memoria para hacer firmas locales |
| `enable_nfc_question` | Se ha detectado que su dispositivo dispone de NFC. ¿Desea habilitarlo para la firma con el DNIe por NFC? |
| `what_is_autofirma_for_title` | ¿Para qué sirve Autofirma? |
| `what_is_autofirma_for_desc` | Esta aplicación permite realizar firmas electrónicas en las páginas de los proveedores de servicios que lo soporten. Para funcionar correctamente debes instalar un certificado electrónico. Consulta la documentación de su sistema Android y con tu proveedor de servicios de certificación. |
| `how_install_certs` | ¿Cómo instalar certificados? |
| `load_cert` | Carga tu certificado en tu dispositivo o en la nube. Impórtalo a través de la opción "Añadir certificado" de la aplicación. |
| `allowed_extensions` | Extensiones permitidas: .p12 y .pfx. Recuerda que necesitas la contraseña de exportación de tu certificado, y que éste debe de incluir la clave privada.  |
| `more_information_underline` | Más información |
| `settings` | Ajustes |

### 9.7 Importación de certificados (`CertImportInstructionsActivity`, `MainFragment`)

| Clave | Texto (es) |
|---|---|
| `title_activity_cert_chooser` | Importar certificado |
| `locate_file_title` | Localiza el archivo |
| `locate_file_message` | Localiza el archivo .p12 o .pfx. en tu teléfono |
| `send_to_device_title` | Envía al dispositivo |
| `send_to_device_message` | Si no lo encuentras, envíalo a tu móvil desde otro dispositivo mediante correo electrónico u otras aplicaciones en la nube. |
| `add_cert` | Añadir certificado |
| `added_cert_title` | Certificado añadido |
| `added_cert_message` | El certificado se ha añadido correctamente |
| `cant_add_cert_title` | No hemos podido añadir tu certificado |
| `cant_add_cert_message` | No hemos podido añadir tu certificado a la aplicación de Autofirma de manera correcta. Inténtalo de nuevo más tarde |

### 9.8 Ajustes (`SettingsActivity`)

| Clave | Texto (es) |
|---|---|
| `my_settings` | MI CONFIGURACIÓN |
| `sign_configuration` | Configuración de firma |
| `trusted_domains` | Dominios de confianza |
| `sign_record` | Histórico de firmas |
| `help` | AYUDA |
| `faq` | Preguntas frecuentes |
| `activate_use_dnie_with_nfc_1` | Activar el uso del DNIe por NFC |
| `how_to_do_visible_sign` | Cómo hacer firma visible |
| `how_to_configure_trusted_domains` | Cómo configurar dominios de confianza |
| `how_to_install_certs` | Cómo instalar certificados |
| `general_info` | INFORMACIÓN GENERAL |
| `accessibility_statement` | Declaración de accesibilidad |
| `accessibility_statement_url` | http://estaticos.redsara.es/comunes/clientefirmaandroid/1/8/0/declaracion_accesibilidad.pdf |
| `legal_announcement` | Aviso legal |
| `privacy_policy` | Política de privacidad |
| `appversion` | Versión v%s |

### 9.9 Idiomas (`LanguageActivity`, `ConditionsActivity`)

| Clave | Texto (es) |
|---|---|
| `espanol` | Español |
| `english` | English |
| `french` | Français |
| `catala` | Catalá |
| `galego` | Galego |
| `euskera` | Euskera |
| `valenciano` | Valencià |

### 9.10 Configuración de firma (`SignConfigurationActivity`, `SelectCacheMinutesDialog`)

| Clave | Texto (es) |
|---|---|
| `allow_dni3_0_NFC` | Permitir firmar con DNIe por NFC |
| `do_visible_sign` | Hacer firma visible |
| `hide_user_id` | Ofuscar identificadores de usuario de los certificados de las firmas visibles |
| `delete_cache_minutes` | Minutos para la eliminación de caché de certificado |
| `select_minutes_value` | Selecciona un valor en minutos |
| `select` | Seleccionar |
| `by_default` | Por defecto |

### 9.11 Dominios de confianza (`TrustedDomainsActivity`)

| Clave | Texto (es) |
|---|---|
| `validate_SSL_connections` | Validar conexiones SSL |
| `trusted_domains_desc` | Introduzca en el siguiente apartado los dominios de confianza para la aplicación |
| `error_format_trusted_domains` | El dominio "%s" tiene un formato incorrecto. |
| `use_asterisk` *(sin uso)* | Use asterisco (*) al principio o final como comodín. |
| `enter_trusted_domains` *(sin uso)* | Introduzca uno o varios dominios de confianza |

### 9.12 Histórico de firmas (`SignsRecordActivity`, `SignsRecordAdapter`)

| Clave | Texto (es) |
|---|---|
| `no_records` | No se encuentran registros |
| `no_records_desc` | No hay firmas registradas que eliminar. |
| `eliminate_history` | Eliminar histórico |
| `eliminate_history_desc` | Si eliminas el histórico no podrás recuperarlo. |
| `local_sign_record` | %1$s local del fichero %2$s |
| `web_sign_record` | %1$s web solicitada por %2$s |
| `web_sign_record_file` | %1$s web del fichero %2$s |
| `web_sign_record_appname_and_file` | %1$s web solicitada por %2$s del fichero %3$s |
| `app_sign_record` | %1$s solicitada por %2$s |
| `app_sign_record_file` | %1$s solicitada desde otra aplicación del fichero %2$s |
| `app_sign_record_appname_and_file` | %1$s solicitada por %2$s del fichero %3$s |
| `app_batch_sign_record` | Firma de lote solicitada por %s |
| `batch_sign_record` | Firma de lote web solicitada por %s |
| `web_operation` | %s web |
| `app_operation` | %s realizada desde otra aplicación |
| `sign` | Firma |
| `cosign` | Cofirma |
| `countersign` | Contrafirma |

### 9.13 Preguntas frecuentes (`FaqActivity`)

| Clave | Texto (es) |
|---|---|
| `question_1` | ¿Cómo puedo realizar firmas electrónicas con esta app? |
| `response_1` | <p>Autofirma App permite firmar con certificado trámites web compatibles con la aplicación. </p><p>Para firmar un trámite, complételo normalmente a través de su navegador web. Si el trámite está preparado para la firma con Autofirma App, esta se ejecutará en el momento de la firma, permitirá al usuario seleccionar el certificado de firma y ejecute la operación. </p><p>También existe la posibilidad de abrir la aplicación y firmar directamente un fichero para uso personal. A los documentos PDF se les agregará una firma, mientras que para los demás ficheros se generará un fichero de firma independiente. </p><p>Recuerde que para poder firmar antes debe haber importado su certificado de firma en Android.</p> |
| `question_2` | La firma de algunos trámites web con Autofirma App falla, mientras que en esos mismos trámites funciona en otros dispositivos. ¿Por qué? |
| `response_2` | Autofirma App carece aún de ciertas funcionalidades que sí están presentes en versiones para otros sistemas operativos. Futuras actualizaciones de la app solventarán estas carencias. Mientras tanto, utilice un PC con Autofirma instalado para completar el trámite web y notifique el problema al responsable del trámite si lo considera preciso. |
| `question_3` | ¿Corren peligro mis certificados si pierdo el dispositivo? |
| `response_3` | Los certificados se almacenan en su dispositivo con un potente cifrado, pero como cualquier sistema criptográfico, en el momento que este está fuera del control de propietario corre el riesgo de ser comprometido. Si pierde el dispositivo debe contactar lo antes posible con su proveedor de servicios de certificación para revocar de inmediato los certificados que este contenía. |

### 9.14 Pantallas de ayuda

| Clave | Texto (es) |
|---|---|
| `dnie_with_nfc_help_text_1` | Autofirma App permite firmar mediante DNI electrónico a través de NFC. Si su dispositivo dispone de conexión NFC, puede habilitar la firma con DNIe activando la conexión NFC del dispositivo y la opción 'Permitir firmar con DNIe por NFC' en la sección 'Configuración de firma'. |
| `dnie_with_nfc_help_text_2` | Una vez activas, al realizar una firma se le permitirá seleccionar si desea firmar con certificado electrónico o con DNI electrónico. |
| `visible_sign_help_text_1` | Autofirma App permite hacer firma visible de documentos PDF que tenga en su dispositivo, en los que aparecerá el propietario y emisor del certificado y la fecha y hora de la firma. Puede habilitar la firma visible activando la opción 'Hacer firma visible' en la sección 'Configuración de firma'. |
| `visible_sign_help_text_2` | Si no desea que su DNI/NIE aparezca visible en el texto de la firma, puede ocultarlo parcialmente activando la opción 'Ofuscar identificadores de usuario de los certificados de las firmas visibles'. |
| `visible_sign_help_text_3` | Durante la firma del documento se le mostrará una miniatura del mismo y controles que le permitirán navegar entre sus páginas y seleccionar la posición en la que desea incluir la firma. |
| `visible_sign_help_text_4` | Seleccione el área en la que posicionar la firma y pulse 'Continuar' para firmar el documento. |
| `trusted_domains_help_text_1` | Si necesita realizar un trámite en alguna web con un dominio que no utilice un certificado SSL en el que Android confíe, puede agregar este dominio a la lista de dominios seguros de la aplicación desde la sección 'Dominios de confianza'. En esta sección puede componer la lista de dominios que considera seguros, para los que no es necesario validar el certificado SSL. Agregue los distintos dominios separados por comas (',') y usando un comodín ('*') al principio o final del nombre si fuese preciso. |
| `trusted_domains_help_text_2` | En este apartado también podría desactivar la validación del certificado SSL para todos los dominios desactivando la opción 'Validar conexiones SSL'. No es seguro desactivar completamente la validación de los certificados de conexión, por lo que debe evitarse siempre que sea posible. |
| `go_to_configuration` | Ir a configuración  |
| `import_certs_help_text_1` | Autofirma App utiliza los certificados del almacén de claves de Android para firmar. Puede instalar un nuevo certificado abriendo directamente el fichero .p12 o .pfx con las claves del certificado e introduciendo su contraseña. También puede seleccionar ese mismo fichero a través de la opción 'Añadir nuevo certificado' de la pantalla principal de Autofirma App. |
| `import_certs_help_text_2` | El certificado recién instalado ya estará disponible en su dispositivo y podrá usarlo desde Autofirma App para firmar. |
| `import_certs_help_text_3` | Si no encuentras el fichero de claves en tu móvil, puedes enviártelo desde otro dispositivo por correo electrónico u otras aplicaciones en la nube. |
| `go_to_import_cert` | Añadir un certificado  |

### 9.15 Versión (`VersionActivity`)

| Clave | Texto (es) |
|---|---|
| `version_desc_p1` | “Autofirma App” v.%s 2025 Gobierno de España |
| `version_desc_p2` | Autofirma App es Software Libre; puedes redistribuirlo y/o modificarlo bajo los términos de la siguiente licencia: “European Software License 1.1”, Cuyo texto completo puede consultarse en la siguiente página Web: |
| `version_desc_link1` | https://eupl.eu/1.1/es |
| `version_desc_p3` | El código fuente de este programa, así como del resto de los componentes del proyecto se pueden descargar libremente desde:  |
| `version_desc_link2` | http://forja-ctt.administracionelectronica.gob.es |
| `version_desc_p4` | El proyecto Autofirma App es un proyecto colaborativo, si desea participar en él, no dude en unirse a la comunidad, accesible desde la siguiente página Web: |
| `version_desc_link3` | https://administracionelectronica.gob.es/ctt/clienteafirma/mas#.Xxp7T0I7mhc |

### 9.16 Selector de ficheros (`FileChooserActivity`, `FileArrayAdapter`)

| Clave | Texto (es) |
|---|---|
| `title_activity_choose_sign_file` | Seleccione el fichero a firmar |
| `file_chooser_directorio_actual` | Directorio actual: %s |
| `file_chooser_directorio` | Directorio |
| `file_chooser_directorio_padre` | Directorio padre |
| `file_chooser_tamano_del_fichero` | Tamaño: |
| `bytes` | bytes |
| `kilobytes` | KB |
| `megabytes` | MB |
| `accesibility_back_parent_folder` | Volver a directorio padre |
| `accesibility_open_folder` | Directorio %1$s |
| `accesibility_select_file` | Fichero %1$s |
| `accesibility_icon_filetype` | Icono del tipo de archivo |
| `error_loading_selected_file` | Ocurrió un error cargando el fichero |
| `error_loading_selected_undefined_file` | Ocurrió un error cargando el fichero |

### 9.17 Firma visible PDF (`PdfSelectPreviewActivity`)

| Clave | Texto (es) |
|---|---|
| `visible_sign` | Firma visible |
| `select_sign_area` | Seleccione el área de firma |
| `page_number` | Página %1$s de %2$s |
| `not_selected_area` | Área no seleccionada |
| `not_selected_area_desc` | No se ha seleccionado ningún área donde realizar la firma visible. |
| `reselect_area` | Volver a seleccionar un área |
| `visible_sign_small` | Firma visible demasiado pequeña |
| `small_area_warning` | El área seleccionada para mostrar la firma tiene un tamaño demasiado pequeño. |
| `pdf_visible_sign_template` | Firmado por $$SUBJECTCN$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$ |
| `pdf_visible_sign_pseudonym_template` | Firmado por $$PSEUDONYM$$ - $$OUS$$ el día $$SIGNDATE=dd/MM/yyyy$$ con un certificado emitido por $$ISSUERCN$$ |

### 9.18 Contraseña de PDF (`PDFPasswordDialog`, `PDFPasswordVisibleSignDialog`)

| Clave | Texto (es) |
|---|---|
| `encrypted_document` | El documento está encriptado |
| `encrypted_document_desc` | Por favor, introduce la contraseña del documento para poder continuar con el proceso de firma |
| `password` | Contraseña |
| `dialog_pdf_bad_password` | Contraseña incorrecta: |
| `error_empty_pdf_password` | La contraseña del PDF no puede estar vacía: |
| `pdf_password_protected` | El documento está protegido con contraseña. |

### 9.19 Certificados y almacenes

| Clave | Texto (es) |
|---|---|
| `choose_cert_type_sign_title` | ¿Con qué firmarás? |
| `choose_cert_type_auth_title` | ¿Con qué te identificarás? |
| `certificate` | Certificado electrónico |
| `dnie` | DNI electrónico |
| `dialog_title_select_cert` | Seleccione un certificado |
| `dialog_alias_cert_text` | %1$s⏎Válido: %2$s⏎Hasta: %3$s⏎Emisor: %4$s |
| `error_title_keystore_empty` | No existe ningún certificado |
| `error_no_certs` | No se han encontrado certificados instalados en su dispositivo. |
| `dialog_pin` | Para poder utilizar el certificado introduzca su código de seguridad.⏎ |
| `security_code_hint` | Código CAN.  |
| `cancel_nfc` | No usar DNIe |
| `error_pin_nulo` | Error, el PIN del DNI es nulo. |
| `expired_cert` | Certificado caducado |
| `expired_cert_soon` | Certificado próximo a caducar |
| `expired_cert_soon_desc` | El certificado seleccionado está próximo a caducar. Contacte con la autoridad emisora para renovarlo. |
| `not_valid_cert` | El certificado no es válido, ya que está caducado. |
| `pseudonym_cert` | Certificado de seudónimo |
| `pseudonym_cert_desc` | El certificado escogido es un certificado de seudónimo. En la firma no aparecerán sus datos personales |
| `error_android_4_1` | Android 4.1 y 4.1.1 no permiten que los nombres de certificados contengan caracteres especiales (espacios, guiones, etc.). Modifique el alias de sus certificados al importarlos para evitar este error. |
| `dialog_msg_loading_keystore` | Cargando almacén de claves |
| `loading_certs` | Cargando certificados |
| `signing` | Realizando firma |
| `dialog_msg_signning` | Firmando |
| `error_loading_keystore` | Error al cargar el almacen de certificados |
| `error_loading_cert` | Error al cargar el certificado |
| `not_selected_cert` | Certificado no seleccionado |
| `error_desc_keystore_empty` | Para firmar necesitas registrar un certificado digital |

### 9.20 DNIe por NFC

| Clave | Texto (es) |
|---|---|
| `dnie_identification` | Identificación con DNIe |
| `dnie_identification_desc` | Para identificarte mediante DNIe es necesario que tengas un DNI electrónico con <b>certificados vigentes</b> y conozcas el <b>código PIN</b>. |
| `is_my_dnie_suitable` | <u>¿Es mi DNI compatible?</u> |
| `is_my_dnie_suitable_desc` | Los DNIe compatibles con este proceso son los <b>DNI 3.0 y 4.0</b>. Si tienes dudas de cuál es el tuyo, puedes consultarlo en el siguiente enlace: |
| `dni_portal_text` | <u>Portal del DNI electrónico. Cuerpo Nacional de Policía</u> |
| `dni_portal_url` | https://www.dnielectronico.es/PortalDNIe/ |
| `enter_can_dni` | Introduzca el CAN del DNI |
| `enter_can_dni_desc` | El CAN es un número situado en la parte inferior derecha del DNI. Es necesario para la lectura del DNI con NFC. |
| `enter_can_dni_hint` | Escribe tu código CAN del DNI |
| `enter_pin_dni` | Introduce el PIN |
| `enter_pin_dni_desc` | Al hacerte el DNIe recibiste un código PIN que puedes recuperar o cambiar en comisarías sin cita previa. |
| `enter_your_pin_code` | Escribe tu código PIN |
| `read_dnie_with_smartphone` | Lee tu DNIe con el móvil |
| `read_dnie_with_smartphone_desc` | Coloca tu DNIe en una superficie lisa y sitúa tu móvil <b>sin funda</b> sobre él hasta que detecte el chip. |
| `read_dnie` | Leer DNIe |
| `actual_step` | Paso %s de 3 |
| `searching_dnie` | Buscando DNIe |
| `put_dnie_near_nfc` | Pon tu móvil sobre el DNIe lo más cerca posible del lector NFC. |
| `nfc_approach` | Acerque su dispositivo al DNIe |
| `enable_nfc` | Por favor, active el NFC para usar DNIe y pulsa atrás para volver |
| `nfc_no_detected` | No se ha habilitado NFC. |
| `enter_valid_can` | Introduzca un CAN válido |
| `enter_valid_pin` | Introduzca un pin válido |
| `incorrect_can` | CAN incorrecto |
| `incorrect_pin` | PIN incorrecto |
| `error_reading_dnie` | Error en la lectura de tu DNIe |
| `error_reading_dnie_try_again` | Se ha producido un error al intentar leer tu DNIe. Por favor, vuelve a intentarlo. Recuerda mantenerlo en una superficie lisa y mantener tu teléfono móvil unos segundos fijo sobre la tarjeta para su correcta lectura. |
| `error_reading_dnie_no_cert` | El DNIe que has aproximado no tiene certificado de firma o el certificado está caducado. Puedes acudir a una comisaría de Policía Nacional a un Punto de Actualización del DNIe (PAD), para solucionarlo. |
| `unsupported_card` | La tarjeta que has proporcionado no parece ser un DNIe. Por favor inténtalo de nuevo |
| `nfc_card_initializing_error` | Error al iniciar la conexión con la tarjeta. Es posible que el CAN sea incorrecto. Inténtelo de nuevo. |
| `error_msc_pin` | El PIN del dispositivo criptográfico es incorrecto. Tenga en cuenta que varios intentos fallidos consecutivos podrían bloquearlo. |
| `error_dni_blocked_dlg` | El DNIe tiene el PIN bloqueado. Puedes acudir a una comisaría de Policía Nacional a un Punto de Actualización del DNIe (PAD) para desbloquearlo. |
| `error_dni_blocked` | Su DNI está bloquedado, deberá acudir a los Puntos de Actualización de las Oficinas de Expedición para poder desbloquearlo.  |

### 9.21 Operaciones web y guardado

| Clave | Texto (es) |
|---|---|
| `title_activity_sign_data` | Firma de datos |
| `title_activity_sign_batch` | Firma de lote |
| `title_activity_select_certificate` | Selección de certificado |
| `title_activity_save_data` | Guardar datos |
| `saveData` | Guardar |
| `default_saved_filename` | datos |
| `file_read_out_of_memory` | El fichero seleccionado es demasiado grande y no hay memoria suficiente para completar la operación de lectura |
| `necessary_pdf_file` | Para poder realizar esta operación es necesario seleccionar un fichero PDF |
| `error_saving_data` | Ocurrió un error al guardar los datos |
| `error_saving_signature` | Ocurrió un error al guardar la firma |
| `error_no_storage_permissions` | El Cliente de firma no tiene permisos de escritura en disco. |

### 9.22 Recursos sin uso en el código (restos de versiones anteriores)

| Clave | Texto (es) |
|---|---|
| `import_cert` | Importar certificado |
| `request_cert` | Solicitar certificado |
| `appsDialogTitle` | Listado de autoridades soportadas |
| `appsDialogMessage` | Seleccione la autoridad de certificación a la que desee solicitar su certificado. |
| `disclaimer` | 2025 Gobierno de España |
| `privacy_policy_url` | https://administracion.gob.es/pag_Home/politicaDePrivacidad.html |
| `close` | Cerrar |
| `error_bad_params` | No se ha realizado correctamente la invocación de la aplicación. Consulte al responsable del trámite. |
| `error_server_connect` | Ocurrió un error en la conexión entre la aplicación y la página web. |
| `error_no_valid_p12` | El fichero "%s" no es un PKCS#12 válido. Seleccione un nuevo almacén para importar. |
| `error` | Error |
| `error_signing` | Error durante la operación de firma |
| `error_title_dni_blocked` | DNI bloqueado |
| `error_json` | Error al tratar JSON. |
| `icon_ca` | Icono de la autoridad de certificación |
| `dialog_msg_loading_data` | Cargando datos |
| `dialog_pdf_password_title` | Documento protegido |
| `dialog_pdf_password` | Introduzca la contraseña: |
| `dialog_can` | Introduzca su código CAN para establecer una conexión NFC con su DNIe.⏎ |
| `security_code` | Código de seguridad |
| `signedfile_title` | Resultado de firma |
| `signedfile_title_result_error` | Resultado de firma: Error al firmar |
| `signedfile_title_result_correct` | Resultado de firma: Firma correcta |
| `signedfile_error` | Lo sentimos la firma no se ha podido realizar. Por favor, reinténtelo de nuevo. |
| `signedfile_correct` | La firma se ha realizado correctamente. |
| `signedfile_original_location` | La firma "%1$s" se ha almacenado en el mismo directorio que el fichero original. |
| `signedfile_downloads_location` | La firma "%1$s" se ha almacenado en su directorio de descargas. |
| `accesibility_icon_sign_ko` | Error en la firma |
| `accesibility_icon_sign_ok` | Firma correcta |
| `nfc_instructions` | Coloque el dispositivo sobre el DNIe y no lo mueva durante la operación de firma |
| `nfc_cancelled` | Se ha cancelado el uso de NFC. Se usará el almacén del sistema. |
| `can_not_can_be_null` | El CAN no puede ser vacío o nulo |
| `title_activity_main_test` | MainActivityTest |
| `accesibility_dialog_can` | Introduzca su código CAN para establecer una conexión NFC con su DNIe. El código CAN contiene seis dígitos y se puede encontrar en la esquina inferior derecha del anverso de su DNI. |
| `menu` | Menú |
| `navigation_drawer_close` | Cerrado |
| `home` | Inicio |
| `menu_elements_list` | Lista de tres elementos |
| `pdf_password` | Contraseña del documento. |
| `not_selected_cert_desc` | No se ha encontrado ningún certificado instalado en el sistema o no se ha seleccionado para realizar la firma. |
| `loading_cert` | Cargando certificado |

---

## 10. Peculiaridades y errores de la app original

«Decisión» sugiere qué hacer en la reimplementación: **replicar** (afecta a lo que ve la web o el usuario y hay
que ser compatible), **corregir** (fallo sin valor de compatibilidad) o **documentar** (corregir, pero dejando
constancia en `docs/deviations/`).

| # | Peculiaridad | § | Decisión |
|---|---|---|---|
| 1 | `MainApplication` no está declarada; si lo estuviera, fallaría por llamar dos veces a `attachBaseContext` | 2.4 | corregir |
| 2 | Splash, bienvenida, aviso legal, privacidad y `save` no aplican el idioma guardado; `save` en un proceso nuevo tiene los catálogos de error vacíos y falla con `NullPointerException` al cancelar o fallar | 2.4, 5.7 | corregir |
| 3 | La pantalla de condiciones pone el idioma en español cada vez que se abre | 2.4 | corregir |
| 4 | Atrás en Ajustes e Idioma abre instancias nuevas de Inicio/Ajustes (la pila crece) | 2.13 | corregir |
| 5 | Casi todas las actividades internas están exportadas sin filtro | 1.4 | corregir |
| 6 | `uses-feature usb.accessory` obligatoria; `FileProvider` y Gson sin uso | 1.2, 1.3 | corregir |
| 7 | Receptor USB registrado sin indicador de exportación (excepción en Android 14+) y nunca dado de baja | 4.4 | corregir |
| 8 | `LoadingCertificateException` (tarjeta USB) se reintenta sin límite | 4.5 | corregir |
| 9 | Tarjeta sin alias `CertFirmaDigital`: la operación se queda colgada sin respuesta | 4.5 | corregir |
| 10 | `selectcert` con DNIe devuelve el certificado de firma, no el de autenticación | 4.5 | documentar |
| 11 | Cancelar en `PinDialog`/`SelectAliasDialog` y almacén vacío llegan a la web como `ERR-23`, no como cancelación | 4.10 | replicar o documentar |
| 12 | Los filtros de certificado de la web (`filters`, `headless`…) se ignoran; `KeyChain` sin filtros | 4.3 | documentar (en Android no se pueden aplicar a `KeyChain`) |
| 13 | Certificado aún no válido se trata como error genérico, no como aviso | 4.6 | corregir |
| 14 | En lotes, cancelar `KeyChain` cancela aunque haya NFC preferido | 6.4 | corregir |
| 15 | Importar desde Inicio abre dos selectores seguidos | 4.8 | corregir |
| 16 | Textos del asistente de importación ligados a la creación de fragmentos, no a la página visible | 4.8 | corregir |
| 17 | La X de los pasos del DNIe abre Inicio sin cancelar la operación (la web no recibe respuesta) | 4.9.3 | corregir |
| 18 | `PinDialog` usa la pista «Código CAN. » para pedir el PIN | 4.4 | corregir |
| 19 | `ChooseCertTypeDialog` construye el `Locale` con la etiqueta completa: el valenciano no se resuelve | 4.2 | corregir |
| 20 | Firma local: formato por extensión (`.pdf`) sin mirar el contenido; nunca cofirma | 3.4 | replicar |
| 21 | Firma local: el histórico se escribe antes de guardar, aunque se cancele el guardado | 3.8 | corregir |
| 22 | Android < 11: un fallo del `MediaScanner` muestra un error después del éxito | 3.8 | corregir |
| 23 | Selector propio: directorios excluidos aparecen como ficheros; `..` decidido por nombre del directorio | 3.3 | corregir |
| 24 | Tamaño «`M`,`FF` MB» con `FF` = dos primeros dígitos de KiB restantes | 3.3 | corregir |
| 25 | Vista previa opcional: «Continuar» con área pequeña produce firma **invisible** | 3.5.3 | replicar |
| 26 | Vista previa: en firma invisible se pierde la contraseña introducida (se vuelve a pedir al firmar) | 3.5.4 | corregir |
| 27 | Vista previa: tras fallar `PdfReader` el código sigue y puede mostrar un diálogo sobre una actividad que se cierra | 3.5.3 | corregir |
| 28 | Coordenadas: resta y suma de `xOffset` y multiplicación final por `zoom` (con zoom 1 no influye) | 3.5.3 | replicar la fórmula |
| 29 | Reintento con contraseña de PDF usa el algoritmo sin componer (inocuo) | 3.7.3 | documentar |
| 30 | `XAdES-ASiC-S` se firma como XAdES trifásica sin contenedor ASiC | 3.7.1 | corregir o documentar |
| 31 | XAdES/FacturaE «monofásicas» necesitan `serverUrl` (se fuerzan a trifásica) | 5.14 | documentar |
| 32 | PAdES sobre datos no PDF: responde `ERR-07` y además sigue firmando | 5.4.4 | corregir |
| 33 | Firma visible pedida por la web con datos en `dat`: `NullPointerException`, la app se cierra; con datos del sobre (`fileid`) se ignora, igual que la expansión de política y la comprobación de PDF | 5.4.2, 5.5 | corregir |
| 34 | La firma visible de la web sustituye `layer2Text` y coordenadas de la página | 5.5 | replicar |
| 35 | Errores de parámetros no llegan a la web (NPE capturada); petición sin `stservlet` → NPE en segundo plano al responder | 5.4.1 | replicar el «no responder»; corregir el cierre |
| 36 | Lotes: errores de descarga del lote intentan responder sin `stservlet` → la app se cierra | 6.3 | corregir |
| 37 | Fallo al cifrar el certificado: se envía `null\|<firma>` | 5.4.5 | corregir |
| 38 | Respuesta de firma sin clave en Base64 URL‑safe con saltos de línea | 5.4.5 | replicar o documentar (AutoScript siempre manda `key`) |
| 39 | Sobre sin clave: decodificador URL‑safe sobre alfabeto estándar (casi siempre falla) | 5.9 | documentar |
| 40 | `cipher` (AES) ignorado: solo DES | 5.9 | documentar (implementar AES es compatible) |
| 41 | `sign`/`selectcert`/`save` no envían `#WAIT` aunque `aw=true` | 5.8.3 | corregir (enviar `#WAIT` es compatible) |
| 42 | Atrás tras un error ya subido sube además `ERR-11` con el mismo `id` | 5.12 | corregir |
| 43 | Errores codificados con `URLEncoder` antes de subirlos (el escritorio los manda sin codificar) | 5.8.1 | replicar |
| 44 | `POST` partido con `StringTokenizer("?")`: se pierde lo que siga a un segundo `?` | 5.10 | corregir |
| 45 | Conexiones sin proxy del sistema y sin tiempos de espera | 5.10 | documentar |
| 46 | Desactivación TLS global y no segura entre hilos; las compilaciones de depuración no validan TLS | 5.10 | corregir |
| 47 | La ayuda de dominios dice «separados por comas»; la app usa saltos de línea | 2.9 | corregir el texto o aceptar ambos |
| 48 | Coincidencia de dominios: comodín decidido sobre la entrada sin recortar; `*` interiores se eliminan | 5.10 | replicar |
| 49 | `save`: nombre por defecto duplicado («datosdatos.pdf») | 5.7 | corregir |
| 50 | `save`: «Volver a intentarlo» cierra la app; error de parámetros sin respuesta; `title`/`exts`/`desc` ignorados | 5.7 | corregir / documentar |
| 51 | Lotes: se pierde el `signid` de la trifásica | 6.4 | corregir |
| 52 | Lotes: un fallo de subida no crítica deja la actividad abierta | 6.5 | corregir |
| 53 | Lotes XML y lotes locales no soportados (error genérico) | 6.1 | corregir (el núcleo Rust ya los tiene) |
| 54 | Histórico: `;` sin escapar; una línea corta aborta la lectura del resto | 2.10, 3.10 | corregir |
| 55 | *Toast* de error de lectura sin espacio entre el texto y el nombre | 5.4.3 | corregir |
| 56 | Un error al procesar tras elegir fichero en la web solo se muestra en un *toast*; la web no recibe respuesta | 5.4.3 | corregir |
| 57 | Caché *sticky* entre invocaciones; la firma local la vacía | 4.7 | replicar |
| 58 | `expandExtraParams` solo con `CAdES`/`PAdES` exactos | 5.4.4 | replicar |
| 59 | Textos: nombre de app en euskera traducido, errata en catalán, escape en inglés; ~50 textos gallegos sin traducir | 9.1 | corregir |
| 60 | Botón «Más información» del diálogo de ayuda oculto | 2.5 | replicar |
| 61 | Manejador de la tecla Inicio que nunca se ejecuta; `MessageDialog` con NPE (código muerto) | 5.12, 0.4 | ignorar |
| 62 | `selectcert`: error de cifrado busca la categoría con una clave equivocada (NPE en vez de `ERR-16`) | 5.6 | corregir |
| 63 | Lector USB sin pantalla de PIN: usa el último PIN del DNIe por NFC | 4.4 | corregir |
| 64 | Sobre descargado (`fileid`) con datos: se firma sin expandir política, sin comprobar PDF y sin firma visible | 5.4.2 | corregir |

---

## 11. Lista de paridad

Una fila por función; es la base de `docs/PARITY-ANDROID.md`.

### 11.1 Ficha técnica y arranque

| Id | Función | Notas |
|---|---|---|
| AND-TEC-01 | Identificador `es.gob.afirma`, versión 1.9 (27), minSdk 23, targetSdk 35 | §1.1 |
| AND-TEC-02 | Permisos (Internet, NFC, almacenamiento < 11) y características | §1.3 |
| AND-TEC-03 | Seguridad de red: CA del sistema, del usuario y 26 CA españolas; tráfico en claro permitido | §1.5 |
| AND-TEC-04 | Sin copia de seguridad de datos de la app; logs solo en depuración | §1.1, §1.7 |
| AND-TEC-05 | Orientación vertical en móvil y libre en tableta | §1.4 |
| AND-NAV-01 | Splash de 2 s con logos y enrutado (bienvenida → condiciones → inicio) | §2.4 |
| AND-NAV-02 | Bienvenida de primera ejecución | §2.4; `skipIntroScreen` |
| AND-NAV-03 | Aceptación de condiciones: idioma, HTML de política y aviso, dos casillas | §2.4; `skipConditionsScreen` |

### 11.2 Pantallas y navegación

| Id | Función | Notas |
|---|---|---|
| AND-NAV-04 | Inicio: «Firmar fichero», «Añadir nuevo certificado», menú Información/Ajustes | §2.5 |
| AND-NAV-05 | Pregunta de primera ejecución para habilitar el DNIe por NFC | §2.5; `firstExecution` |
| AND-NAV-06 | Diálogo de ayuda «¿Para qué sirve Autofirma?» | §2.5 |
| AND-NAV-07 | Diálogos de resultado en Inicio (éxito y error con código `AA`) | §2.5, §3.9 |
| AND-NAV-08 | Ajustes con secciones Mi configuración / Ayuda / Información general | §2.6 |
| AND-NAV-09 | Selección de idioma (6) con recarga de la interfaz | §2.7 |
| AND-NAV-10 | Preguntas frecuentes (3) | §2.11 |
| AND-NAV-11 | Pantallas de ayuda (DNIe NFC, firma visible, dominios, certificados) con accesos directos | §2.11 |
| AND-NAV-12 | Aviso legal y política de privacidad en HTML local por idioma | §2.12 |
| AND-NAV-13 | Declaración de accesibilidad (URL por idioma) | §2.6 |
| AND-NAV-14 | Pantalla de versión con licencia y enlaces | §2.12 |
| AND-NAV-15 | Comportamiento de Atrás por pantalla | §2.13 |
| AND-NAV-16 | Diálogos genéricos (*bottom sheet*) y de progreso | §2.2 |

### 11.3 Firma local

| Id | Función | Notas |
|---|---|---|
| AND-LOC-01 | Selección de fichero con SAF (Android ≥ 11) | §3.1 |
| AND-LOC-02 | Selector propio en Android < 11 (exclusiones, filtros, tamaños, accesibilidad) | §3.3 |
| AND-LOC-03 | Permiso de almacenamiento en Android < 11 | §3.2 |
| AND-LOC-04 | Formato por extensión: PAdES para `.pdf`, CAdES implícita en el resto; SHA‑256 | §3.4 |
| AND-LOC-05 | Firma visible PDF opcional según preferencia | §3.4, §3.5 |
| AND-LOC-06 | Vista previa: navegación de páginas y dibujo del área | §3.5.1–3.5.2 |
| AND-LOC-07 | Validación del área (mínimos 30×45 y 1350) y diálogos | §3.5.3 |
| AND-LOC-08 | Conversión de coordenadas de pantalla a PDF | §3.5.3 |
| AND-LOC-09 | Texto de firma visible (normal y seudónimo) y ofuscación | §3.5.5 |
| AND-LOC-10 | Contraseña de PDF en la vista previa | §3.5.6 |
| AND-LOC-11 | Contraseña de PDF al firmar con reintento | §3.7.3 |
| AND-LOC-12 | Nombre de salida (`_signed.pdf`, `.csig`) y tipo MIME | §3.8 |
| AND-LOC-13 | Guardado con SAF (≥ 11) o junto al original / Descargas con `(n)` (< 11) | §3.8 |
| AND-LOC-14 | Mensajes de resultado y errores de la firma local | §3.7.4, §3.9 |

### 11.4 Certificados y almacenes

| Id | Función | Notas |
|---|---|---|
| AND-CER-01 | Elección «Certificado electrónico» / «DNI electrónico» (si NFC habilitado) | §4.2 |
| AND-CER-02 | Almacén de Android (`KeyChain`) con el selector del sistema | §4.3 |
| AND-CER-03 | Lector USB CCID con CERES o DNIe | §4.4 |
| AND-CER-04 | Tarjeta microSD AET con PIN (por reflexión; inactiva en el APK oficial) | §4.4 |
| AND-CER-05 | Selección automática de `CertFirmaDigital` en tarjetas | §4.5 |
| AND-CER-06 | Lista de certificados de un almacén JCA y aviso de almacén vacío | §4.5 |
| AND-CER-07 | DNIe bloqueado: diálogo y error | §4.5 |
| AND-CER-08 | Avisos de certificado caducado, próximo a caducar (< 7 días) y de seudónimo | §4.6 |
| AND-CER-09 | Caché de certificado (*sticky*) con caducidad configurable; nunca con DNIe | §4.7 |
| AND-CER-10 | Proveedor de la tarjeta en los extraParams del PKCS#1 | §3.6 |
| AND-CER-11 | Asistente de importación de certificados (2 páginas) | §4.8 |
| AND-CER-12 | Importación `.p12/.pfx` en `KeyChain` y mensajes | §4.8 |

### 11.5 DNIe por NFC (interfaz)

| Id | Función | Notas |
|---|---|---|
| AND-NFC-01 | Detección de NFC y preferencia de uso | §4.9.1, §7 |
| AND-NFC-02 | Petición de activar el NFC del sistema | §4.9.1 |
| AND-NFC-03 | Introducción «Identificación con DNIe» y diálogo «¿Es mi DNI compatible?» | §4.9.2 |
| AND-NFC-04 | Paso 1: CAN de 6 cifras (recordado en el proceso) | §4.9.3 |
| AND-NFC-05 | Paso 2: PIN (≥ 4 caracteres) | §4.9.3 |
| AND-NFC-06 | Paso 3 y pantalla «Buscando DNIe» con *foreground dispatch* | §4.9.3, §4.9.6 |
| AND-NFC-07 | Carga del almacén `DNI` sobre la etiqueta NFC | §4.9.7 |
| AND-NFC-08 | Errores: tarjeta no soportada, CAN incorrecto, error de lectura, PIN incorrecto | §4.9.8 |
| AND-NFC-09 | Navegación atrás entre pasos, cierre y cancelaciones | §4.9.3, §4.9.5 |

### 11.6 Firma desde la web

| Id | Función | Notas |
|---|---|---|
| AND-WEB-01 | Registro de `afirma://sign\|cosign\|countersign\|batch\|selectcert\|save` (y `intent://` de Chrome) | §1.4, §5.1 |
| AND-WEB-02 | Análisis de parámetros con la semántica de `afirma-core` 1.9 (operación por *host*) | §5.2 |
| AND-WEB-03 | Firma, cofirma y contrafirma con datos en `dat` | §5.4 |
| AND-WEB-04 | Descarga del sobre por `fileid` con reintentos ante `ERR-06` | §5.4.2, §5.8.2 |
| AND-WEB-05 | Elección del fichero por el usuario cuando no hay datos | §5.4.3 |
| AND-WEB-06 | Comprobación PAdES sobre datos no PDF | §5.4.4 |
| AND-WEB-07 | Expansión de política (solo `CAdES`/`PAdES`) | §5.4.4 |
| AND-WEB-08 | Correspondencia de formatos (XAdES/FacturaE → trifásica, `AUTO` en cofirma/contrafirma) | §3.7.1 |
| AND-WEB-09 | Firma visible pedida por la web (`want`/`optional`, `headless`) | §5.5 |
| AND-WEB-10 | Respuesta `cert\|firma` (DES o Base64) subida al servidor intermedio | §5.4.5, §5.11 |
| AND-WEB-11 | `selectcert` | §5.6 |
| AND-WEB-12 | `save` con diálogo de creación de documento | §5.7 |
| AND-WEB-13 | Formato de errores `ERR-NN:=AA… - …` y tabla por operación | §5.12 |
| AND-WEB-14 | Cancelación con Atrás (`ERR-11`) | §5.12 |
| AND-WEB-15 | Cifrado DES de respuestas y descifrado de sobres | §5.9 |
| AND-WEB-16 | Cliente HTTP (POST con cuerpo, cookies compartidas) | §5.8.4, §5.10 |
| AND-WEB-17 | Validación TLS desactivable y dominios de confianza | §5.10 |
| AND-WEB-18 | Invocación desde otras apps con resultado por intent | §5.13 |
| AND-WEB-19 | Caché de certificado entre invocaciones (`sticky`, `resetsticky`) | §4.7 |
| AND-WEB-20 | Firma trifásica con los firmadores cliente | §5.14 |
| AND-WEB-21 | Cierre de la app tras la operación; relanzar desde recientes abre Inicio | §5.1, §5.4.6 |
| AND-WEB-22 | Registro en el histórico (`WEB`, `APP`) | §3.10, §5.4.5 |

### 11.7 Lotes

| Id | Función | Notas |
|---|---|---|
| AND-BAT-01 | Lote JSON contra servidor (prefirma, PKCS#1, postfirma) | §6.4 |
| AND-BAT-02 | Resultados parciales de la prefirma y reescritura del lote | §6.4 |
| AND-BAT-03 | Respuesta `resultado[\|cert]` (DES o Base64 estándar) con `needcert` | §6.5 |
| AND-BAT-04 | Lote descargado por `fileid` y espera activa `#WAIT` | §6.3 |
| AND-BAT-05 | Errores del lote y su correspondencia | §6.6 |
| AND-BAT-06 | Lotes XML y locales (no soportados en Java) | §6.1 |
| AND-BAT-07 | Registro en el histórico (`BATCH`, `BATCH_APP`) | §6.5 |

### 11.8 Preferencias, histórico e idiomas

| Id | Función | Notas |
|---|---|---|
| AND-PRF-01 | Almacén `afirma.client` con todas las claves y valores por defecto | §7 |
| AND-PRF-02 | Configuración de firma (NFC, firma visible, ofuscación, minutos de caché) | §2.8 |
| AND-PRF-03 | Dominios de confianza: validar SSL y lista con validación de formato | §2.9 |
| AND-PRF-04 | Idioma persistido | §2.7 |
| AND-HIS-01 | Fichero `signsRecord.txt` (formato y escritura) | §3.10 |
| AND-HIS-02 | Pantalla del histórico (orden y descripciones por tipo) | §2.10 |
| AND-HIS-03 | Eliminar histórico con confirmación | §2.10 |
| AND-I18N-01 | Seis idiomas con las mismas 272 claves | §9 |
| AND-I18N-02 | Catálogo de errores `AA` localizado | §8.1 |
| AND-I18N-03 | Textos legales HTML por idioma | §1.6, §2.12 |
