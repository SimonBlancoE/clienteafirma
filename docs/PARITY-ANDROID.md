# Paridad con Cliente @firma móvil (Android)

Estado de cada función de la app Android «Cliente @firma móvil» / Autofirma App 1.9 (`es.gob.afirma`) en
AutoFirma-rs. La especificación detallada de la versión Java está en
[`docs/spec/09-android.md`](spec/09-android.md) (la lista de origen, en su §11; las peculiaridades del original, en
su §10); las diferencias deliberadas, en [`docs/deviations/`](deviations/).

Leyenda: ✅ igual que Java · ➕ igual y mejorado · 🔁 sustituido por un equivalente ·
⚠️ parcial · 🧩 protocolo listo, falta la interfaz (`afirma_protocol::android`,
[ANDROID.md](ANDROID.md) §10; correcciones A1–A21 en
[`deviations/afirma-protocol.md`](deviations/afirma-protocol.md)) · ❌ no implementado · ➖ descartado a propósito.

## Ficha técnica y arranque

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-TEC-01 | Identificador `es.gob.afirma`, versión 1.9 (27), minSdk 23, targetSdk 35 | 🔁 | `io.github.autofirma_rs.android`, versión del espacio de trabajo, targetSdk 35; **minSdk 26** (la accesibilidad con AccessKit necesita `InMemoryDexClassLoader`, [ANDROID.md](ANDROID.md) §1) · 09 §1.1 |
| AND-TEC-02 | Permisos (Internet, NFC, almacenamiento < 11) y características | ❌ pendiente | 09 §1.3 |
| AND-TEC-03 | Seguridad de red: CA del sistema, del usuario y 26 CA españolas; tráfico en claro permitido | ❌ pendiente | 09 §1.5 |
| AND-TEC-04 | Sin copia de seguridad de datos de la app; logs solo en depuración | ❌ pendiente | 09 §1.1, 09 §1.7 |
| AND-TEC-05 | Orientación vertical en móvil y libre en tableta | 🔁 | La app gira en móviles y tabletas (WCAG 1.3.4 pide no bloquear la orientación); la interfaz se adapta (contenido centrado en horizontal). Emulador: capturas en horizontal · 09 §1.4 |
| AND-NAV-01 | Splash de 2 s con logos y enrutado (bienvenida → condiciones → inicio) | ➕ | Arranque de 1,5 s que se salta tocando y con un enlace `afirma://` en frío; mismo enrutado (`nav::route_after_splash`, prueba `enrutado_del_arranque`). Sin logotipos institucionales ([ANDROID.md](ANDROID.md) §9.7). Emulador: captura 01 · 09 §2.4 |
| AND-NAV-02 | Bienvenida de primera ejecución | ✅ | «Comenzar» guarda `skipIntroScreen` (prueba `primera_ejecucion_bienvenida_condiciones_e_inicio`); emulador: captura 02 · 09 §2.4 |
| AND-NAV-03 | Aceptación de condiciones: idioma, HTML de política y aviso, dos casillas | 🔁 | Selector de idioma (sin volver al español, §10 n.º 3), dos casillas y «Aceptar» solo con ambas; los textos de privacidad y aviso legal son propios ([ANDROID.md](ANDROID.md) §9.7). Pruebas en el anfitrión y emulador (capturas 03–05) · 09 §2.4 |

## Pantallas y navegación

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-NAV-04 | Inicio: «Firmar fichero», «Añadir nuevo certificado», menú Información/Ajustes | ➕ | «Firmar fichero» firma (§9.8 de [ANDROID.md](ANDROID.md)), «Añadir nuevo certificado» importa, Información y Ajustes; además accesos a firma web, certificados e histórico. Emulador: capturas 06, `selector.png` y firma de extremo a extremo · 09 §2.5 |
| AND-NAV-05 | Pregunta de primera ejecución para habilitar el DNIe por NFC | ✅ | Una vez, si hay NFC; «Sí» activa `useNfc` (prueba `pregunta_de_nfc_en_la_primera_ejecucion`; el emulador no tiene NFC) · 09 §2.5 |
| AND-NAV-06 | Diálogo de ayuda «¿Para qué sirve Autofirma?» | ✅ | Hoja inferior con los textos del original (sin el botón oculto «Más información»). Emulador: captura 07 · 09 §2.5 |
| AND-NAV-07 | Diálogos de resultado en Inicio (éxito y error con código `AA`) | ✅ | «Fichero firmado» y «¡Algo salió mal!» con «AA<código> - <texto>» sobre Inicio (pruebas `firma_local_con_keychain_de_extremo_a_extremo`, `errores_al_leer_el_documento`, `avisos_del_certificado_caducado`). Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)): capturas `firmado-*` · 09 §2.5, 09 §3.9 |
| AND-NAV-08 | Ajustes con secciones Mi configuración / Ayuda / Información general | ✅ | Tres secciones con la abreviatura del idioma; prueba `ajustes_y_pila_de_atras`, emulador: capturas 16, 34 · 09 §2.6 |
| AND-NAV-09 | Selección de idioma (6) con recarga de la interfaz | ➕ | Seis idiomas más «Idioma del sistema»; se aplica al momento y se guarda (prueba `idioma_inmediato_persistente_y_del_sistema`; emulador: gallego y vuelta, capturas 17, 33) · 09 §2.7 |
| AND-NAV-10 | Preguntas frecuentes (3) | ✅ | Tres preguntas desplegables con las respuestas del original. Emulador: captura 24 · 09 §2.11 |
| AND-NAV-11 | Pantallas de ayuda (DNIe NFC, firma visible, dominios, certificados) con accesos directos | ✅ | Cuatro ayudas con sus accesos directos (iconos en lugar de las ilustraciones). Emulador: capturas 25–28 · 09 §2.11 |
| AND-NAV-12 | Aviso legal y política de privacidad en HTML local por idioma | 🔁 | Textos propios en los seis idiomas, dentro de la app ([ANDROID.md](ANDROID.md) §9.7). Emulador: capturas 30, 31 · 09 §2.12 |
| AND-NAV-13 | Declaración de accesibilidad (URL por idioma) | 🔁 | Declaración propia dentro de la app, con enlace al repositorio. Emulador: captura 29 · 09 §2.6 |
| AND-NAV-14 | Pantalla de versión con licencia y enlaces | 🔁 | Versión, qué es AutoFirma para Android, licencias (enlace EUPL) y código fuente. Emulador: captura 32 · 09 §2.12 |
| AND-NAV-15 | Comportamiento de Atrás por pantalla | ➕ | Pila de pantallas en Rust: Ajustes e Idioma vuelven atrás (§10 n.º 4), las instrucciones retroceden de página, los diálogos se cierran primero y las pantallas raíz dejan la app en segundo plano (pruebas `pila_y_atras`, `ajustes_y_pila_de_atras`; emulador: pasos 3, 7 y recorrido) · 09 §2.13 |
| AND-NAV-16 | Diálogos genéricos (*bottom sheet*) y de progreso | ✅ | Hojas inferiores (ayuda, NFC, mensajes, minutos, borrar histórico, idioma, avisos con dos botones) y diálogo de progreso modal que «Atrás» no cierra («Cargando certificado», «Realizando firma», «Cargando datos») · 09 §2.2 |

## Firma local

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-LOC-01 | Selección de fichero con SAF (Android ≥ 11) | ✅ | `ACTION_OPEN_DOCUMENT` (`*/*`); el documento llega como descriptor y lo lee Rust (máx. 256 MB, AA200105; error AA200102); cancelar no dice nada (pruebas `firmar_fichero_certificados_y_peticiones_web`, `errores_al_leer_el_documento`). Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)) · 09 §3.1 |
| AND-LOC-02 | Selector propio en Android < 11 (exclusiones, filtros, tamaños, accesibilidad) | 🔁 | SAF en todas las versiones: con `minSdk` 26 no hace falta el selector propio de Android < 11 ([ANDROID.md](ANDROID.md) §9.8) · 09 §3.3 |
| AND-LOC-03 | Permiso de almacenamiento en Android < 11 | 🔁 | Sin permiso de almacenamiento: SAF en todas las versiones (`minSdk` 26) · 09 §3.2 |
| AND-LOC-04 | Formato por extensión: PAdES para `.pdf`, CAdES implícita en el resto; SHA‑256 | ➕ | Por el nombre, como el original (§10 n.º 20): `.pdf` → PAdES, resto → CAdES implícita, SHA-256, `mode=implicit`, nunca cofirma; además `.xml` → XAdES (el original no tenía XAdES monofásica). Pruebas `formato_por_el_nombre_del_fichero`, `firma_local_con_keychain_de_extremo_a_extremo` (las tres firmas validadas); Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)): `documento_signed.pdf`, `hola.txt.csig`, `documento.xml.xsig` verificadas con `autofirma verify` · 09 §3.4 |
| AND-LOC-05 | Firma visible PDF opcional según preferencia | ✅ | Con «Hacer firma visible», los PDF pasan por la vista previa (prueba `firma_local_con_keychain_de_extremo_a_extremo`; Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)), capturas `firma-visible-*`) · 09 §3.4, 09 §3.5 |
| AND-LOC-06 | Vista previa: navegación de páginas y dibujo del área | ✅ | Página dibujada con el rasterizador de `afirma-pdf` (el del escritorio) a la resolución de la pantalla, primera/anterior/siguiente/última, «Página n de N», área arrastrando el dedo (sin zoom), relleno y borde negros al 50 %; cambiar de página borra el área; «Atrás» cancela (pruebas `vista_previa_de_un_pdf`, `vista_previa_sin_area_area_pequena_y_atras`; emulador: captura `firma-visible-area-documento-pdf`) · 09 §3.5.1–3.5.2 |
| AND-LOC-07 | Validación del área (mínimos 30×45 y 1350) y diálogos | ✅ | Mínimos 30×45 y 1350 y diálogos «Área no seleccionada» / «Firma visible demasiado pequeña» con «Continuar» (firma invisible, §10 n.º 25) y «Volver a seleccionar un área» (pruebas `minimos_de_30_por_45_y_1350`, `vista_previa_sin_area_area_pequena_y_atras`) · 09 §3.5.3 |
| AND-LOC-08 | Conversión de coordenadas de pantalla a PDF | ➕ | Fórmula del original con zoom 1 (§10 n.º 28) sobre el tamaño de página mostrado (con giro; el original usaba la caja de medios sin girar). Prueba `area_en_coordenadas_pdf`; emulador: la firma aparece donde se dibujó · 09 §3.5.3 |
| AND-LOC-09 | Texto de firma visible (normal y seudónimo) y ofuscación | ✅ | `layer2Text` con la plantilla del idioma (`pdf_visible_sign_template`, o la de seudónimo con un certificado de seudónimo), `obfuscateCertText` de la preferencia (prueba `parametros_de_la_firma_visible`) · 09 §3.5.5 |
| AND-LOC-10 | Contraseña de PDF en la vista previa | ➕ | Diálogo con campo oculto y ojo, vacía y errónea con su texto; la contraseña también vale para la firma invisible (§10 n.º 26). Prueba `pdf_protegido_con_contrasena` · 09 §3.5.6 |
| AND-LOC-11 | Contraseña de PDF al firmar con reintento | ✅ | `PasswordNeeded`/`BadPassword` del firmador → diálogo y reintento con `ownerPassword` sin `userPassword`; cancelar no dice nada (prueba `pdf_protegido_con_contrasena`, firma validada) · 09 §3.7.3 |
| AND-LOC-12 | Nombre de salida (`_signed.pdf`, `.csig`) y tipo MIME | ✅ | `<nombre>_signed.pdf`, `<nombre>.csig` (y `<nombre>.xsig`), tipo `application/<ext>` (prueba `nombres_y_tipos_de_los_ficheros_firmados`; emulador: nombres propuestos en el diálogo de guardado, capturas `guardar-*`) · 09 §3.8 |
| AND-LOC-13 | Guardado con SAF (≥ 11) o junto al original / Descargas con `(n)` (< 11) | 🔁 | `ACTION_CREATE_DOCUMENT` en todas las versiones; Rust escribe en el descriptor; error AA200301; histórico solo tras guardar (§10 n.º 21). Pruebas `datos_para_guardar_se_escriben_una_vez`, `firma_local_con_keychain_de_extremo_a_extremo` (guardado cancelado sin registro); emulador: guardado en Descargas con DocumentsUI · 09 §3.8 |
| AND-LOC-14 | Mensajes de resultado y errores de la firma local | ✅ | Cancelaciones sin mensaje; errores AA200000 (certificado/almacén), AA200002 (firma), AA200102/AA200105 (lectura), AA200301 (guardado) con el catálogo `errors.rs` · 09 §3.7.4, 09 §3.9 |

## Certificados y almacenes

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-CER-01 | Elección «Certificado electrónico» / «DNI electrónico» (si NFC habilitado) | ⚠️ | «¿Con qué firmarás?» con el DNIe habilitado; «Certificado electrónico» → KeyChain; la X cancela; «DNI electrónico» explica que llegará en una próxima versión y vuelve a preguntar (prueba `eleccion_de_almacen_con_dnie_habilitado`) · 09 §4.2 |
| AND-CER-02 | Almacén de Android (`KeyChain`) con el selector del sistema | ✅ | `KeyChain.choosePrivateKeyAlias` (RSA y EC), cadena en un hilo de trabajo y `KeyChainKey` (firma en Java con `Signature`, clave en el TEE/StrongBox si lo está); sin elegir: con DNIe habilitado se vuelve a preguntar, si no se cancela; alias sin clave → AA200000 (pruebas `firma_local_con_keychain_de_extremo_a_extremo`, `avisos_del_certificado_caducado`). Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)): selector y firma con la identidad instalada · 09 §4.3 |
| AND-CER-03 | Lector USB CCID con CERES o DNIe | ❌ pendiente | 09 §4.4 |
| AND-CER-04 | Tarjeta microSD AET con PIN (por reflexión; inactiva en el APK oficial) | ❌ pendiente | 09 §4.4 |
| AND-CER-05 | Selección automática de `CertFirmaDigital` en tarjetas | ❌ pendiente | 09 §4.5 |
| AND-CER-06 | Lista de certificados de un almacén JCA y aviso de almacén vacío | ❌ pendiente | 09 §4.5 |
| AND-CER-07 | DNIe bloqueado: diálogo y error | ❌ pendiente | 09 §4.5 |
| AND-CER-08 | Avisos de certificado caducado, próximo a caducar (< 7 días) y de seudónimo | 🧩 | `certificate_warnings` y `AndroidWebHandler::confirm_certificate_warning` en firma y lotes web (solo KeyChain, no en `selectcert`); «aún no válido» es aviso (§10 n.º 13). La firma local ya los muestra con «Continuar» y «Cancelar» (§9.8 de [ANDROID.md](ANDROID.md); pruebas `avisos_de_caducidad_y_seudonimo`, `avisos_del_certificado_caducado`) · 09 §4.6 |
| AND-CER-09 | Caché de certificado (*sticky*) con caducidad configurable; nunca con DNIe | 🧩 | `StickyKeyCache`: una entrada que caduca a los minutos configurados desde que se guarda, nunca con DNIe por NFC; se refresca al usarla, como Java. La firma local la vacía (`Flows::cache`, prueba `firma_local_con_keychain_de_extremo_a_extremo`) · 09 §4.7 |
| AND-CER-10 | Proveedor de la tarjeta en los extraParams del PKCS#1 | ❌ pendiente | 09 §3.6 |
| AND-CER-11 | Asistente de importación de certificados (2 páginas) | ➕ | Dos páginas con «Continuar», «Atrás» de página y puntos; los textos son los de la página visible (§10 n.º 16); «Añadir certificado» cierra las instrucciones y abre un solo selector (§10 n.º 15). Prueba `importar_certificado`; emulador: capturas 10–12, `selector-p12`, importación de extremo a extremo · 09 §4.8 |
| AND-CER-12 | Importación `.p12/.pfx` en `KeyChain` y mensajes | ✅ | SAF `application/x-pkcs12` → `KeyChain.createInstallIntent` (`EXTRA_PKCS12`) → «Certificado añadido»; cancelado → nada; error → AA201100 con «Volver a intentarlo». El instalador de Android 15 no abre PKCS#12 con PBES2/AES ([ANDROID.md](ANDROID.md) §8). Prueba `importar_certificado`; Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)): `firmante-rsa-legacy.p12` instalado con el botón de la app (capturas `instalador-*`, `certificado-anadido`) · 09 §4.8 |

## DNIe por NFC (interfaz)

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-NFC-01 | Detección de NFC y preferencia de uso | ❌ pendiente | 09 §4.9.1, 09 §7 |
| AND-NFC-02 | Petición de activar el NFC del sistema | ❌ pendiente | 09 §4.9.1 |
| AND-NFC-03 | Introducción «Identificación con DNIe» y diálogo «¿Es mi DNI compatible?» | ❌ pendiente | 09 §4.9.2 |
| AND-NFC-04 | Paso 1: CAN de 6 cifras (recordado en el proceso) | ❌ pendiente | 09 §4.9.3 |
| AND-NFC-05 | Paso 2: PIN (≥ 4 caracteres) | ❌ pendiente | 09 §4.9.3 |
| AND-NFC-06 | Paso 3 y pantalla «Buscando DNIe» con *foreground dispatch* | ❌ pendiente | 09 §4.9.3, 09 §4.9.6 |
| AND-NFC-07 | Carga del almacén `DNI` sobre la etiqueta NFC | ❌ pendiente | 09 §4.9.7 |
| AND-NFC-08 | Errores: tarjeta no soportada, CAN incorrecto, error de lectura, PIN incorrecto | ❌ pendiente | 09 §4.9.8 |
| AND-NFC-09 | Navegación atrás entre pasos, cierre y cancelaciones | ❌ pendiente | 09 §4.9.3, 09 §4.9.5 |

## Firma desde la web

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-WEB-01 | Registro de `afirma://sign\|cosign\|countersign\|batch\|selectcert\|save` (y `intent://` de Chrome) | 🧩 | Reparto por *host* (`WebOperation::from_url`); `signandsave`, `load`, `websocket` y `service` no se atienden. Falta el filtro de intents del manifiesto · 09 §1.4, 09 §5.1 |
| AND-WEB-02 | Análisis de parámetros con la semántica de `afirma-core` 1.9 (operación por *host*) | 🧩 | `android::request`: operación por *host*, solo DES con `key`, sin `cipher` ni `servicetimeout`, todo decodificado al trocear; 89 casos idénticos al oráculo Java (`afirma-core` 1.9) · 09 §5.2 |
| AND-WEB-03 | Firma, cofirma y contrafirma con datos en `dat` | 🧩 | `AndroidWebLauncher::run` con `LocalSigner` y `target=tree` exacto en contrafirma; pruebas de extremo a extremo · 09 §5.4 |
| AND-WEB-04 | Descarga del sobre por `fileid` con reintentos ante `ERR-06` | 🧩 | `op=get` con 10 reintentos cada 2 s ante `ERR-06`; los errores de descarga o del sobre se responden a `rid` (A1) y el sobre pasa por expansión de política, PDF y firma visible (§10 n.º 64) · 09 §5.4.2, 09 §5.8.2 |
| AND-WEB-05 | Elección del fichero por el usuario cuando no hay datos | 🧩 | `AndroidWebHandler::choose_file`; los errores tras elegir se responden (§10 n.º 56). Falta el SAF · 09 §5.4.3 |
| AND-WEB-06 | Comprobación PAdES sobre datos no PDF | 🧩 | AA200106/AA200107 con `ERR-07` y sin seguir firmando (§10 n.º 32) · 09 §5.4.4 |
| AND-WEB-07 | Expansión de política (solo `CAdES`/`PAdES`) | 🧩 | Solo `CAdES`/`PAdES` exactos (§10 n.º 58); incompatibilidad → `ERR-22` AA600109 · 09 §5.4.4 |
| AND-WEB-08 | Correspondencia de formatos (XAdES/FacturaE → trifásica, `AUTO` en cofirma/contrafirma) | 🧩 | `android::formats`: XAdES*/FacturaE → trifásica con `serverUrl` (XAdES-ASiC-S conserva el ASiC, §10 n.º 30); `AUTO` en cofirma/contrafirma entre CAdES, CAdES-ASiC-S y PAdES; CMS, XMLDSig, ODF y OOXML no disponibles · 09 §3.7.1 |
| AND-WEB-09 | Firma visible pedida por la web (`want`/`optional`, `headless`) | 🧩 | `want`/`optional`/`headless`, plantilla de la app y ofuscación (§10 n.º 34); también con `dat` y sobre (§10 n.º 33). Falta la vista previa · 09 §5.5 |
| AND-WEB-10 | Respuesta `cert\|firma` (DES o Base64) subida al servidor intermedio | 🧩 | `C(cert)\|C(firma)` o Base64 URL-safe de Android con saltos de línea (§10 n.º 38, replicado); `ERR-16` si falla el cifrado del certificado (§10 n.º 37) · 09 §5.4.5, 09 §5.11 |
| AND-WEB-11 | `selectcert` | 🧩 | `C(cert)` o Base64 URL-safe; cancelado → `ERR-11` AA201104; `ERR-16` AA200200 (§10 n.º 62); caché también tras el sobre · 09 §5.6 |
| AND-WEB-12 | `save` con diálogo de creación de documento | 🧩 | `OK`, `ERR-11`/`ERR-26`/`ERR-18`/`ERR-22` con los textos fijos (§10 n.º 2); «datos.<ext>» (§10 n.º 49); `title`/`exts`/`desc` a la interfaz (§10 n.º 50). Falta el SAF · 09 §5.7 |
| AND-WEB-13 | Formato de errores `ERR-NN:=AA… - …` y tabla por operación | 🧩 | `android::errors`: catálogo AA y `ERR-NN`, textos de usuario en los seis idiomas, `URLEncoder`; contrastado con el oráculo · 09 §5.12 |
| AND-WEB-14 | Cancelación con Atrás (`ERR-11`) | 🧩 | `request_cancel()` y respuesta de los diálogos; una sola respuesta por invocación (§10 n.º 42). Falta el botón · 09 §5.12 |
| AND-WEB-15 | Cifrado DES de respuestas y descifrado de sobres | 🧩 | `android::cipher` (idéntico a `CipherDataManager` en el oráculo); sin clave decodifica bien (§10 n.º 39) · 09 §5.9 |
| AND-WEB-16 | Cliente HTTP (POST con cuerpo, cookies compartidas) | 🧩 | Cuerpo explícito (§10 n.º 44) y cookies de proceso del cliente común; falta configurarlo en la app sin proxy (§10 n.º 45) · 09 §5.8.4, 09 §5.10 |
| AND-WEB-17 | Validación TLS desactivable y dominios de confianza | 🧩 | `android::domains`: reglas de coincidencia replicadas (§10 n.º 48) y convertidas al cliente común, que decide por petición (§10 n.º 46) · 09 §5.10 |
| AND-WEB-18 | Invocación desde otras apps con resultado por intent | 🧩 | `InvocationMode::App` → `IntentReply` (firma y lotes; errores `ERR-22` incluidos). Falta la actividad · 09 §5.13 |
| AND-WEB-19 | Caché de certificado entre invocaciones (`sticky`, `resetsticky`) | 🧩 | `StickyKeyCache` compartida entre invocaciones (`sticky`, `resetsticky`) · 09 §4.7 |
| AND-WEB-20 | Firma trifásica con los firmadores cliente | 🧩 | `TriphaseClient` del crate con el cliente HTTP de la app, sin diálogos TLS · 09 §5.14 |
| AND-WEB-21 | Cierre de la app tras la operación; relanzar desde recientes abre Inicio | ❌ pendiente | 09 §5.1, 09 §5.4.6 |
| AND-WEB-22 | Registro en el histórico (`WEB`, `APP`) | 🧩 | `WebOutcome::history` (`WEB`/`APP`, operación, fichero elegido, `appname` o paquete llamante); falta escribirlo con `history::SignsHistory` · 09 §3.10, 09 §5.4.5 |

## Lotes

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-BAT-01 | Lote JSON contra servidor (prefirma, PKCS#1, postfirma) | 🧩 | `android::batch::sign_json_batch` en el orden de `BatchSigner`; corrige la decodificación del lote que lo hacía fallar casi siempre (A15) · 09 §6.4 |
| AND-BAT-02 | Resultados parciales de la prefirma y reescritura del lote | 🧩 | Reescritura con `org.json` de Android (orden de inserción, `\/`); `signid` conservado (§10 n.º 51) · 09 §6.4 |
| AND-BAT-03 | Respuesta `resultado[\|cert]` (DES o Base64 estándar) con `needcert` | 🧩 | `C(resultado)[\|C(cert)]` o Base64 estándar (el `+` protegido para el servlet, A9) · 09 §6.5 |
| AND-BAT-04 | Lote descargado por `fileid` y espera activa `#WAIT` | 🧩 | `#WAIT` cada 10 s (tras esperar, como Java) solo con sobre y `aw=true`, sin cruzarse con el resultado; errores de descarga respondidos a `rid` (§10 n.º 36) · 09 §6.3 |
| AND-BAT-05 | Errores del lote y su correspondencia | 🧩 | 4xx ≠ 400 → `ERR-18` AA400001; resto `ERR-14` AA200002; cancelación `ERR-11`; PIN incorrecto → nueva selección · 09 §6.6 |
| AND-BAT-06 | Lotes XML y locales (no soportados en Java) | 🧩 | Lotes XML (servidor) y locales con los firmadores del núcleo (§10 n.º 53) · 09 §6.1 |
| AND-BAT-07 | Registro en el histórico (`BATCH`, `BATCH_APP`) | 🧩 | `WebOutcome::history` con `BATCH`/`BATCH_APP` · 09 §6.5 |

## Preferencias, histórico e idiomas

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-PRF-01 | Almacén `afirma.client` con todas las claves y valores por defecto | ✅ | `prefs::Prefs`: mismas claves, tipos y valores por defecto, en `afirma.client.json` del directorio privado, escritura atómica (pruebas `prefs::tests`) · 09 §7 |
| AND-PRF-02 | Configuración de firma (NFC, firma visible, ofuscación, minutos de caché) | ✅ | Interruptores (NFC deshabilitado sin NFC), minutos 5/15/30/60/120 con «Por defecto», nada se guarda sin «Guardar» (prueba `configuracion_de_firma_y_minutos_de_cache`; emulador: capturas 18–20) · 09 §2.8 |
| AND-PRF-03 | Dominios de confianza: validar SSL y lista con validación de formato | ➕ | «Validar conexiones SSL» al instante; lista validada con la expresión del original y error AA200700; se admiten también comas (§10 n.º 47). Escrita con el teclado en pantalla en el emulador (capturas 21–23) · 09 §2.9 |
| AND-PRF-04 | Idioma persistido | ➕ | `localeConfig`; sin elegir, el idioma del sistema; se recupera tras reiniciar (emulador, paso 8) · 09 §2.7 |
| AND-HIS-01 | Fichero `signsRecord.txt` (formato y escritura) | ✅ | `signsRecord.txt` con el formato de §3.10 (y las correcciones de §10 n.º 54); la firma local registra `LOCAL;sign;<fichero>;null` tras guardar. Pruebas `formato_de_linea`, `firma_local_con_keychain_de_extremo_a_extremo`; Emulador (`emulator-test.sh --sign`, §6.1 de [ANDROID.md](ANDROID.md)): el histórico lista las tres firmas · 09 §3.10 |
| AND-HIS-02 | Pantalla del histórico (orden y descripciones por tipo) | ✅ | Lista de más reciente a más antigua con las descripciones de la tabla de §2.10 (prueba `descripciones_por_tipo`) · 09 §2.10 |
| AND-HIS-03 | Eliminar histórico con confirmación | ✅ | Confirmación y «No se encuentran registros» (prueba `historico_y_borrado`; emulador: captura 15) · 09 §2.10 |
| AND-I18N-01 | Seis idiomas con las mismas 272 claves | ✅ | Seis catálogos con las 272 claves más las propias y las erratas corregidas (§10 n.º 59, [ANDROID.md](ANDROID.md) §9.2); prueba `catalogos_completos` · 09 §9 |
| AND-I18N-02 | Catálogo de errores `AA` localizado | ✅ | Errores de las operaciones web (`android::errors`, seis idiomas); la interfaz (`errors.rs`) muestra esas categorías y las suyas (DNIe, importación, dominios) con los textos de los catálogos de la app en el idioma activo (el original los tenía vacíos en un proceso nuevo, §10 n.º 2); pruebas `mensajes_con_codigo_y_texto_localizado`, `catalogo_completo_sin_codigos_repetidos` · 09 §8.1 |
| AND-I18N-03 | Textos legales HTML por idioma | 🔁 | Textos legales propios en los seis idiomas en los catálogos ([ANDROID.md](ANDROID.md) §9.7) · 09 §1.6, 09 §2.12 |
