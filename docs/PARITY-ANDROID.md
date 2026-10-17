# Paridad con Cliente @firma móvil (Android)

Estado de cada función de la app Android «Cliente @firma móvil» / Autofirma App 1.9 (`es.gob.afirma`) en
AutoFirma-rs. La especificación detallada de la versión Java está en
[`docs/spec/09-android.md`](spec/09-android.md) (la lista de origen, en su §11; las peculiaridades del original, en
su §10); las diferencias deliberadas, en [`docs/deviations/`](deviations/).

Leyenda: ✅ igual que Java · ➕ igual y mejorado · 🔁 sustituido por un equivalente ·
⚠️ parcial · ❌ no implementado · ➖ descartado a propósito.

## Ficha técnica y arranque

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-TEC-01 | Identificador `es.gob.afirma`, versión 1.9 (27), minSdk 23, targetSdk 35 | ❌ pendiente | 09 §1.1 |
| AND-TEC-02 | Permisos (Internet, NFC, almacenamiento < 11) y características | ❌ pendiente | 09 §1.3 |
| AND-TEC-03 | Seguridad de red: CA del sistema, del usuario y 26 CA españolas; tráfico en claro permitido | ❌ pendiente | 09 §1.5 |
| AND-TEC-04 | Sin copia de seguridad de datos de la app; logs solo en depuración | ❌ pendiente | 09 §1.1, 09 §1.7 |
| AND-TEC-05 | Orientación vertical en móvil y libre en tableta | ❌ pendiente | 09 §1.4 |
| AND-NAV-01 | Splash de 2 s con logos y enrutado (bienvenida → condiciones → inicio) | ❌ pendiente | 09 §2.4 |
| AND-NAV-02 | Bienvenida de primera ejecución | ❌ pendiente | 09 §2.4; `skipIntroScreen` |
| AND-NAV-03 | Aceptación de condiciones: idioma, HTML de política y aviso, dos casillas | ❌ pendiente | 09 §2.4; `skipConditionsScreen` |

## Pantallas y navegación

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-NAV-04 | Inicio: «Firmar fichero», «Añadir nuevo certificado», menú Información/Ajustes | ❌ pendiente | 09 §2.5 |
| AND-NAV-05 | Pregunta de primera ejecución para habilitar el DNIe por NFC | ❌ pendiente | 09 §2.5; `firstExecution` |
| AND-NAV-06 | Diálogo de ayuda «¿Para qué sirve Autofirma?» | ❌ pendiente | 09 §2.5 |
| AND-NAV-07 | Diálogos de resultado en Inicio (éxito y error con código `AA`) | ❌ pendiente | 09 §2.5, 09 §3.9 |
| AND-NAV-08 | Ajustes con secciones Mi configuración / Ayuda / Información general | ❌ pendiente | 09 §2.6 |
| AND-NAV-09 | Selección de idioma (6) con recarga de la interfaz | ❌ pendiente | 09 §2.7 |
| AND-NAV-10 | Preguntas frecuentes (3) | ❌ pendiente | 09 §2.11 |
| AND-NAV-11 | Pantallas de ayuda (DNIe NFC, firma visible, dominios, certificados) con accesos directos | ❌ pendiente | 09 §2.11 |
| AND-NAV-12 | Aviso legal y política de privacidad en HTML local por idioma | ❌ pendiente | 09 §2.12 |
| AND-NAV-13 | Declaración de accesibilidad (URL por idioma) | ❌ pendiente | 09 §2.6 |
| AND-NAV-14 | Pantalla de versión con licencia y enlaces | ❌ pendiente | 09 §2.12 |
| AND-NAV-15 | Comportamiento de Atrás por pantalla | ❌ pendiente | 09 §2.13 |
| AND-NAV-16 | Diálogos genéricos (*bottom sheet*) y de progreso | ❌ pendiente | 09 §2.2 |

## Firma local

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-LOC-01 | Selección de fichero con SAF (Android ≥ 11) | ❌ pendiente | 09 §3.1 |
| AND-LOC-02 | Selector propio en Android < 11 (exclusiones, filtros, tamaños, accesibilidad) | ❌ pendiente | 09 §3.3 |
| AND-LOC-03 | Permiso de almacenamiento en Android < 11 | ❌ pendiente | 09 §3.2 |
| AND-LOC-04 | Formato por extensión: PAdES para `.pdf`, CAdES implícita en el resto; SHA‑256 | ❌ pendiente | 09 §3.4 |
| AND-LOC-05 | Firma visible PDF opcional según preferencia | ❌ pendiente | 09 §3.4, 09 §3.5 |
| AND-LOC-06 | Vista previa: navegación de páginas y dibujo del área | ❌ pendiente | 09 §3.5.1–3.5.2 |
| AND-LOC-07 | Validación del área (mínimos 30×45 y 1350) y diálogos | ❌ pendiente | 09 §3.5.3 |
| AND-LOC-08 | Conversión de coordenadas de pantalla a PDF | ❌ pendiente | 09 §3.5.3 |
| AND-LOC-09 | Texto de firma visible (normal y seudónimo) y ofuscación | ❌ pendiente | 09 §3.5.5 |
| AND-LOC-10 | Contraseña de PDF en la vista previa | ❌ pendiente | 09 §3.5.6 |
| AND-LOC-11 | Contraseña de PDF al firmar con reintento | ❌ pendiente | 09 §3.7.3 |
| AND-LOC-12 | Nombre de salida (`_signed.pdf`, `.csig`) y tipo MIME | ❌ pendiente | 09 §3.8 |
| AND-LOC-13 | Guardado con SAF (≥ 11) o junto al original / Descargas con `(n)` (< 11) | ❌ pendiente | 09 §3.8 |
| AND-LOC-14 | Mensajes de resultado y errores de la firma local | ❌ pendiente | 09 §3.7.4, 09 §3.9 |

## Certificados y almacenes

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-CER-01 | Elección «Certificado electrónico» / «DNI electrónico» (si NFC habilitado) | ❌ pendiente | 09 §4.2 |
| AND-CER-02 | Almacén de Android (`KeyChain`) con el selector del sistema | ❌ pendiente | 09 §4.3 |
| AND-CER-03 | Lector USB CCID con CERES o DNIe | ❌ pendiente | 09 §4.4 |
| AND-CER-04 | Tarjeta microSD AET con PIN (por reflexión; inactiva en el APK oficial) | ❌ pendiente | 09 §4.4 |
| AND-CER-05 | Selección automática de `CertFirmaDigital` en tarjetas | ❌ pendiente | 09 §4.5 |
| AND-CER-06 | Lista de certificados de un almacén JCA y aviso de almacén vacío | ❌ pendiente | 09 §4.5 |
| AND-CER-07 | DNIe bloqueado: diálogo y error | ❌ pendiente | 09 §4.5 |
| AND-CER-08 | Avisos de certificado caducado, próximo a caducar (< 7 días) y de seudónimo | ❌ pendiente | 09 §4.6 |
| AND-CER-09 | Caché de certificado (*sticky*) con caducidad configurable; nunca con DNIe | ❌ pendiente | 09 §4.7 |
| AND-CER-10 | Proveedor de la tarjeta en los extraParams del PKCS#1 | ❌ pendiente | 09 §3.6 |
| AND-CER-11 | Asistente de importación de certificados (2 páginas) | ❌ pendiente | 09 §4.8 |
| AND-CER-12 | Importación `.p12/.pfx` en `KeyChain` y mensajes | ❌ pendiente | 09 §4.8 |

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
| AND-WEB-01 | Registro de `afirma://sign\|cosign\|countersign\|batch\|selectcert\|save` (y `intent://` de Chrome) | ❌ pendiente | 09 §1.4, 09 §5.1 |
| AND-WEB-02 | Análisis de parámetros con la semántica de `afirma-core` 1.9 (operación por *host*) | ❌ pendiente | 09 §5.2 |
| AND-WEB-03 | Firma, cofirma y contrafirma con datos en `dat` | ❌ pendiente | 09 §5.4 |
| AND-WEB-04 | Descarga del sobre por `fileid` con reintentos ante `ERR-06` | ❌ pendiente | 09 §5.4.2, 09 §5.8.2 |
| AND-WEB-05 | Elección del fichero por el usuario cuando no hay datos | ❌ pendiente | 09 §5.4.3 |
| AND-WEB-06 | Comprobación PAdES sobre datos no PDF | ❌ pendiente | 09 §5.4.4 |
| AND-WEB-07 | Expansión de política (solo `CAdES`/`PAdES`) | ❌ pendiente | 09 §5.4.4 |
| AND-WEB-08 | Correspondencia de formatos (XAdES/FacturaE → trifásica, `AUTO` en cofirma/contrafirma) | ❌ pendiente | 09 §3.7.1 |
| AND-WEB-09 | Firma visible pedida por la web (`want`/`optional`, `headless`) | ❌ pendiente | 09 §5.5 |
| AND-WEB-10 | Respuesta `cert\|firma` (DES o Base64) subida al servidor intermedio | ❌ pendiente | 09 §5.4.5, 09 §5.11 |
| AND-WEB-11 | `selectcert` | ❌ pendiente | 09 §5.6 |
| AND-WEB-12 | `save` con diálogo de creación de documento | ❌ pendiente | 09 §5.7 |
| AND-WEB-13 | Formato de errores `ERR-NN:=AA… - …` y tabla por operación | ❌ pendiente | 09 §5.12 |
| AND-WEB-14 | Cancelación con Atrás (`ERR-11`) | ❌ pendiente | 09 §5.12 |
| AND-WEB-15 | Cifrado DES de respuestas y descifrado de sobres | ❌ pendiente | 09 §5.9 |
| AND-WEB-16 | Cliente HTTP (POST con cuerpo, cookies compartidas) | ❌ pendiente | 09 §5.8.4, 09 §5.10 |
| AND-WEB-17 | Validación TLS desactivable y dominios de confianza | ❌ pendiente | 09 §5.10 |
| AND-WEB-18 | Invocación desde otras apps con resultado por intent | ❌ pendiente | 09 §5.13 |
| AND-WEB-19 | Caché de certificado entre invocaciones (`sticky`, `resetsticky`) | ❌ pendiente | 09 §4.7 |
| AND-WEB-20 | Firma trifásica con los firmadores cliente | ❌ pendiente | 09 §5.14 |
| AND-WEB-21 | Cierre de la app tras la operación; relanzar desde recientes abre Inicio | ❌ pendiente | 09 §5.1, 09 §5.4.6 |
| AND-WEB-22 | Registro en el histórico (`WEB`, `APP`) | ❌ pendiente | 09 §3.10, 09 §5.4.5 |

## Lotes

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-BAT-01 | Lote JSON contra servidor (prefirma, PKCS#1, postfirma) | ❌ pendiente | 09 §6.4 |
| AND-BAT-02 | Resultados parciales de la prefirma y reescritura del lote | ❌ pendiente | 09 §6.4 |
| AND-BAT-03 | Respuesta `resultado[\|cert]` (DES o Base64 estándar) con `needcert` | ❌ pendiente | 09 §6.5 |
| AND-BAT-04 | Lote descargado por `fileid` y espera activa `#WAIT` | ❌ pendiente | 09 §6.3 |
| AND-BAT-05 | Errores del lote y su correspondencia | ❌ pendiente | 09 §6.6 |
| AND-BAT-06 | Lotes XML y locales (no soportados en Java) | ❌ pendiente | 09 §6.1 |
| AND-BAT-07 | Registro en el histórico (`BATCH`, `BATCH_APP`) | ❌ pendiente | 09 §6.5 |

## Preferencias, histórico e idiomas

| Id | Función | Estado | Notas |
|---|---|---|---|
| AND-PRF-01 | Almacén `afirma.client` con todas las claves y valores por defecto | ❌ pendiente | 09 §7 |
| AND-PRF-02 | Configuración de firma (NFC, firma visible, ofuscación, minutos de caché) | ❌ pendiente | 09 §2.8 |
| AND-PRF-03 | Dominios de confianza: validar SSL y lista con validación de formato | ❌ pendiente | 09 §2.9 |
| AND-PRF-04 | Idioma persistido | ❌ pendiente | 09 §2.7 |
| AND-HIS-01 | Fichero `signsRecord.txt` (formato y escritura) | ❌ pendiente | 09 §3.10 |
| AND-HIS-02 | Pantalla del histórico (orden y descripciones por tipo) | ❌ pendiente | 09 §2.10 |
| AND-HIS-03 | Eliminar histórico con confirmación | ❌ pendiente | 09 §2.10 |
| AND-I18N-01 | Seis idiomas con las mismas 272 claves | ❌ pendiente | 09 §9 |
| AND-I18N-02 | Catálogo de errores `AA` localizado | ❌ pendiente | 09 §8.1 |
| AND-I18N-03 | Textos legales HTML por idioma | ❌ pendiente | 09 §1.6, 09 §2.12 |
