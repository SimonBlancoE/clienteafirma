# Desviaciones de `afirma-keystores` respecto a AutoFirma (Java)

Diferencias deliberadas con el comportamiento de la versión Java
(`afirma-core-keystores`, `afirma-keystores-*`, `afirma-ui-core-jse-keystores`
y la selección de almacén de `afirma-simple`). Salvo que se indique, no
afectan a la interoperabilidad: los nombres de almacén, los parámetros del
protocolo, los alias que se pueden pasar a `-alias`, los textos y los códigos
de error son los de Java.

## Decisión de diseño: DNIe y tarjetas CERES sin jmulticard

Java accede al DNIe (`DNIEJAVA`) y a las tarjetas FNMT CERES (`CERES`,
`CERES_430`) con jmulticard, un controlador Java sobre PC/SC (canal seguro
CWA-14890, PACE con CAN). AutoFirma-rs **no** reimplementa ese controlador:
usa los módulos PKCS#11 existentes y mantenidos por terceros —OpenSC
(`opensc-pkcs11`, controladores `dnie` y `fnmt`), el módulo de la FNMT
(`libpkcs11-fnmtdnie`) y los módulos oficiales de Windows (`DNIe_P11_priv.dll`,
`FNMT_P11_x64.dll`, `TIF_P11.dll`)—, que se detectan en las rutas habituales
de cada sistema (`pkcs11::known::candidate_smartcard_modules`). Se conserva el
comportamiento visible:

- Los almacenes `DNIEJAVA`, `CERES_430`, `CERES` y `SMARTCAFE` son
  "preferentes" y se sondean en el mismo orden al abrir `WINDOWS`, `APPLE`,
  `MOZ_UNI`, `MOZ_UNI_WITH_OS` y `SHARED_NSS`, ocultando sus certificados
  (por huella SHA-1) en los subalmacenes anteriores; si hay tarjeta no se
  cargan los módulos externos de Firefox.
- El PIN se pide **al firmar**, con los textos y títulos de jmulticard
  ("Por favor, introduzca el PIN del DNIe.", "DNI Electrónico: Introducción de
  PIN"...), la casilla "Recordar contraseña durante la sesión" (caché de 1 h
  desde la primera petición) y la confirmación de firma del DNIe, que se pide
  una vez por almacén abierto como en `DnieCacheCallbackHandler`.
- Para pedir el PIN en cada firma se cierra la sesión de usuario del token y se
  vuelve a iniciar (con el PIN de la caché si el usuario lo pidió).

Diferencias que conlleva:

- El tipo de tarjeta se deduce de la etiqueta, fabricante y modelo del token
  (heurística: "DNI"/"DGP" → DNIe; "FNMT"/"CERES"/"TIF" → FNMT). `CERES` y
  `CERES_430` aceptan las mismas tarjetas (un único sondeo) y `SMARTCAFE` (solo
  si `AFIRMA_NSS_ENABLE_GYDSC_NATIVE_DRIVER=true`) cualquier otra.
- El CAN del DNIe sin contacto lo pide el controlador (OpenSC), no AutoFirma.
- Los intentos restantes solo se conocen por `CKF_USER_PIN_FINAL_TRY` (último
  intento); jmulticard los leía de la tarjeta.
- No hay errores específicos de "DNIe quemado" o "tarjeta no válida" del
  controlador; sin tarjeta se devuelve `CardNotPresent` (201114).

## PKCS#12

- Alias como `PKCS12KeyStore` de Java (`friendlyName` en minúsculas; sin nombre,
  `"1"`, `"2"`…), comprobado con el oráculo. Java pierde las entradas con alias
  repetido (las sobrescribe); aquí se conservan con sufijo `" (1)"`, `" (2)"`…
- Sin contraseña (`NoPassword`, línea de comandos sin `-password`) se prueba la
  contraseña vacía (Java carga con contraseña nula, lo que en la práctica
  tampoco da acceso a las claves cifradas).
- **Hueco:** no se admiten claves cifradas con una contraseña distinta de la
  del almacén (`p12-keystore` usa una sola contraseña); Java probaba la del
  almacén, la vacía y después preguntaba (`AOKeyStore.0`).

## PKCS#11

- Se usan todas las ranuras con token (Java: solo la primera de
  `C_GetSlotList(FALSE)`, disponible como `SlotSelection::FirstSlot`). Se
  omiten los tokens no inicializados y, si un token falla al iniciar sesión por
  un motivo que no sea el PIN, solo ese token.
- Tras un error de inicio de sesión solo se vuelve a pedir el PIN si es erróneo
  (`CKR_PIN_INCORRECT`) o de longitud no válida (`CKR_PIN_LEN_RANGE`); Java lo
  pedía de nuevo ante cualquier `LoginException`, lo que podía no terminar
  nunca. Con un PIN fijo (CLI) nunca se reintenta, para no bloquear la tarjeta.
- Sin iniciar sesión (sin contraseña o con PIN al firmar), los certificados de
  entidad final con `CKA_ID` se ofrecen como entradas con clave (las claves
  privadas suelen ser invisibles hasta introducir el PIN); Java no los mostraba
  como entradas con clave.
- Alias: `CKA_LABEL` del certificado; si no tiene, la etiqueta de la clave, el
  `CKA_ID` (texto o hexadecimal) o el CN. Si el certificado no tiene `CKA_ID`
  se empareja con la clave por etiqueta. Alias repetidos con `" (n)"`.
- Se admiten claves con `CKA_ALWAYS_AUTHENTICATE` (inicio de sesión
  `CKU_CONTEXT_SPECIFIC` en cada firma); SunPKCS11 no lo hacía.
- ECDSA con `CKM_ECDSA` sobre la huella truncada al orden de la curva; si el
  módulo devuelve DER en lugar de `r‖s`, se acepta.
- La biblioteca se inicializa una vez por proceso mientras esté en uso; la
  recarga (`refresh`) vuelve a enumerar ranuras y sesiones, y pide de nuevo el
  PIN (como Java al recrear el proveedor).
- Detección automática de controladores de tarjeta en Linux y macOS (Java no
  tenía rutas fijas fuera de Windows).

## Firefox / NSS

- Cadena de inicialización de `softokn3`: `configdir='sql:<dir>'` (Java
  `sql:/<dir>`, que en UNIX produce `sql://home/...`); los valores se escapan y
  en Windows se usan `/` como separador.
- `AFIRMA_NSS_HOME_ENV` se respeta (en Java se sobrescribía y no tenía efecto).
- Bibliotecas NSS en Linux: el triplete multiarquitectura sale del destino de
  compilación (`aarch64-linux-gnu`...) y la comprobación del binario compara la
  arquitectura ELF con la del proceso (Java solo aceptaba x86/x86-64: en
  aarch64 nunca encontraba NSS). Se comprueban también PE (Windows) y Mach-O,
  incluidos binarios universales.
- macOS: se buscan también las ediciones ESR, Developer y Nightly de Firefox y
  Homebrew. No se crean enlaces en `/usr/local/lib` con AppleScript de
  administrador: se carga por ruta absoluta.
- Windows: si `compatibility.ini` no indica el directorio, se prueban las
  instalaciones habituales (`%ProgramFiles%\Mozilla Firefox`). No se usan
  nombres cortos 8.3 ni copias temporales. **Hueco:** no se incluye NSS propio
  para cuando el de Firefox es de otra arquitectura.
- `profiles.ini`: se añaden las rutas de Flatpak
  (`~/.var/app/org.mozilla.firefox/.mozilla/firefox` y `…/config/mozilla/firefox`)
  tras la de snap y se respeta `XDG_CONFIG_HOME`; se descarta una marca BOM; un
  directorio de perfil inexistente cuenta como perfil no válido (Java fallaba).
- La lista de módulos externos conserva el orden del fichero (en Java era el de
  un `HashMap`). Un módulo externo solo cuenta como cargado si tiene algún token.
- `SHARED_NSS` lee los módulos externos del `pkcs11.txt` de la propia base de
  datos compartida (Java leía el del perfil de Firefox por un error de
  herencia, §3.6.11).
- Los almacenes de Firefox informan de su tipo real (Java los inicializaba como
  `SHARED_NSS`, §3.6.10) y se guardan en caché por tipo respetando
  `force_reset`. Al pedir un almacén NSS de otro tipo se liberan de la caché los
  anteriores, de modo que `softokn3` puede reinicializarse con otra base de
  datos si nadie más los usa (Java no podía).
- Si falla la parte NSS y no se pudo añadir ningún otro subalmacén, se devuelve
  error 201108 en lugar de un almacén vacío. Los fallos de inicialización de NSS
  usan siempre 201108 (Java usaba a veces 201107).

## Selección de almacén y almacenes agregados

- En un almacén agregado con varios subalmacenes, el identificador de cada
  entrada es `"<índice>:<alias>"` para evitar colisiones (en Java el segundo
  alias repetido era inaccesible); el alias nativo se conserva para
  `listaliases` y se sigue aceptando en `-alias` (primera coincidencia). Se
  aceptan además `sha1:<hex>` y `sha256:<hex>`.
- `ksb64` acepta Base64 estándar y URL-safe (Java solo el estándar).
- `-store pkcs12:<fichero>` usa la ruta limpia (sin comillas, canónica); Java
  comprobaba la ruta limpia pero abría el texto original.
- Las preferencias que en Java eran solo propiedades del sistema se leen de
  variables de entorno: `AFIRMA_NSS_ENABLE_WRITE`
  (`…mozilla.EnableNssWrite`), `AFIRMA_DO_NOT_REUSE_PKCS11_PROVIDER`,
  `AFIRMA_FORCE_STORE_RESET`; `AFIRMA_NSS_USE_ENVIRONMENT_VARIABLES` es un alias
  de `es.gob.afirma.keystores.mozilla.UseEnvironmentVariables`.
- Tarjetas registradas: "Modificar" sin cambiar el nombre funciona (en Java se
  rechazaba como nombre duplicado).
- **Hueco:** `JAVA`, `JCEKS` y `JAVACE` (almacenes Java) no están implementados
  y devuelven `UNSUPPORTED_KEYSTORE` (600011). `KNOWN_SMARTCARDS` solo se usa
  internamente en el perfil temporal de Windows, como en Java.

## Verificación tras la firma

- `verify::sign_and_verify` reproduce el contrato de `AOPkcs1Signer` con los
  códigos 200112/200113. El envoltorio `VerifyingKey` (interfaz `SigningKey`)
  devuelve `KeyError::Other("El PKCS#1 de firma obtenido no se genero con el
  certificado indicado")`, porque `afirma_core::KeyError` no tiene una variante
  que se traduzca a 200112.

## Almacén de Windows (CryptoAPI / CNG)

- **Detección de clave sin interfaz:** SunMSCAPI, tras la comprobación
  silenciosa, vuelve a adquirir la clave de forma no silenciosa al cargar el
  almacén, lo que puede mostrar diálogos de tarjeta al enumerar. AutoFirma-rs
  solo hace la comprobación silenciosa (`CRYPT_ACQUIRE_SILENT_FLAG`;
  `NTE_SILENT_CONTEXT` cuenta como "tiene clave") y adquiere la clave con
  interfaz al firmar.
- **Preferencia por CNG:** las claves se adquieren con
  `CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG` y se firma con `NCryptSignHash`;
  CryptoAPI (`CryptSignHash`, con reapertura `PROV_RSA_AES` si el CSP no admite
  SHA-2, como SunMSCAPI) solo se usa para claves de CSP antiguos. También
  funcionan claves que solo existen en un KSP.
- **Cadena sin red:** la cadena se construye con
  `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE`
  para no bloquear la carga del almacén en equipos sin red. Si un certificado
  intermedio no está instalado, la cadena puede ser más corta que en Java, que
  permite descargas AIA.
- **Almacén inexistente:** si el almacén de sistema no existe (perfil nuevo,
  libreta de direcciones sin usar), se abre como vacío en modo lectura en lugar
  de crearlo (Java usa `CertOpenSystemStore`, que lo crea).
- **Alias sin nombre:** si un certificado no tiene nombre descriptivo ni
  titular, el alias es su huella SHA-1 en hexadecimal (Java no lo contempla).
- **`dwKeySpec` no estándar:** si el proveedor informa un `dwKeySpec` distinto
  de `AT_KEYEXCHANGE`/`AT_SIGNATURE` (p. ej. Wine), se prueban ambos; la
  verificación posterior de la firma detecta cualquier error.
- **SHA224withRSA:** con CNG se firma el `DigestInfo` con `pszAlgId` nulo. Con
  CryptoAPI no está soportado (no existe `CALG` para SHA-224), igual que en
  SunMSCAPI.

## Llavero de macOS

- **Firma sin exportar la clave:** Java exporta la clave privada y firma en
  software, así que las claves no exportables (tarjetas CryptoTokenKit, Secure
  Enclave) aparecen pero fallan al firmar, con avisos de exportación de macOS.
  AutoFirma-rs firma con `SecKeyCreateSignature` sobre la huella
  (`kSecKeyAlgorithm…SignatureDigest…`) sin exportar nunca la clave; los
  diálogos de acceso o de PIN los muestra macOS.
- **Identidades de tokens:** Java solo enumera la lista de búsqueda clásica.
  AutoFirma-rs consulta además `kSecAttrAccessGroupToken` (opción
  `include_tokens`, activa por defecto). Los duplicados se eliminan por número
  de serie como en Java, y la entrada se marca como de hardware si alguna copia
  procede de un token.
- **Orden determinista:** en Java el orden de los alias, y por tanto qué
  duplicado por número de serie se conserva, depende del orden de un
  `Hashtable`. AutoFirma-rs conserva el orden de enumeración (primero los
  llaveros clásicos, después los tokens). Los alias se generan como en Java:
  etiqueta, sufijos `" 1"`, `" 2"`… ante colisiones sin distinguir mayúsculas, y
  alias en minúsculas.
- **Etiqueta ausente:** en Java, si una identidad no tiene etiqueta se aborta
  la carga del resto. AutoFirma-rs usa el resumen del titular (la etiqueta por
  defecto del llavero) y continúa.

## Filtros de certificados y diálogo de selección

- **Icono ACCV:** Java compara el emisor en mayúsculas con texto en minúsculas,
  de modo que el icono de ACCV nunca aparece. Rust compara sin distinguir
  mayúsculas.
- **Aviso de caducidad:** Java usa `1000*60*60*25*7` ms (7 días y 7 horas).
  Rust usa exactamente 7 días.
- **Titular vacío:** Java muestra una cadena vacía como nombre. Rust usa el
  alias recortado.
- **Orden de los filtros:** Java devuelve los alias en orden de `Hashtable`.
  Rust conserva el orden de entrada. Solo cambia el resultado cuando un filtro
  `qualified:` tiene varias parejas: Java elige una arbitraria y Rust la
  primera.
- **Alias duplicados:** si `ssl:` o `qualified:` devuelven un alias dos veces,
  Java lanza `NullPointerException`. Rust elimina el duplicado.
- **Errores de análisis:** con keyUsage de más de 9 bits, extensiones
  QCStatements o CertificatePolicies mal formadas, o un algoritmo de huella no
  soportado, Java puede lanzar excepciones desde los filtros. Rust trata el
  certificado como "no cumple".
- **Valores binarios en RFC 2254:** en Java son `byte[]` cuyo `toString()` es
  `"[B@hash"`. Rust se comporta igual para la presencia (`attr=*`) y no los hace
  coincidir con ningún otro patrón.
- **Hexadecimal:** el formato `#hex` de `X500Principal.toString()` sigue a
  Java 17+ (minúsculas; Java 8 usaba mayúsculas).
- **Diálogo de selección:** las filas y los datos salen del mismo vector
  filtrado, así que no se reproduce el fallo de Java que devolvía otro
  certificado si una fila fallaba al pintarse (§8.9). El orden secundario es
  determinista: caducidad descendente y después huella SHA-1.
