# Desviaciones de `afirma-core` respecto a AutoFirma Java

Este documento recoge las diferencias deliberadas (o inevitables) entre
`afirma-core` y el núcleo Java (`afirma-core`, `afirma-simple` para la gestión de
errores del protocolo y del proxy). El comportamiento se ha contrastado con el
oráculo Java `tools/oracle/CoreOracle.java` (`tools/oracle/core_oracle.sh`), cuyas
salidas están en `testdata/core/*.golden` y se comprueban en `cargo test`:

| Golden | Qué compara |
|---|---|
| `mime.golden` | `MimeHelper` (tipo, extensión, descripción, `isZipData`), `OfficeAnalizer.isOOXMLDocument/isODFDocument` y `AOFileUtils.isXML` sobre las 60 muestras de `testdata/core/mime` (generadas con `tools/oracle/gen_core_samples.py`) |
| `base64.golden` | `Base64.encode/decode/isBase64` (54 vectores, ambos alfabetos) |
| `load.golden` | `Properties.load` (41 casos: continuaciones, CRLF, comentarios, escapes) |
| `props.golden` | `Properties.store(Writer, "")`, `AOUtil.propertiesAsString` y `AOUtil.base642Properties` |
| `exppolicy.golden` | `ExtraParamsProcessor.expandProperties` (24 casos) |
| `uri.golden` | `AOUtil.createURI` |
| `misc.golden` | `hexify`, `split`, `getCN`/`getOUS`, `Date.toString()` y `DateFormat(DEFAULT, SHORT)` en `es_ES` |

## Correcciones a la especificación (no son desviaciones)

El oráculo mostró que algunos puntos de `docs/spec/07-core.md` no describen el
comportamiento real de Java; se ha seguido a Java:

* **Base64 (§7.1)**: el decodificador **no** rechaza caracteres fuera del alfabeto:
  `WHITE_SPACE_ENC` vale `-9`, así que cualquier byte desconocido (incluidos `-`/`_`
  con el alfabeto estándar o `+`/`/` con el URL-safe, y los no ASCII) se ignora en
  silencio. Solo las entradas de 1 a 3 caracteres producen error.
* **MimeHelper (§6.1)**: si JMimeMagic no detecta nada, el resultado es siempre
  `application/octet-stream` aunque los datos sean un XML válido (la variable local
  `mType` sigue siendo `null` tras fijar `text/xml`). Un XML solo se clasifica como
  `text/xml` si empieza por `<?xml `. Un XML ASCII sin declaración es `text/plain`.
* **JMimeMagic**: cada regla necesita que los datos sean **más largos** que la
  ventana que examina (1 byte para `byte`, 4 para los `short`, 8 para los `long`,
  la longitud del patrón para `string`); el detector de texto y las expresiones
  regulares no miran el **último byte**; el comparador `&` nunca coincide. Por
  ejemplo, un fichero de exactamente 4 bytes `PK\3\4` es `text/plain`, un TIFF es
  `text/plain` y un GIF tiene extensión vacía (`dataobject.bin` en ASiC). Todo ello
  se reproduce.
* **`Properties.store`** en Java 18+ escribe las entradas **ordenadas por clave**
  (la especificación habla del orden de la tabla hash, que era el de Java ≤ 17).

## 1. Detección de tipos de datos

* **JMimeMagic** se sustituye por una tabla generada a partir de su propio
  `magic.xml` (`tools/oracle/gen_magic_table.py` →
  `crates/afirma-core/src/mime/magic_table.rs`). Solo se evalúan las reglas de
  primer nivel (las subreglas no cambian tipo, extensión ni descripción). Las 9
  reglas `regex` se interpretan con un intérprete mínimo de los patrones que
  aparecen (`^`, `\s*`, literales, `/m`); el detector `TextFileDetector` se
  reimplementa con la misma semántica que la expresión ORO
  `/[^[:ascii:][:space:]]/`.
* **`OfficeAnalizer`** lee el ZIP en memoria (sin fichero temporal) con el crate
  `zip`. Para ZIP corruptos o con nombres no UTF-8 el resultado puede diferir.
* **`AOFileUtils.isXML`** usa `roxmltree` (sin DTD) y una comprobación explícita de
  `<!DOCTYPE` en el prólogo, en lugar de Xerces. Las codificaciones se resuelven con
  `encoding_rs` (etiquetas WHATWG: `ISO-8859-1` se trata como windows-1252, lo que no
  afecta a la buena formación); codificaciones que Java admite y WHATWG no (EBCDIC...)
  hacen que el documento no se considere XML.

## 2. `extraParams` (`java.util.Properties`)

* La línea de fecha de `store` usa la zona como `GMT±hh:mm` (o `GMT`) en lugar de
  la abreviatura (`CEST`): Rust no dispone de la base de datos de nombres de zona.
  Es un comentario que ningún lector interpreta.
* `ExtraParams` añade **marcas internas** (`set_internal_flag`) para los valores no
  de texto que Java guarda en el `Properties` (`confirmDifferentProfile` =
  `Boolean.TRUE`). `expand_properties` las copia; en Java su presencia provoca un
  `NullPointerException`.
* `ExtraParams::parse` (ya existente) es tolerante con `\uXXXX` mal formados; el
  nuevo `ExtraParams::load` reproduce el error de Java. Se ha corregido
  `ExtraParams::parse` para que las continuaciones de línea con `\r\n` y las líneas
  de continuación vacías se comporten como en Java.

## 3. Políticas de firma

* `expand_properties` con `expPolicy` y **sin formato** devuelve el error 200115
  (Java: `NullPointerException`, que el protocolo acaba tratando como error
  desconocido de firma).
* `AdESPolicy` descarga el documento de la política (cuando no se da la huella) con
  el cliente HTTP del proceso, por lo que se aplican el proxy y la configuración TLS
  de AutoFirma. Se admiten `http`, `https` y `file`; `ftp` y `jar` producen error.
* `AdESPolicy::as_extra_params` guarda el calificador como texto (Java lo guarda como
  objeto `URL`, invisible para `getProperty`).
* El calificador se valida como en `new URL(...)`: esquema de un protocolo con
  manejador en Java (`http`, `https`, `ftp`, `file`, `jar`, `mailto`, `jrt`), sin más
  comprobaciones.

## 4. Cliente HTTP (`UrlHttpManagerImpl`)

* Cabecera `User-Agent`: `AutoFirma-rs/<versión>` (configurable en `HttpSettings`)
  en lugar de `Java/<versión>`. Como en Java no se envía `Accept-Encoding` y se
  descartan las cabeceras restringidas (`Host`, `Origin`, `Connection`,
  `Content-Length`...).
* **Tiempo de lectura**: Java lo aplica a cada lectura del socket (`SO_TIMEOUT`);
  `ureq` lo aplica a la recepción de las cabeceras y del cuerpo completo.
* **Redirecciones**: se siguen manualmente con las reglas de `HttpURLConnection`
  (300-307 salvo 304-306, máximo 20, nunca cambiando de protocolo, POST→GET salvo en
  307) para poder guardar y enviar las cookies en cada salto. Al cambiar de servidor
  se elimina la cabecera `Authorization` obtenida de la URL.
* **Cookies**: almacén en memoria común a todas las peticiones (`cookie_store`, RFC
  6265) en lugar del `CookieManager` con `ACCEPT_ALL` de Java; las diferencias solo
  afectan a cookies con atributos no válidos.
* POST/PUT con `?` pero sin consulta: cuerpo vacío (Java lanza
  `NoSuchElementException`).
* **TLS**: verificación con el almacén del sistema (`rustls-platform-verifier`, que
  incluye las CA corporativas instaladas en el sistema). El almacén propio de
  AutoFirma (`~/.afirma/TrustedCertsKeystore.jks`) no lo lee el núcleo: la aplicación
  pasa sus certificados en `HttpSettings::extra_trusted_certs` y el cliente acepta el
  servidor si confía el sistema **o** esos certificados (como `MultiX509TrustManager`).
  Las peticiones sin verificación (`disableSslChecks`, dominios seguros,
  `TlsOverride::TrustAll`) usan un agente separado para no reutilizar conexiones no
  verificadas en peticiones verificadas. No se cargan claves de cliente
  (`javax.net.ssl.keyStore`).
* **Diálogo de confianza** (`SSLErrorProcessor`): solo se ofrece ante errores de
  validación del certificado (Java lo ofrece ante cualquier
  `SSLHandshakeException`). La cadena del servidor se descarga con `rustls`
  directamente (atravesando el proxy con `CONNECT`). El diálogo lo implementa la
  aplicación (`TrustPrompt`) y es responsable de persistir los certificados.
* **Proxy del sistema**: variables de entorno, registro de Windows (con
  `ProxyOverride`), `scutil --proxy` en macOS y `gsettings` en GNOME (modo manual).
  No se admiten PAC/WPAD ni la estrategia "navegador" de proxy-vole. El proxy
  personalizado recibe la contraseña ya descifrada (el descifrado de la preferencia
  queda fuera del núcleo). Las exclusiones en formato CIDR no se admiten.
* `DataDownloader`: las URL `ftp://` no están soportadas.

## 5. Utilidades

* `create_uri`: la validación sintáctica de `java.net.URI` es aproximada (caracteres
  ilegales y escapes `%` mal formados); los mensajes de esos errores difieren de los
  de Java. `load_file` no admite `ftp`/`jar`.
* `get_rdn_value_from_ldap_name`: si pasar el nombre a minúsculas cambia su longitud
  (casos Unicode especiales) se usa una búsqueda simplificada.
* `Platform`: el SO y la arquitectura salen del objetivo de compilación; `x86` es
  siempre `X86` (Java en Linux de 32 bits devolvía `OTHER`). `system_root()` usa la
  variable de entorno `SystemRoot` (Java consultaba por error una propiedad del
  sistema con ese nombre).
* `allow.extended.logs` se sustituye por la variable de entorno
  `AFIRMA_ALLOW_EXTENDED_LOGS`.
* Fechas visibles: `AOSimpleSignInfo.toString()` usa el formato de Java 17+ para
  `es_ES` (`16 oct 2026, 13:17`, septiembre `sept`); `Date.toString()` escribe la
  zona como `GMT±hh:mm`.

## 6. Firma PKCS#1 y trifásica

* La autoverificación de `AOPkcs1Signer` usa `ring`: RSA con SHA-1/256/512 (claves de
  1024 a 8192 bits) y SHA-384 (2048 a 8192), ECDSA P-256/P-384 con SHA-256/384. Con
  otras combinaciones (SHA-224, ECDSA con SHA-1, P-521, DSA) se omite la comprobación
  con un aviso en el registro.
* Los errores de la clave (`KeyError`) se traducen a los de JMulticard/Java:
  cancelación 500001, PIN incorrecto 501003, bloqueo 511004, clave no válida 200110,
  otros 200111.
* `TriphaseData` conserva el orden de inserción de los parámetros (Java usa el orden
  de un `ConcurrentHashMap`; el servidor analiza el XML, así que el orden no importa).
  Un parámetro sin atributo `n` produce un error en lugar de un
  `NullPointerException`. Los errores de análisis no llevan código: lo pone el
  llamante (300401 en la prefirma).
* `NONEtri`: si el servidor responde solo `OK` se devuelve 300407 (Java:
  `StringIndexOutOfBoundsException`).

## 7. ASiC-S

* El contenedor se escribe con el crate `zip`: la estructura (comentario
  `mimetype=application/vnd.etsi.asic-s+zip`, orden de entradas, `mimetype`
  comprimida) es la de Java, pero los bytes (campos extra, compresión, fechas) no son
  idénticos a los de `ZipOutputStream`.
