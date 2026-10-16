# Desviaciones de `afirma-protocol` respecto a AutoFirma Java

Este documento recoge, para el crate `afirma-protocol` (protocolo `afirma://`,
servidor WebSocket local, socket de servicio, servidor intermedio, cifrado,
firma trifásica y por lotes), cada punto en el que el comportamiento se
aparta del de AutoFirma 1.9.1/1.10 (especificación: `docs/spec/01-protocol.md`,
referencias `Qn` a su §13). Todo lo no listado aquí reproduce el
comportamiento observable de Java (formatos, separadores, alfabetos Base64,
orden de validación y códigos de error).

Criterio: solo se corrige un fallo claro de Java si la corrección no puede
romper una integración real (AutoScript 1.10.x y los servidores intermedio,
trifásico y de lotes de este repositorio, probados contra los WAR reales).

## Seguridad

| # | Java | Rust | Motivo |
|---|---|---|---|
| S1 (Q13) | El servidor WebSocket y el socket de servicio escuchan en **todas** las interfaces (`new InetSocketAddress(port)`); solo el WebSocket v4 comprueba después que el par sea `127.0.0.1`. | Ambos escuchan **solo en `127.0.0.1`** (configurable en `WebSocketOptions`/`ServiceOptions`). Se mantiene la comprobación de par local (420001). | La página siempre conecta a `wss://127.0.0.1:<puerto>`; escuchar en la red solo expone la aplicación. |
| S2 | `validateURL` solo considera locales los hosts exactamente `localhost` y `127.0.0.1` (`LOCALHOST`, `127.0.0.2`, `[::1]` pasan). | Se rechaza como local cualquier bucle local: `localhost` (cualquier capitalización y `*.localhost`), `127.0.0.0/8`, `0.0.0.0`, `::1`, `::`, IPv4 mapeada. Mismos códigos (600010, 6004xx). | La regla pretende impedir que una web haga hablar a AutoFirma con servicios locales; ningún despliegue real usa un servlet en el bucle local. |
| S3 | `dat` se comprueba con `startsWith("file:/")` **antes** de recortar, pero `DataDownloader` recorta después: `dat=%20file:/etc/passwd` leía el fichero local y lo firmaba/devolvía a la web. | Se rechaza con 600117 cualquier `dat` que, recortado, empiece por `file:` (sin distinguir mayúsculas). | Lectura de ficheros locales arbitrarios desde una web. |
| S4 | Mensajes WebSocket y del socket de servicio sin límite de tamaño. | Límite de 512 MiB por mensaje WebSocket y 64 MiB por petición del socket de servicio (configurable). | Evita agotar la memoria desde cualquier página (el canal no comprueba `Origin`). |

## Robustez / fallos de Java corregidos

| # | Java | Rust | Motivo |
|---|---|---|---|
| R1 (Q1, Q11) | `URLDecoder` convierte `+` en espacio en todos los valores, lo que corrompe el Base64 estándar sin codificar (`properties`, `cipher` en el sobre XML de AutoScript, que escribe los valores sin codificar). | En `properties`, `cipher`, `ksb64` y `key` el `+` se conserva (los `%HH` sí se decodifican). En `dat` se conserva solo si con él el valor es Base64 válido; si no, se aplica la regla de Java. El resto de parámetros sigue la semántica exacta de `URLDecoder`. | En un valor Base64 un espacio nunca es útil (el decodificador lo ignora), así que conservar el `+` solo puede arreglar datos. Un cliente que codificara bien (`%2B`) obtiene lo mismo que con Java. |
| R2 (Q1) | Un `%` mal formado lanza una excepción no capturada: en invocación directa no hay respuesta; por WebSocket asíncrono la página espera indefinidamente. | Error genérico de la operación (200115/200201/200413/200305/200600) con diálogo y respuesta. | La página recibe un error en vez de quedarse esperando. |
| R3 (Q4) | `ksb64` se decodifica con el alfabeto estándar sin normalizar; un valor URL-safe con `-`/`_` (el que envía AutoScript por WebSocket) se descartaba y se usaba el almacén por defecto. | Se normaliza (`-`→`+`, `_`→`/`) antes de decodificar. | El almacén pedido por la web se respetaba solo por casualidad. |
| R4 (Q15) | El socket de servicio solo acepta las versiones 1, 2 y 3; AutoScript 1.10.1 envía `v=4`, así que el modo "service" nunca funcionaba con AutoFirma 1.10. | Se acepta también la versión 4 (con la regla de 4.1 si `jvc>3`). En `save`, además de `OK`→`SAVE_OK` y `CANCEL`, se devuelven tal cual los errores `err-…` (formato 4.1, que Java nunca podía generar aquí). | Arregla el modo de compatibilidad para IE11/Firefox antiguos. |
| R5 (Q14) | El servidor WebSocket v3 pasa la versión **0** a las operaciones: todas fallan con 620011. | Se usa la versión del canal (3). | El camino v3 estaba muerto. |
| R6 (Q17) | El temporizador de inactividad inicial (30 s) solo cierra la aplicación si no se abrió ninguna conexión; una conexión sin mensajes válidos la mantenía viva indefinidamente. | El servidor termina (`ServerExit::IdleTimeout`) si en 30 s no llega ningún mensaje válido. | Evita procesos huérfanos. AutoScript envía el eco nada más conectar. |
| R7 (Q30) | Si el hilo de una operación asíncrona moría, la página esperaba indefinidamente. | Se devuelve el error 200118 (`UNKNOWN_SIGNING_BY_SOCKETS_ERROR`). | — |
| R8 | Operaciones asíncronas por WebSocket concurrentes (un hilo por petición; la nueva sustituye a la anterior en el mapa). | Las operaciones se ejecutan de una en una (el mapa de resultados se sustituye igual, así que la página obtiene el mismo resultado). | Evita diálogos concurrentes. |
| R9 (Q19) | Los errores de parámetros y de descarga del sobre (`fileid`) no se suben al servidor intermedio: la página agota su espera (AS620024). Para `save`, el error del sobre se subía como texto de excepción con el identificador `fileid`, que la página no consulta. | Si se conocen un identificador válido (`id`, o `rid` en las URL con `fileid`) y un `stservlet` válido (no local), el error se sube con el formato de la versión pedida (`ver` + `jvc`; sin `ver` y con `jvc>3` se usa 4.1). Desactivable con `LauncherConfig::upload_all_errors`. La respuesta devuelta por `launch` sigue siendo la de Java. | La página muestra el error en vez de esperar. |
| R10 (Q9) | `selectcert` y `batch` suben el resultado dos veces en invocación directa. | Se sube una vez. | El Retriever borra el fichero en cada lectura; la segunda subida no aporta nada. |
| R11 (Q10) | `load` en invocación directa muestra el diálogo de carga y después falla con 200600 al no poder subir el resultado. | Falla con 200600 (diálogo de error) antes de mostrar el diálogo de carga. | Mismo resultado sin pedir ficheros inútilmente. |
| R12 (Q26) | `servicetimeout` se fija en el gestor HTTP global y queda aplicado a las operaciones posteriores del proceso. | Se aplica solo a la operación que lo indica (tiempo de lectura de esa petición). La postfirma XAdES sigue usando el parámetro adicional `servicetimeout` como tiempo de **conexión**, como Java. | Un tiempo de espera de una web no debe afectar a otra. |
| R13 | Los firmadores trifásicos CAdES modifican los `extraParams` del llamante (quitan `serverUrl`), por lo que el reintento tras una confirmación `ERR-21` fallaba con 600121. | Se trabaja siempre sobre copias. | Arregla el flujo de confirmación del usuario. |
| R14 | Lote local: los `extraparams` se cargan con `Properties.load(InputStream)` (ISO-8859-1) y corrompen los caracteres no ASCII escritos en UTF-8. | Se interpretan como UTF-8. | Textos de firma visible con tildes. |
| R15 | Sobre XML (`fileid`): cualquier nodo de texto en blanco o comentario entre los `<e/>` hace fallar el análisis. | Se ignoran los blancos y comentarios entre elementos (cualquier otro nodo sigue siendo un error). | Solo afecta a entradas que Java rechazaba. |
| R16 (Q12) | El sobre JSON (`{"params":[…]}`) es inalcanzable. | Se detecta por el primer carácter (`{`) y se admite junto al XML. | Permitido por la especificación. |
| R17 | Un mensaje `afirma://websocket?…`/`afirma://service?…` recibido por un canal abierto intentaba abrir otro servidor. | Responde 600002 (operación no soportada). | — |
| R18 | La respuesta trifásica `OK NEWID=` demasiado corta o con Base64 de 1-3 caracteres lanzaba excepciones no controladas (600121/200115). | Siempre 300407 (`MALFORMED_POSTSIGN_RESPONSE`). | Solo afecta a respuestas mal formadas. |
| R19 | `getInternalException` (comprobación de herencia invertida) solo reconstruye una excepción cuando el servidor indica la clase `java.lang.Exception`, que acaba como error genérico 200115. | Se reproduce exactamente ese caso (error sin código → 200115); el resto conserva el código `AOTriphaseException` como en Java. | Paridad. |
| R20 | `FTP` en `dat` se descargaba con `URL.openStream`. | No se admite (error 200102). | Sin uso real y sin cliente FTP. |

## Diferencias de implementación sin efecto en el protocolo

| # | Java | Rust |
|---|---|---|
| I1 | Java-WebSocket envía pings y cierra la conexión si no hay respuesta en 60 s (240 s en lotes síncronos). | No se envían pings: en el bucle local el sistema cierra el socket si el navegador termina. Los pings del navegador se contestan. |
| I2 | TLS del socket de servicio restringido a una lista de suites TLS ≤ 1.2 (incluye CBC/DHE/ECDH estático). | rustls: TLS 1.2 (ECDHE con AES-GCM o ChaCha20) y TLS 1.3, igual para ambos canales. Los navegadores soportados las aceptan. |
| I3 | El texto de las subidas al StorageService se envía sin codificar (los `+`, `%`, `&` se corrompían en el servlet; los no ASCII dependían del juego de caracteres del servidor). | Se codifican solo `%`, `+`, `&`, controles y no ASCII; el servlet los decodifica y almacena exactamente el texto. Los resultados (Base64, `|`, `.`) viajan byte a byte igual que en Java. |
| I4 | Lectura del socket de servicio en trozos con detección de `@EOF`/`idsession` en el último fragmento. | Se lee hasta `@EOF` y se analizan el identificador de sesión y el comando sobre el texto completo (mismo resultado salvo casos degenerados). |
| I5 | Orden de las entradas de mapas Java (`HashMap`/`ConcurrentHashMap`/`Hashtable`). | Se reproduce el orden de `HashMap`/`ConcurrentHashMap` para `TriphaseData` (XML y JSON) y la salida de `org.json` (verificado contra una JVM); el `params` trifásico (`Properties.store`) se escribe en orden alfabético con la fecha en UTC (el servidor solo lo analiza). |
| I6 | `User-Agent: Java/<versión>`. | El del gestor HTTP común de afirma-core. |
| I7 | Diálogo de importación de certificados SSL de servidor (`SSLErrorProcessor`). | Se solicita al gestor HTTP común (`SslErrorHandling::Interactive`) en los mismos puntos que Java (descarga de `dat`, prefirmas, postfirmas CAdES/PAdES, prefirma de lotes); el diálogo lo implementa la aplicación (`afirma_core::http::TrustPrompt`). |
| I8 | Selección de almacén (§12.3: último almacén elegido en el proceso, preferencia "almacén por defecto en llamadas del navegador", biblioteca PKCS#11/PKCS#12 de las preferencias). | El crate entrega a la aplicación el almacén pedido por la web (`KeyStoreParam`, con `resolved_constant()`) y la aplicación aplica la precedencia de sus preferencias. |
| I9 | Plugins con procesadores de firma propios (`anotherParams`). | No hay plugins; los parámetros desconocidos se conservan en `SignParams::other_params`. |
| I10 | Ventanas de error mostradas por el lanzador. | Se notifican con `OperationHandler::show_error` (título y texto localizados como en Java, incluida la caída de los códigos 1xxxxx/2xxxxx al texto genérico). |

## Ampliaciones

- `RequestInfo` (origen de la página —cabecera `Origin` del WebSocket o de la
  petición HTTP del socket de servicio, o host del servidor intermedio—,
  operación, formato resuelto, número de documentos del lote, tamaño, nombre
  y contenido de los datos) se entrega al manejador en la selección de
  certificado, la firma visible, los diálogos de ficheros y el progreso, para
  que la interfaz muestre qué se firma y quién lo pide.
