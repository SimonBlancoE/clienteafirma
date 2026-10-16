# Desviaciones de `afirma-hash` respecto a la versión Java

Crate: `crates/afirma-hash` (plugin «Huellas digitales», `afirma-simple-plugin-hash`,
especificación `docs/spec/06-app-ui-cli-installer.md` §7.5).

Todos los comportamientos de Java citados aquí se han comprobado con el plugin original
(`tools/oracle/HashOracle.java`, `tools/oracle/hash_oracle.sh`). Los formatos de salida
(`.hexhash`, `.hashb64`, `.hash`, `.hashfiles`, `.txthashfiles`, `.hashreport`), los
mensajes y los textos de ayuda son idénticos byte a byte salvo lo indicado.

## Interoperabilidad

| | Java | Rust |
|---|---|---|
| Documentos de Java leídos en Rust | — | Sí (XML y TXT, rutas con `/` o `\`) |
| Documentos de Rust leídos en Java | — | Sí en Linux/macOS; en Windows Java busca rutas con `\` y las nuestras usan `/` (ver 1) |
| Ficheros de huella de un fichero | — | Idénticos en ambos sentidos |

Las pruebas `tests/oracle_live.rs` (con `AFIRMA_HASH_ORACLE`) verifican en vivo que Java
acepta todo lo que generamos y viceversa, incluidos nombres con `& < > " ' \t \n \r \ ;`
y caracteres no ASCII.

## Correcciones de fallos

1. **Separador de las rutas relativas.** Java escribe la ruta con el separador del sistema
   (`sub\hola.txt` en Windows), así que un documento creado en Windows no sirve en Linux y
   al revés. Escribimos siempre `/`. Al comprobar, cada fichero se busca en el documento
   primero tal cual y después cambiando `\` por `/` (si no hay ambigüedad). Así se
   aceptan los documentos de Java para Windows y se conservan los nombres con `\` de
   Linux. *Interoperabilidad:* Java en Windows no encontrará las rutas con `/` de un
   documento nuestro que tenga subdirectorios (lo mismo que ya le pasa con los documentos
   de Java para Linux).

2. **Errores silenciosos al calcular directorios.** En Java, un error de lectura o un
   algoritmo desconocido en un fichero cierra el pool de hilos y el documento se genera
   igualmente con las entradas ya calculadas, sin avisar. Ejemplos: `createdigest DIR
   -halgorithm FOO` da `<entries hashAlgorithm="FOO" recursive="false"/>` con estado 0, y
   un fichero sin permiso de lectura desaparece del documento. Ahora cualquier error
   interrumpe la operación y se devuelve (`HashError`). En la línea de comandos da el
   mensaje `Error durante el calculo de huellas digitales` (`CommandLine.94`) con
   estado -1. Lo mismo al comprobar: Java dejaba de comprobar e informaba de las entradas
   pendientes como `hash_without_file`.

3. **Directorios con ruta relativa en la línea de comandos.** Java calcula la ruta relativa
   con `Path.relativize` entre la ruta indicada (relativa) y la absoluta del fichero, y eso
   lanza `IllegalArgumentException`. Por eso `createdigest dir` genera en silencio un
   documento vacío, y `checkdigest dir -i x.hashfiles` falla con `Error no reconocido:
   java.lang.IllegalArgumentException: 'other' is different type of Path`. Aquí las rutas
   relativas funcionan.

4. **Comprobación de la huella de un fichero** (`CheckHashFileDialog.checkHash`):
   - El hexadecimal sin la `h` final se decodifica bien. Java siempre quita el último
     carácter, y además un hexadecimal de 64 caracteres pasa su prueba de Base64. Por eso
     un SHA-256 en hexadecimal sin `h` se toma por Base64 de 48 bytes y «no coincide».
     Ahora se prueba primero el hexadecimal y solo se quita una `h`/`H` final.
   - Se ignoran los espacios y saltos de línea finales en hexadecimal y en Base64 (un
     fichero editado a mano con CRLF daba error en Java). La huella binaria nunca se
     recorta.
   - Se acepta Base64 URL-safe y sin relleno. Java ignora `-` y `_`, así que la longitud
     no corresponde y da error.
   - Cada interpretación textual solo se acepta si la longitud resultante es la de un
     algoritmo conocido; si no, se pasa a la siguiente (hexadecimal → Base64 → binario).
     Las longitudes desconocidas siguen siendo un error (`CommandLine.94` en la línea de
     comandos).

5. **Carga de documentos de directorio** (`HashDocumentFactory.loadDocument`):
   - El formato se detecta por el contenido (XML si empieza por `<`, tras un BOM o espacios
     opcionales; si no, TXT), no por la extensión. Java falla con un
     `NullPointerException` si el fichero no tiene extensión (imprime `Cannot invoke
     "String.hashCode()"...`).
   - Si el documento no es válido se devuelve un error (`DocumentError::Unsupported` →
     `No se ha podido cargar el documento de huellas` / `El fichero de huellas seleccionado
     no esta soportado.`). En Java el «bucle de formatos alternativos» devuelve un
     documento **vacío** sin cargar (SHA-256, no recursivo), y la comprobación informa de
     todos los ficheros como `file_without_hash`. Ocurre con un XML que no valida, sin
     `hexhash` o sin `hashAlgorithm`, o con un TXT con una línea errónea.

6. **Lector XML.** La validación equivale a `folderhashes.xsd`:
   - raíz `entries` sin espacio de nombres;
   - solo los atributos del esquema (se toleran los `xsi:*`);
   - hijos solo `entry`, con texto opcional y sin elementos hijos;
   - `name` y `hash` obligatorios.

   Diferencias:
   - `hashAlgorithm` es obligatorio. El XSD lo hace opcional, pero Java lo necesita.
   - `recursive="1"` se interpreta como verdadero, como `xs:boolean`. Java lo valida y
     después usa `Boolean.parseBoolean`, que da `false`.
   - `hexhash` es opcional. Si está, `hash` (URL-safe estricto) y `hexhash` (hexadecimal
     estricto, `h` opcional) deben coincidir; si no, el documento está corrupto, como en
     Java.
   - Una huella cuya longitud no es la del algoritmo se considera corrupta. Java la
     compara y da «no coincide».
   - Las entradas duplicadas son un error. En Java gana la última.

7. **Lector TXT** (`TxtHashDocument.load`):
   - Un documento solo con cabeceras (directorio vacío) es válido. Java falla con un
     `NullPointerException` y acaba en el documento vacío del punto 5.
   - La ruta se separa por el **último** `;` (la huella nunca lo contiene). Java usa el
     primero y rompe las rutas con `;`.
   - La huella hexadecimal se valida. Java decodifica basura sin avisar. Se ignoran los
     espacios y tabuladores tras la huella.
   - El juego de caracteres se toma de `;charset=` en la primera línea, sea cual sea su
     longitud y aunque solo haya LF. Java solo mira los 30 primeros bytes y exige `\r`. Se
     quita el BOM UTF-8. Un juego de caracteres desconocido o bytes no válidos dan error.
     Java sustituye los caracteres o cae en el documento vacío.
   - Sin el mínimo de 30 bytes de Java; un documento sin ninguna línea es un error.
   - Se mantiene `Boolean.parseBoolean` para `;recursive=`, las líneas de cabecera
     desconocidas se ignoran y las líneas que empiezan por `;` tras las cabeceras dan
     error, como en Java.

8. **Escritura de documentos.**
   - TXT: se rechazan las rutas que contienen CR/LF o empiezan por `;`
     (`HashError::UnrepresentableName`), porque no se podrían volver a leer. Java
     escribe el documento roto.
   - XML: se rechazan los caracteres no válidos en XML 1.0, como también hace Java
     (`Error al generar el documento de huella digital`).
   - El nombre del algoritmo se escribe siempre en forma canónica (`SHA-256`). Java copia
     tal cual el valor de `-halgorithm` (`sha256`), y el documento XML resultante no
     valida contra su propio XSD al comprobarlo. Lo mismo en el atributo `hashAlgorithm`
     del informe.
   - SHA-224 no se puede escribir en XML (el XSD no lo admite; Java lo escribe y después
     no puede leerlo): error `Error al generar el documento de huella digital`. En TXT y
     en huellas de fichero sí se admite (Java lo deduce de los 28 bytes).

9. **Recorrido de directorios.**
   - Los ciclos de enlaces simbólicos a directorios se cortan, con un aviso en el
     registro. Java recurre hasta que falla.
   - Los enlaces rotos y los ficheros especiales (FIFO, sockets, dispositivos) se omiten
     siempre. Java los omite sin recursión, pero con `-r` falla por un
     `NullPointerException` (`listFiles()` devuelve `null`).
   - Nombres no UTF-8 (Unix): se incluyen con la ruta convertida con sustitución (U+FFFD).
     Java no puede abrirlos y los omite en silencio. Si dos ficheros dan la misma ruta, el
     resultado es un error.

10. **Línea de comandos.**
    - Si falta el valor de `-halgorithm` o `-hformat`, el mensaje es `Error no reconocido:
      No se ha indicado valor para el parametro: -halgorithm`. Java muestra `Error no
      reconocido: Index 2 out of bounds for length 2`.
    - **Estado de salida si las huellas no coinciden:** por defecto `1`
      (`STATUS_MISMATCH`). Java devuelve `0`, y `CliOptions { java_exit_codes: true }`
      restaura ese comportamiento. Los errores siguen siendo `-1` (255).
    - Con `-xml`, el mensaje de la respuesta XML de error se escapa (`&`, `<`, `>`).
      Java no lo escapa.
    - Las descripciones de los comandos (`HashCommand::description`) son las correctas.
      En Java salen con caracteres de sustitución (`plugin.json` en Latin-1 leído como
      UTF-8).
    - Sin el `-gui` de Java (`Runtime.halt(0)` tras los diálogos), la biblioteca devuelve
      `GuiRequest` y la aplicación muestra los diálogos.
    - `File.canRead()`/`canWrite()` se aproximan sin llamadas al sistema. Para leer se
      intenta abrir el fichero o listar el directorio. Para escribir, el padre debe
      existir, ser un directorio y no ser de solo lectura. Por ejemplo, `-o /x` como
      usuario normal se acepta aquí y falla después al escribir con `No se ha podido
      escribir en el fichero de salida`. Java lo rechaza al analizar los parámetros.

11. **Algoritmos.** Se admiten SHA-1, SHA-224, SHA-256, SHA-384 y SHA-512 con los nombres
    de JCA (sin distinguir mayúsculas, `SHA` para SHA-1, OID y `OID.`). Java admite
    además MD5, MD2, SHA-512/224, SHA-512/256 y SHA3-*. Aquí dan `Error durante el
    calculo de huellas digitales`.

## Otras diferencias (sin efecto en los datos)

- Las entradas de los documentos y de las cuatro listas del informe salen ordenadas
  alfabéticamente (por bytes UTF-8). En Java salen en el orden de un `HashMap` o en el
  de terminación de los hilos.
- Salto de línea de los XML: siempre `\n`. Java usa el del sistema (`\r\n` en Windows).
  Los lectores no dependen de ello.
- Paralelismo: tantos hilos como procesadores, hasta 10. Java usa siempre un
  `ForkJoinPool(10)`. El búfer de lectura se ajusta al tamaño del fichero (de 64 KiB a
  25 MiB) y se reutiliza por hilo. Java reserva 25 MiB por fichero.
- Se pueden cancelar los cálculos largos (`HashOptions::cancel`) y seguir su progreso
  (`HashOptions::progress`).

## Peculiaridades que se conservan a propósito

- La lista de nombres omitidos distingue mayúsculas: se omite `thumbs.db`, pero no
  `Thumbs.db` (el nombre real de Windows). Solo se aplica a ficheros: los directorios
  `.Trashes`, `$Recycle.Bin`... sí se recorren. Corregirlo cambiaría qué ficheros entran
  en los documentos respecto a Java.
- Si el documento de huellas está dentro del directorio comprobado, aparece como
  `file_without_hash`.
- El informe `.hashreport` no sigue `reportfolderhashes.xsd`. Las secciones vacías se
  omiten, y el orden es `matching_hash`, `not_matching_hash`, `hash_without_file`,
  `file_without_hash`.
- `checkdigest` sin argumentos muestra la ayuda (estado 0); `createdigest` sin argumentos
  da error (estado -1). Las opciones distinguen mayúsculas, salvo `-help` y los valores
  de `-hformat`.
- Cuando el fichero de datos es un directorio, `checkdigest` con `-o` escribe el informe
  y el mensaje sigue siendo el de la comprobación, no `La operacion ha terminado
  correctamente`.
