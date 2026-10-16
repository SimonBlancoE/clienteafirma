# Desviaciones de `afirma-cli` respecto a la versión Java

Crate: `crates/afirma-cli` (línea de comandos de AutoFirma, `CommandLineLauncher`,
`CommandLineParameters`, `CommandLineMessages`; especificación
`docs/spec/06-app-ui-cli-installer.md` §5 y §7.5.10).

Todo lo citado de Java se ha comprobado con la AutoFirma original en modo sin interfaz
(`tools/oracle/cli_oracle.sh` y `tools/oracle/cli_goldens.py`). Los 179 casos de
`testdata/cli/cases.tsv` (ayudas en los seis idiomas, errores de parámetros, almacenes,
firmas, cofirmas y contrafirmas en todos los formatos, `verify`, `listaliases`,
`batchsign`, modo `-xml`) se comparan en `tests/oracle_golden.rs`: estado de salida y
salida estándar idénticos byte a byte salvo lo que se indica aquí. Las firmas de Rust
tienen la misma estructura (formato, árbol de firmantes, variante) que las de Java para
la misma orden, y `autofirma verify` de Java da sobre ellas exactamente el mismo
veredicto que sobre las suyas (`cli_goldens.py --verify`).

## Comportamiento que se conserva (aunque sea extraño)

- Todo se imprime en la salida estándar, errores incluidos, con un `\n` final; los
  errores devuelven −1 (255 en POSIX).
- Opciones sensibles a mayúsculas (`-XML` es un parámetro desconocido), comando
  insensible (`SIGN`); una opción con valor consume el token siguiente aunque empiece
  por `-`; `-help` fuera de la primera posición es un parámetro desconocido.
- Solo los errores de `CommandLineParameterException` (formato, `-hformat`, URL, tipo de
  almacén desconocido, falta `-i`/`-o`/alias, tipo de clave) imprimen la ayuda del
  comando, y nunca en XML. Los errores del análisis (parámetro desconocido, duplicado,
  valor ausente, fichero de entrada inexistente) se imprimen sin ayuda y sí en XML.
- El diálogo de error con `-gui` depende de que `-gui` aparezca **antes** de la opción
  errónea.
- `-format auto` elige solo PAdES, XAdES o CAdES por el contenido (ni FacturaE ni
  OOXML/ODF); algoritmo por defecto SHA-512; las preferencias no se aplican a la firma
  sin interfaz; `-config` admite rutas locales (PAdES sin modo seguro).
- `listaliases` responde `<result>ok</result>` (las firmas, `true`/`false`); `verify`
  ignora `-xml` y devuelve 0 sea cual sea el resultado; los mensajes de los almacenes
  PKCS#12/PKCS#11 inexistentes son los textos fijos en español de Java.
- La ayuda de `batchsign` no menciona `-config` (aunque se usa); la de `listaliases` no
  menciona `pkcs11:` (aunque se admite); la de `verify` en los idiomas distintos del
  español conserva el `%0` literal de `CommandLineLauncher.23`.
- Cada firma PKCS#1 se verifica con el certificado antes de usarla, como
  `AOPkcs1Signer` (`afirma_keystores::VerifyingKey`), también en `batchsign`.
- La causa que imprime Java en los errores de lectura y escritura (`<ruta> (Is a
  directory)`) se reproduce con el texto del sistema operativo.

## Correcciones y mejoras

1. **Claves ausentes en los catálogos.** Los catálogos en, ca, gl, eu y va carecen de
   `CommandLineLauncher.146`–`149`, y Java imprime `!CommandLineLauncher.148!` en lugar
   del error de alias inexistente (perdiendo el alias). Ahora una clave ausente se toma
   del español. En la ayuda de los comandos de firma, en lugar de
   `... Priority over %0 !CommandLineLauncher.146!` se imprime `... Priority over
   -certgui` (se sustituye el `%0` que esos catálogos ya incluyen en `.23`).

2. **Idioma.** Como en `processCommandLine`, se usa la preferencia `default.locale` y,
   si no existe, la configuración regional del sistema (`CliEnv::os_locale`, por defecto
   `LC_ALL`/`LC_MESSAGES`/`LANG`). Diferencias: un idioma sin catálogo propio se asimila
   al de su lengua (`en_GB` → `en_US`, `ca_ES@valencia` → `va_ES`) o, si no hay, al
   español; Java imprimía `!clave!` en **todos** los mensajes. Nota: con el lanzador
   normal de Java (`SimpleAfirma.main`) la preferencia vacía se rellenaba con `es_ES` y
   se **guardaba** antes de llegar a la línea de comandos; aquí no se escribe ninguna
   preferencia. Las entidades HTML de los textos de validación (`ning&uacute;n`) se
   imprimen como caracteres (`ningún`).

3. **XML escapado.** El mensaje de `<msg>` y los alias de `<alias>` se escapan (`&`, `<`,
   `>`). Para los valores normales la salida es idéntica a la de Java.

4. **`-config`.** Java separa solo por la secuencia literal `\n`, no recorta las claves
   salvo en la última línea y una línea sin `=` produce `Error no reconocido: Range [0,
   -1) out of bounds for length 3`. Ahora se admiten `\n` literal y saltos de línea
   reales, se recortan claves y valores, se ignoran las líneas vacías y las que empiezan
   por `#`, y una línea sin `=` da `La configuracion indicada no tiene el formato
   clave=valor: <línea>` (estado −1). `sign -gui` usa el mismo analizador en modo
   tolerante (descarta las líneas sin `=`, como Java).

5. **Reintento de firma visible.** Si la posición o la página de la firma visible no
   son válidas, Java reintenta sin las claves de firma visible pero concatena las demás
   líneas a `null`, así que la primera se pierde (`nullsignReason=...`). Ahora se
   conservan todas (prueba `reintento_sin_firma_visible_conserva_la_configuracion`).

6. **`batchsign`.** Java descarta el resultado: no imprime nada y termina con 0 aunque
   fallen el almacén, la lectura del lote, la red o el servidor (casos `batch_conn_error`,
   `batch_bad_password` del oráculo). Ahora imprime `La operacion ha terminado
   correctamente ` (o la respuesta XML) con estado 0, o el mensaje de error (en XML con
   `-xml`) con estado −1. Con `-xml` y sin `-o` Java fallaba (`Error no reconocido:
   null`); ahora el resultado del lote se devuelve en `<sign>` en Base64. Además del lote
   XML (`BatchSigner.signXML`, servidores antiguos) se admiten lotes JSON
   (`BatchSigner.signJSON`, los del servidor trifásico actual) cuando el fichero empieza
   por `{`.

7. **`sign -gui`.** Java tenía la condición del formato invertida: con `-format` distinto
   de `auto` ignoraba el formato pedido y elegía uno por el contenido. Ahora la petición
   de interfaz lleva el formato pedido (o ninguno con `auto`). También lleva los
   parámetros de `-config`, que Java descartaba junto con los de las preferencias; se
   recomienda a la aplicación aplicar las preferencias del formato y después estos. El
   algoritmo sigue siendo SHA-512 por defecto, como en Java, pero se indica si se pidió
   expresamente (`algorithm_explicit`).

8. **Contraseñas y diálogos.** Sin `-password`, Java usa los diálogos del almacén (y, sin
   interfaz, abre el PKCS#12 sin contraseña: `listaliases` funciona y la firma falla sin
   mensaje). Ahora se usa el `PasswordCallback` que inyecta la aplicación (por defecto,
   ninguno: `La contrasena del almacen PKCS#12 / PFX no es valida`). `-certgui` usa el
   `CertificateChooser` de la aplicación; si no hay, `No se puede mostrar el dialogo de
   seleccion de certificado (-certgui) en este entorno` (Java sin interfaz terminaba con
   −1 sin imprimir nada). La cancelación da, como en Java, `Error no reconocido: No se ha
   seleccionado certificado`.

9. **Errores de firma con mensaje vacío.** Java imprime el mensaje de la causa; si es
   nulo no imprime nada. Se conserva, pero los firmadores de Rust siempre dan mensaje,
   así que en la práctica se imprime siempre la causa (por ejemplo, Java sin `-password`
   no imprimía nada al fallar la clave; Rust imprime el error del almacén).

10. **PKCS#12 no válido.** Java imprime `El almacen PKCS#12 / PFX no es valido o no pudo
    cargarse`; Rust añade el detalle (`: el fichero no es un almacén PKCS#12 válido:
    ...`).

11. **OOXML sin interfaz.** Java no puede firmar OOXML en modo sin interfaz
    (`Error durante la firma OOXML: java.awt.HeadlessException`); Rust sí. La firma la
    reconoce la versión Java (`verify`: validación incompleta, igual que para un OOXML
    firmado con Java).

12. **`verify` de un ODF u OOXML sin firmar.** Igual que Java (`formato no reconocido`):
    `afirma_signers::validate` devuelve «validación incompleta» para cualquier OOXML/ODF,
    así que la línea de comandos comprueba antes si el documento está firmado.

## Comandos nuevos

- `createdigest` y `checkdigest` (plugin de huellas de Java) son comandos integrados y se
  listan en la ayuda general junto a los demás. Se delega en `afirma-hash`, con sus
  propias desviaciones (`docs/deviations/afirma-hash.md`; en particular, `checkdigest`
  devuelve 1 si las huellas no coinciden salvo con `CliEnv::hash_java_exit_codes`).
- `install (--system|--user) [--browser-policies] [--origins LISTA] [--dry-run]`,
  `uninstall (--system|--user) [--dry-run]`, `doctor [--json]` y `restore-config`, para
  los instaladores, en una sección nueva de la ayuda general («Comandos de integracion
  con el sistema»). Se analizan aquí y se ejecutan con el `SystemOps` de la aplicación
  (con la característica `afirma-system`, `system_adapter::AfirmaSystemOps`).
- `-version`/`--version` y `--help` (en Java eran comandos no reconocidos).

## Fuera del crate

- El ejecutable escribe `output` tal cual (UTF-8). Java escribía en la codificación de la
  consola; en Windows la aplicación debe poner la consola en UTF-8
  (`SetConsoleOutputCP(65001)`) o convertir la salida.
- Una ruta suelta como primer argumento sigue siendo un comando no reconocido, como en
  Java; abrir ficheros en la interfaz lo decide la aplicación antes de llamar a `run`.
