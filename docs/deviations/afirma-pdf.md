# Desviaciones de `afirma-pdf` respecto a AutoFirma Java

Este documento recoge las diferencias deliberadas entre `afirma-pdf` (PAdES, firma
visible, sellos de tiempo de PDF, validación y ataques de sombra) y la versión Java
(`AOPDFSigner` + iText 2.1.7 parcheado, `ValidatePdfSignature`). Referencias a
`docs/spec/04-pades.md` (§n) y a su lista de peculiaridades (§14, Qn).

Contraste realizado (ver «Pruebas» al final): la apariencia visible se ha comparado
píxel a píxel con la de Java para los mismos parámetros (texto por defecto, fuentes y
estilos, giros 90/180/270, rúbrica, rúbrica+texto, campo existente, marca visible,
capas heredadas, páginas giradas, varias páginas, página añadida); los flujos de
contenido de las capas `n2` son idénticos byte a byte en los casos sin giro. La
validación coincide con `ValidatePdfSignature` en los 52 PDF de prueba del
repositorio salvo donde se indica.

## 1. Estrategia de revisiones: siempre actualización incremental (§5.1, Q2, Q3)

* **Java**: en la primera firma de un PDF sin firmas ni contraseña, iText **reescribe
  todo el fichero** (objetos renumerados, revisiones anteriores perdidas, cabecera
  `%PDF-1.7`, compresión completa con flujos de objetos y de referencias cruzadas).
  En las siguientes firmas (o con contraseña o `alwaysCreateRevision=true`) añade una
  actualización incremental.
* **Rust**: **siempre** se añade una actualización incremental: los bytes originales
  son prefijo exacto del resultado (no se pierden revisiones ni firmas previas, y los
  validadores ven el documento original intacto). La sección de referencias cruzadas
  nueva es del mismo tipo que la anterior (flujo `/Type/XRef` si la anterior lo era,
  tabla clásica si era tabla o híbrida); los objetos nuevos no se meten en flujos de
  objetos.
* Consecuencias:
  * `compressPdf` no tiene efecto (no hay reescritura).
  * `pdfVersion` (por defecto 7) no cambia la cabecera; si la versión del documento es
    menor, se escribe `/Version /1.<v>` en el catálogo (Java nunca escribe
    `/Version`, pero su reescritura dejaba la cabecera en 1.7). No se hace en PDF/A.
  * `alwaysCreateRevision` es redundante.
  * Si la tabla de referencias de un PDF **sin firmas** está dañada (no se puede leer
    la sección de `startxref`), se reconstruye el documento completo antes de firmar,
    como la reescritura de Java. Con firmas previas se mantiene el error de Java
    (212002 «Append mode requires a document without errors…»).

## 2. Trailer `/ID` (§5.2, Q4)

* **Java** regenera los dos elementos de `/ID` con valores aleatorios (salvo el primero
  en PDF cifrados).
* **Rust** conserva el primer elemento (identificador permanente, ISO 32000-1
  §14.4) y genera el segundo de forma **determinista** (MD5 de la huella del PDF
  original, la fecha de firma, el certificado y el tipo de firma). Si el documento no
  tenía `/ID` se generan ambos. El determinismo hace reproducible la prefirma
  trifásica (§11.5).

## 3. Objetos auxiliares de iText que no se escriben (§5.2, §5.5, Q6)

* `/Pages` no recibe `/ITXT (2.1.7)`.
* Firma en varias páginas: como Java, un único diccionario campo/widget referenciado
  desde las anotaciones de todas las páginas (con el `/P`, el `/Rect` y la apariencia
  de la primera); pero en `/AcroForm /Fields` el campo aparece **una sola vez** (Java
  lo repite una vez por página).
* Con un `/AcroForm` ya existente solo se modifican `/Fields`, `/SigFlags` (|= 3) y se
  elimina `/NeedAppearances`; no se añaden `/DA` ni entradas `/DR` (`Helv`, `ZaDb`,
  `FRM`), que no tienen efecto visible y que algunos validadores (pyHanko) consideran
  modificaciones sospechosas del formulario. Un `/AcroForm` nuevo se crea como en Java.
* `/Info` se crea con `/ModDate` si el documento no lo tenía.

## 4. Sellos de tiempo (§7, Q5)

* **Java**: ambos tipos están rotos por un error de reflexión (§7.4): el sello de firma
  se omite en silencio y el de documento (`tsType` 2/3) hace fallar la firma (200002).
* **Rust**: funcionan con el cliente RFC 3161 de `afirma-cms` (todos los parámetros
  `tsa*`, HTTP/HTTPS/`socket://`):
  * `tsType` vacío o `1`: sello de firma (atributo no firmado
    `signatureTimeStampToken` sobre el valor de firma, PAdES T). Un fallo de la TSA se
    registra y la firma se entrega sin sello (comportamiento previsto en Java).
  * `2`: sello de documento `/DocTimeStamp` (`ETSI.RFC3161`) **antes** de la firma (el
    orden de Java); `3`: ambos. Un fallo de la TSA aquí hace fallar la operación.
  * El hueco del sello de documento es `signReservedSize` (Java fijaba 27000 bytes y
    fallaba si `signReservedSize` era menor).
  * El `nonce` es aleatorio (Java usaba los milisegundos de la fecha de firma).
* Validado con pyHanko (sellos íntegros y de confianza con la TSA de pruebas).

## 5. Imágenes (rúbrica `signatureRubricImage` y marca `image`) (§8.6.1)

* **Java** convierte todas las imágenes a JPEG (calidad 0,75) y rellena de **blanco**
  los píxeles transparentes.
* **Rust**: los JPEG se incrustan tal cual (`/DCTDecode`, sin recompresión); PNG, GIF
  y BMP se incrustan sin pérdidas (`/FlateDecode`) y el canal alfa se conserva como
  `/SMask`, de modo que la rúbrica transparente deja ver el contenido de la página. Con
  fondo blanco el resultado visible es el mismo (comprobado). Aviso de la interfaz
  Java «No se soporta el uso de imágenes con transparencias» ya no es necesario.

## 6. Apariencia visible

* **Campo existente + rúbrica** (Q7): Java ignora la rúbrica y, si no hay `layer2Text`,
  deja el campo en blanco. Rust dibuja la rúbrica (centrada, sin giro) y el texto como
  en un área nueva. El giro (`signatureRotation`) sigue sin aplicarse a campos
  existentes.
* **Colores** (Q18): Java busca `layer2FontColor` en minúsculas en una tabla con claves
  `lightGray`/`darkGray`, por lo que ambos salen negros. Rust usa el gris claro
  (192,192,192) y el oscuro (64,64,64) que ofrece la interfaz.
* **Máscara de ofuscación mal formada** (`obfuscationMask`): Java registra «se usará la
  por defecto» pero en realidad **no ofusca** nada. Rust aplica la máscara por
  defecto.
* **Capas heredadas** (`includeQuestionMark=true`): la capa `n4` (de altura cero, no se
  ve) se escribe vacía; Java escribe en ella, a tamaño microscópico, el programa del
  signo de interrogación como texto (fallo de `layer4Text`). El resto (n0–n3 y el
  signo de interrogación en `n1`) es igual.
* **Giros no múltiplos de 90º**: la plantilla girada se centra en el campo (Java usa la
  composición de imágenes de iText, solo probada con 90/180/270, que coinciden).
* **Fechas** (`$$SIGNDATE=…$$`, Q11): se formatean como `SimpleDateFormat` con la
  configuración regional **es_ES** (la de los usuarios de AutoFirma; Java usa la de la
  JVM) y la zona horaria del sistema. Los nombres cortos de zona (`z`) se resuelven con
  una tabla para las zonas españolas y europeas más habituales (`CET`/`CEST`,
  `WET`/`WEST`…); para otras zonas se usa `GMT±hh:mm`.
* **PDF/A: fuentes incrustadas** (§8.5, §9.5). Java incrusta GNU FreeFont completa
  (TrueType, `Identity-H`) solo en los PDF/A-1 y usa fuentes estándar sin incrustar en
  PDF/A-2/3 (resultado no conforme: `6.2.11.4.1`). Rust, en **cualquier** PDF/A
  (parte detectada en `pdfaid:part` del XMP), dibuja el texto de la firma visible con
  las fuentes **Liberation 2.1.5** (SIL OFL 1.1, `crates/afirma-pdf/fonts/`), que son
  métricamente compatibles con las estándar: Liberation Sans ↔ Helvetica, Liberation
  Serif ↔ Times, Liberation Mono ↔ Courier. FreeFont no se puede distribuir (GPLv3).
  * Se incrusta un **subconjunto** con los glifos usados (etiqueta `XXXXXX+` determinista)
    como fuente compuesta `Type0`/`CIDFontType2`, `Identity-H`, `CIDToGIDMap /Identity`,
    `/W` con los anchos de la fuente, `CIDSet` completo y `ToUnicode` (unos 10 KB por
    firma; Java incrustaba la fuente entera, unos 300 KB).
  * Negrita y cursiva usan la variante real de la fuente (`-Bold`, `-Italic`,
    `-BoldItalic`) en lugar de simularse (Java simula sobre FreeFont normal). Subrayado
    y tachado se dibujan igual.
  * Maquetación: los anchos de las Liberation coinciden con los AFM en todo WinAnsi salvo
    `¯ ± µ · ÷` en Sans y Serif; por eso, con fuente incrustada se maqueta con los
    anchos de la propia fuente (los mismos de `/W`), de modo que el texto nunca se sale.
  * Con fuente incrustada se pueden escribir caracteres fuera de WinAnsi que tenga la
    fuente (p. ej. cirílico o griego), como hacía Java con FreeFont; en los documentos
    no PDF/A siguen descartándose.
  * Fuera de PDF/A la salida no cambia (fuentes Type 1 estándar sin incrustar, como
    Java); comprobado byte a byte.
* **PDF/A: transparencias y color**. En PDF/A-1 las imágenes (rúbrica y marca) se
  componen sobre blanco sin `/SMask` (como Java, PDF/A-1 no admite transparencias); en
  PDF/A-2/3 se conserva el canal alfa. Si el PDF/A no tiene un perfil de salida RGB
  (`/OutputIntents` sin `DestOutputProfile` de 3 componentes), los recursos de la
  apariencia (y de la página, para la marca) declaran `/DefaultRGB` y `/DefaultGray`
  como `ICCBased` con los perfiles sRGB/gris v2 de «Compact ICC Profiles» (CC0,
  `crates/afirma-pdf/icc/`); Java usaba DeviceRGB/DeviceGray sin más (no conforme:
  `6.2.4.3`).
* Comprobado con veraPDF 1.30.3: las firmas visibles sobre los PDF/A de prueba (1a, 1b,
  2b, 3b; texto por defecto, estilos, cirílico, giro, rúbrica con transparencia, marca,
  varias páginas, cofirma) pasan; antes fallaban por la fuente sin incrustar (y, sin
  perfil de salida RGB, por el color).

## 7. XMP (§5.10, Q15)

* Se actualiza `xmp:ModifyDate` (o se añade) y `xmp:MetadataDate` en la propia
  revisión de la firma (Java reescribe el documento con iText).
* El historial de firma de PDF/A se añade mediante edición de texto del XMP. No se
  replica el reemplazo global de fechas de Java (que podía cambiar `stEvt:when` por la
  fecha de creación). En PDF/A donde el parser DOM de Java falla («prefix rdf … not
  bound», p. ej. `PDF-A1B.pdf`) Java no añade historial; Rust sí.

## 8. Detección y árbol de firmantes (§1.3, §1.4, Q13, Q14, Q23)

* Orden de las firmas: de la más reciente a la más antigua por revisión (Java: orden de
  un `HashMap`, que coincide en el caso habitual `Signature1..9`). La validación de
  Java depende de ese orden («la primera es la más reciente»); con nombres como
  `Signature10` + `Signature1` Java compara las revisiones equivocadas (p. ej. al
  firmar `RFE023 - Formulario_prueba_PDF_mod.pdf` Java informa `MODIFIED_DOCUMENT` en
  lugar de `MODIFIED_FORM`). Rust usa siempre el orden real de revisiones.
* `isSign` usa el parámetro `allowCosigningUnregisteredSignatures` de los
  `extraParams` (Java consulta las propiedades del sistema).
* `configureRespectfulProperties` nunca copia `ETSI.RFC3161` de un sello de documento.
* Las firmas `adbe.x509.rsa_sha1` se leen (certificados de `/Cert`, PKCS#1 en
  `/Contents`), como iText.

## 9. Contraseñas (§9.4, §12.7)

* Las peticiones de contraseña (`pdfpasswordprotected`, `pdfbadpassword`) indican el
  parámetro `ownerPassword`, que es donde Java guarda la contraseña introducida
  (`configure()`), aunque `BadPdfPasswordException.getParam()` devuelva
  `userPassword`. Como `ownerPassword` tiene prioridad sobre `userPassword`, el
  reintento funciona igual.
* Se distingue la contraseña de propietario de la de usuario como iText: con solo la
  de usuario (o sin contraseña cuando la de usuario es vacía) no se puede firmar
  (212005/212004).

## 10. Validación (§10, `ValidatePdfSignature`)

* Una firma cuyo CMS no se puede leer da `KO CORRUPTED_SIGN` para esa firma; Java
  aborta toda la validación con la excepción (p. ej. `CONVENIO_firmado_CF.pdf`:
  `EOFException`).
* Comprobación adicional: el `/ByteRange` debe empezar en 0 y su hueco debe ser
  exactamente la cadena hexadecimal de `/Contents` (defensa frente a «universal
  signature forgery»); si no, `KO CORRUPTED_SIGN`.
* Los sellos de documento se verifican (huella del rango y firma del sello); Java no
  los verifica.
* **Firmas solapadas** (Q16): Java solo marca una anotación si se solapa con *todas*
  las siguientes y se salta elementos. Rust comprueba cada par de widgets de la página
  en el que al menos uno es un campo de firma y cuya intersección tiene área positiva.
* **PDF Shadow Attack**: misma comparación píxel a píxel a 40 ppp en grises, pero con
  el rasterizador `hayro` (Java usa PDFBox). Como las dos imágenes se generan con el
  mismo motor, el criterio es equivalente. Sin la característica `render` la
  comprobación visual se omite (sí se comprueba el solape).
* Comparación de formularios: los valores `/V` indirectos se comparan por contenido
  (Java compara la referencia `N G R` como texto, sin ver cambios dentro del objeto).
* Entradas libres de la tabla de referencias: un objeto liberado en una actualización
  deja de existir (como en iText; `lopdf` las ignoraba, lo que ocultaba el ataque de
  `RFE023 - shadow form.pdf`).
* PDF cifrados: el perfil PAdES se detecta sobre el documento descifrado (Java abre
  sin contraseña y devuelve «No reconocido»).
* El reordenado final (`checkLongStandingValiditySign`) se implementa localmente con
  la semántica exacta de Java (intercambia el primer elemento con el **último** aviso
  de perfil no comprobado); `afirma_core::validity::long_standing_priority` mueve el
  primero y da otro orden cuando hay varias firmas.

## 11. Firma trifásica (§11)

* La prefirma es determinista (mismos datos y parámetros ⇒ mismos bytes), por lo que
  `triphase::postsign` puede regenerar la revisión sin estado y comprueba que coincide
  con `PID`/`PRE`. Excepción: en PDF cifrados con AES el vector de inicialización es
  aleatorio; en ese caso hay que conservar el `PadesPreSign` de la prefirma
  (`PadesSigner::postsign`), como también le ocurre a Java.

## 12. Ayudas para la interfaz (§12.4, Q12, Q17)

* `info::PageLabel` reproduce el escalado del panel de selección de área (contenedor
  466×400, factor 0,9, `pdfRatio`), pero `to_pdf_area` usa el tamaño de la página
  **actual** (Java usa el de la anterior en páginas > 1) y trabaja en puntos.
* `info::visible_area_params` pide `signaturePages=append` cuando la página actual es
  la página en blanco añadida (Java envía `N,append`, que el firmante ignora porque
  `append` solo cuenta como primer elemento, de modo que la firma acababa en la última
  página sin añadir ninguna).
* `render::preview_appearance_for(.., pdfa)` (y `preview_appearance`, sin PDF/A)
  genera una vista previa **exacta** de la apariencia
  (la misma que se escribirá en el PDF); la vista previa de Java es aproximada (AWT,
  sin sustituir etiquetas y con los colores gris claro/gris intercambiados).

## Pruebas

* `cargo test -p afirma-pdf`: firma, cofirma (también sobre firmas de Java), campos,
  marcas, certificación, cifrado RC4-40/RC4-128/AES-128/AES-256, tablas y flujos de
  referencias, ficheros con basura final y tablas dañadas, sellos (TSA local),
  trifásica, renderizado, ataques de sombra y paridad de validación con Java.
* Diferencial con Java (scripts en el informe; oráculo `tools/oracle/PdfOracle.java`):
  firma de los 52 PDF de prueba con ambos (mismos errores/peticiones en los casos no
  firmables), validación cruzada (pdfsig, pyHanko y `ValidatePdfSignature` dan por
  válidas las firmas de Rust, también tras cofirmar Java sobre Rust y Rust sobre Java)
  y comparación de la apariencia renderizada con `pdftoppm`.
* `tools/oracle/gen_pades_fixtures.py` regenera los PDF de `testdata/pades`.
