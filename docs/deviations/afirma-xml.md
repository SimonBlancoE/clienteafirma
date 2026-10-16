# Desviaciones de `afirma-xml` respecto a AutoFirma Java

`afirma-xml` implementa los firmadores XAdES (`AOXAdESSigner`), XMLDSig (`AOXMLDSigSigner`),
FacturaE (`AOFacturaESigner`), XAdES-ASiC-S (`AOXAdESASiCSSigner`), ODF (`AOODFSigner`) y
OOXML (`AOOOXMLSigner`), el sellado XAdES-T (`XAdESTspUtil`) y la validación de firmas XML
(`ValidateXMLSignature`). Las referencias de sección son de `docs/spec/03-xml-signatures.md`.

Por defecto el comportamiento es el de Java, **incluidos sus fallos** cuando cambiarlos afectaría
a la interoperabilidad (p. ej. el hash del `CertDigest`, el orden de la política en baseline, los
índices `0..=N` de los `CommitmentTypeIndication`, el formato de `SigningTime`, el reloj de 12 horas
con `Z` literal de `mdssi:Value`, el `getData` de XMLDSig que solo elimina las firmas 0, 2, 4...
de un documento enveloped, la reutilización de las transformadas de datos en la referencia al
`KeyInfo` de XMLDSig o el error de `isXAdESLTLevel`). Este documento recoge solo las diferencias
deliberadas.

## Cómo se ha contrastado

* **Oráculo Java** (`tools/oracle/XmlOracle.java`, que llama a los firmadores Java por clase, y
  `tools/oracle/xml_differential.py`): 68 casos (XAdES 39 incluido XAdES-T con la TSA de pruebas,
  FacturaE 2, ASiC-S 3, XMLDSig 16, ODF 4, OOXML 4), todos con estructura idéntica. Cada caso se firma en Rust y en Java con la misma clave y parámetros y se compara
  la **estructura** (`tools/oracle/xmlstruct.py`: nombres, espacios de nombres, atributos,
  transformadas y algoritmos; se normalizan UUID, huellas, valores de firma, certificados, fechas
  y los datos de pantalla de OOXML). En las multifirmas cada implementación cofirma o contrafirma
  **la salida de la otra**. Las salidas Java quedan como *golden* en `testdata/xades/java/`,
  `testdata/xmldsig/java/` y `testdata/office/java/` y las pruebas `tests/xades_golden.rs` y
  `tests/formats_golden.rs` repiten la comparación sin Java.
* **Validador independiente**: JSR-105 del JDK (Apache Santuario) mediante
  `tools/oracle/XmlSigVerify.java`; todas las firmas Rust y Java validan salvo las que no pueden
  validar por diseño (referencias externas, primera firma de una cofirma enveloped sin XPath, URI
  relativas de ASiC que el validador genérico no resuelve).
* **LibreOffice 25.2** (`tools/oracle/lo_verify.py`, UNO `DocumentDigitalSignatures`): ODF y OOXML
  (docx, xlsx, pptx), firmas y cofirmas cruzadas Rust/Java; un documento manipulado da «no válida».
* **Veredictos de validación**: `ValidateXMLSignature` de Java y `validation::validate` dan la misma
  lista (`validez error`, en el mismo orden, con `checkCertificates`) para 116 de 117 documentos:
  todos los XML firmados y sin firmar de las pruebas Java (`afirma-crypto-xades`,
  `afirma-crypto-validation`, `afirma-crypto-xadestri-client`: XAdES-A/XL, sellos XML, FacturaE
  antiguas, IGAE...), todos los *golden* XAdES/XMLDSig/FacturaE y variantes con algoritmos de huella
  RIPEMD-160 y desconocidos.

## 1. Generación por inserción de texto (todas las firmas XML)

* **Java** analiza el documento, inserta nodos DOM y **reserializa todo el documento**: reordena
  atributos, elimina el salto de línea tras la declaración XML y, en Enveloped/Enveloping, pierde lo
  que está fuera del elemento raíz (comentarios, instrucciones de proceso como `<?xml-stylesheet?>`
  y DOCTYPE, §3.4.2).
* **Rust** construye el texto de `ds:Signature` y lo **inserta en el texto original** (`splice`),
  de modo que el documento del usuario se conserva byte a byte fuera de la firma. Las huellas se
  calculan sobre el resultado vuelto a analizar con el mismo motor que valida, así que la firma es
  equivalente para cualquier validador (C14N). La declaración XML original se conserva cuando ya
  indica la codificación de salida; si no, se sustituye por la de Java.
* Las cofirmas y contrafirmas también se insertan en el texto de la firma recibida (las firmas
  anteriores no se reserializan y no se invalidan por cambios de forma).

## 2. XAdES / XMLDSig

### 2.1 Formatos y modos sin distinguir mayúsculas
* **Java** valida `format` y `mode` sin distinguir mayúsculas pero luego compara con `equals`:
  `format=xades enveloping` produce una firma sin datos y un modo en minúsculas no reconocido se
  trata como explícito (§6, *quirk* 1).
* **Rust** normaliza al nombre canónico y firma en el formato pedido.

### 2.2 Algoritmo compuesto con el tipo de clave
* **Java** usa el nombre de algoritmo tal cual: `SHA256withRSA` con una clave EC falla en la firma.
* **Rust** compone el algoritmo con el tipo de clave (`composeSignatureAlgorithmName`) cuando el
  nombre no corresponde a la clave o es solo una huella (`SHA256`). Las claves DSA se rechazan con
  `UNSUPPORTED_SIGNATURE_ALGORITHM`.

### 2.3 `RootXmlNodeNamespace` sin prefijo declarado
* **Java** crea el elemento raíz sin declarar su espacio de nombres si no se indica
  `RootXmlNodeNamespacePrefix`, y la salida no es XML con espacios de nombres válido cuando el
  nombre lleva prefijo.
* **Rust** declara el espacio de nombres (con el prefijo del nombre o como espacio por defecto).

### 2.4 `checkCompatibility` con firmas indentadas
* **Java** recorre los nodos hijo en bruto: con firmas indentadas el «segundo hijo» de
  `SignedSignatureProperties` es un texto y la detección baseline falla.
* **Rust** cuenta solo hijos elemento.

### 2.5 Sin acceso a la red durante la firma
* **Política sin huella**: jxades descargaría el documento `policyIdentifier` para calcular su SHA-1.
  Rust no descarga: se omite la política con un aviso (es lo que hace Java cuando la descarga falla).
  Los presets `expPolicy` (`FirmaAGE`, `FirmaAGE18`) siempre llevan huella y no se ven afectados.
* **Externally Detached con URI http(s)**: Java descarga los datos con `CustomUriDereferencer`.
  Rust los pide al `Resolver` configurado (`XadesSigner::with_resolver`); sin él se devuelve
  `DERREFERENCING_DATA_ERROR`. El caso habitual (huella precalculada o `URI=""`) no cambia.
* **Hojas de estilo**: Java solo las incrusta cuando `headless=false` y el usuario elige un fichero;
  en modo sin interfaz (el de AutoFirma) nunca se firman. Rust no las procesa (mismo resultado) y,
  por §1, la instrucción `<?xml-stylesheet?>` del documento se conserva en las firmas Enveloped.

### 2.6 Algoritmos de huella
Se admiten SHA-1, SHA-224, SHA-256, SHA-384 y SHA-512 (los de AutoFirma) y, al validar, también
SHA3-224/256/384/512 en las referencias, como Java (el JDK los incluye). RIPEMD-160 y Whirlpool,
que Santuario reconoce pero no implementa, dan `KO BAD_BUILD_SIGN`, igual que en Java.

## 3. XAdES-T

Igual que Java: el sello se pide sobre la C14N exclusiva del primer `ds:SignatureValue`, se inserta
el fragmento `UnsignedProperties` literal de Java en el primer `QualifyingProperties` 1.3.2 y un fallo
de conexión con la TSA es un error (`TSA_CONNECTION_ERROR`); unos parámetros TSA incompletos dejan la
firma sin sello. El cliente RFC 3161 es el de `afirma-cms` (`tsp`).

## 4. XAdES-ASiC-S

* **`mimetype` sin comprimir**: Java comprime la primera entrada `mimetype`; ETSI EN 319 162-1 exige
  que se almacene (`STORED`) para que el tipo pueda leerse sin descomprimir. Rust la almacena sin
  comprimir; el contenido y el orden de entradas son los de Java.
* El contenedor se lee con un lector ZIP propio (directorio central): los ZIP de Java usan
  *data descriptors* y `afirma_core::asic` falla con ellos («file length not available in local
  header»). Pendiente de corregir en `afirma-core`.
* `asic::validate_container` valida la firma resolviendo la referencia relativa a los datos del
  contenedor (Java no tiene validador ASiC; extensión).

## 5. ODF

* **Algoritmo de firma**: Java usa siempre `rsa-sha1` aunque se pida otro algoritmo (y falla con
  claves EC). Se ha comprobado con LibreOffice 25.2 que valida las firmas `rsa-sha256` y
  `ecdsa-sha256` generadas por Rust (`.odt`, `.ods`, `.odp`, cofirmas cruzadas con Java), así que
  `OdfSigner::new()` (y `signer_for("odf")`) usa **el algoritmo pedido**. El comportamiento exacto
  de Java está disponible con `OdfSigner::java_parity()` / `signer_for("odf-java")`, que es el que se
  compara estructuralmente con el oráculo.
* **`mimetype` sin comprimir y primera entrada**: lo exige ODF 1.2 (Part 3, §3.3); Java la
  recomprime.
* `odf::verify_package` valida criptográficamente las firmas del paquete (Java no valida ODF;
  extensión usada en las pruebas). Un `content.xml` manipulado da firma no válida.

## 6. OOXML

* **Partes de `ppt/`**: Java solo firma las partes bajo `word`, `excel`, `xl` y `powerpoint`, de modo
  que en una presentación solo se firman las relaciones. Rust añade `ppt` y, como Office, **no firma
  las partes destino de relaciones excluidas** (`presProps`, `viewProps`, propiedades del documento,
  miniatura). LibreOffice valida las presentaciones firmadas y cofirmadas (también cofirmas Java de
  presentaciones Rust). Para `docx`/`xlsx` la estructura es idéntica a la de Java.
* **`RelationshipsParser` tolera espacios en blanco**: Java rechaza los `.rels` con nodos de texto
  (paquetes indentados no se detectan como OOXML); Rust los ignora.
* **Firma sin entorno gráfico**: Java obtiene monitores, resolución y profundidad de color de AWT y
  lanza `HeadlessException` sin pantalla. Rust usa `ScreenInfo` (por defecto 1 monitor, 1920×1080,
  32 bits; configurable por la GUI con `OoxmlSigner { screen }`). `WindowsVersion` se escribe como
  `10.0` en Windows (Java usa `os.version`).
* `ooxml::verify_package` valida firmas OOXML (incluidas las referencias del `Manifest`) y devuelve
  las URI que no coinciden (Java no valida OOXML; extensión). Valida también la firma de Word 2016
  del repositorio (`entrada_w2016_SIGNED.docx`).
* **Nota de interoperabilidad (no es desviación)**: LibreOffice 25.2 no elimina los espacios en
  blanco entre elementos `Relationship` al aplicar `RelationshipTransform` (ECMA-376 Part 2,
  §13.2.4.24, exige eliminarlos). Por eso informa como no válidas las firmas Java **y** Rust de
  paquetes cuyos `.rels` están indentados (p. ej. los generados por LibreOffice,
  `testdata/office/inputs/in-ws.pptx`); con `.rels` sin espacios (Office) las valida. Se mantiene
  el algoritmo de la norma, que es el de Java y el de Office.

## 7. Validación (`validation::validate`)

Mismos veredictos y orden que `ValidateXMLSignature`, reproduciendo las fases de JSR-105: análisis
(algoritmo o transformada no reconocidos -> `UNKNOWN UNKOWN_ERROR`), valor de firma y después
referencias (`KO NO_MATCH_DATA` una vez por documento más uno por referencia incorrecta; un error al
calcular una huella -> `KO BAD_BUILD_SIGN` y se detiene), el intercambio de
`checkLongStandingValiditySign` con el **último** `SIGN_PROFILE_NOT_CHECKED` y el
`UNKNOWN UNKOWN_ERROR` de una `Reference` sin `URI` (en Java, un `NullPointerException`).
Diferencias:

* Las referencias http(s) no se descargan: se resuelven con el `Resolver` indicado o fallan
  (`KO BAD_BUILD_SIGN`, como Java sin red).
* Los certificados se comprueban con la hora actual del sistema, igual que Java; no hay validación de
  cadena ni de revocación (tampoco en Java).
