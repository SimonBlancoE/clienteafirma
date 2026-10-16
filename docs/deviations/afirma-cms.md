# Desviaciones de `afirma-cms` respecto a AutoFirma Java

Este documento recoge las diferencias deliberadas entre `afirma-cms` (CMS/PKCS#7,
CAdES, CAdES-ASiC-S, sellos de tiempo y validación binaria) y la versión Java
(commit `0d7f3cf01`). En todo lo demás la salida es estructuralmente idéntica a la
de Java: las pruebas `tests/differential.rs` comparan 64 casos con las firmas
*golden* generadas por la AutoFirma Java (`testdata/cades/*.java.*`); con claves RSA
y el mismo instante de firma, 49 de ellas son idénticas byte a byte.

Referencias de fallos (Gn) según `docs/spec/02-cms-cades.md` §14.2.

## 1. CAdES-T: el sello de tiempo funciona (G1)

* **Java**: `AOCAdESSigner.applyTimeStamp` busca por reflexión `getTsaHashAlgorithm`
  en `CMSTimestamper` (está en `TsaParams`) y `addTimestamp(byte[], String,
  GregorianCalendar)` (la firma real recibe `Calendar`). Ambas búsquedas fallan, la
  excepción se registra y se devuelve la firma sin sellar: **ningún parámetro `tsa*`
  tiene efecto** y nunca se genera CAdES-T.
* **Rust**: si los `extraParams` incluyen `tsaURL`, `CadesSigner::sign` (y por tanto
  `CAdES-ASiC-S`) pide un sello RFC 3161 sobre el valor de firma de cada firmante de
  primer nivel con todos los parámetros `tsa*` (`tsaPolicy`, `tsaHashAlgorithm`
  —SHA-512 por defecto—, `tsaRequireCert`, `tsaUsr`/`tsaPwd`, `tsaSslKeyStore*`,
  `tsaSslTrustStore*`, `tsaExtension*`, `verifyHostname`) y añade el atributo no
  firmado `signatureTimeStampToken` (CAdES-T / CAdES T-Level).
* Diferencias con lo que habría hecho Java de funcionar:
  * Se **añade** el atributo a los no firmados existentes (Java los reemplazaba,
    perdiendo contrafirmas).
  * La salida es **DER** (Java habría producido BER con longitudes indefinidas en
    `ContentInfo`/`SignedData`). Las firmas BER de Java se leen sin problema.
  * Si la TSA falla, la firma **falla** (`410001` sin conexión, `211003` respuesta no
    válida) en lugar de devolver la firma sin sello en silencio.
  * Como en Java, la cofirma y la contrafirma no sellan.
* Interoperabilidad comprobada: la AutoFirma Java valida, lee el árbol y extrae los
  datos de las firmas CAdES-T de Rust (perfil `CAdES T-Level` →
  `UNKNOWN SIGN_PROFILE_NOT_CHECKED`, igual que con sus propias firmas T), y el
  cliente TSP de Java (Bouncy Castle) acepta las respuestas de la TSA de pruebas.

## 2. Cliente RFC 3161

* **Nonce**: Java usa la hora en milisegundos; Rust usa un entero aleatorio de 63
  bits (sin efecto en la interoperabilidad, mejor protección frente a repeticiones).
* **Verificación de la respuesta**: además de las comprobaciones de Bouncy Castle
  (estado, nonce, huella, algoritmo, política, atributo de certificado de firma,
  un único firmante, tipo `id-ct-TSTInfo`, `failInfo`), si el sello incluye el
  certificado de la TSA se verifica criptográficamente su firma; una firma
  incorrecta se rechaza (`211003`). Si el algoritmo no se puede verificar solo se
  avisa.
* **HTTPS**: Java confía en **cualquier** certificado de servidor si no se indica
  `tsaSslTrustStore` (G29). Rust usa el almacén de confianza del sistema
  (`rustls-platform-verifier`, incluye CA corporativas) y, si se indica
  `tsaSslTrustStore` (PKCS#12 en Base64), solo esos certificados. `verifyHostname=false`
  desactiva la verificación del servidor (rustls no permite desactivar solo el nombre).
  Solo se admiten almacenes de tipo `PKCS12` para `tsaSslKeyStore`/`tsaSslTrustStore`
  (Java admite también JKS).
* Tiempo máximo de 120 s para HTTP(S) (Java no fija ninguno); 500 s para `socket://`
  como Java.

## 3. CAdES-ASiC-S (G2, G3, G4, G23)

* **Detección**: `isSign` de Java siempre devuelve `false` (vuelve a leer la firma
  interna como ZIP). Rust devuelve `true` si el ZIP contiene `META-INF/signature.p7s`
  y es una firma CAdES. Ningún otro formato reclama esos ZIP, así que el orden de
  detección no cambia para el resto.
* **Cofirma/contrafirma**: Java llama a `createSContainer` con los nombres
  intercambiados (los datos acaban en `META-INF/signature.p7s` y la firma con el
  nombre de los datos), dejando un contenedor inservible. Rust conserva los nombres.
* **`mimetype`**: Java lo guarda comprimido (DEFLATED), contra ETSI EN 319 162-1.
  Rust lo guarda **sin comprimir**, primero y sin campo extra; las demás entradas
  van comprimidas y se mantiene el comentario `mimetype=application/vnd.etsi.asic-s+zip`.
  Java lee sin problemas los contenedores de Rust (árbol, datos, validación).
* **Parámetros**: Java modifica los `extraParams` del llamante (`mode=explicit`);
  Rust trabaja sobre una copia. En la cofirma Rust fuerza también `mode=explicit`
  (Java permitía incrustar los datos en la firma interna con `mode=implicit`).
* **Datos**: con varias entradas de datos Java toma la "primera" de un `HashMap`
  (orden de hash); Rust toma la primera en el orden del ZIP (igual con una sola).

## 4. Cofirmas: `digestAlgorithms` incluye la huella del nuevo firmante (G6)

* **Java** nunca añade el algoritmo de huella del cofirmante al SET
  `digestAlgorithms`. OpenSSL (y otros verificadores) rechazan entonces las cofirmas
  con una huella distinta de la original (`no matching digest`).
* **Rust** lo añade si no estaba (CAdES y CMS, con y sin datos). El campo no está
  firmado, así que no afecta a ninguna firma. En las contrafirmas no se cambia (las
  contrafirmas resumen el valor de firma, no el contenido).

## 5. Recodificación DER de las firmas existentes (G22, §4.6.3)

Java vuelve a codificar en DER toda la estructura al cofirmar o contrafirmar, lo
que reordena los SET que no estuvieran ordenados. Rust:

* Convierte las longitudes indefinidas en definidas y los OCTET STRING construidos
  (BER) en primitivos, como Java (la salida es siempre DER).
* Reordena los SET que reconstruye: `certificates`, `digestAlgorithms`, `crls`,
  `signerInfos`, los atributos no firmados de los nodos contrafirmados y los valores
  de `counterSignature`.
* **No** reordena los SET internos de los SignerInfo existentes que no modifica
  (atributos firmados y no firmados, valores de atributos) ni recodifica los
  certificados: se copian byte a byte. Así se preservan las firmas de terceros cuyos
  atributos no estuvieran en orden DER y los sellos de archivo (CAdES-A), cuyo
  cálculo depende del orden de los atributos no firmados. Con firmas de AutoFirma el
  resultado es idéntico; con los ficheros de prueba de Java solo difiere el orden de
  los atributos no firmados de firmas CAdES-A cuando se cofirman con
  `allowSignLTSignature=true`.
* El `encapContentInfo` con contenido BER construido se acepta en la cofirma sin
  datos y en `getData` (Java lanza `ClassCastException`, G14).
* Si la firma no tiene `certificates`, la cofirma/contrafirma lo crea (Java lanza
  `NullPointerException`).

## 6. Algoritmo de firma y tipo de clave (G27)

El contrato de `afirma_core::Signer` es componer el algoritmo recibido con el tipo
de la clave (`compose_signature_algorithm`). Por ello `SHA256withRSA` con una clave
EC firma con `SHA256withECDSA` y el `signatureAlgorithm` es coherente con el valor
de firma. Java (CMS y la firma CAdES) usaría el nombre tal cual: escribiría
`rsaEncryption` junto a una firma ECDSA (CAdES) o fallaría al inicializar la firma
(`200110`, CMS). Con nombres ya compuestos (lo que hacen la aplicación y el
protocolo de Java) el resultado es idéntico.

## 7. Firma CMS

* `AOCMSSigner` firma con `Signature.getInstance` sin la autoverificación de
  `AOPkcs1Signer`; Rust tampoco la hace en CMS (sí en CAdES, como Java).
* Los atributos personalizados (`addSignedAttribute`/`addUnsignedAttribute`) no
  existen en la interfaz `Signer`, como no son accesibles desde `extraParams` en Java.
* Contrafirma `NODES` con una lista vacía devuelve la firma de entrada recodificada
  (como Java); el valor `null` de `CounterSignTarget` no existe en Rust.

## 8. Árbol de firmantes

`getSignersStructure(sign, asSimpleSignInfo=true)` de Java devuelve `null` si falta
el certificado de algún firmante; la interfaz Rust tiene un único árbol con
`SimpleSignInfo` y en ese caso el nodo tiene la lista de certificados vacía (nombre
vacío, como con `asSimpleSignInfo=false`). Un SignerInfo con identificador por SKI
sigue haciendo fallar la lectura del árbol (G24).

## 9. Validación

Igual que Java (KO/UNKNOWN y su orden, contrafirmas no validadas, certificado por
número de serie, firma explícita sin datos sin verificar, G18). Diferencias menores:

* Si la verificación de los atributos firmados falla con su codificación original
  se reintenta con la codificación DER ordenada (Bouncy Castle siempre usa la
  ordenada); con firmas correctas no hay diferencia.
* DSA no se verifica (resultado `KO CANT_VALIDATE_CERT`).

## 10. Política de firma sin huella

Java descarga el documento de política cuando falta `policyIdentifierHash` (o vale
`0`) y lo resume, pero en CAdES el identificador ha de ser un OID, así que la firma
siempre acaba fallando. Rust devuelve directamente el error de argumento (mismo
mensaje que Java).

## 11. Detección del tipo de datos

`contentHints`, `mimeType` y el nombre por defecto de los datos ASiC usan el puerto
de JMimeMagic/`MimeHelper` de `afirma_core::mime` (mismos resultados que Java). Si el
análisis falla (datos de 1 GB o más) se usan los valores por defecto, como hace
`CAdESParameters` al capturar la excepción. El detector se puede sustituir con
`afirma_cms::mime::set_data_type_detector`.
