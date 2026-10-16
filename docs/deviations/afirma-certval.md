# Desviaciones de `afirma-certval` respecto a la versión Java

Crate: `crates/afirma-certval` (plugin «Validación de certificados»,
`afirma-simple-plugin-validatecerts`, especificación
`docs/spec/06-app-ui-cli-installer.md` §7.6).

Se conservan los resultados (`ValidationResult`, códigos 0..11 y nombres), sus textos
(`certvalidationmessages.properties`, también sin decodificar en `java_description()` y
`to_json_string()`), los textos de la interfaz (`messages.properties`, `plugin.json`, con la
errata "No esá definido..."), el periodo de validez exacto, la comprobación del emisor
configurado (`CA_NOT_SUPPORTED`), la correspondencia de los estados OCSP y el algoritmo de
las CRL. Lo comprueban las pruebas `tests/java_oracle.rs` con los resultados de la versión
Java guardados en `testdata/certval/java-*.txt` (`tools/oracle/certval_oracle.sh`,
`tools/oracle/CertValOracle.java`): textos y JSON, identificadores CRC de la factoría,
petición OCSP (idéntica byte a byte a la de BouncyCastle y a la de OpenSSL), análisis de
respuestas, CRL con y sin clave del emisor y validación sin red (tabla de Java).

## Selección del mecanismo

1. **OCSP si el certificado lo declara (modo `Auto`, por defecto).** Java usa OCSP solo
   para los emisores de su tabla (`validationfactory.properties`) y CRL para todos los
   demás, aunque declaren OCSP. Nosotros usamos el servicio OCSP de la AIA (solo entradas
   `id-ad-ocsp` con `http`/`https`; Java toma todas las URI, incluidas las `caIssuers`, y se
   queda con la primera o la última que contenga "ocsp") siempre que se conozca el emisor,
   y si no da una respuesta definitiva (válido o revocado: error de red o del servicio,
   respuesta no válida, estado `unknown`...) se consultan las CRL (`crl_fallback`). Si las
   CRL tampoco son concluyentes se devuelve el resultado de OCSP.
2. **Modo `SelectionMode::JavaFactory`.** Reproduce la factoría de Java: identificador
   CRC32 del emisor (misma fórmula), tabla de 10 entradas, `getBestResponder`, OCSP sin
   AIA → "No se dispone de ningún mecanismo de validación..." (`report.no_mechanism`,
   antes de comprobar el periodo de validez, como Java), CA de la tabla como emisor
   configurado (`CA_NOT_SUPPORTED` si no emitió el certificado) y sin alternativa CRL. Las
   comprobaciones de seguridad de esta lista se siguen aplicando.
3. **Certificados de CA incluidos.** Solo se conservan los que siguen en vigor:
   `AC_CAMERFIRMA` (convertido de PEM a DER), `AC_CAMERFIRMA_CAMERALES` y
   `AC_Componentes_Informaticos_SHA256` (FNMT). Los de las AC del DNIe 001-003 (caducados
   en 2021) y RACER (2023) no se incluyen: todo certificado emitido por ellos está caducado
   y se rechaza (`EXPIRED`) antes de usarlos. En modo `Auto` los tres sirven además como
   candidatos a emisor.
4. **Emisor.** Java solo conoce el emisor de su tabla (sin él calcula el `CertID` OCSP con
   el propio certificado y no verifica las CRL). Nosotros lo buscamos en
   `ValidationOptions::issuer` (comprobado como en Java: `CA_NOT_SUPPORTED` si no lo
   emitió), en la cadena (`chain`), entre las CA incluidas y, como mejora, descargándolo de
   la AIA `caIssuers` (DER, PEM o PKCS#7 `certs-only`). Un candidato solo se acepta si su
   titular coincide con el emisor y su clave verifica la firma del certificado. La
   comparación de nombres no distingue mayúsculas ni espacios repetidos (Java compara
   `X500Principal.toString()`).

## Seguridad (Java no hace estas comprobaciones)

5. **Firma de la respuesta OCSP.** Debe firmarla el emisor del certificado o un
   respondedor delegado identificado por el `responderID` (por nombre o por huella de la
   clave) que haya emitido ese emisor, tenga `id-kp-OCSPSigning` y esté en vigor
   (RFC 6960 §4.2.2.2). El certificado del respondedor se busca en la respuesta y, si no
   viene, en `chain`. Si no se cumple → `SERVER_ERROR` (Java devolvía el estado de una
   respuesta firmada por cualquiera).
6. **`CertID`.** Se busca la respuesta individual que corresponde al certificado
   consultado (recalculando el `CertID` si el servicio usa otra huella); Java tomaba la
   primera sin mirarla. Sin coincidencia → `SERVER_ERROR`.
7. **Vigencia de la respuesta OCSP.** `thisUpdate` no puede ser futuro y la respuesta no
   puede estar caducada (`nextUpdate`, o `thisUpdate` + 24 h si no lo tiene), con 5 minutos
   de margen de reloj (`clock_skew`, `ocsp_max_age_without_next_update`). Si no →
   `SERVER_ERROR`.
8. **CRL.** Se exige que el emisor de la CRL sea el del certificado, que no sea una CRL
   delta, que la firme la clave del emisor y que esté vigente (`thisUpdate` no futuro,
   `nextUpdate` no pasado, con el mismo margen). Java solo verificaba la firma si conocía
   la clave del emisor y aceptaba CRL caducadas (en `java-crl.txt`, `ca_stale.crl` da
   `VALID`/`REVOKED` en Java y `SERVER_ERROR` aquí).
9. **Sin emisor no hay validación de revocación.** Con
   `require_verified_revocation = true` (por defecto), si no se encuentra el emisor no se
   aceptan respuestas OCSP ni CRL sin verificar y el resultado es `UNKNOWN`. Con `false` se
   comporta como Java (respuestas y CRL sin verificar).
10. **Sin nonce.** Como Java, la petición OCSP no lleva nonce (muchos servicios con
    respuestas precalculadas no lo admiten); la frescura se controla con el punto 7.
11. **Ficheros `file:` solo locales.** Se rechazan las URL `file://servidor/...` (rutas UNC
    que en Windows abrirían una conexión SMB a un servidor elegido por el certificado).
12. **Sin diálogos de confianza.** Las descargas no muestran el diálogo "¿confiar en este
    servidor?" (Java descargaba las CRL con `DataDownloader`, que puede mostrarlo).

## Transporte

13. **OCSP por GET con el cliente por defecto.** `afirma_core::http::HttpClient` no admite
    cuerpos binarios (el cuerpo de un POST es la consulta de la URL), así que
    `AfirmaHttpFetcher` (que usa `installed_http_client()` para aplicar el proxy y la
    configuración TLS del usuario) envía la petición por GET (RFC 6960, apéndice A.1:
    `<url>/<Base64 con %2B %2F %3D>`), con `Accept: application/ocsp-response`. Con un
    `HttpFetcher` que implemente `post` se usa POST como Java (`Content-Type:
    application/ocsp-request`), con el mismo cuerpo byte a byte; `OcspHttpMethod` permite
    forzar uno u otro. Probado con FNMT, ACCV, Sectigo y DigiCert. *Pendiente:* si
    `afirma-core` añade cuerpos binarios a `HttpRequest`, `AfirmaHttpFetcher::post` puede
    implementarse y se usará POST por defecto.
14. **Tiempos de espera.** Java no fijaba ninguno; aquí 15 s de conexión y 60 s de lectura
    por descarga (`connect_timeout`, `read_timeout`).
15. **Orden de las CRL.** Se prueban primero los puntos de distribución HTTP(S) y de
    fichero y después los LDAP (que suelen estar bloqueados en redes corporativas) y se
    para en la primera CRL válida: Java descargaba y comprobaba **todas** (normalmente la
    misma CRL publicada por varios medios). Una CRL no válida (mal formada, mal firmada,
    caducada) no detiene la búsqueda como en Java; si ninguna sirve, el resultado es
    `SERVER_ERROR` si alguna no era válida, `CANNOT_DOWNLOAD_CRL` si alguna no se pudo
    descargar y `UNKNOWN` en otro caso (lo mismo que Java con un único punto).
16. **LDAP.** Cliente LDAP v3 propio y mínimo (`ldap` del crate): enlace anónimo, búsqueda
    `baseObject` con `(objectClass=*)` del atributo de la URL (por defecto
    `certificateRevocationList;binary`), DN con `%XX` decodificados. No admite `ldaps://`,
    referencias ni autenticación (JNDI sí). Las pruebas lo comprueban con un servidor
    local que a su vez se valida con `ldapsearch` de OpenLDAP.
17. **`ftp://`** no se admite (como el resto de AutoFirma-rs): cuenta como CRL no
    descargable.
18. **Algoritmos.** Se verifican RSA PKCS#1 v1.5 (SHA-1/2), RSASSA-PSS (MGF1 con la misma
    huella) y ECDSA P-256/P-384/P-521. DSA, Ed25519 y PSS con huellas distintas para el
    mensaje y MGF1 no se admiten (la verificación falla).

## Interfaz

- El informe (`ValidationReport`) añade el método usado, el detalle técnico, la fecha y
  motivo de revocación y el origen del emisor; `dialog_title()`, `dialog_message()` y
  `dialog_is_error()` reproducen los diálogos de Java (incluido el de "sin mecanismo").
- La validación es bloqueante: la interfaz debe ejecutarla en un hilo y, como Java, puede
  descartar el resultado si el usuario cierra el diálogo de espera.

## Pruebas

`tests/pki.rs` usa la PKI de `testdata/certval` (`gen.sh`, OpenSSL 3): servidor HTTP en
127.0.0.1, OpenSSL como respondedor OCSP en vivo (`openssl ocsp -reqin`, una ejecución por
petición, en lugar de `-port`, que escucha en todas las interfaces), CRL reales (RSA,
RSASSA-PSS y ECDSA P-384), LDAP, respuestas OCSP alteradas, de otro certificado, de
respondedores no autorizados o de otra CA, caducadas, sin `nextUpdate` y con todos los
estados de error. Ninguna prueba sale de 127.0.0.1. `examples/certval.rs` valida un
certificado real desde la línea de comandos.
