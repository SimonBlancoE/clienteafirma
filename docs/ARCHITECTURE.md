# Arquitectura de AutoFirma-rs

AutoFirma-rs es un fork de [clienteafirma](https://github.com/ctt-gob-es/clienteafirma)
que reimplementa AutoFirma en Rust. El código Java original se conserva intacto en
los directorios `afirma-*` (remoto `upstream`) como referencia y como **oráculo de
pruebas**: las firmas generadas en Rust se comparan y se validan contra la versión
Java.

## Principios

1. **Paridad 1:1 con AutoFirma**: mismos formatos, parámetros (`extraParams`),
   protocolo `afirma://`, códigos de error y comportamiento observable. La
   especificación extraída del código Java está en [`docs/spec/`](spec/).
2. **Portabilidad**: un único ejecutable por plataforma, sin JRE ni dependencias
   externas obligatorias. Las bibliotecas del sistema (PKCS#11, NSS, CNG,
   Security.framework) se cargan dinámicamente cuando se necesitan.
3. **Seguridad**: Rust sin `unsafe` fuera de los puntos de FFI con el sistema;
   sin XXE ni expansión ilimitada de entidades; TLS con `rustls`; criptografía
   de `ring`/RustCrypto; nunca se modifican los bytes de firmas existentes al
   cofirmar o contrafirmar.
4. **Entornos corporativos**: verificación TLS con el almacén del sistema
   (incluidas las CA corporativas), proxy del sistema, preferencias bloqueables
   por directiva (GPO/registro, perfiles de configuración de macOS, `/etc`),
   instaladores silenciosos y sin avisos.

## Crates

| Crate | Responsabilidad | Equivalente Java |
|---|---|---|
| `afirma-core` | Algoritmos, `SigningKey`, `ExtraParams`, certificados, constantes, códigos de error, modelo de árbol de firmantes, detección de tipos de datos | `afirma-core` |
| `afirma-cms` | ASN.1 BER/DER, CMS/PKCS#7, CAdES (firma, cofirma, contrafirma), ASiC-S, sellos de tiempo RFC 3161, validación CAdES | `afirma-crypto-core-pkcs7`, `-cms`, `-cades`, `-cades-multi`, `-core-pkcs7-tsp` |
| `afirma-xml` | DOM XML, C14N, XMLDSig, XAdES, FacturaE, ODF, OOXML, ASiC-S XAdES, validación XML | `afirma-crypto-core-xml`, `-xades`, `-xmlsignature`, `-odf`, `-ooxml` |
| `afirma-pdf` | Lectura de PDF, actualización incremental, PAdES, firma visible, sello de documento, validación y ataques de sombra | `afirma-crypto-pdf`, `-pdf-common` |
| `afirma-keystores` | PKCS#12, PKCS#11 (DNIe, CERES, tarjetas), NSS (Firefox/Chrome Linux), Windows (CNG/CryptoAPI), llavero de macOS, filtros de certificados | `afirma-core-keystores`, `afirma-keystores-*` |
| `afirma-signers` | Registro de firmadores por formato, selección automática de formato, firma masiva, firma trifásica y por lotes | `AOSignerFactory`, `afirma-core-massive`, `afirma-crypto-batch-client`, `*-tri-client` |
| `afirma-protocol` | Protocolo `afirma://`, servidor WebSocket local, servidor intermedio (StorageService/RetrieveService), cifrado de respuestas | `afirma-simple/.../protocol`, `afirma-core/.../misc/protocol` |
| `afirma-system` | Integración con el sistema: manejador de protocolo, CA local y certificado SSL, almacenes de confianza (Windows, macOS, NSS), directivas de navegadores, preferencias y su bloqueo | `afirma-ui-simple-configurator*`, instaladores |
| `autofirma` | Ejecutable: interfaz gráfica (egui), línea de comandos y arranque por protocolo | `afirma-simple` |

## Flujo de una firma

```
entrada (GUI / CLI / afirma://)
      │
      ▼
afirma-signers ── elige formato (AUTO) y firmador ──► afirma-cms | afirma-xml | afirma-pdf
      │                                                   │
      │                         SigningKey::sign(datos)   │
      ▼                                                   ▼
afirma-keystores (PKCS#12 · PKCS#11 · CNG · Keychain · NSS)
```

Todas las operaciones criptográficas con la clave pasan por el trait
`afirma_core::SigningKey`, que recibe los datos a firmar (atributos firmados
DER, `SignedInfo` canonicalizado...) y devuelve la firma PKCS#1 v1.5 o ECDSA
DER. Así los firmadores no dependen del almacén y la firma trifásica/por lotes
reutiliza el mismo mecanismo.

## Pruebas

- Unitarias en cada crate (`cargo test --workspace`).
- **Oráculo Java** (`tools/oracle/`): la AutoFirma Java compilada desde el
  código de `upstream` firma y valida los mismos datos; Apache Santuario
  canonicaliza los mismos XML. Las salidas de referencia se guardan como
  ficheros *golden* para que los tests no requieran Java.
- Validadores externos: OpenSSL (CMS), xmlsec/signxml (XMLDSig), pyHanko y
  pdfsig (PDF).
- Compilación cruzada para Windows y macOS con `tools/cross/Dockerfile`.
