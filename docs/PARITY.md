# Paridad con AutoFirma (Java)

Estado de cada función de AutoFirma 1.9 en AutoFirma-rs. La especificación detallada de la
versión Java está en [`docs/spec/`](spec/) (el checklist completo, en
[06 §13](spec/06-app-ui-cli-installer.md#13-parity-checklist)); las diferencias deliberadas,
en [`docs/deviations/`](deviations/).

Leyenda: ✅ igual que Java · ➕ igual y mejorado · 🔁 sustituido por un equivalente ·
⚠️ parcial · ❌ no implementado · ➖ descartado a propósito.

## Formatos de firma

| Función | Estado | Notas |
|---|---|---|
| CAdES (implícita/explícita, BES/EPES, cofirma, contrafirma de hojas y árbol) | ✅ | 49 salidas idénticas byte a byte a las de Java |
| CMS/PKCS#7, PKCS#1 (`NONE`) | ✅ | |
| CAdES-T (sello de tiempo RFC 3161) | ➕ | Funciona también en PAdES (en Java estaba roto) |
| XAdES 1.3.2 / 1.4.1 / baseline, cuatro modos | ✅ | 68 casos diferenciales con la misma estructura que Java |
| XMLDSig, FacturaE, ASiC-S (CAdES y XAdES) | ✅ | |
| ODF y OOXML | ➕ | Validados por LibreOffice; ODF con el algoritmo pedido (modo Java disponible) |
| PAdES (firma, cofirma, DocMDP, campos vacíos, varias páginas, PDF cifrados) | ➕ | Escritura siempre incremental: el PDF original queda intacto |
| Firma visible PAdES (texto, rúbrica, rotación, ofuscación) | ✅ | 0 píxeles de diferencia con Java en 20 escenarios |
| Validación de firmas (veredictos y textos) | ✅ | XML 116/117, PDF 52/53 iguales que Java (las diferencias son fallos de Java) |
| Detección del ataque de sombra en PDF | ✅ | |
| Resúmenes SHA-3, RIPEMD-160 y Whirlpool, transformada XSLT | ⚠️ | Solo afectan a validar firmas XML de terceros que los usen |
| Claves DSA en firmas XML | ❌ | Sin uso real en certificados actuales |
| Incrustación de fuentes en PDF/A-1 | ⚠️ | La firma se ve igual; usa fuentes estándar no incrustadas |

## Firma desde la web (`afirma://`)

| Función | Estado | Notas |
|---|---|---|
| WebSocket local TLS (v3/v4), servicio por sockets, servidor intermedio (storage/retrieve) | ✅ | Probado con `autoscript.js` en Chromium y con los WAR de Java |
| Operaciones `sign`, `cosign`, `countersign`, `selectcert`, `save`, `signandsave`, `load`, `batch` | ✅ | |
| Firma trifásica (CAdES, XAdES, PAdES, FacturaE, PKCS#1) y por lotes (XML y JSON) | ✅ | |
| Cifrado de respuestas (DES/AES), códigos de error y versiones del protocolo | ✅ | |
| Ventana de la petición (sede, documento, certificado) | ➕ | Ventana compacta nueva; muestra el origen de la petición |
| Firma visible pedida por la web (`visibleSignature=want/optional`) | ✅ | |
| URL `afirma://` en macOS (evento `kAEGetURL`) | ✅ | Compila para macOS; pendiente de prueba en un Mac real |

## Certificados

| Función | Estado | Notas |
|---|---|---|
| Almacén de Windows (CNG/CryptoAPI), llavero de macOS, NSS (Firefox, Chrome en Linux) | ✅ | |
| PKCS#12, PKCS#11 (DNIe, CERES, tarjetas registradas) | ✅ | Probado con SoftHSM2 |
| Controlador DNIe propio de Java (JMulticard) | 🔁 | Se usan los módulos PKCS#11 del DNIe/OpenSC |
| Filtros de certificados (`filters`, `headless`, seudónimos, uso de clave...) | ✅ | |
| Diálogo de selección (vistas, búsqueda, cambio de almacén, detalles) | ➕ | Búsqueda por nombre/NIF, aviso de caducidad |
| PIN con caché de sesión y confirmación DNIe | ✅ | |
| Registro de tarjetas PKCS#11 (añadir, quitar) | ✅ | En «Mis certificados» |
| «Mis certificados»: ver, exportar, almacén por defecto | ➕ | Nuevo |

## Aplicación de escritorio

| Función | Estado | Notas |
|---|---|---|
| Firma de uno o varios ficheros, carpetas, arrastrar y soltar | ✅ | |
| Formato automático por tipo de fichero y preferencias, cambio de formato | ✅ | |
| Cofirma/contrafirma según preferencias, confirmación antes de firmar | ✅ | |
| Nombres de salida `_signed` y `(n)`, sobrescritura masiva | ✅ | |
| Editor de firma visible (área, páginas, apariencia, rúbrica, campos vacíos) | ➕ | Vista previa real del PDF |
| Marca de imagen independiente (`image`, `imagePage`) | ✅ | En el mismo editor que la firma visible |
| Pantalla de resultado y visor de firmas (árbol, sellos, certificados, datos firmados) | ✅ | Página «Verificar firmas» |
| Validación del certificado de firma (OCSP/CRL) | ➕ | Tras firmar, en «Mis certificados» y en Herramientas; verifica las respuestas OCSP y las CRL (Java no lo hacía) |
| Huellas digitales (ficheros y carpetas, crear y comprobar) | ✅ | Salidas idénticas a las de Java |
| Restaurar la instalación / diagnóstico | ➕ | Diagnóstico nuevo con reparación |
| Pantalla de espera del DNIe al arrancar | 🔁 | El almacén y el DNIe se eligen en la página de firma |
| Confirmación al cerrar | ✅ | |
| Ayuda local en HTML | 🔁 | Página de ayuda integrada |
| Seis idiomas | ✅ | |
| Paquetes de idioma (ZIP) | ➖ | Sin uso conocido |
| Complementos (plugins) | 🔁 | Huellas y validación de certificados integrados |
| Aviso de nueva versión | ✅ | Consulta las versiones publicadas del repositorio; mismas exclusiones que Java |
| Instancia única de la interfaz | ➕ | Una segunda ejecución entrega sus ficheros a la ventana abierta |
| Tema de alto contraste, escalado, lector de pantalla | ➕ | Temas claro/oscuro/alto contraste; AccessKit |

## Preferencias

| Función | Estado | Notas |
|---|---|---|
| Todas las claves, valores por defecto y capas usuario/sistema | ✅ | Lee los almacenes de Java existentes |
| Bloqueo por el administrador (`preferencesBlocked`, claves protegidas) | ➕ | Por directiva real (GPO/registro, MDM, `/etc`), no solo en la interfaz |
| Importar/exportar `.afconfig`, restaurar valores de fábrica | ✅ | La firma del fichero se verifica |
| Configuración remota al instalar y actualización diaria | ➕ | Firma verificada también al instalar (Java no la comprobaba) |
| Proxy (ninguno, sistema, manual con autenticación) y contraseña cifrada | ✅ | Botón «Comprobar» |
| Conexiones seguras y dominios sin comprobación TLS | ✅ | |
| Certificados de confianza personales (`TrustedCertsKeystore.jks`) | ✅ | Importar desde fichero o servidor, eliminar, y aviso «Verificación de dominio» ante certificados TLS no reconocidos |

## Línea de comandos

| Función | Estado | Notas |
|---|---|---|
| `sign`, `cosign`, `countersign`, `verify`, `listaliases`, `batchsign`, `createdigest`, `checkdigest` | ✅ | 179 casos comparados con Java (salida y código de salida) |
| `-gui`, `-certgui`, `-config`, `-filter`, `-xml`, ayudas en 6 idiomas | ✅ | |
| `install`, `uninstall`, `doctor`, `restore-config`, `--version` | ➕ | Nuevas |

## Instalación e integración con el sistema

| Función | Estado | Notas |
|---|---|---|
| CA local y certificado SSL (`autofirma.pfx`, `Autofirma_ROOT.cer`) | ✅ | |
| Confianza en Windows, macOS (llavero) y NSS (Firefox, Chrome) | ✅ | |
| Manejador `afirma://`, menús contextuales «Firmar/Verificar/Huella» | ✅ | |
| Instalador de Windows (MSI con propiedades `CONFIG_PATH`, `FIREFOX_SECURITY_ROOTS`...) | ✅ | Probado con Wine; pendiente en Windows real |
| Paquetes de Linux (.deb, .rpm) y AppImage | ➕ | AppImage nuevo |
| Paquete de macOS (.pkg, .dmg) | ✅ | Pendiente de prueba en un Mac real |
| Directivas de navegadores para abrir `afirma://` sin preguntar | ➕ | Nuevo: Chrome, Edge, Firefox |
| Firefox en Linux: confianza en la CA local también para perfiles nuevos | ➕ | `Certificates.Install` |
