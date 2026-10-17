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
| Resúmenes SHA-3 al validar firmas XML | ✅ | |
| Transformada XSLT al validar firmas XML | ⚠️ | Solo afecta a firmas XML de terceros que la usen |
| Claves DSA en firmas XML | ❌ | Sin uso real en certificados actuales |
| Firma visible en PDF/A con fuentes incrustadas | ➕ | PDF/A-1, 2 y 3 siguen siendo conformes (veraPDF); Java solo lo hacía en PDF/A-1 |

## Firma desde la web (`afirma://`)

| Función | Estado | Notas |
|---|---|---|
| WebSocket local TLS (v3/v4), servicio por sockets, servidor intermedio (storage/retrieve) | ✅ | Probado con `autoscript.js` en Chromium y con los WAR de Java |
| Operaciones `sign`, `cosign`, `countersign`, `selectcert`, `save`, `signandsave`, `load`, `batch` | ✅ | |
| Firma trifásica (CAdES, XAdES, PAdES, FacturaE, PKCS#1) y por lotes (XML y JSON) | ✅ | |
| Cifrado de respuestas (DES/AES), códigos de error y versiones del protocolo | ✅ | |
| Ventana de la petición (sede, documento, certificado) | ➕ | Ventana compacta nueva; muestra el origen de la petición |
| Firma visible pedida por la web (`visibleSignature=want/optional`) | ✅ | |
| URL `afirma://` en macOS (evento `kAEGetURL`) | ✅ | En macOS real (CI): el `.pkg` registra el esquema, la URL llega como evento de Apple y la página recibe una firma válida |

## Certificados

| Función | Estado | Notas |
|---|---|---|
| Almacén de Windows (CNG/CryptoAPI), llavero de macOS, NSS (Firefox, Chrome en Linux) | ✅ | Almacén de Windows y llavero de macOS usados desde la web en Windows y macOS reales (CI) |
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
| Instalador de Windows (MSI con propiedades `CONFIG_PATH`, `FIREFOX_SECURITY_ROOTS`...) | ✅ | En Windows real (CI): `install --system`, CA en `LocalMachine\Root`, protocolo, diagnóstico, firma y desinstalación; el MSI, con `msiexec` en Wine |
| Paquetes de Linux (.deb, .rpm) y AppImage | ➕ | AppImage nuevo |
| Paquete de macOS (.pkg, .dmg) | ✅ | En macOS real (CI): `.pkg` instalado con `installer`, CA en el llavero del sistema, `afirma://` registrado, firma y desinstalación |
| Directivas de navegadores para abrir `afirma://` sin preguntar | ➕ | Nuevo: Chrome, Edge, Firefox |
| Firefox en Linux: confianza en la CA local también para perfiles nuevos | ➕ | `Certificates.Install` |

## Cómo se ha comprobado

- **Formatos**: firmas comparadas con las de la versión Java (oráculo en `tools/oracle/`) y
  validadas con OpenSSL, `pdfsig`, pyHanko, LibreOffice y veraPDF.
- **Firma desde la web**: `tools/e2e/web_sign.py` abre una página con el `autoscript.js` real
  en Chromium, la app atiende `afirma://websocket` y la firma devuelta se verifica (CAdES,
  XAdES y PAdES en Linux; CAdES con el ejecutable de Windows en Wine,
  `tools/e2e/wine-autofirma.sh`). En Windows y macOS reales (`tools/ci/web_sign.py`, en la
  CI) Chrome carga la página y AutoFirma se abre con el manejador del sistema (ShellExecute;
  LaunchServices y evento de Apple). Chrome solo conecta porque confía en la CA instalada,
  sin desactivar ninguna comprobación. El certificado del almacén del sistema (Windows) o del
  llavero (macOS) se elige sin diálogo y la firma devuelta es válida.
- **Finder (macOS)**: un PDF abierto con `open -a AutoFirma.app` llega a la aplicación recién
  lanzada.
- **Línea de comandos**: 179 casos comparados con la versión Java (`testdata/cli/`).
- **Instaladores**: MSI con WiX 5 instalado y desinstalado con `msiexec` en Wine; .deb
  instalado y purgado en Debian 13 y .rpm en Rocky Linux 8 (glibc 2.28), con firma por línea
  de comandos y diagnóstico.
- **Pruebas automáticas**: `cargo test --workspace` (más de 630 pruebas), clippy y formato en
  Linux, Windows y macOS reales (`.github/workflows/ci.yml`, en verde).
- **Integración real** (mismo flujo de CI): `install --system`, confianza en el almacén del
  sistema, registro de `afirma://`, diagnóstico sin errores (`tools/ci/check_doctor.py`),
  firma y verificación CAdES/XAdES/PAdES y desinstalación, en Ubuntu, Windows y macOS (con el
  `.pkg` instalado como lo haría un usuario).
