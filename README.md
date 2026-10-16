<p align="center"><img src="packaging/icons/autofirma-256.png" width="96" alt=""></p>

# AutoFirma-rs

Cliente de firma electrónica compatible con **AutoFirma**, reescrito en **Rust**. Es un fork de
[clienteafirma](https://github.com/ctt-gob-es/clienteafirma) (Gobierno de España): firma y
valida los mismos formatos, atiende las mismas peticiones `afirma://` de las sedes electrónicas
y entiende la misma configuración, pero es un único ejecutable nativo, sin Java, con una interfaz
nueva y preparado para desplegarse en equipos corporativos sin avisos.

> Proyecto independiente, sin relación con el Gobierno de España ni con el CTT. Estado: **alfa**.

## Qué ofrece

- **Paridad con AutoFirma 1.9**: CAdES, XAdES, XMLDSig, FacturaE, PAdES (con firma visible
  idéntica a la de Java), ODF, OOXML, ASiC-S (CAdES y XAdES), PKCS#1; firma, cofirma y
  contrafirma; sellos de tiempo; firma trifásica y por lotes; validación con los mismos
  veredictos. Las firmas se comparan en las pruebas con las de la versión Java.
- **Firma desde la web**: protocolo `afirma://` (WebSocket local, servidor intermedio, cifrado
  de respuestas), compatible con el `autoscript.js` de las sedes.
- **Certificados**: almacén de Windows, llavero de macOS, NSS (Firefox, Chrome en Linux),
  PKCS#12, PKCS#11 (DNIe, tarjetas CERES y otras tarjetas registradas), con los mismos filtros.
- **Línea de comandos** compatible (`sign`, `cosign`, `countersign`, `verify`, `listaliases`,
  `batchsign`, `createdigest`, `checkdigest`) y órdenes nuevas para la integración con el
  sistema (`install`, `uninstall`, `doctor`, `restore-config`).
- **Herramientas**: huellas digitales de ficheros y carpetas, diagnóstico y reparación de la
  integración con los navegadores.
- **Idiomas**: español, català, galego, euskara, valencià e inglés.

### Mejoras sobre la versión Java

- Sin Java ni JRE: un único ejecutable nativo que arranca al instante, en Windows, Linux y macOS
  (x86_64 y ARM).
- Interfaz rediseñada: arrastrar y firmar, varios documentos a la vez, vista previa de la firma
  visible sobre el PDF, verificación con informe detallado, tema claro, oscuro y de alto
  contraste, escalado.
- Despliegue corporativo sin avisos: directivas de Chrome, Edge y Firefox para abrir `afirma://`
  sin preguntar, MSI con propiedades para GPO/Intune, perfiles MDM en macOS, preferencias
  bloqueables por directiva y configuración remota con firma verificada
  ([guía de despliegue](docs/DEPLOYMENT.md)).
- Diagnóstico (`autofirma doctor`) y reparación de la integración con un clic.
- Correcciones de seguridad respecto a Java: respuestas OCSP y listas de revocación verificadas,
  configuraciones `.afconfig` firmadas comprobadas al instalar, sin expansión de entidades XML,
  TLS con `rustls` y el almacén de confianza del sistema.

La lista completa de funciones y su estado está en [docs/PARITY.md](docs/PARITY.md); las
diferencias deliberadas con Java, en [docs/deviations/](docs/deviations/).

## Instalación

| Sistema | Paquetes |
|---|---|
| Windows 10/11 | `AutoFirma-<versión>-windows-x86_64.msi` (por equipo, admite instalación silenciosa), ZIP portable |
| Linux | `.deb`, `.rpm`, AppImage y `.tar.gz` portable |
| macOS 10.15+ | `.dmg` y `.pkg` (binario universal) |

Instalación silenciosa en Windows:

```powershell
msiexec /i AutoFirma-2.0.0-windows-x86_64.msi /qn FIREFOX_SECURITY_ROOTS=true
```

La versión portable no necesita instalación: al abrirla por primera vez ofrece integrarse con
los navegadores del usuario (o `autofirma install --user`).

## Uso

- **Escritorio**: abre AutoFirma, arrastra los documentos y pulsa *Firmar*. Para comprobar una
  firma, arrástrala a *Verificar firmas*.
- **Sedes electrónicas**: la sede abre AutoFirma automáticamente; aparece una ventana compacta
  con el nombre de la sede, el documento y tus certificados.
- **Línea de comandos**:

```bash
autofirma sign -i contrato.pdf -o contrato_firmado.pdf -format pades -store auto -filter "subject.contains:12345678Z"
autofirma verify -i contrato_firmado.pdf
autofirma listaliases -store pkcs12:/ruta/certificado.p12 -password ****
autofirma doctor
autofirma --help
```

## Compilación

Requisitos: Rust 1.92 o posterior. En Linux, las cabeceras de X11/Wayland habituales.

```bash
cargo build --release -p autofirma          # target/release/autofirma
cargo test --workspace                       # pruebas
tools/package/linux.sh                       # .deb, .rpm, AppImage, .tar.gz
tools/package/windows-cross.sh --msi         # .exe y .msi desde Linux (Docker)
tools/package/macos.sh                       # .app, .dmg y .pkg (en macOS)
```

## Organización del repositorio

| Ruta | Contenido |
|---|---|
| `crates/autofirma` | Ejecutable: interfaz (egui), línea de comandos y modo protocolo |
| `crates/afirma-core` | Tipos comunes: algoritmos, claves, parámetros, certificados, red |
| `crates/afirma-cms` | ASN.1, CMS, CAdES, ASiC-S, sellos de tiempo |
| `crates/afirma-xml` | XMLDSig, XAdES, FacturaE, ODF, OOXML |
| `crates/afirma-pdf` | PAdES, firma visible, renderizado y validación de PDF |
| `crates/afirma-keystores` | Almacenes de certificados y selección |
| `crates/afirma-signers` | Registro de formatos, selección automática y validación |
| `crates/afirma-protocol` | Protocolo `afirma://` |
| `crates/afirma-system` | Integración con el sistema, preferencias y directivas |
| `crates/afirma-cli`, `afirma-hash`, `afirma-certval` | Línea de comandos, huellas digitales, validación de certificados |
| `docs/` | Arquitectura, especificación extraída de Java, despliegue, paridad y desviaciones |
| `packaging/`, `tools/package/` | Instaladores y scripts de empaquetado |
| `afirma-*` | Código Java original, que se conserva como referencia y como oráculo de pruebas |

El README original de clienteafirma está en [docs/README-original-java.md](docs/README-original-java.md).

## Licencia

Como el original, software libre con doble licencia **GPL 2.0 o posterior** y **EUPL 1.1**
(véase [license/](license/)). Tipografía Inter (SIL OFL 1.1) e iconos Phosphor (MIT) en la
interfaz; fuentes Liberation 2.1.5 (SIL OFL 1.1) para las firmas visibles en PDF/A y perfiles ICC
compactos de saucecontrol (CC0 1.0), con sus licencias en `crates/afirma-pdf/fonts/` y
`crates/afirma-pdf/icc/`.
