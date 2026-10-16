# Desviaciones de `afirma-system` respecto a AutoFirma Java

Este documento recoge las diferencias deliberadas entre `afirma-system` (preferencias,
directivas, CA local, almacenes de confianza, protocolo `afirma://`, directivas de
navegadores, instalación, «Restaurar instalación» y diagnóstico) y la AutoFirma Java
(`afirma-ui-simple-configurator*`, `afirma-simple/.../restoreconfig`, instaladores NSIS/MSI,
`.deb`, `.rpm` y `.pkg`). Referencias de sección según `docs/spec/06-app-ui-cli-installer.md`.

Contrastes con el oráculo Java (`tools/oracle/system/JPrefsGolden.java`, salidas en
`testdata/system/`, comprobadas en `tests/java_golden.rs`): lectura de un árbol
`java.util.prefs` real del JDK (incluidos nombres de nodo alt-base64 y valores con
entidades) y cifrado de la contraseña del proxy (`ProxyUtil.cipherPassword`) idéntico byte
a byte. Las pruebas `tests/nss_real.rs` instalan, comprueban y retiran la CA en bases NSS
reales (perfiles de Firefox clásico y snap, `~/.pki/nssdb`) con `certutil` y con
`softokn3` vía PKCS#11, y verifican con `certutil -L` que la confianza resultante es la de
Java (`C,,` en Firefox; `TCP,TCP,TCP`, que NSS normaliza a `CT,C,C`, en la base compartida).
Para Windows, `tools/oracle/system/wine-test.sh` ejecuta todas las pruebas con Wine en la imagen
`autofirma-cross`, incluidas `tests/windows_real.rs` (registro real, almacén CryptoAPI
`CurrentUser\ROOT` y uno propio, registro del protocolo en `HKCU`). macOS se comprueba
compilando para `aarch64-apple-darwin` y `x86_64-apple-darwin` (`cargo zigbuild`).

## 1. Preferencias (§4)

### 1.1 Almacenamiento
* **Java**: `java.util.prefs` (registro `HKCU/HKLM\Software\JavaSoft\Prefs`, plist
  `com.apple.java.util.prefs`, `~/.java/.userPrefs` y `/etc/.java/.systemPrefs`), con
  persistencia diferida (~30 s).
* **Rust**: almacén nativo JSON con la **misma estructura de nodos** que Java
  (`preferences.json` en el directorio de configuración del usuario; `system-preferences.json`
  en `/etc/autofirma`, `%ProgramData%\AutoFirma` o `/Library/Application Support/AutoFirma`).
  Las preferencias Java del usuario se **migran una vez** (si no existe el JSON); las de
  sistema de Java se **siguen leyendo** siempre (decodificando el escapado de
  `WindowsPreferences`) para respetar despliegues existentes. Cada escritura se persiste de
  inmediato (en Java «Cancelar» no deshacía escrituras ya hechas; aquí tampoco hay
  deshacer, pero no se pierden cambios si el proceso termina).
* Las escrituras de sistema sin privilegios van, como en Java, a la copia de usuario
  (`systempreferences`, `internalpreferences`, `systemkeystores`).

### 1.2 Bloqueo real y directivas (mejora)
* **Java**: resolución usuario → sistema → defecto para **todas** las claves, incluido
  `preferencesBlocked`; el bloqueo solo deshabilita controles y el usuario puede
  desbloquearlo escribiendo en su propio nodo.
* **Rust**, modo `Strict` (por defecto): si `preferencesBlocked=true` está en la capa de
  **sistema**, las claves bloqueables se resuelven sistema → defecto (se ignoran los valores
  de usuario) y no se pueden escribir; las claves de administración (`preferencesBlocked`,
  `allowPersonalTruststore`, `allowAutoImportTrustedCerts`, `requireSignedPrerefences`,
  `certHashToSignedPrerefences`, `configFileUrl`, `allowUpdateConfig`) solo se leen de
  sistema/directiva. Las claves bloqueables son la lista protegida de Java ampliada con
  `xadesMultisign`, `cadesMultisign`, `useDefaultStoreInBrowserCalls`, `allowCertifiedPDF`,
  `padesCertificationLevel` y las claves de detalle de la política FacturaE (como
  recomienda la especificación). El modo `Compat` reproduce exactamente Java.
* **Nueva capa de directivas** (en ambos modos, siempre bloqueante): `HKLM` y `HKCU`
  `SOFTWARE\Policies\AutoFirma` (subclaves `Recommended` y `SmartCards`), preferencias
  gestionadas de macOS (`/Library/Managed Preferences/<bundle-id>.plist`) y
  `/etc/autofirma/policy.json` + `/etc/autofirma/policy.d/*.json` en Linux. Las
  recomendadas actúan como valores de sistema. Los valores se validan contra el tipo de la
  clave (los no válidos se descartan con aviso).
* Se mantiene el identificador de paquete de macOS de Java (`es.gob.afirma.simpleafirma.osx`)
  para que los perfiles MDM existentes sigan aplicándose.

### 1.3 Validación de escrituras
* **Java** no validaba los valores. **Rust** rechaza en `put` valores fuera de la
  enumeración de la clave (p. ej. `xadesSignFormat=XAdES Raro`); la importación `.afconfig`
  los omite y los informa.

### 1.4 `.afconfig`
* Se acepta la declaración `DOCTYPE` estándar de Apple (Java la rechazaba con 230302); no se
  resuelven entidades externas ni personalizadas.
* `requireSignedPrerefences`: se implementa el comportamiento previsto (rechazar ficheros
  **sin** firmar, 522004); Java rechazaba los firmados.
* La verificación criptográfica XMLDSig se delega en `ConfigSignatureVerifier` (lo aporta la
  aplicación con `afirma-xml`); sin verificador, un fichero firmado se rechaza en la
  importación de usuario (522002). Se comprueba la vigencia del certificado (522001) y el
  certificado autorizado (522003) como Java.
* Exportación: mismo formato que Java (sin `DOCTYPE`, compacto, `<true/>`/`<false/>`,
  `<string/>` para vacíos) pero con las claves **ordenadas** (Java usaba el orden de un
  `HashMap`) e incluyendo las directivas obligatorias, que forman parte de la configuración
  efectiva.
* Errata del mensaje 522001 corregida («configuracióon» → «configuración»).

### 1.5 Configuración del sistema y actualización remota (§4.11, §9.6)
* Las descargas `https://` **validan TLS** con el almacén del sistema (rustls + verificador de
  la plataforma); Java desactivaba la validación. Se rechazan las URL `http://`. Límite de
  4 MiB.
* Se aplica `requireSignedPrerefences`/`certHashToSignedPrerefences` también a la
  configuración de sistema y a la remota si el administrador los ha fijado (Java no
  comprobaba la firma). Si el fichero está firmado y no hay verificador ni exigencia de
  firma, se importa sin verificar (como Java) con un aviso.
* `configDate` con el año natural (`%Y%m%d`); una fecha «del futuro» heredada (patrón `YYYY`
  de semana de Java) se considera caducada.
* `allowUpdateConfig` puede venir también de una directiva.

### 1.6 Tarjetas inteligentes
* Las tarjetas impuestas por directiva tienen prioridad sobre las de sistema y las de
  usuario. La importación de sistema escribe siempre en el nodo leído (Java podía escribir
  en `/es/gob/afirma/core/prefs`, que nunca se leía).

### 1.7 Contraseña del proxy
* Se conserva el cifrado reversible de Java (necesario para leer valores existentes); no se
  ha implementado aún el uso del llavero del sistema (ver «Pendiente»).

## 2. Certificados locales (§9.2, §10.4)
* Igual que Java: `CN=Autofirma ROOT` / `CN=127.0.0.1`, RSA-2048, SHA256withRSA, 3650 días,
  `autofirma.pfx` (contraseña `654321`, alias `SocketAutoFirma`, cadena `[SSL, CA]`),
  `Autofirma_ROOT.cer` y `autofirma.cer` (macOS), SKI SHA-1 y AKI, CA con
  `BasicConstraints` crítico, `KeyUsage` y `ExtendedKeyUsage` de Java.
* Mejoras: números de serie **positivos de 128 bits** (Java: entero de 32 bits con signo);
  `notBefore` un día antes (desfase de reloj); el certificado SSL lleva `KeyUsage`
  digitalSignature+keyEncipherment, `ExtendedKeyUsage` serverAuth y SAN `IP:127.0.0.1`,
  `IP:::1`, `DNS:localhost` (sin el `DNS:127.0.0.1` erróneo del configurador; «Restaurar
  instalación» de Java no incluía `DNS:localhost`).
* PKCS#12 con los algoritmos por defecto del JDK moderno (PBES2/AES-256, HMAC-SHA256).
* Regeneración: Java reutilizaba cualquier `autofirma.pfx` existente; aquí, por defecto, se
  regenera si no se abre, la cadena no cuadra o caduca en menos de 30 días. Si solo falta
  `Autofirma_ROOT.cer` se recupera de la cadena (caso B de Java, cuyo fallo de escritura al
  directorio alternativo queda corregido).
* `certs::locate` devuelve el primer juego **utilizable** de los directorios de búsqueda
  (Java usaba el primero que existiera aunque estuviera caducado). En macOS, con privilegios,
  los certificados se generan en `/Library/Application Support/AutoFirma` (no en el
  directorio del usuario que ejecuta el instalador).

## 3. Almacenes de confianza (§9.3–9.5, §10)
* **Windows**: con privilegios, `LocalMachine\ROOT` (sin avisos), igual que el instalador
  NSIS; sin privilegios, `CurrentUser\ROOT` (Windows muestra su diálogo), salvo que la CA ya
  esté en el almacén del equipo. Se retiran todas las CA/certificados de AutoFirma
  anteriores (por CN del sujeto o del emisor, sin distinguir mayúsculas), nunca otros.
* Borrado en CryptoAPI: si tras `CertDeleteCertificateFromStore` sobre el almacén lógico el
  certificado sigue presente (almacenes físicos que no propagan el borrado, observado en
  Wine), se repite sobre el almacén de registro (`CERT_STORE_PROV_SYSTEM_REGISTRY`).
* **macOS**: no se pide ni se maneja la contraseña del usuario (`sudo -S` de Java); con
  privilegios se usa el llavero del sistema (CA `trustRoot`, SSL `trustAsRoot -p ssl`), sin
  ellos el de sesión. La búsqueda por CN (subcadena en `security`) se filtra para borrar
  solo certificados de AutoFirma (Java podía borrar cualquier certificado cuyo nombre
  contuviera `127.0.0.1`). Para despliegues sin interacción se recomienda el perfil MDM con
  `com.apple.security.root` (`browser_policy::macos_mobileconfig`) junto con certificados
  aportados por el administrador.
* **Linux**: anclas del sistema para openSUSE/SLES, Fedora/RHEL, Arch y Debian/Ubuntu (Java
  solo el `.deb`).
* **NSS**: todos los perfiles de todos los `profiles.ini` (clásico, XDG, snap **y** clásico,
  flatpak), honrando `IsRelative`; en Windows todos los perfiles (Java solo uno por usuario);
  `~/.pki/nssdb` y sus variantes snap/flatpak de Chrome, Chromium, Edge y Brave. Nunca se
  crea una base inexistente. Éxito por código de salida (Java: «cualquier salida es error»);
  se retiran todas las copias. Sin `certutil` se usa `softokn3` vía PKCS#11 (nuevo). En
  Windows no se usa el `certutil.exe` de Microsoft ni el NSS de 2010 incluido en Java (solo
  un `nss/certutil.exe` junto al ejecutable o el `softokn3.dll` de Firefox). No se pide la
  contraseña maestra: los perfiles protegidos se informan como error.
* Con privilegios, tras modificar bases de otros usuarios se devuelve la propiedad de los
  ficheros al usuario.
* Firefox no tiene que estar cerrado (bases SQL); Java mostraba bucles de «cierre Firefox».

## 4. Protocolo `afirma://` y menús (§9.3.3, §9.4, §9.5, §10.6.5)
* **Windows**: rutas **entrecomilladas** (`"<exe>" "%1"`, `"<exe>" sign -gui -i "%1"`); por
  usuario en `HKCU\Software\Classes` sin elevación (Java usaba `HKCR` y un `.bat` con UAC).
  «Verificar con Autofirma» se registra en `SystemFileAssociations\.csig|.xsig` y con los
  ProgID `Autofirma.csig`/`Autofirma.xsig` (Java ponía un texto descriptivo como valor
  predeterminado de la extensión); el valor de la extensión solo se fija si nadie la tiene
  asignada (o si contiene el texto de Java). Los verbos de Java bajo `.csig\shell\Verify`
  se eliminan para no duplicar el menú. La desinstalación limpia también las claves de la
  extensión que Java dejaba. Menús de huellas opcionales (antiguo complemento).
* **Linux**: además del `.desktop` (`autofirma.desktop`, `Exec` con comillas según la
  especificación), se fija el valor por defecto en `mimeapps.list` (usuario o `/etc/xdg`) y se
  ejecuta `update-desktop-database`; opcionalmente «Abrir con → Firmar con Autofirma»,
  tipos MIME `.csig`/`.xsig` y script de Nautilus (Java no tenía integración con ficheros).
  El paso de protocolo de «Restaurar instalación» funciona (Java fallaba siempre).
* **macOS**: el esquema lo declara el `Info.plist` (fragmento generado); se refresca
  `lsregister` y se fija el manejador por defecto por usuario con
  `LSSetDefaultHandlerForURLScheme` (Java no lo hacía).

## 5. Directivas de navegadores (nuevo, §9.7)
* Java no configuraba ninguna. Se añaden (opcionalmente) `AutoLaunchProtocolsFromOrigins`,
  `ExternalProtocolDialogShowAlwaysOpenCheckbox`, `LocalNetworkAccessAllowedForUrls` e
  `InsecurePrivateNetworkRequestsAllowedForUrls` (solo con orígenes explícitos) para
  Chrome/Edge/Chromium/Brave, y `Handlers.schemes.afirma` + `Certificates.ImportEnterpriseRoots`
  para Firefox, en el registro (HKLM), ficheros JSON de Linux y preferencias gestionadas /
  `distribution/policies.json` en macOS, más plantillas `.reg` y `.mobileconfig`. Se
  fusionan con las del administrador y al retirarlas solo se quita lo propio.

## 6. Instalación, desinstalación y restauración
* Una única API con planificación y simulación (`install::plan_install`, `execute`), mismas
  opciones que el configurador (`parse_configurator_args`).
* El configurador de Linux ya no escribe `script.sh`/`uninstall.sh` para que los ejecuten
  los paquetes: actúa directamente (con privilegios, para todos los usuarios con UID ≥ 1000
  o directorio bajo `home/`, incluidos los que Java omitía).
* `PATH` de Windows: se notifica `WM_SETTINGCHANGE` y, sin privilegios, se usa el `PATH` del
  usuario.
* «Restaurar instalación»: `security.enterprise_roots.enabled` no se modifica por defecto
  (Java escribía `false` con la casilla desmarcada); detección de root correcta en Linux; no
  se lanzan varios procesos concurrentes; mensajes con los textos de Java.
* La desinstalación no borra recursivamente `%ALLUSERSPROFILE%\Autofirma` ni
  `~/.afirma/Autofirma` (Java sí): solo los ficheros de certificados propios.
* `-language_path` se acepta pero no se procesa aquí (paquetes de idioma: interfaz).

## 7. Pendiente / limitaciones conocidas
* Almacenamiento de la contraseña del proxy en el llavero del sistema.
* Verificación XMLDSig de `.afconfig` (se espera un `ConfigSignatureVerifier` de `afirma-xml`).
* `LSSetDefaultHandlerForURLScheme` solo actúa para el usuario que lo ejecuta (el instalador
  `.pkg` se ejecuta como root: la aplicación debe llamar a
  `protocol::macos_set_default_handler` en su primer arranque).
* Desde macOS 11 `security add-trusted-cert` puede exigir interacción incluso como root fuera
  de un instalador; para despliegues MDM usar el perfil `.mobileconfig`.
* Las preferencias gestionadas de Chrome/Edge escritas directamente en
  `/Library/Managed Preferences` pueden ser reemplazadas por el MDM; se recomienda el perfil.
* Las bases NSS en formato antiguo (`cert8.db`) se tratan con el prefijo `dbm:` y solo si el
  NSS del sistema todavía lo admite.
