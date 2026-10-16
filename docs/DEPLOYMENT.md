# Despliegue de AutoFirma-rs en equipos corporativos

Guía para administradores: instalación silenciosa en Windows, Linux y macOS, despliegue
con GPO, Intune, Configuration Manager (SCCM) y MDM, directivas de navegadores que eliminan los avisos
al abrir `afirma://`, preferencias preconfiguradas y bloqueadas, red (proxy y TLS), firma
de código y comprobación de la instalación.

> Identificadores de AutoFirma-rs (distintos de los de la Autofirma Java a propósito):
>
> | Concepto | Valor |
> |---|---|
> | Nombre visible | AutoFirma |
> | Paquete Linux | `autofirma-rs` |
> | Identificador de macOS (bundle) y dominio de preferencias gestionadas | `io.github.autofirma-rs.AutoFirma` |
> | Identificador del paquete de macOS (`pkgutil`) | `io.github.autofirma-rs.AutoFirma.pkg` |
> | Identificador AppStream (Linux) | `io.github.autofirma_rs.AutoFirma` |
> | UpgradeCode del MSI | `{48D90D3A-830C-4DA9-8F3C-D4E2ADE9EE89}` (fijo, `packaging/windows/ids.wxi`) |
> | Carpeta de instalación en Windows | `%ProgramFiles%\AutoFirma-rs` |
> | Protocolo | `afirma://` (el mismo que la Autofirma Java) |

## 1. Artefactos publicados

| Sistema | Fichero | Uso |
|---|---|---|
| Windows x64 / ARM64 | `AutoFirma-<versión>-windows-<arq>.msi` | Instalación por equipo, silenciosa, GPO/Intune/SCCM |
| Windows x64 / ARM64 | `AutoFirma-<versión>-windows-<arq>-portable.zip` | Portable, sin administrador (`install --user`) |
| Debian, Ubuntu y derivadas | `autofirma-rs_<versión>-1_<amd64\|arm64>.deb` | Instalación por equipo |
| Fedora, RHEL, Rocky, openSUSE | `autofirma-rs-<versión>-1.<x86_64\|aarch64>.rpm` | Instalación por equipo |
| Linux (glibc ≥ 2.28) | `AutoFirma-<versión>-<arq>.AppImage`, `autofirma-rs-<versión>-linux-<arq>.tar.gz` | Portables (`install --user`) |
| macOS 10.15 o posterior (Intel y Apple Silicon) | `AutoFirma-<versión>-macos-universal.pkg` | Instalación por equipo, silenciosa, MDM |
| macOS | `AutoFirma-<versión>-macos-universal.dmg` | Arrastrar a Aplicaciones (sin configuración del sistema) |
| Todos | `SHA256SUMS` (y `SHA256SUMS.asc` si se firma), `autofirma-rs-<versión>.spdx.json` (SBOM) | Verificación e inventario |

En las versiones previas (`2.0.0-alpha.1`), Debian y RPM usan `2.0.0~alpha.1` para que se
ordenen antes que la versión final.

## 2. Qué hace la instalación

Todos los instaladores copian la aplicación y después ejecutan, como administrador y sin
interfaz, la configuración del sistema:

```
autofirma install --system [opciones]
```

que (de forma idempotente, también en reparaciones y actualizaciones):

1. Genera la CA local `CN=Autofirma ROOT` y el certificado SSL de `127.0.0.1` que protege la
   comunicación entre la sede electrónica y AutoFirma (`autofirma.pfx`,
   `Autofirma_ROOT.cer`; mismos nombres que la versión Java). Si ya existen y son válidos,
   los reutiliza.
2. Instala la CA en el almacén de confianza del sistema (Windows `LocalMachine\ROOT`,
   llavero del sistema de macOS, anclas de confianza de la distribución en Linux) y en
   las bases NSS de Firefox (y de Chrome/Chromium en Linux) de **todos** los usuarios.
3. Registra el protocolo `afirma://` y, en Windows, los menús contextuales «Firmar con
   AutoFirma» y «Verificar con AutoFirma» (`.csig`, `.xsig`).
4. Con `--browser-policies`, escribe las directivas de Chrome, Edge, Chromium, Brave y
   Firefox que permiten abrir `afirma://` sin preguntar (sección 6). Solo añade sus
   entradas: las directivas que ya tuviera el administrador se conservan, y al
   desinstalar solo se retiran las propias.

La desinstalación ejecuta `autofirma uninstall --system`, que deshace todo lo anterior
(solo lo que creó AutoFirma). En las actualizaciones no se ejecuta, para no cambiar la CA.

Opciones de `install` que los instaladores pasan según las propiedades de la sección 3 a 5:

| Opción | Efecto | Equivalente Java |
|---|---|---|
| `--browser-policies` | Directivas de navegadores (sección 6) | (nuevo) |
| `--origins <lista>` | Orígenes autorizados, separados por comas (`https://sede.ejemplo.es,https://*.ejemplo.gob.es`); sin ella, cualquier origen | (nuevo) |
| `--firefox-roots` | Firefox confía en las CA del almacén del sistema | `-firefox_roots` |
| `--config-path <ruta\|https://…>` | Importa un fichero de preferencias `.afconfig` como preferencias de sistema | `-config_path` |
| `--update-config` | Vuelve a descargar `--config-path` (solo `https://`) una vez al día | `-update_config` |
| `--default-language <xx_YY>` | Idioma: `es_ES`, `ca_ES`, `gl_ES`, `eu_ES`, `va_ES`, `en_US` | `-default_language` |
| `--keystore-path <pfx> --certificate-path <cer>` | Usa un par CA + SSL corporativo (PKCS#12 con contraseña `654321`) en lugar de generar uno; los dos a la vez | `-keystore_path`, `-certificate_path` |
| `--dry-run` | Muestra lo que haría sin cambiar nada | (nuevo) |

Ficheros que genera la instalación:

| Sistema | Certificados locales | Preferencias de sistema y estado |
|---|---|---|
| Windows | `%ProgramFiles%\AutoFirma-rs\` | `%ProgramData%\AutoFirma\` |
| Linux (paquetes) | `/usr/lib/autofirma-rs/` | `/etc/autofirma/` |
| macOS | `/Library/Application Support/AutoFirma/` | `/Library/Application Support/AutoFirma/` |
| Instalación de usuario (`--user`) | Windows `%ALLUSERSPROFILE%\Autofirma`, Linux `~/.afirma/Autofirma`, macOS `~/Library/Application Support/Autofirma` | configuración del usuario |

## 3. Windows

### 3.1 Instalación silenciosa (MSI)

```bat
msiexec /i AutoFirma-2.0.0-windows-x86_64.msi /qn /norestart /l*v "%TEMP%\autofirma-install.log" ^
    BROWSER_POLICIES=1 ORIGINS="https://sede.ejemplo.es,https://*.ejemplo.gob.es"
```

Propiedades públicas (los nombres coinciden con los del MSI de la Autofirma Java, para
reutilizar los despliegues existentes; como allí, `false` equivale a no indicarla):

| Propiedad | Valor por defecto | Efecto |
|---|---|---|
| `BROWSER_POLICIES` | (vacío) | `1`: directivas de navegadores (`--browser-policies`) |
| `ORIGINS` | (vacío = todos) | Orígenes autorizados para `afirma://` (`--origins`) |
| `FIREFOX_SECURITY_ROOTS` | (vacío) | `true`: Firefox confía en las CA del sistema (`--firefox-roots`) |
| `CONFIG_PATH` | (vacío) | Ruta o URL `https:` de un `.afconfig` (`--config-path`) |
| `UPDATE_CONFIG` | (vacío) | `true`: actualización diaria de `CONFIG_PATH` (`--update-config`) |
| `DEFAULT_LANGUAGE` | (vacío) | `es_ES`, `ca_ES`, `gl_ES`, `eu_ES`, `va_ES` o `en_US` |
| `KEYSTORE_PATH`, `CERTIFICATE_PATH` | (vacío) | Par CA + SSL corporativo (los dos a la vez; ver 5.2) |
| `CREATE_ICON` | `true` | `false`: sin acceso directo en el escritorio |
| `ADD_TO_PATH` | `1` | `0`: no añade la carpeta de instalación al `PATH` del sistema |
| `SKIP_CONFIGURE` | (vacío) | `1`: solo copia ficheros; la configuración la hace el administrador |
| `IGNORE_CONFIGURE_ERRORS` | (vacío) | `1`: si `install --system` falla, la instalación continúa (por defecto se deshace y `msiexec` devuelve 1603) |

No se admiten `USE_SYSTEM_JRE` (no hay Java) ni `LANGUAGE_PATH` (los idiomas van
incluidos). La salida de `install --system` queda en el registro de MSI (`/l*v`). El MSI:

* instala por equipo en `%ProgramFiles%\AutoFirma-rs` (no en `%ProgramFiles%\Autofirma`,
  que usa la versión Java y cuyo desinstalador borra esa carpeta entera);
* crea el acceso directo del menú Inicio y la entrada de «Aplicaciones instaladas»;
* registra `autofirma.exe` en *App Paths* y escribe `HKLM\SOFTWARE\AutoFirma-rs`
  (`InstallDir`, `Version`) para inventario y reglas de detección;
* permite actualizar sobre la misma versión (versiones previas) y rechaza instalar una
  versión anterior a la instalada.

Desinstalación silenciosa:

```bat
msiexec /x AutoFirma-2.0.0-windows-x86_64.msi /qn /norestart
```

o, sin el MSI, buscando los códigos de producto por el UpgradeCode:

```powershell
$installer = New-Object -ComObject WindowsInstaller.Installer
foreach ($code in $installer.RelatedProducts('{48D90D3A-830C-4DA9-8F3C-D4E2ADE9EE89}')) {
    Start-Process msiexec.exe -Wait -ArgumentList "/x $code /qn /norestart"
}
```

### 3.2 Convivencia con la Autofirma Java

Las dos versiones registran el mismo protocolo `afirma://`; el último instalador que se
ejecuta es el que lo atiende. Desinstale antes la versión Java:

```powershell
# MSI de la versión Java (UpgradeCode {A6D90EBF-E089-4281-9269-AE5D20BA74D2})
$installer = New-Object -ComObject WindowsInstaller.Installer
foreach ($code in $installer.RelatedProducts('{A6D90EBF-E089-4281-9269-AE5D20BA74D2}')) {
    Start-Process msiexec.exe -Wait -ArgumentList "/x $code /qn /norestart"
}
# Instalador EXE (NSIS) de la versión Java
$nsis = Join-Path $env:ProgramFiles 'Autofirma\uninstall.exe'
if (Test-Path $nsis) { Start-Process $nsis -Wait -ArgumentList '/S' }
```

### 3.3 Directiva de grupo (GPO)

*Configuración del equipo → Directivas → Configuración de software → Instalación de
software → Nuevo paquete*, ruta UNC al MSI, método **Asignada**. Las propiedades no se
pueden escribir en la GPO: cree una transformación `.mst` (con Orca o `wix` + `torch`) que
fije `BROWSER_POLICIES`, `ORIGINS`, etc. en la tabla `Property` y añádala en la pestaña
*Modificaciones*. Alternativa: un script de inicio con la orden `msiexec` de la sección 3.1.

Las directivas de los navegadores y las preferencias bloqueadas (secciones 6 y 7) también
se pueden desplegar directamente con GPO (Preferencias de registro o plantillas ADMX de
Chrome, Edge y Firefox), sin `BROWSER_POLICIES`.

### 3.4 Microsoft Intune

* **Aplicación de línea de negocio (MSI)**: suba el `.msi` y escriba las propiedades en
  *Argumentos de la línea de comandos* (`BROWSER_POLICIES=1 ORIGINS="https://sede.ejemplo.es"`).
  Asígnela a grupos de **dispositivos** (instalación en contexto de sistema).
* **Aplicación Win32 (.intunewin)**, si necesita más control:
  * Instalación: `msiexec /i "AutoFirma-2.0.0-windows-x86_64.msi" /qn /norestart BROWSER_POLICIES=1`
  * Desinstalación: `msiexec /x "{código de producto}" /qn /norestart`
  * Comportamiento: *Sistema*; códigos de retorno estándar de MSI (0, 1707, 3010, 1641, 1618).
  * Detección: *Código de producto MSI*, o registro `HKLM\SOFTWARE\AutoFirma-rs`, valor
    `Version` (cadena) igual a la versión instalada.
* Directivas de navegadores y preferencias: *Catálogo de configuración* (Chrome, Edge y
  Firefox tienen sus ADMX importables) o un perfil personalizado (OMA-URI) con las claves
  de la sección 6.

### 3.5 Configuration Manager (SCCM/MECM)

Cree una *Aplicación* con tipo de implementación *Windows Installer (\*.msi)*. Programa de
instalación: la orden de la sección 3.1; desinstalación: `msiexec /x {código} /qn`;
detección: código de producto MSI (lo rellena el asistente). Instale *Para el sistema*,
*Tanto si el usuario ha iniciado sesión como si no*.

### 3.6 Versión portable (sin administrador)

Descomprima el ZIP en una carpeta del usuario (p. ej. `%LOCALAPPDATA%\Programs\AutoFirma`)
y ejecute `autofirma.exe install --user`. La CA se instala en el almacén **del usuario** y
Windows muestra un aviso de seguridad que el usuario debe aceptar; por eso en equipos
gestionados se recomienda el MSI, que lo hace por equipo y sin avisos. Detalles en el
`README-portable.txt` del ZIP.

## 4. Linux

### 4.1 Instalación silenciosa

```sh
# Debian, Ubuntu y derivadas
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./autofirma-rs_2.0.0-1_amd64.deb
# Fedora, RHEL, Rocky, Alma
sudo dnf install -y ./autofirma-rs-2.0.0-1.x86_64.rpm
# openSUSE (paquete sin firmar con GPG)
sudo zypper --non-interactive install --allow-unsigned-rpm ./autofirma-rs-2.0.0-1.x86_64.rpm
```

Los paquetes instalan el ejecutable en `/usr/lib/autofirma-rs/autofirma` (con el lanzador
`/usr/bin/autofirma`), el fichero `autofirma.desktop` (`MimeType=x-scheme-handler/afirma;`),
los iconos y los metadatos AppStream, y ejecutan `autofirma install --system` en la
instalación y en cada actualización (`uninstall --system` solo al desinstalar).
Recomiendan `libnss3-tools`/`nss-tools` (certificados en Firefox), `pcscd` y `opensc`
(tarjetas inteligentes y DNIe); `apt` y `dnf` instalan las recomendaciones por defecto.

Los paquetes **sustituyen** al paquete `autofirma` de la versión Java (`Conflicts`), porque
los dos instalan `/usr/bin/autofirma` y el manejador de `afirma://`.

### 4.2 Opciones de instalación

Antes de instalar, cree `/etc/autofirma/install.conf` (líneas `CLAVE=valor`, mismos nombres
que las propiedades del MSI) o pase variables de entorno `AUTOFIRMA_<CLAVE>`:

```ini
# /etc/autofirma/install.conf
BROWSER_POLICIES=1
ORIGINS=https://sede.ejemplo.es,https://*.ejemplo.gob.es
FIREFOX_SECURITY_ROOTS=1
DEFAULT_LANGUAGE=es_ES
# CONFIG_PATH=https://intranet.ejemplo.es/autofirma.afconfig
# KEYSTORE_PATH=/root/autofirma-corp.pfx
# CERTIFICATE_PATH=/root/autofirma-corp-ca.cer
# UPDATE_CONFIG=1
# SKIP_CONFIGURE=1   (no configurar nada)
# STRICT=1           (un fallo de la configuración hace fallar la instalación del paquete)
```

```sh
sudo AUTOFIRMA_BROWSER_POLICIES=1 apt-get install -y ./autofirma-rs_2.0.0-1_amd64.deb
```

Por defecto, si la configuración falla el paquete queda instalado y se muestra un aviso
(no se deja `dpkg`/`rpm` en estado de error); repítala con `sudo autofirma install --system`.

Ejemplo de Ansible:

```yaml
- name: Opciones de AutoFirma
  ansible.builtin.copy:
    dest: /etc/autofirma/install.conf
    content: |
      BROWSER_POLICIES=1
      ORIGINS=https://sede.ejemplo.es
    mode: "0644"
- name: AutoFirma
  ansible.builtin.apt:
    deb: /srv/paquetes/autofirma-rs_2.0.0-1_amd64.deb
```

### 4.3 Usuarios nuevos y perfiles creados después

La instalación configura las bases NSS de Firefox y Chrome/Chromium **existentes**. Si un
usuario crea su perfil de Firefox después (o es un usuario nuevo), basta con que ejecute
`autofirma restore-config` (equivalente a «Restaurar instalación» de la versión Java). En
Linux, Firefox no usa el almacén del sistema (`ImportEnterpriseRoots` solo funciona en
Windows y macOS); para que cualquier perfil nuevo confíe en la CA local sin intervención,
añada a `/etc/firefox/policies/policies.json` la directiva `Certificates.Install` con la
ruta de la CA:

```json
{ "policies": { "Certificates": { "Install": ["/usr/lib/autofirma-rs/Autofirma_ROOT.cer"] } } }
```

Chrome y Chromium en Linux usan su propia base NSS (`~/.pki/nssdb`), que se crea al
abrirlos por primera vez: los usuarios que los abran después de instalar AutoFirma deben
ejecutar `autofirma restore-config`.

### 4.4 Portables (AppImage y .tar.gz)

No necesitan instalación. Para firmar en sedes web, el usuario ejecuta una vez
`./AutoFirma-2.0.0-x86_64.AppImage install --user` (o `./autofirma install --user` desde el
.tar.gz) tras dejar el fichero en su ubicación definitiva. Requieren glibc 2.28 o posterior.

## 5. macOS

### 5.1 Instalación silenciosa

```sh
sudo installer -pkg AutoFirma-2.0.0-macos-universal.pkg -target /
```

El paquete instala `/Applications/AutoFirma.app` (universal: Apple Silicon e Intel) y su
`postinstall` ejecuta `autofirma install --system`, con las opciones de
`/Library/Application Support/AutoFirma/install.conf` (mismo formato que en Linux; créelo
antes de instalar, p. ej. con un script previo del MDM). El `.dmg` solo contiene la
aplicación: al copiarla a mano no se configura el sistema y el usuario debe ejecutar
`/Applications/AutoFirma.app/Contents/MacOS/autofirma install --user`.

Desinstalación:

```sh
sudo "/Applications/AutoFirma.app/Contents/Resources/uninstall.sh"
```

### 5.2 MDM (Jamf Pro, Intune, Kandji, Mosyle…)

* El `.pkg` de las versiones publicadas está firmado con un certificado *Developer ID
  Installer* y notarizado (requisito para `InstallEnterpriseApplication` y para que
  Gatekeeper no lo bloquee); compruébelo con `pkgutil --check-signature`.
* **Confianza de la CA local**: desde macOS 11, cambiar la configuración de confianza del
  llavero del sistema puede exigir la autorización interactiva de un administrador aunque
  el proceso sea root. En instalaciones totalmente desatendidas por MDM, `install --system`
  puede no conseguir marcar la CA como de confianza (lo indica en el registro y en
  `autofirma doctor`). La forma soportada por Apple es distribuir la CA con un **perfil de
  configuración** (carga *Certificate*/`com.apple.security.root`). Como la CA se genera en
  cada equipo, en estos entornos:
  1. genere una sola vez un par CA + certificado SSL corporativo (PKCS#12 con contraseña
     `654321`, como en la versión Java) y distribúyalo a los equipos;
  2. despliegue la CA con un perfil de configuración;
  3. instale indicando ese par a `install --system` (opciones `--keystore-path` y
     `--certificate-path`, equivalentes a `-keystore_path`/`-certificate_path` de Java),
     de modo que no se genere una CA distinta en cada equipo. La clave privada del
     certificado SSL es entonces común a todos los equipos: solo vale para `127.0.0.1`,
     pero distribúyala por un canal protegido y no la reutilice para nada más.
* Directivas de navegadores y preferencias de AutoFirma: perfiles de configuración
  (secciones 6.3 y 7.2).

## 6. Directivas de navegadores (sin avisos al abrir `afirma://`)

Sin directivas, al pulsar «Firmar» en una sede el navegador pregunta si se permite abrir
AutoFirma, y Chrome (y pronto Edge) pide además permiso para que la sede acceda a la red
local (`wss://127.0.0.1`). `autofirma install --system --browser-policies --origins …`
escribe estas directivas automáticamente; también se pueden desplegar directamente con
las herramientas de gestión habituales. Restrinja siempre los orígenes a las sedes que
usen AutoFirma: con `*`, cualquier web podría lanzar AutoFirma sin preguntar.

### 6.1 Chrome, Edge, Chromium y Brave

| Directiva | Valor | Para qué |
|---|---|---|
| `AutoLaunchProtocolsFromOrigins` | `[{"protocol":"afirma","allowed_origins":["https://sede.ejemplo.es","https://ejemplo.gob.es"]}]` | Abre `afirma://` sin el diálogo de protocolo externo. Los orígenes usan el formato de `URLBlocklist`: `https://ejemplo.gob.es` incluye sus subdominios. |
| `ExternalProtocolDialogShowAlwaysOpenCheckbox` | `true` | Muestra la casilla «Permitir siempre» en los orígenes no incluidos |
| `LocalNetworkAccessAllowedForUrls` | `["https://sede.ejemplo.es","https://[*.]ejemplo.gob.es"]` | Evita el aviso de acceso a la red local (Local Network Access) al conectar con `wss://127.0.0.1` |
| `InsecurePrivateNetworkRequestsAllowedForUrls` | igual que la anterior | Versiones anteriores del mismo control (Private Network Access) |

Ubicaciones:

* **Windows** (GPO, Intune o `.reg`): `HKLM\SOFTWARE\Policies\Google\Chrome`,
  `HKLM\SOFTWARE\Policies\Microsoft\Edge`, `HKLM\SOFTWARE\Policies\Chromium`,
  `HKLM\SOFTWARE\Policies\BraveSoftware\Brave`. `AutoLaunchProtocolsFromOrigins` es un
  `REG_SZ` con el JSON; las listas son subclaves con valores `1`, `2`… :

  ```reg
  Windows Registry Editor Version 5.00

  [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome]
  "AutoLaunchProtocolsFromOrigins"="[{\"protocol\":\"afirma\",\"allowed_origins\":[\"https://sede.ejemplo.es\"]}]"
  "ExternalProtocolDialogShowAlwaysOpenCheckbox"=dword:00000001

  [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\LocalNetworkAccessAllowedForUrls]
  "1"="https://sede.ejemplo.es"
  ```

* **Linux**: un JSON en `/etc/opt/chrome/policies/managed/`, `/etc/chromium/policies/managed/`
  (o `/etc/chromium-browser/…`), `/etc/opt/edge/policies/managed/` o
  `/etc/brave/policies/managed/` (AutoFirma usa `autofirma.json`):

  ```json
  {
    "AutoLaunchProtocolsFromOrigins": [
      { "protocol": "afirma", "allowed_origins": ["https://sede.ejemplo.es"] }
    ],
    "ExternalProtocolDialogShowAlwaysOpenCheckbox": true,
    "LocalNetworkAccessAllowedForUrls": ["https://sede.ejemplo.es"]
  }
  ```

* **macOS**: perfil de configuración con los dominios `com.google.Chrome`,
  `com.microsoft.Edge`, `org.chromium.Chromium` o `com.brave.Browser`.

Compruebe el resultado en `chrome://policy` o `edge://policy`.

### 6.2 Firefox

```json
{
  "policies": {
    "Handlers": {
      "schemes": {
        "afirma": { "action": "useSystemDefault", "ask": false }
      }
    },
    "Certificates": { "ImportEnterpriseRoots": true }
  }
}
```

* **Linux**: `/etc/firefox/policies/policies.json` (también lo lee Firefox de Snap) y
  `/etc/firefox-esr/policies/policies.json`.
* **Windows**: `HKLM\SOFTWARE\Policies\Mozilla\Firefox`, valor `Handlers` (`REG_MULTI_SZ`
  con el JSON de `Handlers`, como en la plantilla ADMX de Mozilla) y
  `HKLM\SOFTWARE\Policies\Mozilla\Firefox\Certificates`, `ImportEnterpriseRoots` = `1`
  (DWORD).
* **macOS**: perfil con el dominio `org.mozilla.firefox` (`EnterprisePoliciesEnabled` =
  `true` y las mismas claves) o `Firefox.app/Contents/Resources/distribution/policies.json`.

En Windows y macOS, `ImportEnterpriseRoots` hace que Firefox confíe en la CA local
instalada en el almacén del sistema, aunque el perfil del usuario se cree después de
instalar AutoFirma. En Linux esa directiva no tiene efecto: use `Certificates.Install`
(sección 4.3). Compruebe el resultado en `about:policies`.

### 6.3 Perfil de configuración de macOS (ejemplo)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>es.ejemplo.autofirma</string>
  <key>PayloadUUID</key><string>6F0C7E0E-0D6B-4E0B-9F57-3C1E3B6D2A10</string>
  <key>PayloadDisplayName</key><string>AutoFirma: navegadores</string>
  <key>PayloadScope</key><string>System</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.google.Chrome</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>es.ejemplo.autofirma.chrome</string>
      <key>PayloadUUID</key><string>2B4D1B4E-8E07-4D8E-A6C5-8A4C2C1E9F31</string>
      <key>AutoLaunchProtocolsFromOrigins</key>
      <array>
        <dict>
          <key>protocol</key><string>afirma</string>
          <key>allowed_origins</key><array><string>https://sede.ejemplo.es</string></array>
        </dict>
      </array>
      <key>LocalNetworkAccessAllowedForUrls</key>
      <array><string>https://sede.ejemplo.es</string></array>
    </dict>
    <dict>
      <key>PayloadType</key><string>org.mozilla.firefox</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadIdentifier</key><string>es.ejemplo.autofirma.firefox</string>
      <key>PayloadUUID</key><string>9A3E8F55-1C2D-4B7A-8E61-0F4D7C2B5E92</string>
      <key>EnterprisePoliciesEnabled</key><true/>
      <key>Handlers</key>
      <dict>
        <key>schemes</key>
        <dict>
          <key>afirma</key>
          <dict>
            <key>action</key><string>useSystemDefault</string>
            <key>ask</key><false/>
          </dict>
        </dict>
      </dict>
      <key>Certificates</key>
      <dict><key>ImportEnterpriseRoots</key><true/></dict>
    </dict>
  </array>
</dict>
</plist>
```

(Genere UUID propios con `uuidgen`.)

## 7. Preferencias preconfiguradas y bloqueadas

AutoFirma-rs lee, además de las preferencias del usuario y de sistema, una capa de
**directivas** del administrador:

* **obligatorias** (*mandatory*): el usuario no puede cambiarlas (aparecen bloqueadas);
* **recomendadas** (*recommended*): valor inicial que el usuario puede cambiar;
* **tarjetas inteligentes** (*smartcards*): módulos PKCS#11 adicionales (nombre → biblioteca).

Los nombres de las claves son los de la versión Java (lista completa y valores admitidos
en `docs/spec/06-app-ui-cli-installer.md`, §4.5). Algunas útiles:

| Clave | Ejemplo | Efecto |
|---|---|---|
| `preferencesBlocked` | `true` | Bloquea toda la ventana de preferencias (como en Java) |
| `signatureHashAlgorithm` | `SHA256` | Algoritmo de huella |
| `default.locale` | `es_ES` | Idioma |
| `defaultSignatureFormatPdf` | `PAdES` | Formato por defecto de los PDF |
| `secureConnections` | `true` | Solo conexiones seguras con servidores externos |
| `secureDomainsList` | `*.ejemplo.gob.es` | Dominios de confianza para el protocolo |
| `defaultKeystore` | `WINDOWS` | Almacén de certificados por defecto |
| `proxySelected`, `proxyHost`, `proxyPort`, `proxyExcludedUrls` | | Proxy (sección 8) |
| `checkForUpdates` | `false` | Sin comprobación de actualizaciones |
| `allowPersonalTruststore` | `false` | Impide que el usuario añada certificados de confianza |

Valores: cadenas; los booleanos admiten `true`/`false`, `1`/`0` (DWORD en Windows) o
`<true/>`/`<false/>` (plist). Un valor no válido para su clave se descarta y se avisa en
`autofirma doctor`.

### 7.1 Windows (GPO / Intune)

* Obligatorias: `HKLM\SOFTWARE\Policies\AutoFirma` (y, con menor prioridad,
  `HKCU\SOFTWARE\Policies\AutoFirma`).
* Recomendadas: subclave `Recommended`. Tarjetas: subclave `SmartCards`.

```reg
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\AutoFirma]
"preferencesBlocked"=dword:00000001
"signatureHashAlgorithm"="SHA256"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\AutoFirma\Recommended]
"default.locale"="es_ES"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\AutoFirma\SmartCards]
"Tarjeta corporativa"="C:\\Program Files\\Proveedor\\pkcs11.dll"
```

### 7.2 macOS (perfil de configuración)

Preferencias gestionadas del dominio `io.github.autofirma-rs.AutoFirma`
(`/Library/Managed Preferences/io.github.autofirma-rs.AutoFirma.plist`, o la carpeta del
usuario para perfiles de usuario). Las claves de primer nivel son obligatorias; el
diccionario `Recommended` contiene las recomendadas y `SmartCards` las tarjetas. En Jamf o
Intune, use «Application & Custom Settings» / «Preference file» con ese dominio, o una
carga del perfil con `PayloadType` = `io.github.autofirma-rs.AutoFirma`:

```xml
<dict>
  <key>PayloadType</key><string>io.github.autofirma-rs.AutoFirma</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadIdentifier</key><string>es.ejemplo.autofirma.prefs</string>
  <key>PayloadUUID</key><string>C1D2E3F4-0A1B-4C2D-8E3F-405162738495</string>
  <key>preferencesBlocked</key><true/>
  <key>signatureHashAlgorithm</key><string>SHA256</string>
  <key>Recommended</key>
  <dict><key>default.locale</key><string>es_ES</string></dict>
</dict>
```

### 7.3 Linux

`/etc/autofirma/policy.json` y, en orden alfabético, `/etc/autofirma/policy.d/*.json` (los
posteriores prevalecen; útil para gestionarlos por piezas con Ansible/Puppet):

```json
{
  "mandatory": {
    "preferencesBlocked": true,
    "signatureHashAlgorithm": "SHA256",
    "secureConnections": true
  },
  "recommended": {
    "default.locale": "es_ES",
    "defaultSignatureFormatPdf": "PAdES"
  },
  "smartcards": {
    "Tarjeta corporativa": "/usr/lib/x86_64-linux-gnu/pkcs11/proveedor-pkcs11.so"
  }
}
```

### 7.4 Ficheros `.afconfig` (compatibles con la versión Java)

`CONFIG_PATH` (MSI), `CONFIG_PATH=` en `install.conf` o `--config-path` importan un fichero
de preferencias de la versión Java como preferencias **de sistema** (el usuario puede
cambiarlas salvo que el fichero las bloquee). Con `UPDATE_CONFIG`/`--update-config` y una
URL `https://`, AutoFirma lo vuelve a descargar como mucho una vez al día y aplica los
cambios. Para valores que el usuario no debe poder cambiar, use las directivas anteriores.

## 8. Red: proxy, TLS y puertos

* **Proxy**: AutoFirma usa el proxy del sistema (Windows: configuración de proxy de
  Windows; Linux y macOS: variables `HTTPS_PROXY`, `HTTP_PROXY` y `NO_PROXY`) para sus
  conexiones salientes (servidor intermedio, firma trifásica, sellos de tiempo, OCSP/CRL,
  descarga de configuración). Las preferencias `proxySelected`/`proxyHost`/`proxyPort`/
  `proxyExcludedUrls` (se pueden imponer por directiva) tienen prioridad. Los ficheros
  PAC/WPAD no se interpretan: indique un proxy explícito en esos casos.
* **Inspección TLS corporativa**: AutoFirma valida los servidores con el almacén de
  confianza del sistema, así que confía en la CA de inspección si está instalada en él
  (además de las CA de los prestadores españoles que incluía la versión Java).
* **Servidor local**: AutoFirma escucha solo en `127.0.0.1` (WebSocket seguro; puerto
  63117 por defecto o los que indique la sede, entre 49152 y 65535). No hace falta abrir
  puertos en el cortafuegos ni aparece el aviso del Firewall de Windows. El tráfico a
  `127.0.0.1`/`localhost` no debe pasar por el proxy (los navegadores lo excluyen por
  defecto; revise los PAC que lo fuercen) y las herramientas de inspección TLS o los
  antivirus con «análisis HTTPS» deben excluir `127.0.0.1`, o el navegador verá un
  certificado distinto del de la CA local.

## 9. Firma de código y avisos de seguridad

Un ejecutable o instalador **sin firmar provoca avisos**: «Windows protegió su PC»
(SmartScreen) en Windows y el bloqueo de Gatekeeper («no se puede abrir porque Apple no
puede comprobar si contiene software malicioso») en macOS. El flujo de publicación
(`.github/workflows/release.yml`) firma todo cuando dispone de los secretos; sin ellos
genera paquetes sin firmar, útiles solo para pruebas.

### 9.1 Windows

* Se necesita un certificado de **firma de código Authenticode** de una CA pública:
  * **Azure Artifact Signing** (antes *Trusted Signing*) de Microsoft: certificados de
    vida corta gestionados por Microsoft, sin token físico, integrados en el flujo
    (`Azure/artifact-signing-action`). Requiere validar la identidad de la organización.
  * Un certificado **OV o EV** de una CA comercial. Desde junio de 2023 la clave debe
    residir en hardware (token USB o HSM en la nube: DigiCert KeyLocker, SSL.com eSigner,
    Certum SimplySign, Azure Key Vault o Google Cloud KMS…), por lo que el método de
    «PFX en un secreto» (`WINDOWS_SIGN_PFX_BASE64`) solo sirve con certificados antiguos
    o de una CA interna.
  * Una CA **interna** de la organización solo vale para sus propios equipos (WDAC/AppLocker),
    no evita SmartScreen en equipos ajenos.
* Se firman `autofirma.exe` (antes de empaquetar) y el `.msi`, con SHA-256 y sello de
  tiempo RFC 3161 (la firma sigue siendo válida cuando caduca el certificado).
* SmartScreen se basa en la **reputación** del fichero y del editor: un certificado nuevo
  puede mostrar avisos durante un tiempo hasta acumular descargas; desde 2024 los
  certificados EV ya no conceden reputación inmediata.
* Los despliegues con **Intune, SCCM o GPO no muestran SmartScreen** (no hay marca de
  «descargado de Internet»). Para WDAC/AppLocker, autorice por editor (firma).

### 9.2 macOS

* Programa de desarrolladores de Apple (Apple Developer Program) con dos certificados:
  **Developer ID Application** (firma de `AutoFirma.app` y del `.dmg`) y **Developer ID
  Installer** (firma del `.pkg`).
* La aplicación se firma con *hardened runtime* y el derecho
  `com.apple.security.cs.disable-library-validation`, necesario para cargar módulos PKCS#11
  de terceros (OpenSC, DNIe, tarjetas) y la NSS de Firefox.
* **Notarización** con `notarytool` (clave de API de App Store Connect) y *stapling* del
  ticket en la aplicación, el `.dmg` y el `.pkg`, para que Gatekeeper los acepte también
  sin conexión. Sin notarización, macOS 15 ya no permite abrirla con «Control-clic → Abrir»:
  el usuario tendría que ir a *Ajustes del Sistema → Privacidad y seguridad → Abrir igualmente*.
* Los MDM exigen un `.pkg` firmado con Developer ID Installer.

### 9.3 Linux

No hay control equivalente en el sistema. Publique `SHA256SUMS` firmado con GPG
(`SHA256SUMS.asc`) y, si mantiene un repositorio APT/RPM, firme sus metadatos.

### 9.4 Verificar una descarga

```sh
sha256sum -c SHA256SUMS --ignore-missing
gpg --verify SHA256SUMS.asc SHA256SUMS
gh attestation verify AutoFirma-2.0.0-windows-x86_64.msi --repo autofirma-rs/autofirma-rs
```

En Windows: `Get-AuthenticodeSignature .\AutoFirma-2.0.0-windows-x86_64.msi`; en macOS:
`pkgutil --check-signature AutoFirma-2.0.0-macos-universal.pkg` y
`spctl --assess -vv --type install AutoFirma-2.0.0-macos-universal.pkg`.

## 10. Comprobar la instalación

```sh
autofirma doctor           # informe legible
autofirma doctor --json    # para inventario o scripts; código de salida 1 si hay errores
```

`doctor` comprueba los certificados locales (presencia, validez, cadena), su confianza en
el almacén del sistema y en cada perfil de Firefox/Chrome, el registro de `afirma://`, el
puerto local, las bibliotecas NSS, las directivas de navegadores y las preferencias y
directivas de AutoFirma, e indica cómo corregir cada problema. Ejecutado como
administrador revisa los perfiles de todos los usuarios.

Comprobaciones manuales:

| Sistema | Orden |
|---|---|
| Windows | `reg query HKCR\afirma\shell\open\command` · `certutil -store Root "Autofirma ROOT"` |
| Linux | `xdg-mime query default x-scheme-handler/afirma` · `trust list --filter=ca-anchors \| grep -i autofirma` (Fedora/openSUSE) o `ls /usr/local/share/ca-certificates/` (Debian) |
| macOS | `security find-certificate -c "Autofirma ROOT" /Library/Keychains/System.keychain` |
| Navegadores | `chrome://policy`, `edge://policy`, `about:policies` |

Si algo falla para un usuario concreto (perfil de Firefox nuevo, usuario nuevo),
`autofirma restore-config` repara su configuración (equivale a «Herramientas → Restaurar
instalación» de la versión Java). Para el equipo completo, repita
`autofirma install --system` como administrador (o «Reparar» el MSI).

## 11. Construcción de los paquetes (mantenedores)

| Plataforma | Orden | Notas |
|---|---|---|
| Linux | `tools/package/linux.sh [--target aarch64-unknown-linux-gnu] [--builder zigbuild\|docker\|cargo]` | `.deb` (cargo-deb), `.rpm` (cargo-generate-rpm), `.tar.gz`, AppImage. Con `zigbuild`/`docker` el binario exige solo glibc 2.28. |
| Windows (en Windows) | `cargo build --release -p autofirma --target x86_64-pc-windows-msvc` y `pwsh tools/package/windows.ps1 -Exe … -Arch x64` | ZIP y MSI (WiX 5). Firma: `tools/package/sign-windows.ps1`. |
| Windows (desde Linux) | `tools/package/windows-cross.sh [--msi]` | Imagen `autofirma-cross:latest` (MinGW). ZIP de prueba y MSI de humo con `wixl` (sin acciones personalizadas). |
| macOS | `tools/package/macos.sh` | `.app` universal, `.dmg`, `.pkg`; firma y notarización con las variables documentadas en el script. |
| Todas | etiqueta `v<versión>` → `.github/workflows/release.yml` | Firma si hay secretos, `SHA256SUMS`, SBOM SPDX, atestación de procedencia y Release de GitHub. |

Al publicar una versión: actualice `version` en `Cargo.toml` (la etiqueta debe coincidir)
y añada la entrada `<release>` en
`packaging/linux/io.github.autofirma_rs.AutoFirma.metainfo.xml`.
